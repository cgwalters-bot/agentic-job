//! One ACP session, from starting the agent to its result, recorded as it
//! goes.
//!
//! The session is the task's prompt turn, and what the run's budget
//! (`budget`) adds to it: notices, sent as prompts of their own while the
//! turn runs, to the agents that queue them behind the step they are on
//! (`AgentSpec::notices`; another would end its turn for one); then, near
//! a limit, a `session/cancel` of the turn and one more prompt turn in
//! which the agent hands back; and at the limit a last `session/cancel`.
//!
//! With a bridge (`bridge`), the session does not end with the task's
//! turn: it waits for its client's prompts, each a turn of its own under
//! the same limits, until the client leaves or sends none for the idle
//! timeout (`conversation`).
//!
//! When the session ends, the process group started for the agent is
//! killed, and then every process of the sandbox user (`process`): the
//! agent runs in a login session of that user's, where a signal to the
//! group does not reach.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use agent_client_protocol::schema::ProtocolVersion;
use agent_client_protocol::schema::v1::{
    CancelNotification, ContentBlock, Implementation, InitializeRequest, NewSessionRequest,
    PromptRequest, PromptResponse, RequestPermissionOutcome, RequestPermissionRequest,
    RequestPermissionResponse, SelectedPermissionOutcome, SessionConfigOptionCategory, SessionId,
    SetSessionConfigOptionRequest, TextContent,
};
use agent_client_protocol::{Agent, Client, ConnectionTo, Dispatch, Handled, Lines};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot, watch};

use super::agents::AgentSpec;
use super::bridge::{Bridge, FromClient};
use super::budget::{Budget, LABEL_HAND_BACK, Limits, Signal, Stop, Usage};
use super::clients::Clients;
use super::digest::{self, Dir};
use super::permission::{self, Policy, Request, pick_option};
use super::process::{self, Launch};
use super::transcript::{Log, Tap, set_stop};
use crate::exit::Exit;
use crate::sandbox::root::Root;

pub const RESULT_FILE: &str = "harness.json";
/// The old tree's schema name, which readers of `harness.json` check.
pub const RESULT_SCHEMA: &str = "bot-harness-result/v1";
/// How long the agent gets to wind down after `session/cancel`.
const CANCEL_GRACE: Duration = Duration::from_secs(30);
/// How often the budget is checked.
const BUDGET_TICK: Duration = Duration::from_millis(250);
/// How long an agent whose streams closed gets to exit, so that the
/// failure can say how it did.
const EXIT_GRACE: Duration = Duration::from_secs(1);
const CLIENT_NAME: &str = env!("CARGO_PKG_NAME");
const LOST_STOP_SIGNAL: &str = "the session lost its stop signal";
const AGENT_EXITED: &str = "the agent exited";
const CLIENT_LEFT: &str = "the client left";
const SESSION_ENDED: &str = "the session has ended";
const NO_CANCEL_ANSWER: &str = "the agent did not answer the cancellation";
const TURN_RUNNING: &str = "a turn is running: cancel it or wait for its answer";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Failure,
    Timeout,
    Budget,
    Cancelled,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Timeout => "timeout",
            Outcome::Budget => "budget",
            Outcome::Cancelled => "cancelled",
        }
    }

    /// The exit state of a run whose session ended like this.
    pub fn exit(self) -> Exit {
        match self {
            Outcome::Success => Exit::Success,
            Outcome::Timeout => Exit::Timeout,
            Outcome::Budget => Exit::Limit,
            Outcome::Failure | Outcome::Cancelled => Exit::Failure,
        }
    }
}

/// `harness.json`: how the session went, for the run's summary.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunResult {
    pub schema: String,
    pub agent: String,
    pub command: Vec<String>,
    pub result: Outcome,
    pub stop_reason: Option<String>,
    pub message: Option<String>,
    pub started_at: String,
    pub finished_at: String,
    pub duration_s: u64,
    pub limits: Limits,
    /// Stopped at a limit (`result` is timeout or budget), the agent
    /// finished a turn in which it was asked to hand back.
    #[serde(default)]
    pub handed_back: bool,
}

impl RunResult {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(RESULT_FILE);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }
}

/// What the budget asks of the session short of stopping it.
enum Nudge {
    Notice {
        label: String,
        text: String,
    },
    HandBack {
        why: Stop,
        text: String,
        window: Duration,
    },
}

/// One session: which agent, on what, within which limits.
pub struct Options {
    /// The agent's name, for the record.
    pub name: String,
    pub agent: AgentSpec,
    /// The model (default: the agent's own).
    pub model: Option<String>,
    /// Session config options set after the model, by id and value: an
    /// agent may take one it does not list in `session/new`, as Vibe does
    /// its `max_tokens`. One the agent refuses fails the session.
    pub config_options: Vec<(String, String)>,
    /// The agent's working directory.
    pub cwd: PathBuf,
    /// The task.
    pub prompt: String,
    /// Where `acp.jsonl`, `agent-stderr.log` and `harness.json` go.
    pub out: PathBuf,
    pub permissions: Policy,
    pub limits: Limits,
    /// The run's count of model requests, kept current by whoever serves
    /// the inference (ACP doesn't report them, and it has subagents'
    /// too); `None` in it while nothing is known. `Limits::max_requests`
    /// needs one: a cap with nothing to count is refused.
    pub requests: Option<watch::Receiver<Option<u64>>>,
    pub launch: Launch,
    /// The clients attached to the session; none for a task run.
    pub clients: Clients,
    /// Where a client is reached after the task's turn; none for a task
    /// run, which ends with it.
    pub bridge: Option<Bridge>,
    /// Where the condensed transcript goes, a line per event.
    pub log: Log,
}

/// Watches the budget for the whole run, from before the session exists:
/// the limit stops it through STOP, the rest reaches the session as nudges.
async fn watch_budget(
    limits: Limits,
    requests: Option<watch::Receiver<Option<u64>>>,
    tap: Arc<Tap>,
    stop: watch::Sender<Option<Stop>>,
    nudges: mpsc::UnboundedSender<Nudge>,
) {
    let mut budget = Budget::new(limits);
    let started = Instant::now();
    let mut tick = tokio::time::interval(BUDGET_TICK);
    loop {
        tick.tick().await;
        let usage = Usage {
            elapsed: started.elapsed(),
            requests: requests.as_ref().and_then(|count| *count.borrow()),
            tasks: tap.tasks(),
        };
        // The session may be over: nobody is left to nudge.
        let _ = match budget.check(&usage) {
            Some(Signal::Stop(why)) => return set_stop(&stop, why),
            Some(Signal::Notice { label, text }) => nudges.send(Nudge::Notice { label, text }),
            Some(Signal::HandBack { why, text, window }) => {
                nudges.send(Nudge::HandBack { why, text, window })
            }
            None => Ok(()),
        };
    }
}

fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The agent's standard output as the transport's incoming lines, each
/// recorded as it arrives.
fn incoming(
    stdout: UnixStream,
    tap: Arc<Tap>,
) -> impl futures::Stream<Item = std::io::Result<String>> + Send + 'static {
    futures::stream::unfold(
        (BufReader::new(stdout).lines(), tap),
        |(mut lines, tap)| async move {
            let line = lines.next_line().await.transpose()?;
            if let Ok(line) = &line {
                tap.message(Dir::Recv, line);
            }
            Some((line, (lines, tap)))
        },
    )
}

/// The agent's standard input as the transport's outgoing lines, each
/// recorded as it is sent.
fn outgoing(
    stdin: UnixStream,
    tap: Arc<Tap>,
) -> impl futures::Sink<String, Error = std::io::Error> + Send + 'static {
    futures::sink::unfold((stdin, tap), |(mut stdin, tap), line: String| async move {
        tap.message(Dir::Send, &line);
        stdin.write_all(line.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        Ok::<_, std::io::Error>((stdin, tap))
    })
}

/// Records the agent's standard error until it closes. It is read as
/// bytes: a line that isn't UTF-8 must not end the reading, which would
/// close the stream under an agent that goes on writing to it.
async fn drain_stderr(stderr: UnixStream, tap: Arc<Tap>) {
    let mut stderr = BufReader::new(stderr);
    let mut line = Vec::new();
    while let Ok(1..) = stderr.read_until(b'\n', &mut line).await {
        let text = String::from_utf8_lossy(&line);
        tap.stderr(text.trim_end_matches(['\n', '\r']));
        line.clear();
    }
}

/// Runs the session and writes `harness.json`.
///
/// `Err` is for what keeps a session from being run or recorded at all,
/// and for processes of the sandbox user that could not be stopped. An
/// agent that fails, or cannot be started, is a result.
pub async fn run(opts: Options) -> Result<RunResult> {
    let Options {
        name,
        agent: spec,
        model,
        config_options,
        cwd,
        prompt,
        out,
        permissions,
        limits,
        requests,
        launch,
        mut clients,
        bridge,
        log,
    } = opts;
    // A cap that nothing counts would be no cap, and silently: the
    // caller drops it, knowing so, or supplies the count.
    ensure!(
        limits.max_requests.is_none() || requests.is_some(),
        "the session has a cap on model requests and nothing that counts them"
    );
    std::fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
    // Before anything is started: a user that cannot be stopped again is
    // no sandbox user.
    let sandbox = match &launch {
        Launch::Sandbox { user, .. } => {
            Some(process::SandboxUser::find(user, Root::detect()).await?)
        }
        Launch::Direct => None,
    };
    // Before the agent starts: a relay that cannot be reached is a
    // session that cannot be held.
    let (session_id, attach_to) = watch::channel(None);
    let (conversation, hang_up) = match bridge {
        Some(bridge) => {
            let connected = bridge.connect(attach_to).await?;
            clients.attach(connected.send);
            let conversation = Conversation {
                from_client: connected.from_client,
                idle: connected.idle,
            };
            (Some(conversation), Some(connected.close))
        }
        None => (None, None),
    };
    let (stop_tx, stop_rx) = watch::channel(None);
    let tap = Arc::new(Tap::create(
        &out,
        log,
        limits.clone(),
        stop_tx.clone(),
        clients,
    )?);
    let (argv, env) = spec.command(launch.wrapper(), model.as_deref());
    let task = Task {
        cwd: &cwd,
        model: model.as_deref(),
        model_by_env: spec.model_env.is_some(),
        config_options: &config_options,
        prompt: &prompt,
        notices: spec.notices,
    };
    let started = chrono::Utc::now();
    let (nudge_tx, nudge_rx) = mpsc::unbounded_channel();
    let watcher = tokio::spawn(watch_budget(
        limits.clone(),
        requests,
        tap.clone(),
        stop_tx,
        nudge_tx,
    ));
    // Whatever the agent left running goes before anything reads its
    // files, and whether or not it ever started.
    let (ended, reaped) = match process::spawn(&argv, &env) {
        Ok((mut agent, streams)) => {
            let process::Streams {
                stdin,
                stdout,
                stderr,
            } = streams;
            let stderr = tokio::spawn(drain_stderr(stderr, tap.clone()));
            let signals = Signals {
                stop: stop_rx,
                nudges: nudge_rx,
                cancelling: Arc::new(AtomicBool::new(false)),
                session_id,
                conversation,
            };
            let (ended, exited) = drive(
                &mut agent,
                (stdin, stdout),
                &tap,
                task,
                permissions,
                signals,
            )
            .await;
            // The group started here is the wrapper's, which may be
            // root's and out of this user's reach: the sandbox user's
            // processes are killed first, so the wrapper is not waited
            // for while its agent lives.
            agent.kill_group();
            let reaped = reap(sandbox.as_ref()).await;
            agent.gone().await;
            // With its writers gone the agent's standard error closes;
            // what was written until then belongs in the log.
            let _ = tokio::time::timeout(EXIT_GRACE, stderr).await;
            let ended = match exited {
                Some(status) => ended.agent_exited(status, tap.last_stderr()),
                None => ended,
            };
            (ended, reaped)
        }
        Err(e) => (
            Ended::failure(format!("the agent could not be started: {e:#}")),
            reap(sandbox.as_ref()).await,
        ),
    };
    watcher.abort();
    if let Some(hang_up) = hang_up {
        hang_up.close().await;
    }
    let finished = chrono::Utc::now();

    let Ended {
        mut outcome,
        mut stop_reason,
        mut message,
        handed_back,
    } = ended;
    let transcript = tap.finish();
    if stop_reason.is_none() {
        stop_reason = transcript.stop_reason;
    }
    if let Some(e) = transcript.write_error {
        outcome = Outcome::Failure;
        message = Some(e);
    }
    // What is left running may still be writing the files a caller is
    // about to read: no result of such a session stands.
    if let Err(e) = &reaped {
        outcome = Outcome::Failure;
        message = Some(format!("{e:#}"));
    }
    // Why it didn't succeed, unless the digest already said.
    if let (Outcome::Failure, Some(m)) = (outcome, &message)
        && !transcript.agent_error
    {
        tap.log(&[digest::cut(&format!("⚠ {m}"))]);
    }
    let result = RunResult {
        schema: RESULT_SCHEMA.to_owned(),
        agent: name,
        command: argv,
        result: outcome,
        stop_reason,
        message: message.map(|m| digest::cut(&m)),
        started_at: rfc3339(started),
        finished_at: rfc3339(finished),
        duration_s: (finished - started).num_seconds().max(0).unsigned_abs(),
        limits,
        // A transcript that couldn't be written fails the run all the same.
        handed_back: handed_back && outcome != Outcome::Failure,
    };
    let path = out.join(RESULT_FILE);
    std::fs::write(&path, serde_json::to_string_pretty(&result)? + "\n")
        .with_context(|| format!("writing {}", path.display()))?;
    reaped?;
    Ok(result)
}

/// Stops everything the sandbox user is running, where there is one.
async fn reap(sandbox: Option<&process::SandboxUser>) -> Result<()> {
    match sandbox {
        Some(user) => user.reap().await,
        None => Ok(()),
    }
}

/// What the session asks of the agent.
struct Task<'a> {
    cwd: &'a Path,
    model: Option<&'a str>,
    /// The model went into the agent's environment.
    model_by_env: bool,
    config_options: &'a [(String, String)],
    prompt: &'a str,
    /// The agent takes a prompt sent during a turn (`AgentSpec::notices`).
    notices: bool,
}

/// Speaks ACP with a started agent, over its standard input and output,
/// until the session ends: how it ended, and the agent's exit status if
/// it failed by exiting. Returning closes the agent's standard input.
async fn drive(
    agent: &mut process::Agent,
    (stdin, stdout): (UnixStream, UnixStream),
    tap: &Arc<Tap>,
    task: Task<'_>,
    permissions: Policy,
    signals: Signals,
) -> (Ended, Option<ExitStatus>) {
    let transport = Lines::new(
        Box::pin(outgoing(stdin, tap.clone())),
        Box::pin(incoming(stdout, tap.clone())),
    );
    let policy = Arc::new(permissions);
    let permission_cwd = task.cwd.to_owned();
    let permission_stop = signals.stop.clone();
    let permission_cancelling = signals.cancelling.clone();
    let connection = Client
        .builder()
        .name(CLIENT_NAME)
        .on_receive_request(
            async move |req: RequestPermissionRequest, responder, _cx| {
                let stopped = permission_stop.borrow().is_some()
                    || permission_cancelling.load(Ordering::Relaxed);
                responder.respond(answer_permission(&policy, &permission_cwd, &req, stopped))
            },
            agent_client_protocol::on_receive_request!(),
        )
        // Everything else the agent sends. The tap has already recorded
        // it; unhandled, the SDK would queue session-scoped messages for
        // a session handler forever (growing without bound, and leaving
        // fs/* and terminal/* requests, which the session doesn't
        // advertise, unanswered until the timeout).
        .on_receive_dispatch(
            async move |d: Dispatch, _cx| match d {
                Dispatch::Request(req, responder) => {
                    let method = req.method().to_owned();
                    responder.respond_with_error(
                        agent_client_protocol::Error::method_not_found().data(method),
                    )?;
                    Ok(Handled::Yes)
                }
                Dispatch::Notification(_) => Ok(Handled::Yes),
                // Responses to the session's own requests.
                other => Ok(Handled::No {
                    message: other,
                    retry: false,
                }),
            },
            agent_client_protocol::on_receive_dispatch!(),
        )
        .connect_with(transport, async |cx: ConnectionTo<Agent>| {
            Ok(session(cx, tap, &task, signals).await)
        });
    let mut connection = std::pin::pin!(connection);
    // An error is the transport's: usually the agent closed its streams.
    let transport_failed =
        |e: agent_client_protocol::Error| Ended::failure(format!("the agent failed: {e}"));
    // The agent exiting ends the session, whatever it was waiting for.
    let ended = tokio::select! {
        r = &mut connection => r.unwrap_or_else(transport_failed),
        // Its last answer may still be on its way in: an agent that
        // answers its turn and exits has not failed.
        _ = agent.wait() => match tokio::time::timeout(EXIT_GRACE, &mut connection).await {
            Ok(r) => r.unwrap_or_else(transport_failed),
            Err(_) => Ended::failure(AGENT_EXITED.to_owned()),
        },
    };
    // A failure is usually the agent having died, and its exit status and
    // last words say more than the request that happened to be waiting.
    let exited = match ended.outcome {
        Outcome::Failure => tokio::time::timeout(EXIT_GRACE, agent.wait())
            .await
            .ok()
            .and_then(Result::ok),
        _ => None,
    };
    (ended, exited)
}

/// Answers a permission request from the policy; once the session has
/// been stopped (STOPPED), every request is cancelled, as ACP
/// requires after session/cancel.
fn answer_permission(
    policy: &Policy,
    cwd: &Path,
    req: &RequestPermissionRequest,
    stopped: bool,
) -> RequestPermissionResponse {
    let params = serde_json::to_value(req).unwrap_or(Value::Null);
    let verdict = policy.decide(&Request::from_params(&params, cwd));
    let picked = if stopped {
        None
    } else {
        pick_option(&params["options"], verdict.decision)
    };
    let (outcome, decision) = match picked {
        Some((id, d)) => (
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(id)),
            d.as_str(),
        ),
        // Stopped, no option for the decision, or a malformed request.
        None => (RequestPermissionOutcome::Cancelled, "cancelled"),
    };
    let meta = meta(json!({"decision": decision, "rule": verdict.rule}));
    RequestPermissionResponse::new(outcome).meta(meta)
}

/// The `_meta` the session marks its own messages with.
fn meta(value: Value) -> Map<String, Value> {
    Map::from_iter([(permission::META_KEY.to_owned(), value)])
}

/// How a session ended.
struct Ended {
    outcome: Outcome,
    stop_reason: Option<String>,
    message: Option<String>,
    handed_back: bool,
}

impl Ended {
    fn failure(message: String) -> Self {
        Ended {
            outcome: Outcome::Failure,
            stop_reason: None,
            message: Some(message),
            handed_back: false,
        }
    }

    /// The failure of an agent that exited on its own with STATUS: that,
    /// and the last it said on its standard error, ahead of the request
    /// that failed for it.
    fn agent_exited(self, status: ExitStatus, last_words: Option<String>) -> Self {
        let last_words = last_words
            .map(|line| format!(": {line}"))
            .unwrap_or_default();
        let request = self
            .message
            .filter(|m| m != AGENT_EXITED)
            .map(|m| format!(" ({m})"))
            .unwrap_or_default();
        Ended::failure(format!("{AGENT_EXITED} ({status}){last_words}{request}"))
    }

    /// A conversation that ended as it may: the client left, or went
    /// quiet.
    fn done(message: String) -> Self {
        Ended {
            outcome: Outcome::Success,
            stop_reason: None,
            message: Some(message),
            handed_back: false,
        }
    }

    /// Stopped by the session for WHY.
    fn stopped(why: &Stop, handed_back: bool) -> Self {
        let (outcome, msg) = stopped(why);
        let how = if handed_back {
            "the agent handed back"
        } else {
            "cancelled"
        };
        Ended {
            outcome,
            stop_reason: None,
            message: Some(format!("{msg}; {how}")),
            handed_back,
        }
    }
}

/// What the session is told while it runs.
struct Signals {
    stop: watch::Receiver<Option<Stop>>,
    nudges: mpsc::UnboundedReceiver<Nudge>,
    /// Set from a session/cancel until the turn it cancels has answered:
    /// permission requests are cancelled meanwhile.
    cancelling: Arc<AtomicBool>,
    /// The agent's session, once it has one, for the bridge's client.
    session_id: watch::Sender<Option<String>>,
    conversation: Option<Conversation>,
}

/// What the session goes on to after the task's turn, with a bridge.
struct Conversation {
    from_client: mpsc::Receiver<FromClient>,
    /// How long the session waits for the client's next prompt.
    idle: Duration,
}

/// The client's next message, or `None` once it left; never without a
/// client.
async fn next_from_client(conversation: &mut Option<Conversation>) -> Option<FromClient> {
    match conversation {
        Some(talk) => talk.from_client.recv().await,
        None => std::future::pending().await,
    }
}

/// Why the session was stopped, as its result.
fn stopped(why: &Stop) -> (Outcome, String) {
    match why {
        Stop::Timeout => (Outcome::Timeout, "hit the timeout".to_owned()),
        Stop::Budget(m) => (Outcome::Budget, m.clone()),
    }
}

/// Waits until something decides to stop the session.
async fn wait_stop(stop: &mut watch::Receiver<Option<Stop>>) -> Option<Stop> {
    stop.wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|s| s.clone())
}

/// A `session/prompt` response still on its way.
type Turn<'a, F> = Pin<&'a mut F>;

/// A prompt marked as a budget notice, for the digest.
fn notice_prompt(sid: &SessionId, label: &str, text: String) -> PromptRequest {
    PromptRequest::new(
        sid.clone(),
        vec![ContentBlock::Text(TextContent::new(text))],
    )
    .meta(meta(json!({"notice": label})))
}

/// Asks the agent to stop its turn, and gives it a moment to answer the
/// prompt (with stopReason "cancelled"); permission requests are cancelled
/// meanwhile. The turn's answer, if it came.
async fn cancel_turn<F>(
    cx: &ConnectionTo<Agent>,
    sid: &SessionId,
    cancelling: &AtomicBool,
    turn: Turn<'_, F>,
) -> Option<F::Output>
where
    F: Future,
{
    cancelling.store(true, Ordering::Relaxed);
    let _ = cx.send_notification(CancelNotification::new(sid.clone()));
    let answer = tokio::time::timeout(CANCEL_GRACE, turn).await.ok();
    cancelling.store(false, Ordering::Relaxed);
    answer
}

/// initialize, session/new, then the task's prompt turn and what the
/// budget adds to it, all raced against the timeout and the budget.
async fn session(cx: ConnectionTo<Agent>, tap: &Tap, task: &Task<'_>, signals: Signals) -> Ended {
    let Signals {
        mut stop,
        mut nudges,
        cancelling,
        session_id,
        mut conversation,
    } = signals;
    let sid = tokio::select! {
        r = setup(&cx, task) => match r {
            Ok(sid) => sid,
            Err(ended) => return ended,
        },
        why = wait_stop(&mut stop) => {
            // No session to cancel yet: the process is killed on return.
            let Some(why) = why else {
                return Ended::failure(LOST_STOP_SIGNAL.to_owned());
            };
            tap.log(&[format!("⚠ {} (starting the session)", stopped(&why).1)]);
            return Ended::stopped(&why, false);
        }
    };
    // Nobody waits for it in a task run.
    let _ = session_id.send(Some(sid.to_string()));
    let request = PromptRequest::new(
        sid.clone(),
        vec![ContentBlock::Text(TextContent::new(task.prompt.to_owned()))],
    );
    let mut response = std::pin::pin!(cx.send_request(request).block_task());
    // Whether the client cancelled the task's turn: the session is then
    // the client's to go on with.
    let mut client_cancelled = false;
    let (why, text, window) = loop {
        tokio::select! {
            // In this order: a turn that has ended is not sent a notice,
            // which would start another.
            biased;
            // A task run ends with its turn; with a bridge, a turn that
            // ended well, or that the client cancelled, is followed by the
            // client's.
            r = &mut response => {
                cancelling.store(false, Ordering::Relaxed);
                let ended = prompt_result(r);
                let goes_on = ended.outcome == Outcome::Success
                    || (client_cancelled && ended.outcome == Outcome::Cancelled);
                let Some(talk) = conversation.take().filter(|_| goes_on) else {
                    return ended;
                };
                let link = Link { cx: &cx, tap, sid: &sid, cancelling: &cancelling, notices: task.notices };
                return match converse(&link, &mut stop, &mut nudges, talk).await {
                    Talked::Ended(ended) => ended,
                    Talked::HandBack { why, text, window } => {
                        hand_back(&link, &mut stop, &why, text, window).await
                    }
                };
            }
            why = wait_stop(&mut stop) => {
                return stop_turn(&cx, tap, &sid, &cancelling, why, response.as_mut()).await;
            }
            Some(nudge) = nudges.recv() => match nudge {
                // An agent that would end its turn for a prompt sent
                // during it goes without: it is still interrupted to hand
                // back.
                Nudge::Notice { .. } if !task.notices => {}
                // The others take it as a message for the model's next
                // step; its answer comes with the turn's, and one that
                // refuses it only goes without (the digest says).
                Nudge::Notice { label, text } => {
                    let answer = cx.send_request(notice_prompt(&sid, &label, text)).block_task();
                    tokio::spawn(async move {
                        let _ = answer.await;
                    });
                }
                Nudge::HandBack { why, text, window } => break (why, text, window),
            },
            // A client that attached during the task's turn is treated as
            // during its own turns.
            msg = next_from_client(&mut conversation) => match msg {
                Some(FromClient::Cancel) => {
                    client_cancelled = true;
                    cancelling.store(true, Ordering::Relaxed);
                    let _ = cx.send_notification(CancelNotification::new(sid.clone()));
                }
                Some(FromClient::Prompt { answer, .. }) => {
                    let _ = answer.send(Err(TURN_RUNNING.to_owned()));
                }
                // The task's turn goes on without it, and ends the session.
                None => {
                    tap.log(&[format!("⚠ {CLIENT_LEFT}: the task's turn goes on")]);
                    conversation = None;
                }
            },
        }
    };

    // Near a limit: a notice queued now may never be read (a subagent
    // task can outlast the run), so the turn is interrupted, and what is
    // left of the budget is a turn in which the agent hands back.
    tap.log(&[format!(
        "⚠ {}: interrupting the agent to hand back",
        stopped(&why).1
    )]);
    match cancel_turn(&cx, &sid, &cancelling, response.as_mut()).await {
        Some(r) => match prompt_result(r) {
            // It was done just then.
            ended if ended.outcome == Outcome::Success => return ended,
            ended if ended.outcome == Outcome::Cancelled => {}
            // An agent that answers a cancel with an error isn't asked
            // for more: the limit is still why the run ended.
            _ => return Ended::stopped(&why, false),
        },
        // It doesn't answer, so it can't be asked anything.
        None => return Ended::stopped(&why, false),
    }
    let link = Link {
        cx: &cx,
        tap,
        sid: &sid,
        cancelling: &cancelling,
        notices: task.notices,
    };
    hand_back(&link, &mut stop, &why, text, window).await
}

/// The agent's session, as the session's turns are sent to it.
struct Link<'a> {
    cx: &'a ConnectionTo<Agent>,
    tap: &'a Tap,
    sid: &'a SessionId,
    cancelling: &'a AtomicBool,
    notices: bool,
}

/// Near a limit, with no turn running: the agent's last turn, in which it
/// hands back.
async fn hand_back(
    link: &Link<'_>,
    stop: &mut watch::Receiver<Option<Stop>>,
    why: &Stop,
    text: String,
    window: Duration,
) -> Ended {
    let Link {
        cx,
        tap,
        sid,
        cancelling,
        ..
    } = *link;
    // The limit itself, reached while the turn was being cancelled.
    if stop.borrow().is_some() {
        return Ended::stopped(why, false);
    }
    let request = notice_prompt(sid, LABEL_HAND_BACK, text);
    let mut response = std::pin::pin!(cx.send_request(request).block_task());
    let answer = tokio::select! {
        r = &mut response => Some(r),
        _ = tokio::time::sleep(window) => None,
        _ = wait_stop(stop) => None,
    };
    let handed_back = match answer {
        Some(r) => prompt_result(r).outcome == Outcome::Success,
        None => {
            tap.log(&["⚠ the agent didn't hand back in time".to_owned()]);
            let _ = cancel_turn(cx, sid, cancelling, response.as_mut()).await;
            false
        }
    };
    Ended::stopped(why, handed_back)
}

/// How a conversation ended.
enum Talked {
    Ended(Ended),
    /// Near a limit: the agent is to hand back, no turn running.
    HandBack {
        why: Stop,
        text: String,
        window: Duration,
    },
}

/// Sends a client the answer to its prompt, once.
fn reply(
    answer: &mut Option<oneshot::Sender<Result<Value, String>>>,
    value: Result<Value, String>,
) {
    if let Some(answer) = answer.take() {
        // A client that went away is told nothing.
        let _ = answer.send(value);
    }
}

/// The session after the task's turn: the client's prompts, one turn at a
/// time, under the same limits, until the client leaves or sends none for
/// the idle timeout. A prompt sent during a turn is refused: the client
/// cancels the turn or waits for it.
async fn converse(
    link: &Link<'_>,
    stop: &mut watch::Receiver<Option<Stop>>,
    nudges: &mut mpsc::UnboundedReceiver<Nudge>,
    talk: Conversation,
) -> Talked {
    let Link {
        cx,
        tap,
        sid,
        cancelling,
        notices,
    } = *link;
    let Conversation {
        mut from_client,
        idle,
    } = talk;
    let stopped_by = |why: Option<Stop>| match why {
        Some(why) => {
            tap.log(&[format!("⚠ {}", stopped(&why).1)]);
            Ended::stopped(&why, false)
        }
        None => Ended::failure(LOST_STOP_SIGNAL.to_owned()),
    };
    tap.log(&[format!(
        "⇄ waiting for the client's prompt (up to {}s)",
        idle.as_secs()
    )]);
    let mut deadline = tokio::time::Instant::now() + idle;
    let mut last_failed = None;
    loop {
        let next = tokio::select! {
            biased;
            why = wait_stop(stop) => return Talked::Ended(stopped_by(why)),
            _ = tokio::time::sleep_until(deadline) => {
                return Talked::Ended(last_failed.unwrap_or_else(|| {
                    Ended::done(format!("no prompt from the client for {}s", idle.as_secs()))
                }));
            }
            Some(nudge) = nudges.recv() => match nudge {
                // A notice is for a turn, and none is running.
                Nudge::Notice { .. } => continue,
                Nudge::HandBack { why, text, window } => {
                    tap.log(&[format!("⚠ {}: asking the agent to hand back", stopped(&why).1)]);
                    return Talked::HandBack { why, text, window };
                }
            },
            next = from_client.recv() => next,
        };
        let (prompt, answer) = match next {
            None => {
                return Talked::Ended(
                    last_failed.unwrap_or_else(|| Ended::done(CLIENT_LEFT.to_owned())),
                );
            }
            // No turn to cancel.
            Some(FromClient::Cancel) => continue,
            Some(FromClient::Prompt { prompt, answer }) => (prompt, answer),
        };
        let mut answer = Some(answer);
        let blocks: Vec<ContentBlock> = match serde_json::from_value(prompt) {
            Ok(blocks) => blocks,
            Err(e) => {
                reply(
                    &mut answer,
                    Err(format!("the prompt is not a list of content blocks: {e}")),
                );
                continue;
            }
        };
        let request = PromptRequest::new(sid.clone(), blocks);
        let mut response = std::pin::pin!(cx.send_request(request).block_task());
        loop {
            tokio::select! {
                biased;
                r = &mut response => {
                    cancelling.store(false, Ordering::Relaxed);
                    let r: Result<PromptResponse, agent_client_protocol::Error> = r;
                    let value = r.as_ref().map_err(|e| e.to_string()).and_then(|resp| {
                        serde_json::to_value(resp).map_err(|e| e.to_string())
                    });
                    let ended = prompt_result(r);
                    last_failed = (ended.outcome != Outcome::Success).then_some(ended);
                    reply(&mut answer, value);
                    break;
                }
                why = wait_stop(stop) => {
                    let ended = stop_turn(cx, tap, sid, cancelling, why, response.as_mut()).await;
                    reply(&mut answer, Err(SESSION_ENDED.to_owned()));
                    return Talked::Ended(ended);
                }
                Some(nudge) = nudges.recv() => match nudge {
                    Nudge::Notice { .. } if !notices => {}
                    Nudge::Notice { label, text } => {
                        let answer = cx.send_request(notice_prompt(sid, &label, text)).block_task();
                        tokio::spawn(async move {
                            let _ = answer.await;
                        });
                    }
                    Nudge::HandBack { why, text, window } => {
                        tap.log(&[format!(
                            "⚠ {}: interrupting the agent to hand back",
                            stopped(&why).1
                        )]);
                        let r = cancel_turn(cx, sid, cancelling, response.as_mut()).await;
                        reply(&mut answer, Err(SESSION_ENDED.to_owned()));
                        return match r {
                            Some(Ok(_)) => Talked::HandBack { why, text, window },
                            _ => Talked::Ended(Ended::stopped(&why, false)),
                        };
                    }
                },
                msg = from_client.recv() => match msg {
                    // Permission requests are cancelled until the turn
                    // answers, as ACP asks of a client that cancelled.
                    Some(FromClient::Cancel) => {
                        cancelling.store(true, Ordering::Relaxed);
                        let _ = cx.send_notification(CancelNotification::new(sid.clone()));
                    }
                    Some(FromClient::Prompt { answer, .. }) => {
                        let _ = answer.send(Err(TURN_RUNNING.to_owned()));
                    }
                    None => {
                        tap.log(&[format!("⚠ {CLIENT_LEFT}: cancelling its turn")]);
                        // A turn that never answered neither finished nor
                        // stopped: it fails rather than passing as done.
                        let ended = match cancel_turn(cx, sid, cancelling, response.as_mut()).await {
                            Some(r) => prompt_result(r),
                            None => Ended::failure(format!("{CLIENT_LEFT}; {NO_CANCEL_ANSWER}")),
                        };
                        last_failed = (ended.outcome != Outcome::Success).then_some(ended);
                        return Talked::Ended(last_failed.unwrap_or_else(|| Ended::done(CLIENT_LEFT.to_owned())));
                    }
                },
            }
        }
        // Only an actual turn earns a fresh idle interval.
        deadline = tokio::time::Instant::now() + idle;
    }
}

/// Ends the turn at a limit. The caller then closes the connection and
/// kills the agent.
async fn stop_turn<F>(
    cx: &ConnectionTo<Agent>,
    tap: &Tap,
    sid: &SessionId,
    cancelling: &AtomicBool,
    why: Option<Stop>,
    turn: Turn<'_, F>,
) -> Ended
where
    F: Future<Output = Result<PromptResponse, agent_client_protocol::Error>>,
{
    let Some(why) = why else {
        return Ended::failure(LOST_STOP_SIGNAL.to_owned());
    };
    let (_, msg) = stopped(&why);
    tap.log(&[format!("⚠ {msg}")]);
    let answer = cancel_turn(cx, sid, cancelling, turn).await;
    match answer.map(prompt_result) {
        // The turn had ended before the cancel reached it: spending is
        // reported after the fact, so the reply that crossed the limit is
        // usually the last one, and what the agent finished stands.
        Some(ended) if ended.outcome == Outcome::Success => {
            let msg = format!("{msg}; the agent had already ended its turn");
            tap.log(&[format!("⚠ {msg}")]);
            Ended {
                message: Some(msg),
                ..ended
            }
        }
        _ => Ended::stopped(&why, false),
    }
}

/// initialize, session/new and the model: the session's id, or how it
/// failed.
async fn setup(cx: &ConnectionTo<Agent>, task: &Task<'_>) -> Result<SessionId, Ended> {
    let fail =
        |what: &str, e: agent_client_protocol::Error| Ended::failure(format!("{what} failed: {e}"));
    // fs and terminal are left unadvertised (the defaults), so agents use
    // their own tools inside the sandbox; ACP v2 drops them anyway.
    let init = InitializeRequest::new(ProtocolVersion::V1)
        .client_info(Implementation::new(CLIENT_NAME, env!("CARGO_PKG_VERSION")));
    cx.send_request(init)
        .block_task()
        .await
        .map_err(|e| fail("initialize", e))?;
    let new = cx
        .send_request(NewSessionRequest::new(task.cwd))
        .block_task()
        .await
        .map_err(|e| fail("session/new", e))?;
    let sid = new.session_id;
    // Where the agent has no environment variable for it, the model is a
    // session config option.
    if let (Some(model), false) = (task.model, task.model_by_env) {
        let option = new
            .config_options
            .iter()
            .flatten()
            .find(|o| o.category == Some(SessionConfigOptionCategory::Model))
            .ok_or_else(|| {
                Ended::failure(format!(
                    "the agent has no model option to select {model} with"
                ))
            })?;
        let req = SetSessionConfigOptionRequest::new(sid.clone(), option.id.clone(), model);
        cx.send_request(req)
            .block_task()
            .await
            .map_err(|e| fail(&format!("selecting model {model}"), e))?;
    }
    for (id, value) in task.config_options {
        let req = SetSessionConfigOptionRequest::new(sid.clone(), id.clone(), value.as_str());
        cx.send_request(req)
            .block_task()
            .await
            .map_err(|e| fail(&format!("setting {id} to {value}"), e))?;
    }
    Ok(sid)
}

fn prompt_result(r: Result<PromptResponse, agent_client_protocol::Error>) -> Ended {
    match r {
        Err(e) => Ended::failure(format!("session/prompt failed: {e}")),
        Ok(resp) => {
            let reason = serde_json::to_value(resp.stop_reason)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned));
            let outcome = match reason.as_deref() {
                Some("end_turn") => Outcome::Success,
                Some("cancelled") => Outcome::Cancelled,
                // The agent's own turn limit.
                Some("max_turn_requests") => Outcome::Budget,
                _ => Outcome::Failure,
            };
            let message = (outcome != Outcome::Success)
                .then(|| format!("the agent stopped: {}", reason.as_deref().unwrap_or("?")));
            Ended {
                outcome,
                stop_reason: reason,
                message,
                handed_back: false,
            }
        }
    }
}
