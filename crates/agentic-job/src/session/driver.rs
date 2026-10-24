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
//! A task's turn that ends on an error while the agent runs (a model
//! request the provider refused, usually, after the agent's own retries)
//! is not the end of the task: after a pause, the agent gets the same
//! turn to hand back in, and the run ends at a limit if it did, or as a
//! failure naming the error if it didn't (`after_error`).
//!
//! With a bridge (`bridge`), the session does not end with the task's
//! turn: it waits for its client's prompts, each a turn of its own under
//! the same limits, until the client leaves or sends none for the idle
//! timeout (`conversation`).
//!
//! A task run whose turn ends well without the output the run requires
//! (`Options::output`) is not done either: the agent gets one reminder
//! turn, and the run fails if it still left none (`remind`).
//!
//! An agent whose context is compacted during the task's turn may lose
//! what it was doing and where it hands back: agents have ended their
//! turn after one with nothing handed back (#607, #813). Where the run
//! asks for it (`Options::restate`), an agent that takes notices is sent
//! one after each compaction the transcript sees, restating its task, its
//! hand-back and what its own checkpoint says is left.
//!
//! With a watch of the run's item (`Options::watch`, `steer`), what changes
//! there is sent into whatever turn is running, by `_session/steering` to
//! an agent that takes it and otherwise as a notice is; never as a prompt
//! that would end the turn, and never to start one.
//!
//! An agent whose entry has a `stall-timeout` (`AgentSpec::stall_timeout`)
//! and sends nothing for that long during the task's turn, with no tool
//! call of its running, is taken to be stuck in a model request that will
//! not end soon: Vibe has waited minutes on idle connections, with no
//! timeout of its own, and runs ended there on the job's timeout. The turn
//! is cancelled and the task sent again, once, on the same session, so the
//! work so far is kept; a second stall fails the run, saying so (`Stalls`).
//!
//! A task's turn that ends on a model provider's failure a wait may clear
//! (`provider::Class`: rate-limited, overloaded or unreachable, by the
//! words of the error the agent answers with or says, or by the entry's
//! `rate-limit-code`, `AgentSpec::rate_limit_code`) is not given up on
//! at once. Runs have ended there although a minute's wait would likely
//! have cleared the limit (#1339). The session waits, longer each time
//! and with some jitter, or as long as the provider said to, and sends
//! the task again on the same session, a few times (`PROVIDER_RETRIES`,
//! for a few minutes when it was overloaded: `OVERLOAD_RETRIES`), before
//! the turn is taken as one that ended on an error. An overload that
//! outlasts its waits has the agent switched, once, to the run's fallback
//! model if it names one (`Options::fallback_model`), through its model
//! session config option, so that it keeps its context, and the task sent
//! again on it, the waits starting over. A usage limit
//! or a refused credential is not waited on: nothing within the run
//! clears them. The waits take from the run's time like any other, and a
//! limit reached in one stops the run as ever. The class of the failure
//! the run ended on is in its result (`RunResult::provider_error`), for
//! the run's summary and its caller.
//!
//! When the session ends, the process group started for the agent is
//! killed, and then every process of the sandbox user (`process`): the
//! agent runs in a login session of that user's, where a signal to the
//! group does not reach.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agent_client_protocol::schema::ProtocolVersion;
use agent_client_protocol::schema::v1::{
    CancelNotification, ContentBlock, HttpHeader, Implementation, InitializeRequest, McpServer,
    McpServerHttp, NewSessionRequest, PromptRequest, PromptResponse, RequestPermissionOutcome,
    RequestPermissionRequest, RequestPermissionResponse, SelectedPermissionOutcome,
    SessionConfigId, SessionConfigKind, SessionConfigOption, SessionConfigOptionCategory,
    SessionId, SetSessionConfigOptionRequest, StopReason, TextContent,
};
use agent_client_protocol::{
    Agent, Client, ConnectionTo, Dispatch, Handled, Lines, UntypedMessage,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot, watch};

use super::agents::AgentSpec;
use super::bridge::{Bridge, FromClient};
use super::budget::{
    Budget, LABEL_COMPACTION, LABEL_HAND_BACK, LABEL_PROVIDER_ERROR, LABEL_RATE_LIMITED,
    LABEL_REMINDER, LABEL_STALLED, Limits, Signal, Stop, Usage, hand_back_text,
};
use super::clients::Clients;
use super::digest::{self, Dir};
use super::permission::{self, Policy, Request, pick_option};
use super::process::{self, Launch};
use super::provider::{self, Class};
use super::steer::{self, Seen, Watch};
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
const REFUSED: &str = "the model provider refused the agent's request";
const HANDING_BACK: &str = "the task's turn ended on an error: the agent is to hand back";
/// How long the session waits after a turn that ended on an error before
/// asking the agent to hand back: a rate limit that refused the request
/// may have cleared by then. Never longer than the hand-back window, so
/// a short run is not held up for it.
const ERROR_PAUSE: Duration = Duration::from_secs(60);
/// What the agent is told once when it ended its task's turn without the
/// output the run requires. It names no output type, not even `noop`:
/// which ones the run allows is the brief's to say.
const REMINDER: &str = "You ended your turn without the output this run requires. Hand it back \
                        now, as the brief at the start of the task says; if there is nothing to \
                        hand back, say why in a request the brief allows.";
const NO_OUTPUT: &str = "the agent ended its turn without the output the run requires, even \
                         after a reminder";
/// What a run that failed on a stalled turn says first, which tells it
/// from a run whose agent failed by itself.
pub const STALLED: &str = "the agent stalled";
/// What the agent is told ahead of its task, sent again after its turn
/// stalled.
const STALLED_NOTE: &str = "Your previous turn was cancelled because nothing came from you for \
                            too long, as when a model request hangs. The task follows again. \
                            What you did so far is still in this session and the working \
                            directory: check where you were and carry on from there, without \
                            redoing finished work.";
/// What the agent is told ahead of its task, sent again after the
/// provider rate-limited its turn.
const RATE_LIMITED_NOTE: &str = "Your previous turn ended because the model provider rate-limited \
                                 a request; it has been waited out. The task follows again. What \
                                 you did so far is still in this session and the working \
                                 directory: check where you were and carry on from there, \
                                 without redoing finished work.";
/// The same, after a model request failed at the provider in another way
/// a wait may clear (overloaded, unreachable).
const PROVIDER_ERROR_NOTE: &str = "Your previous turn ended because a model request failed at \
                                   the provider (overloaded or unreachable); it has been waited \
                                   out. The task follows again. What you did so far is still in \
                                   this session and the working directory: check where you were \
                                   and carry on from there, without redoing finished work.";
/// How many times a task's turn that ended on a provider's failure a wait
/// may clear is sent again. With the waits below, about a minute in all
/// is spent on it, and a minute more pausing before the hand-back
/// (`ERROR_PAUSE`): a limit on requests per minute has cleared by then,
/// one that has not is unlikely to soon, and the agent should hand back
/// while it has time to.
const PROVIDER_RETRIES: u32 = 3;
/// The same for an overloaded provider (Anthropic's 529), which is not
/// refusing the run but out of capacity for a while: two runs worked 45
/// minutes and then lost their change to a few minutes of it (#1860).
/// With the waits capped at `MAX_RETRY_WAIT`, about four minutes in all
/// (10, 20, 40, 60, 60 and 60 s), still within the run's time: near a
/// limit the agent hands back instead of waiting on.
const OVERLOAD_RETRIES: u32 = 6;
/// The wait before the first time it is sent again, doubled for each
/// next one (10, 20 and 40 s) plus jitter (`provider::jittered`), and
/// never longer than the hand-back window, so that a short run is not
/// held up for it.
const RETRY_WAIT: Duration = Duration::from_secs(10);
/// The longest of those waits, before jitter.
const MAX_RETRY_WAIT: Duration = Duration::from_secs(60);
/// How long the agent gets to switch to the fallback model: a session
/// config option is set at once, and the run's limits go unwatched
/// meanwhile.
const MODEL_SWITCH_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest `retry-after` of the provider's own that is waited for in
/// place of the computed wait: one that asks for longer is not waited
/// on at all, and the agent hands back instead, as after a failure no
/// wait clears.
const RETRY_AFTER_CAP: Duration = Duration::from_secs(120);

/// Why the agent has not left the output its run requires; `None` when done. It runs
/// commands (as the sandbox user), so it is called off the runtime, and
/// starts none once its flag is set: the session sets it when it stops
/// waiting for the check, before it stops what the sandbox user runs.
pub type OutputCheck = Arc<dyn Fn(&AtomicBool) -> Option<String> + Send + Sync>;
/// What the agent is told after a compaction of its context; `None` for
/// nothing. It runs as an [`OutputCheck`] does, and reads the agent's
/// files the same way.
pub type Restate = OutputCheck;

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

/// What the message of a run its model provider stopped starts with
/// ([`RunResult::stopped_by_provider`]).
pub const PROVIDER_STOPPED: &str = "the model provider stopped the run";

/// `harness.json`: how the session went, for the run's summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// The agent ended its task's turn without the output the run
    /// requires, and was reminded once.
    #[serde(default)]
    pub reminded: bool,
    /// How many times the task's turn stalled (`AgentSpec::stall_timeout`),
    /// and how many times it was sent again after one.
    #[serde(default)]
    pub stalls: u32,
    #[serde(default)]
    pub stall_retries: u32,
    /// The model provider's failure the run ended on, by class
    /// (`provider::Class`); none when it ended on nothing of the kind,
    /// `other` for an error whose words fit no class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_error: Option<Class>,
    /// How many times the task's turn was sent again after a provider's
    /// failure a wait may clear, and the seconds spent waiting for them,
    /// a wait a limit then interrupted included.
    #[serde(default)]
    pub resends: u32,
    #[serde(default)]
    pub resend_wait_s: u64,
    /// The model the agent was switched to when its provider stayed
    /// overloaded (`Options::fallback_model`), as the agent named it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_model: Option<String>,
}

impl RunResult {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(RESULT_FILE);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// The result of a session that [`run`] did not return one for, but
    /// failed with ERROR: a failure that says why, with no command or
    /// hand-back of its own.
    pub fn internal_error(
        agent: String,
        limits: Limits,
        error: &anyhow::Error,
        started: chrono::DateTime<chrono::Utc>,
        finished: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            schema: RESULT_SCHEMA.to_owned(),
            agent,
            command: Vec::new(),
            result: Outcome::Failure,
            stop_reason: None,
            message: Some(digest::cut(&format!("internal error: {error:#}"))),
            started_at: rfc3339(started),
            finished_at: rfc3339(finished),
            duration_s: (finished - started).num_seconds().max(0).unsigned_abs(),
            limits,
            handed_back: false,
            reminded: false,
            stalls: 0,
            stall_retries: 0,
            provider_error: None,
            resends: 0,
            resend_wait_s: 0,
            fallback_model: None,
        }
    }

    /// Whether the run failed because its task's turn stalled, rather than
    /// by anything the agent did.
    pub fn failed_stalled(&self) -> bool {
        self.result == Outcome::Failure
            && self
                .message
                .as_deref()
                .is_some_and(|m| m.starts_with(STALLED))
    }

    /// For a run that failed on a model provider's failure of a known
    /// class, after which its agent could not hand back (as when the
    /// provider is down, and handing back needs it too): the run stopped
    /// there, as a run is at a limit, so that its working tree is handed
    /// back as a partial change rather than lost (#1860). The agent's word
    /// is never needed to keep its change. `None` for any other result,
    /// one the agent's own failure (`other`) ended included. The message
    /// leaves out the error's words, which go into the pull request: they
    /// may name the gateway, a redacted string a patch must not hold, and
    /// the transcript has them.
    pub fn stopped_by_provider(&self) -> Option<Self> {
        let class = self.provider_error.filter(|class| class.kind().is_some())?;
        if self.result != Outcome::Failure {
            return None;
        }
        Some(Self {
            result: Outcome::Budget,
            message: Some(format!(
                "{PROVIDER_STOPPED}: the provider {}, and the agent could not hand back",
                class.describe()
            )),
            handed_back: false,
            ..self.clone()
        })
    }

    /// Whether the run is one [`Self::stopped_by_provider`] made.
    pub fn provider_stopped(&self) -> bool {
        self.result == Outcome::Budget
            && self
                .message
                .as_deref()
                .is_some_and(|m| m.starts_with(PROVIDER_STOPPED))
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
    /// From the watch of the run's item.
    Item(Seen),
}

/// An MCP server the session gives the agent in `session/new`, over
/// streamable HTTP: its name, its URL and the headers that go with every
/// request to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMcp {
    pub name: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
}

/// One session: which agent, on what, within which limits.
pub struct Options {
    /// The agent's name, for the record.
    pub name: String,
    pub agent: AgentSpec,
    /// The model (default: the agent's own).
    pub model: Option<String>,
    /// The model the agent is switched to when its provider stays
    /// overloaded past the waits: none to have it hand back instead.
    pub fallback_model: Option<String>,
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
    /// too); `None` means accounting is unavailable and stops a session
    /// with a request cap. Initialize it with a known count for capped runs.
    /// `Limits::max_requests`
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
    /// Whether the agent has left the output the run requires; none for a
    /// run that requires none. A task's turn that ends well without it
    /// earns one reminder turn, and fails the run if that does not help:
    /// an agent that answers `end_turn` having forgotten its output (as
    /// after a compaction of its context) would otherwise pass for done.
    pub output: Option<OutputCheck>,
    /// What the agent is told after each compaction of its context during
    /// the task's turn, if it takes notices; none to tell it nothing.
    pub restate: Option<Restate>,
    /// The MCP servers the agent is given, which it must take over HTTP;
    /// none for a run without.
    pub mcp_servers: Vec<HttpMcp>,
    /// The run's item, whose new comments and body edits the agent is
    /// sent while it works; none to watch nothing.
    pub watch: Option<Watch>,
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
            repeats: tap.repeats(),
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
        fallback_model,
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
        output,
        restate,
        mcp_servers,
        watch,
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
        Launch::Direct | Launch::Own { .. } => None,
    };
    // Listening before the agent starts: a client may come during the
    // task's turn.
    let (session_id, attach_to) = watch::channel(None);
    let (conversation, hang_up) = match bridge {
        Some(bridge) => {
            let connected = bridge.start(attach_to)?;
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
        spec.provider_error.clone(),
    )?);
    let (argv, env) = spec.command(launch.wrapper(), model.as_deref());
    let task = Task {
        cwd: &cwd,
        model: model.as_deref(),
        model_by_env: spec.model_env.is_some(),
        fallback_model: fallback_model.as_deref(),
        config_options: &config_options,
        prompt: &prompt,
        notices: spec.notices,
        steering: spec.steering,
        hand_back_window: Budget::new(limits.clone()).hand_back_window(),
        stall: spec.stall_timeout.map(Duration::from_secs),
        rate_limit_code: spec.rate_limit_code,
        output,
        restate: restate.filter(|_| spec.notices),
        mcp_servers: &mcp_servers,
    };
    let started = chrono::Utc::now();
    let stalls = Arc::new(Stalls::default());
    let resends = Arc::new(Resends::default());
    let (nudge_tx, nudge_rx) = mpsc::unbounded_channel();
    let item_watcher = watch.map(|watch| {
        let nudges = nudge_tx.clone();
        tokio::spawn(steer::watch(watch, move |seen| {
            nudges.send(Nudge::Item(seen)).is_ok()
        }))
    });
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
                after_error: Arc::default(),
                conversation,
                stalls: stalls.clone(),
                resends: resends.clone(),
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
                Some(status) => {
                    ended.agent_exited(status, tap.last_stderr(), tap.provider_failure())
                }
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
    if let Some(item_watcher) = item_watcher {
        item_watcher.abort();
    }
    let revoked = match hang_up {
        Some(hang_up) => hang_up.close().await,
        None => Ok(()),
    };
    let reaped = reaped.and(revoked);
    let finished = chrono::Utc::now();

    let Ended {
        mut outcome,
        mut stop_reason,
        mut message,
        handed_back,
        reminded,
        mut class,
        ..
    } = ended;
    let transcript = tap.finish();
    if stop_reason.is_none() {
        stop_reason = transcript.stop_reason;
    }
    // The run failed of that, not of the provider: nor is its working
    // tree handed back as if the provider had stopped it.
    if let Some(e) = transcript.write_error {
        outcome = Outcome::Failure;
        message = Some(e);
        class = None;
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
        reminded,
        stalls: stalls.seen.load(Ordering::Relaxed),
        stall_retries: stalls.retried.load(Ordering::Relaxed),
        // A run that ended well got past the provider's failure.
        provider_error: class.filter(|_| outcome != Outcome::Success),
        resends: resends.count.load(Ordering::Relaxed),
        resend_wait_s: resends.waited_ms.load(Ordering::Relaxed) / 1000,
        fallback_model: resends
            .fallback
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take(),
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
    /// `Options::fallback_model`.
    fallback_model: Option<&'a str>,
    config_options: &'a [(String, String)],
    prompt: &'a str,
    /// The agent takes a prompt sent during a turn (`AgentSpec::notices`).
    notices: bool,
    /// The agent takes `_session/steering` (`AgentSpec::steering`).
    steering: bool,
    /// How long the agent gets to hand back after its turn ended on an
    /// error: as long as near a limit.
    hand_back_window: Duration,
    /// `AgentSpec::stall_timeout`.
    stall: Option<Duration>,
    /// `AgentSpec::rate_limit_code`.
    rate_limit_code: Option<i32>,
    output: Option<OutputCheck>,
    /// `Options::restate`, for an agent that takes notices.
    restate: Option<Restate>,
    mcp_servers: &'a [HttpMcp],
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
    let after = signals.after_error.clone();
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
    // The error a failed turn ended on, while the agent is to hand back
    // after it: what the run fails with if the agent doesn't.
    let pending = || after.lock().unwrap_or_else(|e| e.into_inner()).take();
    // An error is the transport's: usually the agent closed its streams,
    // after the error it was to hand back after, if any.
    let transport_failed = |e: agent_client_protocol::Error| {
        let failed = format!("the agent failed: {e}");
        match pending() {
            Some(Pending { error, class }) => Ended {
                class,
                ..Ended::failure(format!("{error}; then {failed}"))
            },
            None => Ended::failure(failed),
        }
    };
    // The agent exiting ends the session, whatever it was waiting for.
    let ended = tokio::select! {
        r = &mut connection => r.unwrap_or_else(transport_failed),
        // Its last answer may still be on its way in: an agent that
        // answers its turn and exits has not failed.
        _ = agent.wait() => match tokio::time::timeout(EXIT_GRACE, &mut connection).await {
            Ok(r) => r.unwrap_or_else(transport_failed),
            // One that exits while it is to hand back after an error
            // failed with that error.
            Err(_) => match pending() {
                Some(Pending { error, class }) => Ended { class, ..Ended::failure(error) },
                None => Ended::failure(AGENT_EXITED.to_owned()),
            },
        },
    };
    // A failure is usually the agent having died, and its exit status and
    // last words say more than the request that happened to be waiting.
    // Not so for an agent that answered its reminder: the session failed
    // it, and it exits only because its standard input closed.
    // Nor for a stalled one, which is alive and only stuck.
    let answered_reminder = ended.reminded && ended.stop_reason.is_some();
    let stalled = ended
        .message
        .as_deref()
        .is_some_and(|m| m.starts_with(STALLED));
    let exited = match ended.outcome {
        Outcome::Failure if !answered_reminder && !stalled => {
            tokio::time::timeout(EXIT_GRACE, agent.wait())
                .await
                .ok()
                .and_then(Result::ok)
        }
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
    /// The agent answered its turn with an error, or said the provider
    /// refused its request: it may still be able to hand back.
    errored: bool,
    /// The agent was reminded of the output the run requires.
    reminded: bool,
    /// The model provider's failure the turn ended on, by class; none
    /// when it ended on nothing of the kind.
    class: Option<Class>,
}

impl Ended {
    fn failure(message: String) -> Self {
        Ended {
            outcome: Outcome::Failure,
            stop_reason: None,
            message: Some(message),
            handed_back: false,
            errored: false,
            reminded: false,
            class: None,
        }
    }

    /// The same, ended on a provider's failure of CLASS, where one is
    /// known.
    fn with_class(self, class: Option<Class>) -> Self {
        Ended {
            class: class.or(self.class),
            ..self
        }
    }

    /// The failure of an agent that exited on its own with STATUS: that,
    /// the provider's failure it died of, the last it said on its
    /// standard error, and the request that was waiting. The provider's
    /// failure comes first: an adapter that crashes after the provider
    /// refused it (claude-agent-acp 0.88.0 on a 429 burst) died of the
    /// refusal, and its last line says only how. The failure is the one
    /// the turn ended on where it ended on one; only an agent that died
    /// mid-turn is taken at the words it let out in that turn (PROVIDER),
    /// which its own log may use for other things.
    fn agent_exited(
        self,
        status: ExitStatus,
        last_words: Option<String>,
        provider: Option<(Class, String)>,
    ) -> Self {
        // A transport that closed under the agent's death is an error
        // too, of no class: the words count then.
        let turn = self.class.filter(|class| *class != Class::Other);
        let said = match turn {
            Some(_) => None,
            None => provider.filter(|(class, _)| *class != Class::Other),
        };
        let class = turn
            .or(said.as_ref().map(|(class, _)| *class))
            .or(self.class);
        let of = match (class, said) {
            (Some(class), Some((_, said))) if class != Class::Other => {
                format!(" after the provider {} ({said})", class.describe())
            }
            (Some(class), None) if class != Class::Other => {
                format!(" after the provider {}", class.describe())
            }
            _ => String::new(),
        };
        let last_words = last_words
            .map(|line| format!(": {line}"))
            .unwrap_or_default();
        let request = self
            .message
            .filter(|m| m != AGENT_EXITED)
            .map(|m| format!(" ({m})"))
            .unwrap_or_default();
        Ended {
            class,
            ..Ended::failure(format!(
                "{AGENT_EXITED} ({status}){of}{last_words}{request}"
            ))
        }
    }

    /// A conversation that ended as it may: the client left, or went
    /// quiet.
    fn done(message: String) -> Self {
        Ended {
            outcome: Outcome::Success,
            stop_reason: None,
            message: Some(message),
            handed_back: false,
            errored: false,
            reminded: false,
            class: None,
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
            errored: false,
            reminded: false,
            class: None,
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
    /// The error the task's turn ended on, while the agent is to hand
    /// back after it, or the task is to be sent again (`after_error`).
    after_error: Arc<Mutex<Option<Pending>>>,
    conversation: Option<Conversation>,
    stalls: Arc<Stalls>,
    resends: Arc<Resends>,
}

/// The error the task's turn ended on, kept while the session waits:
/// what an agent that exits meanwhile failed with.
#[derive(Debug, Clone)]
struct Pending {
    error: String,
    class: Option<Class>,
}

/// The stalls of the task's turn, for the run's result.
#[derive(Default)]
struct Stalls {
    seen: AtomicU32,
    /// The times the task was sent again after one: no more than once.
    retried: AtomicU32,
}

/// The times the task was sent again after a provider's failure, the
/// waits before them, and the model the agent was switched to after
/// them, for the run's result.
#[derive(Default)]
struct Resends {
    count: AtomicU32,
    waited_ms: AtomicU64,
    fallback: Mutex<Option<String>>,
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

/// The task's prompt sent again after its turn stalled or was
/// rate-limited, behind a NOTE that says why.
fn task_again(sid: &SessionId, note: &str, label: &str, task: &str) -> PromptRequest {
    PromptRequest::new(
        sid.clone(),
        vec![
            ContentBlock::Text(TextContent::new(note.to_owned())),
            ContentBlock::Text(TextContent::new(task.to_owned())),
        ],
    )
    .meta(meta(json!({"notice": label})))
}

/// Whether the agent answered a turn with its rate-limit error (CODE,
/// `AgentSpec::rate_limit_code`): that, whatever its words.
fn rate_limited(
    r: &Result<PromptResponse, agent_client_protocol::Error>,
    code: Option<i32>,
) -> bool {
    matches!(r, Err(e) if Some(i32::from(e.code)) == code)
}

/// The model provider's failure the task's turn ended on, if one: by
/// class, with the error as the result says it. An error the agent
/// answered the turn with is classified by its words (and its data: the
/// Claude adapter's `errorKind`), unless its code is the agent's
/// rate-limit code; a turn answered as done after the agent said the
/// provider refused (`Tap::refusal`) by what it said. Anything else ended
/// on no failure of the provider's.
fn provider_failure(
    r: &Result<PromptResponse, agent_client_protocol::Error>,
    code: Option<i32>,
    tap: &Tap,
) -> Option<(Class, String)> {
    match r {
        Err(e) => {
            let class = if rate_limited(r, code) {
                Class::RateLimited
            } else {
                provider::classify(&e.to_string())
            };
            Some((class, format!("session/prompt failed: {e}")))
        }
        Ok(resp) => {
            let said = tap
                .refusal()
                .filter(|_| resp.stop_reason == StopReason::EndTurn)?;
            Some((provider::classify(&said), format!("{REFUSED}: {said}")))
        }
    }
}

/// The wait before the task is sent again after its turn ended on a
/// provider's failure, for the time numbered RETRIED (from 0): doubling
/// from `RETRY_WAIT`, or what the provider said (RETRY_AFTER), with
/// jitter, and never past the hand-back WINDOW. `None` for a provider
/// that asks for more than `RETRY_AFTER_CAP`: not worth the run's time.
fn backoff(retried: u32, window: Duration, retry_after: Option<Duration>) -> Option<Duration> {
    let wait = match retry_after {
        Some(after) if after > RETRY_AFTER_CAP => return None,
        Some(after) => after,
        None => RETRY_WAIT
            .saturating_mul(2u32.saturating_pow(retried))
            .min(MAX_RETRY_WAIT),
    };
    Some(provider::jittered(wait).min(window))
}

/// How many times in all the task is sent again after a provider's
/// failure, when the last was of CLASS.
fn retries(class: Class) -> u32 {
    match class {
        Class::Overloaded => OVERLOAD_RETRIES,
        _ => PROVIDER_RETRIES,
    }
}

/// Waits until UNTIL, or forever without one.
async fn quiet(until: Option<tokio::time::Instant>) {
    match until {
        Some(until) => tokio::time::sleep_until(until).await,
        None => std::future::pending().await,
    }
}

/// What ends the task's turn as the session waits on it.
enum Next<R> {
    /// The turn's answer, and the class of the provider's failure it is,
    /// if one.
    Answered(R, Option<Class>),
    /// Near a limit: the agent is to hand back.
    HandBack(Stop, String, Duration),
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
        after_error: pending_error,
        mut conversation,
        stalls,
        resends,
    } = signals;
    let (sid, model_option) = tokio::select! {
        r = setup(&cx, task) => match r {
            Ok(started) => started,
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
    let mut compacted = tap.compactions();
    // The restatements read after compactions, and what stops the reading
    // once the task's turn is over.
    let (restated_tx, mut restated) = mpsc::unbounded_channel::<String>();
    let restating = Abandon(Arc::default());
    let link = Link {
        cx: &cx,
        tap,
        sid: &sid,
        cancelling: &cancelling,
        notices: task.notices,
        steering: task.steering,
    };
    // Until when the agent may send nothing before its turn is taken for
    // stalled; none without a stall timeout.
    let mut heard = tap.heard();
    let quiet_for = |limit: Duration| tokio::time::Instant::now() + limit;
    let mut quiet_until = task.stall.map(quiet_for);
    // The times the task was sent again after a provider's failure, since
    // the session started or switched to the fallback model, and whether
    // it tried to.
    let mut resent = 0;
    let mut switch_tried = false;
    let next = loop {
        tokio::select! {
            // In this order: a turn that has ended is not sent a notice,
            // which would start another.
            biased;
            r = &mut response => {
                // A provider's failure a wait may clear has the task sent
                // again, a few times; a turn the client cancelled is the
                // client's to go on from.
                let failed = provider_failure(&r, task.rate_limit_code, tap);
                let class = failed.as_ref().map(|(class, _)| *class);
                // An overload that outlasted its waits has the agent
                // switched to the fallback model, once, and the task sent
                // again on it at once, the waits starting over. One the
                // agent cannot switch to leaves the turn ended on the error.
                if let (Some((Class::Overloaded, error)), Some(fallback)) = (&failed, task.fallback_model)
                    && !client_cancelled
                    && !switch_tried
                    && resent >= retries(Class::Overloaded)
                {
                    switch_tried = true;
                    match switch_model(&cx, &sid, model_option.as_ref(), fallback).await {
                        Ok(current) => {
                            tap.log(&[digest::cut(&format!(
                                "⚠ {error}: the provider stayed overloaded; switched the agent to model {current}, sending the task again"
                            ))]);
                            *resends.fallback.lock().unwrap_or_else(|e| e.into_inner()) = Some(current);
                            resends.count.fetch_add(1, Ordering::Relaxed);
                            resent = 0;
                            response.set(cx.send_request(task_again(&sid, PROVIDER_ERROR_NOTE, LABEL_PROVIDER_ERROR, task.prompt)).block_task());
                            quiet_until = task.stall.map(quiet_for);
                            continue;
                        }
                        Err(why) => tap.log(&[digest::cut(&format!(
                            "⚠ the agent could not be switched to the fallback model {fallback}: {why}"
                        ))]),
                    }
                }
                let again = failed.filter(|(class, _)| {
                    class.transient() && !client_cancelled && resent < retries(*class)
                });
                let Some((class, error)) = again else {
                    break Next::Answered(r, class);
                };
                let retry_after = provider::retry_after(&error);
                let Some(wait) = backoff(resent, task.hand_back_window, retry_after) else {
                    tap.log(&[digest::cut(&format!(
                        "⚠ {error}: the provider asks for a wait of {}s, more than the {}s waited for: not sending the task again",
                        retry_after.unwrap_or_default().as_secs(),
                        RETRY_AFTER_CAP.as_secs()
                    ))]);
                    break Next::Answered(r, Some(class));
                };
                resent += 1;
                tap.log(&[digest::cut(&format!(
                    "⚠ {error}: the provider {}; sending the task again in {}s ({resent} of {})",
                    class.describe(),
                    wait.as_secs(),
                    retries(class)
                ))]);
                // An agent that exits meanwhile failed with the error.
                *pending_error.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(Pending { error: error.clone(), class: Some(class) });
                let waited = Instant::now();
                let interrupted = provider_wait(&link, &mut stop, &mut nudges, wait, &error, class).await;
                // What was waited, whether or not the task was then sent.
                resends.waited_ms.fetch_add(
                    u64::try_from(waited.elapsed().as_millis()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
                if let Some(ended) = interrupted {
                    return ended;
                }
                resends.count.fetch_add(1, Ordering::Relaxed);
                pending_error.lock().unwrap_or_else(|e| e.into_inner()).take();
                let (note, label) = if class == Class::RateLimited {
                    (RATE_LIMITED_NOTE, LABEL_RATE_LIMITED)
                } else {
                    (PROVIDER_ERROR_NOTE, LABEL_PROVIDER_ERROR)
                };
                response.set(cx.send_request(task_again(&sid, note, label, task.prompt)).block_task());
                // The wait was no stall.
                quiet_until = task.stall.map(quiet_for);
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
                Nudge::HandBack { why, text, window } => break Next::HandBack(why, text, window),
                Nudge::Item(seen) => from_item(&link, seen, true),
            },
            // What to restate is read off this loop, which goes on
            // meanwhile: the turn may end, or a limit come, while the
            // checkpoint is read, and then nothing is sent.
            Ok(()) = compacted.changed(), if task.restate.is_some() => {
                if let Some(restate) = task.restate.clone() {
                    let (tx, stopped) = (restated_tx.clone(), restating.0.clone());
                    tokio::task::spawn_blocking(move || {
                        if let Some(text) = restate(&stopped) {
                            let _ = tx.send(text);
                        }
                    });
                }
            }
            // Queued as a notice is.
            Some(text) = restated.recv() => {
                tap.log(&["⚠ the agent's context was compacted: restating its task".to_owned()]);
                let answer = cx.send_request(notice_prompt(&sid, LABEL_COMPACTION, text)).block_task();
                tokio::spawn(async move {
                    let _ = answer.await;
                });
            }
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
            Ok(()) = heard.changed(), if quiet_until.is_some() => {
                quiet_until = task.stall.map(quiet_for);
            }
            () = quiet(quiet_until) => {
                let Some(limit) = task.stall else { continue };
                quiet_until = Some(quiet_for(limit));
                // A tool may run for longer than the limit, and only the
                // model is waited for here; nor is a turn the client is
                // cancelling taken for stalled.
                if tap.tool_running() || cancelling.load(Ordering::Relaxed) {
                    continue;
                }
                let first = stalls.seen.fetch_add(1, Ordering::Relaxed) == 0;
                let silent = format!("{STALLED}: nothing from it for {}s in its turn", limit.as_secs());
                tap.log(&[format!(
                    "⚠ {silent}: {}",
                    if first { "cancelling it to send the task again" } else { "cancelling it" }
                )]);
                let answer = cancel_turn(&cx, &sid, &cancelling, response.as_mut()).await;
                match answer {
                    // The turn ended by itself as the cancel went: that
                    // answer stands.
                    Some(r) if !matches!(&r, Ok(resp) if resp.stop_reason == StopReason::Cancelled) => {
                        break Next::Answered(r, None);
                    }
                    Some(_) if first => {
                        stalls.retried.fetch_add(1, Ordering::Relaxed);
                        let again = task_again(&sid, STALLED_NOTE, LABEL_STALLED, task.prompt);
                        response.set(cx.send_request(again).block_task());
                    }
                    Some(_) => return Ended::failure(format!("{silent}, and again after the task was sent again")),
                    None => return Ended::failure(format!("{silent}; {NO_CANCEL_ANSWER}")),
                }
            }
        }
    };
    let (why, text, window) = match next {
        Next::HandBack(why, text, window) => (why, text, window),
        // A task run ends with its turn; with a bridge, a turn that
        // ended well, or that the client cancelled, is followed by the
        // client's.
        Next::Answered(r, class) => {
            cancelling.store(false, Ordering::Relaxed);
            let ended = prompt_result(r, tap).with_class(class);
            // A turn the client cancelled is the client's to go on from.
            if ended.errored && !client_cancelled {
                // The session ends with the hand-back: a client's
                // prompt meanwhile is refused, not left unanswered.
                if let Some(talk) = conversation.take() {
                    tokio::spawn(refuse_prompts(talk));
                }
                *pending_error.lock().unwrap_or_else(|e| e.into_inner()) =
                    ended.message.clone().map(|error| Pending {
                        error,
                        class: ended.class,
                    });
                return after_error(&link, &mut stop, ended, task.hand_back_window).await;
            }
            let goes_on = ended.outcome == Outcome::Success
                || (client_cancelled && ended.outcome == Outcome::Cancelled);
            let Some(talk) = conversation.take().filter(|_| goes_on) else {
                // A conversation's client sees for itself what the
                // agent left; a task run's turn is the run.
                return match &task.output {
                    Some(check) if ended.outcome == Outcome::Success => {
                        remind(&link, &mut stop, &mut nudges, check, ended).await
                    }
                    _ => ended,
                };
            };
            return match converse(&link, &mut stop, &mut nudges, talk).await {
                Talked::Ended(ended) => ended,
                Talked::HandBack { why, text, window } => {
                    hand_back(&link, &mut stop, &why, text, window).await
                }
            };
        }
    };

    drop(restating);
    // Near a limit: a notice queued now may never be read (a subagent
    // task can outlast the run), so the turn is interrupted, and what is
    // left of the budget is a turn in which the agent hands back.
    tap.log(&[format!(
        "⚠ {}: interrupting the agent to hand back",
        stopped(&why).1
    )]);
    match cancel_turn(&cx, &sid, &cancelling, response.as_mut()).await {
        Some(r) => match prompt_result(r, tap) {
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
    hand_back(&link, &mut stop, &why, text, window).await
}

/// The agent's session, as the session's turns are sent to it.
struct Link<'a> {
    cx: &'a ConnectionTo<Agent>,
    tap: &'a Tap,
    sid: &'a SessionId,
    cancelling: &'a AtomicBool,
    notices: bool,
    steering: bool,
}

/// What the watch of the run's item saw: a note is logged, and an update
/// sent into the running turn (IN_TURN), by steering where the agent takes
/// it, else queued as a notice is. One that cannot be sent so is logged,
/// not sent as a prompt that would end the turn or start one.
fn from_item(link: &Link<'_>, seen: Seen, in_turn: bool) {
    let Link { cx, tap, sid, .. } = *link;
    let update = match seen {
        Seen::Note(note) => return tap.log(&[digest::cut(&format!("⚠ {note}"))]),
        Seen::Update(update) => update,
    };
    let not = if !in_turn {
        Some("no turn is running")
    } else if !(link.steering || link.notices) {
        Some("the agent takes no message during its turn")
    } else {
        None
    };
    if let Some(why) = not {
        tap.log(&[digest::cut(&format!(
            "⚠ an update of the run's item not sent ({why}): {}",
            update.url
        ))]);
        return;
    }
    let text = update.message();
    let mut marks = meta(json!({"notice": steer::LABEL_UPDATE, "url": update.url}));
    // Either is answered when the agent has taken it, or refused it (the
    // digest says), so nobody waits for the answer.
    if link.steering {
        // An adapter that finds no turn running is to say so, not start
        // one: the update then goes unsent.
        marks.insert(
            "steering".to_owned(),
            json!({"idleBehavior": "promptRequired"}),
        );
        let params = json!({
            "sessionId": sid,
            "prompt": [ContentBlock::Text(TextContent::new(text))],
            "_meta": marks,
        });
        let request = match UntypedMessage::new(steer::STEER_METHOD, params) {
            Ok(request) => request,
            Err(e) => return tap.log(&[format!("⚠ an update of the run's item not sent: {e}")]),
        };
        let answer = cx.send_request(request).block_task();
        tokio::spawn(async move {
            let _ = answer.await;
        });
    } else {
        let request = PromptRequest::new(
            sid.clone(),
            vec![ContentBlock::Text(TextContent::new(text))],
        )
        .meta(marks);
        let answer = cx.send_request(request).block_task();
        tokio::spawn(async move {
            let _ = answer.await;
        });
    }
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
        Some(r) => prompt_result(r, tap).outcome == Outcome::Success,
        None => {
            tap.log(&["⚠ the agent didn't hand back in time".to_owned()]);
            let _ = cancel_turn(cx, sid, cancelling, response.as_mut()).await;
            false
        }
    };
    Ended::stopped(why, handed_back)
}

/// After the task's turn ended on an error (ERRORED), with the agent still
/// running: ending the run there as done would pass off unfinished work as
/// finished, so the agent is asked to hand back as near a limit, after a
/// pause. A run whose agent did is stopped at a limit, with the error for
/// the reason; one whose agent didn't (the provider still refuses) fails
/// with the error. A limit the run reaches meanwhile stops it as ever.
/// There is no pause after a failure no wait clears (a usage limit, a
/// refused credential): it would only spend the time the hand-back needs.
async fn after_error(
    link: &Link<'_>,
    stop: &mut watch::Receiver<Option<Stop>>,
    errored: Ended,
    window: Duration,
) -> Ended {
    let error = errored.message.clone().unwrap_or_default();
    let class = errored.class;
    let pause = match class {
        Some(class) if class != Class::Other && !class.transient() => Duration::ZERO,
        _ => ERROR_PAUSE.min(window),
    };
    let when = if pause.is_zero() {
        "now".to_owned()
    } else {
        format!("in {}s", pause.as_secs())
    };
    link.tap.log(&[digest::cut(&format!(
        "⚠ {error}: asking the agent to hand back {when}"
    ))]);
    tokio::select! {
        _ = tokio::time::sleep(pause) => {}
        _ = wait_stop(stop) => {}
    }
    let limit = |stop: &watch::Receiver<Option<Stop>>| stop.borrow().clone();
    if let Some(why) = limit(stop) {
        link.tap.log(&[format!("⚠ {}", stopped(&why).1)]);
        return limited(&why, &error, class);
    }
    let why = Stop::Budget(format!("the agent's turn ended on an error ({error})"));
    // Without the error's words, which an agent repeating them as it
    // hands back would have taken for the error again.
    let text = hand_back_text("had a model request fail", window);
    let ended = hand_back(link, stop, &why, text, window)
        .await
        .with_class(class);
    if ended.handed_back {
        return ended;
    }
    match limit(stop) {
        Some(why) => limited(&why, &error, class),
        None => errored,
    }
}

/// A run stopped for WHY after the task's turn ended on ERROR (of CLASS,
/// if a provider's), which it still says.
fn limited(why: &Stop, error: &str, class: Option<Class>) -> Ended {
    let ended = Ended::stopped(why, false);
    Ended {
        message: ended.message.map(|m| format!("{m}, after {error}")),
        class,
        ..ended
    }
}

/// The WAIT before the task is sent again after its turn ended on a
/// provider's failure of CLASS with ERROR, with no turn running: `None`
/// once it is over, or how the session ended in it. A limit reached
/// meanwhile stops the run; near one the agent hands back as it would
/// have, so the wait never runs past the run's time.
async fn provider_wait(
    link: &Link<'_>,
    stop: &mut watch::Receiver<Option<Stop>>,
    nudges: &mut mpsc::UnboundedReceiver<Nudge>,
    wait: Duration,
    error: &str,
    class: Class,
) -> Option<Ended> {
    let over = tokio::time::sleep(wait);
    let mut over = std::pin::pin!(over);
    loop {
        tokio::select! {
            biased;
            why = wait_stop(stop) => {
                let Some(why) = why else {
                    return Some(Ended::failure(LOST_STOP_SIGNAL.to_owned()));
                };
                link.tap.log(&[format!("⚠ {}", stopped(&why).1)]);
                return Some(limited(&why, error, Some(class)));
            }
            Some(nudge) = nudges.recv() => match nudge {
                // A notice is for a turn, and none is running.
                Nudge::Notice { .. } => {}
                Nudge::Item(seen) => from_item(link, seen, false),
                Nudge::HandBack { why, text, window } => {
                    link.tap.log(&[format!("⚠ {}: asking the agent to hand back", stopped(&why).1)]);
                    let ended = hand_back(link, stop, &why, text, window).await;
                    // One that didn't still says what ended the task's turn.
                    return Some(if ended.handed_back {
                        ended.with_class(Some(class))
                    } else {
                        limited(&why, error, Some(class))
                    });
                }
            },
            () = &mut over => return None,
        }
    }
}

/// Sets its flag when dropped: however the wait for a check of the
/// sandbox user's ends, the session returning or its future dropped on a
/// signal, the check goes no further than the command it is in, which
/// the reaping then kills.
struct Abandon(Arc<AtomicBool>);

impl Drop for Abandon {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Whether CHECK finds the agent's output (a check that could not be run
/// finds none), unless a limit stops the session first: the check runs
/// git on the agent's checkout, which the agent can make slow.
async fn has_output(
    check: &OutputCheck,
    stop: &mut watch::Receiver<Option<Stop>>,
) -> Result<Option<String>, Ended> {
    let abandon = Abandon(Arc::default());
    let (check, stopped) = (check.clone(), abandon.0.clone());
    tokio::select! {
        found = tokio::task::spawn_blocking(move || check(&stopped)) => Ok(found.unwrap_or_else(|_| Some("The output check failed.".into()))),
        why = wait_stop(stop) => Err(match why {
            Some(why) => Ended::stopped(&why, false),
            None => Ended::failure(LOST_STOP_SIGNAL.to_owned()),
        }),
    }
}

/// After the task's turn ENDED well: if the agent left no output that the
/// run requires, one more turn in which it is reminded, under the same
/// limits. A run whose agent still left none fails, rather than end well
/// with nothing to show for it.
async fn remind(
    link: &Link<'_>,
    stop: &mut watch::Receiver<Option<Stop>>,
    nudges: &mut mpsc::UnboundedReceiver<Nudge>,
    check: &OutputCheck,
    ended: Ended,
) -> Ended {
    let reason = match has_output(check, stop).await {
        Ok(None) => return ended,
        Ok(Some(reason)) => reason,
        Err(stopped) => return stopped,
    };
    let Link {
        cx,
        tap,
        sid,
        cancelling,
        ..
    } = *link;
    tap.log(&[
        "⚠ the agent ended its turn without its required output: reminding it once".to_owned(),
    ]);
    let request = notice_prompt(sid, LABEL_REMINDER, format!("{REMINDER}\n{reason}"));
    let mut response = std::pin::pin!(cx.send_request(request).block_task());
    let answer = loop {
        tokio::select! {
            biased;
            r = &mut response => break prompt_result(r, tap),
            why = wait_stop(stop) => {
                break stop_turn(cx, tap, sid, cancelling, why, response.as_mut()).await;
            }
            Some(nudge) = nudges.recv() => match nudge {
                // The reminder is all the agent is to do now; an update
                // of its item is still new input to it.
                Nudge::Notice { .. } => {}
                Nudge::Item(seen) => from_item(link, seen, true),
                // Near a limit, as in the task's turn: interrupted, it is
                // asked to hand back.
                Nudge::HandBack { why, text, window } => {
                    tap.log(&[format!(
                        "⚠ {}: interrupting the agent to hand back",
                        stopped(&why).1
                    )]);
                    let ended = match cancel_turn(cx, sid, cancelling, response.as_mut()).await {
                        Some(Ok(_)) => hand_back(link, stop, &why, text, window).await,
                        _ => Ended::stopped(&why, false),
                    };
                    return Ended {
                        reminded: true,
                        ..ended
                    };
                }
            },
        }
    };
    let reminded = Ended {
        reminded: true,
        ..answer
    };
    if reminded.outcome != Outcome::Success {
        return reminded;
    }
    match has_output(check, stop).await {
        Ok(None) => reminded,
        Ok(Some(_)) => Ended {
            reminded: true,
            stop_reason: reminded.stop_reason,
            ..Ended::failure(NO_OUTPUT.to_owned())
        },
        Err(stopped) => Ended {
            reminded: true,
            ..stopped
        },
    }
}

/// Answers each of the client's prompts with HANDING_BACK until it
/// leaves, or the session hangs up on it; a cancel has no turn of its
/// own to end.
async fn refuse_prompts(mut talk: Conversation) {
    while let Some(msg) = talk.from_client.recv().await {
        if let FromClient::Prompt { answer, .. } = msg {
            let _ = answer.send(Err(HANDING_BACK.to_owned()));
        }
    }
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
        ..
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
                Nudge::Item(seen) => {
                    from_item(link, seen, false);
                    continue;
                }
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
                    let ended = prompt_result(r, tap);
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
                    Nudge::Item(seen) => from_item(link, seen, true),
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
                            Some(r) => prompt_result(r, tap),
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
    match answer.map(|r| prompt_result(r, tap)) {
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

/// initialize, session/new and the model: the session's id and its model
/// option, or how it failed.
async fn setup(
    cx: &ConnectionTo<Agent>,
    task: &Task<'_>,
) -> Result<(SessionId, Option<ModelOption>), Ended> {
    let fail =
        |what: &str, e: agent_client_protocol::Error| Ended::failure(format!("{what} failed: {e}"));
    // fs and terminal are left unadvertised (the defaults), so agents use
    // their own tools inside the sandbox; ACP v2 drops them anyway.
    let init = InitializeRequest::new(ProtocolVersion::V1)
        .client_info(Implementation::new(CLIENT_NAME, env!("CARGO_PKG_VERSION")));
    let initialized = cx
        .send_request(init)
        .block_task()
        .await
        .map_err(|e| fail("initialize", e))?;
    // An agent that cannot take them would run without the tools the
    // task is about, or reach for them some other way.
    if !task.mcp_servers.is_empty() && !initialized.agent_capabilities.mcp_capabilities.http {
        return Err(Ended::failure(format!(
            "the agent does not take MCP servers over HTTP (mcpCapabilities.http), which the \
             run's MCP server {} needs",
            task.mcp_servers
                .iter()
                .map(|server| server.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let servers = task
        .mcp_servers
        .iter()
        .map(|server| {
            McpServer::Http(
                McpServerHttp::new(&server.name, &server.url).headers(
                    server
                        .headers
                        .iter()
                        .map(|(name, value)| HttpHeader::new(name, value))
                        .collect(),
                ),
            )
        })
        .collect();
    let new = cx
        .send_request(NewSessionRequest::new(task.cwd).mcp_servers(servers))
        .block_task()
        .await
        .map_err(|e| fail("session/new", e))?;
    let sid = new.session_id;
    let mut model_option = new
        .config_options
        .iter()
        .flatten()
        .find(|o| o.category == Some(SessionConfigOptionCategory::Model))
        .map(|o| ModelOption {
            id: o.id.clone(),
            current: current_value(o).map(str::to_owned),
        });
    // Where the agent has no environment variable for it, the model is a
    // session config option.
    if let (Some(model), false) = (task.model, task.model_by_env) {
        let option = model_option.as_mut().ok_or_else(|| {
            Ended::failure(format!(
                "the agent has no model option to select {model} with"
            ))
        })?;
        let current = select_model(cx, &sid, &option.id, model)
            .await
            .map_err(|e| fail(&format!("selecting model {model}"), e))?;
        // An agent that takes the selection but runs another model (#562:
        // Vibe reported, and told the model it was, its built-in default)
        // would spend the run on a model the caller did not ask for.
        if current.as_deref() != Some(model) {
            return Err(Ended::failure(format!(
                "the agent runs {}, not the requested model {model}",
                current.as_deref().unwrap_or("an unreported model")
            )));
        }
        option.current = current;
    }
    for (id, value) in task.config_options {
        let req = SetSessionConfigOptionRequest::new(sid.clone(), id.clone(), value.as_str());
        cx.send_request(req)
            .block_task()
            .await
            .map_err(|e| fail(&format!("setting {id} to {value}"), e))?;
    }
    Ok((sid, model_option))
}

/// The agent's model session config option, and the model it says the
/// session runs, if it says.
struct ModelOption {
    id: SessionConfigId,
    current: Option<String>,
}

/// The value a select option has.
fn current_value(option: &SessionConfigOption) -> Option<&str> {
    match &option.kind {
        SessionConfigKind::Select(select) => Some(select.current_value.0.as_ref()),
        _ => None,
    }
}

/// Sets the session's model option OPTION to MODEL: the model the agent
/// then says it runs, if it says.
async fn select_model(
    cx: &ConnectionTo<Agent>,
    sid: &SessionId,
    option: &SessionConfigId,
    model: &str,
) -> Result<Option<String>, agent_client_protocol::Error> {
    let req = SetSessionConfigOptionRequest::new(sid.clone(), option.clone(), model);
    let set = cx.send_request(req).block_task().await?;
    Ok(set
        .config_options
        .iter()
        .find(|o| o.id == *option)
        .and_then(current_value)
        .map(str::to_owned))
}

/// Switches the session to the fallback model MODEL, for a provider that
/// stayed overloaded: the model the agent then runs, or why it does not.
/// Not held to MODEL's very name as the run's own model is: Claude Code
/// takes an alias (`opus`) and reports the model it stands for. An agent
/// that reports none, or still the model it ran (#562), was not switched.
async fn switch_model(
    cx: &ConnectionTo<Agent>,
    sid: &SessionId,
    option: Option<&ModelOption>,
    model: &str,
) -> Result<String, String> {
    let option = option.ok_or("the agent has no model option")?;
    let switched = tokio::time::timeout(
        MODEL_SWITCH_TIMEOUT,
        select_model(cx, sid, &option.id, model),
    )
    .await
    .map_err(|_| format!("no answer in {}s", MODEL_SWITCH_TIMEOUT.as_secs()))?
    .map_err(|e| e.to_string())?;
    match switched {
        None => Err("the agent reports no model".to_owned()),
        Some(current) if Some(&current) == option.current.as_ref() => {
            Err(format!("the agent still runs {current}"))
        }
        Some(current) => Ok(current),
    }
}

/// How a turn ended, from its answer and from what the agent said last
/// (TAP): an agent that gave up on a refused model request may say so and
/// answer the turn as done.
fn prompt_result(r: Result<PromptResponse, agent_client_protocol::Error>, tap: &Tap) -> Ended {
    match r {
        Err(e) => Ended {
            errored: true,
            class: Some(provider::classify(&e.to_string())),
            ..Ended::failure(format!("session/prompt failed: {e}"))
        },
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
            let ended = Ended {
                outcome,
                stop_reason: reason,
                message,
                handed_back: false,
                errored: false,
                reminded: false,
                class: None,
            };
            match tap.refusal().filter(|_| outcome == Outcome::Success) {
                Some(said) => Ended {
                    outcome: Outcome::Failure,
                    message: Some(format!("{REFUSED}: {said}")),
                    errored: true,
                    class: Some(provider::classify(&said)),
                    ..ended
                },
                None => ended,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The waits double from RETRY_WAIT, or take the provider's own up to
    /// a cap, grow by at most a quarter of jitter, and stay within the
    /// hand-back window.
    #[test]
    fn backoffs() {
        let secs = Duration::from_secs;
        // (times retried, window, retry-after, the wait before jitter)
        for (retried, window, after, base) in [
            (0, secs(225), None, secs(10)),
            (1, secs(225), None, secs(20)),
            (2, secs(225), None, secs(40)),
            (3, secs(225), None, MAX_RETRY_WAIT),
            (u32::MAX, secs(225), None, MAX_RETRY_WAIT),
            (0, secs(225), Some(secs(30)), secs(30)),
            (2, secs(225), Some(secs(1)), secs(1)),
            (0, secs(225), Some(RETRY_AFTER_CAP), RETRY_AFTER_CAP),
        ] {
            for _ in 0..20 {
                let wait = backoff(retried, window, after).unwrap();
                assert!(
                    wait >= base && wait <= base.mul_f64(1.25),
                    "{retried} {after:?}: {wait:?}"
                );
            }
        }
        // The window caps everything, jitter included.
        assert_eq!(backoff(2, secs(3), None), Some(secs(3)));
        assert_eq!(backoff(0, secs(3), Some(secs(30))), Some(secs(3)));
        assert_eq!(backoff(0, Duration::ZERO, None), Some(Duration::ZERO));
        assert_eq!(backoff(u32::MAX, secs(3), None), Some(secs(3)));
        // A provider that asks for longer than the cap is not waited for.
        assert_eq!(backoff(0, secs(225), Some(secs(121))), None);
        assert_eq!(backoff(0, secs(3), Some(secs(600))), None);
        // Overload is waited out for a few minutes, the rest for about one.
        let waited = |class| -> Duration {
            (0..retries(class))
                .map(|n| backoff(n, secs(3600), None).unwrap())
                .sum()
        };
        let overload = waited(Class::Overloaded);
        assert!(
            overload >= secs(250) && overload <= secs(313),
            "{overload:?}"
        );
        let limited = waited(Class::RateLimited);
        assert!(limited >= secs(70) && limited <= secs(88), "{limited:?}");
    }
}
