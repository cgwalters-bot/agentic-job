//! The daemon: the child agent's ACP client, holding its standard streams
//! for as long as the child runs, and serving the driver's commands on a
//! socket in its directory, one JSON request and one JSON answer to a
//! connection.
//!
//! It speaks JSON-RPC as written, not through the session's SDK client:
//! it only passes prompts on and writes down what comes back, and the
//! main agent reads the child's messages raw from the transcript.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use rustix::process::{Pid, Signal, kill_process_group};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{ChildStdin, Command};
use tokio::sync::{Notify, mpsc, oneshot};

use super::events::Events;
use super::{ACP_LOG, STDERR_LOG};
use crate::session::Record;
use crate::session::digest::Dir;
use crate::session::permission::{self, Policy, pick_option};

/// How long each step of opening the session may take: Vibe imports for
/// several seconds before it answers anything.
const SETUP_TIMEOUT: Duration = Duration::from_secs(120);
/// The largest request a connection may send: a prompt.
pub(super) const MAX_REQUEST_BYTES: u64 = 1 << 20;
/// How long a stopped child gets to be gone.
const KILL_GRACE: Duration = Duration::from_secs(10);
/// How long what an exited child said is read before its exit is.
const READER_GRACE: Duration = Duration::from_secs(5);
const PROTOCOL_VERSION: u64 = 1;
const CLIENT_NAME: &str = "agentic-job-acp-drive";
/// JSON-RPC's code for a method the client does not have.
const METHOD_NOT_FOUND: i64 = -32601;
/// The model's session config option has this category.
const MODEL_CATEGORY: &str = "model";
/// Vibe's legacy runtime caps a reply only by this undeclared option
/// (`run::agent`, which sets it for the main agent).
const VIBE_MAX_TOKENS_OPTION: &str = "max_tokens";

/// A command for the daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Status,
    Prompt { text: String },
    Events { since: usize },
    Cancel,
    Stop,
}

/// What the daemon was started to run.
pub(super) struct Child {
    pub name: String,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub model: Option<String>,
    /// Vibe's `max_tokens` for the model, where it is Vibe.
    pub max_tokens: Option<u64>,
    pub dir: PathBuf,
    pub socket: PathBuf,
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

type Answer = std::result::Result<Value, String>;

struct State {
    events: Events,
    acp: File,
    next_id: u64,
    waiting: HashMap<u64, oneshot::Sender<Answer>>,
    session: Option<String>,
    model: Option<String>,
    /// A turn is running.
    turn: bool,
    /// The running turn was cancelled: permission requests are answered
    /// as cancelled, as ACP requires.
    cancelled: bool,
    /// How the child ended, once it has.
    exited: Option<String>,
}

struct Shared {
    state: Mutex<State>,
    to_child: mpsc::UnboundedSender<String>,
    policy: Policy,
    cwd: PathBuf,
}

impl Shared {
    /// A panic while the lock was held loses nothing a later line needs.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Writes LINE, as it crossed in DIR, to the transcript. The
    /// transcript is the record: a line that cannot be written there is
    /// noted on the daemon's standard error, its log.
    fn record(&self, state: &mut State, dir: Dir, line: &str) {
        let msg = serde_json::from_str::<Value>(line).ok();
        let record = Record {
            ts: now(),
            dir,
            line: msg.is_none().then(|| line.to_owned()),
            msg,
        };
        let written = serde_json::to_string(&record)
            .map_err(std::io::Error::from)
            .and_then(|text| writeln!(state.acp, "{text}"));
        if let Err(err) = written {
            eprintln!("writing the transcript: {err}");
        }
    }

    fn send(&self, state: &mut State, msg: &Value) {
        let line = msg.to_string();
        self.record(state, Dir::Send, &line);
        // A child that is gone has its end in `exited`.
        let _ = self.to_child.send(line);
    }

    /// Sends a request; its answer comes on the receiver.
    fn request(&self, method: &str, params: Value) -> oneshot::Receiver<Answer> {
        self.request_in(&mut self.state(), method, params)
    }

    /// As [`Shared::request`], under the lock the caller holds.
    fn request_in(
        &self,
        state: &mut State,
        method: &str,
        params: Value,
    ) -> oneshot::Receiver<Answer> {
        let (tx, rx) = oneshot::channel();
        if let Some(exited) = &state.exited {
            let _ = tx.send(Err(format!("the agent has exited ({exited})")));
            return rx;
        }
        let id = state.next_id;
        state.next_id += 1;
        state.waiting.insert(id, tx);
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.send(state, &msg);
        rx
    }

    async fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let answer = tokio::time::timeout(timeout, self.request(method, params))
            .await
            .with_context(|| format!("{method}: no answer in {}s", timeout.as_secs()))?
            .with_context(|| format!("{method}: no answer"))?;
        answer.map_err(|err| anyhow::anyhow!("{method} failed: {err}"))
    }

    /// A line from the child's standard output.
    fn received(&self, line: &str) {
        let mut state = self.state();
        self.record(&mut state, Dir::Recv, line);
        let Ok(msg) = serde_json::from_str::<Value>(line) else {
            return;
        };
        let ts = now();
        match (msg.get("id"), msg["method"].as_str()) {
            (Some(id), Some(method)) => {
                let result = if method == "session/request_permission" {
                    Ok(self.permission(&mut state, &msg["params"], ts))
                } else {
                    Err(
                        json!({"code": METHOD_NOT_FOUND, "message": format!("{method} is not offered")}),
                    )
                };
                let answer = match result {
                    Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                    Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error}),
                };
                self.send(&mut state, &answer);
            }
            (None, Some("session/update")) => state.events.update(ts, &msg["params"]["update"]),
            (Some(id), None) => {
                let waiting = id.as_u64().and_then(|id| state.waiting.remove(&id));
                if let Some(tx) = waiting {
                    let answer = match msg.get("error") {
                        Some(error) => Err(error["message"]
                            .as_str()
                            .map_or_else(|| error.to_string(), str::to_owned)),
                        None => Ok(msg["result"].clone()),
                    };
                    let _ = tx.send(answer);
                }
            }
            _ => {}
        }
    }

    /// Answers a permission request as the session answers the main
    /// agent's: from the task's policy, allowing once at most.
    fn permission(&self, state: &mut State, params: &Value, ts: f64) -> Value {
        let verdict = self
            .policy
            .decide(&permission::Request::from_params(params, &self.cwd));
        let picked = if state.cancelled {
            None
        } else {
            pick_option(&params["options"], verdict.decision)
        };
        let (outcome, decision) = match picked {
            Some((id, decision)) => (
                json!({"outcome": "selected", "optionId": id}),
                decision.as_str(),
            ),
            None => (json!({"outcome": "cancelled"}), "cancelled"),
        };
        state
            .events
            .permission(ts, params["toolCall"]["title"].as_str(), decision);
        json!({"outcome": outcome})
    }

    /// The child is gone: every request waiting on it fails.
    fn exited(&self, status: String) {
        let mut state = self.state();
        state.events.exit(now(), &status);
        for (_, tx) in state.waiting.drain() {
            let _ = tx.send(Err(format!("the agent exited ({status})")));
        }
        state.exited = Some(status);
    }

    /// The `prompt` command: sends TEXT as a turn and waits for its end.
    async fn prompt(&self, text: String) -> Value {
        // Sent under the lock that starts the turn: a cancel cannot reach
        // the child before the prompt it cancels.
        let turn = {
            let mut state = self.state();
            if let Some(exited) = &state.exited {
                return json!({"error": format!("the agent has exited ({exited})")});
            }
            if state.turn {
                return json!({"error": "a turn is running: wait for it, or cancel it"});
            }
            state.turn = true;
            state.cancelled = false;
            state.events.prompt(now(), &text);
            let params =
                json!({"sessionId": state.session, "prompt": [{"type": "text", "text": text}]});
            self.request_in(&mut state, "session/prompt", params)
        };
        let answer = turn
            .await
            .unwrap_or_else(|_| Err("the daemon dropped the turn".to_owned()));
        let mut state = self.state();
        state.turn = false;
        match answer {
            Ok(result) => {
                let stop = result["stopReason"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_owned();
                state.events.turn_end(now(), Some(&stop), None);
                json!({"stop_reason": stop})
            }
            Err(error) => {
                state.events.turn_end(now(), None, Some(&error));
                json!({"error": error})
            }
        }
    }

    fn cancel(&self) -> Value {
        let mut state = self.state();
        if !state.turn {
            return json!({"turn": false});
        }
        state.cancelled = true;
        let msg = json!({"jsonrpc": "2.0", "method": "session/cancel",
            "params": {"sessionId": state.session}});
        self.send(&mut state, &msg);
        json!({"turn": true, "cancelled": true})
    }

    fn status(&self, name: &str) -> Value {
        let state = self.state();
        json!({"agent": name, "session": state.session, "model": state.model,
            "turn": state.turn, "exited": state.exited,
            "transcript": PathBuf::from(super::DIR).join(ACP_LOG)})
    }
}

/// Opens the session: initialize, session/new, the model and Vibe's
/// output cap. Returns the model the child reports.
async fn open(shared: &Shared, child: &Child) -> Result<Option<String>> {
    // No filesystem or terminal capability, as for the main agent: the
    // child uses its own tools in the sandbox.
    shared
        .call(
            "initialize",
            json!({"protocolVersion": PROTOCOL_VERSION,
                "clientCapabilities": {"fs": {"readTextFile": false, "writeTextFile": false},
                    "terminal": false},
                "clientInfo": {"name": CLIENT_NAME, "version": env!("CARGO_PKG_VERSION")}}),
            SETUP_TIMEOUT,
        )
        .await?;
    let new = shared
        .call(
            "session/new",
            json!({"cwd": child.cwd, "mcpServers": []}),
            SETUP_TIMEOUT,
        )
        .await?;
    let session = new["sessionId"]
        .as_str()
        .context("session/new answered without a sessionId")?
        .to_owned();
    shared.state().session = Some(session.clone());
    let model_option = |options: &Value| {
        options
            .as_array()
            .into_iter()
            .flatten()
            .find(|o| o["category"] == MODEL_CATEGORY)
            .cloned()
    };
    let mut current = model_option(&new["configOptions"]);
    if let Some(model) = &child.model {
        let option = current
            .as_ref()
            .context("the agent has no model option to select one with")?;
        let set = shared
            .call(
                "session/set_config_option",
                json!({"sessionId": session, "configId": option["id"], "value": model}),
                SETUP_TIMEOUT,
            )
            .await?;
        current = model_option(&set["configOptions"]);
        // As the session holds the main agent to it (#562): an agent that
        // takes the selection and runs another model is no use here.
        let reported = current.as_ref().and_then(|o| o["currentValue"].as_str());
        ensure!(
            reported == Some(model.as_str()),
            "the agent runs {}, not the requested model {model}",
            reported.unwrap_or("an unreported model")
        );
    }
    if let Some(cap) = child.max_tokens {
        shared
            .call(
                "session/set_config_option",
                json!({"sessionId": session, "configId": VIBE_MAX_TOKENS_OPTION,
                    "value": cap.to_string()}),
                SETUP_TIMEOUT,
            )
            .await?;
    }
    Ok(current.and_then(|o| o["currentValue"].as_str().map(str::to_owned)))
}

/// Reads one request from STREAM and writes its answer.
async fn serve_connection(
    shared: Arc<Shared>,
    mut stream: UnixStream,
    name: Arc<str>,
    stop: Arc<Notify>,
) {
    let mut line = String::new();
    let read = (&mut stream)
        .take(MAX_REQUEST_BYTES)
        .read_to_string(&mut line)
        .await;
    let request = read
        .map_err(|e| e.to_string())
        .and_then(|_| serde_json::from_str::<Request>(&line).map_err(|e| e.to_string()));
    let stopping = matches!(request, Ok(Request::Stop));
    let answer = match request {
        Err(err) => json!({"error": format!("a bad request: {err}")}),
        Ok(Request::Status) => shared.status(&name),
        Ok(Request::Prompt { text }) => shared.prompt(text).await,
        Ok(Request::Events { since }) => shared.state().events.since(now(), since),
        Ok(Request::Cancel) => shared.cancel(),
        Ok(Request::Stop) => json!({"stopped": true}),
    };
    // A caller that stopped waiting (`prompt --timeout`) is not an error.
    let _ = stream.write_all(format!("{answer}\n").as_bytes()).await;
    // Only once answered: the daemon does not wait for this task.
    if stopping {
        stop.notify_one();
    }
}

fn append(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

/// Writes what the writer gets to the child's standard input.
async fn write_child(mut stdin: ChildStdin, mut lines: mpsc::UnboundedReceiver<String>) {
    while let Some(line) = lines.recv().await {
        let line = format!("{line}\n");
        if stdin.write_all(line.as_bytes()).await.is_err() || stdin.flush().await.is_err() {
            break;
        }
    }
}

/// Runs the child and serves the driver until `stop`, or until the
/// session could not be opened. Its permission requests are answered from POLICY.
pub(super) async fn serve(child: Child, policy: Policy) -> Result<()> {
    let (program, args) = child.argv.split_first().context("no command")?;
    let mut process = Command::new(program)
        .args(args)
        .current_dir(&child.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own group, so that stopping it stops what it started.
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting {program}"))?;
    let group = process
        .id()
        .and_then(|pid| Pid::from_raw(pid.try_into().ok()?));
    let kill = move || {
        if let Some(group) = group {
            // An error means the group is gone already.
            let _ = kill_process_group(group, Signal::KILL);
        }
    };
    let (stdin, stdout, stderr) = (
        process.stdin.take().context("no stdin")?,
        process.stdout.take().context("no stdout")?,
        process.stderr.take().context("no stderr")?,
    );
    let (to_child, lines) = mpsc::unbounded_channel();
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            events: Events::new(),
            acp: append(&child.dir.join(ACP_LOG))?,
            next_id: 1,
            waiting: HashMap::new(),
            session: None,
            model: None,
            turn: false,
            cancelled: false,
            exited: None,
        }),
        to_child,
        policy,
        cwd: child.cwd.clone(),
    });
    tokio::spawn(write_child(stdin, lines));
    let reader = {
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                shared.received(&line);
            }
        })
    };
    let mut stderr_log = append(&child.dir.join(STDERR_LOG))?;
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let _ = writeln!(stderr_log, "{line}");
        }
    });
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            let status = process.wait().await;
            // What it started goes with it, so that nothing holds its
            // standard output open; then everything it said before it
            // went is taken in first, for a while.
            kill();
            let _ = tokio::time::timeout(READER_GRACE, reader).await;
            shared.exited(match status {
                Ok(status) => status.to_string(),
                Err(err) => format!("could not be waited for: {err}"),
            });
        });
    }

    let model = match open(&shared, &child).await {
        Ok(model) => model,
        Err(err) => {
            kill();
            return Err(err.context(format!("opening a session with {}", child.name)));
        }
    };
    shared.state().model = model;

    // Bound only now: `start` takes a socket that answers for a session
    // that is open.
    let listener = UnixListener::bind(&child.socket)
        .with_context(|| format!("listening on {}", child.socket.display()))?;
    let stop = Arc::new(Notify::new());
    let name: Arc<str> = child.name.clone().into();
    loop {
        tokio::select! {
            () = stop.notified() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                tokio::spawn(serve_connection(shared.clone(), stream, name.clone(), stop.clone()));
            }
        }
    }
    let _ = std::fs::remove_file(&child.socket);
    kill();
    // Give the waiter its chance to write the exit down.
    let deadline = tokio::time::Instant::now() + KILL_GRACE;
    while shared.state().exited.is_none() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

/// The output cap of MODEL (else the active model) in Vibe's
/// configuration TEXT, as `run` wrote it: `max_tokens` is what the legacy
/// runtime caps a reply by.
pub(super) fn vibe_max_tokens(text: &str, model: Option<&str>) -> Result<Option<u64>> {
    let config: Value = toml::from_str(text).context("the child's Vibe configuration")?;
    let wanted = match model {
        Some(model) => model,
        None => config["active_model"]
            .as_str()
            .context("the child's Vibe configuration has no active_model")?,
    };
    let models = config["models"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let found = models
        .iter()
        .find(|m| m["alias"].as_str() == Some(wanted))
        .or_else(|| models.iter().find(|m| m["name"].as_str() == Some(wanted)));
    let Some(found) = found else {
        bail!("the child's Vibe configuration has no model {wanted:?}");
    };
    Ok(found["max_output_tokens"].as_u64())
}
