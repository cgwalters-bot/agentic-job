//! fake-agent: a scripted agent speaking the Agent Client Protocol on its
//! standard streams, with no model behind it. It plays a fixed session, so
//! a run can go end to end (the session, the sandbox, the permission
//! policy and the redaction pass) without inference or credentials, and
//! the session's tests can drive it through what real agents don't
//! readily do. It writes the JSON-RPC by hand rather than through the
//! SDK, so it can misbehave.
//!
//! ```text
//! fake-agent demo          play the built-in session (fake-agent-demo.json),
//!                          or the one in ~/.config/fake-agent/demo.json
//!                          if there is one: `agentic-job run` starts the
//!                          fake agent only this way, and its tests have
//!                          sessions of their own to play; it writes a
//!                          line to its log in ~/.local/state/fake-agent/log
//! fake-agent script FILE [LATER]
//!                          play the session in FILE, and for every prompt
//!                          turn after the first the one in LATER (default:
//!                          one line of text)
//! fake-agent no-mcp FILE   play the session in FILE as an agent that does
//!                          not take MCP servers over HTTP
//! fake-agent fs            send fs/* and terminal/* requests the client
//!                          doesn't advertise, expecting each answered
//! fake-agent flood N       send N agent_message_chunk notifications
//! fake-agent grace         report a cost, then ask permission after the
//!                          client must have cancelled the session for it
//!                          (run with a budget below a dollar)
//! fake-agent slow-init     never answer initialize
//! ```
//!
//! A session is a JSON list of steps, run in order in `session/prompt`,
//! each tool call behind a `session/request_permission`:
//!
//! ```json
//! [{"say": "text"},
//!  {"execute": {"title": "Bash", "command": "git status"}},
//!  {"read": {"title": "Read", "path": "{cwd}/README.md", "lines": 5}},
//!  {"write": {"title": "Write", "path": "{cwd}/x", "content": "..."}},
//!  {"cost": {"usd": 0.01}},
//!  {"task": "Review the change"},
//!  "compact",
//!  {"context": {"used": 24000, "size": 32768}},
//!  {"sleep": 1.5},
//!  {"stop": "refusal"},
//!  {"exit": 7},
//!  {"fail": "message"},
//!  {"rate_limit": "message"},
//!  {"finish": 0},
//!  {"mcp": {"tool": "search", "arguments": {"q": "x"}}}]
//! ```
//!
//! A `task` is a subagent's tool call as opencode reports one, done at
//! once. A `compact` is a compaction of its context as Vibe 2.26.1
//! reports one, and a `context` a `usage_update` of the context's size.
//! A `sleep` (seconds) ends early when the client cancels the turn.
//! A `stop` ends the turn there with that stop reason, even after a
//! cancel, as an agent whose last reply was complete when the cancel
//! came; and an `exit` the
//! process with that status, as an agent that crashed. A `fail` has the
//! turn, when it ends, answered with a JSON-RPC error of that message,
//! as an agent whose model request failed; a `rate_limit` likewise, with
//! Vibe's code for a rate-limited request. A `finish` ends
//! the turn as done and then the process with that status, as an agent
//! that doesn't wait for its client to hang up. An `mcp` step lists the
//! tools of the first MCP server `session/new` gave it over HTTP, with the
//! headers it was given, calls the one named, and says what it got. As
//! real agents do,
//! it takes a `session/prompt` that arrives during a turn without
//! starting another one, and answers it when the turn ends. A
//! `_session/steering` it answers at once, as claude-agent-acp does one
//! that asks not to start a turn: `injected` during a turn,
//! `promptRequired` outside one.
//!
//! `{cwd}` is the session's working directory and `{home}` is `$HOME`.
//! Commands run with `sh -c` in the session's working directory, with
//! the run's read-only GitHub token as `GH_TOKEN` where the run has one,
//! as the launcher gives it to a real agent.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use agentic_job::run::agent::{FAKE_LOG_DIR, GITHUB_TOKEN_VAR};
use agentic_job::run::launch::github_token;
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};

const DEMO: &str = include_str!("fake-agent-demo.json");
/// Under the home directory: a session for `demo` to play in place of
/// the built-in one.
const DEMO_OVERRIDE: &str = ".config/fake-agent/demo.json";
const NAME: &str = "fake-agent";
/// Its log, in FAKE_LOG_DIR.
const LOG_FILE: &str = "fake-agent.log";
const SESSION: &str = "fake-session";
const MODEL_OPTION: &str = "model";
const DEFAULT_MODEL: &str = "fake";
/// A session config option it takes without listing it, as Vibe takes
/// its `max_tokens`; it refuses any other but the model.
const UNLISTED_OPTION: &str = "max_tokens";
/// A model whose selection it accepts but keeps reporting its default,
/// which the session must refuse (#562).
const IGNORED_MODEL: &str = "ignored";
/// A model whose selection it accepts with an answer naming no model,
/// which the session must refuse too.
const UNREPORTED_MODEL: &str = "unreported";
/// How long a scripted request waits for the client's answer.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(60);
/// How long `fs` mode waits for each answer: an unanswered request hangs.
const FS_TIMEOUT: Duration = Duration::from_secs(5);
/// How long `grace` mode waits before its late permission request.
const GRACE_DELAY: Duration = Duration::from_secs(1);
/// What `grace` mode says it has spent.
const GRACE_COST_USD: f64 = 1.0;
/// JSON-RPC's code for an internal error, which a `fail` step answers with.
const INTERNAL_ERROR: i32 = -32603;
/// Vibe's code for a rate-limited model request, which a `rate_limit`
/// step answers with.
const RATE_LIMIT_ERROR: i32 = -31001;
const END_TURN: &str = "end_turn";
const CANCELLED: &str = "cancelled";
/// How often a `sleep` step looks for a cancel.
const SLEEP_SLICE: Duration = Duration::from_millis(50);
/// What a later prompt turn says without a script of its own.
const LATER_TEXT: &str = "Nothing more to do.";
const ALLOW: &str = "allow";
const REJECT: &str = "reject";
/// claude-agent-acp's request that puts a message into the running turn.
const STEER_METHOD: &str = "_session/steering";

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Step {
    Say(String),
    Execute {
        title: String,
        command: String,
    },
    Read {
        title: String,
        path: String,
        lines: Option<usize>,
    },
    Write {
        title: String,
        path: String,
        content: String,
    },
    Cost {
        usd: f64,
    },
    Task(String),
    Compact,
    Context {
        used: u64,
        size: u64,
    },
    Sleep(f64),
    Stop(String),
    Exit(i32),
    Fail(String),
    RateLimit(String),
    Finish(i32),
    Mcp {
        tool: String,
        arguments: Value,
    },
}

enum Mode {
    /// The first prompt turn's steps, and every later one's.
    Script(Vec<Step>, Vec<Step>),
    /// A script, played by an agent without HTTP MCP servers.
    NoMcp(Vec<Step>),
    Fs,
    Flood(usize),
    Grace,
    SlowInit,
}

fn parse_mode(args: &[String]) -> Result<Mode> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    Ok(match args.as_slice() {
        ["demo"] => {
            write_log();
            Mode::Script(demo_script()?, later_default())
        }
        ["script", file] => Mode::Script(read_script(file)?, later_default()),
        ["script", file, later] => Mode::Script(read_script(file)?, read_script(later)?),
        ["no-mcp", file] => Mode::NoMcp(read_script(file)?),
        ["fs"] => Mode::Fs,
        ["flood", n] => Mode::Flood(n.parse().with_context(|| format!("flood: bad count {n}"))?),
        ["grace"] => Mode::Grace,
        ["slow-init"] => Mode::SlowInit,
        _ => bail!(
            "usage: {NAME} demo | script FILE [LATER] | no-mcp FILE | fs | flood N | grace | \
             slow-init"
        ),
    })
}

/// The session `demo` plays: the user's own if there is one.
fn demo_script() -> Result<Vec<Step>> {
    let own = std::env::var_os("HOME").map(|home| Path::new(&home).join(DEMO_OVERRIDE));
    match own.as_deref().map(std::fs::read_to_string) {
        Some(Ok(text)) => parse_script(&text).with_context(|| format!("in ~/{DEMO_OVERRIDE}")),
        _ => parse_script(DEMO).context("in the built-in demo"),
    }
}

/// Writes a line to the log of its own that `demo` keeps, as a real
/// agent does, for `run` to collect. Only `demo`, which only `run`
/// starts, so that the tests' agents write nothing to the tester's home.
fn write_log() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let dir = Path::new(&home).join(FAKE_LOG_DIR);
    // A log that cannot be written is the run's to report missing.
    let _ = std::fs::create_dir_all(&dir).and_then(|()| {
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(LOG_FILE))?;
        writeln!(log, "{NAME} demo started")
    });
}

fn later_default() -> Vec<Step> {
    vec![Step::Say(LATER_TEXT.to_owned())]
}

fn read_script(file: &str) -> Result<Vec<Step>> {
    let text = std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?;
    parse_script(&text).with_context(|| format!("in {file}"))
}

fn parse_script(text: &str) -> Result<Vec<Step>> {
    Ok(serde_json::from_str(text)?)
}

/// The JSON-RPC connection to the client: stdout, and stdin read on a
/// thread so that waits can time out.
struct Conn {
    rx: Receiver<Value>,
    next_id: u64,
    /// The client sent session/cancel.
    cancelled: bool,
    /// A prompt turn is running.
    in_turn: bool,
    /// The ids of the prompts that arrived during it.
    queued: Vec<Value>,
    /// The status to exit with once the turn is answered (`finish`).
    finish: Option<i32>,
    /// The error the turn is answered with (a `fail` or `rate_limit`
    /// step): its code and message.
    fail: Option<(i32, String)>,
    /// The MCP servers `session/new` gave it.
    mcp_servers: Vec<Value>,
}

impl Conn {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                match serde_json::from_str(&line) {
                    Ok(v) => {
                        if tx.send(v).is_err() {
                            break;
                        }
                    }
                    Err(e) => eprintln!("{NAME}: ignoring a line that isn't JSON: {e}"),
                }
            }
        });
        Conn {
            rx,
            next_id: 1,
            cancelled: false,
            in_turn: false,
            queued: Vec::new(),
            finish: None,
            fail: None,
            mcp_servers: Vec::new(),
        }
    }

    fn send(&self, msg: Value) {
        let mut out = std::io::stdout().lock();
        // The client closing the pipe ends the run anyway.
        let _ = writeln!(out, "{msg}").and_then(|()| out.flush());
    }

    fn respond(&self, id: &Value, result: Value) {
        self.send(json!({"jsonrpc": "2.0", "id": id, "result": result}));
    }

    fn update(&self, update: Value) {
        self.send(json!({"jsonrpc": "2.0", "method": "session/update",
            "params": {"sessionId": SESSION, "update": update}}));
    }

    /// The next message, or None after TIMEOUT. Exits when the client
    /// closes stdin.
    fn recv(&mut self, timeout: Option<Duration>) -> Option<Value> {
        let msg = match timeout {
            None => self.rx.recv().ok(),
            Some(t) => match self.rx.recv_timeout(t) {
                Ok(m) => Some(m),
                Err(RecvTimeoutError::Timeout) => return None,
                Err(RecvTimeoutError::Disconnected) => None,
            },
        };
        let Some(msg) = msg else {
            std::process::exit(0);
        };
        if msg["method"] == "session/cancel" {
            self.cancelled = true;
        }
        if self.in_turn && msg["method"] == "session/prompt" {
            self.queued.push(msg["id"].clone());
        }
        // As claude-agent-acp answers one that opts out of starting a turn.
        if msg["method"] == STEER_METHOD {
            let outcome = if self.in_turn {
                "injected"
            } else {
                "promptRequired"
            };
            self.respond(&msg["id"], json!({"outcome": outcome}));
        }
        Some(msg)
    }

    /// Takes in what the client sent meanwhile (a cancel), without waiting.
    fn poll(&mut self) {
        while self.recv(Some(Duration::ZERO)).is_some() {}
    }

    /// Sends a request and waits for its response; other messages in
    /// between are only noted (a cancel).
    fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let end = Instant::now() + timeout;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            let msg = self
                .recv(Some(left))
                .ok_or_else(|| anyhow!("no response to {method} (request {id})"))?;
            if msg["id"] == id && msg.get("method").is_none() {
                return Ok(msg);
            }
        }
    }
}

fn model_options(current: &str) -> Value {
    json!([{
        "id": MODEL_OPTION, "name": "Model", "category": "model", "type": "select",
        "currentValue": current, "options": [{"value": current, "name": current}],
    }])
}

/// Serves requests until the client closes stdin, as a real agent does:
/// exiting after the prompt turn would race the client's cancel.
fn serve(conn: &mut Conn, mode: &Mode) -> Result<()> {
    let mut cwd = PathBuf::from(".");
    let mut model = DEFAULT_MODEL.to_owned();
    let mut turns = 0;
    loop {
        let Some(msg) = conn.recv(None) else {
            unreachable!("recv without a timeout exits at the end of stdin")
        };
        let id = msg["id"].clone();
        match msg["method"].as_str() {
            Some("initialize") => {
                if matches!(mode, Mode::SlowInit) {
                    continue;
                }
                let http = !matches!(mode, Mode::NoMcp(_));
                conn.respond(
                    &id,
                    json!({"protocolVersion": 1,
                        "agentCapabilities": {"mcpCapabilities": {"http": http}},
                        "agentInfo": {"name": NAME, "version": env!("CARGO_PKG_VERSION")}}),
                );
            }
            Some("session/new") => {
                if let Some(c) = msg["params"]["cwd"].as_str() {
                    cwd = PathBuf::from(c);
                }
                conn.mcp_servers = msg["params"]["mcpServers"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                conn.respond(
                    &id,
                    json!({"sessionId": SESSION, "configOptions": model_options(DEFAULT_MODEL)}),
                );
            }
            Some("session/set_config_option") => {
                let value = msg["params"]["value"].as_str();
                match (msg["params"]["configId"].as_str(), value) {
                    (Some(MODEL_OPTION), Some(IGNORED_MODEL)) => {}
                    (Some(MODEL_OPTION), Some(UNREPORTED_MODEL)) => {
                        conn.respond(&id, json!({"configOptions": []}));
                        continue;
                    }
                    (Some(MODEL_OPTION), Some(value)) => model = value.to_owned(),
                    (Some(UNLISTED_OPTION), Some(_)) => {}
                    _ => {
                        conn.send(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602,
                            "message": format!("{NAME} has no such option: {}", msg["params"])}}));
                        continue;
                    }
                }
                conn.respond(&id, json!({"configOptions": model_options(&model)}));
            }
            Some("session/prompt") => {
                conn.cancelled = false;
                conn.in_turn = true;
                let stop = prompt(conn, mode, turns, &cwd)?;
                conn.in_turn = false;
                turns += 1;
                // The prompts taken during the turn end with it.
                for queued in std::mem::take(&mut conn.queued) {
                    conn.respond(&queued, json!({"stopReason": stop}));
                }
                match conn.fail.take() {
                    Some((code, message)) => conn.send(json!({"jsonrpc": "2.0", "id": id,
                        "error": {"code": code, "message": message}})),
                    None => conn.respond(&id, json!({"stopReason": stop})),
                }
                if let Some(status) = conn.finish {
                    std::process::exit(status);
                }
            }
            // Answered as it arrived.
            Some(STEER_METHOD) => {}
            // Notifications (a cancel before the prompt) need no answer.
            _ if id.is_null() => {}
            Some(other) => conn.send(json!({"jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": format!("{NAME} doesn't handle {other}")}})),
            None => {}
        }
    }
}

/// Runs prompt turn number TURN (from 0); returns its stop reason.
fn prompt(conn: &mut Conn, mode: &Mode, turn: usize, cwd: &Path) -> Result<String> {
    match mode {
        Mode::Script(..) | Mode::NoMcp(_) => {
            let steps = match mode {
                Mode::Script(first, _) | Mode::NoMcp(first) if turn == 0 => first,
                Mode::Script(_, later) => later,
                _ => &later_default(),
            };
            let home = std::env::var("HOME").unwrap_or_default();
            let fill = |s: &str| {
                s.replace("{cwd}", &cwd.to_string_lossy())
                    .replace("{home}", &home)
            };
            for (i, step) in steps.iter().enumerate() {
                conn.poll();
                if conn.cancelled && !matches!(step, Step::Stop(_)) {
                    return Ok(CANCELLED.to_owned());
                }
                match step {
                    Step::Stop(reason) => return Ok(reason.clone()),
                    Step::Finish(status) => {
                        conn.finish = Some(*status);
                        return Ok(END_TURN.to_owned());
                    }
                    Step::Fail(message) => conn.fail = Some((INTERNAL_ERROR, message.clone())),
                    Step::RateLimit(message) => {
                        conn.fail = Some((RATE_LIMIT_ERROR, message.clone()))
                    }
                    Step::Exit(status) => {
                        eprintln!("{NAME}: exiting with status {status}, as scripted");
                        std::process::exit(*status);
                    }
                    _ => play(conn, &format!("call-{i}"), step, cwd, &fill)?,
                }
            }
        }
        Mode::Fs => {
            for (method, params) in [
                (
                    "fs/read_text_file",
                    json!({"sessionId": SESSION, "path": "/etc/passwd"}),
                ),
                (
                    "terminal/create",
                    json!({"sessionId": SESSION, "command": "id"}),
                ),
                ("fs/read_text_file", json!({"path": "/etc/passwd"})),
            ] {
                conn.request(method, params, FS_TIMEOUT)?;
            }
        }
        Mode::Flood(n) => {
            let chunk = "x".repeat(1000);
            for _ in 0..*n {
                conn.update(json!({"sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": chunk}}));
            }
        }
        Mode::Grace => {
            conn.update(cost_update(GRACE_COST_USD));
            std::thread::sleep(GRACE_DELAY);
            let call =
                json!({"toolCallId": "t0", "kind": "execute", "rawInput": {"command": "true"}});
            ask_permission(conn, call)?;
        }
        Mode::SlowInit => unreachable!("never gets a session"),
    }
    let stop = if conn.cancelled { CANCELLED } else { END_TURN };
    Ok(stop.to_owned())
}

fn cost_update(usd: f64) -> Value {
    json!({"sessionUpdate": "usage_update", "used": 0, "size": 0,
        "cost": {"amount": usd, "currency": "USD"}})
}

/// Asks the client's permission for a tool call: whether it was granted.
fn ask_permission(conn: &mut Conn, call: Value) -> Result<bool> {
    let answer = conn.request(
        "session/request_permission",
        json!({"sessionId": SESSION, "toolCall": call, "options": [
            {"optionId": ALLOW, "name": "Allow", "kind": "allow_once"},
            {"optionId": REJECT, "name": "Reject", "kind": "reject_once"},
        ]}),
        ANSWER_TIMEOUT,
    )?;
    let outcome = &answer["result"]["outcome"];
    Ok(outcome["outcome"] == "selected" && outcome["optionId"] == ALLOW)
}

fn text_content(text: &str) -> Value {
    json!([{"type": "content", "content": {"type": "text", "text": text}}])
}

/// Plays one step as tool call ID.
fn play(
    conn: &mut Conn,
    id: &str,
    step: &Step,
    cwd: &Path,
    fill: &dyn Fn(&str) -> String,
) -> Result<()> {
    let (title, kind, input) = match step {
        Step::Say(text) => {
            conn.update(json!({"sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": text}}));
            return Ok(());
        }
        Step::Cost { usd } => {
            conn.update(cost_update(*usd));
            return Ok(());
        }
        Step::Task(description) => {
            conn.update(json!({"sessionUpdate": "tool_call", "toolCallId": id,
                "title": "task", "kind": "think", "status": "pending",
                "rawInput": {"description": description}}));
            conn.update(
                json!({"sessionUpdate": "tool_call_update", "toolCallId": id,
                "title": description, "status": "completed"}),
            );
            return Ok(());
        }
        Step::Compact => {
            conn.update(json!({"sessionUpdate": "tool_call", "toolCallId": id,
                "title": "Compacting context", "kind": "think", "status": "in_progress"}));
            conn.update(
                json!({"sessionUpdate": "tool_call_update", "toolCallId": id,
                "title": "Context compacted", "kind": "think", "status": "completed"}),
            );
            return Ok(());
        }
        Step::Context { used, size } => {
            conn.update(json!({"sessionUpdate": "usage_update", "used": used, "size": size}));
            return Ok(());
        }
        Step::Mcp { tool, arguments } => {
            let text = match conn.mcp_servers.iter().find(|s| s["type"] == "http") {
                Some(server) => mcp_call(server, tool, arguments)
                    .unwrap_or_else(|e| format!("MCP failed: {e:#}")),
                None => "MCP failed: no HTTP server was given".to_owned(),
            };
            conn.update(json!({"sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": text}}));
            return Ok(());
        }
        Step::Sleep(secs) => {
            let end = Instant::now() + Duration::try_from_secs_f64(*secs)?;
            while !conn.cancelled {
                let left = end.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                conn.recv(Some(left.min(SLEEP_SLICE)));
            }
            return Ok(());
        }
        // Ends the turn or the process: `prompt` takes these itself.
        Step::Stop(_) | Step::Exit(_) | Step::Fail(_) | Step::RateLimit(_) | Step::Finish(_) => {
            return Ok(());
        }
        Step::Execute { title, command } => (title, "execute", json!({"command": fill(command)})),
        Step::Read { title, path, lines } => {
            (title, "read", json!({"path": fill(path), "lines": lines}))
        }
        Step::Write {
            title,
            path,
            content,
        } => (
            title,
            "edit",
            json!({"path": fill(path), "content": fill(content)}),
        ),
    };
    let call = json!({"toolCallId": id, "title": title, "kind": kind, "rawInput": input});
    let mut update = call.clone();
    update["sessionUpdate"] = json!("tool_call");
    update["status"] = json!("pending");
    conn.update(update);
    if !ask_permission(conn, call)? {
        conn.update(
            json!({"sessionUpdate": "tool_call_update", "toolCallId": id,
            "status": "failed", "content": text_content("The client refused permission")}),
        );
        return Ok(());
    }
    conn.update(
        json!({"sessionUpdate": "tool_call_update", "toolCallId": id, "status": "in_progress"}),
    );
    let (ok, text, raw_output) = match step {
        Step::Execute { .. } => {
            let command = input["command"].as_str().unwrap_or_default();
            let home = std::env::var_os("HOME").map(PathBuf::from);
            let token = match home {
                Some(home) => github_token(&home, |path| std::fs::read_to_string(path))?,
                None => None,
            };
            let mut sh = Command::new("sh");
            sh.args(["-c", command]).current_dir(cwd);
            if let Some(token) = token {
                sh.env(GITHUB_TOKEN_VAR, token);
            }
            match sh.output() {
                Ok(out) => {
                    let code = out.status.code().unwrap_or(-1);
                    let (stdout, stderr) = (
                        String::from_utf8_lossy(&out.stdout),
                        String::from_utf8_lossy(&out.stderr),
                    );
                    // A failure's first line is what the log shows: its error.
                    let text = if code == 0 {
                        format!("{stdout}{stderr}")
                    } else {
                        format!("{stderr}{stdout}")
                    };
                    (code == 0, text, json!({"exit_code": code}))
                }
                Err(e) => (false, format!("running sh: {e}"), Value::Null),
            }
        }
        Step::Read { lines, .. } => {
            let path = input["path"].as_str().unwrap_or_default();
            match std::fs::read_to_string(path) {
                Ok(t) => {
                    let n = lines.unwrap_or(usize::MAX);
                    (
                        true,
                        t.lines().take(n).collect::<Vec<_>>().join("\n"),
                        Value::Null,
                    )
                }
                Err(e) => (false, format!("reading {path}: {e}"), Value::Null),
            }
        }
        Step::Write { .. } => {
            let path = input["path"].as_str().unwrap_or_default();
            let content = input["content"].as_str().unwrap_or_default();
            match std::fs::write(path, content) {
                Ok(()) => (true, format!("wrote {path}"), Value::Null),
                Err(e) => (false, format!("writing {path}: {e}"), Value::Null),
            }
        }
        Step::Say(_)
        | Step::Cost { .. }
        | Step::Task(_)
        | Step::Compact
        | Step::Context { .. }
        | Step::Sleep(_)
        | Step::Stop(_)
        | Step::Exit(_)
        | Step::Fail(_)
        | Step::RateLimit(_)
        | Step::Finish(_)
        | Step::Mcp { .. } => {
            unreachable!("handled above")
        }
    };
    let mut done = json!({"sessionUpdate": "tool_call_update", "toolCallId": id,
        "status": if ok { "completed" } else { "failed" }, "content": text_content(&text)});
    if !raw_output.is_null() {
        done["rawOutput"] = raw_output;
    }
    conn.update(done);
    Ok(())
}

/// Lists the tools of the MCP SERVER, as `session/new` named it, and
/// calls TOOL with ARGUMENTS: what it said, as one line.
fn mcp_call(server: &Value, tool: &str, arguments: &Value) -> Result<String> {
    let url = server["url"]
        .as_str()
        .context("an MCP server without a url")?;
    let http: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .proxy(None)
        .build()
        .into();
    let mut session: Option<String> = None;
    let mut post = |id: Option<u64>, method: &str, params: Value| -> Result<(u16, Value)> {
        let mut message = json!({"jsonrpc": "2.0", "method": method, "params": params});
        if let Some(id) = id {
            message["id"] = json!(id);
        }
        let mut request = http
            .post(url)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json");
        for header in server["headers"].as_array().into_iter().flatten() {
            if let (Some(name), Some(value)) = (header["name"].as_str(), header["value"].as_str()) {
                request = request.header(name, value);
            }
        }
        if let Some(id) = &session {
            request = request.header("mcp-session-id", id);
        }
        let mut answer = request.send(message.to_string())?;
        if let Some(id) = answer.headers().get("mcp-session-id") {
            session = Some(id.to_str()?.to_owned());
        }
        let status = answer.status().as_u16();
        let text = answer.body_mut().read_to_string()?;
        // The answer as JSON, or the last event of a stream.
        let json = text
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .next_back()
            .unwrap_or(&text);
        Ok((
            status,
            serde_json::from_str(json.trim()).unwrap_or(json!(text)),
        ))
    };
    let init = json!({"protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": NAME, "version": env!("CARGO_PKG_VERSION")}});
    post(Some(1), "initialize", init)?;
    post(None, "notifications/initialized", json!({}))?;
    let (_, list) = post(Some(2), "tools/list", json!({}))?;
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    let (status, called) = post(
        Some(3),
        "tools/call",
        json!({"name": tool, "arguments": arguments}),
    )?;
    let said = called["result"]["content"][0]["text"]
        .as_str()
        .map_or_else(|| called.to_string(), str::to_owned);
    Ok(format!(
        "MCP tools: {}; {tool}: HTTP {status}: {said}",
        names.join(", ")
    ))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = parse_mode(&args).and_then(|mode| serve(&mut Conn::new(), &mode));
    if let Err(e) = r {
        eprintln!("{NAME}: error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_parses() {
        let steps = parse_script(DEMO).unwrap();
        assert!(matches!(steps.first(), Some(Step::Say(_))));
        assert!(steps.iter().any(|s| matches!(s, Step::Cost { .. })));
    }

    #[test]
    fn modes() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for (argv, ok) in [
            (&["demo"][..], true),
            (&["fs"], true),
            (&["flood", "3"], true),
            (&["flood", "x"], false),
            (&["script"], false),
            (&["script", "/nonexistent"], false),
            (&["nope"], false),
            (&[], false),
        ] {
            assert_eq!(parse_mode(&args(argv)).is_ok(), ok, "{argv:?}");
        }
        let bad = r#"[{"say": "x"}, {"execute": {"command": "true"}}]"#;
        assert!(parse_script(bad).is_err());
        assert_eq!(
            parse_script(
                r#"[{"sleep": 0.5}, {"stop": "refusal"}, {"exit": 7}, {"fail": "x"},
                    {"rate_limit": "y"}, {"finish": 0}]"#
            )
            .unwrap(),
            [
                Step::Sleep(0.5),
                Step::Stop("refusal".to_owned()),
                Step::Exit(7),
                Step::Fail("x".to_owned()),
                Step::RateLimit("y".to_owned()),
                Step::Finish(0)
            ]
        );
    }
}
