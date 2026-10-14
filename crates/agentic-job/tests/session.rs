//! The session against the scripted fake agent (src/bin/fake-agent.rs): a
//! whole session through the permission policy and into its transcript,
//! the limits, the exit states, and protocol behavior the real agents
//! don't readily show. The old tree's `harness/tests/fake_agent.rs`.
//!
//! With `AGENTIC_JOB_TEST_SANDBOX_USER` set to a user this one can become
//! with `sudo run0`, `nothing_survives_the_session` runs the agent as that
//! user, as a real run does. CI does (the `session-sandbox` job); the
//! agent's binary must then be where that user can run it, named by
//! `AGENTIC_JOB_TEST_FAKE_AGENT`.

// clippy.toml lets test functions unwrap, but not the helpers they share,
// where a panic is just as much the test's failure.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentic_job::exit::Exit;
use agentic_job::session::bridge::{self, Bridge, Relay};
use agentic_job::session::digest::Digest;
use agentic_job::session::{self, Clients, Launch, Limits, Options, Policy, Record};
use serde_json::{Value, json};
use tokio::sync::watch;

const FAKE_AGENT: &str = env!("CARGO_BIN_EXE_fake-agent");
const SANDBOX_USER_VAR: &str = "AGENTIC_JOB_TEST_SANDBOX_USER";
const FAKE_AGENT_VAR: &str = "AGENTIC_JOB_TEST_FAKE_AGENT";
/// How often the test stands in for the proxy's count of model requests.
const REQUESTS_POLL: Duration = Duration::from_millis(50);
const MAX_REQUESTS: u64 = 100;

/// Where the condensed log of a session under test goes.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What a test asks of one session, beyond the agent's mode.
#[derive(Default)]
struct Setup<'a> {
    /// Whether the registry says the agent takes notices during a turn.
    no_notices: bool,
    files: &'a [(&'a str, &'a str)],
    timeout_s: u64,
    budget_aic: Option<f64>,
    /// Cap the model requests at `MAX_REQUESTS`, counted in the file
    /// `requests`, which the agent's own script writes.
    count_requests: bool,
    max_tasks: Option<usize>,
    permissions: Option<&'a str>,
    launch: Launch,
    /// The agent's program, where it isn't the one cargo built.
    agent: Option<String>,
    /// A client at a relay on loopback, played by this function on its
    /// end of the connection, and how long the session waits for it.
    client: Option<(Play, Duration)>,
    /// Session config options set after the model.
    config_options: &'a [(&'a str, &'a str)],
    /// The model the session selects.
    model: Option<&'a str>,
}

/// What a test's client does on its end of the relay.
type Play = fn(&mut Client);

/// A client's end of the relay: everything it was sent, hello first.
struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    got: Vec<Value>,
}

impl Client {
    fn send(&mut self, msg: Value) {
        writeln!(self.writer, "{msg}").unwrap();
    }

    /// The next message, or `None` once the session hung up.
    fn recv(&mut self) -> Option<Value> {
        let mut line = String::new();
        if self.reader.read_line(&mut line).unwrap() == 0 {
            return None;
        }
        let msg: Value = serde_json::from_str(&line).unwrap();
        self.got.push(msg.clone());
        Some(msg)
    }

    /// Sends a request and waits for its response, taking what comes
    /// before it.
    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let msg = self.recv().expect("the session hung up");
            if msg["id"] == id && msg["method"].is_null() {
                return msg;
            }
        }
    }
}

/// Listens on loopback for the session's bridge and plays CLIENT on what
/// connects; the thread returns everything the client was sent.
fn relay(play: Play) -> (String, std::thread::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let thread = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut client = Client {
            reader: BufReader::new(stream.try_clone().unwrap()),
            writer: stream,
            got: Vec::new(),
        };
        client.recv().expect("no hello");
        play(&mut client);
        client.got
    });
    (address, thread)
}

struct Run {
    exit: Exit,
    elapsed: Duration,
    /// The condensed log.
    log: String,
    /// What the relay's client was sent, hello first.
    client: Vec<Value>,
    /// harness.json
    result: Value,
    /// acp.jsonl
    records: Vec<Value>,
    dir: tempfile::TempDir,
}

impl Run {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The first request of METHOD the agent sent.
    fn request(&self, method: &str) -> &Value {
        self.records
            .iter()
            .find(|r| r["dir"] == "recv" && r["msg"]["method"] == method)
            .unwrap_or_else(|| panic!("the agent sent no {method}"))
    }

    /// The session's response to the agent's request ID.
    fn response_to(&self, id: &Value) -> &Value {
        self.records
            .iter()
            .find(|r| r["dir"] == "send" && &r["msg"]["id"] == id && r["msg"]["method"].is_null())
            .unwrap_or_else(|| panic!("no response to request {id}"))
    }

    /// What the transcript adds up to: what the run's summary is made of.
    fn digest(&self) -> Digest {
        let mut digest = Digest::new();
        for record in &self.records {
            let record: Record = serde_json::from_value(record.clone()).unwrap();
            if let Some(msg) = &record.msg {
                digest.feed(record.ts, record.dir, msg);
            }
        }
        digest
    }

    /// The labels of the budget notices the session sent, in order.
    fn notices(&self) -> Vec<&str> {
        self.records
            .iter()
            .filter(|x| x["dir"] == "send" && x["msg"]["method"] == "session/prompt")
            .filter_map(|x| x["msg"]["params"]["_meta"]["botHarness"]["notice"].as_str())
            .collect()
    }

    fn position(&self, pred: impl Fn(&Value) -> bool) -> usize {
        self.records.iter().position(pred).unwrap()
    }
}

/// Keeps the count in FILE current for the session, as `run` does from
/// the inference proxy's.
async fn count_requests(file: PathBuf, count: watch::Sender<Option<u64>>) {
    loop {
        let read = std::fs::read_to_string(&file)
            .ok()
            .and_then(|text| text.trim().parse().ok());
        if count.send(read).is_err() {
            return;
        }
        tokio::time::sleep(REQUESTS_POLL).await;
    }
}

/// Runs a session with the fake agent in MODE (its arguments), in a new
/// directory that holds `work/` (the agent's cwd), `out/` and the setup's
/// files. `{dir}` in any of them is that directory.
fn run(mode: &[&str], setup: Setup) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let here = dir.path().to_string_lossy().into_owned();
    let path = |name: &str| dir.path().join(name);
    let fill = |text: &str| text.replace("{dir}", &here);
    std::fs::create_dir(path("work")).unwrap();
    for (name, content) in setup.files {
        std::fs::write(path(name), fill(content)).unwrap();
    }
    if matches!(setup.launch, Launch::Sandbox { .. }) {
        // Another user's agent reads its script here and works in work/.
        for (name, mode) in [("", 0o755), ("work", 0o777)] {
            std::fs::set_permissions(path(name), std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }
    let program = setup.agent.as_deref().unwrap_or(FAKE_AGENT);
    let command: Vec<String> = std::iter::once(program)
        .chain(mode.iter().copied())
        .map(fill)
        .collect();
    let registry = format!(
        "[fake]\ncommand = {}\nnotices = {}\n",
        json!(command),
        !setup.no_notices
    );
    let log = Captured::default();
    let (count, requests) = watch::channel(None);
    let (bridge, client) = setup
        .client
        .map(|(client, idle)| {
            let (address, thread) = relay(client);
            let bridge = Bridge {
                relay: Relay {
                    address,
                    audience: None,
                    idle,
                },
                hello: bridge::hello("test-run", None),
                redact: Arc::new(|text: &str| text.replace(SECRET, "[REDACTED]")),
            };
            (bridge, thread)
        })
        .unzip();
    let options = Options {
        name: "fake".to_owned(),
        agent: session::agents::parse(&registry, "fake").unwrap(),
        model: setup.model.map(str::to_owned),
        config_options: setup
            .config_options
            .iter()
            .map(|(id, value)| ((*id).to_owned(), (*value).to_owned()))
            .collect(),
        cwd: path("work"),
        prompt: "Do the fake task.\n".to_owned(),
        out: path("out"),
        permissions: setup.permissions.map_or_else(Policy::allow_all, |text| {
            Policy::parse(&fill(text)).unwrap()
        }),
        limits: Limits {
            timeout_s: setup.timeout_s,
            budget_aic: setup.budget_aic,
            max_requests: setup.count_requests.then_some(MAX_REQUESTS),
            max_tasks: setup.max_tasks,
        },
        requests: setup.count_requests.then_some(requests),
        launch: setup.launch,
        clients: Clients::none(),
        bridge,
        log: Box::new(log.clone()),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let start = Instant::now();
    let returned = runtime.block_on(async {
        let counter = tokio::spawn(count_requests(path("requests"), count));
        let returned = session::run(options).await;
        counter.abort();
        returned
    });
    let elapsed = start.elapsed();
    let returned = returned.unwrap_or_else(|e| panic!("the session could not be run: {e:#}"));
    let read = |name: &str| std::fs::read_to_string(path("out").join(name)).unwrap();
    let result: Value = serde_json::from_str(&read(session::RESULT_FILE)).unwrap();
    assert_eq!(result["result"], returned.result.as_str());
    assert_eq!(result["schema"], session::RESULT_SCHEMA);
    let records = read(session::ACP_LOG)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let log = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let client = client.map_or_else(Vec::new, |thread| thread.join().unwrap());
    Run {
        exit: returned.result.exit(),
        elapsed,
        log,
        client,
        result,
        records,
        dir,
    }
}

/// The exit status a run with this session ends with, and its result.
fn assert_result(r: &Run, status: u8, result: &str) {
    assert_eq!(
        (r.exit.code(), r.result["result"].as_str()),
        (status, Some(result)),
        "{:#}\n{}",
        r.result,
        r.log
    );
}

const SCRIPT_MODE: &[&str] = &["script", "{dir}/script.json"];
const SCRIPT_AND_LATER: &[&str] = &["script", "{dir}/script.json", "{dir}/later.json"];

const SCRIPT: &str = r#"[
  {"say": "Scripted."},
  {"execute": {"title": "Bash", "command": "echo hi > hi.txt"}},
  {"execute": {"title": "Bash", "command": "echo failing >&2; exit 3"}},
  {"execute": {"title": "Bash", "command": "git push origin main"}},
  {"read": {"title": "Read", "path": "{cwd}/hi.txt"}},
  {"write": {"title": "Write", "path": "{cwd}/new.txt", "content": "new\n"}},
  {"write": {"title": "Write", "path": "/elsewhere/x", "content": "x"}},
  {"cost": {"usd": 0.5}},
  {"say": "Done."}
]"#;

const POLICY: &str = r#"default = "allow"

[[rule]]
name = "no-push"
decision = "deny"
kind = ["execute"]
command = '\bgit\b.*\bpush\b'

[[rule]]
name = "writes-in-work-only"
decision = "deny"
kind = ["edit"]
outside = ["{dir}/work"]
"#;

#[test]
fn scripted_session() {
    let r = run(
        SCRIPT_MODE,
        Setup {
            files: &[("script.json", SCRIPT)],
            timeout_s: 60,
            budget_aic: Some(100.0),
            permissions: Some(POLICY),
            config_options: &[("max_tokens", "8192")],
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    let work = r.path("work");
    assert_eq!(
        std::fs::read_to_string(work.join("new.txt")).unwrap(),
        "new\n"
    );
    assert_eq!(
        std::fs::read_to_string(work.join("hi.txt")).unwrap(),
        "hi\n"
    );
    assert!(!Path::new("/elsewhere/x").exists());
    let log: Vec<&str> = r.log.lines().collect();
    assert_eq!(
        &log[1..],
        [
            "» Scripted.",
            "▶ Bash: echo hi > hi.txt (exit 0, 0s)",
            "▶ Bash: echo failing >&2; exit 3 (exit 3, 0s)",
            "⚠ tool error: Bash: failing",
            "⛔ denied Bash: git push origin main (rule no-push)",
            "▶ Bash: git push origin main (error, 0s)",
            "⚠ tool error: Bash: The client refused permission",
            "▶ Read: hi.txt (ok, 0s)",
            "✎ Write new.txt",
            "⛔ denied Write: /elsewhere/x (rule writes-in-work-only)",
            "▶ Write: /elsewhere/x (error, 0s)",
            "⚠ tool error: Write: The client refused permission",
            "» Done.",
            "done: end_turn, 6 tool calls",
        ],
        "{}",
        r.log
    );
    assert!(log[0].starts_with("start: fake-agent "), "{}", log[0]);
    // The session says who it is, and asks for nothing it would have to
    // serve from outside the sandbox.
    let init = r
        .records
        .iter()
        .find(|x| x["dir"] == "send" && x["msg"]["method"] == "initialize")
        .unwrap();
    assert_eq!(init["msg"]["params"]["clientInfo"]["name"], "agentic-job");
    // A session option is set before the prompt, and is not the model.
    let set = |x: &Value| x["dir"] == "send" && x["msg"]["method"] == "session/set_config_option";
    let option = r.records.iter().position(set).unwrap();
    assert_eq!(
        r.records[option]["msg"]["params"],
        json!({"sessionId": "fake-session", "configId": "max_tokens", "value": "8192"})
    );
    let prompt = r
        .records
        .iter()
        .position(|x| x["dir"] == "send" && x["msg"]["method"] == "session/prompt")
        .unwrap();
    assert!(option < prompt);
    // What the summary is made of.
    let digest = r.digest();
    assert_eq!(digest.stop_reason.as_deref(), Some("end_turn"));
    assert_eq!(digest.model.as_deref(), Some("fake"));
    assert_eq!(digest.cost_usd, Some(0.5));
    assert_eq!(digest.allowed, 4);
    // (calls, of which failed)
    let tally = |name: &str| {
        let calls = digest.calls.iter().filter(|c| c.display_name() == name);
        let errors: Vec<bool> = calls.map(|c| c.error == Some(true)).collect();
        (
            errors.len(),
            errors.iter().filter(|failed| **failed).count(),
        )
    };
    assert_eq!(
        [tally("Bash"), tally("Read"), tally("Write")],
        [(3, 2), (1, 0), (2, 1)]
    );
    let rules: Vec<_> = digest
        .denied
        .iter()
        .map(|d| d.rule.as_deref().unwrap())
        .collect();
    assert_eq!(rules, ["no-push", "writes-in-work-only"]);
    // Every decision is in the transcript with the rule that made it.
    let push = r
        .records
        .iter()
        .filter(|x| x["dir"] == "recv" && x["msg"]["method"] == "session/request_permission")
        .find(|x| x["msg"]["params"]["toolCall"]["rawInput"]["command"] == "git push origin main")
        .unwrap();
    let answer = &r.response_to(&push["msg"]["id"])["msg"]["result"];
    assert_eq!(
        answer["_meta"]["botHarness"],
        json!({"decision": "deny", "rule": "no-push"})
    );
    assert_eq!(
        std::fs::read_to_string(r.path("out/agent-stderr.log")).unwrap(),
        ""
    );
}

/// The session runs only if the agent reports, after selecting it, the
/// model it was asked for (#562).
#[test]
fn selected_model() {
    for (model, refusal) in [
        ("m1", None),
        (
            "ignored",
            Some("the agent runs fake, not the requested model ignored"),
        ),
        (
            "unreported",
            Some("the agent runs an unreported model, not the requested model unreported"),
        ),
    ] {
        let (status, result, prompted) = match refusal {
            None => (0, "success", true),
            Some(_) => (1, "failure", false),
        };
        let r = run(
            &["demo"],
            Setup {
                timeout_s: 60,
                model: Some(model),
                ..Setup::default()
            },
        );
        assert_result(&r, status, result);
        let sent = |method: &str| {
            r.records
                .iter()
                .any(|x| x["dir"] == "send" && x["msg"]["method"] == method)
        };
        assert_eq!(sent("session/prompt"), prompted, "{model}");
        if let Some(refusal) = refusal {
            let message = r.result["message"].as_str().unwrap();
            assert!(message.contains(refusal), "{message}");
        }
    }
}

/// The cost the agent reports goes over the budget: the session stops at
/// once, with no hand-back, and the next tool call asks permission after
/// the session was cancelled.
const OVER_BUDGET: &str = r#"[
  {"cost": {"usd": 0.5}},
  {"execute": {"title": "Bash", "command": "touch after"}},
  {"say": "Not reached."}
]"#;

#[test]
fn reported_cost_over_budget() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[
                ("script.json", OVER_BUDGET),
                ("later.json", r#"[{"say": "Handed back."}]"#),
            ],
            timeout_s: 60,
            budget_aic: Some(10.0),
            ..Setup::default()
        },
    );
    assert_result(&r, 3, "budget");
    assert!(
        r.log.contains("⚠ over budget: spent 50.0 of 10 AIC"),
        "{}",
        r.log
    );
    assert!(!r.path("work/after").exists());
    assert!(!r.log.contains("Not reached"), "{}", r.log);
    // Spending is not handed back from: the money is gone already.
    assert_eq!(r.notices(), Vec::<&str>::new());
    assert_eq!(r.result["handed_back"], false);
    assert_eq!(
        r.result["message"],
        "over budget: spent 50.0 of 10 AIC; cancelled"
    );
    assert_eq!(r.digest().stop_reason.as_deref(), Some("cancelled"));
    assert!(r.elapsed < Duration::from_secs(30), "took {:?}", r.elapsed);
}

/// The reply that crosses the budget is the turn's last: the agent's
/// answer to the cancel is that its turn had ended, so its work stands
/// and the overrun is only a warning.
#[test]
fn reported_cost_over_budget_after_the_turn_ended() {
    let r = run(
        &["script", "{dir}/script.json"],
        Setup {
            files: &[(
                "script.json",
                r#"[{"cost": {"usd": 0.5}}, {"sleep": 20}, {"stop": "end_turn"}]"#,
            )],
            timeout_s: 60,
            budget_aic: Some(10.0),
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    let message = "over budget: spent 50.0 of 10 AIC; the agent had already ended its turn";
    assert_eq!(r.result["message"], message);
    assert!(r.log.contains(&format!("⚠ {message}")), "{}", r.log);
    assert_eq!(r.result["stop_reason"], "end_turn");
    assert_eq!(r.result["handed_back"], false);
    // The cancel cut the sleep short.
    assert!(r.elapsed < Duration::from_secs(15), "took {:?}", r.elapsed);
}

#[test]
fn unadvertised_requests_are_refused() {
    // Each would hang for the fake agent's 5s if left unanswered.
    let r = run(
        &["fs"],
        Setup {
            timeout_s: 60,
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    let requests: Vec<&Value> = r
        .records
        .iter()
        .filter(|x| {
            x["dir"] == "recv"
                && x["msg"]["method"]
                    .as_str()
                    .is_some_and(|m| m.starts_with("fs/") || m.starts_with("terminal/"))
        })
        .collect();
    assert_eq!(requests.len(), 3);
    for req in requests {
        let id = &req["msg"]["id"];
        assert_eq!(
            r.response_to(id)["msg"]["error"]["code"],
            -32601,
            "request {id}"
        );
    }
    assert!(r.elapsed < Duration::from_secs(5), "took {:?}", r.elapsed);
}

#[test]
fn update_flood() {
    // A smoke test: unhandled, these piled up in the SDK's retry queue,
    // which shows in memory (about 1 GB for 200k), not in the result.
    let r = run(
        &["flood", "20000"],
        Setup {
            timeout_s: 120,
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    assert!(r.records.len() > 20000);
}

#[test]
fn permission_after_cancel() {
    let r = run(
        &["grace"],
        Setup {
            timeout_s: 60,
            budget_aic: Some(10.0),
            ..Setup::default()
        },
    );
    assert_result(&r, 3, "budget");
    let request = r.request("session/request_permission");
    let answer = &r.response_to(&request["msg"]["id"])["msg"]["result"];
    assert_eq!(answer["outcome"]["outcome"], "cancelled", "{answer}");
    assert_eq!(answer["_meta"]["botHarness"]["decision"], "cancelled");
    // The cancel went out before the request came in.
    let cancel = r.position(|x| x["msg"]["method"] == "session/cancel");
    let asked = r.position(|x| std::ptr::eq(x, request));
    assert!(cancel < asked);
}

#[test]
fn timeout_before_the_session() {
    let r = run(
        &["slow-init"],
        Setup {
            timeout_s: 2,
            ..Setup::default()
        },
    );
    assert_result(&r, 124, "timeout");
    assert!(r.elapsed < Duration::from_secs(10), "took {:?}", r.elapsed);
}

/// An agent that answers its turn and exits, without waiting for its
/// standard input to close, is done: its exit must not race its answer.
#[test]
fn an_agent_that_exits_when_done() {
    // A race does not lose every time.
    for attempt in 0..5 {
        let r = run(
            SCRIPT_MODE,
            Setup {
                files: &[("script.json", r#"[{"say": "Done."}, {"finish": 0}]"#)],
                timeout_s: 60,
                ..Setup::default()
            },
        );
        assert_result(&r, 0, "success");
        assert_eq!(r.result["message"], Value::Null, "attempt {attempt}");
        assert!(r.elapsed < Duration::from_secs(30), "took {:?}", r.elapsed);
    }
}

/// A cap on model requests with nothing counting them would be no cap:
/// the session is not run at all.
#[test]
fn a_cap_nothing_counts_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let options = Options {
        name: "fake".to_owned(),
        agent: session::agents::builtin("fake").unwrap(),
        model: None,
        config_options: Vec::new(),
        cwd: dir.path().to_owned(),
        prompt: String::new(),
        out: dir.path().join("out"),
        permissions: Policy::allow_all(),
        limits: Limits {
            timeout_s: 60,
            max_requests: Some(MAX_REQUESTS),
            ..Limits::default()
        },
        requests: None,
        launch: Launch::Direct,
        clients: Clients::none(),
        bridge: None,
        log: Box::new(std::io::sink()),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = runtime.block_on(session::run(options)).unwrap_err();
    assert!(
        format!("{err:#}").contains("nothing that counts"),
        "{err:#}"
    );
    assert!(!dir.path().join("out").exists());
}

/// Exit state 1: every way an agent fails on its own.
#[test]
fn agent_failures() {
    struct Case {
        name: &'static str,
        script: &'static str,
        /// A program to run in place of the fake agent.
        agent: Option<&'static str>,
        config_options: &'static [(&'static str, &'static str)],
        result: &'static str,
        message: &'static [&'static str],
    }
    let cases = [
        Case {
            name: "the agent ends its turn with something other than done",
            script: r#"[{"say": "No."}, {"stop": "refusal"}]"#,
            agent: None,
            config_options: &[],
            result: "failure",
            message: &["the agent stopped: refusal"],
        },
        Case {
            name: "the agent reports a cancel nobody asked for",
            script: r#"[{"stop": "cancelled"}]"#,
            agent: None,
            config_options: &[],
            result: "cancelled",
            message: &["the agent stopped: cancelled"],
        },
        Case {
            name: "the agent exits in the middle of its turn",
            script: r#"[{"say": "Going."}, {"exit": 7}, {"say": "Not reached."}]"#,
            agent: None,
            config_options: &[],
            result: "failure",
            // Its status and what it last wrote to standard error.
            message: &["the agent exited", "exit status: 7", "as scripted"],
        },
        Case {
            name: "the agent cannot be started",
            script: "[]",
            agent: Some("/nonexistent/agent"),
            config_options: &[],
            result: "failure",
            message: &["the agent could not be started", "/nonexistent/agent"],
        },
        Case {
            name: "the agent refuses a session option",
            script: r#"[{"say": "Not reached."}]"#,
            agent: None,
            config_options: &[("max_tokens", "8192"), ("nope", "1")],
            result: "failure",
            message: &["setting nope to 1 failed", "no such option"],
        },
    ];
    for c in cases {
        let name = c.name;
        let r = run(
            SCRIPT_MODE,
            Setup {
                files: &[("script.json", c.script)],
                timeout_s: 60,
                agent: c.agent.map(str::to_owned),
                config_options: c.config_options,
                ..Setup::default()
            },
        );
        assert_result(&r, 1, c.result);
        let message = r.result["message"].as_str().unwrap();
        for part in c.message {
            assert!(message.contains(part), "{name}: {message}");
        }
        assert_eq!(r.result["handed_back"], false, "{name}");
        assert!(!r.log.contains("Not reached"), "{name}: {}", r.log);
        // Well before the timeout: a dead agent is not waited for.
        assert!(
            r.elapsed < Duration::from_secs(30),
            "{name}: took {:?}",
            r.elapsed
        );
    }
}

/// A step that sets the count of model requests the session reads: here
/// the agent's own script writes it, where a real run has the proxy's.
fn use_requests(n: u64) -> String {
    format!(r#"{{"execute": {{"title": "Bash", "command": "echo {n} > ../requests"}}}}"#)
}

#[test]
fn notices_as_the_budget_goes() {
    let script = format!(
        r#"[{}, {{"sleep": 2}}, {}, {{"sleep": 2}}, {{"say": "Done."}}]"#,
        use_requests(60),
        use_requests(85)
    );
    let r = run(
        SCRIPT_MODE,
        Setup {
            files: &[("script.json", &script)],
            timeout_s: 60,
            count_requests: true,
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    assert_eq!(r.notices(), ["60%", "80%"]);
    let told =
        "⚠ notice to the agent: This run has used 60% of its budget (60 of 100 model requests).";
    assert!(r.log.contains(told), "{}", r.log);
    // The notices' own answers don't end the run early.
    assert!(r.log.contains("» Done."), "{}", r.log);
    assert_eq!(r.digest().notices, ["60%", "80%"]);
    assert_eq!(r.result["handed_back"], false);
    assert_eq!(r.result["limits"]["max_requests"], MAX_REQUESTS);
}

/// An agent that isn't known to queue a prompt behind its turn is sent
/// none during it, and is still interrupted to hand back.
#[test]
fn no_notices_for_an_agent_that_takes_none() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            no_notices: true,
            files: &[
                ("script.json", r#"[{"sleep": 60}, {"say": "Not reached."}]"#),
                ("later.json", r#"[{"say": "Handed back."}]"#),
            ],
            // A second to hand back in.
            timeout_s: 20,
            ..Setup::default()
        },
    );
    assert_result(&r, 124, "timeout");
    assert_eq!(r.notices(), ["hand back"]);
    assert_eq!(r.result["handed_back"], true);
    assert!(r.log.contains("» Handed back."), "{}", r.log);
}

/// A turn the session interrupts near a limit, and what the agent does in
/// the turn it then gets to hand back in.
#[test]
fn hand_back_near_a_limit() {
    const HAND_BACK: &str = r#"[
      {"write": {"title": "Write", "path": "{cwd}/partial.txt", "content": "partial\n"}},
      {"say": "Handed back."}
    ]"#;
    struct Case {
        name: &'static str,
        script: String,
        later: &'static str,
        timeout_s: u64,
        count_requests: bool,
        max_tasks: Option<usize>,
        status: u8,
        result: &'static str,
        message: &'static str,
        notices: &'static [&'static str],
        handed_back: bool,
    }
    let over_requests = format!(
        r#"[{}, {{"sleep": 60}}, {{"say": "Not reached."}}]"#,
        use_requests(95)
    );
    let task = r#"{"task": "Review the change"}"#;
    let cases = [
        Case {
            name: "model requests",
            script: over_requests.clone(),
            later: HAND_BACK,
            timeout_s: 60,
            count_requests: true,
            max_tasks: None,
            status: 3,
            result: "budget",
            message: "used 95 of 100 model requests; the agent handed back",
            notices: &["hand back"],
            handed_back: true,
        },
        Case {
            name: "an agent that goes on working is stopped at the end of its hand-back",
            script: over_requests,
            later: r#"[{"sleep": 60}, {"say": "Not reached."}]"#,
            // A second to hand back in.
            timeout_s: 20,
            count_requests: true,
            max_tasks: None,
            status: 3,
            result: "budget",
            message: "used 95 of 100 model requests; cancelled",
            notices: &["hand back"],
            handed_back: false,
        },
        Case {
            name: "subagent tasks",
            script: format!(
                r#"[{task}, {task}, {{"sleep": 1}}, {task}, {{"sleep": 60}}, {{"say": "Not reached."}}]"#
            ),
            later: HAND_BACK,
            timeout_s: 60,
            count_requests: false,
            max_tasks: Some(2),
            status: 3,
            result: "budget",
            message: "started more than 2 subagent tasks; the agent handed back",
            notices: &["last task", "hand back"],
            handed_back: true,
        },
        Case {
            name: "the timeout",
            script: r#"[{"sleep": 60}, {"say": "Not reached."}]"#.to_owned(),
            later: HAND_BACK,
            // A second to hand back in.
            timeout_s: 20,
            count_requests: false,
            max_tasks: None,
            status: 124,
            result: "timeout",
            message: "hit the timeout; the agent handed back",
            notices: &["60%", "80%", "hand back"],
            handed_back: true,
        },
    ];
    for c in cases {
        let name = c.name;
        let r = run(
            SCRIPT_AND_LATER,
            Setup {
                files: &[("script.json", &c.script), ("later.json", c.later)],
                timeout_s: c.timeout_s,
                count_requests: c.count_requests,
                max_tasks: c.max_tasks,
                ..Setup::default()
            },
        );
        assert_result(&r, c.status, c.result);
        assert_eq!(r.result["message"], c.message, "{name}");
        assert_eq!(r.result["handed_back"], c.handed_back, "{name}");
        assert_eq!(r.notices(), c.notices, "{name}");
        assert!(!r.log.contains("Not reached"), "{name}: {}", r.log);
        // Well before the sleeps end, and the timeout where it isn't the limit.
        assert!(
            r.elapsed < Duration::from_secs(30),
            "{name}: took {:?}",
            r.elapsed
        );
        // What the agent wrote while handing back is there to collect.
        assert_eq!(r.path("work/partial.txt").exists(), c.handed_back, "{name}");
        assert_eq!(
            r.log.contains("» Handed back."),
            c.handed_back,
            "{name}: {}",
            r.log
        );
        // The turn was cancelled before the agent was asked to hand back.
        let cancel = r.position(|x| x["msg"]["method"] == "session/cancel");
        let asked =
            r.position(|x| x["msg"]["params"]["_meta"]["botHarness"]["notice"] == "hand back");
        assert!(cancel < asked, "{name}");
        let digest = r.digest();
        assert_eq!(digest.notices, c.notices, "{name}");
        assert_eq!(digest.tasks > 2, c.max_tasks.is_some(), "{name}");
    }
}

/// The command that runs its arguments as USER in a login session of its
/// own, as `run` enters the sandbox (the old tree's `sandboxCommand`).
fn run0(user: &str, cwd: &Path) -> Vec<String> {
    [
        "sudo",
        "run0",
        "--pipe",
        "--no-ask-password",
        "--shell-prompt-prefix=",
        &format!("--user={user}"),
        "--property=CollectMode=inactive-or-failed",
        &format!("--chdir={}", cwd.display()),
        "--setenv=PATH=/usr/local/bin:/usr/bin:/bin",
        "--",
    ]
    .map(str::to_owned)
    .to_vec()
}

/// As the sandbox user where the environment names one, as a real run
/// does; otherwise as this one.
fn launch() -> Launch {
    match std::env::var(SANDBOX_USER_VAR) {
        // The agent works where the session tells it to; the wrapper only
        // needs somewhere that exists.
        Ok(user) => Launch::Sandbox {
            wrapper: run0(&user, Path::new("/")),
            user,
        },
        Err(_) => Launch::Direct,
    }
}

fn processes_of(user: &str) -> String {
    let out = Command::new("pgrep")
        .args(["-l", "-u", user])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A process the agent leaves behind does not outlive the session: one in
/// the background of a tool call, and one that left its session and
/// process group, which only killing the sandbox user's processes ends.
///
/// The second tool call waits until its process has left: `$!` is known
/// before the child has called setsid, and a session that ended in
/// between killed it with the group it was still in.
#[test]
fn nothing_survives_the_session() {
    const STRAYS: &str = r#"[
      {"execute": {"title": "Bash", "command": "sleep 600 >/dev/null 2>&1 </dev/null & echo $! > stray"}},
      {"execute": {"title": "Bash", "command": "setsid sleep 600 >/dev/null 2>&1 </dev/null & echo $! > escaped; for try in $(seq 200); do [ \"$(ps -o sid= -p $! | tr -d ' ')\" != \"$!\" ] || break; sleep 0.05; done; id -un > whoami"}},
      {"say": "Left two behind."}
    ]"#;
    let sandbox_user = std::env::var(SANDBOX_USER_VAR).ok();
    let r = run(
        SCRIPT_MODE,
        Setup {
            files: &[("script.json", STRAYS)],
            timeout_s: 60,
            launch: launch(),
            agent: std::env::var(FAKE_AGENT_VAR).ok(),
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    assert!(r.log.contains("» Left two behind."), "{}", r.log);
    let pid = |name: &str| -> u32 {
        let text = std::fs::read_to_string(r.path("work").join(name)).unwrap();
        text.trim().parse().unwrap()
    };
    let whoami = std::fs::read_to_string(r.path("work/whoami")).unwrap();
    assert!(
        !session::process::is_running(pid("stray")),
        "the background process survived"
    );
    match &sandbox_user {
        Some(user) => {
            assert_eq!(whoami.trim(), user, "the agent did not run as {user}");
            assert!(
                !session::process::is_running(pid("escaped")),
                "the process that left its session survived"
            );
            assert_eq!(processes_of(user), "", "processes of {user} survived");
        }
        // Without a sandbox user nothing holds a process that left the
        // agent's group: that is what the sandbox user is for, and why
        // the case above is no formality. Clean up.
        None => {
            let escaped = pid("escaped");
            assert!(
                session::process::is_running(escaped),
                "the process that left its session was killed with the group"
            );
            let _ = Command::new("kill")
                .args(["-KILL", &escaped.to_string()])
                .status();
        }
    }
}

/// What the agent says that the client must not see.
const SECRET: &str = "sekrit-value";
const LATER: &str = r#"[{"say": "Answered sekrit-value."}]"#;

fn text_prompt(sid: &Value, text: &str) -> Value {
    json!({"sessionId": sid, "prompt": [{"type": "text", "text": text}]})
}

/// The session's own turn, then a client at the relay: it attaches to the
/// session already running, is refused what the bridge does not serve,
/// and has a prompt answered with the run's secret replaced; when it
/// hangs up the session ends as done. Where the environment names a
/// sandbox user (the session-sandbox job), the agent runs as that user.
#[test]
fn a_client_talks_to_the_session() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[
                ("script.json", r#"[{"say": "Task done."}]"#),
                ("later.json", LATER),
            ],
            timeout_s: 60,
            launch: launch(),
            agent: std::env::var(FAKE_AGENT_VAR).ok(),
            client: Some((
                |client| {
                    let init = client.request(1, "initialize", json!({"protocolVersion": 1}));
                    assert_eq!(init["result"]["protocolVersion"], 1, "{init}");
                    let early = client.request(2, "session/prompt", text_prompt(&json!("x"), "hi"));
                    assert_eq!(early["error"]["code"], -32602, "{early}");
                    let new = client.request(
                        3,
                        "session/new",
                        json!({"cwd": "/", "mcpServers": [{"name": "x", "command": "/bin/sh", "args": [], "env": []}]}),
                    );
                    let sid = new["result"]["sessionId"].clone();
                    assert!(sid.is_string(), "{new}");
                    for method in ["session/load", "session/set_mode", "fs/read_text_file"] {
                        let refused = client.request(4, method, json!({"sessionId": sid}));
                        assert_eq!(refused["error"]["code"], -32601, "{method}: {refused}");
                    }
                    let other =
                        client.request(5, "session/prompt", text_prompt(&json!("other"), "hi"));
                    assert_eq!(other["error"]["code"], -32602, "{other}");
                    let bad = client.request(
                        6,
                        "session/prompt",
                        json!({"sessionId": sid, "prompt": "hi"}),
                    );
                    assert!(
                        bad["error"]["message"]
                            .as_str()
                            .unwrap()
                            .contains("content blocks"),
                        "{bad}"
                    );
                    let answer =
                        client.request(7, "session/prompt", text_prompt(&sid, "Hello, agent."));
                    assert_eq!(answer["result"]["stopReason"], "end_turn", "{answer}");
                },
                Duration::from_secs(60),
            )),
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    assert_eq!(r.result["message"], "the client left", "{}", r.log);
    let hello = &r.client[0];
    assert_eq!(
        (&hello["schema"], &hello["run"], &hello["token"]),
        (
            &json!(bridge::HELLO_SCHEMA),
            &json!("test-run"),
            &Value::Null
        )
    );
    let said: String = r
        .client
        .iter()
        .filter(|m| m["method"] == "session/update")
        .filter_map(|m| m["params"]["update"]["content"]["text"].as_str())
        .collect();
    assert!(said.contains("Answered [REDACTED]."), "{:#?}", r.client);
    assert!(!said.contains(SECRET));
    // The client's prompt went to the agent, and into the transcript,
    // after the task's.
    let prompts: Vec<&Value> = r
        .records
        .iter()
        .filter(|x| x["dir"] == "send" && x["msg"]["method"] == "session/prompt")
        .map(|x| &x["msg"]["params"]["prompt"][0]["text"])
        .collect();
    assert_eq!(prompts.len(), 2, "{prompts:?}");
    assert_eq!(prompts[1], "Hello, agent.");
    // The client's mcpServers went nowhere: the agent saw one session/new,
    // the session's own.
    let new: Vec<&Value> = r
        .records
        .iter()
        .filter(|x| x["dir"] == "send" && x["msg"]["method"] == "session/new")
        .collect();
    assert_eq!(new.len(), 1);
    assert_eq!(new[0]["msg"]["params"]["mcpServers"], json!([]));
}

#[test]
fn unsuccessful_client_turns_survive_disconnect_or_idle() {
    for (reason, code, outcome) in [
        ("max_turn_requests", 3, "budget"),
        ("not_an_acp_stop_reason", 1, "failure"),
    ] {
        for wait in [false, true] {
            let later = json!([{"stop": reason}]).to_string();
            let play: Play = if wait {
                |client| {
                    let sid =
                        client.request(1, "session/new", json!({}))["result"]["sessionId"].clone();
                    client.request(2, "session/prompt", text_prompt(&sid, "hi"));
                    while client.recv().is_some() {}
                }
            } else {
                |client| {
                    let sid =
                        client.request(1, "session/new", json!({}))["result"]["sessionId"].clone();
                    client.request(2, "session/prompt", text_prompt(&sid, "hi"));
                }
            };
            let r = run(
                SCRIPT_AND_LATER,
                Setup {
                    files: &[("script.json", "[]"), ("later.json", &later)],
                    timeout_s: 15,
                    client: Some((play, Duration::from_secs(1))),
                    ..Setup::default()
                },
            );
            assert_result(&r, code, outcome);
        }
    }
}

/// A client that leaves during its turn, while the agent runs a command
/// and so cannot answer the cancel: the turn never ended, so the session
/// fails rather than passing as done.
#[test]
fn a_client_leaving_an_unanswered_turn_fails() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[
                ("script.json", "[]"),
                (
                    "later.json",
                    r#"[{"execute": {"title": "Bash", "command": "sleep 45"}}]"#,
                ),
            ],
            timeout_s: 90,
            client: Some((
                |client| {
                    let sid =
                        client.request(1, "session/new", json!({}))["result"]["sessionId"].clone();
                    client.send(
                        json!({"jsonrpc": "2.0", "id": 2, "method": "session/prompt",
                                       "params": text_prompt(&sid, "hi")}),
                    );
                    while let Some(msg) = client.recv() {
                        if msg["params"]["update"]["status"] == "in_progress" {
                            break;
                        }
                    }
                },
                Duration::from_secs(60),
            )),
            ..Setup::default()
        },
    );
    assert_result(&r, 1, "failure");
    assert_eq!(
        r.result["message"], "the client left; the agent did not answer the cancellation",
        "{}",
        r.log
    );
}

#[test]
fn idle_messages_do_not_extend_the_deadline() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[("script.json", "[]"), ("later.json", LATER)],
            timeout_s: 15,
            client: Some((
                |client| {
                    let sid =
                        client.request(1, "session/new", json!({}))["result"]["sessionId"].clone();
                    // Keep invalid traffic arriving beyond the idle interval, but
                    // stop writing once the harness closes the connection.
                    for id in 2..22 {
                        std::thread::sleep(Duration::from_millis(100));
                        let msg = if id % 2 == 0 {
                            json!({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": sid}})
                        } else {
                            json!({"jsonrpc": "2.0", "id": id, "method": "session/prompt", "params": {"sessionId": sid, "prompt": [42]}})
                        };
                        if writeln!(client.writer, "{msg}").is_err() {
                            break;
                        }
                    }
                    while client.recv().is_some() {}
                },
                Duration::from_secs(1),
            )),
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    assert_eq!(r.result["message"], "no prompt from the client for 1s");
    assert!(r.elapsed < Duration::from_secs(3), "{:?}", r.elapsed);
}

/// A client that sends nothing: the session ends at the idle timeout, as
/// done, well within the run's own timeout.
#[test]
fn a_quiet_client_ends_the_session() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[("script.json", "[]"), ("later.json", LATER)],
            timeout_s: 60,
            client: Some((
                |client| while client.recv().is_some() {},
                Duration::from_secs(1),
            )),
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    assert_eq!(r.result["message"], "no prompt from the client for 1s");
    assert!(r.elapsed < Duration::from_secs(30), "{:?}", r.elapsed);
    assert!(
        r.log.contains("waiting for the client's prompt"),
        "{}",
        r.log
    );
}

/// The run's limits hold while the session waits: at the timeout it is
/// stopped as for a task run, whatever the idle timeout says.
#[test]
fn the_timeout_holds_while_waiting_for_the_client() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[("script.json", "[]"), ("later.json", LATER)],
            timeout_s: 2,
            client: Some((
                |client| while client.recv().is_some() {},
                Duration::from_secs(60),
            )),
            ..Setup::default()
        },
    );
    assert_result(&r, 124, "timeout");
}

/// A relay that cannot be reached is a session that is not run.
#[test]
fn an_unreachable_relay_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    // A port that was free a moment ago.
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string();
    let options = Options {
        name: "fake".to_owned(),
        agent: session::agents::builtin("fake").unwrap(),
        model: None,
        config_options: Vec::new(),
        cwd: dir.path().to_owned(),
        prompt: "Do the fake task.\n".to_owned(),
        out: dir.path().join("out"),
        permissions: Policy::allow_all(),
        limits: Limits {
            timeout_s: 60,
            ..Limits::default()
        },
        requests: None,
        launch: Launch::Direct,
        clients: Clients::none(),
        bridge: Some(Bridge {
            relay: Relay {
                address,
                audience: None,
                idle: Duration::from_secs(60),
            },
            hello: bridge::hello("test-run", None),
            redact: Arc::new(str::to_owned),
        }),
        log: Box::new(std::io::sink()),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = runtime.block_on(session::run(options)).unwrap_err();
    assert!(
        format!("{err:#}").contains("connecting to the relay"),
        "{err:#}"
    );
}

/// A client's cancel reaches the agent's turn, and a second prompt while
/// the turn runs is refused rather than queued behind it.
#[test]
fn a_client_cancels_its_turn() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[
                ("script.json", "[]"),
                ("later.json", r#"[{"sleep": 30}, {"say": "Too late."}]"#),
            ],
            timeout_s: 60,
            client: Some((
                |client| {
                    client.request(1, "initialize", json!({"protocolVersion": 1}));
                    let new =
                        client.request(2, "session/new", json!({"cwd": "/", "mcpServers": []}));
                    let sid = new["result"]["sessionId"].clone();
                    let prompt = |id, text| {
                        json!({"jsonrpc": "2.0", "id": id, "method": "session/prompt",
                               "params": text_prompt(&sid, text)})
                    };
                    client.send(prompt(3, "Take your time."));
                    let second =
                        client.request(4, "session/prompt", text_prompt(&sid, "And this."));
                    assert!(
                        second["error"]["message"]
                            .as_str()
                            .unwrap()
                            .contains("a turn is running"),
                        "{second}"
                    );
                    client.send(json!({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": sid}}));
                    let answer = loop {
                        let msg = client.recv().expect("the session hung up");
                        if msg["id"] == 3 {
                            break msg;
                        }
                    };
                    assert_eq!(answer["result"]["stopReason"], "cancelled", "{answer}");
                },
                Duration::from_secs(60),
            )),
            ..Setup::default()
        },
    );
    assert_result(&r, 1, "cancelled");
    assert!(r.elapsed < Duration::from_secs(30), "{:?}", r.elapsed);
    let cancels = r
        .records
        .iter()
        .filter(|x| x["dir"] == "send" && x["msg"]["method"] == "session/cancel")
        .count();
    assert_eq!(cancels, 1);
}

/// A client that attaches during the task's turn is treated as during its
/// own: its prompt is refused while the turn runs, its cancel ends the
/// turn, and the session is then the client's.
#[test]
fn a_client_cancels_the_tasks_turn() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[
                ("script.json", r#"[{"sleep": 30}, {"say": "Too late."}]"#),
                ("later.json", LATER),
            ],
            timeout_s: 60,
            client: Some((
                |client| {
                    client.request(1, "initialize", json!({"protocolVersion": 1}));
                    let new =
                        client.request(2, "session/new", json!({"cwd": "/", "mcpServers": []}));
                    let sid = new["result"]["sessionId"].clone();
                    let busy = client.request(3, "session/prompt", text_prompt(&sid, "Now."));
                    assert!(
                        busy["error"]["message"]
                            .as_str()
                            .unwrap()
                            .contains("a turn is running"),
                        "{busy}"
                    );
                    client.send(json!({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": sid}}));
                    // Refused until the cancelled turn has answered.
                    let answer = (4..100)
                        .map(|id| client.request(id, "session/prompt", text_prompt(&sid, "Hello.")))
                        .find(|answer| {
                            std::thread::sleep(Duration::from_millis(100));
                            answer["error"].is_null()
                        })
                        .unwrap();
                    assert_eq!(answer["result"]["stopReason"], "end_turn", "{answer}");
                },
                Duration::from_secs(60),
            )),
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    assert_eq!(r.result["message"], "the client left", "{}", r.log);
    assert!(r.elapsed < Duration::from_secs(30), "{:?}", r.elapsed);
    let said: String = r
        .client
        .iter()
        .filter_map(|m| m["params"]["update"]["content"]["text"].as_str())
        .collect();
    assert!(said.contains("Answered [REDACTED]."), "{said}");
    assert!(!said.contains("Too late."), "{said}");
    // The task's prompt and the one the client had answered; the refused
    // ones never reached the agent.
    let sent = |method: &str| {
        r.records
            .iter()
            .filter(|x| x["dir"] == "send" && x["msg"]["method"] == method)
            .count()
    };
    assert_eq!((sent("session/prompt"), sent("session/cancel")), (2, 1));
}

/// A client that sends requests and reads none of the answers: the
/// session stops reading once the answers fill the room for them, rather
/// than queueing them without end.
#[test]
fn a_client_that_reads_nothing_is_not_read() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[("script.json", "[]"), ("later.json", LATER)],
            timeout_s: 60,
            client: Some((
                |client| {
                    client
                        .writer
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    // Each answer repeats the request's 4 KiB id.
                    let request = json!({"jsonrpc": "2.0", "id": "i".repeat(4 << 10),
                                         "method": "initialize", "params": {}});
                    let batch = format!("{request}\n").repeat(256);
                    let mut sent = 0;
                    let err = loop {
                        assert!(sent < 256 << 20, "the session took {sent} bytes unread");
                        if let Err(e) = client.writer.write_all(batch.as_bytes()) {
                            break e;
                        }
                        sent += batch.len();
                    };
                    assert!(
                        matches!(
                            err.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ),
                        "{err}"
                    );
                },
                Duration::from_secs(60),
            )),
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    assert_eq!(r.result["message"], "the client left", "{}", r.log);
    assert!(r.elapsed < Duration::from_secs(30), "{:?}", r.elapsed);
}

/// An attached client that stops reading while the agent goes on talking
/// is hung up on once what it is owed fills the room for it; the task's
/// turn goes on.
#[test]
fn a_client_that_falls_behind_is_hung_up_on() {
    let say = json!({"say": "x".repeat(1 << 20)});
    let script = format!(
        "[{{\"sleep\": 1}}, {}]",
        vec![say.to_string(); 40].join(", ")
    );
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[("script.json", &script), ("later.json", LATER)],
            timeout_s: 60,
            client: Some((
                |client| {
                    client.request(1, "initialize", json!({"protocolVersion": 1}));
                    client.request(2, "session/new", json!({"cwd": "/", "mcpServers": []}));
                    std::thread::sleep(Duration::from_secs(5));
                    // A line may be cut short by the hang-up.
                    std::io::copy(&mut client.reader, &mut std::io::sink()).unwrap();
                },
                Duration::from_secs(60),
            )),
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    assert!(
        r.log.contains("the client left: the task's turn goes on"),
        "{}",
        r.log
    );
    assert!(r.elapsed < Duration::from_secs(30), "{:?}", r.elapsed);
}
