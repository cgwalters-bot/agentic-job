//! The session against the scripted fake agent (src/bin/fake-agent.rs): a
//! whole session through the permission policy and into its transcript,
//! the limits, the exit states, and protocol behavior the real agents
//! don't readily show. The old tree's `harness/tests/fake_agent.rs`.
//!
//! With `AGENTIC_JOB_TEST_SANDBOX_USER` set to a user this one can become
//! with `sudo run0`, `nothing_survives_the_session` runs the agent as that
//! user, as a run with `agent-user: sandbox` does; the agent's binary must
//! then be where that user can run it, named by
//! `AGENTIC_JOB_TEST_FAKE_AGENT`. CI covers that user through the reusable
//! workflow instead (the `e2e-sandbox` job), not with these tests.

// clippy.toml lets test functions unwrap, but not the helpers they share,
// where a panic is just as much the test's failure.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentic_job::exit::Exit;
use agentic_job::session::bridge::{self, Bridge, Listen};
use agentic_job::session::digest::Digest;
use agentic_job::session::steer::Watch;
use agentic_job::session::{self, Clients, Launch, Limits, Options, Policy, Record};
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{self, Message, WebSocket};

const FAKE_AGENT: &str = env!("CARGO_BIN_EXE_fake-agent");
const SANDBOX_USER_VAR: &str = "AGENTIC_JOB_TEST_SANDBOX_USER";
const FAKE_AGENT_VAR: &str = "AGENTIC_JOB_TEST_FAKE_AGENT";
/// How often the test stands in for the proxy's count of model requests.
const REQUESTS_POLL: Duration = Duration::from_millis(50);
const MAX_REQUESTS: u64 = 100;
/// The one operator, and the one page, a test's session lets in.
const OPERATOR: &str = "operator@github";
const ORIGIN: &str = "https://review.example.ts.net";
/// What `tailscale serve` passes on for the operator at that page.
const ADMITTED: Headers = &[(bridge::LOGIN_HEADER, OPERATOR), ("Origin", ORIGIN)];

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
    /// Whether it says the agent takes `_session/steering`.
    steering: bool,
    /// The run's item, watched for the agent.
    watch: Option<Watch>,
    files: &'a [(&'a str, &'a str)],
    timeout_s: u64,
    budget_aic: Option<f64>,
    /// Cap the model requests at `MAX_REQUESTS`, counted in the file
    /// `requests`, which the agent's own script writes.
    count_requests: bool,
    max_tasks: Option<usize>,
    max_repeats: Option<usize>,
    permissions: Option<&'a str>,
    launch: Launch,
    /// The agent's program, where it isn't the one cargo built.
    agent: Option<String>,
    /// A client on loopback, played by this function on its end of the
    /// connection, and how long the session waits for it.
    client: Option<(Play, Duration)>,
    /// Handshakes that client's thread makes first, each to be refused.
    refused_first: &'static [Headers],
    /// Session config options set after the model.
    config_options: &'a [(&'a str, &'a str)],
    /// The model the session selects.
    model: Option<&'a str>,
    /// The model it switches to on a lasting overload.
    fallback_model: Option<&'a str>,
    /// The registry's `provider-error` for the agent.
    provider_error: Option<&'a str>,
    /// The file, under the test's directory, whose existence is the
    /// output the run requires; none for a run that requires none.
    output: Option<&'a str>,
    /// What the session tells the agent after a compaction; none for
    /// nothing.
    restate: Option<&'a str>,
    /// The registry's `stall-timeout` for the agent, in seconds.
    stall_s: Option<u64>,
    /// The registry's `rate-limit-code` for the agent.
    rate_limit_code: Option<i32>,
}

/// What a test's client does on its end of the connection.
type Play = fn(&mut Client);

/// A handshake's headers, as `tailscale serve` would pass them on.
type Headers = &'static [(&'static str, &'static str)];

/// A client's end of the bridge: everything it was sent.
struct Client {
    socket: WebSocket<TcpStream>,
    /// Where the bridge listens.
    address: String,
    got: Vec<Value>,
}

impl Client {
    /// Connects to the bridge at ADDRESS with HEADERS; the HTTP status of
    /// the refusal otherwise.
    fn connect(address: &str, headers: Headers) -> Result<Self, u16> {
        let stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut request = format!("ws://{address}/").into_client_request().unwrap();
        for (name, value) in headers {
            request.headers_mut().append(*name, value.parse().unwrap());
        }
        match tungstenite::client(request, stream) {
            Ok((socket, _)) => Ok(Self {
                socket,
                address: address.to_owned(),
                got: Vec::new(),
            }),
            Err(tungstenite::HandshakeError::Failure(tungstenite::Error::Http(response))) => {
                Err(response.status().as_u16())
            }
            Err(e) => panic!("handshake: {e}"),
        }
    }

    /// Sends MSG; false once the session hung up.
    fn try_send(&mut self, msg: &Value) -> bool {
        self.socket.send(Message::text(msg.to_string())).is_ok()
    }

    fn send(&mut self, msg: Value) {
        assert!(self.try_send(&msg), "the session hung up");
    }

    /// The next message, or `None` once the session hung up.
    fn recv(&mut self) -> Option<Value> {
        loop {
            match self.socket.read() {
                Ok(Message::Text(text)) => {
                    let msg: Value = serde_json::from_str(&text).unwrap();
                    self.got.push(msg.clone());
                    return Some(msg);
                }
                Ok(Message::Close(_)) => return None,
                Ok(_) => {}
                Err(tungstenite::Error::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("nothing from the session within the read timeout")
                }
                Err(_) => return None,
            }
        }
    }

    /// Waits until the session SID takes a prompt: the task's turn may
    /// still run when the client attaches, and a prompt meanwhile is
    /// refused. A prompt that is no list of content blocks is refused
    /// without reaching the agent, as running or as malformed.
    fn wait_for_the_task(&mut self, sid: &Value) {
        let probe = json!({"sessionId": sid, "prompt": "not blocks"});
        for _ in 0..600 {
            let answer = self.request(u64::MAX, "session/prompt", probe.clone());
            let why = answer["error"]["message"].as_str().unwrap_or_default();
            if why.contains("content blocks") {
                return;
            }
            assert!(why.contains("a turn is running"), "{answer}");
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the task's turn did not end");
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

/// A bridge on a free loopback port, and the thread that, once the
/// session listens, makes the REFUSED handshakes, each of which must be
/// refused, and then plays CLIENT as the operator; the thread returns
/// everything the client was sent.
fn bridge_and_client(
    play: Play,
    idle: Duration,
    refused: &'static [Headers],
) -> (Bridge, std::thread::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let bridge = Bridge {
        listen: Listen {
            operators: vec![OPERATOR.to_owned()],
            origins: vec![ORIGIN.to_owned()],
            idle,
        },
        listener,
        redact: Arc::new(|text: &str| text.replace(SECRET, "[REDACTED]")),
    };
    let thread = std::thread::spawn(move || {
        for headers in refused {
            assert_eq!(
                Client::connect(&address, headers).err(),
                Some(403),
                "{headers:?}"
            );
        }
        let mut client = Client::connect(&address, ADMITTED).unwrap();
        play(&mut client);
        client.got
    });
    (bridge, thread)
}

struct Run {
    exit: Exit,
    elapsed: Duration,
    /// The condensed log.
    log: String,
    /// What the client was sent.
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
        // The fake agent creates the file after startup; until then the
        // registered count remains zero, as during a short broker outage.
        if read.is_some() && count.send(read).is_err() {
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
    let mut registry = format!(
        "[fake]\ncommand = {}\nnotices = {}\nsteering = {}\n",
        json!(command),
        !setup.no_notices,
        setup.steering
    );
    if let Some(prefix) = setup.provider_error {
        registry.push_str(&format!("provider-error = {}\n", json!(prefix)));
    }
    if let Some(secs) = setup.stall_s {
        registry.push_str(&format!("stall-timeout = {secs}\n"));
    }
    if let Some(code) = setup.rate_limit_code {
        registry.push_str(&format!("rate-limit-code = {code}\n"));
    }
    let log = Captured::default();
    // As in run's registration, accounting starts at a known count.
    let (count, requests) = watch::channel(Some(0));
    let (bridge, client) = setup
        .client
        .map(|(client, idle)| bridge_and_client(client, idle, setup.refused_first))
        .unzip();
    let options = Options {
        name: "fake".to_owned(),
        agent: session::agents::parse(&registry, "fake").unwrap(),
        model: setup.model.map(str::to_owned),
        fallback_model: setup.fallback_model.map(str::to_owned),
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
            max_repeats: setup.max_repeats,
        },
        requests: setup.count_requests.then_some(requests),
        launch: setup.launch,
        clients: Clients::none(),
        bridge,
        log: Box::new(log.clone()),
        output: setup.output.map(|name| {
            let file = path(name);
            Arc::new(move |_: &std::sync::atomic::AtomicBool| {
                (!file.exists()).then(|| "No output was left.".to_owned())
            }) as session::OutputCheck
        }),
        restate: setup.restate.map(|text| {
            let text = text.to_owned();
            Arc::new(move |_: &std::sync::atomic::AtomicBool| Some(text.clone()))
                as session::Restate
        }),
        mcp_servers: Vec::new(),
        watch: setup.watch,
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
        fallback_model: None,
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
        output: None,
        restate: None,
        mcp_servers: Vec::new(),
        watch: None,
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

/// The run's item on a stub of GitHub's issue and comments endpoints:
/// each answer carries an ETag, and a request whose `If-None-Match` is
/// the current one is answered 304.
#[derive(Clone, Default)]
struct StubItem(Arc<Mutex<ItemState>>);

#[derive(Default)]
struct ItemState {
    body: String,
    comments: Vec<Value>,
    /// Bumped by each change, for the ETags.
    version: u64,
    /// Requests answered, and of those 304.
    requests: usize,
    not_modified: usize,
}

const ITEM_URL: &str = "https://github.com/o/r/issues/7";

impl StubItem {
    /// Serves the item on loopback; the watch of it polls every 100ms.
    fn serve(&self, body: &str) -> Watch {
        self.0.lock().unwrap().body = body.to_owned();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let state = self.0.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if std::io::BufRead::read_line(&mut reader, &mut line).unwrap_or(0) == 0
                        || line == "\r\n"
                    {
                        break;
                    }
                    head.push_str(&line.to_ascii_lowercase());
                }
                let mut s = state.lock().unwrap();
                s.requests += 1;
                let comments = head.contains("/comments?");
                let etag = format!("\"{}-{}\"", comments, s.version);
                let (status, body) = if head.contains(&format!("if-none-match: {etag}")) {
                    s.not_modified += 1;
                    ("304 Not Modified", String::new())
                } else if comments {
                    ("200 OK", Value::from(s.comments.clone()).to_string())
                } else {
                    let issue = json!({"html_url": ITEM_URL, "body": s.body,
                        "user": {"login": "opener"}, "updated_at": "2026-10-16T10:00:00Z"});
                    ("200 OK", issue.to_string())
                };
                let _ = (&stream).write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nETag: {etag}\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        });
        Watch {
            item: "o/r#7".parse().unwrap(),
            api,
            token: "read-token".to_owned(),
            interval: Duration::from_millis(100),
        }
    }

    /// After AFTER, someone comments with TEXT; its link.
    fn comment(&self, after: Duration, id: u64, text: &str) -> String {
        let (state, text) = (self.0.clone(), text.to_owned());
        let url = format!("{ITEM_URL}#issuecomment-{id}");
        let link = url.clone();
        std::thread::spawn(move || {
            std::thread::sleep(after);
            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let mut s = state.lock().unwrap();
            s.comments
                .push(json!({"id": id, "html_url": link, "created_at": now,
                "body": text, "user": {"login": "someone"}}));
            s.version += 1;
        });
        url
    }

    /// After AFTER, the item's body becomes BODY.
    fn edit(&self, after: Duration, body: &str) {
        let (state, body) = (self.0.clone(), body.to_owned());
        std::thread::spawn(move || {
            std::thread::sleep(after);
            let mut s = state.lock().unwrap();
            s.body = body;
            s.version += 1;
        });
    }
}

/// What changes on the run's item reaches the agent during its turn, as
/// its agent takes a message then: steered into the turn for one that
/// takes `_session/steering` (claude-agent-acp, for which a prompt would
/// end the turn), queued as a notice for one that takes notices, and not
/// at all for one that takes neither. Each update is sent once, and the
/// turn goes on to its end.
#[test]
fn updates_of_the_item_reach_the_turn() {
    const SCRIPT: &str = r#"[{"sleep": 3}, {"say": "Done."}]"#;
    struct Case {
        name: &'static str,
        no_notices: bool,
        steering: bool,
        /// The method the updates are sent by, if any.
        method: Option<&'static str>,
    }
    let cases = [
        Case {
            name: "steered",
            no_notices: true,
            steering: true,
            method: Some("_session/steering"),
        },
        Case {
            name: "steered where it also takes notices",
            no_notices: false,
            steering: true,
            method: Some("_session/steering"),
        },
        Case {
            name: "as a notice",
            no_notices: false,
            steering: false,
            method: Some("session/prompt"),
        },
        Case {
            name: "not at all",
            no_notices: true,
            steering: false,
            method: None,
        },
    ];
    for c in cases {
        let name = c.name;
        let stub = StubItem::default();
        let watch = stub.serve("The brief.");
        let comment = stub.comment(Duration::from_millis(500), 41, "Also do Z.\nThanks");
        stub.edit(Duration::from_millis(1200), "The brief, edited.");
        let r = run(
            SCRIPT_MODE,
            Setup {
                no_notices: c.no_notices,
                steering: c.steering,
                watch: Some(watch),
                files: &[("script.json", SCRIPT)],
                timeout_s: 60,
                ..Setup::default()
            },
        );
        // The turn ends as its script does, after the updates came.
        assert_result(&r, 0, "success");
        assert_eq!(r.result["stop_reason"], "end_turn", "{name}");
        assert!(r.log.contains("» Done."), "{name}: {}", r.log);
        let sent: Vec<&Value> = r
            .records
            .iter()
            .filter(|x| x["dir"] == "send")
            .map(|x| &x["msg"])
            .filter(|m| m["params"]["_meta"]["botHarness"]["notice"] == "update")
            .collect();
        let task_end =
            r.position(|x| x["dir"] == "recv" && x["msg"]["result"]["stopReason"] == "end_turn");
        let Some(method) = c.method else {
            assert!(sent.is_empty(), "{name}: {sent:?}");
            let not = "not sent (the agent takes no message during its turn)";
            assert_eq!(r.log.matches(not).count(), 2, "{name}: {}", r.log);
            assert!(r.digest().updates.is_empty(), "{name}");
            continue;
        };
        let urls: Vec<&str> = sent
            .iter()
            .map(|m| m["params"]["_meta"]["botHarness"]["url"].as_str().unwrap())
            .collect();
        // The comment, then the body's edit, each once.
        assert_eq!(urls, [comment.as_str(), ITEM_URL], "{name}");
        for m in &sent {
            assert_eq!(m["method"], method, "{name}");
            let at = r.position(|x| x["dir"] == "send" && x["msg"]["id"] == m["id"]);
            assert!(at < task_end, "{name}: sent after the turn ended");
        }
        let text = |i: usize| sent[i]["params"]["prompt"][0]["text"].as_str().unwrap();
        assert!(
            text(0).starts_with(&format!("[item update] New input on {ITEM_URL}, 20"))
                && text(0).contains(&format!("a comment by @someone, {comment}."))
                && text(0).ends_with("\n\n> Also do Z.\n> Thanks"),
            "{name}: {}",
            text(0)
        );
        assert!(
            text(1).contains("an edit of its body (the item is by @opener;")
                && text(1).ends_with("\n\n> The brief, edited."),
            "{name}: {}",
            text(1)
        );
        if method == "_session/steering" {
            for m in &sent {
                assert_eq!(
                    m["params"]["_meta"]["steering"]["idleBehavior"], "promptRequired",
                    "{name}"
                );
                let answer = r.position(|x| x["dir"] == "recv" && x["msg"]["id"] == m["id"]);
                assert_eq!(r.records[answer]["msg"]["result"]["outcome"], "injected");
            }
            // Only the task was a prompt: nothing that would end its turn.
            let prompts = r
                .records
                .iter()
                .filter(|x| x["dir"] == "send" && x["msg"]["method"] == "session/prompt")
                .count();
            assert_eq!(prompts, 1, "{name}");
        }
        assert_eq!(r.digest().updates, urls, "{name}");
        assert!(
            r.log.contains(&format!(
                "⚠ an update of the run's item to the agent: {comment}"
            )),
            "{name}: {}",
            r.log
        );
        // The watch's polls were conditional, and mostly unchanged.
        let s = stub.0.lock().unwrap();
        assert!(
            s.not_modified * 2 > s.requests,
            "{name}: {}/{}",
            s.not_modified,
            s.requests
        );
    }
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
        max_repeats: Option<usize>,
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
    // An agent stuck on one call, as GLM agents have been (#1328): each
    // repeat a model step apart, as a real agent's are, and longer than a
    // few of the budget's checks, so that each is seen.
    let same = r#"{"execute": {"title": "Bash", "command": "echo same"}}, {"sleep": 1}"#;
    let cases = [
        Case {
            name: "model requests",
            script: over_requests.clone(),
            later: HAND_BACK,
            timeout_s: 60,
            count_requests: true,
            max_tasks: None,
            max_repeats: None,
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
            max_repeats: None,
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
            max_repeats: None,
            status: 3,
            result: "budget",
            message: "started more than 2 subagent tasks; the agent handed back",
            notices: &["last task", "hand back"],
            handed_back: true,
        },
        Case {
            name: "one tool call repeated",
            script: format!(
                r#"[{}, {{"sleep": 60}}, {{"say": "Not reached."}}]"#,
                [same; 8].join(", ")
            ),
            later: HAND_BACK,
            timeout_s: 60,
            count_requests: false,
            max_tasks: None,
            max_repeats: Some(3),
            status: 3,
            result: "budget",
            message: "repeated one tool call 5 times; the agent handed back",
            notices: &["repeated", "hand back"],
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
            max_repeats: None,
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
                max_repeats: c.max_repeats,
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

/// A task's turn that ends on an error, as a model request the provider
/// refused ends one: it is no success, and the agent gets a turn to hand
/// back in, which decides between stopped at a limit and failed.
#[test]
fn a_turn_that_ends_on_an_error() {
    // An error whose words fit no class of provider failure: one that a
    // wait may clear is sent again first (`a_rate_limited_turn_is_sent_again`).
    const REFUSAL: &str = "API Error: Request rejected (400) · bad request";
    const PREFIX: Option<&str> = Some("API Error:");
    const HAND_BACK: &str = r#"[
      {"write": {"title": "Write", "path": "{cwd}/partial.txt", "content": "partial\n"}},
      {"say": "Handed back."}
    ]"#;
    let refused = format!(
        r#"[{{"say": "Working."}}, {{"execute": {{"title": "Bash", "command": "true"}}}}, {{"say": "{REFUSAL}"}}]"#
    );
    let failed = r#"[{"say": "Working."}, {"fail": "the model answered nothing usable"}]"#;
    let limit_in_hand_back = format!(r#"[{}, {{"sleep": 60}}]"#, use_requests(100));
    struct Case<'a> {
        name: &'a str,
        script: &'a str,
        later: &'a str,
        provider_error: Option<&'a str>,
        status: u8,
        result: &'a str,
        message: &'a [&'a str],
        handed_back: bool,
        count_requests: bool,
        /// The prompts the session sent as notices.
        notices: &'a [&'a str],
    }
    let cases = [
        Case {
            name: "the agent says the provider refused, then hands back",
            script: &refused,
            later: HAND_BACK,
            provider_error: PREFIX,
            status: 3,
            result: "budget",
            message: &[
                "the agent's turn ended on an error",
                "the model provider refused the agent's request: API Error: Request rejected (400)",
                "the agent handed back",
            ],
            handed_back: true,
            count_requests: false,
            notices: &["hand back"],
        },
        Case {
            name: "the agent says the provider refused, and again while handing back",
            script: &refused,
            later: &refused,
            provider_error: PREFIX,
            status: 1,
            result: "failure",
            message: &["the model provider refused the agent's request: API Error"],
            handed_back: false,
            count_requests: false,
            notices: &["hand back"],
        },
        Case {
            name: "the agent answers its turn with an error, then hands back",
            script: failed,
            later: HAND_BACK,
            provider_error: None,
            status: 3,
            result: "budget",
            message: &[
                "the agent's turn ended on an error (session/prompt failed",
                "nothing usable",
                "the agent handed back",
            ],
            handed_back: true,
            count_requests: false,
            notices: &["hand back"],
        },
        Case {
            name: "the agent answers its turn with an error, and its hand-back too",
            script: failed,
            later: failed,
            provider_error: None,
            status: 1,
            result: "failure",
            message: &["session/prompt failed", "nothing usable"],
            handed_back: false,
            count_requests: false,
            notices: &["hand back"],
        },
        Case {
            name: "an agent with no provider-error is taken at its word",
            script: &refused,
            later: HAND_BACK,
            provider_error: None,
            status: 0,
            result: "success",
            message: &[],
            handed_back: false,
            count_requests: false,
            notices: &[],
        },
        Case {
            name: "an error the agent went on from, to words that are no error",
            script: r#"[{"say": "API Error: 400"}, {"execute": {"title": "Bash", "command": "true"}}, {"say": "API Error responses are retried now."}]"#,
            later: HAND_BACK,
            provider_error: PREFIX,
            status: 0,
            result: "success",
            message: &[],
            handed_back: false,
            count_requests: false,
            notices: &[],
        },
        Case {
            name: "a limit reached while the agent hands back stops it",
            script: &refused,
            later: &limit_in_hand_back,
            provider_error: PREFIX,
            status: 3,
            result: "budget",
            message: &[
                "used 100 of 100 model requests; cancelled, after",
                "the model provider refused the agent's request: API Error",
            ],
            handed_back: false,
            count_requests: true,
            notices: &["hand back"],
        },
        Case {
            name: "an agent that exits as it hands back fails with the error",
            script: failed,
            later: r#"[{"exit": 7}]"#,
            provider_error: None,
            status: 1,
            result: "failure",
            message: &[
                "exit status: 7",
                "session/prompt failed: the model answered nothing usable",
            ],
            handed_back: false,
            count_requests: false,
            notices: &["hand back"],
        },
        Case {
            name: "an agent that exits after its error fails with it",
            script: r#"[{"say": "Working."}, {"fail": "the model answered nothing usable"}, {"finish": 7}]"#,
            later: HAND_BACK,
            provider_error: None,
            status: 1,
            result: "failure",
            message: &[
                "the agent exited",
                "exit status: 7",
                "session/prompt failed: the model answered nothing usable",
            ],
            handed_back: false,
            count_requests: false,
            notices: &[],
        },
    ];
    for c in cases {
        let name = c.name;
        let r = run(
            SCRIPT_AND_LATER,
            Setup {
                files: &[("script.json", c.script), ("later.json", c.later)],
                // Three seconds to hand back in, and as long a pause.
                timeout_s: 60,
                provider_error: c.provider_error,
                count_requests: c.count_requests,
                ..Setup::default()
            },
        );
        assert_result(&r, c.status, c.result);
        let message = r.result["message"].as_str().unwrap_or_default();
        for part in c.message {
            assert!(message.contains(part), "{name}: {message}");
        }
        assert_eq!(r.result["handed_back"], c.handed_back, "{name}");
        assert_eq!(r.notices(), c.notices, "{name}");
        assert_eq!(r.path("work/partial.txt").exists(), c.handed_back, "{name}");
        assert!(
            r.elapsed < Duration::from_secs(30),
            "{name}: took {:?}",
            r.elapsed
        );
    }
}

/// A task's turn that ends well without the output the run requires is
/// followed by one reminder turn, under the same limits; a run whose agent
/// still left none fails (#607), and one that requires none is not
/// reminded.
#[test]
fn a_turn_that_ends_without_the_required_output() {
    const OUTPUT: &str = "work/output.txt";
    const WRITE: &str = r#"[
      {"write": {"title": "Write", "path": "{cwd}/output.txt", "content": "noop\n"}},
      {"say": "Handed back."}
    ]"#;
    const NOTHING: &str = r#"[{"say": "Done, I think."}]"#;
    let at_the_limit = format!(r#"[{}, {{"sleep": 60}}]"#, use_requests(100));
    let near_the_limit = format!(r#"[{}, {{"sleep": 60}}]"#, use_requests(95));
    struct Case<'a> {
        name: &'a str,
        script: &'a str,
        later: &'a str,
        output: Option<&'a str>,
        count_requests: bool,
        status: u8,
        result: &'a str,
        message: Option<&'a str>,
        /// The prompts the session sent as notices.
        notices: &'a [&'a str],
    }
    let cases = [
        Case {
            name: "the output is there when the turn ends",
            script: WRITE,
            later: WRITE,
            output: Some(OUTPUT),
            count_requests: false,
            status: 0,
            result: "success",
            message: None,
            notices: &[],
        },
        Case {
            name: "the reminder has the agent leave its output",
            script: NOTHING,
            later: WRITE,
            output: Some(OUTPUT),
            count_requests: false,
            status: 0,
            result: "success",
            message: None,
            notices: &["reminder"],
        },
        Case {
            name: "the agent leaves no output even after the reminder",
            script: NOTHING,
            later: NOTHING,
            output: Some(OUTPUT),
            count_requests: false,
            status: 1,
            result: "failure",
            message: Some("without the output the run requires, even after a reminder"),
            notices: &["reminder"],
        },
        Case {
            name: "a run that requires no output is not reminded",
            script: NOTHING,
            later: WRITE,
            output: None,
            count_requests: false,
            status: 0,
            result: "success",
            message: None,
            notices: &[],
        },
        Case {
            name: "a limit reached during the reminder stops it",
            script: NOTHING,
            later: &at_the_limit,
            output: Some(OUTPUT),
            count_requests: true,
            status: 3,
            result: "budget",
            message: Some("used 100 of 100 model requests; cancelled"),
            notices: &["reminder"],
        },
        Case {
            name: "near a limit during the reminder, the agent is asked to hand back",
            script: NOTHING,
            later: &near_the_limit,
            output: Some(OUTPUT),
            count_requests: true,
            status: 3,
            result: "budget",
            message: Some("model requests; cancelled"),
            notices: &["reminder", "hand back"],
        },
    ];
    for c in cases {
        let name = c.name;
        let r = run(
            SCRIPT_AND_LATER,
            Setup {
                files: &[("script.json", c.script), ("later.json", c.later)],
                // Three seconds to hand back in.
                timeout_s: 60,
                output: c.output,
                count_requests: c.count_requests,
                ..Setup::default()
            },
        );
        assert_result(&r, c.status, c.result);
        if let Some(part) = c.message {
            let message = r.result["message"].as_str().unwrap_or_default();
            assert!(message.contains(part), "{name}: {message}");
        } else {
            assert!(r.result["message"].is_null(), "{name}: {}", r.result);
        }
        let reminded = !c.notices.is_empty();
        assert_eq!(r.result["reminded"], reminded, "{name}");
        assert_eq!(r.notices(), c.notices, "{name}");
        if reminded {
            assert!(
                r.records.iter().any(|record| {
                    record["dir"] == "send"
                        && record["msg"]["method"] == "session/prompt"
                        && record["msg"]["params"]["prompt"]
                            .as_array()
                            .is_some_and(|blocks| {
                                blocks.iter().any(|block| {
                                    block["text"]
                                        .as_str()
                                        .is_some_and(|text| text.contains("No output was left."))
                                })
                            })
                }),
                "{name}: the reminder omitted the output check's reason"
            );
            assert!(
                r.log
                    .contains("without its required output: reminding it once"),
                "{name}: {}",
                r.log
            );
        }
        if c.status != 3 {
            assert_eq!(r.result["stop_reason"], "end_turn", "{name}");
        }
        assert!(
            r.elapsed < Duration::from_secs(30),
            "{name}: took {:?}",
            r.elapsed
        );
    }
}

/// A task's turn in which the agent sends nothing for its stall timeout,
/// with no tool call running, is cancelled and the task sent again once on
/// the same session; a second stall fails the run, saying so. A quiet tool
/// call is no stall.
#[test]
fn a_stalled_turn_is_sent_again_once() {
    const STALL: &str = r#"[{"say": "Working."}, {"sleep": 60}]"#;
    const DONE: &str = r#"[{"say": "Done."}]"#;
    const QUIET_TOOL: &str =
        r#"[{"execute": {"title": "Bash", "command": "sleep 3"}}, {"say": "Done."}]"#;
    // (name, first turn, later turns, result, the message's start, stalls, retries)
    let cases = [
        ("one stall, then done", STALL, DONE, "success", None, 1, 1),
        (
            "two stalls",
            STALL,
            STALL,
            "failure",
            Some("the agent stalled: nothing from it for 1s in its turn, and again"),
            2,
            1,
        ),
        ("a quiet tool call", QUIET_TOOL, DONE, "success", None, 0, 0),
    ];
    for (name, script, later, result, message, stalls, retries) in cases {
        let r = run(
            SCRIPT_AND_LATER,
            Setup {
                files: &[("script.json", script), ("later.json", later)],
                timeout_s: 60,
                stall_s: Some(1),
                ..Setup::default()
            },
        );
        assert_result(&r, u8::from(result != "success"), result);
        let said = r.result["message"].as_str();
        match message {
            Some(start) => assert!(
                said.is_some_and(|m| m.starts_with(start)),
                "{name}: {said:?}"
            ),
            None => assert_eq!(said, None, "{name}"),
        }
        assert_eq!(
            (
                r.result["stalls"].as_u64(),
                r.result["stall_retries"].as_u64()
            ),
            (Some(stalls), Some(retries)),
            "{name}"
        );
        // The task again, behind a note, on the agent's one session.
        let resent: Vec<&Value> = r
            .records
            .iter()
            .filter(|record| {
                record["dir"] == "send"
                    && record["msg"]["params"]["_meta"][session::permission::META_KEY]["notice"]
                        == "stalled"
            })
            .collect();
        assert_eq!(resent.len() as u64, retries, "{name}");
        for record in resent {
            let params = &record["msg"]["params"];
            assert_eq!(params["sessionId"], "fake-session", "{name}");
            assert_eq!(params["prompt"][1]["text"], "Do the fake task.\n", "{name}");
        }
        let sessions = r
            .records
            .iter()
            .filter(|record| record["msg"]["method"] == "session/new")
            .count();
        assert_eq!(sessions, 1, "{name}");
        assert_eq!(
            r.log.contains("the agent stalled: nothing from it for 1s"),
            stalls > 0,
            "{name}: {}",
            r.log
        );
        assert!(
            r.elapsed < Duration::from_secs(30),
            "{name}: took {:?}",
            r.elapsed
        );
    }
}

/// A task's turn that ends on a model provider's failure a wait may clear
/// (the agent's rate-limit error, or an error or a refusal whose words
/// say rate-limited, overloaded or unreachable, for any agent) is sent
/// again after a wait, on the same session, up to three times, the wait
/// the provider's own where it names one; an overload longer, and then on
/// the run's fallback model if it names one; then, or for any other error,
/// the agent is asked to hand back as after any error, and at once
/// after a failure no wait clears. The class of the failure the run ended
/// on is in its result, an agent that dies of one included, and a wait
/// never runs into the time limit: near it the agent hands back instead.
#[test]
fn a_rate_limited_turn_is_sent_again() {
    const VIBE_RATE_LIMIT: i32 = -31001;
    const ONCE: &str = r#"[{"say": "Working."}, {"rate_limit": "Rate limit exceeded"}]"#;
    const ALWAYS: &str = r#"[{"rate_limit": "Rate limit exceeded"}]"#;
    const FAILED: &str = r#"[{"say": "Working."}, {"fail": "Internal error"}]"#;
    const OVERLOADED: &str = r#"[{"say": "Working."}, {"fail": "AI_RetryError: Failed after 3 attempts. Last error: Service Unavailable"}]"#;
    const ALWAYS_OVERLOADED: &str = r#"[{"fail": "API Error: 529 Overloaded"}]"#;
    const CLOSED: &str = r#"[{"say": "Working."}, {"fail": "socket hang up"}]"#;
    const RETRY_AFTER: &str =
        r#"[{"say": "Working."}, {"fail": "Rate limit exceeded. Retry-After: 1"}]"#;
    const QUOTA: &str = r#"[{"say": "Working."}, {"fail": "You exceeded your current quota, please check your plan and billing details."}]"#;
    const UNAUTHORIZED: &str = r#"[{"say": "Working."}, {"fail": "API Error: 401 {\"type\":\"authentication_error\",\"message\":\"invalid x-api-key\"}"}]"#;
    const SAID_THEN_DIED: &str = r#"[{"say": "API Error: 529 Overloaded"}, {"exit": 7}]"#;
    const NEAR_THE_TIMEOUT: &str = r#"[{"sleep": 36.5}, {"rate_limit": "Rate limit exceeded"}]"#;
    const TOO_LONG_A_WAIT: &str =
        r#"[{"say": "Working."}, {"fail": "Rate limit exceeded, retry after 10 minutes"}]"#;
    const DONE: &str = r#"[{"say": "Done."}]"#;
    const LIMITED: &str = "rate limited";
    const PROVIDER: &str = "provider error";
    const HAND_BACK: &str = "hand back";
    const PREFIX: Option<&str> = Some("API Error:");
    struct Case {
        name: &'static str,
        script: &'static str,
        later: &'static str,
        code: Option<i32>,
        provider_error: Option<&'static str>,
        /// The run's timeout: three seconds to hand back in, and each
        /// wait as long, unless the case is about the timeout.
        timeout_s: u64,
        status: u8,
        result: &'static str,
        message: &'static [&'static str],
        notices: &'static [&'static str],
        /// The seconds of each wait the log says.
        wait_s: u64,
        /// What the log says besides.
        log: &'static [&'static str],
        /// `provider_error` and `resends` in the result.
        class: Option<&'static str>,
        resends: u64,
        /// The run's fallback model, and the result's `fallback_model`.
        fallback: Option<&'static str>,
        switched: Option<&'static str>,
    }
    let case = Case {
        name: "",
        script: ONCE,
        later: DONE,
        code: None,
        provider_error: None,
        timeout_s: 60,
        status: 0,
        result: "success",
        message: &[],
        notices: &[LIMITED],
        wait_s: 3,
        log: &[],
        class: None,
        resends: 1,
        fallback: None,
        switched: None,
    };
    let cases = [
        Case {
            name: "rate-limited once, then done",
            code: Some(VIBE_RATE_LIMIT),
            ..case
        },
        Case {
            name: "always rate-limited",
            script: ALWAYS,
            later: ALWAYS,
            code: Some(VIBE_RATE_LIMIT),
            status: 1,
            result: "failure",
            message: &["session/prompt failed: Rate limit exceeded"],
            notices: &[LIMITED, LIMITED, LIMITED, HAND_BACK],
            log: &["asking the agent to hand back in 3s"],
            class: Some("rate_limited"),
            resends: 3,
            ..case
        },
        Case {
            name: "another error",
            script: FAILED,
            code: Some(VIBE_RATE_LIMIT),
            status: 3,
            result: "budget",
            message: &["the agent handed back"],
            notices: &[HAND_BACK],
            log: &["asking the agent to hand back in 3s"],
            class: Some("other"),
            resends: 0,
            ..case
        },
        Case {
            name: "an agent with no rate-limit-code is sent again by the error's words",
            ..case
        },
        Case {
            name: "overloaded by the error's words, then done",
            script: OVERLOADED,
            notices: &[PROVIDER],
            log: &["the provider was overloaded; sending the task again"],
            ..case
        },
        // Waited out for longer than a rate limit, and then the agent,
        // which needs the provider to hand back too, cannot: the run
        // hands back its working tree itself (tests/run.rs).
        Case {
            name: "always overloaded",
            script: ALWAYS_OVERLOADED,
            later: ALWAYS_OVERLOADED,
            status: 1,
            result: "failure",
            message: &["session/prompt failed: API Error: 529 Overloaded"],
            notices: &[
                PROVIDER, PROVIDER, PROVIDER, PROVIDER, PROVIDER, PROVIDER, HAND_BACK,
            ],
            log: &["(6 of 6)", "asking the agent to hand back in 3s"],
            class: Some("overloaded"),
            resends: 6,
            ..case
        },
        // With a fallback model, the agent is switched to it after the
        // waits, keeping its session, and the task sent again at once:
        // the fake agent's `spare` model serves what the other failed.
        Case {
            name: "always overloaded, then switched to the fallback and done",
            script: ALWAYS_OVERLOADED,
            later: ALWAYS_OVERLOADED,
            fallback: Some("spare"),
            notices: &[
                PROVIDER, PROVIDER, PROVIDER, PROVIDER, PROVIDER, PROVIDER, PROVIDER,
            ],
            log: &[
                "(6 of 6)",
                "the provider stayed overloaded; switched the agent to model spare, sending the task again",
            ],
            switched: Some("spare"),
            resends: 7,
            ..case
        },
        // One the agent will not switch to leaves it to hand back.
        Case {
            name: "always overloaded, and the fallback not taken",
            script: ALWAYS_OVERLOADED,
            later: ALWAYS_OVERLOADED,
            fallback: Some("ignored"),
            status: 1,
            result: "failure",
            message: &["session/prompt failed: API Error: 529 Overloaded"],
            notices: &[
                PROVIDER, PROVIDER, PROVIDER, PROVIDER, PROVIDER, PROVIDER, HAND_BACK,
            ],
            log: &[
                "the agent could not be switched to the fallback model ignored: the agent still runs fake",
                "asking the agent to hand back in 3s",
            ],
            class: Some("overloaded"),
            resends: 6,
            ..case
        },
        Case {
            name: "the connection closed by the error's words, then done",
            script: CLOSED,
            notices: &[PROVIDER],
            log: &["the provider was unreachable; sending the task again"],
            ..case
        },
        Case {
            name: "the provider's retry-after is the wait",
            script: RETRY_AFTER,
            wait_s: 1,
            ..case
        },
        Case {
            name: "a usage limit is not waited on",
            script: QUOTA,
            status: 3,
            result: "budget",
            message: &[
                "the agent's turn ended on an error",
                "exceeded your current quota",
                "the agent handed back",
            ],
            notices: &[HAND_BACK],
            log: &["asking the agent to hand back now"],
            class: Some("quota"),
            resends: 0,
            ..case
        },
        Case {
            name: "a refused credential is not waited on",
            script: UNAUTHORIZED,
            status: 3,
            result: "budget",
            message: &["the agent handed back"],
            notices: &[HAND_BACK],
            log: &["asking the agent to hand back now"],
            class: Some("unauthorized"),
            resends: 0,
            ..case
        },
        Case {
            name: "an agent that dies after saying the provider refused died of it",
            script: SAID_THEN_DIED,
            provider_error: PREFIX,
            status: 1,
            result: "failure",
            message: &[
                "the agent exited",
                "exit status: 7",
                "after the provider was overloaded (API Error: 529 Overloaded)",
            ],
            notices: &[],
            class: Some("overloaded"),
            resends: 0,
            ..case
        },
        Case {
            name: "a provider that asks for longer than the cap is not waited for",
            script: TOO_LONG_A_WAIT,
            status: 3,
            result: "budget",
            message: &[
                "the agent's turn ended on an error",
                "the agent handed back",
            ],
            notices: &[HAND_BACK],
            log: &[
                "asks for a wait of 600s, more than the 120s waited for: not sending the task again",
                "asking the agent to hand back in 3s",
            ],
            class: Some("rate_limited"),
            resends: 0,
            ..case
        },
        // The wait (two seconds, the window) would run past the point
        // where the agent is to hand back for the time: it hands back
        // instead, and the task is not sent again (the budget's notices
        // came during the long turn).
        Case {
            name: "a wait that would run into the time limit hands back instead",
            script: NEAR_THE_TIMEOUT,
            timeout_s: 40,
            status: 124,
            result: "timeout",
            message: &["hit the timeout", "the agent handed back"],
            notices: &["60%", "80%", HAND_BACK],
            wait_s: 2,
            log: &[
                "sending the task again in 2s",
                "hit the timeout: asking the agent to hand back",
            ],
            class: Some("rate_limited"),
            resends: 0,
            ..case
        },
    ];
    for c in cases {
        let name = c.name;
        let r = run(
            SCRIPT_AND_LATER,
            Setup {
                files: &[("script.json", c.script), ("later.json", c.later)],
                timeout_s: c.timeout_s,
                rate_limit_code: c.code,
                provider_error: c.provider_error,
                fallback_model: c.fallback,
                ..Setup::default()
            },
        );
        assert_result(&r, c.status, c.result);
        assert_eq!(
            r.result.get("fallback_model").and_then(Value::as_str),
            c.switched,
            "{name}"
        );
        let said = r.result["message"].as_str();
        if c.message.is_empty() {
            assert_eq!(said, None, "{name}");
        }
        for part in c.message {
            assert!(said.is_some_and(|m| m.contains(part)), "{name}: {said:?}");
        }
        assert_eq!(r.notices(), c.notices, "{name}");
        assert_eq!(
            r.result.get("provider_error").and_then(Value::as_str),
            c.class,
            "{name}: {:#}",
            r.result
        );
        assert_eq!(r.result["resends"].as_u64(), Some(c.resends), "{name}");
        // Each wait was at least a second and at most the wait said; a
        // wait a limit interrupted counts too, with no resend after it.
        let waited = r.result["resend_wait_s"].as_u64().unwrap_or(u64::MAX);
        assert!(
            (c.resends..=c.resends.max(1) * c.wait_s).contains(&waited),
            "{name}: waited {waited}s for {} resend(s)",
            c.resends
        );
        // The task again, behind a note, on the agent's one session.
        let resent: Vec<&Value> = r
            .records
            .iter()
            .filter(|record| {
                let label =
                    &record["msg"]["params"]["_meta"][session::permission::META_KEY]["notice"];
                record["dir"] == "send" && (label == LIMITED || label == PROVIDER)
            })
            .collect();
        assert_eq!(resent.len() as u64, c.resends, "{name}");
        for record in resent {
            let params = &record["msg"]["params"];
            assert_eq!(params["sessionId"], "fake-session", "{name}");
            assert_eq!(params["prompt"][1]["text"], "Do the fake task.\n", "{name}");
        }
        // Each resend was announced with its wait, but the one on the
        // fallback model, which has none; so was a wait a limit then
        // interrupted.
        let announced = r
            .log
            .matches(&format!("sending the task again in {}s", c.wait_s))
            .count() as u64
            + u64::from(c.switched.is_some());
        assert!(
            announced == c.resends || announced == c.resends + 1,
            "{name}: {announced} announced for {} resend(s): {}",
            c.resends,
            r.log
        );
        for part in c.log {
            assert!(r.log.contains(part), "{name}: {part:?} not in {}", r.log);
        }
        assert!(
            r.elapsed < Duration::from_secs(c.timeout_s.min(40) + 15),
            "{name}: took {:?}",
            r.elapsed
        );
    }
}

/// After a compaction of its context during the task's turn, reported or
/// seen in its usage, an agent that takes notices is told its task again
/// (#822), once for each; one that does not, or a run that asks for
/// nothing, is told nothing.
#[test]
fn a_compaction_has_the_task_restated() {
    const RESTATED: &str = "Your context was just compacted. Left: the tests.";
    const REPORTED: &str = r#"["compact", {"sleep": 0.5}, {"say": "Done."}]"#;
    const INFERRED: &str = r#"[
      {"context": {"used": 24000, "size": 32768}},
      {"context": {"used": 3000, "size": 32768}},
      {"sleep": 0.5}, {"say": "Done."}
    ]"#;
    const TWICE: &str =
        r#"["compact", {"sleep": 0.3}, "compact", {"sleep": 0.5}, {"say": "Done."}]"#;
    // (the case, the script, whether the agent takes notices, whether the
    // run restates, how many restatements)
    let cases = [
        ("reported", REPORTED, true, true, 1),
        ("inferred", INFERRED, true, true, 1),
        ("each compaction", TWICE, true, true, 2),
        ("no notices", REPORTED, false, true, 0),
        ("nothing to restate", REPORTED, true, false, 0),
        ("no compaction", r#"[{"say": "Done."}]"#, true, true, 0),
    ];
    for (name, script, notices, restate, count) in cases {
        let r = run(
            SCRIPT_MODE,
            Setup {
                files: &[("script.json", script)],
                timeout_s: 60,
                no_notices: !notices,
                restate: restate.then_some(RESTATED),
                ..Setup::default()
            },
        );
        assert_result(&r, 0, "success");
        assert_eq!(r.notices(), vec!["compaction"; count], "{name}");
        let sent = r
            .records
            .iter()
            .filter(|x| x["msg"]["params"]["_meta"]["botHarness"]["notice"] == "compaction")
            .all(|x| x["msg"]["params"]["prompt"][0]["text"] == RESTATED);
        assert!(sent, "{name}");
        assert_eq!(
            r.log.matches("compacted: restating its task").count(),
            count,
            "{name}: {}",
            r.log
        );
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

/// The session's own turn, then a client on loopback: it attaches to the
/// session already running, is refused what the bridge does not serve,
/// and has a prompt answered with the run's secret replaced; when it
/// hangs up the session ends as done. Where the environment names a
/// sandbox user (`AGENTIC_JOB_TEST_SANDBOX_USER`), the agent runs as that user.
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
                    client.wait_for_the_task(&sid);
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
                    client.wait_for_the_task(&sid);
                    client.request(2, "session/prompt", text_prompt(&sid, "hi"));
                    while client.recv().is_some() {}
                }
            } else {
                |client| {
                    let sid =
                        client.request(1, "session/new", json!({}))["result"]["sessionId"].clone();
                    client.wait_for_the_task(&sid);
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
                    client.wait_for_the_task(&sid);
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
                        if !client.try_send(&msg) {
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

/// A port that is taken is a session that is not run: the bridge binds
/// it before the agent starts.
#[test]
fn a_port_that_is_taken_is_refused() {
    // Taken by this test, or by something else already.
    let _held = TcpListener::bind(("127.0.0.1", bridge::PORT));
    let listen = Listen {
        operators: vec![OPERATOR.to_owned()],
        origins: vec![ORIGIN.to_owned()],
        idle: Duration::from_secs(60),
    };
    let err = Bridge::bind(listen, Arc::new(str::to_owned)).err().unwrap();
    assert!(
        format!("{err:#}").contains("listening on 127.0.0.1:"),
        "{err:#}"
    );
}

/// Handshakes `tailscale serve` would pass on without the operator's
/// login, with another's, or from a page not allowed are refused, and the
/// bridge goes on listening: the operator then attaches, and a second
/// connection is closed unanswered while it is there.
#[test]
fn only_the_operator_attaches() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[("script.json", "[]"), ("later.json", LATER)],
            timeout_s: 60,
            client: Some((
                |client| {
                    let sid =
                        client.request(1, "session/new", json!({}))["result"]["sessionId"].clone();
                    // Another is closed unanswered, even as the operator.
                    let second = TcpStream::connect(&client.address).unwrap();
                    let mut request = format!("ws://{}/", client.address)
                        .into_client_request()
                        .unwrap();
                    for (name, value) in ADMITTED {
                        request.headers_mut().append(*name, value.parse().unwrap());
                    }
                    assert!(tungstenite::client(request, second).is_err());
                    client.wait_for_the_task(&sid);
                    let answer = client.request(2, "session/prompt", text_prompt(&sid, "hi"));
                    assert_eq!(answer["result"]["stopReason"], "end_turn", "{answer}");
                },
                Duration::from_secs(60),
            )),
            refused_first: &[
                &[("Origin", ORIGIN)],
                &[
                    (bridge::LOGIN_HEADER, "intruder@github"),
                    ("Origin", ORIGIN),
                ],
                &[(bridge::LOGIN_HEADER, OPERATOR)],
                &[
                    (bridge::LOGIN_HEADER, OPERATOR),
                    ("Origin", "https://evil.example"),
                ],
            ],
            ..Setup::default()
        },
    );
    assert_result(&r, 0, "success");
    assert_eq!(r.result["message"], "the client left", "{}", r.log);
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
                    client.wait_for_the_task(&sid);
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

/// A client attached when the task's turn ends on an error: its prompts
/// are refused while the agent hands back, and the run ends at a limit.
#[test]
fn a_client_while_the_agent_hands_back_after_an_error() {
    let r = run(
        SCRIPT_AND_LATER,
        Setup {
            files: &[
                // An error whose words fit no class: one a wait may clear
                // would have the task sent again first.
                (
                    "script.json",
                    r#"[{"sleep": 1}, {"fail": "the model answered nothing usable"}]"#,
                ),
                ("later.json", r#"[{"say": "Handed back."}]"#),
            ],
            timeout_s: 60,
            client: Some((
                |client| {
                    let sid =
                        client.request(1, "session/new", json!({}))["result"]["sessionId"].clone();
                    // Refused while the turn runs, then while the agent
                    // is to hand back.
                    let refused = (2..100)
                        .map(|id| client.request(id, "session/prompt", text_prompt(&sid, "Hi.")))
                        .find(|answer| {
                            std::thread::sleep(Duration::from_millis(100));
                            !answer["error"]["message"]
                                .as_str()
                                .unwrap()
                                .contains("a turn is running")
                        })
                        .unwrap();
                    assert!(
                        refused["error"]["message"]
                            .as_str()
                            .unwrap()
                            .contains("the agent is to hand back"),
                        "{refused}"
                    );
                    while client.recv().is_some() {}
                },
                Duration::from_secs(60),
            )),
            ..Setup::default()
        },
    );
    assert_result(&r, 3, "budget");
    assert_eq!(r.result["handed_back"], true, "{}", r.log);
    assert_eq!(r.notices(), ["hand back"]);
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
                        .socket
                        .get_mut()
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    // Each answer repeats the request's 4 KiB id.
                    let request = json!({"jsonrpc": "2.0", "id": "i".repeat(4 << 10),
                                         "method": "initialize", "params": {}})
                    .to_string();
                    let mut sent = 0;
                    let err = loop {
                        assert!(sent < 256 << 20, "the session took {sent} bytes unread");
                        if let Err(e) = client.socket.send(Message::text(request.clone())) {
                            break e;
                        }
                        sent += request.len();
                    };
                    assert!(
                        matches!(
                            &err,
                            tungstenite::Error::Io(e) if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            )
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
                    // A message may be cut short by the hang-up.
                    while client.socket.read().is_ok() {}
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
