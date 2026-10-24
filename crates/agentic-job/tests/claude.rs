//! Opt-in, credentialless adapter evidence on a hosted runner: the real
//! pinned Claude Code ACP adapter, driven by the session as a run drives
//! it, against a loopback stub of the Messages API. No forge writes, no
//! model key and no setup.
//!
//! It holds the agent to its native file tools (#853): a run whose agent
//! edited every file with `python3` heredocs raised the question whether
//! the session, which advertises no ACP `fs` capability, leaves Claude
//! Code without Read, Edit and Write. It does not; this keeps it so, and
//! keeps the session's working directory the one the run gives, where
//! Claude Code edits without asking.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentic_job::run::agent;
use agentic_job::session::digest::Digest;
use agentic_job::session::{self, Clients, Launch, Limits, Options, Policy, Record};
use serde_json::{Value, json};

const PACKAGE: &str = "@agentclientprotocol/claude-agent-acp";
/// Not a key: the stub takes anything.
const STUB_KEY: &str = "test-key-not-secret";
/// The largest request body the stub reads.
const MAX_BODY: usize = 8 << 20;
/// Claude Code's own file tools, which it must offer the model.
const FILE_TOOLS: &[&str] = &["Read", "Edit", "Write"];

#[test]
fn pinned_claude_acp_offers_file_tools() {
    let Ok(package) = std::env::var("AGENTIC_JOB_TEST_CLAUDE_ACP") else {
        eprintln!(
            "skipped: set AGENTIC_JOB_TEST_CLAUDE_ACP to the pinned {PACKAGE} package's directory"
        );
        return;
    };
    let package = PathBuf::from(package);
    // The version runs install, from the reusable workflow at test time.
    let workflow = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/policy.yml");
    let workflow = std::fs::read_to_string(workflow).unwrap();
    let pinned = workflow
        .split(&format!("{PACKAGE}@"))
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .unwrap();
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(package.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["version"], pinned, "{}", package.display());
    // Managed settings win over the environment given here: they would
    // send the stub's requests elsewhere.
    assert!(
        !Path::new(agent::MANAGED_SETTINGS_FILE).exists(),
        "{} would override the stub's address",
        agent::MANAGED_SETTINGS_FILE
    );

    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let work = home.join("work/repo");
    std::fs::create_dir_all(&work).unwrap();
    let target = work.join("result.txt");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stub = Stub {
        target: target.clone(),
        first: Mutex::new(None),
        written: AtomicBool::new(false),
    };
    let stub = Arc::new(stub);
    let stop = Arc::new(AtomicBool::new(false));
    let server = {
        let (stub, stop) = (stub.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let stub = stub.clone();
                        std::thread::spawn(move || stub.serve(stream));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        })
    };

    let mut spec = session::agents::builtin("claude").unwrap();
    spec.command = vec![
        "node".into(),
        package.join("dist/index.js").to_str().unwrap().into(),
    ];
    for (name, value) in [
        ("HOME", home.to_str().unwrap()),
        ("ANTHROPIC_BASE_URL", url.as_str()),
        ("ANTHROPIC_AUTH_TOKEN", STUB_KEY),
    ]
    .into_iter()
    .chain(agent::CLAUDE_QUIET.iter().copied())
    // Pinned empty, as a run's managed settings do.
    .chain(agent::PROVIDER_SWITCHES.iter().map(|name| (*name, "")))
    {
        spec.env.insert(name.into(), value.into());
    }
    let out = root.path().join("out");
    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(session::run(Options {
            name: "claude".into(),
            agent: spec,
            model: None,
            fallback_model: None,
            config_options: Vec::new(),
            cwd: work.clone(),
            prompt: "Write the requested file and stop.".into(),
            out: out.clone(),
            permissions: Policy::for_task(&home).unwrap(),
            limits: Limits {
                timeout_s: 120,
                budget_aic: None,
                max_requests: None,
                max_tasks: Some(0),
                max_repeats: None,
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
        }))
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let stderr = std::fs::read_to_string(out.join(session::STDERR_LOG)).unwrap_or_default();
    assert_eq!(result.result.exit().code(), 0, "{result:?}: {stderr}");

    let first = stub.first.lock().unwrap().take();
    let first = first.unwrap_or_else(|| panic!("no request offered tools: {stderr}"));
    let offered: Vec<&str> = first["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    for tool in FILE_TOOLS {
        assert!(offered.contains(tool), "{tool} is not in {offered:?}");
    }
    // Claude Code tells the model its working directory, in a message of
    // its environment: the session's, where it edits without asking.
    let cwd = format!("Primary working directory: {}", work.display());
    assert!(
        first["messages"].to_string().contains(&cwd),
        "the request does not say {cwd:?}"
    );
    // Write ran as Claude Code's own tool, allowed by the policy, and
    // the transcript records it as an edit.
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "adapter control\n"
    );
    let transcript = std::fs::read_to_string(out.join(session::ACP_LOG)).unwrap();
    let mut digest = Digest::new();
    for line in transcript.lines() {
        let record: Record = serde_json::from_str(line).unwrap();
        if let Some(msg) = &record.msg {
            digest.feed(record.ts, record.dir, msg);
        }
    }
    digest.finish();
    assert!(
        digest.calls.iter().any(|call| call.kind == "edit"),
        "{:?}",
        digest.calls
    );
}

/// A stub of the Messages API: the first request that offers tools is
/// kept and answered with a Write of the target; every other one ends
/// its turn.
struct Stub {
    target: PathBuf,
    first: Mutex<Option<Value>>,
    written: AtomicBool,
}

impl Stub {
    fn serve(&self, mut stream: TcpStream) {
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let path = line.split(' ').nth(1).unwrap_or_default().to_owned();
        let mut length = 0;
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').unwrap();
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap();
            }
        }
        assert!(length <= MAX_BODY);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let (kind, response) = if path.starts_with("/v1/messages/count_tokens") {
            ("application/json", json!({"input_tokens": 1}).to_string())
        } else if path.starts_with("/v1/messages") {
            let body: Value = serde_json::from_slice(&body).unwrap();
            ("text/event-stream", self.reply(body))
        } else {
            let response =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes());
            return;
        };
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        );
    }

    /// The streamed reply to a Messages request BODY.
    fn reply(&self, body: Value) -> String {
        let offers_write = body["tools"]
            .as_array()
            .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == "Write"));
        let block = if offers_write && !self.written.swap(true, Ordering::SeqCst) {
            *self.first.lock().unwrap() = Some(body);
            let input = json!({"file_path": self.target, "content": "adapter control\n"});
            Some(input.to_string())
        } else {
            None
        };
        let event = |name: &str, data: Value| format!("event: {name}\ndata: {data}\n\n");
        let mut out = event(
            "message_start",
            json!({"type": "message_start", "message": {"id": "msg_stub", "type": "message",
                "role": "assistant", "model": "stub", "content": [], "stop_reason": null,
                "stop_sequence": null, "usage": {"input_tokens": 1, "output_tokens": 1}}}),
        );
        let stop_reason = match &block {
            Some(input) => {
                out += &event(
                    "content_block_start",
                    json!({"type": "content_block_start", "index": 0, "content_block":
                        {"type": "tool_use", "id": "toolu_stub", "name": "Write", "input": {}}}),
                );
                out += &event(
                    "content_block_delta",
                    json!({"type": "content_block_delta", "index": 0,
                        "delta": {"type": "input_json_delta", "partial_json": input}}),
                );
                "tool_use"
            }
            None => {
                out += &event(
                    "content_block_start",
                    json!({"type": "content_block_start", "index": 0,
                        "content_block": {"type": "text", "text": ""}}),
                );
                out += &event(
                    "content_block_delta",
                    json!({"type": "content_block_delta", "index": 0,
                        "delta": {"type": "text_delta", "text": "Done."}}),
                );
                "end_turn"
            }
        };
        out += &event(
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        );
        out += &event(
            "message_delta",
            json!({"type": "message_delta", "delta": {"stop_reason": stop_reason,
                "stop_sequence": null}, "usage": {"output_tokens": 1}}),
        );
        out + &event("message_stop", json!({"type": "message_stop"}))
    }
}
