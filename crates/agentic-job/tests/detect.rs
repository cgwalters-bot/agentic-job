//! Stub inference, never a real model or forge credential.
#![allow(clippy::unwrap_used)]

mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;

use serde_json::{Value, json};
use support::{Fault, Proxy};

const CLEAN: &str = r#"{"prompt_injection":false,"secret_leak":false,"malicious_patch":false}"#;

/// One chat-completions answer with a single choice.
fn answer(finish: &str, message: Value) -> String {
    json!({"choices": [{"finish_reason": finish, "message": message}]}).to_string()
}

/// What the model stub does with the detector's one request.
#[derive(Default)]
enum Model {
    /// The detector must not ask at all.
    #[default]
    Unasked,
    /// It answers with this status and body.
    Answer(u16, String),
    /// It reads the request and closes without answering.
    Drop,
    /// It promises one byte more than this body, sends the body and
    /// closes.
    Short(String),
}

/// Reads the detector's one request and checks that it carries only data.
fn read_request(stream: &mut TcpStream) {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break bytes.len();
        }
    };
    let headers = String::from_utf8(bytes).unwrap();
    assert!(headers.starts_with("POST /chat/completions "));
    let len: usize = headers
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    assert!(header_end < 8192);
    let mut request = vec![0; len];
    stream.read_exact(&mut request).unwrap();
    let request: Value = serde_json::from_slice(&request).unwrap();
    assert_eq!(request["max_tokens"], 256);
    assert_eq!(request["model"], "stub");
    assert!(request.get("tools").is_none());
    let evidence: Value =
        serde_json::from_str(request["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(evidence["task"], "task");
    assert_eq!(evidence["patches"].as_array().unwrap().len(), 2);
}

/// Serves the detector's one request as MODEL says.
fn serve(listener: TcpListener, model: Model) {
    let (mut stream, _) = listener.accept().unwrap();
    read_request(&mut stream);
    let (status, body, extra) = match model {
        Model::Unasked => unreachable!(),
        Model::Answer(status, body) => (status, body, 0),
        Model::Drop => return,
        Model::Short(body) => (200, body, 1),
    };
    // The detector stops reading an oversized answer, so the rest of the
    // write may fail.
    let _ = write!(
        stream,
        "HTTP/1.1 {status} Stub\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len() + extra
    );
}

/// One way the detector's run can go: what the proxy and the model do,
/// what stderr then says, and the run states and live tokens the proxy
/// is left with.
#[derive(Default)]
struct Case {
    name: &'static str,
    registration: Option<Fault>,
    ending: Option<Fault>,
    model: Model,
    error: &'static str,
    states: &'static [&'static str],
    live: usize,
}

/// Every way the one detector request can go wrong must fail `detect`,
/// which is what keeps check.yml from releasing the artifact to apply.
#[test]
fn stub_detector_gates_and_always_ends_its_run() {
    let clean = || json!({"content": CLEAN});
    let ok = |message| Model::Answer(200, answer("stop", message));
    let malicious = r#"{"prompt_injection":false,"secret_leak":false,"malicious_patch":true}"#;
    let tool =
        json!([{"id": "1", "type": "function", "function": {"name": "x", "arguments": "{}"}}]);
    let finished: &[&str] = &["finished"];
    let cases = [
        Case {
            name: "clean",
            model: ok(clean()),
            states: finished,
            ..Case::default()
        },
        Case {
            name: "threat",
            model: ok(json!({"content": malicious})),
            error: "refused the proposal",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "not JSON",
            model: ok(json!({"content": "not JSON"})),
            error: "invalid detector verdict",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "truncated",
            model: Model::Answer(200, answer("length", clean())),
            error: "incomplete detector response",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "unavailable",
            model: Model::Answer(503, answer("stop", clean())),
            error: "http status: 503",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "registration refused",
            registration: Some(Fault::Status(503, "upstream error\n")),
            error: "registering the run",
            ..Case::default()
        },
        Case {
            name: "registration lost",
            registration: Some(Fault::Closed),
            error: "cannot reach the inference proxy",
            ..Case::default()
        },
        // The proxy registered the run, but the detector never learned
        // its token, so cannot end it: the proxy's expiry does.
        Case {
            name: "registration reply lost",
            registration: Some(Fault::LostReply),
            error: "cannot reach the inference proxy",
            states: &["active"],
            live: 1,
            ..Case::default()
        },
        // A clean verdict is not enough when the run cannot be ended.
        Case {
            name: "ending refused",
            ending: Some(Fault::Status(503, "upstream error\n")),
            model: ok(clean()),
            error: "ending the run at the proxy failed",
            states: &["active"],
            live: 1,
            ..Case::default()
        },
        Case {
            name: "ending lost",
            ending: Some(Fault::Closed),
            model: ok(clean()),
            error: "to end the run",
            states: &["active"],
            live: 1,
            ..Case::default()
        },
        // Here and below only ureq's text says what went wrong, and
        // this is its shortest stable part.
        Case {
            name: "model drops the connection",
            model: Model::Drop,
            error: "Peer disconnected",
            states: finished,
            ..Case::default()
        },
        // All of a clean answer, but short of the length it promised: a
        // body that ends early must not be taken for the whole of it.
        Case {
            name: "model truncates the body",
            model: Model::Short(answer("stop", clean())),
            error: "Peer disconnected",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "tool calls",
            model: Model::Answer(
                200,
                answer("tool_calls", json!({"content": CLEAN, "tool_calls": tool})),
            ),
            error: "incomplete detector response",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "tool calls on stop",
            model: ok(json!({"content": CLEAN, "tool_calls": tool})),
            error: "detector requested tools",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "function call",
            model: ok(json!({"content": CLEAN, "function_call": {"name": "x", "arguments": "{}"}})),
            error: "detector requested tools",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "no choices",
            model: Model::Answer(200, json!({"choices": []}).to_string()),
            error: "incomplete detector response",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "choices not a list",
            model: Model::Answer(
                200,
                json!({"choices": {"finish_reason": "stop", "message": {"content": CLEAN}}})
                    .to_string(),
            ),
            error: "missing detector choices",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "two choices",
            model: Model::Answer(
                200,
                json!({"choices": [
                    {"finish_reason": "stop", "message": {"content": CLEAN}},
                    {"finish_reason": "stop", "message": {"content": CLEAN}},
                ]})
                .to_string(),
            ),
            error: "incomplete detector response",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "no message",
            model: Model::Answer(
                200,
                json!({"choices": [{"finish_reason": "stop"}]}).to_string(),
            ),
            error: "missing detector verdict",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "content not text",
            model: ok(json!({"content": [{"type": "text", "text": CLEAN}]})),
            error: "missing detector verdict",
            states: finished,
            ..Case::default()
        },
        Case {
            name: "not an object",
            model: Model::Answer(200, "[]".to_owned()),
            error: "missing detector choices",
            states: finished,
            ..Case::default()
        },
        // A clean answer padded past the 32 KiB response cap.
        Case {
            name: "oversized",
            model: Model::Answer(
                200,
                json!({
                    "choices": [{"finish_reason": "stop", "message": {"content": CLEAN}}],
                    "padding": "x".repeat(32 * 1024),
                })
                .to_string(),
            ),
            error: "larger than request limit",
            states: finished,
            ..Case::default()
        },
    ];
    for Case {
        name: case,
        registration,
        ending,
        model,
        error,
        states,
        live,
    } in cases
    {
        let proxy = Proxy::start();
        proxy.admit_unproven();
        proxy.fail_registrations(registration);
        proxy.fail_endings(ending);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        // Without a run the detector must not ask the model at all.
        let asked = !matches!(model, Model::Unasked);
        listener.set_nonblocking(!asked).unwrap();
        let listener = if asked {
            Ok(std::thread::spawn(move || serve(listener, model)))
        } else {
            Err(listener)
        };
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[inference]\nurl = {:?}\nregister = 'plain'\nopenai-url = {url:?}\n",
                proxy.url
            ),
        )
        .unwrap();
        for (name, text) in [
            ("task.md", "task"),
            ("agent_output.json", "{}"),
            ("aw-test.patch", "patch"),
            ("replacement.json", "replacement"),
        ] {
            std::fs::write(dir.path().join(name), text).unwrap();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_agentic-job"))
            .args(["detect", "--config"])
            .arg(dir.path().join("config.toml"))
            .arg("--task")
            .arg(dir.path().join("task.md"))
            .arg("--checked")
            .arg(dir.path())
            .args(["--model", "stub"])
            .output()
            .unwrap();
        match listener {
            Ok(server) => server.join().unwrap(),
            Err(listener) => assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "{case}"
            ),
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.success(), case == "clean", "{case}: {stderr}");
        assert!(stderr.contains(error), "{case}: {stderr}");
        assert_eq!(proxy.run_states(), states, "{case}");
        assert_eq!(proxy.live_tokens().len(), live, "{case}");
    }
}

#[test]
fn oversized_evidence_never_registers() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("task.md"), vec![b'x'; 2 * 1024 * 1024 + 1]).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agentic-job"))
        .args(["detect", "--config", "absent", "--task"])
        .arg(dir.path().join("task.md"))
        .arg("--checked")
        .arg(dir.path())
        .args(["--model", "stub"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("at most 2 MiB"));
}

/// Agent credentials never reach the detector's host. Unsupported modes
/// must block apply, not silently bypass an explicitly enabled detector.
#[test]
fn agent_credential_modes_fail_closed() {
    for inference in [
        "register = 'api-key'\nprovider = 'openai'\nurl = 'http://127.0.0.1:1'",
        "register = 'token-file'\ntoken-file = '/nonexistent'\nurl = 'http://127.0.0.1:1'",
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            format!("[inference]\n{inference}\n"),
        )
        .unwrap();
        for (name, text) in [("task.md", "task"), ("agent_output.json", "{}")] {
            std::fs::write(dir.path().join(name), text).unwrap();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_agentic-job"))
            .args(["detect", "--config"])
            .arg(dir.path().join("config.toml"))
            .arg("--task")
            .arg(dir.path().join("task.md"))
            .arg("--checked")
            .arg(dir.path())
            .args(["--model", "stub"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{inference}: {stderr}");
        assert!(stdout.is_empty(), "{inference}: {stdout}");
        assert!(
            stderr.contains("detector needs run registration"),
            "{stderr}"
        );
    }
}
