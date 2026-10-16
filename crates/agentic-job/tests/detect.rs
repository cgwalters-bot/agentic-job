//! Stub inference, never a real model or forge credential.
#![allow(clippy::unwrap_used)]

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

use serde_json::{Value, json};
use support::{Fault, Proxy};

const CLEAN: &str = r#"{"prompt_injection":false,"secret_leak":false,"malicious_patch":false}"#;

/// One chat-completions answer with a single choice.
fn answer(finish: &str, message: Value) -> String {
    json!({"choices": [{"finish_reason": finish, "message": message}]}).to_string()
}

/// Answers the detector's one request with STATUS and BODY, after
/// checking that it carries only data.
fn serve(listener: TcpListener, status: u16, body: String) {
    let (mut stream, _) = listener.accept().unwrap();
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
    // The detector stops reading an oversized answer, so the rest of the
    // write may fail.
    let _ = write!(
        stream,
        "HTTP/1.1 {status} Stub\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// (case, registration fault, ending fault, status, body, what stderr
/// says, run states)
type Case = (
    &'static str,
    Option<Fault>,
    Option<u16>,
    u16,
    String,
    &'static str,
    &'static [&'static str],
);

/// Every way the one detector request can go wrong must fail `detect`,
/// which is what keeps check.yml from releasing the artifact to apply.
#[test]
fn stub_detector_gates_and_always_ends_its_run() {
    let clean = || json!({"content": CLEAN});
    let malicious = r#"{"prompt_injection":false,"secret_leak":false,"malicious_patch":true}"#;
    let tool =
        json!([{"id": "1", "type": "function", "function": {"name": "x", "arguments": "{}"}}]);
    let cases: Vec<Case> = vec![
        (
            "clean",
            None,
            None,
            200,
            answer("stop", clean()),
            "",
            &["finished"],
        ),
        (
            "threat",
            None,
            None,
            200,
            answer("stop", json!({"content": malicious})),
            "refused the proposal",
            &["finished"],
        ),
        (
            "not JSON",
            None,
            None,
            200,
            answer("stop", json!({"content": "not JSON"})),
            "invalid detector verdict",
            &["finished"],
        ),
        (
            "truncated",
            None,
            None,
            200,
            answer("length", clean()),
            "incomplete detector response",
            &["finished"],
        ),
        (
            "unavailable",
            None,
            None,
            503,
            answer("stop", clean()),
            "http status: 503",
            &["finished"],
        ),
        (
            "registration refused",
            Some(Fault::Status(503, "upstream error\n")),
            None,
            200,
            String::new(),
            "registering the run",
            &[],
        ),
        (
            "registration lost",
            Some(Fault::Closed),
            None,
            200,
            String::new(),
            "cannot reach the inference proxy",
            &[],
        ),
        // A clean verdict is not enough when the run cannot be ended.
        (
            "ending refused",
            None,
            Some(503),
            200,
            answer("stop", clean()),
            "ending the run at the proxy failed",
            &["active"],
        ),
        (
            "tool calls",
            None,
            None,
            200,
            answer("tool_calls", json!({"content": CLEAN, "tool_calls": tool})),
            "incomplete detector response",
            &["finished"],
        ),
        (
            "tool calls on stop",
            None,
            None,
            200,
            answer("stop", json!({"content": CLEAN, "tool_calls": tool})),
            "detector requested tools",
            &["finished"],
        ),
        (
            "function call",
            None,
            None,
            200,
            answer(
                "stop",
                json!({"content": CLEAN, "function_call": {"name": "x", "arguments": "{}"}}),
            ),
            "detector requested tools",
            &["finished"],
        ),
        (
            "no choices",
            None,
            None,
            200,
            json!({"choices": []}).to_string(),
            "incomplete detector response",
            &["finished"],
        ),
        (
            "choices not a list",
            None,
            None,
            200,
            json!({"choices": {"finish_reason": "stop", "message": {"content": CLEAN}}})
                .to_string(),
            "missing detector choices",
            &["finished"],
        ),
        (
            "two choices",
            None,
            None,
            200,
            json!({"choices": [
                {"finish_reason": "stop", "message": {"content": CLEAN}},
                {"finish_reason": "stop", "message": {"content": CLEAN}},
            ]})
            .to_string(),
            "incomplete detector response",
            &["finished"],
        ),
        (
            "no message",
            None,
            None,
            200,
            json!({"choices": [{"finish_reason": "stop"}]}).to_string(),
            "missing detector verdict",
            &["finished"],
        ),
        (
            "content not text",
            None,
            None,
            200,
            answer(
                "stop",
                json!({"content": [{"type": "text", "text": CLEAN}]}),
            ),
            "missing detector verdict",
            &["finished"],
        ),
        (
            "not an object",
            None,
            None,
            200,
            "[]".to_owned(),
            "missing detector choices",
            &["finished"],
        ),
        // A clean answer padded past the 32 KiB response cap.
        (
            "oversized",
            None,
            None,
            200,
            json!({
                "choices": [{"finish_reason": "stop", "message": {"content": CLEAN}}],
                "padding": "x".repeat(32 * 1024),
            })
            .to_string(),
            "larger than request limit",
            &["finished"],
        ),
    ];
    for (case, registration, ending, status, body, error, states) in cases {
        let proxy = Proxy::start();
        proxy.admit_unproven();
        let registers = registration.is_none();
        proxy.fail_registrations(registration);
        proxy.fail_endings(ending);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(!registers).unwrap();
        // Without a run the detector must not ask the model at all.
        let listener = if registers {
            Ok(std::thread::spawn(move || serve(listener, status, body)))
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
        assert_eq!(
            proxy.live_tokens().len(),
            usize::from(ending.is_some()),
            "{case}"
        );
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
