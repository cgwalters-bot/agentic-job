//! Stub inference, never a real model or forge credential.
#![allow(clippy::unwrap_used)]

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

use serde_json::json;
use support::Proxy;

#[test]
fn stub_detector_gates_and_always_ends_its_run() {
    for (content, finish, status, ok) in [
        (
            r#"{"prompt_injection":false,"secret_leak":false,"malicious_patch":false}"#,
            "stop",
            200,
            true,
        ),
        (
            r#"{"prompt_injection":false,"secret_leak":false,"malicious_patch":true}"#,
            "stop",
            200,
            false,
        ),
        ("not JSON", "stop", 200, false),
        ("{}", "length", 200, false),
        ("{}", "stop", 503, false),
    ] {
        let proxy = Proxy::start();
        proxy.admit_unproven();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
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
            let mut body = vec![0; len];
            stream.read_exact(&mut body).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(request["max_tokens"], 256);
            assert_eq!(request["model"], "stub");
            assert!(request.get("tools").is_none());
            let evidence: serde_json::Value =
                serde_json::from_str(request["messages"][1]["content"].as_str().unwrap()).unwrap();
            assert_eq!(evidence["task"], "task");
            assert_eq!(evidence["patches"].as_array().unwrap().len(), 2);
            let body = json!({"choices":[{"finish_reason": finish,"message":{"content":content}}]})
                .to_string();
            write!(
                stream,
                "HTTP/1.1 {status} Stub\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
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
        server.join().unwrap();
        assert_eq!(
            output.status.success(),
            ok,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(proxy.live_tokens().is_empty());
        assert_eq!(proxy.run_states(), ["finished"]);
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
