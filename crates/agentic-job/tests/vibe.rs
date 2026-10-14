//! Opt-in, credentialless adapter evidence on a hosted runner. The real pinned
//! package talks only to a loopback broker fixture; no forge writes or setup.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use agentic_job::run::agent;
use agentic_job::run::inference::{Endpoint, Mode, Token};
use agentic_job::session::digest::Digest;
use agentic_job::session::{self, Clients, Launch, Limits, Options, Policy, Record};
use serde_json::{Value, json};

#[test]
fn pinned_vibe_acp() {
    let Ok(python) = std::env::var("AGENTIC_JOB_TEST_VIBE_PYTHON") else {
        eprintln!("skipped: set AGENTIC_JOB_TEST_VIBE_PYTHON to the pinned Vibe venv's Python");
        return;
    };
    let version = std::process::Command::new(&python)
        .args(["-I", "-c", "import vibe; print(vibe.__version__)"])
        .output()
        .unwrap();
    assert!(version.status.success());
    assert_eq!(String::from_utf8(version.stdout).unwrap().trim(), "2.26.1");
    repository_models(&python);
    for handback in [false, true] {
        run_vibe(&python, handback);
    }
}

/// Models from a configuration repository's file, with its provider and
/// telemetry ignored, are what Vibe resolves, and the caller's model wins.
fn repository_models(python: &str) {
    let source = r#"
active_model = "glm"
enable_telemetry = true
[[providers]]
name = "mistral"
api_base = "https://evil.example/v1"
[[models]]
name = "zai-glm-5-3"
alias = "glm"
provider = "mistral"
max_output_tokens = 4096
[[models]]
name = "devstral-small-latest"
provider = "llamacpp"
"#;
    for (model, active, name, cap) in [
        (None, "glm", "zai-glm-5-3", 4096),
        (
            Some("devstral-small-latest"),
            "devstral-small-latest",
            "devstral-small-latest",
            32000,
        ),
    ] {
        let home = tempfile::tempdir().unwrap();
        let config = agent::vibe(
            &Endpoint {
                url: "http://127.0.0.1:1".into(),
                mode: Mode::Plain,
                anthropic_url: String::new(),
                openai_url: String::new(),
            },
            &Token::new("local-test-token-for-vibe").unwrap(),
            model,
            Some(source),
        )
        .unwrap();
        assert_eq!(config.model.as_deref(), Some(active));
        assert_eq!(config.options, [("max_tokens", cap.to_string())]);
        let path = home.path().join(config.files[0].path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, config.files[0].content.as_ref().unwrap()).unwrap();
        let script = format!(
            r#"
import asyncio
from vibe.core.paths import bootstrap_vibe_home
from vibe.core.config.harness_files import init_harness_files_manager
bootstrap_vibe_home()
init_harness_files_manager("user")
from vibe.core.config.default_orchestrator import build_default_orchestrator
config = asyncio.run(build_default_orchestrator()).config
model = config.get_active_model()
assert model.alias == "{active}" and model.name == "{name}", model
assert model.max_output_tokens == {cap}, model
assert not config.enable_telemetry
# Vibe keeps its built-in model beside the file's; all are on the broker.
assert set(config.models) == {{"glm", "devstral-small-latest", "mistral-medium-3.5"}}
for m in config.models.values():
    assert config.get_provider_for_model(m).api_base == "http://127.0.0.1:1/mistral/v1"
"#
        );
        let out = std::process::Command::new(python)
            .args(["-I", "-c", &script])
            .env_clear()
            .env("HOME", home.path())
            .env("VIBE_HOME", home.path().join(agent::VIBE_HOME))
            .current_dir(home.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn run_vibe(python: &str, handback: bool) {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let work = home.join("work");
    std::fs::create_dir_all(work.join(".vibe")).unwrap();
    // Isolated Python imports and user-only config must ignore both canaries.
    std::fs::write(work.join("vibe.py"), "raise RuntimeError('project import')").unwrap();
    std::fs::write(
        work.join(".vibe/config.toml"),
        "active_model = 'evil'\n[[providers]]\nname = 'mistral'\napi_base = 'http://127.0.0.1:1'\n",
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let token = Token::new("local-test-token-for-vibe").unwrap();
    let config = agent::vibe(
        &Endpoint {
            url,
            mode: Mode::Plain,
            anthropic_url: String::new(),
            openai_url: String::new(),
        },
        &token,
        Some("broker-model"),
        None,
    )
    .unwrap();
    for file in &config.files {
        let path = home.join(file.path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, file.content.as_ref().unwrap()).unwrap();
    }
    // Validate the effective config, not just TOML: Vibe deep-merges its
    // default model, which otherwise leaks Medium capabilities and prices.
    let effective = std::process::Command::new(python)
        .args([
            "-I",
            "-c",
            r#"
import asyncio
from vibe.core.paths import bootstrap_vibe_home
from vibe.core.config.harness_files import init_harness_files_manager
bootstrap_vibe_home()
init_harness_files_manager("user")
from vibe.core.config.default_orchestrator import build_default_orchestrator
config = asyncio.run(build_default_orchestrator()).config
model = config.get_active_model()
# Vibe reports the active model's alias; the built-in's runs it too, so
# Vibe's default and fallback paths do.
assert set(config.models) == {"broker-model", "mistral-medium-3.5"}
assert config.models["mistral-medium-3.5"] == model.model_copy(update={"alias": "mistral-medium-3.5"})
assert model.alias == model.name == model.display_name == "broker-model"
assert model.provider == "mistral" and not model.supports_images
assert model.max_context_length == 32768
assert model.auto_compact_threshold == 24576
assert model.max_output_tokens == 8192
assert model.temperature == 0.2 and model.thinking_levels == ["off"]
assert model.input_price == model.output_price == model.cached_input_price == 0
assert {p.name for p in config.providers} == {"mistral", "llamacpp"}
assert all(p.api_base.endswith("/mistral/v1") and not p.api_key_env_var for p in config.providers)
"#,
        ])
        .env_clear()
        .env("HOME", &home)
        .env("VIBE_HOME", home.join(agent::VIBE_HOME))
        .current_dir(&work)
        .output()
        .unwrap();
    assert!(
        effective.status.success(),
        "{}",
        String::from_utf8_lossy(&effective.stderr)
    );
    let target = work.join("result.txt");
    let (count, requests_count) = tokio::sync::watch::channel(Some(0));
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut requests = Vec::new();
        while requests.len() < if handback { 3 } else { 2 } {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "Vibe did not reach the broker"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "POST /mistral/v1/chat/completions HTTP/1.1");
            let mut length = 0;
            let mut authorized = false;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.split_once(':').unwrap();
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap();
                }
                if name.eq_ignore_ascii_case("authorization") {
                    authorized = value.trim() == "Bearer local-test-token-for-vibe";
                }
            }
            assert!(authorized);
            assert!(length < 1 << 20);
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["model"], "broker-model");
            // The legacy loop sends the session's cap, not the model's.
            assert_eq!(body["max_tokens"], 8192, "{body}");
            if handback && requests.len() == 1 {
                // Cancel a live model request, then accept the harness's
                // hand-back prompt through the same ACP session.
                count.send_replace(Some(91));
                std::thread::sleep(Duration::from_secs(2));
                requests.push(body);
                continue;
            }
            let first = requests.is_empty();
            let delta = if first {
                let tools = body["tools"].as_array().unwrap();
                let name = tools
                    .iter()
                    .find_map(|tool| {
                        let name = tool["function"]["name"].as_str()?;
                        name.ends_with("write_file").then_some(name)
                    })
                    .expect("Vibe must offer its own filesystem tool");
                json!({"tool_calls": [{"index": 0, "id": "write", "type": "function", "function": {
                    "name": name, "arguments": json!({"file_path": target, "content": "adapter control\n"}).to_string(),
                }}]})
            } else {
                json!({"content": "Done."})
            };
            let response = format!(
                "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
                json!({"id": "mock", "object": "chat.completion.chunk", "model": "broker-model", "choices": [{"index": 0, "delta": delta, "finish_reason": null}]}),
                json!({"id": "mock", "object": "chat.completion.chunk", "model": "broker-model", "choices": [{"index": 0, "delta": {}, "finish_reason": if first { "tool_calls" } else { "stop" }}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
            );
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
            requests.push(body);
        }
        requests
    });
    let mut spec = session::agents::builtin("vibe").unwrap();
    spec.command[0] = python.to_owned();
    spec.env
        .insert("HOME".into(), home.to_str().unwrap().into());
    spec.env.insert(
        "VIBE_HOME".into(),
        home.join(agent::VIBE_HOME).to_str().unwrap().into(),
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let out = root.path().join("out");
    let result = runtime
        .block_on(session::run(Options {
            name: "vibe".into(),
            agent: spec,
            model: config.model.clone(),
            config_options: config
                .options
                .iter()
                .map(|(id, value)| ((*id).to_owned(), value.clone()))
                .collect(),
            cwd: work.clone(),
            prompt: "Write the requested file and stop.".into(),
            out: out.clone(),
            permissions: Policy::for_task(&home).unwrap(),
            limits: Limits {
                timeout_s: 60,
                budget_aic: None,
                max_requests: Some(100),
                max_tasks: Some(0),
            },
            requests: Some(requests_count),
            launch: Launch::Direct,
            clients: Clients::none(),
            bridge: None,
            log: Box::new(std::io::sink()),
        }))
        .unwrap();
    assert_eq!(
        result.result.exit().code(),
        if handback { 3 } else { 0 },
        "{result:?}: {}",
        std::fs::read_to_string(out.join("agent-stderr.log")).unwrap()
    );
    assert_eq!(result.handed_back, handback);
    let requests = server.join().unwrap();
    assert!(
        requests[1]["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["role"] == "tool")
    );
    assert_eq!(
        std::fs::read_to_string(work.join("result.txt")).unwrap(),
        "adapter control\n"
    );
    let transcript = std::fs::read_to_string(out.join(session::ACP_LOG)).unwrap();
    assert!(transcript.contains("session/request_permission"));
    // The run's start line names the caller's model, not Vibe's built-in
    // alias (#562); the requests carry it, as checked above.
    let mut digest = Digest::new();
    let start = transcript
        .lines()
        .flat_map(|line| {
            let record: Record = serde_json::from_str(line).unwrap();
            record
                .msg
                .map(|msg| digest.feed(record.ts, record.dir, &msg))
                .unwrap_or_default()
        })
        .find(|line| line.starts_with("start: "))
        .unwrap();
    assert!(start.contains(", broker-model, in "), "{start}");
}
