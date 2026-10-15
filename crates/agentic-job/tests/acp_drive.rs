//! `agentic-job acp-drive` against the scripted agent, as a run's main
//! agent would use it through bash: a prompt and its events, a cancel, a
//! compaction, a child that crashes, and a child the run did not
//! configure. Each test has a home of its own, so its own daemon.

// clippy.toml lets test functions unwrap, but not the helpers they share.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");
const FAKE: &str = env!("CARGO_BIN_EXE_fake-agent");
/// Where the scripted agent's `demo` finds the session it plays.
const DEMO: &str = ".config/fake-agent/demo.json";
const DIR: &str = ".local/state/agentic-job/acp-drive";

struct Drive {
    home: tempfile::TempDir,
}

impl Drive {
    /// A home whose scripted agent plays SCRIPT in its first turn.
    fn new(script: &Value) -> Self {
        let home = tempfile::tempdir().unwrap();
        let demo = home.path().join(DEMO);
        std::fs::create_dir_all(demo.parent().unwrap()).unwrap();
        std::fs::write(&demo, script.to_string()).unwrap();
        Self { home }
    }

    fn home(&self) -> &Path {
        self.home.path()
    }

    fn run(&self, args: &[&str]) -> Output {
        let fake_dir = Path::new(FAKE).parent().unwrap();
        Command::new(BIN)
            .arg("acp-drive")
            .args(args)
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", format!("{}:/usr/bin:/bin", fake_dir.display()))
            .current_dir(self.home())
            .output()
            .unwrap()
    }

    /// Runs ARGS: their exit status and the JSON they printed.
    fn json(&self, args: &[&str]) -> (i32, Value) {
        let out = self.run(args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let value = serde_json::from_str(stdout.trim()).unwrap_or_else(|_| {
            panic!(
                "{args:?} printed no JSON: {stdout:?}, stderr {:?}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().unwrap(), value)
    }

    fn start(&self) -> Value {
        let (code, status) = self.json(&["start", "--agent", "fake"]);
        assert_eq!(code, 0, "{status}");
        status
    }

    fn events(&self, since: usize) -> Value {
        let (code, events) = self.json(&["events", "--since", &since.to_string()]);
        assert_eq!(code, 0, "{events}");
        events
    }

    /// The events so far once one of KIND is among them.
    fn wait_for(&self, kind: &str) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut all = Vec::new();
        loop {
            let got = self.events(all.len());
            all.extend(got["events"].as_array().unwrap().iter().cloned());
            if all.iter().any(|e| e["kind"] == kind) {
                return all;
            }
            assert!(Instant::now() < deadline, "no {kind} event in {all:?}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.home().join(DIR).join(name)
    }
}

impl Drop for Drive {
    fn drop(&mut self) {
        let _ = self.run(&["stop"]);
    }
}

fn kinds(events: &[Value]) -> Vec<&str> {
    events.iter().map(|e| e["kind"].as_str().unwrap()).collect()
}

#[test]
fn a_prompt_and_its_events() {
    let drive = Drive::new(&json!([
        {"say": "Working on it."},
        {"context": {"used": 24000, "size": 32768}},
        "compact",
        {"execute": {"title": "Bash", "command": "echo from-the-child"}},
        {"context": {"used": 20000, "size": 32768}},
        // A compaction it does not report.
        {"context": {"used": 3000, "size": 32768}},
        {"say": "Done."}
    ]));
    let status = drive.start();
    assert_eq!(status["agent"], "fake");
    assert_eq!(status["turn"], false);
    assert!(status["session"].is_string(), "{status}");

    let again = drive.run(&["start", "--agent", "fake"]);
    assert_eq!(again.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&again.stderr).contains("running already"));

    let (code, answer) = drive.json(&["prompt", "Do the task."]);
    assert_eq!((code, &answer), (0, &json!({"stop_reason": "end_turn"})));

    let got = drive.events(0);
    let events = got["events"].as_array().unwrap();
    assert_eq!(
        kinds(events),
        [
            "prompt",
            "message",
            "compaction",
            "compaction",
            "tool_call",
            "permission",
            "tool_result",
            "compaction",
            "message",
            "turn_end"
        ],
        "{events:?}"
    );
    assert_eq!(events[0]["text"], "Do the task.");
    assert_eq!(events[1]["text"], "Working on it.");
    let compactions: Vec<(&Value, &Value)> = events
        .iter()
        .filter(|e| e["kind"] == "compaction")
        .map(|e| (&e["inferred"], &e["status"]))
        .collect();
    assert_eq!(
        compactions,
        [
            (&json!(false), &json!("in_progress")),
            (&json!(false), &json!("completed")),
            (&json!(true), &Value::Null)
        ]
    );
    assert_eq!(events[5]["decision"], "allow");
    assert!(
        events[6]["output"]
            .as_str()
            .unwrap()
            .contains("from-the-child"),
        "{events:?}"
    );
    assert_eq!(events[9]["stop_reason"], "end_turn");
    // Numbered once: nothing is listed twice.
    let next = got["next"].as_u64().unwrap();
    assert_eq!(next, 10);
    assert_eq!(drive.events(10)["events"], json!([]));

    // Every message in both directions is in the transcript.
    let transcript = std::fs::read_to_string(drive.file("acp.jsonl")).unwrap();
    for method in [
        "initialize",
        "session/new",
        "session/prompt",
        "session/request_permission",
    ] {
        assert!(
            transcript.contains(&format!("\"method\":\"{method}\"")),
            "{method}"
        );
    }

    let (code, stopped) = drive.json(&["stop"]);
    assert_eq!((code, &stopped), (0, &json!({"stopped": true})));
    let after = drive.run(&["events"]);
    assert_eq!(after.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&after.stderr).contains("no child agent is running"));
}

#[test]
fn a_cancel() {
    let drive = Drive::new(&json!([
        {"say": "Thinking."},
        {"sleep": 60},
        {"say": "Not reached."}
    ]));
    drive.start();
    // The caller stops waiting; the turn goes on.
    let (code, answer) = drive.json(&["prompt", "--timeout", "1", "Take your time."]);
    assert_eq!(code, 124, "{answer}");
    assert_eq!(answer["running"], true);
    let (code, refused) = drive.json(&["prompt", "Another."]);
    assert_eq!(code, 1);
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("a turn is running"),
        "{refused}"
    );

    let (code, cancelled) = drive.json(&["cancel"]);
    assert_eq!((code, &cancelled["cancelled"]), (0, &json!(true)));
    let events = drive.wait_for("turn_end");
    assert_eq!(kinds(&events), ["prompt", "message", "turn_end"]);
    assert_eq!(events[2]["stop_reason"], "cancelled");
    assert_eq!(drive.json(&["cancel"]).1, json!({"turn": false}));

    // The session goes on after a cancelled turn.
    let (code, answer) = drive.json(&["prompt", "Go on."]);
    assert_eq!((code, &answer), (0, &json!({"stop_reason": "end_turn"})));
}

#[test]
fn a_child_that_crashes() {
    let drive = Drive::new(&json!([{"say": "Going."}, {"exit": 3}]));
    drive.start();
    let (code, answer) = drive.json(&["prompt", "Do the task."]);
    assert_eq!(code, 1);
    let error = answer["error"].as_str().unwrap();
    assert!(error.contains("exited") && error.contains('3'), "{answer}");
    let events = drive.events(0);
    let events = events["events"].as_array().unwrap();
    assert_eq!(
        kinds(events),
        ["prompt", "message", "exit", "turn_end"],
        "{events:?}"
    );
    assert!(events[2]["status"].as_str().unwrap().contains('3'));

    let (code, status) = drive.json(&["status"]);
    assert_eq!(code, 0);
    assert!(status["exited"].as_str().unwrap().contains('3'), "{status}");
    let (code, refused) = drive.json(&["prompt", "Again."]);
    assert_eq!(code, 1);
    assert!(refused["error"].as_str().unwrap().contains("has exited"));
    // What it said on its way out is kept for the transcript.
    let stderr = std::fs::read_to_string(drive.file("stderr.log")).unwrap();
    assert!(stderr.contains("exiting with status 3"), "{stderr}");
    assert_eq!(drive.json(&["stop"]).0, 0);
}

/// Without `[child-agent]`, `run` writes no configuration for one, and
/// there is no Vibe to start; the main agents cannot be children.
#[test]
fn only_a_configured_child_starts() {
    let drive = Drive::new(&json!([]));
    for (agent, said) in [
        ("vibe", "this run has no child agent"),
        ("claude", "cannot be a child agent"),
        ("gemini", "no agent \"gemini\""),
    ] {
        let out = drive.run(&["start", "--agent", agent]);
        assert_eq!(out.status.code(), Some(2), "{agent}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(said), "{agent}: {stderr}");
    }
    assert!(!drive.file("socket").exists());
}
