use std::process::Command;

use serde_json::{Value, json};

#[test]
fn downloaded_artifacts_are_audited_without_being_applied() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["agent-run", "safe-outputs", "checked-outputs"] {
        std::fs::create_dir(dir.path().join(name)).unwrap();
    }
    for (path, content) in [
        (
            "agent-run/summary.json",
            json!({"schema": "agent-run-summary/v1", "run_id": 7,
            "result": "success", "aic": 2.5, "aic_budget": 100,
            "tools": {"Bash": {"calls": 1, "errors": 0}},
            "egress_denied": [{"domain": "example.org", "count": 2}]}),
        ),
        (
            "safe-outputs/outputs.jsonl",
            json!({"type": "noop", "message": "nothing to do"}),
        ),
        (
            "checked-outputs/agent_output.json",
            json!({"items": [], "errors": ["collector refusal"]}),
        ),
        (
            "checked-outputs/report.json",
            json!({"ok": false, "errors": ["policy refusal"], "items": []}),
        ),
    ] {
        std::fs::write(dir.path().join(path), content.to_string()).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_agentic-job"))
        .args(["audit", "--json"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["handed_back"][0]["type"], "noop");
    assert_eq!(report["cost"]["aic"], 2.5);
    let codes: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert_eq!(
        codes,
        ["check_refused", "collector_refused", "proxy_denied"]
    );
}

#[test]
fn hostile_artifact_text_cannot_issue_ci_commands() {
    let dir = tempfile::tempdir().unwrap();
    let hostile = "##[warning]audit-controlled-text\n::warning::modern\r\u{1b}[31m";
    std::fs::write(
        dir.path().join("summary.json"),
        json!({
            "schema": "agent-run-summary/v1", "run_id": hostile, "result": hostile,
            "tools": {hostile: {"calls": 1}}, "failures": [hostile]
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("outputs.jsonl"),
        json!({
            "type": "noop", "message": hostile
        })
        .to_string(),
    )
    .unwrap();
    for json_mode in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agentic-job"));
        command.arg("audit").arg(dir.path());
        if json_mode {
            command.arg("--json");
        }
        let output = command.output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains("##["), "{stdout}");
        assert!(!stdout.lines().any(|line| line.starts_with("::")));
        assert!(!stdout.contains(['\r', '\u{1b}']));
        if json_mode {
            let report: Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(report["handed_back"][0]["message"], hostile);
            assert_eq!(report["run_id"], hostile);
        }
    }
}

#[test]
fn refused_producer_reports_survive_the_download_layout() {
    for phase in ["collector", "policy"] {
        let producer = tempfile::tempdir().unwrap();
        let download = tempfile::tempdir().unwrap();
        std::fs::write(
            download.path().join("summary.json"),
            json!({
                "schema": "agent-run-summary/v1", "aic": 1
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            producer.path().join("agent_output.json"),
            json!({
                "items": [{"type": "noop", "message": "not diagnostic evidence"}],
                "errors": if phase == "collector" { vec!["collector refusal"] } else { vec![] }
            })
            .to_string(),
        )
        .unwrap();
        if phase == "policy" {
            let policy = Command::new(env!("CARGO_BIN_EXE_agentic-job"))
                .args([
                    "policy",
                    "--repo",
                    "bootc-dev/bootc",
                    "--base",
                    "main",
                    "--kind",
                    "branch",
                    "--clone-url",
                    "https://github.com/bootc-dev/bootc",
                    "--outputs",
                    "create_pull_request",
                    "--max-outputs",
                    "1",
                    "--allow",
                ])
                .arg(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/data/policy/allow.toml"),
                )
                .output()
                .unwrap();
            assert!(
                policy.status.success(),
                "{}",
                String::from_utf8_lossy(&policy.stderr)
            );
            std::fs::write(producer.path().join("policy.json"), policy.stdout).unwrap();
            let outputs = producer.path().join("safe-outputs");
            std::fs::create_dir(&outputs).unwrap();
            std::fs::write(
                outputs.join("outputs.jsonl"),
                "{\"type\":\"noop\",\"message\":\"nothing\"}\n",
            )
            .unwrap();
            let check = Command::new(env!("CARGO_BIN_EXE_agentic-job"))
                .arg("check")
                .arg("--policy")
                .arg(producer.path().join("policy.json"))
                .arg("--outputs")
                .arg(outputs)
                .arg("--collected")
                .arg(producer.path().join("agent_output.json"))
                .arg("--report")
                .arg(producer.path().join("report.json"))
                .output()
                .unwrap();
            assert_eq!(check.status.code(), Some(1));
            let report: Value = serde_json::from_slice(
                &std::fs::read(producer.path().join("report.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(report["ok"], false);
            assert!(!report["errors"].as_array().unwrap().is_empty());
        }
        let output = Command::new(env!("CARGO_BIN_EXE_agentic-job"))
            .args(["diagnostics", "copy"])
            .arg(producer.path())
            .arg(download.path().join("check-diagnostics"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(env!("CARGO_BIN_EXE_agentic-job"))
            .args(["audit", "--json"])
            .arg(download.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let codes: Vec<_> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["code"].as_str().unwrap())
            .collect();
        assert!(codes.contains(&if phase == "collector" {
            "collector_refused"
        } else {
            "check_refused"
        }));
        assert_eq!(codes.contains(&"check_missing"), phase == "collector");
        assert!(!codes.contains(&"collector_missing"));
        assert_eq!(report["collector"]["items"], json!([]));
        assert!(report["check"]["patch"].is_null());
    }
}
