//! Native CLI coverage of the legacy create-issue admission corpus.

#![cfg(test)]

use std::process::Command;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

fn issue() -> Value {
    json!({"type": "create_issue", "title": "A flaky test in nightly",
        "body": "The nightly run fails once a week on the same test."})
}

fn check_case(name: &str, limits: &str, lines: &[Value], collect_error: bool, error: Option<&str>) {
    // Each case owns every artifact; an earlier verdict cannot mask a failure
    // to write the current one.
    let dir = tempfile::tempdir().unwrap();
    let path = |file: &str| dir.path().join(file);
    std::fs::write(path("bounds.toml"), format!(
        "hosts = ['github.com']\nrepos = ['example/repo']\nbases = ['main']\nmax_outputs = 2\nmax_patch_bytes = 4096\nmax_patch_files = 2\n[github.outputs]\ncreate_issue = {{ max = 1{limits} }}\nnoop = {{ max = 1 }}\n"
    )).unwrap();
    let made = Command::new(BIN)
        .args(["policy", "--allow"])
        .arg(path("bounds.toml"))
        .args([
            "--repo",
            "example/repo",
            "--clone-url",
            "https://github.com/example/repo",
            "--base",
            "main",
            "--kind",
            "analysis",
            "--outputs",
            "create_issue,noop",
            "--max-outputs",
            "2",
        ])
        .output()
        .unwrap();
    assert_eq!(made.status.code(), Some(0), "{name}: {made:?}");
    let policy: Value = serde_json::from_slice(&made.stdout).unwrap();
    assert_eq!(policy["safe_outputs"]["create_issue"]["max"], 1);
    std::fs::write(path("policy.json"), made.stdout).unwrap();
    std::fs::create_dir(path("out")).unwrap();
    let input = lines
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    std::fs::write(path("out/outputs.jsonl"), input).unwrap();
    let collected = Command::new(BIN)
        .args(["collect", "--policy"])
        .arg(path("policy.json"))
        .arg("--outputs")
        .arg(path("out"))
        .arg("--collected")
        .arg(path("collected.json"))
        .output()
        .unwrap();
    assert_eq!(
        collected.status.code(),
        Some(i32::from(collect_error)),
        "{name}: {collected:?}"
    );
    let checked = Command::new(BIN)
        .args(["check", "--policy"])
        .arg(path("policy.json"))
        .arg("--outputs")
        .arg(path("out"))
        .arg("--collected")
        .arg(path("collected.json"))
        .arg("--report")
        .arg(path("report.json"))
        .output()
        .unwrap();
    let verdict: Value =
        serde_json::from_slice(&std::fs::read(path("report.json")).unwrap()).unwrap();
    assert_eq!(
        checked.status.code(),
        Some(i32::from(error.is_some())),
        "{name}: {checked:?}; {verdict}"
    );
    assert_eq!(verdict["ok"], error.is_none(), "{name}: {verdict}");
    if let Some(error) = error {
        assert!(
            verdict["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value.as_str().unwrap().contains(error)),
            "{name}: {verdict}"
        );
    } else {
        assert_eq!(verdict["errors"], json!([]), "{name}: {verdict}");
        assert_eq!(verdict["items"], json!(lines), "{name}: {verdict}");
    }
}

#[test]
fn create_issue_count_fields_and_relationships() {
    let mut missing_title = issue();
    missing_title.as_object_mut().unwrap().remove("title");
    let mut short_body = issue();
    short_body["body"] = json!("x");
    let mut parent = issue();
    parent["parent"] = json!(7);
    for (name, lines, collect_error, error) in [
        (
            "issue and noop",
            vec![issue(), json!({"type":"noop", "message":"No other change"})],
            false,
            None,
        ),
        (
            "two issues",
            vec![issue(), issue()],
            true,
            Some("Too many items of type 'create_issue'"),
        ),
        ("missing title", vec![missing_title], true, Some("title")),
        ("short body", vec![short_body], true, Some("body")),
        (
            "parent relationship",
            vec![parent],
            false,
            Some("links another issue"),
        ),
    ] {
        check_case(name, "", &lines, collect_error, error);
    }
}

#[test]
fn create_issue_label_limits() {
    let limits = ", allowed = ['triage', 'blocked'], blocked = ['blocked']";
    for (name, bounds, labels, accepted) in [
        ("missing labels", limits, None, true),
        ("empty labels", limits, Some(json!([])), true),
        (
            "case insensitive allow",
            limits,
            Some(json!(["TRIAGE"])),
            true,
        ),
        ("disallowed label", limits, Some(json!(["other"])), false),
        (
            "block takes precedence",
            limits,
            Some(json!(["BLOCKED"])),
            false,
        ),
        (
            "mixed labels",
            limits,
            Some(json!(["triage", "other"])),
            false,
        ),
        ("empty allow without labels", ", allowed = []", None, true),
        (
            "empty allow with empty labels",
            ", allowed = []",
            Some(json!([])),
            true,
        ),
        (
            "empty allow with label",
            ", allowed = []",
            Some(json!(["triage"])),
            false,
        ),
        (
            "block only without labels",
            ", blocked = ['blocked']",
            None,
            true,
        ),
        (
            "block only other label",
            ", blocked = ['blocked']",
            Some(json!(["other"])),
            true,
        ),
        (
            "block only blocked label",
            ", blocked = ['blocked']",
            Some(json!(["BLOCKED"])),
            false,
        ),
    ] {
        let mut item = issue();
        if let Some(labels) = labels {
            item["labels"] = labels;
        }
        check_case(
            name,
            bounds,
            &[item],
            false,
            (!accepted).then_some("label limits"),
        );
    }
}
