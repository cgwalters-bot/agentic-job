//! Issue-creation admission through the shipped policy, collector and checker.

use std::process::Command;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

#[test]
fn bounded_issue_creation() {
    let issue = json!({"type":"create_issue", "title":"A flaky test in nightly",
        "body":"The nightly run fails once a week on the same test."});
    let noop = json!({"type":"noop", "message":"Nothing else to do."});
    let with = |key: &str, value: Value| {
        let mut item = issue.clone();
        item[key] = value;
        item
    };
    let mut cases = vec![
        ("one issue and noop", "", vec![issue.clone(), noop], None),
        (
            "two issues",
            "",
            vec![issue.clone(), issue.clone()],
            Some("Too many items of type 'create_issue'"),
        ),
        (
            "missing title",
            "",
            vec![json!({"type":"create_issue", "body":issue["body"]})],
            Some("title"),
        ),
        (
            "short body",
            "",
            vec![with("body", json!("x"))],
            Some("body"),
        ),
        (
            "parent relationship",
            "",
            vec![with("parent", json!(7))],
            Some("links another issue"),
        ),
    ];
    let limits = ", allowed = ['triage', 'blocked'], blocked = ['blocked']";
    for (name, bounds, labels, refusal) in [
        ("missing labels", limits, None, false),
        ("empty labels", limits, Some(json!([])), false),
        (
            "case insensitive allowed",
            limits,
            Some(json!(["TRIAGE"])),
            false,
        ),
        ("disallowed", limits, Some(json!(["other"])), true),
        (
            "blocked takes precedence",
            limits,
            Some(json!(["BLOCKED"])),
            true,
        ),
        (
            "mixed labels",
            limits,
            Some(json!(["triage", "other"])),
            true,
        ),
        (
            "empty allowed missing labels",
            ", allowed = []",
            None,
            false,
        ),
        (
            "empty allowed empty labels",
            ", allowed = []",
            Some(json!([])),
            false,
        ),
        (
            "empty allowed with label",
            ", allowed = []",
            Some(json!(["triage"])),
            true,
        ),
        (
            "blocked only missing labels",
            ", blocked = ['blocked']",
            None,
            false,
        ),
        (
            "blocked only other label",
            ", blocked = ['blocked']",
            Some(json!(["other"])),
            false,
        ),
        (
            "blocked only blocked label",
            ", blocked = ['blocked']",
            Some(json!(["BLOCKED"])),
            true,
        ),
    ] {
        let mut item = issue.clone();
        if let Some(labels) = labels {
            item["labels"] = labels;
        }
        cases.push((name, bounds, vec![item], refusal.then_some("label limits")));
    }

    for (name, limits, items, refusal) in cases {
        // Each case gets fresh artifacts; a failed command cannot reuse a verdict.
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);
        std::fs::write(path("bounds.toml"), format!(
            "hosts = ['github.com']\nrepos = ['example/repo']\nbases = ['main']\nmax_outputs = 2\nmax_patch_bytes = 4096\nmax_patch_files = 2\n[github.outputs]\ncreate_issue = {{ max = 1{limits} }}\nnoop = {{ max = 1 }}\n"
        )).unwrap();
        let policy = Command::new(BIN)
            .args([
                "policy",
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
                "--allow",
            ])
            .arg(path("bounds.toml"))
            .output()
            .unwrap();
        assert!(policy.status.success(), "{name}: {policy:?}");
        let parsed: Value = serde_json::from_slice(&policy.stdout).unwrap();
        assert_eq!(parsed["safe_outputs"]["create_issue"]["max"], 1);
        std::fs::write(path("policy.json"), policy.stdout).unwrap();
        std::fs::create_dir(path("out")).unwrap();
        std::fs::write(
            path("out/outputs.jsonl"),
            items
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
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
            Some(i32::from(matches!(
                name,
                "two issues" | "missing title" | "short body"
            ))),
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
            .arg(path("verdict.json"))
            .output()
            .unwrap();
        assert_eq!(
            checked.status.code(),
            Some(i32::from(refusal.is_some())),
            "{name}: {checked:?}"
        );
        let verdict: Value =
            serde_json::from_slice(&std::fs::read(path("verdict.json")).unwrap()).unwrap();
        assert_eq!(verdict["ok"], refusal.is_none(), "{name}: {verdict}");
        assert!(verdict["patch"].is_null(), "{name}: {verdict}");
        if let Some(refusal) = refusal {
            assert!(
                verdict["errors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|error| error.as_str().unwrap().contains(refusal)),
                "{name}: {verdict}"
            );
        } else {
            assert_eq!(verdict["errors"], json!([]), "{name}: {verdict}");
            assert_eq!(verdict["items"], json!(items), "{name}: {verdict}");
        }
    }
}
