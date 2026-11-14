//! Bounded issue actions through the serialized policy/collect/check contract.

use std::process::Command;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");
const REPO: &str = "example-org/example";

#[test]
fn bounded_issue_actions_require_an_explicit_target_and_authorized_labels() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    std::fs::write(
        path("bounds.toml"),
        format!(
            "hosts = ['github.com']\nrepos = ['{REPO}']\nbases = ['main']\n\
             max_outputs = 2\nmax_patch_bytes = 4096\nmax_patch_files = 2\n\
             [github.outputs]\nclose_issue = {{ max = 1 }}\n\
             add_labels = {{ max = 1, allowed = ['triage', 'blocked'], blocked = ['blocked'] }}\n"
        ),
    )
    .unwrap();
    let policy = Command::new(BIN)
        .args(["policy", "--allow"])
        .arg(path("bounds.toml"))
        .args(["--repo", REPO, "--clone-url"])
        .arg(format!("https://github.com/{REPO}"))
        .args([
            "--base",
            "main",
            "--kind",
            "analysis",
            "--outputs",
            "close_issue,add_labels",
            "--max-outputs",
            "2",
        ])
        .output()
        .unwrap();
    assert!(policy.status.success(), "{policy:?}");
    let value: Value = serde_json::from_slice(&policy.stdout).unwrap();
    assert_eq!(value["safe_outputs"]["close_issue"], json!({"max": 1}));
    assert_eq!(
        value["safe_outputs"]["add_labels"],
        json!({
            "max": 1, "allowed": ["triage", "blocked"], "blocked": ["blocked"]
        })
    );
    std::fs::write(path("policy.json"), policy.stdout).unwrap();
    std::fs::create_dir(path("out")).unwrap();

    for (kind, target) in [
        ("close_issue", "issue_number"),
        ("add_labels", "item_number"),
    ] {
        let item = if kind == "close_issue" {
            json!({"type": kind, "repo": REPO, target: 7, "body": "Done in #8."})
        } else {
            json!({"type": kind, "repo": REPO, target: 7, "labels": ["triage"]})
        };
        let mut cases = vec![
            ("accepted", None, true),
            (
                "another repository",
                Some(("repo", json!("other/repo"))),
                false,
            ),
            ("no repository", Some(("repo", Value::Null)), false),
            ("no number", Some((target, Value::Null)), false),
            ("zero number", Some((target, json!(0))), false),
            ("over count", None, false),
        ];
        if kind == "add_labels" {
            cases.extend([
                (
                    "case-insensitive allowed label",
                    Some(("labels", json!(["TRIAGE"]))),
                    true,
                ),
                (
                    "disallowed label",
                    Some(("labels", json!(["release"]))),
                    false,
                ),
                ("blocked label", Some(("labels", json!(["BLOCKED"]))), false),
                (
                    "mixed labels",
                    Some(("labels", json!(["triage", "release"]))),
                    false,
                ),
                (
                    "label object",
                    Some(("labels", json!([{"name": "triage"}]))),
                    false,
                ),
            ]);
        } else {
            cases.extend([
                (
                    "duplicate relationship",
                    Some(("duplicate_of", json!("other/repo#8"))),
                    false,
                ),
                ("no closing comment", Some(("body", Value::Null)), false),
                (
                    "blank closing comment",
                    Some(("body", json!(" \n "))),
                    false,
                ),
            ]);
        }
        for (case, change, accepted) in cases {
            let mut candidate = item.clone();
            if let Some((key, value)) = change {
                if value.is_null() {
                    candidate.as_object_mut().unwrap().remove(key);
                } else {
                    candidate[key] = value;
                }
            }
            let lines = if case == "over count" {
                format!("{candidate}\n{candidate}\n")
            } else {
                format!("{candidate}\n")
            };
            std::fs::write(path("out/outputs.jsonl"), lines).unwrap();
            // Never let a stale result make a failed command look successful.
            for name in ["collected.json", "report.json"] {
                if path(name).exists() {
                    std::fs::remove_file(path(name)).unwrap();
                }
            }
            let collected = Command::new(BIN)
                .args(["collect", "--policy"])
                .arg(path("policy.json"))
                .arg("--outputs")
                .arg(path("out"))
                .arg("--collected")
                .arg(path("collected.json"))
                .output()
                .unwrap();
            assert!(
                matches!(collected.status.code(), Some(0 | 1)),
                "{kind}/{case}: {collected:?}"
            );
            if accepted {
                assert!(collected.status.success(), "{kind}/{case}: {collected:?}");
            }
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
            assert_eq!(
                checked.status.code(),
                Some(i32::from(!accepted)),
                "{kind}/{case}: {checked:?}"
            );
            let report: Value =
                serde_json::from_slice(&std::fs::read(path("report.json")).unwrap()).unwrap();
            assert_eq!(report["ok"], accepted, "{kind}/{case}: {report}");
            assert!(report["patch"].is_null(), "{kind}/{case}: {report}");
            if accepted {
                assert_eq!(report["errors"], json!([]), "{kind}/{case}: {report}");
                assert_eq!(
                    report["items"],
                    json!([candidate]),
                    "{kind}/{case}: {report}"
                );
            } else {
                let expected = match case {
                    "another repository" | "no repository" => "repo",
                    "no number" | "zero number" => target,
                    "over count" => "Too many items of type",
                    "duplicate relationship" => "duplicate_of",
                    "no closing comment" | "blank closing comment" => "body",
                    _ => "label",
                };
                assert!(
                    report["errors"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|error| { error.as_str().unwrap().contains(expected) }),
                    "{kind}/{case}: expected {expected:?}: {report}"
                );
            }
        }
    }
}
