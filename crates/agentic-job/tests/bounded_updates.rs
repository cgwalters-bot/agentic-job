//! Bounded-update corpus through the shipped policy, collector and checker.

use std::process::Command;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");
const READY: &str = "mark_pull_request_as_ready_for_review";

struct Run {
    dir: tempfile::TempDir,
}

impl Run {
    fn new(ready: bool) -> Self {
        let dir = tempfile::tempdir().expect("scratch directory");
        let bounds = format!(
            "hosts = ['github.com']\nrepos = ['example/repo']\nbases = ['main']\nmax_outputs = 2\nmax_patch_bytes = 4096\nmax_patch_files = 2\n[github.outputs]\nupdate_issue = {{ max = 1, fields = ['body'] }}\nupdate_pull_request = {{ max = 1, fields = ['title'] }}\n{}",
            if ready {
                format!("{READY} = {{ max = 1 }}\n")
            } else {
                String::new()
            }
        );
        std::fs::write(dir.path().join("bounds.toml"), bounds).expect("write bounds");
        std::fs::create_dir(dir.path().join("out")).expect("create outputs directory");
        Self { dir }
    }

    fn policy(&self, outputs: &str, accepted: bool) {
        let result = Command::new(BIN)
            .args(["policy", "--allow"])
            .arg(self.dir.path().join("bounds.toml"))
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
                outputs,
                "--max-outputs",
                "2",
            ])
            .output()
            .expect("run policy");
        assert_eq!(
            result.status.code(),
            Some(i32::from(!accepted)),
            "{result:?}"
        );
        if accepted {
            std::fs::write(self.dir.path().join("policy.json"), result.stdout)
                .expect("write policy");
        }
    }

    fn check(&self, name: &str, item: Value, error: Option<&str>) {
        let path = |name| self.dir.path().join(name);
        std::fs::write(path("out/outputs.jsonl"), format!("{item}\n")).expect("write request");
        // Remove results so no previous case can supply a passing verdict.
        for file in ["collected.json", "verdict.json"] {
            if path(file).exists() {
                std::fs::remove_file(path(file)).expect("remove previous result");
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
            .expect("run collector");
        if error == Some("Unexpected output type") {
            assert_eq!(collected.status.code(), Some(1), "{name}: {collected:?}");
            assert!(
                String::from_utf8_lossy(&collected.stderr).contains("Unexpected output type"),
                "{name}: {collected:?}"
            );
            assert!(!path("verdict.json").exists());
            return;
        }
        assert_eq!(collected.status.code(), Some(0), "{name}: {collected:?}");
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
            .expect("run checker");
        assert_eq!(
            checked.status.code(),
            Some(i32::from(error.is_some())),
            "{name}: {checked:?}"
        );
        let verdict: Value =
            serde_json::from_slice(&std::fs::read(path("verdict.json")).expect("read verdict"))
                .expect("JSON verdict");
        assert_eq!(verdict["ok"], error.is_none(), "{name}: {verdict}");
        assert!(verdict["patch"].is_null(), "{name}: {verdict}");
        if let Some(error) = error {
            assert!(
                verdict["errors"]
                    .as_array()
                    .expect("error array")
                    .iter()
                    .any(|value| value.as_str().expect("error string").contains(error)),
                "{name}: {verdict}"
            );
        } else {
            assert_eq!(verdict["errors"], json!([]), "{name}: {verdict}");
            assert_eq!(verdict["items"], json!([item]), "{name}: {verdict}");
        }
    }
}

#[test]
fn updates_change_only_the_fields_the_bounds_list() {
    let run = Run::new(false);
    run.policy("update_issue,update_pull_request", true);
    let issue = json!({"type":"update_issue", "repo":"example/repo", "issue_number":7, "body":"b"});
    let pull = json!({"type":"update_pull_request", "repo":"example/repo", "pull_request_number":7, "title":"t"});
    run.check("issue body", issue.clone(), None);
    run.check("pull request title", pull.clone(), None);
    for (name, original, key, value, error) in [
        (
            "body section",
            &issue,
            "operation",
            json!("replace-island"),
            None,
        ),
        (
            "another repository",
            &issue,
            "repo",
            json!("other/repo"),
            Some("requires the policy's explicit repo"),
        ),
        (
            "no number",
            &issue,
            "issue_number",
            Value::Null,
            Some("requires a positive integer issue_number"),
        ),
        (
            "unlisted issue title",
            &issue,
            "title",
            json!("t"),
            Some("with title, which the policy does not let it change"),
        ),
        (
            "unlisted issue status",
            &issue,
            "status",
            json!("closed"),
            Some("with status, which the policy does not let it change"),
        ),
        (
            "issue labels",
            &issue,
            "labels",
            json!(["triage"]),
            Some("with labels, which the policy does not let it change"),
        ),
        (
            "issue assignees",
            &issue,
            "assignees",
            json!(["someone"]),
            Some("with assignees, which the policy does not let it change"),
        ),
        (
            "unlisted pull request body",
            &pull,
            "body",
            json!("b"),
            Some("with body, which the policy does not let it change"),
        ),
        (
            "pull request out of draft",
            &pull,
            "draft",
            json!(false),
            Some("with draft, which the policy does not let it change"),
        ),
        (
            "pull request branch update",
            &pull,
            "update_branch",
            json!(true),
            Some("with update_branch, which the policy does not let it change"),
        ),
    ] {
        let mut item = original.clone();
        if value.is_null() {
            item.as_object_mut().unwrap().remove(key);
        } else {
            item[key] = value;
        }
        run.check(name, item, error);
    }
    let mut alias = pull;
    alias.as_object_mut().unwrap().remove("pull_request_number");
    alias["pr_number"] = json!(7);
    run.check(
        "target alias",
        alias,
        Some("unsupported target field pr_number"),
    );
}

#[test]
fn marking_ready_requires_explicit_bounds_and_target() {
    let ready = json!({"type":READY, "repo":"example/repo", "pull_request_number":7, "reason":"r"});
    let disabled = Run::new(false);
    disabled.policy("update_issue,update_pull_request", true);
    disabled.check(
        "unlisted ready request",
        ready.clone(),
        Some("Unexpected output type"),
    );
    disabled.policy(READY, false);

    let enabled = Run::new(true);
    enabled.policy(READY, true);
    enabled.check("explicit ready bound", ready.clone(), None);
    let mut missing = ready.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("pull_request_number");
    enabled.check(
        "missing target",
        missing,
        Some("requires a positive integer pull_request_number"),
    );
    let mut other = ready;
    other["repo"] = json!("other/repo");
    enabled.check(
        "another repository",
        other,
        Some("requires the policy's explicit repo"),
    );
}
