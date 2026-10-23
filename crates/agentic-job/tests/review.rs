//! The policy workflow validates routing before its read-only API call, then
//! resolves the API snapshot without fetching or executing the reviewed code.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};

fn review(command: &str, pull: Option<&Path>) -> Output {
    let mut cli = Command::new(env!("CARGO_BIN_EXE_agentic-job"));
    cli.args(["review", command]);
    cli.envs([
        ("REVIEW", "true"),
        ("EVENT", "false"),
        ("KIND", "analysis"),
        ("OUTPUTS", "add_comment,noop"),
        ("MAX_OUTPUTS", "1"),
        ("NOTIFY", "none"),
        ("APPLY_PARTIAL", "false"),
        ("ITEM", "147"),
        ("TARGET", "147"),
        ("REPO", "o/r"),
        ("BASE", "main"),
        ("OUTPUT_REPO", ""),
    ]);
    if let Some(pull) = pull {
        cli.arg("--pull-request").arg(pull);
    }
    cli.output().unwrap()
}

#[test]
fn policy_dispatch_uses_a_validated_target_and_returns_only_the_exact_sha() {
    let target = review("dispatch-target", None);
    assert!(target.status.success(), "{target:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&target.stdout).unwrap(),
        json!({"owner":"o", "repo":"r", "pull_number":147})
    );

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("pull.json");
    let sha = "a".repeat(40);
    let mut pull = open_pull();
    pull["head"]["ref"] = json!("--upload-pack=evil");
    pull["head"]["repo"]["full_name"] = json!("fork/r");
    std::fs::write(&file, pull.to_string()).unwrap();
    let resolved = review("resolve-dispatch", Some(&file));
    assert!(resolved.status.success(), "{resolved:?}");
    assert_eq!(resolved.stdout, format!("{sha}\n").as_bytes());

    pull["base"]["repo"]["full_name"] = json!("other/r");
    std::fs::write(&file, pull.to_string()).unwrap();
    let refused = review("resolve-dispatch", Some(&file));
    assert_eq!(refused.status.code(), Some(2), "{refused:?}");
    assert!(refused.stdout.is_empty());
}

#[test]
fn the_task_command_appends_the_base_merge_policy_and_admit_narrows_the_event() {
    let dir = tempfile::tempdir().unwrap();
    let task = || {
        Command::new(env!("CARGO_BIN_EXE_agentic-job"))
            .args(["review", "task", "task.md"])
            .current_dir(dir.path())
            .envs([
                ("EVENT", "true"),
                ("KIND", "analysis"),
                (
                    "OUTPUTS",
                    "add_comment,noop,create_pull_request_review_comment",
                ),
                ("MAX_OUTPUTS", "11"),
                ("NOTIFY", "none"),
                ("REPO", "o/r"),
                ("GITHUB_REPOSITORY", "o/r"),
                ("APPLY_PARTIAL", "false"),
                ("AGENT", "fake"),
            ])
            .output()
            .unwrap()
    };
    std::fs::write(dir.path().join("task.md"), "Trusted base task\n").unwrap();
    let unset = task();
    assert!(unset.status.success(), "{unset:?}");
    let unset = String::from_utf8(unset.stdout).unwrap();
    assert!(
        unset.starts_with("Trusted base task\n\n\n## Merge policy\n\nThe default branch has no")
    );
    let policy = dir.path().join(".github/agentic-job/merge.toml");
    std::fs::create_dir_all(policy.parent().unwrap()).unwrap();
    std::fs::write(&policy, "merge = \"agent\"\n").unwrap();
    let agent = String::from_utf8(task().stdout).unwrap();
    assert!(
        agent
            .starts_with("Trusted base task\n\n\n## Merge policy\n\nThe repository owner set this")
    );
    assert!(agent.contains("merge = \"agent\": an approving review"));
    // A malformed policy fails the run instead of being guessed at.
    std::fs::write(&policy, "merge = \"always\"\n").unwrap();
    let refused = task();
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("may hold only"));

    let decision = dir.path().join("event.json");
    let admit = |base: &str| {
        let got = Command::new(env!("CARGO_BIN_EXE_agentic-job"))
            .args(["review", "admit", "--base", base, "--decision"])
            .arg(&decision)
            .output()
            .unwrap();
        assert!(got.status.success(), "{got:?}");
        serde_json::from_slice::<Value>(&got.stdout).unwrap()
    };
    let event = json!({"admitted":true, "reason":"member", "event":"pull_request", "action":"opened",
        "item":{"kind":"pull_request", "number":147}, "base":"main", "head":{"sha":"a".repeat(40)}});
    std::fs::write(&decision, event.to_string()).unwrap();
    assert_eq!(admit("main"), event);
    let refused = admit("other");
    assert_eq!(refused["admitted"], false);
    assert_eq!(refused["head"], event["head"]);
}

/// A pull request the dispatch in `review` accepts.
fn open_pull() -> Value {
    json!({"number":147, "state":"open",
        "base":{"ref":"main", "repo":{"full_name":"o/r"}},
        "head":{"sha":"a".repeat(40), "repo":{"full_name":"o/r"}}})
}

#[test]
fn resolver_refuses_links_and_oversized_api_snapshots_without_a_sha() {
    let dir = tempfile::tempdir().unwrap();
    // The link names a snapshot that is accepted when read directly, so
    // only the link can be why it is refused.
    let valid = dir.path().join("valid.json");
    std::fs::write(&valid, open_pull().to_string()).unwrap();
    assert!(review("resolve-dispatch", Some(&valid)).status.success());
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&valid, &link).unwrap();
    let large = dir.path().join("large.json");
    std::fs::File::create(&large)
        .unwrap()
        .set_len((4 << 20) + 1)
        .unwrap();
    for path in [&large, &link] {
        let refused = review("resolve-dispatch", Some(path));
        assert_eq!(refused.status.code(), Some(2), "{refused:?}");
        assert!(refused.stdout.is_empty());
    }
}

/// check.yml takes the verdict from stdout and, on a refusal, the report
/// its refusal step reads; check then uploads the folded output for apply.
#[test]
fn check_gets_one_verdict_word_or_a_refusal_report_and_the_folded_output() {
    let dir = tempfile::tempdir().unwrap();
    let collected = dir.path().join("agent_output.json");
    let report = dir.path().join("report.json");
    let cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_agentic-job"))
            .arg("review")
            .args(args)
            .output()
            .unwrap()
    };
    let verdict = || {
        cli(&[
            "verdict",
            "--target",
            "147",
            "--collected",
            collected.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
        ])
    };
    let inline = json!({"type": "create_pull_request_review_comment", "path": "a.rs", "line": 3, "body": "nit: x"});
    let output = json!({"items": [{"type": "add_comment", "body": "VERDICT: CHANGES\nOne."}, inline], "errors": []});
    std::fs::write(&collected, output.to_string()).unwrap();
    let got = verdict();
    assert!(got.status.success(), "{got:?}");
    assert_eq!(got.stdout, b"CHANGES\n");
    assert!(!report.exists());

    let folded = cli(&["fold", collected.to_str().unwrap()]);
    assert!(folded.status.success(), "{folded:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&folded.stdout).unwrap(),
        json!({"items": [{"type": "add_comment",
            "body": "VERDICT: CHANGES\nOne.\n\n### Inline findings\n\n**a.rs, line 3**\n\nnit: x\n"}],
            "errors": []})
    );

    std::fs::write(&collected, json!({"items": [{"type": "noop"}]}).to_string()).unwrap();
    assert_eq!(verdict().stdout, b"\n");
    std::fs::write(&collected, json!({"items": [inline]}).to_string()).unwrap();
    let refused = verdict();
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert!(refused.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&report).unwrap()).unwrap(),
        json!({"ok": false, "errors": ["Review must return exactly one comment or noop"]})
    );

    let refusal = Command::new(env!("CARGO_BIN_EXE_agentic-job"))
        .args(["review", "refusal"])
        .env("REASON", "a\n@user [link](url)")
        .output()
        .unwrap();
    assert_eq!(
        refusal.stdout,
        b"Review refused by policy: a \\@user \\[link\\]\\(url\\)\n"
    );
}
