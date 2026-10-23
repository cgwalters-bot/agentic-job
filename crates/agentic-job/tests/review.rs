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
