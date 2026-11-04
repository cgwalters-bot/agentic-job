//! `agentic-job check` as the check job runs it: `policy`'s own output,
//! a hand-back that git made (`data/check/handback`), and the exit states.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

#[test]
fn neutral_inline_comments_record_only_the_trusted_head_and_item() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    for forge in ["forgejo", "gitlab"] {
        let bounds = dir.path().join("bounds.toml");
        std::fs::write(&bounds, format!(
            "hosts = [\"forge.example\"]\nrepos = [\"owner/name\"]\nbases = [\"main\"]\nmax_outputs = 2\nmax_patch_bytes = 4096\nmax_patch_files = 2\n[{forge}.outputs]\ncreate_pull_request_review_comment = {{ max = 2 }}\n"
        )).unwrap();
        let made = Command::new(BIN)
            .args([
                "policy",
                "--repo",
                "owner/name",
                "--clone-url",
                "https://forge.example/owner/name",
                "--base",
                "main",
                "--kind",
                "analysis",
                "--outputs",
                "create_pull_request_review_comment",
                "--max-outputs",
                "2",
                "--allow",
            ])
            .arg(&bounds)
            .output()
            .unwrap();
        assert!(
            made.status.success(),
            "{}",
            String::from_utf8_lossy(&made.stderr)
        );
        let policy = dir.path().join("policy.json");
        std::fs::write(&policy, made.stdout).unwrap();
        let item = serde_json::json!({"type": "create_pull_request_review_comment", "repo": "owner/name",
            "pull_request_number": 9, "path": "src/x", "line": 2, "body": "Finding."});
        std::fs::write(out.join("outputs.jsonl"), item.to_string()).unwrap();
        let collected = dir.path().join("collected.json");
        let result = Command::new(BIN)
            .arg("collect")
            .arg("--policy")
            .arg(&policy)
            .arg("--outputs")
            .arg(&out)
            .arg("--collected")
            .arg(&collected)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report = dir.path().join("report.json");
        for (head, accepted) in [
            (None, false),
            (Some("bad"), false),
            (Some("2222222222222222222222222222222222222222"), true),
        ] {
            let mut command = Command::new(BIN);
            command
                .arg("check")
                .arg("--policy")
                .arg(&policy)
                .arg("--outputs")
                .arg(&out)
                .arg("--collected")
                .arg(&collected)
                .arg("--report")
                .arg(&report)
                .args(["--comment-repo", "owner/name", "--comment-target", "9"]);
            if let Some(head) = head {
                command.args(["--review-head", head]);
            }
            let result = command.output().unwrap();
            assert_eq!(
                result.status.success(),
                accepted,
                "{forge}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let verdict: Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
            if accepted {
                assert_eq!(
                    verdict["inline_target"],
                    serde_json::json!({"repo": "owner/name", "number": 9, "head": head})
                );
            } else {
                assert!(verdict["inline_target"].is_null());
            }
        }
    }
}

#[test]
fn analysis_comments_use_the_callers_destination_without_a_checkout() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let policy = Command::new(BIN)
        .args([
            "policy",
            "--repo",
            "bootc-dev/bootc",
            "--clone-url",
            "https://github.com/bootc-dev/bootc",
            "--base",
            "bot/topic",
            "--kind",
            "analysis",
            "--outputs",
            "add_comment",
            "--max-outputs",
            "1",
            "--allow",
        ])
        .arg(data("policy/allow.toml"))
        .output()
        .unwrap();
    assert!(
        policy.status.success(),
        "{}",
        String::from_utf8_lossy(&policy.stderr)
    );
    let policy_path = dir.path().join("policy.json");
    std::fs::write(&policy_path, policy.stdout).unwrap();
    for (fields, code) in [
        (serde_json::json!({}), 0),
        (
            serde_json::json!({"repo": "tracker/items", "item_number": 170}),
            0,
        ),
        (
            serde_json::json!({"repo": "bootc-dev/bootc", "item_number": 170}),
            1,
        ),
        (
            serde_json::json!({"repo": "tracker/items", "item_number": 171}),
            1,
        ),
        (serde_json::json!({"pr_number": 171}), 1),
    ] {
        let mut item = fields.as_object().unwrap().clone();
        item.insert("type".into(), serde_json::json!("add_comment"));
        item.insert("body".into(), serde_json::json!("Analysis result."));
        std::fs::write(
            out.join("outputs.jsonl"),
            serde_json::to_vec(&item).unwrap(),
        )
        .unwrap();
        let collected = dir.path().join("collected.json");
        std::fs::write(
            &collected,
            serde_json::to_vec(&serde_json::json!({"items": [item], "errors": []})).unwrap(),
        )
        .unwrap();
        let report = dir.path().join("report.json");
        let result = Command::new(BIN)
            .arg("check")
            .arg("--policy")
            .arg(&policy_path)
            .arg("--outputs")
            .arg(&out)
            .arg("--collected")
            .arg(&collected)
            .arg("--report")
            .arg(&report)
            .args(["--comment-repo", "tracker/items", "--comment-target", "170"])
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(code),
            "{fields}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let verdict: Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
        assert!(verdict["patch"].is_null());
    }
}

fn data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

/// A scratch directory holding the policy of a run that may open a pull
/// request, and a copy of the hand-back.
struct Run {
    dir: tempfile::TempDir,
}

impl Run {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let policy = Command::new(BIN)
            .args([
                "policy",
                "--repo",
                "bootc-dev/bootc",
                "--base",
                "main",
                "--kind",
                "branch",
            ])
            .args(["--clone-url", "https://github.com/bootc-dev/bootc"])
            .args([
                "--outputs",
                "create_pull_request",
                "--max-outputs",
                "1",
                "--allow",
            ])
            .arg(data("policy/allow.toml"))
            .output()
            .expect("running agentic-job");
        assert!(
            policy.status.success(),
            "{}",
            String::from_utf8_lossy(&policy.stderr)
        );
        std::fs::write(dir.path().join("policy.json"), policy.stdout).expect("writing the policy");
        let out = dir.path().join("out");
        std::fs::create_dir(&out).expect("making the outputs directory");
        for entry in
            std::fs::read_dir(data("check/handback")).expect("the hand-back of the test data")
        {
            let entry = entry.expect("an entry of the test data");
            std::fs::copy(entry.path(), out.join(entry.file_name()))
                .expect("copying the hand-back");
        }
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn check(&self, collected: &Path) -> Output {
        Command::new(BIN)
            .arg("check")
            .arg("--policy")
            .arg(self.path("policy.json"))
            .arg("--outputs")
            .arg(self.path("out"))
            .arg("--collected")
            .arg(collected)
            .arg("--report")
            .arg(self.path("verdict.json"))
            .output()
            .expect("running agentic-job")
    }

    fn verdict(&self) -> Value {
        let report = std::fs::read(self.path("verdict.json")).expect("the report was written");
        serde_json::from_slice(&report).expect("the report is JSON")
    }
}

#[test]
fn a_hand_back_within_the_policy_is_accepted() {
    let run = Run::new();
    let output = run.check(&data("check/collected.json"));
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("### Safe outputs: accepted\n"));
    let verdict = run.verdict();
    assert_eq!(verdict["ok"], true);
    assert_eq!(verdict["errors"], serde_json::json!([]));
    assert_eq!(verdict["items"][0]["title"], "Fix the thing");
    assert_eq!(verdict["patch"]["file"], "aw-agent-run-7.patch");
    assert_eq!(
        verdict["patch"]["files"],
        serde_json::json!(["src/lib.rs", "src/new.rs"])
    );
    assert_eq!(
        verdict["patch"]["base_commit"],
        "5fffa916418485beea9050be41cc38857f49c3a1"
    );
}

#[test]
fn public_base_evidence_cannot_complete_an_incomplete_key() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    let run = Run::new();
    let repo = run.path("repo");
    std::fs::create_dir(&repo).unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .current_dir(&repo)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.test")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.test")
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        String::from_utf8(output.stdout).unwrap()
    };
    git(&["init", "-q", "-b", "main"]);
    let header = ["-----BEGIN ", "PRIVATE KEY", "-----"].concat();
    let footer = ["-----END ", "PRIVATE KEY", "-----"].concat();
    let first = format!("const end = '{footer}'; const key = `{header}\n");
    std::fs::write(repo.join("fixture"), format!("{first}`;\n")).unwrap();
    git(&["add", "fixture"]);
    git(&["-c", "core.hooksPath=/dev/null", "commit", "-qm", "Base"]);
    let base = git(&["rev-parse", "HEAD"]).trim().to_owned();
    let mut policy: Value =
        serde_json::from_slice(&std::fs::read(run.path("policy.json")).unwrap()).unwrap();
    policy["clone_url"] = format!("file://{}", repo.display()).into();
    policy["max_patch_bytes"] = (1 << 20).into();
    std::fs::write(run.path("policy.json"), policy.to_string()).unwrap();
    std::fs::write(
        run.path("config.toml"),
        "[commit]\nallow-base-secret-lines = true\n",
    )
    .unwrap();
    let capture = Command::new(BIN)
        .arg("capture-base-secrets")
        .arg("--config")
        .arg(run.path("config.toml"))
        .arg("--policy")
        .arg(run.path("policy.json"))
        .args(["--run-id", "7", "--output"])
        .arg(run.path("evidence.json"))
        .output()
        .unwrap();
    assert!(capture.status.success(), "{:?}", capture.stderr);

    // Generate a real key only at runtime; none of its body was in the base.
    let key =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let body = STANDARD.encode(key.as_ref());
    std::fs::write(
        repo.join("fixture"),
        format!("{first}{body}\n{footer}\n`;\n"),
    )
    .unwrap();
    let added = git(&["diff", "--no-ext-diff", "--no-renames"]);
    // Even a removed header must not authenticate invented old body lines.
    // Such a patch can disclose the key before git am eventually refuses it.
    let removed = format!(
        "diff --git a/fixture b/fixture\nindex 1234567..abcdef0 100644\n--- a/fixture\n+++ b/fixture\n@@ -1,4 +1 @@\n-{first}-{body}\n-{footer}\n-`;\n+after\n"
    );
    std::fs::write(
        run.path("out/base.json"),
        serde_json::json!({"repo": "bootc-dev/bootc", "ref": "main", "commit": base}).to_string(),
    )
    .unwrap();
    for (case, diff) in [("added body", added), ("invented removed body", removed)] {
        let patch = format!(
            "From {} Mon Sep 17 00:00:00 2001\nX-GH-AW-Base-Commit: {base}\nFrom: Test <test@example.test>\nDate: Tue, 3 Nov 2026 00:00:00 +0000\nSubject: [PATCH] Test\n\n---\n{diff}",
            "2".repeat(40)
        );
        std::fs::write(run.path("out/aw-agent-run-7.patch"), patch).unwrap();
        for evidence in [false, true] {
            let mut command = Command::new(BIN);
            command
                .arg("check")
                .arg("--policy")
                .arg(run.path("policy.json"))
                .arg("--outputs")
                .arg(run.path("out"))
                .arg("--collected")
                .arg(data("check/collected.json"))
                .arg("--report")
                .arg(run.path("verdict.json"));
            if evidence {
                command
                    .arg("--base-secret-evidence")
                    .arg(run.path("evidence.json"));
            }
            let result = command.output().unwrap();
            assert_eq!(
                result.status.code(),
                Some(1),
                "{case}, evidence={evidence}: {:?}",
                result.stderr
            );
            assert!(
                run.verdict()["errors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|error| { error.as_str().unwrap().contains("private key") }),
                "{}",
                run.verdict()
            );
        }
    }
}

#[test]
fn a_hand_back_outside_the_policy_is_refused_with_its_reasons() {
    let run = Run::new();
    std::fs::write(run.path("out/notes.txt"), "hi").unwrap();
    let output = run.check(&data("check/collected.json"));
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error: unexpected file \"notes.txt\""),
        "{stderr}"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("- refused: unexpected file"));
    let verdict = run.verdict();
    assert_eq!(verdict["ok"], false);
    assert_eq!(
        verdict["errors"],
        serde_json::json!(["unexpected file \"notes.txt\""])
    );
}

/// The hand-backs of two real runs (`safe-outputs/fixtures`, which the
/// safe-outputs probe also applies), each through `collect` and `check`
/// under a policy of the kind its run had: both are accepted whole.
#[test]
fn the_hand_backs_of_real_runs_are_accepted() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../safe-outputs/fixtures");
    for (name, repo, kind, outputs) in [
        (
            "create-pull-request",
            "cgwalters-bot/homegit",
            "branch",
            "create_pull_request,noop,missing_tool",
        ),
        (
            "add-comment",
            "cgwalters-bot/homegit",
            "analysis",
            "add_comment,noop,missing_data",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = |file: &str| dir.path().join(file);
        let policy = Command::new(BIN)
            .args(["policy", "--repo", repo, "--base", "main"])
            .args(["--kind", kind])
            .arg("--clone-url")
            .arg(format!("https://github.com/{repo}"))
            .args(["--outputs", outputs, "--max-outputs", "3", "--allow"])
            .arg(data("policy/allow.toml"))
            .output()
            .unwrap();
        assert!(
            policy.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&policy.stderr)
        );
        std::fs::write(path("policy.json"), policy.stdout).unwrap();
        let from = fixtures.join(name);
        let source: Value =
            serde_json::from_slice(&std::fs::read(from.join("source.json")).unwrap()).unwrap();
        std::fs::create_dir(path("out")).unwrap();
        for file in source["files"].as_array().unwrap() {
            let file = file.as_str().unwrap();
            std::fs::copy(from.join(file), path("out").join(file)).unwrap();
        }
        for (command, written) in [("collect", "--collected"), ("check", "--report")] {
            let mut run = Command::new(BIN);
            run.arg(command)
                .arg("--policy")
                .arg(path("policy.json"))
                .arg("--outputs")
                .arg(path("out"));
            if command == "check" {
                run.arg("--collected").arg(path("collect.json"));
            }
            let output = run
                .arg(written)
                .arg(path(&format!("{command}.json")))
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(0),
                "{name}: {command}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let verdict: Value =
            serde_json::from_slice(&std::fs::read(path("check.json")).unwrap()).unwrap();
        assert_eq!(verdict["ok"], true, "{name}: {verdict}");
        assert_eq!(verdict["items"].as_array().unwrap().len(), 1, "{name}");
    }
}

#[test]
fn a_check_that_cannot_be_made_is_an_error_and_writes_no_verdict() {
    let run = Run::new();
    let not_json = run.path("collected.json");
    std::fs::write(&not_json, "the collector failed").unwrap();
    for (collected, want) in [
        (run.path("missing.json"), "the collector's result"),
        (not_json, "is not the result of gh-aw's collector"),
    ] {
        let output = run.check(&collected);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(stderr.contains(want), "{stderr}");
        assert!(!run.path("verdict.json").exists());
    }
}
