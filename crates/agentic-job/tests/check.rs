//! `agentic-job check` as the check job runs it: `policy`'s own output,
//! a hand-back that git made (`data/check/handback`), and the exit states.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

#[test]
fn serialized_continuation_policy_requires_exact_trusted_check_context() {
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let bounds = dir.path().join("bounds.toml");
    std::fs::write(&bounds, "hosts = ['github.com']\nrepos = ['example/repo']\nbases = ['main']\nmax_outputs = 1\nmax_patch_bytes = 65536\nmax_patch_files = 10\n[github.outputs]\nnoop = { max = 1 }\n[github.outputs.push_to_pull_request_branch]\nmax = 1\nbranches = ['topic/**']\n").unwrap();
    let head = "a".repeat(40);
    let policy_path = dir.path().join("policy.json");
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    std::fs::write(
        out.join("outputs.jsonl"),
        "{\"type\":\"noop\",\"message\":\"No change\"}\n",
    )
    .unwrap();
    let collected = dir.path().join("collected.json");
    for bound in [false, true] {
        let mut producer = Command::new(BIN);
        producer.args(["policy", "--allow"]).arg(&bounds).args([
            "--repo",
            "example/repo",
            "--output-repo",
            "example/repo",
            "--clone-url",
            "https://github.com/example/repo",
            "--base",
            "topic/fix",
            "--kind",
            "branch",
            "--outputs",
            "push_to_pull_request_branch,noop",
            "--max-outputs",
            "1",
            "--pull-request",
            "12",
            "--head",
            &head,
        ]);
        if bound {
            producer.args(["--continuation-run-id", "7", "--continuation-attempt", "2"]);
        }
        let made = producer.output().unwrap();
        assert!(
            made.status.success(),
            "{}",
            String::from_utf8_lossy(&made.stderr)
        );
        let policy: Value = serde_json::from_slice(&made.stdout).unwrap();
        std::fs::write(&policy_path, &made.stdout).unwrap();
        let identity = json!({"repository":"example/repo", "pull_request":12, "head":head, "run_id":7, "attempt":2});
        assert_eq!(policy.get("continuation"), bound.then_some(&identity));
        let ingest = Command::new(BIN)
            .args(["collect", "--policy"])
            .arg(&policy_path)
            .arg("--outputs")
            .arg(&out)
            .arg("--collected")
            .arg(&collected)
            .output()
            .unwrap();
        assert!(
            ingest.status.success(),
            "{}",
            String::from_utf8_lossy(&ingest.stderr)
        );
        for (field, value) in [
            ("valid", Value::Null),
            ("missing", Value::Null),
            ("repository", json!("other/repo")),
            ("pull_request", json!(13)),
            ("head", json!("b".repeat(40))),
            ("run_id", json!(8)),
            ("attempt", json!(1)),
            ("current-run", json!(8)),
            ("current-attempt", json!(3)),
            ("malformed", Value::Null),
            ("absent-repository", Value::Null),
            ("absent-pull_request", Value::Null),
            ("absent-head", Value::Null),
            ("absent-run_id", Value::Null),
            ("absent-attempt", Value::Null),
            ("duplicate-repository", Value::Null),
            ("duplicate-pull_request", Value::Null),
            ("duplicate-head", Value::Null),
            ("duplicate-run_id", Value::Null),
            ("duplicate-attempt", Value::Null),
        ] {
            let mut context = identity.clone();
            if context.get(field).is_some() {
                context[field] = value;
            }
            if let Some(key) = field.strip_prefix("absent-") {
                context.as_object_mut().unwrap().remove(key);
            }
            // Keep duplicate keys in the serialized input: a Value round trip
            // would erase the malformed wire representation before check saw it.
            let context = if let Some(key) = field.strip_prefix("duplicate-") {
                format!(
                    "{{\"{key}\":{},{}",
                    identity[key],
                    &context.to_string()[1..]
                )
            } else if field == "malformed" {
                "{".to_owned()
            } else {
                context.to_string()
            };
            let report = dir.path().join("report.json");
            // A failed invocation must not leave a previous successful report.
            if report.exists() {
                std::fs::remove_file(&report).unwrap();
            }
            let mut check = Command::new(BIN);
            check
                .args(["check", "--policy"])
                .arg(&policy_path)
                .arg("--outputs")
                .arg(&out)
                .arg("--collected")
                .arg(&collected)
                .arg("--report")
                .arg(&report)
                .args(["--run-id", if field == "current-run" { "8" } else { "7" }]);
            if field != "missing" {
                check.args([
                    "--continuation-context",
                    &context,
                    "--run-attempt",
                    if field == "current-attempt" { "3" } else { "2" },
                ]);
            }
            let result = check.output().unwrap();
            let accepted = (bound && field == "valid") || (!bound && field == "missing");
            assert_eq!(
                result.status.success(),
                accepted,
                "bound={bound} {field}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            if report.exists() {
                let verdict: Value =
                    serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
                assert_eq!(
                    verdict.get("continuation"),
                    (bound && accepted).then_some(&identity)
                );
                assert!(verdict.get("unchanged_completion").is_none());
                assert!(verdict["patch"].is_null());
            }
        }
    }
}

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

/// Port of the legacy corpus's count ceilings, through the real collector.
/// Per-type limits and the total limit must both survive policy serialization.
#[test]
fn output_count_ceilings_through_collect_and_check() {
    use serde_json::json;

    let comment =
        |n| json!({"type": "add_comment", "body": format!("comment {n}"), "item_number": n});
    let tool = json!({"type": "missing_tool", "tool": "cargo-nextest", "reason": "not installed"});
    let data = json!({"type": "missing_data", "data_type": "logs", "reason": "none kept"});
    let mut cases = vec![
        (
            "mixed types",
            vec![comment(1), comment(2), tool.clone(), data.clone()],
            None,
        ),
        (
            "total ceiling",
            vec![
                comment(1),
                comment(2),
                comment(3),
                tool.clone(),
                data.clone(),
            ],
            None,
        ),
        (
            "over total only",
            vec![
                comment(1),
                comment(2),
                comment(3),
                tool.clone(),
                tool.clone(),
                tool.clone(),
            ],
            Some("6 outputs, over max_outputs 5".to_owned()),
        ),
    ];
    for item in [comment(1), tool, data] {
        cases.push(("type ceiling", vec![item.clone(); 3], None));
        cases.push((
            "over type only",
            vec![item.clone(); 4],
            Some(format!(
                "Too many items of type '{}'",
                item["type"].as_str().unwrap()
            )),
        ));
    }

    for (name, items, refusal) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);
        std::fs::write(path("bounds.toml"), "hosts = ['github.com']\nrepos = ['example/repo']\nbases = ['main']\nmax_outputs = 5\nmax_patch_bytes = 4096\nmax_patch_files = 2\n[github.outputs]\nadd_comment = { max = 3 }\nmissing_tool = { max = 3 }\nmissing_data = { max = 3 }\n").unwrap();
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
                "all",
                "--max-outputs",
                "max",
                "--allow",
            ])
            .arg(path("bounds.toml"))
            .output()
            .unwrap();
        assert!(policy.status.success(), "{name}: {policy:?}");
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
        // The collector enforces per-type counts; check must also reject
        // its recorded errors rather than accepting the truncated item list.
        let type_overflow = name == "over type only";
        assert_eq!(
            collected.status.code(),
            Some(i32::from(type_overflow)),
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
            "{name} {items:?}: {checked:?}"
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
                    .any(|error| error.as_str().unwrap().contains(&refusal)),
                "{name}: {verdict}"
            );
        } else {
            assert_eq!(verdict["errors"], json!([]), "{name}: {verdict}");
            assert_eq!(
                verdict["items"].as_array().unwrap().len(),
                items.len(),
                "{name}: {verdict}"
            );
        }
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
fn pull_request_text_and_branch_survive_collect_and_check() {
    use serde_json::json;

    for (name, title, body, branch, want_title, want_body) in [
        (
            "plain control",
            "Fix the thing",
            "Why.",
            "agent-run-7",
            "Fix the thing",
            "Why.",
        ),
        (
            "sanitized text",
            "Fix\u{1} @example-user's thing",
            "cc @example-user see https://evil.example/x",
            "agent-run-7",
            "Fix @example-user's thing",
            "cc @example-user see (evil.example/redacted)",
        ),
        (
            "mixed-case branch",
            "Fix the thing",
            "Why.",
            "Agent-Run-7",
            "Fix the thing",
            "Why.",
        ),
    ] {
        let run = Run::new();
        let request = json!({"type": "create_pull_request", "title": title,
            "body": body, "branch": branch});
        std::fs::write(run.path("out/outputs.jsonl"), request.to_string()).unwrap();
        let collected = run.path("collected.json");
        let output = Command::new(BIN)
            .args(["collect", "--policy"])
            .arg(run.path("policy.json"))
            .arg("--outputs")
            .arg(run.path("out"))
            .arg("--collected")
            .arg(&collected)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{name}: {output:?}");
        // Mentions remain deferred to publication. Only the patch filename,
        // not the requested branch itself, is folded to lowercase.
        let expected = json!([{"type": "create_pull_request", "title": want_title,
            "body": want_body, "branch": branch}]);
        let collected_value: Value =
            serde_json::from_slice(&std::fs::read(&collected).unwrap()).unwrap();
        assert_eq!(collected_value["errors"], json!([]), "{name}");
        assert_eq!(collected_value["items"], expected, "{name}");

        let output = run.check(&collected);
        assert_eq!(output.status.code(), Some(0), "{name}: {output:?}");
        let verdict = run.verdict();
        assert_eq!(verdict["ok"], true, "{name}: {verdict}");
        assert_eq!(verdict["errors"], json!([]), "{name}");
        assert_eq!(verdict["items"], expected, "{name}");
        assert_eq!(verdict["patch"]["file"], "aw-agent-run-7.patch", "{name}");
        assert_eq!(
            verdict["patch"]["files"],
            json!(["src/lib.rs", "src/new.rs"]),
            "{name}"
        );
    }
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
fn malformed_hand_back_entries_are_refused() {
    for (case, want) in [
        ("invalid JSON", "base.json is not"),
        ("short commit", "base.json is not"),
        ("oversized base", "base.json is 4097 bytes, over 4096"),
        ("directory", "unexpected file \"sub\""),
        ("outputs symlink", "outputs.jsonl is not a regular file"),
    ] {
        let run = Run::new();
        let base = run.path("out/base.json");
        match case {
            "invalid JSON" => std::fs::write(&base, "{").unwrap(),
            "short commit" => {
                let mut metadata: Value =
                    serde_json::from_slice(&std::fs::read(&base).unwrap()).unwrap();
                metadata["commit"] = "5fffa9164184".into();
                std::fs::write(&base, metadata.to_string()).unwrap();
            }
            "oversized base" => {
                // Valid JSON at the exact limit is accepted; one whitespace byte
                // more must be refused before parsing, not as malformed JSON.
                let mut bytes = std::fs::read(&base).unwrap();
                bytes.resize(4096, b' ');
                std::fs::write(&base, &bytes).unwrap();
                let accepted = run.check(&data("check/collected.json"));
                assert_eq!(accepted.status.code(), Some(0), "{accepted:?}");
                assert_eq!(run.verdict()["ok"], true);
                std::fs::remove_file(run.path("verdict.json")).unwrap();
                bytes.push(b' ');
                std::fs::write(&base, bytes).unwrap();
            }
            "directory" => std::fs::create_dir(run.path("out/sub")).unwrap(),
            "outputs symlink" => {
                let outputs = run.path("out/outputs.jsonl");
                let target = run.path("real-outputs.jsonl");
                std::fs::rename(&outputs, &target).unwrap();
                std::os::unix::fs::symlink(&target, &outputs).unwrap();
            }
            _ => unreachable!(),
        }
        let output = run.check(&data("check/collected.json"));
        assert_eq!(output.status.code(), Some(1), "{case}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(want), "{case}: {stderr}");
        let verdict = run.verdict();
        assert_eq!(verdict["ok"], false, "{case}: {verdict}");
        assert!(
            verdict["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|error| error.as_str().unwrap().contains(want)),
            "{case}: {verdict}"
        );
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

#[test]
fn malformed_output_lines_survive_collection_as_check_refusals() {
    for (line, diagnostic) in [
        ("{", "Invalid JSON"),
        ("[1, 2]", "Missing required 'type' field"),
        (r#"{"message":"x"}"#, "Missing required 'type' field"),
    ] {
        for keep_valid_request in [false, true] {
            let run = Run::new();
            let outputs = run.path("out/outputs.jsonl");
            let valid = std::fs::read_to_string(&outputs).unwrap();
            if !keep_valid_request {
                std::fs::remove_file(run.path("out/aw-agent-run-7.patch")).unwrap();
                std::fs::remove_file(run.path("out/base.json")).unwrap();
            }
            // Check the accepted control first, then ensure that a bad line
            // cannot be dropped silently, even alongside a valid publication.
            for malformed in [false, true] {
                let mut input = if keep_valid_request {
                    format!("{}\n", valid.trim_end())
                } else {
                    String::new()
                };
                if malformed {
                    input.push_str(line);
                    input.push('\n');
                }
                std::fs::write(&outputs, input).unwrap();
                let collected = run.path("collected.json");
                if collected.exists() {
                    std::fs::remove_file(&collected).unwrap();
                    std::fs::remove_file(run.path("verdict.json")).unwrap();
                }
                let ingest = Command::new(BIN)
                    .args(["collect", "--policy"])
                    .arg(run.path("policy.json"))
                    .arg("--outputs")
                    .arg(run.path("out"))
                    .arg("--collected")
                    .arg(&collected)
                    .output()
                    .unwrap();
                assert_eq!(
                    ingest.status.code(),
                    Some(i32::from(malformed)),
                    "{line}: {ingest:?}"
                );
                // The downstream check must refuse the collector's recorded
                // error, not authorize its otherwise valid remaining items.
                let checked = run.check(&collected);
                let verdict = run.verdict();
                assert_eq!(
                    checked.status.code(),
                    Some(i32::from(malformed)),
                    "{line}: {checked:?}; {verdict}"
                );
                assert_eq!(verdict["ok"], !malformed, "{verdict}");
                if malformed {
                    let expected =
                        format!("Line {}: {diagnostic}", 1 + usize::from(keep_valid_request));
                    assert!(
                        verdict["errors"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|error| error.as_str().unwrap().contains(&expected)),
                        "{line}: {verdict}"
                    );
                } else {
                    assert_eq!(verdict["errors"], serde_json::json!([]));
                    assert_eq!(
                        verdict["items"].as_array().unwrap().len(),
                        usize::from(keep_valid_request)
                    );
                }
            }
        }
    }
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
