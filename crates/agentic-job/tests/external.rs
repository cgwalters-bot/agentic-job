//! Trusted-record CLI adapters. Fetch/API and raw patch/staged apply fixtures
//! live beside the correlation implementation; no external dispatch is made.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

fn command(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .env("GITHUB_REPOSITORY", "owner/caller")
        .env("GITHUB_RUN_ID", "90")
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env_remove("GH_TOKEN")
        .output()
        .unwrap()
}

fn status(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn receipt_is_caller_owned_and_does_not_bypass_policy_check_or_detection() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    std::fs::write(dir.join("bounds.toml"), "hosts = ['github.com']\nrepos = ['owner/target']\nbases = ['main']\nmax_outputs = 2\nmax_patch_bytes = 1048576\nmax_patch_files = 50\n[github.outputs]\ncreate_pull_request = { max = 1 }\nnoop = { max = 1 }\n").unwrap();
    let receipt = json!({
        "record": {
            "dispatch_id":"0123456789abcdef0123456789abcdef", "caller_repository":"owner/caller", "caller_run_id":90,"caller_attempt":1,
            "profile_commit":"a".repeat(40), "target_repository":"owner/target", "target_branch":"main", "base_commit":"b".repeat(40),"item":42,"kind":"implement",
            "repository":"owner/external","repository_id":123,"workflow":".github/workflows/agent.yml","reference":"main","commit":"c".repeat(40),"triggering_actor_id":456,
            "agentic_job":"d".repeat(40),"actions":"e".repeat(40),"artifact_prefix":"external-","check_job":"check","detect_job":"detect",
            "actions_workflow":"example-org/wrapper/.github/workflows/run.yml",
            "policy_workflow":"example-org/tool/.github/workflows/policy.yml",
            "check_workflow":"example-org/tool/.github/workflows/check.yml",
            "dispatched_at":"2026-11-09T12:00:00Z","deadline":"2026-11-09T13:00:00Z","returned_run_id":null
        },
        "run_id":7,"attempt":1,"checked":{"id":10,"digest":format!("sha256:{}","a".repeat(64))},"raw":{"id":11,"digest":format!("sha256:{}","b".repeat(64))}
    });
    std::fs::write(dir.join("receipt.json"), receipt.to_string()).unwrap();
    let policy_args = [
        "policy",
        "--allow",
        "bounds.toml",
        "--repo",
        "owner/target",
        "--clone-url",
        "https://github.com/owner/target",
        "--base",
        "main",
        "--kind",
        "branch",
        "--outputs",
        "create_pull_request,noop",
        "--max-outputs",
        "2",
        "--external-receipt",
        "receipt.json",
        "--output-repo",
        "owner/target",
    ];
    let compiled = command(dir, &policy_args);
    status(&compiled, 0);
    std::fs::write(dir.join("policy.json"), &compiled.stdout).unwrap();
    let policy: Value = serde_json::from_slice(&compiled.stdout).unwrap();
    assert_eq!(policy["external"]["base_commit"], "b".repeat(40));
    assert_eq!(policy["external"]["run_id"], 7);
    assert_eq!(
        policy["safe_outputs"]["create_pull_request"]["ready_when_complete"],
        Value::Null
    );
    // External metadata cannot authorize another bounds target or base.
    let mut changed = policy_args.to_vec();
    changed[4] = "attacker/target";
    status(&command(dir, &changed), 1);
    changed = policy_args.to_vec();
    changed[8] = "other";
    status(&command(dir, &changed), 1);
    // Apply defaults an omitted output repository to the caller, so it
    // must be named, and be the target.
    status(&command(dir, &policy_args[..policy_args.len() - 2]), 2);
    changed = policy_args.to_vec();
    *changed.last_mut().unwrap() = "owner/caller";
    status(&command(dir, &changed), 2);
    let mut replay = receipt.clone();
    replay["record"]["caller_run_id"] = 89.into();
    std::fs::write(dir.join("receipt.json"), replay.to_string()).unwrap();
    status(&command(dir, &policy_args), 2);
    std::fs::create_dir(dir.join("raw")).unwrap();
    std::fs::write(
        dir.join("raw/outputs.jsonl"),
        "{\"type\":\"noop\",\"message\":\"No change\"}\n",
    )
    .unwrap();
    status(
        &command(
            dir,
            &[
                "collect",
                "--policy",
                "policy.json",
                "--outputs",
                "raw",
                "--collected",
                "collected.json",
            ],
        ),
        0,
    );
    let check = [
        "check",
        "--policy",
        "policy.json",
        "--outputs",
        "raw",
        "--collected",
        "collected.json",
        "--report",
        "report.json",
        "--run-id",
        "90",
    ];
    status(&command(dir, &check), 0);
    for (result, expected) in [
        ("success", 0),
        ("", 2),
        ("skipped", 2),
        ("failure", 2),
        ("cancelled", 2),
    ] {
        status(
            &command(
                dir,
                &[
                    "external-release",
                    "--policy",
                    "policy.json",
                    "--report",
                    "report.json",
                    "--detection-result",
                    result,
                ],
            ),
            expected,
        );
    }
    std::fs::write(
        dir.join("raw/base.json"),
        json!({"repo":"owner/target","ref":"main","commit":"f".repeat(40)}).to_string(),
    )
    .unwrap();
    status(&command(dir, &check), 1);
    // Apply-only retries keep the same run's idempotency keys; another run
    // cannot borrow the checked policy even with a successful detector flag.
    let mut retry = Command::new(BIN);
    retry
        .current_dir(dir)
        .args([
            "external-release",
            "--policy",
            "policy.json",
            "--report",
            "report.json",
            "--detection-result",
            "success",
        ])
        .env("GITHUB_REPOSITORY", "owner/caller")
        .env("GITHUB_RUN_ID", "91")
        .env("GITHUB_RUN_ATTEMPT", "1");
    status(&retry.output().unwrap(), 2);
}

/// Run in GitLab caller pipeline PIPELINE, with no GitHub context.
fn gitlab_command(dir: &Path, pipeline: &str, args: &[&str]) -> Output {
    Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .env_remove("GITHUB_REPOSITORY")
        .env_remove("GITHUB_RUN_ID")
        .env_remove("GITHUB_RUN_ATTEMPT")
        .env("CI_SERVER_URL", "https://gitlab.example.com")
        .env("CI_PROJECT_ID", "11")
        .env("CI_PIPELINE_ID", pipeline)
        .env_remove("GITLAB_READ_TOKEN")
        .output()
        .unwrap()
}

#[test]
fn gitlab_fetch_refuses_another_caller_pipeline_and_a_missing_token_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let now = chrono::Utc::now();
    let record = json!({
        "forge": "gitlab", "server": "https://gitlab.example.com",
        "caller_project": "group/caller", "caller_project_id": 11, "caller_pipeline_id": 5001, "caller_job_id": 90001,
        "profile_commit": "1".repeat(40), "kind": "implement", "target_repository": "group/sub/project",
        "target_branch": "main", "base_commit": "2".repeat(40), "item": 7,
        "project": "group/producer", "project_id": 12, "reference": "main", "commit": "3".repeat(40),
        "ci_config_path": "", "pipeline_id": 5002, "user_id": 42,
        "variables": {"AGENTIC_JOB_RELEASE": "v0.6.13", "AGENTIC_JOB_SHA256": "4".repeat(64)},
        "agentic_job": "5".repeat(40), "agent_job": "agent", "check_job": "check", "detect_job": "detect",
        "dispatched_at": now, "deadline": now + chrono::Duration::minutes(30)
    });
    std::fs::write(dir.join("record.json"), record.to_string()).unwrap();
    let fetch = [
        "external-fetch",
        "--forge",
        "gitlab",
        "--record",
        "record.json",
        "--archive",
        "raw.zip",
        "--outputs",
        "raw",
        "--receipt",
        "receipt.json",
    ];
    for (pipeline, reason) in [
        ("5002", "another caller pipeline"),
        ("5001", "GITLAB_READ_TOKEN is required"),
    ] {
        let output = gitlab_command(dir, pipeline, &fetch);
        status(&output, 2);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(reason), "{stderr}");
        assert!(!dir.join("receipt.json").exists());
    }
    // The GitHub default refuses a GitLab record.
    let github = [&fetch[..1], &fetch[3..]].concat();
    let output = command(dir, &github);
    status(&output, 2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown field `forge`"), "{stderr}");
}

#[test]
fn gitlab_receipt_binds_the_caller_pipeline_and_producer_branch_but_is_not_released() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    std::fs::write(dir.join("bounds.toml"), "hosts = ['gitlab.example.com']\nrepos = ['group/sub/project']\nbases = ['main', 'other']\nmax_outputs = 2\nmax_patch_bytes = 1048576\nmax_patch_files = 50\n[gitlab]\npush_repo = 'bot/project'\n[gitlab.outputs]\ncreate_pull_request = { max = 1 }\nnoop = { max = 1 }\n").unwrap();
    let receipt = json!({
        "record": {
            "forge": "gitlab", "server": "https://gitlab.example.com",
            "caller_project": "group/caller", "caller_project_id": 11, "caller_pipeline_id": 5001, "caller_job_id": 90001,
            "profile_commit": "1".repeat(40), "kind": "implement", "target_repository": "group/sub/project",
            "target_branch": "main", "base_commit": "2".repeat(40), "item": 7,
            "project": "group/producer", "project_id": 12, "reference": "main", "commit": "3".repeat(40),
            "ci_config_path": "", "pipeline_id": 5002, "user_id": 42,
            "variables": {"AGENTIC_JOB_RELEASE": "v0.6.13", "AGENTIC_JOB_SHA256": "4".repeat(64)},
            "agentic_job": "5".repeat(40), "agent_job": "agent", "check_job": "check", "detect_job": "detect",
            "dispatched_at": "2026-11-13T10:00:00Z", "deadline": "2026-11-13T15:30:00Z"
        },
        "agent_job_id": 201, "check_job_id": 202, "detect_job_id": 203,
        "raw": {"size": 100, "digest": format!("sha256:{}", "6".repeat(64))}
    });
    std::fs::write(dir.join("receipt.json"), receipt.to_string()).unwrap();
    let policy_args = [
        "policy",
        "--allow",
        "bounds.toml",
        "--repo",
        "group/sub/project",
        "--clone-url",
        "https://gitlab.example.com/group/sub/project",
        "--base",
        "main",
        "--kind",
        "branch",
        "--outputs",
        "create_pull_request,noop",
        "--max-outputs",
        "2",
        "--external-receipt",
        "receipt.json",
        "--output-repo",
        "group/sub/project",
    ];
    // Another caller pipeline, or a GitHub-only environment, cannot use it.
    for (output, reason) in [
        (
            gitlab_command(dir, "5002", &policy_args),
            "another caller pipeline",
        ),
        (command(dir, &policy_args), "missing CI_SERVER_URL"),
    ] {
        status(&output, 2);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(reason), "{stderr}");
    }
    let compiled = gitlab_command(dir, "5001", &policy_args);
    status(&compiled, 0);
    std::fs::write(dir.join("policy.json"), &compiled.stdout).unwrap();
    let policy: Value = serde_json::from_slice(&compiled.stdout).unwrap();
    assert_eq!(
        policy["external"],
        json!({
            "caller_repository": "group/caller", "caller_run_id": 5001, "caller_attempt": 1,
            "repository": "group/producer", "run_id": 5002, "base_commit": "2".repeat(40),
            "raw_digest": format!("sha256:{}", "6".repeat(64)),
            "gitlab": {"server": "https://gitlab.example.com", "caller_project_id": 11}
        })
    );
    assert_eq!(policy["safe_outputs"]["create_pull_request"]["draft"], true);
    // The receipt's target is the only one it admits, of those the bounds do.
    let mut changed = policy_args.to_vec();
    changed[8] = "other";
    let other = gitlab_command(dir, "5001", &changed);
    status(&other, 2);
    let stderr = String::from_utf8_lossy(&other.stderr);
    assert!(stderr.contains("exact implement target/base"), "{stderr}");
    // No publisher takes it, even if the caller leaves out external-release.
    let apply = gitlab_command(
        dir,
        "5001",
        &[
            "apply",
            "--forge",
            "gitlab",
            "--server",
            "https://gitlab.example.com",
            "--repo",
            "group/sub/project",
            "--policy",
            "policy.json",
            "--checked",
            "checked",
            "--run-url",
            "https://gitlab.example.com/group/caller/-/pipelines/5001",
        ],
    );
    status(&apply, 2);
    let stderr = String::from_utf8_lossy(&apply.stderr);
    assert!(stderr.contains("no GitLab detection result"), "{stderr}");
    std::fs::create_dir(dir.join("raw")).unwrap();
    let check = |outputs: &str| {
        std::fs::write(dir.join("raw/outputs.jsonl"), outputs).unwrap();
        for file in ["collected.json", "report.json"] {
            let _ = std::fs::remove_file(dir.join(file));
        }
        status(
            &gitlab_command(
                dir,
                "5001",
                &[
                    "collect",
                    "--policy",
                    "policy.json",
                    "--outputs",
                    "raw",
                    "--collected",
                    "collected.json",
                ],
            ),
            0,
        );
        let output = gitlab_command(
            dir,
            "5001",
            &[
                "check",
                "--policy",
                "policy.json",
                "--outputs",
                "raw",
                "--collected",
                "collected.json",
                "--report",
                "report.json",
                "--run-id",
                "5001",
            ],
        );
        let report: Value =
            serde_json::from_slice(&std::fs::read(dir.join("report.json")).unwrap()).unwrap();
        (output, report)
    };
    let (output, _) = check("{\"type\":\"noop\",\"message\":\"No change\"}\n");
    status(&output, 0);
    // The producer pipeline names the branch, not the caller's.
    const BRANCH_ERROR: &str = "external request branch is not the trusted external run's";
    for (branch, refused) in [("agent-run-5001", true), ("agent-run-5002", false)] {
        let item = json!({"type": "create_pull_request", "title": "Change", "body": "Why.", "branch": branch});
        let (_, report) = check(&format!("{item}\n"));
        assert_eq!(
            report["errors"].to_string().contains(BRANCH_ERROR),
            refused,
            "{branch}: {report}"
        );
    }
    let (output, _) = check("{\"type\":\"noop\",\"message\":\"No change\"}\n");
    status(&output, 0);
    // How GitLab detection reaches this gate is not specified yet.
    let release = gitlab_command(
        dir,
        "5001",
        &[
            "external-release",
            "--policy",
            "policy.json",
            "--report",
            "report.json",
            "--detection-result",
            "success",
        ],
    );
    status(&release, 2);
    assert!(
        String::from_utf8_lossy(&release.stderr).contains("no GitLab detection result"),
        "{}",
        String::from_utf8_lossy(&release.stderr)
    );
    std::fs::write(
        dir.join("raw/base.json"),
        json!({"repo": "group/sub/project", "ref": "main", "commit": "f".repeat(40)}).to_string(),
    )
    .unwrap();
    let (output, report) = check("{\"type\":\"noop\",\"message\":\"No change\"}\n");
    status(&output, 1);
    assert!(
        report["errors"]
            .to_string()
            .contains("differs from the trusted dispatch base"),
        "{report}"
    );
    status(
        &gitlab_command(
            dir,
            "5009",
            &[
                "check",
                "--policy",
                "policy.json",
                "--outputs",
                "raw",
                "--collected",
                "collected.json",
                "--report",
                "other.json",
                "--run-id",
                "5009",
            ],
        ),
        2,
    );
}
