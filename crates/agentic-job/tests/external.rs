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
