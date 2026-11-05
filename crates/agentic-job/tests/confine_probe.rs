//! Rootless refusal and evidence paths of the runner confinement CLI.

use std::fs;
use std::process::Command;

use secure_host::host::User;

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");
const FIXTURE: &str = "/var/tmp/agentic-job-confine-root-file";

#[test]
fn invalid_controls_never_record_success() {
    let dead = Command::new("true").spawn().unwrap();
    let dead_pid = dead.id();
    assert!(dead.wait_with_output().unwrap().status.success());
    let cases = [
        ("../invalid", true, "invalid", "only lowercase letters"),
        ("unset", false, "invalid", "RUNNER_TEMP is not set"),
        ("invalid-pid", true, "not-a-pid", "not a pid"),
        ("dead-pid", true, &dead_pid.to_string(), "not running"),
    ];
    for (label, temp_set, pid, expected) in cases {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("confine-orphan.pid"), pid).unwrap();
        let mut command = Command::new(BIN);
        command.args(["sandbox", "probe", "control", label]);
        if temp_set {
            command.env("RUNNER_TEMP", temp.path());
        } else {
            command.env_remove("RUNNER_TEMP");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success(), "{label}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{label}: {stderr}");
        let records = temp.path().join("confine");
        assert!(
            !records.exists() || fs::read_dir(records).unwrap().next().is_none(),
            "{label}: invalid control must not produce evidence"
        );
    }
}

#[test]
fn missing_fixture_never_records_success() {
    // A prepared privileged CI host may have the actual fixture. Never alter it.
    if fs::symlink_metadata(FIXTURE).is_ok() {
        eprintln!("skipping missing-fixture case: {FIXTURE} exists");
        return;
    }
    for mode in ["control", "confined"] {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("confine-orphan.pid"),
            std::process::id().to_string(),
        )
        .unwrap();
        let output = Command::new(BIN)
            .args(["sandbox", "probe", mode, "missing-fixture"])
            .env("RUNNER_TEMP", temp.path())
            .output()
            .unwrap();
        assert!(!output.status.success(), "{mode}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("missing, so writing it proves nothing"),
            "{mode}: {stderr}"
        );
        assert!(
            fs::read_dir(temp.path().join("confine"))
                .unwrap()
                .next()
                .is_none()
        );
    }
}

/// On a host setup never locked, the runner's sudo is no helper rule: the
/// record says so, and that no second user was found where none was made.
#[test]
fn an_unlocked_host_records_failure() {
    if User::lookup("runner-sandbox").unwrap().is_some() {
        eprintln!("skipping: this host has the removed sandbox user");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(BIN)
        .args(["sandbox", "probe", "no-user", "unlocked"])
        .env("RUNNER_TEMP", temp.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(temp.path().join("confine/unlocked.json")).unwrap())
            .unwrap();
    assert_eq!(record["mode"], "no-user");
    assert_eq!(record["label"], "unlocked");
    assert_eq!(record["results"]["user"], false);
    assert!(
        record["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem.as_str() == Some("sudo-rules: failed, must succeed"))
    );
    // The removed mode is refused, not taken for another.
    let removed = Command::new(BIN)
        .args(["sandbox", "probe", "sandbox-user", "removed"])
        .env("RUNNER_TEMP", temp.path())
        .output()
        .unwrap();
    assert!(!removed.status.success(), "{removed:?}");
}
