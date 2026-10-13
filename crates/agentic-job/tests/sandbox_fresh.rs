//! `sandbox setup` refuses a machine that is not fresh, and has changed
//! nothing when it does.
//!
//! This adds and removes users as root through sudo: it is for a machine
//! that is thrown away, BEFORE `sandbox setup` has run there. CI's
//! `sandbox` job runs it:
//!
//! ```text
//! cargo test --test sandbox_fresh -- --ignored --nocapture
//! ```

// Helpers outside a #[test] function are still test code.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

/// What setup makes first, and so must not exist after a refusal.
const CONFIG_DIR: &str = "/etc/agentic-job";

const EXISTING_USER: &str = "aj-test-existing";

const LEFTOVER_HOME: &str = "/home/aj-test-leftover";

/// What `exit::ERROR` is.
const ERROR: i32 = 2;

fn root(argv: &[&str]) {
    let status = Command::new("sudo")
        .arg("-n")
        .arg("--")
        .args(argv)
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "sudo {argv:?} failed");
}

/// Runs `sandbox setup` with `config` as root; its exit code and what it
/// wrote to standard error.
fn setup(config: &str) -> (Option<i32>, String) {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), config).unwrap();
    let output = Command::new("sudo")
        .args(["-n", "--", BIN, "sandbox", "setup", "--config"])
        .arg(file.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
#[ignore = "adds users as root; CI's sandbox job runs it before `sandbox setup`"]
fn setup_refuses_a_machine_that_is_not_fresh() {
    assert!(
        !Path::new(CONFIG_DIR).exists(),
        "`sandbox setup` already ran here"
    );
    // A fresh host that loaded the policy would be set up by the last case.
    root(&["test", "!", "-e", "/sys/fs/bpf/agentic-job-world-write"]);
    root(&["useradd", "--create-home", EXISTING_USER]);
    root(&["usermod", "-aG", "adm", EXISTING_USER]);
    root(&["mkdir", LEFTOVER_HOME]);

    // The configuration, and what the refusal must say.
    let cases = [
        (
            format!("[sandbox]\nuser = \"{EXISTING_USER}\"\n"),
            "already exists",
        ),
        // The image's user, in a group the configuration could not give it.
        (
            format!("[sandbox]\nuser = \"{EXISTING_USER}\"\nallow-existing-user = true\n"),
            "is in adm",
        ),
        (
            "[sandbox]\nuser = \"aj-test-leftover\"\n".to_owned(),
            "something left it there",
        ),
        (
            "[sandbox]\nuser = \"aj-test-new\"\ngroups = [\"no-such-group\"]\n".to_owned(),
            "no group no-such-group",
        ),
        // Fresh, but the world-write policy is not loaded yet: CI runs
        // this before its loader.
        (
            "[sandbox]\nuser = \"aj-test-new\"\ngroups = []\n".to_owned(),
            "the world-write policy is not loaded",
        ),
    ];
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(config, want)| {
            let (code, stderr) = setup(config);
            let refused = code == Some(ERROR) && stderr.contains(want);
            let untouched = !Path::new(CONFIG_DIR).exists();
            (!refused || !untouched)
                .then(|| format!("{config:?}: exit {code:?}, untouched {untouched}: {stderr}"))
        })
        .collect();

    root(&["userdel", "--remove", EXISTING_USER]);
    root(&["rmdir", LEFTOVER_HOME]);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
