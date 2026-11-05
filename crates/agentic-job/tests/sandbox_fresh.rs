//! `sandbox setup` refuses what it cannot do as asked, and has changed
//! nothing when it does: the removed sandbox user's keys
//! (agentic-job#2989), a setup script, and a host whose world-write
//! policy is not loaded.
//!
//! This runs setup as root through sudo: it is for a machine that is
//! thrown away, BEFORE `sandbox setup` has run there. CI's `sandbox` job
//! runs it:
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

/// The second user's name before agentic-job#2989.
const REMOVED_USER: &str = "runner-sandbox";

/// What `exit::ERROR` is.
const ERROR: i32 = 2;

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
#[ignore = "runs setup as root; CI's sandbox job runs it before `sandbox setup`"]
fn setup_refuses_what_it_cannot_do_and_changes_nothing() {
    assert!(
        !Path::new(CONFIG_DIR).exists(),
        "`sandbox setup` already ran here"
    );
    // A fresh host that loaded the policy would be set up by the last case.
    let loaded = Command::new("sudo")
        .args([
            "-n",
            "--",
            "test",
            "-e",
            "/sys/fs/bpf/agentic-job-world-write",
        ])
        .status()
        .unwrap();
    assert!(!loaded.success(), "the world-write policy is loaded here");

    // The configuration, and what the refusal must say.
    let removed = "was removed with the sandbox user (agentic-job#2989)";
    let cases = [
        ("[sandbox]\ncreate-user = true\n", removed),
        ("[sandbox]\ncreate-user = false\n", removed),
        ("[sandbox]\nuser = \"aj-test-new\"\n", removed),
        ("[sandbox]\ngroups = [\"kvm\"]\n", removed),
        ("[setup]\nscript = \"/bin/true\"\n", "setup runs no script"),
        // Fresh, but the world-write policy is not loaded yet: CI runs
        // this before its loader.
        ("", "the world-write policy is not loaded"),
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
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    let made = Command::new("id")
        .args(["-u", "--", REMOVED_USER])
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!made.success(), "a refused setup made {REMOVED_USER}");
}
