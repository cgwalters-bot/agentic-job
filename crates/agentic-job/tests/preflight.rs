//! Opt-in real guest proof. Run only as the unprivileged runner user on an
//! authorized disposable x86_64 KVM host with QEMU and session libvirt installed.
#![allow(clippy::unwrap_used)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

fn session_guests() -> Vec<String> {
    let output = Command::new("virsh")
        .args(["-c", "qemu:///session", "list", "--all", "--name"])
        .env("LC_ALL", "C")
        .output()
        .expect("listing session guests requires virsh and session libvirt");
    assert!(output.status.success(), "{output:?}");
    let mut names: Vec<_> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|name| name.starts_with("agentic-job-preflight-"))
        .map(str::to_owned)
        .collect();
    names.sort();
    names
}

#[test]
#[ignore = "requires an authorized disposable KVM host, QEMU and session libvirt"]
fn real_kvm_boot_and_session_cleanup() {
    let before = session_guests();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("preflight.toml");
    std::fs::write(&config, "[preflight]\nkvm = true\nlibvirt = \"session\"\n").unwrap();
    let output = Command::new(BIN)
        .args(["sandbox", "preflight", "--config"])
        .arg(&config)
        // The checker must also work with a non-English parent locale.
        .env("LC_ALL", "fr_FR.UTF-8")
        .output()
        .unwrap();
    // Check absence even when the CLI failed after creating the guest.
    assert_eq!(session_guests(), before, "preflight left a session guest");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("a KVM guest booted and stopped"),
        "{stdout}"
    );
    assert!(stdout.contains("created and destroyed a guest"), "{stdout}");
}
