//! The image and the loader refuse a host that either runtime layout
//! prepared before they change anything on it, and the image one whose
//! markers it cannot inspect: the host keeps the binary it has, and no
//! other layout's files appear beside it.
//!
//! This plants each layout's markers as root through sudo: it is for a
//! machine that is thrown away, BEFORE secure-host has run there.
//! The loader is this build's, in its layout; `SECURE_HOST_IMAGE` names
//! the image to run, in root's podman, in whichever layout it was built:
//!
//! ```text
//! SECURE_HOST_IMAGE=sha256:... cargo test --test fresh_host -- --ignored --nocapture
//! ```

// Helpers outside a #[test] function are still test code.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_secure-host");

/// Each layout's setup marker and policy pins (`src/runtime.rs`).
const MARKERS: [&str; 4] = [
    "/etc/secure-host",
    "/etc/agentic-job",
    "/sys/fs/bpf/secure-host-world-write",
    "/sys/fs/bpf/agentic-job-world-write",
];

/// What the image installs, by either layout's names (`src/image.rs`),
/// and what its first step, apt's, writes (`src/apt.rs`).
const INSTALLED: [&str; 6] = [
    "/usr/local/bin/secure-host",
    "/usr/local/bin/agentic-job",
    "/usr/local/lib/secure-host",
    "/usr/local/lib/agentic-job",
    "/etc/apt/apt.conf.d/99-secure-host-network",
    "/etc/apt/apt.conf.d/99-agentic-job-network",
];

/// The host's binary that a refused image must not replace.
const HOST_BINARY: &str = "/usr/local/bin/secure-host";

const IMAGE_VAR: &str = "SECURE_HOST_IMAGE";

fn sudo(args: &[&str]) -> Output {
    Command::new("sudo")
        .args(["-n", "--"])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// Which of MARKERS exist, as root sees them.
fn markers() -> Vec<&'static str> {
    MARKERS
        .into_iter()
        .filter(|marker| sudo(&["test", "-e", marker]).status.success())
        .collect()
}

/// What root sees of INSTALLED: inodes and times too, which an install by
/// rename changes even with the same bytes.
fn installed() -> Vec<String> {
    INSTALLED
        .into_iter()
        .map(|path| {
            let out = sudo(&["ls", "-lRi", "--full-time", path]);
            format!(
                "{path}: {} {}",
                out.status,
                String::from_utf8_lossy(&out.stdout)
            )
        })
        .collect()
}

/// Runs ARGS as root with MARKER planted, and checks that they are refused
/// for it and change nothing installed or marked.
fn refused_with(marker: &str, args: &[&str]) -> Result<(), String> {
    refused(Some(marker), args, &format!("{marker} already exists"))
}

/// Runs ARGS as root with PLANTED, if any, planted, and checks that they
/// fail saying WANT and change nothing installed or marked.
fn refused(planted: Option<&str>, args: &[&str], want: &str) -> Result<(), String> {
    let before = installed();
    if let Some(marker) = planted {
        assert!(
            sudo(&["mkdir", marker]).status.success(),
            "planting {marker}"
        );
    }
    let out = sudo(args);
    let after = installed();
    let present = markers();
    if let Some(marker) = planted {
        assert!(
            sudo(&["rmdir", marker]).status.success(),
            "removing {marker}"
        );
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut wrong = Vec::new();
    if out.status.success() || !stderr.contains(want) {
        wrong.push(format!("{}: not refused with {want}: {stderr}", out.status));
    }
    if before != after {
        wrong.push(format!("changed {before:?} to {after:?}"));
    }
    if present != Vec::from_iter(planted) {
        wrong.push(format!("left {present:?}"));
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!("{args:?} with {planted:?}: {}", wrong.join("; ")))
    }
}

#[test]
#[ignore = "plants markers as root; for a disposable host before secure-host runs"]
fn a_prepared_host_is_refused_before_anything_changes() {
    let image =
        std::env::var(IMAGE_VAR).unwrap_or_else(|_| panic!("{IMAGE_VAR} names the image to run"));
    assert_eq!(markers(), Vec::<&str>::new(), "this host was prepared");
    // A binary already there, for the image to have to leave alone.
    let planted = sudo(&["test", "-e", HOST_BINARY]).status.code() == Some(1);
    if planted {
        let mut tee = Command::new("sudo")
            .args(["-n", "--", "tee", HOST_BINARY])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        tee.stdin
            .take()
            .unwrap()
            .write_all(b"host's own\n")
            .unwrap();
        assert!(tee.wait().unwrap().success(), "planting {HOST_BINARY}");
    }
    // Refused before the configuration is read: it need not be valid.
    let config = tempfile::NamedTempFile::new().unwrap();
    let config = config.path().to_str().unwrap();
    // Refused before the object is read, too.
    let loader = [BIN, "world-write", "/nonexistent/world_write.bpf.o"];
    let run = [
        "podman",
        "run",
        "--rm",
        "--privileged",
        "--pid=host",
        "--network=none",
        "-v",
        "/:/host",
        &image,
        config,
    ];
    // Without --privileged nsenter cannot enter the host's namespace, so
    // the image cannot inspect the markers and must not take that for a
    // fresh host.
    let unprivileged: Vec<&str> = run
        .into_iter()
        .filter(|&arg| arg != "--privileged")
        .collect();
    let wrong: Vec<String> = MARKERS
        .into_iter()
        .flat_map(|marker| [refused_with(marker, &loader), refused_with(marker, &run)])
        .chain([refused(
            None,
            &unprivileged,
            "cannot tell that this host is a fresh one",
        )])
        .filter_map(Result::err)
        .collect();
    if planted {
        assert!(sudo(&["rm", HOST_BINARY]).status.success());
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
