//! The probes of where the run token is, run as a second user: all pass
//! on an agent's configuration as `run` writes it, and each fails when
//! the one thing it names is broken.
//!
//! Needs `AGENTIC_JOB_TEST_SANDBOX_USER`, a user this one can become with
//! `sudo run0`; without it the test passes without having run, as in
//! `session.rs`.

// clippy.toml lets test functions unwrap, but not the helpers they share.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::time::Duration;

use agentic_job::config::Config;
use agentic_job::run::agent::{self, CLAUDE_ENV_FILE, Configuration, Source};
use agentic_job::run::enter::Sandbox;
use agentic_job::run::inference::{Endpoint, Mode, Token};
use agentic_job::run::probe;

const SANDBOX_USER_VAR: &str = "AGENTIC_JOB_TEST_SANDBOX_USER";
const TOKEN: &str = "praxis-run-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const MAX_OUTPUT: usize = 4096;
/// How long a process holds the token on its command line, and how long
/// it is given to be there before the probes look.
const HOLD_S: &str = "15";
const HOLD_SCRIPT: &str = r#"sleep "$1"; :"#;
const HOLD_SETTLE: Duration = Duration::from_secs(3);

/// The probes that failed.
fn failed(sandbox: &Sandbox, token: &Token, given: Option<&Path>) -> Vec<String> {
    failed_in(sandbox, token, given, None)
}

/// The probes that failed, with the token's file read from containers
/// of IMAGE if one is given.
fn failed_in(
    sandbox: &Sandbox,
    token: &Token,
    given: Option<&Path>,
    image: Option<&str>,
) -> Vec<String> {
    probe::token(sandbox, token, &[CLAUDE_ENV_FILE], given, image)
        .unwrap()
        .into_iter()
        .filter(|probe| !probe.passed)
        .map(|probe| probe.what)
        .collect()
}

#[test]
fn each_probe_fails_when_what_it_names_is_broken() {
    let Ok(user) = std::env::var(SANDBOX_USER_VAR) else {
        return;
    };
    let config = Config::parse(&format!("[sandbox]\nuser = \"{user}\"\n")).unwrap();
    let sandbox = Sandbox::new(&config).unwrap();
    let token = Token::new(TOKEN).unwrap();
    let endpoint = Endpoint {
        url: "http://127.0.0.1:9".into(),
        mode: Mode::Plain,
        anthropic_url: "http://127.0.0.1:9/anthropic".into(),
        openai_url: "http://127.0.0.1:9/v1".into(),
    };
    // Claude Code's files as `run` writes them, without root's settings.
    let configuration = Configuration {
        managed: None,
        ..agent::claude(&endpoint, &token, &Source::default())
    };
    agent::install(&sandbox, &configuration).unwrap();
    let file = sandbox.home.join(CLAUDE_ENV_FILE);
    let file = file.to_str().unwrap();
    // A script run as the sandbox user, with the token's file as `$1`.
    let sh = |script: &str| {
        let out = sandbox.run(&["sh", "-c", script, "sh", file], b"", MAX_OUTPUT);
        assert!(out.unwrap().success(), "{script}");
    };
    assert_eq!(failed(&sandbox, &token, None), [""; 0]);

    // (what is broken, how, how it is mended, the probe that says so)
    let cases = [
        (
            "a copy in a shared directory",
            r#"cp "$1" /tmp/agentic-job-test-copy"#,
            "rm -f /tmp/agentic-job-test-copy",
            "in no other file",
        ),
        (
            "a copy elsewhere in the home",
            r#"cp "$1" "$HOME/agentic-job-test-copy""#,
            r#"rm -f "$HOME/agentic-job-test-copy""#,
            "in no other file",
        ),
        (
            "a file others can read",
            r#"chmod 0644 "$1""#,
            r#"chmod 0600 "$1""#,
            "mode 600",
        ),
        (
            "a directory others can enter",
            r#"chmod 0755 "$(dirname "$1")""#,
            r#"chmod 0700 "$(dirname "$1")""#,
            "mode 700",
        ),
    ];
    for (what, breaks, mends, probe) in cases {
        sh(breaks);
        let got = failed(&sandbox, &token, None);
        sh(mends);
        assert_eq!(got.len(), 1, "{what}: {got:?}");
        assert!(got[0].contains(probe), "{what}: {got:?}");
    }

    // What `run` makes of the probes: it goes on only if all passed.
    probe::require(&sandbox, &token, &[CLAUDE_ENV_FILE], None, None).unwrap();
    sh(r#"chmod 0644 "$1""#);
    let err = probe::require(&sandbox, &token, &[CLAUDE_ENV_FILE], None, None).unwrap_err();
    sh(r#"chmod 0600 "$1""#);
    assert!(
        err.to_string().contains("not only where it belongs"),
        "{err:#}"
    );

    // The token on a command line every user can read.
    let holder = std::thread::spawn({
        let sandbox = sandbox.clone();
        // The token is the script's name; the `:` keeps the shell from
        // becoming `sleep`, whose command line would not have it.
        move || sandbox.run(&["sh", "-c", HOLD_SCRIPT, TOKEN, HOLD_S], b"", MAX_OUTPUT)
    });
    std::thread::sleep(HOLD_SETTLE);
    let got = failed(&sandbox, &token, None);
    assert_eq!(got.len(), 1, "a command line: {got:?}");
    assert!(got[0].contains("environment or command line"), "{got:?}");
    assert!(holder.join().unwrap().unwrap().success());

    // A file the token was given in that the sandbox user can read.
    let got = failed(&sandbox, &token, Some(Path::new("/etc/hostname")));
    assert_eq!(got.len(), 1, "a readable given file: {got:?}");
    assert!(got[0].contains("cannot read /etc/hostname"), "{got:?}");
    assert_eq!(
        failed(&sandbox, &token, Some(Path::new("/etc/shadow"))),
        [""; 0]
    );

    // From a rootless container, where the sandbox user has podman: its
    // root reads the file, a subordinate uid does not, until the file is
    // open to all. Pulled directly: this job runs no egress proxy.
    let direct = Config::parse(&format!(
        "[sandbox]\nuser = \"{user}\"\n[egress]\nproxy = false\n"
    ))
    .unwrap();
    let image = direct.sandbox.check.container_image.clone();
    let direct = Sandbox::new(&direct).unwrap();
    let has_podman = direct
        .run(&["podman", "--version"], b"", MAX_OUTPUT)
        .is_ok_and(|out| out.success());
    if has_podman {
        assert!(
            direct
                .run(&["podman", "pull", "-q", &image], b"", 1 << 20)
                .unwrap()
                .success(),
            "pulling {image}"
        );
        let probes = probe::token(&direct, &token, &[CLAUDE_ENV_FILE], None, Some(&image)).unwrap();
        let container: Vec<_> = probes
            .iter()
            .filter(|probe| probe.what.contains("container"))
            .collect();
        assert_eq!(container.len(), 3, "{probes:?}");
        assert!(probes.iter().all(|probe| probe.passed), "{probes:?}");
        sh(r#"chmod 0644 "$1" && chmod 0755 "$(dirname "$1")""#);
        let got = failed_in(&direct, &token, None, Some(&image));
        sh(r#"chmod 0600 "$1" && chmod 0700 "$(dirname "$1")""#);
        assert!(
            got.iter()
                .any(|what| what.contains("as uid 1000, cannot read")),
            "{got:?}"
        );
        assert!(
            !got.iter().any(|what| what.contains("(control)")),
            "{got:?}"
        );
    } else {
        eprintln!("{user} has no podman: the container probes are not tried");
    }

    // The control: with the token gone from its file, finding it nowhere
    // else proves nothing, and the probes say so.
    sh(r#": > "$1""#);
    let got = failed(&sandbox, &token, None);
    assert!(got.iter().any(|what| what.contains("(control)")), "{got:?}");
    sh(r#"rm -f "$1""#);
}
