//! The probes that need the run token, repeated by `run` once the agent
//! is configured and before it starts: the token is in the agent's one
//! file, private to the sandbox user, and nowhere else that user can
//! write or read.
//!
//! These are the token's part of the old tree's
//! `agent-isolation-check.mjs`. The probes that need no token are
//! `sandbox check`'s (step 5), which the run action calls again unless
//! it passed earlier in the same job. One
//! of the old probes is left to that step, since it needs the container
//! image `[sandbox.check]` names: that a container's subordinate uid
//! cannot read the file.
//!
//! The token goes to every search on standard input, never on a command
//! line.

use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::clone::utf8;
use super::enter::Sandbox;
use super::inference::Token;

/// Where the sandbox user can write, and so where a token handed to it
/// could have been left, besides its home.
const SHARED_WRITABLE: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];
/// How long the search of those may take, in seconds.
const SEARCH_TIMEOUT_S: &str = "300";
/// What timeout(1) exits with when it ended the command.
const TIMEOUT_EXIT: i32 = 124;
/// Every command line and environment the sandbox user can read.
const PROCESSES_SCRIPT: &str = "cat /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null; true";
/// What those may add up to on a machine with many processes.
const MAX_PROCESSES_BYTES: usize = 256 << 20;
const MAX_OUTPUT: usize = 1 << 20;
const PRIVATE_FILE_MODE: &str = "600";
const PRIVATE_DIR_MODE: &str = "700";

/// One probe: what was expected, and whether it held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub what: String,
    pub passed: bool,
}

/// The owner and mode of PATH, as the sandbox user sees them; or why
/// they could not be had, which is no owner and mode a probe expects.
fn owner_and_mode(sandbox: &Sandbox, path: &str) -> Result<String> {
    let out = sandbox.run(&["stat", "-c", "%U %a", "--", path], b"", MAX_OUTPUT)?;
    Ok(if out.success() {
        out.text()
    } else {
        format!("stat failed, {}", out.error())
    })
}

/// A probe that PATH is USER's and of MODE. It says what it found: a
/// failed probe whose text is only what was expected cannot be acted on.
fn private(sandbox: &Sandbox, what: &str, path: &str, mode: &str) -> Result<Probe> {
    let user = &sandbox.user;
    let found = owner_and_mode(sandbox, path)?;
    Ok(Probe {
        what: format!("{what} is {user}'s, mode {mode} (it is: {found})"),
        passed: found == format!("{user} {mode}"),
    })
}

/// Whether a search for the token, which exited with CODE and listed
/// FOUND, shows it to be in FILE and nowhere else. grep's own status says
/// nothing: it is an error for every file it could not read. But a
/// search that timeout(1) cut short found nothing only so far.
fn only_in(code: Option<i32>, found: &[&str], file: &str) -> bool {
    code != Some(TIMEOUT_EXIT) && found == [file]
}

/// Whether HAYSTACK holds NEEDLE.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Probes where the run token is. TOKEN_FILE is the agent's file that
/// should hold it, under the sandbox user's home; GIVEN is the runner's
/// own file the token came from, if it came from one.
pub fn token(
    sandbox: &Sandbox,
    token: &Token,
    token_file: &str,
    given: Option<&Path>,
) -> Result<Vec<Probe>> {
    let file = sandbox.home.join(token_file);
    let dir = file.parent().context("the token's file has no directory")?;
    let (file, dir, home) = (utf8(&file)?, utf8(dir)?, utf8(&sandbox.home)?);
    let needle = format!("{}\n", token.expose());
    let user = &sandbox.user;
    let mut probes = Vec::new();
    let mut probe = |what: String, passed: bool| probes.push(Probe { what, passed });

    // The control: a search that cannot find the token where it is
    // proves nothing by not finding it elsewhere.
    let found = sandbox.run(
        &["grep", "-qsF", "-f", "-", "--", file],
        needle.as_bytes(),
        MAX_OUTPUT,
    )?;
    probe(
        format!("{user}'s {file} holds the run token (control)"),
        found.success(),
    );
    for (what, path, mode) in [
        (file, file, PRIVATE_FILE_MODE),
        ("its directory", dir, PRIVATE_DIR_MODE),
    ] {
        let private = private(sandbox, what, path, mode)?;
        probe(private.what, private.passed);
    }

    let search = [
        &[
            "timeout",
            SEARCH_TIMEOUT_S,
            "grep",
            "-rlsF",
            "-f",
            "-",
            "--",
            home,
        ],
        SHARED_WRITABLE,
    ]
    .concat();
    let search = sandbox.run(&search, needle.as_bytes(), MAX_OUTPUT)?;
    let code = search.status.code();
    let timed_out = code == Some(TIMEOUT_EXIT);
    let found = search.text();
    let found: Vec<&str> = found.lines().collect();
    probe(
        format!(
            "{user} finds the token in no other file it can write ({})",
            if timed_out {
                format!("the search took more than {SEARCH_TIMEOUT_S}s")
            } else if found.is_empty() {
                "nowhere".to_owned()
            } else {
                found.join(", ")
            }
        ),
        only_in(code, &found, file),
    );

    let processes = sandbox.run(&["sh", "-c", PROCESSES_SCRIPT], b"", MAX_PROCESSES_BYTES)?;
    probe(
        format!("no process {user} can read has the token in its environment or command line"),
        !holds(&processes.stdout, token.expose().as_bytes()),
    );

    if let Some(given) = given {
        let given = utf8(given)?;
        let read = sandbox.run(&["cat", "--", given], b"", MAX_OUTPUT)?;
        probe(format!("{user} cannot read {given}"), !read.success());
    }
    Ok(probes)
}

/// Probes where TOKEN is, prints what was found, and fails unless every
/// probe passed: what `run` does before it starts an agent that holds
/// the token.
pub fn require(
    sandbox: &Sandbox,
    token: &Token,
    token_file: &str,
    given: Option<&Path>,
) -> Result<()> {
    let probes = self::token(sandbox, token, token_file, given)?;
    ensure!(
        report(&probes),
        "the run token is not only where it belongs: see the failed probes above"
    );
    Ok(())
}

/// Prints PROBES as the old check did, and says whether all passed.
pub fn report(probes: &[Probe]) -> bool {
    for probe in probes {
        let mark = if probe.passed { "ok  " } else { "FAIL" };
        eprintln!("{mark} {}", super::enter::one_line(&probe.what));
    }
    probes.iter().all(|probe| probe.passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_found_in_bytes() {
        let dump = b"PATH=/usr/bin\0TOKEN=praxis-run-abc\0\xff\xfe";
        assert!(holds(dump, b"praxis-run-abc"));
        assert!(!holds(dump, b"praxis-run-abd"));
        assert!(!holds(b"", b"praxis-run-abc"));
    }

    /// The token has to be found in its file, and the search has to have
    /// finished, for it to show the token is nowhere else.
    #[test]
    fn a_search_shows_the_token_only_where_it_finished() {
        const FILE: &str = "/home/agent/.config/x.json";
        // (the search's exit status, what it listed, the verdict)
        let cases: [(Option<i32>, &[&str], bool); 7] = [
            (Some(0), &[FILE], true),
            // grep could not read some file: still a whole search.
            (Some(2), &[FILE], true),
            (Some(TIMEOUT_EXIT), &[FILE], false),
            (Some(TIMEOUT_EXIT), &[], false),
            (Some(1), &[], false),
            (Some(0), &[FILE, "/tmp/copy"], false),
            (Some(0), &["/tmp/copy"], false),
        ];
        for (code, found, want) in cases {
            assert_eq!(only_in(code, found, FILE), want, "{code:?} {found:?}");
        }
    }

    #[test]
    fn a_failed_probe_fails_the_report() {
        let probe = |passed| Probe {
            what: "a probe".into(),
            passed,
        };
        assert!(report(&[probe(true), probe(true)]));
        assert!(!report(&[probe(true), probe(false)]));
        assert!(report(&[]));
    }
}
