//! The probes that need the run token, repeated by `run` once the agent
//! is configured and before it starts: the token is in the agent's one
//! file, private to the sandbox user, and nowhere else that user can
//! write or read.
//!
//! These are the token's part of the old tree's
//! `agent-isolation-check.mjs`. The probes that need no token are
//! `sandbox check`'s (step 5), which the run action calls again unless
//! it passed earlier in the same job. With `[sandbox.check]
//! before-agent`, `run` makes those again too ([`recheck`]), after its
//! own commands as the sandbox user, and adds the old probe that needs
//! the container image `[sandbox.check]` names: that a container's
//! subordinate uid cannot read the token's files.
//!
//! The token goes to every search on standard input, never on a command
//! line.

use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::clone::utf8;
use super::enter::Sandbox;
use super::inference::Token;
use crate::config::Config;

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
/// Any uid but root in a rootless container is a subordinate uid of the
/// sandbox user's, as in `sandbox check`.
const CONTAINER_UID: &str = "1000";
/// Where a token's directory is in the container.
const CONTAINER_DIR: &str = "/token-dir";
/// How long a container may take, image pull included, in seconds.
const CONTAINER_TIMEOUT_S: &str = "600";
/// Reads `$1` and shows nothing of it: a container's output also goes
/// to podman's log driver, which may be the journal.
const READ_SCRIPT: &str = r#"cat -- "$1" >/dev/null"#;
/// A file every uid of the image can read: the control that a
/// subordinate uid's container runs at all.
const WORLD_READABLE: &str = "/etc/os-release";
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
/// FOUND, shows it to be in FILES and nowhere else. grep's own status says
/// nothing: it is an error for every file it could not read. But a
/// search that timeout(1) cut short found nothing only so far.
fn only_in(code: Option<i32>, found: &[&str], files: &[&str]) -> bool {
    let mut found = found.to_vec();
    let mut files = files.to_vec();
    found.sort_unstable();
    files.sort_unstable();
    code != Some(TIMEOUT_EXIT) && found == files
}

/// Whether HAYSTACK holds NEEDLE.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The command that reads PATH, in a rootless container of IMAGE as UID
/// with the directory DIR at [`CONTAINER_DIR`], and logs nothing of it.
fn read_in_container(image: &str, uid: &str, dir: &str, path: &str) -> Vec<String> {
    [
        "timeout",
        "--kill-after=10",
        CONTAINER_TIMEOUT_S,
        "podman",
        "run",
        "--rm",
        "--network=none",
        "--log-driver=none",
        "--security-opt",
        "label=disable",
        "--user",
        uid,
        "-v",
        &format!("{dir}:{CONTAINER_DIR}:ro"),
        image,
        "sh",
        "-c",
        READ_SCRIPT,
        "sh",
        path,
    ]
    .map(str::to_owned)
    .to_vec()
}

/// Probes that a rootless container's subordinate uid cannot read FILE
/// in DIR, with the controls that the container's root, the sandbox
/// user, can, and that the subordinate uid reads what everyone may.
/// Without podman there is no container to read it from.
fn from_container(sandbox: &Sandbox, image: &str, dir: &str, file: &str) -> Result<Vec<Probe>> {
    let user = &sandbox.user;
    if !sandbox
        .run(&["sh", "-c", "command -v podman"], b"", MAX_OUTPUT)?
        .success()
    {
        eprintln!("note: {user} has no podman, so no container to read {file} from");
        return Ok(Vec::new());
    }
    let reads = |uid, path: &str| -> Result<bool> {
        let argv = read_in_container(image, uid, dir, path);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        Ok(sandbox.run(&argv, b"", MAX_OUTPUT)?.success())
    };
    let inside = format!("{CONTAINER_DIR}/{file}");
    Ok(vec![
        Probe {
            what: format!("a container of {user}'s, as its root, reads {file} (control)"),
            passed: reads("0", &inside)?,
        },
        Probe {
            what: format!(
                "a container of {user}'s, as uid {CONTAINER_UID}, reads {WORLD_READABLE} (control)"
            ),
            passed: reads(CONTAINER_UID, WORLD_READABLE)?,
        },
        Probe {
            what: format!("a container of {user}'s, as uid {CONTAINER_UID}, cannot read {file}"),
            passed: !reads(CONTAINER_UID, &inside)?,
        },
    ])
}

/// Probes where the run token is. TOKEN_FILES are the files that should
/// hold it, under the sandbox user's home: the agent's, and its child
/// agent's if the run has one; GIVEN is the runner's own file the token
/// came from, if it came from one. With IMAGE, each file is also read
/// from a container of it.
pub fn token(
    sandbox: &Sandbox,
    token: &Token,
    token_files: &[&str],
    given: Option<&Path>,
    image: Option<&str>,
) -> Result<Vec<Probe>> {
    let needle = format!("{}\n", token.expose());
    let user = &sandbox.user;
    let home = utf8(&sandbox.home)?;
    let mut probes = Vec::new();
    let mut files = Vec::new();
    for token_file in token_files {
        let file = sandbox.home.join(token_file);
        let dir = file.parent().context("the token's file has no directory")?;
        let (file, dir) = (utf8(&file)?.to_owned(), utf8(dir)?.to_owned());

        // The control: a search that cannot find the token where it is
        // proves nothing by not finding it elsewhere.
        let found = sandbox.run(
            &["grep", "-qsF", "-f", "-", "--", &file],
            needle.as_bytes(),
            MAX_OUTPUT,
        )?;
        probes.push(Probe {
            what: format!("{user}'s {file} holds the run token (control)"),
            passed: found.success(),
        });
        for (what, path, mode) in [
            (file.as_str(), file.as_str(), PRIVATE_FILE_MODE),
            ("its directory", dir.as_str(), PRIVATE_DIR_MODE),
        ] {
            probes.push(private(sandbox, what, path, mode)?);
        }
        if let Some(image) = image {
            let name = Path::new(token_file)
                .file_name()
                .and_then(|name| name.to_str())
                .context("the token's file has no name")?;
            probes.extend(from_container(sandbox, image, &dir, name)?);
        }
        files.push(file);
    }
    let mut probe = |what: String, passed: bool| probes.push(Probe { what, passed });

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
        only_in(
            code,
            &found,
            &files.iter().map(String::as_str).collect::<Vec<_>>(),
        ),
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
    token_files: &[&str],
    given: Option<&Path>,
    image: Option<&str>,
) -> Result<()> {
    let probes = self::token(sandbox, token, token_files, given, image)?;
    ensure!(
        report(&probes),
        "the run token is not only where it belongs: see the failed probes above"
    );
    Ok(())
}

/// `sandbox check`'s probes of the sandbox CONFIG describes, again, and
/// an error unless all passed: what `[sandbox.check] before-agent` asks
/// of `run` once it has cloned the target. Between the run action's check
/// and here `run` has run commands as the sandbox user, and a check
/// probes what such a user left behind (a process, a unit, a listener).
pub fn recheck(config: &Config) -> Result<()> {
    eprintln!("Probing the sandbox again before the agent starts (sandbox.check.before-agent)");
    let report = crate::sandbox::check::probes(config, None)?;
    let failures: Vec<&str> = report.failures().into_iter().collect();
    ensure!(
        failures.is_empty(),
        "{} sandbox check(s) failed before the agent started: {}",
        failures.len(),
        failures.join(", ")
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
        const CHILD: &str = "/home/agent/.config/child.toml";
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
            assert_eq!(only_in(code, found, &[FILE]), want, "{code:?} {found:?}");
        }
        // With a child agent, both of its files and no other.
        let cases: [(&[&str], bool); 5] = [
            (&[CHILD, FILE], true),
            (&[FILE, CHILD], true),
            (&[FILE], false),
            (&[CHILD], false),
            (&[FILE, CHILD, "/tmp/copy"], false),
        ];
        for (found, want) in cases {
            assert_eq!(only_in(Some(0), found, &[FILE, CHILD]), want, "{found:?}");
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
