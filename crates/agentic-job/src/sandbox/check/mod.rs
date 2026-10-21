//! `agentic-job sandbox check`: prove, as the sandbox user, that the
//! sandbox holds, before an agent is started in it.
//!
//! Each probe is something the sandbox user tries and must not manage,
//! and each has a positive control: the same attempt somewhere it should
//! work. Without the control, a probe that fails because a program is
//! missing reads as a protection that holds.
//!
//! The probes are a function, [`probes`], because `run` repeats them
//! with `[sandbox.check] before-agent` and the host test that removes
//! protections calls it. None of them is of the run token: those are
//! `run`'s own (`crate::run::probe`), made once the token is in place.
//! docs/sandbox-check.md lists them all.
//!
//! The probes are methods of `Checker` in the modules under this one:
//! `on_host`, `runner` (the runner's own user, which setup
//! has taken root from) and `net`; what a pass leaves for a later check
//! in the same job is `record`.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, ensure};

use super::enter::{Entry, Output};
use super::host::{self, User};
use super::root::Root;
use crate::config::{self, Config};
use crate::exit::Exit;

mod net;
mod on_host;
mod record;
mod runner;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// When all probes pass, leave a record for the next check in this
    /// job (secure-host's check, for `run`'s)
    #[arg(long, conflicts_with = "unless_passed")]
    pub record: bool,
    /// Probe nothing when the record of a check with `--record` is there,
    /// against the same configuration, and no one has entered the sandbox
    /// user since; probe as usual when it is not
    #[arg(long)]
    pub unless_passed: bool,
}

impl Args {
    fn mode(&self) -> Mode {
        match (self.record, self.unless_passed) {
            (true, _) => Mode::Record,
            (false, true) => Mode::UnlessPassed,
            (false, false) => Mode::Probe,
        }
    }
}

/// What a check does with this job's record, besides consuming it: see
/// [`once`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Only probe.
    Probe,
    /// Probe, and leave a record when all probes pass.
    Record,
    /// Take a record in place of probing.
    UnlessPassed,
}

/// How many probes of a batch of independent ones run at once: each is a
/// session of the sandbox user's, and some start a container.
const CONCURRENT_PROBES: usize = 8;

const CANARY_BYTES: usize = 12;

/// Put before every command a probe runs as the sandbox user.
const PROBE_LIMIT: &[&str] = &["timeout", "--kill-after=10", "600"];

/// Any uid other than root in a rootless container maps to a subordinate
/// uid of the sandbox user.
const CONTAINER_UID: &str = "1000";

const CA_MOUNT: &str = "/etc/egress-proxy/ca.pem:/run/egress-ca.pem:ro";

/// What one probe or control found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Stable across runs: tests and readers of the log match on it.
    pub id: String,
    pub what: String,
    pub passed: bool,
}

/// Every outcome of one pass over the probes, in order.
#[derive(Debug, Default)]
pub struct Report {
    outcomes: Vec<Outcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    Succeed,
    Fail,
}

impl Report {
    /// Records that the attempt `id` did or did not succeed, and prints
    /// the line at once: some probes take a while.
    fn expect(&mut self, want: Want, id: &str, what: impl Into<String>, succeeded: bool) {
        let (what, passed) = (what.into(), succeeded == (want == Want::Succeed));
        println!(
            "{}",
            crate::workflow_commands::escaped(&format!(
                "{}: [{id}] {what}",
                if passed { "ok" } else { "FAIL" }
            ))
        );
        self.outcomes.push(Outcome {
            id: id.to_owned(),
            what,
            passed,
        });
    }

    fn note(&self, text: &str) {
        println!("note: {}", crate::workflow_commands::escaped(text));
    }

    /// A control of `runner`'s: see [`Checker::control_or_note`].
    fn control(&mut self, runner: &str, id: &str, what: &str, reached: bool) {
        if reached {
            self.expect(
                Want::Succeed,
                id,
                format!("{runner} reaches {what} (control)"),
                true,
            );
        } else {
            self.note(&format!("{runner} can't reach {what} either (no control)"));
        }
    }

    /// Whether each of `attempts` succeeded, in their order: one result
    /// for each, or none reported at all.
    fn attempts(&mut self, runner: &str, attempts: &[Attempt], succeeded: &[bool]) -> Result<()> {
        ensure!(
            attempts.len() == succeeded.len(),
            "{} results for {} attempts",
            succeeded.len(),
            attempts.len()
        );
        for (attempt, &got) in attempts.iter().zip(succeeded) {
            match attempt.kind {
                AttemptKind::Control => self.control(runner, &attempt.id, &attempt.what, got),
                AttemptKind::Refused | AttemptKind::RefusedInContainer => {
                    self.expect(Want::Fail, &attempt.id, attempt.what.clone(), got);
                }
            }
        }
        Ok(())
    }

    pub fn outcomes(&self) -> &[Outcome] {
        &self.outcomes
    }

    /// The ids of what did not come out as it must.
    pub fn failures(&self) -> BTreeSet<&str> {
        self.outcomes
            .iter()
            .filter(|outcome| !outcome.passed)
            .map(|outcome| outcome.id.as_str())
            .collect()
    }

    pub fn passed(&self) -> bool {
        self.outcomes.iter().all(|outcome| outcome.passed)
    }
}

pub fn run(args: &Args) -> Result<Exit> {
    ensure!(
        !host::is_root(),
        "`sandbox check` runs as the runner's user, which it compares the sandbox user with; it enters the sandbox through the helper"
    );
    let path = Path::new(config::ROOT_COPY);
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))
        .context("`agentic-job sandbox setup` writes this file")?;
    let config = Config::parse(&text).with_context(|| format!("in {}", path.display()))?;
    let record = job_record(record::binary, |name| std::env::var(name).ok(), &text);
    let checked = once(args.mode(), record.as_ref(), || {
        let started = Instant::now();
        let report = probes(&config)?;
        let failures = report.failures();
        if failures.is_empty() {
            println!(
                "{} sandbox checks passed in {:.1}s",
                report.outcomes().len(),
                started.elapsed().as_secs_f64()
            );
            return Ok(true);
        }
        let ids: Vec<&str> = failures.into_iter().collect();
        eprintln!(
            "error: {} sandbox check(s) failed: {}",
            ids.len(),
            ids.join(", ")
        );
        Ok(false)
    })?;
    Ok(match checked {
        Checked::Recorded(file) => {
            println!(
                "The sandbox checks passed earlier in this job, against this configuration ({}): not repeated",
                file.display()
            );
            Exit::Success
        }
        Checked::Probed { passed: true } => Exit::Success,
        Checked::Probed { passed: false } => Exit::Failure,
    })
}

/// Removes this job's record of a passing check, if there is one: what
/// starts the agent (`run`) calls this first, since
/// what that user leaves behind is what the next check has to probe.
pub fn forget_passed() -> Result<()> {
    forget(|name| std::env::var(name).ok())
}

fn forget(env: impl Fn(&str) -> Option<String>) -> Result<()> {
    record::path(env).map_or(Ok(()), |path| record::clear(&path))
}

/// This job's record of a passing check: see [`record`].
#[derive(Debug)]
struct JobRecord {
    file: PathBuf,
    /// What it must say; `None` where there is no telling (see
    /// [`job_record`]), and no record is taken or left, only cleared.
    content: Option<Vec<u8>>,
}

/// Where this job's record is and what it must say, for the configuration
/// `config` (its text) and the executable `binary` names: `None` without
/// a temporary directory, and no `content` when `binary` cannot name the
/// executable or the job cannot be told from another.
fn job_record(
    binary: impl FnOnce() -> Result<String>,
    env: impl Fn(&str) -> Option<String>,
    config: &str,
) -> Option<JobRecord> {
    let file = record::path(&env)?;
    let content = binary()
        .inspect_err(|err| eprintln!("warning: no record of this check for the job: {err:#}"))
        .ok()
        .and_then(|binary| record::for_job(&env, &binary, config))
        .map(|(_, content)| content);
    Some(JobRecord { file, content })
}

/// What [`once`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Checked {
    /// Took the record, this file, of a check earlier in the job, and
    /// probed nothing.
    Recorded(PathBuf),
    /// Made the probes, which all passed or not.
    Probed { passed: bool },
}

/// The probes, `probe`, as `mode` says. Every check consumes `record`
/// (its file and what it must say) before anything else, whether it
/// takes it or not; only [`Mode::UnlessPassed`] takes it in place of the
/// probes, and only [`Mode::Record`] writes one, after probes that all
/// passed. So a record means that secure-host's check passed and nothing
/// entered the sandbox user since, and it spares one check at most.
fn once(
    mode: Mode,
    record: Option<&JobRecord>,
    probe: impl FnOnce() -> Result<bool>,
) -> Result<Checked> {
    if let Some(JobRecord { file, content }) = record {
        let held = match content {
            Some(content) => record::take(file, content)?,
            None => record::clear(file).map(|()| false)?,
        };
        if held && mode == Mode::UnlessPassed {
            return Ok(Checked::Recorded(file.clone()));
        }
    }
    let passed = probe()?;
    // Without the record the next check only probes again.
    if passed
        && mode == Mode::Record
        && let Some(JobRecord {
            file,
            content: Some(content),
        }) = record
        && let Err(err) = record::write(file, content)
    {
        eprintln!("warning: no record of this check for later in the job: {err:#}");
    }
    Ok(Checked::Probed { passed })
}

/// Probes the sandbox `config` describes, as its sandbox user, from the
/// runner's user. `Err` is a probe that could not be made at all; a
/// probe that came out wrong is in the report.
pub fn probes(config: &Config) -> Result<Report> {
    let entry = Entry::new(config)?;
    let checker = Checker {
        config,
        root: entry.root(),
        entry,
        runner: User::current()?,
        canary: canary()?,
        report: Report::default(),
    };
    checker.run()
}

/// A value nothing else on the host has.
fn canary() -> Result<String> {
    let mut bytes = [0u8; CANARY_BYTES];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .context("reading /dev/urandom")?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("isolation-canary-{hex}"))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

struct Checker<'a> {
    config: &'a Config,
    entry: Entry,
    /// How root is had for the controls that need it.
    root: Root,
    runner: User,
    canary: String,
    report: Report,
}

impl Checker<'_> {
    fn run(mut self) -> Result<Report> {
        self.timed("privileges", |this| this.privileges())?;
        if self.config.sandbox.lock_runner {
            self.timed("runner-privileges", |this| this.runner_privileges())?;
        }
        // The metadata and diagnostics rules have probes that name them.
        // The read rule is the secure-host image's loader's to enable and
        // prove, before and after; a probe here would need a process an
        // earlier step left, and `sandbox setup` alone never loads it.
        if self.config.sandbox.deny_runner_reads() {
            self.report.note(
                "sandbox.deny-runner-reads is on: only the secure-host image's world-write loader enables and proves the runner-read rule; this check does not probe it",
            );
        }
        for line in self.config.sandbox.runner_rule_opt_outs(&self.runner.name) {
            self.report.note(&line);
        }
        let environs = self.timed("environments", |this| this.environments())?;
        self.timed("job-variables", |this| this.job_variables(&environs))?;
        self.timed("files", |this| this.files())?;
        self.timed("schedulers", |this| this.schedulers())?;
        self.timed("services", |this| {
            this.services();
            Ok(())
        })?;
        self.timed("local-services", |this| this.local_services())?;
        self.timed("resolved", |this| this.resolved())?;
        self.timed("tailscaled", |this| this.tailscaled())?;
        self.timed("network", |this| this.network())?;
        Ok(self.report)
    }

    fn timed<T>(&mut self, name: &str, run: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        super::timed::stage("check", name, || run(self))
    }

    fn user(&self) -> &str {
        &self.entry.user().name
    }

    /// Runs `argv` as the sandbox user, with a limit on its time: a probe
    /// that hangs has to fail the check, not hold the job.
    fn sandbox(&self, argv: &[&str], input: &[u8]) -> Result<Output> {
        let limited: Vec<&str> = PROBE_LIMIT.iter().chain(argv).copied().collect();
        self.entry.run(&limited, input)
    }

    fn sandbox_succeeds(&self, argv: &[&str]) -> Result<bool> {
        Ok(self.sandbox(argv, b"")?.success())
    }

    /// Diagnostics for positive controls only: expected refusals are not errors.
    fn sandbox_diagnosed(&self, id: &str, argv: &[&str], input: &[u8]) -> Result<bool> {
        let output = self.sandbox(argv, input)?;
        if !output.success() {
            self.report.note(&format!(
                "{id}: command {argv:?} exited {}; stderr: {}",
                output.status,
                bounded_stderr(&output.stderr),
            ));
        }
        Ok(output.success())
    }

    fn has_podman(&self) -> bool {
        host::has_program("podman")
    }

    /// Runs `argv` in a rootless container on the host's network, as a
    /// subordinate uid; with the egress proxy, its authority is there too.
    fn in_container(&self, argv: &[&str]) -> Result<bool> {
        Ok(self.sandbox(&self.container(argv), b"")?.success())
    }

    fn container<'a>(&'a self, argv: &[&'a str]) -> Vec<&'a str> {
        let mount: &[&str] = if self.config.egress.proxy {
            &["--security-opt", "label=disable", "-v", CA_MOUNT]
        } else {
            &[]
        };
        let parts: [&[&str]; 4] = [
            &[
                "podman",
                "run",
                "--rm",
                "--network=host",
                "--user",
                CONTAINER_UID,
            ],
            mount,
            &[self.config.sandbox.check.container_image.as_str()],
            argv,
        ];
        parts.concat()
    }

    /// A control for something the sandbox user must not reach: the
    /// runner's user reaches it. Where it does not either (another
    /// cloud, a network that already refuses it), there is no control,
    /// and the probe says less; that is noted, not failed.
    fn control_or_note(&mut self, id: &str, what: &str, argv: &[&str]) {
        let reached = runner_reaches(argv);
        self.report.control(&self.runner.name, id, what, reached);
    }

    /// Makes the independent `attempts` a few at a time, and then reports
    /// each in their order, as they would have been one after another:
    /// most of the time of a refusal is its own way into the sandbox,
    /// which the next one need not wait for.
    fn attempts(&mut self, attempts: &[Attempt]) -> Result<()> {
        let this = &*self;
        let results = in_order(attempts, |attempt| {
            let argv: Vec<&str> = attempt.argv.iter().map(String::as_str).collect();
            match attempt.kind {
                AttemptKind::Control => Ok(runner_reaches(&argv)),
                AttemptKind::Refused | AttemptKind::RefusedInContainer => {
                    this.refusal_succeeds(attempt, &argv)
                }
            }
        })?;
        self.report.attempts(&self.runner.name, attempts, &results)
    }

    /// Whether the sandbox user succeeds at `attempt`'s `argv`, which it
    /// must not. `Err` when its session never got to `argv`: sudo, the
    /// helper, run0 or PAM failing to start one, which a status alone
    /// would report as a refusal that holds; and, for one in a container,
    /// when podman did not start the container or its command.
    fn refusal_succeeds(&self, attempt: &Attempt, argv: &[&str]) -> Result<bool> {
        let id = &attempt.id;
        let output = self.sandbox(&[&["sh", "-c", ENTER_SCRIPT, ENTERED], argv].concat(), b"")?;
        ensure!(
            entered(&output.stderr),
            "{id}: the sandbox user's session never ran {argv:?}, so its refusal proves nothing (exited {}); stderr: {}",
            output.status,
            bounded_stderr(&output.stderr)
        );
        ensure!(
            attempt.kind != AttemptKind::RefusedInContainer || started(output.status.code()),
            "{id}: podman did not run {argv:?}, so its refusal proves nothing (exited {}); stderr: {}",
            output.status,
            bounded_stderr(&output.stderr)
        );
        Ok(output.success())
    }
}

/// The line a refusal's session prints to its standard error before it
/// makes the attempt: see [`Checker::refusal_succeeds`].
const ENTERED: &str = "agentic-job-sandbox-entered";

/// Prints its `$0`, [`ENTERED`], and becomes the attempt.
const ENTER_SCRIPT: &str = r#"printf '%s\n' "$0" >&2; exec "$@""#;

/// Whether `stderr` has the line [`ENTER_SCRIPT`] prints, whatever the
/// way in printed around it.
fn entered(stderr: &[u8]) -> bool {
    stderr
        .split(|&byte| byte == b'\n')
        .any(|line| line == ENTERED.as_bytes())
}

/// The statuses `podman run` exits with when the container or its command
/// did not start, rather than the command's own: podman's error, a command
/// that could not be run, one that was not found. The same three are
/// `timeout`'s ([`PROBE_LIMIT`]) and the shell's for the same failures.
const NOT_STARTED: std::ops::RangeInclusive<i32> = 125..=127;

/// Whether a container attempt that exited `code` ran its command: one a
/// signal ended (no code) did.
fn started(code: Option<i32>) -> bool {
    code.is_none_or(|code| !NOT_STARTED.contains(&code))
}

/// Independent host attempts and a single lane of container attempts
/// overlap, within the same total bound. Podman startups remain serial;
/// results (including errors) remain in the original report order.
fn in_order<R: Send>(
    attempts: &[Attempt],
    make: impl Fn(&Attempt) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    let make = |attempt: &Attempt| super::timed::stage("check", &attempt.id, || make(attempt));
    let together: Vec<&Attempt> = attempts
        .iter()
        .filter(|attempt| attempt.kind != AttemptKind::RefusedInContainer)
        .collect();
    let containers: Vec<&Attempt> = attempts
        .iter()
        .filter(|attempt| attempt.kind == AttemptKind::RefusedInContainer)
        .collect();
    let (made, container_results) = std::thread::scope(|scope| {
        let make = &make;
        let lane = scope.spawn(|| {
            containers
                .iter()
                .map(|attempt| make(attempt))
                .collect::<Vec<_>>()
        });
        let host_limit = CONCURRENT_PROBES - usize::from(!containers.is_empty());
        let made = concurrently_bounded(&together, host_limit, |attempt| make(attempt));
        let container_results = lane
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        (made, container_results)
    });
    let (mut made, mut container_results) = (made.into_iter(), container_results.into_iter());
    attempts
        .iter()
        .map(|attempt| {
            let result = match attempt.kind {
                AttemptKind::RefusedInContainer => container_results.next(),
                _ => made.next(),
            };
            result.context("an attempt of the batch was not made")?
        })
        .collect()
}

/// Whether the runner's user, this process, succeeds at `argv`.
fn runner_reaches(argv: &[&str]) -> bool {
    host::command(argv)
        .map(|mut command| host::succeeds(&mut command))
        .unwrap_or(false)
}

/// What the runner's user, this process, prints running `argv`: empty
/// when it could not be run.
fn runner_stdout(argv: &[&str]) -> String {
    host::command(argv)
        .and_then(|mut command| Ok(command.stdin(std::process::Stdio::null()).output()?))
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptKind {
    /// The runner's user tries, as a control: see
    /// [`Checker::control_or_note`].
    Control,
    /// The sandbox user tries, and must not manage.
    Refused,
    /// The same from a rootless container, made beside the host attempts but one
    /// at a time: podman's start (its storage lock, its pause process) is
    /// what starts made together could fail at. A container that never
    /// started, or whose command did not, is an `Err` rather than a
    /// refusal that holds ([`started`]).
    RefusedInContainer,
}

/// One of a batch of probes that do not depend on each other.
#[derive(Debug)]
struct Attempt {
    kind: AttemptKind,
    id: String,
    what: String,
    argv: Vec<String>,
}

impl Attempt {
    fn control(id: impl Into<String>, what: impl Into<String>, argv: &[&str]) -> Self {
        Self::new(AttemptKind::Control, id, what, argv)
    }

    fn refused(id: impl Into<String>, what: impl Into<String>, argv: &[&str]) -> Self {
        Self::new(AttemptKind::Refused, id, what, argv)
    }

    fn refused_in_container(id: impl Into<String>, what: impl Into<String>, argv: &[&str]) -> Self {
        Self::new(AttemptKind::RefusedInContainer, id, what, argv)
    }

    fn new(
        kind: AttemptKind,
        id: impl Into<String>,
        what: impl Into<String>,
        argv: &[&str],
    ) -> Self {
        Self {
            kind,
            id: id.into(),
            what: what.into(),
            argv: argv.iter().map(|&arg| arg.to_owned()).collect(),
        }
    }
}

/// `run` for each of `items`, at most [`CONCURRENT_PROBES`] at a time,
/// with the results in the order of the items.
fn concurrently<T: Sync, R: Send>(items: &[T], run: impl Fn(&T) -> R + Sync) -> Vec<R> {
    concurrently_bounded(items, CONCURRENT_PROBES, run)
}

fn concurrently_bounded<T: Sync, R: Send>(
    items: &[T],
    limit: usize,
    run: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let run = &run;
    items
        .chunks(limit)
        .flat_map(|chunk| {
            std::thread::scope(|scope| {
                let started: Vec<_> = chunk
                    .iter()
                    .map(|item| scope.spawn(move || run(item)))
                    .collect();
                started
                    .into_iter()
                    .map(|thread| {
                        thread
                            .join()
                            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                    })
                    .collect::<Vec<R>>()
            })
        })
        .collect()
}

const DIAGNOSTIC_BYTES: usize = 4096;

fn bounded_stderr(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(&stderr[..stderr.len().min(DIAGNOSTIC_BYTES)]);
    // Escape terminal/control characters, including newlines, so a subprocess
    // cannot forge another probe result or a workflow command in the log.
    let mut shown = crate::workflow_commands::escaped(
        &text
            .chars()
            .flat_map(char::escape_default)
            .collect::<String>(),
    );
    if stderr.len() > DIAGNOSTIC_BYTES {
        shown.push_str(" [truncated]");
    }
    shown
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn stderr_is_bounded_and_escaped() {
        for (input, expected) in [
            (b"".as_slice(), ""),
            (b"denied\n\x1b".as_slice(), "denied\\n\\u{1b}"),
            (b"\xff".as_slice(), "\\u{fffd}"),
            (
                b"::add-mask::x ##[error]y".as_slice(),
                ": :add-mask: :x ## [error]y",
            ),
        ] {
            assert_eq!(bounded_stderr(input), expected);
        }
        assert_eq!(
            bounded_stderr(&vec![b'x'; DIAGNOSTIC_BYTES]),
            "x".repeat(DIAGNOSTIC_BYTES)
        );
        assert_eq!(
            bounded_stderr(&vec![b'x'; DIAGNOSTIC_BYTES + 1]),
            format!("{} [truncated]", "x".repeat(DIAGNOSTIC_BYTES))
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_search() {
        assert!(contains(b"A=1\0HOME=/home/agent\0", b"HOME=/home/agent"));
        assert!(!contains(b"A=1\0", b"HOME="));
        assert!(!contains(b"short", b"much longer than the text"));
        // An empty needle must never read as "found".
        assert!(!contains(b"anything", b""));
    }

    #[test]
    fn a_report_fails_on_a_wrong_outcome_of_either_kind() {
        let mut report = Report::default();
        report.expect(Want::Fail, "sudo", "no sudo", false);
        report.expect(Want::Succeed, "sudo-control", "runner has sudo", true);
        assert!(report.passed());
        // The protection is gone.
        report.expect(Want::Fail, "cron", "no crontab", true);
        // The control did not work, so its probe proves nothing.
        report.expect(Want::Succeed, "cron-control", "runner may", false);
        assert!(!report.passed());
        assert_eq!(
            report.failures().into_iter().collect::<Vec<_>>(),
            ["cron", "cron-control"]
        );
    }

    #[test]
    fn a_batch_fails_on_any_refusal_that_succeeded() {
        let attempts = [
            Attempt::control("tcp-control", "a:1", &["true"]),
            Attempt::refused("tcp", "agent can't reach a:1", &["false"]),
            Attempt::control("udp-control", "b:2", &["false"]),
            Attempt::refused("udp", "agent can't reach b:2", &["false"]),
        ];
        let mut report = Report::default();
        report
            .attempts("runner", &attempts, &[true, false, false, false])
            .unwrap();
        assert!(report.passed());
        // The control that failed is a note, not an outcome.
        let ids: Vec<&str> = report.outcomes().iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["tcp-control", "tcp", "udp"]);
        for (index, refusal) in [(1, "tcp"), (3, "udp")] {
            let mut results = [true, false, false, false];
            results[index] = true;
            let mut report = Report::default();
            report.attempts("runner", &attempts, &results).unwrap();
            assert_eq!(report.failures().into_iter().collect::<Vec<_>>(), [refusal]);
        }
        // A result short or over is no report, not a partial one.
        for results in [
            &[true, false, false][..],
            &[true, false, false, false, false],
        ] {
            let mut report = Report::default();
            assert!(report.attempts("runner", &attempts, results).is_err());
            assert!(report.outcomes().is_empty());
        }
    }

    #[test]
    fn a_container_that_did_not_start_refused_nothing() {
        for (code, ran) in [
            (Some(0), true),
            (Some(1), true),
            // curl's "could not connect" and `timeout`'s own limit.
            (Some(7), true),
            (Some(124), true),
            // podman's error, a command it could not run or did not find.
            (Some(125), false),
            (Some(126), false),
            (Some(127), false),
            (Some(128), true),
            (None, true),
        ] {
            assert_eq!(started(code), ran, "{code:?}");
        }
    }

    #[test]
    fn batches_keep_their_order_and_their_bound() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (running, most) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let items: Vec<usize> = (0..3 * CONCURRENT_PROBES + 1).collect();
        let results = concurrently(&items, |&item| {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            most.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(20));
            running.fetch_sub(1, Ordering::SeqCst);
            item * 2
        });
        assert_eq!(
            results,
            items.iter().map(|item| item * 2).collect::<Vec<_>>()
        );
        // How many overlap depends on the machine; that no more than the
        // bound do does not.
        let most = most.into_inner();
        assert!((1..=CONCURRENT_PROBES).contains(&most), "{most}");
    }

    #[test]
    fn results_come_back_under_their_own_attempts() {
        use AttemptKind::{Control, Refused, RefusedInContainer};
        let attempt = |kind, id: &str| Attempt::new(kind, id, id, &[]);
        let many: Vec<Attempt> = (0..CONCURRENT_PROBES + 2)
            .flat_map(|n| {
                [
                    attempt(Refused, &format!("r{n}")),
                    attempt(RefusedInContainer, &format!("c{n}")),
                ]
            })
            .collect();
        for attempts in [
            vec![],
            vec![attempt(Control, "a")],
            vec![attempt(RefusedInContainer, "a")],
            vec![
                attempt(Control, "a"),
                attempt(RefusedInContainer, "b"),
                attempt(Refused, "c"),
                attempt(RefusedInContainer, "d"),
            ],
            vec![
                attempt(RefusedInContainer, "a"),
                attempt(RefusedInContainer, "b"),
                attempt(Control, "c"),
                attempt(Refused, "d"),
                attempt(Refused, "e"),
            ],
            many,
        ] {
            let made = std::sync::Mutex::new(Vec::new());
            let results = in_order(&attempts, |attempt| {
                made.lock().unwrap().push(attempt.kind);
                Ok(attempt.id.clone())
            })
            .unwrap();
            let ids: Vec<&str> = attempts.iter().map(|a| a.id.as_str()).collect();
            assert_eq!(results, ids);
            let made = made.into_inner().unwrap();
            assert_eq!(made.len(), attempts.len());
        }
    }

    #[test]
    fn container_lane_overlaps_host_attempts_but_never_itself() {
        use std::sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        };
        let (host_tx, host_rx) = mpsc::channel();
        let (container_tx, container_rx) = mpsc::channel();
        let (host_rx, container_rx) = (Mutex::new(host_rx), Mutex::new(container_rx));
        let limit = std::time::Duration::from_secs(5);
        let containers = AtomicUsize::new(0);
        let attempts = [
            Attempt::control("host", "host", &[]),
            Attempt::refused_in_container("first", "first", &[]),
            Attempt::refused_in_container("second", "second", &[]),
        ];
        let results = in_order(&attempts, |attempt| {
            if attempt.kind == AttemptKind::RefusedInContainer {
                assert_eq!(containers.fetch_add(1, Ordering::SeqCst), 0);
            }
            if attempt.id == "host" {
                host_tx.send(()).unwrap();
                container_rx.lock().unwrap().recv_timeout(limit).unwrap();
            } else if attempt.id == "first" {
                container_tx.send(()).unwrap();
                host_rx.lock().unwrap().recv_timeout(limit).unwrap();
            }
            if attempt.kind == AttemptKind::RefusedInContainer {
                assert_eq!(containers.fetch_sub(1, Ordering::SeqCst), 1);
            }
            Ok(attempt.id.clone())
        })
        .unwrap();
        assert_eq!(results, ["host", "first", "second"]);
    }

    #[test]
    fn an_attempt_that_was_not_made_fails_the_batch() {
        for kind in [AttemptKind::Refused, AttemptKind::RefusedInContainer] {
            let attempts = [
                Attempt::control("a", "a", &[]),
                Attempt::new(kind, "b", "b", &[]),
            ];
            let err = in_order(&attempts, |attempt| {
                ensure!(attempt.id != "b", "never entered");
                Ok(true)
            })
            .unwrap_err();
            assert_eq!(err.to_string(), "never entered");
        }
    }

    #[test]
    fn a_refusal_proves_its_session_got_in() {
        for (stderr, got_in) in [
            (b"".as_slice(), false),
            (b"sudo: a password is required\n".as_slice(), false),
            (b"agentic-job-sandbox-entered-not\n".as_slice(), false),
            (b"agentic-job-sandbox-entered\n".as_slice(), true),
            (
                b"Running as unit run-u1.service\nagentic-job-sandbox-entered\ncurl: (7) refused\n"
                    .as_slice(),
                true,
            ),
        ] {
            assert_eq!(entered(stderr), got_in, "{}", bounded_stderr(stderr));
        }
        // The script prints the line and then is the attempt, status and all.
        for (argv, status) in [
            (&["true"][..], Some(0)),
            (&["false"][..], Some(1)),
            (&["sh", "-c", "exit 7", "x y"][..], Some(7)),
        ] {
            let output = std::process::Command::new("sh")
                .args(["-c", ENTER_SCRIPT, ENTERED])
                .args(argv)
                .output()
                .unwrap();
            assert!(entered(&output.stderr), "{argv:?}");
            assert_eq!(output.status.code(), status, "{argv:?}");
        }
    }

    #[test]
    fn only_secure_hosts_check_spares_the_next_one_until_the_sandbox_is_entered() {
        use Mode::{Probe, Record, UnlessPassed};
        /// What the probes of a check come to: all pass, one fails, or
        /// they cannot be made.
        #[derive(Debug, Clone, Copy)]
        enum Probes {
            Pass,
            Fail,
            Err,
        }
        /// A step of the job: a check, or something starting the agent
        /// (`run`).
        #[derive(Debug, Clone, Copy)]
        enum Step {
            Check(Mode, Probes),
            Enter,
        }
        /// What a check did: took the record, or probed (`Err` when the
        /// probes could not be made).
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Did {
            Took,
            Probed,
            Err,
        }
        use Did::{Probed, Took};
        use Probes::{Fail, Pass};
        use Step::{Check, Enter};
        // (the binary named, the job's steps) -> what each check did.
        let cases: &[(bool, &[Step], &[Did])] = &[
            // secure-host's check spares run's.
            (
                true,
                &[Check(Record, Pass), Check(UnlessPassed, Fail)],
                &[Probed, Took],
            ),
            // Once: a second run probes.
            (
                true,
                &[
                    Check(Record, Pass),
                    Check(UnlessPassed, Pass),
                    Check(UnlessPassed, Pass),
                ],
                &[Probed, Took, Probed],
            ),
            // run's own check, passing, leaves nothing for the next run.
            (
                true,
                &[Check(UnlessPassed, Pass), Check(UnlessPassed, Fail)],
                &[Probed, Probed],
            ),
            (
                true,
                &[Check(Probe, Pass), Check(UnlessPassed, Fail)],
                &[Probed, Probed],
            ),
            // Entering the sandbox user, or another check, consumes it.
            (
                true,
                &[Check(Record, Pass), Enter, Check(UnlessPassed, Fail)],
                &[Probed, Probed],
            ),
            (
                true,
                &[
                    Check(Record, Pass),
                    Check(Probe, Pass),
                    Check(UnlessPassed, Fail),
                ],
                &[Probed, Probed, Probed],
            ),
            (
                true,
                &[
                    Check(Record, Pass),
                    Check(Record, Fail),
                    Check(UnlessPassed, Fail),
                ],
                &[Probed, Probed, Probed],
            ),
            (
                true,
                &[
                    Check(Record, Pass),
                    Check(Record, Probes::Err),
                    Check(UnlessPassed, Fail),
                ],
                &[Probed, Did::Err, Probed],
            ),
            // A failed check leaves none.
            (
                true,
                &[Check(Record, Fail), Check(UnlessPassed, Pass)],
                &[Probed, Probed],
            ),
            // Written anew after it was taken, it spares one more.
            (
                true,
                &[
                    Check(Record, Pass),
                    Check(UnlessPassed, Pass),
                    Enter,
                    Check(Record, Pass),
                    Check(UnlessPassed, Fail),
                ],
                &[Probed, Took, Probed, Took],
            ),
            // A binary that cannot be named leaves no record.
            (
                false,
                &[Check(Record, Pass), Check(UnlessPassed, Fail)],
                &[Probed, Probed],
            ),
        ];
        for &(named, steps, did) in cases {
            let case = format!("{named} {steps:?}");
            let dir = tempfile::tempdir().unwrap();
            let vars = [
                ("RUNNER_TEMP", dir.path().to_str().unwrap()),
                ("GITHUB_RUN_ID", "7"),
                ("GITHUB_RUN_ATTEMPT", "1"),
                ("GITHUB_JOB", "agent"),
            ];
            let env = |name: &str| {
                vars.iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            };
            let file = record::path(env).unwrap();
            let mut got = Vec::new();
            for &step in steps {
                let (mode, probes) = match step {
                    Enter => {
                        forget(env).unwrap();
                        continue;
                    }
                    Check(mode, probes) => (mode, probes),
                };
                let binary = || {
                    ensure!(named, "no executable");
                    Ok("0.1 ab".to_owned())
                };
                let record = job_record(binary, env, "a = 1\n").unwrap();
                assert_eq!(record.file, file, "{case}");
                let mut made = false;
                let result = once(mode, Some(&record), || {
                    made = true;
                    // The record is gone before any probe is made.
                    assert!(!file.exists(), "{case}");
                    match probes {
                        Pass => Ok(true),
                        Fail => Ok(false),
                        Probes::Err => anyhow::bail!("not made"),
                    }
                });
                got.push(match result {
                    Ok(Checked::Recorded(taken)) => {
                        assert_eq!(taken, file, "{case}");
                        assert!(!made, "{case}");
                        Took
                    }
                    Ok(Checked::Probed { passed }) => {
                        assert!(made && passed == matches!(probes, Pass), "{case}");
                        Probed
                    }
                    Err(_) => Did::Err,
                });
            }
            assert_eq!(got, did, "{case}");
        }
        // Outside a job there is no record to take, clear or leave.
        assert!(job_record(|| Ok("0.1 ab".to_owned()), |_| None, "").is_none());
        forget(|_| None).unwrap();
        assert_eq!(
            once(UnlessPassed, None, || Ok(true)).unwrap(),
            Checked::Probed { passed: true }
        );
    }

    #[test]
    fn the_flags_choose_what_a_check_does_with_the_record() {
        #[derive(clap::Parser)]
        struct Command {
            #[command(flatten)]
            args: Args,
        }
        use clap::Parser;
        for (flags, mode) in [
            (&[][..], Some(Mode::Probe)),
            (&["--record"][..], Some(Mode::Record)),
            (&["--unless-passed"][..], Some(Mode::UnlessPassed)),
            // Only secure-host's check writes a record, and it never takes one.
            (&["--record", "--unless-passed"][..], None),
        ] {
            let parsed =
                Command::try_parse_from(std::iter::once("check").chain(flags.iter().copied()));
            assert_eq!(
                parsed.ok().map(|command| command.args.mode()),
                mode,
                "{flags:?}"
            );
        }
    }

    #[test]
    fn canaries_differ() {
        let (a, b) = (canary().unwrap(), canary().unwrap());
        assert_ne!(a, b);
        assert_eq!(a.len(), "isolation-canary-".len() + 2 * CANARY_BYTES);
    }
}
