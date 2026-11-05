//! `agentic-job sandbox check`: prove, as the runner's user, the only one
//! an agent runs as since agentic-job#2989, that the host's hardening
//! holds before an agent is started.
//!
//! Each probe is something the runner's user tries and must not manage,
//! and has a positive control where one can be had: the same attempt
//! somewhere it should work. Without the control, a probe that fails
//! because a program is missing reads as a protection that holds.
//!
//! The probes are a function, [`probes`], because the host test that
//! removes protections calls it. None of them is of the run token:
//! those are agentic-job's own (`run::probe`), made once the token is in
//! place. They read the host's tables of any [`HostFile`]; agentic-job's
//! `sandbox::check` maps the result to its exit states.
//! cgwalters-forge/actions's secure-host/docs/probes.md lists them all.
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

use crate::config::{self, Egress, HostFile, Sandbox};
use crate::host::{self, User};
use crate::root::Root;

pub mod confine;
mod net;
mod on_host;
mod record;
mod runner;

pub(crate) use net::metadata_request;
pub(crate) use runner::sudo_rules;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// When all probes pass, leave a record for the next check in this
    /// job (secure-host's check, for `run`'s)
    #[arg(long, conflicts_with = "unless_passed")]
    pub record: bool,
    /// Probe nothing when the record of a check with `--record` is there,
    /// against the same configuration, and no agent has run since; probe
    /// as usual when it is not
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

/// How many probes of a batch of independent ones run at once.
const CONCURRENT_PROBES: usize = 8;

const CANARY_BYTES: usize = 12;

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

/// `sandbox check`, with root's copy of the configuration read by
/// `parse`: whether the probes passed, now or as this job's record says.
pub fn run<F: HostFile>(args: &Args, parse: impl FnOnce(&str) -> Result<F>) -> Result<bool> {
    ensure!(
        !host::is_root(),
        "`sandbox check` runs as the runner's user, whose hardening it probes; it has root do the rest through the helper"
    );
    let path = Path::new(config::ROOT_COPY);
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))
        .context("setup (`secure-host setup`, `agentic-job sandbox setup`) writes this file")?;
    let config = parse(&text).with_context(|| format!("in {}", path.display()))?;
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
            true
        }
        Checked::Probed { passed } => passed,
    })
}

/// Removes this job's record of a passing check, if there is one: what
/// starts an agent (agentic-job's `run`) calls this first, since what the
/// agent leaves behind is what the next check has to probe.
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
/// passed. So a record means that secure-host's check passed and no agent
/// ran since, and it spares one check at most.
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

/// Probes the host `config` describes as the runner's user. `Err` is a
/// probe that could not be made at all; a probe that came out wrong is in
/// the report.
pub fn probes<F: HostFile>(config: &F) -> Result<Report> {
    // Checked as setup checked it.
    config.direct()?;
    let checker = Checker {
        config: Tables {
            sandbox: config.sandbox(),
            egress: config.egress(),
        },
        root: Root::detect(),
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

/// The tables of the configuration the probes read.
#[derive(Clone, Copy)]
struct Tables<'a> {
    sandbox: &'a Sandbox,
    egress: &'a Egress,
}

struct Checker<'a> {
    config: Tables<'a>,
    /// How root is had for the controls that need it.
    root: Root,
    runner: User,
    canary: String,
    report: Report,
}

impl Checker<'_> {
    fn run(mut self) -> Result<Report> {
        self.root_control();
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
        for key in self.config.sandbox.check.ignored() {
            self.report.note(&format!(
                "sandbox.check.{key} is ignored: only the removed sandbox user's probes read it (agentic-job#2989)"
            ));
        }
        self.timed("runner-files", |this| {
            this.runner_world_write()?;
            this.host_files();
            Ok(())
        })?;
        self.timed("services", |this| {
            this.services();
            Ok(())
        })?;
        if self.config.sandbox.deny_runner_metadata() {
            self.timed("runner-metadata", |this| this.runner_metadata())?;
        }
        if self.config.egress.write_policy {
            self.timed("write-policy", |this| this.runner_write_policy())?;
        }
        Ok(self.report)
    }

    fn timed<T>(&mut self, name: &str, run: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        crate::timed::stage("check", name, || run(self))
    }
}

/// Whether the runner's user, this process, succeeds at `argv`.
pub(crate) fn runner_reaches(argv: &[&str]) -> bool {
    host::command(argv)
        .map(|mut command| host::succeeds(&mut command))
        .unwrap_or(false)
}

/// What the runner's user, this process, prints running `argv`: empty
/// when it could not be run.
pub(crate) fn runner_stdout(argv: &[&str]) -> String {
    host::command(argv)
        .and_then(|mut command| Ok(command.stdin(std::process::Stdio::null()).output()?))
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    assert!(limit > 0, "a probe pool needs at least one worker");
    let next = &AtomicUsize::new(0);
    let run = &run;
    let mut results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..limit.min(items.len()))
            .map(|_| {
                scope.spawn(move || {
                    let mut made = Vec::new();
                    loop {
                        // Only the index is shared; each worker owns its results.
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(index) else {
                            break;
                        };
                        made.push((index, run(item)));
                    }
                    made
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect::<Vec<_>>()
    });
    results.sort_unstable_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn batches_keep_their_order_and_their_bound() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for (count, limit) in [(0, 8), (1, 1), (9, 1), (25, 7), (25, 8), (3, 8)] {
            let items: Vec<usize> = (0..count).collect();
            // An error in every possible position, plus the all-success case.
            for error in (0..count).map(Some).chain([None]) {
                let (running, most) = (AtomicUsize::new(0), AtomicUsize::new(0));
                let results = concurrently_bounded(&items, limit, |&item| {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    most.fetch_max(now, Ordering::SeqCst);
                    std::thread::yield_now();
                    running.fetch_sub(1, Ordering::SeqCst);
                    if error == Some(item) {
                        Err(item)
                    } else {
                        Ok(item * 2)
                    }
                });
                let expected: Vec<_> = items
                    .iter()
                    .map(|&item| {
                        if error == Some(item) {
                            Err(item)
                        } else {
                            Ok(item * 2)
                        }
                    })
                    .collect();
                assert_eq!(results, expected, "{count} {limit} {error:?}");
                assert_eq!(running.into_inner(), 0);
                assert!(most.into_inner() <= limit);
            }
        }
    }

    #[test]
    fn a_slow_item_does_not_hold_the_next_batch() {
        use std::sync::{Mutex, mpsc};
        for limit in [2, CONCURRENT_PROBES - 1, CONCURRENT_PROBES] {
            for slow in 0..limit {
                let (tx, rx) = mpsc::channel();
                let rx = Mutex::new(rx);
                let items: Vec<_> = (0..limit * 3).collect();
                let results = concurrently_bounded(&items, limit, |&item| {
                    if item == slow {
                        // A chunk barrier cannot start this later item until
                        // we finish. Bound the wait so that regression fails.
                        rx.lock()
                            .unwrap()
                            .recv_timeout(std::time::Duration::from_secs(5))
                            .unwrap();
                    } else if item == limit * 2 {
                        tx.send(()).unwrap();
                    }
                    item
                });
                assert_eq!(results, items);
            }
        }
    }

    #[test]
    fn only_secure_hosts_check_spares_the_next_one_until_an_agent_runs() {
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
            // Starting an agent, or another check, consumes it.
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
    fn a_host_that_is_no_github_runner_has_no_record() {
        // Whatever else a plain host sets, without RUNNER_TEMP there is no
        // record; with it but no run identity, a path to clear and nothing
        // to take or leave. Either way every check makes its probes.
        for (vars, file) in [
            (&[][..], false),
            (
                &[("HOME", "/root"), ("TMPDIR", "/tmp"), ("CI", "true")][..],
                false,
            ),
            (&[("RUNNER_TEMP", "/w/_temp"), ("CI", "true")][..], true),
        ] {
            let env = |name: &str| {
                vars.iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            };
            assert_eq!(record::path(env).is_some(), file, "{vars:?}");
            let record = job_record(|| Ok("0.1 ab".to_owned()), env, "");
            assert_eq!(record.is_some(), file, "{vars:?}");
            assert!(
                record.is_none_or(|record| record.content.is_none()),
                "{vars:?}"
            );
        }
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
