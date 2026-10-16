//! `agentic-job sandbox timed`: secure-host's setup or probes, timed, with
//! one line of the job summary saying how long each took and its stages.
//!
//! It runs as the runner's user, and only the two fixed commands below:
//! nothing of its caller's reaches their arguments, so it is no way to run
//! anything else, as root or not. The timing is informational and never
//! stands in for a passing probe; the command's exit status is this one's.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::Instant;

use anyhow::{Context, Result};
use regex::Regex;

use crate::exit::Exit;

/// The summary GitHub Actions shows for the step; unset or empty for none.
const SUMMARY: &str = "GITHUB_STEP_SUMMARY";
/// Where secure-host installs this program. Root's is called by this
/// path: sudo searches its own `secure_path`, which on RHEL leaves out
/// `/usr/local/bin`.
const INSTALLED: &str = "/usr/local/bin/agentic-job";
/// Where secure-host writes the configuration setup takes.
const RUNNER_TEMP: &str = "RUNNER_TEMP";
/// Longest output line that is still looked at for a stage's timing;
/// a longer one passes through and is not.
const MAX_LINE: usize = 1024;
/// Most bytes of stage lines kept for the summary; the latest are kept.
const MAX_STAGES: usize = 16 * 1024;

/// What `sandbox setup` prints for each of its stages (`timed_setup`).
/// ASCII digits only: a kept line is ASCII, so trimming cuts no character.
static STAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Sandbox setup stage ([a-z-]+): ([0-9]+\.[0-9]{3})s \((?:ok|failed)\)$")
        .expect("a valid pattern")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Label {
    /// `sudo /usr/local/bin/agentic-job sandbox setup` with secure-host's configuration
    Setup,
    /// `agentic-job sandbox check --record`
    Probes,
}

impl Label {
    fn name(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Probes => "probes",
        }
    }

    /// The fixed command, TEMP being the runner's `RUNNER_TEMP`.
    fn command(self, temp: Option<OsString>) -> Result<Command> {
        Ok(match self {
            Self::Setup => {
                let temp = temp
                    .filter(|value| !value.is_empty())
                    .with_context(|| format!("{RUNNER_TEMP} is not set"))?;
                let config = PathBuf::from(temp).join("secure-host/config.toml");
                let mut command = Command::new("sudo");
                command
                    .args([INSTALLED, "sandbox", "setup", "--config"])
                    .arg(config);
                command
            }
            Self::Probes => {
                let mut command = Command::new("agentic-job");
                command.args(["sandbox", "check", "--record"]);
                command
            }
        })
    }
}

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Which of secure-host's steps to run
    #[arg(value_enum)]
    pub label: Label,
}

pub fn run(args: &Args) -> Result<Exit> {
    let summary = std::env::var_os(SUMMARY)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let status = timed(
        args.label,
        args.label.command(std::env::var_os(RUNNER_TEMP))?,
        summary.as_deref(),
    );
    Ok(Exit::Command(status))
}

/// Runs COMMAND with its output passed through, and returns its exit
/// status: 1 where it could not start or a signal ended it.
fn timed(label: Label, mut command: Command, summary: Option<&std::path::Path>) -> u8 {
    let started = Instant::now();
    let (status, stages) = match passthrough(&mut command) {
        Ok(done) => done,
        Err(err) => {
            eprintln!("{err:#}");
            (1, String::new())
        }
    };
    let line = timing_line(label, started.elapsed().as_secs_f64(), status, &stages);
    eprint!("{line}");
    if let Some(path) = summary {
        let written = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .and_then(|mut file| file.write_all(line.as_bytes()));
        if let Err(err) = written {
            eprintln!("Cannot write secure-host timing summary: {err}");
        }
    }
    status
}

fn passthrough(command: &mut Command) -> Result<(u8, String)> {
    let mut child = command
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {command:?}"))?;
    let mut output = child.stdout.take().context("no stdout pipe")?;
    let mut stages = Stages::default();
    let mut out = io::stdout().lock();
    let mut buffer = [0; 8192];
    loop {
        let read = match output.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            // Still waited for: setup must not go on as root unseen.
            Err(err) => {
                eprintln!("reading the command's output: {err}");
                break;
            }
        };
        // A closed stdout must not stop the command or lose its status.
        let _ = out.write_all(&buffer[..read]).and_then(|()| out.flush());
        stages.feed(&buffer[..read]);
    }
    drop(output);
    let status = child.wait().context("waiting for the command")?;
    // A signal is not an exit status: 1.
    let code = status
        .code()
        .map_or(1, |code| u8::try_from(code).unwrap_or(1));
    Ok((code, stages.kept))
}

/// The stage lines of a command's output, bounded however much it prints.
#[derive(Default)]
struct Stages {
    line: Vec<u8>,
    overlong: bool,
    kept: String,
}

impl Stages {
    fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                if !self.overlong
                    && let Ok(line) = std::str::from_utf8(&self.line)
                    && STAGE.is_match(line)
                {
                    self.kept.push_str(line);
                    self.kept.push('\n');
                    if self.kept.len() > MAX_STAGES {
                        // Whole lines only: drop from the front up to a line's end.
                        let excess = self.kept.len() - MAX_STAGES;
                        let cut = self.kept[excess..]
                            .find('\n')
                            .map_or(self.kept.len(), |end| excess + end + 1);
                        self.kept.drain(..cut);
                    }
                }
                self.line.clear();
                self.overlong = false;
            } else if self.line.len() < MAX_LINE {
                self.line.push(byte);
            } else {
                self.overlong = true;
            }
        }
    }
}

/// The summary's line: the whole command's time and status, then each
/// stage's time, from STAGES alone so no other output reaches the summary.
fn timing_line(label: Label, seconds: f64, status: u8, stages: &str) -> String {
    let parts: Vec<String> = stages
        .lines()
        .filter_map(|line| STAGE.captures(line))
        .map(|stage| format!("{} {}s", &stage[1], &stage[2]))
        .collect();
    let stages = if parts.is_empty() {
        String::new()
    } else {
        format!("; {}", parts.join(", "))
    };
    format!(
        "Secure-host {}: {seconds:.3}s (exit {status}){stages}.\n",
        label.name()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(name: &str) -> String {
        format!("Sandbox setup stage {name}: 0.123s (ok)\n")
    }

    #[test]
    fn summary_has_only_timing_stages_including_failures() {
        let cases = [
            (
                Label::Setup,
                1.234,
                7,
                stage("packages")
                    + "untrusted **text**\nSandbox setup stage bad: NaNs (ok)\n"
                    + "Sandbox setup stage wide: \u{661}.\u{662}\u{663}\u{664}s (ok)\n"
                    + "Sandbox setup stage create-user: 0.456s (failed)\n",
                "Secure-host setup: 1.234s (exit 7); packages 0.123s, create-user 0.456s.\n",
            ),
            (
                Label::Probes,
                2.0,
                0,
                String::new(),
                "Secure-host probes: 2.000s (exit 0).\n",
            ),
        ];
        for (label, seconds, status, stages, expected) in cases {
            assert_eq!(timing_line(label, seconds, status, &stages), expected);
        }
    }

    #[test]
    fn the_commands_are_fixed() {
        fn argv(command: &Command) -> Vec<String> {
            std::iter::once(command.get_program())
                .chain(command.get_args())
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect()
        }
        let setup = Label::Setup.command(Some("/tmp/runner".into())).unwrap();
        assert_eq!(
            argv(&setup),
            [
                "sudo",
                "/usr/local/bin/agentic-job",
                "sandbox",
                "setup",
                "--config",
                "/tmp/runner/secure-host/config.toml"
            ]
        );
        for temp in [None, Some(OsString::new())] {
            assert!(Label::Setup.command(temp).is_err());
        }
        let probes = Label::Probes.command(None).unwrap();
        assert_eq!(
            argv(&probes),
            ["agentic-job", "sandbox", "check", "--record"]
        );
    }

    #[test]
    fn stage_lines_are_bounded_and_split_reads_are_joined() {
        let mut stages = Stages::default();
        let line = stage("packages");
        let (head, tail) = line.as_bytes().split_at(10);
        stages.feed(head);
        stages.feed(tail);
        assert_eq!(stages.kept, line);

        // An overlong line ending in a stage line's text is not one.
        let mut stages = Stages::default();
        stages.feed(&vec![b'x'; MAX_LINE * 2]);
        stages.feed(line.as_bytes());
        assert_eq!(stages.kept, "");
        stages.feed(line.as_bytes());
        assert_eq!(stages.kept, line);

        let mut stages = Stages::default();
        for _ in 0..(MAX_STAGES / line.len() + 10) {
            stages.feed(line.as_bytes());
        }
        assert!(stages.kept.len() <= MAX_STAGES);
        assert!(stages.kept.starts_with("Sandbox setup stage packages"));
        assert!(stages.kept.ends_with("(ok)\n"));
    }

    #[test]
    fn status_passes_through_and_the_summary_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let cases = [
            ("printf 'Sandbox setup stage packages: 0.123s (ok)\\n'", 0),
            ("exit 7", 7),
            ("kill -TERM $$", 1),
        ];
        for (script, status) in cases {
            let summary = dir.path().join(format!("summary-{status}"));
            let mut command = Command::new("sh");
            command.args(["-c", script]);
            assert_eq!(timed(Label::Setup, command, Some(&summary)), status);
            let text = std::fs::read_to_string(&summary).unwrap();
            assert!(
                Regex::new(&format!(
                    r"^Secure-host setup: \d+\.\d{{3}}s \(exit {status}\)"
                ))
                .unwrap()
                .is_match(&text),
                "{text}"
            );
            assert_eq!(text.contains("packages 0.123s"), status == 0, "{text}");
        }
        // A command that cannot start fails; a summary that cannot be
        // written does not change the status.
        let absent = dir.path().join("absent");
        assert_eq!(timed(Label::Probes, Command::new(&absent), None), 1);
        for (script, status) in [("exit 0", 0), ("exit 7", 7)] {
            let mut command = Command::new("sh");
            command.args(["-c", script]);
            let summary = absent.join("summary");
            assert_eq!(timed(Label::Setup, command, Some(&summary)), status);
        }
    }
}
