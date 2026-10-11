//! What `run` does in the sandbox: one command at a time as the sandbox
//! user, through step 5's way in ([`crate::sandbox::enter`]), which
//! builds the `run0` command line with the variables `[sandbox] env` and
//! the egress proxy add.
//!
//! This adds what `run` needs on top: a limit on what a command may
//! write back, since the agent's files are read through it; the same
//! command line as a wrapper for the session, which appends the agent to
//! it; and commands that inherit none of the job's own settings.
//!
//! `run` reads and writes the agent's files only through this: as the
//! runner's user, a link the agent planted could make it read the
//! runner's files into an artifact.

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result, bail, ensure};

use crate::config::Config;
use crate::sandbox::enter::Entry;
use crate::sandbox::root::Root;
use crate::session::process::inherited_settings;

/// Stands for the command in a command line that is asked for only to
/// get what comes before it.
const PLACEHOLDER: &str = "agentic-job-command-placeholder";
/// How much of a command's standard error is kept, for an error message.
const MAX_STDERR_BYTES: u64 = 64 << 10;
/// The sandbox user, and the way in.
#[derive(Debug, Clone)]
pub struct Sandbox {
    pub user: String,
    pub home: PathBuf,
    entry: Entry,
}

/// What a command run in the sandbox left.
#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// Standard output as text, without the newline at its end.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim_end().to_owned()
    }

    /// The command's own words on why it failed, on one line.
    pub fn error(&self) -> String {
        let stderr = String::from_utf8_lossy(&self.stderr);
        format!("{}: {}", self.status, one_line(stderr.trim()))
    }
}

/// TEXT on one line and without control characters: what a repository or
/// the agent wrote must not act as a command to the CI system's log.
/// Both of the runner's command syntaxes are broken up: the runner only
/// reads them at the start of a line, but mid-line too, as defense in depth.
pub fn one_line(text: &str) -> String {
    crate::workflow_commands::escaped(
        &text
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect::<String>(),
    )
}

/// Runs one command at a time and gives back what it wrote: the way
/// `run` reads the agent's files and its checkout.
pub trait Runner {
    /// Runs ARGV with INPUT on its standard input; its standard output
    /// may be at most MAX_OUTPUT bytes.
    fn run(&self, argv: &[&str], input: &[u8], max_output: usize) -> Result<Output>;
}

impl Runner for Sandbox {
    fn run(&self, argv: &[&str], input: &[u8], max_output: usize) -> Result<Output> {
        Sandbox::run(self, argv, input, max_output)
    }
}

/// Runs commands as this process's own user. For tests of what `run`
/// does with a checkout: a run itself reads the agent's files only as
/// the sandbox user.
#[derive(Debug, Clone, Copy)]
pub struct Unconfined;

impl Runner for Unconfined {
    fn run(&self, argv: &[&str], input: &[u8], max_output: usize) -> Result<Output> {
        let argv: Vec<String> = argv.iter().map(|&arg| arg.to_owned()).collect();
        over_sockets(&argv, input, max_output)
    }
}

impl Sandbox {
    /// The sandbox user of CONFIG, which `sandbox setup` created. That
    /// it is not this process's own user is the session's to refuse
    /// (`session::process::SandboxUser`).
    pub fn new(config: &Config) -> Result<Self> {
        let entry = Entry::new(config)?;
        // As `sandbox exec`: after the agent, the next check probes.
        crate::sandbox::check::forget_passed()?;
        Ok(Self {
            user: entry.user().name.clone(),
            home: entry.home().to_owned(),
            entry,
        })
    }

    /// How root is had for what a run needs of it.
    pub fn root(&self) -> Root {
        self.entry.root()
    }

    /// The command line that runs what is appended to it as the sandbox
    /// user, in CWD: for the session, which appends the agent's own.
    pub fn wrapper(&self, cwd: &Path) -> Result<Vec<String>> {
        let command = self.entry.command(&[PLACEHOLDER.to_owned()], Some(cwd))?;
        let mut argv = std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(|arg| {
                arg.to_str()
                    .map(str::to_owned)
                    .context("the command line into the sandbox is not UTF-8")
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            argv.pop().as_deref() == Some(PLACEHOLDER),
            "the command line into the sandbox does not end in its command"
        );
        Ok(argv)
    }

    /// Runs ARGV as the sandbox user in its home, with INPUT on its
    /// standard input, and returns what it wrote, of which standard
    /// output may be at most MAX_OUTPUT bytes.
    pub fn run(&self, argv: &[&str], input: &[u8], max_output: usize) -> Result<Output> {
        let mut command = self.wrapper(&self.home)?;
        command.extend(argv.iter().map(|&arg| arg.to_owned()));
        let what = argv.first().copied().unwrap_or_default();
        over_sockets(&command, input, max_output)
            .with_context(|| format!("running {what} as {}", self.user))
    }

    /// As [`Sandbox::run`], and an error if the command fails.
    pub fn checked(&self, argv: &[&str], input: &[u8], max_output: usize) -> Result<Output> {
        let out = self.run(argv, input, max_output)?;
        ensure!(
            out.success(),
            "{} as {} failed ({})",
            argv.first().copied().unwrap_or_default(),
            self.user,
            out.error()
        );
        Ok(out)
    }
}

/// A command that gets none of this process's variables that nothing it
/// starts may inherit: the job's identity-token request among them.
/// Everything `run` starts is made with this, also what runs as the
/// runner's user or as root and holds those already.
pub fn command(program: &str) -> Command {
    let mut command = Command::new(program);
    for name in inherited_settings() {
        command.env_remove(name);
    }
    command
}

/// A connected pair: this process's end, and the one the child inherits.
fn socket_pair() -> std::io::Result<(UnixStream, OwnedFd)> {
    let (ours, theirs) = UnixStream::pair()?;
    Ok((ours, theirs.into()))
}

/// Runs ARGV with its standard streams on sockets, not pipes: `run0
/// --pipe` hands them to PID 1 over D-Bus, and under SELinux PID 1 may
/// not read a pipe made by a service such as a CI runner
/// (`session::process::spawn` has the same need).
fn over_sockets(argv: &[String], input: &[u8], max_output: usize) -> Result<Output> {
    let (program, args) = argv.split_first().context("the command is empty")?;
    let (mut stdin, child_stdin) = socket_pair()?;
    let (stdout, child_stdout) = socket_pair()?;
    let (mut stderr, child_stderr) = socket_pair()?;
    let mut child = {
        let mut command = command(program);
        command
            .args(args)
            .stdin(Stdio::from(child_stdin))
            .stdout(Stdio::from(child_stdout))
            .stderr(Stdio::from(child_stderr));
        // The command owns the child's ends until it is dropped, at the
        // end of this block: kept longer, reading would never end.
        command
            .spawn()
            .with_context(|| format!("starting {program}"))?
    };
    let limit = u64::try_from(max_output)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let (out, err) = std::thread::scope(|scope| {
        scope.spawn(move || {
            // A command that does not read its input closes it early.
            let _ = stdin.write_all(input);
        });
        let err = scope.spawn(move || {
            // The start of it is kept; the rest is read and dropped, so
            // that the command is never left waiting to write.
            let mut err = Vec::new();
            let _ = Read::by_ref(&mut stderr)
                .take(MAX_STDERR_BYTES)
                .read_to_end(&mut err);
            let _ = std::io::copy(&mut stderr, &mut std::io::sink());
            err
        });
        let mut out = Vec::new();
        let read = stdout.take(limit).read_to_end(&mut out);
        if out.len() > max_output {
            // Whatever writes this much is not waited for.
            let _ = child.kill();
        }
        (read.map(|_| out), err.join().unwrap_or_default())
    });
    let status = child.wait().context("waiting for the command")?;
    let stdout = out.context("reading the command's output")?;
    if stdout.len() > max_output {
        bail!("it wrote more than {max_output} bytes");
    }
    Ok(Output {
        status,
        stdout,
        stderr: err,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn commands_run_over_sockets() {
        let out = over_sockets(
            &argv(&[
                "sh",
                "-c",
                "test -S /dev/stdin && test -S /dev/stdout && cat && echo oops >&2 && exit 3",
            ]),
            b"hello",
            16,
        )
        .unwrap();
        assert_eq!(out.stdout, b"hello");
        assert_eq!(out.status.code(), Some(3));
        assert!(out.error().ends_with(": oops"), "{}", out.error());
        // Input nobody reads, and output past the cap.
        let out = over_sockets(&argv(&["true"]), &vec![b'x'; 1 << 20], 16).unwrap();
        assert!(out.success());
        let err = over_sockets(&argv(&["sh", "-c", "yes | head -c 100000"]), b"", 16).unwrap_err();
        assert!(format!("{err:#}").contains("more than 16 bytes"), "{err:#}");
        assert!(over_sockets(&[], b"", 16).is_err());
        // More standard error than is kept does not stall the command.
        let noisy = "head -c 300000 /dev/zero | tr '\\0' e >&2; echo done";
        let out = over_sockets(&argv(&["sh", "-c", noisy]), b"", 16).unwrap();
        assert_eq!(out.stdout, b"done\n");
        assert_eq!(u64::try_from(out.stderr.len()).unwrap(), MAX_STDERR_BYTES);
    }

    /// The session's wrapper is step 5's command line up to the command,
    /// with the directory it was asked for.
    #[test]
    fn the_wrapper_is_the_way_in_without_its_command() {
        let own = Command::new("id").arg("-un").output().unwrap();
        let own = String::from_utf8(own.stdout).unwrap();
        // Any user that exists will do: nothing is run.
        let Ok(config) = Config::parse(&format!("[sandbox]\nuser = \"{}\"\n", own.trim())) else {
            panic!("no configuration for {own}");
        };
        let Ok(sandbox) = Sandbox::new(&config) else {
            // A user this machine has no passwd line for, or root.
            return;
        };
        let wrapper = sandbox.wrapper(Path::new("/somewhere")).unwrap();
        assert_eq!(wrapper.last().map(String::as_str), Some("--"));
        // Through sudo and run0 where setup has not run, and through the
        // helper on a machine it locked, which a job's own tests may
        // well run on: the helper takes the user from root's file.
        let has = |args: &[&str]| wrapper.windows(args.len()).any(|window| window == args);
        match sandbox.root() {
            Root::Sudo => {
                assert!(has(&["run0"]), "{wrapper:?}");
                assert!(has(&["--chdir=/somewhere"]), "{wrapper:?}");
                let user = format!("--user={}", own.trim());
                assert!(has(&[user.as_str()]), "{wrapper:?}");
            }
            Root::Helper => assert!(
                has(&["helper", "enter", "--chdir", "/somewhere"]),
                "{wrapper:?}"
            ),
        }
        assert!(!wrapper.iter().any(|arg| arg == PLACEHOLDER), "{wrapper:?}");
    }

    #[test]
    fn log_lines_stay_one_line() {
        assert_eq!(one_line("a\nb\r::error::c\x1b[0m"), "a b : :error: :c [0m");
        // The form the runner acts on in the middle of a line.
        assert_eq!(
            one_line("x ##[error]y ##[group]"),
            "x ## [error]y ## [group]"
        );
    }
}
