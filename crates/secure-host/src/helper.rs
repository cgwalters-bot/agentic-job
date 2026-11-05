//! `agentic-job helper`: the privileged operations a run still needs
//! once `sandbox setup` has taken root away from the runner's user, and
//! nothing else.
//!
//! After setup the runner's user has one sudo rule, for `helper` of the
//! root-owned copy of this program ([`SELF_COPY`]). So this
//! is the whole of what that user can have root do, and it is kept
//! closed: no operation takes a path, a user or a command that root then
//! acts on. The log read is of one fixed file; every program root runs
//! here is looked up on a fixed PATH and must be root's alone, as must
//! the configuration. The caller is taken for hostile: the agent, the
//! runner's own user, must gain nothing more than it has. Since
//! agentic-job#2989 there is no second user, and no operation enters,
//! stops or cleans up after one.
//!
//! The same operations are what the runner's user did with full sudo
//! before the lock existed, and still does on a host where setup never
//! ran (tests): [`crate::root::Root`] chooses, and [`Exec`] runs a
//! command as root either way.
//!
//! What the program built on this crate adds, its own configuration
//! tables and `session-serve`, comes in through [`HostFile`], which
//! [`run`] reads root's copy of the configuration as.

use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::config::{HostFile, ROOT_COPY};
use crate::egress::{self, ACCESS_LOG};
use crate::host::{self, User};

pub use crate::host::{roots_alone, trusted_program};

/// Root's copy of this program, which the helper's sudo rule names. The
/// build it was made from is in the runner's home, which is closed.
pub const SELF_COPY: &str = "/usr/local/libexec/agentic-job";

/// The command's name, as the sudo rule and the client spell it.
pub const COMMAND: &str = "helper";

/// What the sudo rule allows the runner's user: this program's root-owned
/// copy, its `helper` command, and whatever arguments follow.
pub fn sudoers_command() -> String {
    format!("{SELF_COPY} {COMMAND} *")
}

/// How long a probe's control may take, and what ends it then.
const CONTROL_SECONDS: &str = "60";

const TIMEOUT_KILL_AFTER: &str = "--kill-after=5";

/// What is printed for a log that is not there.
const NO_LOG: &str = "none";

#[derive(Debug, Subcommand)]
pub enum Op {
    /// Do nothing: proves the rule that lets the runner's user run this
    Ping,
    /// Print the size of the egress proxy's log, or `none`
    EgressLogSize,
    /// Print the egress proxy's log from byte FROM on
    EgressLog {
        #[arg(long)]
        from: u64,
    },
    /// Print `tailscale status --json`
    TailscaleStatus,
    /// Hold the bridge listener and revoke serve when its supervisor leaves
    SessionServe,
}

/// Runs OP as root, with root's copy of the configuration read as F;
/// whether what it ran succeeded.
pub fn run<F: HostFile>(op: &Op) -> Result<bool> {
    ensure!(host::is_root(), "`{COMMAND}` runs as root, through sudo");
    program_dirs_are_roots()?;
    let config = root_config::<F>()?;
    // Checked as setup checked it.
    config.direct()?;
    let exec = Direct;
    match op {
        Op::Ping => Ok(true),
        Op::EgressLogSize => {
            match open_log()? {
                Some(file) => println!("{}", file.metadata().context("reading the log")?.len()),
                None => println!("{NO_LOG}"),
            }
            Ok(true)
        }
        Op::EgressLog { from } => {
            let Some(mut file) = open_log()? else {
                return Ok(true);
            };
            file.seek(SeekFrom::Start(*from))
                .with_context(|| format!("reading {ACCESS_LOG}"))?;
            let mut out = std::io::stdout().lock();
            std::io::copy(&mut file, &mut out).context("writing the log")?;
            out.flush().context("writing the log")?;
            Ok(true)
        }
        Op::TailscaleStatus => passthrough(&exec, &["tailscale", "status", "--json"]),
        // Root's own copy decides what serve accepts: the runner's user
        // passes no arguments here.
        Op::SessionServe => config.session_serve().map(|()| true),
    }
}

/// Runs ARGV with our standard output and error, under a time limit;
/// whether it succeeded.
fn passthrough(exec: &Direct, argv: &[&str]) -> Result<bool> {
    let limited = limited(argv, CONTROL_SECONDS)?;
    let limited: Vec<&str> = limited.iter().map(String::as_str).collect();
    let mut command = exec.command(&limited)?;
    let status = command
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("running {}", argv.join(" ")))?;
    Ok(status.success())
}

/// The egress proxy's log, open for reading, or `None` for none. Its
/// directory is the proxy's, so a link left there is not followed, and
/// what is opened must be a plain file of the proxy's: a proxy the
/// agent got hold of must not have root read anything else into the
/// transcript.
fn open_log() -> Result<Option<std::fs::File>> {
    let fd = match rustix::fs::open(
        ACCESS_LOG,
        // NONBLOCK: a FIFO left at the name would otherwise hold this
        // open until something wrote to it.
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => bail!("{ACCESS_LOG} is a link, which is not the proxy's log"),
        Err(err) => return Err(err).with_context(|| format!("opening {ACCESS_LOG}")),
    };
    let file = std::fs::File::from(fd);
    let meta = file
        .metadata()
        .with_context(|| format!("reading {ACCESS_LOG}"))?;
    let owner = User::lookup(egress::EGRESS_USER)?.map(|user| user.uid);
    ensure!(
        meta.is_file() && Some(meta.uid()) == owner,
        "{ACCESS_LOG} is not a plain file of {}'s (owner {}, mode {:o})",
        egress::EGRESS_USER,
        meta.uid(),
        meta.mode() & 0o7777
    );
    Ok(Some(file))
}

/// What the helper printed for a log's size.
pub fn parse_log_size(text: &str) -> Option<Option<u64>> {
    let text = text.trim();
    if text == NO_LOG {
        return Some(None);
    }
    text.parse().ok().map(Some)
}

/// The configuration setup left for root, if it is still root's alone.
fn root_config<F: HostFile>() -> Result<F> {
    let path = Path::new(ROOT_COPY);
    roots_alone(path)?;
    F::load(path).context("`agentic-job sandbox setup` writes this file")
}

/// Refuses unless every directory root looks programs up in is root's
/// alone: then whatever is found there is root's, placed before the
/// lock or by root since.
pub fn program_dirs_are_roots() -> Result<()> {
    host::PATH_DIRS
        .iter()
        .chain(host::SBIN_DIRS)
        .map(Path::new)
        .filter(|dir| dir.is_dir())
        .try_for_each(roots_alone)
}

/// ARGV with its program's full path, under a time limit of SECONDS:
/// what root runs is looked up once, here, on the fixed PATH, and never
/// again by the limiter through whatever PATH it has.
fn limited(argv: &[&str], seconds: &str) -> Result<Vec<String>> {
    let (program, args) = argv.split_first().context("an empty command")?;
    let program = trusted_program(program)?;
    Ok(["timeout", TIMEOUT_KILL_AFTER, seconds]
        .into_iter()
        .map(str::to_owned)
        .chain(std::iter::once(program.display().to_string()))
        .chain(args.iter().map(|&arg| arg.to_owned()))
        .collect())
}

/// Runs a command as root, however this process can.
pub trait Exec {
    /// A command for ARGV as root; an error if it cannot be made.
    fn command(&self, argv: &[&str]) -> Result<Command>;

    /// Runs ARGV as root to its end, with no input; `None` if it could
    /// not be run at all.
    fn output(&self, argv: &[&str]) -> Option<Output> {
        self.command(argv).ok()?.stdin(Stdio::null()).output().ok()
    }
}

/// As this process, which is root: each program by its trusted path.
pub struct Direct;

impl Exec for Direct {
    /// Nothing of the caller's environment reaches what root runs: the
    /// bus address, a loader's variables; only a PATH of root's own
    /// directories, for the program's own lookups.
    fn command(&self, argv: &[&str]) -> Result<Command> {
        let (program, args) = argv.split_first().context("an empty command")?;
        let mut command = Command::new(trusted_program(program)?);
        command
            .args(args)
            .env_clear()
            .env("PATH", host::root_path());
        Ok(command)
    }
}

/// Through sudo, on a host where the runner's user still has it; as it
/// is when this process is root already (setup, running the caller's
/// script). `-n`, so that a host that would ask for a password fails at
/// once.
pub struct ViaSudo;

impl Exec for ViaSudo {
    fn command(&self, argv: &[&str]) -> Result<Command> {
        let (program, args) = argv.split_first().context("an empty command")?;
        if host::is_root() {
            let mut command = Command::new(program);
            command.args(args);
            return Ok(command);
        }
        let mut command = Command::new("sudo");
        command.arg("-n").arg("--").args(argv);
        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_name_the_program_by_its_path() {
        let argv = limited(&["pgrep", "-u", "7"], "30").unwrap();
        assert_eq!(&argv[..3], ["timeout", "--kill-after=5", "30"]);
        assert!(
            argv[3].ends_with("/pgrep") && argv[3].starts_with('/'),
            "{argv:?}"
        );
        assert_eq!(&argv[4..], ["-u", "7"]);
        assert!(limited(&["no-such-program-agentic-job"], "1").is_err());
        assert!(limited(&[], "1").is_err());
    }

    #[test]
    fn log_sizes_as_printed() {
        assert_eq!(parse_log_size("none\n"), Some(None));
        assert_eq!(parse_log_size("1234\n"), Some(Some(1234)));
        assert_eq!(parse_log_size(""), None);
        assert_eq!(parse_log_size("-1"), None);
        assert_eq!(parse_log_size("12 34"), None);
    }

    #[test]
    fn the_sudo_rule_names_the_root_owned_copy() {
        assert_eq!(sudoers_command(), "/usr/local/libexec/agentic-job helper *");
    }

    #[test]
    fn roots_own_files_pass_and_a_users_do_not() {
        // /usr/bin is root's on every host this runs on, and /bin is a
        // link to it on most: a root-owned link passes, whatever its mode.
        roots_alone(Path::new("/usr/bin")).unwrap();
        roots_alone(Path::new("/bin/true")).unwrap();
        if std::fs::symlink_metadata("/bin").is_ok_and(|meta| meta.is_symlink()) {
            roots_alone(Path::new("/bin")).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("program");
        std::fs::write(&file, b"").unwrap();
        if rustix::process::geteuid().is_root() {
            return;
        }
        // The file is this user's, and so is the directory; whichever is
        // named, root would be running what is not root's.
        let err = roots_alone(&file).unwrap_err();
        assert!(format!("{err:#}").contains("not root"), "{err:#}");
    }
}
