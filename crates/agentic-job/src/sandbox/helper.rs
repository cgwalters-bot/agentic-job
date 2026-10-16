//! `agentic-job helper`: the privileged operations a run still needs
//! once `sandbox setup` has taken root away from the runner's user, and
//! nothing else.
//!
//! After setup the runner's user has one sudo rule, for `helper` of the
//! root-owned copy of this program ([`super::setup::SELF_COPY`]). So this
//! is the whole of what that user can have root do, and it is kept
//! closed: no operation takes a path, a user or a command that root then
//! acts on. The sandbox user comes from the root-owned configuration;
//! `enter` runs the caller's command, but as that unprivileged user and
//! only in a directory under its home; the log read is of one fixed
//! file; every program root runs here is looked up on a fixed PATH and
//! must be root's alone, as must the configuration. The caller is taken
//! for hostile: a supervisor the agent got hold of must gain nothing
//! more than it has.
//!
//! The same operations are what the runner's user did with full sudo
//! before the lock existed, and still does on a host where setup never
//! ran (tests): [`super::root::Root`] chooses, and [`Exec`] lets the
//! sequence that stops the sandbox user run either way.

use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use super::egress;
use super::enter::{Entry, RUN0};
use super::host::{self, User};
use super::setup::SELF_COPY;
use crate::config::{self, Config};
use crate::exit::Exit;
use crate::sandbox::egress::ACCESS_LOG;

/// The command's name, as the sudo rule and the client spell it.
pub const COMMAND: &str = "helper";

/// What the sudo rule allows the runner's user: this program's root-owned
/// copy, its `helper` command, and whatever arguments follow.
pub fn sudoers_command() -> String {
    format!("{SELF_COPY} {COMMAND} *")
}

/// Bits that let anyone but the owner write.
const GROUP_OR_OTHER_WRITE: u32 = 0o022;

const OTHER_WRITE: u32 = 0o002;

/// How long one command that stops the sandbox user may take, how long a
/// probe's control may, and what ends either then.
const REAP_STEP_SECONDS: &str = "30";

const CONTROL_SECONDS: &str = "60";

const TIMEOUT_KILL_AFTER: &str = "--kill-after=5";

/// How often, and how many times, the sandbox user's processes are
/// looked for after they were killed: they do not vanish at once.
const SURVIVOR_POLL: Duration = Duration::from_millis(200);

const SURVIVOR_POLLS: u32 = 50;

/// What pgrep exits with when nothing matched.
const PGREP_NONE: i32 = 1;

/// What is printed for a log that is not there.
const NO_LOG: &str = "none";

#[derive(Debug, Subcommand)]
pub enum Op {
    /// Do nothing: proves the rule that lets the runner's user run this
    Ping,
    /// Run ARGV as the sandbox user, in a directory under its home
    Enter {
        #[arg(long, value_name = "DIR")]
        chdir: PathBuf,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Stop every process of the sandbox user, and make sure of it
    Reap,
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
    /// Run a command through pkexec, as root: a probe's control
    PkexecControl,
    /// Take away the sandbox user's lingering, after a probe enabled it
    DisableLinger,
    /// Remove the sandbox user's crontab, after a probe installed one
    CrontabRemove,
}

pub fn run(op: &Op) -> Result<Exit> {
    ensure!(host::is_root(), "`{COMMAND}` runs as root, through sudo");
    program_dirs_are_roots()?;
    let config = root_config()?;
    let entry = Entry::new(&config)?;
    let user = entry.user();
    let exec = Direct;
    match op {
        Op::Ping => Ok(Exit::Success),
        Op::Enter { chdir, argv } => enter(&entry, chdir, argv),
        Op::Reap => reap(user.uid, &exec).map(|()| Exit::Success),
        Op::EgressLogSize => {
            match open_log()? {
                Some(file) => println!("{}", file.metadata().context("reading the log")?.len()),
                None => println!("{NO_LOG}"),
            }
            Ok(Exit::Success)
        }
        Op::EgressLog { from } => {
            let Some(mut file) = open_log()? else {
                return Ok(Exit::Success);
            };
            file.seek(SeekFrom::Start(*from))
                .with_context(|| format!("reading {ACCESS_LOG}"))?;
            let mut out = std::io::stdout().lock();
            std::io::copy(&mut file, &mut out).context("writing the log")?;
            out.flush().context("writing the log")?;
            Ok(Exit::Success)
        }
        Op::TailscaleStatus => passthrough(&exec, &["tailscale", "status", "--json"]),
        Op::SessionServe => {
            ensure!(config.session.listen, "session serve needs session.listen");
            super::session::serve().map(|()| Exit::Success)
        }
        Op::PkexecControl => passthrough(&exec, &["pkexec", "true"]),
        Op::DisableLinger => passthrough(&exec, &["loginctl", "disable-linger", "--", &user.name]),
        Op::CrontabRemove => passthrough(&exec, &["crontab", "-r", "-u", &user.name]),
    }
}

/// Runs ARGV with our standard output and error, under a time limit, and
/// ends with its status.
fn passthrough(exec: &Direct, argv: &[&str]) -> Result<Exit> {
    let limited = limited(argv, CONTROL_SECONDS)?;
    let limited: Vec<&str> = limited.iter().map(String::as_str).collect();
    let mut command = exec.command(&limited)?;
    let status = command
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("running {}", argv.join(" ")))?;
    Ok(if status.success() {
        Exit::Success
    } else {
        Exit::Failure
    })
}

/// Becomes `run0` for ARGV as the sandbox user in CHDIR.
fn enter(entry: &Entry, chdir: &Path, argv: &[String]) -> Result<Exit> {
    check_chdir(chdir, entry.home())?;
    let run0 = entry.run0_argv(argv, chdir)?;
    let (program, args) = run0.split_first().context("an empty run0 command line")?;
    debug_assert_eq!(program, RUN0);
    let program = trusted_program(program)?;
    // Our standard streams are the caller's sockets, which run0 hands to
    // PID 1 as they are: exec, so that nothing stands between. With none
    // of the caller's environment: the bus address, for one, is where
    // run0 would send its request.
    let err = Command::new(&program)
        .args(args)
        .env_clear()
        .env("PATH", host::root_path())
        .exec();
    Err(err).with_context(|| format!("running {}", program.display()))
}

/// A directory the sandbox user's command may start in: its home, or an
/// absolute path under it spelled plainly, with no `.` or `..` and no
/// empty name in it. The directory itself is that user's to make or
/// not; the check is only that root changes into nothing else on the
/// caller's say-so.
fn check_chdir(dir: &Path, home: &Path) -> Result<()> {
    let text = dir.to_str().unwrap_or_default();
    let body = text
        .strip_suffix('/')
        .filter(|_| text.len() > 1)
        .unwrap_or(text);
    let plain = body.starts_with('/')
        && body
            .split('/')
            .skip(1)
            .all(|name| !name.is_empty() && name != "." && name != "..");
    ensure!(
        plain && Path::new(body).starts_with(home),
        "{} is not a directory under the sandbox user's home {}",
        dir.display(),
        home.display()
    );
    Ok(())
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
fn root_config() -> Result<Config> {
    let path = Path::new(config::ROOT_COPY);
    roots_alone(path)?;
    Config::load(path).context("`agentic-job sandbox setup` writes this file")
}

/// Whether META is of something owned by root that nobody but root (or
/// root's group) may write.
fn roots_only(meta: &std::fs::Metadata) -> bool {
    let mode = meta.mode();
    meta.uid() == 0
        && mode & OTHER_WRITE == 0
        && (mode & GROUP_OR_OTHER_WRITE == 0 || meta.gid() == 0)
}

/// Refuses PATH unless it and every directory above it are root's alone,
/// the links among them and what they lead to included. Anything else in
/// the way of a program root runs, or a file root reads, would let its
/// owner choose what root does.
pub fn roots_alone(path: &Path) -> Result<()> {
    let real =
        std::fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))?;
    let prefixes = path.ancestors().chain(real.ancestors());
    for prefix in prefixes {
        // A link's own mode is always 0777 and says nothing; its owner
        // chose where it points, and what it points to is checked next.
        let link = std::fs::symlink_metadata(prefix)
            .with_context(|| format!("reading {}", prefix.display()))?;
        ensure!(
            link.uid() == 0,
            "{} is owned by uid {}, not root, and root runs or reads {}",
            prefix.display(),
            link.uid(),
            path.display()
        );
        let meta =
            std::fs::metadata(prefix).with_context(|| format!("reading {}", prefix.display()))?;
        ensure!(
            roots_only(&meta),
            "{} is not root's alone (owner {}, group {}, mode {:o}), and root runs or reads {}",
            prefix.display(),
            meta.uid(),
            meta.gid(),
            meta.mode() & 0o7777,
            path.display()
        );
    }
    Ok(())
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

/// A program root may run: found on the fixed PATH, and root's alone,
/// the file itself included (root may have put another owner's file in
/// a directory of its own).
pub fn trusted_program(name: &str) -> Result<PathBuf> {
    let path = host::find_program(name).with_context(|| format!("no {name} on this host"))?;
    roots_alone(&path)?;
    Ok(path)
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

/// The login sessions of the user UID, the agent's among them.
fn sessions(uid: u32) -> Vec<String> {
    let Ok(loginctl) = trusted_program("loginctl") else {
        return Vec::new();
    };
    let listing = Command::new(loginctl)
        .args([
            "show-user",
            &uid.to_string(),
            "--property=Sessions",
            "--value",
        ])
        .stdin(Stdio::null())
        .output();
    match listing {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// The processes of the user UID that are still there, as pgrep lists
/// them; `None` for none. Any user may ask.
pub fn survivors(uid: u32) -> Result<Option<String>> {
    let pgrep = trusted_program("pgrep")?;
    let out = Command::new(pgrep)
        .args(["-l", "-u", &uid.to_string()])
        .stdin(Stdio::null())
        .output()
        .context("running pgrep")?;
    match out.status.code() {
        Some(0) => Ok(Some(
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        )),
        Some(PGREP_NONE) => Ok(None),
        _ => bail!(
            "pgrep -u {uid} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
}

/// Stops everything the user UID is running, as root through EXEC, and
/// makes sure of it.
///
/// Its sessions go first: a session scope holds every process started
/// in it, including ones that left their process group (setsid, double
/// forks). Then, as backstops, the user's slice (its service manager
/// and what that started), a manager it may have kept by enabling
/// lingering, and stray processes of its uid. Each step has a time
/// limit, and may fail (a session already gone, a user with no
/// manager): the survivor check is what counts. Root and this process's
/// own user are refused: the caller's checks come first, and this one
/// is the last.
pub fn reap(uid: u32, exec: &dyn Exec) -> Result<()> {
    ensure!(
        uid != 0 && uid != rustix::process::geteuid().as_raw() && uid != real_uid(),
        "refusing to stop every process of uid {uid}: root's or this process's own"
    );
    let uid_text = uid.to_string();
    let slice = format!("user-{uid}.slice");
    let manager = format!("user@{uid}.service");
    let step = |argv: &[&str]| {
        let limited = limited(argv, REAP_STEP_SECONDS).ok()?;
        let limited: Vec<&str> = limited.iter().map(String::as_str).collect();
        exec.output(&limited)
    };
    let sessions = sessions(uid);
    if !sessions.is_empty() {
        let ids: Vec<&str> = sessions.iter().map(String::as_str).collect();
        step(&[&["loginctl", "kill-session", "--signal=KILL"], &ids[..]].concat());
        step(&[&["loginctl", "terminate-session"], &ids[..]].concat());
    }
    step(&["systemctl", "kill", "--signal=KILL", &slice]);
    step(&["loginctl", "disable-linger", &uid_text]);
    step(&["loginctl", "terminate-user", &uid_text]);
    for _ in 0..SURVIVOR_POLLS {
        step(&["pkill", "-KILL", "-u", &uid_text]);
        if survivors(uid)?.is_none() {
            // Killed like that, the user's manager is left failed.
            step(&["systemctl", "reset-failed", &manager]);
            return Ok(());
        }
        std::thread::sleep(SURVIVOR_POLL);
    }
    bail!(
        "processes of uid {uid} survived the end of the session: {}",
        survivors(uid)?.unwrap_or_default()
    )
}

/// The uid of whoever asked for this, through sudo or not.
fn real_uid() -> u32 {
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse().ok())
        .unwrap_or_else(|| rustix::process::getuid().as_raw())
}

/// Whether DIR is one the sandbox user may be entered in.
pub fn chdir_allowed(dir: &Path, home: &Path) -> bool {
    check_chdir(dir, home).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directories_the_sandbox_user_may_start_in() {
        let home = Path::new("/home/agent");
        let cases = [
            ("/home/agent", true),
            ("/home/agent/work/repo", true),
            ("/home/agent/", true),
            ("/home/agent2", false),
            ("/home", false),
            ("/", false),
            ("/home/agent/../runner", false),
            ("/home/agent/./x", false),
            ("/home/agent//x", false),
            ("home/agent", false),
            ("/root", false),
        ];
        for (dir, want) in cases {
            assert_eq!(chdir_allowed(Path::new(dir), home), want, "{dir}");
        }
    }

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

    #[test]
    fn stopping_root_or_oneself_is_refused() {
        struct Never;
        impl Exec for Never {
            fn command(&self, _: &[&str]) -> Result<Command> {
                bail!("not to be run")
            }
        }
        assert!(reap(0, &Never).is_err());
        assert!(reap(rustix::process::geteuid().as_raw(), &Never).is_err());
    }
}
