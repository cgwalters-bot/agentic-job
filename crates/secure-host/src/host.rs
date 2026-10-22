//! What `sandbox setup` and `sandbox check` both need of the host: who a
//! user is, whether a program is there and root's alone, and running one
//! with its failure turned into an error that names it.

use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail, ensure};

/// Bits that let anyone but the owner write.
const GROUP_OR_OTHER_WRITE: u32 = 0o022;

const OTHER_WRITE: u32 = 0o002;

/// Where programs are looked for. A fixed list and not the caller's `PATH`:
/// `sandbox setup` runs as root, and the same list is the sandbox user's
/// `PATH` (agentic-job's `sandbox::enter`).
pub const PATH_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin", "/bin"];

/// Root's programs, which the list above leaves out on some hosts.
pub const SBIN_DIRS: &[&str] = &["/usr/local/sbin", "/usr/sbin", "/sbin"];

/// The PATH of what root runs: both lists, and nothing of the caller's.
pub fn root_path() -> String {
    PATH_DIRS
        .iter()
        .chain(SBIN_DIRS)
        .copied()
        .collect::<Vec<_>>()
        .join(":")
}

/// A user, as `getent passwd` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

impl User {
    /// One line of passwd(5).
    fn parse(line: &str) -> Result<Self> {
        let fields: Vec<&str> = line.trim_end().split(':').collect();
        let [name, _, uid, gid, _, home, _] = fields[..] else {
            bail!("not a passwd line: {line:?}");
        };
        Ok(Self {
            name: name.to_owned(),
            uid: uid.parse().with_context(|| format!("uid of {name}"))?,
            gid: gid.parse().with_context(|| format!("gid of {name}"))?,
            home: PathBuf::from(home),
        })
    }

    /// The user named or numbered `key`, or `None` when there is none.
    ///
    /// Through `getent`, since the released binary is static and its own
    /// libc reads only `/etc/passwd`.
    pub fn lookup(key: &str) -> Result<Option<Self>> {
        // By its path on the fixed list, and root's alone: the helper
        // runs this as root. Setup calls this before it has made the
        // program directories root's, so an image whose getent is not
        // fails setup here, with the reason.
        let getent = trusted_program("getent")?;
        let output = bare(getent)
            .args(["passwd", "--", key])
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .context("running getent")?;
        if !output.status.success() {
            return Ok(None);
        }
        let text = String::from_utf8(output.stdout).context("getent passwd printed no text")?;
        let line = text.lines().next().unwrap_or_default();
        Self::parse(line).map(Some)
    }

    /// The user this process runs as.
    pub fn current() -> Result<Self> {
        let uid = rustix::process::getuid().as_raw();
        Self::lookup(&uid.to_string())?.with_context(|| format!("uid {uid} is not in passwd"))
    }
}

pub fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// The path of `program`, if the host has it.
pub fn find_program(program: &str) -> Option<PathBuf> {
    PATH_DIRS
        .iter()
        .chain(SBIN_DIRS)
        .map(|dir| Path::new(dir).join(program))
        .find(|path| path.is_file())
}

pub fn has_program(program: &str) -> bool {
    find_program(program).is_some()
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

/// A program root may run: found on the fixed PATH, and root's alone,
/// the file itself included (root may have put another owner's file in
/// a directory of its own).
pub fn trusted_program(name: &str) -> Result<PathBuf> {
    let path = find_program(name).with_context(|| format!("no {name} on this host"))?;
    roots_alone(&path)?;
    Ok(path)
}

fn describe(command: &Command) -> String {
    std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(OsStr::to_string_lossy)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Runs `command` to its end with no input; its standard error goes to ours.
pub fn output(command: &mut Command) -> Result<Output> {
    command
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("running {}", describe(command)))
}

/// Runs `command` and returns what it printed, trimmed; an error if it failed.
pub fn run(command: &mut Command) -> Result<String> {
    let output = output(command)?;
    ensure!(
        output.status.success(),
        "{} failed ({})",
        describe(command),
        output.status
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Whether `command` ran and succeeded, with nothing of it shown.
pub fn succeeds(command: &mut Command) -> bool {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Prefixes of the variables that no [`bare`] command inherits: what lets
/// a process use the CI system's own services and ask for the job's
/// identity token.
pub const NOT_INHERITED: &[&str] = &["ACTIONS_"];

/// What the program built on this crate adds to [`NOT_INHERITED`]; see
/// [`also_not_inherited`].
static ALSO_NOT_INHERITED: OnceLock<fn(&OsStr) -> bool> = OnceLock::new();

/// Has [`bare`] also leave out each variable for which IS_SETTING holds:
/// agentic-job's `main` gives it the agent's provider settings and
/// credentials (`session::process::is_inherited_setting`) before it runs
/// anything. Only the first call counts.
pub fn also_not_inherited(is_setting: fn(&OsStr) -> bool) {
    // A second call would be the same program's same list.
    let _ = ALSO_NOT_INHERITED.set(is_setting);
}

/// Whether the variable NAME is one that no [`bare`] command inherits.
pub fn is_not_inherited(name: &OsStr) -> bool {
    for prefix in NOT_INHERITED {
        if name.as_encoded_bytes().starts_with(prefix.as_bytes()) {
            return true;
        }
    }
    ALSO_NOT_INHERITED.get().is_some_and(|also| also(name))
}

/// PROGRAM as a command that gets none of this process's variables that
/// nothing it starts may inherit ([`is_not_inherited`]): the job's
/// identity-token request and `ACTIONS_*` among them. For what runs as
/// the runner's user or as root, which holds them already, so that a
/// command added later that does run as someone else starts without
/// them too.
pub fn bare(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    for (name, _) in std::env::vars_os() {
        if is_not_inherited(&name) {
            command.env_remove(name);
        }
    }
    command
}

/// `argv` as a command.
pub fn command<S: AsRef<OsStr>>(argv: &[S]) -> Result<Command> {
    let (program, args) = argv.split_first().context("an empty command")?;
    let mut command = Command::new(program);
    command.args(args);
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_lines() {
        let user = User::parse("agent:x:1001:1002:An agent,,,:/home/agent:/bin/bash\n").unwrap();
        assert_eq!(
            user,
            User {
                name: "agent".into(),
                uid: 1001,
                gid: 1002,
                home: "/home/agent".into()
            }
        );
        for bad in ["", "agent:x:1001", "agent:x:uid:1:,:/h:/bin/sh"] {
            assert!(User::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    /// The CI system's own variables, whatever a program adds.
    #[test]
    fn the_ci_systems_variables_are_not_inherited() {
        for (name, want) in [
            ("ACTIONS_ID_TOKEN_REQUEST_URL", true),
            ("ACTIONS_RUNTIME_TOKEN", true),
            ("PATH", false),
            ("GITHUB_ACTIONS", false),
        ] {
            assert_eq!(is_not_inherited(OsStr::new(name)), want, "{name}");
        }
    }
}
