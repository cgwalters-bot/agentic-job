//! The agent's process: started with its standard streams on sockets, and
//! ended with everything it left behind.
//!
//! The session is not a sandbox. The only boundary between it and the
//! agent is the wrapper command of [`Launch`], which `run` sets to enter
//! the sandbox user's login session with `run0`. Without a wrapper the
//! agent runs as the caller's user and inherits its environment, which is
//! only fit for tests.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::fd::OwnedFd;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use rustix::process::{Pid, Signal, kill_process_group};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

use crate::sandbox::root::Root;

/// How long a killed process gets to be gone.
const KILL_GRACE: Duration = Duration::from_secs(10);
const ROOT_UID: u32 = 0;
/// The state of a zombie in `/proc/PID/stat`.
const ZOMBIE: &str = "Z";
/// Variables of this process that nothing it starts may inherit: what
/// lets a process ask for the job's identity token and use the CI
/// system's own services (`ACTIONS_*`), and what selects an agent's
/// provider, credential and configuration, which come from the run's
/// configuration and nowhere else. The old tree's launchers cleared the
/// second kind. And the provider's key of `register = "api-key"`, which
/// only `run` holds.
const NOT_INHERITED: &[&str] = &[
    "ACTIONS_",
    crate::run::api_key::API_KEY_VAR,
    "ANTHROPIC_",
    "CLAUDE_",
    "OPENCODE_",
    "VIBE_",
    "MISTRAL_",
];

/// Where the agent runs.
#[derive(Debug, Clone, Default)]
pub enum Launch {
    /// As the caller's user, with its environment: for tests.
    #[default]
    Direct,
    /// As another user, which a wrapper command switches to.
    Sandbox {
        /// The user the agent runs as. When the session ends, every
        /// process of this user is killed: a wrapper such as `run0`
        /// starts the agent in a session of its own, out of reach of a
        /// signal to the process group started here.
        user: String,
        /// The command that runs the agent's argv as that user, such as
        /// `sudo run0 --pipe --user=... --`.
        wrapper: Vec<String>,
    },
}

impl Launch {
    pub(super) fn wrapper(&self) -> &[String] {
        match self {
            Self::Direct => &[],
            Self::Sandbox { wrapper, .. } => wrapper,
        }
    }
}

/// Whether the variable NAME is one of [`NOT_INHERITED`].
pub fn is_inherited_setting(name: &OsStr) -> bool {
    NOT_INHERITED.iter().any(|prefix| {
        if *prefix == "VIBE_" {
            // Vibe's pydantic-settings environment layer is case-insensitive.
            name.as_encoded_bytes()
                .get(..prefix.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(prefix.as_bytes()))
        } else {
            name.as_encoded_bytes().starts_with(prefix.as_bytes())
        }
    })
}

/// The variables of this process that a command it starts must not get.
/// A wrapper such as `run0` passes none of them on anyway; this holds
/// for the wrapper itself, and for an agent started without one.
pub fn inherited_settings() -> impl Iterator<Item = OsString> {
    std::env::vars_os()
        .map(|(name, _)| name)
        .filter(|name| is_inherited_setting(name))
}

/// The session's ends of the agent's standard streams.
pub(super) struct Streams {
    pub stdin: UnixStream,
    pub stdout: UnixStream,
    pub stderr: UnixStream,
}

/// The process started for the agent: the wrapper, or the agent itself.
pub(super) struct Agent {
    child: Child,
    /// Its process group, which it leads.
    group: Option<Pid>,
}

/// A connected pair: the session's end, and the one the child inherits.
fn socket_pair() -> std::io::Result<(UnixStream, OwnedFd)> {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    ours.set_nonblocking(true)?;
    Ok((UnixStream::from_std(ours)?, theirs.into()))
}

/// Starts ARGV with ENV added to its environment, in a process group of
/// its own.
///
/// Its standard streams are sockets, not pipes: `run0 --pipe` hands them
/// to PID 1 over D-Bus, and under SELinux PID 1 may not read a pipe made
/// by a service such as a CI runner, so with pipes run0 fails with
/// "Connection reset by peer". The old tree put a Node script between
/// the two for this.
pub(super) fn spawn(argv: &[String], env: &BTreeMap<String, String>) -> Result<(Agent, Streams)> {
    let (program, args) = argv.split_first().context("the agent's command is empty")?;
    let (stdin, child_stdin) = socket_pair().context("creating a socket pair")?;
    let (stdout, child_stdout) = socket_pair().context("creating a socket pair")?;
    let (stderr, child_stderr) = socket_pair().context("creating a socket pair")?;
    // The command owns the child's ends until it is dropped, at the end
    // of this statement: kept longer, the session would never see the
    // agent close its streams.
    let mut command = Command::new(program);
    for name in inherited_settings() {
        command.env_remove(name);
    }
    // ENV after the removals: what the registry sets for the agent (its
    // model, for one) is the run's own and stays.
    let child = command
        .args(args)
        .envs(env)
        .stdin(Stdio::from(child_stdin))
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::from(child_stderr))
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting {program}"))?;
    let group = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw);
    Ok((
        Agent { child, group },
        Streams {
            stdin,
            stdout,
            stderr,
        },
    ))
}

impl Agent {
    /// Waits for the process to exit.
    pub async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait().await
    }

    /// Kills the process group, so that what a launcher started goes with
    /// it (`npx` and its `node`).
    ///
    /// The group's id is the process's, which is free again once the
    /// process was waited for and the group is empty: in theory another
    /// process could by now lead a group of that id. Every tool that
    /// kills by group lives with that window.
    pub fn kill_group(&mut self) {
        if let Some(group) = self.group {
            // An error means the group is gone already, or is root's (a
            // wrapper under sudo), which ends when the agent does.
            let _ = kill_process_group(group, Signal::KILL);
        }
        let _ = self.child.start_kill();
    }

    /// Waits for a killed process to be gone, for a while.
    pub async fn gone(mut self) {
        let _ = tokio::time::timeout(KILL_GRACE, self.child.wait()).await;
    }
}

/// The user the agent runs as, known to exist and to be safe to stop.
///
/// The session stops it when [`super::run`] returns. A caller that drops
/// that future, or is told to stop while it runs, stops the user itself
/// with [`SandboxUser::reap`].
pub struct SandboxUser {
    name: String,
    uid: u32,
    root: Root,
}

impl SandboxUser {
    /// Looks NAME up, and refuses a user whose processes must not all be
    /// killed: root, and the one this process runs as. ROOT is how the
    /// stopping, which is root's to do, is had.
    pub async fn find(name: &str, root: Root) -> Result<Self> {
        let uid: u32 = Command::new("id")
            .args(["-u", "--", name])
            .stdin(Stdio::null())
            .output()
            .await
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8_lossy(&out.stdout).trim().parse().ok())
            .with_context(|| format!("there is no sandbox user {name}"))?;
        let own = rustix::process::geteuid();
        ensure!(
            uid != ROOT_UID && uid != own.as_raw(),
            "{name} (uid {uid}) cannot be the sandbox user: the session ends by killing every \
             process of that user"
        );
        Ok(Self {
            name: name.to_owned(),
            uid,
            root,
        })
    }

    /// Stops everything the user is running, and makes sure of it: its
    /// sessions, its slice, a lingering manager, and stray processes of
    /// its uid (`sandbox::helper::reap` says how). By uid throughout, the one
    /// `find` checked: a name could come to mean another user between
    /// the check and the kill. On a thread: the sequence blocks on each
    /// command, and a signal here must not leave it half done.
    pub async fn reap(&self) -> Result<()> {
        let (uid, root, name) = (self.uid, self.root, self.name.clone());
        tokio::task::spawn_blocking(move || root.reap(uid))
            .await
            .context("stopping the sandbox user")?
            .with_context(|| format!("stopping {name}"))
    }
}

/// Whether process PID exists and is more than a zombie nobody has
/// collected yet. For tests of what a session leaves behind.
pub fn is_running(pid: u32) -> bool {
    // The state follows the command name, which is in parentheses and may
    // itself hold any character.
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let (_, after) = stat.rsplit_once(')')?;
            after.split_whitespace().next().map(|state| state != ZOMBIE)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// How often, and how many times, a killed process is looked for: it
    /// does not vanish at once.
    const SURVIVOR_POLL: Duration = Duration::from_millis(200);
    const SURVIVOR_POLLS: u32 = 50;

    fn sh(script: &str) -> Vec<String> {
        ["sh", "-c", script].map(str::to_owned).to_vec()
    }

    /// What run0 needs of the streams it is handed, and that they carry
    /// data both ways with the environment set.
    #[tokio::test]
    async fn streams_are_sockets() {
        let script = "test -S /dev/stdin && test -S /dev/stdout && test -S /dev/stderr \
                      && read line && echo \"$GREETING $line\" && echo oops >&2";
        let env = BTreeMap::from([("GREETING".to_owned(), "hello".to_owned())]);
        let (mut agent, mut streams) = spawn(&sh(script), &env).unwrap();
        streams.stdin.write_all(b"agent\n").await.unwrap();
        let (mut out, mut err) = (String::new(), String::new());
        streams.stdout.read_to_string(&mut out).await.unwrap();
        streams.stderr.read_to_string(&mut err).await.unwrap();
        assert_eq!((out.as_str(), err.as_str()), ("hello agent\n", "oops\n"));
        assert!(agent.wait().await.unwrap().success());
    }

    #[test]
    fn settings_that_are_not_inherited() {
        let cases = [
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", true),
            ("ACTIONS_RUNTIME_TOKEN", true),
            ("ANTHROPIC_API_KEY", true),
            ("AGENTIC_JOB_INFERENCE_KEY", true),
            ("ANTHROPIC_MODEL", true),
            ("CLAUDE_CODE_USE_BEDROCK", true),
            ("OPENCODE_CONFIG", true),
            ("PATH", false),
            ("GITHUB_ACTIONS_", false),
            ("anthropic_api_key", false),
        ];
        for (name, want) in cases {
            assert_eq!(is_inherited_setting(OsStr::new(name)), want, "{name}");
        }
    }

    /// A process the agent leaves in its group goes with it.
    #[tokio::test]
    async fn kill_takes_the_group() {
        let (mut agent, mut streams) =
            spawn(&sh("sleep 600 & echo $!; wait"), &BTreeMap::new()).unwrap();
        let mut pid = String::new();
        let mut byte = [0u8; 1];
        while streams.stdout.read_exact(&mut byte).await.is_ok() && byte[0] != b'\n' {
            pid.push(char::from(byte[0]));
        }
        let pid: u32 = pid.parse().unwrap();
        assert!(is_running(pid), "no process {pid}");
        agent.kill_group();
        agent.gone().await;
        // The group is killed at once, but a signal takes a moment.
        for _ in 0..SURVIVOR_POLLS {
            if !is_running(pid) {
                return;
            }
            tokio::time::sleep(SURVIVOR_POLL).await;
        }
        panic!("process {pid} survived");
    }

    #[test]
    fn an_empty_command_is_refused() {
        assert!(spawn(&[], &BTreeMap::new()).is_err());
    }

    /// Killing every process of the sandbox user must never mean this
    /// one's, or root's.
    #[tokio::test]
    async fn sandbox_users_that_are_refused() {
        let own = std::process::Command::new("id")
            .arg("-un")
            .output()
            .unwrap();
        let own = String::from_utf8(own.stdout).unwrap();
        let cases = [
            ("no-such-user-agentic-job", "no sandbox user"),
            ("--help", "no sandbox user"),
            ("root", "cannot be the sandbox user"),
            (own.trim(), "cannot be the sandbox user"),
        ];
        for (name, want) in cases {
            let Err(err) = SandboxUser::find(name, Root::Sudo).await else {
                panic!("{name} was taken as a sandbox user");
            };
            assert!(format!("{err:#}").contains(want), "{name}: {err:#}");
        }
    }
}
