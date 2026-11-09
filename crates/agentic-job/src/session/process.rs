//! The agent's process: started with its standard streams on sockets, and
//! ended with everything it left behind.
//!
//! The session is not a sandbox. The agent is the caller's own user
//! (agentic-job#2989); the wrapper command of [`Launch`], which `run`
//! sets to `env -i`, keeps the caller's environment from it. Without a
//! wrapper the agent inherits that environment, which is only fit for
//! tests.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::fd::OwnedFd;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use rustix::process::{Pid, Signal, kill_process_group};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

/// How long a killed process gets to be gone.
const KILL_GRACE: Duration = Duration::from_secs(10);
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(2);
const DIAGNOSTIC_BYTES: u64 = 8192;
/// The state of a zombie in `/proc/PID/stat`.
const ZOMBIE: &str = "Z";
/// Variables of this process that nothing it starts may inherit: what
/// lets a process ask for the job's identity token and use the CI
/// system's own services (`ACTIONS_*`), and what selects an agent's
/// provider, credential and configuration, which come from the run's
/// configuration and nowhere else. The old tree's launchers cleared the
/// second kind. And the provider's key of `register = "api-key"`, an
/// MCP server's credential and a session's attach secret, which only
/// `run` holds.
const NOT_INHERITED: &[&str] = &[
    "ACTIONS_",
    crate::run::api_key::API_KEY_VAR,
    crate::run::mcp::TOKEN_VAR,
    crate::session::bridge::ATTACH_TOKEN_VAR,
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
    /// As the caller's own user, through a wrapper that clears its
    /// environment (`env -i`): the job is the unit of trust. Only the
    /// agent's process group is killed when the session ends: every
    /// process of the user would be the caller too.
    Own {
        /// The command that runs the agent's argv, such as `env -i HOME=... --`.
        wrapper: Vec<String>,
    },
}

impl Launch {
    pub(super) fn wrapper(&self) -> &[String] {
        match self {
            Self::Direct => &[],
            Self::Own { wrapper } => wrapper,
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
/// A wrapper such as `env -i` passes none of them on anyway; this holds
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
/// Its standard streams are sockets, not pipes, as they were for `run0
/// --pipe`, which handed them to PID 1 over D-Bus when the agent was a
/// second user; agents and their tests have relied on that since.
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
    pub fn diagnostics(&self) -> Diagnostics {
        Diagnostics { group: self.group }
    }

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

/// Process selectors copied before the agent is borrowed by the protocol driver.
pub(super) struct Diagnostics {
    group: Option<Pid>,
}

impl Diagnostics {
    /// Capture the launcher and its children. Bound both the diagnostic
    /// output and time before killing the session.
    pub async fn state(&self) -> String {
        let Some(group) = self.group else {
            return "agent process state: no process group".to_owned();
        };
        let mut command = Command::new("ps");
        let pid = group.as_raw_nonzero().to_string();
        command.args([
            "-o",
            "pid,ppid,stat,wchan:32,comm",
            "-p",
            &pid,
            "--ppid",
            &pid,
        ]);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let captured = async {
            let mut child = command.spawn()?;
            let stdout = child.stdout.take().context("ps has no stdout")?;
            let mut bytes = Vec::new();
            stdout
                .take(DIAGNOSTIC_BYTES)
                .read_to_end(&mut bytes)
                .await?;
            Ok::<_, anyhow::Error>(String::from_utf8_lossy(&bytes).into_owned())
        };
        match tokio::time::timeout(DIAGNOSTIC_TIMEOUT, captured).await {
            Ok(Ok(state)) => format!(
                "agent process state (pid {}):\n{state}",
                group.as_raw_nonzero()
            ),
            Ok(Err(error)) => format!("agent process state unavailable: {error:#}"),
            Err(_) => "agent process state unavailable: ps timed out".to_owned(),
        }
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

    /// The streams are sockets, and carry data both ways with the
    /// environment set.
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
            ("AGENTIC_JOB_MCP_TOKEN", true),
            ("AGENTIC_JOB_ATTACH_TOKEN", true),
            ("ANTHROPIC_MODEL", true),
            ("CLAUDE_CODE_USE_BEDROCK", true),
            ("OPENCODE_CONFIG", true),
            ("PATH", false),
            ("GITHUB_ACTIONS_", false),
            ("anthropic_api_key", false),
        ];
        // As `main` gives them to secure-host, whose commands then leave
        // out the same.
        crate::sandbox::host::also_not_inherited(is_inherited_setting);
        for (name, want) in cases {
            assert_eq!(is_inherited_setting(OsStr::new(name)), want, "{name}");
            assert_eq!(
                crate::sandbox::host::is_not_inherited(OsStr::new(name)),
                want,
                "{name}"
            );
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
}
