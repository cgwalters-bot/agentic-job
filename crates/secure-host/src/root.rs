//! How the runner's user gets the few privileged operations a run needs:
//! reading the egress proxy's log, and the controls of some probes.
//!
//! On a machine `sandbox setup` has set up, the runner's user has no
//! sudo but for one rule, the `helper` command of the root-owned copy of
//! this program ([`helper`]); every operation goes through it, and the
//! helper decides what each means. On a machine setup never ran (the
//! tests, with a user made for them) the runner's user has sudo itself,
//! and the same operations are the commands sudo runs directly.

use std::path::Path;
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result, ensure};

use crate::config::ROOT_COPY;
use crate::egress::ACCESS_LOG;
use crate::helper::{self, Exec, SELF_COPY, ViaSudo};

/// Becomes root for an operation without ever asking for a password.
const SUDO: &[&str] = &["sudo", "-n", "--"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    /// Through the helper, the runner's one remaining sudo rule.
    Helper,
    /// Through sudo directly: a host where the runner's user has it.
    Sudo,
}

impl Root {
    /// The helper's `session-serve`, which only the helper runs.
    pub fn session_serve_command() -> Command {
        Self::helper_command::<&str>("session-serve", &[])
    }

    /// The helper where setup installed it and left the configuration it
    /// reads; sudo itself otherwise.
    pub fn detect() -> Self {
        if Path::new(SELF_COPY).is_file() && Path::new(ROOT_COPY).is_file() {
            Self::Helper
        } else {
            Self::Sudo
        }
    }

    /// A command for the helper's operation OP, with ARGS after it.
    fn helper_command<S: AsRef<std::ffi::OsStr>>(op: &str, args: &[S]) -> Command {
        let mut command = Command::new(SUDO[0]);
        command
            .args(&SUDO[1..])
            .arg(SELF_COPY)
            .arg(helper::COMMAND)
            .arg(op)
            .args(args);
        command
    }

    /// A command for ARGV as root, directly.
    fn sudo_command(argv: &[&str]) -> Result<Command> {
        ViaSudo.command(argv)
    }

    /// Whether root does anything at all for this user: the helper's
    /// rule, which the lock leaves the runner's user.
    pub fn ping(self) -> bool {
        let command = match self {
            Self::Helper => Some(Self::helper_command::<&str>("ping", &[])),
            Self::Sudo => Self::sudo_command(&["true"]).ok(),
        };
        command.is_some_and(|mut command| crate::host::succeeds(&mut command))
    }

    /// The size of the egress proxy's log, or `None` for none.
    pub fn egress_log_size(self) -> Result<Option<u64>> {
        match self {
            Self::Helper => {
                let out = Self::helper_command::<&str>("egress-log-size", &[])
                    .stdin(Stdio::null())
                    .output()
                    .context("running the helper")?;
                ensure!(
                    out.status.success(),
                    "reading the size of {ACCESS_LOG}: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                let text = String::from_utf8_lossy(&out.stdout);
                helper::parse_log_size(&text)
                    .with_context(|| format!("the helper printed {text:?} for the log's size"))
            }
            Self::Sudo => {
                let out = Self::sudo_command(&["stat", "-c", "%s", "--", ACCESS_LOG])?
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .output()
                    .context("running sudo")?;
                if !out.status.success() {
                    return Ok(None);
                }
                let text = String::from_utf8_lossy(&out.stdout);
                Ok(Some(text.trim().parse().with_context(|| {
                    format!("stat printed {text:?} for the size of {ACCESS_LOG}")
                })?))
            }
        }
    }

    /// A process that writes the egress proxy's log from byte FROM on to
    /// its standard output, which is piped. The caller reads what it
    /// wants of it and waits for it.
    pub fn egress_log(self, from: u64) -> Result<Child> {
        let mut command = match self {
            Self::Helper => Self::helper_command("egress-log", &["--from", &from.to_string()]),
            // tail counts from 1.
            Self::Sudo => Self::sudo_command(&[
                "tail",
                "-c",
                &format!("+{}", from.saturating_add(1)),
                "--",
                ACCESS_LOG,
            ])?,
        };
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .context("starting the log's reader")
    }

    /// `tailscale status --json`, as root; `None` where that fails.
    pub fn tailscale_status(self) -> Option<serde_json::Value> {
        let mut command = match self {
            Self::Helper => Self::helper_command::<&str>("tailscale-status", &[]),
            Self::Sudo => Self::sudo_command(&["tailscale", "status", "--json"]).ok()?,
        };
        let out = command
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| serde_json::from_slice(&out.stdout).ok())
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(command: &Command) -> Vec<String> {
        std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn the_helper_is_run_through_its_one_rule() {
        let command = Root::helper_command("egress-log", &["--from", "7"]);
        assert_eq!(
            argv(&command),
            [
                "sudo",
                "-n",
                "--",
                "/usr/local/libexec/agentic-job",
                "helper",
                "egress-log",
                "--from",
                "7"
            ]
        );
        let command = Root::sudo_command(&["true"]).unwrap();
        if !rustix::process::geteuid().is_root() {
            assert_eq!(argv(&command), ["sudo", "-n", "--", "true"]);
        }
        assert!(Root::sudo_command(&[]).is_err());
    }
}
