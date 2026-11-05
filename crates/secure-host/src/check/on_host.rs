//! The probes of the host itself, as the runner's user, the agent's: the
//! world-write policy, the files any user could change, and the services
//! setup stopped.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use super::{Checker, Want};
use crate::setup;
use crate::{host, worker_diagnostics};

const PTRACE_SCOPE: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// The load states of a unit nothing can start: masked by setup, or not
/// on this machine.
const STOPPED_LOAD_STATES: &[&str] = &["masked", "not-found"];

/// A unit that is active on every host this runs on.
const ALWAYS_ACTIVE_UNIT: &str = "systemd-journald.service";

/// Whether this user can create `path`; what it made is removed again.
fn create_and_remove(path: &Path) -> Result<bool> {
    let created = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .is_ok();
    if created {
        std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(created)
}

impl Checker<'_> {
    /// The runner's user has root do something for it: everything after
    /// setup, through the helper; or sudo itself where the machine is not
    /// locked.
    pub(super) fn root_control(&mut self) {
        self.report.expect(
            Want::Succeed,
            "sudo-control",
            format!(
                "{} has root run a command for it through sudo (control)",
                self.runner.name
            ),
            self.root.ping(),
        );
    }

    /// What of the files any user could change or reach.
    pub(super) fn host_files(&mut self) {
        let scope = std::fs::read_to_string(PTRACE_SCOPE).unwrap_or_default();
        self.report.expect(
            Want::Succeed,
            "ptrace-scope",
            format!(
                "ptrace is restricted to descendants or more ({PTRACE_SCOPE} is {})",
                scope.trim()
            ),
            scope.trim().parse::<u32>().is_ok_and(|scope| scope >= 1),
        );
        if self.config.sandbox.unlink_worker_diagnostics() {
            // As the Worker's user, which every later step is: setup's
            // unlinking proved by no path left to connect to. A host with
            // no Worker has no such socket: a note, not a pass. Failing to
            // list processes is still a failure.
            let pids = worker_diagnostics::worker_pids();
            if let Some(why) = pids.as_deref().ok().and_then(worker_diagnostics::skipped) {
                self.report.note(&format!("worker-diagnostics: {why}"));
            } else {
                let linked = pids.and_then(|pids| worker_diagnostics::linked_sockets(&pids));
                let linked = match linked {
                    Ok(found) => found.iter().map(|p| p.display().to_string()).collect(),
                    Err(err) => vec![format!("{err:#}")],
                };
                self.report.expect(
                    Want::Fail,
                    "worker-diagnostics",
                    format!(
                        "no .NET diagnostic socket of {} is linked (sandbox.unlink-worker-diagnostics){}",
                        worker_diagnostics::WORKER_COMM,
                        if linked.is_empty() {
                            String::new()
                        } else {
                            format!(": {}", linked.join(", "))
                        }
                    ),
                    !linked.is_empty(),
                );
            }
        }

        // Any user could weaken what ssh and TLS accept host-wide. Setup
        // also takes group write off, which ssh refuses but is no one's.
        let writable = match setup::writable_crypto_policies(Path::new(setup::CRYPTO_POLICIES)) {
            Ok(found) => found
                .into_iter()
                .filter(|(_, mode)| mode & setup::OTHER_WRITE != 0)
                .map(|(path, mode)| format!("{} ({mode:o})", path.display()))
                .collect(),
            Err(err) => vec![format!("{err:#}")],
        };
        self.report.expect(
            Want::Fail,
            "crypto-policies",
            format!(
                "no file or directory under {} is world-writable{}",
                setup::CRYPTO_POLICIES,
                if writable.is_empty() {
                    String::new()
                } else {
                    format!(": {}", writable.join(", "))
                }
            ),
            !writable.is_empty(),
        );
    }

    /// The world-write policy, by what it does: ordinary permissions let
    /// any user create in the planted directory and append to the planted
    /// file, and the policy must refuse both to the runner's user, which
    /// owns neither. No denial log is read. The control is the same
    /// attempt in its own home.
    pub(super) fn runner_world_write(&mut self) -> Result<()> {
        let created = format!("{}/{}", setup::WORLD_WRITE_PROBE_DIR, self.canary);
        let home_writable = create_and_remove(&self.runner.home.join(&self.canary))?;
        self.report.expect(
            Want::Succeed,
            "runner-world-write-control",
            "runner can write its own home",
            home_writable,
        );
        let wrote = create_and_remove(Path::new(&created))?
            || std::fs::OpenOptions::new()
                .append(true)
                .open(setup::WORLD_WRITE_PROBE_FILE)
                .is_ok();
        self.report.expect(
            Want::Fail,
            "runner-world-write",
            format!(
                "runner can neither create in {} nor append to {}, root's and world-writable",
                setup::WORLD_WRITE_PROBE_DIR,
                setup::WORLD_WRITE_PROBE_FILE
            ),
            wrote,
        );
        Ok(())
    }

    /// The units the configuration says are stopped, are, and masked
    /// (or not on this machine), so that nothing starts them again.
    pub(super) fn services(&mut self) {
        let units = &self.config.sandbox.stop_services;
        if units.is_empty() {
            return;
        }
        let active = |unit: &str| {
            host::succeeds(Command::new("systemctl").args(["is-active", "--quiet", "--", unit]))
        };
        self.report.expect(
            Want::Succeed,
            "service-control",
            format!("{ALWAYS_ACTIVE_UNIT} is active (control)"),
            active(ALWAYS_ACTIVE_UNIT),
        );
        let startable = |unit: &str| {
            let state = Command::new("systemctl")
                .args(["show", "--property=LoadState", "--value", "--", unit])
                .stderr(Stdio::null())
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
                .unwrap_or_default();
            !STOPPED_LOAD_STATES.contains(&state.as_str())
        };
        for unit in units {
            self.report.expect(
                Want::Fail,
                &format!("service:{unit}"),
                format!("{unit} is not running, and is masked"),
                active(unit) || startable(unit),
            );
        }
    }
}
