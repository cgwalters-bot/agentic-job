//! `agentic-job sandbox`: make the host safe for the agent, and prove it.
//! Step 5 of docs/plan.md. `setup` runs as root, and ends by taking root
//! away from the runner's user, the only one an agent runs as; `check`
//! probes as that user, with the one privileged command it keeps
//! ([`helper`], via [`root`]) for what needs root.

use std::path::Path;

use anyhow::{Context, Result, ensure};
use clap::Subcommand;

use crate::config::{Config, Egress, HostFile, Sandbox};
use crate::exit::Exit;

pub mod preflight;
pub(crate) mod session;
pub mod setup;

// What secure-host holds already, at the paths callers know.
pub use ::secure_host::{egress, enter, host, network, proxy, root, worker_diagnostics};

/// secure-host's probes, with `run` reading root's copy of the
/// configuration as agentic-job's.
pub mod check {
    pub use ::secure_host::check::*;

    use anyhow::Result;

    use crate::config::Config;
    use crate::exit::Exit;

    /// In place of the glob's `run`, which returns what they came to, as
    /// an exit state ([`exit`]).
    pub fn run(args: &Args) -> Result<Exit> {
        Ok(exit(::secure_host::check::run(args, Config::parse)?))
    }

    /// The exit state of a check that came to `verdict`: a check that
    /// failed only to reach outside the host is the retryable
    /// [`Exit::NotStarted`], as the run it stood before never started;
    /// the run action names it `control_unreachable`, and the agent does
    /// not start after either failure.
    pub fn exit(verdict: Verdict) -> Exit {
        match verdict {
            Verdict::Passed => Exit::Success,
            Verdict::Failed => Exit::Failure,
            Verdict::Unreachable => Exit::NotStarted,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The states the run action branches on: 4 is the check's own
        /// word for an outside host out of reach, and any other failure
        /// is 1, a hardening failure beside the control included.
        #[test]
        fn an_unreachable_control_is_the_retryable_state() {
            let cases = [
                (Verdict::Passed, 0),
                (Verdict::Failed, 1),
                (Verdict::Unreachable, 4),
            ];
            for (verdict, code) in cases {
                assert_eq!(exit(verdict).code(), code, "{verdict:?}");
            }
        }
    }
}

/// secure-host's runner confinement probes, with agentic-job's configuration
/// and exit states, like `check`.
pub mod probe {
    pub use ::secure_host::check::confine::*;

    use anyhow::Result;

    use crate::exit::Exit;

    pub fn run(args: &Args) -> Result<Exit> {
        Ok(if ::secure_host::check::confine::run(args)? {
            Exit::Success
        } else {
            Exit::Failure
        })
    }
}

/// secure-host's timed setup and probes, its status an exit state.
pub mod timed {
    pub use ::secure_host::timed::*;

    use anyhow::Result;

    use crate::exit::Exit;

    pub fn run(args: &Args) -> Result<Exit> {
        ::secure_host::timed::run(args).map(Exit::Command)
    }
}

/// secure-host's helper, with `run` reading root's copy of the
/// configuration as agentic-job's.
pub mod helper {
    pub use ::secure_host::helper::*;

    use anyhow::Result;

    use crate::config::Config;
    use crate::exit::Exit;

    pub fn run(op: &Op) -> Result<Exit> {
        Ok(if ::secure_host::helper::run::<Config>(op)? {
            Exit::Success
        } else {
            Exit::Failure
        })
    }
}

/// What agentic-job's file adds for the helper: its run tables, checked
/// with the rest, and the session bridge's `session-serve`.
impl HostFile for Config {
    fn load(path: &Path) -> Result<Self> {
        Config::load(path)
    }

    fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    fn egress(&self) -> &Egress {
        &self.egress
    }

    fn direct(&self) -> Result<Vec<network::Direct>> {
        Ok(self.check_host()?.direct)
    }

    /// Checked as `run` checks it.
    fn session_serve(&self) -> Result<()> {
        let listen = crate::session::bridge::Listen::from_config(&self.session)?
            .context("session serve needs session.listen")?;
        ensure!(
            listen.on_tailnet(),
            "session serve is for the tailnet: session.bind is reached without it"
        );
        session::serve(listen.capability.as_deref())
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Harden the runner's user, the agent's, closing its routes to credentials and root
    Setup(setup::Args),
    /// As root, before the secure-host image: install the agents, their managed settings and this binary as the helper
    Prepare(setup::PrepareArgs),
    /// Probe the runner's user's hardening, each probe with a positive control where one can be had
    Check(check::Args),
    /// As the runner's user, before the run: prove the KVM, libvirt session and resources `[preflight]` asks for
    Preflight(preflight::Args),
    /// Run secure-host's setup or probes, and add their time to the job summary
    #[command(hide = true)]
    Timed(timed::Args),
    /// Probe, as the runner's user, the routes a step has before and after the lock; CI's `confined` job runs it
    #[command(hide = true)]
    Probe(probe::Args),
    /// Run the egress proxy; `setup` starts it as its own user unless `egress.rust-proxy = false`
    #[command(hide = true)]
    EgressProxy(proxy::Args),
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::Setup(args) => setup::run(args),
            Self::Prepare(args) => setup::prepare(args),
            Self::Check(args) => check::run(args),
            Self::Preflight(args) => preflight::run(args),
            Self::Timed(args) => timed::run(args),
            Self::Probe(args) => probe::run(args),
            Self::EgressProxy(args) => proxy::run(args).map(|()| Exit::Success),
        }
    }
}
