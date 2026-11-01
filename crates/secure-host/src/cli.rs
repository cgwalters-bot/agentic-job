//! The `secure-host` binary's command line: the steps that secure a
//! host, its configuration and its probes, for any job, with nothing
//! that runs an agent. Each step refuses as the script it replaced did:
//! one message, exit status 1.
//!
//! The hidden commands are what the host calls the binary for once it is
//! set up: the helper's sudo rule, the egress proxy's unit and the
//! probes as the sandbox user. So that the binary can stand in for
//! agentic-job by that name, for one release ([`crate::image`]), `config`
//! takes `--host` and `sandbox` has the probes; those are what the
//! pinned cgwalters-forge/actions/secure-host and agentic-job's actions
//! call it for.

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::config::Host;
use crate::{apt, check, compose, helper, image, local, platform, proxy, setup, world_write};

/// The binary's name, as its image and host know it.
pub const NAME: &str = "secure-host";

#[derive(Debug, Parser)]
#[command(
    name = NAME,
    version,
    about = "Secure a CI host for untrusted steps, and prove it",
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Refuse a host that is not Ubuntu 26.04, RHEL 10 or CentOS Stream 10, by /etc/os-release
    Supported,
    /// As root: bound apt's network waits and keep it off the Azure mirror
    Apt,
    /// As root: load the world-write policy OBJECT through bpftool, and prove it took effect
    WorldWrite(WorldWrite),
    /// As root: create the sandbox user and close its routes to credentials and root
    Setup {
        /// The host's configuration (TOML); copied to /etc/agentic-job/
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// Run the egress proxy from this podman image ID, in root podman:
        /// the image's entrypoint passes its own
        #[arg(long, value_name = "ID")]
        egress_image: Option<String>,
    },
    /// Probe, as the runner's user, the host setup secured
    Check(check::Args),
    /// Probe, as the runner's user, the routes a step has before and after the lock; CI's `confined` job runs it
    #[command(hide = true)]
    Probe(check::confine::Args),
    /// Write a host's configuration from a file and settings given one at a time
    Config(compose::Args),
    /// The image's entrypoint: install this binary on the host mounted at
    /// /host and set the host up through its `nsenter -t 1`
    Image {
        /// The configuration `config` wrote, a path on the host
        config: PathBuf,
    },
    /// The privileged operations the runner's user keeps after setup, run as root through its one sudo rule
    #[command(name = helper::COMMAND, hide = true, subcommand)]
    Helper(helper::Op),
    #[command(hide = true, subcommand)]
    Sandbox(Sandbox),
}

/// The probes and the proxy by agentic-job's `sandbox` names, which the
/// host's units, the probes and the pinned action use.
#[derive(Debug, Subcommand)]
pub enum Sandbox {
    /// `check`, by its old name
    Check(check::Args),
    /// `probe`, by its old name
    Probe(check::confine::Args),
    /// Print the local sockets and ports this user connects to; `check` runs it as the sandbox user
    ProbeLocal,
    /// Run the egress proxy; `setup` starts it as its own user unless `egress.rust-proxy = false`
    EgressProxy(proxy::Args),
}

/// `world-write`'s arguments, which agentic-job's `secure-host` takes too.
#[derive(Debug, clap::Args)]
pub struct WorldWrite {
    /// The policy object, `world_write.bpf.o`, that came with this binary
    pub object: PathBuf,
    /// Also refuse a read (`/proc/PID/environ`) by a process of the runner's
    /// user of another of its processes that is not its descendant; the
    /// Runner.Worker this command runs under is exempt
    #[arg(long)]
    pub deny_runner_reads: bool,
    /// Exempt the one Runner.Worker on the host, not an ancestor: for a
    /// loader the Worker did not start, such as the image's
    #[arg(long, requires = "deny_runner_reads")]
    pub sole_worker: bool,
}

/// `supported`: whether the host is one setup supports, saying why not.
pub fn supported() -> bool {
    let supported = platform::supported_file(Path::new(platform::OS_RELEASE));
    if !supported {
        eprintln!("{}", platform::REFUSAL);
    }
    supported
}

/// `apt`: whether apt is configured, saying why not.
pub fn apt() -> bool {
    apt::configure(Path::new(apt::APT))
        .inspect_err(|err| eprintln!("configuring apt for CI: {err:#}"))
        .is_ok()
}

impl WorldWrite {
    /// Whether the policy is loaded, saying why not.
    pub fn run(&self) -> bool {
        match world_write::load(&self.object, self.deny_runner_reads, self.sole_worker) {
            Ok(()) => true,
            Err(err) => {
                world_write::report_refusal(&err, &mut world_write::run_command, &mut |line| {
                    eprintln!("{line}")
                });
                false
            }
        }
    }
}

impl Command {
    /// Whether the command succeeded; `Err` is one that could not run.
    pub fn run(&self) -> Result<bool> {
        match self {
            Self::Supported => Ok(supported()),
            Self::Apt => Ok(apt()),
            Self::WorldWrite(args) => Ok(args.run()),
            Self::Setup {
                config,
                egress_image,
            } => setup::run_host(config, egress_image.as_deref()).map(|()| true),
            Self::Check(args) | Self::Sandbox(Sandbox::Check(args)) => {
                check::run(args, Host::parse)
            }
            Self::Config(args) => compose::run(args).map(|()| true),
            Self::Image { config } => Ok(image::run(config)
                .inspect_err(|err| eprintln!("secure-host image: {err:#}"))
                .is_ok()),
            Self::Helper(op) => helper::run::<Host>(op),
            Self::Probe(args) | Self::Sandbox(Sandbox::Probe(args)) => {
                check::confine::run::<Host>(args)
            }
            Self::Sandbox(Sandbox::ProbeLocal) => local::run().map(|()| true),
            Self::Sandbox(Sandbox::EgressProxy(args)) => proxy::run(args).map(|()| true),
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    fn parses(args: &[&str]) -> bool {
        Cli::try_parse_from([NAME].iter().chain(args)).is_ok()
    }

    #[test]
    fn the_commands_parse() {
        Cli::command().debug_assert();
        let lines: &[&[&str]] = &[
            &["supported"],
            &["apt"],
            &["world-write", "/tmp/bin/world_write.bpf.o"],
            &[
                "world-write",
                "/tmp/bin/world_write.bpf.o",
                "--deny-runner-reads",
                "--sole-worker",
            ],
            &["setup", "--config", "secure-host/hosted.toml"],
            &["setup", "--config", "/c.toml", "--egress-image", "0"],
            &["check"],
            &["check", "--record"],
            &["config", "--from", "secure-host/hosted.toml"],
            &["image", "/tmp/secure-host/config.toml"],
            &["helper", "ping"],
            &["helper", "session-serve"],
            // CI's confined job, and its JavaScript probe's steps.
            &["probe", "control", "before"],
            &["probe", "confined", "run-step"],
            &["probe", "sandbox-user", "sandbox-user"],
            &["probe", "confined", "main"],
            &["probe", "confined", "post"],
        ];
        for args in lines {
            assert!(parses(args), "{args:?}");
        }
        for bad in [
            &[][..],
            &["setup"],
            &["world-write", "/tmp/bin/world_write.bpf.o", "--sole-worker"],
            &["inference", "/tmp/secure-host/config.toml"],
            &["run", "--policy", "p.json"],
            &["sandbox", "setup", "--config", "c.toml"],
            &["sandbox", "exec", "--", "true"],
            &["secure-host", "apt"],
        ] {
            assert!(!parses(bad), "{bad:?} parsed");
        }
    }

    /// What the pinned action, agentic-job's actions, CI and the host
    /// call the binary for by agentic-job's name, which the image and
    /// the host give it for one release.
    #[test]
    fn it_answers_what_agentic_job_was_called_for() {
        for args in [
            // cgwalters-forge/actions/secure-host: config.mjs and "Prove it".
            &[
                "config",
                "--host",
                "--from",
                "/in/config.toml",
                "--string",
                "sandbox.runner-user=runner",
                "--boolean",
                "egress.write-policy=false",
            ][..],
            &["sandbox", "check"],
            // The run action, and CI's confined job.
            &["sandbox", "check", "--unless-passed"],
            &["sandbox", "check", "--record"],
            &["sandbox", "probe", "control", "before"],
            &["sandbox", "probe", "confined", "run-step"],
            // `sandbox check`, as the sandbox user.
            &["sandbox", "probe-local"],
        ] {
            assert!(parses(args), "{args:?}");
        }
    }

    /// The proxy setup starts is this binary's, with every option it may
    /// be given, from the host's copy and from the image.
    #[test]
    fn the_egress_proxy_command_line_parses() {
        let refused = [("fd7a:115c:a1e0::1".to_owned(), 443)];
        for (transparent, refused) in [(false, &[][..]), (true, &[][..]), (false, &refused[..])] {
            for binary in [setup::PROXY.host, setup::PROXY.image] {
                let args = crate::egress::rust_proxy_args(
                    binary,
                    setup::PROXY.command,
                    true,
                    transparent,
                    refused,
                );
                let parsed = Cli::try_parse_from(&args);
                assert!(parsed.is_ok(), "{parsed:?}");
            }
        }
    }
}
