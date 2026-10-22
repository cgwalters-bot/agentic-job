//! `agentic-job secure-host`: the steps of the `secure-host` action that
//! come after it has fetched this binary and before `sandbox setup`. Each
//! refuses as the script it replaced did: one message, exit status 1.
//! `image` is the secure-host image's entrypoint, which runs them.
//!
//! Started as `secure-host` (a copy or link of the binary by that name),
//! it offers only [`Host`]: those steps, then setup from a host's own
//! file ([`crate::config::HostConfig`]) and the probes.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::exit::Exit;
use crate::sandbox;

pub mod image;
pub mod inference;

// What the secure-host crate holds already, at the paths callers know.
pub use ::secure_host::{apt, platform, world_write};

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(flatten)]
    Host(Host),
    /// Refuse a runner that cannot open a TCP connection to the inference proxy CONFIG names
    Inference {
        /// The configuration `agentic-job config --host` wrote
        config: PathBuf,
    },
    /// The secure-host image's entrypoint: install this binary on the host
    /// mounted at /host and set the host up through its `nsenter -t 1`
    Image {
        /// The configuration `agentic-job config --host` wrote, a path on the host
        config: PathBuf,
    },
}

/// The commands that secure a host, without `run`, `inference` or any
/// other that reads a run's tables: all that the binary offers when it is
/// started as [`NAME`]. `[setup]` may still install agent CLIs.
#[derive(Debug, Subcommand)]
pub enum Host {
    /// Refuse a host that is not Ubuntu 26.04 or RHEL 10, by /etc/os-release
    Supported,
    /// As root: bound apt's network waits and keep it off the Azure mirror
    Apt,
    /// As root: load the world-write policy OBJECT through bpftool, and prove it took effect
    WorldWrite {
        /// The policy object, `world_write.bpf.o`, that came with this binary
        object: PathBuf,
        /// Also refuse a read (`/proc/PID/environ`) by a process of the runner's
        /// user of another of its processes that is not its descendant; the
        /// Runner.Worker this command runs under is exempt
        #[arg(long)]
        deny_runner_reads: bool,
        /// Exempt the one Runner.Worker on the host, not an ancestor: for a
        /// loader the Worker did not start, such as the image's
        #[arg(long, requires = "deny_runner_reads")]
        sole_worker: bool,
    },
    /// As root: `sandbox setup` from a file with only `[sandbox]`, `[egress]` and `[setup]`
    Setup {
        /// The host's configuration (TOML); copied to /etc/agentic-job/
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },
    /// `sandbox check`: probe the host setup secured, as the runner's user
    Check(sandbox::check::Args),
}

/// The name that starts the binary as [`HostCli`]: a host secured for
/// any job needs none of the commands that run an agent.
pub const NAME: &str = "secure-host";

#[derive(Debug, Parser)]
#[command(
    name = NAME,
    version,
    about = "Secure a CI host for untrusted steps, and prove it",
    propagate_version = true
)]
pub struct HostCli {
    #[command(subcommand)]
    pub command: Host,
}

/// Whether the binary was started as [`NAME`], by the last part of ARGV0.
pub fn invoked_as(argv0: &OsStr) -> bool {
    Path::new(argv0).file_name() == Some(OsStr::new(NAME))
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::Host(command) => command.run(),
            Self::Inference { config } => match inference::run(config) {
                Ok(()) => Ok(Exit::Success),
                Err(err) => {
                    eprintln!("error: {err:#}");
                    Ok(Exit::Failure)
                }
            },
            Self::Image { config } => match image::run(config) {
                Ok(()) => Ok(Exit::Success),
                Err(err) => {
                    eprintln!("secure-host image: {err:#}");
                    Ok(Exit::Failure)
                }
            },
        }
    }
}

impl Host {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::Supported => {
                if platform::supported_file(Path::new(platform::OS_RELEASE)) {
                    return Ok(Exit::Success);
                }
                eprintln!("{}", platform::REFUSAL);
            }
            Self::Apt => match apt::configure(Path::new(apt::APT)) {
                Ok(()) => return Ok(Exit::Success),
                Err(err) => eprintln!("configuring apt for CI: {err:#}"),
            },
            Self::WorldWrite {
                object,
                deny_runner_reads,
                sole_worker,
            } => match world_write::load(object, *deny_runner_reads, *sole_worker) {
                Ok(()) => return Ok(Exit::Success),
                Err(err) => {
                    world_write::report_refusal(&err, &mut world_write::run_command, &mut |line| {
                        eprintln!("{line}")
                    })
                }
            },
            // These two fail as `sandbox` does, with an error.
            Self::Setup { config } => {
                return sandbox::setup::run(&sandbox::setup::Args {
                    config: config.clone(),
                    egress_image: None,
                    host_only: true,
                });
            }
            Self::Check(args) => return sandbox::check::run(args),
        }
        Ok(Exit::Failure)
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_host_commands_parse_under_their_own_name() {
        HostCli::command().debug_assert();
        let lines: &[&[&str]] = &[
            &["supported"],
            &["apt"],
            &["world-write", "/tmp/bin/world_write.bpf.o"],
            &[
                "world-write",
                "/tmp/bin/world_write.bpf.o",
                "--deny-runner-reads",
            ],
            &[
                "world-write",
                "/tmp/bin/world_write.bpf.o",
                "--deny-runner-reads",
                "--sole-worker",
            ],
            &["setup", "--config", "secure-host/hosted.toml"],
            &["check"],
            &["check", "--record"],
        ];
        for args in lines {
            HostCli::try_parse_from([NAME].iter().chain(*args))
                .unwrap_or_else(|err| panic!("{args:?}: {err}"));
        }
        for bad in [
            &[][..],
            &["setup"],
            &["world-write", "/tmp/bin/world_write.bpf.o", "--sole-worker"],
            &["inference", "/tmp/secure-host/config.toml"],
            &["image", "/tmp/secure-host/config.toml"],
            &["run", "--policy", "p.json"],
            &["sandbox", "exec", "--", "true"],
            &["config", "--host"],
        ] {
            assert!(
                HostCli::try_parse_from([NAME].iter().chain(bad)).is_err(),
                "{bad:?} parsed"
            );
        }
    }

    #[test]
    fn the_name_is_the_last_part_of_argv0() {
        for (argv0, want) in [
            ("secure-host", true),
            ("/usr/local/bin/secure-host", true),
            ("./secure-host", true),
            ("agentic-job", false),
            ("/usr/local/bin/agentic-job", false),
            ("secure-host.old", false),
            ("/opt/secure-host/agentic-job", false),
        ] {
            assert_eq!(invoked_as(OsStr::new(argv0)), want, "{argv0}");
        }
    }
}
