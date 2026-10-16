//! `agentic-job secure-host`: the steps of the `secure-host` action that
//! come after it has fetched this binary and before `sandbox setup`. Each
//! refuses as the script it replaced did: one message, exit status 1.

use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;

use crate::exit::Exit;

pub mod apt;
pub mod inference;
pub mod platform;
pub mod world_write;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Refuse a host that is not Ubuntu 26.04 or RHEL 10, by /etc/os-release
    Supported,
    /// As root: bound apt's network waits and keep it off the Azure mirror
    Apt,
    /// As root: load the world-write policy OBJECT through bpftool, and prove it took effect
    WorldWrite {
        /// The policy object, `world_write.bpf.o`, that came with this binary
        object: PathBuf,
    },
    /// Refuse a runner that cannot open a TCP connection to the inference proxy CONFIG names
    Inference {
        /// The configuration `agentic-job config --host` wrote
        config: PathBuf,
    },
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::Supported => {
                if platform::supported_file(std::path::Path::new(platform::OS_RELEASE)) {
                    return Ok(Exit::Success);
                }
                eprintln!("{}", platform::REFUSAL);
            }
            Self::Apt => match apt::configure(std::path::Path::new(apt::APT)) {
                Ok(()) => return Ok(Exit::Success),
                Err(err) => eprintln!("configuring apt for CI: {err:#}"),
            },
            Self::Inference { config } => match inference::run(config) {
                Ok(()) => return Ok(Exit::Success),
                Err(err) => eprintln!("error: {err:#}"),
            },
            Self::WorldWrite { object } => match world_write::load(object) {
                Ok(()) => return Ok(Exit::Success),
                Err(err) => {
                    world_write::report_refusal(&err, &mut world_write::run_command, &mut |line| {
                        eprintln!("{line}")
                    })
                }
            },
        }
        Ok(Exit::Failure)
    }
}
