//! `agentic-job sandbox`: make the host safe for the agent, and prove it.
//! Step 5 of docs/plan.md. `setup` runs as root, and ends by taking root
//! away from the runner's user; `check` runs as the runner's user and
//! enters the sandbox ([`enter`]) for each probe, through the one
//! privileged command that user keeps ([`helper`], via [`root`]).

use anyhow::Result;
use clap::Subcommand;

use crate::exit::Exit;

pub mod check;
pub mod egress;
pub mod enter;
pub mod exec;
pub mod helper;
pub mod host;
pub mod local;
pub mod network;
pub mod root;
pub mod setup;
mod view;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the sandbox user, close its routes to credentials and root
    Setup(setup::Args),
    /// Probe the sandbox as the sandbox user, each probe with a positive control
    Check(check::Args),
    /// Run one command as the sandbox user, with none of this environment
    Exec(exec::Args),
    /// Print the local sockets and ports this user connects to; `check` runs it as the sandbox user
    #[command(hide = true)]
    ProbeLocal,
    /// Print the network rules setup would load; CI compares them with the old tree's
    #[command(hide = true)]
    NftRules(NftRulesArgs),
}

#[derive(Debug, clap::Args)]
pub struct NftRulesArgs {
    /// The sandbox user's uid, and each range of its subordinate uids as START-END
    #[arg(long = "uid", value_name = "UID", required = true)]
    pub uids: Vec<String>,
    /// A URL reached directly, as `[egress] direct` has them
    #[arg(long, value_name = "URL")]
    pub direct: Vec<String>,
    /// The egress proxy's uid; without it, the rules of a host that has no proxy
    #[arg(long, value_name = "UID")]
    pub proxy_uid: Option<u32>,
    /// Literal DNS resolver allowed for the proxy
    #[arg(long, value_name = "IP")]
    pub resolver: Vec<std::net::IpAddr>,
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::Setup(args) => setup::run(args),
            Self::Check(args) => check::run(args),
            Self::Exec(args) => exec::run(args),
            Self::ProbeLocal => local::run(),
            Self::NftRules(args) => {
                let direct = args
                    .direct
                    .iter()
                    .map(|url| network::Direct::parse(url))
                    .collect::<Result<Vec<_>>>()?;
                print!(
                    "{}",
                    network::rules_with_resolvers(
                        &args.uids,
                        &direct,
                        args.proxy_uid,
                        &args.resolver,
                        &[]
                    )
                );
                Ok(Exit::Success)
            }
        }
    }
}
