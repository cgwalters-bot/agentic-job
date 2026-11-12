//! `agentic-job push`: where a run's commit goes on GitHub, which is the
//! safe-outputs library's ([`safe_outputs::apply::push`]), re-exported
//! here. `push resolve` is policy.yml's, with the policy job's read-only
//! token, and `push target` apply.yml's fork step, with apply's; this
//! reads the token from the environment and the handlers' files without
//! following a link, and prints the answer as step outputs.

use anyhow::Result;
pub use safe_outputs::apply::push::*;

use super::github::GH_TOKEN_ENV;
use crate::exit::Exit;
use crate::policy::{Bounds, Load};

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// For policy: print the branch, head, current base and author of the pull request a run pushes to
    Resolve {
        #[command(flatten)]
        request: ResolveArgs,
        /// Trusted caller bounds; absent, only the addressed PR supplies its base
        #[arg(long, value_name = "FILE")]
        allow: Option<std::path::PathBuf>,
    },
    /// For apply: print the repository a run's commit is pushed to, forking for a new pull request
    Target(TargetArgs),
    /// For apply: set draft state after a verified continuation, respecting hold labels
    Finish(super::readiness::Args),
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::Resolve { request, allow } => {
                let github = super::github::from_env(GH_TOKEN_ENV)?;
                let upstream = allow
                    .as_deref()
                    .map(Bounds::load)
                    .transpose()?
                    .and_then(|bounds| bounds.github)
                    .is_some_and(|github| github.outputs.upstream_pull_request_base);
                let pull = resolve(&github, request, upstream)?;
                println!("branch={}", pull.branch);
                println!("head={}", pull.head);
                println!("replacement-base={}", pull.base);
                println!("author={}", pull.author);
            }
            Self::Target(args) => {
                let github =
                    super::github::from_role_env(super::roles::Role::ForkPush, GH_TOKEN_ENV)?;
                let target = target(&github, args, &super::read_checked)?;
                if let Some(repo) = target.repo {
                    println!("repo={repo}");
                }
                if let Some(base) = target.current_base {
                    println!("current-base={base}");
                }
            }
            Self::Finish(args) => return super::readiness::run(args),
        }
        Ok(Exit::Success)
    }
}
