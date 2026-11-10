//! `agentic-job replacement`: rebuild and push a replacement series that
//! `check` accepted, for apply.yml, which is the safe-outputs library's
//! ([`safe_outputs::apply::replacement`]). This runs from policy's binary,
//! never from a producer checkout, reads the hand-back's files without
//! following a link, and escapes git's messages, which hold the agent's
//! text and end up in the step's log.

use std::path::Path;

use anyhow::{Result, anyhow};
use safe_outputs::apply::replacement as library;
pub use safe_outputs::apply::replacement::{Built, PushArgs, TrialArgs};

use crate::exit::Exit;
use crate::workflow_commands::escaped;

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Rebuild the checked series on its base and print its head and tree as step outputs
    Trial(TrialArgs),
    /// Push a rebuilt head over the branch, only while the branch is still the policy's head
    Push(PushArgs),
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        let repo = Path::new(".");
        match self {
            Self::Trial(args) => {
                let built = library::trial(args, repo, &super::read_checked).map_err(shown)?;
                println!("head={}\ntree={}", built.head, built.tree);
            }
            Self::Push(args) => {
                push(
                    repo,
                    &args.remote,
                    &args.branch,
                    &args.original_head,
                    &args.replacement_head,
                )?;
            }
        }
        Ok(Exit::Success)
    }
}

/// ERR, which may hold git's messages, escaped for the step's log.
fn shown(err: anyhow::Error) -> anyhow::Error {
    anyhow!(escaped(&format!("{err:#}")))
}

/// [`library::push`], its error escaped.
pub(super) fn push(
    repo: &Path,
    remote: &str,
    branch: &str,
    original: &str,
    replacement: &str,
) -> Result<bool> {
    library::push(repo, remote, branch, original, replacement).map_err(shown)
}

/// [`library::git`], its error escaped.
pub(super) fn git(repo: &Path, args: &[&str]) -> Result<String> {
    library::git(repo, args).map_err(shown)
}
