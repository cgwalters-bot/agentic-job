//! `agentic-job replacement`: rebuild and push a replacement series that
//! `check` accepted, for apply.yml, which is the safe-outputs library's
//! ([`safe_outputs::apply::replacement`]). This runs from policy's binary,
//! never from a producer checkout, reads the hand-back's files without
//! following a link, and escapes git's messages, which hold the agent's
//! text and end up in the step's log.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use safe_outputs::apply::replacement as library;
pub use safe_outputs::apply::replacement::{Built, PushArgs, TrialArgs};

use crate::exit::Exit;
use crate::policy::{Load, Policy};
use crate::workflow_commands::escaped;

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Rebuild the checked series on its base and print its head and tree as step outputs
    Trial {
        #[command(flatten)]
        args: TrialArgs,
        /// Trusted policy.json; enables exact old-side recovery for replacement trials
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Push a rebuilt head over the branch, only while the branch is still the policy's head
    Push(PushArgs),
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        let repo = Path::new(".");
        match self {
            Self::Trial { args, policy } => {
                let built = if let Some(path) = policy {
                    let policy = Policy::load(path)?;
                    let credentials: Vec<_> = ["GH_TOKEN", "GITHUB_TOKEN", "SAFE_OUTPUTS_PAT"]
                        .into_iter()
                        .chain(
                            safe_outputs::apply::roles::Role::ALL
                                .into_iter()
                                .map(|role| role.token_env()),
                        )
                        .filter_map(|name| {
                            std::env::var(name).ok().filter(|value| !value.is_empty())
                        })
                        .collect();
                    let trial = library::trial_recovered(
                        args,
                        repo,
                        &super::read_checked,
                        &policy,
                        &|bytes| validate_application(bytes, &credentials),
                    )
                    .map_err(shown)?;
                    println!(
                        "restored-lines={}\nadded-placeholders={}",
                        trial.restored_lines, trial.added_placeholders
                    );
                    if trial.added_placeholders > 0 {
                        eprintln!(
                            "warning: replacement adds {} inference-address placeholders; keep the pull request in draft for manual review",
                            trial.added_placeholders
                        );
                    }
                    trial.built
                } else {
                    library::trial(args, repo, &super::read_checked).map_err(shown)?
                };
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

/// Apply has no producer run token to compare, so conservatively refuse any
/// credential shape in recovered application bytes. Never sanitize it into a
/// different mail or quote it in the error. This is stricter than handback's
/// warnings, intentionally, at the new recovery boundary.
fn validate_application(bytes: &[u8], credentials: &[String]) -> Result<()> {
    anyhow::ensure!(
        !crate::redact::is_secret_shaped(bytes)
            && !credentials
                .iter()
                .filter(|value| !value.is_empty())
                .any(|value| {
                    bytes
                        .windows(value.len())
                        .any(|piece| piece == value.as_bytes())
                }),
        "credential-shaped or known credential in application bytes"
    );
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_validation_refuses_shapes_and_known_opaque_credentials() {
        let opaque = "opaque.example.test:8443".to_owned();
        let credentials = vec![opaque.clone()];
        let run_token = ["praxis", "-run-", &"a".repeat(64)].concat();
        let private_key = ["-----BEGIN ", "PRIVATE KEY-----"].concat();
        for value in [opaque, run_token, private_key] {
            let error = validate_application(value.as_bytes(), &credentials).unwrap_err();
            assert!(!error.to_string().contains(&value));
        }
        assert!(validate_application(b"url=inference.example.test:8443\n", &credentials).is_ok());
    }
}
