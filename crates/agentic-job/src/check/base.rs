//! Trusted pre-agent evidence. Only the policy job calls this command; check
//! never accepts evidence from the producer's proposals directory.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};

use crate::config::Config;
use crate::exit::Exit;
use crate::policy::{Load, Policy};
use crate::run::clone::Checkout;
use crate::run::enter::{Runner, Unconfined};
use crate::run::public_addresses::PublicAddresses;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub policy: PathBuf,
    #[arg(long)]
    pub run_id: String,
    #[arg(long)]
    pub output: PathBuf,
}

pub fn run(args: &Args) -> Result<Exit> {
    let config = args
        .config
        .as_deref()
        .map(Config::load)
        .transpose()?
        .unwrap_or_default();
    let policy = Policy::load(&args.policy)?;
    let mut public = PublicAddresses::default();
    if config.commit.replay_redacted_endpoints {
        let endpoint = crate::run::inference::Endpoint::from_config(&config.inference)?;
        let literals = crate::run::inference_addresses(endpoint.as_ref())
            .iter()
            .map(|address| safe_outputs::replay::Literal::new(address))
            .collect::<Result<Vec<_>>>()?;
        safe_outputs::replay::validate_literals(&literals)?;
        ensure!(
            !literals.is_empty(),
            "endpoint replay requires configured broker endpoints"
        );
        public.replay = Some(Box::new(safe_outputs::replay::Provenance { literals }));
    }
    if config.commit.allow_base_secret_lines {
        ensure!(
            !policy.private,
            "base secret allowances require a public target"
        );
        crate::run::clone::check(&policy)?;
        let dir = tempfile::tempdir()?;
        // No credential helper, user git configuration, hooks or checkout of
        // repository code. An unauthenticated fetch is also the public proof.
        let git = |argv: &[&str]| -> Result<String> {
            let home = format!("HOME={}", dir.path().display());
            let command = [
                &[
                    "env",
                    "-u",
                    "GIT_CONFIG_COUNT",
                    "-u",
                    "GIT_CONFIG_PARAMETERS",
                    "GIT_TERMINAL_PROMPT=0",
                    "GIT_CONFIG_NOSYSTEM=1",
                    "GIT_CONFIG_GLOBAL=/dev/null",
                    &home,
                    "timeout",
                    "120",
                    "git",
                    "-c",
                    "credential.helper=",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-C",
                    dir.path()
                        .to_str()
                        .context("temporary checkout path is not UTF-8")?,
                ][..],
                argv,
            ]
            .concat();
            let output = Unconfined
                .run(&command, b"", 4096)
                .context("reading public base")?;
            ensure!(output.success(), "reading public base failed");
            String::from_utf8(output.stdout).context("public base command is not UTF-8")
        };
        git(&["init", "-q"])?;
        let reference = policy
            .safe_outputs
            .push_to_pull_request_branch
            .as_ref()
            .map_or(policy.base.as_str(), |push| push.head.as_str());
        git(&[
            "fetch",
            "--quiet",
            "--depth=1",
            "--no-tags",
            "--",
            &policy.clone_url,
            reference,
        ])?;
        let checkout = Checkout {
            dir: dir.path().to_owned(),
            base_commit: git(&["rev-parse", "FETCH_HEAD"])?.trim().to_owned(),
            secondary: None,
        };
        public.capture_secrets(
            &Unconfined,
            &checkout,
            &[crate::run::handback::patch_name(&policy, &args.run_id)],
        )?;
    }
    let bytes = serde_json::to_vec(&public)?;
    ensure!(
        bytes.len() <= 1 << 20,
        "serialized base evidence exceeds 1 MiB"
    );
    std::fs::write(&args.output, bytes).context("writing public base evidence")?;
    Ok(Exit::Success)
}
