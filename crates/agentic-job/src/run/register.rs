//! `agentic-job register`: the `github-oidc` registration `run` would
//! make, in a job of its own before the agent's, so that the agent's job
//! holds no `id-token: write`. With that permission any step of the job,
//! and anything that becomes the runner's user, can mint identity tokens
//! for any audience, not only the broker's (tracker#674). This job runs
//! this binary and nothing of the agent's; what leaves it is the broker's
//! run token alone: narrow, capped by the broker, expiring, and ended by
//! `run`, which takes it over from [`inference::RUN_TOKEN_VAR`].
//!
//! The token is appended to `--output`, the step's `$GITHUB_OUTPUT`, as
//! `run-token`, and never printed. A configuration with another mode, or
//! none, writes nothing: `run` then registers as it always did.
//!
//! The output is not masked (GitHub drops a masked job output), and with
//! step debug logging the runner logs every output it sets, value
//! included, in a log anyone who can read the run can read. So with
//! [`DEBUG_VAR`] set, which the runner sets exactly then, this refuses
//! before it registers anything.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::Args as ClapArgs;

use super::inference::{self, Identity, Mode, NEVER, OidcRequest, Retry, Run};
use crate::config::Config;
use crate::exit::Exit;

/// The name of the output that holds the token.
pub const OUTPUT: &str = "run-token";

/// Set (to `1`) by the runner when step debug logging is on, as for a
/// re-run with debug logging.
pub const DEBUG_VAR: &str = "RUNNER_DEBUG";

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// The run's configuration, as the policy job wrote it
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
    /// The file the token is appended to as `run-token=TOKEN`: the step's $GITHUB_OUTPUT
    #[arg(long, value_name = "FILE")]
    pub output: PathBuf,
}

pub fn run(args: &Args) -> Result<Exit> {
    let checked = Config::load(&args.config)?.check()?;
    let Some(endpoint) = checked
        .endpoint
        .filter(|endpoint| matches!(endpoint.mode, Mode::GithubOidc { .. }))
    else {
        eprintln!("Nothing to register: inference.register is not \"github-oidc\"");
        return Ok(Exit::Success);
    };
    // Any value but empty: fail closed on one the runner may use later.
    ensure!(
        std::env::var_os(DEBUG_VAR).is_none_or(|value| value.is_empty()),
        "Refusing to register: with step debug logging on ({DEBUG_VAR} is set), the runner \
         would log the run token as it sets the {OUTPUT} output; re-run without debug logging"
    );
    let identity = Identity {
        oidc: OidcRequest::from_env(),
        ..Identity::default()
    };
    let run = Run::register(
        &endpoint,
        &identity,
        Retry::default(),
        checked.limits.timeout_s,
        NEVER,
    )?;
    let mut output = std::fs::OpenOptions::new()
        .append(true)
        .open(&args.output)
        .with_context(|| format!("opening {}", args.output.display()))?;
    // `Token` holds no line break, so this is one line of the file.
    writeln!(output, "{OUTPUT}={}", run.token().expose())
        .with_context(|| format!("writing {}", args.output.display()))?;
    eprintln!(
        "Wrote the run token to {} as {OUTPUT}, for {}",
        args.output.display(),
        inference::RUN_TOKEN_VAR
    );
    Ok(Exit::Success)
}
