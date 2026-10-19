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
//! On GitHub the output is not masked (GitHub drops a masked job output),
//! and with step debug logging the runner logs every output it sets,
//! value included, in a log anyone who can read the run can read. So with
//! [`DEBUG_VAR`] set, which the runner sets exactly then, this refuses
//! before it registers anything.
//!
//! Forgejo's runner differs; at forgejo/runner v13.2.0 (df6b843f):
//! - It logs every output it sets, value included, whatever the debug
//!   mode: `Setting output %s=%s` at info level (act/runner/command.go,
//!   `setOutput`), after the step's result (act/runner/step.go). Its
//!   reporter keeps no such row while a step runs, but once the last
//!   step has a result it keeps them all (internal/pkg/report/reporter.go,
//!   `Fire`, `duringSteps`), and `register` is its job's last step: the
//!   token would be in the job log of every run.
//! - `::add-mask::` masks a value in that log (reporter.go,
//!   `handleCommand`) and in the runner's own at debug level
//!   (act/runner/logger.go, `valueMasker`; not at trace level, where the
//!   reporter copies each entry before it is masked), and a job output
//!   with a masked value is passed on as it is (reporter.go,
//!   `setOutputs`). So with [`FORGEJO_VAR`] set this masks the token
//!   before it writes it.
//! - It sets no [`DEBUG_VAR`]. Its debug mode is the secret
//!   [`STEP_DEBUG_VAR`] (reporter.go, `NewReporter`), which only shows
//!   `::debug::` lines and is not in a step's environment unless the
//!   workflow puts it there. This refuses with it set too, on either
//!   forge, for a runner that one day logs more in debug mode.

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
/// Forgejo's step debug switch: a secret the runner reads itself, in a
/// step's environment only if the workflow passes it there.
pub const STEP_DEBUG_VAR: &str = "ACTIONS_STEP_DEBUG";
/// Set to `true` by Forgejo's runner in every job.
pub const FORGEJO_VAR: &str = "FORGEJO_ACTIONS";

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
    for debug in [DEBUG_VAR, STEP_DEBUG_VAR] {
        ensure!(
            std::env::var_os(debug).is_none_or(|value| value.is_empty()),
            "Refusing to register: with step debug logging on ({debug} is set), the runner \
             would log the run token as it sets the {OUTPUT} output; re-run without debug logging"
        );
    }
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
    // Only on Forgejo: GitHub would honour the mask and drop the output.
    // The runner takes the line from stdout as a command and logs `***`;
    // `Token`'s characters need no escaping in it.
    if std::env::var_os(FORGEJO_VAR).is_some_and(|value| value == "true") {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "::add-mask::{}", run.token().expose())
            .and_then(|()| stdout.flush())
            .context("masking the run token")?;
    }
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
