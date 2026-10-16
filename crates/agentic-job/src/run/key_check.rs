//! `agentic-job check-key`: the provider's API key of a configuration
//! with `register = "api-key"`, checked as `run` checks it, but before
//! `sandbox setup`. A key that was never passed, is empty, or is one the
//! provider refuses (the wrong `provider` included) then fails the job in
//! seconds rather than after the minutes of setup. Not a control: `run`
//! checks the key again. Like `run`, it reads the key from its
//! environment and never prints it, the provider's answer included.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args as ClapArgs;

use super::api_key::ApiKey;
use super::inference::{self, Endpoint, Mode, NEVER, Retry};
use crate::config::Config;
use crate::exit::Exit;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// The run's configuration, as the policy job wrote it
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
}

pub fn run(args: &Args) -> Result<Exit> {
    let config = Config::load(&args.config)?;
    match Endpoint::from_config(&config.inference)? {
        Some(Endpoint {
            url,
            mode: Mode::ApiKey { provider },
            ..
        }) => {
            inference::check_api_key(
                &url,
                provider,
                ApiKey::from_env().as_deref(),
                Retry::default(),
                NEVER,
            )?;
            eprintln!("The {} API at {url} took the key", provider.as_str());
        }
        _ => eprintln!("No API key to check: inference.register is not \"api-key\""),
    }
    Ok(Exit::Success)
}
