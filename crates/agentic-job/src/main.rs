//! The `agentic-job` binary, or `secure-host` by that name: parse the
//! command line, run the command, and
//! turn its result into the exit states of docs/plan.md.

use std::process::ExitCode;

use agentic_job::cli::Cli;
use agentic_job::exit;
use agentic_job::secure_host::{self, HostCli};
use clap::Parser;

fn main() -> ExitCode {
    // clap exits with `exit::ERROR` itself on bad arguments.
    let result = if std::env::args_os()
        .next()
        .is_some_and(|argv0| secure_host::invoked_as(&argv0))
    {
        HostCli::parse().command.run()
    } else {
        Cli::parse().command.run()
    };
    match result {
        Ok(code) => code.into(),
        Err(err) => {
            eprintln!(
                "error: {}",
                agentic_job::run::enter::one_line(&format!("{err:#}"))
            );
            ExitCode::from(exit::ERROR)
        }
    }
}
