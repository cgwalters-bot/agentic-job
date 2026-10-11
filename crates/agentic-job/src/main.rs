//! The `agentic-job` binary: parse the command line, run the command, and
//! turn its result into the exit states of docs/plan.md.

use std::process::ExitCode;

use agentic_job::cli::Cli;
use agentic_job::exit;
use clap::Parser;

fn main() -> ExitCode {
    // clap exits with `exit::ERROR` itself on bad arguments.
    let cli = Cli::parse();
    match cli.command.run() {
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
