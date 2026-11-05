//! The `secure-host` binary: parse the command line, run the command,
//! and exit 0 when it succeeded, 1 when it refused or a probe failed, and
//! 2 for bad arguments or a command that could not run.

use std::process::ExitCode;

use clap::Parser;
use secure_host::cli::Cli;

/// What clap exits with on bad arguments, and so does a command that
/// could not run.
const ERROR: u8 = 2;

fn main() -> ExitCode {
    match Cli::parse().command.run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(ERROR)
        }
    }
}
