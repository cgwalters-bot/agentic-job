//! `agentic-job sandbox exec`: one command as the sandbox user, for a
//! step of a job that runs no agent.
//!
//! After `sandbox setup` the steps of a job are the runner's user's,
//! without root; a step that runs code the job does not trust (a build
//! script from a pull request, a dependency's install hook) can go one
//! further and run it as the sandbox user, which has none of the job's
//! files, tokens or environment and reaches the network as the
//! configuration says. This is the way in for such a step, the same one
//! `run` takes for an agent ([`super::enter`]), and it gives its caller
//! no privilege the helper does not already give it.
//!
//! As a step's shell it takes the step's script as a file, which the
//! sandbox user could not read where the runner keeps it:
//!
//! ```yaml
//! - shell: agentic-job sandbox exec --stdin {0} -- bash -eo pipefail -s
//!   run: make check
//! ```

use std::fs::File;
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::enter::Entry;
use crate::config::{self, Config};
use crate::exit::Exit;

/// What a shell reports for a command a signal ended: this, and the
/// signal's number.
const SIGNALLED: i32 = 128;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Where the command starts: a directory under the sandbox user's home, which is the default
    #[arg(long, value_name = "DIR")]
    pub chdir: Option<PathBuf>,
    /// A file the command gets as its standard input, in place of this process's own
    #[arg(long, value_name = "FILE")]
    pub stdin: Option<PathBuf>,
    /// The command and its arguments
    #[arg(last = true, required = true)]
    pub argv: Vec<String>,
}

pub fn run(args: &Args) -> Result<Exit> {
    let config = Config::load(Path::new(config::ROOT_COPY))
        .context("`agentic-job sandbox setup` writes this file")?;
    let entry = Entry::new(&config)?;
    // What the sandbox user does next is for the next check to probe:
    // a passing one earlier in the job no longer vouches for the host.
    super::check::forget_passed()?;
    // Opened here, as the caller: the sandbox user gets its bytes and
    // not its path.
    let input: Box<dyn Read + Send> = match &args.stdin {
        Some(path) => {
            Box::new(File::open(path).with_context(|| format!("opening {}", path.display()))?)
        }
        None => Box::new(std::io::stdin()),
    };
    let status = entry.stream(&args.argv, args.chdir.as_deref(), input)?;
    let code = status
        .code()
        .or_else(|| status.signal().map(|signal| SIGNALLED + signal))
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(u8::MAX);
    Ok(Exit::Command(code))
}
