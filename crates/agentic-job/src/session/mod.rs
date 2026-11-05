//! The ACP session, which the `acp-session` crate holds: re-exported
//! here, at the paths `run` and callers have used, beside what is the
//! command line's own: `session connect` ([`connect`]), a client of the
//! bridge, not a session, and the exit state a session's outcome maps to.

pub use acp_session::*;

pub mod connect;

use crate::exit::Exit;

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Join a session run's conversation from a terminal or another agent: each line of standard input is a prompt
    Connect(connect::Args),
}

impl Command {
    pub fn run(&self) -> anyhow::Result<Exit> {
        match self {
            Self::Connect(args) => connect::run(args),
        }
    }
}

/// The exit state of a run whose session ended like OUTCOME.
pub fn exit(outcome: Outcome) -> Exit {
    match outcome {
        Outcome::Success => Exit::Success,
        Outcome::NoRequests => Exit::NotStarted,
        Outcome::Timeout => Exit::Timeout,
        Outcome::Budget => Exit::Limit,
        Outcome::Failure | Outcome::Cancelled => Exit::Failure,
    }
}
