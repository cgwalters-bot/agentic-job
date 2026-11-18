//! Exit states, as docs/plan.md defines them. Callers (the workflow,
//! `bot-runs`) branch on these numbers, so they are part of the interface.

use std::process::ExitCode;

/// Bad arguments or an internal error. Also what clap exits with.
pub const ERROR: u8 = 2;

/// What a command that ran to completion reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The agent ended its turn; the outputs were accepted; every probe passed.
    Success,
    /// The agent failed or cancelled; the outputs were refused; a probe failed.
    Failure,
    /// `run`: a request, task or spending limit stopped the agent, or it
    /// handed back after a turn that ended on an error.
    Limit,
    /// `run`: the run never started (sandbox probe, proxy registration or
    /// clone failed), or the agent made no model request before its startup
    /// deadline, so it is safe to retry. `run` maps the errors of that
    /// phase to this itself: an `Err` out of a command is [`ERROR`].
    /// `sandbox check`: only a control that reaches outside the host failed.
    NotStarted,
    /// A security-sensitive stop; no public handback or automatic retry.
    SecurityStop,
    /// `run`: the timeout stopped the agent.
    Timeout,
    /// `sandbox timed`: the exit status of the command it ran, which is
    /// that command's to choose.
    Command(u8),
}

impl Exit {
    /// Preserve the stop classification through command errors and their context.
    pub fn error_code(error: &anyhow::Error) -> u8 {
        if error.is::<crate::security_stop::Stop>() {
            Self::SecurityStop.code()
        } else {
            ERROR
        }
    }

    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Limit => 3,
            Self::NotStarted => 4,
            Self::SecurityStop => 5,
            Self::Timeout => 124,
            Self::Command(code) => code,
        }
    }
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        Self::from(exit.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_the_plan() {
        let cases = [
            (Exit::Success, 0),
            (Exit::Failure, 1),
            (Exit::Limit, 3),
            (Exit::NotStarted, 4),
            (Exit::SecurityStop, 5),
            (Exit::Timeout, 124),
        ];
        for (exit, code) in cases {
            assert_eq!(exit.code(), code, "{exit:?}");
            assert_ne!(exit.code(), ERROR, "{exit:?} collides with ERROR");
        }
    }
}
