//! What a command started for the agent must not carry. Since
//! agentic-job#2989 there is no second user to enter: the agent is the
//! runner's own user, and agentic-job's `run::enter` starts its commands
//! with a cleared environment.

use std::process::ExitStatus;

/// What lets a process ask for the job's identity token: never passed on
/// to a command started for the agent.
pub const OIDC_REQUEST_VARS: &[&str] = &[
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
];

/// What a probe's command left: its status and all it wrote.
#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn success(&self) -> bool {
        self.status.success()
    }
}
