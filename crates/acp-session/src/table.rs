//! The session's tables of the `--config` file, as written: agentic-job's
//! `config` re-exports them, and the session's own types check them
//! ([`crate::Limits::from_config`], [`crate::bridge::Listen::from_config`],
//! [`crate::steer::interval`]).

use serde::Deserialize;

/// What stops a run. Zero means not set. `session::Limits::from_config`
/// checks it: a run needs a timeout, and one of `max-requests` and
/// `budget` unless it says `uncapped`. Step 3.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Limits {
    pub timeout_minutes: u64,
    /// Model requests, as the inference proxy counts them.
    pub max_requests: u64,
    /// Subagent tasks the agent may start.
    pub max_tasks: u64,
    /// Identical tool calls in a row before the agent is told to change
    /// approach, and then asked to hand back; zero for no limit.
    pub max_repeats: u64,
    /// In AIC, hundredths of a dollar, of the cost the agent reports.
    pub budget: u64,
    /// Asks for a run with neither `max-requests` nor `budget`.
    pub uncapped: bool,
}

/// A conversation with an operator after the task's turn
/// (specs/session.md). Off unless `listen` is set.
/// `session::bridge::Listen::from_config` checks it. Also the watch of
/// the run's item, off unless `watch-item` is set, which
/// `session::steer::interval` checks.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Session {
    /// Whether `run` listens for a client, which `sandbox setup` exposes
    /// on the runner's tailnet name with `tailscale serve`.
    pub listen: bool,
    /// The tailnet logins that may attach, as `tailscale serve` names
    /// them in `Tailscale-User-Login`.
    pub operators: Vec<String>,
    /// The `Origin`s a client may connect from, such as the review
    /// board's `https://NAME.TAILNET.ts.net`.
    pub origins: Vec<String>,
    /// A Tailscale app capability, such as
    /// `example.com/cap/agentic-job-session`, that lets a node in without
    /// a login, such as a tagged agent host: the tailnet policy's grants
    /// decide who holds it. Empty for none.
    pub capability: String,
    /// How long the session waits for the client's next prompt. Zero
    /// means the default.
    pub idle_minutes: u64,
    /// Whether the session watches the run's item (`run --watch-item`)
    /// and passes its new comments and body edits to the agent
    /// (`session::steer`). Off by default.
    pub watch_item: bool,
    /// How often it polls the item, in seconds. Zero means the default.
    pub watch_seconds: u64,
}
