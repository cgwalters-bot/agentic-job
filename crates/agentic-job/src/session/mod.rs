//! The ACP session: one agent process, driven over the Agent Client
//! Protocol (<https://agentclientprotocol.com>), recorded, and held to its
//! limits. It came from the old tree's `harness/` (`bot-harness`) in
//! step 3 of docs/plan.md.
//!
//! It is a library with no command of its own: `run` drives it with
//! [`run()`], which
//!
//! - starts the agent ([`agents`]) behind the caller's wrapper, with its
//!   standard streams on sockets, so that `run0` can take it into the
//!   sandbox user's login session ([`process`]);
//! - opens a session in the work directory and sends the task as a
//!   prompt, advertising no filesystem or terminal capability, so the
//!   agent uses its own tools inside the sandbox;
//! - answers the agent's permission requests from a policy
//!   ([`permission`]);
//! - warns the agent as the run nears a limit, has it hand back near
//!   one, and stops it at one ([`budget`]);
//! - records every message in both directions to `acp.jsonl`
//!   ([`transcript`]) and prints a condensed line for each event
//!   ([`digest`]);
//! - kills what the agent left running, and writes `harness.json`.
//!
//! A session is the agent-facing half of an ACP proxy: the agent's
//! client, with a list of attached clients ([`clients`]) that the agent's
//! notifications are passed on to. The list is empty for a task run. With
//! `[session] listen`, [`bridge`] is the client-facing half, and the
//! session goes on after the task's turn to its client's prompts
//! (specs/session.md).

pub mod agents;
pub mod bridge;
pub mod budget;
pub mod clients;
pub mod digest;
mod driver;
pub mod permission;
pub mod process;
pub mod transcript;
pub mod vibe;

pub use agents::AgentSpec;
pub use budget::Limits;
pub use clients::Clients;
pub use driver::{Options, Outcome, OutputCheck, RESULT_FILE, RESULT_SCHEMA, RunResult, run};
pub use permission::Policy;
pub use process::Launch;
pub use transcript::{ACP_LOG, Log, Record, STDERR_LOG};
