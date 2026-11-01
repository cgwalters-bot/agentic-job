//! secure-host: secure a CI host for untrusted steps, and prove it.
//!
//! The host's side of agentic-job, for any job that runs code it does not
//! trust: it knows nothing of agents, inference or safe outputs, and
//! agentic-job depends on it, never the other way round. It holds the
//! host setup ([`setup`]), the network rules, the egress proxy and the
//! helper among it, and the probes that prove it ([`check`]); agentic-job
//! adds its agents through [`setup::Program`], or in a step of its own
//! before ([`config::Prepared`]). The `secure-host` binary ([`cli`]) and
//! its image's entrypoint ([`image`]) are here too, and agentic-job's
//! `sandbox` re-exports these at their old paths. docs/layout.md has the
//! map.

pub mod apt;
pub mod check;
pub mod cli;
pub mod compose;
pub mod config;
pub mod egress;
pub mod enter;
pub mod files;
pub mod helper;
pub mod host;
pub mod image;
pub mod local;
pub mod network;
pub mod platform;
pub mod proxy;
pub mod root;
pub mod setup;
pub mod timed;
pub mod view;
pub mod worker_diagnostics;
pub mod workflow_commands;
pub mod world_write;
