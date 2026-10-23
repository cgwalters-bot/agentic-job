//! agentic-job runs a coding agent as an unprivileged user on a hardened
//! CI host and checks what it hands back.
//!
//! One module per command, each holding that command's arguments (`Args`)
//! and its entry point (`run`); [`cli`] only assembles them. A command is
//! implemented by filling in its module, so two commands being written at
//! once touch different files. docs/layout.md has the map.

pub mod acp_drive;
pub mod activate;
pub mod apply;
pub mod audit;
pub mod check;
pub mod cli;
pub mod collect;
pub mod config;
pub mod event;
pub mod exit;
// The `::` is the secure-host crate's, not the `secure_host` module's.
pub use ::secure_host::files;
pub mod handback;
pub mod policy;
pub mod redact;
pub mod review;
pub mod run;
pub mod sandbox;
pub mod secure_host;
pub mod session;
pub mod workflows;

pub mod detect;
mod workflow_commands;
