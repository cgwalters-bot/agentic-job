//! agentic-job runs a coding agent as an unprivileged user on a hardened
//! CI host and checks what it hands back.
//!
//! One module per command, each holding that command's arguments (`Args`)
//! and its entry point (`run`); [`cli`] only assembles them. A command is
//! implemented by filling in its module, so two commands being written at
//! once touch different files. docs/layout.md has the map.

pub mod audit;
pub mod check;
pub mod cli;
pub mod config;
pub mod event;
pub mod exit;
pub mod files;
pub mod policy;
pub mod redact;
pub mod run;
pub mod sandbox;
pub mod session;

mod workflow_commands;
