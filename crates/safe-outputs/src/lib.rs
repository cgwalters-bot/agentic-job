//! gh-aw's safe-output contract, as a library: the request vocabulary
//! ([`vocabulary`]), the framing of an `outputs.jsonl`, read-only
//! ([`decode`]), the collector that validates and sanitizes one as
//! gh-aw's does ([`collect`]), the policy a run's
//! outputs are held to ([`contract`]) and the bounds it is compiled within
//! ([`bounds`]), the check of a hand-back against that policy
//! ([`check`]), and the publication of what check accepted to Forgejo,
//! GitLab and GitHub ([`apply`]).
//!
//! It is given text, settings and a token, and reads no environment or
//! credential of its own: event admission, compiling a request into a
//! policy, run identity, artifacts, checkpoints, memory, secret scanning,
//! reading the hand-back and credential acquisition belong to its caller
//! (agentic-job's `policy`, `event`, `collect`, `check`, `apply` and
//! `handback check`). Only [`apply`] reaches out, to the forge it is given
//! and with git in a checkout of its own.
//! docs/safe-outputs.md#library-boundary lists what moved here and what
//! stays.

pub mod advisory;
pub mod apply;
pub mod bounds;
pub mod check;
pub mod collect;
pub mod contract;
pub mod decode;
pub mod document;
pub mod replay;
#[cfg(test)]
mod replay_tests;
pub mod vocabulary;

pub use vocabulary::*;
