//! Informational monotonic timing for host setup stages and probes.
//!
//! Consumers may collect these lines for their summaries. Timing never
//! authorizes an operation or substitutes for a passing probe.

use std::sync::OnceLock;
use std::time::Instant;

use anyhow::Result;

/// The first word of each line; the legacy layout's readers match its own.
const PREFIX: &str = crate::runtime::name("Secure-host", "Sandbox");

/// The first stage of this process that failed: the innermost, where
/// stages nest.
static FAILED: OnceLock<String> = OnceLock::new();

/// The name of the first stage of this process that failed, if any.
pub fn failed_stage() -> Option<&'static str> {
    FAILED.get().map(String::as_str)
}

/// Log a stage's duration and preserve its result, including failures.
/// Consumers may parse these informational lines, but timing is not a check record.
pub fn stage<T>(kind: &str, name: &str, run: impl FnOnce() -> Result<T>) -> Result<T> {
    let started = Instant::now();
    let result = run();
    if result.is_err() {
        // Only the first is kept: a later one is a consequence or an
        // enclosing stage.
        let _ = FAILED.set(name.to_owned());
    }
    println!(
        "{PREFIX} {kind} stage {name}: {:.3}s ({})",
        started.elapsed().as_secs_f64(),
        if result.is_ok() { "ok" } else { "failed" }
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_values_and_errors() {
        assert_eq!(stage("setup", "fixture", || Ok(42)).unwrap(), 42);
        let error = stage::<()>("check", "fixture", || anyhow::bail!("probe failed")).unwrap_err();
        assert_eq!(error.to_string(), "probe failed");
    }
}
