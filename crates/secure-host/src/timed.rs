//! Informational monotonic timing for host setup stages and probes.
//!
//! Consumers may collect these lines for their summaries. Timing never
//! authorizes an operation or substitutes for a passing probe.

use std::time::Instant;

use anyhow::Result;

/// Log a stage's duration and preserve its result, including failures.
/// Consumers may parse these informational lines, but timing is not a check record.
pub fn stage<T>(kind: &str, name: &str, run: impl FnOnce() -> Result<T>) -> Result<T> {
    let started = Instant::now();
    let result = run();
    println!(
        "Secure-host {kind} stage {name}: {:.3}s ({})",
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
