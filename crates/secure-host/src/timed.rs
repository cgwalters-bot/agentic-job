//! Informational monotonic timing for host setup stages and probes.
//!
//! Consumers may collect these lines for their summaries. Timing never
//! authorizes an operation or substitutes for a passing probe.

use std::time::Instant;

use anyhow::Result;

/// Log a stage's duration and preserve its result, including failures.
/// The output format is also consumed by existing job summary adapters.
pub fn stage<T>(kind: &str, name: &str, run: impl FnOnce() -> Result<T>) -> Result<T> {
    let started = Instant::now();
    let result = run();
    println!(
        "Sandbox {kind} stage {name}: {:.3}s ({})",
        started.elapsed().as_secs_f64(),
        if result.is_ok() { "ok" } else { "failed" }
    );
    result
}
