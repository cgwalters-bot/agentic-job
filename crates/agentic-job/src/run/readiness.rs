//! Admission, not a credential scanner. A scanner cannot prove absence of
//! credentials in same-uid memory, files or local services. Until independent
//! runtime evidence exists, even an apparently clean runner must be refused.

use anyhow::{Result, anyhow, bail};

use crate::config::Config;

/// Parser and validation errors can quote settings, including malformed
/// credentials. Before admission, discard their complete error chains rather
/// than adding context that would still expose the original diagnostic.
pub(super) fn configuration<T>(result: Result<T>, preflight: bool) -> Result<T> {
    result.map_err(|error| {
        if preflight {
            anyhow!(
                "runner preflight refused: configuration could not be read, parsed or validated; \
                 details withheld because settings may contain credentials"
            )
        } else {
            error
        }
    })
}

/// Bounded and value-free: no filesystem walks, network requests, subprocesses
/// or reads of credential values. Configuration is only a necessary condition,
/// never evidence that the installed policy is active.
pub(super) fn require(config: &Config) -> Result<()> {
    let mut missing = Vec::new();
    if !config.sandbox.lock_runner {
        missing.push("sandbox.lock-runner is required to prevent removal of enforcement");
    }
    if !config.sandbox.deny_runner_metadata() {
        missing.push("sandbox.deny-runner-metadata is required to block cloud credentials");
    }
    if !config.egress.proxy || !config.egress.write_policy {
        missing.push("egress.proxy and egress.write-policy are required for runner egress");
    }
    if std::env::var_os(super::agent::GITHUB_TOKEN_VAR).is_some_and(|v| !v.is_empty()) {
        missing.push("agent GitHub read credentials are unsupported; set github-reads: false");
    }
    // Do not turn a clean scan, hidepid=2, a host-check record, or requested
    // policy into an attestation. In particular the old sandbox uid set can be
    // empty while no rule confines the runner at all. There is deliberately no
    // caller-supplied boolean or evidence file that can bypass these refusals.
    missing.extend([
        "active runner and subordinate-uid egress/metadata enforcement is unproven (sandbox uid rules are not evidence)",
        "CI/OIDC/supervisor credential isolation across environment, settings, files, procfs and local services is unproven; local credential proxies are unsupported",
        "independent same-uid process-memory isolation evidence is unavailable (env_clear, hidepid and token-shape scans are insufficient)",
    ]);
    bail!("runner preflight refused: {}", missing.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_controls_are_not_runtime_evidence() {
        for (text, expected) in [
            ("", "egress.proxy and egress.write-policy"),
            (
                "[egress]\nproxy = true\nwrite-policy = false\n",
                "egress.proxy and egress.write-policy",
            ),
            (
                "[egress]\nproxy = false\nwrite-policy = true\n",
                "egress.proxy and egress.write-policy",
            ),
            (
                "[sandbox]\nlock-runner = false\ndeny-runner-metadata = false\n",
                "sandbox.deny-runner-metadata",
            ),
            (
                "[sandbox]\ncreate-user = false\n[egress]\nproxy = true\nwrite-policy = true\n",
                "active runner and subordinate-uid",
            ),
            (
                "[sandbox]\ndeny-runner-reads = true\nunlink-worker-diagnostics = true\n[egress]\nproxy = true\nwrite-policy = true\n",
                "independent same-uid process-memory isolation",
            ),
        ] {
            let config = Config::parse(text).unwrap();
            let error = require(&config).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            assert!(
                error.contains("isolation evidence is unavailable"),
                "{error}"
            );
        }
    }
}
