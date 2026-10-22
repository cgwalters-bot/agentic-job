//! The tables of a host's configuration that the host setup reads, as
//! agentic-job's `--config` file and a host's own file both have them.

use std::path::PathBuf;

use serde::Deserialize;

/// The sandbox user's way out to the network.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Egress {
    /// Whether the sandbox user reaches the network only through the
    /// egress proxy. Off, its network is open but for the cloud metadata
    /// service and the tailnet.
    pub proxy: bool,
    /// URLs the sandbox user reaches directly and not through the egress
    /// proxy: the inference proxy, so that the run token never crosses
    /// the egress proxy. Each is an IPv4 address on the tailnet, with a
    /// port; with any, the rest of the tailnet is closed to the sandbox
    /// user.
    pub direct: Vec<String>,
    /// The write rules, in place of the ones that come with the binary
    /// (`egress/policy.toml`).
    pub policy: Option<PathBuf>,
    /// Whether the proxy is this binary's own (`sandbox egress-proxy`)
    /// rather than mitmproxy: the same policy, and no Python or package
    /// index at setup. On by default; `false` keeps mitmproxy, which
    /// needs Python's venv module (`python3-venv`) in `[setup] packages`,
    /// until it is removed (#919).
    pub rust_proxy: bool,
    /// Whether every process of the runner's user (and its subordinate
    /// uids), each later step and action of the job and the runner
    /// itself, is held to the proxy's write rules too, with the runner's
    /// own writes added (cgwalters-forge/actions's
    /// secure-host/docs/egress.md): a step can then read from
    /// anywhere but send a job's secrets or sources only where a rule
    /// allows. Off by default; needs the Rust proxy and
    /// `sandbox.lock-runner`, without which the runner's user could
    /// remove the rules.
    pub write_policy: bool,
}

impl Default for Egress {
    fn default() -> Self {
        Self {
            proxy: true,
            direct: Vec::new(),
            policy: None,
            rust_proxy: true,
            write_policy: false,
        }
    }
}
