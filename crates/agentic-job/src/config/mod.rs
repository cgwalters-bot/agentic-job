//! The `--config` file: one TOML file for a run, with a table per
//! concern. `sandbox setup` reads the caller's file and copies it to
//! [`ROOT_COPY`]; `run` reads only that copy, which is root's.
//!
//! Each table's struct belongs to the step of docs/plan.md that uses it
//! (see docs/layout.md). What the types cannot say (that `github-oidc`
//! has an audience, for one) is checked in one place, [`checked`], for
//! the command that writes the file and the two that read it.

pub mod checked;
pub mod compose;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

// secure-host's now, at the paths callers know.
pub use ::secure_host::config::{
    HOST_TABLE, HostFile, LEGACY_HOST_TABLE, Prepared, ROOT_COPY, Refusal, Sandbox,
    host_table_names,
};

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `[host]`, or `[sandbox]` by its deprecated name ([`host_table_names`]).
    #[serde(rename = "host", alias = "sandbox")]
    pub sandbox: Sandbox,
    pub egress: Egress,
    pub inference: Inference,
    pub agent: Agent,
    /// A second agent the main one may start and drive (`acp-drive`).
    #[serde(rename = "child-agent")]
    pub child_agent: ChildAgent,
    pub limits: Limits,
    pub setup: Setup,
    pub commit: Commit,
    pub session: Session,
    /// Remote MCP servers `run` serves the agent, by name, with a
    /// credential the agent never holds (`run::mcp`). At most one.
    pub mcp: BTreeMap<String, Mcp>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        host_table_names(text)?;
        let config: Self = toml::from_str(text).context("parsing the configuration")?;
        config.sandbox.refuse_removed()?;
        config.setup.refuse_removed()?;
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }
}

/// The file of a job that secures its host and runs no agent: only the
/// tables that set up the machine. `secure-host setup` reads it, so that
/// a run's table in a host's file is refused instead of acted on as root
/// for a job that has no run: `[agent]` has setup write that agent's
/// managed settings, and `[child-agent]` has it install the Vibe runtime.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct HostConfig {
    #[serde(rename = "host", alias = "sandbox")]
    pub sandbox: Sandbox,
    pub egress: Egress,
    pub setup: Setup,
}

impl HostConfig {
    pub fn parse(text: &str) -> Result<Self> {
        host_table_names(text)?;
        let config: Self = toml::from_str(text).context("parsing the host configuration")?;
        config.sandbox.refuse_removed()?;
        config.setup.refuse_removed()?;
        Ok(config)
    }
}

/// A host's file is a run's with every run table at its default, so
/// that `sandbox setup` and `sandbox check` act on it unchanged.
impl From<HostConfig> for Config {
    fn from(host: HostConfig) -> Self {
        Self {
            sandbox: host.sandbox,
            egress: host.egress,
            setup: host.setup,
            ..Self::default()
        }
    }
}

/// `[egress]`, which secure-host's setup reads. Step 5.
pub use ::secure_host::config::Egress;

/// The inference proxy and how a run announces itself to it. Step 6a.
/// `run::inference::Endpoint::from_config` checks it.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Inference {
    /// The proxy, as `http://HOST:PORT`. Empty: the run has no inference,
    /// which only an agent with no model behind it can do without.
    pub url: String,
    /// How the run gets its token. There is no default: `plain` proves
    /// nothing about who registers, so it is never chosen by leaving a
    /// key out.
    pub register: Option<Register>,
    /// For `github-oidc`: the audience of the identity token.
    pub audience: Option<String>,
    /// For `token-file`: where the token is.
    pub token_file: Option<PathBuf>,
    /// For `github-oidc`: the HTTP proxy that the request for the job's
    /// identity token goes through, on a host that reaches the CI system
    /// only through one. Unset, it goes directly, as everything to the
    /// inference proxy does.
    pub identity_proxy: Option<String>,
    /// For `api-key`: which API the provider at `url` speaks.
    pub provider: Option<Provider>,
    /// Where the proxy serves the Anthropic Messages API (`URL/anthropic`
    /// unless set) and the OpenAI Responses API (`URL/v1`).
    pub anthropic_url: Option<String>,
    pub openai_url: Option<String>,
    /// For `github-oidc` and `plain`: `run` serves the agent a proxy of its
    /// own in front of the broker, which the sandbox user may then not
    /// reach, so that the agent never holds the run token.
    pub front: bool,
    /// Stop a silent child agent sleeping on a long upstream rate limit.
    /// Requires the local proxy (`front` or `api-key`); off by default.
    pub stop_long_retry_after: bool,
    /// Legacy no-op. Hand-backs now replace inference addresses unconditionally.
    pub allow_base_address_lines: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Register {
    /// Send the run's identifier and no proof.
    Plain,
    /// Send the CI system's identity token.
    GithubOidc,
    /// No run API: the token is given.
    TokenFile,
    /// No broker: `run` serves the proxy itself, with the provider's API
    /// key from its own environment.
    ApiKey,
}

impl Register {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::GithubOidc => "github-oidc",
            Self::TokenFile => "token-file",
            Self::ApiKey => "api-key",
        }
    }
}

/// The API a provider's key is for, under `register = "api-key"`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// The Anthropic Messages API, for Claude Code.
    Anthropic,
    /// An OpenAI-compatible API (Responses, Chat Completions), for opencode.
    Openai,
    /// GitHub's Copilot API, which serves both, billed to the owner of
    /// the GitHub token used as the key: for Claude Code or opencode.
    Github,
}

impl Provider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Openai => "openai",
            Self::Github => "github",
        }
    }
}

/// Which agent, and where its configuration comes from. Step 6a.
/// `run::agent` reads it.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Agent {
    /// An entry of the session's registry: `claude`, `opencode` or `fake`.
    pub name: String,
    pub model: Option<String>,
    /// The model the session switches the agent to when the provider
    /// stays overloaded past its waits (#1860), such as `opus` for a run
    /// of `fable`: only for Claude Code (and the fake agent), whose model
    /// is a name the provider resolves, not one its configuration defines.
    pub fallback_model: Option<String>,
    /// A public repository holding the agent's configuration, as the URL
    /// to clone: the binary builds no forge URL.
    pub config_repo: Option<String>,
    /// The branch or tag of it (default: its default branch).
    pub config_ref: Option<String>,
    /// The directory of it the configuration is in (default: its root).
    pub config_path: Option<PathBuf>,
    /// Installs source skills and, for Claude/opencode, this binary's
    /// skills and subagents where the agent reads them, for a task that names one. Off: a
    /// task that does not use them gets no instructions it did not ask
    /// for.
    pub skills: bool,
    /// Include the redacted session in the run summary. On by default.
    pub render_session: bool,
    /// The context window, in tokens, of each Vibe model the job defines
    /// by name (the main agent's and the child's), by that name: without
    /// an entry, a model gets `run::agent`'s fallback. A model of a
    /// configuration repository declares its own.
    pub context_windows: BTreeMap<String, u64>,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            name: String::new(),
            model: None,
            fallback_model: None,
            config_repo: None,
            config_ref: None,
            config_path: None,
            skills: false,
            render_session: true,
            context_windows: BTreeMap::new(),
        }
    }
}

/// The run's child agent: one the main agent may start over ACP with
/// `agentic-job acp-drive`, to drive it turn by turn and watch how it
/// works. Off unless `name` is set; only `vibe` can be one.
/// `Config::check` holds it to the run's request cap.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct ChildAgent {
    pub name: String,
    pub model: Option<String>,
}

/// What stops a run. Zero means not set. `session::Limits::from_config`
/// checks it: a run needs a timeout, and one of `max-requests` and
/// `budget` unless it says `uncapped`. Step 3.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Limits {
    pub timeout_minutes: u64,
    /// Model requests, as the inference proxy counts them.
    pub max_requests: u64,
    /// Subagent tasks the agent may start.
    pub max_tasks: u64,
    /// Identical tool calls in a row before the agent is told to change
    /// approach, and then asked to hand back; zero for no limit.
    pub max_repeats: u64,
    /// In AIC, hundredths of a dollar, of the cost the agent reports.
    pub budget: u64,
    /// Asks for a run with neither `max-requests` nor `budget`.
    pub uncapped: bool,
}

/// What the task needs installed. Step 5.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Setup {
    /// Names for the host's package manager.
    pub packages: Vec<String>,
    /// The agent programs, each `NAME@VERSION` with an exact version,
    /// installed for every user with `npm install -g`.
    pub npm: Vec<String>,
    /// Agent programs from the npm tarballs pinned in this binary, each
    /// `NAME@VERSION` as pinned, installed without npm or their scripts
    /// (`sandbox::setup::agents`).
    pub agents: Vec<String>,
    /// For toolchains: run as the runner's user, the agent's, in the
    /// agent's home after setup (the reusable workflow's setup-script
    /// step), never by setup and never as root.
    pub script: Option<PathBuf>,
    /// Tools installed in the removed sandbox user's home, read only to
    /// be refused by name ([`Setup::refuse_removed`]).
    #[serde(rename = "tools")]
    removed_tools: Option<serde::de::IgnoredAny>,
}

impl Setup {
    /// Refuses `setup.tools`, which went with the sandbox user's home.
    pub fn refuse_removed(&self) -> Result<()> {
        ensure!(
            self.removed_tools.is_none(),
            "setup.tools {}",
            Sandbox::REMOVED_KEY
        );
        Ok(())
    }

    /// A name is handed to a package manager run as root, so it must not
    /// read as an option; and an agent program without an exact version
    /// is whatever the registry serves that day.
    fn validate(&self) -> Result<()> {
        self.refuse_removed()?;
        let plain = |name: &str| {
            !name.is_empty() && !name.starts_with('-') && !name.contains(char::is_whitespace)
        };
        ::secure_host::config::check_packages(&self.packages)?;
        for spec in &self.npm {
            let version = spec
                .rsplit_once('@')
                .map(|(name, version)| (plain(name), version));
            ensure!(
                plain(spec)
                    && matches!(version, Some((true, v)) if v.starts_with(|c: char| c.is_ascii_digit())
                        && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))),
                "setup.npm: {spec:?} is not NAME@VERSION with an exact version"
            );
        }
        if !self.agents.is_empty() {
            let pinned = crate::sandbox::setup::agents::pinned()?;
            for spec in &self.agents {
                ensure!(
                    pinned.contains(spec),
                    "setup.agents: {spec:?} is not a pinned agent (pinned: {})",
                    pinned.join(", ")
                );
            }
        }
        Ok(())
    }
}

/// The commit a run's change is handed back as. Step 6b;
/// `run::handback` checks it.
#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Commit {
    /// Permit exact public-base secret-shaped patch lines, never run secrets.
    pub allow_base_secret_lines: bool,
    /// Who the commit is by, as `Name <address>`. Without it,
    /// `agent <agent@localhost>`, as in the old tree.
    pub author: Option<String>,
    /// Lines put at the end of the commit's message, each `Key: value`:
    /// `Generated-by: AI`, for one.
    pub trailers: Vec<String>,
    /// Format the agent's Rust before the change is taken: `just fmt`
    /// where the checkout's Justfile has it, else `cargo fmt --all`, run
    /// as the sandbox user ([`crate::run::handback`]). Off by default.
    pub format: bool,
}

/// A remote MCP server, `[mcp.NAME]`: `run` serves it to the agent on
/// loopback, forwards only the ALLOWED tools, and puts the credential in
/// the workflow's secret SECRET in place of the run's own token.
/// `run::mcp::Server::from_config` checks it.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Mcp {
    /// Where the server speaks MCP's streamable HTTP: https only.
    pub url: String,
    /// The name of the workflow's secret that holds its credential.
    pub secret: String,
    /// The names of the tools the agent may call, exactly.
    pub allowed: Vec<String>,
}

/// A conversation with an operator after the task's turn
/// (specs/session.md). Off unless `listen` is set.
/// `session::bridge::Listen::from_config` checks it. Also the watch of
/// the run's item, off unless `watch-item` is set, which
/// `session::steer::interval` checks.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Session {
    /// Whether `run` listens for a client, which `sandbox setup` exposes
    /// on the runner's tailnet name with `tailscale serve`.
    pub listen: bool,
    /// The tailnet logins that may attach, as `tailscale serve` names
    /// them in `Tailscale-User-Login`.
    pub operators: Vec<String>,
    /// The `Origin`s a client may connect from, such as the review
    /// board's `https://NAME.TAILNET.ts.net`.
    pub origins: Vec<String>,
    /// A Tailscale app capability, such as
    /// `example.com/cap/agentic-job-session`, that lets a node in without
    /// a login, such as a tagged agent host: the tailnet policy's grants
    /// decide who holds it. Empty for none.
    pub capability: String,
    /// Where `run` listens instead, `ADDRESS:PORT`, for an attach gateway
    /// that reaches the job without the tailnet: no `tailscale serve`,
    /// and a client is let in only with the run's attach secret
    /// (`session::bridge::ATTACH_TOKEN_VAR`). Empty for the tailnet.
    pub bind: String,
    /// How long the session waits for the client's next prompt. Zero
    /// means the default.
    pub idle_minutes: u64,
    /// Whether the session watches the run's item (`run --watch-item`)
    /// and passes its new comments and body edits to the agent
    /// (`session::steer`). Off by default.
    pub watch_item: bool,
    /// How often it polls the item, in seconds. Zero means the default.
    pub watch_seconds: u64,
    /// Whether the agent is nudged on the clock, halfway through the
    /// run's timeout and before its end, as an update of the item is
    /// sent (`session::budget::timed`). Off by default.
    pub nudges: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
        [host]
        runner-user = "agent"
        stop-services = ["docker.service"]

        [inference]
        url = "http://proxy.example:18080"
        register = "github-oidc"
        audience = "proxy"

        [agent]
        name = "claude"
        model = "opus"

        [limits]
        timeout-minutes = 75
        max-requests = 150

        [setup]
        packages = ["just"]

        [commit]
        author = "A Bot <bot@example.com>"
        trailers = ["Generated-by: AI"]
    "#;

    #[test]
    fn base_address_lines_are_opt_in() {
        assert!(
            !toml::from_str::<Config>("")
                .unwrap()
                .inference
                .allow_base_address_lines
        );
        assert!(
            toml::from_str::<Config>("[inference]\nallow-base-address-lines = true\n")
                .unwrap()
                .inference
                .allow_base_address_lines
        );
    }

    #[test]
    fn empty_is_the_defaults() {
        let config = Config::parse("").unwrap();
        assert_eq!(config, Config::default());
        assert!(config.sandbox.lock_runner);
        // No mode is chosen for a run that names none.
        assert_eq!(config.inference.register, None);
    }

    #[test]
    fn every_table_of_the_plan_parses() {
        let config = Config::parse(FULL).unwrap();
        assert_eq!(config.sandbox.stop_services, ["docker.service"]);
        assert_eq!(config.inference.register, Some(Register::GithubOidc));
        assert_eq!(config.inference.audience.as_deref(), Some("proxy"));
        assert_eq!(config.agent.name, "claude");
        assert_eq!(config.limits.timeout_minutes, 75);
        assert_eq!(config.setup.packages, ["just"]);
        assert_eq!(config.commit.trailers, ["Generated-by: AI"]);
    }

    /// The egress proxy is the Rust one unless the host configuration
    /// asks for mitmproxy.
    #[test]
    fn the_rust_proxy_is_the_default() {
        assert!(Config::default().egress.rust_proxy);
        for (text, want) in [
            ("", true),
            ("[egress]\nproxy = true\n", true),
            ("[egress]\nrust-proxy = true\n", true),
            ("[egress]\nrust-proxy = false\n", false),
        ] {
            assert_eq!(
                Config::parse(text).unwrap().egress.rust_proxy,
                want,
                "{text}"
            );
        }
        assert!(Config::parse("[egress]\nrust_proxy = true\n").is_err());
        assert!(Config::parse("[egress]\nrust-proxy = \"yes\"\n").is_err());
    }

    #[test]
    fn sandbox_and_setup_refuse_what_the_types_allow() {
        let good = r#"
            [host]
            runner-user = "runner"
            deny-runner-metadata = true
            unlink-worker-diagnostics = true
            deny-runner-reads = true
            close-resolved = true
            private-dirs = ["/opt/hca"]
            stop-services = ["docker.socket", "docker.service"]
            env = { PATH = "/home/agent/.cargo/bin:/usr/bin" }
            [host.check]
            allow-sockets = ["/run/snapd.socket", "/run/pcscd/", "@ISCSIADM_ABSTRACT_NAMESPACE"]
            allow-tcp-ports = [3128]
            containers = false
            fetch-repo = "https://git.example.org/a/b"
            [setup]
            packages = ["just", "gcc-c++"]
            npm = ["opencode-ai@1.2.3", "@agentclientprotocol/claude-agent-acp@0.4.0-beta.1"]
            agents = ["opencode-ai@1.18.35"]
        "#;
        let config = Config::parse(good).unwrap();
        assert!(!config.sandbox.check.containers);
        assert!(Config::default().sandbox.check.containers);
        // Only the removed sandbox user's probes read these: accepted
        // while the pinned image still makes them, and named as ignored.
        assert_eq!(
            config.sandbox.check.ignored(),
            ["fetch-repo", "allow-sockets", "allow-tcp-ports"]
        );
        assert!(Config::default().sandbox.check.ignored().is_empty());
        config.sandbox.validate().unwrap();
        config.setup.validate().unwrap();
        Config::default().sandbox.validate().unwrap();

        let bad = [
            "[host]\nrunner-user = \"root\"",
            "[host]\nrunner-user = \"x) ALL=(ALL) NOPASSWD: ALL #\"",
            "[host]\nlock-runner = false\ndeny-runner-metadata = true",
            "[host]\nlock-runner = false\nunlink-worker-diagnostics = true",
            "[host]\nlock-runner = false\ndeny-runner-reads = true",
            "[host]\nprivate-dirs = [\"relative\"]",
            "[host]\nstop-services = [\"--now\"]",
            "[host]\nstop-services = [\"docker\"]",
            "[host]\nenv = { ACTIONS_ID_TOKEN_REQUEST_URL = \"x\" }",
            "[host]\nenv = { \"A=B\" = \"x\" }",
            "[host]\nenv = { A = \"x\\ny\" }",
            "[host.check]\ncontainer-image = \"--privileged\"",
            "[setup]\npackages = [\"--installroot=/\"]",
            "[setup]\nnpm = [\"opencode-ai\"]",
            "[setup]\nnpm = [\"opencode-ai@latest\"]",
            "[setup]\nnpm = [\"opencode-ai@^1.2.3\"]",
            "[setup]\nnpm = [\"@scope/name\"]",
            "[setup]\nagents = [\"opencode-ai@1.18.34\"]",
            "[setup]\nagents = [\"opencode-linux-x64@1.18.35\"]",
        ];
        for text in bad {
            let config = Config::parse(text).unwrap_or_else(|err| panic!("{text:?}: {err:#}"));
            assert!(
                config
                    .sandbox
                    .validate()
                    .and(config.setup.validate())
                    .is_err(),
                "{text:?} was accepted"
            );
        }
    }

    /// Every key of the removed sandbox user is refused when the file is
    /// read, naming the decision, whatever its value: a file that still
    /// asks for that user is not run as if it had one.
    #[test]
    fn the_sandbox_users_keys_are_refused_by_name() {
        for (text, key) in [
            ("[host]\ncreate-user = false", "host.create-user"),
            ("[host]\ncreate-user = true", "host.create-user"),
            ("[host]\nuser = \"runner-sandbox\"", "host.user"),
            ("[host]\ngroups = []", "host.groups"),
            ("[host]\ngroups = [\"kvm\"]", "host.groups"),
            (
                "[host]\nallow-existing-user = true",
                "host.allow-existing-user",
            ),
            ("[host]\nfilesystem-view = false", "host.filesystem-view"),
            (
                "[host.check]\nbefore-agent = true",
                "host.check.before-agent",
            ),
            (
                "[setup.tools]\nrepository = \"https://example.org/t.git\"",
                "setup.tools",
            ),
        ] {
            // By the table's old name too, with the new name in the error.
            let legacy = text.replacen("[host", "[sandbox", 1);
            for parsed in [
                Config::parse(text).map(drop),
                HostConfig::parse(text).map(drop),
                Config::parse(&legacy).map(drop),
                HostConfig::parse(&legacy).map(drop),
            ] {
                let err = format!("{:#}", parsed.unwrap_err());
                assert!(
                    err.starts_with(&format!("{key} was removed with the sandbox user")),
                    "{text:?}: {err}"
                );
                assert!(err.contains("agentic-job#2989"), "{err}");
            }
        }
        // A misspelling is still unknown, not removed.
        let err = format!(
            "{:#}",
            Config::parse("[host]\ncreate_user = false").unwrap_err()
        );
        assert!(err.contains("unknown field"), "{err}");
    }

    /// The runner's rules follow the lock unless set, and a locked host's
    /// file that turns one off is told what that leaves open.
    #[test]
    fn runner_rules_follow_the_lock() {
        // The file, then whether each rule is on (metadata, diagnostics,
        // reads), then the keys of the opt-outs named.
        let cases: [(&str, [bool; 3], &[&str]); 7] = [
            ("", [true; 3], &[]),
            ("[host]\nlock-runner = true", [true; 3], &[]),
            ("[host]\nlock-runner = false", [false; 3], &[]),
            (
                "[host]\ndeny-runner-metadata = false",
                [false, true, true],
                &["deny-runner-metadata"],
            ),
            (
                "[host]\nunlink-worker-diagnostics = false",
                [true, false, true],
                &["unlink-worker-diagnostics"],
            ),
            (
                "[host]\ndeny-runner-reads = false\ndeny-runner-metadata = true",
                [true, true, false],
                &["deny-runner-reads"],
            ),
            (
                "[host]\nlock-runner = false\ndeny-runner-reads = false",
                [false; 3],
                &[],
            ),
        ];
        for (text, on, named) in cases {
            let sandbox = Config::parse(text).unwrap().sandbox;
            sandbox.validate().unwrap();
            let rules = sandbox.runner_rules();
            assert_eq!(rules.map(|(_, on, _)| on), on, "{text:?}");
            let opt_outs = sandbox.runner_rule_opt_outs("runner");
            let prefixes: Vec<String> = named
                .iter()
                .map(|key| format!("host.{key} = false: runner "))
                .collect();
            assert_eq!(opt_outs.len(), named.len(), "{text:?}: {opt_outs:?}");
            for (line, prefix) in opt_outs.iter().zip(&prefixes) {
                assert!(line.starts_with(prefix), "{text:?}: {line}");
            }
        }
    }

    /// The action's own host file loads as a host's, and as the same
    /// configuration a run's parser makes of it; a run's table does not.
    #[test]
    fn a_host_file_has_only_the_machines_tables() {
        // Read at test time: secure-host/ is outside crates/.
        // Units each stops whose listeners `local-sockets` would refuse:
        // acpid's is on some hosted runners only.
        for (name, units) in [
            ("hosted.toml", &["acpid.socket", "acpid.service"][..]),
            (
                "rhel-cloud.toml",
                &[
                    "cockpit.socket",
                    "cockpit.service",
                    "sssd-kcm.socket",
                    "sssd-kcm.service",
                    "gssproxy.service",
                    "sshd-unix-local.socket",
                ][..],
            ),
        ] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../secure-host")
                .join(name);
            let text = std::fs::read_to_string(path).unwrap();
            let host = HostConfig::parse(&text).unwrap();
            assert!(host.sandbox.close_resolved);
            // What CI's confined job proves, with no override.
            assert!(host.sandbox.runner_rules().iter().all(|(_, on, _)| *on));
            if name == "rhel-cloud.toml" {
                assert!(host.sandbox.check.ignored().is_empty());
            }
            for unit in units {
                assert!(
                    host.sandbox.stop_services.iter().any(|s| s == unit),
                    "{name}: {unit}"
                );
            }
            assert_eq!(Config::from(host), Config::parse(&text).unwrap());
        }
        assert_eq!(Config::from(HostConfig::default()), Config::default());
        for text in [
            "[inference]\nurl = \"http://proxy.example:18080\"",
            "[agent]\nname = \"claude\"",
            "[child-agent]\nname = \"vibe\"",
            "[limits]\ntimeout-minutes = 10",
            "[commit]\nauthor = \"A Bot <bot@example.com>\"",
            "[session]\nlisten = true",
            "[mcp.docs]\nurl = \"https://mcp.example\"",
            "[sandbx]\nlock-runner = true",
            "[host]\nusr = \"x\"",
            "[sandbox]\nusr = \"x\"",
            "[host.check]\nusr = \"x\"",
            "[host]\n[sandbox]",
        ] {
            assert!(HostConfig::parse(text).is_err(), "{text:?} parsed");
        }
    }

    /// `[sandbox]`, `[host]`'s deprecated name, reads as `[host]` in a
    /// run's file and a host's alike: defaults, explicit opt-outs, the
    /// nested check table and validation. Both names together are
    /// refused, empty or not, by either reader.
    #[test]
    fn the_host_tables_old_name_reads_as_the_new_one() {
        let run = "[agent]\nname = \"claude\"\n[limits]\ntimeout-minutes = 10\n";
        for body in [
            "",
            "lock-runner = true\n",
            "lock-runner = false\ndeny-runner-metadata = false\n",
            "deny-runner-metadata = false\nunlink-worker-diagnostics = false\n\
             deny-runner-reads = false\nclose-resolved = false\n",
            "runner-user = \"runner\"\nprivate-dirs = [\"/srv\"]\n\
             stop-services = [\"docker.service\"]\nenv = { LANG = \"C.UTF-8\" }\n\
             [NAME.check]\ncontainers = false\ncontainer-image = \"quay.io/x/curl\"\n",
            "[NAME.check]\n",
        ] {
            let text = |name: &str| format!("[{name}]\n{}", body.replace("NAME", name));
            let (new, old) = (text(HOST_TABLE), text(LEGACY_HOST_TABLE));
            let host = HostConfig::parse(&new).unwrap();
            assert_eq!(host, HostConfig::parse(&old).unwrap(), "{body:?}");
            host.sandbox.validate().unwrap();
            let full = |text: &str| Config::parse(&format!("{run}{text}")).unwrap();
            assert_eq!(full(&new), full(&old), "{body:?}");
            assert_eq!(full(&new).sandbox, host.sandbox);
        }
        assert_eq!(
            HostConfig::parse("[host]\n").unwrap(),
            HostConfig::default()
        );
        assert_eq!(
            HostConfig::parse("[sandbox]\n").unwrap(),
            HostConfig::default()
        );
        let both = "[host] and [sandbox], its deprecated name, are both set";
        for (text, want) in [
            ("[host]\n[sandbox]\n", both),
            ("[sandbox]\n[host]\nlock-runner = false\n", both),
            ("[sandbox.check]\n[host]\n", both),
            ("[host]\nrunner-user = \"root\"\n", "host.runner-user"),
            ("[sandbox]\nrunner-user = \"root\"\n", "host.runner-user"),
            (
                "[sandbox]\nlock-runner = false\ndeny-runner-reads = true\n",
                "host.deny-runner-reads needs host.lock-runner",
            ),
            (
                "[sandbox.check]\ncontainer-image = \"-x\"\n",
                "host.check.container-image",
            ),
        ] {
            for err in [
                Config::parse(text).and_then(|config| config.sandbox.validate()),
                HostConfig::parse(text).and_then(|config| config.sandbox.validate()),
            ] {
                let err = format!("{:#}", err.unwrap_err());
                assert!(err.contains(want), "{text:?}: {err}");
            }
        }
    }

    /// A misspelled key must not silently leave a protection at its default.
    #[test]
    fn unknown_keys_and_values_are_refused() {
        let cases = [
            "[host]\nusr = \"x\"",
            "[sandbox]\nusr = \"x\"",
            "[host]\n[sandbox]",
            "[sandbx]\nlock-runner = true",
            "[inference]\nregister = \"oidc\"",
            "[inference]\nprovider = \"mistral\"",
            "[limits]\ntimeout = 5",
            "[limits]\nmax-requests = -1",
        ];
        for text in cases {
            assert!(Config::parse(text).is_err(), "{text:?} parsed");
        }
    }
}
