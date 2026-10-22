//! The `--config` file: one TOML file for a run, with a table per
//! concern. `sandbox setup` reads the caller's file and copies it to
//! [`ROOT_COPY`]; `run` reads only that copy, which the sandbox user
//! cannot change.
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

/// Where `sandbox setup` puts the root-owned copy.
pub const ROOT_COPY: &str = "/etc/agentic-job/config.toml";

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
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
        toml::from_str(text).context("parsing the configuration")
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
    pub sandbox: Sandbox,
    pub egress: Egress,
    pub setup: Setup,
}

impl HostConfig {
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).context("parsing the host configuration")
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

/// The sandbox user, what is closed to it, and what `sandbox check`
/// probes with. Step 5.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Sandbox {
    /// Whether `sandbox setup` creates the sandbox user, the separate uid
    /// an agent runs as and `helper enter` is the one way into. On by
    /// default. Off, the host hardens the runner's own user alone (the
    /// lock, the metadata rule, the egress proxy and the rest): for plain
    /// CI that runs nothing as another user, which then has no account
    /// with a home, subordinate uids and a session to leave anything in.
    pub create_user: bool,
    pub user: String,
    /// Supplementary groups of the sandbox user; unset,
    /// [`Self::DEFAULT_GROUPS`] ([`Self::groups`]).
    pub groups: Option<Vec<String>>,
    /// An image may ship the sandbox user; otherwise one that exists
    /// means an earlier job left it, and `sandbox setup` refuses.
    pub allow_existing_user: bool,
    /// Whose home is closed. `sandbox setup` takes it from `SUDO_USER`
    /// when this is not set.
    pub runner_user: Option<String>,
    /// Whether `sandbox setup` ends by taking root away from the runner's
    /// user, leaving it the one sudo rule for the helper
    /// (`sandbox::helper`). On by default; off only for a machine that
    /// must keep root for the runner's user after the job, which the
    /// docs say is no machine an agent should run on.
    pub lock_runner: bool,
    /// Confine the sandbox user's commands to a read-only view of the host,
    /// writable only in its home and the temporary directories. Off by
    /// default; the world-write policy applies either way.
    pub filesystem_view: bool,
    /// Whether the network rules also refuse the runner's user (and its
    /// subordinate uids) the cloud metadata service, as they always
    /// refuse the sandbox user: a step of the job, a third-party action
    /// among them, then cannot ask it for the instance's identity or a
    /// cloud role's credentials. Unset, [`Self::lock_runner`]'s value
    /// ([`Self::deny_runner_metadata`]); needs it, since with sudo the
    /// runner's user could remove the rule.
    pub deny_runner_metadata: Option<bool>,
    /// Whether `sandbox setup` unlinks the .NET diagnostic sockets of
    /// GitHub's `Runner.Worker`, through which any step, as the Worker's
    /// own user, could have it dump its memory and the job's secrets with
    /// it, around Yama (`sandbox::worker_diagnostics`). Unset,
    /// [`Self::lock_runner`]'s value ([`Self::unlink_worker_diagnostics`]);
    /// needs it, since with sudo the runner's user reads the Worker's
    /// memory anyway.
    pub unlink_worker_diagnostics: Option<bool>,
    /// Whether the secure-host image loads the world-write policy with
    /// its runner-read rule on (`secure-host world-write
    /// --deny-runner-reads`), so that a step cannot read the environment,
    /// and the tokens in it, of a process an earlier step left running.
    /// Only the image reads it (`secure_host::image`), and it refuses a
    /// host with no single `Runner.Worker` to exempt. Unset,
    /// [`Self::lock_runner`]'s value ([`Self::deny_runner_reads`]); needs
    /// it, since with sudo the runner's user could clear the rule's map.
    pub deny_runner_reads: Option<bool>,
    /// Whether `sandbox setup` closes systemd-resolved to every user but
    /// root and, on the bus, the runner's. resolved answers any local user over its
    /// Varlink socket and the system bus, as itself, so the uid rules do
    /// not stop the sandbox user sending names out through it, around
    /// the egress proxy. Off by default; a host without resolved has
    /// nothing to close.
    pub close_resolved: bool,
    /// More directories closed to every user but their owner, besides
    /// the runner user's home and [`Sandbox::ALWAYS_PRIVATE_DIRS`]. One
    /// that does not exist is skipped.
    pub private_dirs: Vec<PathBuf>,
    /// systemd units stopped and masked until reboot by `sandbox setup`,
    /// a container daemon for one, with the units that trigger them.
    pub stop_services: Vec<String>,
    /// Variables every command of the sandbox user gets, over the fixed
    /// ones (see `sandbox::enter`).
    pub env: BTreeMap<String, String>,
    pub check: SandboxCheck,
}

impl Sandbox {
    /// The old tree's name, which its readers and docs know.
    pub const DEFAULT_USER: &'static str = "runner-sandbox";

    /// `/dev/kvm` is what the work this was built for needs. Not
    /// `libvirt`: its polkit rule grants all of `qemu:///system`.
    pub const DEFAULT_GROUPS: &'static [&'static str] = &["kvm"];

    /// The hosted compute agent's token on some runner images, and
    /// tailscaled's socket, whose API dials the tailnet for any user.
    /// Closed whatever the configuration says.
    pub const ALWAYS_PRIVATE_DIRS: &'static [&'static str] = &["/opt/hca", "/var/run/tailscale"];

    /// Membership of these is root by another name, or reads what the
    /// sandbox is there to keep from the agent.
    pub const FORBIDDEN_GROUPS: &'static [&'static str] = &[
        "root",
        "wheel",
        "sudo",
        "admin",
        "adm",
        "disk",
        "shadow",
        "docker",
        "podman",
        "lxd",
        "incus",
        "incus-admin",
        "libvirt",
        "systemd-journal",
    ];

    /// Variables that let a process ask for the job's identity token.
    pub const FORBIDDEN_ENV_PREFIX: &'static str = "ACTIONS_";

    pub fn groups(&self) -> Vec<String> {
        self.groups.clone().unwrap_or_else(|| {
            Self::DEFAULT_GROUPS
                .iter()
                .map(|&group| group.to_owned())
                .collect()
        })
    }

    pub fn deny_runner_metadata(&self) -> bool {
        self.deny_runner_metadata.unwrap_or(self.lock_runner)
    }

    pub fn unlink_worker_diagnostics(&self) -> bool {
        self.unlink_worker_diagnostics.unwrap_or(self.lock_runner)
    }

    pub fn deny_runner_reads(&self) -> bool {
        self.deny_runner_reads.unwrap_or(self.lock_runner)
    }

    /// The rules that confine the runner's own user beyond the lock, by
    /// key, whether each is on, and what every later step of the job can
    /// still do without it.
    pub fn runner_rules(&self) -> [(&'static str, bool, &'static str); 3] {
        [
            (
                "deny-runner-metadata",
                self.deny_runner_metadata(),
                "reaches the cloud metadata service, the instance's identity and a cloud role's credentials",
            ),
            (
                "unlink-worker-diagnostics",
                self.unlink_worker_diagnostics(),
                "can have Runner.Worker dump its memory, and the job's secrets, through its .NET diagnostic sockets",
            ),
            (
                "deny-runner-reads",
                self.deny_runner_reads(),
                "reads the environment, and the tokens in it, of a process an earlier step left running",
            ),
        ]
    }

    /// Why each rule a locked host's file turned off leaves the runner's
    /// user less confined, for setup and check to say. Without the lock,
    /// setup's message about it covers them.
    pub fn runner_rule_opt_outs(&self, runner: &str) -> Vec<String> {
        if !self.lock_runner {
            return Vec::new();
        }
        self.runner_rules()
            .into_iter()
            .filter(|(_, on, _)| !on)
            .map(|(key, _, off)| format!("sandbox.{key} = false: {runner} {off}"))
            .collect()
    }

    /// What the types cannot say. The user's name goes into a sudoers
    /// file and a polkit rule, so it is held to the portable character
    /// set and not to what `useradd` happens to accept.
    fn validate(&self) -> Result<()> {
        let name_ok = |name: &str| {
            let mut chars = name.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
                && name.len() <= 32
                && chars
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        };
        ensure!(
            name_ok(&self.user) && self.user != "root",
            "sandbox.user: {:?} is not a user name the sandbox can have",
            self.user
        );
        if let Some(runner) = &self.runner_user {
            ensure!(
                name_ok(runner) && *runner != self.user,
                "sandbox.runner-user: {runner:?} must be a user other than the sandbox user"
            );
        }
        ensure!(
            self.lock_runner || !self.deny_runner_metadata(),
            "sandbox.deny-runner-metadata needs sandbox.lock-runner: a runner's user with sudo could remove the rule"
        );
        ensure!(
            self.lock_runner || !self.unlink_worker_diagnostics(),
            "sandbox.unlink-worker-diagnostics needs sandbox.lock-runner: a runner's user with sudo reads the Worker's memory anyway"
        );
        ensure!(
            self.lock_runner || !self.deny_runner_reads(),
            "sandbox.deny-runner-reads needs sandbox.lock-runner: a runner's user with sudo could clear the rule"
        );
        // What only the sandbox user has, which nothing would make.
        ensure!(
            self.create_user || !self.allow_existing_user,
            "sandbox.allow-existing-user needs sandbox.create-user: without it there is no sandbox user to take from the image"
        );
        ensure!(
            self.create_user || !self.filesystem_view,
            "sandbox.filesystem-view needs sandbox.create-user: the view confines the sandbox user's commands"
        );
        ensure!(
            self.create_user || self.groups.as_ref().is_none_or(Vec::is_empty),
            "sandbox.groups needs sandbox.create-user: they are the sandbox user's groups"
        );
        for group in &self.groups() {
            ensure!(
                name_ok(group),
                "sandbox.groups: {group:?} is not a group name"
            );
            ensure!(
                !Self::FORBIDDEN_GROUPS.contains(&group.as_str()),
                "sandbox.groups: membership of {group} would give the sandbox user root or the host's secrets"
            );
        }
        for dir in &self.private_dirs {
            ensure!(
                dir.is_absolute(),
                "sandbox.private-dirs: {} is not an absolute path",
                dir.display()
            );
        }
        for unit in &self.stop_services {
            ensure!(
                unit.contains('.') && !unit.starts_with('-') && !unit.contains(char::is_whitespace),
                "sandbox.stop-services: {unit:?} is not a unit name such as docker.service"
            );
        }
        for (name, value) in &self.env {
            ensure!(
                !name.is_empty()
                    && !name.starts_with(|c: char| c.is_ascii_digit())
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "sandbox.env: {name:?} is not a variable name"
            );
            ensure!(
                !name.starts_with(Self::FORBIDDEN_ENV_PREFIX),
                "sandbox.env: {name} is refused: {}* variables are the job's, never the sandbox user's",
                Self::FORBIDDEN_ENV_PREFIX
            );
            ensure!(
                !value.contains(['\0', '\n']),
                "sandbox.env: the value of {name} has a newline or NUL in it"
            );
        }
        self.check.validate()
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self {
            create_user: true,
            user: Self::DEFAULT_USER.to_owned(),
            groups: None,
            allow_existing_user: false,
            runner_user: None,
            lock_runner: true,
            filesystem_view: false,
            deny_runner_metadata: None,
            unlink_worker_diagnostics: None,
            deny_runner_reads: None,
            close_resolved: false,
            private_dirs: Vec::new(),
            stop_services: Vec::new(),
            env: BTreeMap::new(),
            check: SandboxCheck::default(),
        }
    }
}

/// What `sandbox check` probes with, `[sandbox.check]`. Step 5.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct SandboxCheck {
    /// A public page the sandbox user must reach: the positive control
    /// of every probe that expects a connection to fail.
    pub control_url: String,
    /// A small image that has `curl`, for the probes from a container.
    pub container_image: String,
    /// Unix sockets the sandbox user may connect to, besides the host's
    /// own (`sandbox::check` has that list): a path, a directory ending
    /// in `/` for everything under it, a path ending in `*` for every
    /// path that starts so, or `@name` for an abstract one.
    pub allow_sockets: Vec<String>,
    /// Local TCP ports the sandbox user may connect to.
    pub allow_tcp_ports: Vec<u16>,
    /// Whether `run` makes these probes again once it has cloned the
    /// target, before it registers the run, and also tries to read the
    /// run token from a rootless container as a subordinate uid. Off, the run action's `sandbox check
    /// --unless-passed` before `run` is the last full check: what the
    /// sandbox user did in `run`'s own preparation (the clone, the
    /// agent's files), and a token that a container's other uids could
    /// read, would go unprobed. It costs a full check's time.
    pub before_agent: bool,
}

impl SandboxCheck {
    pub const DEFAULT_CONTROL_URL: &'static str = "https://github.com/";

    pub const DEFAULT_CONTAINER_IMAGE: &'static str =
        "registry.access.redhat.com/ubi10/ubi-minimal";

    fn validate(&self) -> Result<()> {
        ensure!(
            self.control_url.starts_with("https://") || self.control_url.starts_with("http://"),
            "sandbox.check.control-url: {:?} is not an http or https URL",
            self.control_url
        );
        ensure!(
            !self.container_image.is_empty() && !self.container_image.starts_with('-'),
            "sandbox.check.container-image: {:?} is not an image name",
            self.container_image
        );
        for socket in &self.allow_sockets {
            ensure!(
                socket.starts_with('/') || socket.starts_with('@'),
                "sandbox.check.allow-sockets: {socket:?} is neither a path nor an @abstract name"
            );
        }
        Ok(())
    }
}

impl Default for SandboxCheck {
    fn default() -> Self {
        Self {
            control_url: Self::DEFAULT_CONTROL_URL.to_owned(),
            container_image: Self::DEFAULT_CONTAINER_IMAGE.to_owned(),
            allow_sockets: Vec::new(),
            allow_tcp_ports: Vec::new(),
            before_agent: false,
        }
    }
}

/// The sandbox user's way out to the network. Step 5.
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
    /// Run as the sandbox user, never as root: for toolchains.
    pub script: Option<PathBuf>,
    /// Trusted caller-selected tools, installed before network lockdown.
    pub tools: Option<Tools>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Tools {
    pub repository: String,
    pub revision: String,
    pub recipe: String,
}

impl Tools {
    fn validate(&self) -> Result<()> {
        // A moving ref would let a later repository compromise replace host
        // setup code without a caller configuration change.
        ensure!(
            self.revision.len() == 40 && self.revision.bytes().all(|b| b.is_ascii_hexdigit()),
            "setup.tools.revision must be a full 40-digit commit pin"
        );
        ensure!(
            self.repository.starts_with("https://")
                && self.repository.len() > "https://".len()
                && !self.repository.contains(char::is_whitespace)
                && !self.repository.contains(['\0', '@', '?', '#']),
            "setup.tools.repository must be a public HTTPS clone URL without credentials"
        );
        ensure!(
            !self.recipe.is_empty()
                && self.recipe.len() <= 64
                && self
                    .recipe
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                && !self.recipe.starts_with('-'),
            "setup.tools.recipe must be one just recipe name"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tools_tests {
    use super::*;

    #[test]
    fn tools_are_opt_in_and_reject_unpinned_or_option_like_settings() {
        assert!(Config::parse("").unwrap().setup.tools.is_none());
        for (repository, revision, recipe, accepted) in [
            (
                "https://example.org/tools.git",
                "a".repeat(40),
                "install-tools",
                true,
            ),
            (
                "https://example.org/tools.git",
                "main".into(),
                "install-tools",
                false,
            ),
            (
                "https://example.org/tools.git",
                "g".repeat(40),
                "install-tools",
                false,
            ),
            (
                "https://token@example.org/tools.git",
                "a".repeat(40),
                "install-tools",
                false,
            ),
            ("file:///tmp/tools", "a".repeat(40), "install-tools", false),
            (
                "https://example.org/tools.git",
                "a".repeat(40),
                "--evaluate",
                false,
            ),
            (
                "https://example.org/tools.git",
                "a".repeat(40),
                "install tools",
                false,
            ),
        ] {
            let text = format!(
                "[setup.tools]\nrepository = {repository:?}\nrevision = {revision:?}\nrecipe = {recipe:?}\n"
            );
            let config = Config::parse(&text).unwrap();
            assert_eq!(config.setup.validate().is_ok(), accepted, "{text}");
        }
        assert!(
            Config::parse("[setup.tools]\nrepository = 'https://example.org/tools.git'").is_err()
        );
    }
}

impl Setup {
    /// A name is handed to a package manager run as root, so it must not
    /// read as an option; and an agent program without an exact version
    /// is whatever the registry serves that day.
    fn validate(&self) -> Result<()> {
        if let Some(tools) = &self.tools {
            tools.validate()?;
        }
        let plain = |name: &str| {
            !name.is_empty() && !name.starts_with('-') && !name.contains(char::is_whitespace)
        };
        for package in &self.packages {
            ensure!(
                plain(package),
                "setup.packages: {package:?} is not a package name"
            );
        }
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
    /// Who the commit is by, as `Name <address>`. Without it,
    /// `agent <agent@localhost>`, as in the old tree.
    pub author: Option<String>,
    /// Lines put at the end of the commit's message, each `Key: value`:
    /// `Generated-by: AI`, for one.
    pub trailers: Vec<String>,
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
    /// How long the session waits for the client's next prompt. Zero
    /// means the default.
    pub idle_minutes: u64,
    /// Whether the session watches the run's item (`run --watch-item`)
    /// and passes its new comments and body edits to the agent
    /// (`session::steer`). Off by default.
    pub watch_item: bool,
    /// How often it polls the item, in seconds. Zero means the default.
    pub watch_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
        [sandbox]
        user = "agent"
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
    fn empty_is_the_defaults() {
        let config = Config::parse("").unwrap();
        assert_eq!(config, Config::default());
        assert_eq!(config.sandbox.user, Sandbox::DEFAULT_USER);
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
            [sandbox]
            groups = ["kvm", "render"]
            runner-user = "runner"
            deny-runner-metadata = true
            unlink-worker-diagnostics = true
            deny-runner-reads = true
            close-resolved = true
            private-dirs = ["/opt/hca"]
            stop-services = ["docker.socket", "docker.service"]
            env = { PATH = "/home/agent/.cargo/bin:/usr/bin" }
            [sandbox.check]
            allow-sockets = ["/run/snapd.socket", "/run/pcscd/", "@ISCSIADM_ABSTRACT_NAMESPACE"]
            allow-tcp-ports = [3128]
            before-agent = true
            [setup]
            packages = ["just", "gcc-c++"]
            npm = ["opencode-ai@1.2.3", "@agentclientprotocol/claude-agent-acp@0.4.0-beta.1"]
            agents = ["opencode-ai@1.18.35"]
        "#;
        let config = Config::parse(good).unwrap();
        assert!(config.sandbox.check.before_agent);
        assert!(!Config::default().sandbox.check.before_agent);
        config.sandbox.validate().unwrap();
        config.setup.validate().unwrap();
        assert_eq!(config.sandbox.groups(), ["kvm", "render"]);
        Config::default().sandbox.validate().unwrap();
        // The sandbox user is made unless a host opts out; without it the
        // default groups mean nothing, and none named is no group at all.
        assert!(Config::default().sandbox.create_user);
        assert_eq!(Config::default().sandbox.groups(), Sandbox::DEFAULT_GROUPS);
        for text in [
            "[sandbox]\ncreate-user = false",
            "[sandbox]\ncreate-user = false\ngroups = []",
            "[sandbox]\ncreate-user = true\ngroups = []",
        ] {
            let sandbox = Config::parse(text).unwrap().sandbox;
            sandbox
                .validate()
                .unwrap_or_else(|err| panic!("{text:?}: {err:#}"));
        }
        assert!(Config::parse("[sandbox]\ncreate_user = false").is_err());

        let bad = [
            "[sandbox]\nuser = \"root\"",
            "[sandbox]\nuser = \"a b\"",
            "[sandbox]\nuser = \"x) ALL=(ALL) NOPASSWD: ALL #\"",
            "[sandbox]\nuser = \"agent\"\nrunner-user = \"agent\"",
            "[sandbox]\nlock-runner = false\ndeny-runner-metadata = true",
            "[sandbox]\nlock-runner = false\nunlink-worker-diagnostics = true",
            "[sandbox]\nlock-runner = false\ndeny-runner-reads = true",
            "[sandbox]\ncreate-user = false\nallow-existing-user = true",
            "[sandbox]\ncreate-user = false\nfilesystem-view = true",
            "[sandbox]\ncreate-user = false\ngroups = [\"kvm\"]",
            "[sandbox]\ngroups = [\"docker\"]",
            "[sandbox]\ngroups = [\"wheel\"]",
            "[sandbox]\nprivate-dirs = [\"relative\"]",
            "[sandbox]\nstop-services = [\"--now\"]",
            "[sandbox]\nstop-services = [\"docker\"]",
            "[sandbox]\nenv = { ACTIONS_ID_TOKEN_REQUEST_URL = \"x\" }",
            "[sandbox]\nenv = { \"A=B\" = \"x\" }",
            "[sandbox]\nenv = { A = \"x\\ny\" }",
            "[sandbox.check]\ncontrol-url = \"ftp://example.com\"",
            "[sandbox.check]\ncontainer-image = \"--privileged\"",
            "[sandbox.check]\nallow-sockets = [\"run/x\"]",
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

    /// The runner's rules follow the lock unless set, and a locked host's
    /// file that turns one off is told what that leaves open.
    #[test]
    fn runner_rules_follow_the_lock() {
        // The file, then whether each rule is on (metadata, diagnostics,
        // reads), then the keys of the opt-outs named.
        let cases: [(&str, [bool; 3], &[&str]); 7] = [
            ("", [true; 3], &[]),
            ("[sandbox]\nlock-runner = true", [true; 3], &[]),
            ("[sandbox]\nlock-runner = false", [false; 3], &[]),
            (
                "[sandbox]\ndeny-runner-metadata = false",
                [false, true, true],
                &["deny-runner-metadata"],
            ),
            (
                "[sandbox]\nunlink-worker-diagnostics = false",
                [true, false, true],
                &["unlink-worker-diagnostics"],
            ),
            (
                "[sandbox]\ndeny-runner-reads = false\ndeny-runner-metadata = true",
                [true, true, false],
                &["deny-runner-reads"],
            ),
            (
                "[sandbox]\nlock-runner = false\ndeny-runner-reads = false",
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
                .map(|key| format!("sandbox.{key} = false: runner "))
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
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../secure-host/hosted.toml");
        let text = std::fs::read_to_string(path).unwrap();
        let host = HostConfig::parse(&text).unwrap();
        assert!(host.sandbox.close_resolved);
        // What CI's confined job proves, with no override.
        assert!(host.sandbox.runner_rules().iter().all(|(_, on, _)| *on));
        assert_eq!(Config::from(host), Config::parse(&text).unwrap());
        assert_eq!(Config::from(HostConfig::default()), Config::default());
        for text in [
            "[inference]\nurl = \"http://proxy.example:18080\"",
            "[agent]\nname = \"claude\"",
            "[child-agent]\nname = \"vibe\"",
            "[limits]\ntimeout-minutes = 10",
            "[commit]\nauthor = \"A Bot <bot@example.com>\"",
            "[session]\nlisten = true",
            "[mcp.docs]\nurl = \"https://mcp.example\"",
            "[sandbx]\nuser = \"x\"",
            "[sandbox]\nusr = \"x\"",
        ] {
            assert!(HostConfig::parse(text).is_err(), "{text:?} parsed");
        }
    }

    /// A misspelled key must not silently leave a protection at its default.
    #[test]
    fn unknown_keys_and_values_are_refused() {
        let cases = [
            "[sandbox]\nusr = \"x\"",
            "[sandbx]\nuser = \"x\"",
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
