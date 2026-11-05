//! The tables of a host's configuration that the host setup reads, as
//! agentic-job's `--config` file and a host's own file both have them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail, ensure};
use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::network::Direct;

/// Where `sandbox setup` puts the root-owned copy.
pub const ROOT_COPY: &str = "/etc/agentic-job/config.toml";

/// A host's configuration file as the program built on this crate has
/// it: these tables and any of its own, read and checked as that program
/// does. The helper reads the root-owned copy ([`ROOT_COPY`]) through
/// it. agentic-job's `Config`, with its run tables, is one.
pub trait HostFile: Sized {
    /// Reads the file at PATH.
    fn load(path: &Path) -> Result<Self>;

    fn sandbox(&self) -> &Sandbox;

    fn egress(&self) -> &Egress;

    /// Checks the tables that set up the host, as setup does, and
    /// returns where the network rules let a connection go without the
    /// egress proxy.
    fn direct(&self) -> Result<Vec<Direct>>;

    /// The helper's `session-serve`, as root: what the program has the
    /// host serve for a session, decided by this file alone. Refused
    /// unless the program has one.
    fn session_serve(&self) -> Result<()> {
        bail!("this program serves no session")
    }
}

/// What is closed to the runner's user, the only one an agent runs as,
/// and what `sandbox check` probes with. Step 5.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Sandbox {
    /// Keys of the second user setup no longer makes, read only to be
    /// refused by name ([`Sandbox::refuse_removed`]) rather than as
    /// unknown.
    #[serde(rename = "create-user")]
    removed_create_user: Option<IgnoredAny>,
    #[serde(rename = "user")]
    removed_user: Option<IgnoredAny>,
    #[serde(rename = "groups")]
    removed_groups: Option<IgnoredAny>,
    #[serde(rename = "allow-existing-user")]
    removed_allow_existing_user: Option<IgnoredAny>,
    #[serde(rename = "filesystem-view")]
    removed_filesystem_view: Option<IgnoredAny>,
    /// Whose home is closed. `sandbox setup` takes it from `SUDO_USER`
    /// when this is not set.
    pub runner_user: Option<String>,
    /// Whether `sandbox setup` ends by taking root away from the runner's
    /// user, leaving it the one sudo rule for the helper
    /// ([`crate::helper`]). On by default; off only for a machine that
    /// must keep root for the runner's user after the job, which the
    /// docs say is no machine an agent should run on.
    pub lock_runner: bool,
    /// Whether the network rules refuse the runner's user (and its
    /// subordinate uids) the cloud metadata service: a step of the job,
    /// the agent or a third-party action
    /// among them, then cannot ask it for the instance's identity or a
    /// cloud role's credentials. Unset, [`Self::lock_runner`]'s value
    /// ([`Self::deny_runner_metadata`]); needs it, since with sudo the
    /// runner's user could remove the rule.
    pub deny_runner_metadata: Option<bool>,
    /// Whether `sandbox setup` unlinks the .NET diagnostic sockets of
    /// GitHub's `Runner.Worker`, through which any step, as the Worker's
    /// own user, could have it dump its memory and the job's secrets with
    /// it, around Yama ([`crate::worker_diagnostics`]). Unset,
    /// [`Self::lock_runner`]'s value ([`Self::unlink_worker_diagnostics`]);
    /// needs it, since with sudo the runner's user reads the Worker's
    /// memory anyway.
    pub unlink_worker_diagnostics: Option<bool>,
    /// Whether the secure-host image loads the world-write policy with
    /// its runner-read rule on (`secure-host world-write
    /// --deny-runner-reads`), so that a step cannot read the environment,
    /// and the tokens in it, of a process an earlier step left running.
    /// Only the image reads it (agentic-job's `secure_host::image`), and
    /// it refuses a host with no single `Runner.Worker` to exempt. Unset,
    /// [`Self::lock_runner`]'s value ([`Self::deny_runner_reads`]); needs
    /// it, since with sudo the runner's user could clear the rule's map.
    pub deny_runner_reads: Option<bool>,
    /// Whether `sandbox setup` closes systemd-resolved to every user but
    /// root and, on the bus, the runner's. resolved answers any local user over its
    /// Varlink socket and the system bus, as itself, so the uid rules do
    /// not stop a user sending names out through it, around the egress
    /// proxy. Off by default; a host without resolved has
    /// nothing to close.
    pub close_resolved: bool,
    /// More directories closed to every user but their owner, besides
    /// the runner user's home and [`Sandbox::ALWAYS_PRIVATE_DIRS`]. One
    /// that does not exist is skipped.
    pub private_dirs: Vec<PathBuf>,
    /// systemd units stopped and masked until reboot by `sandbox setup`,
    /// a container daemon for one, with the units that trigger them.
    pub stop_services: Vec<String>,
    /// Variables every command of the agent gets, over the fixed ones
    /// (agentic-job's `run::enter`).
    pub env: BTreeMap<String, String>,
    pub check: SandboxCheck,
}

impl Sandbox {
    /// The second user's name before agentic-job#2989, which `sandbox
    /// probe` makes sure no setup created.
    pub const REMOVED_USER: &'static str = "runner-sandbox";

    /// What [`Self::refuse_removed`] says of a key of the removed second
    /// user.
    pub const REMOVED_KEY: &'static str = "was removed with the sandbox user \
         (agentic-job#2989): the runner's user is the only agent user and setup creates no \
         other, so delete the key";

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

    /// Refuses a key of the removed second user, by name, rather than
    /// ignore it: a file that still asks for that user is not run as if
    /// it had one. Called on every parse and again by [`Self::validate`].
    pub fn refuse_removed(&self) -> Result<()> {
        let removed = [
            ("create-user", &self.removed_create_user),
            ("user", &self.removed_user),
            ("groups", &self.removed_groups),
            ("allow-existing-user", &self.removed_allow_existing_user),
            ("filesystem-view", &self.removed_filesystem_view),
        ];
        if let Some((key, _)) = removed.iter().find(|(_, set)| set.is_some()) {
            bail!("sandbox.{key} {}", Self::REMOVED_KEY);
        }
        self.check.refuse_removed()
    }

    /// What the types cannot say. The runner user's name goes into a
    /// sudoers file and a polkit rule, so it is held to the portable
    /// character set and not to what `useradd` happens to accept.
    pub fn validate(&self) -> Result<()> {
        self.refuse_removed()?;
        let name_ok = |name: &str| {
            let mut chars = name.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
                && name.len() <= 32
                && chars
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        };
        if let Some(runner) = &self.runner_user {
            ensure!(
                name_ok(runner) && runner != "root",
                "sandbox.runner-user: {runner:?} is not a user name the runner can have"
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
                "sandbox.env: {name} is refused: {}* variables are the job's, never the agent's",
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
            removed_create_user: None,
            removed_user: None,
            removed_groups: None,
            removed_allow_existing_user: None,
            removed_filesystem_view: None,
            runner_user: None,
            lock_runner: true,
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

/// What the probes run with, `[sandbox.check]`. Step 5.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct SandboxCheck {
    /// A small image that has `curl`, for agentic-job's probes from a
    /// container.
    pub container_image: String,
    /// Whether those probes pull and run `container-image`.
    pub containers: bool,
    /// `run`'s repeat of the removed sandbox user's probes, read only to
    /// be refused by name ([`Sandbox::refuse_removed`]).
    #[serde(rename = "before-agent")]
    removed_before_agent: Option<IgnoredAny>,
    /// Settings of the removed sandbox user's probes, which this binary
    /// no longer reads ([`Self::ignored`]). Accepted, not refused, while
    /// the pinned secure-host image still makes those probes: its hosts'
    /// files must keep them until that image is past agentic-job#2989.
    #[serde(rename = "control-url")]
    legacy_control_url: Option<IgnoredAny>,
    #[serde(rename = "fetch-repo")]
    legacy_fetch_repo: Option<IgnoredAny>,
    #[serde(rename = "allow-sockets")]
    legacy_allow_sockets: Option<IgnoredAny>,
    #[serde(rename = "allow-tcp-ports")]
    legacy_allow_tcp_ports: Option<IgnoredAny>,
}

impl SandboxCheck {
    pub const DEFAULT_CONTAINER_IMAGE: &'static str =
        "registry.access.redhat.com/ubi10/ubi-minimal";

    fn refuse_removed(&self) -> Result<()> {
        ensure!(
            self.removed_before_agent.is_none(),
            "sandbox.check.before-agent {}",
            Sandbox::REMOVED_KEY
        );
        Ok(())
    }

    /// The keys a file sets that only the removed sandbox user's probes
    /// read, for `sandbox check` to say it ignores them.
    pub fn ignored(&self) -> Vec<&'static str> {
        [
            ("control-url", &self.legacy_control_url),
            ("fetch-repo", &self.legacy_fetch_repo),
            ("allow-sockets", &self.legacy_allow_sockets),
            ("allow-tcp-ports", &self.legacy_allow_tcp_ports),
        ]
        .into_iter()
        .filter_map(|(key, set)| set.is_some().then_some(key))
        .collect()
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.container_image.is_empty() && !self.container_image.starts_with('-'),
            "sandbox.check.container-image: {:?} is not an image name",
            self.container_image
        );
        Ok(())
    }
}

impl Default for SandboxCheck {
    fn default() -> Self {
        Self {
            container_image: Self::DEFAULT_CONTAINER_IMAGE.to_owned(),
            containers: true,
            removed_before_agent: None,
            legacy_control_url: None,
            legacy_fetch_repo: None,
            legacy_allow_sockets: None,
            legacy_allow_tcp_ports: None,
        }
    }
}

/// The host's way out to the network.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Egress {
    /// Whether setup starts the egress proxy, which
    /// [`Self::write_policy`] holds the runner's user to.
    pub proxy: bool,
    /// URLs reached directly and not through the egress proxy: the
    /// inference proxy, so that the run token never crosses the egress
    /// proxy. Each is an IPv4 address on the tailnet, with a port; under
    /// [`Self::write_policy`] the runner's user reaches each and no other
    /// tailnet address.
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
