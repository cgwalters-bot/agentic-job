//! `agentic-job sandbox setup`: create the sandbox user and close its
//! routes to credentials and root. Run as root, once, on a machine that is
//! thrown away after the job.
//!
//! The boundary is the separate uid: it cannot read another uid's
//! processes through `/proc` or memory, and has no sudo. The rest closes what
//! runner images leave open to every local user, which starts to matter
//! once something runs as a user other than the runner's.
//!
//! Setup is the last thing that runs as root with the runner's user's own
//! sudo. It ends by taking that away ([`lock_runner`]): every step after
//! it, the supervisor (`sandbox check`, `run`) and the job's own, runs as
//! an unprivileged user that has root do only what the helper allows
//! ([`super::helper`]). docs/sandbox-check.md says what that closes and
//! how the probes prove it.

use std::fs;
use std::io::{ErrorKind, Write};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use rustix::fs::Mode;

use super::enter::{Entry, RUN0};
use super::host::{self, User};
use super::network::{self, Direct};
use super::{egress, helper, worker_diagnostics};
use crate::config::{self, Config, Sandbox};
use crate::exit::Exit;
use crate::run::agent::{self, Kind};
use crate::run::inference::Endpoint;
use crate::session::bridge::{self, Listen};

pub mod agents;
pub mod resolved;
mod tools;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The run's configuration (TOML); copied to /etc/agentic-job/
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
    /// Run the egress proxy from this podman image ID, in root podman:
    /// the secure-host image's entrypoint passes its own.
    #[arg(long, value_name = "ID")]
    pub egress_image: Option<String>,
    /// Hold the file to [`config::HostConfig`]: `secure-host setup`'s.
    #[arg(skip)]
    pub host_only: bool,
}

/// Root's: the configuration `run` reads, and what else setup leaves for
/// the supervisor. That it exists also says setup ran here before.
pub const CONFIG_DIR: &str = "/etc/agentic-job";

/// A copy of this program that the sandbox user can run: `sandbox check`
/// starts it there to see the host as that user does. The build it was
/// made from is in the runner's home, which is closed.
pub const SELF_COPY: &str = "/usr/local/libexec/agentic-job";

/// Root-owned and writable by the sandbox group alone, not world-writable,
/// so the world-write policy leaves it be: what the view must deny is the
/// sandbox's otherwise permitted writes.
pub const VIEW_PROBE_DIR: &str = "/etc/agentic-job/write-probe";

/// Root-owned, world-writable and not sticky, on the root filesystem, with
/// [`WORLD_WRITE_PROBE_FILE`] in it: what the world-write policy must keep
/// every other user from changing, which `sandbox check` tries.
pub const WORLD_WRITE_PROBE_DIR: &str = "/etc/agentic-job/world-write-probe";

/// Root-owned, mode 0666.
pub const WORLD_WRITE_PROBE_FILE: &str = "/etc/agentic-job/world-write-probe/file";

/// Where secure-host's loader (`secure-host world-write`) pins the
/// world-write policy: a link for each of its programs, and its map.
pub const WORLD_WRITE_PIN: &str = "/sys/fs/bpf/agentic-job-world-write";

/// The policy's programs, each pinned as a link under `WORLD_WRITE_PIN/links`.
pub const WORLD_WRITE_LINKS: &[&str] = &[
    "world_write_permission",
    "world_write_open",
    "world_write_file_permission",
    "world_write_setattr",
    // Inert unless the loader's `--deny-runner-reads` enables its map.
    "runner_read_check",
];

/// `[setup] script`, where the sandbox user can read it.
const SCRIPT_COPY: &str = "/etc/agentic-job/setup-script";

/// The last matching sudoers rule wins, and this file is read last.
/// No dot in the name: sudo skips such files.
const SUDOERS_DENY: &str = "/etc/sudoers.d/zz-agentic-job-sandbox";

const VISUDO_CHECK: &[&str] = &["visudo", "-q", "-c", "-f"];

/// polkit takes the first rule that answers, and reads this file first;
/// that also covers `pkexec`, and lingering, which is a polkit action.
const POLKIT_RULES_DIR: &str = "/etc/polkit-1/rules.d";

const POLKIT_DENY: &str = "/etc/polkit-1/rules.d/00-agentic-job-sandbox.rules";

/// Something that runs a user's commands later, and its lists of who may
/// use it.
struct Scheduler {
    allow: &'static str,
    deny: &'static str,
    /// Whether every user may use it when neither list exists. Then a
    /// deny list has to be made; where only root may, making one would
    /// open it to everyone the list does not name.
    open_without_lists: bool,
}

/// Nothing may start the sandbox user's processes outside a session,
/// where the supervisor cannot stop them. With neither list, Debian's
/// cron takes everyone (cronie only root, but it ships an empty deny
/// list), and at takes only root.
const SCHEDULERS: &[Scheduler] = &[
    Scheduler {
        allow: "/etc/cron.allow",
        deny: "/etc/cron.deny",
        open_without_lists: true,
    },
    Scheduler {
        allow: "/etc/at.allow",
        deny: "/etc/at.deny",
        open_without_lists: false,
    },
];

/// A group that is root by another name, through a daemon that does as
/// its members ask or a device they may write. A process keeps the groups
/// it started with whatever the user database says later, so what the
/// group leads to is closed instead, and `sandbox check` tries it.
#[derive(Debug)]
pub struct RootGroup {
    pub name: &'static str,
    /// What membership opens, for the probe's words.
    pub grants: &'static str,
    /// The units stopped when the runner's user is in the group.
    pub units: &'static [&'static str],
    /// The sockets the daemon takes orders on, which the probe tries.
    pub sockets: &'static [&'static str],
}

pub const DISK_GROUP: &str = "disk";

pub const SHADOW_GROUP: &str = "shadow";

pub const ROOT_GROUPS: &[RootGroup] = &[
    RootGroup {
        name: "docker",
        grants: "the container daemon, which starts root containers",
        units: &["docker.socket", "docker.service", "containerd.service"],
        sockets: &["/var/run/docker.sock", "/run/containerd/containerd.sock"],
    },
    RootGroup {
        name: "podman",
        grants: "root's podman service",
        units: &["podman.socket", "podman.service"],
        sockets: &["/run/podman/podman.sock"],
    },
    RootGroup {
        name: "lxd",
        grants: "the LXD daemon, which starts privileged containers",
        units: &[
            "snap.lxd.daemon.unix.socket",
            "snap.lxd.daemon.service",
            "lxd.socket",
            "lxd.service",
        ],
        sockets: &[
            "/var/snap/lxd/common/lxd/unix.socket",
            "/var/lib/lxd/unix.socket",
        ],
    },
    RootGroup {
        name: "incus",
        grants: "the Incus daemon",
        units: &["incus.socket", "incus.service"],
        sockets: &["/var/lib/incus/unix.socket"],
    },
    RootGroup {
        name: "incus-admin",
        grants: "the Incus daemon",
        units: &["incus.socket", "incus.service"],
        sockets: &["/var/lib/incus/unix.socket"],
    },
    RootGroup {
        name: "libvirt",
        grants: "libvirt's system instance, which runs VMs as root",
        units: &[
            "libvirtd.socket",
            "libvirtd.service",
            "virtqemud.socket",
            "virtqemud.service",
        ],
        sockets: &[
            "/var/run/libvirt/libvirt-sock",
            "/run/libvirt/virtqemud-sock",
        ],
    },
    RootGroup {
        name: DISK_GROUP,
        grants: "the block devices, root's filesystem among them",
        units: &[],
        sockets: &[],
    },
    RootGroup {
        name: SHADOW_GROUP,
        grants: "the password hashes",
        units: &[],
        sockets: &[],
    },
];

/// Groups that read the host's logs: a way to secrets others wrote
/// there, not to root. Noted, not closed.
pub const READ_ONLY_GROUPS: &[&str] = &["adm", "systemd-journal"];

/// Where the block devices are, for the `disk` group's closure.
const DEV: &str = "/dev";

const SHADOW_FILES: &[&str] = &["/etc/shadow", "/etc/gshadow"];

const NSSWITCH: &str = "/etc/nsswitch.conf";

/// What `passwd -S` prints for an account with no password at all, on
/// which `su` would ask nothing.
const NO_PASSWORD: &str = "NP";

/// The system crypto policy, which ssh, TLS libraries and others read.
/// Some images leave its files group- or world-writable (RHEL 10's runner
/// image has `back-ends/openssh.config` mode 0646): ssh then refuses its
/// included configuration, so plain ssh and git over ssh fail for every
/// user but the one the image was built for, and any user could weaken
/// what every program on the host accepts.
pub const CRYPTO_POLICIES: &str = "/etc/crypto-policies";

/// Most entries looked at under [`CRYPTO_POLICIES`]; a real one has tens.
const MAX_CRYPTO_POLICY_ENTRIES: usize = 4096;

const GROUP_WRITE: u32 = 0o020;

pub const OTHER_WRITE: u32 = 0o002;

/// The permission bits of a mode, without the file type.
const MODE_BITS: u32 = 0o7777;

/// Some images set `XDG_RUNTIME_DIR` to the runner's here, and PAM hands
/// it to every session, which breaks other users' session bus and
/// rootless podman (actions/runner-images#14649). The hosted images also
/// set an `ACTIONS_*` variable here, a path and no secret; it goes too,
/// so that "the sandbox user has no `ACTIONS_*` variable" has no
/// exception to argue about. The runner itself has long read the file.
const ENVIRONMENT: &str = "/etc/environment";

const IMAGE_ENV_VARS: &[&str] = &["XDG_RUNTIME_DIR"];

const PTRACE_SCOPE: &str = "/proc/sys/kernel/yama/ptrace_scope";

const SUBUID: &str = "/etc/subuid";

const RESOLV_CONF: &str = "/etc/resolv.conf";

const PRIVATE_MODE: u32 = 0o700;

/// Root's files that every user reads, and the programs and directories
/// every user enters.
const MODE_FILE: u32 = 0o644;

const MODE_PROGRAM: u32 = 0o755;

/// What sudo wants of a file in sudoers.d.
const MODE_SUDOERS: u32 = 0o440;

const ROOT_UMASK: u32 = 0o022;

/// Package mirrors time out now and then, and one timeout would
/// otherwise fail the whole run.
const INSTALL_ATTEMPTS: u32 = 4;

const INSTALL_PAUSE: Duration = Duration::from_secs(20);

pub fn run(args: &Args) -> Result<Exit> {
    let started = Instant::now();
    // Every stage is timed, so that the log accounts for all of setup's
    // time and not only for the stages that were thought slow.
    let result = setup(args);
    println!(
        "Sandbox setup total: {:.3}s ({})",
        started.elapsed().as_secs_f64(),
        if result.is_ok() { "ok" } else { "failed" }
    );
    result
}

/// What the preflight read and decided, before setup changes anything.
struct Preflight {
    /// The configuration as written, which setup installs.
    text: String,
    config: Config,
    install_vibe: bool,
    direct: Vec<Direct>,
    /// What the egress proxy refuses the sandbox user: `inference.front`'s
    /// broker.
    refused: Vec<(String, u16)>,
    /// A session run's: its bridge is served on the tailnet.
    session: Option<Listen>,
    runner: User,
    /// The sandbox user, where the image ships it and that is allowed.
    existing: Option<User>,
    /// The resolvers the egress proxy may use: none without it.
    resolvers: Vec<IpAddr>,
}

fn setup(args: &Args) -> Result<Exit> {
    let Preflight {
        text,
        config,
        install_vibe: needs_vibe,
        direct,
        refused,
        session,
        runner,
        existing,
        resolvers,
    } = timed_setup("preflight", || {
        let text = fs::read_to_string(&args.config)
            .with_context(|| format!("reading {}", args.config.display()))?;
        let config = if args.host_only {
            config::HostConfig::parse(&text).map(Config::from)
        } else {
            Config::parse(&text)
        }
        .with_context(|| format!("in {}", args.config.display()))?;
        let config::checked::Host {
            direct,
            refused,
            session,
            install_vibe,
        } = config.check_host()?;
        if let Some(image) = &args.egress_image {
            egress::check_image_id(image)?;
            ensure!(
                !config.egress.proxy || config.egress.rust_proxy,
                "--egress-image runs the Rust proxy alone: egress.rust-proxy = false cannot run from it"
            );
        }
        ensure!(host::is_root(), "`sandbox setup` must run as root");
        ensure!(
            session.is_none() || host::has_program("tailscale"),
            "session.listen needs tailscale: the session's client reaches it over the tailnet"
        );
        ensure!(
            host::has_program(RUN0),
            "{RUN0} not found: the sandbox is entered with it, and it needs systemd {RUN0_SYSTEMD} or later"
        );
        let version = host::run(Command::new(RUN0).arg("--version"))?;
        ensure!(
            systemd_version(&version).is_some_and(|v| v >= RUN0_SYSTEMD),
            "{RUN0} is from {:?}: the sandbox is entered with `{RUN0} --pipe`, which needs systemd {RUN0_SYSTEMD} or later",
            version.lines().next().unwrap_or_default()
        );
        // Root's umask is the caller's, and some images build with 000.
        rustix::process::umask(Mode::from_raw_mode(ROOT_UMASK));
        // Before anything else is decided: a machine that was set up before
        // is refused whoever asks, and however.
        ensure!(
            !Path::new(CONFIG_DIR).exists(),
            "{CONFIG_DIR} already exists: `sandbox setup` ran on this machine before, and the sandbox needs a fresh one for every job"
        );
        let runner = runner_user(&config)?;
        // Every refusal comes before the first change.
        let existing = preflight(&config, &runner)?;
        if !config.setup.agents.is_empty() {
            agents::check_platform()?;
        }
        if config.sandbox.close_resolved {
            resolved::bus_policy(&runner.name)?;
        }
        require_world_write_policy(Path::new(WORLD_WRITE_PIN))?;
        let mut resolvers = Vec::new();
        if config.egress.proxy {
            let resolv_conf = match fs::read_to_string(RESOLV_CONF) {
                Ok(text) => text,
                Err(err) if err.kind() == ErrorKind::NotFound => String::new(),
                Err(err) => return Err(err).with_context(|| format!("reading {RESOLV_CONF}")),
            };
            resolvers = network::resolvers(&resolv_conf)
                .with_context(|| format!("reading resolvers from {RESOLV_CONF}"))?;
            // A local stub (resolved's) passes on what the proxy asks to
            // its own upstream, which may be the tailnet's resolver; the
            // proxy then resolves the tailnet's names, though it cannot
            // reach them. Other stubs (dnsmasq) keep their upstream
            // elsewhere and are not read.
            for path in [RESOLV_CONF, resolved::UPSTREAM_RESOLV_CONF] {
                let text = match fs::read_to_string(path) {
                    Ok(text) => text,
                    Err(err) if err.kind() == ErrorKind::NotFound => continue,
                    Err(err) => return Err(err).with_context(|| format!("reading {path}")),
                };
                let on_tailnet = network::tailnet_resolvers(&text);
                ensure!(
                    on_tailnet.is_empty(),
                    "{path} names {} on the tailnet, which the egress proxy may not reach: join the tailnet without its DNS (tailscale up --accept-dns=false)",
                    on_tailnet.join(", ")
                );
            }
        }
        Ok(Preflight {
            text,
            config,
            install_vibe,
            direct,
            refused,
            session,
            runner,
            existing,
            resolvers,
        })
    })?;
    let sandbox = timed_setup("create-user", || {
        fs::create_dir(CONFIG_DIR).with_context(|| format!("creating {CONFIG_DIR}"))?;
        fs::set_permissions(CONFIG_DIR, fs::Permissions::from_mode(MODE_PROGRAM))
            .with_context(|| format!("setting the mode of {CONFIG_DIR}"))?;
        create_user(&config, &runner, existing)
    })?;
    // Before any sandbox mount view or user manager inherits /proc.
    timed_setup("proc-hidepid", hide_other_processes)?;
    if config.sandbox.filesystem_view {
        timed_setup("filesystem-view", || install_filesystem_view(&sandbox))?;
    }
    let (subuids, runner_uids, write_uids) = timed_setup("environment-and-private-dirs", || {
        let text = fs::read_to_string(SUBUID).with_context(|| format!("reading {SUBUID}"))?;
        let subuids = subuid_ranges(&sandbox, &text)?;
        let all_runner: Vec<String> = std::iter::once(runner.uid.to_string())
            .chain(subordinate_ranges(&runner, &text))
            .collect();
        let of = |on: bool| if on { all_runner.clone() } else { Vec::new() };
        let runner_uids = of(config.sandbox.deny_runner_metadata());
        let write_uids = of(config.egress.write_policy);
        drop_image_environment()?;
        close_private_dirs(&config, &runner)?;
        Ok((subuids, runner_uids, write_uids))
    })?;
    timed_setup("stop-services", || {
        stop_services(&config.sandbox.stop_services)
    })?;
    if config.sandbox.close_resolved {
        timed_setup("close-resolved", || resolved::close(&runner.name))?;
    }
    timed_setup("install-self", || {
        install_self()?;
        // The helper's copy, the configuration it reads and the programs it
        // runs are what the runner's one sudo rule gives root to: their
        // directories are made root's alone first, or setup refuses.
        for path in std::iter::once(SELF_COPY)
            .chain(std::iter::once(CONFIG_DIR))
            .chain(host::PATH_DIRS.iter().copied())
            .chain(host::SBIN_DIRS.iter().copied())
            .filter(|path| Path::new(path).exists())
        {
            make_roots_alone(Path::new(path))?;
        }
        Ok(())
    })?;
    timed_setup("packages", || install_packages(&config.setup.packages))?;
    timed_setup("privileged-binary-allowlist", privileged_binaries::check)?;
    timed_setup("npm", || install_npm(&config.setup.npm))?;
    timed_setup("agents", || {
        for spec in &config.setup.agents {
            agents::check_node(spec)?;
            let dir = agents::install(
                spec,
                Path::new(agents::ROOT),
                Path::new(agents::BIN_DIR),
                &agents::fetch,
            )?;
            // What /usr/local/bin now runs: no one else may replace it.
            make_roots_alone(&dir)?;
        }
        Ok(())
    })?;
    if needs_vibe {
        timed_setup("vibe", install_vibe)?;
    }
    // After the packages: one of them may be what a rule is for (polkit,
    // at), and a rule is written only for what is there. The runner's
    // rules take effect now too, which nothing running needs: the job's
    // step is waiting on this process, root already.
    timed_setup("deny-privileges", || {
        deny_privileges(
            &sandbox.name,
            config.sandbox.lock_runner.then_some(runner.name.as_str()),
        )
    })?;
    if let Some(tools) = &config.setup.tools {
        timed_setup("caller-tools", || tools::install(tools, &sandbox))?;
    }
    // The proxy first, since the rules name its uid; and both after the
    // installs, which root does on the open network.
    let proxy_uid = config
        .egress
        .proxy
        .then(|| {
            timed_setup("egress-proxy", || {
                egress::start(&config.egress, args.egress_image.as_deref(), &refused)
            })
        })
        .transpose()?;
    timed_setup("network-rules", || {
        let uids: Vec<String> = std::iter::once(sandbox.uid.to_string())
            .chain(subuids.iter().cloned())
            .collect();
        network::apply(&network::rules_with_resolvers(
            &uids,
            &direct,
            proxy_uid,
            &resolvers,
            &runner_uids,
            session.is_some().then_some(bridge::PORT),
            &write_uids,
        ))
    })?;
    // After the rules, which keep the sandbox user from what it serves.
    if session.is_some() {
        timed_setup("session-serve", serve_session)?;
    }
    if !write_uids.is_empty() {
        println!(
            "{} (uids {}) writes only where the egress proxy's rules allow: egress.write-policy",
            runner.name,
            write_uids.join(", ")
        );
    }
    if !runner_uids.is_empty() {
        println!(
            "{} (uids {}) can't reach the metadata service either: sandbox.deny-runner-metadata",
            runner.name,
            runner_uids.join(", ")
        );
    }
    match proxy_uid {
        Some(_) => println!(
            "{} reaches the network only through the egress proxy, {}",
            sandbox.name,
            egress::proxy_url()
        ),
        None => println!(
            "{} has no egress proxy: its network is open but for the metadata service and the tailnet",
            sandbox.name
        ),
    }
    timed_setup("probe-dirs", || {
        // Writable by DAC, so that the probes prove the view and the
        // world-write policy, each on a directory the other leaves alone.
        fs::create_dir(VIEW_PROBE_DIR).context("creating filesystem-view probe directory")?;
        host::run(Command::new("chown").args([&format!("root:{}", sandbox.gid), VIEW_PROBE_DIR]))?;
        fs::set_permissions(VIEW_PROBE_DIR, fs::Permissions::from_mode(0o770))?;
        // Root owns both, and the policy has no exemption but the owner's.
        fs::create_dir(WORLD_WRITE_PROBE_DIR).context("creating world-write probe directory")?;
        fs::set_permissions(WORLD_WRITE_PROBE_DIR, fs::Permissions::from_mode(0o777))?;
        install_file(Path::new(WORLD_WRITE_PROBE_FILE), b"", 0o666, None)
    })?;
    timed_setup("ssh-and-ptrace", || {
        fix_crypto_policies(Path::new(CRYPTO_POLICIES))?;
        restrict_ptrace()
    })?;
    if config.sandbox.unlink_worker_diagnostics() {
        timed_setup("worker-diagnostics", worker_diagnostics::unlink)?;
    }
    println!(
        "Sandbox user {} (uid {}, subordinate uids {}), in addition to {} whose home {} is closed to it",
        sandbox.name,
        sandbox.uid,
        subuids.join(", "),
        runner.name,
        runner.home.display()
    );
    if let Some(script) = &config.setup.script {
        timed_setup("sandbox-script", || run_setup_script(&config, script))?;
    }
    timed_setup("configuration", || {
        write_managed_settings(&config)?;
        // Late, so a setup that failed leaves nothing `sandbox check` and
        // `run` would take for a finished one; before the lock, whose proof
        // runs the helper, which reads it.
        install_file(
            Path::new(config::ROOT_COPY),
            text.as_bytes(),
            MODE_FILE,
            None,
        )
    })?;
    if config.sandbox.lock_runner {
        timed_setup("lock-runner", || lock_runner(&runner))?;
    } else {
        println!(
            "sandbox.lock-runner = false: {} keeps its sudo, and every step after this one has root",
            runner.name
        );
    }
    for line in config.sandbox.runner_rule_opt_outs(&runner.name) {
        println!("{line}");
    }
    Ok(Exit::Success)
}

/// Publishes the address. The run's trusted guard enables serve only while
/// it holds the bridge listener, and revokes it before releasing that port.
fn serve_session() -> Result<()> {
    let status: serde_json::Value = serde_json::from_str(&host::run(
        Command::new("tailscale").args(["status", "--json"]),
    )?)
    .context("reading tailscale status")?;
    let endpoint = format!("wss://{}/", session_name(&status)?);
    install_file(
        Path::new(bridge::ENDPOINT_FILE),
        format!("{endpoint}\n").as_bytes(),
        MODE_FILE,
        None,
    )?;
    println!("The session's client connects at {endpoint}");
    Ok(())
}

/// This machine's tailnet name, which must have a certificate: without
/// one, `tailscale serve --https` waits for a capability that never comes,
/// so the run would only time out later with no cause.
fn session_name(status: &serde_json::Value) -> Result<&str> {
    let name = status["Self"]["DNSName"]
        .as_str()
        .map(|name| name.trim_end_matches('.'))
        .filter(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        })
        .context("tailscale status names no DNS name for this machine")?;
    let certified = status["CertDomains"]
        .as_array()
        .is_some_and(|domains| domains.iter().any(|domain| domain.as_str() == Some(name)));
    ensure!(certified, "{}", super::session::HTTPS_DISABLED);
    Ok(name)
}

/// The agent's managed settings, root's, from the same configuration
/// `run` will read: `run` has no root to write them with. A
/// configuration that names no agent `run` could start is `run`'s to
/// refuse, not setup's.
fn write_managed_settings(config: &Config) -> Result<()> {
    let Ok(kind) = Kind::parse(&config.agent.name) else {
        return Ok(());
    };
    let endpoint = Endpoint::from_config(&config.inference)?;
    if let Some((path, content)) = agent::managed_settings(kind, endpoint.as_ref()) {
        let path = Path::new(path);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        install_file(path, content.as_bytes(), MODE_FILE, None)?;
    }
    Ok(())
}

/// The manager is a system service: its children, including socket-activated
/// user units, inherit this view even when they reset their own properties.
/// Preflight already refuses any process of this uid, so no old children can
/// keep an unrestricted namespace alive.
fn install_filesystem_view(user: &User) -> Result<()> {
    let text = super::view::manager_drop_in(user)?;
    let dir = PathBuf::from(format!("/etc/systemd/system/user@{}.service.d", user.uid));
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    install_file(
        &dir.join("agentic-job-view.conf"),
        text.as_bytes(),
        MODE_FILE,
        None,
    )?;
    host::run(Command::new("systemctl").arg("daemon-reload"))?;
    Ok(())
}

/// The user whose job this is: the one that called sudo, unless the
/// configuration names it.
fn runner_user(config: &Config) -> Result<User> {
    let name = match &config.sandbox.runner_user {
        Some(name) => name.clone(),
        None => std::env::var("SUDO_USER").ok().filter(|name| name != "root").context(
            "whose job is this? Start `sandbox setup` with sudo as the runner's user, or set sandbox.runner-user",
        )?,
    };
    let runner = User::lookup(&name)?.with_context(|| format!("no user {name}"))?;
    ensure!(
        runner.uid != 0,
        "the runner user {name} is root: there is nothing to keep from the sandbox user that root's own files do not already hold"
    );
    Ok(runner)
}

/// Where `useradd` makes homes, from its own defaults.
fn home_base() -> Result<PathBuf> {
    let defaults = host::run(Command::new("useradd").arg("-D"))?;
    Ok(defaults
        .lines()
        .find_map(|line| line.strip_prefix("HOME="))
        .map_or_else(|| PathBuf::from("/home"), PathBuf::from))
}

/// The groups of `groups`, as `id -Gn` prints them, that the sandbox
/// user must not be in.
fn forbidden_groups(groups: &str) -> Vec<&str> {
    groups
        .split_whitespace()
        .filter(|group| Sandbox::FORBIDDEN_GROUPS.contains(group))
        .collect()
}

/// Whether any process runs as `uid`. pgrep exits 1 for none; anything
/// else but 0 is pgrep not working, which must not read as none.
fn has_processes(uid: u32) -> Result<bool> {
    let status = Command::new("pgrep")
        .arg("-u")
        .arg(uid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .context("running pgrep")?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!("pgrep -u {uid} failed ({status})"),
    }
}

/// Refuses a machine that is not fresh, before anything is changed. A
/// machine that ran a job before would hand this one the previous job's
/// sandbox user, with whatever that agent left to run at its next login.
/// Returns the sandbox user if the image ships it and the configuration
/// says so.
fn preflight(config: &Config, runner: &User) -> Result<Option<User>> {
    let name = &config.sandbox.user;
    let Some(user) = User::lookup(name)? else {
        let home = home_base()?.join(name);
        ensure!(
            !home.exists(),
            "{} already exists, with no user {name}: something left it there",
            home.display()
        );
        for group in &config.sandbox.groups {
            ensure!(
                host::succeeds(Command::new("getent").args(["group", "--", group.as_str()])),
                "no group {group}: take it out of sandbox.groups if the sandbox user does not need it"
            );
        }
        return Ok(None);
    };
    ensure!(
        config.sandbox.allow_existing_user,
        "the user {name} already exists: on a fresh machine nothing has made it yet. If the image ships it, set sandbox.allow-existing-user"
    );
    // The configuration's groups were checked; the image's were not.
    let groups = host::run(Command::new("id").args(["-Gn", "--", name.as_str()]))?;
    let forbidden = forbidden_groups(&groups);
    ensure!(
        forbidden.is_empty() && user.gid != 0,
        "the user {name} is in {}: that is root by another name, or reads what the sandbox keeps from the agent",
        if forbidden.is_empty() {
            "root's group".to_owned()
        } else {
            forbidden.join(", ")
        }
    );
    ensure!(
        !has_processes(user.uid)?,
        "processes of {name} are already running"
    );
    ensure_distinct(&user, runner)?;
    if config.sandbox.filesystem_view {
        super::view::properties(&user)?;
        ensure!(
            fs::canonicalize(&user.home).is_ok_and(|path| path == user.home),
            "sandbox home {} must be a real directory, with no symlink components",
            user.home.display()
        );
    }
    Ok(Some(user))
}

/// Also by uid: another name for root or the runner is still them.
fn ensure_distinct(sandbox: &User, runner: &User) -> Result<()> {
    ensure!(
        sandbox.uid != 0 && sandbox.uid != runner.uid,
        "the sandbox user {} has uid {}, root's or {}'s",
        sandbox.name,
        sandbox.uid,
        runner.name
    );
    Ok(())
}

/// The sandbox user: the image's, or a new one with its home, a group of
/// its own, and subordinate uids and gids, which useradd assigns.
fn create_user(config: &Config, runner: &User, existing: Option<User>) -> Result<User> {
    if let Some(user) = existing {
        return Ok(user);
    }
    let name = &config.sandbox.user;
    // Hosted images seed /etc/skel with hundreds of MB of toolchains. An
    // empty private skeleton avoids copying them; useradd still sets the
    // home's mode and owner according to the host's account policy.
    // Prevent another local user from planting startup files in the skeleton.
    let skeleton = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .context("creating empty user skeleton")?;
    let mut useradd = useradd_command(config, skeleton.path());
    timed_setup("create-user-useradd", || {
        host::run(&mut useradd).map(|_| ())
    })?;
    let user = timed_setup("create-user-lookup", || {
        User::lookup(name)?.with_context(|| format!("useradd made no user {name}"))
    })?;
    ensure_distinct(&user, runner)?;
    Ok(user)
}

fn useradd_command(config: &Config, skeleton: &Path) -> Command {
    let mut useradd = Command::new("useradd");
    // This is a fresh, password-locked job account, not a recycled login.
    // Resetting lastlog/faillog can extend sparse per-UID databases; neither
    // database participates in sandbox authorization. Keep home creation,
    // the private group and ordinary (not system) subordinate-ID allocation.
    useradd.args([
        "--no-log-init",
        "--create-home",
        "--user-group",
        "--shell",
        "/bin/bash",
    ]);
    useradd.arg("--skel").arg(skeleton);
    if !config.sandbox.groups.is_empty() {
        useradd.arg("--groups").arg(config.sandbox.groups.join(","));
    }
    useradd.args(["--", config.sandbox.user.as_str()]);
    useradd
}

/// The subordinate uid ranges of `user`, each as `START-END`. Containers
/// the sandbox user starts run as these, so the network rules name them.
pub fn subuid_ranges(user: &User, subuid: &str) -> Result<Vec<String>> {
    let ranges = subordinate_ranges(user, subuid);
    ensure!(
        !ranges.is_empty(),
        "{} has no subordinate uids in {SUBUID}, which rootless podman needs",
        user.name
    );
    Ok(ranges)
}

/// [`subuid_ranges`], none being an answer: the runner's user may have
/// no rootless containers to cover.
fn subordinate_ranges(user: &User, subuid: &str) -> Vec<String> {
    // subuid(5) names the owner or gives its uid.
    let uid = user.uid.to_string();
    subuid
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let (name, start, count) = (fields.next()?, fields.next()?, fields.next()?);
            let (start, count) = (
                start.parse::<u64>().ok()?,
                count.trim().parse::<u64>().ok()?,
            );
            ((name == user.name || name == uid) && count > 0)
                .then(|| format!("{start}-{}", start + count - 1))
        })
        .collect()
}

/// The sudoers rules: the sandbox user has nothing; the runner's user,
/// when the machine is locked, nothing but the helper. The last matching
/// rule wins, so the grant follows the denial.
fn sudoers_rules(sandbox: &str, locked_runner: Option<&str>) -> String {
    let mut rules = format!("{sandbox} ALL=(ALL:ALL) !ALL\n");
    if let Some(runner) = locked_runner {
        rules.push_str(&format!(
            "{runner} ALL=(ALL:ALL) !ALL\n{runner} ALL=(root) NOPASSWD: {}\n",
            helper::sudoers_command()
        ));
    }
    rules
}

/// What `sudo -l` lists for the locked runner's user, and nothing else:
/// the probe compares.
pub fn runner_sudo_rules() -> Vec<String> {
    vec![
        "(ALL : ALL) !ALL".to_owned(),
        format!("(root) NOPASSWD: {}", helper::sudoers_command()),
    ]
}

/// One rule for every user named: polkit takes the first rule that
/// answers.
fn polkit_deny(users: &[&str]) -> String {
    let test = users
        .iter()
        .map(|user| format!("subject.user == \"{user}\""))
        .collect::<Vec<_>>()
        .join(" || ");
    format!(
        "polkit.addRule(function(action, subject) {{\n  if ({test}) return polkit.Result.NO;\n}});\n"
    )
}

/// What to add to a deny list `text` so that it names `user`, if it does
/// not already.
fn denial(text: &str, user: &str) -> Option<String> {
    if text.lines().any(|line| line.trim() == user) {
        return None;
    }
    let separator = if text.is_empty() || text.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    Some(format!("{separator}{user}\n"))
}

/// Takes away the sandbox user's sudo, its polkit actions, and every way
/// to leave a process behind for later: cron, at, and a lingering user
/// manager. With LOCKED_RUNNER, the runner's user's sudo (but for the
/// helper) and polkit actions go too.
fn deny_privileges(user: &str, locked_runner: Option<&str>) -> Result<()> {
    install_file(
        Path::new(SUDOERS_DENY),
        sudoers_rules(user, locked_runner).as_bytes(),
        MODE_SUDOERS,
        Some(VISUDO_CHECK),
    )?;
    if Path::new(POLKIT_RULES_DIR).is_dir() {
        let users: Vec<&str> = std::iter::once(user).chain(locked_runner).collect();
        install_file(
            Path::new(POLKIT_DENY),
            polkit_deny(&users).as_bytes(),
            MODE_FILE,
            None,
        )?;
    }
    for scheduler in SCHEDULERS {
        scheduler.deny(user)?;
    }
    host::run(Command::new("loginctl").args(["disable-linger", "--", user]))?;
    Ok(())
}

impl Scheduler {
    /// Keeps `user` from this scheduler. A deny list that is there is
    /// added to in place, keeping its owner and mode, which its readers
    /// depend on. One we make is world-readable: cron's own programs are
    /// not root, and one that cannot read the list allows everyone.
    fn deny(&self, user: &str) -> Result<()> {
        let (allow, deny) = (Path::new(self.allow), Path::new(self.deny));
        // An allow list is all that is read when there is one.
        match fs::read_to_string(allow) {
            Ok(allowed) => {
                ensure!(
                    !allowed.lines().any(|line| line.trim() == user),
                    "{} lists {user}: the sandbox user must not be able to schedule commands",
                    self.allow
                );
                return Ok(());
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err).with_context(|| format!("reading {}", self.allow)),
        }
        match fs::read_to_string(deny) {
            Ok(text) => denial(&text, user).map_or(Ok(()), |line| {
                fs::OpenOptions::new()
                    .append(true)
                    .open(deny)
                    .and_then(|mut file| file.write_all(line.as_bytes()))
                    .with_context(|| format!("adding {user} to {}", self.deny))
            }),
            Err(err) if err.kind() == ErrorKind::NotFound && self.open_without_lists => {
                install_file(deny, format!("{user}\n").as_bytes(), MODE_FILE, None)
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("reading {}", self.deny)),
        }
    }
}

/// Whether a variable the image sets for every session is one the
/// sandbox user's must not get.
fn image_variable(name: &str) -> bool {
    IMAGE_ENV_VARS.contains(&name) || name.starts_with(Sandbox::FORBIDDEN_ENV_PREFIX)
}

/// `text`, which is environment(5) lines, without those that set a
/// variable `dropped` names; and the names that went.
fn without_variables(text: &str, dropped: impl Fn(&str) -> bool) -> Option<(String, Vec<String>)> {
    let name = |line: &str| -> Option<String> {
        let line = line.trim_start();
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let (name, _) = line.split_once('=')?;
        dropped(name).then(|| name.to_owned())
    };
    let (gone, kept): (Vec<&str>, Vec<&str>) =
        text.split('\n').partition(|line| name(line).is_some());
    let names: Vec<String> = gone.into_iter().filter_map(name).collect();
    (!names.is_empty()).then(|| (kept.join("\n"), names))
}

fn drop_image_environment() -> Result<()> {
    let path = Path::new(ENVIRONMENT);
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        // Left unread, its variables would stay.
        Err(err) => return Err(err).with_context(|| format!("reading {ENVIRONMENT}")),
    };
    if let Some((kept, names)) = without_variables(&text, image_variable) {
        let mode = fs::metadata(path)
            .with_context(|| format!("reading the mode of {ENVIRONMENT}"))?
            .permissions()
            .mode()
            & MODE_BITS;
        install_file(path, kept.as_bytes(), mode, None)?;
        println!("Dropped {} from {ENVIRONMENT}", names.join(", "));
    }
    Ok(())
}

/// The directories the sandbox user must not see into: the runner's home,
/// which holds the runner's credentials and the job's files; the ones
/// every runner of the old tree had closed; and the configured ones. The
/// configuration adds to the list and cannot shorten it.
pub fn private_dirs(config: &Config, runner: &User) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::iter::once(runner.home.clone())
        .chain(Sandbox::ALWAYS_PRIVATE_DIRS.iter().map(PathBuf::from))
        .chain(config.sandbox.private_dirs.iter().cloned())
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    dirs.retain(|dir| seen.insert(dir.clone()));
    dirs
}

fn close_private_dirs(config: &Config, runner: &User) -> Result<()> {
    for dir in private_dirs(config, runner)
        .iter()
        .filter(|dir| dir.is_dir())
    {
        fs::set_permissions(dir, fs::Permissions::from_mode(PRIVATE_MODE))
            .with_context(|| format!("closing {}", dir.display()))?;
    }
    Ok(())
}

/// Nothing in setup takes world write away: the world-write policy,
/// loaded before it, refuses another user's change at access time. A
/// host without it is refused, as the walk that did this before refused
/// one it could not finish. Its loader proved it took effect.
fn require_world_write_policy(pin: &Path) -> Result<()> {
    let missing: Vec<&str> = WORLD_WRITE_LINKS
        .iter()
        .copied()
        .filter(|name| !pin.join("links").join(name).exists())
        .collect();
    ensure!(
        missing.is_empty(),
        "the world-write policy is not loaded ({} has no link for {}): load it first, as secure-host does with `agentic-job secure-host world-write`",
        pin.display(),
        missing.join(", ")
    );
    Ok(())
}

/// Log monotonic wall time even when a stage fails, without changing its result.
fn timed_setup<T>(stage: &str, run: impl FnOnce() -> Result<T>) -> Result<T> {
    super::timed::stage("setup", stage, run)
}

mod privileged_binaries;

/// The groups of USER, from the user database: the ones its running
/// processes carry too.
fn groups_of(user: &str) -> Result<Vec<String>> {
    let listing = host::run(Command::new("id").args(["-Gn", "--", user]))?;
    Ok(listing.split_whitespace().map(str::to_owned).collect())
}

/// `passwd -S` for USER: the account's status field, such as `NP`.
fn password_status(user: &str) -> Result<String> {
    let line = host::run(Command::new("passwd").args(["-S", "--", user]))?;
    line.split_whitespace()
        .nth(1)
        .map(str::to_owned)
        .with_context(|| format!("passwd -S printed {line:?} for {user}"))
}

/// Takes root away from the runner's user, whose sudo was all that let
/// setup itself run: its sudoers deny rule and the helper's grant are in
/// place already ([`deny_privileges`]); this closes what its groups lead
/// to, makes sure `su` asks for a password nobody has, and proves it,
/// as that user.
fn lock_runner(runner: &User) -> Result<()> {
    let groups = groups_of(&runner.name)?;
    for group in ROOT_GROUPS
        .iter()
        .filter(|group| groups.iter().any(|name| name == group.name))
    {
        let units: Vec<String> = group.units.iter().map(|&unit| unit.to_owned()).collect();
        if !units.is_empty() {
            println!(
                "{} is in {}, which leads to {}: stopping its daemon",
                runner.name, group.name, group.grants
            );
            stop_services(&units)?;
        }
        if group.name == DISK_GROUP {
            host::run(Command::new("find").args([
                DEV, "-xdev", "-type", "b", "-exec", "chmod", "go-rw", "{}", "+",
            ]))?;
            println!(
                "{} is in {DISK_GROUP}: block devices are root's alone now",
                runner.name
            );
        }
        if group.name == SHADOW_GROUP {
            for file in SHADOW_FILES.iter().filter(|file| Path::new(file).exists()) {
                fs::set_permissions(file, fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("closing {file}"))?;
            }
            println!(
                "{} is in {SHADOW_GROUP}: the password files are root's alone now",
                runner.name
            );
        }
    }
    helper::roots_alone(Path::new(SELF_COPY))?;
    if let Some(sources) = sudoers_sources_besides_files()? {
        println!(
            "note: {NSSWITCH} takes sudo rules from {sources} after the files; a rule there for {} would win over the deny rule. The proof below is of this machine as it is",
            runner.name
        );
    }
    let after: Vec<String> = sudoers_after_ours()?;
    ensure!(
        after.is_empty(),
        "{} sorts after {SUDOERS_DENY} in {}, and sudo would read it later: a rule there for {} would win. Remove it, or set sandbox.lock-runner = false",
        after.join(", "),
        Path::new(SUDOERS_DENY)
            .parent()
            .map(Path::display)
            .map_or_else(String::new, |p| p.to_string()),
        runner.name
    );
    match password_status("root")?.as_str() {
        NO_PASSWORD => {
            host::run(Command::new("passwd").args(["-l", "root"]))?;
            println!("root had no password, on which su would have asked nothing: locked");
        }
        status if status.starts_with('P') => println!(
            "note: root has a password ({status}); whoever knows it can become root with su"
        ),
        _ => {}
    }
    for root_process in root_processes_in_our_cgroup()? {
        println!("note: a root process in this job's cgroup besides setup's own: {root_process}");
    }
    // The proof, as the runner's user: no sudo, then the helper.
    let as_runner = |argv: &[&str]| -> Result<bool> {
        Ok(host::succeeds(
            Command::new("runuser")
                .args(["-u", &runner.name, "--"])
                .args(argv),
        ))
    };
    ensure!(
        !as_runner(&["sudo", "-n", "true"])?,
        "{} still has sudo after the lock",
        runner.name
    );
    ensure!(
        as_runner(&["sudo", "-n", "--", SELF_COPY, helper::COMMAND, "ping"])?,
        "{} cannot run the helper through sudo after the lock",
        runner.name
    );
    let listing = host::run(Command::new("sudo").args(["-l", "-U", &runner.name]))?;
    println!(
        "{} has no root now but the helper ({SELF_COPY} {}); sudo lists:\n{listing}",
        runner.name,
        helper::COMMAND
    );
    Ok(())
}

/// Where sudo takes its rules from besides the files, as nsswitch.conf
/// says (`sss` on hosts joined to a domain): `None` for nowhere.
fn sudoers_sources_besides_files() -> Result<Option<String>> {
    let text = match fs::read_to_string(NSSWITCH) {
        Ok(text) => text,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("reading {NSSWITCH}")),
    };
    let others: Vec<&str> = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("sudoers:"))
        .flat_map(str::split_whitespace)
        .filter(|source| *source != "files" && !source.starts_with('['))
        .collect();
    Ok((!others.is_empty()).then(|| others.join(", ")))
}

/// The files of sudoers.d that sudo reads after ours (lexically later,
/// and not skipped for a dot or a trailing tilde).
fn sudoers_after_ours() -> Result<Vec<String>> {
    let ours = Path::new(SUDOERS_DENY);
    let (dir, name) = (
        ours.parent().context("the sudoers rule has no directory")?,
        ours.file_name().context("the sudoers rule has no name")?,
    );
    let mut after = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let entry = entry?;
        let other = entry.file_name();
        let text = other.to_string_lossy();
        if other.as_os_str() > name && !text.contains('.') && !text.ends_with('~') {
            after.push(entry.path().display().to_string());
        }
    }
    after.sort();
    Ok(after)
}

/// The processes running as root in the cgroup this one is in, but for
/// this process and its ancestors (sudo): a root process the job started
/// and left, which the runner's user may still be able to talk to.
/// Listed, since what such a process does cannot be known from here.
fn root_processes_in_our_cgroup() -> Result<Vec<String>> {
    let cgroup = fs::read_to_string("/proc/self/cgroup").context("reading /proc/self/cgroup")?;
    // cgroup v2: one line, `0::/path`.
    let Some(path) = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::trim)
    else {
        return Ok(Vec::new());
    };
    let procs = fs::read_to_string(format!("/sys/fs/cgroup{path}/cgroup.procs"))
        .with_context(|| format!("listing the processes of the cgroup {path}"))?;
    let mut ancestors = std::collections::BTreeSet::new();
    let mut pid = std::process::id();
    while pid > 1 {
        ancestors.insert(pid);
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        pid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|ppid| ppid.trim().parse().ok())
            .unwrap_or(0);
    }
    let mut found = Vec::new();
    for pid in procs
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
    {
        if ancestors.contains(&pid) {
            continue;
        }
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|uids| uids.split_whitespace().next())
            .and_then(|uid| uid.parse::<u32>().ok());
        if uid == Some(0) {
            let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            let cmdline = String::from_utf8_lossy(&cmdline).replace('\0', " ");
            found.push(format!("{pid} {}", cmdline.trim()));
        }
    }
    Ok(found)
}

/// What under ROOT, ROOT included, is a file or directory that its
/// group or other users may write, with its mode. A symbolic link counts
/// by what it points to, which is what a reader opens (the back-ends are
/// links into `/usr/share/crypto-policies` on Fedora and RHEL), and is not
/// descended into. An absent ROOT has none.
pub fn writable_crypto_policies(root: &Path) -> Result<Vec<(PathBuf, u32)>> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    let mut seen = 0;
    while let Some(path) = pending.pop() {
        seen += 1;
        ensure!(
            seen <= MAX_CRYPTO_POLICY_ENTRIES,
            "more than {MAX_CRYPTO_POLICY_ENTRIES} entries under {}",
            root.display()
        );
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == ErrorKind::NotFound && path == root => return Ok(found),
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        };
        let meta = if meta.is_symlink() {
            // A dangling link has nothing to write.
            let Ok(target) = fs::metadata(&path) else {
                continue;
            };
            target
        } else {
            if meta.is_dir() {
                for entry in
                    fs::read_dir(&path).with_context(|| format!("listing {}", path.display()))?
                {
                    pending.push(entry?.path());
                }
            }
            meta
        };
        let mode = meta.permissions().mode() & MODE_BITS;
        if (meta.is_file() || meta.is_dir()) && mode & (GROUP_WRITE | OTHER_WRITE) != 0 {
            found.push((path, mode));
        }
    }
    found.sort();
    Ok(found)
}

/// Takes group and other write off every file and directory of the
/// crypto policy under ROOT. Through a link this changes its target.
/// The mode is changed on what is opened, from that file's own mode, so
/// a link swapped since the walk gets write taken away and nothing else
/// (a mode read before the swap could set a planted file's setuid bit on
/// the new target).
fn fix_crypto_policies(root: &Path) -> Result<()> {
    for (path, _) in writable_crypto_policies(root)? {
        // Non-blocking, so that a FIFO swapped in does not hang setup.
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags((rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY).bits() as i32)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let meta = file.metadata()?;
        if !(meta.is_file() || meta.is_dir()) {
            continue;
        }
        let mode = meta.permissions().mode() & MODE_BITS;
        let wanted = mode & !(GROUP_WRITE | OTHER_WRITE);
        file.set_permissions(fs::Permissions::from_mode(wanted))
            .with_context(|| format!("setting the mode of {}", path.display()))?;
        println!(
            "Made {} writable by its owner only (mode {mode:o} to {wanted:o})",
            path.display()
        );
    }
    Ok(())
}

/// Hardening only (the uid split is the boundary): some images let any
/// process attach to any other of its uid. A stricter setting is left.
/// The runner-read rule leaves attaches to Yama, so its loader calls it too.
pub(crate) fn restrict_ptrace() -> Result<()> {
    let scope = fs::read_to_string(PTRACE_SCOPE)
        .with_context(|| format!("reading {PTRACE_SCOPE} (a kernel without Yama?)"))?;
    if scope.trim() == "0" {
        fs::write(PTRACE_SCOPE, "1\n").with_context(|| format!("writing {PTRACE_SCOPE}"))?;
    }
    Ok(())
}

/// Apply to the host, not just one entry path. Reset any image-provided
/// exemption to root's group, which the sandbox user cannot belong to.
fn hide_other_processes() -> Result<()> {
    host::run(Command::new("mount").args(["-o", "remount,hidepid=invisible,gid=0", "/proc"]))
        .context("hiding other users' processes on the host /proc")?;
    Ok(())
}

/// Stops `units` and masks them until reboot, with the units that
/// trigger them: stopped alone, a unit is started again by its socket, a
/// path or timer, or a dependency, after `sandbox check` found it
/// stopped. A unit that is not on the machine is skipped.
fn stop_services(units: &[String]) -> Result<()> {
    let (present, absent): (Vec<&String>, Vec<&String>) = units.iter().partition(|unit| {
        host::succeeds(Command::new("systemctl").args(["cat", "--", unit.as_str()]))
    });
    if !absent.is_empty() {
        let names: Vec<&str> = absent.iter().map(|unit| unit.as_str()).collect();
        println!("Not on this machine, so not stopped: {}", names.join(", "));
    }
    let mut stopped: Vec<String> = Vec::new();
    for unit in present {
        let triggers = host::run(Command::new("systemctl").args([
            "show",
            "--property=TriggeredBy",
            "--value",
            "--",
            unit,
        ]))?;
        for name in std::iter::once(unit.as_str()).chain(triggers.split_whitespace()) {
            if !stopped.iter().any(|seen| seen == name) {
                stopped.push(name.to_owned());
            }
        }
    }
    if !stopped.is_empty() {
        host::run(
            Command::new("systemctl")
                .args(["stop", "--"])
                .args(&stopped),
        )?;
        host::run(
            Command::new("systemctl")
                .args(["mask", "--runtime", "--"])
                .args(&stopped),
        )?;
        // A runtime mask is below `/etc/systemd/system` in the load path,
        // so a unit file there still loads, and the unit can start.
        let mut unmasked = Vec::new();
        for unit in &stopped {
            let state = host::run(Command::new("systemctl").args([
                "show",
                "--property=LoadState",
                "--value",
                "--",
                unit,
            ]))?;
            if state != "masked" {
                unmasked.push(format!("{unit} ({state})"));
            }
        }
        ensure!(
            unmasked.is_empty(),
            "sandbox.stop-services: masking left {} startable; a unit file in /etc/systemd/system overrides a runtime mask: remove it, or mask the unit there",
            unmasked.join(", ")
        );
        println!("Stopped and masked until reboot: {}", stopped.join(", "));
    }
    Ok(())
}

/// What `run0 --pipe` needs.
const RUN0_SYSTEMD: u32 = 257;

/// The systemd version `--version` printed first: `systemd 259 (259.5-1)`.
fn systemd_version(text: &str) -> Option<u32> {
    let mut words = text.lines().next()?.split_whitespace();
    (words.next()? == "systemd").then_some(())?;
    words.next()?.parse().ok()
}

/// Makes PATH and every directory above it root's alone, as the helper
/// requires of what root runs or reads ([`helper::roots_alone`]): group
/// write by a group other than root's goes (Debian's `staff` on
/// `/usr/local`), as does other write; something not owned by root
/// cannot be made right from here and refuses setup.
fn make_roots_alone(path: &Path) -> Result<()> {
    for prefix in path.ancestors() {
        let meta = fs::symlink_metadata(prefix)
            .with_context(|| format!("reading {}", prefix.display()))?;
        ensure!(
            meta.uid() == 0,
            "{} is owned by uid {}, and the helper's {} must be root's alone: this image cannot be locked",
            prefix.display(),
            meta.uid(),
            path.display()
        );
        if meta.is_symlink() {
            continue;
        }
        let mode = meta.permissions().mode() & MODE_BITS;
        let mut wanted = mode & !OTHER_WRITE;
        if meta.gid() != 0 {
            wanted &= !GROUP_WRITE;
        }
        if wanted != mode {
            fs::set_permissions(prefix, fs::Permissions::from_mode(wanted))
                .with_context(|| format!("setting the mode of {}", prefix.display()))?;
            println!(
                "Made {} root's alone (mode {mode:o} to {wanted:o})",
                prefix.display()
            );
        }
    }
    helper::roots_alone(path)
}

fn install_self() -> Result<()> {
    let own = std::env::current_exe().context("finding this program's own file")?;
    let bytes = fs::read(&own).with_context(|| format!("reading {}", own.display()))?;
    let dest = Path::new(SELF_COPY);
    if let Some(dir) = dest.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    install_file(dest, &bytes, MODE_PROGRAM, None)
}

/// How the host installs packages, and what makes a failed attempt worth
/// repeating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    Dnf,
    Apt,
}

impl PackageManager {
    fn detect() -> Option<Self> {
        [(Self::Dnf, "dnf"), (Self::Apt, "apt-get")]
            .into_iter()
            .find_map(|(manager, program)| host::has_program(program).then_some(manager))
    }

    fn install(self, packages: &[String]) -> Command {
        let mut command = match self {
            Self::Dnf => {
                let mut command = Command::new("dnf");
                command.args(["install", "-y", "--"]);
                command
            }
            Self::Apt => {
                let mut command = Command::new("apt-get");
                command.env("DEBIAN_FRONTEND", "noninteractive");
                command.args(["install", "-y", "--no-install-recommends", "--"]);
                command
            }
        };
        command.args(packages);
        command
    }

    /// Only after a failed install: try the image's existing index first.
    fn refresh(self) -> Command {
        let (program, args): (&str, &[&str]) = match self {
            Self::Dnf => ("dnf", &["clean", "expire-cache"]),
            Self::Apt => ("apt-get", &["update", "-q"]),
        };
        let mut command = Command::new(program);
        command.args(args);
        command
    }

    fn refresh_before(self, attempt: u32) -> bool {
        attempt > 1
    }

    fn needed(self, package: &str) -> bool {
        self.needed_with(package, |package| {
            Command::new("dpkg-query")
                .args(["--show", "--showformat=${Status}", "--", package])
                .output()
                .is_ok_and(|out| out.status.success() && out.stdout == b"install ok installed")
        })
    }

    fn needed_with(self, package: &str, installed: impl FnOnce(&str) -> bool) -> bool {
        if self != Self::Apt || !plain_deb_name(package) {
            return true;
        }
        // Query package state, not PATH: a runner's private toolchain is
        // not necessarily usable by the sandbox. Version/release requests,
        // local .debs and apt patterns go to apt unchanged.
        !installed(package)
    }
}

fn plain_deb_name(package: &str) -> bool {
    !package.is_empty()
        && package
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"+.-:".contains(&c))
}

fn install_packages(packages: &[String]) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }
    let manager = PackageManager::detect()
        .context("setup.packages: this host has neither dnf nor apt-get")?;
    let packages: Vec<String> = packages
        .iter()
        .filter(|package| manager.needed(package))
        .cloned()
        .collect();
    if packages.is_empty() {
        return Ok(());
    }
    for attempt in 1..=INSTALL_ATTEMPTS {
        if manager.refresh_before(attempt) {
            let _ = host::output(&mut manager.refresh());
        }
        // Its output is the job log's: what was installed, or why not.
        if manager
            .install(&packages)
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(());
        }
        eprintln!("warning: installing packages failed (attempt {attempt} of {INSTALL_ATTEMPTS})");
        if attempt < INSTALL_ATTEMPTS {
            std::thread::sleep(INSTALL_PAUSE * attempt);
        }
    }
    bail!(
        "installing {} failed {INSTALL_ATTEMPTS} times",
        packages.join(" ")
    )
}

/// The agent programs. Their versions are exact (the configuration is
/// refused otherwise), so a run is repeatable; their install scripts run
/// as root here, as in the old tree, which is why the list is the
/// caller's and not the task's.
fn install_npm(specs: &[String]) -> Result<()> {
    if specs.is_empty() {
        return Ok(());
    }
    ensure!(
        host::has_program("npm"),
        "setup.npm: no npm on this host; add it to setup.packages"
    );
    let status = Command::new("npm")
        .args(["install", "-g", "--no-audit", "--no-fund", "--"])
        .args(specs)
        .status()
        .context("running npm")?;
    ensure!(
        status.success(),
        "npm install -g {} failed ({status})",
        specs.join(" ")
    );
    Ok(())
}

/// Installed before credentials and network rules, like the npm agents.
/// Neither the checkout nor caller setup code selects the package or path.
fn install_vibe() -> Result<()> {
    const HOME: &str = "/opt/agentic-job/vibe";
    const PACKAGE: &str = "mistral-vibe==2.26.1";
    install_packages(&["python3-venv".to_owned()])?;
    host::run(Command::new("python3").args(["-m", "venv", HOME]))?;
    host::run(Command::new(format!("{HOME}/bin/pip")).args([
        "install",
        "--disable-pip-version-check",
        PACKAGE,
    ]))?;
    Ok(())
}

/// `[setup] script`, as the sandbox user in its home: for toolchains,
/// which then belong to the user that runs them. Never as root.
fn run_setup_script(config: &Config, script: &Path) -> Result<()> {
    let bytes = fs::read(script).with_context(|| format!("reading {}", script.display()))?;
    install_file(Path::new(SCRIPT_COPY), &bytes, MODE_PROGRAM, None)?;
    let entry = Entry::new(config)?;
    let output = entry.run(&[SCRIPT_COPY], b"")?;
    // Captured setup output is only a log, so complete escaping avoids a
    // suspension window (and cross-stream ordering or signal cleanup).
    std::io::stdout().write_all(
        crate::workflow_commands::escaped(&String::from_utf8_lossy(&output.stdout)).as_bytes(),
    )?;
    std::io::stderr().write_all(
        crate::workflow_commands::escaped(&String::from_utf8_lossy(&output.stderr)).as_bytes(),
    )?;
    ensure!(
        output.success(),
        "setup.script failed as {} ({})",
        config.sandbox.user,
        output.status
    );
    Ok(())
}

/// Installs a root-owned file with `mode`, once `validate` (a command the
/// path is appended to), if given, accepts it. Written beside the
/// destination and renamed, so a reader never sees half of it.
fn install_file(path: &Path, content: &[u8], mode: u32, validate: Option<&[&str]>) -> Result<()> {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    let tmp = PathBuf::from(name);
    let written = (|| -> Result<()> {
        // Not through a link someone left at that name.
        let _ = fs::remove_file(&tmp);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        file.write_all(content)?;
        // The mode given at creation went through the umask.
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        drop(file);
        if let Some(validate) = validate {
            host::run(host::command(validate)?.arg(&tmp))
                .with_context(|| format!("{} would not be valid", path.display()))?;
        }
        fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written?;
    // SELinux: give the new file the label its place calls for.
    if host::has_program("restorecon") {
        host::run(Command::new("restorecon").arg(path))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_name_needs_a_dns_name_with_a_certificate() {
        let name = "runner.tail1234.ts.net";
        let status = |dns: &str, certs: serde_json::Value| serde_json::json!({"Self": {"DNSName": dns}, "CertDomains": certs});
        let disabled = Err("HTTPS certificates disabled");
        for (status, wanted) in [
            (
                status("runner.tail1234.ts.net.", serde_json::json!([name])),
                Ok(name),
            ),
            (
                status("runner.tail1234.ts.net.", serde_json::Value::Null),
                disabled,
            ),
            (
                status("runner.tail1234.ts.net.", serde_json::json!(["other"])),
                disabled,
            ),
            (
                status("Runner!.", serde_json::json!(["Runner!"])),
                Err("no DNS name"),
            ),
        ] {
            match (session_name(&status), wanted) {
                (Ok(got), Ok(wanted)) => assert_eq!(got, wanted),
                (Err(error), Err(wanted)) => {
                    assert!(format!("{error:#}").contains(wanted), "{error:#}")
                }
                (got, wanted) => panic!("{status}: got {got:?}, wanted {wanted:?}"),
            }
        }
    }

    #[test]
    fn crypto_policies_are_left_writable_by_their_owner_only() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("crypto-policies");
        let outside = dir.path().join("share");
        fs::create_dir_all(root.join("back-ends")).unwrap();
        fs::create_dir(&outside).unwrap();
        // Path under ROOT (or beside it), its mode, and whether it is found.
        let files = [
            ("back-ends/openssh.config", 0o646, true),
            ("back-ends/gnutls.config", 0o664, true),
            ("config", 0o644, false),
            ("../share/opensslcnf.txt", 0o666, true),
            ("../share/nss.txt", 0o644, false),
        ];
        for (name, mode, _) in files {
            let path = root.join(name);
            fs::write(&path, "").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        }
        symlink(
            "../../share/opensslcnf.txt",
            root.join("back-ends/opensslcnf.config"),
        )
        .unwrap();
        symlink("../../share/nss.txt", root.join("back-ends/nss.config")).unwrap();
        symlink("absent", root.join("back-ends/dangling.config")).unwrap();
        // A linked directory counts itself, and is not walked into.
        let linked = dir.path().join("linked");
        fs::create_dir(&linked).unwrap();
        fs::write(linked.join("inside"), "").unwrap();
        fs::set_permissions(linked.join("inside"), fs::Permissions::from_mode(0o666)).unwrap();
        symlink(&linked, root.join("linked")).unwrap();
        for (path, mode) in [
            (&root, 0o755),
            (&root.join("back-ends"), 0o777),
            (&linked, 0o775),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }

        let mut want: Vec<(PathBuf, u32)> = files
            .iter()
            .filter(|(name, _, found)| *found && !name.starts_with(".."))
            .map(|(name, mode, _)| (root.join(name), *mode))
            .chain([
                (root.join("back-ends"), 0o777),
                (root.join("back-ends/opensslcnf.config"), 0o666),
                (root.join("linked"), 0o775),
            ])
            .collect();
        want.sort();
        assert_eq!(writable_crypto_policies(&root).unwrap(), want);

        fix_crypto_policies(&root).unwrap();
        assert_eq!(writable_crypto_policies(&root).unwrap(), []);
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & MODE_BITS;
        assert_eq!(mode(&root.join("back-ends/openssh.config")), 0o644);
        assert_eq!(mode(&outside.join("opensslcnf.txt")), 0o644);
        assert_eq!(mode(&root.join("back-ends")), 0o755);
        assert_eq!(mode(&linked), 0o755);
        assert_eq!(mode(&linked.join("inside")), 0o666);

        // A host without a crypto policy has nothing to fix; one that is
        // too large to look at is refused, not passed.
        assert_eq!(
            writable_crypto_policies(&dir.path().join("absent")).unwrap(),
            []
        );
        let large = dir.path().join("large");
        fs::create_dir(&large).unwrap();
        for index in 0..MAX_CRYPTO_POLICY_ENTRIES {
            fs::write(large.join(index.to_string()), "").unwrap();
        }
        assert!(writable_crypto_policies(&large).is_err());
    }

    #[test]
    fn systemd_versions() {
        let cases = [
            ("systemd 259 (259.5-0ubuntu3.4)\n+PAM +AUDIT", Some(259)),
            ("systemd 257 (257.9-1.el10)", Some(257)),
            ("systemd 256", Some(256)),
            ("systemd 257.1 (x)", None),
            ("run0 257", None),
            ("", None),
            ("systemd", None),
        ];
        for (text, want) in cases {
            assert_eq!(systemd_version(text), want, "{text:?}");
        }
    }

    #[test]
    fn subordinate_uid_ranges() {
        let agent = |name: &str| User {
            name: name.to_owned(),
            uid: 1001,
            gid: 1001,
            home: "/home/agent".into(),
        };
        let subuid = "runner:100000:65536\nagent:165536:65536\n1001:300000:1000\nother:1:1\n";
        assert_eq!(
            subuid_ranges(&agent("agent"), subuid).unwrap(),
            ["165536-231071", "300000-300999"]
        );
        for (user, text) in [
            ("agent", ""),
            ("agent", "agent:x:1\n"),
            ("agen", "agent:165536:65536\n"),
            ("agent", "agent:5:0\n"),
        ] {
            assert!(
                subuid_ranges(&agent(user), text).is_err(),
                "{user} in {text:?}"
            );
            // The runner's user may have none; that is no refusal.
            assert!(subordinate_ranges(&agent(user), text).is_empty());
        }
    }

    #[test]
    fn groups_an_image_gave_the_user() {
        assert_eq!(forbidden_groups("agent kvm render"), Vec::<&str>::new());
        assert_eq!(forbidden_groups("agent docker kvm adm"), ["docker", "adm"]);
    }

    #[test]
    fn private_directories_add_to_the_defaults() {
        let runner = User {
            name: "runner".into(),
            uid: 1001,
            gid: 1001,
            home: "/home/runner".into(),
        };
        let config =
            Config::parse("[sandbox]\nprivate-dirs = [\"/srv/work\", \"/opt/hca\"]").unwrap();
        let dirs: Vec<String> = private_dirs(&config, &runner)
            .iter()
            .map(|dir| dir.display().to_string())
            .collect();
        assert_eq!(
            dirs,
            [
                "/home/runner",
                "/opt/hca",
                "/var/run/tailscale",
                "/srv/work"
            ]
        );
    }

    #[test]
    fn deny_files() {
        assert_eq!(sudoers_rules("agent", None), "agent ALL=(ALL:ALL) !ALL\n");
        assert_eq!(
            sudoers_rules("agent", Some("runner")),
            "agent ALL=(ALL:ALL) !ALL\nrunner ALL=(ALL:ALL) !ALL\nrunner ALL=(root) NOPASSWD: /usr/local/libexec/agentic-job helper *\n"
        );
        assert_eq!(
            polkit_deny(&["agent"]),
            "polkit.addRule(function(action, subject) {\n  if (subject.user == \"agent\") return polkit.Result.NO;\n});\n"
        );
        assert_eq!(
            polkit_deny(&["agent", "runner"]),
            "polkit.addRule(function(action, subject) {\n  if (subject.user == \"agent\" || subject.user == \"runner\") return polkit.Result.NO;\n});\n"
        );
        let cases = [
            ("", Some("agent\n")),
            ("daemon\n", Some("agent\n")),
            ("daemon", Some("\nagent\n")),
            ("daemon\nagent\n", None),
            ("agent", None),
            // Another user's name that only contains ours.
            ("agent2\n", Some("agent\n")),
        ];
        for (text, want) in cases {
            assert_eq!(denial(text, "agent").as_deref(), want, "{text:?}");
        }
    }

    #[test]
    fn image_variables_are_dropped_and_nothing_else() {
        let cases = [
            (
                "PATH=/usr/bin\nXDG_RUNTIME_DIR=/run/user/1001\nLANG=C\n",
                Some(("PATH=/usr/bin\nLANG=C\n", vec!["XDG_RUNTIME_DIR"])),
            ),
            ("  XDG_RUNTIME_DIR=/x", Some(("", vec!["XDG_RUNTIME_DIR"]))),
            (
                "A=1\nexport ACTIONS_RUNNER_ACTION_ARCHIVE_CACHE=/opt/cache\nACTIONS_X=\"y\"\n",
                Some((
                    "A=1\n",
                    vec!["ACTIONS_RUNNER_ACTION_ARCHIVE_CACHE", "ACTIONS_X"],
                )),
            ),
            ("PATH=/usr/bin\n", None),
            ("XDG_RUNTIME_DIR_OTHER=1\n", None),
            ("GITHUB_ACTIONS_X=1\nNOTE=ACTIONS_=1\n", None),
            ("# XDG_RUNTIME_DIR=/x\n", None),
        ];
        for (text, want) in cases {
            let got = without_variables(text, image_variable);
            let want = want.map(|(kept, names): (&str, Vec<&str>)| {
                (
                    kept.to_owned(),
                    names.into_iter().map(str::to_owned).collect::<Vec<_>>(),
                )
            });
            assert_eq!(got, want, "{text:?}");
        }
    }

    #[test]
    fn setup_requires_every_world_write_link() {
        let temp = tempfile::tempdir().unwrap();
        let links = temp.path().join("links");
        let refused = |pin: &Path| require_world_write_policy(pin).err().map(|e| e.to_string());
        assert!(
            refused(temp.path())
                .unwrap()
                .contains("world_write_permission")
        );
        fs::create_dir(&links).unwrap();
        for (index, name) in WORLD_WRITE_LINKS.iter().enumerate() {
            let error = refused(temp.path()).unwrap();
            assert!(error.contains(name), "{error}");
            assert!(error.contains("not loaded"), "{error}");
            fs::write(links.join(name), b"").unwrap();
            assert_eq!(
                refused(temp.path()).is_none(),
                index == WORLD_WRITE_LINKS.len() - 1
            );
        }
    }

    #[test]
    fn setup_timing_preserves_results() {
        assert_eq!(timed_setup("test", || Ok(42)).unwrap(), 42);
        let error = timed_setup::<()>("test", || bail!("stage failure")).unwrap_err();
        assert_eq!(error.to_string(), "stage failure");
    }

    #[test]
    fn the_runner_keeps_exactly_the_helper() {
        assert_eq!(
            runner_sudo_rules(),
            [
                "(ALL : ALL) !ALL",
                "(root) NOPASSWD: /usr/local/libexec/agentic-job helper *"
            ]
        );
    }

    #[test]
    fn package_commands() {
        let packages = ["just".to_owned(), "gcc".to_owned()];
        let args = |command: &Command| -> Vec<String> {
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect()
        };
        assert_eq!(
            args(&PackageManager::Dnf.install(&packages)),
            ["install", "-y", "--", "just", "gcc"]
        );
        assert_eq!(
            args(&PackageManager::Apt.install(&packages)),
            [
                "install",
                "-y",
                "--no-install-recommends",
                "--",
                "just",
                "gcc"
            ]
        );
    }

    #[test]
    fn only_missing_plain_deb_packages_need_installation() {
        for manager in [PackageManager::Apt, PackageManager::Dnf] {
            for (package, installed, needed) in [
                ("nftables", true, false),
                ("python3-venv", false, true),
                ("libfoo1:amd64", true, false),
                ("tool=1.2", true, true),
                ("tool/stable", true, true),
                ("./tool.deb", true, true),
                ("tool*", true, true),
                ("?installed", true, true),
            ] {
                assert_eq!(
                    manager.needed_with(package, |_| installed),
                    manager == PackageManager::Dnf || needed,
                    "{manager:?}: {package}"
                );
            }
            assert!(!manager.refresh_before(1));
            assert!(manager.refresh_before(2));
        }
    }

    #[test]
    fn job_user_keeps_home_groups_and_subordinate_ids_without_login_logs() {
        let config = Config::parse("[sandbox]\nuser = 'job-user'\ngroups = ['kvm']").unwrap();
        let skeleton = tempfile::tempdir().unwrap();
        assert_eq!(std::fs::read_dir(skeleton.path()).unwrap().count(), 0);
        let command = useradd_command(&config, skeleton.path());
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "--no-log-init",
                "--create-home",
                "--user-group",
                "--shell",
                "/bin/bash",
                "--skel",
                skeleton.path().to_str().unwrap(),
                "--groups",
                "kvm",
                "--",
                "job-user",
            ]
        );
    }
}
