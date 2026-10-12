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
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::IpAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use rustix::fs::Mode;

use super::enter::{Entry, RUN0};
use super::host::{self, User};
use super::network::{self, Direct};
use super::{egress, helper};
use crate::config::{self, Config, Sandbox};
use crate::exit::Exit;
use crate::run::agent::{self, Kind};
use crate::run::inference::Endpoint;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The run's configuration (TOML); copied to /etc/agentic-job/
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
}

/// Root's: the configuration `run` reads, and what else setup leaves for
/// the supervisor. That it exists also says setup ran here before.
pub const CONFIG_DIR: &str = "/etc/agentic-job";

/// A copy of this program that the sandbox user can run: `sandbox check`
/// starts it there to see the host as that user does. The build it was
/// made from is in the runner's home, which is closed.
pub const SELF_COPY: &str = "/usr/local/libexec/agentic-job";

/// Root-owned, writable by the sandbox group, but not by the runner after
/// hardening. The view must deny the sandbox's otherwise permitted writes.
pub const VIEW_PROBE_DIR: &str = "/etc/agentic-job/write-probe";

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

/// Sticky world-writable directories, meant to stay that way.
const SHARED_TMP: &[&str] = &["/tmp", "/var/tmp"];

/// Where the walk over the filesystem leaves the setuid-root programs it
/// passes: root's, in the configuration directory.
const SETUID_LIST: &str = "/etc/agentic-job/setuid-root";

/// Setuid-root programs every host this runs on has: the control of the
/// probe that looks for ones no package owns.
pub const SETUID_CONTROLS: &[&str] = &["/usr/bin/sudo", "/usr/bin/su", "/bin/su"];

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

/// Some images leave this group-writable, and ssh refuses to run with a
/// group-writable included configuration: plain ssh and git over ssh then
/// fail for every user but the one the image was built for.
const SSH_CRYPTO_POLICY: &str = "/etc/crypto-policies/back-ends/openssh.config";

const GROUP_WRITE: u32 = 0o020;

const OTHER_WRITE: u32 = 0o002;

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
    direct: Vec<Direct>,
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
        direct,
        runner,
        existing,
        resolvers,
    } = timed_setup("preflight", || {
        let text = fs::read_to_string(&args.config)
            .with_context(|| format!("reading {}", args.config.display()))?;
        let config =
            Config::parse(&text).with_context(|| format!("in {}", args.config.display()))?;
        let direct = config.check_host()?.direct;
        ensure!(host::is_root(), "`sandbox setup` must run as root");
        ensure!(
            host::has_program(RUN0),
            "{RUN0} not found: the sandbox is entered with it, and it needs systemd 257 or later"
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
        let mut resolvers = Vec::new();
        if config.egress.proxy {
            let resolv_conf = match fs::read_to_string(RESOLV_CONF) {
                Ok(text) => text,
                Err(err) if err.kind() == ErrorKind::NotFound => String::new(),
                Err(err) => return Err(err).with_context(|| format!("reading {RESOLV_CONF}")),
            };
            let on_tailnet = network::tailnet_resolvers(&resolv_conf);
            resolvers = network::resolvers(&resolv_conf)
                .with_context(|| format!("reading resolvers from {RESOLV_CONF}"))?;
            ensure!(
                on_tailnet.is_empty(),
                "{RESOLV_CONF} names {} on the tailnet, which the egress proxy may not reach: join the tailnet without its DNS (tailscale up --accept-dns=false)",
                on_tailnet.join(", ")
            );
        }
        Ok(Preflight {
            text,
            config,
            direct,
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
    if !config.sandbox.world_write_walk {
        timed_setup("filesystem-view", || install_filesystem_view(&sandbox))?;
    }
    let subuids = timed_setup("environment-and-private-dirs", || {
        let subuids = subuid_ranges(
            &sandbox,
            &fs::read_to_string(SUBUID).with_context(|| format!("reading {SUBUID}"))?,
        )?;
        drop_image_environment()?;
        close_private_dirs(&config, &runner)?;
        Ok(subuids)
    })?;
    timed_setup("stop-services", || {
        stop_services(&config.sandbox.stop_services)
    })?;
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
    // The proxy first, since the rules name its uid; and both after the
    // installs, which root does on the open network.
    let proxy_uid = config
        .egress
        .proxy
        .then(|| timed_setup("egress-proxy", || egress::start(&config.egress)))
        .transpose()?;
    timed_setup("network-rules", || {
        let uids: Vec<String> = std::iter::once(sandbox.uid.to_string())
            .chain(subuids.iter().cloned())
            .collect();
        network::apply(&network::rules_with_resolvers(
            &uids, &direct, proxy_uid, &resolvers,
        ))
    })?;
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
    timed_setup("view-probe-dir", || {
        // In view mode this stays writable by DAC, so probes prove mount confinement.
        // Walk mode removes world write access, including for the runner.
        fs::create_dir(VIEW_PROBE_DIR).context("creating filesystem-view probe directory")?;
        host::run(Command::new("chown").args([&format!("root:{}", sandbox.gid), VIEW_PROBE_DIR]))?;
        fs::set_permissions(VIEW_PROBE_DIR, fs::Permissions::from_mode(0o777))?;
        Ok(())
    })?;
    optional_hardening_walk(config.sandbox.world_write_walk, |stage, operation| {
        timed_setup(stage, operation)
    })?;
    timed_setup("ssh-and-ptrace", || {
        fix_ssh_crypto_policy()?;
        restrict_ptrace()
    })?;
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
    Ok(Exit::Success)
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
    if !config.sandbox.world_write_walk {
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
    let mut useradd = Command::new("useradd");
    useradd.args(["--create-home", "--user-group", "--shell", "/bin/bash"]);
    if !config.sandbox.groups.is_empty() {
        useradd.arg("--groups").arg(config.sandbox.groups.join(","));
    }
    host::run(useradd.args(["--", name.as_str()]))?;
    let user = User::lookup(name)?.with_context(|| format!("useradd made no user {name}"))?;
    ensure_distinct(&user, runner)?;
    Ok(user)
}

/// The subordinate uid ranges of `user`, each as `START-END`. Containers
/// the sandbox user starts run as these, so the network rules name them.
pub fn subuid_ranges(user: &User, subuid: &str) -> Result<Vec<String>> {
    // subuid(5) names the owner or gives its uid.
    let uid = user.uid.to_string();
    let ranges: Vec<String> = subuid
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
        .collect();
    ensure!(
        !ranges.is_empty(),
        "{} has no subordinate uids in {SUBUID}, which rootless podman needs",
        user.name
    );
    Ok(ranges)
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

fn optional_hardening_walk(
    enabled: bool,
    mut run: impl FnMut(&str, fn() -> Result<()>) -> Result<()>,
) -> Result<()> {
    // Both stages share the walk's single traversal; the view has none.
    if enabled {
        run("world-write-and-setuid-walk", strip_world_write)?;
        run("setuid-package-ownership", strip_unowned_setuid)?;
    }
    Ok(())
}

/// Log monotonic wall time even when a stage fails, without changing its result.
fn timed_setup<T>(stage: &str, run: impl FnOnce() -> Result<T>) -> Result<T> {
    let started = Instant::now();
    let result = run();
    println!(
        "Sandbox setup stage {stage}: {:.3}s ({})",
        started.elapsed().as_secs_f64(),
        if result.is_ok() { "ok" } else { "failed" }
    );
    result
}

/// `find` arguments that match what is world-writable under `root` and
/// not sticky, on that one filesystem, outside the shared temporary
/// directories. `sandbox check` looks with the same ones.
pub fn world_writable_find(root: &str) -> Vec<String> {
    let prune = SHARED_TMP.iter().flat_map(|dir| ["-path", *dir, "-o"]);
    [root, "-xdev", "("]
        .into_iter()
        .chain(prune)
        .chain([
            "-false", ")", "-prune", "-o", "(", "-type", "f", "-o", "-type", "d", ")", "-perm",
            "-0002", "!", "-perm", "-1000",
        ])
        .map(str::to_owned)
        .collect()
}

/// `find` arguments that match the setuid-root programs under `root`, on
/// that one filesystem.
pub fn setuid_root_find(root: &str) -> Vec<String> {
    [
        root, "-xdev", "-type", "f", "-perm", "-4000", "-user", "root", "-print",
    ]
    .map(str::to_owned)
    .to_vec()
}

mod privileged_binaries;

/// World-writable system files include ones root loads code from (a
/// polkit rule, a unit): any user could make itself root through them.
/// Some runner images are built with umask 000. The same walk, the
/// slowest thing setup does, writes down the setuid-root programs it
/// passes for [`strip_unowned_setuid`].
fn strip_world_write() -> Result<()> {
    let mounts = fs::read_to_string("/proc/self/mountinfo")
        .context("reading mount table for hardening walk")?;
    let mut args = hardening_find("/", &readonly_mounts(&mounts)?);
    let root_device = fs::metadata("/")?.dev();
    // Separate temporary filesystems used to have their own scans. Give
    // them starting points in the same invocation instead, without revisiting
    // their contents when they are already on the root filesystem.
    for dir in SHARED_TMP {
        match fs::metadata(dir) {
            Ok(metadata) if metadata.dev() != root_device => args.insert(2, (*dir).to_owned()),
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("checking filesystem of {dir}"));
            }
        }
    }
    let (count, shown) = run_hardening_find(&args, Path::new(SETUID_LIST))?;
    if count != 0 {
        println!(
            "Removed world write access from {} paths, such as:\n  {}",
            count,
            shown.join("\n  ")
        );
    }
    Ok(())
}

/// Use the mode find already statted instead of asking chmod to stat every
/// match again. Setup runs before untrusted processes, on a fresh host; like
/// the old find/chmod pass this requires the traversed tree to be quiescent.
/// NUL framing keeps whitespace and non-UTF-8 paths exact. Retain only ten
/// examples, not the image's potentially hundreds of thousands of matches.
fn run_hardening_find(args: &[String], inventory: &Path) -> Result<(usize, Vec<String>)> {
    let mut child = Command::new("find")
        .args(args)
        .arg("-fprint")
        .arg(inventory)
        .args([")", ")"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("starting hardening walk")?;
    let result = (|| {
        let stdout = child.stdout.take().context("hardening walk stdout")?;
        harden_find_records(BufReader::new(stdout))
    })();
    // A failed chmod or malformed record must not leave a producer blocked on
    // its pipe, or a setup subprocess running after the refusal.
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().context("waiting for hardening walk")?;
    let fixed = result?;
    ensure!(status.success(), "hardening walk failed ({status})");
    Ok(fixed)
}

fn harden_find_records(mut reader: impl BufRead) -> Result<(usize, Vec<String>)> {
    // Allow room beyond Linux's path-based chmod limit, but refuse oversized
    // records rather than retaining unbounded find output from a deep tree.
    const MAX_RECORD: u64 = 8192;
    let mut record = Vec::new();
    let mut count = 0;
    let mut shown = Vec::new();
    loop {
        record.clear();
        let size = reader
            .by_ref()
            .take(MAX_RECORD + 1)
            .read_until(0, &mut record)?;
        if size == 0 {
            break;
        }
        ensure!(
            size as u64 <= MAX_RECORD && record.last() == Some(&0),
            "invalid hardening walk record length"
        );
        record.pop();
        let separator = record
            .iter()
            .position(|byte| *byte == b' ')
            .context("hardening walk record missing mode")?;
        let mode = u32::from_str_radix(std::str::from_utf8(&record[..separator])?, 8)
            .context("invalid hardening walk mode")?;
        ensure!(
            mode <= MODE_BITS && mode & 0o002 != 0 && mode & 0o1000 == 0,
            "unexpected hardening walk mode"
        );
        let path = Path::new(std::ffi::OsStr::from_bytes(&record[separator + 1..]));
        ensure!(path.is_absolute(), "hardening walk path is not absolute");
        fs::set_permissions(path, fs::Permissions::from_mode(mode & !0o002))
            .with_context(|| format!("removing world write from {}", path.display()))?;
        count += 1;
        if shown.len() < 10 {
            shown.push(format!("{:?}", path));
        }
    }
    Ok((count, shown))
}

/// Keep mount paths as bytes escaped by the kernel, never as find patterns.
fn readonly_mounts(text: &str) -> Result<Vec<String>> {
    let mut mounts = Vec::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(
            fields.len() >= 10 && fields.contains(&"-"),
            "invalid mountinfo line"
        );
        let mut path = fields[4].to_owned();
        for (escaped, literal) in [
            ("\\040", " "),
            ("\\011", "\t"),
            ("\\012", "\n"),
            ("\\134", "\\"),
        ] {
            path = path.replace(escaped, literal);
        }
        let options: Vec<_> = fields[5].split(',').collect();
        // Read-only alone does not prevent executing a setuid program.
        mounts.push((path, options.contains(&"ro") && options.contains(&"nosuid")));
    }
    // A writable bind mount below a read-only mount must still be visited.
    Ok(mounts
        .iter()
        .filter(|(path, ro)| {
            *ro && !mounts
                .iter()
                .any(|(child, readonly)| !readonly && Path::new(child).starts_with(path))
        })
        .map(|(path, _)| path.clone())
        .collect())
}

fn find_literal_path(path: &str) -> String {
    path.chars()
        .flat_map(|c| {
            if "\\*?[]".contains(c) {
                vec!['\\', c]
            } else {
                vec![c]
            }
        })
        .collect()
}

/// One GNU find pass. Pruning encloses BOTH actions: comma must not bypass it.
/// Closed directories must still be hardened: another setup or job step can
/// reopen them later. Only pseudo-filesystems and read-only, nosuid mounts
/// without writable descendants are pruned, independently of directory modes.
/// Symlinks cannot match either action under find's default no-follow policy.
/// Test their directory-entry type before -fstype forces a metadata lookup.
fn hardening_find(root: &str, readonly: &[String]) -> Vec<String> {
    let mut args: Vec<String> = [
        "-O3",
        root,
        "-xdev",
        "-ignore_readdir_race",
        "(",
        "-type",
        "l",
        "-o",
        "-fstype",
        "proc",
        "-o",
        "-fstype",
        "sysfs",
    ]
    .map(str::to_owned)
    .to_vec();
    for path in readonly {
        args.extend(["-o".to_owned(), "-path".to_owned(), find_literal_path(path)]);
    }
    args.extend(
        [
            ")",
            "-prune",
            "-o",
            "(",
            "(",
            "!",
            "-path",
            "/tmp/*",
            "!",
            "-path",
            "/var/tmp/*",
            "!",
            "-path",
            "/tmp",
            "!",
            "-path",
            "/var/tmp",
            "(",
            "-type",
            "f",
            "-o",
            "-type",
            "d",
            ")",
            "-perm",
            "-0002",
            "!",
            "-perm",
            "-1000",
            "-printf",
            "%m %p\\0",
            ")",
            ",",
            "(",
            "-type",
            "f",
            "-perm",
            "-4000",
            "-user",
            "root",
        ]
        .map(str::to_owned),
    );
    args
}

/// Whether the host's package manager accounts for the file at PATH.
pub fn package_owned(path: &str) -> bool {
    let (query, path): (&[&str], String) = if host::has_program("dpkg-query") {
        // dpkg-query takes a pattern: a path with a glob character in it
        // is asked about as itself.
        let escaped = path
            .chars()
            .flat_map(|c| {
                if "*?[\\".contains(c) {
                    vec!['\\', c]
                } else {
                    vec![c]
                }
            })
            .collect();
        (&["dpkg-query", "-S", "--"], escaped)
    } else if host::has_program("rpm") {
        (&["rpm", "-qf", "--"], path.to_owned())
    } else {
        // No way to tell: nothing is called unowned on such a host.
        return true;
    };
    host::command(query).is_ok_and(|mut command| host::succeeds(command.arg(path)))
}

/// A setuid-root program that no package owns is someone's own way to
/// root, kept for whoever knows of it: it loses the bit. The distribution's
/// (sudo, su, pkexec, mount...) stay, each closed by its own policy or
/// needing a password root does not have.
fn strip_unowned_setuid() -> Result<()> {
    strip_unowned_setuid_list(Path::new(SETUID_LIST))
}

fn strip_unowned_setuid_list(list: &Path) -> Result<()> {
    let listed = match fs::read_to_string(list) {
        Ok(text) => text,
        Err(err) if err.kind() == ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err).with_context(|| format!("reading {}", list.display())),
    };
    let programs: Vec<&str> = listed.lines().filter(|line| !line.is_empty()).collect();
    let unowned: Vec<&str> = programs
        .iter()
        .copied()
        .filter(|path| !package_owned(path))
        .collect();
    if !unowned.is_empty() {
        host::run(Command::new("chmod").args(["u-s", "--"]).args(&unowned))?;
    }
    println!(
        "{} setuid-root programs, {} of them no package's: {}",
        programs.len(),
        unowned.len(),
        if unowned.is_empty() {
            "nothing to take the bit from".to_owned()
        } else {
            format!("took the bit from {}", unowned.join(", "))
        }
    );
    Ok(())
}

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

fn fix_ssh_crypto_policy() -> Result<()> {
    let path = Path::new(SSH_CRYPTO_POLICY);
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(());
    };
    let mode = metadata.permissions().mode() & MODE_BITS;
    fs::set_permissions(path, fs::Permissions::from_mode(mode & !GROUP_WRITE))
        .with_context(|| format!("setting the mode of {SSH_CRYPTO_POLICY}"))
}

/// Hardening only (the uid split is the boundary): some images let any
/// process attach to any other of its uid. A stricter setting is left.
fn restrict_ptrace() -> Result<()> {
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

fn stop_services(units: &[String]) -> Result<()> {
    let (present, absent): (Vec<&String>, Vec<&String>) = units.iter().partition(|unit| {
        host::succeeds(Command::new("systemctl").args(["cat", "--", unit.as_str()]))
    });
    if !absent.is_empty() {
        let names: Vec<&str> = absent.iter().map(|unit| unit.as_str()).collect();
        println!("Not on this machine, so not stopped: {}", names.join(", "));
    }
    if !present.is_empty() {
        host::run(
            Command::new("systemctl")
                .args(["stop", "--"])
                .args(&present),
        )?;
        let names: Vec<&str> = present.iter().map(|unit| unit.as_str()).collect();
        println!("Stopped {}", names.join(", "));
    }
    Ok(())
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

    /// Run before every attempt but dnf's first: a half-fetched index is
    /// not used again, and apt's may be older than the image.
    fn refresh(self) -> Command {
        let (program, args): (&str, &[&str]) = match self {
            Self::Dnf => ("dnf", &["clean", "expire-cache"]),
            Self::Apt => ("apt-get", &["update", "-q"]),
        };
        let mut command = Command::new(program);
        command.args(args);
        command
    }
}

fn install_packages(packages: &[String]) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }
    let manager = PackageManager::detect()
        .context("setup.packages: this host has neither dnf nor apt-get")?;
    for attempt in 1..=INSTALL_ATTEMPTS {
        if attempt > 1 || manager == PackageManager::Apt {
            let _ = host::output(&mut manager.refresh());
        }
        // Its output is the job log's: what was installed, or why not.
        if manager
            .install(packages)
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
    fn hardening_records_are_exact_and_bounded() {
        let temp = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let mut records = Vec::new();
        let mut paths = Vec::new();
        for index in 0..12 {
            let name = format!("space newline\n{index}").into_bytes();
            let mut name = name;
            name.push(0xff);
            let path = root.join(std::ffi::OsStr::from_bytes(&name));
            fs::write(&path, b"fixture").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o6766)).unwrap();
            records.extend_from_slice(b"6766 ");
            records.extend_from_slice(path.as_os_str().as_bytes());
            records.push(0);
            paths.push(path);
        }
        let (count, shown) = harden_find_records(&records[..]).unwrap();
        assert_eq!(count, 12);
        assert_eq!(shown.len(), 10);
        for path in paths {
            assert_eq!(fs::metadata(path).unwrap().mode() & MODE_BITS, 0o6764);
        }
        for record in [
            b"666 /missing".as_slice(),
            b"invalid\0",
            b"1777 /tmp\0",
            b"666 relative\0",
            b"666 /nonexistent-hardening-fixture\0",
        ] {
            assert!(harden_find_records(record).is_err(), "{record:?}");
        }
        assert!(harden_find_records(&vec![b'x'; 8193][..]).is_err());
        assert!(
            run_hardening_find(
                &hardening_find("/nonexistent-hardening-fixture", &[]),
                &root.join("list")
            )
            .is_err()
        );
    }

    #[test]
    fn traversal_stages_follow_the_selected_mode() {
        for (enabled, expected) in [
            (false, &[][..]),
            (
                true,
                &["world-write-and-setuid-walk", "setuid-package-ownership"][..],
            ),
        ] {
            let mut stages = Vec::new();
            super::optional_hardening_walk(enabled, |stage, _operation| {
                stages.push(stage.to_owned());
                Ok(())
            })
            .unwrap();
            assert_eq!(stages, expected);
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
    fn setup_timing_preserves_results() {
        assert_eq!(timed_setup("test", || Ok(42)).unwrap(), 42);
        let error = timed_setup::<()>("test", || bail!("stage failure")).unwrap_err();
        assert_eq!(error.to_string(), "stage failure");
    }

    #[test]
    fn find_arguments_match_the_old_tree() {
        assert_eq!(
            world_writable_find("/").join(" "),
            "/ -xdev ( -path /tmp -o -path /var/tmp -o -false ) -prune -o ( -type f -o -type d ) -perm -0002 ! -perm -1000"
        );
        assert_eq!(
            setuid_root_find("/").join(" "),
            "/ -xdev -type f -perm -4000 -user root -print"
        );
    }

    #[test]
    fn hardening_walk_finds_open_directory_and_prunes_readonly_actions() {
        let temp = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let root_path = fs::canonicalize(temp.path()).unwrap();
        let root = root_path.as_path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
        let open = root.join("planted");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        let private = root.join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        let hidden = private.join("hidden");
        fs::create_dir(&hidden).unwrap();
        fs::set_permissions(&hidden, fs::Permissions::from_mode(0o777)).unwrap();
        let program = private.join("setuid");
        fs::write(&program, b"fixture").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o4755)).unwrap();
        let uid = fs::metadata(root).unwrap().uid();
        let shared = tempfile::tempdir().unwrap();
        fs::set_permissions(shared.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let shared_program = shared.path().join("setuid");
        fs::write(&shared_program, b"fixture").unwrap();
        fs::set_permissions(&shared_program, fs::Permissions::from_mode(0o4755)).unwrap();
        let shared_open = shared.path().join("open");
        fs::create_dir(&shared_open).unwrap();
        fs::set_permissions(&shared_open, fs::Permissions::from_mode(0o777)).unwrap();
        let list = root.join("setuid-list");
        // Supply a synthetic read-only mount path without requiring mounts.
        let mut args = hardening_find(
            root.to_str().unwrap(),
            &[private.to_str().unwrap().to_owned()],
        );
        args.insert(2, shared.path().to_str().unwrap().to_owned());
        // Unprivileged tests cannot create root-owned files. Substitute
        // only the inventory's owner predicate to exercise the same action.
        let owner = args.iter().position(|arg| arg == "-user").unwrap() + 1;
        args[owner] = uid.to_string();
        let (count, _) = run_hardening_find(&args, &list).unwrap();
        assert_eq!(count, 1);
        assert_eq!(fs::metadata(open).unwrap().mode() & 0o777, 0o775);
        assert_eq!(fs::metadata(hidden).unwrap().mode() & 0o777, 0o777);
        assert_eq!(fs::metadata(shared_open).unwrap().mode() & 0o777, 0o777);
        assert_eq!(
            fs::read_to_string(list).unwrap().trim(),
            shared_program.to_str().unwrap()
        );
    }

    #[test]
    fn readonly_mount_pruning_preserves_writable_children() {
        let mounts = "1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:1 / /read\\040only ro,nosuid - ext4 /dev/root rw\n3 1 8:1 / /parent ro,nosuid - ext4 /dev/root rw\n4 3 8:1 / /parent/child rw - ext4 /dev/root rw\n5 1 8:1 / /stacked ro,nosuid - ext4 /dev/root rw\n6 1 8:1 / /stacked rw - ext4 /dev/root rw\n7 1 8:1 / /suid ro - ext4 /dev/root rw\n";
        assert_eq!(readonly_mounts(mounts).unwrap(), ["/read only"]);
        assert_eq!(find_literal_path("/a[*]?\\"), "/a\\[\\*\\]\\?\\\\");
        assert!(readonly_mounts("invalid").is_err());
    }

    #[test]
    fn hardening_walk_hardens_directories_before_they_are_reopened() {
        let temp = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let uid = fs::metadata(&root).unwrap().uid();
        let hidden = root.join("hidden");
        fs::write(&hidden, b"fixture").unwrap();
        let list = root.join("inventory");
        // The walking user stands in for setup's root, which can traverse a
        // directory closed to the sandbox regardless of its owner.
        for (label, mode) in [("closed", 0o700), ("open", 0o755)] {
            fs::set_permissions(&root, fs::Permissions::from_mode(mode)).unwrap();
            fs::set_permissions(&hidden, fs::Permissions::from_mode(0o4777)).unwrap();
            let mut args = hardening_find(root.to_str().unwrap(), &[]);
            let owner = args.iter().position(|arg| arg == "-user").unwrap() + 1;
            args[owner] = uid.to_string();
            assert_eq!(run_hardening_find(&args, &list).unwrap().0, 1, "{label}");
            // A later job step opening the directory must not expose a path
            // that retained world-write or escaped the setuid inventory.
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(
                fs::read_to_string(&list)
                    .unwrap()
                    .contains(hidden.to_str().unwrap()),
                "{label}"
            );
            assert_eq!(fs::metadata(&hidden).unwrap().mode() & 0o002, 0, "{label}");
        }
    }

    #[test]
    fn streaming_walk_preserves_selection_and_exact_paths() {
        let temp = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let inventory = root.join("inventory");
        let cases = [
            ("ordinary", 0o666, 0o664),
            ("sticky", 0o1666, 0o1666),
            ("readonly", 0o644, 0o644),
            ("executable", 0o777, 0o775),
        ];
        for (name, mode, _) in cases {
            let path = root.join(name);
            fs::write(&path, b"fixture").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let exact = root.join(std::ffi::OsStr::from_bytes(b"space \n\xff"));
        fs::write(&exact, b"fixture").unwrap();
        fs::set_permissions(&exact, fs::Permissions::from_mode(0o666)).unwrap();
        let directory = root.join("directory");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o666)).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
        std::os::unix::fs::symlink(root.join("missing"), root.join("dangling")).unwrap();
        std::os::unix::fs::symlink(&directory, root.join("directory-link")).unwrap();
        std::os::unix::fs::symlink("loop", root.join("loop")).unwrap();
        let args = hardening_find(root.to_str().unwrap(), &[]);
        assert_eq!(run_hardening_find(&args, &inventory).unwrap().0, 4);
        for (name, _, expected) in cases {
            assert_eq!(
                fs::metadata(root.join(name)).unwrap().mode() & MODE_BITS,
                expected,
                "{name}"
            );
        }
        assert_eq!(fs::metadata(&exact).unwrap().mode() & MODE_BITS, 0o664);
        assert_eq!(fs::metadata(&directory).unwrap().mode() & MODE_BITS, 0o775);
        assert_eq!(
            fs::metadata(outside.path()).unwrap().mode() & MODE_BITS,
            0o666
        );
        // A traversal error still refuses setup even after successful changes.
        let mut failing = args;
        failing.insert(2, root.join("missing").to_str().unwrap().to_owned());
        fs::set_permissions(&exact, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(run_hardening_find(&failing, &inventory).is_err());
        assert_eq!(fs::metadata(&exact).unwrap().mode() & MODE_BITS, 0o664);
    }

    #[test]
    #[ignore = "root fixture; fresh-runner CI only, before sandbox setup"]
    fn hardening_walk_subordinate_owner() {
        if std::env::var_os("AGENTIC_JOB_ROOT_WALK_TEST").is_none() {
            let status = Command::new("sudo")
                .args(["-n", "--", "env", "AGENTIC_JOB_ROOT_WALK_TEST=1"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "sandbox::setup::tests::hardening_walk_subordinate_owner",
                ])
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        // An owner from a subordinate range can reopen its private directory.
        // setpriv exercises those same kernel owner rights without depending
        // on the runner's container storage or user-namespace configuration.
        // The setuid inventory covers the shared temporary trees, but world
        // write is deliberately left alone there, so each tree is a case.
        let subordinate = 200000;
        for (base, world_write_removed) in [("/var/lib", true), ("/var/tmp", false)] {
            let temp = tempfile::tempdir_in(base).unwrap();
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
            let private = temp.path().join("private");
            fs::create_dir(&private).unwrap();
            std::os::unix::fs::chown(&private, Some(subordinate), None).unwrap();
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
            let program = private.join("setuid");
            fs::copy("/bin/true", &program).unwrap();
            fs::set_permissions(&program, fs::Permissions::from_mode(0o4755)).unwrap();
            let open = private.join("world-write");
            fs::write(&open, b"fixture").unwrap();
            fs::set_permissions(&open, fs::Permissions::from_mode(0o666)).unwrap();
            let list = temp.path().join("inventory");
            let args = hardening_find(temp.path().to_str().unwrap(), &[]);
            run_hardening_find(&args, &list).unwrap();
            assert!(
                fs::read_to_string(&list)
                    .unwrap()
                    .contains(program.to_str().unwrap()),
                "{base}"
            );
            strip_unowned_setuid_list(&list).unwrap();
            let status = Command::new("setpriv")
                .args([
                    "--reuid=200000",
                    "--regid=200000",
                    "--clear-groups",
                    "chmod",
                    "755",
                ])
                .arg(&private)
                .status()
                .unwrap();
            assert!(status.success(), "{base}");
            assert_eq!(
                fs::metadata(&private).unwrap().mode() & 0o777,
                0o755,
                "{base}"
            );
            assert_eq!(fs::metadata(&program).unwrap().mode() & 0o4000, 0, "{base}");
            assert_eq!(
                fs::metadata(&open).unwrap().mode() & 0o002 == 0,
                world_write_removed,
                "{base}"
            );
            assert!(
                Command::new("setpriv")
                    .args(["--reuid=1001", "--regid=1001", "--clear-groups"])
                    .arg(&program)
                    .status()
                    .unwrap()
                    .success(),
                "{base}"
            );
        }
    }

    #[test]
    #[ignore = "local traversal benchmark; creates 30000 files, no host hardening"]
    fn hardening_walk_local_benchmark() {
        let temp = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let private = root.join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        for index in 0..30000 {
            fs::write(private.join(index.to_string()), b"").unwrap();
        }
        let list = root.join("setuid-list");
        let root_str = root.to_str().unwrap();
        let after = hardening_find(root_str, &[]);
        let mut before = after.clone();
        let printf = before.iter().position(|arg| arg == "-printf").unwrap();
        before.splice(
            printf..printf + 2,
            ["-print", "-exec", "chmod", "o-w", "{}", "+"].map(str::to_owned),
        );
        before.extend(["-fprint", list.to_str().unwrap(), ")", ")"].map(str::to_owned));
        for label in ["before", "after", "after", "before"] {
            for index in 0..30000 {
                fs::set_permissions(
                    private.join(index.to_string()),
                    fs::Permissions::from_mode(0o666),
                )
                .unwrap();
            }
            let start = Instant::now();
            if label == "before" {
                let output = Command::new("find").args(&before).output().unwrap();
                assert!(output.status.success(), "{output:?}");
                assert_eq!(
                    output.stdout.split(|byte| *byte == b'\n').count() - 1,
                    30000
                );
            } else {
                assert_eq!(run_hardening_find(&after, &list).unwrap().0, 30000);
            }
            println!(
                "Local synthetic walk {label}: {:.6}s (30000 files in private tree)",
                start.elapsed().as_secs_f64()
            );
        }
    }

    #[test]
    #[ignore = "local symlink traversal benchmark; no host hardening"]
    fn hardening_walk_symlink_benchmark() {
        let temp = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        for index in 0..30000 {
            std::os::unix::fs::symlink("missing", root.join(index.to_string())).unwrap();
        }
        let inventory = root.join("inventory");
        let after = hardening_find(root.to_str().unwrap(), &[]);
        let mut before = after.clone();
        // The only difference from current main is the early symlink prune.
        assert_eq!(&before[5..8], ["-type", "l", "-o"]);
        before.drain(5..8);
        for (label, args) in [
            ("before", &before),
            ("after", &after),
            ("after", &after),
            ("before", &before),
        ] {
            let start = Instant::now();
            assert_eq!(run_hardening_find(args, &inventory).unwrap().0, 0);
            assert!(fs::read(&inventory).unwrap().is_empty());
            println!(
                "Local symlink walk {label}: {:.6}s",
                start.elapsed().as_secs_f64()
            );
        }
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
}
