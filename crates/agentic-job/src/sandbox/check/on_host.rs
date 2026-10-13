//! The probes of the host itself: privileges, the environments and
//! files of the runner's processes, schedulers, services, and the
//! listeners and sockets a local user can connect to, tailscaled's too.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};

use super::{Checker, Want, contains};
use crate::config::Sandbox;
use crate::sandbox::enter::OIDC_REQUEST_VARS;
use crate::sandbox::local::{ABSTRACT_PREFIX, Reached};
use crate::sandbox::setup::{self, SELF_COPY};
use crate::sandbox::{egress, host, network};

/// A variable of a process of the runner's, standing in for the tokens in
/// the environments of real job steps.
const CANARY_VAR: &str = "AGENT_ISOLATION_CANARY";

/// How long the stand-in process lives if nothing stops it.
const DECOY_SECONDS: &str = "300";

const DECOY_WAIT: Duration = Duration::from_millis(100);

const DECOY_TRIES: u32 = 50;

/// Fails only if `$1` can be neither listed nor entered: a directory of
/// mode 0711 hides its names and still gives up every file whose name is
/// known.
const LIST_OR_ENTER: &str = r#"ls -- "$1" >/dev/null 2>&1 || cd -- "$1""#;

/// Succeeds if `$1` can be created (and is then removed) or, failing
/// that, `$2` opened to append: either is a write.
const WRITE_OR_APPEND: &str = r#"{ : > "$1" && rm -f -- "$1"; } 2>/dev/null || : >> "$2""#;

/// Either enumeration, directory access, or a known-PID command-line read
/// exposes the other user's process. hidepid=1 is not sufficient.
const PROC_VISIBLE: &str = r#"for pid do
    for path in /proc/[0-9]*; do
        [ "$path" != "/proc/$pid" ] || exit 0
    done
    ls -- "/proc/$pid" >/dev/null 2>&1 && exit 0
    cat -- "/proc/$pid/cmdline" >/dev/null 2>&1 && exit 0
done
exit 1"#;

/// Another process of the same uid lists and reads the shell. Not `$$`, which
/// systemd would make `$` in a user service's command line.
const PROC_SELF: &str = r#"pid=$(exec sh -c 'echo "$PPID"')
ls "/proc/$pid" >/dev/null && cat "/proc/$pid/cmdline" >/dev/null"#;

/// Where a CI system says the job's files are. A work or temporary
/// directory outside the runner's home is one more place to close; these
/// are GitHub's and Forgejo's names for them.
const WORK_DIR_VARS: &[&str] = &["RUNNER_TEMP", "RUNNER_WORKSPACE", "GITHUB_WORKSPACE"];

/// Where tailscaled listens, on runners that joined a tailnet. The socket
/// itself is open to all; its directory is root's only, by setup.
const TAILSCALE_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

const LOCALAPI_STATUS: &str = "http://local-tailscaled.sock/localapi/v0/status";

const PTRACE_SCOPE: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// Unix sockets every host offers its users, and which answer by who is
/// asking: the system bus, the journal, the user database, PID 1's
/// notification socket and its own and its helpers' Varlink services,
/// and the helper polkit starts to check a password, which newer polkit
/// has in place of a setuid program.
///
/// Named one by one, as seen on the runners this was tried on, and not
/// by directory: systemd-resolved's sockets are under `/run/systemd/`
/// too, and resolve names for any user as its own; and a later systemd
/// may put a service there that hands out user namespaces with uids the
/// network rules do not know. A path ending in `/` is everything under
/// it; one ending in `*` is every path that starts so.
const HOST_SOCKETS: &[&str] = &[
    "/run/dbus/system_bus_socket",
    "/run/systemd/journal/",
    "/run/systemd/userdb/io.systemd.DynamicUser",
    "/run/systemd/userdb/io.systemd.Multiplexer",
    "/run/systemd/notify",
    "/run/systemd/io.systemd.AskPassword",
    "/run/systemd/io.systemd.Credentials",
    "/run/systemd/io.systemd.FactoryReset",
    "/run/systemd/io.systemd.Hostname",
    "/run/systemd/io.systemd.Login",
    "/run/systemd/io.systemd.ManagedOOM",
    "/run/systemd/io.systemd.Manager",
    "/run/systemd/io.systemd.MuteConsole",
    "/run/systemd/io.systemd.sysext",
    "/run/polkit/agent-helper.socket",
];

/// A unit that is active on every host this runs on.
const ALWAYS_ACTIVE_UNIT: &str = "systemd-journald.service";

/// pkexec refuses a caller whose parent is PID 1, which a command started
/// straight from `run0` is; an agent would call it from a shell, so the
/// probe does. The `&&` keeps the shell from replacing itself with it.
const PKEXEC_FROM_A_SHELL: &str = "pkexec true && true";

/// A socket any user may connect to.
const MODE_OPEN_SOCKET: u32 = 0o666;

/// Whether this user can create `path`; what it made is removed again.
fn create_and_remove(path: &Path) -> Result<bool> {
    let created = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .is_ok();
    if created {
        std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(created)
}

/// The names of the variables in `environs`, the `NAME=value` entries of
/// any number of processes with a NUL after each, that have `needle`
/// anywhere in them. Names only: a value may be what must not be shown.
fn variables_holding(environs: &[u8], needle: &[u8]) -> BTreeSet<String> {
    environs
        .split(|&byte| byte == 0)
        .filter(|entry| contains(entry, needle))
        .map(|entry| {
            let name = entry.split(|&byte| byte == b'=').next().unwrap_or_default();
            String::from_utf8_lossy(name).into_owned()
        })
        .collect()
}

/// A process of the runner's with the canary in its environment; gone
/// when this is dropped.
struct Decoy(Child);

impl Decoy {
    fn start(canary: &str) -> Result<Self> {
        let child = Command::new("sleep")
            .arg(DECOY_SECONDS)
            .env(CANARY_VAR, canary)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("starting sleep")?;
        let decoy = Self(child);
        // Until it has exec'd, its environment is still ours.
        for _ in 0..DECOY_TRIES {
            if decoy.has(canary) {
                break;
            }
            std::thread::sleep(DECOY_WAIT);
        }
        Ok(decoy)
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }

    fn has(&self, canary: &str) -> bool {
        std::fs::read(format!("/proc/{}/environ", self.pid()))
            .is_ok_and(|environ| contains(&environ, canary.as_bytes()))
    }
}

impl Drop for Decoy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Whether the Unix socket `name` is one the sandbox user may reach.
fn socket_allowed(name: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|entry| {
        if let Some(prefix) = entry.strip_suffix('*') {
            name.starts_with(prefix)
        } else if entry.ends_with('/') {
            name.starts_with(entry.as_str())
        } else {
            name == entry
        }
    })
}

/// systemd's daemons (udevd for one) take notifications from their own
/// children on an abstract datagram socket named by a random 64-bit
/// number, and check who sent each. The name differs on every boot, so
/// no list can hold it.
fn systemd_notification_socket(name: &str) -> bool {
    name.strip_prefix(ABSTRACT_PREFIX).is_some_and(|number| {
        number.bytes().all(|byte| byte.is_ascii_digit()) && number.parse::<u64>().is_ok()
    })
}

impl Checker<'_> {
    /// No sudo, no polkit action, no lingering user manager.
    pub(super) fn privileges(&mut self) -> Result<()> {
        let user = self.user().to_owned();
        // The runner's user has root do something for it: everything
        // after setup, through the helper; or sudo itself where the
        // machine is not locked.
        self.report.expect(
            Want::Succeed,
            "sudo-control",
            format!(
                "{} has root run a command for it through sudo (control)",
                self.runner.name
            ),
            self.root.ping(),
        );
        let got = self.sandbox_succeeds(&["sudo", "-n", "true"])?;
        self.report
            .expect(Want::Fail, "sudo", format!("{user} has no sudo"), got);

        if host::has_program("pkexec") {
            self.report.expect(
                Want::Succeed,
                "polkit-control",
                "root runs a command through pkexec (control)",
                self.root.pkexec_control(),
            );
            let got = self.sandbox_succeeds(&["sh", "-c", PKEXEC_FROM_A_SHELL])?;
            self.report.expect(
                Want::Fail,
                "polkit",
                format!("{user} is refused by polkit (pkexec)"),
                got,
            );
        } else {
            self.report
                .note("no pkexec on this host, so no polkit action to try with it");
        }

        // Enabling one's own lingering is a polkit action that is open to
        // every user by default; the control shows logind answers at all.
        let got = self.sandbox_succeeds(&["loginctl", "list-sessions", "--no-legend"])?;
        self.report.expect(
            Want::Succeed,
            "linger-control",
            format!("{user} asks logind for its sessions (control)"),
            got,
        );
        let enabled = self.sandbox_succeeds(&["loginctl", "enable-linger"])?;
        if enabled {
            // Do not leave what the probe was there to find.
            let _ = self.root.disable_linger(&user);
        }
        self.report.expect(
            Want::Fail,
            "linger",
            format!("{user} can't keep a user manager running after its sessions (enable-linger)"),
            enabled,
        );

        // The groups it really has, whoever made the user.
        let groups = self.sandbox(&["id", "-Gn"], b"")?;
        let groups = String::from_utf8_lossy(&groups.stdout).trim().to_owned();
        self.report.expect(
            Want::Succeed,
            "groups-control",
            format!("{user} lists its groups (control)"),
            !groups.is_empty(),
        );
        let forbidden: Vec<&str> = groups
            .split_whitespace()
            .filter(|group| Sandbox::FORBIDDEN_GROUPS.contains(group))
            .collect();
        self.report.expect(
            Want::Fail,
            "groups",
            if forbidden.is_empty() {
                format!("{user} is in no group that is root by another name ({groups})")
            } else {
                format!("{user} is in {}", forbidden.join(", "))
            },
            !forbidden.is_empty(),
        );
        Ok(())
    }

    /// The runner's processes' environments are closed to the sandbox
    /// user. Returns every environment it can read, NUL-separated.
    pub(super) fn environments(&mut self) -> Result<Vec<u8>> {
        let user = self.user().to_owned();
        let decoy = Decoy::start(&self.canary)?;
        self.report.expect(
            Want::Succeed,
            "proc-control-runner",
            "the runner reads its live decoy's command line (control)",
            std::fs::read(format!("/proc/{}/cmdline", decoy.pid()))
                .is_ok_and(|cmdline| contains(&cmdline, b"sleep")),
        );
        let mut entries: Vec<(&str, &[&str])> = vec![
            ("session", &[]),
            (
                "user-manager",
                &[
                    "systemd-run",
                    "--user",
                    "--pipe",
                    "--wait",
                    "--collect",
                    "--quiet",
                ],
            ),
        ];
        if self.has_podman() {
            entries.push(("podman-userns", &["podman", "unshare"]));
        }
        let checker_pid = std::process::id().to_string();
        let decoy_pid = decoy.pid().to_string();
        for (name, prefix) in entries {
            let control = self.sandbox_succeeds(&[prefix, &["sh", "-c", PROC_SELF]].concat())?;
            self.report.expect(
                Want::Succeed,
                &format!("proc-control-sandbox-{name}"),
                format!("{user} lists and reads its own process via {name} (control)"),
                control,
            );
            let got = self.sandbox_succeeds(
                &[
                    prefix,
                    &[
                        "sh",
                        "-c",
                        PROC_VISIBLE,
                        "sh",
                        "1",
                        &checker_pid,
                        &decoy_pid,
                    ],
                ]
                .concat(),
            )?;
            self.report.expect(
                Want::Fail,
                "proc-other-users",
                format!("{user} cannot list or read other users' processes via {name}"),
                got,
            );
        }
        let targets = [
            (std::process::id(), "environ-self", "this process's"),
            (decoy.pid(), "environ-runner", "another runner process's"),
        ];
        for (pid, id, whose) in targets {
            let got = self.sandbox_succeeds(&["cat", &format!("/proc/{pid}/environ")])?;
            self.report.expect(
                Want::Fail,
                id,
                format!("{user} can't read {whose} environment"),
                got,
            );
        }
        self.report.expect(
            Want::Succeed,
            "environ-control-runner",
            format!(
                "{} reads the canary in its own process's environment (control)",
                self.runner.name
            ),
            decoy.has(&self.canary),
        );
        let environs = self
            .sandbox(
                &["sh", "-c", "cat /proc/[0-9]*/environ 2>/dev/null; true"],
                b"",
            )?
            .stdout;
        let home = format!("HOME={}", self.entry.home().display());
        self.report.expect(
            Want::Succeed,
            "environ-control-sandbox",
            format!("{user} reads its own processes' environments (control)"),
            contains(&environs, home.as_bytes()),
        );
        self.report.expect(
            Want::Fail,
            "environ-canary",
            format!("no environment {user} can read holds the canary"),
            contains(&environs, self.canary.as_bytes()),
        );
        let prefix = Sandbox::FORBIDDEN_ENV_PREFIX;
        let named = variables_holding(&environs, prefix.as_bytes());
        self.report.expect(
            Want::Fail,
            "environ-job-variables",
            if named.is_empty() {
                format!("no environment {user} can read has {prefix} in it")
            } else {
                let names: Vec<&str> = named.iter().map(String::as_str).collect();
                format!(
                    "an environment {user} can read has {prefix} in {}",
                    names.join(", ")
                )
            },
            !named.is_empty(),
        );
        Ok(environs)
    }

    /// The variables that ask for the job's identity token are in every
    /// step's environment when the job may have one, this process's too;
    /// what runs as the sandbox user starts without them.
    pub(super) fn job_variables(&mut self, environs: &[u8], has_token: bool) -> Result<()> {
        let user = self.user().to_owned();
        let values: Vec<(&str, String)> = OIDC_REQUEST_VARS
            .iter()
            .filter_map(|&name| Some((name, std::env::var(name).ok().filter(|v| !v.is_empty())?)))
            .collect();
        // A run token was got with the identity token, so then the
        // variables must be here to be proven absent from the sandbox.
        if has_token || !values.is_empty() {
            self.report.expect(
                Want::Succeed,
                "oidc-control",
                format!(
                    "this process has {} (control)",
                    OIDC_REQUEST_VARS.join(" and ")
                ),
                values.len() == OIDC_REQUEST_VARS.len(),
            );
        } else {
            self.report.note(
                "this process has no identity-token request variables, so there are none to leak",
            );
        }
        let env = self.sandbox(&["env"], b"")?.stdout;
        let env = String::from_utf8_lossy(&env);
        let home = format!("HOME={}", self.entry.home().display());
        self.report.expect(
            Want::Succeed,
            "env-control",
            format!("{user} runs env (control)"),
            env.lines().any(|line| line == home),
        );
        self.report.expect(
            Want::Fail,
            "env-job-variables",
            format!(
                "{user}'s environment has no {}* variables",
                Sandbox::FORBIDDEN_ENV_PREFIX
            ),
            env.lines()
                .any(|line| line.starts_with(Sandbox::FORBIDDEN_ENV_PREFIX)),
        );
        for (name, value) in values {
            self.report.expect(
                Want::Fail,
                &format!("oidc-value:{name}"),
                format!("no process {user} can read has {name}'s value"),
                contains(environs, value.as_bytes()),
            );
        }
        Ok(())
    }

    /// The directories setup closed, the directory this runs in, and
    /// what on the root filesystem any user may write.
    pub(super) fn files(&mut self) -> Result<()> {
        let user = self.user().to_owned();
        self.report.expect(
            Want::Succeed,
            "private-dir-control",
            format!(
                "{} lists its own home {} (control)",
                self.runner.name,
                self.runner.home.display()
            ),
            std::fs::read_dir(&self.runner.home).is_ok(),
        );
        let mut dirs = setup::private_dirs(self.config, &self.runner);
        // Where the job's files are, if not under one of those: the
        // directory this runs in and the ones the CI system names. Only
        // what is the runner's own, so that running this from / says
        // nothing.
        let work_dirs = std::env::current_dir().into_iter().chain(
            WORK_DIR_VARS
                .iter()
                .filter_map(std::env::var_os)
                .map(PathBuf::from),
        );
        for dir in work_dirs {
            let ours = std::fs::metadata(&dir).is_ok_and(|m| m.uid() == self.runner.uid);
            if ours && !dirs.iter().any(|closed| dir.starts_with(closed)) {
                dirs.push(dir);
            }
        }
        for dir in dirs {
            let shown = dir.display().to_string();
            // A closed directory can still be seen to be one from outside.
            if !std::fs::metadata(&dir).is_ok_and(|meta| meta.is_dir()) {
                self.report.note(&format!("no {shown} on this host"));
                continue;
            }
            let got = self.sandbox_succeeds(&["sh", "-c", LIST_OR_ENTER, "sh", &shown])?;
            self.report.expect(
                Want::Fail,
                &format!("private-dir:{shown}"),
                format!("{user} can neither list nor enter {shown}"),
                got,
            );
        }

        // Run on both paths: this is host-policy evidence, not a compatibility
        // requirement. Ubuntu AppArmor can deny util-linux's uid_map write
        // while permitting the profiled Podman user namespace entry point.
        let diagnostic = self.sandbox_diagnosed(
            "util-linux-userns-diagnostic",
            &["unshare", "--user", "--map-root-user", "--mount", "true"],
            b"",
        )?;
        // The stderr noted above reads like an error, so say what it is (#401).
        let why = if diagnostic {
            ""
        } else {
            "; information only, not a failure: usually Ubuntu's AppArmor user \
             namespace restriction, which leaves unprofiled programs such as \
             util-linux `unshare` without the capability to write uid_map, while \
             Podman's profiled entry point, which filesystem-view-userns requires, \
             keeps it"
        };
        self.report.note(&format!(
            "util-linux-userns-diagnostic: success={diagnostic}; filesystem_view={}{why}",
            self.config.sandbox.filesystem_view
        ));
        if self.config.sandbox.filesystem_view {
            self.filesystem_view()?;
        }
        self.world_write()?;

        let scope = std::fs::read_to_string(PTRACE_SCOPE).unwrap_or_default();
        self.report.expect(
            Want::Succeed,
            "ptrace-scope",
            format!(
                "ptrace is restricted to descendants or more ({PTRACE_SCOPE} is {})",
                scope.trim()
            ),
            scope.trim().parse::<u32>().is_ok_and(|scope| scope >= 1),
        );
        Ok(())
    }

    /// The world-write policy, by what it does: ordinary permissions let
    /// any user create in the planted directory and append to the planted
    /// file, and the policy must refuse both to the runner's user and to
    /// the sandbox user, neither of which owns them. No denial log is
    /// read. Each user's control is the same attempt in its own home. The
    /// runner has no view, so its probe proves the policy alone; under the
    /// view the sandbox user's attempt also meets a read-only mount.
    fn world_write(&mut self) -> Result<()> {
        let user = self.user().to_owned();
        let created = format!("{}/{}", setup::WORLD_WRITE_PROBE_DIR, self.canary);
        let home_writable = create_and_remove(&self.runner.home.join(&self.canary))?;
        self.report.expect(
            Want::Succeed,
            "runner-world-write-control",
            "runner can write its own home",
            home_writable,
        );
        let wrote = create_and_remove(Path::new(&created))?
            || std::fs::OpenOptions::new()
                .append(true)
                .open(setup::WORLD_WRITE_PROBE_FILE)
                .is_ok();
        self.report.expect(
            Want::Fail,
            "runner-world-write",
            format!(
                "runner can neither create in {} nor append to {}, root's and world-writable",
                setup::WORLD_WRITE_PROBE_DIR,
                setup::WORLD_WRITE_PROBE_FILE
            ),
            wrote,
        );
        let home = self.entry.home().join(&self.canary);
        let control = self.sandbox_succeeds(&[
            "sh",
            "-c",
            WRITE_OR_APPEND,
            "sh",
            &home.display().to_string(),
            &home.display().to_string(),
        ])?;
        let wrote = self.sandbox_succeeds(&[
            "sh",
            "-c",
            WRITE_OR_APPEND,
            "sh",
            &created,
            setup::WORLD_WRITE_PROBE_FILE,
        ])?;
        self.report.expect(
            Want::Succeed,
            "world-write-control",
            format!("{user} can write its own home (control)"),
            control,
        );
        self.report.expect(
            Want::Fail,
            "world-write",
            format!(
                "{user} can neither create in {} nor append to {}, root's and world-writable",
                setup::WORLD_WRITE_PROBE_DIR,
                setup::WORLD_WRITE_PROBE_FILE
            ),
            wrote,
        );
        Ok(())
    }

    /// Exercise the run0 session and the inherited manager view independently.
    /// Merely finding ReadOnlyPaths in a unit's properties is not enforcement.
    fn filesystem_view(&mut self) -> Result<()> {
        let outside = format!("{}/{}", setup::VIEW_PROBE_DIR, self.canary);
        for (id, manager) in [
            ("filesystem-view", false),
            ("filesystem-view-manager", true),
        ] {
            let attempt = |path: &str| -> Result<bool> {
                let script = "f=$1; : > \"$f\" && rm -f -- \"$f\"";
                if manager {
                    self.sandbox_succeeds(&[
                        "systemd-run",
                        "--user",
                        "--pipe",
                        "--wait",
                        "--collect",
                        "--property=ProtectSystem=no",
                        "--property=ProtectHome=no",
                        "--property=ReadOnlyPaths=",
                        "--property=ReadWritePaths=",
                        "sh",
                        "-c",
                        script,
                        "sh",
                        path,
                    ])
                } else {
                    self.sandbox_succeeds(&["sh", "-c", script, "sh", path])
                }
            };
            let control = self.entry.home().join(&self.canary);
            let control = attempt(&control.display().to_string())?;
            let wrote = attempt(&outside)?;
            self.report.expect(
                Want::Succeed,
                &format!("{id}-control"),
                "can write inside sandbox home",
                control,
            );
            self.report.expect(
                Want::Fail,
                id,
                "cannot write planted group-writable host directory",
                wrote,
            );
        }
        let nested = "mount -o remount,rw / 2>/dev/null || :; f=$1; : > \"$f\" && rm -f -- \"$f\"";
        let control = self.entry.home().join(&self.canary);
        let works = self.sandbox_diagnosed(
            "filesystem-view-nested-control",
            &[
                "podman",
                "unshare",
                "unshare",
                "--mount",
                "sh",
                "-c",
                nested,
                "sh",
                &control.display().to_string(),
            ],
            b"",
        )?;
        let escaped = self.sandbox_succeeds(&[
            "podman", "unshare", "unshare", "--mount", "sh", "-c", nested, "sh", &outside,
        ])?;
        self.report.expect(
            Want::Succeed,
            "filesystem-view-nested-control",
            "nested namespace can write home",
            works,
        );
        self.report.expect(
            Want::Fail,
            "filesystem-view-nested",
            "nested namespace cannot remount host writable",
            escaped,
        );
        let socket_script = include_str!("socket-view.py");
        let socket_control = self.sandbox_succeeds(&[
            "python3",
            "-I",
            "-c",
            socket_script,
            &control.display().to_string(),
        ])?;
        let socket_escape =
            self.sandbox_succeeds(&["python3", "-I", "-c", socket_script, &outside])?;
        self.report.expect(
            Want::Succeed,
            "filesystem-view-socket-control",
            "socket-activated user service can write home",
            socket_control,
        );
        self.report.expect(
            Want::Fail,
            "filesystem-view-socket",
            "socket-activated user service cannot write outside view",
            socket_escape,
        );
        let namespaces = self.sandbox_diagnosed(
            "filesystem-view-userns",
            &["podman", "unshare", "unshare", "--mount", "true"],
            b"",
        )?;
        self.report.expect(
            Want::Succeed,
            "filesystem-view-userns",
            "Podman's nested user and mount namespaces still work",
            namespaces,
        );
        let pam = self.sandbox_diagnosed(
            "filesystem-view-pam",
            &["python3", "-I", "-"],
            include_bytes!("pam.py"),
        )?;
        self.report.expect(
            Want::Succeed,
            "filesystem-view-pam",
            "same-uid processes cannot trace, write memory or use the root of sd-pam",
            pam,
        );
        if Path::new("/dev/kvm").exists() {
            let kvm = self.sandbox_succeeds(&["python3", "-I", "-c", "import os,fcntl; fd=os.open('/dev/kvm',os.O_RDWR); assert fcntl.ioctl(fd,0xAE00,0)==12; os.close(fd)"])?;
            self.report.expect(
                Want::Succeed,
                "filesystem-view-kvm",
                "KVM opens and reports its API version",
                kvm,
            );
        } else {
            self.report
                .note("no /dev/kvm on this host; KVM compatibility not tested");
        }
        Ok(())
    }

    /// cron and at would run the sandbox user's commands outside any
    /// session, after the supervisor has stopped everything it can see.
    pub(super) fn schedulers(&mut self) -> Result<()> {
        let user = self.user().to_owned();
        if host::has_program("crontab") {
            let listed = Command::new("crontab")
                .arg("-l")
                .stdin(Stdio::null())
                .output();
            self.report.expect(
                Want::Succeed,
                "cron-control",
                format!("{} may use crontab (control)", self.runner.name),
                listed.is_ok_and(|output| {
                    output.status.success()
                        || String::from_utf8_lossy(&output.stderr).contains("no crontab")
                }),
            );
            let installed = self
                .sandbox(&["crontab", "-"], b"# agentic-job sandbox check\n")?
                .success();
            if installed {
                let _ = self.root.crontab_remove(&user);
            }
            self.report.expect(
                Want::Fail,
                "cron",
                format!("{user} can't install a crontab"),
                installed,
            );
        } else {
            self.report.note("no crontab on this host");
        }
        if host::has_program("at") {
            // Where at has neither of its lists, only root may use it,
            // and the runner's user is no control.
            self.control_or_note("at-control", "at", &["at", "-l"]);
            let got = self.sandbox_succeeds(&["at", "-l"])?;
            self.report
                .expect(Want::Fail, "at", format!("{user} can't use at"), got);
        } else {
            self.report.note("no at on this host");
        }
        Ok(())
    }

    /// The units the configuration says are stopped, are.
    pub(super) fn services(&mut self) {
        let units = &self.config.sandbox.stop_services;
        if units.is_empty() {
            return;
        }
        let active = |unit: &str| {
            host::succeeds(Command::new("systemctl").args(["is-active", "--quiet", "--", unit]))
        };
        self.report.expect(
            Want::Succeed,
            "service-control",
            format!("{ALWAYS_ACTIVE_UNIT} is active (control)"),
            active(ALWAYS_ACTIVE_UNIT),
        );
        for unit in units {
            self.report.expect(
                Want::Fail,
                &format!("service:{unit}"),
                format!("{unit} is not running"),
                active(unit),
            );
        }
    }

    /// The sandbox user connects to no Unix socket and no local TCP port
    /// but the host's own and the configured ones. The control is a pair
    /// of listeners of ours, which it must find and connect to. The Unix
    /// one is a path, since the prober reports abstract sockets without
    /// trying them.
    pub(super) fn local_services(&mut self) -> Result<()> {
        let user = self.user().to_owned();
        let control_path = format!("/tmp/agentic-job-{}.sock", self.canary);
        let control_unix =
            UnixListener::bind(&control_path).context("listening on a socket in /tmp")?;
        std::fs::set_permissions(
            &control_path,
            std::fs::Permissions::from_mode(MODE_OPEN_SOCKET),
        )?;
        let control_tcp =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("listening on loopback")?;
        let controls = [
            Reached::Unix(control_path.clone()),
            Reached::Tcp(control_tcp.local_addr()?),
        ];
        let output = self.sandbox(&[SELF_COPY, "sandbox", "probe-local"], b"");
        drop((control_unix, control_tcp));
        let _ = std::fs::remove_file(&control_path);
        let output = output?;
        let reached: Vec<Reached> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(Reached::parse)
            .collect();
        self.report.expect(
            Want::Succeed,
            "local-control",
            format!(
                "{user} finds and reaches a Unix socket and a TCP port opened for it (control)"
            ),
            output.success() && controls.iter().all(|control| reached.contains(control)),
        );

        let check = &self.config.sandbox.check;
        let allowed: Vec<String> = HOST_SOCKETS
            .iter()
            .map(|&socket| socket.to_owned())
            // Its own session's: its bus and its systemd manager.
            .chain([format!("/run/user/{}/", self.entry.user().uid)])
            .chain(check.allow_sockets.iter().cloned())
            .collect();
        let (unix, tcp): (Vec<&Reached>, Vec<&Reached>) = reached
            .iter()
            .filter(|reached| !controls.contains(*reached))
            .filter(|reached| match reached {
                Reached::Unix(name) => !socket_allowed(name, &allowed),
                Reached::UnixDatagram(name) => {
                    !socket_allowed(name, &allowed) && !systemd_notification_socket(name)
                }
                Reached::Tcp(addr) => {
                    let port = addr.port();
                    // The egress proxy is where it is meant to connect.
                    let proxy = self.config.egress.proxy && port == egress::PROXY_PORT;
                    // Without one its network is open, and a resolver
                    // on loopback is how it resolves names: the rules
                    // close that port only behind the proxy.
                    let resolver = !self.config.egress.proxy
                        && addr.ip().is_loopback()
                        && port == network::DNS_PORT;
                    !proxy && !resolver && !check.allow_tcp_ports.contains(&port)
                }
            })
            .partition(|reached| !matches!(reached, Reached::Tcp(_)));
        let list = |found: &[&Reached]| {
            found
                .iter()
                .map(|reached| reached.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        self.report.expect(
            Want::Fail,
            "local-sockets",
            if unix.is_empty() {
                format!("{user} connects to no Unix socket but the host's own and the allowed ones")
            } else {
                format!(
                    "{user} connects to {} (stop what listens there, or name it in sandbox.check.allow-sockets)",
                    list(&unix)
                )
            },
            !unix.is_empty(),
        );
        self.report.expect(
            Want::Fail,
            "local-tcp",
            if tcp.is_empty() {
                format!("{user} connects to no local TCP port but the allowed ones")
            } else {
                format!(
                    "{user} connects to {} (stop what listens there, or name the port in sandbox.check.allow-tcp-ports)",
                    list(&tcp)
                )
            },
            !tcp.is_empty(),
        );
        Ok(())
    }

    /// Through its LocalAPI, tailscaled would dial and list the tailnet
    /// for anyone, whatever the packet filter says.
    pub(super) fn tailscaled(&mut self) -> Result<()> {
        let user = self.user().to_owned();
        // Its socket is in a directory setup closed, so the daemon is
        // looked for by its process, which any user sees.
        if !host::succeeds(Command::new("pgrep").args(["-x", "tailscaled"])) {
            self.report
                .note("no tailscaled on this host, so no LocalAPI to reach");
            return Ok(());
        }
        self.report.expect(
            Want::Succeed,
            "tailscale-control",
            "root uses tailscaled's LocalAPI (control)",
            self.root.tailscale_status().is_some(),
        );
        let got = self.sandbox_succeeds(&["tailscale", "status"])?;
        self.report.expect(
            Want::Fail,
            "tailscale-status",
            format!("{user} can't run tailscale status"),
            got,
        );
        let got = self.sandbox_succeeds(&[
            "curl",
            "-sS",
            "-m",
            "10",
            "-o",
            "/dev/null",
            "--unix-socket",
            TAILSCALE_SOCKET,
            LOCALAPI_STATUS,
        ])?;
        self.report.expect(
            Want::Fail,
            "tailscale-localapi",
            format!("{user} can't call tailscaled's LocalAPI"),
            got,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_visibility_probe_detects_a_live_process() {
        for (pid, visible) in [(std::process::id().to_string(), true), ("0".into(), false)] {
            let output = Command::new("sh")
                .args(["-c", PROC_VISIBLE, "sh", &pid])
                .output()
                .unwrap();
            assert_eq!(output.status.success(), visible, "{pid}: {output:?}");
        }
    }

    #[test]
    fn proc_self_probe_survives_systemd_expansion() {
        // systemd replaces `$$` and `${NAME}` in a service's arguments.
        for script in [PROC_SELF, PROC_VISIBLE] {
            assert!(!script.contains("$$") && !script.contains("${"), "{script}");
        }
        let status = Command::new("sh").args(["-c", PROC_SELF]).status().unwrap();
        assert!(status.success(), "{status}");
    }

    #[test]
    fn variables_are_named_and_their_values_are_not() {
        let environs =
            b"HOME=/home/agent\0ACTIONS_RUNTIME_TOKEN=secret\0\0LANG=C\0COPY=xACTIONS_y\0";
        let named: Vec<String> = variables_holding(environs, b"ACTIONS_")
            .into_iter()
            .collect();
        assert_eq!(named, ["ACTIONS_RUNTIME_TOKEN", "COPY"]);
        assert!(variables_holding(b"HOME=/home/agent\0", b"ACTIONS_").is_empty());
    }

    #[test]
    fn allowed_sockets() {
        let allowed: Vec<String> = [
            "/run/dbus/system_bus_socket",
            "/run/systemd/",
            "/run/x/io.systemd.*",
            "@named",
        ]
        .iter()
        .map(|&s| s.to_owned())
        .collect();
        let cases = [
            ("/run/dbus/system_bus_socket", true),
            ("/run/systemd/journal/stdout", true),
            ("/run/systemd", false),
            ("/run/systemd-other/x", false),
            ("/run/dbus/system_bus_socket2", false),
            ("/run/docker.sock", false),
            ("/run/x/io.systemd.Hostname", true),
            ("/run/x/io.systemd", false),
            ("/run/x/resolve/io.systemd.Resolve", false),
            ("@named", true),
            ("@named-other", false),
        ];
        for (name, want) in cases {
            assert_eq!(socket_allowed(name, &allowed), want, "{name}");
        }
    }

    #[test]
    fn systemd_notification_sockets_by_name() {
        let cases = [
            ("@14028884306257329759", true),
            ("@0", true),
            // More than 64 bits, a name with letters, a path, no name.
            ("@140288843062573297590", false),
            ("@1402888430625732975a", false),
            ("@ISCSIADM_ABSTRACT_NAMESPACE", false),
            ("/run/14028884306257329759", false),
            ("@", false),
        ];
        for (name, want) in cases {
            assert_eq!(systemd_notification_socket(name), want, "{name}");
        }
    }
}
