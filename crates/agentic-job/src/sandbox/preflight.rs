//! `agentic-job sandbox preflight`: prove, as the user the agent runs as
//! and before anything of the run's starts, what a runner profile asks of
//! its host (docs/dispatch.md#capability-preflight). A runner label or a
//! device node is not proof: the preflight opens `/dev/kvm` for reading
//! and writing, boots a guest with KVM and no fallback to emulation, and,
//! for `libvirt = "session"`, creates and destroys a guest in
//! `qemu:///session`. It does not touch `qemu:///system`, which setup
//! refuses the runner's user by refusing the `libvirt` group.
//!
//! The guest is one boot sector built here: it writes to QEMU's
//! `isa-debug-exit` port, which ends QEMU with a status only a guest
//! that ran can produce, and halts where that device is absent, as under
//! libvirt. Every command has a fixed time limit and is killed when it
//! passes it or the job is cancelled; a libvirt guest is destroyed, and
//! its absence checked, whatever came before.

use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use ring::rand::SecureRandom;
use rustix::fs::{Mode, OFlags};
use serde::Deserialize;
use tokio::sync::watch;

use crate::config::Config;
use crate::exit::Exit;

/// The `[preflight]` table. Each check is off unless its key is set.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Preflight {
    /// `/dev/kvm` usable by the agent's user, hardware virtualization,
    /// and a guest that boots and stops with KVM.
    pub kvm: bool,
    /// A libvirt instance the agent's user may use; needs `kvm`.
    pub libvirt: Option<Libvirt>,
    /// The fewest CPUs this process may run on.
    pub vcpus: Option<u64>,
    /// The least memory, in GiB, the host and this process's cgroups allow.
    pub memory_gib: Option<u64>,
    /// The least free space, in GiB, an unprivileged user has in the
    /// working directory's filesystem.
    pub disk_gib: Option<u64>,
}

/// Only the user's own instance: `qemu:///system` runs guests as root.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Libvirt {
    Session,
}

/// The largest each resource may ask for: far above any one host, so
/// that a typo is refused rather than read as a demand no host meets.
const MAX_VCPUS: u64 = 4096;

const MAX_MEMORY_GIB: u64 = 64 * 1024;

const MAX_DISK_GIB: u64 = 1024 * 1024;

const GIB: u64 = 1 << 30;

impl Preflight {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.libvirt.is_none() || self.kvm,
            "preflight.libvirt needs preflight.kvm: its guest is a KVM guest"
        );
        for (key, value, max) in [
            ("vcpus", self.vcpus, MAX_VCPUS),
            ("memory-gib", self.memory_gib, MAX_MEMORY_GIB),
            ("disk-gib", self.disk_gib, MAX_DISK_GIB),
        ] {
            if let Some(value) = value {
                ensure!(
                    (1..=max).contains(&value),
                    "preflight.{key} must be from 1 to {max}, not {value}"
                );
            }
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The run's configuration; a file with no `[preflight]` checks nothing
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
}

/// QEMU for x86 guests, the boot sector's: by this name on PATH, as
/// Debian and Fedora install it, or else RHEL's only build.
const QEMU: &str = "qemu-system-x86_64";

const QEMU_KVM: &str = "/usr/libexec/qemu-kvm";

/// The machine both offer: RHEL 10's QEMU has no `pc` (i440fx). Its
/// built-in AHCI controller takes an `if=ide` drive, and libvirt's
/// `sata` bus.
const MACHINE: &str = "q35";

const VIRSH: &str = "virsh";

const SESSION_URI: &str = "qemu:///session";

const KVM_DEVICE: &str = "/dev/kvm";

/// `isa-debug-exit`'s port, and the byte the guest writes to it. QEMU
/// then exits with `(byte << 1) | 1`, which nothing else makes it do.
const DEBUG_EXIT_PORT: &str = "0xf4";

const DEBUG_EXIT_BYTE: u8 = 0x31;

const GUEST_EXIT_STATUS: i32 = ((DEBUG_EXIT_BYTE as i32) << 1) | 1;

/// The guest's code, at 0x7c00 in real mode: `mov al, BYTE; out 0xf4, al;
/// cli; hlt; jmp` back to the `hlt`.
const GUEST_CODE: [u8; 8] = [0xb0, DEBUG_EXIT_BYTE, 0xe6, 0xf4, 0xfa, 0xf4, 0xeb, 0xfd];

const SECTOR: usize = 512;

const BOOT_SIGNATURE: [u8; 2] = [0x55, 0xaa];

/// The guest's memory, in MiB: the firmware and one sector need little.
const GUEST_MIB: &str = "16";

/// How much of a command's standard error a refusal quotes.
const MAX_DIAGNOSTIC: usize = 300;

/// What the preflight reads and runs, so that tests can stand in for
/// the host.
#[derive(Debug, Clone)]
pub struct Host {
    pub root: bool,
    pub kvm: PathBuf,
    pub cpuinfo: PathBuf,
    pub meminfo: PathBuf,
    /// The process's cgroup membership and mounted hierarchies.
    pub cgroup: PathBuf,
    pub mountinfo: PathBuf,
    pub initial_cgroup_namespace: bool,
    pub disk: PathBuf,
    /// QEMU's builds, the first one installed used.
    pub qemu: Vec<Program>,
    pub virsh: Program,
    pub limits: Limits,
}

/// A program and the arguments that come before the preflight's.
#[derive(Debug, Clone)]
pub struct Program {
    pub path: PathBuf,
    pub args: Vec<OsString>,
}

impl Program {
    fn new(path: &str) -> Self {
        Self {
            path: path.into(),
            args: Vec::new(),
        }
    }

    /// Whether it is a file: at its path, or for a bare name in PATH.
    fn installed(&self) -> bool {
        if self.path.components().count() > 1 {
            return self.path.is_file();
        }
        std::env::var_os("PATH")
            .is_some_and(|dirs| std::env::split_paths(&dirs).any(|d| d.join(&self.path).is_file()))
    }
}

/// How long each command may take. Fixed: a host that needs longer to
/// boot a guest of one sector is not fit for VM tests. The cleanup's
/// two commands fit in the runner's grace between a cancellation's
/// SIGINT and its SIGKILL, about ten seconds.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub boot: Duration,
    pub session: Duration,
    pub cleanup: Duration,
}

impl Limits {
    pub const DEFAULT: Self = Self {
        boot: Duration::from_secs(60),
        session: Duration::from_secs(60),
        cleanup: Duration::from_secs(4),
    };
}

impl Host {
    pub fn system() -> Self {
        Self {
            root: rustix::process::geteuid().is_root(),
            kvm: KVM_DEVICE.into(),
            cpuinfo: "/proc/cpuinfo".into(),
            meminfo: "/proc/meminfo".into(),
            cgroup: "/proc/self/cgroup".into(),
            mountinfo: "/proc/self/mountinfo".into(),
            initial_cgroup_namespace: std::fs::read_link("/proc/self/ns/cgroup")
                .is_ok_and(|ns| is_initial_cgroup_namespace(&ns)),
            disk: ".".into(),
            qemu: vec![Program::new(QEMU), Program::new(QEMU_KVM)],
            virsh: Program::new(VIRSH),
            limits: Limits::DEFAULT,
        }
    }
}

pub fn run(args: &Args) -> Result<Exit> {
    let preflight = Config::load(&args.config)?.preflight;
    if preflight.is_empty() {
        println!("preflight: nothing asked of this host");
        return Ok(Exit::Success);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the preflight's runtime")?;
    let result = runtime.block_on(async {
        let cancel = cancel_on_signal()?;
        check(&preflight, &Host::system(), cancel).await
    });
    match result {
        Ok(()) => Ok(Exit::Success),
        Err(err) => {
            eprintln!("::error::preflight did not pass: {err:#}");
            Ok(Exit::Failure)
        }
    }
}

/// True once the job is cancelled: the runner sends SIGINT, then SIGTERM.
fn cancel_on_signal() -> Result<watch::Receiver<bool>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt()).context("handling SIGINT")?;
    let mut terminate = signal(SignalKind::terminate()).context("handling SIGTERM")?;
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        let _ = tx.send(true);
    });
    Ok(rx)
}

/// Every check `preflight` asks for, in order, stopping at the first
/// that fails.
pub async fn check(
    preflight: &Preflight,
    host: &Host,
    cancel: watch::Receiver<bool>,
) -> Result<()> {
    ensure!(
        !host.root,
        "it runs as root, which proves nothing of the agent's user: run it as that user"
    );
    resources(preflight, host)?;
    if !preflight.kvm {
        return Ok(());
    }
    ensure!(
        cfg!(target_arch = "x86_64"),
        "the KVM preflight's guest is x86 code, for x86-64 hosts only"
    );
    device_verdict(&host.kvm, device_state(&host.kvm))?;
    let cpuinfo = std::fs::read_to_string(&host.cpuinfo)
        .with_context(|| format!("reading {}", host.cpuinfo.display()))?;
    ensure!(
        hardware_virtualization(&cpuinfo),
        "the CPU has no hardware virtualization (vmx or svm in {})",
        host.cpuinfo.display()
    );
    println!(
        "preflight: {} opened for reading and writing",
        host.kvm.display()
    );
    let dir = tempfile::Builder::new()
        .prefix("agentic-job-preflight-")
        .tempdir()
        .context("creating the guest's directory")?;
    let image = dir.path().join("guest.img");
    std::fs::write(&image, boot_sector()).context("writing the guest's image")?;
    let runner = Runner { cancel };
    boot(host, &runner, &image).await?;
    if preflight.libvirt == Some(Libvirt::Session) {
        session(host, &runner, dir.path(), &image).await?;
    }
    Ok(())
}

fn resources(preflight: &Preflight, host: &Host) -> Result<()> {
    if let Some(want) = preflight.vcpus {
        let have = std::thread::available_parallelism()
            .context("counting the CPUs this process may use")?
            .get() as u64;
        enough("CPUs", have, want)?;
    }
    if let Some(want) = preflight.memory_gib {
        ensure!(
            host.initial_cgroup_namespace,
            "cannot prove effective memory in a cgroup namespace: ancestor limits may be hidden"
        );
        let meminfo = std::fs::read_to_string(&host.meminfo)
            .with_context(|| format!("reading {}", host.meminfo.display()))?;
        let mut have = mem_total(&meminfo)
            .with_context(|| format!("no MemTotal in {}", host.meminfo.display()))?;
        let own = std::fs::read_to_string(&host.cgroup)
            .with_context(|| format!("reading {}", host.cgroup.display()))?;
        let mounts = std::fs::read_to_string(&host.mountinfo)
            .with_context(|| format!("reading {}", host.mountinfo.display()))?;
        if let Some(limit) = cgroup_memory_max(&mounts, &own)? {
            have = have.min(limit);
        }
        enough("GiB of memory", have / GIB, want)?;
    }
    if let Some(want) = preflight.disk_gib {
        let stat = rustix::fs::statvfs(&host.disk)
            .with_context(|| format!("reading the free space of {}", host.disk.display()))?;
        enough(
            "GiB of free disk",
            stat.f_bavail.saturating_mul(stat.f_frsize) / GIB,
            want,
        )?;
    }
    Ok(())
}

fn enough(what: &str, have: u64, want: u64) -> Result<()> {
    ensure!(have >= want, "{have} {what}, below the {want} asked for");
    println!("preflight: {have} {what}, at least the {want} asked for");
    Ok(())
}

/// `MemTotal` of /proc/meminfo, in bytes.
fn mem_total(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let mut words = line.split_whitespace().skip(1);
    let kib: u64 = words.next()?.parse().ok()?;
    (words.next() == Some("kB")).then(|| kib.saturating_mul(1024))
}

/// Most cgroup levels looked at: the hierarchy is a few deep.
const MAX_CGROUP_DEPTH: usize = 64;

/// Decode the four escapes used in proc's mountinfo path fields. Decode
/// backslashes last so a literal `\040` is not mistaken for a space.
fn mount_path(field: &str) -> PathBuf {
    field
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
        .into()
}

fn absolute_cgroup_path(path: &Path) -> bool {
    path.is_absolute() && !path.components().any(|c| c == Component::ParentDir)
}

/// Linux reserves PROC_CGROUP_INIT_INO (0xeffffffb) for the initial
/// cgroup namespace (include/linux/proc_ns.h). Comparing with PID 1 is
/// insufficient: PID 1 may itself be in the same noninitial namespace.
/// Unknown namespace identities are refused, not assumed to be initial.
fn is_initial_cgroup_namespace(link: &Path) -> bool {
    link == Path::new("cgroup:[4026531835]")
}

/// The least visible `memory.max` of this process's cgroup v2 and its
/// ancestors. Map membership through mountinfo's filesystem root, not a
/// hard-coded /sys path: bind mounts and cgroup namespaces can expose a
/// different hierarchy root. Never interpret an unmappable path or a
/// missing limit as unlimited. Ancestors hidden by a namespace cannot be
/// inspected; a mount rooted below the namespace root is refused.
fn cgroup_memory_max(mounts: &str, own: &str) -> Result<Option<u64>> {
    ensure!(
        !own.lines().any(|l| l
            .split(':')
            .nth(1)
            .is_some_and(|cs| cs.split(',').any(|c| c == "memory"))),
        "cannot prove effective memory with a cgroup v1 memory controller"
    );
    let Some(path) = own.lines().find_map(|l| l.strip_prefix("0::")) else {
        ensure!(!own.trim().is_empty(), "cannot read cgroup membership");
        return Ok(None);
    };
    let path = Path::new(path);
    ensure!(
        absolute_cgroup_path(path),
        "cannot resolve cgroup membership {path:?}"
    );
    let mut candidates = Vec::new();
    for line in mounts.lines() {
        let Some((fields, fs)) = line.split_once(" - ") else {
            continue;
        };
        if fs.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let fields: Vec<_> = fields.split_whitespace().collect();
        ensure!(fields.len() >= 6, "invalid cgroup2 mountinfo entry: {line}");
        let root = mount_path(fields[3]);
        let mount = mount_path(fields[4]);
        ensure!(
            absolute_cgroup_path(&root) && absolute_cgroup_path(&mount),
            "invalid cgroup2 mount paths"
        );
        if let Ok(relative) = path.strip_prefix(&root) {
            candidates.push((root, mount, relative));
        }
    }
    // Prefer the widest view so a bind mount cannot hide an ancestor's cap.
    candidates.sort_by_key(|(root, _, _)| root.components().count());
    let (root, mount, relative) = candidates
        .first()
        .context("cannot map cgroup membership to a cgroup2 mount")?;
    ensure!(
        root == Path::new("/"),
        "cannot prove effective memory: cgroup2 mount hides ancestors above {}",
        root.display()
    );
    let mut dir = mount.join(relative);
    let mut least: Option<u64> = None;
    for _ in 0..MAX_CGROUP_DEPTH {
        let file = dir.join("memory.max");
        match std::fs::read_to_string(&file) {
            Ok(text) => {
                let text = text.trim();
                if text != "max" {
                    let limit: u64 = text
                        .parse()
                        .with_context(|| format!("{} holds {text:?}", file.display()))?;
                    least = Some(least.map_or(limit, |l| l.min(limit)));
                }
            }
            // Only the hierarchy root lacks memory.max. Verify that this
            // really is a readable hierarchy, not an unavailable mount.
            Err(err) if err.kind() == ErrorKind::NotFound && dir == *mount => {
                std::fs::read_to_string(dir.join("cgroup.controllers"))
                    .context("cannot read the cgroup2 hierarchy root")?;
            }
            Err(err) => return Err(err).with_context(|| format!("reading {}", file.display())),
        }
        if dir == *mount {
            return Ok(least);
        }
        ensure!(dir.pop(), "cannot walk cgroup ancestors");
    }
    bail!("cgroup hierarchy exceeds {MAX_CGROUP_DEPTH} levels; cannot prove effective memory")
}

/// What opening the KVM device as this process found.
#[derive(Debug)]
enum Device {
    Missing,
    NotCharacter,
    Denied(std::io::Error),
    Opened,
}

/// The device as this process's own credentials find it: opened for
/// reading and writing, not followed if it is a link.
fn device_state(path: &Path) -> Device {
    match std::fs::symlink_metadata(path) {
        Err(err) if err.kind() == ErrorKind::NotFound => return Device::Missing,
        Err(err) => return Device::Denied(err),
        Ok(meta) if !meta.file_type().is_char_device() => return Device::NotCharacter,
        Ok(_) => {}
    }
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY;
    match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(_) => Device::Opened,
        Err(errno) => Device::Denied(errno.into()),
    }
}

fn device_verdict(path: &Path, device: Device) -> Result<()> {
    let path = path.display();
    match device {
        Device::Opened => Ok(()),
        Device::Missing => bail!("{path} does not exist: the host offers no KVM"),
        Device::NotCharacter => bail!("{path} is not a character device"),
        Device::Denied(err) => bail!(
            "{path} cannot be opened for reading and writing by uid {}: {err}",
            rustix::process::geteuid().as_raw()
        ),
    }
}

/// Whether /proc/cpuinfo's flags name Intel's or AMD's virtualization.
fn hardware_virtualization(cpuinfo: &str) -> bool {
    cpuinfo
        .lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(key, _)| key.trim() == "flags")
        .any(|(_, flags)| flags.split_whitespace().any(|f| f == "vmx" || f == "svm"))
}

fn boot_sector() -> Vec<u8> {
    let mut sector = vec![0; SECTOR];
    sector[..GUEST_CODE.len()].copy_from_slice(&GUEST_CODE);
    sector[SECTOR - BOOT_SIGNATURE.len()..].copy_from_slice(&BOOT_SIGNATURE);
    sector
}

/// Runs the preflight's commands, each killed at its limit or once the
/// job is cancelled.
struct Runner {
    cancel: watch::Receiver<bool>,
}

impl Runner {
    /// PROGRAM with ARGS, its output once it ends within LIMIT. A cleanup
    /// command is not stopped by cancellation, only by its limit.
    async fn output(
        &self,
        program: &Program,
        args: &[OsString],
        limit: Duration,
        cleanup: bool,
    ) -> Result<Output> {
        let name = program.path.display();
        let child = tokio::process::Command::new(&program.path)
            .args(&program.args)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| match err.kind() {
                ErrorKind::NotFound => anyhow!("{name} is not installed"),
                _ => anyhow!(err).context(format!("starting {name}")),
            })?;
        let mut cancel = self.cancel.clone();
        let cancelled = async move {
            // A dropped sender cancels nothing.
            if cleanup || cancel.wait_for(|c| *c).await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            output = tokio::time::timeout(limit, child.wait_with_output()) => output
                .map_err(|_| anyhow!("{name} did not finish within {}s", limit.as_secs_f64()))?
                .with_context(|| format!("waiting for {name}")),
            () = cancelled => bail!("cancelled while {name} ran"),
        }
    }
}

/// The last line a command wrote to standard error, shortened.
fn diagnostic(output: &Output) -> String {
    let text = String::from_utf8_lossy(&output.stderr);
    let line = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let mut line = line.trim().to_owned();
    if line.len() > MAX_DIAGNOSTIC {
        let mut end = MAX_DIAGNOSTIC;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line.truncate(end);
        line.push('…');
    }
    if line.is_empty() {
        "no message".to_owned()
    } else {
        line
    }
}

/// Boots the guest with KVM and no other accelerator, so that QEMU
/// refuses to start rather than emulate, and waits for it to exit.
async fn boot(host: &Host, runner: &Runner, image: &Path) -> Result<()> {
    let mut drive = OsString::from("format=raw,if=ide,file=");
    drive.push(image);
    let args: Vec<OsString> = [
        "-accel",
        "kvm",
        "-cpu",
        "host",
        "-machine",
        MACHINE,
        "-m",
        GUEST_MIB,
        "-smp",
        "1",
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-serial",
        "none",
        "-monitor",
        "none",
        "-nic",
        "none",
        "-no-reboot",
        "-device",
        &format!("isa-debug-exit,iobase={DEBUG_EXIT_PORT},iosize=0x04"),
        "-drive",
    ]
    .into_iter()
    .map(OsString::from)
    .chain([drive])
    .collect();
    let qemu = host.qemu.iter().find(|q| q.installed()).with_context(|| {
        let names: Vec<String> = host
            .qemu
            .iter()
            .map(|q| q.path.display().to_string())
            .collect();
        format!("QEMU is not installed: none of {}", names.join(", "))
    })?;
    let started = Instant::now();
    let output = runner
        .output(qemu, &args, host.limits.boot, false)
        .await
        .context("booting a guest with KVM")?;
    ensure!(
        output.status.code() == Some(GUEST_EXIT_STATUS),
        "booting a guest with KVM: {} ended with {} rather than the guest's exit: {}",
        qemu.path.display(),
        output.status,
        diagnostic(&output)
    );
    println!(
        "preflight: a KVM guest booted and stopped in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// A fresh identity even across PID reuse and interrupted invocations.
fn domain_uuid() -> Result<String> {
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("generating the guest's random identity"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = format!("{:032x}", u128::from_be_bytes(bytes));
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// The libvirt guest: transient, so that destroying it removes it.
fn domain_xml(uuid: &str, image: &Path) -> Result<String> {
    let image = image.to_str().context("the guest's path is not UTF-8")?;
    ensure!(
        !image.contains(['&', '<', '>', '\'', '"']),
        "the guest's path {image:?} has a character XML would need escaped"
    );
    Ok(format!(
        "<domain type='kvm'>
  <name>agentic-job-preflight-{uuid}</name>
  <uuid>{uuid}</uuid>
  <memory unit='MiB'>{GUEST_MIB}</memory>
  <vcpu>1</vcpu>
  <os><type arch='x86_64' machine='{MACHINE}'>hvm</type><boot dev='hd'/></os>
  <cpu mode='host-passthrough'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>destroy</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw'/>
      <source file='{image}'/>
      <target dev='sda' bus='sata'/>
    </disk>
  </devices>
</domain>
"
    ))
}

fn virsh_args(args: &[&str]) -> Vec<OsString> {
    ["-c", SESSION_URI]
        .iter()
        .chain(args)
        .map(OsString::from)
        .collect()
}

/// virsh with ARGS, its standard output if it succeeded.
async fn virsh(
    host: &Host,
    runner: &Runner,
    args: &[&str],
    limit: Duration,
    cleanup: bool,
) -> Result<String> {
    let what = format!("virsh {}", args.first().copied().unwrap_or_default());
    let output = runner
        .output(&host.virsh, &virsh_args(args), limit, cleanup)
        .await
        .with_context(|| what.clone())?;
    ensure!(
        output.status.success(),
        "{what}: {}: {}",
        output.status,
        diagnostic(&output)
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// `qemu:///session` answers as this user, creates the guest, which
/// runs, and destroys it. The guest is destroyed, and its absence
/// checked, after any failure past the answer.
async fn session(host: &Host, runner: &Runner, dir: &Path, image: &Path) -> Result<()> {
    let uri = virsh(host, runner, &["uri"], host.limits.session, false)
        .await
        .with_context(|| format!("{SESSION_URI} did not answer"))?;
    ensure!(
        uri.trim() == SESSION_URI,
        "virsh connected to {:?}, not {SESSION_URI}",
        uri.trim()
    );
    let uuid = domain_uuid()?;
    let xml = dir.join("guest.xml");
    std::fs::write(&xml, domain_xml(&uuid, image)?).context("writing the guest's domain")?;
    let xml = xml.to_str().context("the domain's path is not UTF-8")?;
    let started = Instant::now();
    let checked = async {
        virsh(host, runner, &["create", xml], host.limits.session, false).await?;
        let state = virsh(
            host,
            runner,
            &["domstate", &uuid],
            host.limits.session,
            false,
        )
        .await?;
        ensure!(
            state.trim() == "running",
            "the guest is {:?}, not running",
            state.trim()
        );
        Ok(())
    }
    .await;
    // Creation can have taken effect even if virsh timed out or was cancelled.
    // Always clean up, but use our random UUID, never a possibly reused name.
    let cleaned = clean_up(host, runner, &uuid).await;
    match (checked, cleaned) {
        (Ok(()), Ok(())) => {
            println!(
                "preflight: {SESSION_URI} created and destroyed a guest in {:.1}s",
                started.elapsed().as_secs_f64()
            );
            Ok(())
        }
        (Err(err), Ok(())) => Err(err.context(format!("a guest in {SESSION_URI}"))),
        (Ok(()), Err(err)) => Err(err),
        (Err(err), Err(cleanup)) => {
            Err(err.context(format!("a guest in {SESSION_URI}, and then {cleanup:#}")))
        }
    }
}

/// Destroys UUID, whether or not its creation got far enough to need it,
/// and checks it is gone.
async fn clean_up(host: &Host, runner: &Runner, uuid: &str) -> Result<()> {
    let limit = host.limits.cleanup;
    let destroyed = virsh(host, runner, &["destroy", uuid], limit, true).await;
    let listed = virsh(host, runner, &["list", "--all", "--uuid"], limit, true)
        .await
        .context("cleaning up the guest")?;
    if listed.lines().any(|l| l.trim() == uuid) {
        let why = destroyed
            .err()
            .map(|e| format!(": {e:#}"))
            .unwrap_or_default();
        bail!("cleaning up the guest: {uuid} is still defined{why}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_off_and_bounded() {
        let parse = |text: &str| Config::parse(text).map(|c| c.preflight);
        assert!(parse("").unwrap().is_empty());
        let full = parse(
            "[preflight]\nkvm = true\nlibvirt = \"session\"\nvcpus = 64\nmemory-gib = 256\ndisk-gib = 500\n",
        )
        .unwrap();
        assert_eq!(full.libvirt, Some(Libvirt::Session));
        assert_eq!(
            (full.vcpus, full.memory_gib, full.disk_gib),
            (Some(64), Some(256), Some(500))
        );
        for (text, want) in [
            ("libvirt = \"session\"", "needs preflight.kvm"),
            ("kvm = true\nlibvirt = \"system\"", "unknown variant"),
            ("vcpus = 0", "preflight.vcpus must be from 1"),
            ("vcpus = 4097", "preflight.vcpus must be from 1"),
            ("memory-gib = 0", "preflight.memory-gib must be from 1"),
            ("disk-gib = 1048577", "preflight.disk-gib must be from 1"),
            ("vcpus = -1", "invalid value"),
            ("kvm = \"yes\"", "invalid type"),
            ("max-guests = 4", "unknown field"),
        ] {
            let err = format!(
                "{:#}",
                parse(&format!("[preflight]\n{text}\n")).unwrap_err()
            );
            assert!(err.contains(want), "{text:?}: {err}");
        }
    }

    #[test]
    fn the_device_must_open_for_reading_and_writing() {
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("kvm");
        std::fs::write(&regular, "").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink("/dev/null", &link).unwrap();
        // /dev/null is a character device anyone opens: the control.
        for (path, want) in [
            (dir.path().join("missing"), Some("does not exist")),
            (regular, Some("is not a character device")),
            (link, Some("is not a character device")),
            (PathBuf::from("/dev/null"), None),
        ] {
            let verdict = device_verdict(&path, device_state(&path));
            match want {
                None => verdict.unwrap(),
                Some(want) => {
                    let err = format!("{:#}", verdict.unwrap_err());
                    assert!(err.contains(want), "{}: {err}", path.display());
                }
            }
        }
        let denied = std::io::Error::from(rustix::io::Errno::ACCESS);
        let err = format!(
            "{:#}",
            device_verdict(Path::new(KVM_DEVICE), Device::Denied(denied)).unwrap_err()
        );
        assert!(
            err.contains("/dev/kvm cannot be opened for reading and writing by uid"),
            "{err}"
        );
    }

    #[test]
    fn virtualization_is_a_cpu_flag() {
        for (cpuinfo, want) in [
            ("flags\t\t: fpu vme vmx sse\n", true),
            ("flags\t\t: fpu svm\n", true),
            ("flags\t\t: fpu vme sse hypervisor\n", false),
            ("vmx flags\t: ept vpid\nflags\t: fpu\n", false),
            ("model name\t: vmx\n", false),
            ("", false),
        ] {
            assert_eq!(hardware_virtualization(cpuinfo), want, "{cpuinfo:?}");
        }
    }

    #[test]
    fn memory_is_the_least_of_host_and_cgroups() {
        assert_eq!(
            mem_total("MemFree: 1 kB\nMemTotal:  2048 kB\n"),
            Some(2 << 20)
        );
        assert_eq!(mem_total("MemTotal: 2048\n"), None);
        assert_eq!(mem_total(""), None);

        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("a/b");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(root.path().join("a/memory.max"), "4096\n").unwrap();
        std::fs::write(leaf.join("memory.max"), "max\n").unwrap();
        std::fs::write(root.path().join("cgroup.controllers"), "memory\n").unwrap();
        let mounts = format!(
            "1 0 0:1 / {} rw - cgroup2 cgroup rw\n",
            root.path().display()
        );
        let read = |own: &str| cgroup_memory_max(&mounts, own);
        assert_eq!(read("0::/a/b\n").unwrap(), Some(4096));
        assert_eq!(read("0::/a\n").unwrap(), Some(4096));
        assert_eq!(read("0::/\n").unwrap(), None);
        assert!(read("1:memory:/a\n").is_err());
        assert!(read("0::/../a\n").is_err());
        std::fs::write(leaf.join("memory.max"), "1024\n").unwrap();
        assert_eq!(read("0::/a/b\n").unwrap(), Some(1024));
        std::fs::write(leaf.join("memory.max"), "lots\n").unwrap();
        assert!(read("0::/a/b\n").is_err());
    }

    #[test]
    fn memory_discovery_maps_mounts_and_refuses_unavailable_limits() {
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().join("cgroup view");
        std::fs::create_dir_all(mount.join("child")).unwrap();
        std::fs::write(mount.join("memory.max"), "4096").unwrap();
        std::fs::write(mount.join("child/memory.max"), "max").unwrap();
        let escaped = mount.display().to_string().replace(' ', "\\040");
        for (root, own, want) in [
            ("/", "0::/\n", Some(Some(4096))),
            ("/", "0::/child\n", Some(Some(4096))),
            ("/", "0::/missing\n", None),
            ("/", "0::/../child\n", None),
            ("/", "0::relative\n", None),
            ("/", "", None),
            ("/", "0::/\n1:cpu,memory:/limited\n", None),
            ("/other", "0::/child\n", None),
            // A subtree mount can be mapped, but hides ancestor limits.
            ("/parent", "0::/parent/child\n", None),
        ] {
            let mounts = format!("1 0 0:1 {root} {escaped} rw - cgroup2 cgroup rw\n");
            let result = cgroup_memory_max(&mounts, own);
            match want {
                Some(want) => assert_eq!(result.unwrap(), want, "{root}: {own}"),
                None => assert!(result.is_err(), "{root}: {own}: {result:?}"),
            }
        }
        assert!(cgroup_memory_max("", "0::/\n").is_err());
        let mounts = format!("1 0 0:1 / {escaped} rw - cgroup2 cgroup rw\n");
        std::fs::remove_file(mount.join("memory.max")).unwrap();
        assert!(cgroup_memory_max(&mounts, "0::/\n").is_err());
        std::fs::write(mount.join("cgroup.controllers"), "memory").unwrap();
        assert_eq!(cgroup_memory_max(&mounts, "0::/child\n").unwrap(), None);
        std::fs::remove_file(mount.join("child/memory.max")).unwrap();
        assert!(cgroup_memory_max(&mounts, "0::/child\n").is_err());
    }

    #[test]
    fn namespaced_memory_cannot_ignore_hidden_ancestors() {
        assert!(is_initial_cgroup_namespace(Path::new(
            "cgroup:[4026531835]"
        )));
        for link in ["cgroup:[4026533000]", "", "mnt:[4026531835]"] {
            assert!(!is_initial_cgroup_namespace(Path::new(link)));
        }
        // The visible root can say max even when a hidden ancestor caps
        // memory. Refuse before trusting files inside that namespace.
        let host = Host {
            initial_cgroup_namespace: false,
            ..Host::system()
        };
        let err = resources(
            &Preflight {
                memory_gib: Some(1),
                ..Preflight::default()
            },
            &host,
        )
        .unwrap_err();
        assert!(err.to_string().contains("ancestor limits may be hidden"));
    }

    #[test]
    fn the_guest_is_one_boot_sector() {
        let sector = boot_sector();
        assert_eq!(sector.len(), SECTOR);
        assert_eq!(&sector[..GUEST_CODE.len()], GUEST_CODE);
        assert_eq!(&sector[SECTOR - 2..], BOOT_SIGNATURE);
        assert_eq!(GUEST_EXIT_STATUS, 99);
        let xml = domain_xml("g", Path::new("/tmp/d/guest.img")).unwrap();
        for part in [
            "<domain type='kvm'>",
            "machine='q35'",
            "<source file='/tmp/d/guest.img'/>",
            "bus='sata'",
        ] {
            assert!(xml.contains(part), "{part}: {xml}");
        }
        assert!(domain_xml("g", Path::new("/tmp/a'b")).is_err());
    }

    #[test]
    fn qemu_is_found_by_name_or_path() {
        for (path, want) in [
            ("sh", true),
            ("/bin/sh", true),
            ("/nonexistent/qemu-kvm", false),
            ("agentic-job-no-such-program", false),
            ("/dev", false),
        ] {
            assert_eq!(Program::new(path).installed(), want, "{path}");
        }
    }

    /// sh running a script at PATH, which appends its arguments to LOG
    /// and runs BODY. `$STARTED` is a file beside it, for a body to say
    /// it started. Read by sh, not executed: a script written as another
    /// test forks would be busy for exec.
    fn script(path: &Path, log: &Path, body: &str) -> Program {
        let dir = path.parent().unwrap().display();
        let text = format!(
            "STARTED='{dir}/started'\necho \"$*\" >> '{}'\n{body}\n",
            log.display()
        );
        std::fs::write(path, text).unwrap();
        Program {
            path: "/bin/sh".into(),
            args: vec![path.into()],
        }
    }

    /// virsh that answers each subcommand with its case of BODIES, and
    /// does nothing for the others.
    fn virsh_script(bodies: &[(&str, &str)]) -> String {
        let mut text = String::from("case \"$3\" in\n");
        for (sub, body) in bodies {
            text.push_str(&format!("{sub}) {body} ;;\n"));
        }
        text.push_str("esac");
        text
    }

    const QEMU_OK: &str = "exit 99";

    #[tokio::test]
    async fn failed_create_preserves_an_existing_guest() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("existing");
        std::fs::write(&marker, "unsaved guest state").unwrap();
        let log = dir.path().join("log");
        let host = Host {
            virsh: script(
                &dir.path().join("virsh"),
                &log,
                &virsh_script(&[
                    URI,
                    ("create", "echo 'error: domain already exists' >&2; exit 1"),
                    (
                        "destroy",
                        "if [ \"$4\" = agentic-job-preflight-$PPID ]; then rm \"${STARTED%/*}/existing\"; fi",
                    ),
                    ("list", "echo agentic-job-preflight-$PPID"),
                ]),
            ),
            ..Host::system()
        };
        let (_tx, cancel) = watch::channel(false);
        let err = session(
            &host,
            &Runner { cancel },
            dir.path(),
            Path::new("/guest.img"),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("domain already exists"));
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "unsaved guest state"
        );
        let xml = std::fs::read_to_string(dir.path().join("guest.xml")).unwrap();
        let uuid = xml
            .split_once("<uuid>")
            .unwrap()
            .1
            .split_once("</uuid>")
            .unwrap()
            .0;
        assert_eq!(uuid.len(), 36);
        assert!(xml.contains(&format!("<name>agentic-job-preflight-{uuid}</name>")));
        let log = std::fs::read_to_string(&log).unwrap();
        assert!(log.contains(&format!("destroy {uuid}\n")), "{log}");
        assert!(log.contains("list --all --uuid\n"), "{log}");
        assert_ne!(domain_uuid().unwrap(), uuid);
    }

    /// Each command's limit: far above what a script that answers takes,
    /// far below one that sleeps.
    const LIMIT: Duration = Duration::from_secs(2);

    const URI: (&str, &str) = ("uri", "echo qemu:///session");

    const RUNNING: (&str, &str) = (
        "domstate",
        "if [ \"$LC_ALL\" = C ]; then echo running; else echo 'en cours'; fi",
    );

    struct Case {
        name: &'static str,
        preflight: &'static str,
        root: bool,
        device: &'static str,
        cpuinfo: &'static str,
        qemu: Option<&'static str>,
        virsh: &'static [(&'static str, &'static str)],
        /// Cancel the job once a script has run `touch "$STARTED"`.
        cancel_on_start: bool,
        /// A part of the error, or none for success.
        want: Option<&'static str>,
        /// The virsh subcommands run, in order.
        calls: &'static [&'static str],
    }

    const KVM: &str = "kvm = true";

    const SESSION: &str = "kvm = true\nlibvirt = \"session\"";

    const VMX: &str = "flags\t: fpu vmx\n";

    const BASE: Case = Case {
        name: "",
        preflight: SESSION,
        root: false,
        device: "/dev/null",
        cpuinfo: VMX,
        qemu: Some(QEMU_OK),
        virsh: &[URI, RUNNING],
        cancel_on_start: false,
        want: None,
        calls: &["uri", "create", "domstate", "destroy", "list"],
    };

    /// Each refusal beside its positive control, against stand-ins for
    /// the device, /proc and the programs: the real ones need a KVM host.
    #[tokio::test]
    async fn each_refusal_and_its_control() {
        let cases = [
            Case {
                name: "session guest created and destroyed",
                ..BASE
            },
            Case {
                name: "kvm guest alone",
                preflight: KVM,
                calls: &[],
                ..BASE
            },
            Case {
                name: "enough resources",
                preflight: "vcpus = 1\nmemory-gib = 1\ndisk-gib = 1",
                calls: &[],
                ..BASE
            },
            Case {
                name: "root",
                root: true,
                want: Some("runs as root"),
                calls: &[],
                ..BASE
            },
            Case {
                name: "missing device",
                device: "/nonexistent/kvm",
                want: Some("/nonexistent/kvm does not exist"),
                calls: &[],
                ..BASE
            },
            Case {
                name: "not a device",
                device: "/proc/self/cgroup",
                want: Some("is not a character device"),
                calls: &[],
                ..BASE
            },
            Case {
                name: "no virtualization",
                cpuinfo: "flags\t: fpu hypervisor\n",
                want: Some("no hardware virtualization"),
                calls: &[],
                ..BASE
            },
            Case {
                name: "too few CPUs",
                preflight: "vcpus = 4096",
                want: Some("CPUs, below the 4096 asked for"),
                calls: &[],
                ..BASE
            },
            Case {
                name: "too little memory",
                preflight: "memory-gib = 65536",
                want: Some("GiB of memory, below the 65536"),
                calls: &[],
                ..BASE
            },
            Case {
                name: "too little disk",
                preflight: "disk-gib = 1048576",
                want: Some("GiB of free disk, below the 1048576"),
                calls: &[],
                ..BASE
            },
            Case {
                name: "no qemu",
                qemu: None,
                want: Some("QEMU is not installed: none of"),
                calls: &[],
                ..BASE
            },
            Case {
                name: "qemu without kvm",
                qemu: Some("echo 'qemu: failed to initialize kvm: Permission denied' >&2; exit 1"),
                want: Some("failed to initialize kvm"),
                calls: &[],
                ..BASE
            },
            Case {
                name: "guest never stops",
                qemu: Some("exec sleep 30"),
                want: Some("did not finish within"),
                calls: &[],
                ..BASE
            },
            Case {
                name: "cancelled boot",
                qemu: Some("touch \"$STARTED\"; exec sleep 30"),
                cancel_on_start: true,
                want: Some("cancelled while"),
                calls: &[],
                ..BASE
            },
            Case {
                name: "session does not answer",
                virsh: &[("uri", "exec sleep 30")],
                want: Some("qemu:///session did not answer"),
                calls: &["uri"],
                ..BASE
            },
            Case {
                name: "session refuses",
                virsh: &[("uri", "echo 'error: no socket' >&2; exit 1")],
                want: Some("error: no socket"),
                calls: &["uri"],
                ..BASE
            },
            Case {
                name: "another instance",
                virsh: &[("uri", "echo qemu:///system")],
                want: Some("not qemu:///session"),
                calls: &["uri"],
                ..BASE
            },
            Case {
                name: "create fails, cleanup still runs",
                virsh: &[URI, ("create", "echo 'error: no kvm' >&2; exit 1")],
                want: Some("error: no kvm"),
                calls: &["uri", "create", "destroy", "list"],
                ..BASE
            },
            Case {
                name: "create times out, cleanup still runs",
                virsh: &[URI, ("create", "exec sleep 30")],
                want: Some("did not finish within"),
                calls: &["uri", "create", "destroy", "list"],
                ..BASE
            },
            Case {
                name: "cancelled create, cleanup still runs",
                virsh: &[URI, ("create", "touch \"$STARTED\"; exec sleep 30")],
                cancel_on_start: true,
                want: Some("cancelled while"),
                calls: &["uri", "create", "destroy", "list"],
                ..BASE
            },
            Case {
                name: "guest not running",
                virsh: &[URI, ("domstate", "echo 'shut off'")],
                want: Some("not running"),
                ..BASE
            },
            Case {
                name: "cancelled while running, cleanup still runs",
                virsh: &[URI, ("domstate", "touch \"$STARTED\"; exec sleep 30")],
                cancel_on_start: true,
                want: Some("cancelled while"),
                ..BASE
            },
            Case {
                name: "cleanup fails",
                virsh: &[
                    URI,
                    RUNNING,
                    (
                        "destroy",
                        "echo \"$4\" > \"${STARTED%/*}/uuid\"; echo 'error: busy' >&2; exit 1",
                    ),
                    ("list", "cat \"${STARTED%/*}/uuid\"; echo other"),
                ],
                want: Some("is still defined: virsh destroy"),
                ..BASE
            },
            Case {
                name: "cleanup times out",
                virsh: &[URI, RUNNING, ("list", "exec sleep 30")],
                want: Some("cleaning up the guest"),
                ..BASE
            },
        ];
        for case in cases {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("log");
            std::fs::write(&log, "").unwrap();
            let cpuinfo = dir.path().join("cpuinfo");
            std::fs::write(&cpuinfo, case.cpuinfo).unwrap();
            let qemu = dir.path().join("qemu");
            let qemu = match case.qemu {
                Some(body) => script(&qemu, &dir.path().join("qemu.log"), body),
                None => Program {
                    path: qemu,
                    args: Vec::new(),
                },
            };
            let virsh = script(&dir.path().join("virsh"), &log, &virsh_script(case.virsh));
            // Resource controls must not depend on this test runner's
            // namespace or resource allocation.
            let meminfo = dir.path().join("meminfo");
            std::fs::write(&meminfo, "MemTotal: 2097152 kB\n").unwrap();
            let cgroup = dir.path().join("cgroup");
            std::fs::write(&cgroup, "0::/\n").unwrap();
            let mountinfo = dir.path().join("mountinfo");
            std::fs::write(
                &mountinfo,
                format!(
                    "1 0 0:1 / {} rw - cgroup2 cgroup rw\n",
                    dir.path().display()
                ),
            )
            .unwrap();
            std::fs::write(dir.path().join("memory.max"), "max").unwrap();
            let host = Host {
                root: case.root,
                kvm: case.device.into(),
                cpuinfo,
                meminfo,
                cgroup,
                mountinfo,
                initial_cgroup_namespace: true,
                qemu: vec![qemu],
                virsh,
                limits: Limits {
                    boot: LIMIT,
                    session: LIMIT,
                    cleanup: LIMIT,
                },
                ..Host::system()
            };
            let preflight = Config::parse(&format!("[preflight]\n{}\n", case.preflight))
                .unwrap()
                .preflight;
            // A dropped sender cancels nothing.
            let (tx, rx) = watch::channel(false);
            if case.cancel_on_start {
                let started = dir.path().join("started");
                tokio::spawn(async move {
                    while !started.exists() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    let _ = tx.send(true);
                });
            }
            let result = check(&preflight, &host, rx).await;
            match case.want {
                None => result.unwrap_or_else(|e| panic!("{}: {e:#}", case.name)),
                Some(want) => {
                    let err = format!("{:#}", result.unwrap_err());
                    assert!(err.contains(want), "{}: {err}", case.name);
                }
            }
            let calls: Vec<String> = std::fs::read_to_string(&log)
                .unwrap()
                .lines()
                .map(|l| l.split_whitespace().nth(2).unwrap_or_default().to_owned())
                .collect();
            assert_eq!(calls, case.calls, "{}", case.name);
            // QEMU, when it ran, was given KVM and nothing to fall back to.
            if let Ok(args) = std::fs::read_to_string(dir.path().join("qemu.log")) {
                assert!(
                    args.starts_with("-accel kvm -cpu host -machine q35 "),
                    "{}: {args}",
                    case.name
                );
                assert!(!args.contains("tcg"), "{}: {args}", case.name);
            }
        }
    }
}
