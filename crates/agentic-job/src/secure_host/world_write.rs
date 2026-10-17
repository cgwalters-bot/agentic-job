//! `agentic-job secure-host world-write OBJECT`: load the access-time
//! world-write policy as root, before `sandbox setup`, which refuses a host
//! without it. Every kernel operation goes through bpftool; this program
//! only decides what to ask of it and checks what it reports.
//!
//! OBJECT is the release's `world_write.bpf.o`, taken by its pinned
//! checksum with the binary, or compiled with a build of the same source:
//! no compiler here. The threat is any user but the owner changing a
//! world-writable file or non-sticky directory on the root filesystem
//! (docs/secure-host.md). Every refusal leaves the step failed; nothing
//! falls back to running without the policy.
//!
//! The same object holds the runner-read rule, which stays off unless
//! `--deny-runner-reads` asks for it: no task of the runner's user reads
//! (`/proc/PID/environ` and the like) another of that user's tasks that it
//! is not an ancestor of, Runner.Worker excepted. The threat is a step
//! reading the tokens in the environment of a process an earlier step of
//! the job left running.

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

use super::platform;
use crate::sandbox::host;
use crate::sandbox::setup::{WORLD_WRITE_LINKS, WORLD_WRITE_PIN};

/// What `statfs` reports for the BPF filesystem.
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;
const BPF_FS: &str = "/sys/fs/bpf";

/// How long one command may take, in `timeout(1)`'s terms: an install
/// from a slow mirror included.
const COMMAND_TIMEOUT: &str = "120";
/// Most of a command's output that is taken; bpftool's link list is far less.
const MAX_OUTPUT: usize = 1024 * 1024;

/// The unprivileged user the activation probe writes as.
const PROBE_USER: &str = "nobody";
/// Where the probe's two files go: on the root filesystem, which is all
/// the policy covers, and root's alone but for them.
const PROBE_PREFIX: &str = ".agentic-world-write-";

/// The runner's process that runs each step, and ends the job's orphans
/// by reading their environments: an ancestor of this loader.
const WORKER: &str = "Runner.Worker";
/// How many ancestors are looked through for it.
const MAX_ANCESTORS: usize = 32;
/// How long the read probe's target may take to become `sleep`.
const TARGET_TRIES: u32 = 50;
const TARGET_WAIT: std::time::Duration = std::time::Duration::from_millis(20);
/// The read probe's target lives no longer than this, in seconds.
const TARGET_SECONDS: &str = "120";

/// One command, its program looked up on root's fixed path; what it
/// printed, or an error with its status and standard error.
pub type Run<'a> = &'a mut dyn FnMut(&str, &[String]) -> Result<String>;

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

/// The policy map's value: the root filesystem's device as the kernel
/// encodes `dev_t` (major in the top 12 bits, minor in the low 20; not the
/// userspace encoding `stat` reports), then 1 for enabled, each a u32 in
/// this machine's byte order. No kernel offsets are needed.
pub fn root_config(dev: u64) -> Result<[u8; 8]> {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xffff_f000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffff_ff00);
    ensure!(
        major <= 0xfff && minor <= 0xf_ffff,
        "root device exceeds kernel dev_t"
    );
    let kernel =
        u32::try_from((major << 20) | minor).context("root device exceeds kernel dev_t")?;
    let mut value = [0; 8];
    value[..4].copy_from_slice(&kernel.to_ne_bytes());
    value[4..].copy_from_slice(&1u32.to_ne_bytes());
    Ok(value)
}

/// The ancestor of this loader the runner-read rule exempts, and the
/// user and group it runs as: the runner's.
#[derive(Debug, PartialEq, Eq)]
pub struct Worker {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// A `/proc/PID/status`'s name, parent and real uid and gid.
fn status_fields(status: &str) -> Result<(&str, u32, u32, u32)> {
    let field = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
            .map(str::trim)
            .with_context(|| format!("no {key} in the process status"))
    };
    let first = |key: &str| -> Result<u32> {
        field(key)?
            .split_whitespace()
            .next()
            .and_then(|id| id.parse().ok())
            .with_context(|| format!("unexpected {key} in the process status"))
    };
    let ppid = field("PPid")?
        .parse()
        .context("unexpected PPid in the process status")?;
    Ok((field("Name")?, ppid, first("Uid")?, first("Gid")?))
}

/// The nearest ancestor of PID named [`WORKER`], by the status STATUS
/// reads of each, at most [`MAX_ANCESTORS`] up. Its uid must not be
/// root's: that would make every root process a runner's. The action's
/// steps before this one are the job's own, so nothing untrusted has run
/// that could have named itself so.
pub fn find_worker(pid: u32, status: &mut dyn FnMut(u32) -> Result<String>) -> Result<Worker> {
    let mut pid = pid;
    for _ in 0..MAX_ANCESTORS {
        let text = status(pid)?;
        let (name, ppid, uid, gid) = status_fields(&text)?;
        if name == WORKER {
            ensure!(uid != 0, "{WORKER} runs as root");
            return Ok(Worker { pid, uid, gid });
        }
        ensure!(ppid > 0, "no {WORKER} among this process's ancestors");
        pid = ppid;
    }
    bail!("no {WORKER} within {MAX_ANCESTORS} ancestors of this process")
}

/// The one process named [`WORKER`] of PIDS, by the status STATUS reads
/// of each, for a loader that is not the Worker's descendant: the
/// image's, whose parent is conmon. One that ended in between is skipped;
/// a root one, or a second, is refused, rather than a guess at which is
/// this job's. As for [`find_worker`], nothing untrusted has run before.
pub fn sole_worker(pids: &[u32], status: &mut dyn FnMut(u32) -> Result<String>) -> Result<Worker> {
    let mut found = None;
    for &pid in pids {
        let Ok(text) = status(pid) else { continue };
        let (name, _, uid, gid) = status_fields(&text)?;
        if name != WORKER {
            continue;
        }
        ensure!(uid != 0, "{WORKER} {pid} runs as root");
        ensure!(found.is_none(), "more than one {WORKER} runs on this host");
        found = Some(Worker { pid, uid, gid });
    }
    found.with_context(|| format!("no {WORKER} runs on this host"))
}

/// The runner-read map's value: the runner's kuid, the Worker's tgid in
/// the initial pid namespace (this loader's), then 1 for enabled, each a
/// u32 in this machine's byte order.
pub fn runner_config(worker: &Worker) -> [u8; 12] {
    let mut value = [0; 12];
    value[..4].copy_from_slice(&worker.uid.to_ne_bytes());
    value[4..8].copy_from_slice(&worker.pid.to_ne_bytes());
    value[8..].copy_from_slice(&1u32.to_ne_bytes());
    value
}

/// One map's entry 0 set to VALUE, through its pin under PIN/maps.
fn update_map(map: &str, value: &[u8], run: Run) -> Result<()> {
    let mut update = strings(&[
        "map",
        "update",
        "pinned",
        &format!("{WORLD_WRITE_PIN}/maps/{map}"),
        "key",
        "hex",
        "00",
        "00",
        "00",
        "00",
        "value",
        "hex",
    ]);
    update.extend(value.iter().map(|byte| format!("{byte:02x}")));
    run("bpftool", &update)?;
    Ok(())
}

/// Enables the runner-read rule for WORKER; [`attach`] has checked its link.
pub fn enable_runner_reads(worker: &Worker, run: Run) -> Result<()> {
    update_map("runner_reads", &runner_config(worker), run)
}

/// Loads OBJECT, requires each program to be attached, and only then
/// enables the policy for the root device DEV.
pub fn attach(object: &str, dev: u64, run: Run) -> Result<()> {
    let links = format!("{WORLD_WRITE_PIN}/links");
    let maps = format!("{WORLD_WRITE_PIN}/maps");
    run(
        "bpftool",
        &strings(&[
            "prog",
            "loadall",
            object,
            &links,
            "autoattach",
            "pinmaps",
            &maps,
        ]),
    )?;
    // autoattach can fall back to pinning a program, and a program pin is
    // NOT an attachment: each expected pin must be a tracing link before
    // the map enables anything. All links, not `link show pinned PATH`:
    // bpftool 7.6.0's single-link path can fail after printing valid JSON
    // (do_show tests a stale errno), while enumeration ends on ENOENT, and
    // `-f` reports each link's pin paths.
    let listed = run("bpftool", &strings(&["-j", "-f", "link", "show"]))?;
    let listed: Value = serde_json::from_str(&listed).context("bpftool's link list is not JSON")?;
    let listed = listed.as_array().context("expected bpftool link array")?;
    for name in WORLD_WRITE_LINKS {
        let pin = format!("{links}/{name}");
        let matches: Vec<&Value> = listed
            .iter()
            .filter(|link| {
                link["pinned"]
                    .as_array()
                    .is_some_and(|pins| pins.iter().any(|path| path.as_str() == Some(&pin)))
            })
            .collect();
        let [link] = matches[..] else {
            bail!("not a modify-return tracing link: {name}");
        };
        ensure!(
            link["type"] == "tracing" && link["attach_type"] == "modify_return",
            "not a modify-return tracing link: {name}"
        );
    }
    update_map("root_fs", &root_config(dev)?, run)
}

/// The command that installs bpftool where the image lacks it. Ubuntu's
/// bpftool is a wrapper for the running kernel's linux-tools package
/// (hosted ubuntu-26.04 ships both); RHEL's is the bpftool package.
/// OS_RELEASE was admitted by [`platform::supported`] already.
pub fn bpftool_install(os_release: &str, kernel: &str) -> Result<(&'static str, Vec<String>)> {
    let id = os_release.lines().find_map(|line| {
        let value = line.strip_prefix("ID=")?;
        let value = value.strip_prefix('"').unwrap_or(value);
        let value = value.strip_suffix('"').unwrap_or(value);
        (!value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.'))
        .then_some(value)
    });
    match id {
        Some("ubuntu") => {
            ensure!(
                !kernel.is_empty()
                    && kernel
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte)),
                "unexpected kernel release {kernel:?}"
            );
            Ok((
                "apt-get",
                strings(&[
                    "-o",
                    "Acquire::Retries=3",
                    "install",
                    "-y",
                    "--no-install-recommends",
                    "linux-tools-common",
                    &format!("linux-tools-{kernel}"),
                ]),
            ))
        }
        Some("rhel") => Ok(("dnf", strings(&["install", "-y", "bpftool"]))),
        other => bail!(
            "no bpftool package known for {}",
            other.unwrap_or("this host")
        ),
    }
}

/// Installs bpftool where `bpftool version` fails: it is missing, or it is
/// Ubuntu's wrapper without the running kernel's tools. An install that
/// leaves none that runs refuses.
pub fn ensure_bpftool(run: Run, os_release: &str) -> Result<()> {
    let version = strings(&["version"]);
    if run("bpftool", &version).is_ok() {
        return Ok(());
    }
    let kernel = run("uname", &strings(&["-r"]))?;
    let (program, args) = bpftool_install(os_release, kernel.trim())?;
    run(program, &args)?;
    run("bpftool", &version)?;
    Ok(())
}

/// Runs PROGRAM on root's fixed path, none of the job's identity settings
/// passed on, stopped after [`COMMAND_TIMEOUT`].
pub fn run_command(program: &str, args: &[String]) -> Result<String> {
    let described = std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(|arg| format!("{arg:?}"))
        .collect::<Vec<_>>()
        .join(" ");
    let output = host::bare("timeout")
        .env("PATH", host::root_path())
        .arg(COMMAND_TIMEOUT)
        .arg(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("{described}: could not start it"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    ensure!(
        output.status.success(),
        "{described}: {}\nstderr: {}",
        output.status,
        if stderr.is_empty() { "(empty)" } else { stderr }
    );
    ensure!(
        output.stdout.len() <= MAX_OUTPUT,
        "{described}: printed more than {MAX_OUTPUT} bytes"
    );
    String::from_utf8(output.stdout).with_context(|| format!("{described}: printed no text"))
}

/// The refusal, and what the host was, for whoever has to say why: each
/// diagnostic's own failure is reported in its place.
pub fn report_refusal(error: &anyhow::Error, run: Run, log: &mut dyn FnMut(String)) {
    log(format!("world-write setup refused: {error:#}"));
    for (program, args) in [("bpftool", "version"), ("uname", "-r")] {
        match run(program, &strings(&[args])) {
            Ok(output) => log(format!("{program} {args}: {}", output.trim())),
            Err(err) => log(format!("diagnostic failed: {err:#}")),
        }
    }
}

/// A write of PATH as [`PROBE_USER`] must fail with EACCES when DENIED and
/// succeed otherwise; any other failure is a broken probe, not a verdict.
fn probe_write(path: &Path, denied: bool) -> Result<()> {
    let output = host::bare("timeout")
        .env("PATH", host::root_path())
        // The shell's own message for EACCES, in no other language.
        .env("LC_ALL", "C")
        .args([
            COMMAND_TIMEOUT,
            "runuser",
            "-u",
            PROBE_USER,
            "--",
            "/bin/sh",
            "-c",
            r#"printf control >> "$1""#,
            "sh",
        ])
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .context("running the write probe as nobody")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    // strerror(EACCES), as the shell reports a redirection it was refused.
    let refused = !output.status.success() && stderr.contains("Permission denied");
    ensure!(
        output.status.success() || refused,
        "the write probe of {} failed for another reason: {}",
        path.display(),
        stderr.trim()
    );
    ensure!(
        refused == denied,
        "a write by {PROBE_USER} to {} was {}",
        path.display(),
        if refused { "refused" } else { "allowed" }
    );
    Ok(())
}

/// The runner's process, with no environment, until it is dropped.
struct Target(std::process::Child);

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `setpriv`'s arguments to run a command as WORKER's user and group.
fn as_runner(worker: &Worker) -> Vec<String> {
    vec![
        format!("--reuid={}", worker.uid),
        format!("--regid={}", worker.gid),
        "--clear-groups".to_owned(),
        "--".to_owned(),
    ]
}

/// A process of the runner's user reading the environment of another of
/// its processes, a sibling, must fail with EACCES when DENIED and
/// succeed otherwise; any other failure is a broken probe, not a verdict.
/// The target's environment holds only PATH, and nothing read is kept.
/// Before setup's hidepid, which would make the refusal ENOENT.
fn probe_runner_read(worker: &Worker, denied: bool) -> Result<()> {
    let target = Target(
        host::bare("setpriv")
            .env_clear()
            .env("PATH", host::root_path())
            .args(as_runner(worker))
            .args(["sleep", TARGET_SECONDS])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("starting the read probe's target")?,
    );
    let pid = target.0.id();
    // Until it has exec'd sleep, the uid change has left it undumpable.
    let comm = format!("/proc/{pid}/comm");
    let mut tries = 0;
    while fs::read_to_string(&comm).ok().as_deref() != Some("sleep\n") {
        tries += 1;
        ensure!(
            tries < TARGET_TRIES,
            "the read probe's target did not start"
        );
        std::thread::sleep(TARGET_WAIT);
    }
    let environ = format!("/proc/{pid}/environ");
    let output = host::bare("timeout")
        .env_clear()
        .env("PATH", host::root_path())
        // cat's own message for EACCES, in no other language.
        .env("LC_ALL", "C")
        .arg(COMMAND_TIMEOUT)
        .arg("setpriv")
        .args(as_runner(worker))
        .args(["cat", &environ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
        .context("running the read probe as the runner's user")?;
    drop(target);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // strerror(EACCES), as cat reports the open it was refused.
    let refused = !output.status.success() && stderr.contains("Permission denied");
    ensure!(
        output.status.success() || refused,
        "the read probe of {environ} failed for another reason: {}",
        stderr.trim()
    );
    ensure!(
        refused == denied,
        "a read by the runner's user of {environ} was {}",
        if refused { "refused" } else { "allowed" }
    );
    Ok(())
}

/// With SOLE_WORKER, the Worker the runner-read rule exempts is
/// [`sole_worker`] on the host rather than an ancestor.
pub fn load(object: &Path, deny_runner_reads: bool, sole_worker: bool) -> Result<()> {
    ensure!(
        platform::supported_file(Path::new(platform::OS_RELEASE)),
        platform::REFUSAL
    );
    ensure!(host::is_root(), "world-write loading requires root");
    ensure!(
        fs::symlink_metadata(object).is_ok_and(|meta| meta.is_file()),
        "policy object {} is not a regular file",
        object.display()
    );
    let object = object
        .to_str()
        .with_context(|| format!("policy object {} is not UTF-8", object.display()))?;
    let worker = if deny_runner_reads {
        let mut status = |pid| {
            fs::read_to_string(format!("/proc/{pid}/status"))
                .with_context(|| format!("reading the status of process {pid}"))
        };
        let worker = if sole_worker {
            self::sole_worker(
                &crate::sandbox::worker_diagnostics::worker_pids()?,
                &mut status,
            )?
        } else {
            find_worker(std::process::id(), &mut status)?
        };
        // The rule decides reads only: an attach (`/proc/PID/mem`,
        // process_vm_readv) is Yama's, which must not be scope 0.
        crate::sandbox::setup::restrict_ptrace()?;
        probe_runner_read(&worker, false)?;
        Some(worker)
    } else {
        None
    };
    let run: Run = &mut run_command;
    let os_release = fs::read_to_string(platform::OS_RELEASE).context("reading os-release")?;
    ensure_bpftool(run, &os_release)?;
    let mounted = rustix::fs::statfs(BPF_FS).with_context(|| format!("statfs {BPF_FS}"))?;
    #[allow(clippy::useless_conversion)] // f_type's width is the platform's
    if i64::from(mounted.f_type) != BPF_FS_MAGIC {
        run("mount", &strings(&["-t", "bpf", "bpf", BPF_FS]))?;
    }
    // Exclusive and root's: a rerun or a stale pin is refused, rather than
    // a live policy replaced.
    DirBuilder::new()
        .mode(0o700)
        .create(WORLD_WRITE_PIN)
        .with_context(|| format!("creating {WORLD_WRITE_PIN}"))?;
    let nobody = run("id", &strings(&["-u", PROBE_USER]))?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|uid| *uid > 0)
        .context("requires an unprivileged nobody user for the activation probe")?;
    // Fixed-size fixtures, not an inventory. A baseline, and an owned file
    // as the positive control, tell a policy denial from DAC or a broken
    // probe.
    let probe = tempfile::Builder::new()
        .prefix(PROBE_PREFIX)
        .tempdir_in("/")
        .context("creating the probe directory")?;
    fs::set_permissions(probe.path(), fs::Permissions::from_mode(0o755))?;
    let foreign = probe.path().join("foreign");
    let owned = probe.path().join("owned");
    for path in [&foreign, &owned] {
        fs::write(path, "probe")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
    }
    std::os::unix::fs::chown(&owned, Some(nobody), None)?;
    probe_write(&foreign, false)?;
    probe_write(&owned, false)?;
    attach(object, fs::metadata("/")?.dev(), run)?;
    probe_write(&foreign, true)?;
    probe_write(&owned, false)?;
    probe.close().context("removing the probe directory")?;
    println!(
        "world-write: enabled root-device policy; {} tracing links pinned",
        WORLD_WRITE_LINKS.len()
    );
    if let Some(worker) = worker {
        enable_runner_reads(&worker, run)?;
        probe_runner_read(&worker, true)?;
        println!(
            "world-write: enabled the runner-read rule for uid {}, {WORKER} {} exempt",
            worker.uid, worker.pid
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// As `bpftool -j -f link show` prints them (not `link show pinned`).
    fn links() -> Vec<Value> {
        WORLD_WRITE_LINKS
            .iter()
            .enumerate()
            .map(|(index, name)| {
                serde_json::json!({
                    "id": index + 1, "type": "tracing", "prog_id": index + 10,
                    "prog_type": "tracing", "attach_type": "modify_return",
                    "target_obj_id": 0, "target_btf_id": index + 100,
                    "pinned": [format!("{WORLD_WRITE_PIN}/links/{name}")],
                })
            })
            .collect()
    }

    #[test]
    fn userspace_dev_becomes_kernel_dev_t() {
        for (major, minor) in [(0u64, 0u64), (8, 1), (259, 65537), (4095, 1_048_575)] {
            let dev = (minor & 0xff)
                | ((major & 0xfff) << 8)
                | ((minor & !0xff) << 12)
                | ((major & !0xfff) << 32);
            let value = root_config(dev).unwrap();
            let word = |at: usize| u32::from_ne_bytes(value[at..at + 4].try_into().unwrap());
            assert_eq!(u64::from(word(0)), (major << 20) | minor);
            assert_eq!(word(4), 1);
        }
        for dev in [1 << 44, 1 << 32] {
            assert!(format!("{:#}", root_config(dev).unwrap_err()).contains("exceeds"));
        }
    }

    fn status(name: &str, ppid: u32, uid: u32) -> String {
        format!(
            "Name:\t{name}\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t9\nPid:\t9\n\
             PPid:\t{ppid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t118\t118\t118\t118\n"
        )
    }

    /// The loader under sudo under a step's shell under the Worker, and
    /// what must refuse: no Worker, a root one, a chain too long, a
    /// status that cannot be read or parsed.
    #[test]
    fn the_worker_is_the_nearest_ancestor_of_that_name() {
        let chain = |names: &[(&str, u32)]| {
            let names: Vec<(String, u32)> = names
                .iter()
                .map(|(name, uid)| ((*name).to_owned(), *uid))
                .collect();
            move |pid: u32| -> Result<String> {
                let index = usize::try_from(pid).unwrap() - 1;
                let (name, uid) = names.get(index).context("no such process")?;
                // Each process's parent is the next one; the last is init's child.
                let ppid = if index + 1 == names.len() { 0 } else { pid + 1 };
                Ok(status(name, ppid, *uid))
            }
        };
        let hosted = [
            ("agentic-job", 0),
            ("sudo", 0),
            ("sudo", 0),
            ("bash", 1001),
            (WORKER, 1001),
            ("Runner.Listener", 1001),
            ("systemd", 0),
        ];
        assert_eq!(
            find_worker(1, &mut chain(&hosted)).unwrap(),
            Worker {
                pid: 5,
                uid: 1001,
                gid: 118
            }
        );
        let deep: Vec<(&str, u32)> = std::iter::repeat_n(("bash", 1001), MAX_ANCESTORS)
            .chain([(WORKER, 1001)])
            .collect();
        let within = &deep[1..];
        assert_eq!(find_worker(1, &mut chain(within)).unwrap().pid, 32);
        for (names, refusal) in [
            (
                &[("sudo", 0), ("bash", 1001), ("systemd", 0)][..],
                "no Runner.Worker among",
            ),
            (&[("sudo", 0), (WORKER, 0)], "Runner.Worker runs as root"),
            (
                &[("sudo", 0), ("Runner.Worke", 1001)],
                "no Runner.Worker among",
            ),
            (&deep, "within 32 ancestors"),
            (&[], "no such process"),
        ] {
            let err = find_worker(1, &mut chain(names)).unwrap_err();
            assert!(format!("{err:#}").contains(refusal), "{err:#}");
        }
        for broken in [
            "Name:\tbash\nUid:\t1\nGid:\t1\n",
            "Name:\tbash\nPPid:\tone\nUid:\t1\nGid:\t1\n",
            "PPid:\t1\nUid:\t1\nGid:\t1\n",
            "Name:\tbash\nPPid:\t1\nUid:\t\nGid:\t1\n",
            "Name:\tbash\nPPid:\t1\nUid:\t1\n",
        ] {
            assert!(
                find_worker(1, &mut |_| Ok(broken.to_owned())).is_err(),
                "{broken}"
            );
        }
    }

    /// The image's loader, under conmon: the one Worker on the host, by
    /// pid, whatever its ancestors; anything but exactly one non-root
    /// Worker refuses.
    #[test]
    fn the_sole_worker_is_the_only_one_of_that_name() {
        let host = |names: &'static [(&'static str, u32)]| {
            move |pid: u32| -> Result<String> {
                let (name, uid) = names
                    .get(usize::try_from(pid).unwrap())
                    .context("no such process")?;
                Ok(status(name, 1, *uid))
            }
        };
        let hosted: &[(&str, u32)] = &[
            ("systemd", 0),
            ("conmon", 0),
            (WORKER, 1001),
            ("sleep", 1001),
        ];
        // Pid 9 ended before its status was read.
        assert_eq!(
            sole_worker(&[1, 9, 2, 3], &mut host(hosted)).unwrap(),
            Worker {
                pid: 2,
                uid: 1001,
                gid: 118
            }
        );
        for (names, refusal) in [
            (
                &[("systemd", 0), ("bash", 1001)][..],
                "no Runner.Worker runs",
            ),
            (&[("systemd", 0), (WORKER, 0)], "runs as root"),
            (
                &[(WORKER, 1001), (WORKER, 1002)],
                "more than one Runner.Worker",
            ),
        ] {
            let pids: Vec<u32> = (0..u32::try_from(names.len()).unwrap()).collect();
            let err = sole_worker(&pids, &mut host(names)).unwrap_err();
            assert!(format!("{err:#}").contains(refusal), "{err:#}");
        }
    }

    #[test]
    fn the_runner_read_map_names_the_runner_and_its_worker() {
        let worker = Worker {
            pid: 2345,
            uid: 1001,
            gid: 118,
        };
        let value = runner_config(&worker);
        let word = |at: usize| u32::from_ne_bytes(value[at..at + 4].try_into().unwrap());
        assert_eq!([word(0), word(4), word(8)], [1001, 2345, 1]);
        let mut calls = Vec::new();
        enable_runner_reads(&worker, &mut |program, args| {
            calls.push((program.to_owned(), args.to_vec()));
            Ok(String::new())
        })
        .unwrap();
        let [(program, args)] = &calls[..] else {
            panic!("{calls:?}")
        };
        assert_eq!(program, "bpftool");
        let map = format!("{WORLD_WRITE_PIN}/maps/runner_reads");
        let hex: Vec<String> = value.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            args[..8],
            strings(&["map", "update", "pinned", &map, "key", "hex", "00", "00"])
        );
        assert_eq!(args[args.len() - 12..], hex[..]);
    }

    #[test]
    fn every_link_is_checked_before_the_map_enables_it() {
        let mut calls = Vec::new();
        attach("policy.o", 2049, &mut |program, args| {
            calls.push((program.to_owned(), args.to_vec()));
            Ok(Value::from(links()).to_string())
        })
        .unwrap();
        let links_pin = format!("{WORLD_WRITE_PIN}/links");
        let maps_pin = format!("{WORLD_WRITE_PIN}/maps");
        assert_eq!(
            calls[0],
            (
                "bpftool".to_owned(),
                strings(&[
                    "prog",
                    "loadall",
                    "policy.o",
                    &links_pin,
                    "autoattach",
                    "pinmaps",
                    &maps_pin
                ])
            )
        );
        assert_eq!(calls[1].1, strings(&["-j", "-f", "link", "show"]));
        assert_eq!(
            calls[2].1[..4],
            strings(&["map", "update", "pinned", &format!("{maps_pin}/root_fs")])
        );
        let value: Vec<String> = root_config(2049)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(calls[2].1[calls[2].1.len() - 8..], value[..]);
        assert_eq!(calls.len(), 3);
    }

    #[test]
    fn a_failing_command_stops_loading_where_it_failed() {
        for failed in 0..3 {
            let mut count = 0;
            let err = attach("policy.o", 2049, &mut |_, _| {
                count += 1;
                if count == failed + 1 {
                    bail!("bpftool failure")
                }
                Ok(Value::from(links()).to_string())
            })
            .unwrap_err();
            assert!(format!("{err:#}").contains("bpftool failure"));
            assert_eq!(count, failed + 1);
        }
    }

    /// Whatever the list says short of every tracing link, the map is
    /// never updated.
    #[test]
    fn an_unattached_program_is_never_enabled() {
        let mut invalid = vec![
            "null".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "invalid json".to_owned(),
        ];
        let mut doubled = links();
        doubled.push(links()[0].clone());
        invalid.push(Value::from(doubled).to_string());
        let overrides = [
            serde_json::json!({"type": "program"}),
            serde_json::json!({"attach_type": "trace_fentry"}),
            serde_json::json!({"attach_type": null}),
            serde_json::json!({"pinned": null}),
            serde_json::json!({"pinned": ["/other/pin"]}),
        ];
        for index in 0..WORLD_WRITE_LINKS.len() {
            for change in &overrides {
                let mut changed = links();
                for (key, value) in change.as_object().unwrap() {
                    changed[index][key] = value.clone();
                }
                invalid.push(Value::from(changed).to_string());
            }
            let mut fewer = links();
            fewer.remove(index);
            invalid.push(Value::from(fewer).to_string());
        }
        for listed in invalid {
            let mut count = 0;
            let result = attach("policy.o", 2049, &mut |_, _| {
                count += 1;
                Ok(if count == 1 {
                    String::new()
                } else {
                    listed.clone()
                })
            });
            assert!(result.is_err(), "{listed}");
            assert_eq!(count, 2, "{listed}: must not enable an unattached program");
        }
    }

    #[test]
    fn unrelated_links_do_not_interfere() {
        let mut listed = links();
        listed.push(serde_json::json!({"type": "cgroup", "pinned": ["/unrelated"]}));
        attach("policy.o", 2049, &mut |_, _| {
            Ok(Value::from(listed.clone()).to_string())
        })
        .unwrap();
    }

    #[test]
    fn command_failures_keep_status_and_stderr() {
        let err = run_command(
            "sh",
            &strings(&["-c", "printf 'pin lookup failed' >&2; exit 23"]),
        )
        .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("exit status: 23"), "{message}");
        assert!(message.contains("stderr: pin lookup failed"), "{message}");
        assert!(message.contains("\"sh\""), "{message}");
        assert_eq!(
            run_command("sh", &strings(&["-c", "printf ok"])).unwrap(),
            "ok"
        );
    }

    #[test]
    fn every_refusal_reports_the_host_even_without_bpftool() {
        for unavailable in [false, true] {
            let calls = RefCell::new(Vec::new());
            let mut messages = Vec::new();
            report_refusal(
                &anyhow::anyhow!("original failure"),
                &mut |program, args| {
                    calls.borrow_mut().push((program.to_owned(), args.to_vec()));
                    if program == "bpftool" && unavailable {
                        bail!("bpftool missing");
                    }
                    Ok(if program == "bpftool" {
                        "bpftool v7.6.0\n"
                    } else {
                        "7.0.0\n"
                    }
                    .to_owned())
                },
                &mut |message| messages.push(message),
            );
            assert_eq!(
                calls.into_inner(),
                [
                    ("bpftool".to_owned(), strings(&["version"])),
                    ("uname".to_owned(), strings(&["-r"]))
                ]
            );
            assert_eq!(messages[0], "world-write setup refused: original failure");
            if unavailable {
                assert_eq!(messages[1], "diagnostic failed: bpftool missing");
            } else {
                assert_eq!(messages[1], "bpftool version: bpftool v7.6.0");
            }
            assert_eq!(messages[2], "uname -r: 7.0.0");
        }
    }

    #[test]
    fn bpftool_is_installed_only_where_it_does_not_run() {
        let ubuntu = "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"26.04\"\n";
        let rhel = "NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nVERSION_ID=\"10.1\"\n";
        let kernel = "7.0.0-1012-azure";
        let apt = (
            "apt-get",
            strings(&[
                "-o",
                "Acquire::Retries=3",
                "install",
                "-y",
                "--no-install-recommends",
                "linux-tools-common",
                "linux-tools-7.0.0-1012-azure",
            ]),
        );
        let dnf = ("dnf", strings(&["install", "-y", "bpftool"]));
        assert_eq!(bpftool_install(ubuntu, kernel).unwrap(), apt);
        assert_eq!(bpftool_install(rhel, "6.12.0-55.el10.x86_64").unwrap(), dnf);
        for (release, kernel, refusal) in [
            (ubuntu, "7.0 -x", "unexpected kernel release"),
            (ubuntu, "", "unexpected kernel release"),
            ("ID=fedora\n", "6.12", "no bpftool package known for fedora"),
            ("NAME=x\n", "6.12", "no bpftool package known for this host"),
        ] {
            let err = bpftool_install(release, kernel).unwrap_err();
            assert!(format!("{err:#}").contains(refusal), "{err:#}");
        }
        let version = ("bpftool".to_owned(), strings(&["version"]));
        let uname = ("uname".to_owned(), strings(&["-r"]));
        let own = |(program, args): (&str, Vec<String>)| (program.to_owned(), args);
        for (present, release, expected) in [
            (true, ubuntu, vec![version.clone()]),
            (
                false,
                ubuntu,
                vec![
                    version.clone(),
                    uname.clone(),
                    own(apt.clone()),
                    version.clone(),
                ],
            ),
            (
                false,
                rhel,
                vec![
                    version.clone(),
                    uname.clone(),
                    own(dnf.clone()),
                    version.clone(),
                ],
            ),
        ] {
            let mut calls = Vec::new();
            let mut installed = present;
            ensure_bpftool(
                &mut |program, args| {
                    calls.push((program.to_owned(), args.to_vec()));
                    if program == "bpftool" && !installed {
                        bail!("bpftool missing");
                    }
                    if program == "apt-get" || program == "dnf" {
                        installed = true;
                    }
                    Ok(if program == "uname" {
                        format!("{kernel}\n")
                    } else {
                        String::new()
                    })
                },
                release,
            )
            .unwrap();
            assert_eq!(calls, expected);
        }
        // An install that leaves no bpftool that runs refuses.
        let err = ensure_bpftool(
            &mut |program, _| {
                if program == "bpftool" {
                    bail!("bpftool missing");
                }
                Ok(format!("{kernel}\n"))
            },
            ubuntu,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("bpftool missing"));
    }
}
