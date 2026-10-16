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
    let mut update = strings(&[
        "map",
        "update",
        "pinned",
        &format!("{maps}/root_fs"),
        "key",
        "hex",
        "00",
        "00",
        "00",
        "00",
        "value",
        "hex",
    ]);
    update.extend(root_config(dev)?.iter().map(|byte| format!("{byte:02x}")));
    run("bpftool", &update)?;
    Ok(())
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

pub fn load(object: &Path) -> Result<()> {
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
    println!("world-write: enabled root-device policy; four tracing links pinned");
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

    /// Whatever the list says short of four tracing links, the map is
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
