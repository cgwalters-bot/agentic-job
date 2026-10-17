//! `agentic-job secure-host image CONFIG`: the entrypoint of the
//! `FROM scratch` image (`secure-host/Containerfile`), run as
//!
//! ```text
//! sudo podman run --rm --privileged --pid=host --network=none -v /:/host IMAGE@sha256:... CONFIG
//! ```
//!
//! The image holds this binary and the BPF objects and nothing else, so
//! the host is set up by the host's own tools: the process takes the
//! host's root as its own, installs the binary and objects there (for
//! `sandbox check`, the probes and `sandbox exec` after it), and runs the
//! secure-host steps through the host's `nsenter -t 1`, in the host's
//! mount, network and other namespaces. The world-write links are pinned
//! in the host's bpffs and the egress proxy is a systemd unit (running
//! this same image in root podman: `egress::PODMAN`), so both
//! outlive the container. CONFIG is a path on the host, a configuration
//! `agentic-job config --host` wrote. Any failed step fails the whole.

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};

use super::platform;
use crate::config::{Config, HostConfig};
use crate::sandbox::{egress, host};

/// Where `-v /:/host` puts the host's root.
pub const HOST_ROOT: &str = "/host";
/// The image's own files, at its root (`secure-host/Containerfile`).
const IMAGE_BINARY: &str = "/agentic-job";
const IMAGE_OBJECT: &str = "/world_write.bpf.o";
/// Where they go on the host: the binary where the action installs it,
/// which `sandbox timed` and the sudo rules name.
const HOST_BINARY: &str = "/usr/local/bin/agentic-job";
const HOST_OBJECT_DIR: &str = "/usr/local/lib/agentic-job";
const HOST_OBJECT: &str = "/usr/local/lib/agentic-job/world_write.bpf.o";
/// util-linux's, on Ubuntu and RHEL alike.
const NSENTER: &str = "/usr/bin/nsenter";
/// Every namespace of the host's init but the user namespace, which a
/// rootful `--privileged` container already shares, and the PID
/// namespace, which `--pid=host` shares.
const NAMESPACES: &[&str] = &["--mount", "--uts", "--ipc", "--net", "--cgroup"];

/// What podman tells a container about itself; with `--privileged`, the
/// ID of the image it runs, `imageid="…"`.
const CONTAINERENV: &str = "/run/.containerenv";
/// A real one is a few hundred bytes.
const MAX_CONTAINERENV_BYTES: u64 = 64 * 1024;
const IMAGE_ID_KEY: &str = "imageid=";

/// The ID of the image this container runs, from TEXT, podman's
/// [`CONTAINERENV`]: setup runs the egress proxy from it too.
fn image_id(text: &str) -> Result<String> {
    let id = text
        .lines()
        .find_map(|line| line.strip_prefix(IMAGE_ID_KEY))
        .with_context(|| {
            format!("{CONTAINERENV} names no image: run the image with root podman --privileged")
        })?
        .trim_matches('"');
    egress::check_image_id(id)?;
    Ok(id.to_owned())
}

/// Whether the host's configuration CONFIG, checked as setup checks it,
/// asks for the runner-read rule (`sandbox.deny-runner-reads`). Read
/// here as well as by setup: the rule is the world-write step's.
fn deny_runner_reads(config: &Path) -> Result<bool> {
    let text =
        fs::read_to_string(config).with_context(|| format!("reading {}", config.display()))?;
    let config =
        Config::from(HostConfig::parse(&text).with_context(|| format!("in {}", config.display()))?);
    config.check_host()?;
    Ok(config.sandbox.deny_runner_reads)
}

/// The commands run on the host, in order, as the action runs them:
/// apt's waits bounded, the world-write policy loaded, with the
/// runner-read rule if DENY_RUNNER_READS, then setup, with the egress
/// proxy from IMAGE.
pub fn host_steps(config: &Path, image: &str, deny_runner_reads: bool) -> Result<Vec<Vec<String>>> {
    let config = config
        .to_str()
        .with_context(|| format!("configuration {} is not UTF-8", config.display()))?;
    // Read on the host, from its root: a relative path would be the
    // container's working directory, which nothing there knows.
    ensure!(
        config.starts_with('/'),
        "configuration {config:?} must be an absolute path on the host"
    );
    // conmon, not the Worker, is this process's parent: the loader
    // finds the Worker on the host instead of among its ancestors.
    let world_write: &[&str] = if deny_runner_reads {
        &[
            "secure-host",
            "world-write",
            HOST_OBJECT,
            "--deny-runner-reads",
            "--sole-worker",
        ]
    } else {
        &["secure-host", "world-write", HOST_OBJECT]
    };
    let steps: [&[&str]; 3] = [
        &["secure-host", "apt"],
        world_write,
        &[
            "sandbox",
            "setup",
            "--config",
            config,
            "--egress-image",
            image,
        ],
    ];
    Ok(steps
        .iter()
        .map(|args| {
            ["--target", "1"]
                .iter()
                .chain(NAMESPACES)
                .chain(&["--", HOST_BINARY])
                .chain(*args)
                .map(|arg| (*arg).to_owned())
                .collect()
        })
        .collect())
}

/// Writes SOURCE to PATH, replacing whatever is there in one rename:
/// a running binary cannot be written over in place.
fn install(source: &mut File, path: &str, mode: u32) -> Result<()> {
    let path = Path::new(path);
    let dir = path.parent().context("an install path has a directory")?;
    let mut temp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("creating a file in {}", dir.display()))?;
    io::copy(source, &mut temp).with_context(|| format!("writing {}", path.display()))?;
    temp.flush()?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temp.persist(path)
        .with_context(|| format!("installing {}", path.display()))?;
    Ok(())
}

pub fn run(config: &Path) -> Result<()> {
    ensure!(host::is_root(), "the secure-host image runs as root");
    // Read before the root changes, which hides the image's files.
    let env = crate::files::read_regular(Path::new(CONTAINERENV), MAX_CONTAINERENV_BYTES)
        .with_context(|| format!("reading {CONTAINERENV}: run the image with root podman"))?;
    let image = image_id(&String::from_utf8_lossy(&env))?;
    // Refused before the configuration is read from the host's root.
    host_steps(config, &image, false)?;
    let mut binary = File::open(IMAGE_BINARY).with_context(|| format!("opening {IMAGE_BINARY}"))?;
    let mut object = File::open(IMAGE_OBJECT).with_context(|| format!("opening {IMAGE_OBJECT}"))?;
    // The host's root, so that its paths and symbolic links resolve as on
    // the host, and its nsenter finds its own libraries.
    rustix::process::chroot(HOST_ROOT)
        .with_context(|| format!("changing root to {HOST_ROOT}: run with -v /:{HOST_ROOT}"))?;
    rustix::process::chdir("/").context("entering the host's root")?;
    // Before anything on the host changes.
    ensure!(
        platform::supported_file(Path::new(platform::OS_RELEASE)),
        platform::REFUSAL
    );
    let steps = host_steps(config, &image, deny_runner_reads(config)?)?;
    install(&mut binary, HOST_BINARY, 0o755)?;
    fs::create_dir_all(HOST_OBJECT_DIR).with_context(|| format!("creating {HOST_OBJECT_DIR}"))?;
    install(&mut object, HOST_OBJECT, 0o644)?;
    for args in steps {
        // The container's environment (`container=podman`, its HOME and
        // hostname) is not the host's; root's fixed path is all it gets.
        let status = Command::new(NSENTER)
            .args(&args)
            .env_clear()
            .env("PATH", host::root_path())
            .env("HOME", "/root")
            .stdin(Stdio::null())
            .status()
            .with_context(|| format!("starting {NSENTER}"))?;
        ensure!(status.success(), "{NSENTER} {}: {status}", args.join(" "));
    }
    println!("secure-host: the host is set up; {HOST_BINARY} is installed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_step_runs_the_installed_binary_in_the_hosts_namespaces() {
        let image = "0123456789abcdef".repeat(4);
        let steps = host_steps(Path::new("/tmp/secure-host/config.toml"), &image, false).unwrap();
        let prefix = [
            "--target",
            "1",
            "--mount",
            "--uts",
            "--ipc",
            "--net",
            "--cgroup",
            "--",
            HOST_BINARY,
        ];
        let tails: [&[&str]; 3] = [
            &["secure-host", "apt"],
            &["secure-host", "world-write", HOST_OBJECT],
            &[
                "sandbox",
                "setup",
                "--config",
                "/tmp/secure-host/config.toml",
                "--egress-image",
                &image,
            ],
        ];
        assert_eq!(steps.len(), tails.len());
        for (step, tail) in steps.iter().zip(tails) {
            assert_eq!(step[..prefix.len()], prefix);
            assert_eq!(step[prefix.len()..], *tail);
        }
        assert_eq!(
            Path::new(HOST_OBJECT).parent(),
            Some(Path::new(HOST_OBJECT_DIR))
        );
    }

    /// `sandbox.deny-runner-reads` is off by default and changes only the
    /// world-write step; a file setup would refuse is refused here first.
    #[test]
    fn the_host_file_turns_on_the_runner_read_rule() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        for (text, want) in [
            ("", Ok(false)),
            ("[sandbox]\ndeny-runner-reads = false\n", Ok(false)),
            ("[sandbox]\ndeny-runner-reads = true\n", Ok(true)),
            (
                "[sandbox]\nlock-runner = false\ndeny-runner-reads = true\n",
                Err("needs sandbox.lock-runner"),
            ),
            ("[agent]\nname = \"claude\"\n", Err("unknown field")),
            ("[sandbox]\ndeny-runner-read = true\n", Err("unknown field")),
        ] {
            fs::write(&path, text).unwrap();
            match (deny_runner_reads(&path), want) {
                (Ok(got), Ok(want)) => assert_eq!(got, want, "{text:?}"),
                (Err(err), Err(want)) => assert!(format!("{err:#}").contains(want), "{err:#}"),
                (got, want) => panic!("{text:?}: {got:?}, not {want:?}"),
            }
        }
        let image = "0".repeat(64);
        let off = host_steps(&path, &image, false).unwrap();
        let on = host_steps(&path, &image, true).unwrap();
        assert_eq!((&off[0], &off[2]), (&on[0], &on[2]));
        assert_eq!(off[1].last().map(String::as_str), Some(HOST_OBJECT));
        assert_eq!(on[1][..off[1].len()], off[1]);
        assert_eq!(
            on[1][off[1].len()..],
            ["--deny-runner-reads", "--sole-worker"]
        );
    }

    #[test]
    fn an_install_replaces_the_file_whole_with_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agentic-job");
        fs::write(&path, "old binary, longer than the new one").unwrap();
        let mut source = tempfile::tempfile().unwrap();
        source.write_all(b"new").unwrap();
        std::io::Seek::rewind(&mut source).unwrap();
        install(&mut source, path.to_str().unwrap(), 0o755).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o755);
        // Nothing left beside it.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_configuration_is_a_host_path() {
        for config in ["config.toml", "./config.toml", ""] {
            let err = host_steps(Path::new(config), &"0".repeat(64), false).unwrap_err();
            assert!(format!("{err:#}").contains("absolute path"), "{config:?}");
        }
    }

    /// The image's own ID, as root podman writes it for a privileged
    /// container, and nothing that could name another image.
    #[test]
    fn the_image_id_is_podmans_own() {
        let id = "0123456789abcdef".repeat(4);
        let env = format!(
            "engine=\"podman-5.4.0\"\nname=\"secure-host\"\nid=\"{}\"\n\
             image=\"localhost/secure-host:latest\"\nimageid=\"{id}\"\nrootless=0\n",
            "f".repeat(64)
        );
        assert_eq!(image_id(&env).unwrap(), id);
        for (text, want) in [
            ("engine=\"podman-5.4.0\"\n".to_owned(), "names no image"),
            (String::new(), "names no image"),
            ("imageid=\"\"\n".to_owned(), "not a podman image ID"),
            (
                "imageid=\"localhost/secure-host:latest\"\n".to_owned(),
                "not a podman image ID",
            ),
            (
                format!("imageid=\"{id} --privileged\"\n"),
                "not a podman image ID",
            ),
        ] {
            let err = image_id(&text).unwrap_err();
            assert!(format!("{err:#}").contains(want), "{text:?}: {err:#}");
        }
        // The setup step passes it as one argument of its own.
        let steps = host_steps(Path::new("/c.toml"), &id, false).unwrap();
        assert_eq!(steps[2].last(), Some(&id));
    }
}
