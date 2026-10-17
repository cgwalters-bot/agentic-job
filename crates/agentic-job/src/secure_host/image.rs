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
//! in the host's bpffs and the egress proxy is a systemd unit, so both
//! outlive the container. CONFIG is a path on the host, a configuration
//! `agentic-job config --host` wrote. Any failed step fails the whole.

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};

use super::platform;
use crate::sandbox::host;

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

/// The commands run on the host, in order, as the action runs them:
/// apt's waits bounded, the world-write policy loaded, then setup.
pub fn host_steps(config: &Path) -> Result<Vec<Vec<String>>> {
    let config = config
        .to_str()
        .with_context(|| format!("configuration {} is not UTF-8", config.display()))?;
    // Read on the host, from its root: a relative path would be the
    // container's working directory, which nothing there knows.
    ensure!(
        config.starts_with('/'),
        "configuration {config:?} must be an absolute path on the host"
    );
    let steps: [&[&str]; 3] = [
        &["secure-host", "apt"],
        &["secure-host", "world-write", HOST_OBJECT],
        &["sandbox", "setup", "--config", config],
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
    let steps = host_steps(config)?;
    // Opened before the root changes, which hides the image's files.
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
        let steps = host_steps(Path::new("/tmp/secure-host/config.toml")).unwrap();
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
            let err = host_steps(Path::new(config)).unwrap_err();
            assert!(format!("{err:#}").contains("absolute path"), "{config:?}");
        }
    }
}
