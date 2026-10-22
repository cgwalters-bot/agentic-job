//! `agentic-job secure-host apt`: bound apt's network waits and keep it
//! off the Azure mirror, as root, before any package is installed. For a
//! disposable CI host only: it rewrites the runner's apt sources in place.
//!
//! Package bodies from `azure.archive.ubuntu.com` stalled, and mirror-list
//! fallback alone did not prevent it, so that endpoint is replaced rather
//! than reordered (which mirror+file would pick at random); suites,
//! components, signing and the other mirrors are left as they are
//! (cgwalters-forge/actions's secure-host/docs/setup.md). A host without
//! `/etc/apt`, a dnf one, is left
//! alone.

use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::Regex;

pub const APT: &str = "/etc/apt";

/// `Timeout` is apt's connection and data timeout, so it interrupts a
/// stalled body; `Retries` only retries a failed file.
pub const NETWORK_CONFIG: &str =
    "Acquire::http::Timeout \"10\";\nAcquire::https::Timeout \"10\";\nAcquire::Retries \"3\";\n";

/// Where the configuration above goes, under `apt.conf.d`.
const NETWORK_CONFIG_FILE: &str = "99-agentic-job-network";

/// The mirror lists and source lists the runner's image configures.
const SOURCES: &[&str] = &[
    "apt-mirrors.txt",
    "apt-mirrors-security.txt",
    "sources.list",
];
const SOURCES_DIR: &str = "sources.list.d";

/// The Azure host as a whole name: followed by a path, a space or the end,
/// so that `azure.archive.ubuntu.com.example` is not it.
static AZURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u:\b)(https?://)azure\.archive\.ubuntu\.com(/|\s|$)").expect("a valid pattern")
});

pub fn configure(apt: &Path) -> Result<()> {
    if !apt.exists() {
        return Ok(());
    }
    let mut files: Vec<_> = SOURCES.iter().map(|name| apt.join(name)).collect();
    let dir = apt.join(SOURCES_DIR);
    if dir.exists() {
        for entry in fs::read_dir(&dir).with_context(|| format!("listing {}", dir.display()))? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".list") || name.ends_with(".sources") {
                files.push(dir.join(&*name));
            }
        }
    }
    for path in files {
        if !path.exists() {
            continue;
        }
        let old =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let updated = AZURE.replace_all(&old, "${1}archive.ubuntu.com${2}");
        if updated != old {
            fs::write(&path, &*updated).with_context(|| format!("writing {}", path.display()))?;
        }
    }
    let config = apt.join("apt.conf.d").join(NETWORK_CONFIG_FILE);
    fs::write(&config, NETWORK_CONFIG).with_context(|| format!("writing {}", config.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror-list fallback and source trust settings are kept, and a
    /// second run changes nothing.
    #[test]
    fn sources_keep_fallback_and_trust_and_rerun_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let apt = dir.path();
        fs::create_dir(apt.join("sources.list.d")).unwrap();
        fs::create_dir(apt.join("apt.conf.d")).unwrap();
        let cases = [
            (
                "apt-mirrors.txt",
                "http://azure.archive.ubuntu.com/ubuntu\nhttp://archive.ubuntu.com/ubuntu\n",
                "http://archive.ubuntu.com/ubuntu\nhttp://archive.ubuntu.com/ubuntu\n",
            ),
            (
                "apt-mirrors-security.txt",
                "http://security.ubuntu.com/ubuntu\n",
                "http://security.ubuntu.com/ubuntu\n",
            ),
            (
                "sources.list",
                "deb mirror+file:/etc/apt/apt-mirrors.txt noble main\n",
                "deb mirror+file:/etc/apt/apt-mirrors.txt noble main\n",
            ),
            (
                "sources.list.d/ubuntu.sources",
                "URIs: https://azure.archive.ubuntu.com/ubuntu\nSuites: noble noble-updates\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n",
                "URIs: https://archive.ubuntu.com/ubuntu\nSuites: noble noble-updates\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n",
            ),
            (
                "sources.list.d/ports.list",
                "deb http://ports.ubuntu.com/ubuntu-ports noble main\n",
                "deb http://ports.ubuntu.com/ubuntu-ports noble main\n",
            ),
            (
                "sources.list.d/other.list",
                "deb https://azure.archive.ubuntu.com.example/ubuntu noble main\n",
                "deb https://azure.archive.ubuntu.com.example/ubuntu noble main\n",
            ),
            (
                "sources.list.d/backup.sources.disabled",
                "http://azure.archive.ubuntu.com/ubuntu",
                "http://azure.archive.ubuntu.com/ubuntu",
            ),
            (
                "sources.list.d/adjacent.list",
                "deb http://azure.archive.ubuntu.com http://azure.archive.ubuntu.com/ubuntu",
                "deb http://archive.ubuntu.com http://archive.ubuntu.com/ubuntu",
            ),
        ];
        for (name, input, _) in cases {
            fs::write(apt.join(name), input).unwrap();
        }
        for _ in 0..2 {
            configure(apt).unwrap();
            for (name, _, expected) in cases {
                assert_eq!(
                    fs::read_to_string(apt.join(name)).unwrap(),
                    expected,
                    "{name}"
                );
            }
            assert_eq!(
                fs::read_to_string(apt.join("apt.conf.d/99-agentic-job-network")).unwrap(),
                NETWORK_CONFIG
            );
        }
        for directive in [
            "Acquire::http::Timeout \"10\";",
            "Acquire::https::Timeout \"10\";",
            "Acquire::Retries \"3\";",
        ] {
            assert!(
                NETWORK_CONFIG.lines().any(|line| line == directive),
                "{directive}"
            );
        }
        configure(&apt.join("missing")).unwrap();
    }

    /// What the timeout is for: apt itself abandons a body that stalls
    /// after it started, rather than waiting on it.
    #[test]
    fn apt_abandons_a_stalled_body_at_its_data_timeout() {
        use std::io::{Read, Write};
        use std::time::{Duration, Instant};

        const HELPER: &str = "/usr/lib/apt/apt-helper";
        if !Path::new(HELPER).exists() {
            eprintln!("skipped: no {HELPER}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (started, body) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\npartial body")
                .unwrap();
            started.send(()).unwrap();
            // Held open, and silent, until the test ends.
            std::thread::sleep(Duration::from_secs(30));
            drop(stream);
        });
        let begun = Instant::now();
        let status = std::process::Command::new("timeout")
            .args([
                "10",
                HELPER,
                "-o",
                "Acquire::http::Timeout=1",
                "-o",
                "Acquire::Retries=0",
            ])
            .arg("download-file")
            .arg(format!("http://127.0.0.1:{port}/package.deb"))
            .arg(dir.path().join("package.deb"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        body.recv_timeout(Duration::from_secs(1))
            .expect("the body had started");
        // `timeout` exits 124 when it had to stop apt: apt must stop itself.
        assert!(!status.success());
        assert_ne!(status.code(), Some(124), "apt was stopped by the watchdog");
        assert!(begun.elapsed() < Duration::from_secs(9));
    }
}
