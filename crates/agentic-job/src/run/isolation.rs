//! Standalone run's isolation default and producer-reported provenance.

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{Config, HOST_TABLE, Isolation, LEGACY_HOST_TABLE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Source {
    #[default]
    Declared,
    Detected,
}

impl Source {
    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::Declared => "declared by caller",
            Self::Detected => "detected GitLab container",
        }
    }

    fn is_declared(&self) -> bool {
        *self == Self::Declared
    }
}

pub(crate) fn mode(source: Option<Source>) -> Isolation {
    if source.is_some() {
        Isolation::External
    } else {
        Isolation::Managed
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub host_isolation: Isolation,
    // Keep declared records readable by older checkers.
    #[serde(default, skip_serializing_if = "Source::is_declared")]
    pub host_isolation_source: Source,
}

pub(super) fn select(config: &mut Config, text: &str) -> Result<Option<Source>> {
    select_with(
        config,
        text,
        gitlab_job(
            std::env::var_os("GITLAB_CI").as_deref(),
            std::env::var_os("CI_DISPOSABLE_ENVIRONMENT").as_deref(),
            std::env::var_os("CI_SHARED_ENVIRONMENT").as_deref(),
            std::env::var_os("GITHUB_ACTIONS").as_deref(),
        ) && container()
            && !engine_in_reach(),
    )
}

fn select_with(config: &mut Config, text: &str, detected: bool) -> Result<Option<Source>> {
    if config.sandbox.isolation == Isolation::External {
        return Ok(Some(Source::Declared));
    }
    // Detection is a hint, not a delegation: a job that asks for the local
    // egress proxy keeps managed mode, so check_held still refuses a proxy
    // that cannot hold the agent rather than dropping it unannounced.
    if detected && !config.egress.proxy {
        let table: toml::Table = toml::from_str(text).context("reading host isolation setting")?;
        let explicit = [HOST_TABLE, LEGACY_HOST_TABLE].iter().any(|name| {
            table
                .get(*name)
                .and_then(|host| host.get("isolation"))
                .is_some()
        });
        if !explicit {
            config.sandbox.isolation = Isolation::External;
            return Ok(Some(Source::Detected));
        }
    }
    Ok(None)
}

fn gitlab_job(
    gitlab: Option<&OsStr>,
    disposable: Option<&OsStr>,
    shared: Option<&OsStr>,
    github: Option<&OsStr>,
) -> bool {
    // GitLab's shell executor sets GITLAB_CI even if the runner itself is
    // containerized. GitLab Runner labels shell/SSH jobs shared, not disposable.
    let yes = Some(OsStr::new("true"));
    gitlab == yes && disposable == yes && shared.is_none() && github.is_none()
}

fn container() -> bool {
    let regular_marker = |path| {
        Path::new(path)
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.is_file())
    };
    if regular_marker("/.dockerenv") || regular_marker("/run/.containerenv") {
        return true;
    }
    // Kubernetes commonly hides the host cgroup path. Match the kubelet's
    // per-pod hosts file bind mount, not Kubernetes service environment vars.
    const MAX_MOUNTINFO_BYTES: u64 = 1 << 20;
    let mut text = String::new();
    std::fs::File::open("/proc/self/mountinfo")
        .and_then(|file| file.take(MAX_MOUNTINFO_BYTES + 1).read_to_string(&mut text))
        .is_ok_and(|size| size as u64 <= MAX_MOUNTINFO_BYTES && kubelet_hosts_mount(&text))
}

/// A container engine address handed to the job: its presence alone, never
/// a connection, keeps the managed default.
const ENGINE_VARS: [&str; 2] = ["DOCKER_HOST", "CONTAINER_HOST"];

const ENGINE_SOCKETS: [&str; 8] = [
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/run/podman/podman.sock",
    "/var/run/podman/podman.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/crio/crio.sock",
];

/// Whether a host engine may be in the job's reach. A disposable job with
/// an engine socket (say, for image builds) can start containers with host
/// mounts, so its runner does not own the host's isolation.
fn engine_in_reach() -> bool {
    let uid = rustix::process::getuid().as_raw();
    let user = [
        format!("/run/user/{uid}/docker.sock"),
        format!("/run/user/{uid}/podman/podman.sock"),
    ];
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|dir| {
            let dir = Path::new(&dir);
            [dir.join("docker.sock"), dir.join("podman/podman.sock")]
        })
        .into_iter()
        .flatten();
    ENGINE_VARS
        .iter()
        .any(|name| std::env::var_os(name).is_some())
        || ENGINE_SOCKETS
            .iter()
            .map(PathBuf::from)
            .chain(user.iter().map(PathBuf::from))
            .chain(runtime)
            .any(|path| path.symlink_metadata().is_ok())
}

fn kubelet_hosts_mount(text: &str) -> bool {
    text.lines().any(|line| {
        let mut fields = line.split_ascii_whitespace().skip(3);
        let Some(root) = fields.next() else {
            return false;
        };
        fields.next() == Some("/etc/hosts")
            && root
                .strip_prefix("/var/lib/kubelet/pods/")
                .and_then(|path| path.split_once('/'))
                .is_some_and(|(pod, file)| !pod.is_empty() && file == "etc-hosts")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation_selection() {
        use Source::{Declared, Detected};

        const NO_PROXY: &str = "[egress]\nproxy = false\n";
        for (text, gitlab, github, container, want) in [
            (NO_PROXY, None, None, false, None),
            (NO_PROXY, None, None, true, None),
            (NO_PROXY, Some("false"), None, true, None),
            (NO_PROXY, Some("true"), None, false, None),
            (NO_PROXY, Some("true"), Some("true"), true, None),
            (NO_PROXY, Some("true"), None, true, Some(Detected)),
            (
                "[host]\n[egress]\nproxy = false\n",
                Some("true"),
                None,
                true,
                Some(Detected),
            ),
            // The local proxy, by default or by name, keeps managed.
            ("", Some("true"), None, true, None),
            (
                "[egress]\nproxy = true\nwrite-policy = true\n",
                Some("true"),
                None,
                true,
                None,
            ),
            (
                "[host]\nisolation = 'managed'\n[egress]\nproxy = false\n",
                Some("true"),
                None,
                true,
                None,
            ),
            (
                "sandbox.isolation = 'managed'",
                Some("true"),
                None,
                true,
                None,
            ),
            (
                "[host]\nisolation = 'external'",
                Some("true"),
                None,
                true,
                Some(Declared),
            ),
            (
                "[sandbox]\nisolation = 'external'",
                None,
                Some("true"),
                false,
                Some(Declared),
            ),
        ] {
            let mut config = Config::parse(text).unwrap();
            let detected = gitlab_job(
                gitlab.map(OsStr::new),
                Some(OsStr::new("true")),
                None,
                github.map(OsStr::new),
            ) && container;
            assert_eq!(
                select_with(&mut config, text, detected).unwrap(),
                want,
                "{text:?}"
            );
            assert_eq!(
                config.sandbox.isolation,
                if want.is_some() {
                    Isolation::External
                } else {
                    Isolation::Managed
                },
                "{text:?}"
            );
        }
    }

    #[test]
    fn isolation_gitlab_executor_detection() {
        for (disposable, shared, want) in [
            (None, None, false),
            (None, Some("true"), false),
            (Some("false"), None, false),
            (Some("true"), Some("true"), false),
            (Some("true"), None, true),
        ] {
            let yes = Some(OsStr::new("true"));
            assert_eq!(
                gitlab_job(
                    yes,
                    disposable.map(OsStr::new),
                    shared.map(OsStr::new),
                    None
                ),
                want
            );
        }
    }

    #[test]
    fn isolation_kubelet_mount_detection() {
        for (mount, want) in [
            ("", false),
            (
                "42 41 8:1 /etc/hosts /etc/hosts rw - ext4 /dev/sda1 rw",
                false,
            ),
            (
                "42 41 8:1 /var/lib/kubelet/pods/abc/etc-hosts /tmp/hosts rw - ext4 /dev/sda1 rw",
                false,
            ),
            (
                "42 41 8:1 /var/lib/kubelet/pods/abc/elsewhere/etc-hosts /etc/hosts rw - ext4 /dev/sda1 rw",
                false,
            ),
            (
                "42 41 8:1 /var/lib/kubelet/pods/abc/etc-hosts /etc/hosts rw - ext4 /dev/sda1 rw",
                true,
            ),
        ] {
            assert_eq!(kubelet_hosts_mount(mount), want, "{mount:?}");
        }
    }
}
