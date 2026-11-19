//! Runtime layout is a build-time contract, not a path supplied by a job.
//!
//! Standalone builds use secure-host names. Consumers pinned to an older
//! deployed image can opt into its complete layout until they migrate that
//! image and their readers together. Never mix layouts on a running host:
//! in particular a check record or a BPF pin from one is not proof for another.

use std::path::Path;

use anyhow::{Result, ensure};

/// Each layout's setup marker, neutral then legacy: root's configuration
/// directory, which setup creates.
pub(crate) const CONFIG_DIRS: [&str; 2] = ["/etc/secure-host", "/etc/agentic-job"];

/// Each layout's world-write policy pins, neutral then legacy.
pub(crate) const PIN_DIRS: [&str; 2] = [
    "/sys/fs/bpf/secure-host-world-write",
    "/sys/fs/bpf/agentic-job-world-write",
];

/// Select a fixed name for the layout this binary was built to use.
pub(crate) const fn name(neutral: &'static str, legacy: &'static str) -> &'static str {
    if cfg!(feature = "legacy-runtime") {
        legacy
    } else {
        neutral
    }
}

/// Refuse a host on which any of PATHS exists: a host a run of either
/// layout already prepared, which a build of the other would otherwise
/// take for a fresh one. Configuration and pins are still read only from
/// this build's own layout.
pub(crate) fn refuse_prepared<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<()> {
    for path in paths {
        ensure!(
            !Path::new(path).exists(),
            "{path} already exists: this host was prepared before, by this build or one of another runtime layout, and needs to be a fresh one"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prior_layout_marker_is_refused_and_a_fresh_host_is_not() {
        let host = tempfile::tempdir().unwrap();
        let [neutral, legacy] = ["secure-host", "agentic-job"].map(|name| {
            host.path()
                .join(name)
                .into_os_string()
                .into_string()
                .unwrap()
        });
        // The control: nothing of either layout is there.
        refuse_prepared([neutral.as_str(), legacy.as_str()]).unwrap();
        for (prior, other) in [(&neutral, &legacy), (&legacy, &neutral)] {
            std::fs::create_dir(prior).unwrap();
            let err = refuse_prepared([other.as_str(), prior.as_str()]).unwrap_err();
            assert!(
                err.to_string()
                    .starts_with(&format!("{prior} already exists"))
            );
            std::fs::remove_dir(prior).unwrap();
        }
    }

    #[test]
    fn privileged_paths_use_one_layout() {
        let prefix = if cfg!(feature = "legacy-runtime") {
            "agentic-job"
        } else {
            "secure-host"
        };
        assert_eq!(crate::setup::CONFIG_DIR, format!("/etc/{prefix}"));
        assert_eq!(
            crate::config::ROOT_COPY,
            format!("/etc/{prefix}/config.toml")
        );
        assert_eq!(
            crate::network::RULES_FILE,
            format!("/etc/{prefix}/rules.nft")
        );
        assert_eq!(
            crate::helper::SELF_COPY,
            format!("/usr/local/libexec/{prefix}")
        );
        assert_eq!(
            crate::world_write::WORLD_WRITE_PIN,
            format!("/sys/fs/bpf/{prefix}-world-write")
        );
        assert_eq!(
            crate::setup::WORLD_WRITE_PROBE_FILE,
            format!("/etc/{prefix}/world-write-probe/file")
        );
        assert_eq!(
            crate::setup::SERVE_ENDPOINT,
            format!("/etc/{prefix}/session-endpoint")
        );
    }
}
