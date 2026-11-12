//! Runtime layout is a build-time contract, not a path supplied by a job.
//!
//! Standalone builds use secure-host names. Consumers pinned to an older
//! deployed image can opt into its complete layout until they migrate that
//! image and their readers together. Never mix layouts on a running host:
//! in particular a check record or a BPF pin from one is not proof for another.

/// Select a fixed name for the layout this binary was built to use.
pub(crate) const fn name(neutral: &'static str, legacy: &'static str) -> &'static str {
    if cfg!(feature = "legacy-runtime") {
        legacy
    } else {
        neutral
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_paths_use_one_layout() {
        let prefix = name("secure-host", "agentic-job");
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
