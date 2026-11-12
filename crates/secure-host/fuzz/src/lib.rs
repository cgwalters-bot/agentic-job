//! Pure parser exercises: no files, processes, network or host setup.

use secure_host::config::{HOST_TABLE, Host, LEGACY_HOST_TABLE};
use secure_host::platform;

/// Bound allocation and parser work even when replaying an oversized artifact.
pub const MAX_INPUT: usize = 16 * 1024;

fn text(data: &[u8]) -> Option<&str> {
    if data.len() > MAX_INPUT {
        return None;
    }
    std::str::from_utf8(data).ok()
}

pub fn host_config(data: &[u8]) {
    let Some(text) = text(data) else { return };
    let parsed = Host::parse(text);
    if let Ok(host) = &parsed {
        // Exercise validation and the direct-destination parser, not just Serde.
        let _ = host.check();
    }
    let Ok(mut table) = toml::from_str::<toml::Table>(text) else {
        assert!(parsed.is_err());
        return;
    };
    if table.contains_key(HOST_TABLE) && table.contains_key(LEGACY_HOST_TABLE) {
        assert!(parsed.is_err(), "ambiguous host tables must be refused");
        return;
    }
    // Reformatting TOML and renaming the deprecated table must not change
    // admission or the effective host/egress configuration.
    if let Some(legacy) = table.remove(LEGACY_HOST_TABLE) {
        table.insert(HOST_TABLE.to_owned(), legacy);
    }
    let canonical = Host::parse(&toml::to_string(&table).expect("serializing a TOML table"));
    assert_eq!(parsed.is_ok(), canonical.is_ok());
    if let (Ok(host), Ok(canonical)) = (parsed, canonical) {
        assert_eq!(host.sandbox, canonical.sandbox);
        assert_eq!(host.egress, canonical.egress);
        assert_eq!(host.check().is_ok(), canonical.check().is_ok());
    }
}

pub fn os_release(data: &[u8]) {
    let Some(text) = text(data) else { return };
    let supported = platform::supported(text);
    // ID_LIKE and other non-identity fields cannot establish support.
    assert_eq!(
        supported,
        platform::supported(&format!("ID_LIKE=ubuntu\nNAME=example\n{text}"))
    );
    if supported {
        // Even a matching duplicate identity field must fail closed.
        for field in ["ID=ubuntu", "VERSION_ID=26.04"] {
            assert!(!platform::supported(&format!("{text}\n{field}\n")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_seed_corpora() {
        for (target, exercise) in [
            ("host_config", host_config as fn(&[u8])),
            ("os_release", os_release as fn(&[u8])),
        ] {
            let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("corpus")
                .join(target);
            let mut count = 0;
            for entry in std::fs::read_dir(corpus).unwrap() {
                let data = std::fs::read(entry.unwrap().path()).unwrap();
                assert!(data.len() <= MAX_INPUT);
                exercise(&data);
                count += 1;
            }
            assert!(count > 0, "empty seed corpus for {target}");
        }
    }

    #[test]
    fn input_boundaries() {
        for exercise in [host_config, os_release] {
            for data in [
                &b""[..],
                &b"\xff\0"[..],
                &vec![b' '; MAX_INPUT],
                &vec![b' '; MAX_INPUT + 1],
            ] {
                exercise(data);
            }
        }
        assert!(text(&vec![b' '; MAX_INPUT]).is_some());
        assert!(text(&vec![b' '; MAX_INPUT + 1]).is_none());
        assert!(text(b"\xff").is_none());
    }

    #[test]
    fn seeds_reach_acceptance_and_refusal_paths() {
        for (seed, parse_ok, check_ok) in [
            (
                include_str!("../corpus/host_config/defaults.toml"),
                true,
                true,
            ),
            (
                include_str!("../corpus/host_config/legacy.toml"),
                true,
                true,
            ),
            (
                include_str!("../corpus/host_config/prepared.toml"),
                true,
                true,
            ),
            (
                include_str!("../corpus/host_config/refused.toml"),
                true,
                false,
            ),
            (
                include_str!("../corpus/host_config/ambiguous.toml"),
                false,
                false,
            ),
        ] {
            let parsed = Host::parse(seed);
            assert_eq!(parsed.is_ok(), parse_ok, "{seed}");
            assert_eq!(
                parsed.is_ok_and(|host| host.check().is_ok()),
                check_ok,
                "{seed}"
            );
        }
        for (seed, supported) in [
            (include_str!("../corpus/os_release/ubuntu"), true),
            (include_str!("../corpus/os_release/rhel"), true),
            (include_str!("../corpus/os_release/centos"), true),
            (include_str!("../corpus/os_release/duplicate"), false),
            (include_str!("../corpus/os_release/derivative"), false),
            (include_str!("../corpus/os_release/shell"), false),
        ] {
            assert_eq!(platform::supported(seed), supported, "{seed}");
        }
    }
}
