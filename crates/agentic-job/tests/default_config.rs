//! The action chooses its default configuration before it has a Rust
//! binary, with `secure-host/default-config.sh`. Its own os-release parser
//! is held to secure-host's admission table here, so the two cannot drift.

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

use secure_host::platform::cases;

/// The selector, beside the configurations it names.
const ACTION_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../secure-host");

fn default_config(text: &str) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let release = dir.path().join("os-release");
    std::fs::write(&release, text).unwrap();
    Command::new("bash")
        .arg(Path::new(ACTION_DIR).join("default-config.sh"))
        .arg(release)
        .output()
        .unwrap()
}

#[test]
fn the_selector_names_an_action_configuration_for_each_admitted_host() {
    for (id, text, expected) in cases::release_files() {
        let selected = default_config(&text);
        assert_eq!(selected.status.success(), expected, "{text}");
        let config = String::from_utf8(selected.stdout).unwrap();
        let config = config.trim();
        if !expected {
            assert_eq!(config, "", "{text}");
            continue;
        }
        let want = if id == "ubuntu" {
            "hosted.toml"
        } else {
            "rhel-cloud.toml"
        };
        assert_eq!(config, want, "{text}");
        assert!(Path::new(ACTION_DIR).join(config).is_file(), "{config}");
    }
}

#[test]
fn the_selector_refuses_what_admission_refuses() {
    for text in cases::MALFORMED {
        let selected = default_config(text);
        assert!(!selected.status.success(), "{text:?}");
        assert!(selected.stdout.is_empty(), "{text:?}");
    }
}
