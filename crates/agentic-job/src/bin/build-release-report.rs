//! Offline, dry-run ledger for source-addressed release retention.
//!
//! Input is one JSON snapshot on stdin: `releases` is the paginated GitHub
//! Releases API flattened to an array; `pins` records resolved transitive
//! caller -> wrapper/action SHA -> source digest evidence, and `unresolved`
//! names gaps (including uninspected refs and queued/in-flight runs).
//! Absence of an observed reference is never authorization to delete.
//! This tool has no forge client, token handling or deletion operation.

use std::collections::BTreeMap;
use std::io::Read;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    releases: Vec<Release>,
    pins: Vec<Pin>,
    unresolved: Vec<String>,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    caller: String,
    reference: String,
    wrapper: String,
    wrapper_sha: String,
    source: String,
}

#[derive(Serialize)]
struct Entry<'a> {
    release: &'a str,
    status: &'static str,
    references: Vec<&'a Pin>,
    action: &'static str,
}

#[derive(Serialize)]
struct Report<'a> {
    schema: u32,
    dry_run: bool,
    deletion_authorized: bool,
    unresolved: &'a [String],
    releases: Vec<Entry<'a>>,
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn report(snapshot: &Snapshot) -> Result<Report<'_>> {
    let mut pins: BTreeMap<&str, Vec<&Pin>> = BTreeMap::new();
    for pin in &snapshot.pins {
        ensure!(
            hex(&pin.source, 64),
            "invalid source digest for {}",
            pin.caller
        );
        ensure!(
            hex(&pin.wrapper_sha, 40),
            "unresolved wrapper SHA for {}",
            pin.caller
        );
        ensure!(
            !pin.caller.is_empty() && !pin.reference.is_empty() && !pin.wrapper.is_empty(),
            "pin evidence must name caller, reference and wrapper"
        );
        pins.entry(&pin.source).or_default().push(pin);
    }
    let mut releases = BTreeMap::new();
    for release in &snapshot.releases {
        let Some(source) = release.tag_name.strip_prefix("build-") else {
            continue;
        };
        ensure!(
            hex(source, 64),
            "invalid build release {}",
            release.tag_name
        );
        let references = pins.get(source).cloned().unwrap_or_default();
        let entry = Entry {
            release: &release.tag_name,
            status: if references.is_empty() {
                "no-observed-pin-reference"
            } else {
                "referenced"
            },
            references,
            action: "keep",
        };
        ensure!(
            releases.insert(source, entry).is_none(),
            "duplicate build release {source}"
        );
    }
    Ok(Report {
        schema: 1,
        dry_run: true,
        deletion_authorized: false,
        unresolved: &snapshot.unresolved,
        releases: releases.into_values().collect(),
    })
}

fn read_snapshot(input: impl Read) -> Result<Snapshot> {
    let mut bytes = Vec::new();
    input.take(MAX_SNAPSHOT_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_SNAPSHOT_BYTES,
        "release snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes"
    );
    serde_json::from_slice(&bytes).context("parsing release/pin snapshot")
}

fn main() -> Result<()> {
    ensure!(
        std::env::args_os().len() == 1,
        "usage: build-release-report < snapshot.json"
    );
    let snapshot = read_snapshot(std::io::stdin().lock())?;
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report(&snapshot)?)?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ledger_keeps_referenced_and_unresolved_releases_and_ignores_versions() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let snapshot: Snapshot = serde_json::from_value(json!({
            "releases": [{"tag_name": format!("build-{b}")}, {"tag_name": "v1.2.3"}, {"tag_name": format!("build-{a}")}],
            "pins": [{"caller": "example-org/caller", "reference": "refs/heads/main", "wrapper": "example-org/actions/.github/workflows/job.yml", "wrapper_sha": "c".repeat(40), "source": a}],
            "unresolved": ["retained tags and queued runs not yet inspected"]
        })).unwrap();
        let report = report(&snapshot).unwrap();
        assert_eq!(report.releases.len(), 2);
        assert_eq!(report.releases[0].status, "referenced");
        assert_eq!(report.releases[0].references.len(), 1);
        assert_eq!(report.releases[1].status, "no-observed-pin-reference");
        assert!(report.releases.iter().all(|entry| entry.action == "keep"));
        assert!(!report.deletion_authorized);
    }

    #[test]
    fn missing_inventory_and_malformed_evidence_are_not_empty_reference_sets() {
        for bytes in ["{}", r#"{"releases":[],"pins":[]}"#, "{"] {
            assert!(read_snapshot(bytes.as_bytes()).is_err());
        }
        let mut snapshot = Snapshot {
            releases: vec![Release {
                tag_name: "build-short".into(),
            }],
            pins: vec![],
            unresolved: vec![],
        };
        assert!(report(&snapshot).is_err());
        snapshot.releases.clear();
        snapshot.pins.push(Pin {
            caller: "example/caller".into(),
            reference: "main".into(),
            wrapper: "example/actions".into(),
            wrapper_sha: "main".into(),
            source: "a".repeat(64),
        });
        assert!(report(&snapshot).is_err());
        assert!(read_snapshot(std::io::repeat(b' ').take(MAX_SNAPSHOT_BYTES + 1)).is_err());
    }
}
