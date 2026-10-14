//! release-check: decides whether the `release` workflow may publish a
//! version, before anything is tagged.
//!
//! ```text
//! git tag --list 'v*' | release-check VERSION
//! ```
//!
//! VERSION must be `MAJOR.MINOR.PATCH`, the workspace's version (the one
//! this binary was built with, so the published binary reports it), and
//! newer than every `vMAJOR.MINOR.PATCH` tag on standard input. Callers
//! pin these tags and Dependabot proposes the highest, so a tag that goes
//! backwards or skips the version check would be offered as an upgrade.
//! Prints the newest such tag, empty when there is none, as the start of
//! the release notes. Pre-release and build suffixes are refused, in
//! VERSION and in tags alike: a `v` tag that is not one could still look
//! newer to whoever compares versions next, so it stops the release.
//! It reads names only and runs nothing it is given.

use anyhow::{Context, Result, bail, ensure};
use std::io::Read;

const WORKSPACE_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Tag names are short; this bounds what is read, not what is expected.
const MAX_INPUT_BYTES: u64 = 1 << 20;

type Version = (u64, u64, u64);

/// `MAJOR.MINOR.PATCH`: decimal, no leading zeros, nothing else.
fn parse(s: &str) -> Option<Version> {
    let mut parts = s.split('.');
    let mut next = || {
        let p = parts.next()?;
        let valid = !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && (p == "0" || !p.starts_with('0'));
        if valid { p.parse().ok() } else { None }
    };
    let v = (next()?, next()?, next()?);
    parts.next().is_none().then_some(v)
}

/// The tag names, refused whole past the limit: a list cut short could
/// lose the newest tag and let an older version through.
fn read_tags(input: impl Read) -> Result<String> {
    let mut tags = String::new();
    input
        .take(MAX_INPUT_BYTES + 1)
        .read_to_string(&mut tags)
        .context("reading tags")?;
    ensure!(
        tags.len() as u64 <= MAX_INPUT_BYTES,
        "more than {MAX_INPUT_BYTES} bytes of tags"
    );
    Ok(tags)
}

/// The newest version tag, or an error saying why `version` may not be
/// released.
fn check(version: &str, workspace: &str, tags: &str) -> Result<Option<String>> {
    let Some(wanted) = parse(version) else {
        bail!("{version:?} is not MAJOR.MINOR.PATCH");
    };
    ensure!(
        version == workspace,
        "{version} is not the workspace's version {workspace}: raise it in Cargo.toml first"
    );
    let mut newest = None;
    for (tag, number) in tags.lines().filter_map(|t| Some((t, t.strip_prefix('v')?))) {
        let Some(v) = parse(number) else {
            bail!("tag {tag:?} is not vMAJOR.MINOR.PATCH");
        };
        newest = newest.max(Some((v, tag)));
    }
    match newest {
        Some((v, tag)) if v >= wanted => bail!("{version} is not newer than {tag}"),
        newest => Ok(newest.map(|(_, tag)| tag.to_owned())),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [version] = args.as_slice() else {
        bail!("usage: git tag --list 'v*' | release-check VERSION");
    };
    let tags = read_tags(std::io::stdin())?;
    let newest = check(version, WORKSPACE_VERSION, &tags)?;
    println!("{}", newest.unwrap_or_default());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_plain_versions() {
        for (s, want) in [
            ("0.0.4", Some((0, 0, 4))),
            ("1.10.0", Some((1, 10, 0))),
            ("v1.0.0", None),
            ("1.0", None),
            ("1.0.0.0", None),
            ("01.0.0", None),
            ("1.0.0-rc.1", None),
            ("1.0.0+build", None),
            ("1..0", None),
            (" 1.0.0", None),
            ("+1.0.0", None),
            ("1.0.99999999999999999999", None),
        ] {
            assert_eq!(parse(s), want, "{s:?}");
        }
    }

    #[test]
    fn admits_only_a_newer_workspace_version() {
        let tags = "build-abc\nv0.0.2\nv0.0.10\nv0.0.3\n";
        for (version, workspace, tags, want) in [
            ("0.0.11", "0.0.11", tags, Ok(Some("v0.0.10"))),
            ("0.1.0", "0.1.0", tags, Ok(Some("v0.0.10"))),
            ("0.1.0", "0.1.0", "build-abc\n", Ok(None)),
            ("0.1.0", "0.1.0", "", Ok(None)),
            ("0.1.0", "0.1.0", "v0.0.1\nv1.0\n", Err("\"v1.0\" is not")),
            ("2.0.0", "2.0.0", "v1.0.0-rc.1\n", Err("is not vMAJOR")),
            // Compared as numbers: 0.0.9 sorts after 0.0.10 as text.
            ("0.0.9", "0.0.9", tags, Err("not newer than v0.0.10")),
            ("0.0.10", "0.0.10", tags, Err("not newer than v0.0.10")),
            ("0.0.11", "0.0.12", tags, Err("not the workspace")),
            ("v0.0.11", "0.0.11", tags, Err("is not MAJOR.MINOR.PATCH")),
            ("0.0.11\n", "0.0.11", tags, Err("is not MAJOR.MINOR.PATCH")),
        ] {
            let got = check(version, workspace, tags);
            match (&got, want) {
                (Ok(got), Ok(want)) => assert_eq!(got.as_deref(), want, "{version}"),
                (Err(got), Err(want)) => {
                    assert!(got.to_string().contains(want), "{version}: {got}")
                }
                _ => panic!("{version}: got {got:?}, want {want:?}"),
            }
        }
    }

    #[test]
    fn refuses_a_tag_list_past_the_limit() {
        let limit = MAX_INPUT_BYTES as usize;
        assert_eq!(read_tags("v1.0.0\n".as_bytes()).unwrap(), "v1.0.0\n");
        assert_eq!(
            read_tags(vec![b'v'; limit].as_slice()).unwrap().len(),
            limit
        );
        assert!(read_tags(vec![b'v'; limit + 1].as_slice()).is_err());
    }
}
