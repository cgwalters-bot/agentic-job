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
//!
//! Post-release only: `git tag --list 'v*' | release-check --forwarder-image`
//! compares the local forwarder's pinned upstream image with the newest tag.
//! It fetches only Containerfile.pin at the forwarder's full upstream commit;
//! it does not run the image or compare with the unreleased workspace version.

use anyhow::{Context, Result, bail, ensure};
use std::io::Read;
use std::time::Duration;

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
    match newest_tag(tags)? {
        Some((v, tag)) if v >= wanted => bail!("{version} is not newer than {tag}"),
        newest => Ok(newest.map(|(_, tag)| tag.to_owned())),
    }
}

fn newest_tag(tags: &str) -> Result<Option<(Version, &str)>> {
    let mut newest = None;
    for (tag, number) in tags.lines().filter_map(|t| Some((t, t.strip_prefix('v')?))) {
        let Some(v) = parse(number) else {
            bail!("tag {tag:?} is not vMAJOR.MINOR.PATCH");
        };
        newest = newest.max(Some((v, tag)));
    }
    Ok(newest)
}

fn forwarder_commit(action: &str) -> Result<String> {
    let docs = yaml_rust2::YamlLoader::load_from_str(action)?;
    ensure!(docs.len() == 1, "expected one forwarder YAML document");
    let steps = docs[0]["runs"]["steps"]
        .as_vec()
        .context("forwarder has no steps")?;
    let pins: Vec<_> = steps
        .iter()
        .filter_map(|step| step["uses"].as_str())
        .filter_map(|uses| uses.strip_prefix("cgwalters-forge/actions/secure-host@"))
        .collect();
    let [commit] = pins.as_slice() else {
        bail!("expected exactly one actions/secure-host forwarder pin");
    };
    ensure!(
        commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "forwarder must pin a full actions/secure-host commit"
    );
    Ok((*commit).to_owned())
}

fn check_image(pin: &str, tags: &str) -> Result<String> {
    let (_, newest) = newest_tag(tags)?.context("no vMAJOR.MINOR.PATCH tags after release")?;
    let image = pin
        .trim()
        .strip_prefix("FROM ghcr.io/cgwalters-forge/secure-host:")
        .context("expected the secure-host image in Containerfile.pin")?;
    let (tag, digest) = image
        .split_once("@sha256:")
        .context("missing image digest")?;
    ensure!(
        tag.strip_prefix('v').and_then(parse).is_some()
            && digest.len() == 64
            && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid secure-host image pin"
    );
    ensure!(
        tag == newest,
        "forwarder's image tag {tag} differs from newest release tag {newest}; update the forwarder after release"
    );
    Ok(tag.to_owned())
}

fn check_forwarder(tags: &str) -> Result<String> {
    let action = read_tags(std::fs::File::open("secure-host/action.yml")?)?;
    let commit = forwarder_commit(&action)?;
    // One fixed-origin, commit-addressed read; no checkout or image execution.
    // Bound time and bytes so a stalled or oversized response stops the check.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .max_redirects(0)
        .build()
        .into();
    let mut response = agent
        .get(format!("https://raw.githubusercontent.com/cgwalters-forge/actions/{commit}/secure-host/Containerfile.pin"))
        .call()
        .context("fetching forwarder's Containerfile.pin")?;
    let pin = read_tags(response.body_mut().as_reader())?;
    check_image(&pin, tags)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--forwarder-image"] {
        let tags = read_tags(std::io::stdin())?;
        println!("{}", check_forwarder(&tags)?);
        return Ok(());
    }
    let [version] = args.as_slice() else {
        bail!("usage: git tag --list 'v*' | release-check VERSION|--forwarder-image");
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

    #[test]
    fn post_release_image_matches_newest_numeric_tag() {
        let pin = format!(
            "FROM ghcr.io/cgwalters-forge/secure-host:v0.6.10@sha256:{}\n",
            "a".repeat(64)
        );
        for (tags, error) in [
            ("build-abc\nv0.6.9\nv0.6.10\n", None),
            ("v0.6.11\nv0.6.9\n", Some("v0.6.11")),
            ("v0.6.9\n", Some("v0.6.9")),
            ("", Some("no vMAJOR")),
            ("v0.6.10-rc.1\n", Some("not vMAJOR")),
        ] {
            let result = check_image(&pin, tags);
            if let Some(error) = error {
                let message = result.unwrap_err().to_string();
                assert!(message.contains(error), "{message}");
                if error.starts_with('v') {
                    assert!(message.contains("image tag v0.6.10"), "{message}");
                }
            } else {
                assert_eq!(result.unwrap(), "v0.6.10");
            }
        }
        for invalid in [
            pin.replace("@sha256:", "@sha512:"),
            pin.replace("v0.6.10", "latest"),
            pin.replace("secure-host:", "other:"),
        ] {
            assert!(check_image(&invalid, "v0.6.10").is_err());
        }
    }

    #[test]
    fn only_a_single_full_forwarder_commit_is_accepted() {
        let uses = format!("cgwalters-forge/actions/secure-host@{}", "a".repeat(40));
        let action = format!("runs:\n  steps:\n    - uses: {uses}\n");
        assert_eq!(forwarder_commit(&action).unwrap(), "a".repeat(40));
        for invalid in [
            action.replace(&"a".repeat(40), "main"),
            action.replace(&"a".repeat(40), "a/b?ref=main"),
            format!("{action}    - uses: {uses}\n"),
            "runs: {}".to_owned(),
        ] {
            assert!(forwarder_commit(&invalid).is_err());
        }
    }

    #[test]
    fn caller_opts_in_only_after_image_publication() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap();
        let docs = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
        let doc = &docs[0];
        assert_eq!(
            doc["on"]["workflow_dispatch"]["inputs"]["check-forwarder-image"]["default"].as_bool(),
            Some(false)
        );
        let job = &doc["jobs"]["forwarder-image"];
        assert_eq!(job["needs"].as_str(), Some("image"));
        assert_eq!(job["if"].as_str(), Some("inputs.check-forwarder-image"));
        assert_eq!(job["permissions"]["contents"].as_str(), Some("read"));
        let steps = job["steps"].as_vec().unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["with"]["ref"].as_str(), Some("refs/heads/main"));
        assert!(
            steps[1]["run"]
                .as_str()
                .unwrap()
                .ends_with("-- --forwarder-image")
        );
    }
}
