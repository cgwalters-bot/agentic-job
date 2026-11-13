//! Inactive building block for exact old-side inference-address recovery.
//!
//! The threat is a producer using a placeholder as a wildcard for unrelated
//! public-base content. Only one host:port literal may replace a placeholder,
//! at the exact old-side path and line, with every other byte matching.
//! There is deliberately no filesystem, git, logging or publisher integration
//! here. A future trusted caller must authenticate the public preimage, keep
//! the result application-only, and use the same revalidated result for trial
//! and publication. Never use the producer's checkout as the preimage source.

use std::sync::LazyLock;

use anyhow::{Result, ensure};
use regex::Regex;

use crate::check::read_patch;
use crate::contract::{COMMIT_RE, PatchRules};

const PLACEHOLDER: &str = "<inference-address>";
const MAX_BYTES: usize = 1 << 20;
const MAX_FILES: usize = 50;

static HUNK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@")
        .expect("valid hunk expression")
});

/// Application-only bytes and safe counts. Intentionally not Debug/Serialize:
/// the recovered old-side bytes must not become diagnostics or artifacts.
pub struct Recovered {
    patch: String,
    pub restored_lines: usize,
    /// Added lines remain redacted and need a draft-review warning.
    pub added_placeholders: usize,
}

impl Recovered {
    /// For trial and publication only, not an upload or diagnostic.
    pub fn application_patch(&self) -> &str {
        &self.patch
    }
}

/// Recover one validated mail against authenticated public BASE.
///
/// READ_PREIMAGE must return the regular UTF-8 blob at BASE:PATH, not a working
/// tree file or a fuzzy lookup, reading at most LIMIT bytes. Its errors are
/// suppressed to avoid leaking source text. Both blobs and patch are bounded
/// by the smaller of MAX_PATCH_BYTES and 1 MiB, and at most 50 files are read.
/// The caller must still compare actual changed paths after exact application.
/// Series orchestration, credential checks and receipt/digest binding remain
/// the caller's responsibility; this function does not enable any publisher.
pub fn reconstruct(
    patch: &str,
    rules: &PatchRules<'_>,
    base: &str,
    max_patch_bytes: usize,
    mut read_preimage: impl FnMut(&str, usize) -> Result<Vec<u8>>,
) -> Result<Recovered> {
    let limit = max_patch_bytes.min(MAX_BYTES);
    ensure!(patch.len() <= limit, "recovery patch exceeds byte limit");
    ensure!(
        COMMIT_RE.is_match(base),
        "recovery requires a full base commit"
    );
    let reading = read_patch(patch, rules, base);
    // Do not echo parser errors: they can quote producer text.
    ensure!(
        reading.problems.is_empty(),
        "recovery requires a valid patch"
    );
    ensure!(
        reading.files.len() <= MAX_FILES,
        "recovery exceeds file limit"
    );
    ensure!(
        patch.ends_with('\n')
            && !patch.contains('\r')
            && !patch
                .lines()
                .any(|line| line == "\\ No newline at end of file"),
        "recovery does not support CR or missing final newlines"
    );

    let mut output = String::with_capacity(patch.len());
    let mut preimage;
    let mut old_lines = Vec::new();
    let mut old_position = 0usize;
    let mut previous_end = 0usize;
    let mut remaining = (0usize, 0usize);
    let mut restored_lines = 0;
    let mut added_placeholders = 0;
    let mut in_files = false;
    let mut new_file = false;

    for line in patch.split_inclusive('\n') {
        let text = &line[..line.len() - 1];
        if remaining != (0, 0) {
            let prefix = text.as_bytes().first().copied().unwrap_or(b' ');
            let body = text.get(1..).unwrap_or("");
            if prefix == b' ' || prefix == b'-' {
                let expected = old_lines.get(old_position).copied();
                ensure!(expected.is_some(), "recovery old-side position is absent");
                let expected = expected.unwrap_or("");
                if body.contains(PLACEHOLDER) {
                    ensure!(
                        matches_redaction(body, expected),
                        "recovery old-side mismatch"
                    );
                    output.push(char::from(prefix));
                    output.push_str(expected);
                    output.push('\n');
                    restored_lines += 1;
                } else {
                    ensure!(body == expected, "recovery old-side mismatch");
                    output.push_str(line);
                }
                old_position += 1;
                remaining.0 -= 1;
            } else {
                output.push_str(line);
            }
            if prefix == b' ' || prefix == b'+' {
                remaining.1 -= 1;
            }
            if prefix == b'+' {
                added_placeholders += body.matches(PLACEHOLDER).count();
            }
        } else if text.starts_with("diff --git ") {
            in_files = true;
            new_file = false;
            previous_end = 0;
            output.push_str(line);
        } else if in_files && text == "--- /dev/null" {
            new_file = true;
            old_lines.clear();
            output.push_str(line);
        } else if in_files && let Some(path) = text.strip_prefix("--- a/") {
            // read_patch has already checked this exact path and mail shape.
            let bytes = read_preimage(path, limit)
                .map_err(|_| anyhow::anyhow!("recovery preimage unavailable"))?;
            ensure!(bytes.len() <= limit, "recovery preimage exceeds byte limit");
            preimage = String::from_utf8(bytes)
                .map_err(|_| anyhow::anyhow!("recovery preimage is not UTF-8"))?;
            ensure!(
                preimage.is_empty() || preimage.ends_with('\n'),
                "recovery preimage lacks final newline"
            );
            old_lines = preimage.split_terminator('\n').collect();
            output.push_str(line);
        } else if in_files && let Some(captures) = HUNK.captures(text) {
            let number = |index| -> Result<usize> {
                captures.get(index).map_or(Ok(1), |value| {
                    value
                        .as_str()
                        .parse()
                        .map_err(|_| anyhow::anyhow!("recovery hunk overflow"))
                })
            };
            let start = number(1)?;
            remaining = (number(2)?, number(4)?);
            old_position = if remaining.0 == 0 {
                start
            } else {
                start
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("recovery invalid hunk start"))?
            };
            ensure!(
                old_position >= previous_end
                    && old_position <= old_lines.len()
                    && (!new_file || remaining.0 == 0),
                "recovery hunk position is invalid or overlapping"
            );
            previous_end = old_position
                .checked_add(remaining.0)
                .ok_or_else(|| anyhow::anyhow!("recovery hunk overflow"))?;
            output.push_str(line);
        } else {
            output.push_str(line);
        }
        ensure!(output.len() <= limit, "recovered patch exceeds byte limit");
    }
    let recovered = read_patch(&output, rules, base);
    ensure!(
        recovered.problems.is_empty() && recovered.files == reading.files,
        "recovered patch failed revalidation"
    );
    Ok(Recovered {
        patch: output,
        restored_lines,
        added_placeholders,
    })
}

fn matches_redaction(redacted: &str, original: &str) -> bool {
    let Some((prefix, suffix)) = redacted.split_once(PLACEHOLDER) else {
        return false;
    };
    if suffix.contains(PLACEHOLDER) {
        return false;
    }
    let Some(address) = original
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
    else {
        return false;
    };
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    if port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || port.parse::<u16>().is_err()
    {
        return false;
    }
    if let Some(ipv6) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return ipv6.parse::<std::net::Ipv6Addr>().is_ok();
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::process::Command;

    const BASE: &str = "1111111111111111111111111111111111111111";
    const ADDRESS: &str = "inference.example.test:8443";

    fn rules() -> PatchRules<'static> {
        PatchRules {
            protected_files: &[],
            protect_top_level_dot_folders: true,
            unprotected_dot_folders: &[],
            protected_paths: &[],
            max_patch_files: 2,
            commit_author: None,
        }
    }

    fn mail(hunk: &str) -> String {
        format!(
            "From {} Mon Sep 17 00:00:00 2001\nX-GH-AW-Base-Commit: {BASE}\n\
             From: Test <test@example.test>\nDate: Tue, 3 Nov 2026 00:00:00 +0000\n\
             Subject: [PATCH] Change setting\n\n---\ndiff --git a/config b/config\n\
             index 1234567..abcdef0 100644\n--- a/config\n+++ b/config\n{hunk}",
            "2".repeat(40)
        )
    }

    fn recover(patch: &str, preimage: &str) -> Result<Recovered> {
        reconstruct(patch, &rules(), BASE, MAX_BYTES, |path, limit| {
            ensure!(path == "config", "wrong path");
            assert_eq!(limit, MAX_BYTES);
            Ok(preimage.as_bytes().to_vec())
        })
    }

    fn git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .current_dir(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn context_and_removal_apply_exactly_against_public_preimage() {
        for hunk in [
            "@@ -1,2 +1,2 @@\n url=<inference-address>\n-old\n+new\n",
            "@@ -1,2 +1 @@\n-url=<inference-address>\n old\n",
        ] {
            let preimage = format!("url={ADDRESS}\nold\n");
            let original = mail(hunk);
            let recovered = recover(&original, &preimage).unwrap();
            assert_eq!(recovered.restored_lines, 1);
            assert_eq!(recovered.added_placeholders, 0);
            assert_eq!(
                recovered.application_patch(),
                original.replace(PLACEHOLDER, ADDRESS)
            );
            let repo = tempfile::tempdir().unwrap();
            git(repo.path(), &["init", "--quiet"]);
            std::fs::write(repo.path().join("config"), &preimage).unwrap();
            std::fs::write(repo.path().join("change.patch"), &original).unwrap();
            let failed = Command::new("git")
                .current_dir(repo.path())
                .args(["apply", "--check", "change.patch"])
                .output()
                .unwrap();
            assert!(!failed.status.success());
            std::fs::write(
                repo.path().join("change.patch"),
                recovered.application_patch(),
            )
            .unwrap();
            git(repo.path(), &["apply", "--check", "change.patch"]);
            git(repo.path(), &["apply", "change.patch"]);
            let actual = std::fs::read_to_string(repo.path().join("config")).unwrap();
            assert_eq!(
                actual,
                if hunk.contains("+new") {
                    format!("url={ADDRESS}\nnew\n")
                } else {
                    "old\n".to_owned()
                }
            );
        }
    }

    #[test]
    fn added_placeholders_are_never_reconstructed() {
        let patch =
            mail("@@ -1,2 +1,2 @@\n url=<inference-address>\n-old\n+url=<inference-address>\n");
        let recovered = recover(&patch, &format!("url={ADDRESS}\nold\n")).unwrap();
        assert_eq!(recovered.restored_lines, 1);
        assert_eq!(recovered.added_placeholders, 1);
        assert!(
            recovered
                .application_patch()
                .contains("+url=<inference-address>\n")
        );
    }

    #[test]
    fn rejects_unprovable_recovery_without_disclosing_preimage() {
        let patch = mail("@@ -1,2 +1,2 @@\n url=<inference-address>\n-old\n+new\n");
        for (case, patch, preimage) in [
            (
                "non-placeholder mismatch",
                patch.clone(),
                format!("url={ADDRESS}\nwrong\n"),
            ),
            (
                "prefix mismatch",
                patch.clone(),
                format!("other={ADDRESS}\nold\n"),
            ),
            (
                "wrong position",
                patch.clone(),
                format!("other\nurl={ADDRESS}\nold\n"),
            ),
            (
                "wrong path",
                patch.replace("config", "other"),
                format!("url={ADDRESS}\nold\n"),
            ),
            (
                "wrong base",
                patch.replace(BASE, &"3".repeat(40)),
                format!("url={ADDRESS}\nold\n"),
            ),
            (
                "malformed hunk",
                patch.replace("-1,2", "-1,3"),
                format!("url={ADDRESS}\nold\n"),
            ),
            (
                "non-address",
                patch.clone(),
                "url=unrelated source bytes\nold\n".into(),
            ),
            (
                "ambiguous placeholders",
                patch.replace(PLACEHOLDER, "<inference-address><inference-address>"),
                format!("url={ADDRESS}\nold\n"),
            ),
            (
                "CR",
                patch.replace('\n', "\r\n"),
                format!("url={ADDRESS}\nold\n"),
            ),
            (
                "missing final newline",
                patch.clone(),
                format!("url={ADDRESS}\nold"),
            ),
        ] {
            let err = recover(&patch, &preimage).err().unwrap();
            let shown = format!("{err:#}");
            assert!(!shown.contains(ADDRESS), "{case}");
            assert!(!shown.contains("unrelated source bytes"), "{case}");
        }
        let err = reconstruct(&patch, &rules(), BASE, MAX_BYTES, |_, _| {
            anyhow::bail!("source includes {ADDRESS}")
        })
        .err()
        .unwrap();
        assert_eq!(format!("{err:#}"), "recovery preimage unavailable");
    }

    #[test]
    fn enforces_size_bounds_before_and_after_reconstruction() {
        let patch = mail("@@ -1 +1 @@\n-url=<inference-address>\n+new\n");
        assert!(
            reconstruct(&patch, &rules(), BASE, patch.len() - 1, |_, _| {
                panic!("must not read preimage")
            })
            .is_err()
        );
        let preimage = format!("url={ADDRESS}\n");
        assert!(
            reconstruct(&patch, &rules(), BASE, patch.len(), |_, _| {
                Ok(preimage.as_bytes().to_vec())
            })
            .is_err()
        );
        assert!(recover(&patch, &"x".repeat(MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn only_one_host_port_literal_is_eligible() {
        for (address, accepted) in [
            ("inference.example.test:443", true),
            ("192.0.2.1:8443", true),
            ("[2001:db8::1]:443", true),
            ("example.test:0", true),
            ("example.test", false),
            ("example.test:65536", false),
            ("example.test:443/path", false),
            ("example.test:443 other", false),
            ("user@example.test:443", false),
            ("[not-ipv6]:443", false),
            ("example.test:+443", false),
            ("-example.test:443", false),
        ] {
            assert_eq!(
                matches_redaction("url=<inference-address>/v1", &format!("url={address}/v1")),
                accepted,
                "{address}"
            );
        }
    }

    #[test]
    fn exact_trial_can_use_each_reconstructed_predecessor() {
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "--quiet"]);
        std::fs::write(repo.path().join("config"), format!("url={ADDRESS}\nold\n")).unwrap();
        git(repo.path(), &["add", "config"]);
        let identity = ["-c", "user.name=Test", "-c", "user.email=test@example.test"];
        git(
            repo.path(),
            &[identity.as_slice(), &["commit", "--quiet", "-m", "Base"]].concat(),
        );
        for (before, after) in [("old", "middle"), ("middle", "new")] {
            let patch = mail(&format!(
                "@@ -1,2 +1,2 @@\n url=<inference-address>\n-{before}\n+{after}\n"
            ));
            let recovered = reconstruct(&patch, &rules(), BASE, MAX_BYTES, |path, _| {
                let output = Command::new("git")
                    .current_dir(repo.path())
                    .args(["show", &format!("HEAD:{path}")])
                    .output()
                    .unwrap();
                ensure!(output.status.success(), "preimage unavailable");
                Ok(output.stdout)
            })
            .unwrap();
            std::fs::write(
                repo.path().join("change.patch"),
                recovered.application_patch(),
            )
            .unwrap();
            git(
                repo.path(),
                &[identity.as_slice(), &["am", "--keep-cr", "change.patch"]].concat(),
            );
            assert_eq!(
                std::fs::read_to_string(repo.path().join("config")).unwrap(),
                format!("url={ADDRESS}\n{after}\n")
            );
        }
    }

    #[test]
    fn refuses_overlapping_hunks_and_missing_old_side_lines() {
        for hunk in [
            "@@ -1 +1 @@\n-url=<inference-address>\n+new\n@@ -1 +2 @@\n-url=<inference-address>\n+other\n",
            "@@ -2 +2 @@\n-url=<inference-address>\n+new\n",
            "@@ -0 +1 @@\n-url=<inference-address>\n+new\n",
        ] {
            assert!(recover(&mail(hunk), &format!("url={ADDRESS}\n")).is_err());
        }
    }
}
