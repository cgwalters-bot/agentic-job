//! Building block for exact old-side inference-address recovery.
//!
//! The threat is a producer using a placeholder as a wildcard for unrelated
//! public-base content. Only one host:port literal may replace a placeholder,
//! at the exact old-side path and line, with every other byte matching.
//! There is deliberately no filesystem, git or logging access here. The
//! opt-in replacement trial authenticates its public preimage; other callers
//! must do the same, keep the result application-only, and use it for both trial
//! and publication. No workflow enables recovery. Never use the producer's
//! checkout as the preimage source.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use anyhow::{Result, ensure};
use regex::Regex;
use ring::digest::{self, Digest};

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
    postimages: Vec<Postimage>,
    pub restored_lines: usize,
    /// Added lines remain redacted and need a draft-review warning.
    pub added_placeholders: usize,
}

struct Postimage {
    path: String,
    content: Option<(usize, Digest)>,
}

impl Recovered {
    /// For trial and publication only, not an upload or diagnostic.
    pub fn application_patch(&self) -> &str {
        &self.patch
    }

    /// Bind application to the exact authenticated hunk positions, not git's
    /// context search. Read immutable result blobs, never working-tree files;
    /// None means an absent path. Errors deliberately disclose no source bytes.
    pub fn verify_application(
        &self,
        mut read: impl FnMut(&str, usize) -> Result<Option<Vec<u8>>>,
    ) -> Result<()> {
        for expected in &self.postimages {
            let actual = read(
                &expected.path,
                expected.content.as_ref().map_or(0, |(size, _)| *size),
            )
            .map_err(|_| anyhow::anyhow!("recovery result unavailable"))?;
            let matches = match (&expected.content, actual) {
                (None, None) => true,
                (Some((size, hash)), Some(bytes)) => {
                    bytes.len() == *size
                        && digest::digest(&digest::SHA256, &bytes).as_ref() == hash.as_ref()
                }
                _ => false,
            };
            ensure!(
                matches,
                "recovery applied at different positions or produced different bytes"
            );
        }
        Ok(())
    }
}

fn finish_postimage(
    path: &str,
    deleted: bool,
    mut result: String,
    old_lines: &[&str],
    old_position: usize,
) -> Result<Postimage> {
    for line in old_lines.get(old_position..).unwrap_or_default() {
        result.push_str(line);
        result.push('\n');
    }
    ensure!(
        !deleted || result.is_empty(),
        "recovery deletion leaves old-side content"
    );
    Ok(Postimage {
        path: path.to_owned(),
        content: (!deleted).then(|| {
            (
                result.len(),
                digest::digest(&digest::SHA256, result.as_bytes()),
            )
        }),
    })
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
    // read_patch reports distinct paths, not sections. Re-reading one path
    // would reset the overlap guard below and defeat the preimage read bound.
    // Its validated headers name the same plain path on both sides, so exact
    // header identity is sufficient. Refuse before invoking the reader at all.
    let mut sections = BTreeSet::new();
    for header in patch.lines().filter(|line| line.starts_with("diff --git ")) {
        ensure!(sections.insert(header), "recovery repeats a file section");
    }
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
    let mut postimages = Vec::new();
    let mut file_path = "";
    let mut postimage = String::new();
    let mut postimage_lines = 0;
    let mut deleted = false;

    for line in patch.split_inclusive('\n') {
        let text = &line[..line.len() - 1];
        if remaining != (0, 0) {
            let prefix = text.as_bytes().first().copied().unwrap_or(b' ');
            let body = text.get(1..).unwrap_or("");
            if prefix == b' ' || prefix == b'-' {
                let expected = old_lines.get(old_position).copied();
                ensure!(expected.is_some(), "recovery old-side position is absent");
                let expected = expected.unwrap_or("");
                if body == expected {
                    output.push_str(line);
                } else if body.contains(PLACEHOLDER) {
                    ensure!(
                        matches_redaction(body, expected),
                        "recovery old-side mismatch"
                    );
                    output.push(char::from(prefix));
                    output.push_str(expected);
                    output.push('\n');
                    restored_lines += 1;
                } else {
                    anyhow::bail!("recovery old-side mismatch");
                }
                old_position += 1;
                remaining.0 -= 1;
            } else {
                output.push_str(line);
            }
            if prefix == b' ' || prefix == b'+' {
                remaining.1 -= 1;
                postimage.push_str(if prefix == b' ' {
                    old_lines[old_position - 1]
                } else {
                    body
                });
                postimage.push('\n');
                postimage_lines += 1;
            }
            if prefix == b'+' {
                added_placeholders += body.matches(PLACEHOLDER).count();
            }
        } else if text.starts_with("diff --git ") {
            if in_files {
                postimages.push(finish_postimage(
                    file_path,
                    deleted,
                    std::mem::take(&mut postimage),
                    &old_lines,
                    old_position,
                )?);
            }
            file_path = text
                .strip_prefix("diff --git a/")
                .and_then(|header| header.split_once(" b/"))
                .map(|(path, _)| path)
                .ok_or_else(|| anyhow::anyhow!("recovery invalid file header"))?;
            in_files = true;
            new_file = false;
            previous_end = 0;
            old_position = 0;
            old_lines.clear();
            deleted = false;
            postimage_lines = 0;
            output.push_str(line);
        } else if in_files && (text == "+++ /dev/null" || text.starts_with("deleted file mode ")) {
            deleted = true;
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
            let position = if remaining.0 == 0 {
                start
            } else {
                start
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("recovery invalid hunk start"))?
            };
            ensure!(
                position >= previous_end
                    && position <= old_lines.len()
                    && (!new_file || remaining.0 == 0),
                "recovery hunk position is invalid or overlapping"
            );
            for line in &old_lines[old_position..position] {
                postimage.push_str(line);
                postimage.push('\n');
                postimage_lines += 1;
            }
            old_position = position;
            let new_start = number(3)?;
            let new_position = if remaining.1 == 0 {
                Some(new_start)
            } else {
                new_start.checked_sub(1)
            };
            ensure!(
                new_position == Some(postimage_lines),
                "recovery inconsistent new-side position"
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
    if in_files {
        postimages.push(finish_postimage(
            file_path,
            deleted,
            postimage,
            &old_lines,
            old_position,
        )?);
    }
    let recovered = read_patch(&output, rules, base);
    ensure!(
        recovered.problems.is_empty() && recovered.files == reading.files,
        "recovered patch failed revalidation"
    );
    Ok(Recovered {
        patch: output,
        postimages,
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
    fn duplicate_context_cannot_redirect_a_recovered_hunk() {
        let preimage = format!("url={ADDRESS}\nold\nurl={ADDRESS}\nold\n");
        let redirected = mail("@@ -1,2 +3,2 @@\n url=<inference-address>\n-old\n+new\n");
        let error = recover(&redirected, &preimage).err().unwrap();
        assert_eq!(error.to_string(), "recovery inconsistent new-side position");

        let patch = mail("@@ -1,2 +1,2 @@\n url=<inference-address>\n-old\n+new\n");
        let recovered = recover(&patch, &preimage).unwrap();
        let exact = format!("url={ADDRESS}\nnew\nurl={ADDRESS}\nold\n");
        recovered
            .verify_application(|path, limit| {
                assert_eq!(path, "config");
                assert_eq!(limit, exact.len());
                Ok(Some(exact.as_bytes().to_vec()))
            })
            .unwrap();
        let relocated = format!("url={ADDRESS}\nold\nurl={ADDRESS}\nnew\n");
        for bytes in [Some(relocated.into_bytes()), None] {
            let error = recovered
                .verify_application(|_, _| Ok(bytes.clone()))
                .unwrap_err();
            assert!(!format!("{error:#}").contains(ADDRESS));
        }
    }

    #[test]
    fn new_positions_include_preceding_hunk_deltas() {
        let patch =
            mail("@@ -1 +1,2 @@\n url=<inference-address>\n+inserted\n@@ -3 +4 @@\n-old\n+new\n");
        let preimage = format!("url={ADDRESS}\nuntouched\nold\n");
        let recovered = recover(&patch, &preimage).unwrap();
        let result = format!("url={ADDRESS}\ninserted\nuntouched\nnew\n");
        recovered
            .verify_application(|_, _| Ok(Some(result.as_bytes().to_vec())))
            .unwrap();
        assert!(recover(&patch.replace("-3 +4", "-3 +3"), &preimage).is_err());
    }

    #[test]
    fn application_verification_distinguishes_deleted_and_empty_files() {
        let original = mail("@@ -1 +0,0 @@\n-url=<inference-address>\n");
        let deleted = original.replace("+++ b/config", "+++ /dev/null").replace(
            "index 1234567..abcdef0 100644",
            "deleted file mode 100644\nindex 1234567..0000000",
        );
        let recovered = recover(&deleted, &format!("url={ADDRESS}\n")).unwrap();
        recovered
            .verify_application(|_, limit| {
                assert_eq!(limit, 0);
                Ok(None)
            })
            .unwrap();
        assert!(
            recovered
                .verify_application(|_, _| Ok(Some(Vec::new())))
                .is_err()
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

    #[test]
    fn refuses_duplicate_sections_before_reading_preimages() {
        let edited = "diff --git a/config b/config\nindex 1234567..abcdef0 100644\n\
                      --- a/config\n+++ b/config\n\
                      @@ -1 +1 @@\n-url=<inference-address>\n+new\n";
        let added = "diff --git a/config b/config\nnew file mode 100644\n\
                     index 0000000..abcdef0\n--- /dev/null\n+++ b/config\n\
                     @@ -0,0 +1 @@\n+new\n";
        let removed = "diff --git a/config b/config\ndeleted file mode 100644\n\
                       index 1234567..0000000\n--- a/config\n+++ /dev/null\n\
                       @@ -1 +0,0 @@\n-url=<inference-address>\n";
        let original = mail("@@ -1 +1 @@\n-url=<inference-address>\n+new\n");
        let prefix = original.split_once("diff --git ").unwrap().0;
        for sections in [
            edited.repeat(2),
            edited.repeat(MAX_FILES + 1),
            added.repeat(2),
            format!("{removed}{added}"),
        ] {
            let patch = format!("{prefix}{sections}");
            // The general parser intentionally returns a distinct path set.
            // Recovery must not confuse that set's size with its read count.
            let reading = read_patch(&patch, &rules(), BASE);
            assert!(reading.problems.is_empty(), "{:?}", reading.problems);
            assert_eq!(reading.files, ["config"]);
            let err = reconstruct(&patch, &rules(), BASE, MAX_BYTES, |_, _| {
                panic!("duplicate sections must be rejected before preimage reads")
            })
            .err()
            .unwrap();
            assert_eq!(err.to_string(), "recovery repeats a file section");
        }
    }

    #[test]
    fn reads_each_distinct_file_once_within_the_file_limit() {
        let original = mail("@@ -1 +1 @@\n-url=<inference-address>\n+new\n");
        let (prefix, section) = original.split_once("diff --git ").unwrap();
        let section = format!("diff --git {section}");
        let mut rules = rules();
        rules.max_patch_files = (MAX_FILES + 1) as u32;
        for count in [2, MAX_FILES, MAX_FILES + 1] {
            let paths: Vec<_> = (0..count).map(|i| format!("config{i}")).collect();
            let mut patch = prefix.to_owned();
            for path in &paths {
                patch.push_str(&section.replace("config", path));
            }
            let mut reads = Vec::new();
            let result = reconstruct(&patch, &rules, BASE, MAX_BYTES, |path, limit| {
                assert_eq!(limit, MAX_BYTES);
                reads.push(path.to_owned());
                Ok(format!("url={ADDRESS}\n").into_bytes())
            });
            if count <= MAX_FILES {
                assert_eq!(result.unwrap().restored_lines, count);
                assert_eq!(reads, paths);
            } else {
                assert_eq!(
                    result.err().unwrap().to_string(),
                    "recovery exceeds file limit"
                );
                assert!(reads.is_empty());
            }
        }
    }
}
