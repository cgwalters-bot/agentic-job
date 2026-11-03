//! Exact base-file lines that may disclose an inference endpoint in a patch.
//!
//! Capture before starting the agent: consulting its git database afterwards
//! would let it manufacture a public base. This is not a credential exception.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use safe_outputs::contract::PatchRules;

use super::{clone::Checkout, enter::Runner};

/// A conservative bound for both the base evidence and any eligible patch.
const MAX_BYTES: usize = 1 << 20;
const MAX_FILES: u32 = 50;

#[derive(Clone, Default)]
pub struct PublicAddresses {
    patches: BTreeMap<String, Base>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: &str = "inference.example.test:8443";
    const NAME: &str = "aw-agent-run-1.patch";
    const COMMIT: &str = "1111111111111111111111111111111111111111";

    fn public() -> PublicAddresses {
        PublicAddresses {
            patches: BTreeMap::from([(
                NAME.to_owned(),
                Base {
                    commit: COMMIT.to_owned(),
                    lines: BTreeMap::from([(("config".to_owned(), ADDRESS.to_owned()), 1)]),
                    addresses: vec![ADDRESS.to_owned()],
                },
            )]),
        }
    }

    fn patch(body: &str) -> String {
        format!(
            "From {} Mon Sep 17 00:00:00 2001\nX-GH-AW-Base-Commit: {COMMIT}\nFrom: Test <test@example.test>\nDate: Tue, 3 Nov 2026 00:00:00 +0000\nSubject: [PATCH] Test\n\n---\ndiff --git a/config b/config\nindex 1234567..abcdef0 100644\n--- a/config\n+++ b/config\n{body}",
            "2".repeat(40)
        )
    }

    #[test]
    fn only_authenticated_hunk_lines_are_allowed() {
        let moved = patch(&format!(
            "@@ -1,2 +1,2 @@\n-{ADDRESS}\n after\n+{ADDRESS}\n"
        ));
        let public = public();
        let allowed = public.allowed_lines(NAME, &moved);
        assert_eq!(allowed.len(), 2);
        for line in allowed {
            assert!(moved.split('\n').nth(line - 1).unwrap().ends_with(ADDRESS));
        }
        for (case, name, text) in [
            ("other patch", "other.patch", moved.clone()),
            ("wrong base", NAME, moved.replace(COMMIT, &"3".repeat(40))),
            (
                "malformed hunk",
                NAME,
                moved.replace("@@ -1,2 +1,2 @@", "@@ -1,3 +1,2 @@"),
            ),
            ("different file", NAME, moved.replace("config", "other")),
            (
                "over size bound",
                NAME,
                format!("{moved}{}", "x".repeat(MAX_BYTES)),
            ),
        ] {
            assert!(public.allowed_lines(name, &text).is_empty(), "{case}");
        }
        // A forged duplicate removal cannot buy additional moves.
        let duplicates = patch(&format!(
            "@@ -1,2 +1,2 @@\n-{ADDRESS}\n-{ADDRESS}\n+{ADDRESS}\n+{ADDRESS}\n"
        ));
        assert!(public.allowed_lines(NAME, &duplicates).is_empty());
        // A signature is not a hunk, including a CRLF signature delimiter.
        for delimiter in ["-- ", "-- \r"] {
            let signature = patch(&format!(
                "@@ -1 +1 @@\n-old\n+new\n{delimiter}\n+{ADDRESS}\n"
            ));
            assert!(public.allowed_lines(NAME, &signature).is_empty());
        }
        // But a removed source line `- ` reads like one within its hunk.
        let removed = patch(&format!("@@ -1,3 +1,2 @@\n-- \n {ADDRESS}\n after\n"));
        assert_eq!(public.allowed_lines(NAME, &removed).len(), 1);
        // And an empty line is context that lost its space, not the hunk's end.
        let blank = patch(&format!("@@ -1,3 +1,2 @@\n-x\n\n {ADDRESS}\n"));
        assert_eq!(public.allowed_lines(NAME, &blank).len(), 1);
    }

    #[test]
    fn eligible_patches_have_at_most_max_files() {
        let public = public();
        for (others, allowed) in [(MAX_FILES - 1, 1), (MAX_FILES, 0)] {
            let mut text = patch(&format!("@@ -1 +1 @@\n {ADDRESS}\n"));
            for file in 0..others {
                text.push_str(&format!(
                    "diff --git a/f{file} b/f{file}\nindex 1234567..abcdef0 100644\n\
                     --- a/f{file}\n+++ b/f{file}\n@@ -1 +1 @@\n-old\n+new\n"
                ));
            }
            assert_eq!(public.allowed_lines(NAME, &text).len(), allowed, "{others}");
        }
    }

    /// Answers every command with SCRIPT's output and status.
    struct Scripted(String);

    impl Runner for Scripted {
        fn run(&self, _: &[&str], input: &[u8], max: usize) -> Result<super::super::enter::Output> {
            super::super::enter::Unconfined.run(&["sh", "-c", &self.0], input, max)
        }
    }

    #[test]
    fn capture_fails_closed_beyond_its_bounds() {
        let checkout = Checkout {
            dir: "/nonexistent".into(),
            base_commit: COMMIT.to_owned(),
            secondary: None,
        };
        let record = format!("{COMMIT}:config");
        // One record of exactly MAX_BYTES with its NUL and newline.
        let fill = MAX_BYTES - record.len() - 2;
        for (case, script, ok) in [
            ("no match", "exit 1".to_owned(), true),
            (
                "at bound",
                format!("printf '%s\\000' {record}; head -c {fill} /dev/zero | tr '\\0' x; echo"),
                true,
            ),
            (
                "over bound",
                format!(
                    "printf '%s\\000' {record}; head -c {} /dev/zero | tr '\\0' x; echo",
                    fill + 1
                ),
                false,
            ),
            ("git failed", "exit 2".to_owned(), false),
            ("timed out", "exit 124".to_owned(), false),
            (
                "wrong base",
                format!("printf '%s:config\\000x\\n' {}", "3".repeat(40)),
                false,
            ),
        ] {
            let result = PublicAddresses::capture(
                &Scripted(script),
                &checkout,
                &[NAME.to_owned()],
                &[ADDRESS.to_owned()],
            );
            assert_eq!(result.is_ok(), ok, "{case}");
        }
    }

    /// Evidence from one tree's base never covers the other tree's patch.
    #[test]
    fn primary_and_secondary_evidence_stay_apart() {
        let dir = tempfile::tempdir().unwrap();
        let commit = |name: &str, file: &str| {
            let repo = dir.path().join(name);
            std::fs::create_dir(&repo).unwrap();
            std::fs::write(repo.join(file), format!("{ADDRESS}\nafter\n")).unwrap();
            let git = |args: &[&str]| {
                let output = std::process::Command::new("git")
                    .current_dir(&repo)
                    .env("GIT_AUTHOR_NAME", "Test")
                    .env("GIT_AUTHOR_EMAIL", "test@example.test")
                    .env("GIT_COMMITTER_NAME", "Test")
                    .env("GIT_COMMITTER_EMAIL", "test@example.test")
                    .args(args)
                    .output()
                    .unwrap();
                assert!(output.status.success(), "{:?}", output.stderr);
                String::from_utf8(output.stdout).unwrap()
            };
            git(&["init", "-q"]);
            git(&["add", file]);
            git(&["-c", "core.hooksPath=/dev/null", "commit", "-qm", "Base"]);
            Checkout {
                base_commit: git(&["rev-parse", "HEAD"]).trim().to_owned(),
                dir: repo,
                secondary: None,
            }
        };
        // The address is in `config` of the primary, `other` of the secondary.
        let checkout = Checkout {
            secondary: Some(Box::new(commit("secondary", "other"))),
            ..commit("primary", "config")
        };
        let names = ["primary.patch".to_owned(), "secondary.patch".to_owned()];
        let public = PublicAddresses::capture(
            &super::super::enter::Unconfined,
            &checkout,
            &names,
            &[ADDRESS.to_owned()],
        )
        .unwrap();
        let moved = patch(&format!(
            "@@ -1,2 +1,2 @@\n-{ADDRESS}\n after\n+{ADDRESS}\n"
        ));
        let primary = moved.replace(COMMIT, &checkout.base_commit);
        let secondary = moved.replace(COMMIT, &checkout.secondary.as_ref().unwrap().base_commit);
        for (name, text, allowed) in [
            (&names[0], &primary, 2),
            (&names[0], &secondary, 0),
            (&names[1], &primary, 0),
            (&names[1], &secondary, 0),
            (&names[1], &secondary.replace("config", "other"), 2),
        ] {
            assert_eq!(public.allowed_lines(name, text).len(), allowed, "{name}");
        }
    }
}

#[derive(Clone)]
struct Base {
    commit: String,
    lines: BTreeMap<(String, String), usize>,
    addresses: Vec<String>,
}

impl PublicAddresses {
    /// No endpoint means no exception. Failure to obtain bounded evidence
    /// fails closed, before the agent spends a run on the task.
    pub fn capture(
        runner: &dyn Runner,
        checkout: &Checkout,
        patches: &[String],
        addresses: &[String],
    ) -> Result<Self> {
        let mut public = Self::default();
        if addresses.is_empty() {
            return Ok(public);
        }
        for (tree, patch) in std::iter::once(checkout)
            .chain(checkout.secondary.as_deref())
            .zip(patches)
        {
            let mut argv = vec![
                "timeout",
                "30",
                "git",
                "-c",
                "grep.lineNumber=false",
                "-c",
                "grep.column=false",
                "-C",
                tree.dir.to_str().context("checkout path is not UTF-8")?,
                "grep",
                "--no-textconv",
                "--no-recurse-submodules",
                "--full-name",
                "--null",
                "--text",
                "--fixed-strings",
            ];
            for address in addresses {
                argv.extend(["-e", address]);
            }
            argv.extend([tree.base_commit.as_str(), "--"]);
            let output = runner.run(&argv, b"", MAX_BYTES + 1)?;
            ensure!(
                output.success() || output.status.code() == Some(1),
                "reading public inference address lines failed"
            );
            ensure!(
                output.stdout.len() <= MAX_BYTES,
                "public inference address evidence exceeds {MAX_BYTES} bytes"
            );
            let text = std::str::from_utf8(&output.stdout)
                .context("public inference address evidence is not UTF-8")?;
            let mut lines = BTreeMap::new();
            let prefix = format!("{}:", tree.base_commit);
            for record in text.split_terminator('\n') {
                let (path, line) = record
                    .split_once('\0')
                    .context("invalid public address evidence")?;
                let path = path
                    .strip_prefix(&prefix)
                    .context("public address evidence has wrong base")?;
                ensure!(!line.contains('\0'), "public address evidence contains NUL");
                *lines.entry((path.to_owned(), line.to_owned())).or_default() += 1;
            }
            let addresses = addresses
                .iter()
                .filter(|address| {
                    lines
                        .keys()
                        .any(|(_, line)| line.contains(address.as_str()))
                })
                .cloned()
                .collect();
            public.patches.insert(
                patch.clone(),
                Base {
                    commit: tree.base_commit.clone(),
                    lines,
                    addresses,
                },
            );
        }
        Ok(public)
    }

    /// Only structurally validated patch hunks qualify, never mail headers,
    /// messages, filenames, JSON requests or replacement commit series.
    pub fn allowed_lines(&self, name: &str, patch: &str) -> BTreeSet<usize> {
        let Some(base) = self.patches.get(name) else {
            return BTreeSet::new();
        };
        if patch.len() > MAX_BYTES {
            return BTreeSet::new();
        }
        let rules = PatchRules {
            protected_files: &[],
            protect_top_level_dot_folders: false,
            unprotected_dot_folders: &[".github".to_owned()],
            protected_paths: &[],
            max_patch_files: MAX_FILES,
            commit_author: None,
        };
        if !safe_outputs::check::read_patch(patch, &rules, &base.commit)
            .problems
            .is_empty()
        {
            return BTreeSet::new();
        }
        let mut path = "";
        // The old and new lines the current hunk has yet to consume: a
        // removed source line may read like the signature delimiter `-- `,
        // and what follows the last hunk is never one of its lines.
        let (mut old_left, mut new_left) = (0usize, 0usize);
        let mut occurrences: BTreeMap<(String, String), Vec<(usize, u8)>> = BTreeMap::new();
        for (index, line) in patch.split_terminator('\n').enumerate() {
            let structural = line.trim_end_matches('\r');
            if old_left > 0 || new_left > 0 {
                let kind = line.as_bytes().first().copied();
                // An empty line is a context line that lost its space, as
                // `read_patch` reads it.
                let (old_used, new_used) = match kind {
                    Some(b'\\') => (0, 0),
                    Some(b' ') | None => (1, 1),
                    Some(b'-') => (1, 0),
                    Some(b'+') => (0, 1),
                    Some(_) => (old_left, new_left),
                };
                old_left = old_left.saturating_sub(old_used);
                new_left = new_left.saturating_sub(new_used);
                let Some(kind @ (b' ' | b'-' | b'+')) = kind else {
                    continue;
                };
                let key = (path.to_owned(), line[1..].to_owned());
                if base.lines.contains_key(&key) {
                    occurrences.entry(key).or_default().push((index + 1, kind));
                }
            } else if let Some(header) = structural.strip_prefix("diff --git a/") {
                path = header.split_once(" b/").map_or("", |(path, _)| path);
            } else if let Some(counts) = hunk_counts(structural) {
                (old_left, new_left) = counts;
            }
        }
        let mut allowed = BTreeSet::new();
        for (key, lines) in occurrences {
            let old = lines.iter().filter(|(_, kind)| *kind != b'+').count();
            let added = lines.iter().filter(|(_, kind)| *kind == b'+').count();
            let removed = lines.iter().filter(|(_, kind)| *kind == b'-').count();
            // A move consumes a removal in this same file. Merely finding
            // the address somewhere in the base must not allow extra copies.
            let moves = old <= base.lines[&key] && added <= removed;
            allowed.extend(lines.into_iter().filter_map(|(line, kind)| {
                (old <= base.lines[&key] && (kind != b'+' || moves)).then_some(line)
            }));
        }
        allowed
    }

    pub fn contains_address_on(&self, line: &str) -> bool {
        self.patches
            .values()
            .any(|base| base.addresses.iter().any(|address| line.contains(address)))
    }
}

/// The old and new line counts of the hunk header `@@ -a[,b] +c[,d] @@`.
fn hunk_counts(header: &str) -> Option<(usize, usize)> {
    let ranges = header.strip_prefix("@@ -")?.split_once(" @@")?.0;
    let (old, new) = ranges.split_once(" +")?;
    let count = |range: &str| match range.split_once(',') {
        Some((_, count)) => count.parse().ok(),
        None => Some(1),
    };
    Some((count(old)?, count(new)?))
}
