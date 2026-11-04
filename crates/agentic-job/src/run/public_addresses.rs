//! Exact base-file lines that may disclose already-public bytes in a patch.
//!
//! Capture before starting the agent: consulting its git database afterwards
//! would let it manufacture a public base. Known run credentials are never exempt.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use regex::Regex;
use safe_outputs::contract::PatchRules;
use serde::{Deserialize, Serialize};

use super::{clone::Checkout, enter::Runner};

/// A conservative bound for both the base evidence and any eligible patch.
const MAX_BYTES: usize = 1 << 20;
const MAX_FILES: u32 = 50;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAddresses {
    patches: BTreeMap<String, Base>,
    #[serde(default)]
    secrets: BTreeMap<String, Base>,
    #[serde(default)]
    key_blocks: BTreeSet<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: &str = "inference.example.test:8443";
    const NAME: &str = "aw-agent-run-1.patch";
    const COMMIT: &str = "1111111111111111111111111111111111111111";

    fn public() -> PublicAddresses {
        PublicAddresses {
            secrets: BTreeMap::new(),
            key_blocks: BTreeSet::new(),
            patches: BTreeMap::from([(
                NAME.to_owned(),
                Base {
                    commit: COMMIT.to_owned(),
                    lines: BTreeMap::from([(
                        "config".to_owned(),
                        BTreeMap::from([(line_hash(ADDRESS), 1)]),
                    )]),
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

    #[test]
    fn pem_blocks_require_ordered_matching_markers() {
        let begin = ["-----BEGIN ", "RSA PRIVATE KEY", "-----"].concat();
        let end = "-----END RSA PRIVATE KEY-----";
        let other = "-----END EC PRIVATE KEY-----";
        for (text, count) in [
            (format!("{begin}\nbody\n{end}\n"), 1),
            (format!("const key = '{begin}body{end}';\n"), 1),
            (
                format!("const end = '{end}'; const key = `{begin}\n`;\n"),
                0,
            ),
            (format!("{begin}\nbody\n{other}\n"), 0),
            (format!("{begin}\nbody\n-----END CERTIFICATE-----\n"), 0),
            (format!("{begin}\nbody\n"), 0),
            (format!("{begin}{begin}body{end}\n"), 0),
        ] {
            assert_eq!(pem_blocks(&text).len(), count);
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
            let result = PublicAddresses::capture_patterns(
                &Scripted(script),
                &checkout,
                &[NAME.to_owned()],
                &[ADDRESS.to_owned()],
                true,
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
        let public = PublicAddresses::capture_patterns(
            &super::super::enter::Unconfined,
            &checkout,
            &names,
            &[ADDRESS.to_owned()],
            true,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Base {
    commit: String,
    lines: BTreeMap<String, BTreeMap<String, usize>>,
    addresses: Vec<String>,
}

impl PublicAddresses {
    pub fn capture_secrets(
        &mut self,
        runner: &dyn Runner,
        checkout: &Checkout,
        patches: &[String],
    ) -> Result<()> {
        // Capture only candidate header lines, never private key bodies. The
        // serialized evidence contains line digests, not credential values.
        let mut evidence = Self::capture_patterns(
            runner,
            checkout,
            patches,
            &["-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----".to_owned()],
            false,
        )?;
        for base in evidence.patches.values_mut() {
            base.addresses.clear();
        }
        let mut bytes = 0;
        for (tree, patch) in std::iter::once(checkout)
            .chain(checkout.secondary.as_deref())
            .zip(patches)
        {
            if let Some(base) = evidence.patches.get(patch) {
                for path in base.lines.keys() {
                    let object = format!("{}:{path}", tree.base_commit);
                    let output = runner.run(
                        &[
                            "timeout",
                            "30",
                            "git",
                            "-C",
                            tree.dir.to_str().context("checkout path is not UTF-8")?,
                            "show",
                            "--no-textconv",
                            &object,
                        ],
                        b"",
                        MAX_BYTES + 1,
                    )?;
                    ensure!(output.success(), "reading public key block evidence failed");
                    bytes += output.stdout.len();
                    ensure!(
                        bytes <= MAX_BYTES,
                        "public key block evidence exceeds {MAX_BYTES} bytes"
                    );
                    let text = std::str::from_utf8(&output.stdout)
                        .context("public key block evidence is not UTF-8")?;
                    for block in pem_blocks(text).into_values() {
                        self.key_blocks.insert(block_hash(patch, path, &block));
                    }
                }
            }
        }
        self.secrets = evidence.patches;
        Ok(())
    }

    pub fn allowed_secret_lines(&self, name: &str, patch: &str) -> BTreeSet<usize> {
        let mut allowed = Self {
            patches: self.secrets.clone(),
            ..Self::default()
        }
        .allowed_lines(name, patch);
        if allowed.is_empty() {
            return allowed;
        }
        let patch_lines: Vec<_> = patch.split_terminator('\n').collect();
        // An actual PEM header alone is not evidence for its body. Reassemble
        // old/new hunk sides and require the entire block byte for byte. An
        // incomplete block in limited diff context gets no exception.
        for side in *b"-+" {
            let mut projected = String::new();
            let mut indices = Vec::new();
            let mut paths = Vec::new();
            let mut path = "";
            for (index, line) in patch_lines.iter().enumerate() {
                if let Some(header) = line.strip_prefix("diff --git a/") {
                    path = header.split_once(" b/").map_or("", |(path, _)| path);
                }
                match line.as_bytes().first() {
                    Some(kind) if *kind == side || *kind == b' ' => {
                        projected.push_str(&line[1..]);
                        projected.push('\n');
                        indices.push(index + 1);
                        paths.push(path);
                    }
                    Some(b'+' | b'-' | b'\\') => {}
                    _ => {
                        projected.push('\n');
                        indices.push(0);
                        paths.push(path);
                    }
                }
            }
            let lines: Vec<_> = projected.split_terminator('\n').collect();
            let blocks = pem_blocks(&projected);
            for (index, line) in lines.iter().enumerate() {
                if crate::redact::is_private_key(line.as_bytes()) {
                    // Removed bodies disclose bytes too. The producer's patch
                    // can invent old lines, so headers alone never suffice,
                    // even for deletions of an incomplete public fixture.
                    let block = blocks.get(&index);
                    if block.is_some_and(|block| {
                        !self
                            .key_blocks
                            .contains(&block_hash(name, paths[index], block))
                    }) || block.is_none()
                    {
                        allowed.remove(&indices[index]);
                    }
                }
            }
        }
        allowed
    }

    /// No pattern means no exception. Failure to obtain bounded evidence
    /// fails closed, before the agent spends a run on the task.
    fn capture_patterns(
        runner: &dyn Runner,
        checkout: &Checkout,
        patches: &[String],
        addresses: &[String],
        fixed: bool,
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
                if fixed {
                    "--fixed-strings"
                } else {
                    "--extended-regexp"
                },
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
            let mut lines: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
            let mut found_addresses = BTreeSet::new();
            let prefix = format!("{}:", tree.base_commit);
            for record in text.split_terminator('\n') {
                let (path, line) = record
                    .split_once('\0')
                    .context("invalid public address evidence")?;
                let path = path
                    .strip_prefix(&prefix)
                    .context("public address evidence has wrong base")?;
                ensure!(!line.contains('\0'), "public address evidence contains NUL");
                *lines
                    .entry(path.to_owned())
                    .or_default()
                    .entry(line_hash(line))
                    .or_default() += 1;
                ensure!(
                    lines.len() <= MAX_FILES as usize,
                    "public base evidence exceeds {MAX_FILES} files"
                );
                found_addresses.extend(
                    addresses
                        .iter()
                        .filter(|address| line.contains(address.as_str()))
                        .cloned(),
                );
            }
            let addresses = addresses
                .iter()
                .filter(|address| found_addresses.contains(*address))
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
                let key = (path.to_owned(), line_hash(&line[1..]));
                if base
                    .lines
                    .get(path)
                    .is_some_and(|lines| lines.contains_key(&key.1))
                {
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
            let count = base.lines[&key.0][&key.1];
            let moves = old <= count && added <= removed;
            allowed.extend(lines.into_iter().filter_map(|(line, kind)| {
                (old <= count && (kind != b'+' || moves)).then_some(line)
            }));
        }
        allowed
    }
}

fn line_hash(line: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, line.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn block_hash(patch: &str, path: &str, block: &str) -> String {
    line_hash(&format!("{patch}\0{path}\0{block}"))
}

fn pem_blocks(text: &str) -> BTreeMap<usize, String> {
    static MARKER: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"-----(BEGIN|END) ([A-Z0-9 ]{0,32}PRIVATE KEY)-----")
            .expect("the built-in PEM marker pattern is valid")
    });
    let lines: Vec<_> = text.split_terminator('\n').collect();
    let mut blocks = BTreeMap::new();
    let mut start = None;
    for (index, line) in lines.iter().enumerate() {
        // An allowance is per line, so two headers on one line cannot be
        // authenticated independently. Refuse that ambiguous case entirely.
        if MARKER
            .captures_iter(line)
            .filter(|marker| &marker[1] == "BEGIN")
            .count()
            > 1
        {
            start = None;
            continue;
        }
        // Process markers in byte order, including on quoted single-line
        // fixtures: a footer before a header cannot complete that header.
        for marker in MARKER.captures_iter(line) {
            if &marker[1] == "BEGIN" {
                start = Some((index, marker[2].to_owned()));
            } else if let Some((first, label)) = start.take()
                && label == marker[2]
            {
                blocks.insert(first, lines[first..=index].join("\n"));
            }
        }
    }
    blocks
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
