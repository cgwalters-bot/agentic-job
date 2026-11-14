//! Old-side endpoint replay. Authority comes from trusted configuration, not
//! patch metadata. Recovered bytes stay in memory and never enter an artifact.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use anyhow::{Result, ensure};
use regex::Regex;
use serde::{Deserialize, Serialize};

pub const PLACEHOLDER: &str = "<inference-address>";
pub const MAX_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Literal {
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Provenance {
    pub literals: Vec<Literal>,
}

impl Literal {
    pub fn new(value: &str) -> Result<Self> {
        ensure!(
            (8..=512).contains(&value.len()),
            "replay endpoint length outside bounds"
        );
        ensure!(
            !value.contains(['\n', '\r', '\0']),
            "invalid replay endpoint"
        );
        Ok(Self {
            bytes: value.len(),
            sha256: digest(value.as_bytes()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub patch_sha256: String,
    pub base_commit: String,
    pub literals: Vec<Literal>,
    pub tree: String,
}

pub fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn validate_literals(literals: &[Literal]) -> Result<()> {
    ensure!(literals.len() <= 8, "too many replay endpoints");
    for literal in literals {
        ensure!(
            (8..=512).contains(&literal.bytes) && hex(&literal.sha256, 64),
            "invalid replay endpoint provenance"
        );
    }
    Ok(())
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Redact only substrings authenticated by the trusted endpoint digests. No
/// wildcard placeholder matching: the complete surrounding line must match.
fn redact(line: &str, literals: &[Literal]) -> String {
    let mut out = Vec::new();
    let mut at = 0;
    let bytes = line.as_bytes();
    while at < bytes.len() {
        let found = literals
            .iter()
            .filter(|literal| {
                bytes
                    .get(at..at + literal.bytes)
                    .is_some_and(|part| digest(part) == literal.sha256)
            })
            .max_by_key(|literal| literal.bytes);
        if let Some(literal) = found {
            out.extend_from_slice(PLACEHOLDER.as_bytes());
            at += literal.bytes;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).expect("replacement preserves UTF-8")
}

/// Call only after the normal patch parser and path/bounds checks. Every old
/// line, not only a replacement, is matched at its exact declared coordinate.
/// The callback reads blobs from the independently fetched, verified base.
pub fn recover(
    patch: &str,
    base_commit: &str,
    literals: &[Literal],
    mut blob: impl FnMut(&str) -> Result<String>,
) -> Result<String> {
    validate_literals(literals)?;
    ensure!(
        patch.len() <= MAX_BYTES && hex(base_commit, 40),
        "replay patch/base outside bounds"
    );
    ensure!(
        patch
            .lines()
            .filter(|line| *line == format!("X-GH-AW-Base-Commit: {base_commit}"))
            .count()
            == 1,
        "replay base differs from checked base"
    );
    static HUNK: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@")
            .expect("valid hunk pattern")
    });
    let mut files: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut path = String::new();
    let mut total = 0;
    let (mut old, mut old_left, mut new_left) = (0usize, 0usize, 0usize);
    let (mut old_end, mut delta) = (0usize, 0isize);
    let mut result = String::new();
    for line in patch.split_inclusive('\n') {
        let text = line.strip_suffix('\n').unwrap_or(line);
        if old_left > 0 || new_left > 0 {
            let kind = text.as_bytes().first().copied();
            if kind == Some(b'\\') {
                // No-newline markers need byte-level EOF handling. Refuse rather
                // than infer different semantics for a replay-eligible patch.
                anyhow::bail!(
                    "replay does not support no-newline markers; regenerate with final newlines"
                );
            }
            let consumes_old = kind != Some(b'+');
            let consumes_new = kind != Some(b'-');
            ensure!(
                !consumes_old || old_left > 0,
                "replay old hunk count mismatch"
            );
            ensure!(
                !consumes_new || new_left > 0,
                "replay new hunk count mismatch"
            );
            if consumes_old {
                ensure!(
                    matches!(kind, Some(b' ' | b'-') | None),
                    "invalid replay hunk line"
                );
                if !files.contains_key(&path) {
                    let content = blob(&path)?;
                    total += content.len();
                    ensure!(
                        total <= MAX_BYTES && files.len() < 50,
                        "replay base blobs exceed bounds"
                    );
                    ensure!(
                        content.ends_with('\n') && !content.contains('\0'),
                        "replay requires bounded text with final newlines"
                    );
                    files.insert(
                        path.clone(),
                        content.split_inclusive('\n').map(str::to_owned).collect(),
                    );
                }
                let original = files[&path]
                    .get(old)
                    .ok_or_else(|| anyhow::anyhow!("replay old coordinate outside base blob"))?;
                let supplied = if text.is_empty() { "\n" } else { &line[1..] };
                ensure!(
                    supplied == original
                        || (supplied.contains(PLACEHOLDER)
                            && redact(original, literals) == supplied),
                    "replay old line mismatch: regenerate patch against declared base and trusted endpoint configuration"
                );
                result.push(if kind == Some(b'-') { '-' } else { ' ' });
                result.push_str(original);
                old += 1;
                old_left -= 1;
            } else {
                // Added values are never recovered.
                result.push_str(line);
            }
            if consumes_new {
                new_left -= 1;
            }
        } else if let Some(header) = text.strip_prefix("diff --git a/") {
            let (a, b) = header
                .split_once(" b/")
                .ok_or_else(|| anyhow::anyhow!("invalid replay path header"))?;
            ensure!(
                a == b
                    && !a.is_empty()
                    && !a.starts_with('/')
                    && a.split('/').all(|part| !part.is_empty()
                        && part != "."
                        && part != ".."
                        && !part.starts_with('-'))
                    && a.bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"/_.+@=,-".contains(&byte)),
                "unsupported replay path"
            );
            ensure!(!files.contains_key(a), "duplicate replay path");
            path = a.to_owned();
            old_end = 0;
            delta = 0;
            result.push_str(line);
        } else if let Some(hunk) = HUNK.captures(text) {
            let number =
                |i| -> Result<usize> { Ok(hunk.get(i).map_or("1", |m| m.as_str()).parse()?) };
            let (start, count, new_start, new_count) =
                (number(1)?, number(2)?, number(3)?, number(4)?);
            ensure!(
                start <= MAX_BYTES
                    && new_start <= MAX_BYTES
                    && count <= MAX_BYTES
                    && new_count <= MAX_BYTES
                    && !path.is_empty(),
                "replay coordinates outside bounds"
            );
            old = if count == 0 {
                start
            } else {
                start
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("invalid replay old coordinate"))?
            };
            let new = if new_count == 0 {
                new_start
            } else {
                new_start
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("invalid replay new coordinate"))?
            };
            ensure!(
                old >= old_end && new as isize == old as isize + delta,
                "overlapping or inconsistent replay coordinates"
            );
            old_end = old + count;
            delta += new_count as isize - count as isize;
            (old_left, new_left) = (count, new_count);
            result.push_str(line);
        } else {
            ensure!(
                !text.starts_with("\\ No newline"),
                "replay does not support no-newline markers"
            );
            result.push_str(line);
        }
        ensure!(
            result.len() <= MAX_BYTES,
            "recovered replay patch exceeds bound"
        );
    }
    ensure!(old_left == 0 && new_left == 0, "incomplete replay hunk");
    Ok(result)
}
