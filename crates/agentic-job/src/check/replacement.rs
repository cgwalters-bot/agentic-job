//! A replacement is data, not a bundle or a repository configuration.
//! Check each mail separately so a reverted forbidden edit cannot hide in
//! the final tree. Apply constructs a linear series from these checked mails.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::{BASE_COMMIT_HEADER, PatchInfo, read_patch};
use crate::policy::Push;

pub const REPLACEMENT_FILE: &str = "replacement.json";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Replacement {
    pub base_commit: String,
    /// One plain `git format-patch --stdout --no-signature -1` mail per commit.
    pub commits: Vec<String>,
}

pub fn check(content: &[u8], push: &Push, max_bytes: u64) -> Result<PatchInfo> {
    ensure!(
        push.replacement_max_commits > 0,
        "branch replacement is not allowed by bounds"
    );
    ensure!(
        content.len() as u64 <= max_bytes,
        "replacement exceeds the patch byte limit"
    );
    let series: Replacement = serde_json::from_slice(content)?;
    ensure!(
        push.replacement_base.is_some()
            && series.base_commit.len() == 40
            && series
                .base_commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "replacement requires a resolved policy base and a full commit id"
    );
    // Apply binds this claim to the policy snapshot or the base branch head
    // it resolves itself. Check has no forge access and grants no write.
    ensure!(
        !series.commits.is_empty() && series.commits.len() <= push.replacement_max_commits as usize,
        "replacement commit count is outside bounds"
    );
    let mut all_files = BTreeSet::new();
    let mut commit_files = Vec::new();
    for mail in &series.commits {
        let headers: Vec<_> = mail
            .split('\n')
            .take_while(|line| !line.is_empty())
            .collect();
        let dates: Vec<_> = headers
            .iter()
            .enumerate()
            .filter_map(|(index, line)| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("date"))
                    .map(|(_, date)| (index, date.trim()))
            })
            .collect();
        ensure!(
            dates.len() == 1
                && chrono::DateTime::parse_from_rfc2822(dates[0].1).is_ok()
                && headers
                    .get(dates[0].0 + 1)
                    .is_none_or(|line| !line.starts_with([' ', '\t'])),
            "replacement mail requires one valid Date header for deterministic reruns"
        );
        // The protocol supplies the base separately. Inserting our header
        // leaves duplicate headers and extra mails to the existing strict reader.
        let (first, rest) = mail
            .split_once('\n')
            .ok_or_else(|| anyhow::anyhow!("replacement mail has no header"))?;
        let patch = format!(
            "{first}\n{BASE_COMMIT_HEADER}: {}\n{rest}",
            series.base_commit
        );
        let reading = read_patch(&patch, &push.rules(), &series.base_commit);
        ensure!(
            reading.problems.is_empty(),
            "replacement mail: {}",
            reading.problems.join("; ")
        );
        all_files.extend(reading.files.iter().cloned());
        commit_files.push(reading.files);
    }
    ensure!(
        all_files.len() <= push.max_patch_files as usize,
        "replacement exceeds the total file limit"
    );
    Ok(PatchInfo {
        file: REPLACEMENT_FILE.into(),
        bytes: content.len(),
        base_commit: series.base_commit,
        files: all_files.into_iter().collect(),
        commit_files: Some(commit_files),
    })
}
