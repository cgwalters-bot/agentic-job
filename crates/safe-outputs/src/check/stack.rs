//! Experimental, read-only validation of an ordered stack proposal.
//!
//! A later publisher must construct each commit on its predecessor, compare
//! actual changed paths, bind the checked bytes to trusted artifacts and apply
//! the ordinary publication gates. This is not a publishable receipt and is not
//! accepted by the CLI or workflows. Secret scanning belongs to the caller, as
//! for the ordinary library checker; `inspect` must check each step's entire
//! content before it can enter the accepted prefix.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::replacement::read_mail;
use crate::contract::{COMMIT_RE, PatchRules};

/// Hard ceilings, independent of the trusted caller's opt-in count.
pub const MAX_STEPS: u32 = 10;
pub const MAX_BYTES: usize = 1024 * 1024;
const MAX_TITLE_BYTES: usize = 128;
const MAX_BODY_BYTES: usize = 48_000;
const MAX_ISSUE: u64 = 2_147_483_647;

/// Repository and branch are deliberately absent: those are caller-owned.
/// Step order, not producer-selected branches, defines the future parent chain.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub base_commit: String,
    // Decode each step only when reached, preserving a valid prefix when a
    // later step has an invalid schema. Invalid JSON still refuses everything.
    pub steps: Vec<Box<RawValue>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub issue: u64,
    pub title: String,
    /// Prose; a future publisher adds the issue's closing line.
    pub body: String,
    /// One plain `git format-patch --stdout --no-signature -1` mail, without
    /// the protocol's base header. Each mail contains only this step's diff.
    pub patch: String,
}

#[derive(Debug)]
pub struct CheckedStep {
    pub step: Step,
    pub files: Vec<String>,
}

#[derive(Debug)]
pub struct Refusal {
    /// One-based position. No step at or above this position was accepted.
    pub position: usize,
    pub reason: String,
}

#[derive(Debug)]
pub struct CheckedStack {
    pub accepted: Vec<CheckedStep>,
    pub refused: Option<Refusal>,
}

/// Check an ordered proposal, retaining only the prefix before the first refusal.
///
/// The concrete threats are unbounded fan-out and hiding a forbidden edit with
/// a later revert. `max_steps` is a trusted opt-in (zero disables stacks); patch
/// rules and byte limits apply independently to every step, never the final
/// aggregate diff. The whole envelope is capped before JSON decoding. Invalid
/// envelopes return an error, with no accepted prefix. `inspect` is read-only:
/// it must not publish, since this function does not authorize any writes.
pub fn check(
    content: &[u8],
    max_steps: u32,
    base_commit: &str,
    max_patch_bytes: u64,
    rules: &PatchRules<'_>,
    mut inspect: impl FnMut(&Step) -> Result<()>,
) -> Result<CheckedStack> {
    ensure!(
        max_steps > 0 && max_steps <= MAX_STEPS,
        "stack step limit must be explicitly set to 1..={MAX_STEPS}"
    );
    ensure!(
        content.len() <= MAX_BYTES,
        "stack proposal exceeds byte limit"
    );
    let proposal: Proposal = serde_json::from_slice(content)
        .map_err(|_| anyhow::anyhow!("invalid stack proposal envelope"))?;
    ensure!(
        COMMIT_RE.is_match(base_commit) && proposal.base_commit == base_commit,
        "stack proposal does not match the trusted base commit"
    );
    ensure!(
        !proposal.steps.is_empty() && proposal.steps.len() <= max_steps as usize,
        "stack step count is outside bounds"
    );
    let mut checked = CheckedStack {
        accepted: Vec::new(),
        refused: None,
    };
    let mut issues = BTreeSet::new();
    for (index, value) in proposal.steps.into_iter().enumerate() {
        let result = (|| {
            // Do not include serde's diagnostic: an invalid value may contain
            // a secret. Callers must likewise keep inspect errors value-free.
            // Decode directly from the original JSON: going through Value
            // would silently discard duplicate fields before schema validation.
            let step: Step = serde_json::from_str(value.get())
                .map_err(|_| anyhow::anyhow!("invalid stack step schema"))?;
            ensure!(
                (1..=MAX_ISSUE).contains(&step.issue) && issues.insert(step.issue),
                "stack step requires a distinct positive issue number within bounds"
            );
            ensure!(
                !step.title.trim().is_empty()
                    && step.title.len() <= MAX_TITLE_BYTES
                    && !step.title.chars().any(char::is_control),
                "stack step title is empty, oversized or contains control characters"
            );
            ensure!(
                !step.body.trim().is_empty() && step.body.len() <= MAX_BODY_BYTES,
                "stack step body is empty or oversized"
            );
            ensure!(
                step.patch.len() as u64 <= max_patch_bytes,
                "stack step exceeds the patch byte limit"
            );
            // Before the patch is read: its problems quote the patch's lines.
            inspect(&step)?;
            // The base header the reader is given authenticates the
            // proposal's root provenance only. It does not claim the
            // resulting commit ID or prove ancestry; applying each diff on
            // its predecessor is the publisher's job.
            let files = read_mail(&step.patch, base_commit, rules, "stack step patch")?;
            Ok(CheckedStep { step, files })
        })();
        match result {
            Ok(step) => checked.accepted.push(step),
            Err(error) => {
                checked.refused = Some(Refusal {
                    position: index + 1,
                    reason: error.to_string(),
                });
                break;
            }
        }
    }
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::fixtures::policy;
    use serde_json::{Value, json};
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};

    const BASE: &str = "1111111111111111111111111111111111111111";

    fn step(issue: u64, path: &str) -> Value {
        json!({
            "issue": issue, "title": format!("Step {issue}"), "body": "Why this change.",
            "patch": format!(
                "From {BASE} Mon Sep 17 00:00:00 2001\n\
                 From: agent <agent@localhost>\n\
                 Date: Tue, 6 Oct 2026 21:02:35 -0400\n\
                 Subject: [PATCH] Change things\n\n\
                 Why it changes.\n---\n\
                 diff --git a/{path} b/{path}\n\
                 index f328e4d..a83147c 100644\n\
                 --- a/{path}\n+++ b/{path}\n\
                 @@ -1 +1 @@\n-old\n+new\n"
            )
        })
    }

    fn proposal() -> Value {
        json!({"base_commit": BASE, "steps": [
            step(1, "one.rs"), step(2, "two.rs"), step(3, "three.rs")
        ]})
    }

    fn checked(value: &Value) -> CheckedStack {
        let policy = policy();
        check(
            value.to_string().as_bytes(),
            3,
            BASE,
            4096,
            &policy.safe_outputs.create_pull_request.unwrap().rules(),
            |_| Ok(()),
        )
        .unwrap()
    }

    #[test]
    fn three_steps_keep_their_own_diff() {
        let checked = checked(&proposal());
        assert!(checked.refused.is_none());
        assert_eq!(checked.accepted.len(), 3);
        for (step, path) in checked
            .accepted
            .iter()
            .zip(["one.rs", "two.rs", "three.rs"])
        {
            assert_eq!(step.files, [path]);
        }
    }

    fn git(repo: &Path, args: &[&str], input: Option<&str>) -> String {
        let mut child = Command::new("git")
            .current_dir(repo)
            .args([
                "-c",
                "user.name=agent",
                "-c",
                "user.email=agent@localhost",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(input) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    #[test]
    fn real_git_series_checks_each_step_not_the_final_diff() {
        let policy = policy();
        let pr = policy.safe_outputs.create_pull_request.unwrap();
        for protected_middle in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let repo = dir.path();
            git(repo, &["init", "--quiet"], None);
            for path in ["one.rs", "AGENTS.md"] {
                std::fs::write(repo.join(path), "old\n").unwrap();
            }
            git(repo, &["add", "."], None);
            git(repo, &["commit", "--quiet", "-m", "Initial tree"], None);
            let base = git(repo, &["rev-parse", "HEAD"], None).trim().to_owned();
            let mut steps = Vec::new();
            for index in 1..=3 {
                let path = if protected_middle && index > 1 {
                    "AGENTS.md"
                } else {
                    "one.rs"
                };
                let content = if protected_middle && index == 3 {
                    "old\n".to_owned()
                } else {
                    format!("step {index}\n")
                };
                std::fs::write(repo.join(path), content).unwrap();
                git(repo, &["add", "."], None);
                git(
                    repo,
                    &["commit", "--quiet", "-m", &format!("Step {index}")],
                    None,
                );
                let patch = git(
                    repo,
                    &["format-patch", "--stdout", "--no-signature", "-1"],
                    None,
                );
                steps.push(json!({
                    "issue": index, "title": format!("Step {index}"),
                    "body": "Why this change.", "patch": patch
                }));
            }
            let tree = git(repo, &["rev-parse", "HEAD^{tree}"], None);
            // The forbidden edit/revert is invisible in the aggregate diff.
            assert_eq!(
                git(repo, &["diff", "--name-only", &base, "HEAD"], None),
                "one.rs\n"
            );
            let content = json!({"base_commit": base, "steps": steps}).to_string();
            let checked =
                check(content.as_bytes(), 3, &base, 4096, &pr.rules(), |_| Ok(())).unwrap();
            if protected_middle {
                assert_eq!(checked.accepted.len(), 1);
                let refusal = checked.refused.unwrap();
                assert_eq!(refusal.position, 2);
                assert!(refusal.reason.contains("protected files"));
            } else {
                assert!(checked.refused.is_none());
                assert_eq!(checked.accepted.len(), 3);
                // Replay genuine mails on the root to exercise dependent diffs.
                git(repo, &["reset", "--hard", &base], None);
                for step in checked.accepted {
                    assert_eq!(step.files, ["one.rs"]);
                    git(repo, &["am", "--quiet"], Some(&step.step.patch));
                }
                assert_eq!(git(repo, &["rev-parse", "HEAD^{tree}"], None), tree);
            }
        }
    }

    #[test]
    fn refusal_keeps_prefix_and_does_not_inspect_later_steps() {
        let mut proposal = proposal();
        proposal["steps"][1] = step(2, "AGENTS.md");
        let policy = policy();
        let mut inspected = Vec::new();
        let checked = check(
            proposal.to_string().as_bytes(),
            3,
            BASE,
            4096,
            &policy.safe_outputs.create_pull_request.unwrap().rules(),
            |step| {
                inspected.push(step.issue);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(inspected, [1, 2]);
        assert_eq!(checked.accepted.len(), 1);
        let refusal = checked.refused.unwrap();
        assert_eq!(refusal.position, 2);
        assert!(
            refusal.reason.contains("protected files"),
            "{}",
            refusal.reason
        );
    }

    #[test]
    fn step_schema_metadata_and_size_refusals_preserve_prefix() {
        for (key, value) in [
            ("issue", json!(0)),
            ("issue", json!(1)),
            ("issue", json!(MAX_ISSUE + 1)),
            ("title", json!("")),
            ("title", json!("x".repeat(MAX_TITLE_BYTES + 1))),
            ("title", json!("bad\ntitle")),
            ("body", json!(" ")),
            ("body", json!("x".repeat(MAX_BODY_BYTES + 1))),
            ("branch", json!("redirect")),
            ("patch", json!("x".repeat(4097))),
            ("patch", json!("not a mail\n")),
            // A rebuild must be the same commit.
            (
                "patch",
                json!(
                    step(2, "two.rs")["patch"]
                        .as_str()
                        .unwrap()
                        .replace("Date: Tue, 6 Oct 2026 21:02:35 -0400\n", "")
                ),
            ),
        ] {
            let mut proposal = proposal();
            proposal["steps"][1][key] = value;
            let checked = checked(&proposal);
            assert_eq!(checked.accepted.len(), 1, "{key}");
            assert_eq!(checked.refused.unwrap().position, 2, "{key}");
        }
    }

    #[test]
    fn duplicate_step_fields_refuse_without_inspecting_or_losing_prefix() {
        let policy = policy();
        let pr = policy.safe_outputs.create_pull_request.unwrap();
        for field in ["issue", "title", "body", "patch"] {
            let second = step(2, "two.rs");
            let mut duplicate = second.to_string();
            duplicate.pop();
            duplicate.push_str(&format!(",{field:?}:{}}}", second[field]));
            let content = format!(
                "{{\"base_commit\":{BASE:?},\"steps\":[{},{duplicate},{}]}}",
                step(1, "one.rs"),
                step(3, "three.rs")
            );
            let mut inspected = Vec::new();
            let checked = check(content.as_bytes(), 3, BASE, 4096, &pr.rules(), |step| {
                inspected.push(step.issue);
                Ok(())
            })
            .unwrap();
            assert_eq!(inspected, [1], "{field}");
            assert_eq!(checked.accepted.len(), 1, "{field}");
            let refusal = checked.refused.unwrap();
            assert_eq!(refusal.position, 2, "{field}");
            assert_eq!(refusal.reason, "invalid stack step schema", "{field}");
        }
    }

    #[test]
    fn envelope_and_opt_in_bounds_refuse_before_inspection() {
        let policy = policy();
        let pr = policy.safe_outputs.create_pull_request.unwrap();
        let normal = proposal().to_string();
        for (content, limit, base) in [
            (normal.clone(), 0, BASE),
            (normal.clone(), MAX_STEPS + 1, BASE),
            (normal.clone(), 2, BASE),
            (normal.clone(), 3, "bad"),
            ("x".repeat(MAX_BYTES + 1), 3, BASE),
            ("{}".into(), 3, BASE),
            (
                format!("{{\"base_commit\":{BASE:?},\"base_commit\":{BASE:?},\"steps\":[]}}"),
                3,
                BASE,
            ),
            (
                format!("{{\"base_commit\":{BASE:?},\"steps\":[],\"steps\":[]}}"),
                3,
                BASE,
            ),
            (
                json!({"base_commit": BASE, "steps": []}).to_string(),
                3,
                BASE,
            ),
            (
                json!({"base_commit": BASE, "steps": [], "extra": true}).to_string(),
                3,
                BASE,
            ),
            (normal, 3, "2222222222222222222222222222222222222222"),
        ] {
            assert!(
                check(content.as_bytes(), limit, base, 4096, &pr.rules(), |_| {
                    panic!("must not inspect an invalid envelope")
                })
                .is_err()
            );
        }
    }

    #[test]
    fn caller_inspection_refusal_stops_the_prefix() {
        let policy = policy();
        let checked = check(
            proposal().to_string().as_bytes(),
            3,
            BASE,
            4096,
            &policy.safe_outputs.create_pull_request.unwrap().rules(),
            |step| {
                ensure!(step.issue != 2, "caller secret scan refused step");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(checked.accepted.len(), 1);
        assert_eq!(checked.refused.unwrap().position, 2);
    }

    #[test]
    fn per_step_file_count_and_pinned_author_are_not_lost() {
        let policy = policy();
        let pr = policy.safe_outputs.create_pull_request.unwrap();
        for rules in [
            PatchRules {
                max_patch_files: 0,
                ..pr.rules()
            },
            PatchRules {
                commit_author: Some("Other <other@example.com>"),
                ..pr.rules()
            },
        ] {
            let checked = check(
                proposal().to_string().as_bytes(),
                3,
                BASE,
                4096,
                &rules,
                |_| Ok(()),
            )
            .unwrap();
            assert!(checked.accepted.is_empty());
            assert_eq!(checked.refused.unwrap().position, 1);
        }
    }
}
