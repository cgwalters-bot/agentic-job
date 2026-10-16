//! `agentic-job check`: check handed-back outputs and the patch against
//! the policy. Step 4 of docs/plan.md.
//!
//! This is the second half of the check. The first is gh-aw's collector
//! (`collect_ndjson_output.cjs`), which knows the request types, counts
//! them, and validates and sanitizes their fields; it is run before this,
//! configured with the policy's `safe_outputs`, and its result is given
//! here with `--collected`. Nothing of it is done again. What is done
//! here is what gh-aw leaves to the workflow it generates, or does not do
//! at all: the hand-back holds only the files it may, within their sizes
//! and free of secret-shaped strings; the requests fit the policy; a pull
//! request comes with exactly its patch, against the policy's repository
//! and base; and the patch passes the rules of [`patch`]. One thing of
//! the collector's is mended: a Markdown link it redacted is made plain
//! text again ([`links`]).

pub mod checkpoint;
pub mod links;
mod patch;
pub mod replacement;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use self::patch::{BASE_COMMIT_HEADER, PatchReading, read_patch};
use crate::exit::Exit;
use crate::files;
use crate::policy::{
    CREATE_PULL_REQUEST, HIDE_COMMENT, MARK_READY, PUSH_TO_PULL_REQUEST_BRANCH, PatchRules, Policy,
    update_fields,
};
use crate::redact;

/// The requests the agent wrote, one JSON object to a line.
pub const OUTPUTS_FILE: &str = "outputs.jsonl";

/// Which repository, branch and commit a patch is against.
pub const BASE_FILE: &str = "base.json";

const MAX_OUTPUTS_BYTES: u64 = 1 << 20;
const MAX_BASE_BYTES: u64 = 4096;

/// The collector's result is the requests again, sanitized, as one JSON
/// value: a little more than the requests themselves.
const MAX_COLLECTED_BYTES: u64 = 4 * MAX_OUTPUTS_BYTES;

/// How much of a request's title, or of a reason, one line of the summary
/// or of the log shows.
const SHOWN_CHARS: usize = 300;

/// How much of a commit id the summary shows.
const SHORT_COMMIT: usize = 12;

static PATCH_FILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^aw-[a-z0-9][a-z0-9._-]{0,99}\.patch$").expect("a valid pattern")
});

static COMMIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{40}$").expect("a valid pattern"));

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
}

/// What `check` decided. `--report` holds this as JSON.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verdict {
    pub ok: bool,
    /// Every reason for a refusal.
    pub errors: Vec<String>,
    /// The requests, as the collector sanitized them.
    pub items: Vec<Map<String, Value>>,
    pub patch: Option<PatchInfo>,
    /// Where the policy has complete work opened ready, the checkpoint the
    /// pull request or push says the work stopped at: apply keeps it a draft.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<checkpoint::Checkpoint>,
}

/// The patch of an accepted pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PatchInfo {
    pub file: String,
    pub bytes: usize,
    pub base_commit: String,
    /// The paths the patch names. git can still apply it to others (see
    /// [`patch`]): whoever applies it compares this with what changed.
    pub files: Vec<String>,
    /// Present only for a bounded replacement; apply checks every commit diff.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_files: Option<Vec<Vec<String>>>,
}

/// What gh-aw's collector writes: the requests it accepted, and why it
/// refused the others.
#[derive(Debug, Deserialize)]
struct Collected {
    items: Vec<Map<String, Value>>,
    errors: Vec<String>,
}

/// `base.json`.
#[derive(Debug, Deserialize)]
struct Base {
    repo: String,
    r#ref: String,
    commit: String,
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
            ok: errors.is_empty(),
            errors,
            items,
            patch,
            checkpoint: None,
        }
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
        if let Some(patch) = &self.patch {
            let commit: String = patch.base_commit.chars().take(SHORT_COMMIT).collect();
            lines.push(format!(
                "- patch `{}` ({} bytes) against {commit}",
                patch.file, patch.bytes
            ));
        }
        lines.extend(
            self.errors
                .iter()
                .map(|error| format!("- refused: {}", one_line(error))),
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

/// The output type that opens an issue, and the fields of one that act
/// on other issues.
const CREATE_ISSUE: &str = "create_issue";
const ISSUE_LINKS: &[&str] = &["parent", "blocked_by"];

fn item_type(item: &Map<String, Value>) -> &str {
    item.get("type").and_then(Value::as_str).unwrap_or_default()
}

/// What gh-aw's collector appends, of its own, to a result holding no
/// request but `missing_tool` and `missing_data`, or none at all.
const COLLECTORS_INCOMPLETE: &str = "report_incomplete";

/// The diagnostics a hand-back may hold beside the incomplete report.
const DIAGNOSTICS: &[&str] = &["missing_tool", "missing_data"];

/// Drops the collector's incomplete report, which says no more than the
/// run's own exit does and which no policy allows, so that a hand-back
/// of nothing or of diagnostics only passes as before. Only the last
/// item, and only where the collector puts one: anything else of that
/// type, an agent's included (which the collector refuses as of a type
/// its configuration lacks), is left to be refused below.
fn drop_collectors_incomplete(items: &mut Vec<Map<String, Value>>) {
    if let Some((last, rest)) = items.split_last()
        && item_type(last) == COLLECTORS_INCOMPLETE
        && rest
            .iter()
            .all(|item| DIAGNOSTICS.contains(&item_type(item)))
    {
        items.pop();
    }
}

/// What the apply job writes, hidden, into each body it posts, so that a
/// re-run finds what was already applied and skips it. A request holding
/// it could make a re-run skip another request, so none may.
const APPLIED_MARKER: &str = "agentic-job-applied";

fn holds_marker(value: &Value) -> bool {
    match value {
        Value::String(text) => text.to_ascii_lowercase().contains(APPLIED_MARKER),
        Value::Array(values) => values.iter().any(holds_marker),
        Value::Object(map) => map_holds_marker(map),
        _ => false,
    }
}

fn map_holds_marker(map: &Map<String, Value>) -> bool {
    map.iter().any(|(key, value)| {
        key.to_ascii_lowercase().contains(APPLIED_MARKER) || holds_marker(value)
    })
}

/// The fields of a request that would take it out of the policy. gh-aw's
/// rules let a request name a repository of its own, and a pull request a
/// base branch and whether it is a draft; whether a handler honours them
/// is the handler's configuration, which this does not see. The policy
/// has fixed all three, so a request that says otherwise is refused.
#[cfg(test)]
fn redirections(item: &Map<String, Value>, policy: &Policy) -> Vec<String> {
    redirections_to(item, policy, None)
}

fn redirections_to(
    item: &Map<String, Value>,
    policy: &Policy,
    comment: Option<(&str, u64)>,
) -> Vec<String> {
    let output = item_type(item);
    let differs = |key: &str, same: &dyn Fn(&str) -> bool| {
        item.get(key)
            .filter(|value| !value.as_str().is_some_and(same))
            .map(|value| format!("a {output} with {key} {value}, which is not the policy's"))
    };
    let repo = if matches!(output, "add_comment" | HIDE_COMMENT) {
        comment.map_or(policy.repo.as_str(), |(repo, _)| repo)
    } else {
        &policy.repo
    };
    let mut problems: Vec<String> = differs("repo", &|value| value.eq_ignore_ascii_case(repo))
        .into_iter()
        .collect();
    if output == "add_comment"
        && let Some((_, target)) = comment
    {
        for key in [
            "item_number",
            "pr",
            "pr_number",
            "issue_number",
            "pull_request_number",
            "pull_number",
            "pr-number",
        ] {
            if let Some(value) = item.get(key) {
                let number = value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()));
                if number != Some(target) {
                    problems.push(format!(
                        "an add_comment with {key} outside the caller's fixed item"
                    ));
                }
            }
        }
        // These select an existing comment or a discussion reply, not the
        // caller's issue/PR. No trusted comment-ID allowlist is configured.
        for key in [
            "comment_id",
            "commentId",
            "comment-id",
            "reply_to_id",
            "target",
        ] {
            if item.contains_key(key) {
                problems.push(format!(
                    "an add_comment with {key}, outside the caller's fixed destination"
                ));
            }
        }
    }
    if output == HIDE_COMMENT {
        // Hiding moderates what other people wrote, so only on the item
        // the run was started for: apply gives the handler that number as
        // its target, and the handler refuses a comment on any other item,
        // which only it can look up. Without a fixed item (`*`) there is
        // none to hold it to.
        if comment.is_none() {
            problems.push(format!(
                "a {output} needs the run's triggering issue or pull request as its comment target"
            ));
        }
        // The handler hides as spam a request without a reason.
        let reason = item.get("reason").map_or(Some("SPAM"), Value::as_str);
        let allowed = policy
            .safe_outputs
            .others
            .get(output)
            .map_or(&[][..], |limit| &limit.allowed_reasons[..]);
        if !reason.is_some_and(|reason| allowed.iter().any(|allowed| allowed == reason)) {
            problems.push(format!(
                "a {output} for reason {}, which the policy does not allow",
                item.get("reason")
                    .map_or_else(|| "SPAM (none given)".to_owned(), Value::to_string)
            ));
        }
    }
    if output == CREATE_PULL_REQUEST {
        problems.extend(differs("base", &|base| base == policy.base));
        if item
            .get("draft")
            .is_some_and(|draft| draft != &Value::Bool(true))
        {
            problems.push(format!("a {output} that is not a draft"));
        }
    }
    if output == PUSH_TO_PULL_REQUEST_BRANCH {
        // The pull request and its branch are the request's, not the
        // agent's: the handler pushes to the number configured, and finds
        // the patch by the branch.
        problems.extend(differs("branch", &|branch| branch == policy.base));
        let target = policy
            .safe_outputs
            .push_to_pull_request_branch
            .as_ref()
            .map(|push| push.target.as_str());
        for key in [
            "pull_request_number",
            "pr_number",
            "pull_number",
            "pr",
            "item_number",
        ] {
            if let Some(value) = item.get(key) {
                let number = value
                    .as_u64()
                    .map(|n| n.to_string())
                    .or_else(|| value.as_str().map(str::to_owned));
                if number.as_deref() != target {
                    problems.push(format!(
                        "a {output} with {key} {value}, which is not the policy's pull request"
                    ));
                }
            }
        }
    }
    if output == "update_project" {
        // Only the board proposal grammar is exposed. The handler also supports
        // project/schema/draft mutations and aliases: none are bounded here.
        const KEYS: &[&str] = &[
            "type",
            "project",
            "target_repo",
            "content_type",
            "content_number",
            "fields",
        ];
        for key in item.keys().filter(|key| !KEYS.contains(&key.as_str())) {
            problems.push(format!("an update_project with unsupported field {key}"));
        }
        let limit = policy.safe_outputs.others.get(output);
        if !item
            .get("project")
            .and_then(Value::as_str)
            .is_some_and(|project| {
                limit.is_some_and(|limit| limit.projects.iter().any(|allowed| allowed == project))
            })
        {
            problems.push("an update_project outside the policy's named projects".to_owned());
        }
        if item.get("target_repo").and_then(Value::as_str) != Some(policy.repo.as_str()) {
            problems
                .push("an update_project requires the policy's explicit target_repo".to_owned());
        }
        if item.get("content_type").and_then(Value::as_str) != Some("issue")
            || !item
                .get("content_number")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0 && n <= 2_147_483_647)
        {
            problems.push(
                "an update_project requires issue content and a positive integer content_number"
                    .to_owned(),
            );
        }
        match item.get("fields").and_then(Value::as_object) {
            Some(fields) if !fields.is_empty() => {
                for (field, value) in fields {
                    if !limit.is_some_and(|limit| limit.fields.contains(field)) {
                        problems.push(format!(
                            "an update_project with field {field:?} not listed in the policy"
                        ));
                    }
                    if !(value.is_string() || value.is_number()) {
                        problems.push(format!(
                            "an update_project with unsupported value for {field:?}"
                        ));
                    }
                }
            }
            _ => problems.push("an update_project requires a nonempty fields object".to_owned()),
        }
    }
    let single_target = target_key(output);
    let targets: &[&str] = match output {
        "close_pull_request" => &["pull_request_number"],
        "link_sub_issue" => &["parent_issue_number", "sub_issue_number"],
        _ => single_target.as_slice(),
    };
    if !targets.is_empty() {
        if !item
            .get("repo")
            .and_then(Value::as_str)
            .is_some_and(|repo| repo.eq_ignore_ascii_case(&policy.repo))
        {
            problems.push(format!("a {output} requires the policy's explicit repo"));
        }
        // Do not let handler fallback to event context, aliases or temporary
        // IDs choose an item. Repository scope remains the compiled run's repo.
        for key in targets {
            if !item
                .get(*key)
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0 && n <= 9_007_199_254_740_991)
            {
                problems.push(format!("a {output} requires a positive integer {key}"));
            }
        }
        for alias in [
            "item_number",
            "issue_number",
            "pr_number",
            "pull_number",
            "pull_request_number",
            "pr",
            "target",
            "duplicate_of",
        ] {
            if !targets.contains(&alias) && item.contains_key(alias) {
                problems.push(format!("a {output} with unsupported target field {alias}"));
            }
        }
    }
    if let Some(known) = update_fields(output).or((output == MARK_READY).then_some(&[][..])) {
        // Every key is named: gh-aw's handlers act on fields their
        // configuration says to leave alone (`UPDATE_FIELDS`), so the
        // policy's list, not the handler's, decides. `draft` and
        // `update_branch` are refused like any field the bounds leave out,
        // so a pull request stays a draft unless the bounds say otherwise.
        let listed = policy
            .safe_outputs
            .others
            .get(output)
            .map_or(&[][..], |limit| &limit.fields[..]);
        let allowed = |key: &str| known.contains(&key) && listed.iter().any(|field| field == key);
        for key in item.keys().map(String::as_str) {
            let permitted = matches!(key, "type" | "repo")
                || Some(key) == target_key(output)
                || (output == MARK_READY && key == "reason")
                // How a body is combined with the current one.
                || (key == "operation" && allowed("body"))
                || allowed(key);
            if !permitted {
                problems.push(format!(
                    "a {output} with {key}, which the policy does not let it change"
                ));
            }
        }
    }
    if output == "remove_labels"
        && !item
            .get("labels")
            .and_then(Value::as_array)
            .is_some_and(|labels| !labels.is_empty())
    {
        problems.push("a remove_labels requires a nonempty labels array".to_owned());
    }
    if output == "create_check_run" {
        // An agent-chosen success could satisfy a required check by that name.
        if item.get("conclusion").and_then(Value::as_str) == Some("success") {
            problems.push("a create_check_run that concludes success".to_owned());
        }
        // The handler posts on this pull request's head, in the calling
        // repository; without one it would take the apply job's own commit.
        if !item
            .get("pull_request_number")
            .and_then(Value::as_u64)
            .is_some_and(|n| n > 0 && n <= 9_007_199_254_740_991)
        {
            problems.push(
                "a create_check_run requires a positive integer pull_request_number".to_owned(),
            );
        }
        for alias in ["pr_number", "pull_number", "pr", "item_number", "target"] {
            if item.contains_key(alias) {
                problems.push(format!(
                    "a create_check_run with unsupported target field {alias}"
                ));
            }
        }
    }
    if output == "create_discussion" {
        // The handler takes a request's category over the pinned one, so an
        // agent could post in Announcements or a category others watch.
        let pinned = policy
            .safe_outputs
            .others
            .get(output)
            .and_then(|limit| limit.category.as_deref());
        problems.extend(differs("category", &|category| Some(category) == pinned));
    }
    if matches!(output, CREATE_ISSUE | "add_labels" | "remove_labels")
        && let Some(limit) = policy.safe_outputs.others.get(output)
        && (limit.allowed.is_some() || !limit.blocked.is_empty())
        && let Some(labels) = item.get("labels")
    {
        match labels.as_array() {
            Some(labels) => {
                // The pinned label handlers use max for both requests and
                // labels per request. Refuse rather than silently drop labels.
                if output != CREATE_ISSUE && labels.len() > limit.max as usize {
                    problems.push(format!("a {output} exceeding the per-request label limit"));
                }
                for label in labels {
                    let permitted = label.as_str().is_some_and(|label| {
                        label == label.trim()
                            // A conservative fixed-point subset of gh-aw's
                            // sanitizer: no Unicode hardening, mention escaping,
                            // punctuation removal or UTF-16 truncation can alter it.
                            && (output == CREATE_ISSUE
                                || (!label.is_empty()
                                    && label.len() <= 64
                                    && !label.starts_with('-')
                                    && label.bytes().all(|b| {
                                        b.is_ascii_alphanumeric() || b" -_./:".contains(&b)
                                    })))
                            && !limit
                                .blocked
                                .iter()
                                .any(|blocked| blocked.eq_ignore_ascii_case(label))
                            && limit.allowed.as_ref().is_none_or(|allowed| {
                                allowed
                                    .iter()
                                    .any(|allowed| allowed.eq_ignore_ascii_case(label))
                            })
                    });
                    if !permitted {
                        problems.push(format!(
                            "a {output} with label {label}, outside the policy's label limits"
                        ));
                    }
                }
            }
            None => problems.push(format!("a {output} whose labels are not an array")),
        }
    }
    if let Some((key, people)) = match output {
        "add_reviewer" => Some(("pull_request_number", "reviewers")),
        "assign_to_user" => Some(("issue_number", "assignees")),
        _ => None,
    } {
        // Whoever is named is notified. The handlers silently drop a login
        // outside `allowed`, and fall back to the triggering item without a
        // number, so check refuses instead; `policy` requires the list.
        if !item
            .get("repo")
            .and_then(Value::as_str)
            .is_some_and(|repo| repo.eq_ignore_ascii_case(&policy.repo))
        {
            problems.push(format!("a {output} requires the policy's explicit repo"));
        }
        if !item
            .get(key)
            .and_then(Value::as_u64)
            .is_some_and(|n| n > 0 && n <= 9_007_199_254_740_991)
        {
            problems.push(format!("a {output} requires a positive integer {key}"));
        }
        // Other targets, and other ways to name people: teams and the
        // singular `assignee` have no bounds here.
        for alias in [
            "item_number",
            "issue_number",
            "pull_request_number",
            "pr_number",
            "pull_number",
            "pr",
            "target",
            "team_reviewers",
            "assignee",
        ] {
            if alias != key && item.contains_key(alias) {
                problems.push(format!("a {output} with unsupported field {alias}"));
            }
        }
        let limit = policy.safe_outputs.others.get(output);
        match item.get(people).and_then(Value::as_array) {
            Some(logins) if !logins.is_empty() => {
                // The handlers use max for both requests and logins per
                // request, and would drop the rest.
                if limit.is_none_or(|limit| logins.len() > limit.max as usize) {
                    problems.push(format!("a {output} exceeding the per-request login limit"));
                }
                for login in logins {
                    // Exactly as listed: the handlers compare logins so.
                    if !login.as_str().is_some_and(|login| {
                        limit
                            .and_then(|limit| limit.allowed.as_ref())
                            .is_some_and(|allowed| allowed.iter().any(|allowed| allowed == login))
                    }) {
                        problems.push(format!(
                            "a {output} naming {login}, which the policy does not allow"
                        ));
                    }
                }
            }
            _ => problems.push(format!("a {output} requires a nonempty {people} array")),
        }
    }
    if output == "close_issue" && item.contains_key("body") {
        problems.push("a close_issue with body; closure does not post comments".to_owned());
    }
    if output == CREATE_ISSUE {
        // gh-aw's handler links the new issue to any issue the request
        // names; nothing bounds which, so those requests are refused.
        problems.extend(
            ISSUE_LINKS
                .iter()
                .filter(|key| item.contains_key(**key))
                .map(|key| format!("a {output} with {key}, which links another issue")),
        );
    }
    problems
}

/// The field naming the one item an output acts on, for those that must
/// name it explicitly.
fn target_key(output: &str) -> Option<&'static str> {
    match output {
        "close_issue" | "update_issue" => Some("issue_number"),
        "add_labels" | "remove_labels" => Some("item_number"),
        "update_pull_request" | MARK_READY => Some("pull_request_number"),
        _ => None,
    }
}

/// A check run named otherwise than the policy pins, in the agent's own
/// lines. The handler names the run from its configuration, the bounds'
/// pin, and gh-aw's collector drops a `name` its rules do not list, so
/// another name would not be posted; it is refused rather than seem
/// honoured. The pin, not this, is what keeps the name.
fn check_run_names(lines: &[u8], policy: &Policy) -> Vec<String> {
    let pinned = policy
        .safe_outputs
        .others
        .get("create_check_run")
        .and_then(|limit| limit.name.as_deref());
    String::from_utf8_lossy(lines)
        .lines()
        .filter_map(|line| serde_json::from_str::<Map<String, Value>>(line).ok())
        .filter(|item| item_type(item).replace('-', "_") == "create_check_run")
        .filter_map(|item| {
            item.get("name")
                .filter(|name| name.as_str().is_none() || name.as_str() != pinned)
                .map(|name| {
                    format!("a create_check_run with name {name}, which is not the policy's")
                })
        })
        .collect()
}

fn is_handback_file(name: &str) -> bool {
    name == OUTPUTS_FILE
        || name == BASE_FILE
        || name == replacement::REPLACEMENT_FILE
        || PATCH_FILE_RE.is_match(name)
}

/// The most a file of a hand-back may hold.
fn max_bytes_of(name: &str, policy: &Policy) -> u64 {
    match name {
        OUTPUTS_FILE => MAX_OUTPUTS_BYTES,
        BASE_FILE => MAX_BASE_BYTES,
        _ => policy.max_patch_bytes,
    }
}

/// The name of the patch for a pull request's branch: gh-aw's
/// (`sanitizeForFilename` of `git_patch_utils.cjs`), which its handlers
/// look for.
pub fn patch_file_name(branch: &str) -> String {
    static UNSAFE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"[/\\:*?"<>|]"#).expect("a valid pattern"));
    static DASHES_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("-{2,}").expect("a valid pattern"));

    let name = UNSAFE_RE.replace_all(branch, "-");
    let name = DASHES_RE.replace_all(&name, "-");
    let name = name.strip_prefix('-').unwrap_or(&name);
    let name = name.strip_suffix('-').unwrap_or(name);
    format!("aw-{}.patch", name.to_lowercase())
}

/// Checks the hand-back in `dir` (`outputs.jsonl`, `base.json`, one
/// `aw-*.patch`) and the collector's result for it against `policy`.
///
/// An error is something wrong with the check's own inputs, the
/// directory or the collector's result; whatever is wrong with the
/// hand-back is a refusal, in the verdict.
pub fn check_outputs(dir: &Path, collected: &Path, policy: &Policy) -> Result<Verdict> {
    check_outputs_to(dir, collected, policy, None)
}

fn check_outputs_to(
    dir: &Path,
    collected: &Path,
    policy: &Policy,
    comment: Option<(&str, u64)>,
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
    for name in &names {
        let Some(name) = name.to_str().filter(|name| is_handback_file(name)) else {
            errors.push(format!("unexpected file {name:?}"));
            continue;
        };
        match files::read_regular(&dir.join(name), max_bytes_of(name, policy)) {
            Ok(content) if redact::is_secret_shaped(&content) => {
                errors.push(format!("a secret-shaped string in {name}"));
            }
            Ok(content) => {
                contents.insert(name.to_owned(), content);
            }
            Err(err) => errors.push(format!("{name} {err}")),
        }
    }
    // Taken from a path of its own and never from `dir`, which the agent's
    // machine uploaded: a result found there could be the agent's.
    let collected_bytes = files::read_regular(collected, MAX_COLLECTED_BYTES)
        .with_context(|| format!("the collector's result {}", collected.display()))?;
    if redact::is_secret_shaped(&collected_bytes) {
        errors.push("a secret-shaped string in the collected outputs".to_owned());
    }
    if !errors.is_empty() {
        return Ok(Verdict::new(errors, Vec::new(), None));
    }

    let mut collected: Collected = serde_json::from_slice(&collected_bytes).with_context(|| {
        format!(
            "{} is not the result of gh-aw's collector",
            collected.display()
        )
    })?;
    drop_collectors_incomplete(&mut collected.items);
    // Mending joins nothing to a link's text (`links::repair`), so it
    // makes no secret-shaped string, URL or mention the collector missed.
    for item in &mut collected.items {
        item.values_mut().for_each(links::repair_value);
    }
    let items = if contents.contains_key(OUTPUTS_FILE) {
        errors.extend(collected.errors);
        collected.items
    } else {
        if !collected.items.is_empty() || !collected.errors.is_empty() {
            errors.push(format!(
                "the collector's result holds outputs, and there is no {OUTPUTS_FILE}"
            ));
        }
        Vec::new()
    };

    // The collector counts each type against the configuration it was
    // given. Counting again costs nothing and shows a collector that was
    // given another configuration than this policy's.
    if items.len() > usize::try_from(policy.max_outputs).unwrap_or(usize::MAX) {
        errors.push(format!(
            "{} outputs, over max_outputs {}",
            items.len(),
            policy.max_outputs
        ));
    }
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for item in &items {
        *counts.entry(item_type(item)).or_default() += 1;
    }
    for (output, count) in counts {
        match policy.safe_outputs.max_of(output) {
            None => errors.push(format!(
                "an output of type {output:?}, which the policy does not allow"
            )),
            Some(max) if count > max => {
                errors.push(format!("{count} outputs of type {output:?}, over {max}"));
            }
            Some(_) => {}
        }
    }

    errors.extend(
        items
            .iter()
            .flat_map(|item| redirections_to(item, policy, comment)),
    );
    if let Some(lines) = contents.get(OUTPUTS_FILE) {
        errors.extend(check_run_names(lines, policy));
    }
    errors.extend(
        items
            .iter()
            .filter(|item| map_holds_marker(item))
            .map(|item| {
                format!(
                    "a {} holding {APPLIED_MARKER}, which apply writes",
                    item_type(item)
                )
            }),
    );

    let patch_names: Vec<&str> = contents
        .keys()
        .map(String::as_str)
        .filter(|name| PATCH_FILE_RE.is_match(name))
        .collect();
    // The output that carries the patch: a pull request to open, or a
    // push to the open one the run started from, whose head is pinned.
    let carrier = policy.safe_outputs.patch_carrier().map(|(output, rules)| {
        let commit_author = policy.commit_author.as_deref();
        (
            output,
            PatchRules {
                commit_author,
                ..rules
            },
        )
    });
    let pinned = policy
        .safe_outputs
        .push_to_pull_request_branch
        .as_ref()
        .map(|push| push.head.as_str());
    let request =
        carrier.and_then(|(output, _)| items.iter().find(|item| item_type(item) == output));
    // Read only where it decides something: a policy without
    // `ready_when_complete` opens every pull request as a draft anyway.
    let mut checkpoint = None;
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
    let mut patch = None;
    if let Some(content) = contents.get(replacement::REPLACEMENT_FILE) {
        if request.is_none() || policy.safe_outputs.push_to_pull_request_branch.is_none() {
            errors.push("a replacement without a push request".into());
        } else if !patch_names.is_empty() || contents.contains_key(BASE_FILE) {
            errors.push("a replacement alongside a patch or base.json".into());
        } else if let Some(push) = &policy.safe_outputs.push_to_pull_request_branch {
            match replacement::check(content, push, policy.max_patch_bytes) {
                Ok(info) => patch = Some(info),
                Err(error) => errors.push(format!("replacement: {error}")),
            }
        }
        return Ok(Verdict {
            checkpoint,
            ..Verdict::new(errors, items, patch)
        });
    }
    match (request, carrier) {
        (Some(request), Some((output, rules))) => {
            // The patch is read against any commit base.json names, so that
            // a hand-back refused for its base is told what else is wrong.
            let base = contents
                .get(BASE_FILE)
                .and_then(|content| serde_json::from_slice::<Base>(content).ok())
                .filter(|base| COMMIT_RE.is_match(&base.commit));
            let ours = |base: &Base| {
                base.repo.eq_ignore_ascii_case(&policy.repo)
                    && base.r#ref == policy.base
                    && pinned.is_none_or(|head| base.commit == head)
            };
            if !base.as_ref().is_some_and(ours) {
                errors.push(match pinned {
                    // A branch that moved since the run was asked for is
                    // another's work, which the push would be on top of
                    // or beside: the run is asked for again instead.
                    Some(head) => format!(
                        "{BASE_FILE} is not {{repo: {}, ref: {}, commit: {head}}}: the pull request's head the run was asked for",
                        policy.repo, policy.base
                    ),
                    None => format!(
                        "{BASE_FILE} is not {{repo: {}, ref: {}, commit: SHA}}",
                        policy.repo, policy.base
                    ),
                });
            }
            let branch = request
                .get("branch")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let want = patch_file_name(branch);
            match (patch_names.as_slice(), contents.get(&want), base) {
                ([_], Some(content), Some(base)) => {
                    // What is not UTF-8 in it is in a file's content, where
                    // the rules look only at the first byte of a line.
                    let text = String::from_utf8_lossy(content);
                    let PatchReading { problems, files } = read_patch(&text, &rules, &base.commit);
                    errors.extend(problems.iter().map(|problem| format!("{want}: {problem}")));
                    patch = Some(PatchInfo {
                        file: want,
                        bytes: content.len(),
                        base_commit: base.commit,
                        files,
                        commit_files: None,
                    });
                }
                ([_], Some(_), None) => {}
                _ => errors.push(format!(
                    "{output} needs exactly one patch, {want}; there is {}",
                    if patch_names.is_empty() {
                        "none".to_owned()
                    } else {
                        patch_names.join(", ")
                    }
                )),
            }
        }
        (None, carrier) if !patch_names.is_empty() => {
            errors.push(format!(
                "a patch without a {}",
                carrier.map_or(CREATE_PULL_REQUEST, |(output, _)| output)
            ));
        }
        // Without the rules for a patch there is no request to check: the
        // count above has refused it.
        _ => {}
    }
    Ok(Verdict {
        checkpoint,
        ..Verdict::new(errors, items, patch)
    })
}

pub fn run(args: &Args) -> Result<Exit> {
    let policy = Policy::load(&args.policy)?;
    let comment = args.comment_repo.as_deref().zip(args.comment_target);
    let verdict = check_outputs_to(&args.outputs, &args.collected, &policy, comment)?;
    if let Some(report) = &args.report {
        let json = serde_json::to_string_pretty(&verdict).context("writing the verdict")?;
        std::fs::write(report, json + "\n")
            .with_context(|| format!("writing the report {}", report.display()))?;
    }
    for error in &verdict.errors {
        eprintln!("error: {}", one_line(error));
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

    const BASE: &str = "1111111111111111111111111111111111111111";
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
            check_outputs(&out, &collected, policy).unwrap()
        }
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

    /// A push to pull request 42's branch `agent-run-12` at `HEAD`.
    mod push {
        use super::*;
        use crate::policy::tests::{HEAD, push_policy};

        const PUSH_PATCH: &str = "aw-agent-run-12.patch";

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
            ("close_issue", "issue_number", "labels"),
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
        for body in [json!("comment"), json!(""), Value::Null] {
            let item = json!({"type": "close_issue", "repo": policy.repo, "issue_number": 7, "body": body});
            assert!(!redirections(item.as_object().unwrap(), &policy).is_empty());
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
        let token = format!("ghp_{}", "a1B2".repeat(10));
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
                "a secret in a request",
                Handback {
                    items: vec![json!({"type": "noop", "message": token})],
                    ..Handback::default()
                },
                "a secret-shaped string in outputs.jsonl",
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
                "a secret in the patch",
                pr().with(
                    PATCH_NAME,
                    Some(patch_of("src/k.rs").replace("+x\n", &format!("+{token}\n"))),
                ),
                "a secret-shaped string in aw-agent-run-7.patch",
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
        std::fs::create_dir(out.join(BASE_FILE)).unwrap();
        let collected = dir.path().join("agent_output.json");
        std::fs::write(&collected, r#"{"items":[],"errors":[]}"#).unwrap();

        let verdict = check_outputs(&out, &collected, &policy()).unwrap();
        assert_eq!(
            verdict.errors,
            [
                "base.json is not a regular file",
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
            if output == "close_pull_request" {
                // Posted on the pull request as it is closed.
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
