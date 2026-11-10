//! The check of a hand-back against its policy, after the collector
//! ([`crate::collect`]): what gh-aw leaves to the workflow it generates,
//! or does not do at all. The requests fit the policy, in their number,
//! their targets and every field that would take them out of it; a pull
//! request comes with exactly its patch, against the policy's repository
//! and base; and the patch passes the rules of [`read_patch`]. One thing
//! of the collector's is mended: a Markdown link it redacted is made
//! plain text again ([`links`]).
//!
//! It is given the hand-back's files as its caller read them
//! ([`Handback`]), the collector's result, the policy and what the
//! trusted caller says of the run ([`Trusted`]), and reads no file,
//! environment or forge. What the caller's own publishers refuse
//! ([`Publishers`]) and what is its run's lifecycle (agentic-job's
//! checkpoint and memory) it asks the caller for, where they fall in the
//! order of refusals.

pub mod handler_limits;
pub mod inline;
pub mod links;
mod patch;
pub mod replacement;

#[cfg(test)]
pub(crate) mod fixtures;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::LazyLock;

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use self::patch::{BASE_COMMIT_HEADER, PatchReading, read_patch};
use crate::contract::{COMMIT_RE, PatchRules, Policy, Secondary, update_fields};
use crate::{
    CREATE_PULL_REQUEST, CREATE_REVIEW_COMMENT, Forge, HIDE_COMMENT, KIND_TARGETS, MARK_READY,
    OUTPUTS_FILE, PUSH_TO_PULL_REQUEST_BRANCH, REVIEW_THREAD_OUTPUTS,
};

/// Which repository, branch and commit a patch is against.
pub const BASE_FILE: &str = "base.json";

/// The same, for the policy's secondary pull request's patch.
pub const SECONDARY_BASE_FILE: &str = "secondary-base.json";

static PATCH_FILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^aw-[a-z0-9][a-z0-9._-]{0,99}\.patch$").expect("a valid pattern")
});

/// The patch of an accepted pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PatchInfo {
    pub file: String,
    pub bytes: usize,
    pub base_commit: String,
    /// The paths the patch names. git can still apply it to others (see
    /// [`read_patch`]): whoever applies it compares this with what changed.
    pub files: Vec<String>,
    /// Present only for a bounded replacement; apply checks every commit diff.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_files: Option<Vec<Vec<String>>>,
}

/// What gh-aw's collector writes: the requests it accepted, and why it
/// refused the others.
#[derive(Debug, Deserialize)]
pub struct Collected {
    pub items: Vec<Map<String, Value>>,
    pub errors: Vec<String>,
}

/// `base.json`.
#[derive(Debug, Deserialize)]
struct Base {
    repo: String,
    r#ref: String,
    commit: String,
}

/// The files of a hand-back, as the caller read them: each a regular
/// file, within the bound the caller holds it to. Which files a hand-back
/// may hold, and how they are read, are the caller's.
#[derive(Debug, Clone, Default)]
pub struct Handback<'a> {
    /// [`OUTPUTS_FILE`], the agent's own lines, if it was handed back:
    /// without it, the collector's result may hold nothing.
    pub outputs: Option<&'a [u8]>,
    /// [`BASE_FILE`].
    pub base: Option<&'a [u8]>,
    /// [`SECONDARY_BASE_FILE`].
    pub secondary_base: Option<&'a [u8]>,
    /// [`replacement::REPLACEMENT_FILE`].
    pub replacement: Option<&'a [u8]>,
    /// Every patch, by its file name ([`is_patch_file_name`]).
    pub patches: BTreeMap<&'a str, &'a [u8]>,
}

/// What the trusted caller says of the run, never the hand-back: the
/// policy holds the repository, base, head, targets and limits, and this
/// the rest.
#[derive(Debug, Clone, Copy, Default)]
pub struct Trusted<'a> {
    /// The repository and issue or pull request comments go to, fixed by
    /// the caller.
    pub comment: Option<(&'a str, u64)>,
    /// The run's identifier: the only run whose branch a secondary pull
    /// request may be on.
    pub run_id: Option<&'a str>,
}

/// What the caller's own publishers refuse, which only it knows: this
/// library publishes nothing.
pub trait Publishers {
    /// Why a neutral inline comment ([`CREATE_REVIEW_COMMENT`] off GitHub)
    /// cannot be published, if it cannot.
    fn inline_comment(&self, item: &Map<String, Value>, forge: Forge) -> Result<()>;

    /// What the caller's own handlers refuse of ITEMS, for the types the
    /// policy routes to them (`native_handlers`).
    fn native_refusals(&self, items: &[Value], routed: &[String]) -> Vec<String>;
}

/// What [`check`] found: every reason for a refusal, in the order found
/// (once or more), the requests as the collector sanitized them, and the
/// patches it accepted.
#[derive(Debug, Clone, PartialEq)]
pub struct Checked {
    pub errors: Vec<String>,
    pub items: Vec<Map<String, Value>>,
    pub patch: Option<PatchInfo>,
    /// The patch of the policy's secondary pull request, in its own
    /// repository.
    pub secondary_patch: Option<PatchInfo>,
}

/// The output type that opens an issue, and the fields of one that act
/// on other issues.
pub const CREATE_ISSUE: &str = "create_issue";
pub const ISSUE_LINKS: &[&str] = &["parent", "blocked_by"];

/// A request's type.
pub fn item_type(item: &Map<String, Value>) -> &str {
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
/// it could make a re-run skip another request, so none may. GitHub's
/// publishing hides the line naming it ([`crate::apply::publish`]).
pub const APPLIED_MARKER: &str = "agentic-job-applied";

fn holds_marker(value: &Value) -> bool {
    match value {
        Value::String(text) => text.to_ascii_lowercase().contains(APPLIED_MARKER),
        Value::Array(values) => values.iter().any(holds_marker),
        Value::Object(map) => map_holds_marker(map),
        _ => false,
    }
}

/// Whether a request holds [`APPLIED_MARKER`], in a key or a value.
pub fn map_holds_marker(map: &Map<String, Value>) -> bool {
    map.iter().any(|(key, value)| {
        key.to_ascii_lowercase().contains(APPLIED_MARKER) || holds_marker(value)
    })
}

/// The policy's secondary pull request, if ITEM is the request for it: a
/// `create_pull_request` whose `repo` is that repository, exactly.
pub fn secondary_target<'a>(
    item: &Map<String, Value>,
    policy: &'a Policy,
) -> Option<&'a Secondary> {
    policy.secondary_pull_request.as_ref().filter(|target| {
        item_type(item) == CREATE_PULL_REQUEST
            && item.get("repo").and_then(Value::as_str) == Some(target.repo.as_str())
    })
}

/// The fields of a request that would take it out of the policy. gh-aw's
/// rules let a request name a repository of its own, and a pull request a
/// base branch and whether it is a draft; whether a handler honours them
/// is the handler's configuration, which this does not see. The policy
/// has fixed all three, so a request that says otherwise is refused.
/// COMMENT is the caller's fixed comment target.
pub fn redirections_to(
    item: &Map<String, Value>,
    policy: &Policy,
    comment: Option<(&str, u64)>,
    publishers: &dyn Publishers,
) -> Vec<String> {
    let output = item_type(item);
    let differs = |key: &str, same: &dyn Fn(&str) -> bool| {
        item.get(key)
            .filter(|value| !value.as_str().is_some_and(same))
            .map(|value| format!("a {output} with {key} {value}, which is not the policy's"))
    };
    // The one request that may name another repository, and then only as
    // the policy writes it, as `run` does: gh-aw's handler compares it so.
    if let Some(target) = secondary_target(item, policy) {
        let mut problems: Vec<String> = differs("base", &|base| base == target.base)
            .into_iter()
            .collect();
        if item
            .get("draft")
            .is_some_and(|draft| draft != &Value::Bool(true))
        {
            problems.push(format!("a {output} that is not a draft"));
        }
        return problems;
    }
    let repo = if matches!(output, "add_comment" | HIDE_COMMENT)
        || REVIEW_THREAD_OUTPUTS.contains(&output)
    {
        comment.map_or(policy.repo.as_str(), |(repo, _)| repo)
    } else {
        &policy.repo
    };
    let mut problems: Vec<String> = differs("repo", &|value| value.eq_ignore_ascii_case(repo))
        .into_iter()
        .collect();
    problems.extend(
        item.keys()
            .filter(|key| policy.forge.refuses_field(key))
            .map(|key| {
                format!(
                    "a {output} with {key}, which this forge cannot resolve: it numbers issues \
                     and pull requests apart"
                )
            }),
    );
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
    if REVIEW_THREAD_OUTPUTS.contains(&output) {
        if output == CREATE_REVIEW_COMMENT
            && policy.forge != Forge::Github
            && let Err(err) = publishers.inline_comment(item, policy.forge)
        {
            problems.push(format!("{err:#}"));
        }
        // On the run's triggering pull request only: apply gives the
        // handlers its number as their target, so a request cannot name
        // another, and the handlers (and apply, for a reply) refuse a
        // comment or thread on any other, which only they can look up.
        // Without a fixed item (`*`) there is no pull request to hold them
        // to; one that is an issue the forge refuses at apply.
        match comment {
            None => problems.push(format!(
                "a {output} needs the run's triggering pull request as its comment target"
            )),
            Some((_, target)) => {
                if let Some(value) = item.get("pull_request_number")
                    && value.as_u64() != Some(target)
                {
                    problems.push(format!(
                        "a {output} with pull_request_number {value}, which is not the run's pull request #{target}"
                    ));
                }
            }
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
    let kind_named;
    let targets: &[&str] = match output {
        "close_pull_request" => &["pull_request_number"],
        "link_sub_issue" => &["parent_issue_number", "sub_issue_number"],
        // GitLab numbers issues and merge requests apart, so a label
        // request names which by its field: exactly one, as another is
        // refused below as an unsupported target.
        "add_labels" | "remove_labels" if policy.forge == Forge::Gitlab => {
            kind_named = [KIND_TARGETS
                .iter()
                .copied()
                .find(|key| item.contains_key(*key))
                .unwrap_or(KIND_TARGETS[0])];
            &kind_named
        }
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
        && item
            .get("labels")
            .and_then(Value::as_array)
            .is_none_or(|labels| labels.is_empty())
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
    // The handler posts the body on the issue, then closes it, so whoever
    // watches the issue learns why; without one it fails in apply instead.
    if output == "close_issue"
        && item
            .get("body")
            .and_then(Value::as_str)
            .is_none_or(|body| body.trim().is_empty())
    {
        problems.push("a close_issue requires a body saying why it is closed".to_owned());
    }
    // Finished or overtaken: `duplicate` would mark an issue a duplicate
    // of nothing, as `duplicate_of`, which names another issue, is refused.
    if output == "close_issue"
        && item
            .get("state_reason")
            .is_some_and(|reason| !matches!(reason.as_str(), Some("completed" | "not_planned")))
    {
        problems.push(format!(
            "a close_issue with state_reason {}, not completed or not_planned",
            item["state_reason"]
        ));
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
pub fn target_key(output: &str) -> Option<&'static str> {
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

/// The name of the patch for a pull request's branch: gh-aw's
/// (`sanitizeForFilename` of `git_patch_utils.cjs`), which its handlers
/// look for.
pub fn patch_file_name(branch: &str) -> String {
    format!("aw-{}.patch", for_file_name(branch))
}

/// The name of the patch for a pull request's branch in the repository
/// REPO that a request names as its `repo`: the name gh-aw's handlers look
/// for first (`getPatchPathForBranchInRepo`), so that the secondary pull
/// request's patch is never taken for the run's own.
pub fn patch_file_name_in(repo: &str, branch: &str) -> String {
    format!("aw-{}-{}.patch", for_file_name(repo), for_file_name(branch))
}

/// Whether NAME is a patch file name `check` takes at all.
pub fn is_patch_file_name(name: &str) -> bool {
    PATCH_FILE_RE.is_match(name)
}

/// How `run` names a run's branch: this, then its identifier.
pub const RUN_BRANCH_PREFIX: &str = "agent-run-";

/// Whether BRANCH is a run's own, as `run` names it (`agent-run-ID`).
pub fn is_run_branch(branch: &str) -> bool {
    branch
        .strip_prefix(RUN_BRANCH_PREFIX)
        .is_some_and(|id| (1..=20).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit()))
}

/// gh-aw's `sanitizeForFilename`.
fn for_file_name(value: &str) -> String {
    static UNSAFE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"[/\\:*?"<>|]"#).expect("a valid pattern"));
    static DASHES_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("-{2,}").expect("a valid pattern"));

    let name = UNSAFE_RE.replace_all(value, "-");
    let name = DASHES_RE.replace_all(&name, "-");
    let name = name.strip_prefix('-').unwrap_or(&name);
    let name = name.strip_suffix('-').unwrap_or(name);
    name.to_lowercase()
}

/// Checks HANDBACK and the collector's result for it against POLICY.
///
/// POLICY must have passed [`Policy::validate`]: what holds a patch to
/// draft pull requests and protected dot-folders is checked there, not
/// again here.
///
/// Whatever is wrong with the hand-back is a refusal, in
/// [`Checked::errors`]. PUBLISHERS says what the caller's publishers
/// refuse. LIFECYCLE is called once, given the request that carries the
/// patch if there is one, for the caller's own checks of its run (a
/// checkpoint, memory), whose refusals fall here in the order.
pub fn check(
    handback: &Handback<'_>,
    mut collected: Collected,
    policy: &Policy,
    trusted: Trusted<'_>,
    publishers: &dyn Publishers,
    mut lifecycle: impl FnMut(Option<&Map<String, Value>>) -> Vec<String>,
) -> Checked {
    let Trusted { comment, run_id } = trusted;
    // Only patches: the caller decides which files a hand-back may hold,
    // and one it misnames is refused here too.
    let mut errors: Vec<String> = handback
        .patches
        .keys()
        .filter(|name| !is_patch_file_name(name))
        .map(|name| format!("unexpected file {name:?}"))
        .collect();
    drop_collectors_incomplete(&mut collected.items);
    if let Some(advisory) = &policy.advisory {
        let checked = (|| -> Result<()> {
            let lines = handback
                .outputs
                .ok_or_else(|| anyhow::anyhow!("advisory requires outputs"))?;
            let text = std::str::from_utf8(lines)?;
            let raw = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(serde_json::from_str)
                .collect::<Result<Vec<Value>, _>>()?;
            advisory.check_items(&raw, crate::advisory::MAX_PROSE_BYTES, false)?;
            let items = collected
                .items
                .iter()
                .cloned()
                .map(Value::Object)
                .collect::<Vec<_>>();
            advisory.check_items(&items, crate::advisory::MAX_PROSE_BYTES, false)?;
            anyhow::ensure!(
                comment == Some((advisory.repo.as_str(), advisory.pull)),
                "advisory check destination differs from policy"
            );
            Ok(())
        })();
        if let Err(error) = checked {
            errors.push(error.to_string());
        }
    }
    // Mending joins nothing to a link's text (`links::repair`), so it
    // makes no secret-shaped string, URL or mention the collector missed.
    for item in &mut collected.items {
        item.values_mut().for_each(links::repair_value);
    }
    let items = if handback.outputs.is_some() {
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
    // A pull request in the secondary repository counts against its own
    // `max`, apart from the run's own: the collector was given their sum.
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    let mut secondary_count = 0;
    for item in &items {
        if secondary_target(item, policy).is_some() {
            secondary_count += 1;
        } else {
            *counts.entry(item_type(item)).or_default() += 1;
        }
    }
    if let Some(target) = &policy.secondary_pull_request
        && secondary_count > target.max
    {
        errors.push(format!(
            "{secondary_count} outputs of type {CREATE_PULL_REQUEST:?} for {}, over {}",
            target.repo, target.max
        ));
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
            .flat_map(|item| redirections_to(item, policy, comment, publishers)),
    );
    if let Some(lines) = handback.outputs {
        errors.extend(check_run_names(lines, policy));
    }
    // What the caller's own handlers would refuse after the session,
    // refused here.
    if !policy.native_handlers.is_empty() {
        let values: Vec<Value> = items.iter().cloned().map(Value::Object).collect();
        errors.extend(publishers.native_refusals(&values, &policy.native_handlers));
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

    let patch_names: Vec<&str> = handback
        .patches
        .keys()
        .copied()
        .filter(|name| is_patch_file_name(name))
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
        .map(|push| push.head.as_str())
        .or_else(|| {
            policy
                .external
                .as_ref()
                .map(|external| external.base_commit.as_str())
        });
    let request = carrier.and_then(|(output, _)| {
        items
            .iter()
            .find(|item| item_type(item) == output && secondary_target(item, policy).is_none())
    });
    if let Some(external) = &policy.external {
        let expected = format!("{RUN_BRANCH_PREFIX}{}", external.run_id);
        if let Some(request) = request
            && request.get("branch").and_then(Value::as_str) != Some(expected.as_str())
        {
            errors.push("external request branch is not the trusted external run's".into());
        }
        // Even a no-op hand-back must not carry a different base snapshot.
        if let Some(content) = handback.base {
            let base = serde_json::from_slice::<Base>(content).ok();
            if !base.is_some_and(|base| {
                base.repo == policy.repo
                    && base.r#ref == policy.base
                    && base.commit == external.base_commit
            }) {
                errors.push("external base.json differs from the trusted dispatch base".into());
            }
        }
    }
    // Its branch names its patch, so that is the run's under the prefix,
    // as `run` writes it: never a name that gh-aw's handler could take for
    // the run's own pull request's patch (`Secondary::branch`). It is this
    // run's, not one an agent could take from an earlier run to push over
    // that run's open pull request, so check must be told which run it is.
    let secondary = policy.secondary_pull_request.as_ref().and_then(|target| {
        let item = items
            .iter()
            .find(|item| secondary_target(item, policy).is_some())?;
        let branch = item
            .get("branch")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if run_id.is_none() {
            errors.push(format!(
                "a {CREATE_PULL_REQUEST} for {} without the run's identifier to hold its \
                 branch to (`check --run-id`)",
                target.repo
            ));
        }
        let own = request.and_then(|item| item.get("branch").and_then(Value::as_str));
        let run_branch = branch
            .strip_prefix(target.branch_prefix.as_str())
            .filter(|run| {
                is_run_branch(run)
                    && own.is_none_or(|own| own == *run)
                    && run_id.is_some_and(|id| run.strip_prefix(RUN_BRANCH_PREFIX) == Some(id))
            });
        if run_branch.is_none() {
            errors.push(format!(
                "a {CREATE_PULL_REQUEST} for {} on branch {branch:?}, which is not the run's \
                 branch under {:?}",
                target.repo, target.branch_prefix
            ));
        }
        Some((target, patch_file_name_in(&target.repo, branch)))
    });
    // The run's own patch is any other: a second one is refused below.
    let patch_names: Vec<&str> = patch_names
        .into_iter()
        .filter(|name| secondary.as_ref().is_none_or(|(_, want)| name != want))
        .collect();
    // Before the replacement's early return: the caller's checks go with
    // either.
    errors.extend(lifecycle(request));
    // The secondary pull request's patch: against its own repository and
    // base, within its own budgets and protected files, by the author the
    // bounds pin for every commit of the run.
    let mut secondary_patch = None;
    match &secondary {
        Some((target, want)) => {
            let base = handback
                .secondary_base
                .and_then(|content| serde_json::from_slice::<Base>(content).ok())
                .filter(|base| COMMIT_RE.is_match(&base.commit))
                .filter(|base| base.repo.eq_ignore_ascii_case(&target.repo))
                .filter(|base| base.r#ref == target.base);
            if base.is_none() {
                errors.push(format!(
                    "{SECONDARY_BASE_FILE} is not {{repo: {}, ref: {}, commit: SHA}}",
                    target.repo, target.base
                ));
            }
            match (handback.patches.get(want.as_str()), base) {
                (Some(content), Some(base)) => {
                    if content.len() as u64 > target.max_patch_bytes {
                        errors.push(format!(
                            "{want} is {} bytes, over {}",
                            content.len(),
                            target.max_patch_bytes
                        ));
                    }
                    let rules = PatchRules {
                        commit_author: policy.commit_author.as_deref(),
                        ..target.rules()
                    };
                    let text = String::from_utf8_lossy(content);
                    let PatchReading { problems, files } = read_patch(&text, &rules, &base.commit);
                    errors.extend(problems.iter().map(|problem| format!("{want}: {problem}")));
                    secondary_patch = Some(PatchInfo {
                        file: want.clone(),
                        bytes: content.len(),
                        base_commit: base.commit,
                        files,
                        commit_files: None,
                    });
                }
                (Some(_), None) => {}
                (None, _) => errors.push(format!(
                    "the {CREATE_PULL_REQUEST} for {} needs its patch, {want}",
                    target.repo
                )),
            }
        }
        None if handback.secondary_base.is_some() => errors.push(format!(
            "{SECONDARY_BASE_FILE} without a {CREATE_PULL_REQUEST} for the policy's secondary \
             repository"
        )),
        None => {}
    }
    let mut patch = None;
    if let Some(content) = handback.replacement {
        if request.is_none() || policy.safe_outputs.push_to_pull_request_branch.is_none() {
            errors.push("a replacement without a push request".into());
        } else if !patch_names.is_empty() || handback.base.is_some() || secondary_patch.is_some() {
            errors.push("a replacement alongside a patch or base.json".into());
        } else if let Some(push) = &policy.safe_outputs.push_to_pull_request_branch {
            match replacement::check(content, push, policy.max_patch_bytes) {
                Ok(info) => patch = Some(info),
                Err(error) => errors.push(format!("replacement: {error}")),
            }
        }
        return Checked {
            errors,
            items,
            patch,
            secondary_patch,
        };
    }
    match (request, carrier) {
        (Some(request), Some((output, rules))) => {
            // The patch is read against any commit base.json names, so that
            // a hand-back refused for its base is told what else is wrong.
            let base = handback
                .base
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
            match (
                patch_names.as_slice(),
                handback.patches.get(want.as_str()),
                base,
            ) {
                ([_], Some(content), Some(base)) => {
                    // Read within the larger of the two patches' budgets.
                    if content.len() as u64 > policy.max_patch_bytes {
                        errors.push(format!(
                            "{want} is {} bytes, over {}",
                            content.len(),
                            policy.max_patch_bytes
                        ));
                    }
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
    Checked {
        errors,
        items,
        patch,
        secondary_patch,
    }
}
