//! Publishing what check accepted to a forge that is not GitHub, from a
//! job of its own that holds the write token: the plan of every write
//! ([`plan`]), the [`Publisher`]s for Forgejo ([`forgejo`]) and GitLab
//! ([`gitlab`]), the push both make ([`git`]), the last-mile filtering
//! of mentions and quick actions ([`mentions`]) and neutral inline
//! comments ([`inline`]). For Forgejo the outputs in [`SUPPORTED`], and
//! for GitLab those in [`GITLAB_SUPPORTED`]. On GitHub, [`publish`]
//! publishes the types the bounds route away from gh-aw's handlers, with
//! GitHub's client and [`Publisher`] ([`github`]).
//!
//! The input is the check job's upload: check's `report.json` and the
//! patch beside it. That upload went through a machine other than the
//! agent's, but apply holds it to the policy again rather than take the
//! report's word: the same counts, types, destinations, marker, handler
//! limits and patch rules check applies, and a patch that is byte for
//! byte the size check reported. Everything is decided before the first
//! write ([`plan`]), and what only the forge can say (an item's kind, a
//! label's ID) is asked before it too ([`Publisher::preflight`]), so a
//! refusal leaves the forge as it was.
//!
//! The caller may also have it set a commit status, after every other
//! write ([`Op::Status`]): its state, commit and link are the caller's,
//! and so is its context ([`Provenance::status_context`]). No request
//! can ask for one.
//!
//! The caller reads the upload ([`Upload::read`], without following a
//! link), and gives the token, where to publish ([`Target`]) and how it
//! names itself ([`Provenance`]); nothing here reads the environment.
//! docs/safe-outputs.md#library-boundary says what stays with the caller.

pub mod forgejo;
pub mod git;
pub mod github;
pub mod gitlab;
pub mod inline;
pub mod mentions;
pub mod publish;
pub mod push;
pub mod replacement;
pub mod roles;
pub mod secondary;
pub mod stack;
/// For tests alone, the library's and its callers', which turn on
/// `test-support` for theirs: a failure there is a test's.
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used)]
pub mod testing;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::check::{self, PatchReading, handler_limits};
use crate::contract::{PatchRules, Policy};
use crate::{
    CREATE_PULL_REQUEST, CREATE_REVIEW_COMMENT, ITEM_NUMBER, KIND_TARGETS, MISSING_DATA, NOOP,
    PUSH_TO_PULL_REQUEST_BRANCH,
};

/// Check's verdict, as the check job uploads it.
pub const REPORT_FILE: &str = "report.json";

pub const ADD_COMMENT: &str = "add_comment";
pub const CREATE_ISSUE: &str = "create_issue";
pub const ADD_LABELS: &str = "add_labels";
pub const REMOVE_LABELS: &str = "remove_labels";
pub const CLOSE_ISSUE: &str = "close_issue";
pub const CLOSE_PULL_REQUEST: &str = "close_pull_request";
const MISSING_TOOL: &str = "missing_tool";

/// What says why a run wrote nothing: the run's status reports it, and
/// apply writes nothing for it.
pub const NO_WRITE: &[&str] = &[NOOP, MISSING_TOOL, MISSING_DATA];

/// What this publishes. Anything else is refused, not left out: a run
/// whose closing or labelling is silently dropped looks done when it is
/// not.
const SUPPORTED: &[&str] = &[
    CREATE_REVIEW_COMMENT,
    ADD_COMMENT,
    CREATE_PULL_REQUEST,
    PUSH_TO_PULL_REQUEST_BRANCH,
    CREATE_ISSUE,
    ADD_LABELS,
    REMOVE_LABELS,
    CLOSE_ISSUE,
    CLOSE_PULL_REQUEST,
    NOOP,
    MISSING_TOOL,
    MISSING_DATA,
];

/// What this publishes to GitLab: all of [`SUPPORTED`]. The others are
/// refused, as there.
const GITLAB_SUPPORTED: &[&str] = &[
    CREATE_REVIEW_COMMENT,
    ADD_COMMENT,
    CREATE_PULL_REQUEST,
    PUSH_TO_PULL_REQUEST_BRANCH,
    CREATE_ISSUE,
    ADD_LABELS,
    REMOVE_LABELS,
    CLOSE_ISSUE,
    CLOSE_PULL_REQUEST,
    NOOP,
    MISSING_TOOL,
    MISSING_DATA,
];

/// The fields apply maps onto Forgejo and GitLab, of those gh-aw's rules
/// let each type hold (`safe-outputs/validation.json`). Another is
/// refused, never dropped: `create_issue`'s `temporary_id`, `parent`,
/// `blocked_by` and `fields` and `close_issue`'s `confidence`,
/// `rationale`, `suggest` and `duplicate_of` would each be left undone.
/// On GitLab the label types name their item by its kind instead
/// ([`GITLAB_LABEL_FIELDS`]).
const FIELDS: &[(&str, &[&str])] = &[
    (CREATE_ISSUE, &["type", "repo", "title", "body", "labels"]),
    (ADD_LABELS, &["type", "repo", "item_number", "labels"]),
    (REMOVE_LABELS, &["type", "repo", "item_number", "labels"]),
    (
        CLOSE_ISSUE,
        &["type", "repo", "issue_number", "body", "state_reason"],
    ),
    (
        CLOSE_PULL_REQUEST,
        &["type", "repo", "pull_request_number", "body"],
    ),
    // The commit's message is the patch's; the others name the policy's
    // pull request and branch, or are refused by check's rules.
    (
        PUSH_TO_PULL_REQUEST_BRANCH,
        &["type", "repo", "pull_request_number", "branch", "message"],
    ),
];

/// The fields of `add_labels` and `remove_labels` on GitLab, which numbers
/// issues and merge requests apart: exactly one of the two targets, never
/// `item_number`, which could be either.
const GITLAB_LABEL_FIELDS: &[&str] = &[
    "type",
    "repo",
    "issue_number",
    "pull_request_number",
    "labels",
];

/// The collector's bounds on a title and a body, in characters
/// (`safe-outputs/validation.json`), held again before the footer.
const MAX_TITLE_CHARS: usize = 128;
const MAX_BODY_CHARS: usize = 65_000;

/// check's own bound on the collector's result, which the report repeats.
const MAX_REPORT_BYTES: u64 = 4 << 20;

/// The longest run link the footer takes.
const MAX_RUN_URL: usize = 2048;

/// A branch git and the forge both take as written, that cannot be read
/// as an option or a path out of `refs/heads/`.
static BRANCH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$").expect("a valid pattern"));

/// A full commit SHA.
pub static COMMIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{40}$").expect("a valid pattern"));

/// What Forgejo reads as a work-in-progress pull request: it has no draft
/// flag, and refuses to merge one whose title starts so (its default
/// `WORK_IN_PROGRESS_PREFIXES`).
pub const DRAFT_PREFIX: &str = "WIP: ";

/// What GitLab reads as a draft merge request, which it will not merge;
/// it has no longer taken `WIP:` since 16.0.
pub const GITLAB_DRAFT_PREFIX: &str = "Draft: ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Forge {
    Forgejo,
    Gitlab,
}

impl Forge {
    pub fn name(self) -> &'static str {
        match self {
            Self::Forgejo => "Forgejo",
            Self::Gitlab => "GitLab",
        }
    }

    /// Its syntax in [`mentions`].
    pub fn syntax(self) -> &'static str {
        match self {
            Self::Forgejo => "forgejo",
            Self::Gitlab => "gitlab",
        }
    }

    fn supported(self) -> &'static [&'static str] {
        match self {
            Self::Forgejo => SUPPORTED,
            Self::Gitlab => GITLAB_SUPPORTED,
        }
    }

    fn draft_prefix(self) -> &'static str {
        match self {
            Self::Forgejo => DRAFT_PREFIX,
            Self::Gitlab => GITLAB_DRAFT_PREFIX,
        }
    }
}

/// A commit status's state: those GitHub and Forgejo both have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum State {
    Pending,
    Success,
    Failure,
    Error,
}

impl State {
    /// Its name in the forge's API.
    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Error => "error",
        }
    }

    /// The status's description: fixed, as nothing a run wrote goes in it.
    pub fn description(self) -> &'static str {
        match self {
            Self::Pending => "The run is in progress",
            Self::Success => "The run succeeded",
            Self::Failure => "The run failed",
            Self::Error => "The run could not finish",
        }
    }
}

/// One write, everything about it decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Inline(inline::InlineComment),
    Comment {
        issue: u64,
        body: String,
    },
    PullRequest(PullRequest),
    Push(BranchPush),
    Issue(NewIssue),
    Labels(LabelChange),
    Close(Close),
    /// The caller's, never a request's.
    Status(CommitStatus),
}

/// One commit on the open pull request's branch the policy names, in the
/// bounds' fork, at the head the run was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchPush {
    /// The policy's pull request.
    pub number: u64,
    /// The bounds' `push_repo`, which the pull request must be from.
    pub push_repo: String,
    /// As [`PullRequest::private`].
    pub private: bool,
    /// The pull request's branch: the policy's `base`.
    pub branch: String,
    /// The policy's pinned head: what the branch must hold, and the commit
    /// check read the patch against.
    pub head: String,
    pub patch: Vec<u8>,
    /// As [`PullRequest::files`].
    pub files: Vec<String>,
    /// As [`PullRequest::committer`].
    pub committer: Committer,
}

/// A commit status with the caller's context, linking the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitStatus {
    pub sha: String,
    pub state: State,
    pub target_url: String,
    /// [`Provenance::status_context`].
    pub context: String,
}

/// Who commits a pushed patch, as git takes it: [`Provenance::committer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committer {
    pub name: String,
    pub email: String,
}

/// What an issue number names. Forgejo numbers issues and pull requests
/// together, so a request for one may name the other; GitLab numbers them
/// apart (`#5` and `!5`), so only the caller can say which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Kind {
    Issue,
    PullRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIssue {
    pub title: String,
    pub body: String,
    /// Names of labels the repository has: never created.
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelChange {
    /// An issue or a pull request.
    pub item: u64,
    /// Which, where the forge numbers the two apart (GitLab): the
    /// request's target field says. None where they share numbers.
    pub kind: Option<Kind>,
    pub add: bool,
    /// Distinct names, as check admitted them, in their own case.
    pub labels: Vec<String>,
}

/// A comment saying why, then the item closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Close {
    pub number: u64,
    pub kind: Kind,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequest {
    pub base: String,
    /// The commit check read the patch against, on `base`.
    pub base_commit: String,
    /// The fork `branch` is pushed to, never the target repository.
    pub push_repo: String,
    /// A private run's: the fork must be private whatever the forge says
    /// of the target.
    pub private: bool,
    pub branch: String,
    pub title: String,
    pub body: String,
    /// Opened as a draft: on Forgejo and GitLab, which have no such flag,
    /// the title says so too ([`DRAFT_PREFIX`], [`GITLAB_DRAFT_PREFIX`]).
    pub draft: bool,
    pub patch: Vec<u8>,
    /// The paths the patch names, as check read them: the only paths the
    /// pushed commit may change.
    pub files: Vec<String>,
    /// The commit's committer; it keeps the patch's author, which check
    /// holds to the bounds' `commit_author`.
    pub committer: Committer,
}

/// What a write made: its page, and what the forge numbers it by, where
/// its answer says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Made {
    pub url: String,
    /// A pull request's number.
    pub number: Option<u64>,
    pub id: Option<u64>,
    pub node_id: Option<String>,
}

impl Made {
    /// What the forge's ANSWER to `METHOD PATH` says was made: refused
    /// without the page it is at.
    pub fn from_answer(answer: &Value, method: &str, path: &str) -> Result<Self> {
        let url = answer["html_url"]
            .as_str()
            .with_context(|| format!("{method} {path}: the response names no html_url"))?;
        Ok(Self {
            url: url.to_owned(),
            number: answer["number"].as_u64(),
            id: answer["id"].as_u64(),
            node_id: answer["node_id"].as_str().map(str::to_owned),
        })
    }
}

/// The writes a forge does for apply. A comment and a pull request return
/// what they made; the others the URL of what they made or changed.
pub trait Publisher {
    fn inline_comment(&self, comment: &inline::InlineComment) -> Result<String> {
        anyhow::bail!(
            "inline comments are not supported for #{}",
            comment.target.number
        )
    }
    /// Refuses OP when what the forge says makes it one apply must not
    /// write (another kind of item, another repository's, a label the
    /// repository lacks), reading only. [`publish`] asks this of every op
    /// before the first write.
    fn preflight(&self, op: &Op) -> Result<()>;

    /// Checks the whole ordered batch before writing. Publishers whose
    /// operations depend on earlier changes may project that state here;
    /// the write methods must still check the live state themselves.
    fn preflight_batch(&self, ops: &[Op]) -> Result<()> {
        for op in ops {
            self.preflight(op)?;
        }
        Ok(())
    }

    fn comment(&self, issue: u64, body: &str) -> Result<Made>;
    /// Pushes the patch to a new branch of the fork and opens a pull
    /// request from it.
    fn open_pull_request(&self, pr: &PullRequest) -> Result<Made>;
    /// Pushes the patch on the pull request's branch, and returns the pull
    /// request's URL.
    fn push_to_branch(&self, push: &BranchPush) -> Result<String>;
    fn create_issue(&self, issue: &NewIssue) -> Result<String>;
    /// Adds the labels the item lacks, or removes those it has; with
    /// nothing to change, writes nothing.
    fn change_labels(&self, change: &LabelChange) -> Result<String>;
    /// Comments and closes; an item closed already gets neither.
    fn close(&self, close: &Close) -> Result<String>;
    fn status(&self, status: &CommitStatus) -> Result<String>;

    /// The numeric ID of the account the credential authenticates as, as
    /// the forge answers, for [`roles::Routed`] to hold to its binding.
    fn actor_id(&self) -> Result<u64> {
        anyhow::bail!("this publisher cannot report its authenticated actor")
    }
}

/// Where the trusted caller has apply publish.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub forge: Forge,
    pub repo: &'a str,
    pub push_repo: Option<&'a str>,
    pub comment_target: Option<u64>,
    pub run_url: &'a str,
    /// The commit status the caller sets, and the commit it is for.
    pub status: Option<(State, &'a str)>,
    pub provenance: Provenance<'a>,
}

/// How the trusted caller names what it publishes: never a request's.
#[derive(Debug, Clone, Copy)]
pub struct Provenance<'a> {
    /// What the footer under every body names, linking the run:
    /// `> Generated by [NAME](RUN_URL)`.
    pub name: &'a str,
    /// The context of every commit status written, so that a branch
    /// protection rule naming it can trust it.
    pub status_context: &'a str,
    /// The committer of a pushed commit, by name and email.
    pub committer: (&'a str, &'a str),
}

impl Provenance<'_> {
    fn committer(&self) -> Committer {
        Committer {
            name: self.committer.0.to_owned(),
            email: self.committer.1.to_owned(),
        }
    }
}

/// The check job's upload, as its caller reads it.
#[derive(Clone, Copy)]
pub struct Upload<'a> {
    /// Where the upload is.
    pub dir: &'a Path,
    /// The content of the regular file at a path, if it is at most the
    /// given bytes: never through a link.
    pub read: &'a dyn Fn(&Path, u64) -> Result<Vec<u8>>,
}

/// What [`check::redirections_to`] asks of the publishers here: whether
/// a neutral inline comment can be published. Off GitHub no type goes to
/// native handlers, and [`plan`] refuses every type it does not publish.
pub(crate) struct Neutral;

impl check::Publishers for Neutral {
    fn inline_comment(&self, item: &Map<String, Value>, forge: crate::Forge) -> Result<()> {
        inline::fields(item, forge)
    }

    fn native_refusals(&self, _: &[Value], _: &[String]) -> Vec<String> {
        Vec::new()
    }
}

/// check's verdict (agentic-job's `check::Verdict`), read back. Unknown
/// fields (warnings, memory) are check's and decide nothing here.
#[derive(Debug, Deserialize)]
pub struct Report {
    #[serde(default)]
    pub inline_target: Option<inline::CheckedTarget>,
    pub ok: bool,
    pub errors: Vec<String>,
    pub items: Vec<Map<String, Value>>,
    pub patch: Option<ReportPatch>,
    /// The policy's secondary pull request's patch, which only GitHub's
    /// apply opens.
    #[serde(default)]
    pub secondary_patch: Option<ReportPatch>,
    #[serde(default)]
    pub checkpoint: Option<Value>,
    /// The run's summary as check sanitized it, for a caller to post.
    #[serde(default)]
    pub run_summary: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReportPatch {
    pub file: String,
    pub bytes: usize,
    pub base_commit: String,
    pub files: Vec<String>,
    #[serde(default)]
    pub commit_files: Option<Value>,
}

/// Decides every write, or refuses with every reason found.
pub fn plan(
    checked: &Upload<'_>,
    policy: &Policy,
    target: &Target<'_>,
) -> Result<Vec<Op>, Vec<String>> {
    let mut errors = Vec::new();
    if !target.repo.eq_ignore_ascii_case(&policy.repo) {
        errors.push(format!(
            "apply publishes to {}, and the policy is for {}",
            target.repo, policy.repo
        ));
    }
    // A policy for GitHub lets through what GitLab reads otherwise, such
    // as an `item_number` that may be an issue's or a merge request's.
    // Forgejo's callers predate the policy's `forge`, and are not held to it.
    if target.forge == Forge::Gitlab && policy.forge != crate::Forge::Gitlab {
        errors.push(format!(
            "apply publishes to GitLab, and the policy is for {:?}",
            policy.forge
        ));
    }
    if let Err(err) = footer(target.provenance.name, target.run_url) {
        errors.push(format!("{err:#}"));
    }
    let report = match read_report(checked) {
        Ok(report) => report,
        Err(err) => {
            errors.push(format!("{err:#}"));
            return Err(errors);
        }
    };
    if !report.ok || !report.errors.is_empty() {
        errors.push("check refused this hand-back".to_owned());
        return Err(errors);
    }

    if report.items.len() > usize::try_from(policy.max_outputs).unwrap_or(usize::MAX) {
        errors.push(format!(
            "{} outputs, over max_outputs {}",
            report.items.len(),
            policy.max_outputs
        ));
    }
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for item in &report.items {
        *counts.entry(check::item_type(item)).or_default() += 1;
    }
    for (output, count) in counts {
        if !target.forge.supported().contains(&output) {
            errors.push(format!(
                "an output of type {output:?}, which apply does not publish to {}",
                target.forge.name()
            ));
        }
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

    let comment = target
        .comment_target
        .map(|number| (policy.repo.as_str(), number));
    let mut ops = Vec::new();
    for item in &report.items {
        let output = check::item_type(item);
        errors.extend(check::redirections_to(item, policy, comment, &Neutral));
        errors.extend(handler_limits::refusals(item));
        if check::map_holds_marker(item) {
            errors.push(format!("a {output} holding the marker apply writes"));
        }
        let text = |key: &str| item.get(key).and_then(Value::as_str);
        match output {
            CREATE_REVIEW_COMMENT => {
                match inline::plan(item, report.inline_target.as_ref(), policy, target) {
                    Ok(comment) => ops.push(Op::Inline(comment)),
                    Err(err) => errors.push(format!("{err:#}")),
                }
            }
            ADD_COMMENT => match (target.comment_target, text("body")) {
                (None, _) => errors.push(
                    "an add_comment, and the caller gave no --comment-target for it".to_owned(),
                ),
                (_, None) => errors.push("an add_comment without a body".to_owned()),
                (Some(issue), Some(body)) => ops.push(Op::Comment {
                    issue,
                    body: with_footer(
                        &mentions::filter(body, target.forge.syntax()),
                        target.provenance.name,
                        target.run_url,
                    ),
                }),
            },
            CREATE_PULL_REQUEST => match pull_request(checked, policy, &report, item, target) {
                Ok(pr) => ops.push(Op::PullRequest(pr)),
                Err(err) => errors.push(format!("{err:#}")),
            },
            PUSH_TO_PULL_REQUEST_BRANCH => {
                match branch_push(checked, policy, &report, item, target) {
                    Ok(push) => ops.push(Op::Push(push)),
                    Err(err) => errors.push(format!("{err:#}")),
                }
            }
            output if NO_WRITE.contains(&output) => {}
            _ => match metadata(item, target) {
                Ok(Some(op)) => ops.push(op),
                Ok(None) => {}
                Err(err) => errors.push(format!("{err:#}")),
            },
        }
    }
    let carriers = [CREATE_PULL_REQUEST, PUSH_TO_PULL_REQUEST_BRANCH];
    let carried = report
        .items
        .iter()
        .any(|item| carriers.contains(&check::item_type(item)));
    if report.patch.is_some() && !carried {
        errors.push(
            "a patch without a create_pull_request or push_to_pull_request_branch".to_owned(),
        );
    }
    // The caller's alone: no request of the run names a commit status.
    if let Some((state, sha)) = target.status {
        if COMMIT_RE.is_match(sha) {
            ops.push(Op::Status(CommitStatus {
                sha: sha.to_owned(),
                state,
                target_url: target.run_url.to_owned(),
                context: target.provenance.status_context.to_owned(),
            }));
        } else {
            errors.push(format!("--status-sha {sha:?} is not a full commit SHA"));
        }
    }
    // A push moves the head the inline comments were checked against, and
    // their anchors with it: refuse both rather than fail halfway.
    let inline: Vec<u64> = ops
        .iter()
        .filter_map(|op| match op {
            Op::Inline(comment) => Some(comment.target.number),
            _ => None,
        })
        .collect();
    for op in &ops {
        if let Op::Push(push) = op
            && inline.contains(&push.number)
        {
            errors.push(format!(
                "a push_to_pull_request_branch and inline comments on #{}: the push moves the head the comments were checked against",
                push.number
            ));
        }
    }
    // The policy has no secondary pull request off GitHub.
    if report.secondary_patch.is_some() {
        errors.push("a secondary pull request off GitHub".to_owned());
    }
    if errors.is_empty() {
        // The pull request first: its push makes the last checks, against
        // the repository (base commit, applied paths, a new branch), and a
        // refusal there is to leave no comment pointing at nothing; a push
        // to a pull request's branch alike. Closing last of the requests,
        // as what a reader is least able to undo, and then the caller's
        // status, which is to say how all of it went.
        ops.sort_by_key(|op| match op {
            Op::PullRequest(_) | Op::Push(_) => 0,
            Op::Issue(_) => 1,
            Op::Comment { .. } | Op::Inline(_) => 2,
            Op::Labels(_) => 3,
            Op::Close(_) => 4,
            Op::Status(_) => 5,
        });
        Ok(ops)
    } else {
        Err(errors)
    }
}

/// Check's report in the upload.
pub fn read_report(checked: &Upload<'_>) -> Result<Report> {
    let path = checked.dir.join(REPORT_FILE);
    let bytes = (checked.read)(&path, MAX_REPORT_BYTES)
        .with_context(|| format!("check's report {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not check's report", path.display()))
}

/// The pull request of `item`, with its patch read again and held to the
/// policy's rules, as check held it.
fn pull_request(
    checked: &Upload<'_>,
    policy: &Policy,
    report: &Report,
    item: &Map<String, Value>,
    target: &Target<'_>,
) -> Result<PullRequest> {
    let push_repo = bound_fork(policy, target, CREATE_PULL_REQUEST)?;
    let text = |key: &str| {
        item.get(key)
            .and_then(Value::as_str)
            .with_context(|| format!("a create_pull_request without a {key}"))
    };
    let (title, body, branch) = (text("title")?, text("body")?, text("branch")?);
    anyhow::ensure!(
        plain_branch(branch) && branch != policy.base,
        "a create_pull_request for branch {branch:?}, which apply does not push"
    );
    // In the target itself, only a run's own branch name, never one its
    // people or other automation use.
    anyhow::ensure!(
        !push_repo.eq_ignore_ascii_case(&policy.repo) || check::is_run_branch(branch),
        "a create_pull_request for branch {branch:?} of {push_repo} itself, which apply \
         pushes only as a run's own {}ID",
        check::RUN_BRANCH_PREFIX
    );
    let pr_rules = policy
        .safe_outputs
        .create_pull_request
        .as_ref()
        .context("a create_pull_request, which the policy does not allow")?;
    let (bytes, base_commit, files) = checked_patch(
        checked,
        policy,
        report,
        CREATE_PULL_REQUEST,
        branch,
        pr_rules.rules(),
    )?;
    // Complete work under `ready_when_complete` opens ready, as on
    // GitHub; anything else a draft.
    let draft = pr_rules.draft && !(pr_rules.ready_when_complete && report.checkpoint.is_none());
    Ok(PullRequest {
        base: policy.base.clone(),
        base_commit,
        push_repo: push_repo.to_owned(),
        private: policy.private,
        branch: branch.to_owned(),
        // GitLab notifies on a title's mentions too, `@all` among them.
        title: format!(
            "{}{}",
            if draft {
                target.forge.draft_prefix()
            } else {
                ""
            },
            mentions::filter(title, target.forge.syntax())
        ),
        body: with_footer(
            &mentions::filter(body, target.forge.syntax()),
            target.provenance.name,
            target.run_url,
        ),
        draft,
        patch: bytes,
        files,
        committer: target.provenance.committer(),
    })
}

/// The push of `item` to the open pull request the policy names, with its
/// patch read again as [`pull_request`]'s is. The pull request, its
/// branch and its head are the policy's, which the policy job read from
/// the forge and held to the bounds' `branches`; none is the hand-back's.
fn branch_push(
    checked: &Upload<'_>,
    policy: &Policy,
    report: &Report,
    item: &Map<String, Value>,
    target: &Target<'_>,
) -> Result<BranchPush> {
    let output = PUSH_TO_PULL_REQUEST_BRANCH;
    let push_repo = bound_fork(policy, target, output)?;
    unmapped(item, output, target.forge)?;
    let push = policy
        .safe_outputs
        .push_to_pull_request_branch
        .as_ref()
        .with_context(|| format!("a {output}, which the policy does not allow"))?;
    // GitHub's apply marks the pull request ready; Forgejo has no draft
    // to take back, and a `WIP:` or `Draft:` title is not apply's to edit.
    anyhow::ensure!(
        !push.ready_when_complete,
        "a {output} under ready_when_complete, which apply does not mark ready on {}",
        target.forge.name()
    );
    let pull = &push.target;
    let number = pull
        .parse::<u64>()
        .ok()
        .filter(|number| *number > 0 && number.to_string() == *pull)
        .with_context(|| format!("the policy's pull request {pull:?} is not a number"))?;
    let branch = &policy.base;
    anyhow::ensure!(
        plain_branch(branch),
        "a {output} to branch {branch:?}, which apply does not push"
    );
    let (patch, base_commit, files) =
        checked_patch(checked, policy, report, output, branch, push.rules())?;
    // check holds base.json to the pinned head too; held here as well, as
    // the push's lease is on it.
    anyhow::ensure!(
        base_commit == push.head,
        "check read the patch against {base_commit}, not the head {} the run was asked for",
        push.head
    );
    Ok(BranchPush {
        number,
        push_repo: push_repo.to_owned(),
        private: policy.private,
        branch: branch.clone(),
        head: base_commit,
        patch,
        files,
        committer: target.provenance.committer(),
    })
}

/// The fork a branch is pushed to: never the target, whose own CI would
/// run it with the target's secrets, and the one the bounds name, not one
/// the caller's command line or the hand-back chose. On GitLab, bounds
/// naming no `push_repo` whose `own-branch-repos` accept the target may
/// have the caller push to the target itself, as GitHub's own-branch
/// pushes ([`push`]): that caller's acceptance of the target's CI.
fn bound_fork<'a>(policy: &Policy, target: &Target<'a>, output: &str) -> Result<&'a str> {
    let missing = || format!("a {output}, and the caller gave no --push-repo for its branch");
    let push_repo = target.push_repo.with_context(missing)?;
    if target.forge == Forge::Gitlab
        && policy.push_repo.is_none()
        && push_repo.eq_ignore_ascii_case(&policy.repo)
    {
        anyhow::ensure!(
            policy.safe_outputs.accepts_own_branches(&policy.repo)?,
            "--push-repo {push_repo} is the target itself, which the caller's own-branch-repos \
             bounds do not accept"
        );
        return Ok(push_repo);
    }
    anyhow::ensure!(
        !owner(push_repo).eq_ignore_ascii_case(owner(&policy.repo)),
        "--push-repo {push_repo} is of the owner of {}; its branch goes to another owner's fork",
        policy.repo
    );
    anyhow::ensure!(
        policy
            .push_repo
            .as_deref()
            .is_some_and(|named| named.eq_ignore_ascii_case(push_repo)),
        "--push-repo {push_repo} is not the push_repo the bounds name ({})",
        policy.push_repo.as_deref().unwrap_or("none")
    );
    Ok(push_repo)
}

/// Whether git and the forge both take BRANCH as written, and neither
/// can read it as an option or a path out of `refs/heads/`.
fn plain_branch(branch: &str) -> bool {
    BRANCH_RE.is_match(branch)
        && !branch.contains("..")
        && !branch.contains("//")
        && !branch.ends_with(['/', '.'])
        && !branch.ends_with(".lock")
}

/// The patch check accepted for OUTPUT's BRANCH, read again and held to
/// RULES and the bounds' `commit_author`, as check held it: its bytes,
/// its base commit and the paths it names.
fn checked_patch(
    checked: &Upload<'_>,
    policy: &Policy,
    report: &Report,
    output: &str,
    branch: &str,
    rules: PatchRules<'_>,
) -> Result<(Vec<u8>, String, Vec<String>)> {
    let patch = report
        .patch
        .as_ref()
        .with_context(|| format!("a {output}, and check accepted no patch"))?;
    anyhow::ensure!(
        patch.commit_files.is_none(),
        "a replacement series, which apply does not push off GitHub"
    );
    let name = check::patch_file_name(branch);
    anyhow::ensure!(
        patch.file == name,
        "check accepted the patch {:?}, and the {output}'s is {name}",
        patch.file
    );
    anyhow::ensure!(
        COMMIT_RE.is_match(&patch.base_commit),
        "check's base commit {:?} is not a commit id",
        patch.base_commit
    );
    // `name` is one plain file name: `patch_file_name` takes out `/`.
    let bytes = (checked.read)(&checked.dir.join(&name), policy.max_patch_bytes)
        .with_context(|| format!("the patch {name}"))?;
    anyhow::ensure!(
        bytes.len() == patch.bytes,
        "the patch {name} is {} bytes, and check read {}",
        bytes.len(),
        patch.bytes
    );
    let rules = PatchRules {
        commit_author: policy.commit_author.as_deref(),
        ..rules
    };
    let PatchReading { problems, files } =
        check::read_patch(&String::from_utf8_lossy(&bytes), &rules, &patch.base_commit);
    anyhow::ensure!(
        problems.is_empty(),
        "the patch {name}: {}",
        problems.join("; ")
    );
    anyhow::ensure!(
        files == patch.files,
        "the patch {name} names other paths than check reported"
    );
    Ok((bytes, patch.base_commit.clone(), files))
}

/// Refuses a field of ITEM, of OUTPUT in [`FIELDS`], that apply does not
/// map onto FORGE.
fn unmapped(item: &Map<String, Value>, output: &str, forge: Forge) -> Result<()> {
    let fields = match output {
        ADD_LABELS | REMOVE_LABELS if forge == Forge::Gitlab => GITLAB_LABEL_FIELDS,
        _ => FIELDS
            .iter()
            .find(|(name, _)| *name == output)
            .map_or(&[][..], |(_, fields)| fields),
    };
    let unmapped: Vec<&str> = item
        .keys()
        .map(String::as_str)
        .filter(|key| !fields.contains(key))
        .collect();
    anyhow::ensure!(
        unmapped.is_empty(),
        "a {output} with {}, which apply does not map onto {}",
        unmapped.join(", "),
        forge.name()
    );
    Ok(())
}

/// The op of an issue, label or close request, its every field mapped or
/// refused, and its text filtered as a comment's is. Its repository,
/// target and labels are held to the policy by
/// [`check::redirections_to`], as every request is; what the forge says
/// of them, by [`Publisher::preflight`]. None for a type with no op.
fn metadata(item: &Map<String, Value>, target: &Target<'_>) -> Result<Option<Op>> {
    let forge = target.forge;
    let output = check::item_type(item);
    if !FIELDS.iter().any(|(name, _)| *name == output) {
        return Ok(None);
    }
    unmapped(item, output, forge)?;
    let required = |key: &str, max: usize| -> Result<&str> {
        let text = item
            .get(key)
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .with_context(|| format!("a {output} without a {key}"))?;
        anyhow::ensure!(
            text.chars().count() <= max,
            "a {output} whose {key} is over {max} characters"
        );
        Ok(text)
    };
    let body = || -> Result<String> {
        let body = required("body", MAX_BODY_CHARS)?;
        Ok(with_footer(
            &mentions::filter(body, forge.syntax()),
            target.provenance.name,
            target.run_url,
        ))
    };
    let number = |key: &str| {
        item.get(key)
            .and_then(Value::as_u64)
            .filter(|number| *number > 0)
            .with_context(|| format!("a {output} without a positive integer {key}"))
    };
    let labels = || -> Result<Vec<String>> {
        let listed = match item.get("labels") {
            None => &[][..],
            Some(Value::Array(listed)) => listed.as_slice(),
            Some(_) => anyhow::bail!("a {output} whose labels are not an array"),
        };
        let mut names: Vec<String> = Vec::new();
        for label in listed {
            let name = label
                .as_str()
                .filter(|name| !name.trim().is_empty())
                .with_context(|| format!("a {output} with label {label}, which is not a name"))?;
            // Only exact repeats: a repository may have `Docs` and `docs`,
            // and the publisher resolves names to labels once each.
            if !names.iter().any(|named| named == name) {
                names.push(name.to_owned());
            }
        }
        Ok(names)
    };
    Ok(Some(match output {
        CREATE_ISSUE => Op::Issue(NewIssue {
            title: mentions::filter(required("title", MAX_TITLE_CHARS)?, forge.syntax()),
            body: body()?,
            labels: labels()?,
        }),
        ADD_LABELS | REMOVE_LABELS => {
            let labels = labels()?;
            anyhow::ensure!(!labels.is_empty(), "a {output} without labels");
            // Forgejo numbers issues and pull requests together; GitLab
            // apart, so there the request names which, and only once.
            let (target, kind) = match forge {
                Forge::Forgejo => (number(ITEM_NUMBER)?, None),
                Forge::Gitlab => {
                    let named: Vec<&str> = KIND_TARGETS
                        .iter()
                        .copied()
                        .filter(|key| item.contains_key(*key))
                        .collect();
                    let [key] = named[..] else {
                        anyhow::bail!(
                            "a {output} on GitLab names its item by exactly one of {}",
                            KIND_TARGETS.join(" and ")
                        );
                    };
                    let kind = if key == KIND_TARGETS[0] {
                        Kind::Issue
                    } else {
                        Kind::PullRequest
                    };
                    (number(key)?, Some(kind))
                }
            };
            Op::Labels(LabelChange {
                item: target,
                kind,
                add: output == ADD_LABELS,
                labels,
            })
        }
        CLOSE_ISSUE => {
            // Neither Forgejo nor GitLab records a reason, so only gh-aw's
            // default means the same there.
            if let Some(reason) = item.get("state_reason") {
                anyhow::ensure!(
                    reason == "completed",
                    "a close_issue with state_reason {reason}, which {} does not record",
                    forge.name()
                );
            }
            Op::Close(Close {
                number: number("issue_number")?,
                kind: Kind::Issue,
                body: body()?,
            })
        }
        CLOSE_PULL_REQUEST => Op::Close(Close {
            number: number("pull_request_number")?,
            kind: Kind::PullRequest,
            body: body()?,
        }),
        _ => anyhow::bail!("a {output}, which apply does not map onto {}", forge.name()),
    }))
}

/// The OWNER of OWNER/NAME.
pub fn owner(repo: &str) -> &str {
    repo.split_once('/').map_or(repo, |(owner, _)| owner)
}

/// gh-aw's footer, adapted: the run a post came from, so that a reader
/// can find its log and what it was asked. The NAME and the link are the
/// caller's ([`Provenance::name`]).
pub fn footer(name: &str, run_url: &str) -> Result<String> {
    let plain = run_url
        .strip_prefix("https://")
        .or_else(|| run_url.strip_prefix("http://"))
        .is_some_and(|rest| !rest.is_empty());
    anyhow::ensure!(
        plain
            && run_url.len() <= MAX_RUN_URL
            && !run_url
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || "()[]<>\"'`".contains(c)),
        "--run-url {run_url:?} is not a plain http(s) link"
    );
    Ok(format!("> Generated by [{name}]({run_url})"))
}

/// BODY with the footer: before its trailer block if it ends in one, so
/// that the block stays its last lines byte for byte (a merger may read
/// `Closes #N` and `Key: value` trailers only there), after it otherwise.
pub fn with_footer(body: &str, name: &str, run_url: &str) -> String {
    // `plan` refuses before any write when the link is not one.
    let footer = footer(name, run_url).unwrap_or_default();
    match trailer_start(body) {
        Some(0) => format!("{footer}\n\n{body}"),
        Some(start) => format!(
            "{}\n\n{footer}\n\n{}",
            body[..start].trim_end(),
            &body[start..]
        ),
        None => format!("{}\n\n{footer}", body.trim_end()),
    }
}

/// A line of a trailer block: a git-style `Key: value` trailer, or a
/// closing keyword with an issue number.
static TRAILER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[A-Za-z0-9][A-Za-z0-9-]*: \S.*|(?i:closes|fixes|resolves) #[0-9]+)$")
        .expect("a valid pattern")
});

/// Where BODY's trailer block starts: the run of trailer lines at its
/// end, with no blank line among them, after a blank line or nothing.
fn trailer_start(body: &str) -> Option<usize> {
    let text = body.trim_end_matches(['\n', '\r']);
    let (mut start, mut end) = (None, text.len());
    loop {
        let line_start = text[..end].rfind('\n').map_or(0, |i| i + 1);
        let line = text[line_start..end].trim_end_matches('\r');
        if !TRAILER_RE.is_match(line) {
            return start.filter(|_| line.trim().is_empty());
        }
        start = Some(line_start);
        if line_start == 0 {
            return start;
        }
        end = line_start - 1;
    }
}

/// Asks the forge about every op, then makes the writes in order. A
/// failure after the first write names what was already made, so that
/// whoever runs it again knows.
pub fn publish(ops: &[Op], publisher: &dyn Publisher) -> Result<Vec<String>> {
    publisher.preflight_batch(ops)?;
    let mut made = Vec::new();
    for op in ops {
        let url = match op {
            Op::Inline(comment) => publisher.inline_comment(comment),
            Op::Comment { issue, body } => publisher.comment(*issue, body).map(|made| made.url),
            Op::PullRequest(pr) => publisher.open_pull_request(pr).map(|made| made.url),
            Op::Push(push) => publisher.push_to_branch(push),
            Op::Issue(issue) => publisher.create_issue(issue),
            Op::Labels(change) => publisher.change_labels(change),
            Op::Close(close) => publisher.close(close),
            Op::Status(status) => publisher.status(status),
        };
        match url {
            Ok(url) => made.push(url),
            Err(err) if made.is_empty() => return Err(err),
            Err(err) => {
                return Err(err.context(format!("after publishing {}", made.join(", "))));
            }
        }
    }
    Ok(made)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use serde_json::json;

    use super::*;
    use crate::check::BASE_COMMIT_HEADER;
    use crate::check::fixtures::HEAD;
    use crate::contract::OutputLimit;

    const BASE: &str = "1111111111111111111111111111111111111111";
    const BRANCH: &str = "agent-run-7";
    const PATCH_NAME: &str = "aw-agent-run-7.patch";
    const RUN: &str = "https://forge.example/o/r/actions/runs/7";
    const PUSH_REPO: &str = "bot/bootc";

    /// The caller's no-follow read, as far as these tests need it.
    pub(super) fn read(path: &Path, max: u64) -> Result<Vec<u8>> {
        let metadata = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(
            metadata.is_file(),
            "{} is not a regular file",
            path.display()
        );
        anyhow::ensure!(
            metadata.len() <= max,
            "{} is over {max} bytes",
            path.display()
        );
        Ok(std::fs::read(path)?)
    }

    pub(super) fn upload(dir: &Path) -> Upload<'_> {
        Upload { dir, read: &read }
    }

    /// The collector's configuration for POLICY, as agentic-job's
    /// `collect::config` makes it for a policy without a secondary pull
    /// request.
    pub(super) fn collector_config(policy: &Policy) -> Map<String, Value> {
        let Value::Object(config) = serde_json::to_value(&policy.safe_outputs).unwrap() else {
            panic!("the policy's safe_outputs is not an object");
        };
        config
    }

    pub(super) fn policy() -> Policy {
        let mut policy = crate::check::fixtures::policy();
        policy.push_repo = Some(PUSH_REPO.to_owned());
        let labels = OutputLimit {
            max: 2,
            allowed: Some(vec!["triage".to_owned(), "bug".to_owned()]),
            blocked: vec!["release".to_owned()],
            ..OutputLimit::default()
        };
        for (output, limit) in [
            (ADD_COMMENT, OutputLimit::default()),
            (CREATE_ISSUE, OutputLimit::default()),
            (CLOSE_ISSUE, OutputLimit::default()),
            (CLOSE_PULL_REQUEST, OutputLimit::default()),
            (ADD_LABELS, labels.clone()),
            (REMOVE_LABELS, labels),
            (NOOP, OutputLimit::default()),
            (MISSING_TOOL, OutputLimit::default()),
            (MISSING_DATA, OutputLimit::default()),
        ] {
            policy
                .safe_outputs
                .others
                .insert(output.to_owned(), OutputLimit { max: 1, ..limit });
        }
        policy.max_outputs = 20;
        policy
    }

    fn patch() -> String {
        format!(
            "From 2222222222222222222222222222222222222222 Mon Sep 17 00:00:00 2001\n\
             {BASE_COMMIT_HEADER}: {BASE}\n\
             From: agent <agent@localhost>\n\
             Date: Tue, 6 Oct 2026 21:02:35 -0400\n\
             Subject: [PATCH] Change things\n\
             \n\
             ---\n \
             src/x | 1 +\n\
             \n\
             diff --git a/src/x b/src/x\nnew file mode 100644\nindex 0000000..587be6b\n\
             --- /dev/null\n+++ b/src/x\n@@ -0,0 +1 @@\n+x\n"
        )
    }

    fn pull_request_item() -> Value {
        json!({"type": "create_pull_request", "title": "Fix it", "body": "Why.", "branch": BRANCH})
    }

    fn comment_item() -> Value {
        json!({"type": "add_comment", "body": "Done."})
    }

    const REPO: &str = "bootc-dev/bootc";

    fn issue_item() -> Value {
        json!({"type": CREATE_ISSUE, "repo": REPO, "title": "Flaky @user test",
            "body": "It fails, says @user.", "labels": ["bug", "BUG"]})
    }

    fn labels_item(output: &str) -> Value {
        json!({"type": output, "repo": REPO, "item_number": 5, "labels": ["triage"]})
    }

    fn close_item() -> Value {
        json!({"type": CLOSE_ISSUE, "repo": REPO, "issue_number": 6,
            "state_reason": "completed", "body": "Fixed by !9.\n\nCloses #6"})
    }

    fn close_pull_request_item() -> Value {
        json!({"type": CLOSE_PULL_REQUEST, "repo": REPO, "pull_request_number": 7,
            "body": "Superseded."})
    }

    /// Every type apply maps, in the order it writes them, and the ones
    /// that write nothing.
    #[test]
    fn metadata() {
        let dir = checked(&[
            close_item(),
            close_pull_request_item(),
            labels_item(REMOVE_LABELS),
            labels_item(ADD_LABELS),
            json!({"type": NOOP, "message": "Nothing else."}),
            json!({"type": MISSING_DATA, "reason": "No logs."}),
            json!({"type": MISSING_TOOL, "reason": "No browser."}),
            comment_item(),
            issue_item(),
            pull_request_item(),
        ]);
        let ops = plan(&upload(dir.path()), &policy(), &target(Some(64))).unwrap();
        let footer = format!("> Generated by [example-ci]({RUN})");
        let labels = |add| {
            Op::Labels(LabelChange {
                item: 5,
                kind: None,
                add,
                labels: vec!["triage".to_owned()],
            })
        };
        assert!(matches!(ops[0], Op::PullRequest(_)), "{ops:?}");
        assert_eq!(
            ops[1..],
            [
                Op::Issue(NewIssue {
                    title: "Flaky @\u{200b}user test".to_owned(),
                    body: format!("It fails, says @\u{200b}user.\n\n{footer}"),
                    labels: vec!["bug".to_owned(), "BUG".to_owned()],
                }),
                Op::Comment {
                    issue: 64,
                    body: format!("Done.\n\n{footer}")
                },
                labels(false),
                labels(true),
                // The footer before the trailer, and the reference filtered.
                Op::Close(Close {
                    number: 6,
                    kind: Kind::Issue,
                    body: format!("Fixed by !\u{200b}9.\n\n{footer}\n\nCloses #6"),
                }),
                Op::Close(Close {
                    number: 7,
                    kind: Kind::PullRequest,
                    body: format!("Superseded.\n\n{footer}"),
                }),
            ]
        );
        // A hand-back of no-write outcomes alone writes nothing.
        let dir = checked(&[json!({"type": NOOP, "message": "Nothing to do."})]);
        assert_eq!(
            plan(&upload(dir.path()), &policy(), &target(None)).unwrap(),
            []
        );
    }

    /// A checked upload of `items`, with the patch check would report.
    pub(super) fn checked(items: &[Value]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let patch = patch();
        std::fs::write(dir.path().join(PATCH_NAME), &patch).unwrap();
        let carried = items.iter().any(|i| i["type"] == CREATE_PULL_REQUEST);
        let report = json!({
            "ok": true,
            "errors": [],
            "items": items,
            "patch": carried.then(|| json!({
                "file": PATCH_NAME, "bytes": patch.len(), "base_commit": BASE, "files": ["src/x"],
            })),
        });
        std::fs::write(dir.path().join(REPORT_FILE), report.to_string()).unwrap();
        dir
    }

    /// A caller other than agentic-job, so that nothing of its own is
    /// left in what is planned.
    pub(super) const PROVENANCE: Provenance<'static> = Provenance {
        name: "example-ci",
        status_context: "example-ci/apply",
        committer: ("example-ci", "ci@example.invalid"),
    };

    pub(super) fn target(comment_target: Option<u64>) -> Target<'static> {
        Target {
            forge: Forge::Forgejo,
            repo: "bootc-dev/bootc",
            push_repo: Some(PUSH_REPO),
            comment_target,
            run_url: RUN,
            status: None,
            provenance: PROVENANCE,
        }
    }

    /// A run on GitLab, under a policy for GitLab.
    fn on_gitlab(_: &Path, policy: &mut Policy, target: &mut Target<'static>) {
        policy.forge = crate::Forge::Gitlab;
        target.forge = Forge::Gitlab;
    }

    /// On GitLab, bounds naming no fork whose `own-branch-repos` accept
    /// the target let the caller push a run's branch to the target itself,
    /// with every other rule unchanged; nothing else does.
    #[test]
    fn own_branches_on_gitlab() {
        let own = |policy: &mut Policy, target: &mut Target<'static>| {
            policy.push_repo = None;
            policy.safe_outputs.own_branch_repos = vec![vec!["Bootc-Dev/*".to_owned()]];
            target.push_repo = Some("bootc-dev/bootc");
        };
        let not_accepted = "is the target itself, which the caller's own-branch-repos bounds \
                            do not accept";
        type Change = fn(&mut Policy, &mut Target<'static>);
        let cases: &[(&str, Change, &str)] = &[
            (BRANCH, |_, _| {}, ""),
            (
                BRANCH,
                |policy, _| policy.safe_outputs.own_branch_repos.clear(),
                not_accepted,
            ),
            (
                BRANCH,
                |policy, _| policy.safe_outputs.own_branch_repos = vec![vec!["other/*".into()]],
                not_accepted,
            ),
            // Another file's patterns must accept it too.
            (
                BRANCH,
                |policy, _| {
                    policy
                        .safe_outputs
                        .own_branch_repos
                        .push(vec!["other/*".into()]);
                },
                not_accepted,
            ),
            (
                "fix-it",
                |_, _| {},
                "pushes only as a run's own agent-run-ID",
            ),
            (
                BRANCH,
                |policy, _| policy.push_repo = Some(PUSH_REPO.to_owned()),
                "is of the owner of bootc-dev/bootc",
            ),
            (
                BRANCH,
                |policy, target| {
                    policy.forge = crate::Forge::Forgejo;
                    target.forge = Forge::Forgejo;
                },
                "is of the owner of bootc-dev/bootc",
            ),
        ];
        for (branch, change, want) in cases {
            let dir = checked(&[
                json!({"type": "create_pull_request", "title": "Fix it", "body": "Why.", "branch": branch}),
            ]);
            let (mut policy, mut target) = (policy(), target(None));
            on_gitlab(dir.path(), &mut policy, &mut target);
            own(&mut policy, &mut target);
            change(&mut policy, &mut target);
            match plan(&upload(dir.path()), &policy, &target) {
                Ok(ops) if want.is_empty() => {
                    let Op::PullRequest(pr) = &ops[0] else {
                        panic!("{ops:?}")
                    };
                    assert_eq!(pr.push_repo, "bootc-dev/bootc");
                    assert_eq!(pr.title, "Draft: Fix it");
                }
                Err(errors) if !want.is_empty() => {
                    assert!(errors.join(";").contains(want), "{want}: {errors:?}")
                }
                other => panic!("{branch} {want:?}: {other:?}"),
            }
        }
        // A push to the policy's merge request in the target itself.
        let dir = checked_push(&[push_item()]);
        let (mut policy, mut target) = (push_policy(), target(None));
        on_gitlab(dir.path(), &mut policy, &mut target);
        own(&mut policy, &mut target);
        let ops = plan(&upload(dir.path()), &policy, &target).unwrap();
        let Op::Push(push) = &ops[0] else {
            panic!("{ops:?}")
        };
        assert_eq!(push.push_repo, "bootc-dev/bootc");
    }

    /// On GitLab a draft is a `Draft:` title, and no line of a body runs a
    /// quick action.
    #[test]
    fn accepted_on_gitlab() {
        let body = "Why.\n/merge\n/assign @all";
        let dir = checked(&[
            json!({"type": "add_comment", "body": body}),
            json!({"type": "create_pull_request", "title": "Fix it @all", "body": body, "branch": BRANCH}),
        ]);
        let (mut policy, mut target) = (policy(), target(Some(64)));
        on_gitlab(dir.path(), &mut policy, &mut target);
        let ops = plan(&upload(dir.path()), &policy, &target).unwrap();
        let want = format!(
            "Why.\n\u{200b}/merge\n\u{200b}/assign @\u{200b}all\n\n> Generated by [example-ci]({RUN})"
        );
        let Op::PullRequest(pr) = &ops[0] else {
            panic!("{ops:?}")
        };
        assert_eq!(pr.title, "Draft: Fix it @\u{200b}all");
        assert_eq!(pr.body, want);
        assert_eq!(
            ops[1],
            Op::Comment {
                issue: 64,
                body: want
            }
        );
    }

    /// On GitLab a label request's item is of the kind its field names,
    /// and every title and body has its mentions and quick actions broken.
    #[test]
    fn metadata_on_gitlab() {
        let text = "Done. @all\n/close\n  /label ~release";
        let dir = checked(&[
            json!({"type": ADD_LABELS, "repo": REPO, "issue_number": 5, "labels": ["triage"]}),
            json!({"type": REMOVE_LABELS, "repo": REPO, "pull_request_number": 5,
                "labels": ["bug"]}),
            json!({"type": CREATE_ISSUE, "repo": REPO, "title": "/close @here", "body": text}),
            json!({"type": CLOSE_ISSUE, "repo": REPO, "issue_number": 5, "body": text}),
            json!({"type": CLOSE_PULL_REQUEST, "repo": REPO, "pull_request_number": 5,
                "body": text}),
            json!({"type": NOOP, "message": "Nothing else."}),
        ]);
        let (mut policy, mut target) = (policy(), target(None));
        on_gitlab(dir.path(), &mut policy, &mut target);
        let ops = plan(&upload(dir.path()), &policy, &target).unwrap();
        let body = format!(
            "Done. @\u{200b}all\n\u{200b}/close\n  \u{200b}/label ~release\n\n> Generated by [example-ci]({RUN})"
        );
        let change = |kind, add, label: &str| {
            Op::Labels(LabelChange {
                item: 5,
                kind: Some(kind),
                add,
                labels: vec![label.to_owned()],
            })
        };
        let close = |kind| {
            Op::Close(Close {
                number: 5,
                kind,
                body: body.clone(),
            })
        };
        assert_eq!(
            ops,
            [
                Op::Issue(NewIssue {
                    title: "\u{200b}/close @\u{200b}here".to_owned(),
                    body: body.clone(),
                    labels: vec![],
                }),
                change(Kind::Issue, true, "triage"),
                change(Kind::PullRequest, false, "bug"),
                close(Kind::Issue),
                close(Kind::PullRequest),
            ]
        );
        // No-write outcomes alone stay no-write on GitLab too.
        let dir = checked(&[
            json!({"type": NOOP, "message": "Nothing to do."}),
            json!({"type": MISSING_DATA, "reason": "No logs."}),
        ]);
        assert_eq!(plan(&upload(dir.path()), &policy, &target).unwrap(), []);
    }

    #[test]
    fn filters_every_planned_body() {
        let mut items = [
            comment_item(),
            pull_request_item(),
            issue_item(),
            close_item(),
            close_pull_request_item(),
        ];
        for item in &mut items {
            item["body"] = json!("@user @org/team !12 `@code` user@example.com");
        }
        let dir = checked(&items);
        let ops = plan(&upload(dir.path()), &policy(), &target(Some(64))).unwrap();
        assert_eq!(ops.len(), items.len());
        for op in ops {
            let body = match op {
                Op::Comment { body, .. } => body,
                Op::PullRequest(pr) => pr.body,
                Op::Issue(issue) => issue.body,
                Op::Close(close) => close.body,
                Op::Inline(comment) => comment.body,
                Op::Labels(_) | Op::Push(_) | Op::Status(_) => unreachable!(),
            };
            assert!(body.starts_with(
                "@\u{200b}user @\u{200b}org/team !\u{200b}12 `@code` user@example.com"
            ));
        }
    }

    #[test]
    fn accepted() {
        let dir = checked(&[comment_item(), pull_request_item()]);
        let ops = plan(&upload(dir.path()), &policy(), &target(Some(64))).unwrap();
        let footer = format!("\n\n> Generated by [example-ci]({RUN})");
        assert_eq!(
            ops[1],
            Op::Comment {
                issue: 64,
                body: format!("Done.{footer}")
            }
        );
        let Op::PullRequest(pr) = &ops[0] else {
            panic!("{ops:?}")
        };
        assert_eq!(pr.title, "WIP: Fix it");
        assert_eq!(pr.body, format!("Why.{footer}"));
        assert_eq!((pr.base.as_str(), pr.branch.as_str()), ("main", BRANCH));
        assert_eq!(pr.base_commit, BASE);
        assert_eq!(pr.push_repo, PUSH_REPO);
        assert_eq!(pr.patch, patch().into_bytes());
        assert_eq!(pr.files, ["src/x"]);
        assert_eq!(pr.committer, PROVENANCE.committer());
    }

    /// The footer goes before a trailer block at the end of a body, which
    /// stays its last lines byte for byte, and after the body otherwise.
    #[test]
    fn footer_placement() {
        let footer = format!("> Generated by [example-ci]({RUN})");
        let generated = "Generated-by: https://github.com/cgwalters/#llms";
        let cases = [
            ("Why.", format!("Why.\n\n{footer}")),
            ("Why.\n\n", format!("Why.\n\n{footer}")),
            (
                "Why.\n\nCloses #5",
                format!("Why.\n\n{footer}\n\nCloses #5"),
            ),
            (
                &format!("Why.\n\n{generated}\nCloses #5") as &str,
                format!("Why.\n\n{footer}\n\n{generated}\nCloses #5"),
            ),
            (
                "Why.\n\nfixes #5\nRESOLVES #6\n",
                format!("Why.\n\n{footer}\n\nfixes #5\nRESOLVES #6\n"),
            ),
            ("Closes #5", format!("{footer}\n\nCloses #5")),
            // Not at the end, or not after a blank line: not a block.
            (
                "Closes #5\n\nWhy.",
                format!("Closes #5\n\nWhy.\n\n{footer}"),
            ),
            ("Why.\nCloses #5", format!("Why.\nCloses #5\n\n{footer}")),
            (
                "Why.\n\nCloses #5\n\nThen.",
                format!("Why.\n\nCloses #5\n\nThen.\n\n{footer}"),
            ),
            (
                "Why.\n\nCloses #5\nsee https://x",
                format!("Why.\n\nCloses #5\nsee https://x\n\n{footer}"),
            ),
            (
                "Why.\n\nCloses #5 too",
                format!("Why.\n\nCloses #5 too\n\n{footer}"),
            ),
        ];
        for (body, want) in cases {
            assert_eq!(with_footer(body, PROVENANCE.name, RUN), want, "{body:?}");
        }

        // A pull request's body and a comment's alike.
        let body = format!("Why.\n\n{generated}\nCloses #5");
        let dir = checked(&[
            json!({"type": "add_comment", "body": body}),
            json!({"type": "create_pull_request", "title": "Fix it", "body": body, "branch": BRANCH}),
        ]);
        let ops = plan(&upload(dir.path()), &policy(), &target(Some(64))).unwrap();
        let tail = format!("\n\n{footer}\n\n{generated}\nCloses #5");
        let Op::PullRequest(pr) = &ops[0] else {
            panic!("{ops:?}")
        };
        assert_eq!(pr.body, format!("Why.{tail}"));
        assert_eq!(pr.body.lines().last(), Some("Closes #5"));
        assert_eq!(
            ops[1],
            Op::Comment {
                issue: 64,
                body: format!("Why.{tail}")
            }
        );
    }

    /// Every refusal is decided before any write, and names its reason.
    #[test]
    fn refusals() {
        type Change = fn(&Path, &mut Policy, &mut Target<'static>);
        let none: Change = |_, _, _| {};
        let cases: &[(&[Value], Change, &str)] = &[
            (
                &[json!({"type": "update_issue", "issue_number": 5, "body": "x"})],
                none,
                "\"update_issue\", which apply does not publish",
            ),
            (
                &[json!({"type": NOOP, "message": "x"})],
                |_, policy, _| {
                    policy.safe_outputs.others.remove(NOOP);
                },
                "\"noop\", which the policy does not allow",
            ),
            (
                &[labels_item(ADD_LABELS), labels_item(ADD_LABELS)],
                none,
                "2 outputs of type \"add_labels\", over 1",
            ),
            // Fields with no Forgejo meaning are refused, not dropped.
            (
                &[
                    json!({"type": CREATE_ISSUE, "title": "t", "body": "b", "temporary_id": "aw_x1"}),
                ],
                none,
                "a create_issue with temporary_id, which apply does not map onto Forgejo",
            ),
            (
                &[json!({"type": CREATE_ISSUE, "title": "t", "body": "b", "fields": [{"a": 1}]})],
                none,
                "a create_issue with fields, which apply does not map",
            ),
            (
                &[
                    json!({"type": CLOSE_ISSUE, "repo": REPO, "issue_number": 6, "body": "b",
                    "confidence": "HIGH", "rationale": "r"}),
                ],
                none,
                "a close_issue with confidence, rationale, which apply does not map",
            ),
            (
                &[
                    json!({"type": CLOSE_ISSUE, "repo": REPO, "issue_number": 6, "body": "b",
                    "state_reason": "not_planned"}),
                ],
                none,
                "state_reason \"not_planned\", which Forgejo does not record",
            ),
            // Targets: the policy's repository, named explicitly, by the
            // field of the item's kind.
            (
                &[json!({"type": CLOSE_ISSUE, "issue_number": 6, "body": "b"})],
                none,
                "a close_issue requires the policy's explicit repo",
            ),
            (
                &[
                    json!({"type": CLOSE_ISSUE, "repo": "other/repo", "issue_number": 6, "body": "b"}),
                ],
                none,
                "a close_issue with repo \"other/repo\", which is not the policy's",
            ),
            (
                &[json!({"type": CREATE_ISSUE, "repo": "other/repo", "title": "t", "body": "b"})],
                none,
                "a create_issue with repo \"other/repo\", which is not the policy's",
            ),
            (
                &[
                    json!({"type": CLOSE_PULL_REQUEST, "repo": REPO, "issue_number": 7, "body": "b"}),
                ],
                none,
                "a close_pull_request requires a positive integer pull_request_number",
            ),
            (
                &[json!({"type": ADD_LABELS, "repo": REPO, "labels": ["triage"]})],
                none,
                "a add_labels requires a positive integer item_number",
            ),
            (
                &[json!({"type": CLOSE_ISSUE, "repo": REPO, "issue_number": 6, "body": " "})],
                none,
                "a close_issue without a body",
            ),
            // Labels: the policy's lists, counts and shapes.
            (
                &[
                    json!({"type": ADD_LABELS, "repo": REPO, "item_number": 5, "labels": ["release"]}),
                ],
                none,
                "label \"release\", outside the policy's label limits",
            ),
            (
                &[
                    json!({"type": REMOVE_LABELS, "repo": REPO, "item_number": 5, "labels": ["wontfix"]}),
                ],
                none,
                "label \"wontfix\", outside the policy's label limits",
            ),
            (
                &[json!({"type": ADD_LABELS, "repo": REPO, "item_number": 5,
                    "labels": ["triage", "bug", "triage"]})],
                none,
                "exceeding the per-request label limit",
            ),
            (
                &[json!({"type": ADD_LABELS, "repo": REPO, "item_number": 5, "labels": []})],
                none,
                "a add_labels without labels",
            ),
            (
                &[json!({"type": CREATE_ISSUE, "title": "t", "body": "b", "labels": [7]})],
                none,
                "a create_issue with label 7, which is not a name",
            ),
            // Text bounds, before the footer.
            (
                &[json!({"type": CREATE_ISSUE, "title": "t".repeat(129), "body": "b"})],
                none,
                "a create_issue whose title is over 128 characters",
            ),
            (
                &[
                    json!({"type": CLOSE_PULL_REQUEST, "repo": REPO, "pull_request_number": 7,
                    "body": "é".repeat(65_001)}),
                ],
                none,
                "a close_pull_request whose body is over 65000 characters",
            ),
            (
                &[json!({"type": CREATE_ISSUE, "title": "t"})],
                none,
                "a create_issue without a body",
            ),
            (
                &[
                    json!({"type": CREATE_ISSUE, "title": "t", "body": "<!-- agentic-job-applied: 1 -->"}),
                ],
                none,
                "a create_issue holding the marker",
            ),
            (
                &[comment_item(), comment_item()],
                none,
                "2 outputs of type \"add_comment\", over 1",
            ),
            (
                &[comment_item()],
                |_, policy, _| {
                    policy.safe_outputs.others.remove(ADD_COMMENT);
                },
                "which the policy does not allow",
            ),
            (
                &[comment_item(), pull_request_item()],
                |_, policy, _| policy.max_outputs = 1,
                "2 outputs, over max_outputs 1",
            ),
            (
                &[comment_item()],
                |_, _, target| target.comment_target = None,
                "no --comment-target",
            ),
            (
                &[json!({"type": "add_comment", "body": "x", "item_number": 65})],
                none,
                "outside the caller's fixed item",
            ),
            (
                &[json!({"type": "add_comment", "body": "x", "repo": "other/repo"})],
                none,
                "which is not the policy's",
            ),
            (
                &[json!({"type": "add_comment", "body": "<!-- agentic-job-applied: 1/0/0 -->"})],
                none,
                "holding the marker",
            ),
            (
                &[json!({"type": "add_comment", "body": "https://a ".repeat(51)})],
                none,
                "E008",
            ),
            (
                &[comment_item()],
                |_, _, target| target.repo = "bootc-dev/other",
                "the policy is for bootc-dev/bootc",
            ),
            (
                &[comment_item()],
                |_, _, target| target.run_url = "javascript:alert(1)",
                "not a plain http(s) link",
            ),
            // GitLab: a GitLab policy, labels on an item of a named kind.
            (
                &[comment_item()],
                |_, _, target| target.forge = Forge::Gitlab,
                "apply publishes to GitLab, and the policy is for Github",
            ),
            (
                &[labels_item(ADD_LABELS)],
                on_gitlab,
                "a add_labels with item_number, which this forge cannot resolve",
            ),
            (
                &[labels_item(REMOVE_LABELS)],
                on_gitlab,
                "a remove_labels with item_number, which apply does not map onto GitLab",
            ),
            (
                &[json!({"type": ADD_LABELS, "repo": REPO, "issue_number": 5,
                    "pull_request_number": 5, "labels": ["triage"]})],
                on_gitlab,
                "a add_labels on GitLab names its item by exactly one of issue_number and pull_request_number",
            ),
            (
                &[json!({"type": ADD_LABELS, "repo": REPO, "labels": ["triage"]})],
                on_gitlab,
                "a add_labels on GitLab names its item by exactly one of",
            ),
            (
                &[
                    json!({"type": ADD_LABELS, "repo": "other/repo", "pull_request_number": 5,
                    "labels": ["triage"]}),
                ],
                on_gitlab,
                "a add_labels with repo \"other/repo\", which is not the policy's",
            ),
            (
                &[
                    json!({"type": ADD_LABELS, "repo": REPO, "pull_request_number": 5,
                    "labels": ["release"]}),
                ],
                on_gitlab,
                "label \"release\", outside the policy's label limits",
            ),
            (
                &[
                    json!({"type": REMOVE_LABELS, "repo": REPO, "issue_number": 5, "labels": ["triage"]}),
                    json!({"type": REMOVE_LABELS, "repo": REPO, "pull_request_number": 5, "labels": ["triage"]}),
                ],
                on_gitlab,
                "2 outputs of type \"remove_labels\", over 1",
            ),
            (
                &[
                    json!({"type": CLOSE_ISSUE, "repo": REPO, "issue_number": 6, "body": "b",
                    "state_reason": "not_planned"}),
                ],
                on_gitlab,
                "state_reason \"not_planned\", which GitLab does not record",
            ),
            (
                &[comment_item()],
                |_, _, target| target.run_url = "https://x/) [y](https://z",
                "not a plain http(s) link",
            ),
            (
                &[comment_item()],
                |dir, _, _| {
                    let report = json!({"ok": false, "errors": ["no"], "items": []});
                    std::fs::write(dir.join(REPORT_FILE), report.to_string()).unwrap();
                },
                "check refused",
            ),
            (
                &[comment_item()],
                |dir, _, _| std::fs::remove_file(dir.join(REPORT_FILE)).unwrap(),
                "check's report",
            ),
            (
                &[pull_request_item()],
                |dir, _, _| {
                    let path = dir.join(PATCH_NAME);
                    std::fs::write(&path, patch() + "+z\n").unwrap();
                },
                "bytes, and check read",
            ),
            (
                &[pull_request_item()],
                |dir, _, _| {
                    let path = dir.join(PATCH_NAME);
                    std::fs::rename(&path, dir.join("elsewhere")).unwrap();
                    std::os::unix::fs::symlink(dir.join("elsewhere"), &path).unwrap();
                },
                "is not a regular file",
            ),
            (
                &[pull_request_item()],
                |dir, _, _| {
                    let protected = patch().replace("src/x", ".github/workflows/x.yml");
                    std::fs::write(dir.join(PATCH_NAME), &protected).unwrap();
                    let mut report: Value =
                        serde_json::from_slice(&std::fs::read(dir.join(REPORT_FILE)).unwrap())
                            .unwrap();
                    report["patch"]["bytes"] = protected.len().into();
                    report["patch"]["files"] = json!([".github/workflows/x.yml"]);
                    std::fs::write(dir.join(REPORT_FILE), report.to_string()).unwrap();
                },
                "the patch aw-agent-run-7.patch: ",
            ),
            (
                &[
                    json!({"type": "create_pull_request", "title": "t", "body": "b", "branch": "--upload-pack=x"}),
                ],
                none,
                "which apply does not push",
            ),
            (
                &[
                    json!({"type": "create_pull_request", "title": "t", "body": "b", "branch": "a/../b"}),
                ],
                none,
                "which apply does not push",
            ),
            (
                &[json!({"type": "create_pull_request", "title": "t", "branch": BRANCH})],
                none,
                "without a body",
            ),
            (
                &[pull_request_item()],
                |dir, _, _| {
                    let mut report: Value =
                        serde_json::from_slice(&std::fs::read(dir.join(REPORT_FILE)).unwrap())
                            .unwrap();
                    report["patch"]["commit_files"] = json!([["src/x"]]);
                    std::fs::write(dir.join(REPORT_FILE), report.to_string()).unwrap();
                },
                "a replacement series",
            ),
            (
                &[pull_request_item()],
                |dir, _, _| {
                    let mut report: Value =
                        serde_json::from_slice(&std::fs::read(dir.join(REPORT_FILE)).unwrap())
                            .unwrap();
                    report["items"] = json!([comment_item()]);
                    std::fs::write(dir.join(REPORT_FILE), report.to_string()).unwrap();
                },
                "a patch without a create_pull_request",
            ),
            (
                &[comment_item()],
                |dir, _, _| {
                    let mut report: Value =
                        serde_json::from_slice(&std::fs::read(dir.join(REPORT_FILE)).unwrap())
                            .unwrap();
                    report["secondary_patch"] = json!({"file": "aw-o-tool-x.patch", "bytes": 1,
                        "base_commit": BASE, "files": ["x"]});
                    std::fs::write(dir.join(REPORT_FILE), report.to_string()).unwrap();
                },
                "a secondary pull request off GitHub",
            ),
            (
                &[
                    json!({"type": "create_pull_request", "title": "t", "body": "b", "branch": "main"}),
                ],
                none,
                "which apply does not push",
            ),
            (
                &[
                    json!({"type": "create_pull_request", "title": "t", "body": "b", "branch": BRANCH, "draft": false}),
                ],
                none,
                "that is not a draft",
            ),
            (
                &[pull_request_item()],
                |_, _, target| target.push_repo = None,
                "no --push-repo",
            ),
            (
                &[pull_request_item()],
                |_, _, target| target.push_repo = Some("other/bootc"),
                "--push-repo other/bootc is not the push_repo the bounds name (bot/bootc)",
            ),
            (
                &[pull_request_item()],
                |_, policy, _| policy.push_repo = None,
                "is not the push_repo the bounds name (none)",
            ),
            (
                &[pull_request_item()],
                |_, policy, target| {
                    policy.push_repo = Some("Bootc-Dev/Bootc".to_owned());
                    target.push_repo = Some("bootc-dev/bootc");
                },
                "is of the owner of bootc-dev/bootc",
            ),
            (
                &[pull_request_item()],
                |_, policy, target| {
                    policy.push_repo = Some("bootc-dev/bootc-fork".to_owned());
                    target.push_repo = Some("bootc-dev/bootc-fork");
                },
                "is of the owner of bootc-dev/bootc",
            ),
        ];
        for (items, change, want) in cases {
            let dir = checked(items);
            let mut policy = policy();
            let mut target = target(Some(64));
            change(dir.path(), &mut policy, &mut target);
            let errors = plan(&upload(dir.path()), &policy, &target).unwrap_err();
            assert!(
                errors.iter().any(|error| error.contains(want)),
                "{items:?}: {errors:?}"
            );
        }
    }

    #[test]
    fn ready_when_complete() {
        for (checkpoint, title) in [(None, "Fix it"), (Some(json!({})), "WIP: Fix it")] {
            let dir = checked(&[pull_request_item()]);
            let mut report: Value =
                serde_json::from_slice(&std::fs::read(dir.path().join(REPORT_FILE)).unwrap())
                    .unwrap();
            if let Some(checkpoint) = checkpoint {
                report["checkpoint"] = checkpoint;
            }
            std::fs::write(dir.path().join(REPORT_FILE), report.to_string()).unwrap();
            let mut policy = policy();
            policy
                .safe_outputs
                .create_pull_request
                .as_mut()
                .unwrap()
                .ready_when_complete = true;
            let ops = plan(&upload(dir.path()), &policy, &target(None)).unwrap();
            let Op::PullRequest(pr) = &ops[0] else {
                panic!("{ops:?}")
            };
            assert_eq!(pr.title, title);
        }
    }

    const PUSH_PATCH: &str = "aw-agent-run-12.patch";

    /// A push moves the head inline comments on its own pull request were
    /// checked against, so both are refused; comments elsewhere are not.
    #[test]
    fn push_and_inline_on_one_item() {
        for (forge, number, refused) in [
            (Forge::Forgejo, 42, true),
            (Forge::Forgejo, 64, false),
            (Forge::Gitlab, 42, true),
            (Forge::Gitlab, 64, false),
        ] {
            let dir = checked_push(&[
                push_item(),
                json!({"type": CREATE_REVIEW_COMMENT, "repo": "bootc-dev/bootc",
                    "pull_request_number": number, "path": "src/x", "line": 2, "body": "Finding."}),
            ]);
            let path = dir.path().join(REPORT_FILE);
            let mut report: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            report["inline_target"] =
                json!({"repo": "bootc-dev/bootc", "number": number, "head": HEAD});
            std::fs::write(&path, report.to_string()).unwrap();
            let mut policy = push_policy();
            policy.safe_outputs.others.insert(
                CREATE_REVIEW_COMMENT.to_owned(),
                OutputLimit {
                    max: 1,
                    ..OutputLimit::default()
                },
            );
            policy.forge = crate::Forge::Forgejo;
            let mut target = target(Some(number));
            if forge == Forge::Gitlab {
                on_gitlab(dir.path(), &mut policy, &mut target);
            }
            match plan(&upload(dir.path()), &policy, &target) {
                Err(errors) if refused => {
                    assert!(errors.join(";").contains("moves the head"), "{errors:?}")
                }
                Ok(ops) if !refused => assert!(matches!(ops[1], Op::Inline(_)), "{ops:?}"),
                other => panic!("{forge:?} #{number}: {other:?}"),
            }
        }
    }

    /// A push run's policy: pull request 42's branch `agent-run-12` at
    /// `HEAD`, from the bounds' fork, with a comment allowed.
    fn push_policy() -> Policy {
        let mut policy = crate::check::fixtures::push_policy_to(PUSH_REPO);
        policy.safe_outputs.others.insert(
            ADD_COMMENT.to_owned(),
            OutputLimit {
                max: 1,
                ..OutputLimit::default()
            },
        );
        policy
    }

    fn push_item() -> Value {
        json!({"type": PUSH_TO_PULL_REQUEST_BRANCH, "message": "Fix it\n\nWhy.",
            "branch": "agent-run-12"})
    }

    /// A checked upload of a push's ITEMS, with the patch check would
    /// report, against the pull request's head.
    fn checked_push(items: &[Value]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let patch = patch().replace(BASE, HEAD);
        std::fs::write(dir.path().join(PUSH_PATCH), &patch).unwrap();
        let report = json!({
            "ok": true, "errors": [], "items": items,
            "patch": {"file": PUSH_PATCH, "bytes": patch.len(), "base_commit": HEAD,
                "files": ["src/x"]},
        });
        std::fs::write(dir.path().join(REPORT_FILE), report.to_string()).unwrap();
        dir
    }

    /// The push to the policy's pull request, then the caller's status
    /// after every other write; and every refusal before any. GitLab's
    /// alike, as the patch rules and the policy's merge request, branch
    /// and head are the same.
    #[test]
    fn pushes() {
        for forge in [Forge::Forgejo, Forge::Gitlab] {
            pushes_on(forge);
        }
    }

    fn pushes_on(forge: Forge) {
        let on = |dir: &Path, policy: &mut Policy, target: &mut Target<'static>| {
            if forge == Forge::Gitlab {
                on_gitlab(dir, policy, target);
            }
        };
        let dir = checked_push(&[comment_item(), push_item()]);
        let mut status = Target {
            status: Some((State::Success, HEAD)),
            ..target(Some(64))
        };
        let mut policy = push_policy();
        on(dir.path(), &mut policy, &mut status);
        let ops = plan(&upload(dir.path()), &policy, &status).unwrap();
        assert_eq!(ops.len(), 3, "{ops:?}");
        assert_eq!(
            ops[0],
            Op::Push(BranchPush {
                number: 42,
                push_repo: PUSH_REPO.to_owned(),
                private: false,
                branch: "agent-run-12".to_owned(),
                head: HEAD.to_owned(),
                patch: patch().replace(BASE, HEAD).into_bytes(),
                files: vec!["src/x".to_owned()],
                committer: PROVENANCE.committer(),
            })
        );
        assert!(matches!(ops[1], Op::Comment { .. }), "{ops:?}");
        assert_eq!(
            ops[2],
            Op::Status(CommitStatus {
                sha: HEAD.to_owned(),
                state: State::Success,
                target_url: RUN.to_owned(),
                context: "example-ci/apply".to_owned(),
            })
        );

        type Change = fn(&Path, &mut Policy, &mut Target<'static>);
        let none: Change = |_, _, _| {};
        let cases: &[(Value, Change, &str)] = &[
            (
                push_item(),
                |_, _, target| target.push_repo = None,
                "a push_to_pull_request_branch, and the caller gave no --push-repo",
            ),
            (
                push_item(),
                |_, _, target| target.push_repo = Some("other/bootc"),
                "--push-repo other/bootc is not the push_repo the bounds name (bot/bootc)",
            ),
            (
                push_item(),
                |_, policy, target| {
                    policy.push_repo = Some("bootc-dev/fork".to_owned());
                    target.push_repo = Some("bootc-dev/fork");
                },
                "is of the owner of bootc-dev/bootc",
            ),
            // The pull request and branch are the policy's.
            (
                json!({"type": PUSH_TO_PULL_REQUEST_BRANCH, "message": "m", "branch": "main"}),
                none,
                "with branch \"main\", which is not the policy's",
            ),
            (
                json!({"type": PUSH_TO_PULL_REQUEST_BRANCH, "message": "m",
                    "branch": "agent-run-12", "pull_request_number": 43}),
                none,
                "with pull_request_number 43, which is not the policy's pull request",
            ),
            (
                json!({"type": PUSH_TO_PULL_REQUEST_BRANCH, "message": "m",
                    "branch": "agent-run-12", "force": true}),
                none,
                "a push_to_pull_request_branch with force, which apply does not map",
            ),
            (
                push_item(),
                |_, policy, _| {
                    let push = policy.safe_outputs.push_to_pull_request_branch.as_mut();
                    push.unwrap().target = "042".to_owned();
                },
                "the policy's pull request \"042\" is not a number",
            ),
            // The patch is on the head the run was asked for.
            (
                push_item(),
                |dir, _, _| {
                    std::fs::write(dir.join(PUSH_PATCH), patch()).unwrap();
                    let path = dir.join(REPORT_FILE);
                    let text = std::fs::read_to_string(&path).unwrap();
                    std::fs::write(&path, text.replace(HEAD, BASE)).unwrap();
                },
                "check read the patch against 1111111111111111111111111111111111111111, not the head 2222",
            ),
            (
                push_item(),
                |dir, _, _| {
                    let protected = patch()
                        .replace(BASE, HEAD)
                        .replace("src/x", ".forgejo/workflows/x.yml");
                    std::fs::write(dir.join(PUSH_PATCH), &protected).unwrap();
                    let path = dir.join(REPORT_FILE);
                    let mut report: Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    report["patch"]["bytes"] = protected.len().into();
                    report["patch"]["files"] = json!([".forgejo/workflows/x.yml"]);
                    std::fs::write(path, report.to_string()).unwrap();
                },
                "the patch aw-agent-run-12.patch: ",
            ),
            (
                push_item(),
                |_, policy, _| {
                    policy.commit_author = Some("Bot <bot@example.org>".to_owned());
                },
                "the patch aw-agent-run-12.patch: ",
            ),
            (
                push_item(),
                |dir, _, _| {
                    let path = dir.join(REPORT_FILE);
                    let mut report: Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    report["patch"]["commit_files"] = json!([["src/x"]]);
                    std::fs::write(path, report.to_string()).unwrap();
                },
                "a replacement series, which apply does not push off GitHub",
            ),
            (
                push_item(),
                |_, policy, _| {
                    let push = policy.safe_outputs.push_to_pull_request_branch.as_mut();
                    push.unwrap().ready_when_complete = true;
                },
                "under ready_when_complete, which apply does not mark ready on Forgejo",
            ),
            (
                push_item(),
                |_, _, target| target.status = Some((State::Failure, "main")),
                "--status-sha \"main\" is not a full commit SHA",
            ),
            // A check run is GitHub's, and a status is never a request's.
            (
                json!({"type": "create_check_run", "name": "agentic-job", "conclusion": "success"}),
                none,
                "\"create_check_run\", which apply does not publish to Forgejo",
            ),
            (
                json!({"type": "set_status", "state": "success"}),
                none,
                "\"set_status\", which apply does not publish to Forgejo",
            ),
        ];
        for (item, change, want) in cases {
            let dir = checked_push(std::slice::from_ref(item));
            let mut policy = push_policy();
            let mut target = target(Some(64));
            on(dir.path(), &mut policy, &mut target);
            change(dir.path(), &mut policy, &mut target);
            let errors = plan(&upload(dir.path()), &policy, &target).unwrap_err();
            let want = want.replace("Forgejo", forge.name());
            assert!(
                errors.iter().any(|error| error.contains(&want)),
                "{forge:?} {item}: {errors:?}"
            );
        }
    }

    #[derive(Default)]
    struct Recording {
        calls: RefCell<Vec<String>>,
        fail_at: Option<usize>,
        /// The op whose preflight the forge refuses.
        refuse: Option<usize>,
        preflights: RefCell<usize>,
    }

    impl Publisher for Recording {
        fn preflight(&self, _: &Op) -> Result<()> {
            let mut asked = self.preflights.borrow_mut();
            anyhow::ensure!(self.refuse != Some(*asked), "no such label");
            *asked += 1;
            Ok(())
        }
        fn comment(&self, issue: u64, _: &str) -> Result<Made> {
            self.call(format!("comment {issue}"))
        }
        fn open_pull_request(&self, pr: &PullRequest) -> Result<Made> {
            self.call(format!("pull {}", pr.branch))
        }
        fn push_to_branch(&self, push: &BranchPush) -> Result<String> {
            self.call(format!("push {} {}", push.number, push.branch))
                .map(|made| made.url)
        }
        fn status(&self, status: &CommitStatus) -> Result<String> {
            self.call(format!("status {}", status.state.name()))
                .map(|made| made.url)
        }
        fn create_issue(&self, issue: &NewIssue) -> Result<String> {
            self.call(format!("issue {}", issue.labels.join(",")))
                .map(|made| made.url)
        }
        fn change_labels(&self, change: &LabelChange) -> Result<String> {
            let sign = if change.add { '+' } else { '-' };
            self.call(format!(
                "labels {} {sign}{}",
                change.item,
                change.labels.join(",")
            ))
            .map(|made| made.url)
        }
        fn close(&self, close: &Close) -> Result<String> {
            self.call(format!("close {:?} {}", close.kind, close.number))
                .map(|made| made.url)
        }
    }

    impl Recording {
        fn call(&self, what: String) -> Result<Made> {
            let mut calls = self.calls.borrow_mut();
            anyhow::ensure!(self.fail_at != Some(calls.len()), "refused");
            calls.push(what.clone());
            Ok(Made {
                url: format!("url of {what}"),
                ..Made::default()
            })
        }
    }

    #[test]
    fn publishes_in_order_and_names_what_was_made() {
        let dir = checked(&[comment_item(), pull_request_item()]);
        let ops = plan(&upload(dir.path()), &policy(), &target(Some(64))).unwrap();
        let recording = Recording::default();
        assert_eq!(
            publish(&ops, &recording).unwrap(),
            ["url of pull agent-run-7", "url of comment 64"]
        );
        // A refused pull request leaves no comment behind.
        let recording = Recording {
            fail_at: Some(0),
            ..Recording::default()
        };
        let err = format!("{:#}", publish(&ops, &recording).unwrap_err());
        assert_eq!(err, "refused");
        assert!(recording.calls.borrow().is_empty());
        let recording = Recording {
            fail_at: Some(1),
            ..Recording::default()
        };
        let err = format!("{:#}", publish(&ops, &recording).unwrap_err());
        assert_eq!(err, "after publishing url of pull agent-run-7: refused");
    }

    /// Every op is asked of the forge before the first write, so that a
    /// refusal of any writes nothing; a failure after a write names what
    /// was made.
    #[test]
    fn publishes_metadata() {
        let dir = checked(&[
            close_pull_request_item(),
            close_item(),
            labels_item(ADD_LABELS),
            comment_item(),
            issue_item(),
        ]);
        let ops = plan(&upload(dir.path()), &policy(), &target(Some(64))).unwrap();
        let all = [
            "issue bug,BUG",
            "comment 64",
            "labels 5 +triage",
            "close PullRequest 7",
            "close Issue 6",
        ];
        // The op the forge refuses, the write that fails, and the writes
        // made and the error, if any.
        type Case<'a> = (Option<usize>, Option<usize>, &'a [&'a str], Option<&'a str>);
        let cases: &[Case] = &[
            (None, None, &all, None),
            (Some(0), None, &[], Some("no such label")),
            (Some(4), None, &[], Some("no such label")),
            (None, Some(0), &[], Some("refused")),
            (
                None,
                Some(3),
                &all[..3],
                Some(
                    "after publishing url of issue bug,BUG, url of comment 64, \
                     url of labels 5 +triage: refused",
                ),
            ),
        ];
        for (refuse, fail_at, made, error) in cases {
            let recording = Recording {
                refuse: *refuse,
                fail_at: *fail_at,
                ..Recording::default()
            };
            let result = publish(&ops, &recording).map_err(|err| format!("{err:#}"));
            assert_eq!(*recording.calls.borrow(), *made, "{refuse:?} {fail_at:?}");
            match (result, error) {
                (Ok(urls), None) => assert_eq!(urls.len(), all.len()),
                (Err(err), Some(want)) => assert_eq!(err, *want),
                (result, _) => panic!("{refuse:?} {fail_at:?}: {result:?}"),
            }
        }
    }
}
