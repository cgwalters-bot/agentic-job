//! `agentic-job event`: decide whether the event that started a workflow
//! may start an agent run, and if so turn it into the run's task context.
//!
//! A caller's workflow may be triggered by anything (`on:` is the
//! caller's), and the event's payload is a stranger's text: the title of
//! an issue, the body of a comment, the name of a branch. This command is
//! the one place that reads it. It decides from the caller's bounds file
//! (the `[trigger]` table) who may start a run and from which events,
//! fail closed, and writes the untrusted text into the task file behind a
//! fence it cannot close, so the agent reads it as data. The decision and
//! the targets (the triggering issue or pull request, the pull request's
//! base and head) go to `event.json` for the workflow, which has the token
//! to fetch the actor's permission and to react; the binary holds none.
//!
//! This is gh-aw's `pre_activation` and `activation` jobs in one command:
//! its role check (`roles:` as an exact allowlist, bots refused unless
//! listed, a comment's actor must be its author), its fork rule (a pull
//! request from another repository is refused by default), its slash
//! commands (the body must start with the command) and its sanitized
//! context, with one difference: the text is fenced.

mod context;
mod guards;

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::exit::Exit;
use crate::files;
use crate::policy;

pub use context::write_task;

/// `event.json`'s schema.
pub const SCHEMA: &str = "agentic-job-event/v1";

/// What the command writes under `--out`.
pub const DECISION_FILE: &str = "event.json";
pub const TASK_FILE: &str = "task.md";

/// The events this command knows how to read. A bounds file lists a
/// subset of these; anything else is refused.
pub const EVENTS: &[&str] = &[
    "issues",
    "discussion",
    "issue_comment",
    "pull_request",
    "pull_request_target",
    "pull_request_review_comment",
    "schedule",
    "workflow_dispatch",
];

/// The pull-request events: the same payload, read the same way. A
/// `pull_request_target` workflow runs from the base branch's files, so
/// the bounds file it reads are the repository's and not the pull
/// request's.
const PULL_REQUEST_EVENTS: &[&str] = &["pull_request", "pull_request_target"];

/// gh-aw's default `roles:`: an exact allowlist, so `maintain` is not
/// `write` and `admin` is not either.
pub const DEFAULT_ROLES: &[&str] = &["admin", "maintain", "write"];

/// gh-aw's `roles: all`: any person, whatever their role, and without a
/// permission to fetch. Bots are still admitted only by name.
pub const ALL_ROLES: &str = "all";

/// The most an event payload, a permission response and a caller's task
/// may be, in bytes.
const MAX_EVENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PERMISSION_BYTES: u64 = 64 * 1024;
const MAX_PULL_REQUEST_BYTES: u64 = 1024 * 1024;
/// The caller's own task. With the event's text ([`context::MAX_TEXT_BYTES`])
/// and the lines around it, the task file stays under what `run` accepts.
pub const MAX_TASK_BYTES: u64 = 64 * 1024;

/// The actor that is every workflow's own: a run it starts is a loop.
const GITHUB_ACTIONS: &str = "github-actions[bot]";

/// The actions of an event that may start a run. An edit is not one: the
/// editor may not be the author, and the text that was checked is gone.
const ISSUE_ACTIONS: &[&str] = &["opened", "reopened", "labeled"];
const COMMENT_ACTIONS: &[&str] = &["created"];
const PULL_REQUEST_ACTIONS: &[&str] = &[
    "opened",
    "reopened",
    "synchronize",
    "ready_for_review",
    "labeled",
];

/// A command at the very start of the body, as gh-aw matches it: no
/// leading whitespace, then a word boundary.
static COMMAND_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/([A-Za-z0-9][A-Za-z0-9._-]*)(?:[ \t]|\r?\n|$)").expect("a valid pattern")
});

static LOGIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$").expect("a valid pattern")
});

/// A commit id, the one thing of a pull request's head the task file
/// repeats unfenced.
static SHA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{40}$").expect("a valid pattern"));

/// A branch name as git allows one: no space or control character, none
/// of its special characters, not starting with a dash. The pull
/// request's base becomes the run's base, which the bounds then check.
static REF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[^\s~^:?*\[\\\x00-\x1f-][^\s~^:?*\[\\\x00-\x1f]*$").expect("a valid pattern")
});

/// The event's values may start with a dash: they are a stranger's text.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The caller's bounds file, for its [trigger] table
    #[arg(long, value_name = "FILE")]
    pub allow: PathBuf,
    /// The event's name (GITHUB_EVENT_NAME)
    #[arg(long, value_name = "NAME", allow_hyphen_values = true)]
    pub event_name: String,
    /// The event's payload (GITHUB_EVENT_PATH)
    #[arg(long, value_name = "FILE")]
    pub event: PathBuf,
    /// Who started the workflow (github.actor)
    #[arg(long, value_name = "LOGIN", allow_hyphen_values = true)]
    pub actor: String,
    /// The repository the workflow runs in, OWNER/NAME (github.repository)
    #[arg(long, value_name = "REPO", allow_hyphen_values = true)]
    pub repository: String,
    /// The actor's permission on that repository: the response of
    /// GET /repos/OWNER/NAME/collaborators/LOGIN/permission, fetched by the
    /// workflow. Without it, only a schedule or a listed bot may start a run
    #[arg(long, value_name = "FILE")]
    pub actor_permission: Option<PathBuf>,
    /// For a comment on a pull request, the pull request itself: the response
    /// of GET /repos/OWNER/NAME/pulls/N, fetched by the workflow, so that the
    /// fork rule applies to its head. Without it such a comment is admitted
    /// only where forks are
    #[arg(long, value_name = "FILE")]
    pub pull_request: Option<PathBuf>,
    /// The caller's own task text, put before the event's
    #[arg(long, value_name = "FILE")]
    pub task: Option<PathBuf>,
    /// Where event.json and task.md are written
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
}

/// The `[trigger]` table of the bounds file. Absent, no event starts a run.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    /// The events that may start a run, from [`EVENTS`].
    pub events: Vec<String>,
    /// The roles an actor may have, exactly; [`DEFAULT_ROLES`] by default,
    /// or [`ALL_ROLES`] alone for anyone.
    #[serde(default = "default_roles")]
    pub roles: Vec<String>,
    /// Bot logins admitted without a role (`dependabot[bot]`).
    #[serde(default)]
    pub bots: Vec<String>,
    /// Whether a pull request whose head is in another repository may
    /// start a run.
    #[serde(default)]
    pub forks: bool,
    /// The commands a comment must start with (`/agent`), one of which
    /// every comment event needs.
    #[serde(default)]
    pub commands: Vec<String>,
    /// RFC 3339 deadline, inclusive: no run starts at or after it.
    #[serde(default, rename = "stop-after")]
    pub stop_after: Option<String>,
    /// Label commands, matched exactly on the label added by the event.
    /// When nonempty, item events must be `labeled` with a listed label.
    #[serde(default)]
    pub labels: Vec<String>,
}

fn default_roles() -> Vec<String> {
    DEFAULT_ROLES.iter().map(|role| role.to_string()).collect()
}

impl Trigger {
    /// Refuse a table that cannot mean what it says.
    pub fn validate(&self) -> Result<()> {
        guards::validate(self)?;
        for event in &self.events {
            if !EVENTS.contains(&event.as_str()) {
                bail!("[trigger] events: {event:?} is not one of {EVENTS:?}");
            }
        }
        for command in &self.commands {
            let Some(name) = command.strip_prefix('/') else {
                bail!("[trigger] commands: {command:?} must start with a slash");
            };
            if !COMMAND_RE.is_match(command) || name.contains(char::is_whitespace) {
                bail!("[trigger] commands: {command:?} is not a command name");
            }
        }
        for bot in &self.bots {
            if bot == GITHUB_ACTIONS {
                bail!("[trigger] bots: {GITHUB_ACTIONS} would let a run start the next");
            }
            if !LOGIN_RE.is_match(bot) {
                bail!("[trigger] bots: {bot:?} is not a login");
            }
        }
        for label in &self.labels {
            if label.trim().is_empty() || label.len() > 50 || label.contains(char::is_control) {
                bail!(
                    "[trigger] labels: {label:?} must be nonempty, at most 50 bytes and contain no control characters"
                );
            }
        }
        let comment_events = ["issue_comment", "pull_request_review_comment"];
        if self.commands.is_empty()
            && self
                .events
                .iter()
                .any(|e| comment_events.contains(&e.as_str()))
        {
            bail!("[trigger] commands is empty, and a comment event needs one");
        }
        if self.roles.is_empty() && self.bots.is_empty() {
            bail!("[trigger] roles and bots are both empty: nobody may start a run");
        }
        if self.roles.len() > 1 && self.roles.iter().any(|role| role == ALL_ROLES) {
            bail!("[trigger] roles: {ALL_ROLES:?} admits anyone and must stand alone");
        }
        Ok(())
    }
}

/// The response of the collaborator-permission API, the two fields read.
#[derive(Debug, Clone, Deserialize)]
pub struct Permission {
    /// The coarse level (`admin`, `write`, `read`, `none`).
    pub permission: String,
    /// The role (`admin`, `maintain`, `write`, `triage`, `read`), when the
    /// API gives it.
    #[serde(default)]
    pub role_name: Option<String>,
    /// Whose permission it is: it must be the actor's.
    pub user: PermissionUser,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PermissionUser {
    pub login: String,
}

impl Permission {
    fn role(&self) -> &str {
        self.role_name.as_deref().unwrap_or(&self.permission)
    }
}

/// What kind of thing the event is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Issue,
    PullRequest,
    Discussion,
}

/// The issue or pull request the event is about: the default target of
/// the run's outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub kind: ItemKind,
    pub number: u64,
    /// Its page, when the payload's is under the repository's.
    pub url: Option<String>,
}

/// A pull request's head: its commit, and its branch only when it is in
/// the repository itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    pub sha: String,
}

/// What the workflow may react to, so the human sees the run started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReactTo {
    Issue { number: u64 },
    Comment { id: u64 },
    ReviewComment { id: u64 },
}

/// `event.json`: the decision, and what the workflow needs of the event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub schema: String,
    pub admitted: bool,
    /// Why it was refused, or what admitted it.
    pub reason: String,
    pub event: String,
    pub action: Option<String>,
    pub actor: String,
    /// The actor's role, when one was checked.
    pub role: Option<String>,
    pub item: Option<Item>,
    /// The command that started the run: a slash command without its slash,
    /// or the exact label name for a label command.
    pub command: Option<String>,
    /// For a pull request, its base branch; the run should start there.
    pub base: Option<String>,
    /// For a pull request, its head.
    pub head: Option<Head>,
    /// A key for the caller's `concurrency.group`, one run per item.
    pub concurrency: String,
    pub react_to: Option<ReactTo>,
}

/// The untrusted text of the event, each piece named for the agent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Text {
    /// Who wrote the comment or opened the item.
    pub author: String,
    /// What the comment said, after the command.
    pub request: Option<String>,
    /// The item's title and body.
    pub title: Option<String>,
    pub body: Option<String>,
    /// A review comment's place in the diff.
    pub diff: Option<String>,
}

/// What a read of the event yields: the decision and the text to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub decision: Decision,
    pub text: Text,
}

/// The inputs of a decision, with the payload already parsed.
pub struct Input<'a> {
    pub trigger: &'a Trigger,
    pub event_name: &'a str,
    pub payload: &'a Value,
    pub actor: &'a str,
    pub repository: &'a str,
    pub permission: Option<&'a Permission>,
    /// The pull request a comment is on, fetched by the workflow.
    pub pull_request: Option<&'a Value>,
}

pub fn run(args: &Args) -> Result<Exit> {
    let bounds = policy::Bounds::load(&args.allow)?;
    let Some(trigger) = bounds.trigger.as_ref() else {
        bail!(
            "{}: no [trigger] table, so no event may start a run",
            args.allow.display()
        );
    };
    trigger
        .validate()
        .with_context(|| args.allow.display().to_string())?;
    let payload = files::read_regular(&args.event, MAX_EVENT_BYTES)
        .with_context(|| format!("reading the event {}", args.event.display()))?;
    let payload: Value = serde_json::from_slice(&payload)
        .with_context(|| format!("{}: not JSON", args.event.display()))?;
    let permission = args
        .actor_permission
        .as_deref()
        .map(load_permission)
        .transpose()?;
    let pull_request = args
        .pull_request
        .as_deref()
        .map(|path| -> Result<Value> {
            let bytes = files::read_regular(path, MAX_PULL_REQUEST_BYTES)
                .with_context(|| format!("reading the pull request {}", path.display()))?;
            serde_json::from_slice(&bytes).with_context(|| format!("{}: not JSON", path.display()))
        })
        .transpose()?;
    let task = args
        .task
        .as_deref()
        .map(|path| {
            let bytes = files::read_regular(path, MAX_TASK_BYTES)
                .with_context(|| format!("reading the task {}", path.display()))?;
            String::from_utf8(bytes).with_context(|| format!("{}: not UTF-8", path.display()))
        })
        .transpose()?;
    let mut outcome = decide(&Input {
        trigger,
        event_name: &args.event_name,
        payload: &payload,
        actor: &args.actor,
        repository: &args.repository,
        permission: permission.as_ref(),
        pull_request: pull_request.as_ref(),
    });
    if outcome.decision.admitted
        && let Some(reason) = guards::check(trigger)?
    {
        outcome.decision.admitted = false;
        outcome.decision.reason = reason;
        outcome.text = Text::default();
    }
    std::fs::create_dir_all(&args.out)
        .with_context(|| format!("creating {}", args.out.display()))?;
    // The task first and the decision last, so that a decision that says
    // "admitted" is never on disk without the task it admits; and no task
    // of an earlier decision survives a refusal.
    let task_path = args.out.join(TASK_FILE);
    match std::fs::remove_file(&task_path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("removing {}", task_path.display())),
    }
    if outcome.decision.admitted {
        write_task(&task_path, task.as_deref(), &outcome)?;
    }
    let decision_path = args.out.join(DECISION_FILE);
    let json = serde_json::to_vec_pretty(&outcome.decision)?;
    std::fs::write(&decision_path, json)
        .with_context(|| format!("writing {}", decision_path.display()))?;
    if outcome.decision.admitted {
        eprintln!("admitted: {}", outcome.decision.reason);
        Ok(Exit::Success)
    } else {
        eprintln!("refused: {}", outcome.decision.reason);
        Ok(Exit::Failure)
    }
}

fn load_permission(path: &Path) -> Result<Permission> {
    let bytes = files::read_regular(path, MAX_PERMISSION_BYTES)
        .with_context(|| format!("reading the permission {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("{}: not a permission response", path.display()))
}

/// The decision, pure: every refusal names its reason, and a refusal
/// still carries what was read so the workflow can say what happened.
pub fn decide(input: &Input<'_>) -> Outcome {
    let mut outcome = Outcome {
        decision: Decision {
            schema: SCHEMA.to_string(),
            admitted: false,
            reason: String::new(),
            event: input.event_name.to_string(),
            action: str_at(input.payload, &["action"]).map(str::to_string),
            actor: input.actor.to_string(),
            role: None,
            item: None,
            command: None,
            base: None,
            head: None,
            concurrency: input.event_name.to_string(),
            react_to: None,
        },
        text: Text::default(),
    };
    match read(input, &mut outcome) {
        Ok(reason) => {
            outcome.decision.admitted = true;
            outcome.decision.reason = one_line(&reason);
        }
        Err(reason) => {
            outcome.decision.admitted = false;
            outcome.decision.reason = one_line(&reason);
            outcome.text = Text::default();
        }
    }
    outcome
}

/// The reason is one line: the workflow writes it to a file of
/// `name=value` lines, and a repository name in it is the payload's.
fn one_line(reason: &str) -> String {
    reason.replace(char::is_control, " ")
}

/// The checks, in the order a refusal should be reported: the event, the
/// actor, then what the event says.
fn read(input: &Input<'_>, outcome: &mut Outcome) -> std::result::Result<String, String> {
    let event = input.event_name;
    if !input.trigger.events.iter().any(|allowed| allowed == event) {
        return Err(format!("the bounds do not let a {event} event start a run"));
    }
    if !LOGIN_RE.is_match(input.actor) {
        return Err("the actor is not a login".to_string());
    }
    let payload_repo = str_at(input.payload, &["repository", "full_name"]);
    if event != "schedule"
        && payload_repo.is_none_or(|repo| !repo.eq_ignore_ascii_case(input.repository))
    {
        return Err(format!(
            "the event's repository {} is not {}",
            payload_repo.unwrap_or("(none)"),
            input.repository
        ));
    }
    if event == "schedule" {
        outcome.decision.concurrency = "schedule".to_string();
        return Ok("a schedule".to_string());
    }
    // A schedule has no sender; every other event has, and it is the actor.
    let sender = str_at(input.payload, &["sender", "login"]).ok_or("the event has no sender")?;
    if sender != input.actor {
        return Err(format!(
            "the actor {} is not the event's sender {sender}",
            input.actor
        ));
    }
    outcome.decision.role = check_actor(input)?;
    if event == "workflow_dispatch" {
        outcome.decision.concurrency = "dispatch".to_string();
        return Ok(format!("dispatched by {}", input.actor));
    }
    let action = outcome.decision.action.clone().unwrap_or_default();
    let action = action.as_str();
    match event {
        "issues" => read_issue(input, action, outcome),
        "discussion" => read_discussion(input, action, outcome),
        "issue_comment" => read_comment(input, action, outcome),
        "pull_request_review_comment" => read_review_comment(input, action, outcome),
        pull if PULL_REQUEST_EVENTS.contains(&pull) => read_pull_request(input, action, outcome),
        other => Err(format!("{other} events are not supported")),
    }
}

/// Who the actor is: a bot on the list, or a collaborator with a listed
/// role. The bot check comes first so that a bot is never admitted by a
/// role it happens to hold.
fn check_actor(input: &Input<'_>) -> std::result::Result<Option<String>, String> {
    let actor = input.actor;
    let is_bot = actor.ends_with("[bot]")
        || str_at(input.payload, &["sender", "type"]).is_some_and(|kind| kind == "Bot");
    if actor == GITHUB_ACTIONS {
        return Err("github-actions[bot] may not start a run: that is a loop".to_string());
    }
    if is_bot {
        return if input.trigger.bots.iter().any(|bot| bot == actor) {
            Ok(None)
        } else {
            Err(format!("{actor} is a bot the bounds do not list"))
        };
    }
    if input.trigger.roles.iter().any(|role| role == ALL_ROLES) {
        return Ok(None);
    }
    let Some(permission) = input.permission else {
        return Err(format!(
            "no permission of {actor} was given, and one is needed"
        ));
    };
    if permission.user.login != actor {
        return Err(format!(
            "the permission given is {}'s, not {actor}'s",
            permission.user.login
        ));
    }
    let role = permission.role();
    if input.trigger.roles.iter().any(|allowed| allowed == role) {
        Ok(Some(role.to_string()))
    } else {
        Err(format!(
            "{actor} has the role {role:?}, and the bounds admit {:?}",
            input.trigger.roles
        ))
    }
}

fn read_issue(
    input: &Input<'_>,
    action: &str,
    outcome: &mut Outcome,
) -> std::result::Result<String, String> {
    allowed_action(ISSUE_ACTIONS, action)?;
    let command = match_label(input, action)?;
    let issue = input.payload.get("issue").ok_or("no issue in the event")?;
    if issue.get("pull_request").is_some() {
        return Err("an issues event about a pull request".to_string());
    }
    let item = item_of(input, issue, ItemKind::Issue)?;
    outcome.text = Text {
        author: str_at(issue, &["user", "login"])
            .unwrap_or_default()
            .to_string(),
        request: None,
        title: str_at(issue, &["title"]).map(str::to_string),
        body: str_at(issue, &["body"]).map(str::to_string),
        diff: None,
    };
    let decision = &mut outcome.decision;
    decision.concurrency = format!("issue-{}", item.number);
    decision.react_to = Some(ReactTo::Issue {
        number: item.number,
    });
    let reason = format!("issue #{} {action} by {}", item.number, input.actor);
    decision.item = Some(item);
    decision.command = command;
    Ok(reason)
}

fn match_label(input: &Input<'_>, action: &str) -> std::result::Result<Option<String>, String> {
    if input.trigger.labels.is_empty() {
        return Ok(None);
    }
    allowed_action(&["labeled"], action)?;
    let label = str_at(input.payload, &["label", "name"]).ok_or("the event has no label name")?;
    if !input.trigger.labels.iter().any(|allowed| allowed == label) {
        return Err(format!("{label:?} is not one of the bounds' labels"));
    }
    Ok(Some(label.to_string()))
}

fn read_discussion(
    input: &Input<'_>,
    action: &str,
    outcome: &mut Outcome,
) -> std::result::Result<String, String> {
    allowed_action(&["labeled"], action)?;
    if input.trigger.labels.is_empty() {
        return Err("a discussion needs a label command in the bounds".to_string());
    }
    let command = match_label(input, action)?;
    let discussion = input
        .payload
        .get("discussion")
        .ok_or("no discussion in the event")?;
    let item = item_of(input, discussion, ItemKind::Discussion)?;
    outcome.text = Text {
        author: str_at(discussion, &["user", "login"])
            .unwrap_or_default()
            .to_string(),
        title: str_at(discussion, &["title"]).map(str::to_string),
        body: str_at(discussion, &["body"]).map(str::to_string),
        ..Text::default()
    };
    outcome.decision.concurrency = format!("discussion-{}", item.number);
    outcome.decision.command = command;
    let reason = format!("discussion #{} labeled by {}", item.number, input.actor);
    outcome.decision.item = Some(item);
    Ok(reason)
}

fn read_comment(
    input: &Input<'_>,
    action: &str,
    outcome: &mut Outcome,
) -> std::result::Result<String, String> {
    allowed_action(COMMENT_ACTIONS, action)?;
    let comment = input
        .payload
        .get("comment")
        .ok_or("no comment in the event")?;
    let issue = input.payload.get("issue").ok_or("no issue in the event")?;
    check_author(input, comment)?;
    let kind = if issue.get("pull_request").is_some() {
        ItemKind::PullRequest
    } else {
        ItemKind::Issue
    };
    let item = item_of(input, issue, kind)?;
    // The payload of a comment on a pull request says nothing about where
    // the head is. The workflow fetches the pull request and passes it in:
    // it has to be this one, and then the fork rule applies to it as to a
    // pull_request event. Without it, such a comment is admitted only
    // where forks are, since the run could be about a fork's code.
    let (base, head) = match (kind, input.pull_request) {
        (ItemKind::Issue | ItemKind::Discussion, _) => (None, None),
        (ItemKind::PullRequest, Some(pull)) => {
            let number = u64_at(pull, &["number"]).ok_or("the pull request given has no number")?;
            if number != item.number {
                return Err(format!(
                    "the pull request given is #{number}, and the comment is on #{}",
                    item.number
                ));
            }
            (base_of(pull)?, Some(check_head(input, pull)?))
        }
        (ItemKind::PullRequest, None) if input.trigger.forks => (None, None),
        (ItemKind::PullRequest, None) => {
            return Err(
                "a comment on a pull request is admitted only with the pull request \
                 fetched (--pull-request) or with forks = true: its payload does not \
                 say where the head is"
                    .to_string(),
            );
        }
    };
    let body = str_at(comment, &["body"]).unwrap_or_default();
    let (command, request) = match_command(input.trigger, body)?;
    let id = u64_at(comment, &["id"]).ok_or("the comment has no id")?;
    outcome.text = Text {
        author: str_at(comment, &["user", "login"])
            .unwrap_or_default()
            .to_string(),
        request: Some(request),
        title: str_at(issue, &["title"]).map(str::to_string),
        body: str_at(issue, &["body"]).map(str::to_string),
        diff: None,
    };
    let decision = &mut outcome.decision;
    decision.concurrency = match kind {
        ItemKind::Issue => format!("issue-{}", item.number),
        ItemKind::PullRequest => format!("pull-{}", item.number),
        ItemKind::Discussion => format!("discussion-{}", item.number),
    };
    decision.react_to = Some(ReactTo::Comment { id });
    decision.command = Some(command.clone());
    decision.base = base;
    decision.head = head;
    let reason = format!("/{command} on #{} by {}", item.number, input.actor);
    decision.item = Some(item);
    Ok(reason)
}

fn read_pull_request(
    input: &Input<'_>,
    action: &str,
    outcome: &mut Outcome,
) -> std::result::Result<String, String> {
    allowed_action(PULL_REQUEST_ACTIONS, action)?;
    let command = match_label(input, action)?;
    let pull = input
        .payload
        .get("pull_request")
        .ok_or("no pull request in the event")?;
    let item = item_of(input, pull, ItemKind::PullRequest)?;
    let head = Some(check_head(input, pull)?);
    outcome.text = Text {
        author: str_at(pull, &["user", "login"])
            .unwrap_or_default()
            .to_string(),
        request: None,
        title: str_at(pull, &["title"]).map(str::to_string),
        body: str_at(pull, &["body"]).map(str::to_string),
        diff: None,
    };
    let decision = &mut outcome.decision;
    decision.concurrency = format!("pull-{}", item.number);
    decision.react_to = Some(ReactTo::Issue {
        number: item.number,
    });
    decision.base = base_of(pull)?;
    decision.head = head;
    decision.command = command;
    let reason = format!("pull request #{} {action} by {}", item.number, input.actor);
    decision.item = Some(item);
    Ok(reason)
}

fn read_review_comment(
    input: &Input<'_>,
    action: &str,
    outcome: &mut Outcome,
) -> std::result::Result<String, String> {
    allowed_action(COMMENT_ACTIONS, action)?;
    let comment = input
        .payload
        .get("comment")
        .ok_or("no comment in the event")?;
    let pull = input
        .payload
        .get("pull_request")
        .ok_or("no pull request in the event")?;
    check_author(input, comment)?;
    let item = item_of(input, pull, ItemKind::PullRequest)?;
    let head = Some(check_head(input, pull)?);
    let body = str_at(comment, &["body"]).unwrap_or_default();
    let (command, request) = match_command(input.trigger, body)?;
    let id = u64_at(comment, &["id"]).ok_or("the comment has no id")?;
    let place = format!(
        "{} line {}",
        str_at(comment, &["path"]).unwrap_or("?"),
        u64_at(comment, &["line"]).unwrap_or(0)
    );
    let diff = str_at(comment, &["diff_hunk"]).map(|hunk| format!("{place}\n{hunk}"));
    outcome.text = Text {
        author: str_at(comment, &["user", "login"])
            .unwrap_or_default()
            .to_string(),
        request: Some(request),
        title: str_at(pull, &["title"]).map(str::to_string),
        body: str_at(pull, &["body"]).map(str::to_string),
        diff,
    };
    let decision = &mut outcome.decision;
    decision.concurrency = format!("pull-{}", item.number);
    decision.react_to = Some(ReactTo::ReviewComment { id });
    decision.command = Some(command.clone());
    decision.base = base_of(pull)?;
    decision.head = head;
    let reason = format!(
        "/{command} on pull request #{} by {}",
        item.number, input.actor
    );
    decision.item = Some(item);
    Ok(reason)
}

fn allowed_action(allowed: &[&str], action: &str) -> std::result::Result<(), String> {
    if allowed.contains(&action) {
        Ok(())
    } else {
        Err(format!(
            "the action {action:?} does not start a run (only {allowed:?})"
        ))
    }
}

/// A comment's actor must be its author: an edit, a reaction or a
/// re-delivery by someone else is not that person asking.
fn check_author(input: &Input<'_>, comment: &Value) -> std::result::Result<(), String> {
    let author = str_at(comment, &["user", "login"]).ok_or("the comment has no author")?;
    if author == input.actor {
        Ok(())
    } else {
        Err(format!(
            "the actor {} is not the comment's author {author}",
            input.actor
        ))
    }
}

/// A pull request's head is in the repository, or the bounds allow forks.
/// Its commit is reported either way, as the one name for it that holds no
/// author's text; its branch only when it is the repository's own: a
/// fork's branch is never something a run starts from by name.
fn check_head(input: &Input<'_>, pull: &Value) -> std::result::Result<Head, String> {
    let repo_id = u64_at(input.payload, &["repository", "id"]).ok_or("the repository has no id")?;
    let own = u64_at(pull, &["head", "repo", "id"]) == Some(repo_id);
    if !own && !input.trigger.forks {
        return Err(format!(
            "the pull request's head is in {}, not in {}, and the bounds do not allow forks",
            str_at(pull, &["head", "repo", "full_name"]).unwrap_or("another repository"),
            input.repository
        ));
    }
    let sha = str_at(pull, &["head", "sha"]).ok_or("the head has no sha")?;
    if !SHA_RE.is_match(sha) {
        return Err("the head's sha is not a commit id".to_string());
    }
    let git_ref = if own {
        Some(
            str_at(pull, &["head", "ref"])
                .ok_or("the head has no ref")?
                .to_string(),
        )
    } else {
        None
    };
    Ok(Head {
        git_ref,
        sha: sha.to_string(),
    })
}

/// A pull request's base branch, when it is named like one.
fn base_of(pull: &Value) -> std::result::Result<Option<String>, String> {
    match str_at(pull, &["base", "ref"]) {
        Some(base) if REF_RE.is_match(base) => Ok(Some(base.to_string())),
        Some(_) => Err("the pull request's base is not a branch name".to_string()),
        None => Ok(None),
    }
}

/// The body must start with one of the bounds' commands. What follows,
/// on that line and below it, is the request.
fn match_command(trigger: &Trigger, body: &str) -> std::result::Result<(String, String), String> {
    if trigger.commands.is_empty() {
        return Err("the bounds list no command, and a comment needs one".to_string());
    }
    let Some(found) = COMMAND_RE.captures(body) else {
        return Err("the comment does not start with a command".to_string());
    };
    let name = &found[1];
    if !trigger
        .commands
        .iter()
        .any(|command| command.strip_prefix('/') == Some(name))
    {
        return Err(format!(
            "/{name} is not one of the bounds' commands {:?}",
            trigger.commands
        ));
    }
    // Everything after the command is the request: the rest of its line
    // and the lines below it.
    let request = body[found.get(0).map_or(0, |m| m.end())..]
        .trim()
        .to_string();
    Ok((name.to_string(), request))
}

/// The most an item's URL may be: the repository's page and a number.
pub(crate) const MAX_URL_BYTES: usize = 256;

/// The item's number and, when it is the repository's own page, its URL.
/// No text of the event: `event.json` is read by the workflow unfenced.
fn item_of(input: &Input<'_>, value: &Value, kind: ItemKind) -> std::result::Result<Item, String> {
    let prefix = format!("https://github.com/{}/", input.repository);
    let url = str_at(value, &["html_url"])
        .filter(|url| {
            url.len() <= MAX_URL_BYTES
                && url.starts_with(&prefix)
                && url.chars().all(|c| c.is_ascii_graphic())
        })
        .map(str::to_string);
    Ok(Item {
        kind,
        number: u64_at(value, &["number"]).ok_or("no number")?,
        url,
    })
}

fn at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |value, key| value.get(key))
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    at(value, path).and_then(Value::as_str)
}

fn u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    at(value, path).and_then(Value::as_u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trigger(commands: &[&str]) -> Trigger {
        Trigger {
            events: EVENTS.iter().map(|e| e.to_string()).collect(),
            roles: default_roles(),
            bots: vec![],
            forks: false,
            commands: commands.iter().map(|c| c.to_string()).collect(),
            stop_after: None,
            labels: vec![],
        }
    }

    #[test]
    fn label_commands_use_the_added_label_and_existing_security_checks() {
        let permission = Permission {
            permission: "write".into(),
            role_name: None,
            user: PermissionUser {
                login: "alice".into(),
            },
        };
        let cases = [
            (
                "issues",
                "labeled",
                Some("agent-review"),
                "write",
                false,
                true,
            ),
            ("issues", "labeled", Some("other"), "write", false, false),
            ("issues", "labeled", None, "write", false, false),
            (
                "issues",
                "opened",
                Some("agent-review"),
                "write",
                false,
                false,
            ),
            (
                "issues",
                "unlabeled",
                Some("agent-review"),
                "write",
                false,
                false,
            ),
            (
                "issues",
                "labeled",
                Some("agent-review"),
                "read",
                false,
                false,
            ),
            (
                "pull_request_target",
                "labeled",
                Some("agent-review"),
                "write",
                false,
                true,
            ),
            (
                "pull_request_target",
                "labeled",
                Some("agent-review"),
                "write",
                true,
                false,
            ),
            (
                "discussion",
                "labeled",
                Some("agent-review"),
                "write",
                false,
                true,
            ),
            (
                "discussion",
                "labeled",
                Some("other"),
                "write",
                false,
                false,
            ),
            (
                "discussion",
                "labeled",
                Some("agent-review"),
                "read",
                false,
                false,
            ),
        ];
        for (event, action, label, role, fork, admitted) in cases {
            let mut trigger = trigger(&["/agent"]);
            trigger.labels = vec!["agent-review".into()];
            let mut permission = permission.clone();
            permission.permission = role.into();
            let mut payload = serde_json::json!({
                "repository": {"id": 1, "full_name": "octo/repo"},
                "sender": {"login": "alice", "type": "User"},
                "action": action,
                "label": {"name": label},
            });
            let key = match event {
                "issues" => "issue",
                "discussion" => "discussion",
                _ => "pull_request",
            };
            payload[key] = serde_json::json!({
                "number": 12, "title": "Review this", "body": "Item text",
                "user": {"login": "bob"},
                "labels": [{"name": "agent-review"}],
                "base": {"ref": "main"},
                "head": {"repo": {"id": if fork { 2 } else { 1 }},
                    "ref": "feature", "sha": "a".repeat(40)},
            });
            let outcome = decide(&Input {
                trigger: &trigger,
                event_name: event,
                payload: &payload,
                actor: "alice",
                repository: "octo/repo",
                permission: Some(&permission),
                pull_request: None,
            });
            assert_eq!(
                outcome.decision.admitted, admitted,
                "{event} {action} {label:?} {role} fork={fork}: {}",
                outcome.decision.reason
            );
            if admitted {
                assert_eq!(outcome.decision.command.as_deref(), Some("agent-review"));
                assert_eq!(outcome.text.author, "bob");
                assert_eq!(outcome.decision.item.as_ref().unwrap().number, 12);
            } else {
                assert_eq!(outcome.text, Text::default());
                assert_eq!(outcome.decision.command, None);
            }
        }
    }

    #[test]
    fn label_configuration_is_validated() {
        for (label, valid) in [
            ("agent-review".to_owned(), true),
            ("review requested".to_owned(), true),
            ("".to_owned(), false),
            ("  ".to_owned(), false),
            ("a\nb".to_owned(), false),
            ("a".repeat(49), true),
            ("a".repeat(50), true),
            ("a".repeat(51), false),
            ("é".repeat(25), true),
            ("é".repeat(26), false),
        ] {
            let mut trigger = trigger(&["/agent"]);
            trigger.labels = vec![label.clone()];
            assert_eq!(trigger.validate().is_ok(), valid, "{label:?}");
        }
    }

    #[test]
    fn commands_match_at_the_start_only() {
        let t = trigger(&["/agent", "/review"]);
        let cases: &[(&str, Option<(&str, &str)>)] = &[
            ("/agent fix it", Some(("agent", "fix it"))),
            ("/agent", Some(("agent", ""))),
            ("/agent\nmore", Some(("agent", "more"))),
            ("/agent   fix it  \nmore", Some(("agent", "fix it  \nmore"))),
            ("/review", Some(("review", ""))),
            (" /agent", None),
            ("please /agent", None),
            ("/agentx", None),
            ("/other", None),
            ("", None),
        ];
        for (body, expected) in cases {
            let got = match_command(&t, body).ok();
            let expected = expected.map(|(c, r)| (c.to_string(), r.to_string()));
            assert_eq!(got, expected, "{body:?}");
        }
    }

    /// What keeps a reason from spanning two lines of $GITHUB_OUTPUT.
    #[test]
    fn a_reason_is_one_line() {
        assert_eq!(one_line("a\nb\r\tc"), "a b  c");
    }

    #[test]
    fn a_base_is_a_branch_name() {
        let cases = [
            ("main", true),
            ("release/1.2", true),
            ("feature.v2", true),
            ("-x", false),
            ("a b", false),
            ("a\nb", false),
            ("a~b", false),
            ("", false),
        ];
        for (name, ok) in cases {
            assert_eq!(REF_RE.is_match(name), ok, "{name:?}");
        }
    }

    #[test]
    fn a_trigger_table_is_validated() {
        let mut t = trigger(&["/agent"]);
        t.validate().unwrap();
        t.commands = vec!["agent".into()];
        assert!(t.validate().is_err());
        t.commands = vec!["/a b".into()];
        assert!(t.validate().is_err());
        t.commands = vec![];
        t.bots = vec![GITHUB_ACTIONS.into()];
        assert!(t.validate().is_err());
        t.bots = vec![];
        t.events = vec!["push".into()];
        assert!(t.validate().is_err());
        t.events = vec![];
        t.roles = vec![];
        assert!(t.validate().is_err());
        // A comment event with no command would refuse every comment.
        let mut t = trigger(&[]);
        assert!(t.validate().is_err());
        t.events = vec!["issues".into()];
        t.validate().unwrap();
        // "all" admits anyone, so beside a role it would hide that.
        t.roles = vec![ALL_ROLES.into()];
        t.validate().unwrap();
        t.roles = vec![ALL_ROLES.into(), "write".into()];
        assert!(t.validate().is_err());
    }
}
