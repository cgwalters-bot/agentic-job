//! GitHub's native publishing (agentic-job's `publish`): the output types
//! the bounds route away from gh-aw's handlers (`native_handlers`, GitHub
//! only) published without them, as gh-aw's handlers at apply.yml's pin
//! publish them: the same requests in the same order, with the same
//! bodies, and the same records of them (`safe-output-items.jsonl`,
//! `safe-output-errors.json`, the step's outputs and summary). For the
//! types of [`HANDLERS`], on the [`Publisher`] for GitHub and its client;
//! agentic-job's `tests/data/publication` records what gh-aw sends.
//!
//! The caller reads the requests, the handlers' configuration and the
//! run's variables ([`Run::read`]), gives the check job's [`Upload`] and
//! the GitHub client, and writes each log line [`apply`] gives it as the
//! workflow command it names, escaped as its log takes untrusted text.
//!
//! apply.yml runs this after the steps that edit the requests and the
//! guard that leaves out what an earlier attempt applied, all of which
//! stay as they are, and before gh-aw's handler step, which reads only
//! the requests this leaves it (`--remainder`). Each request goes to one
//! of the two: the remainder is written before anything is published,
//! and not at all when this refuses, so gh-aw's step then finds none.
//! A pull request or push that fails here has it written again: gh-aw's
//! handler manager starts each comment after a failed one with a warning
//! that its changes were not applied, and its comments are left gh-aw's.
//! The routed requests come first in the run's order and are published
//! first, so the order of everything published is the run's. Review
//! comments are buffered and submitted in one review after the other
//! routed requests, as gh-aw's manager submits them after everything:
//! a run with them leaves gh-aw's handlers nothing to publish.
//!
//! Where gh-aw's handlers would do what this does not, this refuses the
//! run before the first write rather than do something else: a request
//! after one of gh-aw's types, a field or setting this does not read, a
//! temporary ID, a workflow input gh-aw reads from a file this ignores,
//! a mention it would look up, or a label this cannot tell gh-aw would
//! keep as written. A pull request or push that fails is not
//! followed by the routed comments after it, which gh-aw would post with
//! a note of its own; a push goes only onto the head the run was asked
//! for, where gh-aw's handler would apply the patch on a branch rewritten
//! since; and nothing here falls back to opening an issue or a pull
//! request, or commenting on a discussion. gh-aw reads settings this does not
//! (`GH_AW_SAFE_OUTPUT_MESSAGES`, `GH_AW_TRACKER_ID` and the like):
//! apply.yml sets none of them for either.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use serde_json::{Map, Value, json};

use super::git::{Moved, Push, TooLarge};
use super::github::{ACTIONS_COMMITTER, Github, GithubPublisher, Refused};
use super::{
    ADD_COMMENT, ADD_LABELS, CLOSE_ISSUE, CLOSE_PULL_REQUEST, CREATE_ISSUE, Close, Committer,
    Kind as ItemKind, Made, Publisher, PullRequest, REMOVE_LABELS, Report, Upload, read_report,
};
use crate::check::{self, handler_limits::LINK_RE};
use crate::collect::markdown::outside_code;
use crate::collect::sanitize::{
    JS_SPACE, Mentions, is_js_space, js_trim, sanitize_with, utf16_len, utf16_prefix,
};
use crate::contract::Policy;
use crate::{CREATE_PULL_REQUEST, CREATE_REVIEW_COMMENT, PUSH_TO_PULL_REQUEST_BRANCH};

/// What this publishes of one type, as gh-aw's handler does.
#[derive(Debug)]
pub struct Handler {
    pub output: &'static str,
    /// The fields of a request this publishes as gh-aw does; any other is
    /// refused. `repo` only as the handler's own.
    fields: &'static [&'static str],
    /// The settings apply.yml writes for the handler; any other is refused.
    settings: &'static [&'static str],
    /// Those of them that must be as given (JSON): what this does is all
    /// it can do.
    fixed: &'static [(&'static str, &'static str)],
}

/// The types `agentic-job publish` publishes, each where the bounds'
/// `native_handlers` name it. A comment's numbers are those its fixed
/// target ignores; a pull request's `base` is only the handler's own and
/// its `labels` only empty.
pub const HANDLERS: &[Handler] = &[
    Handler {
        output: "document",
        fields: &["type", "title", "files", "summary", "gist_id"],
        settings: &["max", "document", "target-repo", "target"],
        fixed: &[],
    },
    Handler {
        output: ADD_COMMENT,
        fields: &["type", "body", "item_number", "pr", "pr_number", "repo"],
        settings: &["max", "target-repo", "target"],
        fixed: &[],
    },
    Handler {
        output: CREATE_PULL_REQUEST,
        fields: &[
            "type", "title", "body", "branch", "draft", "repo", "base", "labels",
        ],
        settings: &[
            "max",
            "protected_files",
            "protect_top_level_dot_folders",
            "protected_dot_folder_excludes",
            "protected_files_policy",
            "draft",
            "max_patch_size",
            "max_patch_files",
            "signed_commits",
            "fallback_as_issue",
            "preserve_branch_name",
            "auto_close_issue",
            "target-repo",
            "base_branch",
            "branch_prefix",
            "title_prefix",
            "head-repo",
            "allowed_repos",
        ],
        fixed: &[
            ("signed_commits", "false"),
            ("fallback_as_issue", "false"),
            ("preserve_branch_name", "true"),
            ("auto_close_issue", "false"),
            ("protected_files_policy", r#""blocked""#),
        ],
    },
    // The number alone names the item: no temporary ID, alias or fallback
    // to the event's.
    Handler {
        output: ADD_LABELS,
        fields: &["type", "repo", "item_number", "labels"],
        settings: &[
            "max",
            "allowed",
            "blocked",
            "target-repo",
            "target",
            "issue_intent",
            "create_if_missing",
        ],
        fixed: &[
            ("target", r#""*""#),
            ("issue_intent", "false"),
            ("create_if_missing", "false"),
        ],
    },
    Handler {
        output: REMOVE_LABELS,
        fields: &["type", "repo", "item_number", "labels"],
        settings: &["max", "allowed", "blocked", "target-repo", "target"],
        fixed: &[("target", r#""*""#)],
    },
    // No `duplicate_of` and no intent metadata, which gh-aw's handler would
    // also act on.
    Handler {
        output: CLOSE_ISSUE,
        fields: &["type", "repo", "issue_number", "body", "state_reason"],
        settings: &["max", "target-repo", "target", "issue_intent", "allow_body"],
        fixed: &[
            ("target", r#""*""#),
            ("issue_intent", "false"),
            ("allow_body", "true"),
        ],
    },
    Handler {
        output: CLOSE_PULL_REQUEST,
        fields: &["type", "repo", "pull_request_number", "body"],
        settings: &["max", "target-repo", "target"],
        fixed: &[("target", r#""*""#)],
    },
    // The pull request is the handler's fixed `target`, which the number a
    // request names does not change; the commit's message is the patch's.
    // `head`, `author` and the replacement settings are apply.yml's, which
    // the handler does not read.
    Handler {
        output: PUSH_TO_PULL_REQUEST_BRANCH,
        fields: &["type", "repo", "pull_request_number", "branch", "message"],
        settings: &[
            "max",
            "target",
            "head",
            "author",
            "replacement_max_commits",
            "replacement_max_files",
            "replacement_base",
            "protected_files",
            "protect_top_level_dot_folders",
            "protected_dot_folder_excludes",
            "allow_workflows",
            "protected_files_policy",
            "max_patch_size",
            "max_patch_files",
            "signed_commits",
            "fallback_as_pull_request",
            "if_no_changes",
            "target-repo",
            "head-repo",
            "allowed_repos",
            "checkout_mapping",
        ],
        fixed: &[
            ("signed_commits", "false"),
            ("fallback_as_pull_request", "false"),
            ("if_no_changes", r#""error""#),
            ("protected_files_policy", r#""blocked""#),
        ],
    },
    // No `temporary_id`, `parent` or other link to another issue, which
    // check refuses too. The bounds' `allowed` and `blocked` are check's,
    // which the handler does not read. `comment_on_duplicate` is this
    // port's alone: gh-aw's handler has no such setting.
    Handler {
        output: CREATE_ISSUE,
        fields: &["type", "repo", "title", "body", "labels"],
        settings: &[
            "max",
            "target-repo",
            "title_prefix",
            "allowed",
            "blocked",
            "comment_on_duplicate",
        ],
        fixed: &[],
    },
    // On the handler's fixed `target`, whatever number a request names;
    // buffered into one review of event COMMENT, which gh-aw's handler
    // manager submits once every request is handled.
    Handler {
        output: CREATE_REVIEW_COMMENT,
        fields: &[
            "type",
            "repo",
            "pull_request_number",
            "path",
            "line",
            "start_line",
            "side",
            "body",
        ],
        settings: &["max", "target-repo", "target"],
        fixed: &[],
    },
];

/// The handler of OUTPUT, if this publishes it.
pub fn handler(output: &str) -> Option<&'static Handler> {
    HANDLERS.iter().find(|handler| handler.output == output)
}

/// The field naming the one item OUTPUT acts on, where it names one.
fn number_field(output: &str) -> Option<&'static str> {
    match output {
        ADD_LABELS | REMOVE_LABELS => Some("item_number"),
        CLOSE_ISSUE => Some("issue_number"),
        CLOSE_PULL_REQUEST => Some("pull_request_number"),
        _ => None,
    }
}

/// The largest number JavaScript holds exactly, which gh-aw's handlers
/// read a request's number as.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// `MAX_LABELS`: the most labels one add_labels may name.
const MAX_LABELS: usize = 10;

/// The longest label gh-aw's sanitizer keeps whole.
const MAX_LABEL: usize = 64;

/// The ways to close an issue gh-aw's handler takes, in its words.
const STATE_REASONS: &[&str] = &["completed", "not_planned", "duplicate"];

/// The workflow_dispatch inputs and repository_dispatch payload gh-aw's
/// `resolveInvocationContext` reads the event from instead of the
/// runner's: a label's records would name the item from them.
const DISPATCH_CONTEXT_INPUTS: &[&str] = &[
    "event_name",
    "eventName",
    "event_payload",
    "eventPayload",
    "aw_context",
    "awContext",
    "target_repo",
    "targetRepo",
];

/// The `X-GitHub-Api-Version` gh-aw's handlers send (its constants.cjs).
const API_VERSION: &str = "2026-03-10";

/// The URL policy apply.yml gives gh-aw's handlers, the only one this
/// sanitizes by.
const URL_POLICY: &str = "allowed-or-code-region";

/// The types gh-aw's handlers publish nothing for here: a routed request
/// may come after one of them.
const QUIET: &[&str] = &["noop", "missing_tool", "missing_data"];

/// The types that push code, whose first failure gh-aw's handler manager
/// notes in each comment after it (`CODE_PUSH_TYPES`).
const CODE_PUSHES: &[&str] = &[CREATE_PULL_REQUEST, PUSH_TO_PULL_REQUEST_BRANCH];

/// What gh-aw's footer reads from GH_AW_TMP when there: an agent's
/// metadata, and firewall and gateway logs. check's upload holds none.
const FOOTER_INPUTS: &[&str] = &[
    "aw_info.json",
    "usage",
    "sandbox/firewall/logs",
    "mcp-logs/gateway.jsonl",
    "mcp-logs/rpc-messages.jsonl",
];

/// The handlers' sanitizer's own default bound.
const MAX_SANITIZED: usize = 524_288;

/// `MAX_GITHUB_BODY_LENGTH` and comment_limit_helpers.cjs's limits.
const MAX_BODY_UNITS: usize = 65_536;
const MAX_MENTIONS: usize = 10;
const MAX_LINKS: usize = 50;

/// The most mentions a body keeps (`mentions.max`, unset).
const MAX_ALLOWED_MENTIONS: usize = 50;

/// apply.yml's bound on the workflow's name in a footer.
const MAX_WORKFLOW_NAME: usize = 100;

/// A pull request's title, at most (`sanitizeTitle`).
const MAX_TITLE: usize = 128;

/// gh-aw's error codes a summary names (error_codes.cjs).
const SUMMARY_CODES: &[&str] = &[
    "ERR_VALIDATION",
    "ERR_PERMISSION",
    "ERR_API",
    "ERR_CONFIG",
    "ERR_NOT_FOUND",
    "ERR_PARSE",
    "ERR_SYSTEM",
    "E001",
    "E002",
    "E007",
    "E009",
    "E010",
    "E099",
    "CONFIG_HASH_MISMATCH",
    "RATE_LIMIT_EXCEEDED",
    "POLICY_FILE_PROTECTION_DENIED",
];

static REPO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").expect("a valid pattern"));

static NUMBER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[1-9][0-9]*$").expect("a valid pattern"));

/// An https origin as `new URL()` writes it back, which the footer's
/// links and the execution provenance are made of.
static ORIGIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$").expect("a valid pattern")
});

/// A mention as gh-aw's mention resolution reads one
/// (`extractMentions`).
static KNOWN_MENTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:^|[^A-Za-z0-9_`])@([A-Za-z0-9](?:[A-Za-z0-9_-]{0,37}[A-Za-z0-9])?(?:/[A-Za-z0-9._-]+)?)",
    )
    .expect("a valid pattern")
});

/// A mention as `enforceCommentLimits` counts one.
static MENTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:^|[^A-Za-z0-9])@[A-Za-z0-9](?:[A-Za-z0-9_-]{0,37}[A-Za-z0-9])?(?:/[A-Za-z0-9._-]+)?",
    )
    .expect("a valid pattern")
});

static HTML_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<code(?-u:\b)[^>]*>(?s:.)*?</code>").expect("a valid pattern")
});

/// `stripExecutionProvenance`'s reserved markers.
static RESERVED_MARKER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?i)<!--[-![{JS_SPACE}]]*gh-aw-(?:execution|agentic-workflow)[{JS_SPACE}]*:"
    ))
    .expect("a valid pattern")
});

/// The name the guard put last in a body, which apply.yml's hook hides
/// as the request is sent, after [`check::APPLIED_MARKER`].
static APPLIED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^: [0-9]+/[0-9]+/[0-9a-f]{16}$").expect("a valid pattern"));

/// What the runner and apply.yml tell gh-aw's handlers about the run, in
/// the variables they read.
#[derive(Debug, Clone)]
pub struct Run {
    /// `GITHUB_SERVER_URL`, an https origin.
    server: String,
    /// `GITHUB_REPOSITORY`, where the run is.
    repository: String,
    repository_id: String,
    run_id: String,
    run_attempt: String,
    /// `GITHUB_JOB`: apply.yml's `apply`.
    job: String,
    /// `GH_AW_JOB_CHECK_RUN_ID`.
    check_run_id: String,
    /// `GH_AW_WORKFLOW_ID`.
    workflow_id: String,
    /// `GH_AW_WORKFLOW_NAME`, cut as apply.yml cuts it.
    workflow_name: String,
    event_name: String,
    /// The event's payload, `{}` without one.
    event: Value,
    actor: String,
    links: Links,
}

/// The links gh-aw's sanitizer keeps, as a step's `GH_AW_SAFE_OUTPUTS_URLS`
/// and `GH_AW_ALLOWED_DOMAINS` and the runner's server and API URLs say.
#[derive(Debug, Clone)]
pub struct Links {
    /// The hosts links are kept to (`buildAllowedDomains`).
    domains: Vec<String>,
}

impl Links {
    /// The policy from VARIABLE; refused unless it is [`URL_POLICY`].
    pub fn read(variable: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        let var = |name: &str| variable(name).unwrap_or_default();
        let urls = var("GH_AW_SAFE_OUTPUTS_URLS");
        ensure!(
            urls == URL_POLICY,
            "GH_AW_SAFE_OUTPUTS_URLS is {urls:?}, and this sanitizes as {URL_POLICY:?} only"
        );
        let server = variable("GITHUB_SERVER_URL").unwrap_or_else(|| "https://github.com".into());
        Ok(Self {
            domains: allowed_domains(
                &var("GH_AW_ALLOWED_DOMAINS"),
                &[&server, &var("GITHUB_API_URL")],
            ),
        })
    }

    /// Whether gh-aw's sanitizer keeps a link to HOST.
    pub fn keeps(&self, host: &str) -> bool {
        let host = host.to_lowercase();
        self.domains.iter().any(|domain| {
            let domain = domain.to_lowercase();
            match domain.strip_prefix("*.") {
                Some(base) => host == base || host.ends_with(&format!(".{base}")),
                None => host == domain || host.ends_with(&format!(".{domain}")),
            }
        })
    }
}

impl Run {
    /// The run from VARIABLE, as gh-aw's handlers read it; refused where
    /// they would read something this does not.
    pub fn read(variable: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        let var = |name: &str| variable(name).unwrap_or_default();
        let required = |name: &str| {
            let value = var(name);
            ensure!(
                !value.is_empty() && value.trim() == value,
                "{name} is not set, or not as gh-aw's handlers take it"
            );
            Ok(value)
        };
        let numeric = |name: &str| {
            let value = var(name);
            ensure!(
                NUMBER_RE.is_match(&value),
                "{name} is not a positive integer"
            );
            Ok(value)
        };
        let server = variable("GITHUB_SERVER_URL").unwrap_or_else(|| "https://github.com".into());
        ensure!(
            ORIGIN_RE.is_match(&server),
            "GITHUB_SERVER_URL {server:?} is not an https origin as gh-aw writes one back"
        );
        let repository = var("GITHUB_REPOSITORY");
        ensure!(
            REPO_RE.is_match(&repository),
            "GITHUB_REPOSITORY {repository:?} is not OWNER/NAME"
        );
        let links = Links::read(variable)?;
        let mut workflow_name = var("GH_AW_WORKFLOW_NAME");
        if workflow_name.is_empty() {
            workflow_name = "Workflow".into();
        }
        if utf16_len(&workflow_name) > MAX_WORKFLOW_NAME {
            workflow_name = format!("{}…", utf16_prefix(&workflow_name, MAX_WORKFLOW_NAME - 1));
        }
        let event = match variable("GITHUB_EVENT_PATH").filter(|path| Path::new(path).exists()) {
            Some(path) => {
                let text = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading the event {path}"))?;
                serde_json::from_str(&text).with_context(|| format!("the event {path}"))?
            }
            None => json!({}),
        };
        Ok(Self {
            links,
            server,
            repository,
            repository_id: numeric("GITHUB_REPOSITORY_ID")?,
            run_id: numeric("GITHUB_RUN_ID")?,
            run_attempt: numeric("GITHUB_RUN_ATTEMPT")?,
            job: required("GITHUB_JOB")?,
            check_run_id: numeric("GH_AW_JOB_CHECK_RUN_ID")?,
            workflow_id: required("GH_AW_WORKFLOW_ID")?,
            workflow_name,
            event_name: var("GITHUB_EVENT_NAME"),
            event,
            actor: var("GITHUB_ACTOR"),
        })
    }

    /// The run's page.
    fn run_url(&self) -> String {
        format!(
            "{}/{}/actions/runs/{}",
            self.server, self.repository, self.run_id
        )
    }

    /// Whether gh-aw's sanitizer keeps a link to HOST.
    fn keeps_link(&self, host: &str) -> bool {
        self.links.keeps(host)
    }

    /// The `#N` a footer names, if the event names an issue, a pull
    /// request or a discussion, as KIND reads the event: an issue's number
    /// first, which a pull request's handler takes only for an issue.
    fn triggering(&self, kind: &str) -> Result<Option<String>> {
        let issue = self.event_number("issue")?.filter(|_| {
            kind == ADD_COMMENT
                || self.event["issue"]["pull_request"].is_null()
                || self.event["issue"]["pull_request"] == Value::Bool(false)
        });
        Ok(
            match (
                issue,
                self.event_number("pull_request")?,
                self.event_number("discussion")?,
            ) {
                (Some(n), _, _) | (None, Some(n), _) => Some(format!("#{n}")),
                (None, None, Some(n)) => Some(format!("discussion #{n}")),
                (None, None, None) => None,
            },
        )
    }

    /// The `#N` a closing comment's footer names: the event's issue, or
    /// else its pull request (`buildCommentBody`).
    fn closing_triggering(&self) -> Result<Option<String>> {
        Ok(self
            .event_number("issue")?
            .or(self.event_number("pull_request")?)
            .map(|n| format!("#{n}")))
    }

    /// The `#N` the footer of an issue or a review names
    /// (`formatIssueBody`, the review buffer's footer): the event's issue
    /// unless it is a pull request's, or else its pull request, or else its
    /// discussion.
    fn item_triggering(&self) -> Result<Option<String>> {
        let issue = self.event_number("issue")?;
        let of_pull = truthy(&self.event["issue"]["pull_request"]);
        let pull = self
            .event_number("pull_request")?
            .or(issue.filter(|_| of_pull));
        Ok(
            match (
                issue.filter(|_| !of_pull),
                pull,
                self.event_number("discussion")?,
            ) {
                (Some(n), _, _) | (None, Some(n), _) => Some(format!("#{n}")),
                (None, None, Some(n)) => Some(format!("discussion #{n}")),
                (None, None, None) => None,
            },
        )
    }

    /// The number of the event's KEY (`issue`, `pull_request`,
    /// `discussion`), where it names one.
    fn event_number(&self, key: &str) -> Result<Option<u64>> {
        match &self.event[key]["number"] {
            Value::Null => Ok(None),
            Value::Number(n) if n.as_u64().is_some_and(|n| n > 0) => Ok(n.as_u64()),
            Value::Number(n) if n.as_u64() == Some(0) => Ok(None),
            other => bail!("the event's {key} number {other} is not one gh-aw writes as is"),
        }
    }

    /// What gh-aw's label handlers call the item in their records
    /// (`contextType`): a pull request where the event is one's, as
    /// `resolveInvocationContext` reads it.
    fn context_kind(&self) -> Result<&'static str> {
        self.read_as_dispatched()?;
        Ok(if truthy(&self.event["pull_request"]) {
            "pull request"
        } else {
            "issue"
        })
    }

    /// Refuses a dispatch whose inputs or payload gh-aw's
    /// `resolveInvocationContext` would read the event from, or refuse
    /// (a `target_repo` it does not allow), as the label and closing
    /// handlers resolve their item.
    fn read_as_dispatched(&self) -> Result<()> {
        match self.event_name.as_str() {
            "workflow_dispatch" => {
                for input in DISPATCH_CONTEXT_INPUTS {
                    ensure!(
                        self.event["inputs"].get(input).is_none(),
                        "the dispatch's input {input}, which gh-aw's handlers would read the \
                         event from"
                    );
                }
            }
            "repository_dispatch" => ensure!(
                !self.event["client_payload"].is_object(),
                "the dispatch's client_payload, which gh-aw's handlers would read the event from"
            ),
            _ => {}
        }
        Ok(())
    }

    /// The people the event names, who may be mentioned
    /// (`extractKnownAuthorsFromPayload`): not bots.
    fn known_authors(&self) -> Vec<String> {
        let event = &self.event;
        let mut users = Vec::new();
        let mut user = |user: &Value| {
            if let Some(login) = user["login"].as_str().filter(|login| !login.is_empty())
                && user["type"] != "Bot"
            {
                users.push(login.to_owned());
            }
        };
        let assignees = |value: &Value| value.as_array().cloned().unwrap_or_default();
        match self.event_name.as_str() {
            "issues" => {
                user(&event["issue"]["user"]);
                assignees(&event["issue"]["assignees"])
                    .iter()
                    .for_each(&mut user);
            }
            "pull_request" | "pull_request_target" => {
                user(&event["pull_request"]["user"]);
                assignees(&event["pull_request"]["assignees"])
                    .iter()
                    .for_each(&mut user);
            }
            "issue_comment" => {
                user(&event["comment"]["user"]);
                user(&event["issue"]["user"]);
                assignees(&event["issue"]["assignees"])
                    .iter()
                    .for_each(&mut user);
            }
            "pull_request_review_comment" => {
                user(&event["comment"]["user"]);
                user(&event["pull_request"]["user"]);
                assignees(&event["pull_request"]["assignees"])
                    .iter()
                    .for_each(&mut user);
            }
            "pull_request_review" => {
                user(&event["review"]["user"]);
                user(&event["pull_request"]["user"]);
                assignees(&event["pull_request"]["assignees"])
                    .iter()
                    .for_each(&mut user);
            }
            "discussion" => user(&event["discussion"]["user"]),
            "discussion_comment" => {
                user(&event["comment"]["user"]);
                user(&event["discussion"]["user"]);
            }
            "release" => user(&event["release"]["author"]),
            "workflow_dispatch" if !self.actor.is_empty() => users.push(self.actor.clone()),
            _ => {}
        }
        users
    }

    /// The mentions a handler keeps by default
    /// (`resolveAllowedMentionsFromPayload`): those of the event's people
    /// its own reading finds. One it would look up, as it does for a name
    /// it reads otherwise, is refused.
    fn default_mentions(&self) -> Result<Vec<String>> {
        let known = dedupe(self.known_authors());
        let text = known
            .iter()
            .map(|author| format!("@{author}"))
            .collect::<Vec<_>>()
            .join(" ");
        let lower: Vec<String> = known.iter().map(|author| author.to_lowercase()).collect();
        let mut allowed = Vec::new();
        for caps in KNOWN_MENTION_RE.captures_iter(&text) {
            let name = caps[1].to_owned();
            if allowed
                .iter()
                .any(|seen: &String| seen.to_lowercase() == name.to_lowercase())
            {
                continue;
            }
            ensure!(
                lower.contains(&name.to_lowercase()),
                "the event names {name:?} in a way gh-aw's handlers would look up"
            );
            allowed.push(name);
        }
        Ok(allowed)
    }
}

/// Whether JavaScript takes VALUE for true.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(n) => n.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// NAMES without a second spelling of one, case ignored, in order.
fn dedupe(names: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    names
        .into_iter()
        .filter(|name| seen.insert(name.to_lowercase()))
        .collect()
}

/// `buildAllowedDomains`: LISTED (comma-separated), or gh-aw's own
/// defaults without it, and the hosts of the server and API URLS.
fn allowed_domains(listed: &str, urls: &[&str]) -> Vec<String> {
    let mut domains: Vec<String> = listed
        .split(',')
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .map(str::to_owned)
        .collect();
    if listed.is_empty() {
        domains = crate::GH_AW_LINK_DOMAINS
            .iter()
            .map(|domain| (*domain).to_owned())
            .collect();
    }
    for url in urls {
        let Some(host) = url_host(url) else {
            continue;
        };
        if host == "github.com" {
            domains.extend(
                [
                    "github.com",
                    "api.github.com",
                    "raw.githubusercontent.com",
                    "*.githubusercontent.com",
                ]
                .map(str::to_owned),
            );
        } else if host.starts_with("api.") {
            domains.push(host);
        } else {
            domains.extend([format!("api.{host}"), format!("raw.{host}")]);
            domains.insert(domains.len() - 2, host);
        }
    }
    let mut seen = BTreeSet::new();
    domains.retain(|domain| seen.insert(domain.clone()));
    domains
}

/// The host of URL, lowercase, as `new URL(url).hostname` gives it.
fn url_host(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if host.starts_with('[') {
        host.split_inclusive(']').next()?
    } else {
        host.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_lowercase())
}

/// `normalizeBranchName`, without a salt.
pub fn normalize_branch(name: &str) -> String {
    static INVALID: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[^a-zA-Z0-9\-_/.]+").expect("a valid pattern"));
    static DASHES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"-+").expect("a valid pattern"));
    if js_trim(name).is_empty() {
        return name.to_owned();
    }
    let normalized = INVALID.replace_all(name, "-");
    let normalized = DASHES.replace_all(&normalized, "-");
    let mut normalized = normalized.trim_matches('-').to_owned();
    if normalized.len() > 128 {
        // ASCII alone is left: a cut is at a character.
        normalized.truncate(128);
    }
    normalized.trim_end_matches('-').to_owned()
}

/// A handler's setting KEY of CONFIG as text.
fn setting<'a>(config: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    config
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("the handler setting {key} is not text"))
}

/// A request routed here, with its place among all of the run's.
#[derive(Debug, Clone)]
struct Routed {
    index: usize,
    item: Map<String, Value>,
}

/// The run's requests, split between the two sets of handlers.
#[derive(Debug)]
struct Split {
    ours: Vec<Routed>,
    /// The others, in order: what gh-aw's handlers are given.
    rest: Vec<Value>,
}

/// Splits ITEMS between this, for the types of ROUTED, and gh-aw's
/// handlers, or refuses with every reason found.
fn split(items: &[Value], routed: &[String]) -> Result<Split, Vec<String>> {
    let mut errors = Vec::new();
    let (mut ours, mut rest) = (Vec::new(), Vec::new());
    let mut theirs: Option<&str> = None;
    let mut fallback: Option<&str> = None;
    for (index, item) in items.iter().enumerate() {
        let Some(map) = item.as_object() else {
            errors.push(format!("request {} is not an object", index + 1));
            continue;
        };
        let output = check::item_type(map);
        if !routed.iter().any(|routed| routed == output) {
            if !QUIET.contains(&output) {
                theirs.get_or_insert(output);
            }
            if CODE_PUSHES.contains(&output) {
                fallback.get_or_insert(output);
            }
            rest.push(item.clone());
            continue;
        }
        if let Some(theirs) = theirs {
            errors.push(format!(
                "a {output} after a {theirs}, which gh-aw's handlers publish: published first, \
                 it would change the run's order"
            ));
        }
        let Some(handler) = handler(output) else {
            errors.push(format!(
                "the bounds route {output} to agentic-job publish, which does not publish it"
            ));
            continue;
        };
        errors.extend(shape(output, map));
        for (key, value) in map {
            if !handler.fields.contains(&key.as_str()) {
                errors.push(format!(
                    "a {output} with the field {key:?}, which agentic-job publish does not publish"
                ));
            }
            if holds_temporary_reference(value) {
                errors.push(format!(
                    "a {output} naming a temporary ID (#aw_) in {key:?}, which gh-aw's handlers \
                     resolve across types"
                ));
            }
        }
        ours.push(Routed {
            index,
            item: map.clone(),
        });
    }
    let routes = |output: &str| {
        ours.iter()
            .any(|routed| check::item_type(&routed.item) == output)
    };
    // gh-aw's handler manager submits the review once every request is
    // handled, its own handlers' too: here it would come before theirs.
    if let Some(theirs) = theirs.filter(|_| routes(CREATE_REVIEW_COMMENT)) {
        errors.push(format!(
            "a {CREATE_REVIEW_COMMENT} and a {theirs}, which gh-aw's handlers publish: the review \
             is submitted after everything else, and would be before it"
        ));
    }
    // apply.yml lets gh-aw's step open up to the run's create_issue count
    // of issues, a pull request's in its place among them: with those
    // opened here, there could be more.
    if let Some(fallback) = fallback.filter(|_| routes(CREATE_ISSUE)) {
        errors.push(format!(
            "a {CREATE_ISSUE} and a {fallback}, which gh-aw's handlers publish and may open an \
             issue for: the run's create_issue count bounds both"
        ));
    }
    if errors.is_empty() {
        Ok(Split { ours, rest })
    } else {
        Err(errors)
    }
}

/// Why ITEM, a request of OUTPUT, is not one this publishes as gh-aw's
/// handler would, from what it holds alone: its number other than a
/// positive integer, a label other than a plain string the handler's
/// sanitizer leaves as it is, or another way to close an issue.
fn shape(output: &str, item: &Map<String, Value>) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(key) = number_field(output)
        && !item
            .get(key)
            .and_then(Value::as_u64)
            .is_some_and(|n| n > 0 && n <= MAX_SAFE_INTEGER)
    {
        errors.push(format!(
            "a {output} without a positive integer {key}, which agentic-job publish requires"
        ));
    }
    if output == CREATE_REVIEW_COMMENT {
        errors.extend(review_comment_shape(item).err());
    }
    if output == "document" {
        errors.extend(
            crate::document::Document::parse(item)
                .err()
                .map(|err| format!("{err:#}")),
        );
    }
    if output == CREATE_ISSUE {
        errors.extend(
            ["title", "body"]
                .iter()
                .filter(|key| item.get(**key).is_some_and(|value| !value.is_string()))
                .map(|key| format!("a {output} whose {key} is not text")),
        );
    }
    if matches!(output, ADD_LABELS | REMOVE_LABELS | CREATE_ISSUE) {
        match item.get("labels") {
            None => {}
            Some(Value::Array(labels)) => errors.extend(
                labels
                    .iter()
                    .filter(|label| !label.as_str().is_some_and(plain_label))
                    .map(|label| {
                        format!(
                            "a {output} with the label {label}, which agentic-job publish does \
                             not publish (a plain label of at most {MAX_LABEL} letters, digits \
                             and \" -_./:\")"
                        )
                    }),
            ),
            Some(_) => errors.push(format!("a {output} whose labels are not an array")),
        }
    }
    if output == CLOSE_ISSUE
        && let Some(reason) = item.get("state_reason")
        && !reason.as_str().is_some_and(|reason| {
            STATE_REASONS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(reason))
        })
    {
        errors.push(format!(
            "a {output} with state_reason {reason}, which is not one of {}",
            STATE_REASONS.join(", ")
        ));
    }
    errors
}

/// Why ITEM, a review comment, is not one gh-aw's handler buffers as it
/// is: a path, a positive line (and start line at most that), a side of
/// LEFT or RIGHT and a body, each as JSON's type for it.
fn review_comment_shape(item: &Map<String, Value>) -> Result<(), String> {
    let output = CREATE_REVIEW_COMMENT;
    let line = |key: &str| {
        item.get(key)
            .and_then(Value::as_u64)
            .filter(|n| *n > 0 && *n <= MAX_SAFE_INTEGER)
    };
    let text = |key: &str| {
        item.get(key)
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty())
    };
    if !text("path") || !text("body") {
        return Err(format!("a {output} without a path and a body"));
    }
    let Some(end) = line("line") else {
        return Err(format!("a {output} without a positive integer line"));
    };
    if item.contains_key("start_line") && line("start_line").is_none_or(|start| start > end) {
        return Err(format!(
            "a {output} whose start_line is not a positive integer up to its line"
        ));
    }
    if item
        .get("side")
        .is_some_and(|side| side != "LEFT" && side != "RIGHT")
    {
        return Err(format!("a {output} whose side is not LEFT or RIGHT"));
    }
    Ok(())
}

/// Whether gh-aw's label sanitizer (`sanitizeLabelContent`, the cut to
/// [`MAX_LABEL`]) leaves LABEL as it is, as for check's subset: no
/// Unicode, entities, mentions or punctuation it would change, and no
/// leading `-`, which it refuses.
fn plain_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL
        && label == label.trim()
        && !label.starts_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" -_./:".contains(&b))
}

/// Why `agentic-job publish` would refuse ITEMS whatever the forge holds:
/// for check, so that the agent can still mend them.
pub fn refusals(items: &[Value], routed: &[String]) -> Vec<String> {
    split(items, routed).err().unwrap_or_default()
}

/// Whether VALUE holds `#aw_` anywhere, case ignored.
fn holds_temporary_reference(value: &Value) -> bool {
    match value {
        Value::String(text) => text.to_ascii_lowercase().contains("#aw_"),
        Value::Array(values) => values.iter().any(holds_temporary_reference),
        Value::Object(map) => map.values().any(holds_temporary_reference),
        _ => false,
    }
}

/// One routed request, everything that does not take the forge decided.
#[derive(Debug, Clone)]
enum Op {
    Document {
        index: usize,
        max: u64,
        repo: String,
        issue: u64,
        document: crate::document::Document,
        settings: crate::document::Settings,
    },
    Comment {
        advisory: Option<crate::advisory::Advisory>,
        index: usize,
        item: Map<String, Value>,
        /// The handler's `target-repo` and `target`.
        repo: String,
        issue: u64,
        max: u64,
    },
    PullRequest {
        index: usize,
        max: u64,
        /// Why it fails before anything is pushed, as gh-aw's handler fails it.
        failure: Option<String>,
        pr: Box<PullRequest>,
    },
    Labels {
        index: usize,
        max: u64,
        request: LabelRequest,
    },
    Close {
        index: usize,
        max: u64,
        /// The handler's `target-repo`.
        repo: String,
        /// The body as the request has it, empty for none.
        close: Close,
        /// An issue's, lowercase.
        state_reason: Option<String>,
        /// The `#N` the comment's footer names.
        triggering: Option<String>,
    },
    Push {
        index: usize,
        max: u64,
        push: Box<PushRequest>,
    },
    Issue {
        index: usize,
        max: u64,
        issue: IssueRequest,
    },
    ReviewComment {
        index: usize,
        max: u64,
        comment: ReviewComment,
    },
}

/// A routed create_pull_request_review_comment, decided but for its
/// body's mentions.
#[derive(Debug, Clone)]
struct ReviewComment {
    /// The handler's `target-repo` and `target`.
    repo: String,
    number: u64,
    path: String,
    line: u64,
    start_line: Option<u64>,
    /// LEFT or RIGHT.
    side: String,
    /// As the request has it.
    body: String,
    /// The `#N` the review's footer names.
    triggering: Option<String>,
}

/// A routed create_issue, decided but for its body's mentions.
#[derive(Debug, Clone)]
struct IssueRequest {
    /// The handler's `target-repo`.
    repo: String,
    /// As the handler opens it: sanitized, behind its `title_prefix`.
    title: String,
    /// The request's, without a first heading repeating its title.
    body: String,
    /// As the request names them, once each.
    labels: Vec<String>,
    /// The event's issue, where the new one is in the run's repository:
    /// the body says it is related, and it is made its sub-issue.
    parent: Option<u64>,
    /// The `#N` the footer names.
    triggering: Option<String>,
    /// The bounds' `comment_on_duplicate`: an open issue titled exactly
    /// [`Self::title`] gets the body as a comment in place of a new issue.
    comment_on_duplicate: bool,
}

/// A routed push_to_pull_request_branch, decided.
#[derive(Debug, Clone)]
struct PushRequest {
    /// The handler's `target-repo`, which the pull request is in.
    repo: String,
    /// The handler's `head-repo`: the pull request has to be from it, and
    /// the commit goes there.
    head_repo: String,
    /// The handler's `target`.
    number: u64,
    /// The policy's base: the pull request's branch.
    branch: String,
    /// The head the run was asked for, which check read the patch
    /// against: the branch has to be there still.
    head: String,
    patch: Vec<u8>,
    files: Vec<String>,
    /// `max_patch_size`, which bounds the changed files too.
    max_kb: u64,
    allow_workflows: bool,
    /// How gh-aw's handler ends it before it reads the forge, if it does.
    early: Option<Early>,
}

/// A request gh-aw's handler fails, or skips with its result, from what
/// it holds alone.
#[derive(Debug, Clone)]
enum Early {
    Failed(String),
    Skipped(Value),
}

/// A routed add_labels or remove_labels, decided.
#[derive(Debug, Clone)]
struct LabelRequest {
    /// Added, or else removed.
    add: bool,
    /// The handler's `target-repo`.
    repo: String,
    number: u64,
    /// As the request names them, in order: the handler counts them
    /// before it drops any.
    labels: Vec<String>,
    /// The handler's `allowed` and `blocked` patterns.
    allowed: Vec<String>,
    blocked: Vec<String>,
    /// What the handler calls the item (`contextType`).
    kind: &'static str,
}

impl Op {
    fn index(&self) -> usize {
        match self {
            Self::Comment { index, .. }
            | Self::Document { index, .. }
            | Self::PullRequest { index, .. }
            | Self::Labels { index, .. }
            | Self::Close { index, .. }
            | Self::Push { index, .. }
            | Self::Issue { index, .. }
            | Self::ReviewComment { index, .. } => *index,
        }
    }

    fn max(&self) -> u64 {
        match self {
            Self::Comment { max, .. }
            | Self::Document { max, .. }
            | Self::PullRequest { max, .. }
            | Self::Labels { max, .. }
            | Self::Close { max, .. }
            | Self::Push { max, .. }
            | Self::Issue { max, .. }
            | Self::ReviewComment { max, .. } => *max,
        }
    }

    fn output(&self) -> &'static str {
        match self {
            Self::Document { .. } => "document",
            Self::Comment { .. } => ADD_COMMENT,
            Self::PullRequest { .. } => CREATE_PULL_REQUEST,
            Self::Labels { request, .. } if request.add => ADD_LABELS,
            Self::Labels { .. } => REMOVE_LABELS,
            Self::Close {
                close:
                    Close {
                        kind: ItemKind::Issue,
                        ..
                    },
                ..
            } => CLOSE_ISSUE,
            Self::Close { .. } => CLOSE_PULL_REQUEST,
            Self::Push { .. } => PUSH_TO_PULL_REQUEST_BRANCH,
            Self::Issue { .. } => CREATE_ISSUE,
            Self::ReviewComment { .. } => CREATE_REVIEW_COMMENT,
        }
    }
}

/// The handler settings of OUTPUT in HANDLERS, held to those apply.yml
/// writes for it.
fn settings<'a>(handlers: &'a Map<String, Value>, output: &str) -> Result<&'a Map<String, Value>> {
    let config = handlers
        .get(output)
        .and_then(Value::as_object)
        .with_context(|| format!("no handler configuration for {output}"))?;
    let handler = handler(output)
        .with_context(|| format!("{output}, which agentic-job publish does not publish"))?;
    for key in config.keys() {
        ensure!(
            handler.settings.contains(&key.as_str()),
            "the {output} handler setting {key:?}, which agentic-job publish does not read"
        );
    }
    for (key, want) in handler.fixed {
        let want: Value = serde_json::from_str(want).context("a fixed setting")?;
        ensure!(
            config.get(*key) == Some(&want),
            "the {output} handler's {key} is not {want}, which is all agentic-job publish does"
        );
    }
    let max = config.get("max").and_then(Value::as_u64).unwrap_or(0);
    ensure!(
        max >= 1,
        "the {output} handler's max is not a positive integer"
    );
    let repo = setting(config, "target-repo")?;
    ensure!(
        REPO_RE.is_match(repo),
        "the {output} handler's target-repo {repo:?} is not OWNER/NAME"
    );
    Ok(config)
}

/// A request's `repo`, which must be the handler's own: gh-aw would
/// publish another spelling of it as written.
fn same_repo(item: &Map<String, Value>, repo: &str) -> Result<()> {
    match item.get("repo") {
        None => Ok(()),
        Some(Value::String(named)) if js_trim(named) == repo => Ok(()),
        Some(named) => bail!("a request naming the repository {named}, which is not {repo}"),
    }
}

/// Decides each routed request, or refuses with every reason found.
fn plan(
    ours: Vec<Routed>,
    handlers: &Map<String, Value>,
    checked: &Upload<'_>,
    policy: &Policy,
    run: &Run,
) -> Result<Vec<Op>, Vec<String>> {
    let mut errors = Vec::new();
    // gh-aw's footer, which reads FOOTER_INPUTS, ends the routed comments,
    // pull requests and closing comments.
    let footer = ours
        .iter()
        .any(|routed| !matches!(check::item_type(&routed.item), ADD_LABELS | REMOVE_LABELS));
    let mut ops = Vec::new();
    let mut report: Option<Report> = None;
    for Routed { index, item } in ours {
        let output = check::item_type(&item).to_owned();
        let decided = settings(handlers, &output).and_then(|config| {
            same_repo(&item, setting(config, "target-repo")?)?;
            let max = config.get("max").and_then(Value::as_u64).unwrap_or(1);
            let repo = setting(config, "target-repo")?.to_owned();
            if output == "document" {
                let document = crate::document::Document::parse(&item)?;
                let settings = policy.safe_outputs.others.get("document")
                    .context("document is not allowed")?.document.clone().unwrap_or_default();
                document.authorize(&settings)?;
                let target = setting(config, "target")?;
                ensure!(NUMBER_RE.is_match(target), "document requires one fixed issue target");
                return Ok(Op::Document { index, max, repo, issue: target.parse()?, document, settings });
            }
            let number = || -> Result<u64> {
                number_field(&output)
                    .and_then(|key| item.get(key))
                    .and_then(Value::as_u64)
                    .context("the request's number")
            };
            if matches!(output.as_str(), ADD_LABELS | REMOVE_LABELS) {
                let patterns = |key: &str| -> Result<Vec<String>> {
                    let patterns: Vec<String> = match config.get(key) {
                        None => Vec::new(),
                        Some(value) => serde_json::from_value(value.clone()).with_context(|| {
                            format!("the {output} handler's {key} is not a list of labels")
                        })?,
                    };
                    // JavaScript folds the case of ASCII alone outside
                    // Unicode mode, and some other characters to ASCII
                    // when it lowercases (`K`, the Kelvin sign).
                    ensure!(
                        patterns.iter().all(|pattern| pattern.is_ascii()),
                        "the {output} handler's {key} names a label that is not ASCII"
                    );
                    Ok(patterns)
                };
                let labels = item
                    .get("labels")
                    .map(|labels| serde_json::from_value(labels.clone()))
                    .transpose()
                    .context("the request's labels")?
                    .unwrap_or_default();
                return Ok(Op::Labels {
                    index,
                    max,
                    request: LabelRequest {
                        add: output == ADD_LABELS,
                        repo,
                        number: number()?,
                        labels,
                        allowed: patterns("allowed")?,
                        blocked: patterns("blocked")?,
                        kind: run.context_kind()?,
                    },
                });
            }
            if matches!(output.as_str(), CLOSE_ISSUE | CLOSE_PULL_REQUEST) {
                let issue = output == CLOSE_ISSUE;
                run.read_as_dispatched()?;
                return Ok(Op::Close {
                    triggering: run.closing_triggering()?,
                    index,
                    max,
                    repo,
                    close: Close {
                        number: number()?,
                        kind: if issue {
                            ItemKind::Issue
                        } else {
                            ItemKind::PullRequest
                        },
                        body: item
                            .get("body")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    },
                    state_reason: issue.then(|| {
                        item.get("state_reason")
                            .and_then(Value::as_str)
                            .unwrap_or("completed")
                            .to_lowercase()
                    }),
                });
            }
            if output == CREATE_ISSUE {
                return Ok(Op::Issue {
                    index,
                    max,
                    issue: issue_request(&item, config, run)?,
                });
            }
            if output == CREATE_REVIEW_COMMENT {
                let target = setting(config, "target")?;
                ensure!(
                    NUMBER_RE.is_match(target),
                    "a {output} without one pull request to comment on (the handler's target is \
                     {target:?})"
                );
                // The handler reads the event as dispatched, for its footer.
                run.read_as_dispatched()?;
                let text = |key: &str| item.get(key).and_then(Value::as_str).unwrap_or_default();
                return Ok(Op::ReviewComment {
                    index,
                    max,
                    comment: ReviewComment {
                        repo,
                        number: target.parse().context("the review comment's target")?,
                        path: text("path").to_owned(),
                        line: item.get("line").and_then(Value::as_u64).unwrap_or_default(),
                        start_line: item.get("start_line").and_then(Value::as_u64),
                        side: item
                            .get("side")
                            .and_then(Value::as_str)
                            .unwrap_or("RIGHT")
                            .to_owned(),
                        body: text("body").to_owned(),
                        triggering: run.item_triggering()?,
                    },
                });
            }
            if output == ADD_COMMENT {
                let target = setting(config, "target")?;
                ensure!(
                    NUMBER_RE.is_match(target),
                    "an add_comment without one item to comment on (the handler's target is {target:?})"
                );
                return Ok(Op::Comment {
                    advisory: policy.advisory.clone(),
                    index,
                    repo: setting(config, "target-repo")?.to_owned(),
                    issue: target.parse().context("the comment target")?,
                    max,
                    item,
                });
            }
            if report.is_none() {
                report = Some(read_report(checked)?);
            }
            let report = report.as_ref().context("check's report")?;
            if output == PUSH_TO_PULL_REQUEST_BRANCH {
                // The handler reads the event as dispatched, for its comment.
                run.read_as_dispatched()?;
                return Ok(Op::Push {
                    index,
                    max,
                    push: Box::new(branch_push(&item, config, checked, report, policy)?),
                });
            }
            let (pr, failure) = pull_request(&item, config, checked, report, policy, run)?;
            Ok(Op::PullRequest {
                index,
                max,
                failure,
                pr: Box::new(pr),
            })
        });
        match decided {
            Ok(op) => ops.push(op),
            Err(err) => errors.push(format!("{err:#}")),
        }
    }
    for input in FOOTER_INPUTS.iter().filter(|_| footer) {
        if checked.dir.join(input).exists() {
            errors.push(format!(
                "{input} is in {}, which gh-aw's footer would read",
                checked.dir.display()
            ));
        }
    }
    if errors.is_empty() {
        Ok(ops)
    } else {
        Err(errors)
    }
}

/// The pull request ITEM asks for under the handler's CONFIG, and why it
/// fails before anything is pushed, if it does: everything but its body's
/// own mentions decided, as gh-aw's handler decides it.
fn pull_request(
    item: &Map<String, Value>,
    config: &Map<String, Value>,
    checked: &Upload<'_>,
    report: &Report,
    policy: &Policy,
    run: &Run,
) -> Result<(PullRequest, Option<String>)> {
    let draft = config
        .get("draft")
        .and_then(Value::as_bool)
        .context("the create_pull_request handler's draft is not a boolean")?;
    let head_repo = setting(config, "head-repo")?;
    ensure!(
        REPO_RE.is_match(head_repo),
        "the create_pull_request handler's head-repo {head_repo:?} is not OWNER/NAME"
    );
    ensure!(
        config.get("allowed_repos") == Some(&json!([head_repo])),
        "the create_pull_request handler allows other repositories than its head-repo"
    );
    let base = setting(config, "base_branch")?;
    ensure!(
        !base.is_empty() && normalize_branch(base) == base,
        "the base branch {base:?} is not one gh-aw's handler takes as written"
    );
    if let Some(asked) = item.get("base") {
        ensure!(
            asked
                .as_str()
                .map(js_trim)
                .is_some_and(|asked| asked.is_empty() || asked == base),
            "a create_pull_request for another base than {base}"
        );
    }
    ensure!(
        item.get("labels")
            .is_none_or(|labels| labels.as_array().is_some_and(Vec::is_empty)),
        "a create_pull_request with labels, which agentic-job publish does not add"
    );
    let text = |key: &str| {
        item.get(key)
            .and_then(Value::as_str)
            .with_context(|| format!("a create_pull_request without a {key}"))
    };
    let (title, body, branch) = (text("title")?, text("body")?, text("branch")?);

    // The branch the handler pushes: its name normalized, behind the
    // prefix, which apply.yml's guard has the run's own.
    let prefix = normalize_branch(setting(config, "branch_prefix").unwrap_or_default());
    let mut branch = normalize_branch(js_trim(branch));
    ensure!(!branch.is_empty(), "a create_pull_request without a branch");
    if !prefix.is_empty() && !branch.starts_with(&prefix) {
        branch = format!("{prefix}{branch}");
    }

    let patch = report
        .patch
        .as_ref()
        .context("a create_pull_request, and check accepted no patch")?;
    ensure!(
        patch.commit_files.is_none(),
        "a replacement series, which only a push carries"
    );
    let name = check::patch_file_name(text("branch")?);
    if let Some(receipt) = &patch.replay {
        ensure!(
            receipt.base_commit == patch.base_commit
                && receipt.patch_sha256.len() == 64
                && super::COMMIT_RE.is_match(&receipt.tree),
            "invalid endpoint replay receipt"
        );
    }
    ensure!(
        patch.file == name,
        "check accepted the patch {:?}, and the pull request's is {name}",
        patch.file
    );
    ensure!(
        super::COMMIT_RE.is_match(&patch.base_commit),
        "check's base commit {:?} is not a commit id",
        patch.base_commit
    );
    let bytes = (checked.read)(&checked.dir.join(&name), policy.max_patch_bytes)
        .with_context(|| format!("the patch {name}"))?;
    ensure!(
        bytes.len() == patch.bytes,
        "the patch {name} is {} bytes, and check read {}",
        bytes.len(),
        patch.bytes
    );
    let rules = policy
        .safe_outputs
        .create_pull_request
        .as_ref()
        .context("a create_pull_request, which the policy does not allow")?;
    let rules = crate::contract::PatchRules {
        commit_author: policy.commit_author.as_deref(),
        ..rules.rules()
    };
    let reading = check::read_patch(&String::from_utf8_lossy(&bytes), &rules, &patch.base_commit);
    ensure!(
        reading.problems.is_empty(),
        "the patch {name}: {}",
        reading.problems.join("; ")
    );
    ensure!(
        reading.files == patch.files,
        "the patch {name} names other paths than check reported"
    );
    ensure!(
        !reading.files.is_empty(),
        "the patch {name} changes nothing"
    );

    // Here, so that a body this cannot treat as gh-aw does is refused
    // before anything is written.
    let body = without_title_heading(js_trim(title), body)?;
    let title_prefix = setting(config, "title_prefix").unwrap_or_default();
    let title = js_trim(title);
    let title = if title.is_empty() {
        "Agent Output"
    } else {
        title
    };
    let title = apply_title_prefix(&sanitize_title(title, title_prefix, run)?, title_prefix);
    let failure = pull_request_failure(config, &bytes, &patch.files);
    Ok((
        PullRequest {
            replay: patch.replay.clone(),
            base: base.to_owned(),
            base_commit: patch.base_commit.clone(),
            push_repo: head_repo.to_owned(),
            private: policy.private,
            branch,
            title,
            // Without the title's heading: `pull_request_body` makes the
            // rest of the body it is opened with.
            body,
            draft,
            patch: bytes,
            files: patch.files.clone(),
            // What the GitHub publisher commits as: the job's identity.
            committer: Committer {
                name: ACTIONS_COMMITTER.0.to_owned(),
                email: ACTIONS_COMMITTER.1.to_owned(),
            },
        },
        failure,
    ))
}

/// Why gh-aw's handler fails the patch FILES of BYTES under CONFIG before
/// it pushes anything, if it does: its file count, size and protected
/// files, as it counts them.
fn pull_request_failure(
    config: &Map<String, Value>,
    bytes: &[u8],
    files: &[String],
) -> Option<String> {
    let max_files = positive(config, "max_patch_files", 100);
    let count = files.len() as u64;
    if count > max_files {
        return Some(format!(
            "E003: Cannot create pull request with more than {max_files} files (received {count}). \
             To increase the limit, set `max-patch-files: {count}` (or higher) under \
             `safe-outputs.create-pull-request` in your workflow frontmatter."
        ));
    }
    if let Some(failure) = patch_size_failure(config, bytes) {
        return Some(failure);
    }
    let found = protected_files(config, files);
    (!found.is_empty()).then(|| {
        format!(
            "Cannot create pull request: patch modifies protected files ({}). Add them to the \
             allowed-files configuration field or set protected-files: fallback-to-issue to \
             create a review issue instead.",
            found.join(", ")
        )
    })
}

/// A handler's setting KEY of CONFIG where it is a positive integer, or
/// DEFAULT.
fn positive(config: &Map<String, Value>, key: &str, default: u64) -> u64 {
    config
        .get(key)
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
        .unwrap_or(default)
}

/// Why the handlers that carry a patch fail BYTES for its size under
/// CONFIG, if they do.
fn patch_size_failure(config: &Map<String, Value>, bytes: &[u8]) -> Option<String> {
    let max_kb = positive(config, "max_patch_size", 4096);
    let kb = (bytes.len() as u64).div_ceil(1024);
    (kb > max_kb)
        .then(|| format!("Patch size ({kb} KB) exceeds maximum allowed size ({max_kb} KB)"))
}

/// Those of FILES the handlers that carry a patch take for protected
/// under CONFIG (`checkFileProtection`).
fn protected_files<'a>(config: &Map<String, Value>, files: &'a [String]) -> Vec<&'a str> {
    let names = |key: &str| -> Vec<String> {
        config
            .get(key)
            .and_then(Value::as_array)
            .map(|names| {
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let protected = names("protected_files");
    let excluded: BTreeSet<String> = names("protected_dot_folder_excludes")
        .iter()
        .map(|name| name.trim_end_matches('/').to_owned())
        .filter(|name| !name.is_empty())
        .collect();
    let dot_folders = config.get("protect_top_level_dot_folders") == Some(&Value::Bool(true));
    files
        .iter()
        .filter(|file| {
            let basename = file.rsplit('/').next().unwrap_or_default();
            let folder = file.split_once('/').map(|(folder, _)| folder);
            protected
                .iter()
                .any(|name| name == basename || name == *file)
                || (dot_folders
                    && folder.is_some_and(|folder| {
                        folder.starts_with('.') && folder.len() > 1 && !excluded.contains(folder)
                    }))
        })
        .map(String::as_str)
        .collect()
}

/// The push ITEM asks for under the handler's CONFIG, with check's patch
/// read again and held to the policy, as [`pull_request`] reads one. The
/// pull request, its branch and its head are the policy's; the handler
/// is given them, and nothing of the request names them.
fn branch_push(
    item: &Map<String, Value>,
    config: &Map<String, Value>,
    checked: &Upload<'_>,
    report: &Report,
    policy: &Policy,
) -> Result<PushRequest> {
    let output = PUSH_TO_PULL_REQUEST_BRANCH;
    let rules = policy
        .safe_outputs
        .push_to_pull_request_branch
        .as_ref()
        .with_context(|| format!("a {output}, which the policy does not allow"))?;
    let target = setting(config, "target")?;
    ensure!(
        NUMBER_RE.is_match(target) && target == rules.target,
        "a {output} without the policy's pull request to push to (the handler's target is {target:?})"
    );
    let head = setting(config, "head")?;
    ensure!(
        head == rules.head && super::COMMIT_RE.is_match(head),
        "the {output} handler's head {head:?} is not the policy's"
    );
    let repo = setting(config, "target-repo")?;
    ensure!(
        repo.eq_ignore_ascii_case(&policy.repo),
        "the {output} handler's target-repo {repo} is not the policy's {}",
        policy.repo
    );
    let head_repo = setting(config, "head-repo")?;
    ensure!(
        REPO_RE.is_match(head_repo),
        "the {output} handler's head-repo {head_repo:?} is not OWNER/NAME"
    );
    ensure!(
        config.get("allowed_repos") == Some(&json!([head_repo])),
        "the {output} handler allows other repositories than its head-repo"
    );
    // The workspace is the target's checkout, which gh-aw's handler would
    // otherwise look for and apply the patch in.
    ensure!(
        config.get("checkout_mapping") == Some(&json!({repo.to_ascii_lowercase(): "."})),
        "the {output} handler's checkout_mapping is not its target-repo's workspace"
    );
    let branch = item
        .get("branch")
        .and_then(Value::as_str)
        .with_context(|| format!("a {output} without a branch"))?;
    ensure!(
        branch == policy.base,
        "a {output} for the branch {branch:?}, not the policy's {}",
        policy.base
    );
    let patch = report
        .patch
        .as_ref()
        .with_context(|| format!("a {output}, and check accepted no patch"))?;
    // apply.yml's guard pushes a replacement series itself, and leaves
    // gh-aw's handler none.
    ensure!(
        patch.commit_files.is_none(),
        "a replacement series, which the guard pushes"
    );
    let name = check::patch_file_name(branch);
    ensure!(
        patch.file == name,
        "check accepted the patch {:?}, and the push's is {name}",
        patch.file
    );
    ensure!(
        patch.base_commit == head,
        "check read the patch against {}, not the head {head} the run was asked for",
        patch.base_commit
    );
    let bytes = (checked.read)(&checked.dir.join(&name), policy.max_patch_bytes)
        .with_context(|| format!("the patch {name}"))?;
    ensure!(
        bytes.len() == patch.bytes,
        "the patch {name} is {} bytes, and check read {}",
        bytes.len(),
        patch.bytes
    );
    let rules = crate::contract::PatchRules {
        commit_author: policy.commit_author.as_deref(),
        ..rules.rules()
    };
    let reading = check::read_patch(&String::from_utf8_lossy(&bytes), &rules, head);
    ensure!(
        reading.problems.is_empty(),
        "the patch {name}: {}",
        reading.problems.join("; ")
    );
    ensure!(
        reading.files == patch.files && !reading.files.is_empty(),
        "the patch {name} names other paths than check reported"
    );
    // `validatePatch`, before the handler reads the forge.
    let found = protected_files(config, &patch.files);
    let early = match patch_size_failure(config, &bytes) {
        Some(failure) => Some(Early::Failed(failure)),
        None if !found.is_empty() => {
            let error = format!(
                "Cannot push to pull request branch: patch modifies protected files ({}). Add \
                 them to the allowed-files configuration field or set protected-files: \
                 fallback-to-issue to create a review issue instead.",
                found.join(", ")
            );
            Some(Early::Skipped(json!({"success": false, "skipped": true,
                "reasonCode": "POLICY_FILE_PROTECTION_DENIED", "error": error})))
        }
        None => None,
    };
    Ok(PushRequest {
        repo: repo.to_owned(),
        head_repo: head_repo.to_owned(),
        number: target.parse().context("the push's target")?,
        branch: branch.to_owned(),
        head: head.to_owned(),
        patch: bytes,
        files: patch.files.clone(),
        max_kb: positive(config, "max_patch_size", 4096),
        allow_workflows: config.get("allow_workflows") == Some(&Value::Bool(true)),
        early,
    })
}

/// The issue ITEM asks for under the handler's CONFIG, as gh-aw's handler
/// makes it, all but its body's mentions.
fn issue_request(
    item: &Map<String, Value>,
    config: &Map<String, Value>,
    run: &Run,
) -> Result<IssueRequest> {
    static HEADING: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!("^#+[{JS_SPACE}]*")).expect("a valid pattern"));
    let text = |key: &str| item.get(key).and_then(Value::as_str).unwrap_or_default();
    let repo = setting(config, "target-repo")?;
    let prefix = match config.get("title_prefix") {
        None | Some(Value::Null) => "",
        Some(Value::String(prefix)) => prefix,
        Some(_) => bail!("the create_issue handler's title_prefix is not text"),
    };
    let comment_on_duplicate = match config.get("comment_on_duplicate") {
        None => false,
        Some(Value::Bool(on)) => *on,
        Some(_) => bail!("the create_issue handler's comment_on_duplicate is not a boolean"),
    };
    let title = js_trim(text("title"));
    let body = without_title_heading(title, text("body"))?;
    // Without a title, the body's first line that holds anything.
    let title = match title {
        "" => text("body")
            .split('\n')
            .map(|line| js_trim(&HEADING.replace(line, "")).to_owned())
            .find(|line| !line.is_empty())
            .unwrap_or_else(|| "Agent Output".to_owned()),
        title => title.to_owned(),
    };
    let mut title = sanitize_title(&title, prefix, run)?;
    if js_trim(&title).is_empty() {
        title = "Agent Output".to_owned();
    }
    let labels: Vec<String> = item
        .get("labels")
        .map(|labels| serde_json::from_value(labels.clone()))
        .transpose()
        .context("the request's labels")?
        .unwrap_or_default();
    Ok(IssueRequest {
        title: apply_title_prefix(&title, prefix),
        body,
        labels: labels.into_iter().fold(Vec::new(), |mut kept, label| {
            if !kept.contains(&label) {
                kept.push(label);
            }
            kept
        }),
        // The handler compares the names as written.
        parent: run
            .event_number("issue")?
            .filter(|_| repo == run.repository),
        triggering: run.item_triggering()?,
        repo: repo.to_owned(),
        comment_on_duplicate,
    })
}

/// `sanitizeTitle`: TITLE sanitized, without PREFIX where it starts so,
/// cut to [`MAX_TITLE`].
fn sanitize_title(title: &str, prefix: &str, run: &Run) -> Result<String> {
    let mut title = sanitize_with(title, MAX_SANITIZED, &Mentions::All, &|host| {
        run.keeps_link(host)
    });
    let clean = js_trim(prefix);
    if !clean.is_empty() {
        let bare = clean.trim_end_matches(is_js_space);
        let separated = [":", " -", " |"]
            .iter()
            .map(|separator| format!("{bare}{separator}"))
            .find(|variation| title.starts_with(variation.as_str()));
        match separated {
            Some(variation) => title = js_trim(&title[variation.len()..]).to_owned(),
            None => {
                while title.starts_with(clean) {
                    title = js_trim(&title[clean.len()..]).to_owned();
                }
            }
        }
    }
    if utf16_len(&title) > MAX_TITLE {
        let cut = utf16_prefix(&title, MAX_TITLE);
        ensure!(
            utf16_len(cut) == MAX_TITLE,
            "a title gh-aw would cut inside a character"
        );
        title = cut.trim_end_matches(is_js_space).to_owned();
    }
    Ok(title)
}

/// `applyTitlePrefix`.
fn apply_title_prefix(title: &str, prefix: &str) -> String {
    if js_trim(prefix).is_empty() {
        return title.to_owned();
    }
    let clean = js_trim(title);
    if !clean.is_empty() && !clean.starts_with(prefix) {
        let space = !prefix.ends_with(' ') && (prefix.ends_with(']') || prefix.ends_with('-'));
        return format!("{prefix}{}{clean}", if space { " " } else { "" });
    }
    clean.to_owned()
}

/// `removeDuplicateTitleFromDescription`: BODY without a first heading
/// that is TITLE.
fn without_title_heading(title: &str, body: &str) -> Result<String> {
    if title.is_empty() {
        return Ok(body.to_owned());
    }
    if body.is_empty() {
        return Ok(String::new());
    }
    let (title, body) = (js_trim(title), js_trim(body));
    if title.is_empty() || body.is_empty() {
        return Ok(body.to_owned());
    }
    // JavaScript folds case outside Unicode mode as Rust does for ASCII
    // alone, and only ASCII matches ASCII then.
    ensure!(
        title.is_ascii() || !body.starts_with('#'),
        "a body that starts with a heading under a title that is not ASCII"
    );
    let heading = Regex::new(&format!(
        r"^#{{1,6}}[{JS_SPACE}]+(?i-u:{})[{JS_SPACE}]*(?:\r?\n)*",
        regex::escape(title)
    ))
    .context("the title as a pattern")?;
    Ok(match heading.find(body) {
        Some(found) => js_trim(&body[found.end()..]).to_owned(),
        None => body.to_owned(),
    })
}

/// `generateHistoryUrl`: a search for what the workflow made in REPO, of
/// those things the search type SEARCH finds; for `issues`, with ISSUES
/// only the issues.
fn history_url(run: &Run, repo: &str, search: &str, issues: bool) -> String {
    let only = if issues { " is:issue" } else { "" };
    let query = format!(
        "repo:{repo}{only} \"gh-aw-workflow-id: {}\"",
        run.workflow_id
    );
    let mut encoded = String::new();
    for byte in query.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    format!("{}/search?q={encoded}&type={search}", run.server)
}

/// `generateXMLMarker`, for RUN_URL.
fn xml_marker(run: &Run, run_url: &str) -> String {
    format!(
        "<!-- gh-aw-agentic-workflow: {}, id: {}, workflow_id: {}, run: {run_url} -->",
        run.workflow_name, run.run_id, run.workflow_id
    )
}

/// gh-aw's default footer: who made it, for which item, and the search
/// for what else the workflow made where there is one.
fn footer(run: &Run, triggering: Option<&str>, history: Option<&str>) -> String {
    let run_url = run.run_url();
    let triggering = triggering.map(|n| format!(" for {n}")).unwrap_or_default();
    let history = history
        .map(|history| format!(" · [◷]({history})"))
        .unwrap_or_default();
    format!(
        "> Generated by [{}]({run_url}){triggering}{history}\n\n{}",
        run.workflow_name,
        xml_marker(run, &run_url)
    )
}

/// `stripExecutionProvenance`: BODY without the HTML comments that hold
/// a reserved marker, end trimmed.
fn strip_provenance(body: &str) -> String {
    let mut result = String::new();
    let mut position = 0;
    while position < body.len() {
        let Some(found) = body[position..].find("<!--") else {
            result.push_str(&body[position..]);
            break;
        };
        let start = position + found;
        result.push_str(&body[position..start]);
        let (mut depth, mut end) = (0usize, start);
        while end < body.len() {
            let rest = &body[end..];
            if rest.starts_with("<!--") {
                depth += 1;
                end += 4;
            } else if depth > 0 && rest.starts_with("--!>") {
                depth -= 1;
                end += 4;
            } else if depth > 0 && rest.starts_with("-->") {
                depth -= 1;
                end += 3;
            } else {
                end += rest.chars().next().map_or(1, char::len_utf8);
            }
            if depth == 0 {
                break;
            }
        }
        let comment = &body[start..end];
        if depth > 0 {
            if RESERVED_MARKER_RE.is_match(comment) {
                static UNCLOSED: LazyLock<Regex> = LazyLock::new(|| {
                    Regex::new(&format!(
                        r"(?i)(<!--[-![{JS_SPACE}]]*)gh-aw-((?:execution|agentic-workflow)[{JS_SPACE}]*:)"
                    ))
                    .expect("a valid pattern")
                });
                result.push_str(&UNCLOSED.replace_all(comment, "${1}gh-aw&#45;${2}"));
            } else {
                result.push_str(comment);
            }
            break;
        }
        if !RESERVED_MARKER_RE.is_match(comment) {
            result.push_str(comment);
        }
        position = end;
    }
    result.trim_end_matches(is_js_space).to_owned()
}

/// `appendExecutionProvenance`: BODY with the marker of the run and job
/// that published it.
fn with_provenance(run: &Run, body: &str) -> String {
    let run_url = format!(
        "{}/{}/actions/runs/{}",
        run.server, run.repository, run.run_id
    );
    let metadata = json!({
        "version": 1,
        "repo_id": run.repository_id,
        "repository": run.repository,
        "aw_workflow_id": run.workflow_id,
        "run_id": run.run_id,
        "run_attempt": run.run_attempt,
        "run_url": run_url,
        "publishing_job": {"key": run.job, "check_run_id": run.check_run_id},
    });
    let mut payload = String::new();
    for c in metadata.to_string().chars() {
        match c {
            '<' | '>' | '&' | '-' => payload.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => payload.push(c),
        }
    }
    format!(
        "{}\n\n{}\n<!-- gh-aw-execution: {payload} -->",
        strip_provenance(body),
        xml_marker(run, &run_url)
    )
}

/// BODY as apply.yml's hook sends it: the name the guard put last in it
/// hidden in an HTML comment.
fn hide_applied(body: &str) -> String {
    let marker = check::APPLIED_MARKER;
    // JavaScript's line ends, which its `^` and `$` stop at.
    let ends = |c: char| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}');
    let mut lines = Vec::new();
    let mut start = 0;
    for (at, c) in body.char_indices() {
        if ends(c) {
            lines.push((start, at));
            start = at + c.len_utf8();
        }
    }
    lines.push((start, body.len()));
    let prefix = format!("{marker}:");
    let last = lines
        .iter()
        .rev()
        .find(|(start, end)| body[*start..*end].starts_with(&prefix));
    match last {
        Some((start, end)) if names_applied(&body[*start..*end], marker) => format!(
            "{}<!-- {} -->{}",
            &body[..*start],
            &body[*start..*end],
            &body[*end..]
        ),
        _ => body.to_owned(),
    }
}

/// Whether LINE is the name the guard writes after MARKER.
fn names_applied(line: &str, marker: &str) -> bool {
    line.strip_prefix(marker)
        .is_some_and(|rest| APPLIED_RE.is_match(rest))
}

/// `enforceCommentLimits`: why BODY is no comment gh-aw's handler posts.
fn comment_limits(body: &str) -> Option<String> {
    let length = utf16_len(body);
    if length > MAX_BODY_UNITS {
        return Some(format!(
            "E006: Comment body exceeds maximum length of {MAX_BODY_UNITS} characters (got \
             {length}). Reduce the comment body to {MAX_BODY_UNITS} characters or fewer."
        ));
    }
    let mut mentions = 0;
    outside_code(body, &mut |segment, _, _| {
        mentions += MENTION_RE
            .find_iter(&HTML_CODE_RE.replace_all(segment, " "))
            .count();
        segment.to_owned()
    });
    if mentions > MAX_MENTIONS {
        return Some(format!(
            "E007: Comment contains {mentions} mentions, maximum is {MAX_MENTIONS}. Reduce the \
             number of @mentions to {MAX_MENTIONS} or fewer."
        ));
    }
    let links = LINK_RE.find_iter(body).count();
    (links > MAX_LINKS).then(|| {
        format!(
            "E008: Comment contains {links} links, maximum is {MAX_LINKS}. Reduce the number of \
             URLs to {MAX_LINKS} or fewer."
        )
    })
}

/// How one request ended, as gh-aw's handler manager records it.
#[derive(Debug, Clone)]
struct Outcome {
    output: &'static str,
    index: usize,
    kind: Kind,
    /// The handler's result, as the summary and manifest read it.
    result: Value,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Success,
    Skipped,
    Failed,
}

impl Outcome {
    fn succeeded(op: &Op, result: Value) -> Self {
        Self {
            output: op.output(),
            index: op.index(),
            kind: Kind::Success,
            result,
            error: None,
        }
    }

    fn failed(op: &Op, error: String) -> Self {
        Self {
            output: op.output(),
            index: op.index(),
            kind: Kind::Failed,
            result: Value::Null,
            error: Some(error),
        }
    }

    fn skipped(op: &Op, result: Value) -> Self {
        let error = ["reason", "warning", "error"]
            .iter()
            .find_map(|key| result[key].as_str().filter(|text| !text.is_empty()))
            .unwrap_or("Handler returned skipped: true")
            .to_owned();
        Self {
            output: op.output(),
            index: op.index(),
            kind: Kind::Skipped,
            result,
            error: Some(error),
        }
    }
}

/// How the routed requests ended, and what the review of the comments
/// buffered for one made, which gh-aw's handler manager records after
/// everything else: of each type, its handler's result.
struct Published {
    outcomes: Vec<Outcome>,
    reviewed: Vec<(&'static str, Value)>,
}

/// gh-aw's type of what its review buffer makes of the comments.
const SUBMIT_REVIEW: &str = "submit_pull_request_review";

/// Publishes OPS in order with PUBLISHER, allowing the DEFAULTS mentions,
/// and returns how each ended. Review comments are buffered, and submitted
/// in one review after the others, as gh-aw's handler manager submits
/// them.
fn publish(
    ops: &[Op],
    publisher: &GithubPublisher,
    run: &Run,
    defaults: &[String],
    log: &mut dyn FnMut(&Annotation),
) -> Result<Published> {
    let mut outcomes: Vec<Outcome> = Vec::new();
    let mut processed: std::collections::BTreeMap<&str, u64> = Default::default();
    let mut pushed_failed = None;
    let mut review = Review::default();
    for op in ops {
        let count = processed.entry(op.output()).or_default();
        let max = op.max();
        if *count >= max {
            outcomes.push(match op {
                Op::Comment { .. } => Outcome::skipped(
                    op,
                    json!({"success": false, "skipped": true, "reasonCode": "MAX_COUNT_REACHED",
                        "reason": "Max count reached", "error": format!("Max count of {max} reached")}),
                ),
                _ => Outcome::failed(op, format!("Max count of {max} reached")),
            });
            continue;
        }
        *count += 1;
        let outcome = match (op, &pushed_failed) {
            (Op::Comment { .. }, Some((output, error))) => Outcome::failed(
                op,
                format!("not posted: the {output} before it failed ({error})"),
            ),
            (op, _) => {
                let mut buffer = (outcomes.len(), &mut review);
                publish_one(op, publisher, run, defaults, &mut buffer, log)
            }
        };
        if outcome.kind == Kind::Failed {
            let error = outcome.error.clone().unwrap_or_default();
            log(&command(
                "error",
                &format!(
                    "✗ Message {} ({}) failed: {error}",
                    op.index() + 1,
                    op.output()
                ),
            ));
            if CODE_PUSHES.contains(&op.output()) && pushed_failed.is_none() {
                pushed_failed = Some((op.output(), error));
            }
        }
        outcomes.push(outcome);
    }
    let mut reviewed = Vec::new();
    if let Some(pull) = &review.pull {
        let github = publisher.github.for_role(super::roles::Role::Review)?;
        match submit_review(pull, &review, run, &github, log) {
            ReviewEnd::Made(result) => {
                let comments = result["review_comments"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                reviewed.push((SUBMIT_REVIEW, result));
                reviewed.extend(comments.into_iter().map(|c| (CREATE_REVIEW_COMMENT, c)));
            }
            // `rollbackReviewResultsForPR`, `skipReviewResultsForPR`.
            ReviewEnd::Failed(error) => {
                log(&command(
                    "error",
                    &format!(
                        "✗ Failed to submit PR review for {}#{}: {error}",
                        pull.repo, pull.number
                    ),
                ));
                for (at, _) in &review.comments {
                    outcomes[*at].kind = Kind::Failed;
                    outcomes[*at].error = Some(format!("Review finalization failed: {error}"));
                }
            }
            ReviewEnd::Skipped(reason) => {
                log(&command("warning", &reason));
                for (at, _) in &review.comments {
                    outcomes[*at].kind = Kind::Skipped;
                }
            }
        }
    }
    Ok(Published { outcomes, reviewed })
}

/// The review comments buffered for one review, as gh-aw's review buffer
/// holds them.
#[derive(Default)]
struct Review {
    /// What the first one read of the pull request.
    pull: Option<ReviewedPull>,
    /// Each comment as the forge is sent it, with the place of its outcome.
    comments: Vec<(usize, Value)>,
}

/// The pull request a review is of.
struct ReviewedPull {
    repo: String,
    number: u64,
    /// Its head, which the review is of.
    head: String,
    /// The `#N` the review's footer names.
    triggering: Option<String>,
}

/// How a review ended.
enum ReviewEnd {
    /// The review buffer's result.
    Made(Value),
    /// Not submitted, as a locked pull request takes none: why.
    Skipped(String),
    /// Not submitted: the error.
    Failed(String),
}

/// Buffers COMMENT for the review, as gh-aw's handler does, its outcome
/// to be at AT: the pull request read, and its body sanitized allowing
/// the DEFAULTS mentions.
fn buffer_review_comment(
    op: &Op,
    comment: &ReviewComment,
    defaults: &[String],
    github: &Github,
    run: &Run,
    at: usize,
    review: &mut Review,
) -> Outcome {
    let ReviewComment {
        repo,
        number,
        path,
        line,
        ..
    } = comment;
    let pull = match github.request("GET", &format!("/repos/{repo}/pulls/{number}"), None) {
        Ok(pull) => pull,
        Err(err) => {
            return Outcome::failed(op, format!("Failed to fetch pull request details: {err:#}"));
        }
    };
    let Some(head) = pull["head"]["sha"].as_str().filter(|sha| !sha.is_empty()) else {
        return Outcome::failed(op, "Pull request head commit SHA not found".to_owned());
    };
    let body = sanitize_with(
        js_trim(&comment.body),
        MAX_SANITIZED,
        &Mentions::Allowing {
            aliases: defaults,
            max: MAX_ALLOWED_MENTIONS,
        },
        &|host| run.keeps_link(host),
    );
    let mut sent = json!({"path": path, "line": line, "body": body});
    let mut metadata = json!({"path": path, "line": line});
    if let Some(start) = comment.start_line {
        sent["start_line"] = json!(start);
        metadata["start_line"] = json!(start);
    }
    sent["side"] = json!(comment.side);
    metadata["side"] = json!(comment.side);
    if comment.start_line.is_some() {
        sent["start_side"] = json!(comment.side);
    }
    // The first comment's pull request is the review's.
    review.pull.get_or_insert_with(|| ReviewedPull {
        repo: repo.clone(),
        number: *number,
        head: head.to_owned(),
        triggering: comment.triggering.clone(),
    });
    review.comments.push((at, sent));
    Outcome::succeeded(
        op,
        json!({"success": true, "buffered": true, "deferred_manifest": true,
            "pull_request_number": number, "repo": repo, "metadata": metadata}),
    )
}

/// The review buffer's `MAX_REVIEW_BODY_LENGTH`, and its fallback for
/// comments the forge could not anchor.
const MAX_REVIEW_BODY: usize = 65_000;
const FALLBACK_EXCERPT: usize = 500;
const FALLBACK_HEADER: &str = "### Comments that could not be inline-anchored";
const FALLBACK_EMPTY: &str = "_(empty comment body)_";
const FALLBACK_TRUNCATED: &str =
    "\n\n_(Fallback review body truncated to fit GitHub length limits.)_";
const FALLBACK_OMITTED: &str =
    "_(Unanchored comment details omitted to fit GitHub length limits.)_";

/// The most times a review of a locked pull request is sent again, and the
/// most it waits before each (`LOCKED_PR_RETRY_*`).
const LOCKED_RETRIES: u32 = 3;
const LOCKED_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Submits REVIEW of PULL as one review of event COMMENT, as gh-aw's review
/// buffer does (`submitReview`): comments on paths the pull request does
/// not change left out, the footer as its body, and those the forge cannot
/// anchor put in its body instead.
fn submit_review(
    pull: &ReviewedPull,
    review: &Review,
    run: &Run,
    github: &Github,
    log: &mut dyn FnMut(&Annotation),
) -> ReviewEnd {
    let ReviewedPull {
        repo, number, head, ..
    } = pull;
    let body = format!("\n\n{}\n", footer(run, pull.triggering.as_deref(), None));
    let mut comments: Vec<Value> = review.comments.iter().map(|(_, c)| c.clone()).collect();
    match diff_paths(github, repo, *number) {
        Ok(Some(paths)) if !paths.is_empty() => comments.retain(|comment| {
            let path = comment["path"].as_str().unwrap_or_default();
            let kept = paths.contains(path);
            if !kept {
                log(&command(
                    "warning",
                    &format!(
                        "Skipping review comment at '{path}:{}' — path not found in PR #{number} diff",
                        comment["line"]
                    ),
                ));
            }
            kept
        }),
        Ok(_) => {}
        Err(err) => log(&command(
            "warning",
            &format!(
                "Failed to validate comment paths against PR diff: {err:#}. Proceeding without \
                 path validation."
            ),
        )),
    }
    let before = match review_state(github, repo, *number, "before", log) {
        Ok(state) => state,
        Err(error) => return ReviewEnd::Failed(error),
    };
    let path = format!("/repos/{repo}/pulls/{number}/reviews");
    let operation = format!("pulls.createReview {repo}#{number}");
    let create = |comments: &[Value], body: &str| {
        let mut params = json!({"commit_id": head, "event": "COMMENT"});
        if !comments.is_empty() {
            params["comments"] = json!(comments);
        }
        if !body.is_empty() {
            params["body"] = json!(body);
        }
        github.request_retrying_up_to("POST", &path, Some(&params), &operation, 1)
    };
    let made = |answer: Value, submitted: &[Value], log: &mut dyn FnMut(&Annotation)| {
        review_made(answer, submitted, before.clone(), pull, github, log)
    };
    let err = match create(&comments, &body) {
        Ok(answer) => return made(answer, &comments, log),
        Err(err) => err,
    };
    let message = format!("{err:#}");
    if message.to_lowercase().contains("lock prevents review") {
        for _ in 0..LOCKED_RETRIES {
            std::thread::sleep(github.retry_wait.min(LOCKED_WAIT));
            match create(&comments, &body) {
                Ok(answer) => return made(answer, &comments, log),
                Err(err)
                    if format!("{err:#}")
                        .to_lowercase()
                        .contains("lock prevents review") => {}
                Err(err) => return ReviewEnd::Failed(format!("{err:#}")),
            }
        }
        return ReviewEnd::Skipped(format!("Review skipped — PR #{number} is locked"));
    }
    let unanchored = |message: &str| {
        message.contains("Line could not be resolved")
            || message.contains("Path could not be resolved")
    };
    if !unanchored(&message) || comments.is_empty() {
        return ReviewEnd::Failed(message);
    }
    let indices = unanchored_indices(&err, comments.len());
    if !indices.is_empty() && indices.len() < comments.len() {
        let of = |lost: bool| -> Vec<Value> {
            comments
                .iter()
                .enumerate()
                .filter(|(at, _)| indices.contains(at) == lost)
                .map(|(_, comment)| comment.clone())
                .collect()
        };
        let (lost, kept) = (of(true), of(false));
        match create(&kept, &with_unanchored(&body, &lost)) {
            Ok(answer) => return made(answer, &kept, log),
            Err(err) => log(&command(
                "warning",
                &format!(
                    "Failed to submit partially anchored PR review: {err:#}. Falling back to \
                     body-only review."
                ),
            )),
        }
    }
    match create(&[], &with_unanchored(&body, &comments)) {
        Ok(answer) => made(answer, &[], log),
        Err(err) => ReviewEnd::Failed(format!("{err:#}")),
    }
}

/// The paths pull request NUMBER of REPO changes, its files' and the
/// names they had, as the review buffer reads them: up to ten pages of
/// 100, or None past that.
fn diff_paths(github: &Github, repo: &str, number: u64) -> Result<Option<BTreeSet<String>>> {
    const MAX_PAGES: u64 = 10;
    const PER_PAGE: usize = 100;
    let mut paths = BTreeSet::new();
    for page in 1..=MAX_PAGES {
        let files = github.request(
            "GET",
            &format!("/repos/{repo}/pulls/{number}/files?per_page={PER_PAGE}&page={page}"),
            None,
        )?;
        let files = files.as_array().cloned().unwrap_or_default();
        for file in &files {
            for key in ["filename", "previous_filename"] {
                if let Some(path) = file[key].as_str().filter(|path| !path.is_empty()) {
                    paths.insert(path.to_owned());
                }
            }
        }
        if files.len() < PER_PAGE {
            return Ok(Some(paths));
        }
    }
    Ok(None)
}

/// What gh-aw records of the reviews of pull request NUMBER of REPO,
/// PHASE (`before`, `after`) its review (`fetchPullRequestReviewState`):
/// None where the forge failed it for now, and an error where it would
/// not answer at all, which fails the review.
fn review_state(
    github: &Github,
    repo: &str,
    number: u64,
    phase: &str,
    log: &mut dyn FnMut(&Annotation),
) -> Result<Option<Value>, String> {
    let read = || -> Result<Value> {
        let pull = github.request("GET", &format!("/repos/{repo}/pulls/{number}"), None)?;
        let reviews = github.request(
            "GET",
            &format!("/repos/{repo}/pulls/{number}/reviews?per_page=100"),
            None,
        )?;
        let teams = match &pull["requested_teams"] {
            Value::Null => &pull["requested_team_reviewers"],
            teams => teams,
        };
        let teams: Vec<&str> = teams
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|team| {
                team.as_str()
                    .or_else(|| team["slug"].as_str())
                    .or_else(|| team["name"].as_str())
            })
            .filter(|team| !team.is_empty())
            .collect();
        let reviews: Vec<Value> = reviews
            .as_array()
            .into_iter()
            .flatten()
            .map(|review| {
                let mut kept = Map::new();
                if !review["id"].is_null() {
                    kept.insert("id".into(), review["id"].clone());
                }
                for (key, value) in [
                    ("user", &review["user"]["login"]),
                    ("state", &review["state"]),
                    ("submitted_at", &review["submitted_at"]),
                ] {
                    if truthy(value) {
                        kept.insert(key.into(), value.clone());
                    }
                }
                Value::Object(kept)
            })
            .filter(|review| review.as_object().is_some_and(|kept| !kept.is_empty()))
            .collect();
        Ok(
            json!({"requested_reviewers": names_of(&pull["requested_reviewers"], "login"),
            "requested_team_reviewers": teams, "reviews": reviews}),
        )
    };
    match read() {
        Ok(state) => Ok(Some(state)),
        Err(err) if super::github::is_transient(&err) => {
            log(&command(
                "warning",
                &format!(
                    "Failed to capture {phase} PR review state for #{number}: {err:#}. \
                     Continuing without execution-state metadata."
                ),
            ));
            Ok(None)
        }
        Err(err) => Err(format!(
            "ERR_API: Failed to capture {phase} PR review state for #{number}: {err:#} \
             (non-transient)"
        )),
    }
}

/// The review buffer's result for the review the forge ANSWERed with
/// SUBMITTED comments, its state BEFORE and after, and its comments' IDs.
fn review_made(
    answer: Value,
    submitted: &[Value],
    before: Option<Value>,
    pull: &ReviewedPull,
    github: &Github,
    log: &mut dyn FnMut(&Annotation),
) -> ReviewEnd {
    let ReviewedPull { repo, number, .. } = pull;
    let after = match before {
        Some(_) => match review_state(github, repo, *number, "after", log) {
            Ok(state) => state,
            Err(error) => return ReviewEnd::Failed(error),
        },
        None => None,
    };
    let id = &answer["id"];
    let mut comments: Vec<Value> = submitted
        .iter()
        .map(|comment| {
            let mut metadata = json!({"path": comment["path"], "line": comment["line"]});
            if !comment["start_line"].is_null() {
                metadata["start_line"] = comment["start_line"].clone();
            }
            metadata["side"] = comment["side"].clone();
            metadata["review_id"] = id.clone();
            json!({"repo": repo, "pull_request_number": number, "metadata": metadata})
        })
        .collect();
    if !submitted.is_empty() {
        let path = format!("/repos/{repo}/pulls/{number}/reviews/{id}/comments?per_page=100");
        match github.request("GET", &path, None) {
            Ok(Value::Array(listed)) if !listed.is_empty() => {
                comments = listed
                    .iter()
                    .map(|comment| {
                        let mut metadata = json!({"review_id": id});
                        for key in ["node_id", "path", "side"] {
                            if truthy(&comment[key]) {
                                metadata[key] = comment[key].clone();
                            }
                        }
                        for key in ["line", "start_line"] {
                            if !comment[key].is_null() {
                                metadata[key] = comment[key].clone();
                            }
                        }
                        let mut ordered = Map::new();
                        for key in ["review_id", "node_id", "path", "line", "start_line", "side"] {
                            if let Some(value) = metadata.get(key) {
                                ordered.insert(key.into(), value.clone());
                            }
                        }
                        json!({"id": comment["id"], "url": comment["html_url"], "repo": repo,
                            "pull_request_number": number, "metadata": ordered})
                    })
                    .collect();
            }
            Ok(_) => {}
            Err(err) => log(&command(
                "warning",
                &format!("Could not resolve IDs for review comments on {repo}#{number}: {err:#}"),
            )),
        }
    }
    let mut metadata = json!({"review_id": id, "review_event": "COMMENT"});
    if truthy(&answer["state"]) {
        metadata["review_state"] = answer["state"].clone();
    }
    let mut result = json!({"success": true, "url": answer["html_url"], "number": number,
        "review_id": id, "review_url": answer["html_url"], "pull_request_number": number,
        "repo": repo, "event": "COMMENT", "comment_count": submitted.len(),
        "review_comments": comments, "metadata": metadata});
    if let Some(before) = before {
        result["before_state"] = before;
    }
    if let Some(after) = after {
        result["after_state"] = after;
    }
    ReviewEnd::Made(result)
}

/// The places of the comments the forge's refusal ERR says it could not
/// anchor (`extractUnresolvableCommentIndices`), of COUNT.
fn unanchored_indices(err: &anyhow::Error, count: usize) -> Vec<usize> {
    static FIELD: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"comments(?:\[|\.)(\d+)(?:\]|\.|$)").expect("a valid pattern")
    });
    let refused = err
        .downcast_ref::<super::github::Retried>()
        .and_then(|retried| retried.refused.as_ref())
        .or_else(|| err.downcast_ref::<Refused>());
    let mut indices: Vec<usize> = refused
        .map(|refused| refused.errors.as_slice())
        .unwrap_or_default()
        .iter()
        .filter(|error| {
            error["message"].as_str().is_some_and(|message| {
                message.contains("Line could not be resolved")
                    || message.contains("Path could not be resolved")
            })
        })
        .filter_map(|error| FIELD.captures(error["field"].as_str()?))
        .filter_map(|caps| caps[1].parse::<usize>().ok())
        .filter(|at| *at < count)
        .collect();
    indices.sort_unstable();
    indices.dedup();
    indices
}

/// BODY with COMMENTS in a section of their own, as excerpts the review's
/// length allows (`appendUnanchoredCommentsSection`).
fn with_unanchored(body: &str, comments: &[Value]) -> String {
    let escape = |text: &str| {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    };
    let block = |comment: &Value, text: &str| {
        let summary = format!(
            "{}:{}",
            comment["path"].as_str().unwrap_or_default(),
            comment["line"]
        );
        format!(
            "<details><summary>{}</summary>\n\n{}\n\n</details>",
            escape(&summary),
            escape(text)
        )
    };
    let prefix = if body.is_empty() {
        format!("{FALLBACK_HEADER}\n\n")
    } else {
        format!("\n\n{FALLBACK_HEADER}\n\n")
    };
    let overhead: usize = comments
        .iter()
        .enumerate()
        .map(|(at, comment)| usize::from(at > 0) * 2 + utf16_len(&block(comment, "")))
        .sum();
    let available =
        MAX_REVIEW_BODY as i64 - (utf16_len(body) + utf16_len(&prefix) + overhead) as i64;
    let limit = match comments.len() {
        0 => FALLBACK_EXCERPT,
        _ if available <= 0 => 0,
        n => FALLBACK_EXCERPT.min(usize::try_from(available).unwrap_or(0) / n),
    };
    let blocks: Vec<String> = comments
        .iter()
        .map(|comment| {
            let text = js_trim(comment["body"].as_str().unwrap_or_default());
            if limit == 0 {
                return block(comment, FALLBACK_EMPTY);
            }
            let excerpt = if utf16_len(text) > limit {
                format!("{}…", utf16_prefix(text, limit.saturating_sub(1)))
            } else {
                text.to_owned()
            };
            block(
                comment,
                if excerpt.is_empty() {
                    FALLBACK_EMPTY
                } else {
                    &excerpt
                },
            )
        })
        .collect();
    let merged = format!("{body}{prefix}{}", blocks.join("\n\n"));
    if utf16_len(&merged) <= MAX_REVIEW_BODY {
        return merged;
    }
    let max = MAX_REVIEW_BODY - utf16_len(FALLBACK_TRUNCATED);
    let omitted = format!("{body}{prefix}{FALLBACK_OMITTED}");
    if utf16_len(body) <= max && utf16_len(&omitted) <= MAX_REVIEW_BODY {
        return omitted;
    }
    format!("{}{FALLBACK_TRUNCATED}", utf16_prefix(body, max))
}

/// Publishes OP with PUBLISHER, as [`publish`] does once it is to: a
/// review comment buffered in the review of REVIEW, its outcome to be at
/// the place REVIEW names.
fn publish_one(
    op: &Op,
    publisher: &GithubPublisher,
    run: &Run,
    defaults: &[String],
    review: &mut (usize, &mut Review),
    log: &mut dyn FnMut(&Annotation),
) -> Outcome {
    let github = match publisher
        .github
        .for_role(super::roles::Role::output(op.output()))
    {
        Ok(github) => github,
        Err(err) => return Outcome::failed(op, format!("{err:#}")),
    };
    let publisher = &GithubPublisher {
        github,
        git: publisher.git.clone(),
        item_repo: publisher.item_repo.clone(),
        repo: publisher.repo.clone(),
    };
    match op {
        Op::Document {
            document,
            settings,
            repo,
            issue,
            ..
        } => match super::document::publish(&publisher.github, document, settings, repo, *issue) {
            Ok(result) => {
                if let Some(error) = result["comment_error"].as_str() {
                    let mut outcome = Outcome::failed(op, error.to_owned());
                    outcome.result = result;
                    outcome
                } else {
                    Outcome::succeeded(op, result)
                }
            }
            Err(err) => Outcome::failed(op, format!("{err:#}")),
        },
        Op::ReviewComment { comment, .. } => {
            let (at, review) = review;
            buffer_review_comment(op, comment, defaults, &publisher.github, run, *at, review)
        }
        Op::Comment {
            item, repo, issue, ..
        } => comment(op, item, repo, *issue, defaults, publisher, run),
        Op::PullRequest {
            failure: Some(failure),
            ..
        } => Outcome::failed(op, failure.clone()),
        Op::PullRequest { pr, .. } => pull_request_outcome(op, pr, defaults, publisher, run),
        Op::Labels { request, .. } if request.add => add_labels(op, request, &publisher.github),
        Op::Labels { request, .. } => remove_labels(op, request, &publisher.github),
        Op::Close {
            repo,
            close,
            state_reason,
            triggering,
            ..
        } => close_item(
            op,
            repo,
            close,
            state_reason.as_deref(),
            triggering.as_deref(),
            &publisher.github,
            run,
        ),
        Op::Push { push, .. } => push_outcome(op, push, publisher, run, log),
        Op::Issue { issue, .. } => issue_outcome(op, issue, defaults, &publisher.github, run, log),
    }
}

/// `linkSubIssue`'s queries, as the handler sends them.
const ISSUE_NODE_QUERY: &str = "\n      query($owner: String!, $repo: String!, $issueNumber: Int!) {\n        repository(owner: $owner, name: $repo) {\n          issue(number: $issueNumber) {\n            id\n          }\n        }\n      }\n    ";
const ADD_SUB_ISSUE: &str = "\n      mutation AddSubIssue($parentId: ID!, $subIssueId: ID!) {\n        addSubIssue(input: { issueId: $parentId, subIssueId: $subIssueId }) {\n          issue {\n            id\n            number\n          }\n          subIssue {\n            id\n            number\n          }\n        }\n      }\n    ";

/// Opens the issue of ISSUE, as gh-aw's handler does with apply.yml's
/// settings, allowing the DEFAULTS mentions; one the event's issue is
/// related to becomes its sub-issue, or that issue gets a comment saying
/// so where the forge will not link them.
fn issue_outcome(
    op: &Op,
    issue: &IssueRequest,
    defaults: &[String],
    github: &Github,
    run: &Run,
    log: &mut dyn FnMut(&Annotation),
) -> Outcome {
    let IssueRequest { repo, labels, .. } = issue;
    if labels.len() > MAX_LABELS {
        return Outcome::failed(
            op,
            format!(
                "E003: Cannot add more than {MAX_LABELS} labels (received {})",
                labels.len()
            ),
        );
    }
    let body = sanitize_with(
        &issue.body,
        MAX_SANITIZED,
        &Mentions::Allowing {
            aliases: defaults,
            max: MAX_ALLOWED_MENTIONS,
        },
        &|host| run.keeps_link(host),
    );
    // `formatIssueBody`: the footer and the workflow's marker after it.
    let mut lines: Vec<String> = body.split('\n').map(str::to_owned).collect();
    if let Some(parent) = issue.parent {
        lines.push(format!("Related to #{parent}"));
    }
    let history = history_url(run, repo, "issues", true);
    lines.extend([
        String::new(),
        footer(run, issue.triggering.as_deref(), Some(&history)),
        String::new(),
        format!("<!-- gh-aw-workflow-id: {} -->", run.workflow_id),
        String::new(),
    ]);
    let body = with_provenance(run, js_trim(&lines.join("\n")));
    if utf16_len(&body) > MAX_BODY_UNITS {
        return Outcome::failed(
            op,
            format!(
                "ERR_VALIDATION: Issue body exceeds GitHub's maximum length of {MAX_BODY_UNITS} \
                 characters"
            ),
        );
    }
    if issue.comment_on_duplicate {
        match open_duplicate(github, repo, &issue.title) {
            Ok(Some(number)) => return duplicate_comment(op, github, repo, number, &body),
            Ok(None) => {}
            // Opening it anyway could make the duplicate the bounds ask
            // to be spared.
            Err(err) => {
                return Outcome::failed(
                    op,
                    format!(
                        "could not search {repo} for an open issue titled {:?}: {err:#}",
                        issue.title
                    ),
                );
            }
        }
    }
    let made = github.request_retrying(
        "POST",
        &format!("/repos/{repo}/issues"),
        Some(
            &json!({"title": issue.title, "body": hide_applied(&body), "labels": labels,
            "assignees": []}),
        ),
        &format!("create_issue in {repo}"),
    );
    let made = match made {
        Ok(made) => made,
        Err(err) => {
            let error = format!("{err:#}");
            if error.contains("Issues has been disabled in this repository") {
                return Outcome::failed(op, "Issues disabled for repository".to_owned());
            }
            return Outcome::failed(op, error);
        }
    };
    // An answer naming no issue links nothing.
    if let Some(parent) = issue.parent
        && let Some(number) = made["number"].as_u64()
        && let Err(err) = link_sub_issue(github, repo, parent, number)
    {
        // Best effort, as the handler's: the issue is made.
        let path = format!("/repos/{repo}/issues/{parent}/comments");
        let note = with_provenance(run, &format!("Created related issue: #{number}"));
        if let Err(also) = github.request("POST", &path, Some(&json!({"body": note}))) {
            log(&command(
                "warning",
                &format!(
                    "Could not link #{number} as a sub-issue of #{parent} ({err:#}), nor \
                     comment on it: {also:#}"
                ),
            ));
        }
    }
    Outcome::succeeded(
        op,
        json!({"success": true, "repo": repo, "number": made["number"], "url": made["html_url"],
            "body": body, "id": made["id"], "metadata": {"node_id": made["node_id"]},
            "temporaryId": temporary_id(), "_repo": repo}),
    )
}

/// The oldest open issue of REPO titled exactly TITLE, among the first
/// page of what the forge's search finds, oldest first; a pull request is
/// not one.
fn open_duplicate(github: &Github, repo: &str, title: &str) -> Result<Option<u64>> {
    // A phrase cannot hold a quote; each answer is held to the repository,
    // the state and the exact title below, whatever the search made of it.
    let phrase = title.replace(['"', '\\'], " ");
    let found = github.search_issues(&format!(
        "repo:{repo} is:issue is:open in:title \"{phrase}\" sort:created-asc"
    ))?;
    let in_repo = format!("/repos/{repo}").to_ascii_lowercase();
    Ok(found
        .iter()
        .filter(|item| {
            item.get("pull_request").is_none()
                && item["state"] == "open"
                && item["title"] == title
                && item["repository_url"]
                    .as_str()
                    .is_some_and(|url| url.to_ascii_lowercase().ends_with(&in_repo))
        })
        .filter_map(|item| item["number"].as_u64())
        .min())
}

/// Posts BODY, the issue's as it would have been opened, on issue NUMBER
/// of REPO, its duplicate.
fn duplicate_comment(op: &Op, github: &Github, repo: &str, number: u64, body: &str) -> Outcome {
    let path = format!("/repos/{repo}/issues/{number}/comments");
    match github.request("POST", &path, Some(&json!({"body": hide_applied(body)}))) {
        Ok(made) => Outcome::succeeded(
            op,
            json!({"success": true, "repo": repo, "duplicate_of": number,
                "url": made["html_url"], "body": body, "id": made["id"], "_repo": repo}),
        ),
        Err(err) => Outcome::failed(
            op,
            format!("could not comment on #{number}, the open issue of the same title: {err:#}"),
        ),
    }
}

/// Makes issue CHILD of REPO a sub-issue of PARENT there, as
/// `linkSubIssue` does: both node IDs asked for, then linked.
fn link_sub_issue(github: &Github, repo: &str, parent: u64, child: u64) -> Result<()> {
    let (owner, name) = repo.split_once('/').context("the repository")?;
    let node = |number: u64| -> Result<Value> {
        let data = github.graphql(
            ISSUE_NODE_QUERY,
            json!({"owner": owner, "repo": name, "issueNumber": number}),
        )?;
        Ok(data["repository"]["issue"]["id"].clone())
    };
    let (parent, child) = (node(parent)?, node(child)?);
    github.graphql(
        ADD_SUB_ISSUE,
        json!({"parentId": parent, "subIssueId": child}),
    )?;
    Ok(())
}

/// A line for the caller's log, as the workflow command [`Self::kind`]
/// names: the caller writes it on one line, escaped as its log takes
/// untrusted text, which [`Self::text`] may hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    /// `error` or `warning`.
    pub kind: &'static str,
    pub text: String,
}

/// LINE as the workflow command KIND (`error`, `warning`).
fn command(kind: &'static str, line: &str) -> Annotation {
    Annotation {
        kind,
        text: line.to_owned(),
    }
}

/// gh-aw's error when the branch moved on since the run was asked for and
/// git refused the push (`nonFastForwardPatterns`); `fallback_as_pull_request`
/// is off.
const NON_FAST_FORWARD: &str = "Failed to push changes: remote PR branch changed while the \
                                workflow was running (non-fast-forward). Re-run the workflow on \
                                the latest PR branch state.";

/// Pushes the patch of PUSH as one commit on its pull request's branch,
/// as gh-aw's handler does under apply.yml's settings, and comments on
/// the pull request with the commit. The branch has to be at the head the
/// run was asked for still: one that moved on is not pushed to, and one
/// rewritten since is refused, where gh-aw's handler would apply the
/// patch on whatever it now holds.
fn push_outcome(
    op: &Op,
    push: &PushRequest,
    publisher: &GithubPublisher,
    run: &Run,
    log: &mut dyn FnMut(&Annotation),
) -> Outcome {
    match &push.early {
        Some(Early::Failed(error)) => return Outcome::failed(op, error.clone()),
        Some(Early::Skipped(result)) => return Outcome::skipped(op, result.clone()),
        None => {}
    }
    let PushRequest {
        repo,
        head_repo,
        number,
        ..
    } = push;
    let github = &publisher.github;
    let Ok(pull) = github.request("GET", &format!("/repos/{repo}/pulls/{number}"), None) else {
        return Outcome::failed(
            op,
            format!("Failed to determine branch name for PR {number} in {repo}"),
        );
    };
    if pull["head"]["repo"].is_null() {
        return Outcome::failed(
            op,
            "Cannot push to PR: head repository is null (likely a deleted fork)".to_owned(),
        );
    }
    // gh-aw's handler takes a head naming no repository for `head-repo`;
    // this does not.
    let actual = pull["head"]["repo"]["full_name"]
        .as_str()
        .unwrap_or_default();
    if !actual.eq_ignore_ascii_case(head_repo) {
        return Outcome::failed(
            op,
            format!(
                "Cannot push to PR: head repository '{actual}' does not match expected \
                 '{head_repo}'. Writes to repositories other than the configured head-repo \
                 remain blocked."
            ),
        );
    }
    let branch = normalize_branch(pull["head"]["ref"].as_str().unwrap_or_default());
    if branch != push.branch {
        return Outcome::failed(
            op,
            format!(
                "the pull request's branch is {branch:?}, not {:?}, which the run was asked to \
                 push to",
                push.branch
            ),
        );
    }
    if let Some(blocked) = unpushable(github, head_repo, &branch, log) {
        return Outcome::failed(op, blocked);
    }
    if !push.allow_workflows
        && push
            .files
            .iter()
            .any(|file| file.starts_with(".github/workflows/"))
    {
        return Outcome::failed(op, WORKFLOWS_SCOPE.to_owned());
    }
    let fork = format!("{}/{head_repo}.git", publisher.git);
    let pushed = github.git().push(
        &Push {
            from: &fork,
            base: &branch,
            base_commit: &push.head,
            to: &fork,
            branch: &branch,
            patch: &push.patch,
            files: &push.files,
            head: Some(&push.head),
            committer: Some(ACTIONS_COMMITTER),
            // So that the commit is the same whenever it is made.
            at_author_date: true,
            max_changed_kb: Some(push.max_kb),
        },
        None,
    );
    let commit = match pushed {
        Ok(commit) => commit,
        Err(err) if err.is::<Moved>() => return Outcome::failed(op, NON_FAST_FORWARD.to_owned()),
        Err(err) if err.is::<TooLarge>() => return Outcome::failed(op, err.to_string()),
        Err(err) => return Outcome::failed(op, format!("Failed to push changes: {err:#}")),
    };
    let commit_url = format!("{}/{head_repo}/commit/{commit}", run.server);
    // `updateActivationCommentWithCommit`, without an activation comment:
    // a new one on the pull request, whose failure fails nothing.
    let note = format!(
        "\n\nCommit pushed: [`{}`]({commit_url})\n\n{}",
        &commit[..7],
        footer(run, None, None)
    );
    let body = sanitize_with(&note, MAX_SANITIZED, &Mentions::All, &|host| {
        run.keeps_link(host)
    });
    let path = format!("/repos/{repo}/issues/{number}/comments");
    let commented = github
        .for_role(super::roles::Role::Review)
        .and_then(|github| github.request("POST", &path, Some(&json!({"body": body}))));
    if let Err(err) = commented {
        log(&command(
            "warning",
            &format!("Failed to create comment on {repo}#{number}: {err:#}"),
        ));
    }
    let mut result = json!({"success": true, "number": number, "repo": repo,
        "head_repo": head_repo, "url": format!("{}/{repo}/pull/{number}", run.server),
        "branch_name": branch, "commit_sha": commit, "commit_url": commit_url});
    if let Some(before) = pull["head"]["sha"].as_str().filter(|sha| !sha.is_empty()) {
        result["before_state"] = json!({"head_sha": before});
    }
    result["after_state"] = json!({"head_sha": commit});
    Outcome::succeeded(op, result)
}

/// gh-aw's error for a push of workflow files without `allow_workflows`
/// (`buildWorkflowsScopeError`).
const WORKFLOWS_SCOPE: &str = "Branch push rejected: the branch includes changes to workflow \
     files (.github/workflows/**) requiring the 'workflows' scope. The token used for the \
     safe-outputs checkout does not have this scope. Fix: configure \
     'push-to-pull-request-branch.allow-workflows: true' with a GitHub App in \
     'safe-outputs.github-app', or exclude workflow files from the changeset.";

/// Why gh-aw's handler does not push to BRANCH of REPO
/// (`checkBranchPushable`): the default branch, or one with protection
/// rules, or whose rules cannot be read.
fn unpushable(
    github: &Github,
    repo: &str,
    branch: &str,
    log: &mut dyn FnMut(&Annotation),
) -> Option<String> {
    match github.request("GET", &format!("/repos/{repo}"), None) {
        Ok(found) if found["default_branch"].as_str() == Some(branch) => {
            return Some(format!(
                "Cannot push to branch \"{branch}\": this is the repository's default branch. \
                 Agents must not push directly to the default branch."
            ));
        }
        Ok(_) => {}
        Err(err) => log(&command(
            "warning",
            &format!("Could not check repository default branch: {err:#}"),
        )),
    }
    let path = format!(
        "/repos/{repo}/branches/{}/protection",
        uri_component(branch)
    );
    let err = match github.request("GET", &path, None) {
        Ok(_) => {
            return Some(format!(
                "Cannot push to branch \"{branch}\": this branch has protection rules. Agents \
                 must not push directly to protected branches."
            ));
        }
        Err(err) => err,
    };
    match err.downcast_ref::<Refused>().map(|refused| refused.status) {
        Some(404) => None,
        // The forge holds a push to its rules anyway.
        Some(403) => {
            log(&command(
                "warning",
                &format!(
                    "Could not check branch protection rules for \"{branch}\" (insufficient \
                     permissions): {err:#}"
                ),
            ));
            None
        }
        _ => Some(format!(
            "Cannot verify branch protection rules for \"{branch}\": {err:#}. Push blocked to \
             prevent accidental writes to protected branches."
        )),
    }
}

/// Posts the comment of ITEM on ISSUE of REPO, as gh-aw's handler does.
fn comment(
    op: &Op,
    item: &Map<String, Value>,
    repo: &str,
    issue: u64,
    defaults: &[String],
    publisher: &GithubPublisher,
    run: &Run,
) -> Outcome {
    // The item's author may be mentioned, where the forge says who it is.
    let mut aliases = Vec::new();
    if let Ok(found) =
        publisher
            .github
            .request("GET", &format!("/repos/{repo}/issues/{issue}"), None)
        && let Some(login) = found["user"]["login"]
            .as_str()
            .filter(|login| !login.is_empty())
        && found["user"]["type"] != "Bot"
    {
        aliases.push(login.to_owned());
    }
    aliases.extend(defaults.iter().cloned());
    let aliases = dedupe(aliases);
    let body = item.get("body").and_then(Value::as_str).unwrap_or_default();
    let body = sanitize_with(
        body,
        MAX_SANITIZED,
        &Mentions::Allowing {
            aliases: &aliases,
            max: MAX_ALLOWED_MENTIONS,
        },
        &|host| run.keeps_link(host),
    );
    if let Some(error) = comment_limits(&body) {
        return Outcome::failed(op, error);
    }
    let triggering = match run.triggering(ADD_COMMENT) {
        Ok(triggering) => triggering,
        Err(err) => return Outcome::failed(op, format!("{err:#}")),
    };
    let body = format!(
        "{body}\n\n{}",
        footer(
            run,
            triggering.as_deref(),
            Some(&history_url(run, repo, "issues", false))
        )
    );
    let body = with_provenance(run, &body);
    if let Some(error) = comment_limits(&body) {
        return Outcome::failed(op, error);
    }
    let body = hide_applied(&body);
    let body = if let Op::Comment {
        advisory: Some(advisory),
        ..
    } = op
    {
        let prepare = (|| -> Result<String> {
            ensure!(
                repo == advisory.repo
                    && issue == advisory.pull
                    && publisher.item_repo == advisory.repo,
                "advisory writer target differs from policy"
            );
            let body = advisory.body(&body)?;
            let pull =
                publisher
                    .github
                    .request("GET", &format!("/repos/{repo}/pulls/{issue}"), None)?;
            advisory.check_pull(&pull)?;
            Ok(body)
        })();
        match prepare {
            Ok(body) => body,
            Err(err) => return Outcome::failed(op, format!("{err:#}")),
        }
    } else {
        body
    };
    match publisher.comment(issue, &body) {
        Ok(Made { url, id, .. }) => Outcome {
            output: ADD_COMMENT,
            index: op.index(),
            kind: Kind::Success,
            result: json!({"success": true, "commentId": id, "url": url, "itemNumber": issue,
                "repo": repo, "isDiscussion": false}),
            error: None,
        },
        Err(err) => match err.downcast_ref::<Refused>() {
            // A locked item is a state gh-aw's handler leaves as it is.
            Some(refused)
                if refused.status == 423
                    || (refused.status == 403
                        && refused.message.to_lowercase().contains("locked")) =>
            {
                Outcome::skipped(
                    op,
                    json!({"success": true, "warning": format!("Target is locked: {}", refused.message),
                        "skipped": true, "reasonCode": "TARGET_LOCKED", "reason": "Target is locked",
                        "target": {"repo": repo, "number": issue}}),
                )
            }
            Some(refused)
                if refused.status == 404
                    || refused.message.contains("404")
                    || refused.message.to_lowercase().contains("not found") =>
            {
                Outcome::failed(
                    op,
                    format!(
                        "{}: #{issue} is not an issue or pull request of {repo}, and agentic-job \
                         publish comments on no discussion",
                        refused.message
                    ),
                )
            }
            _ => Outcome::failed(op, format!("{err:#}")),
        },
    }
}

/// Opens the pull request PR, as gh-aw's handler does.
fn pull_request_outcome(
    op: &Op,
    pr: &PullRequest,
    defaults: &[String],
    publisher: &GithubPublisher,
    run: &Run,
) -> Outcome {
    let body = match pull_request_body(&pr.body, defaults, publisher, run) {
        Ok(body) => body,
        Err(err) => return Outcome::failed(op, format!("{err:#}")),
    };
    if utf16_len(&body) > MAX_BODY_UNITS {
        return Outcome::failed(
            op,
            format!(
                "Pull request body exceeds GitHub's maximum length of {MAX_BODY_UNITS} characters"
            ),
        );
    }
    let pr = PullRequest {
        body: hide_applied(&body),
        ..pr.clone()
    };
    match publisher.open_pull_request(&pr) {
        Ok(made) => {
            let temporary_id = temporary_id();
            Outcome {
                output: CREATE_PULL_REQUEST,
                index: op.index(),
                kind: Kind::Success,
                result: json!({"success": true, "number": made.number, "url": made.url,
                    "id": made.id, "metadata": {"node_id": made.node_id}, "branch_name": pr.branch,
                    "temporaryId": temporary_id, "repo": publisher.repo, "head_repo": pr.push_repo,
                    "base": pr.base}),
                error: None,
            }
        }
        Err(err) => Outcome::failed(op, format!("{err:#}")),
    }
}

/// A pull request's BODY, without a first heading repeating the title, as
/// gh-aw's handler writes it: sanitized, with the footer, the workflow's
/// marker and the run's provenance.
fn pull_request_body(
    body: &str,
    defaults: &[String],
    publisher: &GithubPublisher,
    run: &Run,
) -> Result<String> {
    let body = sanitize_with(
        body,
        MAX_SANITIZED,
        &Mentions::Allowing {
            aliases: defaults,
            max: MAX_ALLOWED_MENTIONS,
        },
        &|host| run.keeps_link(host),
    );
    let triggering = run.triggering(CREATE_PULL_REQUEST)?;
    let history = history_url(run, &publisher.repo, "pullrequests", false);
    let mut lines: Vec<String> = body.split('\n').map(str::to_owned).collect();
    lines.push(String::new());
    lines.push(footer(run, triggering.as_deref(), Some(&history)));
    lines.push(String::new());
    lines.push(format!("<!-- gh-aw-workflow-id: {} -->", run.workflow_id));
    lines.push(String::new());
    Ok(with_provenance(run, js_trim(&lines.join("\n"))))
}

/// `generateTemporaryId`: `aw_` and eight letters or digits.
fn temporary_id() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 8];
    // Not a secret: it only tells requests apart within a run.
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes);
    let id: String = bytes
        .iter()
        .map(|byte| char::from(CHARS[usize::from(*byte) % CHARS.len()]))
        .collect();
    format!("aw_{id}")
}

/// Adds the labels of REQUEST, as gh-aw's handler does: no write where
/// it would make none, and the item's state before and after recorded.
fn add_labels(op: &Op, request: &LabelRequest, github: &Github) -> Outcome {
    let LabelRequest {
        repo,
        number,
        labels,
        allowed,
        blocked,
        kind,
        ..
    } = request;
    if labels.is_empty() {
        let message = format!(
            "No labels provided. Skipping add_labels. Provide at least one label from {}",
            label_source(allowed, "the repository's available labels")
        );
        return Outcome::skipped(
            op,
            json!({"success": true, "skipped": true, "reasonCode": "NO_LABELS_PROVIDED",
                "reason": "No labels provided", "number": number, "labelsAdded": [],
                "message": message}),
        );
    }
    if labels.len() > MAX_LABELS {
        return Outcome::failed(
            op,
            format!(
                "E003: Cannot add more than {MAX_LABELS} labels (received {})",
                labels.len()
            ),
        );
    }
    let kept = kept_labels(labels, allowed, blocked, MAX_LABELS);
    if kept.is_empty() {
        return Outcome::succeeded(
            op,
            json!({"success": true, "number": number, "labelsAdded": [],
                "message": "No valid labels found"}),
        );
    }
    let issue = format!("/repos/{repo}/issues/{number}");
    let before = match github.request("GET", &issue, None) {
        Ok(found) => issue_state(&found),
        Err(err) => return Outcome::failed(op, format!("{err:#}")),
    };
    let answer = match github.request_retrying(
        "POST",
        &format!("{issue}/labels"),
        Some(&json!({"labels": kept})),
        &format!("add_labels to {kind} #{number} in {repo}"),
    ) {
        Ok(answer) => answer,
        Err(err) => return Outcome::failed(op, format!("{err:#}")),
    };
    let mut after = before.clone();
    after["labels"] = json!(names_of(&answer, "name"));
    Outcome::succeeded(
        op,
        json!({"success": true, "number": number, "repo": repo, "labelsAdded": kept,
            "labels": label_records(&answer, &kept), "contextType": kind,
            "before_state": before, "after_state": after}),
    )
}

/// Removes the labels of REQUEST one at a time, as gh-aw's handler does:
/// one the item does not have, or that the forge will not remove, is
/// left, and the request succeeds.
fn remove_labels(op: &Op, request: &LabelRequest, github: &Github) -> Outcome {
    let LabelRequest {
        repo,
        number,
        labels,
        allowed,
        blocked,
        kind,
        ..
    } = request;
    if labels.is_empty() {
        let source = if allowed.is_empty() {
            "the issue/PR's current labels".to_owned()
        } else {
            label_source(allowed, "")
        };
        return Outcome::failed(
            op,
            format!("No labels provided. Please provide at least one label from {source}"),
        );
    }
    // The handler's `max` bounds the labels of one request too.
    let max = usize::try_from(op.max()).unwrap_or(usize::MAX);
    let kept = kept_labels(labels, allowed, blocked, max);
    if kept.is_empty() {
        return Outcome::succeeded(
            op,
            json!({"success": true, "number": number, "labelsRemoved": [],
                "message": "No valid labels found"}),
        );
    }
    let (mut removed, mut failed) = (Vec::new(), Vec::new());
    for label in &kept {
        let path = format!(
            "/repos/{repo}/issues/{number}/labels/{}",
            uri_component(label)
        );
        match github.request("DELETE", &path, None) {
            Ok(_) => removed.push(label.clone()),
            Err(err) => {
                let error = format!("{err:#}");
                if !(error.contains("Label does not exist") || error.contains("404")) {
                    failed.push(json!({"label": label, "error": error}));
                }
            }
        }
    }
    let mut result = json!({"success": true, "number": number, "labelsRemoved": removed});
    if !failed.is_empty() {
        result["failedLabels"] = json!(failed);
    }
    result["contextType"] = json!(kind);
    Outcome::succeeded(op, result)
}

/// "the allowed list: [...]" of ALLOWED, or OTHERWISE where there are none.
fn label_source(allowed: &[String], otherwise: &str) -> String {
    if allowed.is_empty() {
        return otherwise.to_owned();
    }
    format!("the allowed list: {}", json!(allowed))
}

/// What gh-aw's label handlers keep of LABELS (`validateLabels`): those
/// no BLOCKED pattern matches and, where there are ALLOWED ones, one of
/// them does, once each, the first MAX. [`plain_label`] holds each to
/// what its sanitizer leaves as it is.
fn kept_labels(
    labels: &[String],
    allowed: &[String],
    blocked: &[String],
    max: usize,
) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    for label in labels {
        let blocked = blocked.iter().any(|pattern| matches_glob(label, pattern));
        let allowed =
            allowed.is_empty() || allowed.iter().any(|pattern| matches_glob(label, pattern));
        if !blocked && allowed && !kept.contains(label) {
            kept.push(label.clone());
        }
    }
    kept.truncate(max);
    kept
}

/// `matchesSimpleGlob`: TEXT is PATTERN, case ignored, `*` any run of
/// characters. Both are ASCII here.
fn matches_glob(text: &str, pattern: &str) -> bool {
    if text.is_empty() || pattern.is_empty() {
        return false;
    }
    if text.eq_ignore_ascii_case(pattern) {
        return true;
    }
    let pattern: Vec<String> = pattern.split('*').map(regex::escape).collect();
    Regex::new(&format!("(?i)^{}$", pattern.join(".*"))).is_ok_and(|glob| glob.is_match(text))
}

/// TEXT as octokit writes a path parameter: all but RFC 3986's unreserved
/// characters percent-encoded.
fn uri_component(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The KEY of each entry of LIST that has one, or the entry where it is
/// text (`normalizeLabelNames`, `normalizeAssigneeLogins`).
fn names_of(list: &Value, key: &str) -> Vec<String> {
    list.as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.as_str().or_else(|| entry[key].as_str()))
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `extractIssueStateFromData`: what gh-aw records of ISSUE before and
/// after it changes it.
fn issue_state(issue: &Value) -> Value {
    json!({
        "title": issue["title"].as_str().unwrap_or_default(),
        "body_hash": body_hash(issue["body"].as_str().unwrap_or_default()),
        "state": issue["state"].as_str().unwrap_or_default(),
        "labels": names_of(&issue["labels"], "name"),
        "assignees": names_of(&issue["assignees"], "login"),
    })
}

/// `hashNormalizedBody`: the SHA-256 of BODY with CRLF line ends, the
/// spaces and tabs ending each line and the whitespace around it gone.
fn body_hash(body: &str) -> String {
    let body = body.replace("\r\n", "\n");
    let lines: Vec<&str> = body
        .split('\n')
        .map(|line| line.trim_end_matches([' ', '\t']))
        .collect();
    ring::digest::digest(&ring::digest::SHA256, js_trim(&lines.join("\n")).as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `buildLabelRecords`: each of NAMES with the IDs the forge's ANSWER
/// gives the label of that name, case ignored, the last one listed.
fn label_records(answer: &Value, names: &[String]) -> Vec<Value> {
    let details: Vec<&Value> = answer
        .as_array()
        .into_iter()
        .flatten()
        .filter(|label| label["name"].is_string())
        .collect();
    names
        .iter()
        .map(|name| {
            let mut record = Map::new();
            record.insert("name".into(), json!(name));
            let detail = details.iter().rev().find(|label| {
                label["name"]
                    .as_str()
                    .is_some_and(|other| other.to_lowercase() == name.to_lowercase())
            });
            if let Some(detail) = detail {
                if detail["id"].is_number() {
                    record.insert("database_id".into(), detail["id"].clone());
                }
                if detail["node_id"].is_string() {
                    record.insert("node_id".into(), detail["node_id"].clone());
                } else if detail["id"].is_string() {
                    record.insert("node_id".into(), detail["id"].clone());
                }
            }
            Value::Object(record)
        })
        .collect()
}

/// Comments on and closes the item of CLOSE in REPO, as gh-aw's handlers
/// do (`createCloseEntityHandler`): the comment first, even on an item
/// closed already, which is not closed again. A pull request is closed
/// even where its comment fails; an issue is not. The comment's footer
/// names TRIGGERING.
fn close_item(
    op: &Op,
    repo: &str,
    close: &Close,
    state_reason: Option<&str>,
    triggering: Option<&str>,
    github: &Github,
    run: &Run,
) -> Outcome {
    let number = close.number;
    if js_trim(&close.body).is_empty() {
        return Outcome::failed(op, "No comment body provided".to_owned());
    }
    let body = sanitize_with(&close.body, MAX_SANITIZED, &Mentions::All, &|host| {
        run.keeps_link(host)
    });
    let (noun, path) = match close.kind {
        ItemKind::Issue => ("issue", format!("/repos/{repo}/issues/{number}")),
        ItemKind::PullRequest => ("pull request", format!("/repos/{repo}/pulls/{number}")),
    };
    let entity = match github.request("GET", &path, None) {
        Ok(entity) => entity,
        Err(err) => return Outcome::failed(op, format!("{err:#}")),
    };
    let closed_already = entity["state"] == "closed";
    let body = format!("{}\n\n{}\n", js_trim(&body), footer(run, triggering, None));
    let comment = github.request(
        "POST",
        &format!("/repos/{repo}/issues/{number}/comments"),
        Some(&json!({"body": hide_applied(&body)})),
    );
    let posted = match (comment, close.kind) {
        (Ok(_), _) => true,
        (Err(err), ItemKind::Issue) => {
            return Outcome::failed(
                op,
                format!("ERR_API: Failed to add comment to {noun} #{number}: {err:#}"),
            );
        }
        (Err(_), ItemKind::PullRequest) => false,
    };
    let closed = if closed_already {
        entity
    } else {
        let change = match state_reason {
            Some(reason) => json!({"state": "closed", "state_reason": reason}),
            None => json!({"state": "closed"}),
        };
        match github.request("PATCH", &path, Some(&change)) {
            Ok(closed) => closed,
            Err(err) => return Outcome::failed(op, format!("{err:#}")),
        }
    };
    Outcome::succeeded(
        op,
        match close.kind {
            ItemKind::Issue => json!({"success": true, "number": closed["number"],
                "url": closed["html_url"], "title": closed["title"],
                "alreadyClosed": closed_already}),
            ItemKind::PullRequest => json!({"success": true,
                "pull_request_number": closed["number"], "pull_request_url": closed["html_url"],
                "alreadyClosed": closed_already, "commentPosted": posted}),
        },
    )
}

/// The manifest entry of a success (`extractCreatedItemFromResult`).
fn manifest_entry(outcome: &Outcome, timestamp: &str) -> Option<Value> {
    if outcome.kind != Kind::Success
        && !(outcome.output == "document" && outcome.result["revision"].is_string())
    {
        return None;
    }
    created_item(outcome.output, &outcome.result, timestamp)
}

/// The manifest entry of what a handler of OUTPUT made, by its RESULT;
/// none for what it only buffered (`extractCreatedItemFromResult`).
fn created_item(output: &str, result: &Value, timestamp: &str) -> Option<Value> {
    if ["staged", "skipped", "deferred_manifest"]
        .iter()
        .any(|key| result[*key] == true)
    {
        return None;
    }
    let first = |keys: &[&str], present: fn(&Value) -> bool| {
        keys.iter()
            .map(|key| &result[*key])
            .find(|value| present(value))
            .cloned()
    };
    let set = |value: &Value| !value.is_null();
    let url = first(
        &[
            "url",
            "projectUrl",
            "html_url",
            "pull_request_url",
            "review_url",
            "issue_url",
        ],
        truthy,
    );
    let number = first(
        &[
            "number",
            "pull_request_number",
            "prNumber",
            "issue_number",
            "itemNumber",
        ],
        set,
    );
    let repo = first(&["repo", "_repo"], truthy);
    let id = first(
        &["id", "commentId", "comment_id", "review_id", "issue_id"],
        set,
    );
    let mut entry = Map::new();
    entry.insert("type".into(), json!(output));
    if let Some(url) = url {
        entry.insert("url".into(), url);
    }
    if let Some(number) = &number {
        entry.insert("number".into(), number.clone());
    }
    if let Some(repo) = &repo {
        entry.insert("repo".into(), repo.clone());
    }
    entry.insert("provider".into(), json!("github"));
    if let Some(id) = id {
        entry.insert("id".into(), id);
    }
    if repo.is_some() || number.is_some() {
        let mut target = Map::new();
        target.insert("provider".into(), json!("github"));
        if let Some(repo) = repo {
            target.insert("repository".into(), repo);
        }
        if let Some(number) = number {
            target.insert("number".into(), number);
        }
        if truthy(&result["contextType"]) {
            target.insert("kind".into(), result["contextType"].clone());
        }
        entry.insert("target".into(), Value::Object(target));
    }
    if result["labels"].is_array() {
        entry.insert("labels".into(), result["labels"].clone());
    } else if let Some(added) = result["labelsAdded"].as_array() {
        let labels: Vec<Value> = added.iter().map(|name| json!({"name": name})).collect();
        entry.insert("labels".into(), json!(labels));
    }
    if truthy(&result["temporaryId"]) {
        entry.insert("temporaryId".into(), result["temporaryId"].clone());
    }
    // An answer without a node ID gives none, rather than a null one.
    let mut metadata: Map<String, Value> = result["metadata"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, value)| !value.is_null())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if output == PUSH_TO_PULL_REQUEST_BRANCH && truthy(&result["commit_sha"]) {
        metadata.insert("commit_sha".into(), result["commit_sha"].clone());
    }
    if !metadata.is_empty() {
        entry.insert("metadata".into(), Value::Object(metadata));
    }
    for key in ["before_state", "after_state"] {
        if truthy(&result[key]) {
            entry.insert(key.into(), result[key].clone());
        }
    }
    for key in ["labelsAdded", "labelsSuggested", "labelsBefore"] {
        if result[key].is_array() {
            entry.insert(key.into(), result[key].clone());
        }
    }
    entry.insert("timestamp".into(), json!(timestamp));
    Some(Value::Object(entry))
}

/// What gh-aw's handler manager counts of OUTCOMES
/// (`computeSafeOutputsStatus`): applied, skipped, failed, and the status.
fn status(outcomes: &[Outcome]) -> (usize, usize, usize, &'static str) {
    let count = |kind| outcomes.iter().filter(|o| o.kind == kind).count();
    let (applied, skipped, failed) = (
        count(Kind::Success),
        count(Kind::Skipped),
        count(Kind::Failed),
    );
    let status = match (failed, applied + skipped, skipped) {
        (0, _, 0) => "success",
        (0, _, _) => "completed_with_skips",
        (_, 0, _) => "failure",
        _ => "partial_success",
    };
    (applied, skipped, failed, status)
}

/// The step's outputs, as gh-aw's handler manager sets them.
fn outputs(outcomes: &[Outcome]) -> Vec<(&'static str, String)> {
    let (applied, skipped, failed, status) = status(outcomes);
    let mut outputs = vec![
        ("processed_count", applied.to_string()),
        ("items_succeeded", applied.to_string()),
        ("items_applied", applied.to_string()),
        ("items_skipped", skipped.to_string()),
        ("items_warnings", "0".to_owned()),
        ("items_cancelled", "0".to_owned()),
        ("items_deferred", "0".to_owned()),
        ("items_failed", failed.to_string()),
        ("status", status.to_owned()),
    ];
    // The manager returns before these when it has nothing to publish.
    if outcomes.is_empty() {
        return outputs;
    }
    let pushes_failed: Vec<String> = outcomes
        .iter()
        .filter(|o| o.kind == Kind::Failed && CODE_PUSHES.contains(&o.output))
        .map(|o| format!("{}:{}", o.output, o.error.as_deref().unwrap_or_default()))
        .collect();
    outputs.extend([
        ("create_discussion_errors", String::new()),
        ("create_discussion_error_count", "0".to_owned()),
        ("code_push_failure_errors", pushes_failed.join("\n")),
        ("code_push_failure_count", pushes_failed.len().to_string()),
    ]);
    let first = |output: &str| {
        outcomes
            .iter()
            .find(|o| o.kind == Kind::Success && o.output == output)
            .map(|o| &o.result)
    };
    if let Some(pr) = first(CREATE_PULL_REQUEST) {
        if let Some(number) = pr["number"].as_u64() {
            outputs.push(("created_pr_number", number.to_string()));
        }
        if let Some(url) = pr["url"].as_str() {
            outputs.push(("created_pr_url", url.to_owned()));
        }
    }
    if let Some(comment) = first(ADD_COMMENT) {
        if let Some(id) = comment["commentId"].as_u64() {
            outputs.push(("comment_id", id.to_string()));
        }
        if let Some(url) = comment["url"].as_str() {
            outputs.push(("comment_url", url.to_owned()));
        }
    }
    if let Some(issue) = first(CREATE_ISSUE) {
        if let Some(number) = issue["number"].as_u64() {
            outputs.push(("created_issue_number", number.to_string()));
        }
        if let Some(url) = issue["url"].as_str() {
            outputs.push(("created_issue_url", url.to_owned()));
        }
    }
    if let Some(push) = first(PUSH_TO_PULL_REQUEST_BRANCH) {
        for (name, key) in [
            ("push_commit_sha", "commit_sha"),
            ("push_commit_url", "commit_url"),
        ] {
            if let Some(value) = push[key].as_str().filter(|value| !value.is_empty()) {
                outputs.push((name, value.to_owned()));
            }
        }
    }
    outputs
}

/// What a handler that pushed writes to the step summary before gh-aw's
/// handler manager writes its own, for OUTCOME on RUN.
fn summary_section(run: &Run, outcome: &Outcome) -> Option<String> {
    let result = &outcome.result;
    let text = |key: &str| result[key].as_str().unwrap_or_default();
    if outcome.kind != Kind::Success {
        return None;
    }
    match outcome.output {
        CREATE_PULL_REQUEST => Some(format!(
            "\n\n## Pull Request\n- **Pull Request**: [#{}]({})\n- **Branch**: `{}`\n- **Base Branch**: `{}`\n",
            result["number"],
            text("url"),
            text("branch_name"),
            text("base"),
        )),
        PUSH_TO_PULL_REQUEST_BRANCH => {
            let tree = format!(
                "{}/{}/tree/{}",
                run.server,
                text("head_repo"),
                text("branch_name")
            );
            Some(format!(
                "\n## Push to Branch\n- **Branch**: `{}`\n- **Commit**: [{}]({})\n- **URL**: [{tree}]({tree})\n",
                text("branch_name"),
                text("commit_sha").get(..7).unwrap_or_default(),
                text("commit_url"),
            ))
        }
        _ => None,
    }
}

/// `formatDisplayType`: `add_comment` as `Add Comment`.
fn display_type(output: &str) -> String {
    output
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(chars).collect()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `toSummarySafeErrorCode`.
fn summary_code(error: &str) -> &str {
    static CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&format!(r"^[{JS_SPACE}]*([A-Z][A-Z0-9_]*)[{JS_SPACE}]*:"))
            .expect("a valid pattern")
    });
    CODE_RE
        .captures(error)
        .and_then(|caps| caps.get(1))
        .map(|code| code.as_str())
        .filter(|code| SUMMARY_CODES.contains(code))
        .unwrap_or("UNCLASSIFIED")
}

/// The first of FIELDS of VALUE that is set, as `pickFirstField`.
fn first_field<'a>(value: &'a Value, fields: &[&str]) -> Option<&'a Value> {
    fields
        .iter()
        .map(|field| &value[*field])
        .find(|v| !v.is_null() && *v != &json!(""))
}

/// `formatTargetLine`.
fn target_line(run: &Run, result: &Value, item: &Value) -> String {
    const NUMBERS: &[&str] = &[
        "number",
        "issue_number",
        "pull_request_number",
        "discussion_number",
        "pr_number",
        "issueNumber",
        "sub_issue_number",
        "parent_issue_number",
        "milestone_number",
    ];
    const REPOS: &[&str] = &["repo", "repoSlug", "repository"];
    const URLS: &[&str] = &[
        "url",
        "html_url",
        "issue_url",
        "pull_request_url",
        "discussion_url",
        "comment_url",
        "reply_url",
        "review_url",
        "item_url",
        "commit_url",
        "check_run_url",
        "projectUrl",
        "autofixUrl",
        "artifactUrl",
        "run_url",
        "workflow_run_url",
    ];
    let target = if result["target"].is_object() {
        &result["target"]
    } else {
        &Value::Null
    };
    let text = |value: &Value| match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let number = first_field(target, NUMBERS)
        .or_else(|| first_field(result, NUMBERS))
        .or_else(|| first_field(item, NUMBERS))
        .map(text);
    let repo = first_field(target, REPOS)
        .or_else(|| first_field(result, REPOS))
        .or_else(|| first_field(item, &["repo", "target_repo", "repoSlug", "repository"]))
        .map(text);
    let fallback = repo.clone().unwrap_or_else(|| run.repository.clone());
    let url = first_field(target, URLS)
        .or_else(|| first_field(result, URLS))
        .or_else(|| first_field(item, URLS))
        .map(text);
    let entity = |repo: &str| number.as_ref().map(|number| format!("{repo}#{number}"));
    let (url, label) = match url {
        Some(url) => (Some(url), entity(repo.as_deref().unwrap_or_default())),
        None => {
            let url = number
                .as_deref()
                .filter(|n| REPO_RE.is_match(&fallback) && NUMBER_RE.is_match(n))
                .map(|n| format!("{}/{fallback}/issues/{n}", run.server));
            (url, entity(&fallback))
        }
    };
    let link = match url.filter(|url| url.starts_with("https://") || url.starts_with("http://")) {
        Some(url) => Some(format!("[{}]({url})", label.unwrap_or_else(|| url.clone()))),
        None => label,
    };
    link.map(|link| format!("**Target:** {link}\n\n"))
        .unwrap_or_default()
}

/// The step summary gh-aw's handler manager writes for OUTCOMES of ITEMS
/// (`writeSafeOutputSummaries`).
fn summary(run: &Run, outcomes: &[Outcome], items: &[Value]) -> String {
    if outcomes.is_empty() {
        return String::new();
    }
    let (applied, skipped, failed, status) = status(outcomes);
    let emoji = if failed > 0 {
        "❌"
    } else if skipped > 0 {
        "⚠️"
    } else {
        "✅"
    };
    let mut text = format!(
        "<details>\n<summary>{emoji} Safe Output Processing Summary ({applied} applied, \
         {skipped} skipped, {failed} failed)</summary>\n\n"
    );
    text += &format!("Processed {} safe-output message(s).\n\n", outcomes.len());
    text += &format!("Status: **{status}**\n\n");
    text += &format!(
        "Applied: **{applied}** · Skipped: **{skipped}** · Warnings: **0** · Failed: \
         **{failed}** · Cancelled: **0** · Deferred: **0**\n\n"
    );
    // `generateOutcomeOverview`: one row of each outcome, type and reason.
    let mut rows: Vec<(String, String, usize, String)> = Vec::new();
    for outcome in outcomes {
        let (status, reason) = match outcome.kind {
            Kind::Success => ("Success", String::new()),
            Kind::Skipped => (
                "Skipped",
                ["reason", "reasonCode", "errorCode"]
                    .iter()
                    .find_map(|key| outcome.result[key].as_str())
                    .unwrap_or_default()
                    .to_owned(),
            ),
            Kind::Failed => (
                "Failed",
                summary_code(outcome.error.as_deref().unwrap_or_default()).to_owned(),
            ),
        };
        let kind = display_type(outcome.output);
        match rows
            .iter_mut()
            .find(|row| row.0 == status && row.1 == kind && row.3 == reason)
        {
            Some(row) => row.2 += 1,
            None => rows.push((status.to_owned(), kind, 1, reason)),
        }
    }
    text += "| Outcome | Type | Count | Reason |\n|---|---|---:|---|\n";
    for (status, kind, count, reason) in rows {
        let reason = reason
            .replace('\\', "\\\\")
            .replace('|', "\\|")
            .replace("\r\n", "<br>")
            .replace('\n', "<br>");
        text += &format!("| {status} | {kind} | {count} | {reason} |\n");
    }
    text += "\n";
    for outcome in outcomes {
        let item = items.get(outcome.index).unwrap_or(&Value::Null);
        let kind = display_type(outcome.output);
        let (emoji, status) = match outcome.kind {
            Kind::Success => ("✅", "Success"),
            Kind::Skipped => ("⚠️", "Skipped"),
            Kind::Failed => ("❌", "Failed"),
        };
        text += &format!(
            "<details>\n<summary>{emoji} {kind} - {status} (Message {})</summary>\n\n### {kind}\n\n",
            outcome.index + 1
        );
        let result = &outcome.result;
        match outcome.kind {
            Kind::Success => {
                text += &target_line(run, result, item);
                if let Some(temporary) = result["temporaryId"].as_str() {
                    text += &format!("**Temporary ID:** `{temporary}`\n\n");
                }
                let title = [&result["title"], &item["title"]]
                    .into_iter()
                    .find_map(|title| title.as_str().filter(|title| !title.is_empty()));
                if let Some(title) = title {
                    text += &format!("**Title:** {title}\n\n");
                }
                // `formatLabels` of the first that is set: an empty list
                // is, and names none.
                let labels = [&result["labelsAdded"], &result["labels"], &item["labels"]]
                    .into_iter()
                    .find(|labels| truthy(labels))
                    .map(|labels| names_of(labels, "name"))
                    .unwrap_or_default();
                if !labels.is_empty() {
                    text += &format!("**Labels:** {}\n\n", labels.join(", "));
                }
            }
            Kind::Skipped | Kind::Failed => {
                text += &target_line(run, result, item);
                let code = result["reasonCode"]
                    .as_str()
                    .or_else(|| result["errorCode"].as_str());
                let reason = result["reason"].as_str();
                if let Some(code) = code {
                    text += &format!("**Reason Code:** `{code}`\n\n");
                }
                if let Some(reason) = reason {
                    text += &format!("**Reason:** {reason}\n\n");
                }
                if let (None, None, Some(error)) = (code, reason, &outcome.error) {
                    text += &format!(
                        "**Error:** `{}` (see the job logs for details)\n\n",
                        summary_code(error)
                    );
                }
            }
        }
        text += "</details>\n\n";
    }
    text + "</details>\n\n"
}

/// gh-aw's safe-output-errors.json for the failures of OUTCOMES, if any.
fn error_report(
    run: &Run,
    workflow: &str,
    outcomes: &[Outcome],
    timestamp: &str,
) -> Option<String> {
    let failures: Vec<&Outcome> = outcomes.iter().filter(|o| o.kind == Kind::Failed).collect();
    if failures.is_empty() {
        return None;
    }
    let lines: Vec<String> = failures
        .iter()
        .map(|o| {
            format!(
                "  - {}: {}",
                o.output,
                o.error.as_deref().unwrap_or_default()
            )
        })
        .collect();
    let mut report = Map::new();
    report.insert("timestamp".into(), json!(timestamp));
    report.insert("status".into(), json!("failure"));
    report.insert("errorCode".into(), json!("E099"));
    report.insert(
        "message".into(),
        json!(format!(
            "{} safe output(s) failed:\n{}",
            failures.len(),
            lines.join("\n")
        )),
    );
    if !workflow.is_empty() {
        report.insert("workflow".into(), json!(workflow));
    }
    report.insert("run_id".into(), json!(run.run_id));
    report.insert(
        "failures".into(),
        failures
            .iter()
            .map(|o| json!({"type": o.output, "error": o.error}))
            .collect(),
    );
    serde_json::to_string_pretty(&Value::Object(report))
        .ok()
        .map(|text| text + "\n")
}

/// REST, gh-aw's requests, with the warning its handler manager puts
/// first in each add_comment after the create_pull_request that FAILED.
/// Each of them comes after it: [`split`] refuses a routed request after
/// one of gh-aw's.
fn warn_of_failure(rest: &[Value], failed: &Outcome) -> Vec<Value> {
    let note = format!(
        "\n\n---\n> [!WARNING]\n> The `{}` operation failed: {}. The code changes were not applied.\n\n",
        failed.output,
        failed.error.as_deref().unwrap_or_default()
    );
    rest.iter()
        .cloned()
        .map(|mut item| {
            if let Some(map) = item.as_object_mut()
                && check::item_type(map) == ADD_COMMENT
            {
                let body = map.get("body").and_then(Value::as_str).unwrap_or_default();
                map.insert("body".into(), Value::String(note.clone() + body));
            }
            item
        })
        .collect()
}

/// What apply's earlier steps leave [`apply`]: the requests, the
/// handlers' configuration, check's upload and its policy.
#[derive(Clone, Copy)]
pub struct Checked<'a> {
    pub items: &'a [Value],
    pub handlers: &'a Map<String, Value>,
    pub upload: Upload<'a>,
    pub policy: &'a Policy,
}

/// What [`apply`] writes besides the forge: where, and the time it stamps.
pub struct Records<'a> {
    pub remainder: &'a Path,
    pub made: &'a Path,
    pub errors: &'a Path,
    /// `$GITHUB_OUTPUT` and `$GITHUB_STEP_SUMMARY`, where set.
    pub output: Option<&'a Path>,
    pub summary: Option<&'a Path>,
    /// `GITHUB_WORKFLOW`, which the error report names.
    pub workflow: &'a str,
}

/// Splits, plans and publishes the routed requests of ITEMS, writing the
/// records; returns whether every one was published or left as gh-aw's
/// handler leaves it. LOG is given each line for the step's log.
pub fn apply(
    checked: &Checked<'_>,
    run: &Run,
    publisher: &GithubPublisher,
    records: &Records<'_>,
    log: &mut dyn FnMut(&Annotation),
) -> Result<bool> {
    let Checked {
        items,
        handlers,
        upload,
        policy,
    } = *checked;
    let refuse = |errors: Vec<String>| -> Result<bool> {
        bail!(
            "agentic-job publish refused the run, and nothing was published: {}",
            errors.join("; ")
        )
    };
    if let Some(advisory) = &policy.advisory {
        policy.validate()?;
        let report = read_report(&upload)?;
        ensure!(
            report.ok && report.errors.is_empty(),
            "advisory requires a successful check report"
        );
        let accepted = report
            .items
            .into_iter()
            .map(Value::Object)
            .collect::<Vec<_>>();
        advisory.check_items(&accepted, crate::advisory::MAX_PROSE_BYTES, false)?;
        // The applied guard can remove an already-posted request. It cannot
        // expand this batch, reroute it, or add a review/status operation.
        advisory.check_items(items, crate::advisory::MAX_FINAL_BYTES, true)?;
        let config = &handlers[ADD_COMMENT];
        ensure!(
            config["target-repo"] == advisory.repo
                && config["target"]
                    .as_str()
                    .and_then(|value| value.parse::<u64>().ok())
                    == Some(advisory.pull),
            "advisory handler destination differs from policy"
        );
    }
    let Split { ours, rest } = match split(items, &policy.native_handlers) {
        Ok(split) => split,
        Err(errors) => return refuse(errors),
    };
    if items.iter().any(|item| item["type"] == "document") {
        ensure!(
            items
                .iter()
                .filter(|item| item["type"] == "document")
                .count()
                == 1
                && items.iter().all(|item| matches!(
                    item["type"].as_str(),
                    Some("document" | "noop" | "missing_tool" | "missing_data")
                )),
            "document runs permit one document and no other writing outputs"
        );
    }
    let ops = match plan(ours, handlers, &upload, policy, run) {
        Ok(ops) => ops,
        Err(errors) => return refuse(errors),
    };
    // A refusal too, so before the remainder hands gh-aw the rest; only
    // the routed comments, pull requests, issues and review comments keep
    // mentions, and so read the event's people.
    let defaults = if ops.iter().any(|op| {
        matches!(
            op,
            Op::Comment { .. }
                | Op::PullRequest { .. }
                | Op::Issue { .. }
                | Op::ReviewComment { .. }
        )
    }) {
        run.default_mentions()
    } else {
        Ok(Vec::new())
    };
    let defaults = match defaults {
        Ok(defaults) => defaults,
        Err(err) => return refuse(vec![format!("{err:#}")]),
    };
    // Before anything is published: gh-aw's handlers take only the rest.
    let remainder = json!({"items": rest, "errors": []}).to_string();
    std::fs::write(records.remainder, remainder)
        .with_context(|| format!("writing {}", records.remainder.display()))?;
    let Published { outcomes, reviewed } = publish(&ops, publisher, run, &defaults, log)?;
    if let Some(failed) = outcomes
        .iter()
        .find(|o| o.kind == Kind::Failed && CODE_PUSHES.contains(&o.output))
    {
        let remainder = json!({"items": warn_of_failure(&rest, failed), "errors": []}).to_string();
        std::fs::write(records.remainder, remainder)
            .with_context(|| format!("writing {}", records.remainder.display()))?;
    }
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut made = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(records.made)
        .with_context(|| format!("opening {}", records.made.display()))?;
    let entries = outcomes
        .iter()
        .filter_map(|o| manifest_entry(o, &timestamp))
        .chain(
            reviewed
                .iter()
                .filter_map(|(output, result)| created_item(output, result, &timestamp)),
        );
    for entry in entries {
        writeln!(made, "{entry}").with_context(|| format!("writing {}", records.made.display()))?;
    }
    if let Some(report) = error_report(run, records.workflow, &outcomes, &timestamp) {
        std::fs::write(records.errors, report)
            .with_context(|| format!("writing {}", records.errors.display()))?;
    }
    if let Some(path) = records.output {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        for (name, value) in outputs(&outcomes) {
            // A failure's words may take more than one line, which the
            // runner reads up to a delimiter they cannot hold.
            let line = if value.contains('\n') {
                let delimiter = format!("ghadelimiter_{}", temporary_id());
                format!("{name}<<{delimiter}\n{value}\n{delimiter}")
            } else {
                format!("{name}={value}")
            };
            writeln!(file, "{line}").with_context(|| format!("writing {}", path.display()))?;
        }
    }
    if let Some(path) = records.summary {
        let mut text: String = outcomes
            .iter()
            .filter_map(|outcome| summary_section(run, outcome))
            .collect();
        text += &summary(run, &outcomes, items);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        file.write_all(text.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(outcomes.iter().all(|o| o.kind != Kind::Failed))
}

/// Refuses SERVER, where git finds the repositories, unless it is https:
/// the token goes to it. A file URL is a test's server of bare
/// repositories.
pub fn check_server(server: &str) -> Result<()> {
    ensure!(
        server.starts_with("https://") || server.starts_with("file:///"),
        "--server {server:?} is not an https address"
    );
    Ok(())
}

/// The [`GithubPublisher`] for CHECKED's run with GITHUB, whose git is at
/// SERVER: comments go to the add_comment handler's repository or the
/// run's, and pull requests to the create_pull_request handler's or the
/// policy's.
pub fn publisher(
    github: Github,
    server: &str,
    checked: &Checked<'_>,
    run: &Run,
) -> Result<GithubPublisher> {
    check_server(server)?;
    let target_repo = |output: &str| {
        checked
            .handlers
            .get(output)
            .and_then(|config| config["target-repo"].as_str())
    };
    Ok(GithubPublisher {
        github: github.with_api_version(API_VERSION),
        git: server.trim_end_matches('/').to_owned(),
        item_repo: target_repo(ADD_COMMENT)
            .unwrap_or(&run.repository)
            .to_owned(),
        repo: target_repo(CREATE_PULL_REQUEST)
            .unwrap_or(&checked.policy.repo)
            .to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use super::super::REPORT_FILE;
    use super::super::tests::upload;
    use super::*;
    use crate::apply::testing::{PROVENANCE, Request, TOKEN, serve, sh};
    use crate::check::BASE_COMMIT_HEADER;
    use crate::contract::NATIVE_OUTPUTS;

    const SERVER: &str = "https://github.com";
    const REPO: &str = "owner/repo";
    const FORK: &str = "agentic-bot/repo";

    #[test]
    fn document_native_route_retains_revision_even_when_comment_fails() {
        for comment_ok in [true, false] {
            let mut routes = BTreeMap::from([
                (
                    "GET /user".into(),
                    (200, json!({"id": 7, "login": "example-bot"})),
                ),
                (
                    "POST /gists".into(),
                    (
                        201,
                        json!({"id": "abc123", "owner": {"id": 7}, "public": false, "history": [{"version": "a".repeat(40)}]}),
                    ),
                ),
            ]);
            if comment_ok {
                routes.insert(
                    "POST /repos/owner/repo/issues/7/comments".into(),
                    (201, json!({"id": 10})),
                );
            }
            let (github, requests) = crate::apply::testing::forge(routes);
            let publisher = GithubPublisher {
                github,
                git: String::new(),
                item_repo: REPO.into(),
                repo: REPO.into(),
            };
            let dir = tempfile::tempdir().unwrap();
            let path = |name: &str| dir.path().join(name);
            let mut policy = crate::check::fixtures::policy();
            policy.safe_outputs.create_pull_request = None;
            policy.safe_outputs.others.insert(
                "document".into(),
                crate::contract::OutputLimit {
                    max: 1,
                    ..Default::default()
                },
            );
            policy.native_handlers = vec!["document".into()];
            policy.validate().unwrap();
            let items = [
                json!({"type": "document", "title": "Findings", "files": {"findings.md": "Evidence."}, "summary": ["First.", "Second.", "Third."]}),
            ];
            let handlers = json!({"document": {"max": 1, "target-repo": REPO, "target": "7"}});
            let ok = apply(
                &Checked {
                    items: &items,
                    handlers: handlers.as_object().unwrap(),
                    upload: upload(dir.path()),
                    policy: &policy,
                },
                &run(1, "http://127.0.0.1:1"),
                &publisher,
                &Records {
                    remainder: &path("remainder.json"),
                    made: &path("made.jsonl"),
                    errors: &path("errors.json"),
                    output: None,
                    summary: None,
                    workflow: "agentic-job",
                },
                &mut |_| {},
            )
            .unwrap();
            assert_eq!(ok, comment_ok);
            let made = read_json(&path("made.jsonl"));
            assert_eq!(made["type"], "document");
            assert_eq!(made["url"], "https://gist.github.com/example-bot/abc123");
            assert_eq!(made["metadata"]["revision"], "a".repeat(40));
            assert_eq!(read_json(&path("remainder.json"))["items"], json!([]));
            assert_eq!(requests.try_iter().count(), 3);
        }
    }

    /// What gh-aw's handlers sent, as agentic-job's publication tests
    /// record it with the pinned handlers.
    fn corpus() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../agentic-job/tests/data/publication")
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// The run as publication.rs gives it to gh-aw's handlers.
    fn run(attempt: u64, api: &str) -> Run {
        let domains = crate::link_domains().join(",");
        let attempt = attempt.to_string();
        let vars: BTreeMap<&str, &str> = [
            ("GITHUB_SERVER_URL", SERVER),
            ("GITHUB_API_URL", api),
            ("GITHUB_REPOSITORY", REPO),
            ("GITHUB_REPOSITORY_ID", "77"),
            ("GITHUB_RUN_ID", "4242"),
            ("GITHUB_RUN_ATTEMPT", attempt.as_str()),
            ("GITHUB_JOB", "apply"),
            ("GITHUB_EVENT_NAME", "workflow_dispatch"),
            ("GITHUB_ACTOR", "owner"),
            ("GH_AW_JOB_CHECK_RUN_ID", "9001"),
            ("GH_AW_WORKFLOW_ID", "agentic-job"),
            ("GH_AW_WORKFLOW_NAME", "agentic-job"),
            ("GH_AW_SAFE_OUTPUTS_URLS", URL_POLICY),
            ("GH_AW_ALLOWED_DOMAINS", domains.as_str()),
        ]
        .into_iter()
        .collect();
        Run::read(&|name| vars.get(name).map(|value| (*value).to_owned())).unwrap()
    }

    fn policy() -> Policy {
        let mut policy = crate::check::fixtures::policy();
        policy.native_handlers = NATIVE_OUTPUTS
            .iter()
            .map(|output| (*output).to_owned())
            .collect();
        policy
    }

    /// What the loopback forge was sent, in order.
    type Sent = Arc<Mutex<Vec<Request>>>;

    /// A forge holding SEED, which makes comments, issues, pull requests
    /// and reviews, adds and removes labels and changes items as
    /// publication.rs's does (IDs from 1001), and answers FAULTS' requests
    /// with their status once, and their `answer` or else a message.
    fn forge(seed: &Value, faults: &[Value]) -> (Github, Sent) {
        let mut seed = seed.as_object().cloned().unwrap_or_default();
        let faults: Vec<(String, u16, String)> = faults
            .iter()
            .map(|fault| {
                let answer = match &fault["answer"] {
                    Value::Null => json!({"message": "injected failure"}),
                    answer => answer.clone(),
                };
                (
                    format!(
                        "{} {}",
                        fault["method"].as_str().unwrap(),
                        fault["path"].as_str().unwrap()
                    ),
                    u16::try_from(fault["status"].as_u64().unwrap()).unwrap(),
                    answer.to_string(),
                )
            })
            .collect();
        let sent: Sent = Arc::default();
        let log = Arc::clone(&sent);
        let mut next_id = 1000;
        let mut faults = faults;
        let (server, _requests) = serve(usize::MAX, move |request: &Request| {
            log.lock().unwrap().push(Request {
                line: request.line.clone(),
                authorization: request.authorization.clone(),
                api_version: request.api_version.clone(),
                body: request.body.clone(),
            });
            let asked = request.line.trim_end_matches(" HTTP/1.1");
            let (method, path) = asked.split_once(' ').unwrap();
            if let Some(at) = faults.iter().position(|(fault, ..)| fault == asked) {
                let (_, status, answer) = faults.remove(at);
                return (status, answer);
            }
            let comments = Regex::new(r"^/repos/([^/]+/[^/]+)/issues/(\d+)/comments$").unwrap();
            let labels = Regex::new(r"^(/repos/[^/]+/[^/]+/issues/\d+)/labels(?:/(.+))?$").unwrap();
            let not_found = (404, json!({"message": "Not Found"}).to_string());
            if let Some(caps) = labels.captures(path) {
                let Some(issue) = seed.get_mut(&caps[1]) else {
                    return not_found;
                };
                let held = issue["labels"].as_array_mut().unwrap();
                match (method, caps.get(2)) {
                    ("POST", None) => {
                        for name in request.body["labels"].as_array().unwrap() {
                            if !held.iter().any(|label| &label["name"] == name) {
                                held.push(json!({"name": name}));
                            }
                        }
                    }
                    ("DELETE", Some(name)) => {
                        let name = name.as_str().replace("%20", " ");
                        let before = held.len();
                        held.retain(|label| label["name"] != name.as_str());
                        if held.len() == before {
                            return not_found;
                        }
                    }
                    _ => return not_found,
                }
                return (200, Value::Array(held.clone()).to_string());
            }
            // A list is the seed's, or else empty, whatever page is asked.
            let listed = path.split('?').next().unwrap();
            match method {
                "GET" => match seed.get(path).or_else(|| seed.get(listed)) {
                    Some(value) => (200, value.to_string()),
                    None if ["/files", "/reviews", "/comments"]
                        .iter()
                        .any(|list| listed.ends_with(list)) =>
                    {
                        (200, "[]".to_owned())
                    }
                    None => (404, json!({"message": "Not Found"}).to_string()),
                },
                "POST" if path.ends_with("/reviews") => {
                    next_id += 1;
                    let id = next_id;
                    let web = format!("{SERVER}/{REPO}/pull/7");
                    let mut comments = vec![];
                    for comment in request.body["comments"].as_array().into_iter().flatten() {
                        next_id += 1;
                        let mut comment = comment.clone();
                        comment["id"] = json!(next_id);
                        comment["html_url"] = json!(format!("{web}#discussion_r{next_id}"));
                        comments.push(comment);
                    }
                    let review = json!({"id": id, "state": "COMMENTED", "body": request.body["body"],
                        "commit_id": request.body["commit_id"],
                        "user": {"login": "agentic-bot", "type": "User"},
                        "html_url": format!("{web}#pullrequestreview-{id}")});
                    seed.insert(format!("{path}/{id}/comments"), json!(comments));
                    seed.entry(path.to_owned())
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .unwrap()
                        .push(review.clone());
                    (200, review.to_string())
                }
                "POST" if comments.is_match(path) => {
                    let caps = comments.captures(path).unwrap();
                    next_id += 1;
                    let comment = json!({
                        "id": next_id,
                        "node_id": format!("IC_{next_id}"),
                        "body": request.body["body"],
                        "user": {"login": "agentic-bot", "type": "User"},
                        "html_url": format!("{SERVER}/{}/issues/{}#issuecomment-{next_id}", &caps[1], &caps[2]),
                    });
                    (201, comment.to_string())
                }
                "POST" if path == format!("/repos/{REPO}/pulls") => {
                    next_id += 1;
                    let pull = json!({
                        "id": next_id,
                        "node_id": format!("N_{next_id}"),
                        "number": 1,
                        "html_url": format!("{SERVER}/{REPO}/pull/1"),
                    });
                    (201, pull.to_string())
                }
                "POST" if path == format!("/repos/{REPO}/issues") => {
                    next_id += 1;
                    let numbered =
                        Regex::new(r"^/repos/[^/]+/[^/]+/(?:issues|pulls)/(\d+)$").unwrap();
                    let number = seed
                        .keys()
                        .filter_map(|key| numbered.captures(key))
                        .map(|caps| caps[1].parse::<u64>().unwrap())
                        .max()
                        .unwrap_or(0)
                        + 1;
                    let issue = json!({
                        "id": next_id,
                        "node_id": format!("N_{next_id}"),
                        "number": number,
                        "title": request.body["title"],
                        "body": request.body["body"],
                        "html_url": format!("{SERVER}/{REPO}/issues/{number}"),
                    });
                    seed.insert(format!("/repos/{REPO}/issues/{number}"), issue.clone());
                    (201, issue.to_string())
                }
                // An issue's node ID, and linking a sub-issue to its parent.
                "POST" if path == "/graphql" => {
                    let variables = &request.body["variables"];
                    let query = request.body["query"].as_str().unwrap();
                    let data = if query.contains("issue(number: $issueNumber)") {
                        let issue = format!(
                            "/repos/{}/{}/issues/{}",
                            variables["owner"].as_str().unwrap(),
                            variables["repo"].as_str().unwrap(),
                            variables["issueNumber"]
                        );
                        match seed.get(&issue) {
                            Some(issue) => {
                                json!({"repository": {"issue": {"id": issue["node_id"]}}})
                            }
                            None => return not_found,
                        }
                    } else if query.contains("addSubIssue(") {
                        json!({"addSubIssue": {"issue": {"id": variables["parentId"]},
                            "subIssue": {"id": variables["subIssueId"]}}})
                    } else {
                        return not_found;
                    };
                    (200, json!({"data": data}).to_string())
                }
                "PATCH" => match seed.get_mut(path).and_then(Value::as_object_mut) {
                    Some(item) => {
                        for (key, value) in request.body.as_object().unwrap() {
                            item.insert(key.clone(), value.clone());
                        }
                        (200, Value::Object(item.clone()).to_string())
                    }
                    None => not_found,
                },
                _ => not_found,
            }
        });
        let mut github = Github::new(&server, TOKEN.to_owned(), PROVENANCE)
            .unwrap()
            .with_api_version(API_VERSION);
        github.retry_wait = std::time::Duration::ZERO;
        (github, sent)
    }

    /// Git in DIR as publication.rs runs it: no configuration of the
    /// machine's, and a fixed date, so that each commit is the corpus's.
    fn git(dir: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    /// The repositories publication.rs makes for a case with GIT, as it
    /// makes them: the output repository and the fork under ROOT, each
    /// with the base commit on main and the case's branches, and the
    /// case's patch from its base, with check's base header and report in
    /// CHECKED. Returns what `{head:BRANCH}` stands for.
    fn repositories(git: &Value, root: &Path, checked: &Path) -> Vec<(String, String)> {
        let seed = root.join("seed");
        std::fs::create_dir_all(&seed).unwrap();
        self::git(&seed, &["init", "-q", "--initial-branch=main"]);
        let commit = |change: &Value| {
            for (name, content) in change["files"].as_object().unwrap() {
                let file = seed.join(name);
                std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                std::fs::write(file, content.as_str().unwrap()).unwrap();
            }
            self::git(&seed, &["add", "--all"]);
            self::git(
                &seed,
                &[
                    "-c",
                    "user.name=Agent",
                    "-c",
                    "user.email=agent@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    change["message"].as_str().unwrap(),
                ],
            );
        };
        for (name, content) in git["files"].as_object().unwrap() {
            let file = seed.join(name);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, content.as_str().unwrap()).unwrap();
        }
        commit(&json!({"message": "Base", "files": {}}));
        for (branch, change) in git["branches"].as_object().into_iter().flatten() {
            self::git(&seed, &["checkout", "-q", "-b", branch, "main"]);
            commit(change);
            self::git(&seed, &["checkout", "-q", "main"]);
        }
        for repo in [REPO, FORK] {
            let bare = root.join(format!("{repo}.git"));
            std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
            self::git(
                root,
                &[
                    "clone",
                    "-q",
                    "--bare",
                    seed.to_str().unwrap(),
                    bare.to_str().unwrap(),
                ],
            );
        }
        let heads: Vec<(String, String)> = self::git(
            &seed,
            &["for-each-ref", "--format=%(refname:short)", "refs/heads"],
        )
        .lines()
        .map(|name| {
            (
                format!("{{head:{name}}}"),
                self::git(&seed, &["rev-parse", name]),
            )
        })
        .collect();
        let from = git["patch"]["base"].as_str().unwrap_or("main");
        let base = self::git(&seed, &["rev-parse", from]);
        self::git(&seed, &["checkout", "-q", "-b", "agent", from]);
        commit(&git["patch"]);
        let patch = self::git(
            &seed,
            &["format-patch", "--stdout", &format!("{from}..agent")],
        ) + "\n";
        let (from, rest) = patch.split_once('\n').unwrap();
        let patch = format!("{from}\n{BASE_COMMIT_HEADER}: {base}\n{rest}");
        let branch = git["patch"]["branch"].as_str().unwrap();
        let name = check::patch_file_name(branch);
        std::fs::write(checked.join(&name), &patch).unwrap();
        let files: Vec<&String> = git["patch"]["files"].as_object().unwrap().keys().collect();
        let report = json!({"ok": true, "errors": [], "items": [], "patch": {
            "file": name, "bytes": patch.len(), "base_commit": base, "files": files}});
        std::fs::write(checked.join(REPORT_FILE), report.to_string()).unwrap();
        heads
    }

    /// What was pushed to the fork's BRANCH beyond SINCE, as
    /// publication.rs records it.
    fn pushed(root: &Path, branch: &str, since: &str) -> Value {
        let bare = root.join(format!("{FORK}.git"));
        let log = sh(
            &bare,
            &[
                "log",
                "--format=%H",
                "--reverse",
                &format!("{since}..{branch}"),
            ],
        );
        log.lines()
            .map(|commit| {
                let show = |format: &str| {
                    sh(
                        &bare,
                        &["show", "-s", &format!("--format={format}"), commit],
                    )
                };
                let files = sh(
                    &bare,
                    &["diff-tree", "--no-commit-id", "--name-only", "-r", commit],
                );
                json!({
                    "author": show("%an <%ae>"),
                    "committer": show("%cn <%ce>"),
                    "message": show("%B"),
                    "files": files.lines().collect::<Vec<_>>(),
                })
            })
            .collect()
    }

    /// TEXT with what differs from one run to the next as the corpus
    /// writes it.
    fn normalized(text: &str) -> String {
        let time = Regex::new(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z").unwrap();
        let temporary = Regex::new(r"\baw_[A-Za-z0-9]{8}\b").unwrap();
        let text = time.replace_all(text, "{time}");
        temporary.replace_all(&text, "{temporary_id}").into_owned()
    }

    /// A request as the corpus records one: its method, path, body and
    /// the order of the body's keys.
    fn recorded(method: &str, path: &str, body: &Value) -> Value {
        let mut entry = json!({"method": method, "path": path});
        if !body.is_null() {
            entry["body"] = body.clone();
            entry["keys"] = json!(body.as_object().map(|body| body.keys().collect::<Vec<_>>()));
        }
        entry
    }

    /// Each corpus case of the routed types, published here against the
    /// requests gh-aw's handlers took after the recorded guard: the same
    /// writes, byte for byte and key for key, no read gh-aw did not make,
    /// the same pushed commit, and the same records of it all.
    #[test]
    fn publishes_as_the_corpus_records() {
        let cases: Vec<Value> =
            serde_json::from_value(read_json(&corpus().join("cases.json"))).unwrap();
        let mut compared = 0;
        for case in &cases {
            let name = case["name"].as_str().unwrap();
            // A case routing only some of them (`native`) is gh-aw's in
            // part: tests/publication.rs runs both steps.
            let routed = case["native"].is_null()
                && case["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|item| NATIVE_OUTPUTS.contains(&item["type"].as_str().unwrap()));
            if !routed {
                continue;
            }
            compared += 1;
            let golden = read_json(&corpus().join(format!("{name}.json")));
            let root = tempfile::tempdir().unwrap();
            let checked = root.path().join("checked");
            std::fs::create_dir_all(&checked).unwrap();
            let mut text = case.to_string();
            if !case["git"].is_null() {
                for (placeholder, value) in repositories(&case["git"], root.path(), &checked) {
                    text = text.replace(&placeholder, &value);
                }
            }
            let case: Value = serde_json::from_str(&text).unwrap();
            let (github, sent) = forge(
                &case["forge"],
                case["faults"].as_array().map_or(&[], Vec::as_slice),
            );
            let publisher = GithubPublisher {
                github,
                git: root.path().display().to_string(),
                item_repo: REPO.into(),
                repo: REPO.into(),
            };
            for (at, attempt) in golden["attempts"].as_array().unwrap().iter().enumerate() {
                let what = format!("{name}, attempt {}", at + 1);
                // A guard that refused the run left neither step anything.
                if attempt["guard"]["exit"] != 0 {
                    continue;
                }
                let api = publisher.github.api_url().to_owned();
                let mut run = run(at as u64 + 1, &api);
                if let Some(event) = case.get("event") {
                    run.event = event.clone();
                    run.event_name = case["event_name"].as_str().unwrap().to_owned();
                }
                let records_dir = tempfile::tempdir().unwrap();
                let path = |file: &str| records_dir.path().join(file);
                std::fs::write(path("output"), "").unwrap();
                let records = Records {
                    remainder: &path("remainder.json"),
                    made: &path("made.jsonl"),
                    errors: &path("errors.json"),
                    output: Some(&path("output")),
                    summary: Some(&path("summary")),
                    workflow: "agentic-job",
                };
                let items = attempt["guard"]["items"].as_array().unwrap();
                let handlers = attempt["handler_config"].as_object().unwrap();
                // What the guard changed, such as an issue an earlier
                // attempt left open, as it changed it.
                for write in attempt["requests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|request| request["step"] == "guard" && request["method"] != "GET")
                {
                    let (method, path) = (
                        write["method"].as_str().unwrap(),
                        write["path"].as_str().unwrap(),
                    );
                    let body = Some(&write["body"]).filter(|body| !body.is_null());
                    publisher.github.request(method, path, body).unwrap();
                }
                sent.lock().unwrap().clear();
                let policy = case_policy(&case);
                let inputs = Checked {
                    items,
                    handlers,
                    upload: upload(&checked),
                    policy: &policy,
                };
                let ok = apply(&inputs, &run, &publisher, &records, &mut |_| {})
                    .unwrap_or_else(|err| panic!("{what}: {err:#}"));
                let apply_step = &attempt["apply"];
                assert_eq!(
                    i64::from(!ok),
                    apply_step["exit"].as_i64().unwrap(),
                    "{what}: exit"
                );

                let ours: Vec<(String, String, Value, String)> = sent
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|request| {
                        let (method, rest) = request.line.split_once(' ').unwrap();
                        let path = rest.trim_end_matches(" HTTP/1.1").to_owned();
                        (
                            method.to_owned(),
                            path,
                            request.body.clone(),
                            request.api_version.clone(),
                        )
                    })
                    .collect();
                let theirs: Vec<&Value> = attempt["requests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|request| request["step"] == "apply")
                    .collect();
                let writes = |requests: Vec<Value>| -> Vec<String> {
                    requests.iter().map(Value::to_string).collect()
                };
                assert_eq!(
                    writes(
                        ours.iter()
                            .filter(|(method, ..)| method != "GET")
                            .map(|(method, path, body, _)| recorded(method, path, body))
                            .collect()
                    ),
                    writes(
                        theirs
                            .iter()
                            .filter(|request| request["method"] != "GET")
                            .map(|request| recorded(
                                request["method"].as_str().unwrap(),
                                request["path"].as_str().unwrap(),
                                &request["body"]
                            ))
                            .collect()
                    ),
                    "{what}: writes"
                );
                for (method, path, _, version) in &ours {
                    assert_eq!(version, API_VERSION, "{what}: {method} {path}");
                    assert!(
                        theirs
                            .iter()
                            .any(|request| request["method"] == method.as_str()
                                && request["path"] == path.as_str()),
                        "{what}: {method} {path}, which gh-aw's handlers did not ask"
                    );
                }

                let made = std::fs::read_to_string(path("made.jsonl")).unwrap_or_default();
                let made: Vec<Value> = made
                    .lines()
                    .map(|line| serde_json::from_str(&normalized(line)).unwrap())
                    .collect();
                assert_eq!(
                    Value::Array(made).to_string(),
                    apply_step["made"].to_string(),
                    "{what}: made"
                );
                let mut outputs: BTreeMap<String, String> = std::fs::read_to_string(path("output"))
                    .unwrap()
                    .lines()
                    .map(|line| {
                        let (name, value) = line.split_once('=').unwrap();
                        (name.to_owned(), value.to_owned())
                    })
                    .collect();
                outputs.insert("result".into(), String::new());
                assert_eq!(
                    serde_json::to_value(&outputs).unwrap(),
                    apply_step["outputs"],
                    "{what}: outputs"
                );
                assert_eq!(
                    normalized(&std::fs::read_to_string(path("summary")).unwrap_or_default()),
                    apply_step["summary"].as_str().unwrap(),
                    "{what}: summary"
                );
                let errors = std::fs::read_to_string(path("errors.json"))
                    .map_or(Value::Null, |text| {
                        serde_json::from_str(&normalized(&text)).unwrap()
                    });
                assert_eq!(
                    errors.to_string(),
                    apply_step["errors"].to_string(),
                    "{what}: errors"
                );
                // gh-aw's step is left nothing of a routed type.
                let remainder = read_json(&path("remainder.json"));
                assert_eq!(remainder["items"], json!([]), "{what}: remainder");
            }
            if let Some(branch) = case["git"]["patch"]["branch"].as_str() {
                let want = &golden["pushed"][format!("{FORK}:refs/heads/{branch}")];
                // A push's commit goes on the branch as it was.
                let since = match case["git"]["branches"][branch].is_null() {
                    true => "main".to_owned(),
                    false => sh(&root.path().join("seed"), &["rev-parse", branch]),
                };
                assert_eq!(&pushed(root.path(), branch, &since), want, "{name}: pushed");
            }
        }
        assert_eq!(compared, 31, "the corpus's cases of the routed types");
    }

    /// The policy check's upload holds for CASE, as publication.rs writes
    /// it: a push's pull request branch is its base.
    fn case_policy(case: &Value) -> Policy {
        let mut policy = policy();
        if let Some(push) = case["config"].get(PUSH_TO_PULL_REQUEST_BRANCH) {
            policy.repo = REPO.to_owned();
            policy.base = case["env"]["BASE"].as_str().unwrap().to_owned();
            policy.safe_outputs.push_to_pull_request_branch =
                Some(serde_json::from_value(push.clone()).unwrap());
        }
        policy
    }

    /// apply.yml's hook and `stripExecutionProvenance`, against what the
    /// pinned code gave for each.
    #[test]
    fn markers() {
        let applied = "agentic-job-applied: 1/2/0123456789abcdef";
        let hidden = format!("<!-- {applied} -->");
        for (body, want) in [
            (format!("x\n{applied}\ny"), format!("x\n{hidden}\ny")),
            (format!("{applied}\r\nend"), format!("{hidden}\r\nend")),
            (
                format!("{applied}\nagentic-job-applied: no"),
                format!("{applied}\nagentic-job-applied: no"),
            ),
            (
                format!("{applied} agentic-job-applied: 3/4/0123456789abcdef"),
                format!("{applied} agentic-job-applied: 3/4/0123456789abcdef"),
            ),
            (format!("a {applied}"), format!("a {applied}")),
        ] {
            assert_eq!(hide_applied(&body), want, "{body:?}");
        }
        for (body, want) in [
            (
                "a <!-- x --> b <!-- gh-aw-execution: {} --> c  \n",
                "a <!-- x --> b  c",
            ),
            ("a <!-- <!-- gh-aw-agentic-workflow: n --> --> b", "a  b"),
            (
                "a <!--  GH-AW-Execution : x",
                "a <!--  gh-aw&#45;Execution : x",
            ),
            ("a <!-- open", "a <!-- open"),
        ] {
            assert_eq!(strip_provenance(body), want, "{body:?}");
        }
    }

    fn comment_item() -> Value {
        json!({"type": ADD_COMMENT, "body": "Done."})
    }

    #[test]
    fn advisory_writer_rechecks_immediately_before_posting() {
        let advisory = crate::advisory::Advisory {
            repo: REPO.into(),
            pull: 7,
            base: "main".into(),
            head: "a".repeat(40),
        };
        let pull = json!({"number":7,"state":"open","base":{"ref":"main",
            "repo":{"full_name":REPO}},"head":{"sha":advisory.head}});
        for (pointer, value, success) in [
            ("/state", json!("open"), true),
            ("/state", json!("closed"), false),
            ("/head/sha", json!("b".repeat(40)), false),
            ("/base/ref", json!("release"), false),
            ("/base/repo/full_name", json!("other/repo"), false),
            ("/number", json!(8), false),
        ] {
            let mut changed = pull.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            let (github, sent) = forge(&json!({format!("/repos/{REPO}/pulls/7"):changed}), &[]);
            let run = run(1, "https://api.github.com");
            let publisher = GithubPublisher {
                github,
                git: SERVER.into(),
                repo: REPO.into(),
                item_repo: REPO.into(),
            };
            let mut item = comment_item().as_object().unwrap().clone();
            item.insert(
                "body".into(),
                json!("Prose.\nagentic-job-applied: 4242/0/0123456789abcdef"),
            );
            let op = Op::Comment {
                advisory: Some(advisory.clone()),
                index: 0,
                item: item.clone(),
                repo: REPO.into(),
                issue: 7,
                max: 1,
            };
            let outcome = comment(&op, &item, REPO, 7, &[], &publisher, &run);
            assert_eq!(
                outcome.kind == Kind::Success,
                success,
                "{pointer}: {outcome:?}"
            );
            let sent = sent.lock().unwrap();
            let posts = sent
                .iter()
                .filter(|request| request.line.starts_with("POST "))
                .collect::<Vec<_>>();
            assert_eq!(posts.len(), usize::from(success));
            if success {
                let last = &sent[sent.len() - 2];
                assert!(
                    last.line
                        .starts_with(&format!("GET /repos/{REPO}/pulls/7 "))
                );
                let body = posts[0].body["body"].as_str().unwrap();
                assert!(body.contains(&advisory.head));
                assert!(body.contains("<!-- agentic-job-applied:"));
                assert!(body.len() <= crate::advisory::MAX_FINAL_BYTES);
            }
        }
    }

    #[test]
    fn advisory_apply_refuses_missing_failed_reports_and_rerouting() {
        let mut policy = crate::advisory::tests::policy();
        policy.repo = REPO.into();
        policy.advisory.as_mut().unwrap().repo = REPO.into();
        let root = tempfile::tempdir().unwrap();
        let (github, sent) = forge(&json!({}), &[]);
        let run = run(1, "https://api.github.com");
        let publisher = GithubPublisher {
            github,
            git: SERVER.into(),
            repo: REPO.into(),
            item_repo: REPO.into(),
        };
        let comment = json!({"type":"add_comment","repo":REPO,"item_number":7,"body":"Prose."});
        let noop = json!({"type":"noop","message":"No findings."});
        let handlers = json!({"add_comment":{"max":1,"target-repo":REPO,"target":"7"}});
        for (report, items, reroute, expected) in [
            (None, vec![comment.clone()], false, false),
            (Some(false), vec![comment.clone()], false, false),
            (
                Some(true),
                vec![comment.clone(), comment.clone()],
                false,
                false,
            ),
            (Some(true), vec![comment.clone()], true, false),
            (Some(true), vec![noop.clone()], false, true),
            (Some(true), vec![], false, true), // applied guard removed replay
        ] {
            if let Some(ok) = report {
                std::fs::write(
                    root.path().join(REPORT_FILE),
                    json!({"ok":ok,"errors":[],"items":[noop],"patch":null}).to_string(),
                )
                .unwrap();
            }
            let mut handlers = handlers.clone();
            if reroute {
                handlers[ADD_COMMENT]["target"] = json!("8");
            }
            let checked = Checked {
                items: &items,
                handlers: handlers.as_object().unwrap(),
                upload: upload(root.path()),
                policy: &policy,
            };
            let records = Records {
                remainder: &root.path().join("rest.json"),
                made: &root.path().join("made.jsonl"),
                errors: &root.path().join("errors.json"),
                output: None,
                summary: None,
                workflow: "advisory",
            };
            let result = apply(&checked, &run, &publisher, &records, &mut |_| {});
            assert_eq!(result.is_ok(), expected, "{result:?}");
        }
        assert!(sent.lock().unwrap().is_empty());
    }

    fn pull_request_item() -> Value {
        json!({"type": CREATE_PULL_REQUEST, "title": "Fix it", "body": "Why.",
            "branch": "agent-run-4242"})
    }

    /// A request of a type gh-aw's handlers keep.
    fn gh_aw_item() -> Value {
        json!({"type": "create_discussion", "title": "Flaky", "body": "Why."})
    }

    /// Each request goes to one set of handlers, the routed ones in the
    /// run's order and first; what gh-aw's would publish otherwise
    /// refuses the run.
    #[test]
    fn routing() {
        let routed = vec![ADD_COMMENT.to_owned(), CREATE_PULL_REQUEST.to_owned()];
        let (comment, pr) = (comment_item(), pull_request_item());
        let noop = json!({"type": "noop", "message": "m"});
        let labels = json!({"type": "add_labels", "labels": ["x"]});
        for (items, ours, rest) in [
            (
                vec![pr.clone(), comment.clone(), labels.clone()],
                vec![0, 1],
                vec![labels.clone()],
            ),
            (
                vec![noop.clone(), comment.clone(), noop.clone()],
                vec![1],
                vec![noop.clone(), noop.clone()],
            ),
            (vec![labels.clone()], vec![], vec![labels.clone()]),
        ] {
            let split = split(&items, &routed).unwrap();
            let indices: Vec<usize> = split.ours.iter().map(|routed| routed.index).collect();
            assert_eq!(indices, ours, "{items:?}");
            assert_eq!(split.rest, rest, "{items:?}");
        }
        // The policy's types alone.
        let only = split(
            std::slice::from_ref(&comment),
            &[CREATE_PULL_REQUEST.to_owned()],
        )
        .unwrap();
        assert!(only.ours.is_empty());
        assert_eq!(only.rest, std::slice::from_ref(&comment));

        let with = |item: &Value, key: &str, value: Value| {
            let mut item = item.clone();
            item[key] = value;
            item
        };
        for (items, want) in [
            (
                vec![labels.clone(), comment.clone()],
                "a add_comment after a add_labels",
            ),
            (
                vec![with(&comment, "temporary_id", json!("aw_abc"))],
                "the field \"temporary_id\"",
            ),
            (
                vec![with(&comment, "comment_id", json!(5))],
                "the field \"comment_id\"",
            ),
            (
                vec![with(&comment, "body", json!("see #AW_abc"))],
                "temporary ID",
            ),
            (
                vec![with(&pr, "dependencies", json!(["x"]))],
                "the field \"dependencies\"",
            ),
            (vec![json!("x")], "not an object"),
        ] {
            let errors = split(&items, &routed).unwrap_err();
            assert!(
                errors.iter().any(|error| error.contains(want)),
                "{want}: {errors:?}"
            );
        }
    }

    /// A checked upload of the corpus's pull request, its repositories
    /// under the directory returned, and the handlers' configuration.
    fn pull_request_case() -> (tempfile::TempDir, PathBuf, Value) {
        let cases: Vec<Value> =
            serde_json::from_value(read_json(&corpus().join("cases.json"))).unwrap();
        let case = cases
            .iter()
            .find(|case| case["name"] == "create-pull-request")
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let checked = root.path().join("checked");
        std::fs::create_dir_all(&checked).unwrap();
        repositories(&case["git"], root.path(), &checked);
        let golden = read_json(&corpus().join("create-pull-request.json"));
        let mut handlers = golden["attempts"][0]["handler_config"].clone();
        handlers[ADD_COMMENT] = json!({"max": 2, "target-repo": REPO, "target": "7"});
        (root, checked, handlers)
    }

    /// What gh-aw's handlers would publish otherwise refuses the run
    /// before anything is published.
    #[test]
    fn plan_refusals() {
        type Change = fn(&mut Value, &mut Value, &Path);
        let cases: &[(Value, Change, &str)] = &[
            (
                comment_item(),
                |handlers, _, _| handlers[ADD_COMMENT]["hide_older_comments"] = json!(true),
                "\"hide_older_comments\"",
            ),
            (
                comment_item(),
                |handlers, _, _| handlers[ADD_COMMENT]["target"] = json!("*"),
                "without one item",
            ),
            (
                comment_item(),
                |handlers, _, _| {
                    handlers.as_object_mut().unwrap().remove(ADD_COMMENT);
                },
                "no handler configuration for add_comment",
            ),
            (
                comment_item(),
                |_, item, _| item["repo"] = json!("other/repo"),
                "which is not owner/repo",
            ),
            (
                comment_item(),
                |_, _, checked| std::fs::write(checked.join("aw_info.json"), "{}").unwrap(),
                "aw_info.json",
            ),
            (
                pull_request_item(),
                |handlers, _, _| {
                    handlers[CREATE_PULL_REQUEST]["fallback_as_issue"] = json!(true);
                },
                "fallback_as_issue",
            ),
            (
                pull_request_item(),
                |handlers, _, _| handlers[CREATE_PULL_REQUEST]["allowed_repos"] = json!(["a/b"]),
                "allows other repositories",
            ),
            (
                pull_request_item(),
                |_, item, _| item["base"] = json!("other"),
                "another base",
            ),
            (
                pull_request_item(),
                |_, item, _| item["labels"] = json!(["x"]),
                "with labels",
            ),
            (
                pull_request_item(),
                |_, item, _| item["branch"] = json!("agent-run-1"),
                "the pull request's is aw-agent-run-1.patch",
            ),
            (
                pull_request_item(),
                |_, _, checked| std::fs::remove_file(checked.join(REPORT_FILE)).unwrap(),
                "check's report",
            ),
            (
                pull_request_item(),
                |_, item, _| {
                    item["title"] = json!("Réparer");
                    item["body"] = json!("# Réparer\n\nA local reproduction.");
                },
                "under a title that is not ASCII",
            ),
        ];
        let run = run(1, "http://127.0.0.1:1");
        for (item, change, want) in cases {
            let (_root, checked, mut handlers) = pull_request_case();
            let mut item = item.clone();
            change(&mut handlers, &mut item, &checked);
            let Split { ours, .. } = split(&[item], &policy().native_handlers).unwrap();
            let errors = plan(
                ours,
                handlers.as_object().unwrap(),
                &upload(&checked),
                &policy(),
                &run,
            )
            .unwrap_err();
            assert!(
                errors.iter().any(|error| error.contains(want)),
                "{want}: {errors:?}"
            );
        }
    }

    /// Every type the bounds may route has a handler here, and no other.
    #[test]
    fn handlers_are_the_native_outputs() {
        let ours: Vec<&str> = HANDLERS.iter().map(|handler| handler.output).collect();
        assert_eq!(ours, NATIVE_OUTPUTS);
    }

    /// Labels and closing requests this cannot publish as gh-aw does are
    /// refused from what they hold, where check can refuse them too, or
    /// from the handlers' settings and the event before anything is
    /// published.
    #[test]
    fn label_and_close_refusals() {
        let routed = policy().native_handlers;
        let labels = json!({"type": ADD_LABELS, "item_number": 7, "labels": ["triage"]});
        let close = json!({"type": CLOSE_ISSUE, "issue_number": 7, "body": "Done."});
        let with = |item: &Value, key: &str, value: Value| {
            let mut item = item.clone();
            item[key] = value;
            item
        };
        for (item, want) in [
            (
                with(&labels, "item_number", json!("7")),
                "positive integer item_number",
            ),
            (
                with(&labels, "item_number", json!(0)),
                "positive integer item_number",
            ),
            (
                with(&labels, "issue_number", json!(7)),
                "the field \"issue_number\"",
            ),
            (with(&labels, "labels", json!(["a@b"])), "the label \"a@b\""),
            (
                with(&labels, "labels", json!([" triage"])),
                "the label \" triage\"",
            ),
            (
                with(&labels, "labels", json!(["-triage"])),
                "the label \"-triage\"",
            ),
            (
                with(&labels, "labels", json!([{"name": "x"}])),
                "the label {",
            ),
            (with(&labels, "labels", json!("triage")), "not an array"),
            (
                with(&close, "state_reason", json!("wontfix")),
                "state_reason \"wontfix\"",
            ),
            (
                with(&close, "duplicate_of", json!(8)),
                "the field \"duplicate_of\"",
            ),
            (
                json!({"type": CLOSE_PULL_REQUEST, "body": "Done."}),
                "positive integer pull_request_number",
            ),
        ] {
            let errors = split(std::slice::from_ref(&item), &routed).unwrap_err();
            assert!(
                errors.iter().any(|error| error.contains(want)),
                "{want}: {errors:?}"
            );
        }
        assert!(split(&[with(&close, "state_reason", json!("DUPLICATE"))], &routed).is_ok());

        let handlers = json!({
            ADD_LABELS: {"max": 1, "allowed": ["triage"], "target-repo": REPO, "target": "*",
                "issue_intent": false, "create_if_missing": false},
            CLOSE_ISSUE: {"max": 1, "target-repo": REPO, "target": "*", "issue_intent": false,
                "allow_body": true},
        });
        type Change = fn(&mut Value, &mut Run);
        let cases: &[(&Value, Change, &str)] = &[
            (
                &labels,
                |handlers, _| handlers[ADD_LABELS]["create_if_missing"] = json!(true),
                "create_if_missing is not false",
            ),
            (
                &labels,
                |handlers, _| handlers[ADD_LABELS]["max_labels"] = json!(3),
                "\"max_labels\"",
            ),
            (
                &labels,
                |handlers, _| handlers[ADD_LABELS]["blocked"] = json!(["\u{212a}*"]),
                "not ASCII",
            ),
            (
                &labels,
                |_, run| {
                    run.event = json!({"inputs": {"event_payload": "{}"}});
                },
                "event_payload",
            ),
            (
                &close,
                |_, run| {
                    run.event = json!({"inputs": {"target_repo": "other/repo"}});
                },
                "target_repo",
            ),
            (
                &labels,
                |_, run| {
                    run.event_name = "repository_dispatch".into();
                    run.event = json!({"client_payload": {}});
                },
                "client_payload",
            ),
            (
                &close,
                |_, run| run.event = json!({"issue": {"number": "7"}}),
                "is not one gh-aw writes as is",
            ),
            (
                &close,
                |handlers, _| handlers[CLOSE_ISSUE]["state_reason"] = json!("not_planned"),
                "\"state_reason\"",
            ),
            (
                &close,
                |handlers, _| handlers[CLOSE_ISSUE]["target"] = json!("triggering"),
                "target is not \"*\"",
            ),
        ];
        for (item, change, want) in cases {
            let mut handlers = handlers.clone();
            let mut run = run(1, "http://127.0.0.1:1");
            change(&mut handlers, &mut run);
            let Split { ours, .. } = split(&[(*item).clone()], &routed).unwrap();
            let errors = plan(
                ours,
                handlers.as_object().unwrap(),
                &upload(Path::new("/nonexistent")),
                &policy(),
                &run,
            )
            .unwrap_err();
            assert!(
                errors.iter().any(|error| error.contains(want)),
                "{want}: {errors:?}"
            );
        }
    }

    /// What gh-aw's label handlers keep, the path a label is removed at,
    /// and the hash of a body they record.
    #[test]
    fn labels_as_gh_aw_keeps_them() {
        let names = |names: &[&str]| -> Vec<String> {
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        for (labels, allowed, blocked, max, want) in [
            (&["a", "b", "a"][..], &[][..], &[][..], 10, &["a", "b"][..]),
            (&["Bug", "docs"], &["bug"], &[], 10, &["Bug"]),
            (
                &["area: ci", "area/x", "kind"],
                &["area*"],
                &[],
                10,
                &["area: ci", "area/x"],
            ),
            (&["wontfix", "triage"], &[], &["WONT*"], 10, &["triage"]),
            (&["a.b", "axb"], &["a.b"], &[], 10, &["a.b"]),
            (&["a", "b", "c"], &[], &[], 2, &["a", "b"]),
        ] {
            assert_eq!(
                kept_labels(&names(labels), &names(allowed), &names(blocked), max),
                names(want),
                "{labels:?} {allowed:?} {blocked:?}"
            );
        }
        assert_eq!(uri_component("good first issue"), "good%20first%20issue");
        assert_eq!(uri_component("area/ci: x_y.z~"), "area%2Fci%3A%20x_y.z~");
        assert_eq!(
            body_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(body_hash(" a \t\r\nb\n\n"), body_hash("a\nb"));
        assert_ne!(body_hash("a\n b"), body_hash("a\nb"));
    }

    /// A pull request that fails is not followed by the comments after
    /// it, as gh-aw's would be with its note; the comment before it is
    /// posted, and gh-aw's handlers are left the rest.
    #[test]
    fn a_failed_pull_request_stops_the_comments_after_it() {
        let (root, checked, mut handlers) = pull_request_case();
        handlers[CREATE_PULL_REQUEST]["protected_files"] = json!(["lib.rs"]);
        let (github, sent) = forge(
            &json!({"/repos/owner/repo/issues/7":
            {"number": 7, "user": {"login": "owner"}}}),
            &[],
        );
        let publisher = GithubPublisher {
            github,
            git: root.path().display().to_string(),
            item_repo: REPO.into(),
            repo: REPO.into(),
        };
        let records = tempfile::tempdir().unwrap();
        let path = |file: &str| records.path().join(file);
        std::fs::write(path("output"), "").unwrap();
        let issue = gh_aw_item();
        let items = [
            comment_item(),
            pull_request_item(),
            comment_item(),
            issue.clone(),
        ];
        let policy = policy();
        let ok = apply(
            &Checked {
                items: &items,
                handlers: handlers.as_object().unwrap(),
                upload: upload(&checked),
                policy: &policy,
            },
            &run(1, "http://127.0.0.1:1"),
            &publisher,
            &Records {
                remainder: &path("remainder.json"),
                made: &path("made.jsonl"),
                errors: &path("errors.json"),
                output: Some(&path("output")),
                summary: None,
                workflow: "agentic-job",
            },
            &mut |_| {},
        )
        .unwrap();
        assert!(!ok);
        let lines: Vec<String> = sent
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.line.clone())
            .collect();
        assert_eq!(
            lines,
            [
                "GET /repos/owner/repo/issues/7 HTTP/1.1",
                "POST /repos/owner/repo/issues/7/comments HTTP/1.1"
            ]
        );
        assert_eq!(read_json(&path("remainder.json"))["items"], json!([issue]));
        let errors = read_json(&path("errors.json"));
        assert_eq!(errors["failures"].as_array().unwrap().len(), 2);
        assert!(
            errors["failures"][0]["error"]
                .as_str()
                .unwrap()
                .starts_with(
                    "Cannot create pull request: patch modifies protected files (src/lib.rs)"
                )
        );
        assert!(
            errors["failures"][1]["error"]
                .as_str()
                .unwrap()
                .starts_with("not posted: the create_pull_request before it failed")
        );
        let made = std::fs::read_to_string(path("made.jsonl")).unwrap();
        assert_eq!(made.lines().count(), 1);
        let output = std::fs::read_to_string(path("output")).unwrap();
        assert!(output.contains("items_failed=2\n"), "{output}");
        assert!(output.contains("status=partial_success\n"), "{output}");
        // Nothing was pushed.
        let fork = root.path().join(format!("{FORK}.git"));
        assert_eq!(
            sh(&fork, &["for-each-ref", "--format=%(refname)"]),
            "refs/heads/main"
        );
    }

    /// gh-aw's comments after a pull request that failed here start with
    /// the warning its handler manager puts first; nothing else changes.
    #[test]
    fn gh_aw_comments_after_a_failed_pull_request_warn_of_it() {
        let failed = Outcome {
            output: CREATE_PULL_REQUEST,
            index: 0,
            kind: Kind::Failed,
            result: Value::Null,
            error: Some("injected failure".into()),
        };
        let note = "\n\n---\n> [!WARNING]\n> The `create_pull_request` operation failed: \
                    injected failure. The code changes were not applied.\n\n";
        let labels = json!({"type": "add_labels", "labels": ["x"]});
        let rest = [
            labels.clone(),
            json!({"type": "add_comment", "item_number": 7, "body": "Done."}),
            json!({"type": "add_comment"}),
        ];
        assert_eq!(
            warn_of_failure(&rest, &failed),
            [
                labels,
                json!({"type": "add_comment", "item_number": 7, "body": format!("{note}Done.")}),
                json!({"type": "add_comment", "body": note}),
            ]
        );
    }

    /// A mention gh-aw would look up, or a pull request after a comment
    /// whose body this cannot write as gh-aw does, refuses the run before
    /// anything is published or gh-aw's handlers are left the rest.
    #[test]
    fn refusals_leave_gh_aw_nothing() {
        let issue = gh_aw_item();
        let mut heading = pull_request_item();
        heading["title"] = json!("Réparer");
        heading["body"] = json!("# Réparer\n\nA local reproduction.");
        for (items, bot, want) in [
            (vec![comment_item(), issue.clone()], true, "look up"),
            (vec![comment_item(), heading, issue], false, "not ASCII"),
        ] {
            let (root, checked, handlers) = pull_request_case();
            let (github, sent) = forge(&json!({}), &[]);
            let publisher = GithubPublisher {
                github,
                git: root.path().display().to_string(),
                item_repo: REPO.into(),
                repo: REPO.into(),
            };
            let records = tempfile::tempdir().unwrap();
            let path = |file: &str| records.path().join(file);
            let policy = policy();
            let mut run = run(1, "http://127.0.0.1:1");
            if bot {
                run.actor = "renovate[bot]".into();
            }
            let err = apply(
                &Checked {
                    items: &items,
                    handlers: handlers.as_object().unwrap(),
                    upload: upload(&checked),
                    policy: &policy,
                },
                &run,
                &publisher,
                &Records {
                    remainder: &path("remainder.json"),
                    made: &path("made.jsonl"),
                    errors: &path("errors.json"),
                    output: None,
                    summary: None,
                    workflow: "agentic-job",
                },
                &mut |_| {},
            )
            .unwrap_err();
            assert!(format!("{err:#}").contains(want), "{want}: {err:#}");
            assert!(!path("remainder.json").exists(), "{want}");
            assert!(sent.lock().unwrap().is_empty(), "{want}");
        }
    }

    /// A run gh-aw's handlers would read otherwise is refused.
    #[test]
    fn run_refusals() {
        let base: BTreeMap<&str, &str> = [
            ("GITHUB_REPOSITORY", REPO),
            ("GITHUB_REPOSITORY_ID", "77"),
            ("GITHUB_RUN_ID", "4242"),
            ("GITHUB_RUN_ATTEMPT", "1"),
            ("GITHUB_JOB", "apply"),
            ("GH_AW_JOB_CHECK_RUN_ID", "9001"),
            ("GH_AW_WORKFLOW_ID", "agentic-job"),
            ("GH_AW_SAFE_OUTPUTS_URLS", URL_POLICY),
        ]
        .into_iter()
        .collect();
        let read = |changes: &[(&'static str, &'static str)]| {
            let mut vars = base.clone();
            vars.extend(changes.iter().copied());
            Run::read(&|name| vars.get(name).map(|value| (*value).to_owned()))
        };
        let run = read(&[]).unwrap();
        assert_eq!(run.server, SERVER);
        assert_eq!(run.workflow_name, "Workflow");
        let long = read(&[("GH_AW_WORKFLOW_NAME", "n".repeat(101).leak())]).unwrap();
        assert_eq!(long.workflow_name, format!("{}…", "n".repeat(99)));
        for (changes, want) in [
            (
                vec![("GH_AW_SAFE_OUTPUTS_URLS", "allowed-only")],
                "GH_AW_SAFE_OUTPUTS_URLS",
            ),
            (
                vec![("GITHUB_SERVER_URL", "https://ghe.example/sub")],
                "https origin",
            ),
            (
                vec![("GITHUB_SERVER_URL", "http://github.com")],
                "https origin",
            ),
            (vec![("GITHUB_RUN_ATTEMPT", "")], "GITHUB_RUN_ATTEMPT"),
            (vec![("GH_AW_WORKFLOW_ID", " x")], "GH_AW_WORKFLOW_ID"),
        ] {
            let err = format!("{:#}", read(&changes).unwrap_err());
            assert!(err.contains(want), "{err}");
        }
        // The mentions it keeps are the event's people, as gh-aw reads
        // them; a name it would look up refuses the run.
        for (event_name, actor, want) in [
            ("workflow_dispatch", "Owner", Ok(vec!["Owner".to_owned()])),
            ("workflow_dispatch", "", Ok(vec![])),
            ("push", "owner", Ok(vec![])),
            ("workflow_dispatch", "renovate[bot]", Err("look up")),
        ] {
            let mut run = read(&[]).unwrap();
            run.event_name = event_name.into();
            run.actor = actor.into();
            match (run.default_mentions(), want) {
                (Ok(got), Ok(want)) => assert_eq!(got, want),
                (Err(err), Err(want)) => assert!(format!("{err:#}").contains(want)),
                (got, want) => panic!("{got:?}, not {want:?}"),
            }
        }
        let mut run = read(&[]).unwrap();
        run.event =
            json!({"issue": {"number": 5, "pull_request": {}}, "pull_request": {"number": 6}});
        assert_eq!(run.triggering(ADD_COMMENT).unwrap().as_deref(), Some("#5"));
        assert_eq!(
            run.triggering(CREATE_PULL_REQUEST).unwrap().as_deref(),
            Some("#6")
        );
        run.event = json!({"discussion": {"number": 3}});
        assert_eq!(
            run.triggering(ADD_COMMENT).unwrap().as_deref(),
            Some("discussion #3")
        );
        run.event = json!({"issue": {"number": "5"}});
        assert!(run.triggering(ADD_COMMENT).is_err());
        // A closing comment names the event's issue, or else its pull
        // request; the label handlers' records, a pull request's kind.
        run.event =
            json!({"issue": {"number": 5, "pull_request": {}}, "pull_request": {"number": 6}});
        assert_eq!(run.closing_triggering().unwrap().as_deref(), Some("#5"));
        assert_eq!(run.context_kind().unwrap(), "pull request");
        run.event = json!({"pull_request": {"number": 6}, "discussion": {"number": 3}});
        assert_eq!(run.closing_triggering().unwrap().as_deref(), Some("#6"));
        run.event = json!({"discussion": {"number": 3}});
        assert_eq!(run.closing_triggering().unwrap(), None);
        assert_eq!(run.context_kind().unwrap(), "issue");
        // An issue's or a review's footer names a pull request's issue as
        // the pull request, after an issue of its own.
        for (event, want) in [
            (json!({"issue": {"number": 5}}), Some("#5")),
            (
                json!({"issue": {"number": 5, "pull_request": {}}}),
                Some("#5"),
            ),
            (
                json!({"issue": {"number": 5, "pull_request": {}}, "pull_request": {"number": 6}}),
                Some("#6"),
            ),
            (json!({"discussion": {"number": 3}}), Some("discussion #3")),
            (json!({}), None),
        ] {
            run.event = event;
            assert_eq!(run.item_triggering().unwrap().as_deref(), want);
        }
    }

    /// The corpus's case NAME, with its repositories made under the
    /// directory returned and its placeholders filled, check's upload in
    /// the path returned, and the handlers' configuration it recorded.
    fn corpus_case(name: &str) -> (tempfile::TempDir, PathBuf, Value, Value) {
        let cases: Vec<Value> =
            serde_json::from_value(read_json(&corpus().join("cases.json"))).unwrap();
        let case = cases.iter().find(|case| case["name"] == name).unwrap();
        let root = tempfile::tempdir().unwrap();
        let checked = root.path().join("checked");
        std::fs::create_dir_all(&checked).unwrap();
        let mut text = case.to_string();
        if !case["git"].is_null() {
            for (placeholder, value) in repositories(&case["git"], root.path(), &checked) {
                text = text.replace(&placeholder, &value);
            }
        }
        let golden = read_json(&corpus().join(format!("{name}.json")));
        let handlers = golden["attempts"][0]["handler_config"].clone();
        (
            root,
            checked,
            serde_json::from_str(&text).unwrap(),
            handlers,
        )
    }

    /// What publishing ITEMS of CASE under HANDLERS and POLICY did against
    /// its forge with FAULTS: whether all were published, the request
    /// lines sent, and the records.
    fn publish_case(
        case: &Value,
        root: &Path,
        checked: &Path,
        items: &[Value],
        handlers: &Value,
        policy: &Policy,
        faults: &[Value],
    ) -> (bool, Vec<Request>, tempfile::TempDir) {
        let (github, sent) = forge(&case["forge"], faults);
        let publisher = GithubPublisher {
            github,
            git: root.display().to_string(),
            item_repo: REPO.into(),
            repo: REPO.into(),
        };
        let records = tempfile::tempdir().unwrap();
        let path = |file: &str| records.path().join(file);
        std::fs::write(path("output"), "").unwrap();
        let run = run(1, "http://127.0.0.1:1");
        let ok = apply(
            &Checked {
                items,
                handlers: handlers.as_object().unwrap(),
                upload: upload(checked),
                policy,
            },
            &run,
            &publisher,
            &Records {
                remainder: &path("remainder.json"),
                made: &path("made.jsonl"),
                errors: &path("errors.json"),
                output: Some(&path("output")),
                summary: Some(&path("summary")),
                workflow: "agentic-job",
            },
            &mut |_| {},
        )
        .unwrap();
        let sent = std::mem::take(&mut *sent.lock().unwrap());
        (ok, sent, records)
    }

    /// The writes among SENT, as `METHOD PATH`.
    fn writes(sent: &[Request]) -> Vec<String> {
        sent.iter()
            .map(|request| request.line.trim_end_matches(" HTTP/1.1").to_owned())
            .filter(|line| !line.starts_with("GET "))
            .collect()
    }

    /// A push onto a branch someone moved since the run was asked for is
    /// not made, in gh-aw's words for it; the routed comment after it is
    /// not posted, and gh-aw's has the warning its manager would give it.
    #[test]
    fn a_push_onto_a_moved_branch_fails_and_stops_what_follows() {
        for routed_comment in [true, false] {
            let (root, checked, case, mut handlers) = corpus_case("push-to-pull-request-branch");
            handlers[ADD_COMMENT] = json!({"max": 1, "target-repo": REPO, "target": "7"});
            let seed = root.path().join("seed");
            git(&seed, &["checkout", "-q", "feature"]);
            std::fs::write(seed.join("NOTES"), "moved\n").unwrap();
            git(&seed, &["add", "NOTES"]);
            git(
                &seed,
                &[
                    "-c",
                    "user.name=Someone",
                    "-c",
                    "user.email=someone@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "Move",
                ],
            );
            let fork = root.path().join(format!("{FORK}.git"));
            git(&seed, &["push", "-q", fork.to_str().unwrap(), "feature"]);
            let moved = git(&seed, &["rev-parse", "HEAD"]);
            let mut policy = case_policy(&case);
            if !routed_comment {
                policy.native_handlers = vec![PUSH_TO_PULL_REQUEST_BRANCH.to_owned()];
            }
            let comment = json!({"type": ADD_COMMENT, "item_number": 7, "body": "Pushed."});
            let items = [case["items"][0].clone(), comment.clone()];
            let (ok, sent, records) = publish_case(
                &case,
                root.path(),
                &checked,
                &items,
                &handlers,
                &policy,
                &[],
            );
            assert!(!ok);
            assert!(writes(&sent).is_empty(), "{:?}", writes(&sent));
            assert_eq!(git(&fork, &["rev-parse", "feature"]), moved);
            let errors = read_json(&records.path().join("errors.json"));
            assert_eq!(errors["failures"][0]["error"], NON_FAST_FORWARD);
            let output = std::fs::read_to_string(records.path().join("output")).unwrap();
            assert!(output.contains("code_push_failure_count=1\n"), "{output}");
            let remainder = read_json(&records.path().join("remainder.json"))["items"].clone();
            if routed_comment {
                assert_eq!(remainder, json!([]));
                assert_eq!(
                    errors["failures"][1]["error"],
                    format!(
                        "not posted: the {PUSH_TO_PULL_REQUEST_BRANCH} before it failed \
                         ({NON_FAST_FORWARD})"
                    )
                );
            } else {
                let body = remainder[0]["body"].as_str().unwrap();
                assert!(
                    body.starts_with(&format!(
                        "\n\n---\n> [!WARNING]\n> The `{PUSH_TO_PULL_REQUEST_BRANCH}` operation \
                         failed: {NON_FAST_FORWARD}. The code changes were not applied.\n\n"
                    )) && body.ends_with("Pushed."),
                    "{body}"
                );
            }
        }
    }

    /// A push gh-aw's handler would make otherwise is refused before
    /// anything is published; one of a protected file is skipped, as it
    /// skips it, with nothing written.
    #[test]
    fn push_refusals() {
        type Change = fn(&mut Value, &mut Value, &Path);
        let cases: &[(Change, &str)] = &[
            (
                |handlers, _, _| {
                    handlers[PUSH_TO_PULL_REQUEST_BRANCH]["signed_commits"] = json!(true)
                },
                "signed_commits is not false",
            ),
            (
                |handlers, _, _| {
                    handlers[PUSH_TO_PULL_REQUEST_BRANCH]["fallback_as_pull_request"] = json!(true);
                },
                "fallback_as_pull_request is not false",
            ),
            (
                |handlers, _, _| {
                    handlers[PUSH_TO_PULL_REQUEST_BRANCH]["checkout_mapping"] = json!({})
                },
                "checkout_mapping",
            ),
            (
                |handlers, _, _| {
                    handlers[PUSH_TO_PULL_REQUEST_BRANCH]["allowed_repos"] = json!(["a/b"])
                },
                "allows other repositories",
            ),
            (
                |handlers, _, _| handlers[PUSH_TO_PULL_REQUEST_BRANCH]["target"] = json!("*"),
                "the policy's pull request",
            ),
            (
                |handlers, _, _| {
                    handlers[PUSH_TO_PULL_REQUEST_BRANCH]["head"] = json!("a".repeat(40))
                },
                "is not the policy's",
            ),
            (
                |handlers, _, _| {
                    handlers[PUSH_TO_PULL_REQUEST_BRANCH]["title_prefix"] = json!("[x]")
                },
                "\"title_prefix\"",
            ),
            (
                |handlers, _, _| {
                    handlers[PUSH_TO_PULL_REQUEST_BRANCH]["target-repo"] = json!("other/repo");
                },
                "target-repo other/repo is not the policy's",
            ),
            (
                |_, item, _| item["branch"] = json!("other"),
                "not the policy's feature",
            ),
            (
                |_, item, _| item["commit_message"] = json!("x"),
                "the field \"commit_message\"",
            ),
            (
                |_, _, checked| {
                    let path = checked.join(REPORT_FILE);
                    let mut report = read_json(&path);
                    report["patch"]["commit_files"] = json!([]);
                    std::fs::write(path, report.to_string()).unwrap();
                },
                "replacement series",
            ),
        ];
        for (change, want) in cases {
            let (root, checked, case, mut handlers) = corpus_case("push-to-pull-request-branch");
            let mut item = case["items"][0].clone();
            change(&mut handlers, &mut item, &checked);
            let (github, sent) = forge(&case["forge"], &[]);
            let publisher = GithubPublisher {
                github,
                git: root.path().display().to_string(),
                item_repo: REPO.into(),
                repo: REPO.into(),
            };
            let records = tempfile::tempdir().unwrap();
            let path = |file: &str| records.path().join(file);
            let err = apply(
                &Checked {
                    items: &[item],
                    handlers: handlers.as_object().unwrap(),
                    upload: upload(&checked),
                    policy: &case_policy(&case),
                },
                &run(1, "http://127.0.0.1:1"),
                &publisher,
                &Records {
                    remainder: &path("remainder.json"),
                    made: &path("made.jsonl"),
                    errors: &path("errors.json"),
                    output: None,
                    summary: None,
                    workflow: "agentic-job",
                },
                &mut |_| {},
            )
            .unwrap_err();
            assert!(format!("{err:#}").contains(want), "{want}: {err:#}");
            assert!(sent.lock().unwrap().is_empty(), "{want}");
            assert!(!path("remainder.json").exists(), "{want}");
        }

        let (root, checked, case, mut handlers) = corpus_case("push-to-pull-request-branch");
        handlers[PUSH_TO_PULL_REQUEST_BRANCH]["protected_files"] = json!(["sub.rs"]);
        // A push admitted by its pull request's author, which `push
        // target` checked, publishes as any other.
        handlers[PUSH_TO_PULL_REQUEST_BRANCH]["author"] = json!("cgwalters-bot");
        let items = [case["items"][0].clone()];
        let policy = case_policy(&case);
        let (ok, sent, records) = publish_case(
            &case,
            root.path(),
            &checked,
            &items,
            &handlers,
            &policy,
            &[],
        );
        assert!(ok);
        assert!(sent.is_empty());
        let output = std::fs::read_to_string(records.path().join("output")).unwrap();
        assert!(output.contains("status=completed_with_skips\n"), "{output}");
        let summary = std::fs::read_to_string(records.path().join("summary")).unwrap();
        assert!(
            summary.contains("**Reason Code:** `POLICY_FILE_PROTECTION_DENIED`"),
            "{summary}"
        );
    }

    /// Under `comment_on_duplicate`, the oldest open issue titled exactly
    /// as asked gets the body as a comment and no issue is opened; with
    /// none, the issue is opened; a search that fails opens nothing.
    #[test]
    fn a_duplicate_issue_is_commented_on() {
        let issue = json!({"type": CREATE_ISSUE, "title": "Flaky", "body": "Why."});
        let handlers = json!({CREATE_ISSUE: {"max": 1, "target-repo": REPO, "title_prefix": "",
            "comment_on_duplicate": true}});
        let found = |number: u64, title: &str| {
            json!({"number": number, "title": title, "state": "open",
                "repository_url": format!("https://api.github.com/repos/{REPO}")})
        };
        let mut pull = found(2, "Flaky");
        pull["pull_request"] = json!({});
        let mut closed = found(1, "Flaky");
        closed["state"] = json!("closed");
        let mut elsewhere = found(3, "Flaky");
        elsewhere["repository_url"] = json!("https://api.github.com/repos/other/repo");
        let search = "GET /search/issues?q=repo%3Aowner%2Frepo%20is%3Aissue%20is%3Aopen%20in%3Atitle%20%22Flaky%22%20sort%3Acreated-asc&per_page=100 HTTP/1.1";
        // What the search answers, the request that publishes, and
        // whether the run succeeds.
        for (answer, posted, ok) in [
            (
                Some(json!([
                    pull,
                    closed,
                    elsewhere,
                    found(9, "Flaky"),
                    found(4, "flaky"),
                    found(5, "Flaky")
                ])),
                Some("POST /repos/owner/repo/issues/5/comments HTTP/1.1"),
                true,
            ),
            (
                Some(json!([found(4, "Flaky tests")])),
                Some("POST /repos/owner/repo/issues HTTP/1.1"),
                true,
            ),
            (None, None, false),
        ] {
            let seed = answer.map_or(
                json!({}),
                |items| json!({"/search/issues": {"items": items}}),
            );
            let (github, sent) = forge(&seed, &[]);
            let git = tempfile::tempdir().unwrap();
            let publisher = GithubPublisher {
                github,
                git: git.path().display().to_string(),
                item_repo: REPO.into(),
                repo: REPO.into(),
            };
            let records = tempfile::tempdir().unwrap();
            let path = |file: &str| records.path().join(file);
            let policy = policy();
            let published = apply(
                &Checked {
                    items: std::slice::from_ref(&issue),
                    handlers: handlers.as_object().unwrap(),
                    upload: upload(Path::new("/nonexistent")),
                    policy: &policy,
                },
                &run(1, "http://127.0.0.1:1"),
                &publisher,
                &Records {
                    remainder: &path("remainder.json"),
                    made: &path("made.jsonl"),
                    errors: &path("errors.json"),
                    output: None,
                    summary: None,
                    workflow: "agentic-job",
                },
                &mut |_| {},
            )
            .unwrap();
            assert_eq!(published, ok, "{posted:?}");
            let lines: Vec<String> = sent
                .lock()
                .unwrap()
                .iter()
                .map(|request| request.line.clone())
                .collect();
            assert_eq!(lines[0], search);
            assert_eq!(lines.get(1).map(String::as_str), posted);
            if posted.is_some_and(|line| line.contains("/comments")) {
                assert_eq!(lines.len(), 2, "{lines:?}");
                let body = sent.lock().unwrap()[1].body["body"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                assert!(body.starts_with("Why.\n"), "{body}");
                let made = std::fs::read_to_string(path("made.jsonl")).unwrap();
                assert!(made.contains("/issues/5#issuecomment-"), "{made}");
            }
        }
    }

    /// Issues and review comments this cannot publish as gh-aw does are
    /// refused from what they hold, or from the handlers' settings and the
    /// event, before anything is published.
    #[test]
    fn issue_and_review_comment_refusals() {
        let routed = policy().native_handlers;
        let issue = json!({"type": CREATE_ISSUE, "title": "Flaky", "body": "Why."});
        let comment = json!({"type": CREATE_REVIEW_COMMENT, "path": "src/lib.rs", "line": 2,
            "body": "Overflows."});
        let with = |item: &Value, key: &str, value: Value| {
            let mut item = item.clone();
            item[key] = value;
            item
        };
        for (items, want) in [
            (
                vec![with(&issue, "labels", json!(["a@b"]))],
                "the label \"a@b\"",
            ),
            (vec![with(&issue, "title", json!(5))], "title is not text"),
            (
                vec![with(&issue, "parent", json!(7))],
                "the field \"parent\"",
            ),
            (
                vec![with(&comment, "line", json!(0))],
                "positive integer line",
            ),
            (
                vec![with(&comment, "line", json!("2"))],
                "positive integer line",
            ),
            (vec![with(&comment, "start_line", json!(3))], "start_line"),
            (
                vec![with(&comment, "side", json!("UP"))],
                "side is not LEFT or RIGHT",
            ),
            (vec![with(&comment, "body", json!(""))], "a path and a body"),
            (
                vec![with(&comment, "start_side", json!("LEFT"))],
                "the field \"start_side\"",
            ),
            (
                vec![comment.clone(), gh_aw_item()],
                "the review is submitted after everything else",
            ),
        ] {
            let errors = split(&items, &routed).unwrap_err();
            assert!(
                errors.iter().any(|error| error.contains(want)),
                "{want}: {errors:?}"
            );
        }
        assert!(split(&[with(&comment, "start_line", json!(1))], &routed).is_ok());
        // gh-aw's pull request or push may open an issue in its place.
        for theirs in [
            pull_request_item(),
            json!({"type": PUSH_TO_PULL_REQUEST_BRANCH}),
        ] {
            let errors = split(&[issue.clone(), theirs], &[CREATE_ISSUE.to_owned()]).unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("create_issue count bounds both")),
                "{errors:?}"
            );
        }
        let closing = json!({"type": CLOSE_ISSUE, "issue_number": 7, "body": "Done."});
        assert!(split(&[issue.clone(), closing], &[CREATE_ISSUE.to_owned()]).is_ok());

        let handlers = json!({
            CREATE_ISSUE: {"max": 1, "target-repo": REPO, "title_prefix": ""},
            CREATE_REVIEW_COMMENT: {"max": 1, "target-repo": REPO, "target": "7"},
        });
        type Change = fn(&mut Value, &mut Run);
        let cases: &[(&Value, Change, &str)] = &[
            (
                &issue,
                |handlers, _| handlers[CREATE_ISSUE]["labels"] = json!(["triage"]),
                "\"labels\"",
            ),
            (
                &issue,
                |handlers, _| handlers[CREATE_ISSUE]["title_prefix"] = json!(5),
                "title_prefix is not text",
            ),
            (
                &issue,
                |handlers, _| handlers[CREATE_ISSUE]["comment_on_duplicate"] = json!("yes"),
                "comment_on_duplicate is not a boolean",
            ),
            (
                &issue,
                |_, run| run.event = json!({"issue": {"number": "7"}}),
                "is not one gh-aw writes as is",
            ),
            (
                &comment,
                |handlers, _| handlers[CREATE_REVIEW_COMMENT]["target"] = json!("*"),
                "without one pull request",
            ),
            (
                &comment,
                |handlers, _| handlers[CREATE_REVIEW_COMMENT]["side"] = json!("LEFT"),
                "\"side\"",
            ),
            (
                &comment,
                |_, run| run.event = json!({"inputs": {"aw_context": "{}"}}),
                "aw_context",
            ),
        ];
        for (item, change, want) in cases {
            let mut handlers = handlers.clone();
            let mut run = run(1, "http://127.0.0.1:1");
            change(&mut handlers, &mut run);
            let Split { ours, .. } = split(&[(*item).clone()], &routed).unwrap();
            let errors = plan(
                ours,
                handlers.as_object().unwrap(),
                &upload(Path::new("/nonexistent")),
                &policy(),
                &run,
            )
            .unwrap_err();
            assert!(
                errors.iter().any(|error| error.contains(want)),
                "{want}: {errors:?}"
            );
        }
    }

    /// A review the forge refuses for comments it cannot anchor is
    /// submitted again with those in its body, as gh-aw's buffer does; one
    /// of a locked pull request is skipped; any other refusal fails the
    /// comments buffered for it.
    #[test]
    fn reviews_fall_back_as_gh_aw_does() {
        let (root, checked, case, _) = corpus_case("review-comment");
        let handlers =
            json!({CREATE_REVIEW_COMMENT: {"max": 2, "target-repo": REPO, "target": "7"}});
        let items = [
            json!({"type": CREATE_REVIEW_COMMENT, "path": "src/lib.rs", "line": 1, "body": "One."}),
            json!({"type": CREATE_REVIEW_COMMENT, "path": "src/lib.rs", "line": 2, "body": "Two."}),
        ];
        let reviews = "POST /repos/owner/repo/pulls/7/reviews";
        let unresolved = |errors: Value| {
            json!({"method": "POST", "path": "/repos/owner/repo/pulls/7/reviews", "status": 422,
                "answer": {"message": "Unprocessable Entity", "errors": errors}})
        };
        let line = json!({"resource": "PullRequestReviewComment", "field": "comments[1].line",
            "message": "Line could not be resolved"});
        let locked = json!({"method": "POST", "path": "/repos/owner/repo/pulls/7/reviews",
            "status": 422, "answer": {"message": "Unprocessable Entity: lock prevents review"}});
        let broken = json!({"method": "POST", "path": "/repos/owner/repo/pulls/7/reviews",
            "status": 500});
        let section = "### Comments that could not be inline-anchored";
        // The faults, how many reviews are asked for, the comments and
        // body of the last, and how the run ends.
        type Want = (usize, &'static [u64], Option<&'static str>, &'static str);
        let cases: Vec<(Vec<Value>, Want)> = vec![
            (
                vec![unresolved(json!([line]))],
                (
                    2,
                    &[1],
                    Some("<summary>src/lib.rs:2</summary>\n\nTwo."),
                    "success",
                ),
            ),
            (
                vec![unresolved(json!(["Line could not be resolved"]))],
                (
                    2,
                    &[],
                    Some("<summary>src/lib.rs:1</summary>\n\nOne."),
                    "success",
                ),
            ),
            (
                vec![locked.clone(), locked.clone(), locked.clone(), locked],
                (4, &[1, 2], None, "completed_with_skips"),
            ),
            (vec![broken.clone(), broken], (2, &[1, 2], None, "failure")),
        ];
        for (faults, (asked, lines, body, status)) in cases {
            let policy = policy();
            let (ok, sent, records) = publish_case(
                &case,
                root.path(),
                &checked,
                &items,
                &handlers,
                &policy,
                &faults,
            );
            let posted: Vec<&Request> = sent
                .iter()
                .filter(|request| request.line.starts_with(reviews))
                .collect();
            assert_eq!(posted.len(), asked, "{status}");
            let last = &posted[asked - 1].body;
            let got: Vec<u64> = last["comments"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|comment| comment["line"].as_u64().unwrap())
                .collect();
            assert_eq!(got, lines, "{status}");
            if let Some(body) = body {
                let text = last["body"].as_str().unwrap();
                assert!(text.contains(section) && text.contains(body), "{text}");
            }
            let output = std::fs::read_to_string(records.path().join("output")).unwrap();
            assert!(output.contains(&format!("status={status}\n")), "{output}");
            assert_eq!(ok, status != "failure");
            let made =
                std::fs::read_to_string(records.path().join("made.jsonl")).unwrap_or_default();
            let made: Vec<Value> = made
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            if status == "success" {
                assert_eq!(made[0]["type"], SUBMIT_REVIEW);
                assert_eq!(made.len(), 1 + lines.len());
            } else {
                assert!(made.is_empty(), "{made:?}");
            }
            if status == "failure" {
                let errors = read_json(&records.path().join("errors.json"));
                assert!(
                    errors["failures"][1]["error"]
                        .as_str()
                        .unwrap()
                        .starts_with("Review finalization failed: ERR_API: "),
                    "{errors}"
                );
            }
        }
    }

    /// The fallback section keeps each comment to an excerpt, escaped.
    #[test]
    fn unanchored_comments_are_excerpts() {
        let long = "x".repeat(FALLBACK_EXCERPT + 1);
        let comments = [
            json!({"path": "a&b.rs", "line": 3, "body": long}),
            json!({"path": "c.rs", "line": 4, "body": "  "}),
        ];
        let body = with_unanchored("Footer.", &comments);
        assert_eq!(
            body,
            format!(
                "Footer.\n\n{FALLBACK_HEADER}\n\n<details><summary>a&amp;b.rs:3</summary>\n\n{}…\n\n\
                 </details>\n\n<details><summary>c.rs:4</summary>\n\n{FALLBACK_EMPTY}\n\n</details>",
                "x".repeat(FALLBACK_EXCERPT - 1)
            )
        );
    }
}
