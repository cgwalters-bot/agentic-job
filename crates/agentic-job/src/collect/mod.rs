//! `agentic-job collect`: what gh-aw's collector (`collect_ndjson_output.cjs`
//! at the commit check.yml pins) makes of a hand-back's `outputs.jsonl`:
//! check.yml's collector wherever it takes every type the policy allows,
//! and a caller's off GitHub, which has no `actions/github-script` to run
//! gh-aw's in. It writes the `{items, errors}` that `check --collected` reads.
//!
//! The requests it takes are those of [`TYPES`], each validated and its
//! text sanitized as gh-aw's collector does for that type ([`sanitize`]).
//! Any other type is an error, even where the policy allows it: passed on
//! unvalidated, it would reach an applier unsanitized. Only `handback
//! check`, which applies nothing, passes one on ([`Unported::PassOn`]). Fixtures that
//! gh-aw's collector wrote, on the same lines and configuration, hold the
//! two to the same result (`tests/data/collect`).
//!
//! Where the two differ, this mostly refuses more: a line that is not
//! JSON is not repaired, nor is JSON that serde_json cannot hold (a lone
//! surrogate, a number past f64, nesting past 128); a whole number written
//! `1.0` stays a float, which `check` refuses where it wants a number. A
//! numeric entity for a lone surrogate becomes U+FFFD. Otherwise they
//! differ only where JavaScript and Rust read text apart and no renderer
//! does: U+2028 and U+2029 as line ends, a carriage return just before the
//! fence that balancing adds. `create_issue`'s labels written as one
//! string holding a JSON array that serde_json cannot hold (a lone
//! surrogate, a number past f64) are split at commas instead. Like gh-aw's, it leaves mentions in what is posted (the
//! types that open or comment on an issue, a pull request or a
//! discussion) to the applier, which knows who may be mentioned there, and
//! it does not add gh-aw's incomplete report to a result without requests,
//! which `check` would drop.
//!
//! Also like gh-aw's, it passes a few fields on as they are, unchecked and
//! unsanitized, where gh-aw has no check for the type `validation.json`
//! gives them ([`Rule::AsIs`]: `create_issue`'s `blocked_by`,
//! `assign_to_user`'s `assignees`, `update_project`'s `fields` and
//! `view`). Refusing them here would refuse what gh-aw takes; `check`
//! holds each to the policy, and refuses what it does not allow.
//!
//! It is also what `handback check` validates the requests with in the
//! session, and check.yml's collector for a policy whose types are all
//! [`TYPES`], so the agent is told of a field error in the words the
//! check job refuses it in. [`field_guide`] tells it the fields.

pub(crate) mod markdown;
mod sanitize;

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value, json};

use self::sanitize::{is_js_space, js_trim};
use crate::check::{MAX_OUTPUTS_BYTES, OUTPUTS_FILE};
use crate::exit::Exit;
use crate::files::{self, ReadError};
use crate::policy::{
    CREATE_REVIEW_COMMENT, HIDE_COMMENT, HIDE_REASONS, MARK_READY, PUSH_TO_PULL_REQUEST_BRANCH,
    Policy, REPLY_TO_REVIEW_COMMENT, RESOLVE_REVIEW_THREAD,
};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The policy.json that `policy` printed for this run
    #[arg(long, value_name = "FILE")]
    pub policy: PathBuf,
    /// The directory holding the handed-back outputs
    #[arg(long, value_name = "DIR", required_unless_present = "unported")]
    pub outputs: Option<PathBuf>,
    /// Where to write what was collected, which `check --collected` reads
    #[arg(long, value_name = "FILE", required_unless_present = "unported")]
    pub collected: Option<PathBuf>,
    /// Collect nothing: print, a line each, the types the policy allows
    /// that this does not validate, for which gh-aw's collector is needed
    #[arg(long, conflicts_with_all = ["outputs", "collected"])]
    pub unported: bool,
}

/// What [`collect`] does with a request of a type the policy allows and
/// [`TYPES`] does not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unported {
    /// Refuse it: passed on, it would reach an applier unsanitized.
    Refuse,
    /// Pass it on as it is, for `handback check`, where nothing is
    /// applied and the check job's collector validates it later.
    PassOn,
}

/// What the collector made of the requests: those it took, sanitized,
/// and why it refused the others.
#[derive(Debug, Default, PartialEq, Serialize)]
pub struct Collected {
    pub items: Vec<Map<String, Value>>,
    pub errors: Vec<String>,
}

/// The longest text gh-aw's validator gives a sanitized field without a
/// `maxLength` of its own (`MAX_BODY_LENGTH`).
const MAX_BODY_LENGTH: usize = 65_000;

/// How long a label name is cut to, and an issue intent's rationale
/// (`ISSUE_INTENT_RATIONALE_MAX_LENGTH`).
const MAX_LABEL_LENGTH: usize = 128;
const MAX_RATIONALE_LENGTH: usize = 280;

/// The fields a label may have where it is an object (`validateIssueIntentLabels`).
const LABEL_KEYS: &[&str] = &["name", "rationale", "confidence", "suggest"];
const CONFIDENCES: &[&str] = &["LOW", "MEDIUM", "HIGH"];

/// A string field's constraints, in the terms of gh-aw's `validation.json`.
#[derive(Debug, Clone, Copy)]
struct Text {
    required: bool,
    /// Sanitized, to at most `max_length` (`MAX_BODY_LENGTH` where unset).
    /// Unsanitized, gh-aw applies no length at all.
    sanitize: bool,
    max_length: Option<usize>,
    /// The fewest characters it may have once sanitized and trimmed.
    min_length: Option<usize>,
    /// What it must match once trimmed, and how a mismatch is worded.
    pattern: Option<&'static LazyLock<Pattern>>,
    pattern_error: Option<&'static str>,
    /// The values it may take, in any case; it is passed on as written here.
    choices: Option<&'static [&'static str]>,
    /// What a refusal of it missing calls its type, in place of `string`.
    type_hint: Option<&'static str>,
}

const TEXT: Text = Text {
    required: false,
    sanitize: false,
    max_length: None,
    min_length: None,
    pattern: None,
    pattern_error: None,
    choices: None,
    type_hint: None,
};

/// A `pattern` as gh-aw writes it, for JavaScript, and compiled to mean
/// the same here: `\d` is ASCII in JavaScript, any digit in `regex`.
#[derive(Debug)]
struct Pattern {
    source: &'static str,
    regex: Regex,
}

impl Pattern {
    fn new(source: &'static str) -> Self {
        let regex = Regex::new(&source.replace(r"\d", "[0-9]")).expect("a valid pattern");
        Self { source, regex }
    }
}

/// What an output type's field must be, in the terms of gh-aw's
/// `validation.json`, which [`Field::to_json`] writes it in.
#[derive(Debug)]
enum Rule {
    Text(Text),
    Flag,
    /// `positiveInteger` where required, else `optionalPositiveInteger`:
    /// a number, or a string JavaScript's `parseInt` reads as one; with
    /// `allowNull`, a null passed on as one.
    PositiveInteger {
        required: bool,
        allow_null: bool,
    },
    /// `issueOrPRNumber`: a number or a string, taken as it is.
    IssueOrPrNumber,
    /// `issueNumberOrTemporaryId`: a positive integer as for
    /// [`Rule::PositiveInteger`], or a temporary ID, written `#aw_…` in
    /// lower case.
    IssueOrTemporaryId {
        required: bool,
    },
    /// Strings, each sanitized to at most this length.
    TextList(usize),
    /// `create_issue`'s `labels`: [`Rule::TextList`], which gh-aw also
    /// takes as a string, a JSON array or names split at commas.
    LabelList(usize),
    /// `labels` of `add_labels`, `remove_labels` and `update_issue`
    /// (`ISSUE_INTENT_LABEL_TYPES`): names, or objects with a `name` and
    /// a `rationale`, `confidence` or `suggest`.
    IntentLabels {
        required: bool,
    },
    /// `type: array`: any array, as it is.
    List,
    /// Any value, as it is: no `type`, or one gh-aw's validator has no
    /// check for (`object`, `[]string`). gh-aw neither checks nor
    /// sanitizes these, even where `validation.json` says to sanitize to
    /// `unapplied_max`; `check` holds each of them to the policy itself.
    AsIs {
        type_name: Option<&'static str>,
        unapplied_max: Option<usize>,
    },
}

#[derive(Debug)]
struct Field {
    name: &'static str,
    rule: Rule,
    /// `x-strip-on-error`: an invalid value is dropped, not refused.
    strip_on_error: bool,
}

/// A rule gh-aw checks a request of a type against before its fields
/// (`customValidation`).
#[derive(Debug)]
enum Custom {
    /// At least one of these fields, other than `false`.
    RequiresOneOf(&'static [&'static str]),
    /// `start_line`, where it and `line` are given, not after `line`.
    StartLineNotAfterLine,
    /// `parent_issue_number` and `sub_issue_number` not the same.
    ParentAndSubDifferent,
}

/// What the collector does with the @-mentions in a request's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mentions {
    /// Left to the applier, which knows who may be mentioned where it
    /// posts (`MENTION_AWARE_OUTPUT_TYPES`).
    Deferred,
    /// Wrapped in code, so that none notifies anyone.
    Wrapped,
}

/// An output type the collector takes: its default count, fields and
/// custom rule as gh-aw's `validation.json` has them (a test holds them
/// to it), and what becomes of its mentions.
#[derive(Debug)]
struct OutputType {
    name: &'static str,
    default_max: u32,
    mentions: Mentions,
    /// `collapseData`, which applies only to `data`, never enabled here:
    /// only the test holding the table to `validation.json` reads it.
    #[cfg_attr(not(test), allow(dead_code))]
    collapse_data: bool,
    custom: Option<Custom>,
    /// In `validation.json`'s order: the first field refused is the one
    /// reported.
    fields: &'static [Field],
}

static TEMPORARY_ID: LazyLock<Pattern> =
    LazyLock::new(|| Pattern::new("^#?aw_[A-Za-z0-9_]{3,12}$"));
static PROJECT: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(r"^(https://[^/]+/(orgs|users)/[^/]+/projects/\d+|#?aw_[A-Za-z0-9_]{3,12})$")
});
static TARGET_REPO: LazyLock<Pattern> =
    LazyLock::new(|| Pattern::new("^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$"));

const PROJECT_ERROR: &str = "must be a full GitHub project URL (e.g., \
    https://github.com/orgs/myorg/projects/42) or temporary project ID (e.g., #aw_project1)";
const NODE_ID_HINT: &str = "GraphQL node ID string (e.g. 'IC_kwDOABCD123456'); numeric REST \
    comment IDs are accepted but may not resolve for all comment types (e.g. PR review comments)";

const OPERATIONS: &[&str] = &["replace", "append", "prepend", "replace-island"];

const fn field(name: &'static str, rule: Rule) -> Field {
    Field {
        name,
        rule,
        strip_on_error: false,
    }
}

const fn string(name: &'static str, text: Text) -> Field {
    field(name, Rule::Text(text))
}

const fn text(name: &'static str, max_length: usize) -> Field {
    string(
        name,
        Text {
            sanitize: true,
            max_length: Some(max_length),
            ..TEXT
        },
    )
}

const fn required_text(name: &'static str, max_length: usize) -> Field {
    string(
        name,
        Text {
            required: true,
            sanitize: true,
            max_length: Some(max_length),
            ..TEXT
        },
    )
}

/// A required body, sanitized, of at least MIN_LENGTH characters.
const fn long_body(min_length: usize) -> Field {
    string(
        "body",
        Text {
            required: true,
            sanitize: true,
            max_length: Some(MAX_BODY_LENGTH),
            min_length: Some(min_length),
            ..TEXT
        },
    )
}

/// A string passed on as it is, its `maxLength` unused (gh-aw applies it
/// only when sanitizing).
const fn raw_text(name: &'static str, max_length: usize) -> Field {
    string(
        name,
        Text {
            max_length: Some(max_length),
            ..TEXT
        },
    )
}

/// A required string, passed on as it is.
const fn required_raw(name: &'static str) -> Field {
    string(
        name,
        Text {
            required: true,
            ..TEXT
        },
    )
}

const fn choice(name: &'static str, choices: &'static [&'static str]) -> Field {
    string(
        name,
        Text {
            choices: Some(choices),
            ..TEXT
        },
    )
}

const fn pattern(name: &'static str, pattern: &'static LazyLock<Pattern>) -> Field {
    string(
        name,
        Text {
            pattern: Some(pattern),
            ..TEXT
        },
    )
}

const fn positive(name: &'static str) -> Field {
    field(
        name,
        Rule::PositiveInteger {
            required: false,
            allow_null: false,
        },
    )
}

const fn required_positive(name: &'static str) -> Field {
    field(
        name,
        Rule::PositiveInteger {
            required: true,
            allow_null: false,
        },
    )
}

const fn number(name: &'static str) -> Field {
    field(name, Rule::IssueOrPrNumber)
}

const fn flag(name: &'static str) -> Field {
    field(name, Rule::Flag)
}

const fn repo() -> Field {
    raw_text("repo", 256)
}

/// An enrichment field gh-aw drops where it is invalid.
const fn stripped(mut field: Field) -> Field {
    field.strip_on_error = true;
    field
}

const fn as_is(name: &'static str, type_name: Option<&'static str>) -> Field {
    field(
        name,
        Rule::AsIs {
            type_name,
            unapplied_max: None,
        },
    )
}

/// An output type of no custom rule nor `collapseData`.
const fn output(
    name: &'static str,
    default_max: u32,
    mentions: Mentions,
    fields: &'static [Field],
) -> OutputType {
    OutputType {
        name,
        default_max,
        mentions,
        collapse_data: false,
        custom: None,
        fields,
    }
}

const fn with_custom(mut of: OutputType, custom: Custom) -> OutputType {
    of.custom = Some(custom);
    of
}

/// The fields of the types whose rules name a pattern, which a
/// constant expression in a call cannot borrow.
const PULL_REQUEST_FIELDS: &[Field] = &[
    text("base", 128),
    required_text("body", MAX_BODY_LENGTH),
    required_text("branch", 256),
    field("dependencies", Rule::TextList(256)),
    flag("draft"),
    field("labels", Rule::TextList(128)),
    repo(),
    positive("stack_position"),
    text("stack_root", 256),
    pattern("temporary_id", &TEMPORARY_ID),
    required_text("title", 128),
];

const COMMENT_FIELDS: &[Field] = &[
    required_text("body", MAX_BODY_LENGTH),
    positive("comment_id"),
    number("item_number"),
    number("pr"),
    number("pr_number"),
    raw_text("reply_to_id", 256),
    repo(),
    choice("target", &["status"]),
    pattern("temporary_id", &TEMPORARY_ID),
];

const PROJECT_FIELDS: &[Field] = &[
    field(
        "content_number",
        Rule::IssueOrTemporaryId { required: false },
    ),
    choice("content_type", &["issue", "pull_request", "draft_issue"]),
    flag("create_if_missing"),
    text("draft_body", MAX_BODY_LENGTH),
    pattern("draft_issue_id", &TEMPORARY_ID),
    text("draft_title", 256),
    field("field_definitions", Rule::List),
    as_is("fields", Some("object")),
    positive("issue"),
    choice("operation", &["create_fields", "create_view"]),
    string(
        "project",
        Text {
            required: true,
            sanitize: true,
            max_length: Some(512),
            pattern: Some(&PROJECT),
            pattern_error: Some(PROJECT_ERROR),
            ..TEXT
        },
    ),
    positive("pull_request"),
    pattern("target_repo", &TARGET_REPO),
    pattern("temporary_id", &TEMPORARY_ID),
    as_is("view", Some("object")),
];

/// The output types that are collected: those of `validation.json`, in
/// its order, which are all those a policy may allow (a test holds them
/// to both).
const TYPES: &[OutputType] = &[
    output(
        "create_pull_request",
        1,
        Mentions::Deferred,
        PULL_REQUEST_FIELDS,
    ),
    output("add_comment", 1, Mentions::Deferred, COMMENT_FIELDS),
    OutputType {
        collapse_data: true,
        ..output(
            "create_issue",
            1,
            Mentions::Deferred,
            &[
                as_is("blocked_by", None),
                long_body(20),
                field("fields", Rule::List),
                field("labels", Rule::LabelList(MAX_LABEL_LENGTH)),
                number("parent"),
                repo(),
                string("temporary_id", TEXT),
                required_text("title", 128),
            ],
        )
    },
    output(
        "create_discussion",
        1,
        Mentions::Deferred,
        &[
            long_body(64),
            text("category", 128),
            repo(),
            required_text("title", 128),
        ],
    ),
    output(
        HIDE_COMMENT,
        5,
        Mentions::Wrapped,
        &[
            string(
                "comment_id",
                Text {
                    required: true,
                    max_length: Some(256),
                    type_hint: Some(NODE_ID_HINT),
                    ..TEXT
                },
            ),
            choice("reason", HIDE_REASONS),
            repo(),
        ],
    ),
    with_custom(
        output(
            CREATE_REVIEW_COMMENT,
            1,
            Mentions::Deferred,
            &[
                required_text("body", MAX_BODY_LENGTH),
                required_positive("line"),
                required_raw("path"),
                positive("pull_request_number"),
                repo(),
                choice("side", &["LEFT", "RIGHT"]),
                positive("start_line"),
            ],
        ),
        Custom::StartLineNotAfterLine,
    ),
    output(
        REPLY_TO_REVIEW_COMMENT,
        10,
        Mentions::Deferred,
        &[
            required_text("body", MAX_BODY_LENGTH),
            required_positive("comment_id"),
            positive("pull_request_number"),
            repo(),
        ],
    ),
    output(
        RESOLVE_REVIEW_THREAD,
        10,
        Mentions::Wrapped,
        &[required_raw("thread_id")],
    ),
    output(
        "close_issue",
        1,
        Mentions::Wrapped,
        &[
            text("body", MAX_BODY_LENGTH),
            stripped(choice("confidence", CONFIDENCES)),
            number("duplicate_of"),
            positive("issue_number"),
            stripped(text("rationale", MAX_RATIONALE_LENGTH)),
            repo(),
            choice("state_reason", &["completed", "not_planned", "duplicate"]),
            flag("suggest"),
        ],
    ),
    output(
        "add_labels",
        5,
        Mentions::Wrapped,
        &[
            field("item_number", Rule::IssueOrTemporaryId { required: false }),
            field("labels", Rule::IntentLabels { required: true }),
            repo(),
        ],
    ),
    output(
        "remove_labels",
        5,
        Mentions::Wrapped,
        &[
            field("item_number", Rule::IssueOrTemporaryId { required: false }),
            field("labels", Rule::IntentLabels { required: true }),
            repo(),
        ],
    ),
    with_custom(
        output(
            "update_issue",
            1,
            Mentions::Wrapped,
            &[
                field("assignees", Rule::TextList(39)),
                text("body", MAX_BODY_LENGTH),
                number("issue_number"),
                field("labels", Rule::IntentLabels { required: false }),
                field(
                    "milestone",
                    Rule::PositiveInteger {
                        required: false,
                        allow_null: true,
                    },
                ),
                choice("operation", OPERATIONS),
                repo(),
                choice("status", &["open", "closed"]),
                text("title", 128),
            ],
        ),
        Custom::RequiresOneOf(&[
            "status",
            "title",
            "body",
            "labels",
            "assignees",
            "milestone",
        ]),
    ),
    with_custom(
        output(
            "update_pull_request",
            1,
            Mentions::Wrapped,
            &[
                text("body", MAX_BODY_LENGTH),
                flag("draft"),
                choice("operation", OPERATIONS),
                number("pr"),
                number("pr_number"),
                number("pull_request_number"),
                repo(),
                text("title", 256),
                flag("update_branch"),
            ],
        ),
        Custom::RequiresOneOf(&["title", "body", "update_branch"]),
    ),
    output(
        MARK_READY,
        1,
        Mentions::Wrapped,
        &[
            number("pull_request_number"),
            required_text("reason", MAX_BODY_LENGTH),
            repo(),
        ],
    ),
    with_custom(
        output(
            "add_reviewer",
            3,
            Mentions::Wrapped,
            &[
                number("pull_request_number"),
                repo(),
                field("reviewers", Rule::TextList(39)),
                field("team_reviewers", Rule::TextList(100)),
            ],
        ),
        Custom::RequiresOneOf(&["reviewers", "team_reviewers"]),
    ),
    output(
        "assign_to_user",
        1,
        Mentions::Wrapped,
        &[
            text("assignee", 39),
            field(
                "assignees",
                Rule::AsIs {
                    type_name: Some("[]string"),
                    unapplied_max: Some(39),
                },
            ),
            stripped(choice("confidence", CONFIDENCES)),
            number("issue_number"),
            stripped(text("rationale", MAX_RATIONALE_LENGTH)),
            repo(),
            flag("suggest"),
        ],
    ),
    output(
        "close_pull_request",
        1,
        Mentions::Wrapped,
        &[
            required_text("body", MAX_BODY_LENGTH),
            positive("pull_request_number"),
            repo(),
        ],
    ),
    with_custom(
        output(
            "link_sub_issue",
            5,
            Mentions::Wrapped,
            &[
                field(
                    "parent_issue_number",
                    Rule::IssueOrTemporaryId { required: true },
                ),
                repo(),
                field(
                    "sub_issue_number",
                    Rule::IssueOrTemporaryId { required: true },
                ),
            ],
        ),
        Custom::ParentAndSubDifferent,
    ),
    output(
        "create_check_run",
        1,
        Mentions::Wrapped,
        &[
            string(
                "conclusion",
                Text {
                    required: true,
                    choices: Some(&[
                        "success",
                        "failure",
                        "neutral",
                        "cancelled",
                        "skipped",
                        "timed_out",
                        "action_required",
                    ]),
                    ..TEXT
                },
            ),
            number("pr"),
            number("pr_number"),
            number("pull_number"),
            number("pull_request_number"),
            required_text("summary", MAX_BODY_LENGTH),
            text("text", MAX_BODY_LENGTH),
            required_text("title", 256),
        ],
    ),
    output("update_project", 10, Mentions::Wrapped, PROJECT_FIELDS),
    output(
        PUSH_TO_PULL_REQUEST_BRANCH,
        1,
        Mentions::Wrapped,
        &[
            text("branch", 256),
            required_text("message", MAX_BODY_LENGTH),
            number("pull_request_number"),
            repo(),
        ],
    ),
    output(
        "noop",
        2,
        Mentions::Wrapped,
        &[required_text("message", MAX_BODY_LENGTH)],
    ),
    output(
        "missing_tool",
        20,
        Mentions::Wrapped,
        &[
            text("alternatives", 512),
            required_text("reason", 256),
            text("tool", 128),
        ],
    ),
    output(
        "missing_data",
        20,
        Mentions::Wrapped,
        &[
            text("alternatives", 256),
            text("context", 256),
            text("data_type", 128),
            text("reason", 256),
        ],
    ),
];

/// The `noop` messages gh-aw takes for an agent trying the tool out, and
/// drops without counting (`intent_probe.cjs`).
const PROBE_MESSAGES: &[&str] = &[
    "test",
    "testing",
    "test no base",
    "probe",
    "placeholder",
    "dummy",
    "temp",
    "temporary",
    "todo",
    "tbd",
    "wip",
    "example",
];

impl Text {
    fn to_json(self) -> Map<String, Value> {
        let mut rule = Map::new();
        if self.required {
            rule.insert("required".into(), true.into());
        }
        rule.insert("type".into(), "string".into());
        if self.sanitize {
            rule.insert("sanitize".into(), true.into());
        }
        if let Some(max) = self.max_length {
            rule.insert("maxLength".into(), max.into());
        }
        if let Some(min) = self.min_length {
            rule.insert("minLength".into(), min.into());
        }
        if let Some(pattern) = self.pattern {
            rule.insert("pattern".into(), pattern.source.into());
        }
        if let Some(error) = self.pattern_error {
            rule.insert("patternError".into(), error.into());
        }
        if let Some(choices) = self.choices {
            rule.insert("enum".into(), choices.into());
        }
        if let Some(hint) = self.type_hint {
            rule.insert("typeHint".into(), hint.into());
        }
        rule
    }

    fn describe(self) -> String {
        let mut what = match self.choices {
            Some(choices) => format!("one of: {}", choices.join(", ")),
            None => "string".to_owned(),
        };
        if let Some(pattern) = self.pattern {
            what.push_str(&format!(" matching `{}`", pattern.source));
        }
        if self.required {
            what.push_str(", required");
        }
        // The length is kept to only where the text is sanitized.
        if let (true, Some(max)) = (self.sanitize, self.max_length) {
            what.push_str(&format!(", cut to {max} characters"));
        }
        if let Some(min) = self.min_length {
            what.push_str(&format!(", at least {min} characters"));
        }
        what
    }
}

impl Rule {
    fn required(&self) -> bool {
        match self {
            Self::Text(text) => text.required,
            Self::PositiveInteger { required, .. }
            | Self::IssueOrTemporaryId { required }
            | Self::IntentLabels { required } => *required,
            _ => false,
        }
    }

    /// The rule as gh-aw's `validation.json` writes it.
    fn to_json(&self) -> Map<String, Value> {
        let value = match self {
            Self::Text(text) => return text.to_json(),
            Self::Flag => json!({"type": "boolean"}),
            Self::PositiveInteger {
                required: true,
                allow_null,
            } => {
                debug_assert!(!allow_null);
                json!({"required": true, "positiveInteger": true})
            }
            Self::PositiveInteger {
                required: false,
                allow_null: false,
            } => json!({"optionalPositiveInteger": true}),
            Self::PositiveInteger {
                required: false,
                allow_null: true,
            } => json!({"optionalPositiveInteger": true, "allowNull": true}),
            Self::IssueOrPrNumber => json!({"issueOrPRNumber": true}),
            Self::IssueOrTemporaryId { required: true } => {
                json!({"required": true, "issueNumberOrTemporaryId": true})
            }
            Self::IssueOrTemporaryId { required: false } => {
                json!({"issueNumberOrTemporaryId": true})
            }
            Self::TextList(max) | Self::LabelList(max) => json!({
                "type": "array", "itemType": "string", "itemSanitize": true, "itemMaxLength": max
            }),
            Self::IntentLabels { required: true } => json!({"required": true, "type": "array"}),
            Self::IntentLabels { required: false } | Self::List => json!({"type": "array"}),
            Self::AsIs {
                type_name,
                unapplied_max,
            } => {
                let mut rule = Map::new();
                if let Some(type_name) = type_name {
                    rule.insert("type".into(), (*type_name).into());
                }
                if let Some(max) = unapplied_max {
                    rule.insert("sanitize".into(), true.into());
                    rule.insert("maxLength".into(), (*max).into());
                }
                return rule;
            }
        };
        match value {
            Value::Object(rule) => rule,
            _ => unreachable!("a rule is an object"),
        }
    }

    /// What the rule wants, for the agent: [`field_guide`].
    fn describe(&self) -> String {
        let required = if self.required() { ", required" } else { "" };
        match self {
            Self::Text(text) => text.describe(),
            Self::Flag => "boolean".to_owned(),
            Self::PositiveInteger {
                allow_null: true, ..
            } => "positive integer or null".to_owned(),
            Self::PositiveInteger { .. } => format!("positive integer{required}"),
            Self::IssueOrPrNumber => "number or string".to_owned(),
            Self::IssueOrTemporaryId { .. } => {
                format!("positive integer or temporary ID `aw_…`{required}")
            }
            Self::TextList(max) => format!("list of strings, each cut to {max} characters"),
            Self::LabelList(max) => format!(
                "list of strings, each cut to {max} characters, or one string of them \
                 separated by commas"
            ),
            Self::IntentLabels { .. } => format!(
                "list of names, or of objects with a `name` and optionally a `rationale`, a \
                 `confidence` of LOW, MEDIUM or HIGH and a boolean `suggest`{required}"
            ),
            Self::List => "list".to_owned(),
            Self::AsIs {
                type_name: Some("object"),
                ..
            } => "object".to_owned(),
            Self::AsIs {
                type_name: Some(_), ..
            } => "list of strings".to_owned(),
            Self::AsIs {
                type_name: None, ..
            } => "any JSON value".to_owned(),
        }
    }
}

/// The type of a JSON value as JavaScript's `typeof` names it, but for
/// an array, as gh-aw names it.
fn js_type(value: &Value) -> &'static str {
    match value {
        Value::Null | Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
    }
}

/// Whether JavaScript takes VALUE for true.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|n| n != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// A number as JavaScript writes it, near enough for an error message.
fn js_number(n: f64) -> String {
    if n == n.trunc() && n.abs() < 1e21 {
        format!("{}", n as i128)
    } else {
        format!("{n}")
    }
}

/// JavaScript's `String(value)`, near enough for what gh-aw compares.
fn js_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => js_number(n.as_f64().unwrap_or(f64::NAN)),
        Value::String(s) => s.clone(),
        Value::Array(entries) => entries
            .iter()
            .map(|entry| match entry {
                Value::Null => String::new(),
                entry => js_string(entry),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_owned(),
    }
}

/// JavaScript's `parseInt(text, 10)`: the digits after any whitespace and
/// a sign, up to the first other character.
fn js_parse_int(text: &str) -> Option<f64> {
    let text = text.trim_start_matches(is_js_space);
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let digits = &digits[..digits.bytes().take_while(u8::is_ascii_digit).count()];
    let value: f64 = digits.parse().ok()?;
    Some(if negative { -value } else { value })
}

/// VALUE, a number or a string, as gh-aw reads it for a positive
/// integer: a string as `parseInt` does, a number as it is.
fn as_integer(value: &Value) -> Option<f64> {
    match value {
        Value::String(s) => js_parse_int(s),
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

/// N, a whole number, as JavaScript writes it, not `5.0`.
fn whole(n: f64) -> Value {
    if n < 2f64.powi(53) {
        (n as u64).into()
    } else {
        n.into()
    }
}

/// Whether N is what gh-aw takes for a positive integer.
fn is_positive_integer(n: f64) -> bool {
    n > 0.0 && n == n.trunc() && n.is_finite()
}

/// VALUE as `${value}` writes it, where it is a number or a string.
fn shown(value: &Value) -> String {
    js_string(value)
}

/// gh-aw's `isTemporaryId`, in any case. Its `/i` folds ASCII only;
/// `regex`'s `(?i)` would take `ſ` for `s` and the Kelvin sign for `k`.
fn is_temporary_id(text: &str) -> bool {
    static ID: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("^#?[aA][wW]_[A-Za-z0-9_]{3,12}$").expect("a valid pattern"));
    ID.is_match(text)
}

/// What sanitizes a text of at most a length, for a request.
type Sanitizer<'a> = dyn Fn(&str, usize) -> String + 'a;

impl Field {
    /// The rule as gh-aw's `validation.json` writes it.
    fn to_json(&self) -> Map<String, Value> {
        let mut rule = self.rule.to_json();
        if self.strip_on_error {
            rule.insert("x-strip-on-error".into(), true.into());
        }
        rule
    }

    /// How gh-aw names the rule where a value got past it unconverted:
    /// its type, else its keys.
    fn kind(&self) -> String {
        let rule = self.to_json();
        match rule.get("type").and_then(Value::as_str) {
            Some(type_name) => format!("type={type_name}"),
            None if rule.is_empty() => "unspecified".to_owned(),
            None => {
                let mut keys: Vec<&str> = rule.keys().map(String::as_str).collect();
                keys.sort_unstable();
                keys.join(",")
            }
        }
    }

    /// Whether VALUE, blank, means the field was left out: for a field
    /// that is not free text (`isBlankOptionalField`).
    fn blank_means_absent(&self, value: &Value) -> bool {
        let blank = value.as_str().is_some_and(|s| js_trim(s).is_empty());
        if !blank || self.rule.required() {
            return false;
        }
        self.name == "stack_root"
            || match &self.rule {
                Rule::Text(text) => {
                    text.pattern.is_some()
                        || text.choices.is_some()
                        || text.min_length.is_some_and(|min| min > 0)
                }
                Rule::AsIs { type_name, .. } => type_name.is_some(),
                _ => true,
            }
    }

    /// VALUE as gh-aw's `validateField` passes it on, if at all, for a
    /// request of type OF on line LINE.
    fn validate(
        &self,
        value: Option<&Value>,
        of: &OutputType,
        line: usize,
        sanitize: &Sanitizer<'_>,
    ) -> Result<Option<Value>, String> {
        let (name, type_name) = (self.name, of.name);
        let at = format!("Line {line}: {type_name} '{name}'");
        let missing =
            |kind: &str| format!("Line {line}: {type_name} requires a '{name}' field ({kind})");
        let required = self.rule.required();
        // These two word a missing value their own way.
        match self.rule {
            Rule::PositiveInteger { required: true, .. } => {
                let value = value
                    .filter(|value| !value.is_null())
                    .ok_or_else(|| format!("{at} is required"))?;
                return positive_integer(value, &at).map(Some);
            }
            Rule::IssueOrTemporaryId { .. } => {
                return match value.filter(|value| !value.is_null()) {
                    None if required => Err(format!("{at} is required")),
                    None => Ok(None),
                    Some(value) => issue_or_temporary_id(value, &at).map(Some),
                };
            }
            _ => {}
        }
        let kind = match &self.rule {
            Rule::Text(text) => text.type_hint.unwrap_or("string"),
            _ => "array",
        };
        let has_min = matches!(&self.rule, Rule::Text(text) if text.min_length.is_some());
        let value = match value {
            None | Some(Value::Null) if required => return Err(missing(kind)),
            Some(Value::String(s)) if required && !has_min && js_trim(s).is_empty() => {
                return Err(missing(kind));
            }
            Some(Value::Null)
                if matches!(
                    self.rule,
                    Rule::PositiveInteger {
                        allow_null: true,
                        ..
                    }
                ) =>
            {
                return Ok(Some(Value::Null));
            }
            None | Some(Value::Null) => return Ok(None),
            Some(value) => value,
        };
        let number_or_string = || match value {
            Value::Number(_) | Value::String(_) => Ok(()),
            _ => Err(format!("{at} must be a number or string")),
        };
        let array = || {
            value.as_array().ok_or_else(|| {
                if required {
                    missing("array")
                } else {
                    format!("{at} must be an array")
                }
            })
        };
        let strings =
            |entries: &[Value], max: usize| {
                entries
                    .iter()
                    .map(|entry| {
                        entry.as_str().map(|s| sanitize(s, max).into()).ok_or_else(|| {
                        format!("Line {line}: {type_name} {name} array must contain only strings")
                    })
                    })
                    .collect::<Result<Vec<Value>, _>>()
                    .map(|list| Some(Value::Array(list)))
            };
        match &self.rule {
            Rule::Text(text) => {
                let Value::String(value) = value else {
                    return Err(if required {
                        missing(kind)
                    } else {
                        format!("{at} must be a string")
                    });
                };
                validate_text(*text, value, &at, sanitize).map(Some)
            }
            Rule::Flag => match value {
                Value::Bool(_) => Ok(Some(value.clone())),
                _ => Err(format!("{at} must be a boolean")),
            },
            Rule::PositiveInteger { .. } => positive_integer(value, &at).map(Some),
            Rule::IssueOrPrNumber => {
                number_or_string()?;
                Ok(Some(value.clone()))
            }
            Rule::TextList(max) => strings(array()?, *max),
            Rule::LabelList(max) => match value {
                Value::String(s) => strings(&split_labels(s), *max),
                _ => strings(array()?, *max),
            },
            Rule::IntentLabels { .. } => {
                let prefix = format!("Line {line}: {type_name} {name}");
                intent_labels(array()?, &prefix, sanitize).map(Some)
            }
            Rule::List => array().map(|_| Some(value.clone())),
            Rule::AsIs { .. } => Ok(Some(value.clone())),
            Rule::IssueOrTemporaryId { .. } => unreachable!("validated above"),
        }
    }
}

/// VALUE, a string, as gh-aw's `validateField` passes it on under TEXT,
/// for the field AT.
fn validate_text(
    text: Text,
    value: &str,
    at: &str,
    sanitize: &Sanitizer<'_>,
) -> Result<Value, String> {
    if let Some(pattern) = text.pattern
        && !pattern.regex.is_match(js_trim(value))
    {
        return Err(match text.pattern_error {
            Some(error) => format!("{at} {error}"),
            None => format!("{at} must match pattern {}", pattern.source),
        });
    }
    if let Some(choices) = text.choices {
        let lower = value.to_lowercase();
        return match choices.iter().find(|choice| choice.to_lowercase() == lower) {
            Some(choice) => Ok(match (text.sanitize, text.max_length) {
                (true, Some(max)) => sanitize(choice, max).into(),
                _ => (*choice).into(),
            }),
            None if choices.len() == 2 => {
                Err(format!("{at} must be '{}' or '{}'", choices[0], choices[1]))
            }
            None => Err(format!("{at} must be one of: {}", choices.join(", "))),
        };
    }
    let value = if text.sanitize {
        sanitize(
            &markdown::unfence(value),
            text.max_length.unwrap_or(MAX_BODY_LENGTH),
        )
    } else {
        value.to_owned()
    };
    if let Some(min) = text.min_length
        && sanitize::utf16_len(js_trim(&value)) < min
    {
        return Err(format!("{at} is too short (minimum {min} characters)"));
    }
    Ok(value.into())
}

/// VALUE as `validatePositiveInteger` passes it on, for the field AT.
fn positive_integer(value: &Value, at: &str) -> Result<Value, String> {
    if !matches!(value, Value::Number(_) | Value::String(_)) {
        return Err(format!("{at} must be a number or string"));
    }
    match as_integer(value) {
        Some(n) if is_positive_integer(n) => Ok(whole(n)),
        _ => Err(format!(
            "{at} must be a valid positive integer (got: {})",
            shown(value)
        )),
    }
}

/// VALUE as `validateIssueNumberOrTemporaryId` passes it on, for the
/// field AT.
fn issue_or_temporary_id(value: &Value, at: &str) -> Result<Value, String> {
    if !matches!(value, Value::Number(_) | Value::String(_)) {
        return Err(format!("{at} must be a number or string"));
    }
    if let Value::String(id) = value
        && is_temporary_id(id)
    {
        return Ok(format!("#{}", id.strip_prefix('#').unwrap_or(id).to_lowercase()).into());
    }
    match as_integer(value) {
        Some(n) if is_positive_integer(n) => Ok(whole(n)),
        _ => Err(format!(
            "{at} must be a positive integer or temporary ID (got: {})",
            shown(value)
        )),
    }
}

/// `create_issue`'s labels written as one string, as gh-aw reads them: a
/// JSON array's strings, or else the names between commas.
fn split_labels(text: &str) -> Vec<Value> {
    let trimmed = js_trim(text);
    if trimmed.starts_with('[')
        && let Ok(Value::Array(entries)) = serde_json::from_str::<Value>(trimmed)
    {
        return entries.into_iter().filter(Value::is_string).collect();
    }
    text.split(',')
        .map(js_trim)
        .filter(|name| !name.is_empty())
        .map(Value::from)
        .collect()
}

/// LABELS as `validateIssueIntentLabels` passes them on; PREFIX names the
/// field in a refusal.
fn intent_labels(
    labels: &[Value],
    prefix: &str,
    sanitize: &Sanitizer<'_>,
) -> Result<Value, String> {
    let mut normalized = Vec::with_capacity(labels.len());
    for (index, label) in labels.iter().enumerate() {
        let at = format!("{prefix}[{index}]");
        let label = match label {
            Value::String(name) => {
                let name = sanitize(name, MAX_LABEL_LENGTH);
                if name.is_empty() {
                    return Err(format!("{at} must be a non-empty string"));
                }
                normalized.push(name.into());
                continue;
            }
            Value::Object(label) => label,
            _ => return Err(format!("{at} must be a string or an object with 'name'")),
        };
        let unsupported: Vec<&str> = label
            .keys()
            .map(String::as_str)
            .filter(|key| !LABEL_KEYS.contains(key))
            .collect();
        if !unsupported.is_empty() {
            return Err(format!(
                "{at} contains unsupported fields: {}",
                unsupported.join(", ")
            ));
        }
        let Some(Value::String(name)) = label.get("name") else {
            return Err(format!("{at}.name must be a string"));
        };
        let name = sanitize(name, MAX_LABEL_LENGTH);
        if name.is_empty() {
            return Err(format!("{at}.name must be a non-empty string"));
        }
        let mut out = Map::new();
        out.insert("name".into(), name.into());
        // A rationale or confidence that is not one is dropped.
        if let Some(Value::String(rationale)) = label.get("rationale") {
            let rationale = sanitize(&markdown::unfence(rationale), MAX_RATIONALE_LENGTH);
            let rationale = sanitize::utf16_prefix(js_trim(&rationale), MAX_RATIONALE_LENGTH);
            if !rationale.is_empty() {
                out.insert("rationale".into(), rationale.into());
            }
        }
        match label.get("confidence") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if s.is_empty() => {}
            Some(confidence) => {
                let confidence = js_trim(&js_string(confidence)).to_uppercase();
                if CONFIDENCES.contains(&confidence.as_str()) {
                    out.insert("confidence".into(), confidence.into());
                }
            }
        }
        match label.get("suggest") {
            None | Some(Value::Bool(false)) => {}
            Some(Value::Bool(true)) => {
                out.insert("suggest".into(), true.into());
            }
            Some(_) => return Err(format!("{at}.suggest must be a boolean")),
        }
        normalized.push(Value::Object(out));
    }
    Ok(Value::Array(normalized))
}

impl Custom {
    /// The rule as `validation.json` names it.
    #[cfg(test)]
    fn to_json(&self) -> String {
        match self {
            Self::RequiresOneOf(fields) => format!("requiresOneOf:{}", fields.join(",")),
            Self::StartLineNotAfterLine => "startLineLessOrEqualLine".to_owned(),
            Self::ParentAndSubDifferent => "parentAndSubDifferent".to_owned(),
        }
    }

    /// Whether ITEM, a request of type TYPE_NAME on line LINE, keeps the
    /// rule (`executeCustomValidation`).
    fn check(&self, item: &Map<String, Value>, type_name: &str, line: usize) -> Result<(), String> {
        match self {
            Self::RequiresOneOf(fields) => {
                if fields
                    .iter()
                    .any(|field| item.get(*field).is_some_and(|v| *v != Value::Bool(false)))
                {
                    return Ok(());
                }
                let fields: Vec<String> = fields.iter().map(|f| format!("'{f}'")).collect();
                Err(format!(
                    "Line {line}: {type_name} requires at least one of: {} fields",
                    fields.join(", ")
                ))
            }
            // gh-aw compares any two values as JavaScript does; where one
            // is neither a number nor a string, this leaves it to the
            // fields' rules, which refuse it: the reason can differ, never
            // whether the request is refused.
            Self::StartLineNotAfterLine => {
                let start = item.get("start_line").and_then(as_integer);
                let end = item.get("line").and_then(as_integer);
                match (start, end) {
                    (Some(start), Some(end)) if start > end => Err(format!(
                        "Line {line}: {type_name} 'start_line' must be less than or equal to 'line'"
                    )),
                    _ => Ok(()),
                }
            }
            Self::ParentAndSubDifferent => {
                let (parent, sub) = (
                    item.get("parent_issue_number"),
                    item.get("sub_issue_number"),
                );
                // JavaScript's `===`, strings in any case: two missing are
                // the same, two arrays or objects never are.
                let same = match (parent, sub) {
                    (None, None) => true,
                    (Some(Value::String(a)), Some(Value::String(b))) => {
                        a.to_lowercase() == b.to_lowercase()
                    }
                    (Some(Value::Number(a)), Some(Value::Number(b))) => a.as_f64() == b.as_f64(),
                    (Some(Value::Null), Some(Value::Null)) => true,
                    (Some(Value::Bool(a)), Some(Value::Bool(b))) => a == b,
                    _ => false,
                };
                if same {
                    Err(format!(
                        "Line {line}: {type_name} 'parent_issue_number' and 'sub_issue_number' \
                         must be different"
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl OutputType {
    /// ITEM, from line LINE, as gh-aw's `validateItem` passes it on: its
    /// type and its fields, each validated, and nothing else.
    fn validate(
        &self,
        item: &Map<String, Value>,
        line: usize,
        keeps_link: &dyn Fn(&str) -> bool,
    ) -> Result<Map<String, Value>, String> {
        // `normalizeBlankOptionalFields`, before the custom rule too.
        let mut item = item.clone();
        for field in self.fields {
            if item
                .get(field.name)
                .is_some_and(|value| field.blank_means_absent(value))
            {
                item.remove(field.name);
            }
        }
        if let Some(custom) = &self.custom {
            custom.check(&item, self.name, line)?;
        }
        let sanitize = |text: &str, max: usize| {
            sanitize::sanitize(text, max, self.mentions == Mentions::Wrapped, keeps_link)
        };
        let mut validated = Map::new();
        validated.insert("type".into(), self.name.into());
        let mut first_error = None;
        for field in self.fields {
            let value = item.get(field.name);
            match field.validate(value, self, line, &sanitize) {
                Ok(Some(valid)) => {
                    validated.insert(field.name.into(), valid);
                }
                Ok(None) => {
                    if let Some(value) = value {
                        first_error.get_or_insert_with(|| {
                            format!(
                                "Line {line}: {} '{}' validation ({}) accepted {} but did not \
                                 produce a normalized value",
                                self.name,
                                field.name,
                                field.kind(),
                                js_type(value)
                            )
                        });
                    }
                }
                Err(_) if field.strip_on_error && !field.rule.required() => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        if item.contains_key("data") {
            return Err(format!(
                "Line {line}: {} 'data' is not enabled (set safe-outputs.data in workflow \
                 frontmatter)",
                self.name
            ));
        }
        Ok(validated)
    }
}

/// The fields of the output type NAME, as [`collect`] validates them, for
/// the agent's guide: `` `body` (string, required, …), `item_number`
/// (number or string) ``. None for a type it does not validate.
pub fn field_guide(name: &str) -> Option<String> {
    let of = TYPES.iter().find(|of| of.name == name)?;
    let fields: Vec<String> = of
        .fields
        .iter()
        .map(|field| format!("`{}` ({})", field.name, field.rule.describe()))
        .collect();
    Some(fields.join(", "))
}

/// The types POLICY allows that [`collect`] does not validate.
pub fn unported(policy: &Policy) -> Vec<&str> {
    policy
        .safe_outputs
        .types()
        .filter(|name| !TYPES.iter().any(|of| of.name == *name))
        .collect()
}

/// The configuration the collector is given for POLICY: its
/// `safe_outputs`, with its secondary pull request's `max` added to
/// `create_pull_request`'s, since the collector counts a pull request of
/// either repository alike; `check` counts each against its own.
pub fn config(policy: &Policy) -> Result<Map<String, Value>> {
    let Value::Object(mut config) = serde_json::to_value(&policy.safe_outputs)? else {
        bail!("the policy's safe_outputs is not an object");
    };
    if let Some(secondary) = &policy.secondary_pull_request
        && let Some(Value::Object(pull)) = config.get_mut("create_pull_request")
    {
        let max = pull.get("max").and_then(Value::as_u64).unwrap_or(0);
        pull.insert("max".into(), (max + u64::from(secondary.max)).into());
    }
    Ok(config)
}

/// What [`collect`] makes of the `outputs.jsonl` in OUTPUTS under
/// POLICY: none at all if there is none, as gh-aw's collector takes a
/// missing file.
pub fn collect_dir(outputs: &Path, policy: &Policy, unported: Unported) -> Result<Collected> {
    let path = outputs.join(OUTPUTS_FILE);
    let text = match files::read_regular(&path, MAX_OUTPUTS_BYTES) {
        Ok(bytes) => {
            String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))?
        }
        Err(ReadError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => bail!("{} {err}", path.display()),
    };
    Ok(collect(
        &text,
        &config(policy)?,
        &|host| policy.keeps_link_to(host),
        unported,
    ))
}

/// Whether a `noop`'s MESSAGE is an agent trying the tool out.
fn is_probe(message: Option<&Value>) -> bool {
    let Some(Value::String(message)) = message else {
        return false;
    };
    let words: Vec<&str> = message
        .split(is_js_space)
        .filter(|w| !w.is_empty())
        .collect();
    PROBE_MESSAGES.contains(&words.join(" ").to_lowercase().as_str())
}

/// What gh-aw's collector makes of TEXT, the lines of an `outputs.jsonl`,
/// under CONFIG, the policy's `safe_outputs` as its `config.json`, with
/// https links kept to the hosts KEEPS_LINK takes.
pub fn collect(
    text: &str,
    config: &Map<String, Value>,
    keeps_link: &dyn Fn(&str) -> bool,
    unported: Unported,
) -> Collected {
    let config: Map<String, Value> = config
        .iter()
        .map(|(name, value)| (name.replace('-', "_"), value.clone()))
        .collect();
    let mut collected = Collected::default();
    for (index, line) in js_trim(text).split('\n').enumerate() {
        let line_text = js_trim(line);
        if line_text.is_empty() {
            continue;
        }
        let taken = &collected.items;
        match request(index + 1, line_text, &config, taken, keeps_link, unported) {
            Ok(Some(item)) => collected.items.push(item),
            Ok(None) => {}
            Err(error) => collected.errors.push(error),
        }
    }
    collected
}

/// The request on line LINE, TEXT, validated, if it is not dropped, or
/// why it is refused, given the requests TAKEN before it.
fn request(
    line: usize,
    text: &str,
    config: &Map<String, Value>,
    taken: &[Map<String, Value>],
    keeps_link: &dyn Fn(&str) -> bool,
    unported: Unported,
) -> Result<Option<Map<String, Value>>, String> {
    let item: Map<String, Value> = match serde_json::from_str(text) {
        Ok(Value::Object(item)) => item,
        Ok(_) => return Err(format!("Line {line}: Missing required 'type' field")),
        Err(err) => return Err(format!("Line {line}: Invalid JSON - {err}")),
    };
    let kind = match item.get("type") {
        Some(Value::String(kind)) if !kind.is_empty() => kind.replace('-', "_"),
        Some(kind) if truthy(kind) => {
            return Err(format!(
                "Line {line}: Invalid JSON - 'type' is not a string"
            ));
        }
        _ => return Err(format!("Line {line}: Missing required 'type' field")),
    };
    let Some(limits) = config.get(&kind).filter(|limits| truthy(limits)) else {
        let expected: Vec<&str> = config.keys().map(String::as_str).collect();
        return Err(format!(
            "Line {line}: Unexpected output type '{kind}'. Expected one of: {}",
            expected.join(", ")
        ));
    };
    if kind == "noop" && is_probe(item.get("message")) {
        return Ok(None);
    }
    let of = TYPES.iter().find(|of| of.name == kind);
    let max = limits
        .get("max")
        .filter(|max| truthy(max))
        .and_then(Value::as_f64)
        .unwrap_or_else(|| of.map_or(1.0, |of| f64::from(of.default_max)));
    let count = taken.iter().filter(|item| item["type"] == kind).count();
    if count as f64 >= max {
        return Err(format!(
            "Line {line}: Too many items of type '{kind}'. Maximum allowed: {}.",
            js_number(max)
        ));
    }
    let Some(of) = of else {
        if unported == Unported::PassOn {
            let mut item = item;
            item.insert("type".into(), kind.into());
            return Ok(Some(item));
        }
        let known: Vec<&str> = TYPES.iter().map(|of| of.name).collect();
        return Err(format!(
            "Line {line}: Unsupported output type '{kind}': agentic-job collect validates only {}",
            known.join(", ")
        ));
    };
    of.validate(&item, line, keeps_link).map(Some)
}

pub fn run(args: &Args) -> Result<Exit> {
    let policy = Policy::load(&args.policy)?;
    let (Some(outputs), Some(path)) = (&args.outputs, &args.collected) else {
        for name in unported(&policy) {
            println!("{name}");
        }
        return Ok(Exit::Success);
    };
    let collected = collect_dir(outputs, &policy, Unported::Refuse)?;
    let json = serde_json::to_string(&collected).context("writing what was collected")?;
    std::fs::write(path, json + "\n").with_context(|| format!("writing {}", path.display()))?;
    for error in &collected.errors {
        eprintln!("error: {}", crate::run::enter::one_line(error));
    }
    Ok(if collected.errors.is_empty() {
        Exit::Success
    } else {
        Exit::Failure
    })
}

#[cfg(test)]
mod tests;
