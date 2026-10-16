//! What a run hands back, as gh-aw's safe outputs: the requests the agent
//! wrote (JSON Lines, [`AGENT_OUTPUTS`] in its home), and for a pull
//! request a patch of its working tree. The patch is made here and not
//! taken from the agent, the way gh-aw's own server makes one from the
//! git state: `git format-patch` of one commit against the commit the run
//! started from, with gh-aw's base-commit header.
//!
//! Everything here is the agent's: its lines, its files, its checkout and
//! that checkout's git configuration. So every file is read and every git
//! command run through a [`Runner`], which in a run is the sandbox user: a
//! link the agent planted then reaches only what the agent could read
//! anyway. Nothing is trusted for being written here either; `check`
//! reads all of it again on another machine.
//!
//! One thing differs from the old tree's `handback.mjs` on purpose. There
//! the commit's message was the pull request's title alone, and a worker
//! on the operator's machine wrote the real one when it applied the
//! change. Nobody does that for a change applied by a job, so the message
//! is the title and body of the pull request's request, with the
//! configured trailers.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::clone::{self, Checkout};
use super::enter::Runner;
use crate::check::checkpoint::Checkpoint;
use crate::check::{BASE_COMMIT_HEADER, BASE_FILE, OUTPUTS_FILE, patch_file_name};
use crate::config;
use crate::policy::{CREATE_PULL_REQUEST, Kind, PUSH_TO_PULL_REQUEST_BRANCH, Policy};
use crate::session::{Outcome, RunResult};

/// Under the sandbox user's home: the agent's requests, and its own
/// account of the run.
pub const AGENT_OUTPUTS: &str = "out/safe-outputs.jsonl";
pub const AGENT_OUTCOME: &str = "out/outcome.json";
/// Under the sandbox user's home: a whole series of commits that replaces
/// a pull request's branch.
const REPLACEMENT_PATH: &str = "out/replacement.json";
/// The largest of each that is taken. `check` refuses a bigger requests
/// file as well.
pub const MAX_OUTPUTS_BYTES: usize = 1 << 20;
pub const MAX_OUTCOME_BYTES: usize = 64 << 10;
/// The most lines of the requests file that are passed on.
pub const MAX_LINES: usize = 1000;
/// The file of the run's results that holds the agent's outcome.
pub const OUTCOME_FILE: &str = "outcome.json";
/// Where the outcome names the untracked binary files left out of the patch.
pub const OMITTED_BINARY_FILES: &str = "omitted_untracked_binary_files";
/// Who the commit is by, unless `[commit] author` says.
pub const DEFAULT_AUTHOR: (&str, &str) = ("agent", "agent@localhost");

const MAX_TITLE_CHARS: usize = 100;
const MAX_REASON_CHARS: usize = 200;
/// What a pull request made up for an agent that wrote no summary says.
const NO_SUMMARY: &str = "Partial change: the agent did not say what it did or that it was done.";
/// A subject longer than this is cut: it is one line of a mail header.
const MAX_SUBJECT_CHARS: usize = 200;
/// What `git status` may write: the names of the changed files.
const MAX_STATUS_BYTES: usize = 8 << 20;
const MAX_GIT_OUTPUT: usize = 4096;
/// How long one git command, or the reading of one file, may take.
const GIT_TIMEOUT_S: &str = "120";
const READ_TIMEOUT_S: &str = "30";
/// Put before a line of the message that git or `check` would take for
/// the start of a patch or of a mail.
const QUOTE: &str = "    ";
/// Git on the agent's checkout: none of its hooks or its file monitor,
/// and no signing. The rest of the checkout's configuration, and of the
/// sandbox user's own, stays in force: git runs as the agent, so it
/// gives the agent nothing it did not have. What of it would change
/// the commit or the mail made of it is overridden where they are made:
/// the identity by [`IDENTITY_VARS`], the mail by [`FORMAT_PATCH`].
const GIT_SETTINGS: &[&str] = &[
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "commit.gpgsign=false",
];
/// Who a commit is by, as git takes it from its environment: over
/// anything the checkout's configuration says (`author.name`, for one,
/// which `-c user.name=` would not override).
const IDENTITY_VARS: [(&str, bool); 4] = [
    ("GIT_AUTHOR_NAME", true),
    ("GIT_AUTHOR_EMAIL", false),
    ("GIT_COMMITTER_NAME", true),
    ("GIT_COMMITTER_EMAIL", false),
];
/// The patch, as `format-patch` writes one with no configuration. Each
/// option after the first four takes back a setting of the checkout's
/// that would change the mail: headers of the agent's own (a second
/// `From:` or `Date:`, which `git am` takes over the first), a sign-off
/// in the configured author's name, another sender, recipients, an
/// attachment, a numbered or renamed subject, threading, a base.
pub(crate) const FORMAT_PATCH: &[&str] = &[
    "format-patch",
    "--stdout",
    "--no-renames",
    "--no-signature",
    "--no-add-header",
    "--no-to",
    "--no-cc",
    "--no-from",
    "--no-signoff",
    "--no-attach",
    "--no-thread",
    "--no-numbered",
    "--no-cover-letter",
    "--no-base",
    "--subject-prefix=PATCH",
    "-1",
    "HEAD",
];
/// What starts a line that git reads as a subject in the body of a mail.
const IN_BODY_SUBJECT: &str = "[PATCH";
/// The headers of a mail that git reads from the start of its body as
/// well, and takes over the mail's own: who the commit is by, when, and
/// its subject.
const IN_BODY_HEADERS: [&str; 3] = ["from", "subject", "date"];
/// A line of the agent's that would read as somebody's sign-off of the
/// commit. Nobody signed off what an agent wrote.
const SIGN_OFF: &str = "signed-off-by:";
/// Reads the regular file `$1`, at most `$2` bytes of it. A link is not
/// followed, though as the sandbox user it could only name what the
/// agent can read: what is handed back is a file the agent wrote.
const READ_SCRIPT: &str = r#"test ! -L "$1" && test -f "$1" && exec head -c "$2" -- "$1""#;
/// Runs the command it is given and passes on at most `$1` bytes of what
/// it writes, so that too much output is cut and not an error. The
/// command's own status is the last line of standard error: a pipe's is
/// that of `head`.
const LIMIT_SCRIPT: &str = r#"limit=$1; shift; { "$@"; echo "$?" >&2; } | head -c "$limit""#;

/// The branch a run's pull request is on, which also names its patch.
pub fn run_branch(run_id: &str) -> String {
    format!("agent-run-{run_id}")
}

/// TEXT with every run of whitespace as one space.
fn squeeze(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn cut(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

/// Squeezed TEXT cut to MAX_CHARS at the last space within them, so that
/// no word is cut in two; a first word longer than that is cut anyway.
fn cut_words(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_owned();
    }
    let kept = cut(text, max_chars + 1);
    match kept.rfind(' ') {
        Some(space) if space > 0 => kept[..space].to_owned(),
        _ => cut(text, max_chars),
    }
}

/// A JSON object with its keys in the order they were written. The
/// agent's own request is passed on with one field changed, and should
/// otherwise read as the agent wrote it. Objects inside it are not kept
/// in order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Object(Vec<(String, Value)>);

impl Object {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0
            .iter()
            .find_map(|(name, value)| (name == key).then_some(value))
    }

    /// Sets KEY where it is, or adds it at the end.
    pub fn set(&mut self, key: &str, value: Value) {
        match self.0.iter_mut().find(|(name, _)| name == key) {
            Some(entry) => entry.1 = value,
            None => self.0.push((key.to_owned(), value)),
        }
    }

    pub fn to_value(&self) -> Value {
        Value::Object(self.0.iter().cloned().collect())
    }

    fn text(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Value::as_str)
    }
}

impl Serialize for Object {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Object;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Object, A::Error> {
                let mut object = Object::default();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    // As a JSON parser has it: the last of two wins.
                    object.set(&key, value);
                }
                Ok(object)
            }
        }

        deserializer.deserialize_map(Visitor)
    }
}

/// OUTCOME, the agent's `outcome.json`, with `stopped_early` set when
/// the session was stopped at a limit and the agent did not say so
/// itself: a run cancelled in the middle of a turn wrote none, and its
/// working tree is collected all the same.
pub fn mark_stopped_early(mut outcome: Object, harness: Option<&RunResult>) -> Object {
    let Some(harness) = harness else {
        return outcome;
    };
    let stopped = matches!(harness.result, Outcome::Timeout | Outcome::Budget);
    let said = outcome.get("stopped_early").is_some_and(truthy);
    if stopped && !said {
        let why = harness
            .message
            .as_deref()
            .filter(|message| !message.is_empty())
            .unwrap_or(harness.result.as_str());
        outcome.set(
            "stopped_early",
            json!(format!(
                "the run was stopped at a limit: {}",
                cut(&squeeze(why), MAX_REASON_CHARS)
            )),
        );
    }
    outcome
}

/// Whether the agent set VALUE to something: what JavaScript, which the
/// old tree read it with, takes for true.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|n| n != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// The request for a pull request, in the order gh-aw's examples give
/// its fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PullRequest {
    pub r#type: &'static str,
    pub title: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

/// The request for a change the agent did not ask to have proposed, from
/// its outcome. One of a run that stopped early says so: the change is a
/// partial one, to be continued.
pub fn default_pull_request(outcome: &Object, run_id: &str) -> PullRequest {
    let summary = outcome.text("summary").unwrap_or_default().trim();
    let first = summary.lines().next().unwrap_or_default();
    let title = cut_words(&squeeze(first), MAX_TITLE_CHARS);
    let partial = match outcome.get("stopped_early") {
        Some(early) if truthy(early) => {
            let why = early
                .as_str()
                .filter(|why| !why.trim().is_empty())
                .map(|why| format!(" ({})", cut(&squeeze(why), MAX_REASON_CHARS)))
                .unwrap_or_default();
            format!("\n\nPartial change: the run stopped early{why}.")
        }
        // An agent that wrote no summary may have been cut off before it
        // could (as by a provider's refusal it took for the end of its
        // turn): its change is not passed off as finished.
        _ if summary.is_empty() => format!("\n\n{NO_SUMMARY}"),
        _ => String::new(),
    };
    let body = if summary.is_empty() {
        format!("Changes from agent run {run_id}.")
    } else {
        summary.to_owned()
    };
    PullRequest {
        r#type: CREATE_PULL_REQUEST,
        title: if title.is_empty() {
            format!("Agent run {run_id}")
        } else {
            title
        },
        body: format!("{body}{partial}"),
        branch: None,
    }
}

/// The checkpoint of a pull request made up from OUTCOME, for work that
/// [`default_pull_request`] calls partial: under `ready_when_complete`
/// that work would otherwise open ready for review.
fn fallback_checkpoint(outcome: &Object) -> Option<Checkpoint> {
    let summary = outcome.text("summary").unwrap_or_default().trim();
    let left = match outcome.get("stopped_early") {
        Some(early) if truthy(early) => early
            .as_str()
            .map(|why| cut(&squeeze(why), MAX_REASON_CHARS))
            .filter(|why| !why.is_empty())
            .unwrap_or_else(|| "the run stopped early".to_owned()),
        _ if summary.is_empty() => NO_SUMMARY.to_owned(),
        _ => return None,
    };
    Some(Checkpoint {
        reason: "incomplete".to_owned(),
        done: if summary.is_empty() {
            "unknown: the agent wrote no summary".to_owned()
        } else {
            "what the description above says".to_owned()
        },
        left,
        next: "read this change and its description, then continue the task".to_owned(),
    })
}

/// The `outputs.jsonl` to hand back, and what goes with it.
#[derive(Debug, PartialEq, Eq)]
pub struct Outputs {
    pub text: String,
    /// Whether a patch is to go with it.
    pub wants_patch: bool,
    /// The title and body of the pull request, the agent's own or the
    /// one made up: the message of the commit.
    pub message: Option<(String, String)>,
}

/// The type of request that carries a run's change, and the branch it
/// goes to: a pull request from the run's own branch, or, for a run that
/// fixes a pull request, a push to that pull request's branch, the
/// policy's base.
pub fn carrier(policy: &Policy, run_id: &str) -> (&'static str, String) {
    if policy.safe_outputs.push_to_pull_request_branch.is_some() {
        (PUSH_TO_PULL_REQUEST_BRANCH, policy.base.clone())
    } else {
        (CREATE_PULL_REQUEST, run_branch(run_id))
    }
}

/// A push's `message` as the title and body of its commit.
fn split_message(message: &str) -> (String, String) {
    let message = message.trim();
    let (title, body) = message.split_once('\n').unwrap_or((message, ""));
    (
        title.trim().to_owned(),
        body.trim_start_matches('\n').to_owned(),
    )
}

/// The agent's lines, its request for the change given the change's
/// branch, and a request made from its outcome when it changed files
/// without asking for one. A line that is not a JSON object stays as it
/// is, for the check to refuse.
pub fn build_outputs(
    agent_text: &str,
    policy: &Policy,
    has_changes: bool,
    outcome: &Object,
    run_id: &str,
) -> Outputs {
    let (kind, branch) = carrier(policy, run_id);
    let push = kind == PUSH_TO_PULL_REQUEST_BRANCH;
    let mut fallback = default_pull_request(outcome, run_id);
    if policy.safe_outputs.ready_when_complete()
        && let Some(checkpoint) = fallback_checkpoint(outcome)
    {
        fallback.body = format!("{}\n\n{}", fallback.body, checkpoint.markdown());
    }
    let mut message = None;
    let mut lines: Vec<String> = agent_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(MAX_LINES)
        .map(|line| {
            let Ok(mut item) = serde_json::from_str::<Object>(line) else {
                return line.to_owned();
            };
            // gh-aw takes a type with dashes as well.
            if item
                .text("type")
                .map(|kind| kind.replace('-', "_"))
                .as_deref()
                != Some(kind)
            {
                return line.to_owned();
            }
            // Keep the request consistent with the fallback commit message.
            // Explicit invalid values stay for gh-aw's collector to refuse.
            if push && item.get("message").is_none() {
                item.set(
                    "message",
                    json!(format!("{}\n\n{}", fallback.title, fallback.body)),
                );
            }
            let text = |key: &str, default: &str| {
                item.text(key)
                    .filter(|text| !text.trim().is_empty())
                    .unwrap_or(default)
                    .to_owned()
            };
            // Of several, which the check refuses, the first.
            message.get_or_insert_with(|| match item.text("message") {
                Some(text) if push && !text.trim().is_empty() => split_message(text),
                _ if push => (fallback.title.clone(), fallback.body.clone()),
                _ => (text("title", &fallback.title), text("body", &fallback.body)),
            });
            item.set("branch", json!(branch));
            serde_json::to_string(&item).unwrap_or_else(|_| line.to_owned())
        })
        .collect();
    let allowed = push || policy.safe_outputs.create_pull_request.is_some();
    if has_changes && message.is_none() && allowed {
        let request = if push {
            let PullRequest { title, body, .. } = &fallback;
            json!({"type": kind, "message": format!("{title}\n\n{body}"), "branch": branch})
        } else {
            json!(PullRequest {
                branch: Some(branch),
                ..fallback.clone()
            })
        };
        if let Ok(line) = serde_json::to_string(&request) {
            lines.push(line);
            message = Some((fallback.title, fallback.body));
        }
    }
    Outputs {
        text: lines.iter().map(|line| format!("{line}\n")).collect(),
        wants_patch: message.is_some() && has_changes,
        message,
    }
}

/// Whether LINE of the agent's text may not stand in a commit's message
/// as it is, because of what git makes of it when it reads the patch as
/// a mail (`git am`):
///
/// - the end of the message, the start of a change or the start of
///   another mail. `check` refuses most of these; a line of dashes it
///   cannot tell from the one `format-patch` ends the message with, and
///   git would drop the rest of the message there;
/// - a header in the body, or a `[PATCH]` line, which git takes over the
///   mail's own: the agent's text would choose the commit's author and
///   date, and a subject other than the title;
/// - a scissors line, above which git drops everything when told to
///   look for one;
/// - a sign-off.
fn needs_quoting(line: &str) -> bool {
    let starts_patch = ["---", "@@ -", "Index: ", "diff -"]
        .iter()
        .any(|start| line.starts_with(start));
    // What starts a mail: `From `, and further on a time.
    let starts_mail = line.starts_with("From ")
        && line
            .as_bytes()
            .windows(3)
            .any(|w| w[0].is_ascii_digit() && w[1] == b':' && w[2].is_ascii_digit());
    let lower = line.trim_start_matches('>').trim_start().to_lowercase();
    let header = IN_BODY_HEADERS.iter().any(|name| {
        lower
            .strip_prefix(name)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    });
    let scissors = (line.contains(">8") || line.contains("8<"))
        && line.chars().all(|c| "-<>8 \u{2702}".contains(c));
    starts_patch
        || starts_mail
        || header
        || scissors
        || lower.starts_with(SIGN_OFF)
        || line.trim_start().starts_with(IN_BODY_SUBJECT)
}

/// The message of the hand-back's commit: the pull request's title as
/// its subject, its body, and the configured trailers.
pub fn commit_message(title: &str, body: &str, trailers: &[String], run_id: &str) -> String {
    let plain = |text: &str| -> String {
        text.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    };
    let subject = cut(&squeeze(&plain(title)), MAX_SUBJECT_CHARS);
    let subject = if subject.is_empty() {
        format!("Agent run {run_id}")
    } else {
        subject
    };
    let body: Vec<String> = body
        .lines()
        .map(|line| plain(&line.replace('\t', "    ")).trim_end().to_owned())
        .map(|line| {
            if needs_quoting(&line) {
                format!("{QUOTE}{line}")
            } else {
                line
            }
        })
        .collect();
    // A body made from the same summary as the title starts by saying
    // the subject again.
    let repeats = body
        .iter()
        .position(|line| !line.is_empty())
        .filter(|&first| body[first] == subject);
    let body = body[repeats.map_or(0, |first| first + 1)..].join("\n");
    let mut message = subject;
    for part in [body.trim_matches('\n'), &trailers.join("\n")] {
        if !part.is_empty() {
            message.push_str("\n\n");
            message.push_str(part);
        }
    }
    message.push('\n');
    message
}

/// The author of the commit: `[commit] author`, as `Name <address>`.
pub fn author(commit: &config::Commit) -> Result<(String, String)> {
    let Some(author) = commit.author.as_deref() else {
        return Ok((DEFAULT_AUTHOR.0.to_owned(), DEFAULT_AUTHOR.1.to_owned()));
    };
    let parsed = author
        .strip_suffix('>')
        .and_then(|rest| rest.split_once('<'))
        .map(|(name, address)| (name.trim(), address))
        .filter(|(name, address)| {
            !name.is_empty()
                && address.contains('@')
                && !author.contains(|c: char| c.is_control())
                && !address.contains(['<', '>', ' '])
                && !name.contains(['<', '>'])
        });
    let (name, address) =
        parsed.with_context(|| format!("commit.author: {author:?} is not `Name <address>`"))?;
    Ok((name.to_owned(), address.to_owned()))
}

/// Whether every trailer of `[commit] trailers` is one line of `Key:
/// value`, as git reads one.
pub fn check_trailers(trailers: &[String]) -> Result<()> {
    for trailer in trailers {
        let ok = trailer.split_once(": ").is_some_and(|(key, value)| {
            !key.is_empty()
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !value.trim().is_empty()
        }) && !trailer.contains(|c: char| c.is_control());
        anyhow::ensure!(
            ok,
            "commit.trailers: {trailer:?} is not one line of `Key: value`"
        );
    }
    Ok(())
}

/// What the run found of the agent's change.
#[derive(Debug)]
pub struct Change {
    /// The paths that differ from the commit the run started from.
    pub files: Vec<String>,
    /// What `summary.json` says of the patch: `{base, bytes}`, or `{base,
    /// error}` for a change that could not be handed back, or null.
    pub patch: Value,
    /// The agent's outcome, with `stopped_early` filled in.
    pub outcome: Value,
    /// Why a change was not handed back.
    pub dropped: Option<String>,
}

impl Change {
    fn drop_patch(&mut self, base: &str, why: String) {
        self.patch = json!({"base": base, "error": why});
        self.dropped = Some(why);
    }
}

/// What [`collect`] is given.
pub struct Request<'a> {
    pub runner: &'a dyn Runner,
    /// The agent's home, where its outcome and its requests are.
    pub home: &'a Path,
    pub checkout: &'a Checkout,
    pub policy: &'a Policy,
    pub commit: &'a config::Commit,
    pub run_id: &'a str,
    /// How the session ended; none if it did not say.
    pub harness: Option<&'a RunResult>,
    /// Where `outcome.json` goes.
    pub run_dir: &'a Path,
    /// Where the hand-back goes: nothing is written there if nothing is
    /// handed back.
    pub safe_outputs: &'a Path,
}

/// The regular file PATH as RUNNER reads it, if it is at most MAX bytes.
fn read_agent_file(runner: &dyn Runner, path: &Path, max: usize) -> Option<Vec<u8>> {
    let limit = (max + 1).to_string();
    let argv = [
        "timeout",
        READ_TIMEOUT_S,
        "sh",
        "-c",
        READ_SCRIPT,
        "sh",
        path.to_str()?,
        &limit,
    ];
    let out = runner.run(&argv, b"", max + 1).ok()?;
    (out.success() && out.stdout.len() <= max).then_some(out.stdout)
}

struct Git<'a> {
    runner: &'a dyn Runner,
    dir: &'a str,
    /// Who its commits are by, as `NAME=value` for its environment.
    identity: Vec<String>,
}

impl<'a> Git<'a> {
    fn new(runner: &'a dyn Runner, dir: &'a str, author: &(String, String)) -> Self {
        let identity = IDENTITY_VARS
            .iter()
            .map(|(var, name)| format!("{var}={}", if *name { &author.0 } else { &author.1 }))
            .collect();
        Self {
            runner,
            dir,
            identity,
        }
    }
}

impl Git<'_> {
    fn argv<'a>(&'a self, args: &[&'a str]) -> Vec<&'a str> {
        let mut argv = vec!["timeout", GIT_TIMEOUT_S, "env"];
        argv.extend(self.identity.iter().map(String::as_str));
        argv.push("git");
        argv.extend(GIT_SETTINGS.iter().flat_map(|&setting| ["-c", setting]));
        argv.extend(["-C", self.dir]);
        argv.extend(args);
        argv
    }

    /// Whether the command ran and succeeded, and what it wrote.
    fn run(&self, args: &[&str], input: &[u8]) -> Option<(i32, Vec<u8>)> {
        let out = self
            .runner
            .run(&self.argv(args), input, MAX_GIT_OUTPUT)
            .ok()?;
        Some((out.status.code()?, out.stdout))
    }

    fn ok(&self, args: &[&str]) -> bool {
        matches!(self.run(args, b""), Some((0, _)))
    }

    /// What the command wrote, cut at LIMIT bytes, if it succeeded or
    /// was cut.
    fn limited(&self, args: &[&str], limit: usize) -> Option<Vec<u8>> {
        let limit_text = limit.to_string();
        let mut argv = vec!["sh", "-c", LIMIT_SCRIPT, "sh", &limit_text];
        argv.extend(self.argv(args));
        let out = self.runner.run(&argv, b"", limit).ok()?;
        // A command whose output was cut was stopped by that.
        let succeeded = String::from_utf8_lossy(&out.stderr).lines().last() == Some("0");
        (out.success() && (succeeded || out.stdout.len() >= limit)).then_some(out.stdout)
    }
}

/// The working tree as one commit on top of BASE, formatted as gh-aw's
/// patch. `Ok(None)` when nothing differs; `Err` is why it cannot be
/// handed back.
fn build_patch(
    git: &Git<'_>,
    base: &str,
    message: &str,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, String> {
    let failed = |what: &str| format!("git {what} failed");
    // Exit status 1: there are differences.
    match git.run(&["diff", "--cached", "--quiet"], b"") {
        Some((0, _)) => return Ok(None),
        Some((1, _)) => {}
        _ => return Err(failed("diff")),
    }
    // The message as it is given: no line of it is a comment.
    let commit = [
        "commit",
        "-q",
        "--no-verify",
        "--cleanup=whitespace",
        "-F",
        "-",
    ];
    if !matches!(git.run(&commit, message.as_bytes()), Some((0, _))) {
        return Err(failed("commit"));
    }
    let formatted = git
        .limited(FORMAT_PATCH, max_bytes + 1)
        .ok_or_else(|| failed("format-patch"))?;
    if formatted.len() > max_bytes {
        return Err(format!("the change is over {max_bytes} bytes"));
    }
    let first = formatted
        .iter()
        .position(|&b| b == b'\n')
        .ok_or("git format-patch gave no patch")?;
    let mut patch = formatted[..=first].to_vec();
    patch.extend_from_slice(format!("{BASE_COMMIT_HEADER}: {base}\n").as_bytes());
    patch.extend_from_slice(&formatted[first + 1..]);
    Ok(Some(patch))
}

/// Stage the working tree, but leave untracked binary build litter out.
/// Already staged or tracked binaries still reach `check`, which refuses them.
fn stage_patch(git: &Git<'_>, base: &str, status: &[u8]) -> Result<Vec<String>, String> {
    if !git.ok(&["reset", "-q", "--soft", base]) {
        return Err("git reset failed".into());
    }
    if !git.ok(&["add", "--all"]) {
        return Err("git add failed".into());
    }
    let stats = git
        .limited(
            &["diff", "--cached", "--no-renames", "--numstat", "-z"],
            MAX_STATUS_BYTES + 1,
        )
        .filter(|bytes| bytes.len() <= MAX_STATUS_BYTES)
        .ok_or("git diff numstat failed or was too large")?;
    let untracked: HashSet<&[u8]> = status
        .split(|&b| b == 0)
        .filter_map(|entry| entry.strip_prefix(b"?? "))
        .collect();
    let mut paths = Vec::new();
    let mut omitted = Vec::new();
    for entry in stats.split(|&b| b == 0) {
        if let Some(path) = entry.strip_prefix(b"-\t-\t")
            && untracked.contains(&path)
        {
            // Literal, NUL-delimited pathspecs also handle tabs, newlines and
            // names that would otherwise be interpreted as pathspec magic.
            paths.extend_from_slice(b":(literal)");
            paths.extend_from_slice(path);
            paths.push(0);
            omitted.push(String::from_utf8_lossy(path).into_owned());
        }
    }
    if !paths.is_empty()
        && !matches!(
            git.run(
                &[
                    "reset",
                    "-q",
                    base,
                    "--pathspec-from-file=-",
                    "--pathspec-file-nul"
                ],
                &paths
            ),
            Some((0, _))
        )
    {
        return Err("git reset of untracked binary files failed".into());
    }
    omitted.sort();
    Ok(omitted)
}

/// The paths `git status --porcelain=v1 -z` lists.
fn changed_files(status: &[u8]) -> Vec<String> {
    let mut files: Vec<String> = status
        .split(|&b| b == 0)
        .filter(|entry| entry.len() > 3)
        .map(|entry| String::from_utf8_lossy(&entry[3..]).into_owned())
        .collect();
    files.sort();
    files
}

#[derive(Serialize)]
struct Base<'a> {
    repo: &'a str,
    r#ref: &'a str,
    commit: &'a str,
}

fn write(path: &Path, content: &[u8]) -> Result<()> {
    std::fs::write(path, content).with_context(|| format!("writing {}", path.display()))
}

/// Whether a run of POLICY must leave an output: one that allows any.
/// A turn that ends without one is then not done (the session's
/// `OutputCheck`).
pub fn requires_output(policy: &Policy) -> bool {
    policy.safe_outputs.types().next().is_some()
}

/// Whether the agent left something to hand back: a request, a
/// replacement, or for a branch run that may carry one, a change of its
/// checkout. Asked while the agent still runs, only to decide whether to
/// remind it of its output: [`collect`] decides what is handed back. So a
/// checkout git cannot read counts as changed, and a requests file over
/// its limit as none (`check` would refuse it).
pub fn has_output(runner: &dyn Runner, home: &Path, checkout: &Checkout, policy: &Policy) -> bool {
    let requests = read_agent_file(runner, &home.join(AGENT_OUTPUTS), MAX_OUTPUTS_BYTES);
    if requests.is_some_and(|bytes| {
        if policy.safe_outputs.push_to_pull_request_branch.is_none() {
            return !bytes.trim_ascii().is_empty();
        }
        bytes.split(|b| *b == b'\n').any(|line| {
            let Ok(item) = serde_json::from_slice::<serde_json::Value>(line) else {
                return false;
            };
            let field = match item["type"].as_str() {
                Some("noop") => "message",
                Some("missing_data") => "reason",
                // A push request alone cannot carry a change.
                _ => return false,
            };
            item[field].as_str().is_some_and(|s| !s.trim().is_empty())
        })
    }) {
        return true;
    }
    let replacement = home.join(REPLACEMENT_PATH);
    let Ok(replacement) = clone::utf8(&replacement) else {
        return true;
    };
    if ["-e", "-L"].iter().any(|test| {
        runner
            .run(&["test", test, replacement], b"", MAX_GIT_OUTPUT)
            .is_ok_and(|output| output.success())
    }) {
        return true;
    }
    if policy.kind != Kind::Branch || policy.safe_outputs.patch_carrier().is_none() {
        return false;
    }
    let Ok(dir) = clone::utf8(&checkout.dir) else {
        return true;
    };
    let author = (DEFAULT_AUTHOR.0.to_owned(), DEFAULT_AUTHOR.1.to_owned());
    let git = Git::new(runner, dir, &author);
    // A byte of it is enough to know that something changed.
    let status = git.limited(
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        1,
    );
    let head = git
        .run(&["rev-parse", "--verify", "HEAD"], b"")
        .filter(|(status, _)| *status == 0)
        .map(|(_, out)| String::from_utf8_lossy(&out).trim().to_owned());
    match (status, head) {
        (Some(status), Some(head)) => !status.is_empty() || head != checkout.base_commit,
        _ => true,
    }
}

/// A fix must not silently succeed with work stranded in a rebase or an
/// unmerged index, even if it also wrote a request. This is a completion
/// check, not output admission: `check` still validates every proposal.
pub fn output_missing(
    runner: &dyn Runner,
    home: &Path,
    checkout: &Checkout,
    policy: &Policy,
) -> Option<String> {
    if policy.safe_outputs.push_to_pull_request_branch.is_some() {
        let unreadable = || Some("The fix checkout could not be inspected.".to_owned());
        let Ok(dir) = clone::utf8(&checkout.dir) else {
            return unreadable();
        };
        let author = (DEFAULT_AUTHOR.0.to_owned(), DEFAULT_AUTHOR.1.to_owned());
        let git = Git::new(runner, dir, &author);
        for name in ["rebase-merge", "rebase-apply"] {
            let Some(path) = git.run(&["rev-parse", "--git-path", name], b"") else {
                return unreadable();
            };
            if path.0 != 0 {
                return unreadable();
            }
            let path = String::from_utf8_lossy(&path.1);
            let path = checkout.dir.join(path.trim());
            let Ok(path) = clone::utf8(&path) else {
                return unreadable();
            };
            if runner
                .run(&["test", "-e", path], b"", MAX_GIT_OUTPUT)
                .is_ok_and(|out| out.success())
            {
                return Some(
                    "A rebase is still in progress. Finish or abort it before handing back.".into(),
                );
            }
        }
        match git.limited(&["ls-files", "--unmerged", "-z"], 1) {
            Some(out) if out.is_empty() => {}
            Some(_) => {
                return Some(
                    "The working tree has unresolved conflicts. Resolve them before handing back."
                        .into(),
                );
            }
            None => return unreadable(),
        }
    }
    (!has_output(runner, home, checkout, policy)).then(|| "No hand-back was left.".to_owned())
}

/// Collects what the agent left: its outcome into the run's results, and
/// its requests and its change into the hand-back.
///
/// An error is this machine's (a directory that cannot be written).
/// Whatever is wrong with what the agent left is not: a file that is
/// missing, too big or not what it should be counts as not written, and
/// a change that cannot be made a patch is dropped, with the reason in
/// the result.
pub fn collect(request: &Request<'_>) -> Result<Change> {
    let Request {
        runner,
        checkout,
        policy,
        run_id,
        ..
    } = *request;
    let base = checkout.base_commit.as_str();
    let git = Git::new(
        runner,
        clone::utf8(&checkout.dir)?,
        &author(request.commit)?,
    );
    let status = git.limited(
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--no-renames",
            "--untracked-files=all",
        ],
        MAX_STATUS_BYTES,
    );
    let files = changed_files(status.as_deref().unwrap_or_default());
    // Commits of its own count as a change too, though it was asked to
    // make none.
    let head = git
        .run(&["rev-parse", "--verify", "HEAD"], b"")
        .filter(|(status, _)| *status == 0)
        .map(|(_, out)| String::from_utf8_lossy(&out).trim().to_owned());
    // A checkout git can no longer read is not one without changes.
    let unreadable = status.is_none() || head.is_none();
    let changed = !files.is_empty() || head.as_deref().is_some_and(|head| head != base);

    let outcome = read_agent_file(runner, &request.home.join(AGENT_OUTCOME), MAX_OUTCOME_BYTES)
        .and_then(|bytes| serde_json::from_slice::<Object>(&bytes).ok())
        .unwrap_or_default();
    let mut outcome = mark_stopped_early(outcome, request.harness);
    // An explicit replacement is the complete series, not a working-tree
    // fixup. Never reset/squash the producer's checkout on this path.
    let replacement_path = request.home.join(REPLACEMENT_PATH);
    let replacement_path_text = clone::utf8(&replacement_path)?;
    let has_replacement = ["-e", "-L"].iter().any(|test| {
        runner
            .run(&["test", test, replacement_path_text], b"", MAX_GIT_OUTPUT)
            .is_ok_and(|output| output.success())
    });
    if has_replacement {
        let text = serde_json::to_vec(&outcome)?;
        write(&request.run_dir.join(OUTCOME_FILE), &text)?;
        let mut change = Change {
            files,
            patch: Value::Null,
            outcome: outcome.to_value(),
            dropped: None,
        };
        let max = usize::try_from(policy.max_patch_bytes).unwrap_or(usize::MAX - 1);
        let content = read_agent_file(runner, &replacement_path, max);
        let agent_text =
            read_agent_file(runner, &request.home.join(AGENT_OUTPUTS), MAX_OUTPUTS_BYTES)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
        let outputs = build_outputs(&agent_text, policy, true, &outcome, run_id);
        if policy.safe_outputs.push_to_pull_request_branch.is_none()
            || !outputs.wants_patch
            || content.is_none()
        {
            change.drop_patch(
                base,
                "replacement requires a push request and a bounded regular replacement.json".into(),
            );
            return Ok(change);
        }
        if let Some(content) = content {
            // Shell command substitution removes final newlines. Repair only
            // that transport loss; the unchanged strict checker still parses
            // every mail and bounds the normalized JSON before accepting it.
            let mut content = content;
            if let Ok(mut series) =
                serde_json::from_slice::<crate::check::replacement::Replacement>(&content)
            {
                let mut repaired = false;
                for mail in &mut series.commits {
                    if !mail.ends_with('\n') {
                        mail.push('\n');
                        repaired = true;
                    }
                }
                if repaired {
                    eprintln!("warning: restored missing final newline in replacement mail");
                    content = serde_json::to_vec(&series)?;
                }
            }
            // Check refuses it again on another machine; this only names a
            // malformed series in the agent job, not after check.
            if let Some(push) = &policy.safe_outputs.push_to_pull_request_branch
                && let Err(error) =
                    crate::check::replacement::check(&content, push, policy.max_patch_bytes)
            {
                change.drop_patch(base, format!("replacement.json: {error:#}"));
                return Ok(change);
            }
            create_dir(request.safe_outputs)?;
            write(
                &request
                    .safe_outputs
                    .join(crate::check::replacement::REPLACEMENT_FILE),
                &content,
            )?;
            write(
                &request.safe_outputs.join(OUTPUTS_FILE),
                outputs.text.as_bytes(),
            )?;
            change.patch = json!({"base": base, "bytes": content.len()});
        }
        return Ok(change);
    }
    let staged = if policy.kind == Kind::Branch && changed && !unreadable {
        stage_patch(&git, base, status.as_deref().unwrap_or_default())
    } else {
        Ok(Vec::new())
    };
    if let Ok(omitted) = &staged
        && !omitted.is_empty()
    {
        // Only added to what the agent said: a summary that is this note
        // alone would become the title of the pull request.
        if let Some(summary) = outcome
            .text("summary")
            .filter(|summary| !summary.trim().is_empty())
        {
            let summary = format!(
                "{summary}\nHand-back omitted {} untracked binary file(s); see {OMITTED_BINARY_FILES}.",
                omitted.len()
            );
            outcome.set("summary", json!(summary));
        }
        outcome.set(OMITTED_BINARY_FILES, json!(omitted));
    }
    let mut text = serde_json::to_string(&outcome).context("writing the outcome")?;
    text.push('\n');
    write(&request.run_dir.join(OUTCOME_FILE), text.as_bytes())?;

    let agent_text = read_agent_file(runner, &request.home.join(AGENT_OUTPUTS), MAX_OUTPUTS_BYTES)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    // An analysis run's change is not handed back.
    let only_litter = staged
        .as_ref()
        .is_ok_and(|omitted| !omitted.is_empty() && git.ok(&["diff", "--cached", "--quiet"]));
    let has_changes = changed && !only_litter && policy.kind == Kind::Branch;
    let mut change = Change {
        files,
        patch: Value::Null,
        outcome: outcome.to_value(),
        dropped: None,
    };
    if policy.kind != Kind::Branch && agent_text.is_empty() {
        return Ok(change);
    }
    if unreadable && policy.kind == Kind::Branch {
        change.drop_patch(base, "git cannot read the checkout any more".to_owned());
    }

    let outputs = build_outputs(&agent_text, policy, has_changes, &outcome, run_id);
    if let (true, Some((title, body))) = (outputs.wants_patch, &outputs.message) {
        let message = commit_message(title, body, &request.commit.trailers, run_id);
        let max = usize::try_from(policy.max_patch_bytes).unwrap_or(usize::MAX - 1);
        match staged.and_then(|_| build_patch(&git, base, &message, max)) {
            Err(why) => {
                // As in the old tree, the requests go with the change.
                change.drop_patch(base, why);
                return Ok(change);
            }
            Ok(None) => {}
            Ok(Some(patch)) => {
                create_dir(request.safe_outputs)?;
                let name = patch_file_name(&carrier(policy, run_id).1);
                write(&request.safe_outputs.join(name), &patch)?;
                let base_file = Base {
                    repo: &policy.repo,
                    r#ref: &policy.base,
                    commit: base,
                };
                let mut text = serde_json::to_string(&base_file).context("writing the base")?;
                text.push('\n');
                write(&request.safe_outputs.join(BASE_FILE), text.as_bytes())?;
                change.patch = json!({"base": base, "bytes": patch.len()});
            }
        }
    }
    if !outputs.text.is_empty() {
        create_dir(request.safe_outputs)?;
        write(
            &request.safe_outputs.join(OUTPUTS_FILE),
            outputs.text.as_bytes(),
        )?;
    }
    if has_changes && !outputs.wants_patch {
        change.drop_patch(
            base,
            format!(
                "changes dropped: {} is not an allowed output",
                carrier(policy, run_id).0
            ),
        );
    }
    Ok(change)
}

fn create_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::process::Command;

    use super::*;
    use crate::check;
    use crate::policy::SafeOutputs;
    use crate::run::enter::Unconfined;
    use crate::session::Limits;

    const RUN_ID: &str = "42";

    fn policy(kind: Kind, outputs: Value) -> Policy {
        Policy {
            context: Vec::new(),
            repo: "o/r".into(),
            clone_url: "https://example.invalid/o/r".into(),
            base: "main".into(),
            kind,
            max_outputs: 3,
            max_patch_bytes: 1 << 20,
            safe_outputs: serde_json::from_value::<SafeOutputs>(outputs).unwrap(),
        }
    }

    fn pull_requests() -> Value {
        json!({
            "create_pull_request": {
                "max": 1, "protected_files": ["CODEOWNERS"], "protect_top_level_dot_folders": true,
                "protected_files_policy": "blocked", "draft": true, "max_patch_size": 1024,
                "max_patch_files": 100,
            },
            "noop": {"max": 1},
        })
    }

    fn object(value: Value) -> Object {
        serde_json::from_value(value).unwrap()
    }

    fn harness(result: Outcome, message: Option<&str>) -> RunResult {
        RunResult {
            schema: crate::session::RESULT_SCHEMA.into(),
            agent: "fake".into(),
            command: Vec::new(),
            result,
            stop_reason: None,
            message: message.map(str::to_owned),
            started_at: String::new(),
            finished_at: String::new(),
            duration_s: 0,
            limits: Limits {
                timeout_s: 60,
                budget_aic: None,
                max_requests: None,
                max_tasks: None,
            },
            handed_back: false,
            reminded: false,
        }
    }

    /// The old tree's cases, from `handback.test.mjs`.
    #[test]
    fn outputs() {
        let outcome = object(json!({"summary": "Fix the parser.\nIt dropped the last line."}));
        let branch = run_branch(RUN_ID);
        let made_up = format!(
            "{{\"type\":\"create_pull_request\",\"title\":\"Fix the parser.\",\
             \"body\":\"Fix the parser.\\nIt dropped the last line.\",\"branch\":\"{branch}\"}}\n"
        );
        let own = |kind: &str| {
            format!(
                "{{\"type\":\"{kind}\",\"title\":\"T\",\"body\":\"B\",\"branch\":\"{branch}\"}}\n"
            )
        };
        // (the case, the agent's text, whether it changed files, the text, a patch)
        let cases: &[(&str, &str, bool, String, bool)] = &[
            ("nothing", "", false, String::new(), false),
            (
                "a change the agent did not request",
                "",
                true,
                made_up,
                true,
            ),
            (
                "the agent's own request gets the run's branch",
                "{\"type\":\"create_pull_request\",\"title\":\"T\",\"body\":\"B\",\"branch\":\"evil/../x\"}\n",
                true,
                own("create_pull_request"),
                true,
            ),
            (
                "dashes in the type",
                "{\"type\":\"create-pull-request\",\"title\":\"T\",\"body\":\"B\"}",
                true,
                own("create-pull-request"),
                true,
            ),
            (
                "a noop without changes",
                "{\"type\":\"noop\",\"message\":\"m\"}",
                false,
                "{\"type\":\"noop\",\"message\":\"m\"}\n".into(),
                false,
            ),
            (
                "a request without changes has no patch",
                "{\"type\":\"create_pull_request\",\"title\":\"T\",\"body\":\"B\"}",
                false,
                own("create_pull_request"),
                false,
            ),
            (
                "a line that is not JSON stays for the check",
                "oops\n",
                false,
                "oops\n".into(),
                false,
            ),
            (
                "neither does an array",
                "  [1]  \n\n",
                false,
                "[1]\n".into(),
                false,
            ),
        ];
        let policy = policy(Kind::Branch, pull_requests());
        for (name, agent_text, has_changes, text, wants_patch) in cases {
            let got = build_outputs(agent_text, &policy, *has_changes, &outcome, RUN_ID);
            assert_eq!(got.text, *text, "{name}");
            assert_eq!(got.wants_patch, *wants_patch, "{name}");
        }
        // The message is the request's own text, and the outcome's where
        // it has none.
        let own = build_outputs(
            "{\"type\":\"create_pull_request\",\"title\":\"T\",\"body\":7}",
            &policy,
            true,
            &outcome,
            RUN_ID,
        );
        assert_eq!(
            own.message,
            Some((
                "T".into(),
                "Fix the parser.\nIt dropped the last line.".into()
            ))
        );
        // Not allowed: no pull request is made up for the change.
        let noop_only = self::policy(Kind::Branch, json!({"noop": {"max": 1}}));
        let got = build_outputs("", &noop_only, true, &outcome, RUN_ID);
        assert_eq!((got.text.as_str(), got.wants_patch), ("", false));
        // No more lines are passed on than the cap.
        let many = "{\"type\":\"noop\"}\n".repeat(MAX_LINES + 5);
        let got = build_outputs(&many, &policy, false, &outcome, RUN_ID);
        assert_eq!(got.text.lines().count(), MAX_LINES);
    }

    /// Under `ready_when_complete`, a pull request made up for work the
    /// fallback calls partial carries a checkpoint, so that apply keeps
    /// it a draft; complete work, or a policy without it, carries none.
    #[test]
    fn made_up_partial_work_is_a_checkpoint_where_complete_work_opens_ready() {
        let mut ready = pull_requests();
        ready["create_pull_request"]["ready_when_complete"] = json!(true);
        let ready = policy(Kind::Branch, ready);
        let off = policy(Kind::Branch, pull_requests());
        let cases = [
            (json!({"summary": "Fixed it."}), &ready, None),
            (
                json!({"summary": "Half of it.", "stopped_early": "out of time"}),
                &ready,
                Some("out of time"),
            ),
            (json!({}), &ready, Some(NO_SUMMARY)),
            (json!({"stopped_early": "out of time"}), &off, None),
        ];
        for (outcome, policy, left) in cases {
            let got = build_outputs("", policy, true, &object(outcome.clone()), RUN_ID);
            let (_, body) = got.message.unwrap();
            let request: Value = serde_json::from_str(got.text.trim()).unwrap();
            assert_eq!(request["body"], body.as_str(), "{outcome}");
            let found = crate::check::checkpoint::find(&body).unwrap();
            assert_eq!(found.as_ref().map(|c| c.left.as_str()), left, "{outcome}");
            assert!(found.is_none_or(|c| c.reason == "incomplete"));
        }
    }

    /// A run that fixes a pull request asks for a push to its branch,
    /// the policy's base, whatever branch the agent named.
    #[test]
    fn a_push_goes_to_the_pull_requests_branch() {
        let outcome = object(json!({"summary": "Fix the parser.\nIt dropped the last line."}));
        let policy = crate::policy::tests::push_policy();
        // (the case, the agent's text, the text, the message)
        let cases: &[(&str, &str, &str, (&str, &str))] = &[
            (
                "made up from the outcome",
                "",
                "{\"type\":\"push_to_pull_request_branch\",\"message\":\"Fix the parser.\\n\\nFix the parser.\\nIt dropped the last line.\",\"branch\":\"agent-run-12\"}\n",
                (
                    "Fix the parser.",
                    "Fix the parser.\nIt dropped the last line.",
                ),
            ),
            (
                "the agent's own, with the branch put right",
                "{\"type\":\"push_to_pull_request_branch\",\"message\":\"T\\n\\nB\\nC\",\"branch\":\"main\"}",
                "{\"type\":\"push_to_pull_request_branch\",\"message\":\"T\\n\\nB\\nC\",\"branch\":\"agent-run-12\"}\n",
                ("T", "B\nC"),
            ),
            (
                "a missing message uses the outcome in both request and commit",
                "{\"type\":\"push_to_pull_request_branch\"}",
                "{\"type\":\"push_to_pull_request_branch\",\"message\":\"Fix the parser.\\n\\nFix the parser.\\nIt dropped the last line.\",\"branch\":\"agent-run-12\"}\n",
                (
                    "Fix the parser.",
                    "Fix the parser.\nIt dropped the last line.",
                ),
            ),
            (
                "an explicit null stays for the collector to refuse",
                "{\"type\":\"push_to_pull_request_branch\",\"message\":null}",
                "{\"type\":\"push_to_pull_request_branch\",\"message\":null,\"branch\":\"agent-run-12\"}\n",
                (
                    "Fix the parser.",
                    "Fix the parser.\nIt dropped the last line.",
                ),
            ),
            (
                "an explicit number stays for the collector to refuse",
                "{\"type\":\"push_to_pull_request_branch\",\"message\":7}",
                "{\"type\":\"push_to_pull_request_branch\",\"message\":7,\"branch\":\"agent-run-12\"}\n",
                (
                    "Fix the parser.",
                    "Fix the parser.\nIt dropped the last line.",
                ),
            ),
            (
                "an empty message is the outcome's",
                "{\"type\":\"push_to_pull_request_branch\",\"message\":\" \"}",
                "{\"type\":\"push_to_pull_request_branch\",\"message\":\" \",\"branch\":\"agent-run-12\"}\n",
                (
                    "Fix the parser.",
                    "Fix the parser.\nIt dropped the last line.",
                ),
            ),
            (
                "a pull request is left for the check to refuse",
                "{\"type\":\"create_pull_request\",\"title\":\"T\",\"body\":\"B\"}",
                "{\"type\":\"create_pull_request\",\"title\":\"T\",\"body\":\"B\"}\n{\"type\":\"push_to_pull_request_branch\",\"message\":\"Fix the parser.\\n\\nFix the parser.\\nIt dropped the last line.\",\"branch\":\"agent-run-12\"}\n",
                (
                    "Fix the parser.",
                    "Fix the parser.\nIt dropped the last line.",
                ),
            ),
        ];
        for (name, agent_text, text, (title, body)) in cases {
            let got = build_outputs(agent_text, &policy, true, &outcome, RUN_ID);
            assert_eq!(got.text, *text, "{name}");
            assert!(got.wants_patch, "{name}");
            assert_eq!(
                got.message,
                Some(((*title).to_owned(), (*body).to_owned())),
                "{name}"
            );
        }
    }

    #[test]
    fn made_up_pull_requests() {
        let long = "x".repeat(300);
        // (the outcome, the title, the body)
        let cases = [
            (
                json!({}),
                "Agent run 9",
                "Changes from agent run 9.\n\nPartial change: the agent did not say what it did or that it was done.",
            ),
            (
                json!({"summary": " \n "}),
                "Agent run 9",
                "Changes from agent run 9.\n\nPartial change: the agent did not say what it did or that it was done.",
            ),
            (json!({"summary": "  one\n\ntwo  "}), "one", "one\n\ntwo"),
            (
                json!({"summary": "one", "stopped_early": "out of\ntime"}),
                "one",
                "one\n\nPartial change: the run stopped early (out of time).",
            ),
            (
                json!({"stopped_early": true}),
                "Agent run 9",
                "Changes from agent run 9.\n\nPartial change: the run stopped early.",
            ),
            (
                json!({"summary": "one", "stopped_early": null}),
                "one",
                "one",
            ),
            (
                json!({"summary": 5}),
                "Agent run 9",
                "Changes from agent run 9.\n\nPartial change: the agent did not say what it did or that it was done.",
            ),
        ];
        for (outcome, title, body) in cases {
            let got = default_pull_request(&object(outcome.clone()), "9");
            assert_eq!(
                (got.title.as_str(), got.body.as_str()),
                (title, body),
                "{outcome}"
            );
        }
        let got = default_pull_request(&object(json!({"summary": long})), "9");
        assert_eq!(got.title.chars().count(), MAX_TITLE_CHARS);
        let words = format!("{} tail", "word ".repeat(30));
        let got = default_pull_request(&object(json!({"summary": words})), "9");
        assert_eq!(got.title, "word ".repeat(20).trim_end());
    }

    #[test]
    fn titles_are_cut_between_words() {
        // (the text, the most characters, what is kept)
        let cases = [
            ("short title", 20, "short title"),
            ("exactly ten", 11, "exactly ten"),
            ("one two three", 7, "one two"),
            ("one two three", 8, "one two"),
            ("one two three", 6, "one"),
            ("ééé ééé", 5, "ééé"),
            ("unbroken", 4, "unbr"),
            ("", 4, ""),
        ];
        for (text, max, want) in cases {
            assert_eq!(cut_words(text, max), want, "{text:?} {max}");
        }
    }

    #[test]
    fn a_run_stopped_at_a_limit_is_marked() {
        let stopped = harness(Outcome::Timeout, Some("hit the timeout; cancelled"));
        // (the outcome, how the session ended, the outcome's stopped_early)
        let cases = [
            (
                json!({}),
                Some(&stopped),
                json!("the run was stopped at a limit: hit the timeout; cancelled"),
            ),
            (
                json!({"stopped_early": null}),
                Some(&harness(Outcome::Budget, None)),
                json!("the run was stopped at a limit: budget"),
            ),
            // What the agent said while handing back stands.
            (
                json!({"stopped_early": "out of requests"}),
                Some(&stopped),
                json!("out of requests"),
            ),
            (
                json!({}),
                Some(&harness(Outcome::Success, None)),
                Value::Null,
            ),
            (
                json!({}),
                Some(&harness(Outcome::Failure, Some("the agent failed"))),
                Value::Null,
            ),
            (json!({}), None, Value::Null),
        ];
        for (outcome, harness, want) in cases {
            let got = mark_stopped_early(object(outcome.clone()), harness);
            assert_eq!(
                got.get("stopped_early").cloned().unwrap_or(Value::Null),
                want,
                "{outcome}"
            );
        }
        // The agent's fields stay in the order it wrote them.
        let got = mark_stopped_early(object(json!({"z": 1, "a": 2})), Some(&stopped));
        let text = serde_json::to_string(&got).unwrap();
        assert!(
            text.starts_with("{\"z\":1,\"a\":2,\"stopped_early\":"),
            "{text}"
        );
    }

    #[test]
    fn commit_messages() {
        let trailers = vec!["Generated-by: AI".to_owned()];
        // (title, body, trailers, the message)
        let cases: &[(&str, &str, &[String], &str)] = &[
            ("Fix it", "", &[], "Fix it\n"),
            ("  Fix\n it\t now ", "Why.\n", &[], "Fix it now\n\nWhy.\n"),
            (
                "",
                "Why.",
                &trailers,
                "Agent run 42\n\nWhy.\n\nGenerated-by: AI\n",
            ),
            ("T", "", &trailers, "T\n\nGenerated-by: AI\n"),
            // What git would take for the end of the message or the start
            // of a patch is quoted; the rest of a body is the agent's.
            (
                "T",
                "\n\nOne.\r\n---\n--- a/x\n@@ -1 +1 @@\ndiff --git a/x b/x\nIndex: x\n\
                 From me Mon Sep 17 00:00:00 2001\n-- \n+++ fine\n# kept\n - a list\n\n",
                &[],
                "T\n\nOne.\n    ---\n    --- a/x\n    @@ -1 +1 @@\n    diff --git a/x b/x\n    Index: x\n\
                 \x20   From me Mon Sep 17 00:00:00 2001\n--\n+++ fine\n# kept\n - a list\n",
            ),
            // Headers git would read from the body over the mail's own,
            // a sign-off nobody gave, and a scissors line.
            (
                "T",
                "From: Somebody Else <human@example.org>\nSUBJECT : another\n>date: 1970\n\
                 Signed-off-by: A Human <human@example.org>\n-- >8 --\nFrom here on, prose: fine.\n\
                 Dated: no header\n8< is not scissors",
                &[],
                "T\n\n    From: Somebody Else <human@example.org>\n    SUBJECT : another\n\
                 \x20   >date: 1970\n    Signed-off-by: A Human <human@example.org>\n    -- >8 --\n\
                 From here on, prose: fine.\nDated: no header\n8< is not scissors\n",
            ),
            // A body that starts with its own subject does not say it twice.
            (
                "One thing",
                "\nOne thing\n\nAnd why.",
                &[],
                "One thing\n\nAnd why.\n",
            ),
            (
                "One thing",
                "One thing",
                &trailers,
                "One thing\n\nGenerated-by: AI\n",
            ),
            // A line git would read as the subject, over the title.
            (
                "T",
                "[PATCH] another subject\n [PATCH v2 1/3] and another\nA [PATCH] in prose",
                &[],
                "T\n\n    [PATCH] another subject\n     [PATCH v2 1/3] and another\nA [PATCH] in prose\n",
            ),
        ];
        for (title, body, trailers, want) in cases {
            assert_eq!(
                commit_message(title, body, trailers, RUN_ID),
                *want,
                "{title:?} {body:?}"
            );
        }
        let long = commit_message(&"x".repeat(500), "", &[], RUN_ID);
        assert_eq!(long.trim_end().chars().count(), MAX_SUBJECT_CHARS);
    }

    #[test]
    fn authors_and_trailers() {
        let commit = |author: Option<&str>| config::Commit {
            author: author.map(str::to_owned),
            trailers: Vec::new(),
        };
        assert_eq!(
            author(&commit(None)).unwrap(),
            ("agent".to_owned(), "agent@localhost".to_owned())
        );
        assert_eq!(
            author(&commit(Some("A Bot <bot@example.com>"))).unwrap(),
            ("A Bot".to_owned(), "bot@example.com".to_owned())
        );
        for bad in [
            "bot@example.com",
            "<bot@example.com>",
            "A Bot <bot>",
            "A Bot <a@b> x",
            "A <B> <a@b>",
            "A\nBot <a@b>",
            "A Bot <a b@c>",
        ] {
            assert!(author(&commit(Some(bad))).is_err(), "{bad}");
        }
        check_trailers(&["Generated-by: AI".into(), "Refs: #12 and more".into()]).unwrap();
        for bad in [
            "Generated-by:AI",
            "No colon",
            ": x",
            "A b: c",
            "A: b\nC: d",
            "A: ",
        ] {
            assert!(check_trailers(&[bad.to_owned()]).is_err(), "{bad}");
        }
    }

    #[test]
    fn changed_file_names() {
        assert_eq!(
            changed_files(b" M b.rs\0?? a dir/new\0D  gone\0"),
            ["a dir/new", "b.rs", "gone"]
        );
        assert!(changed_files(b"").is_empty());
    }

    fn sh(dir: &Path, script: &str) -> String {
        let out = Command::new("sh")
            .args(["-ec", script])
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A home with a checkout in it, as a run leaves one for the agent.
    struct Home {
        dir: tempfile::TempDir,
        checkout: Checkout,
    }

    impl Home {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            for sub in ["work/r", "out", "results"] {
                std::fs::create_dir_all(dir.path().join(sub)).unwrap();
            }
            let repo = dir.path().join("work/r");
            sh(
                &repo,
                "git init -q -b main . && echo one > a.txt && git add . && \
                 git -c user.name=t -c user.email=t@example.invalid commit -q -m Base",
            );
            let head = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&repo)
                .output()
                .unwrap();
            let checkout = Checkout {
                dir: repo,
                base_commit: String::from_utf8(head.stdout).unwrap().trim().to_owned(),
            };
            Self { dir, checkout }
        }

        fn path(&self, name: &str) -> std::path::PathBuf {
            self.dir.path().join(name)
        }

        fn collect(&self, policy: &Policy, commit: &config::Commit) -> Change {
            self.collect_with_harness(policy, commit, None)
        }

        fn collect_with_harness(
            &self,
            policy: &Policy,
            commit: &config::Commit,
            harness: Option<&RunResult>,
        ) -> Change {
            let _ = std::fs::remove_dir_all(self.path("safe-outputs"));
            collect(&Request {
                runner: &Unconfined,
                home: self.dir.path(),
                checkout: &self.checkout,
                policy,
                commit,
                run_id: RUN_ID,
                harness,
                run_dir: &self.path("results"),
                safe_outputs: &self.path("safe-outputs"),
            })
            .unwrap()
        }

        /// What `check` makes of the hand-back, with the requests as
        /// gh-aw's collector would pass them on.
        fn verdict(&self, policy: &Policy) -> check::Verdict {
            let outputs = std::fs::read_to_string(self.path("safe-outputs/outputs.jsonl"))
                .unwrap_or_default();
            let items: Vec<Value> = outputs
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let collected = self.path("collected.json");
            std::fs::write(
                &collected,
                json!({"items": items, "errors": []}).to_string(),
            )
            .unwrap();
            check::check_outputs(&self.path("safe-outputs"), &collected, policy).unwrap()
        }
    }

    /// What counts as the output a run requires, for the reminder: a
    /// request, a replacement, or a change of a branch run that may carry
    /// one; a run that allows no output requires none.
    #[test]
    fn what_counts_as_output() {
        let analysis = policy(Kind::Analysis, json!({"add_comment": {"max": 1}}));
        let branch = policy(Kind::Branch, pull_requests());
        let no_carrier = policy(Kind::Branch, json!({"noop": {"max": 1}}));
        assert!(!requires_output(&policy(Kind::Branch, json!({}))));
        assert!(requires_output(&analysis) && requires_output(&branch));
        // (the case, what the agent does, the policy, whether it counts)
        let cases = [
            ("nothing", "true", &branch, false),
            (
                "blank requests",
                "printf '\\n \\n' > ../../out/safe-outputs.jsonl",
                &analysis,
                false,
            ),
            (
                "a request",
                "echo '{}' > ../../out/safe-outputs.jsonl",
                &analysis,
                true,
            ),
            (
                "a replacement",
                "echo '{}' > ../../out/replacement.json",
                &analysis,
                true,
            ),
            ("an edit", "echo two >> a.txt", &branch, true),
            ("a new file", "echo new > b.txt", &branch, true),
            (
                "a commit",
                "git -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m X",
                &branch,
                true,
            ),
            (
                "an edit no output carries",
                "echo two >> a.txt",
                &no_carrier,
                false,
            ),
            (
                "an edit of an analysis",
                "echo two >> a.txt",
                &analysis,
                false,
            ),
            (
                "a checkout git cannot read",
                "rm -rf .git/objects",
                &branch,
                true,
            ),
        ];
        for (case, script, policy, counts) in cases {
            let home = Home::new();
            sh(&home.checkout.dir, script);
            assert_eq!(
                has_output(&Unconfined, home.dir.path(), &home.checkout, policy),
                counts,
                "{case}"
            );
        }
    }

    #[test]
    fn fix_completion() {
        let policy = crate::policy::tests::push_policy();
        assert!(requires_output(&policy));
        let cases = [
            ("nothing", "true", Some("No hand-back")),
            ("edit", "echo two >> a.txt", None),
            (
                "push alone",
                "echo '{\"type\":\"push_to_pull_request_branch\"}' > ../../out/safe-outputs.jsonl",
                Some("No hand-back"),
            ),
            (
                "noop",
                "echo '{\"type\":\"noop\",\"message\":\"Already fixed\"}' > ../../out/safe-outputs.jsonl",
                None,
            ),
            (
                "empty noop",
                "echo '{\"type\":\"noop\",\"message\":\" \"}' > ../../out/safe-outputs.jsonl",
                Some("No hand-back"),
            ),
            (
                "missing data",
                "echo '{\"type\":\"missing_data\",\"reason\":\"Need the failing log\"}' > ../../out/safe-outputs.jsonl",
                None,
            ),
            (
                "merge rebase",
                "mkdir .git/rebase-merge; echo two >> a.txt",
                Some("rebase is still in progress"),
            ),
            (
                "apply rebase",
                "mkdir .git/rebase-apply",
                Some("rebase is still in progress"),
            ),
            (
                "noop during rebase",
                "mkdir .git/rebase-merge; echo '{\"type\":\"noop\",\"message\":\"Done\"}' > ../../out/safe-outputs.jsonl",
                Some("rebase is still in progress"),
            ),
            (
                "conflicts",
                "export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid; git checkout -qb other; echo other > a.txt; git commit -qam other; git checkout -q -; echo ours > a.txt; git commit -qam ours; git merge other >/dev/null 2>&1 || true",
                Some("unresolved conflicts"),
            ),
            (
                "unreadable",
                "rm -rf .git/objects",
                Some("could not be inspected"),
            ),
        ];
        for (case, script, expected) in cases {
            let home = Home::new();
            sh(&home.checkout.dir, script);
            let reason = output_missing(&Unconfined, home.dir.path(), &home.checkout, &policy);
            match expected {
                Some(text) => assert!(
                    reason.as_deref().is_some_and(|r| r.contains(text)),
                    "{case}: {reason:?}"
                ),
                None => assert_eq!(reason, None, "{case}"),
            }
        }
    }

    /// A change with a message that tries everything `check` refuses in
    /// one is handed back as a patch `check` accepts, with that message.
    #[test]
    fn a_change_is_handed_back_as_a_patch_the_check_accepts() {
        let home = Home::new();
        let policy = policy(Kind::Branch, pull_requests());
        let commit = config::Commit {
            author: Some("A Bot <bot@example.com>".into()),
            trailers: vec!["Generated-by: AI".into()],
        };
        sh(
            &home.checkout.dir,
            "echo two >> a.txt && mkdir sub && printf 'caf\\303\\251\\n' > 'sub/new-file.txt'",
        );
        let body = "From: Somebody Else <human@example.org>\nSubject: another subject\n\
                    Date: Thu, 1 Jan 1970 00:00:00 +0000\n\n\
                    Why: the parser dropped a line \u{2014} caf\u{e9}.\n\n---\n--- a/x\n+++ b/x\n\
                    @@ -1 +1 @@\ndiff --git a/.github/x b/.github/x\nFrom x Mon Sep 17 00:00:00 2001\n\
                    Signed-off-by: Somebody Else <human@example.org>";
        let request = json!({"type": "create_pull_request", "title": "parser: Keep the last line", "body": body});
        std::fs::write(
            home.path(AGENT_OUTPUTS),
            format!("{request}\n{{\"type\":\"noop\",\"message\":\"m\"}}\n"),
        )
        .unwrap();
        std::fs::write(
            home.path(AGENT_OUTCOME),
            "{\"summary\": \"Done.\", \"tests\": []}",
        )
        .unwrap();

        let change = home.collect(&policy, &commit);
        assert_eq!(change.files, ["a.txt", "sub/new-file.txt"]);
        assert_eq!(change.dropped, None);
        assert_eq!(change.outcome["summary"], "Done.");
        let patch_name = "aw-agent-run-42.patch";
        let patch = std::fs::read_to_string(home.path("safe-outputs").join(patch_name)).unwrap();
        assert_eq!(
            change.patch,
            json!({"base": home.checkout.base_commit, "bytes": patch.len()})
        );
        let mut lines = patch.lines();
        assert!(lines.next().unwrap().starts_with("From "), "{patch}");
        assert_eq!(
            lines.next().unwrap(),
            format!("X-GH-AW-Base-Commit: {}", home.checkout.base_commit)
        );
        assert_eq!(lines.next().unwrap(), "From: A Bot <bot@example.com>");
        assert!(
            patch.contains("Subject: [PATCH] parser: Keep the last line\n"),
            "{patch}"
        );
        assert!(
            patch.contains("\n    --- a/x\n+++ b/x\n    @@ -1 +1 @@\n"),
            "{patch}"
        );
        assert!(patch.contains("\nGenerated-by: AI\n---\n"), "{patch}");
        assert_eq!(
            std::fs::read_to_string(home.path("safe-outputs/base.json")).unwrap(),
            format!(
                "{{\"repo\":\"o/r\",\"ref\":\"main\",\"commit\":\"{}\"}}\n",
                home.checkout.base_commit
            )
        );
        assert_eq!(
            std::fs::read_to_string(home.path("results/outcome.json")).unwrap(),
            "{\"summary\":\"Done.\",\"tests\":[]}\n"
        );
        let verdict = home.verdict(&policy);
        assert!(verdict.ok, "{:?}", verdict.errors);
        let checked = verdict.patch.unwrap();
        assert_eq!(checked.files, ["a.txt", "sub/new-file.txt"]);
        assert_eq!(checked.base_commit, home.checkout.base_commit);

        // Applied as the apply job applies it, the commit is by the
        // configured author and says what the request said: nothing in
        // the agent's text chose its author, its date or its subject, cut
        // its message short or signed it off.
        let applied = home.path("applied");
        sh(
            home.dir.path(),
            &format!(
                "git clone -q work/r applied && cd applied && git checkout -q {} && \
                 git -c user.name=apply -c user.email=apply@example.invalid am -q --3way ../safe-outputs/{patch_name}",
                home.checkout.base_commit
            ),
        );
        let log = sh(&applied, "git log -1 --format='%an <%ae>%n%ad%n%B'");
        let mut lines = log.lines();
        assert_eq!(lines.next(), Some("A Bot <bot@example.com>"), "{log}");
        assert!(!lines.next().unwrap().contains("1970"), "{log}");
        let message: Vec<&str> = lines.collect();
        assert_eq!(
            message.join("\n").trim_end(),
            commit_message("parser: Keep the last line", body, &commit.trailers, RUN_ID).trim_end(),
        );
        assert_eq!(
            sh(&applied, "git log -1 --format='%(trailers:only,unfold)'").trim(),
            "Generated-by: AI"
        );
        assert_eq!(
            sh(&applied, "git diff --name-only HEAD~1"),
            "a.txt\nsub/new-file.txt\n"
        );
    }

    /// A push is handed back as a patch named for the pull request's
    /// branch, against the head the policy pins, and the check takes it.
    #[test]
    fn a_push_is_handed_back_as_a_patch_the_check_accepts() {
        let home = Home::new();
        let mut policy = crate::policy::tests::push_policy();
        policy.repo = "o/r".into();
        if let Some(push) = policy.safe_outputs.push_to_pull_request_branch.as_mut() {
            push.head.clone_from(&home.checkout.base_commit);
        }
        sh(&home.checkout.dir, "echo two >> a.txt");
        std::fs::write(
            home.path(AGENT_OUTPUTS),
            "{\"type\":\"push_to_pull_request_branch\",\"message\":\"parser: Keep the last line\\n\\nWhy.\"}\n",
        )
        .unwrap();
        let change = home.collect(&policy, &config::Commit::default());
        assert_eq!(change.dropped, None);
        let patch =
            std::fs::read_to_string(home.path("safe-outputs/aw-agent-run-12.patch")).unwrap();
        assert!(
            patch.contains("Subject: [PATCH] parser: Keep the last line\n"),
            "{patch}"
        );
        assert_eq!(
            std::fs::read_to_string(home.path("safe-outputs/base.json")).unwrap(),
            format!(
                "{{\"repo\":\"o/r\",\"ref\":\"agent-run-12\",\"commit\":\"{}\"}}\n",
                home.checkout.base_commit
            )
        );
        let verdict = home.verdict(&policy);
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert_eq!(verdict.patch.unwrap().files, ["a.txt"]);
    }

    #[test]
    fn a_push_without_a_message_uses_the_patch_message() {
        let home = Home::new();
        let mut policy = crate::policy::tests::push_policy();
        policy.repo = "o/r".into();
        policy
            .safe_outputs
            .push_to_pull_request_branch
            .as_mut()
            .unwrap()
            .head
            .clone_from(&home.checkout.base_commit);
        sh(&home.checkout.dir, "echo two >> a.txt");
        std::fs::write(
            home.path(AGENT_OUTPUTS),
            "{\"type\":\"push_to_pull_request_branch\"}\n",
        )
        .unwrap();
        std::fs::write(
            home.path(AGENT_OUTCOME),
            "{\"summary\":\"parser: Keep the last line\\nIt was dropped.\"}\n",
        )
        .unwrap();
        let change = home.collect(&policy, &config::Commit::default());
        assert_eq!(change.dropped, None);
        let outputs = std::fs::read_to_string(home.path("safe-outputs/outputs.jsonl")).unwrap();
        let item: Value = serde_json::from_str(outputs.trim()).unwrap();
        assert_eq!(
            item["message"],
            "parser: Keep the last line\n\nparser: Keep the last line\nIt was dropped."
        );
        let patch =
            std::fs::read_to_string(home.path("safe-outputs/aw-agent-run-12.patch")).unwrap();
        assert!(patch.contains("Subject: [PATCH] parser: Keep the last line\n"));
        assert!(patch.contains("\nIt was dropped.\n"));
        let verdict = home.verdict(&policy);
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert_eq!(verdict.patch.unwrap().files, ["a.txt"]);
    }

    /// A home whose checkout has one commit over its base, the policy that
    /// allows replacing the branch with it, and that commit's mail.
    fn replacement_home() -> (Home, Policy, String) {
        let home = Home::new();
        let mut policy = crate::policy::tests::push_policy();
        policy.repo = "o/r".into();
        let push = policy
            .safe_outputs
            .push_to_pull_request_branch
            .as_mut()
            .unwrap();
        push.head.clone_from(&home.checkout.base_commit);
        push.replacement_base = Some(home.checkout.base_commit.clone());
        push.replacement_max_commits = 2;
        sh(
            &home.checkout.dir,
            "echo two >> a.txt && git add a.txt && git -c user.name=t -c user.email=t@example.invalid commit -qm 'parser: Keep the last line'",
        );
        let mail = sh(
            &home.checkout.dir,
            "git format-patch --stdout --no-signature --no-renames -1 HEAD",
        );
        std::fs::write(
            home.path(AGENT_OUTPUTS),
            "{\"type\":\"push_to_pull_request_branch\",\"message\":\"Replace the series\"}\n",
        )
        .unwrap();
        (home, policy, mail)
    }

    #[test]
    fn a_replacement_preserves_the_series_and_checkout() {
        let (home, policy, mail) = replacement_home();
        let head = sh(&home.checkout.dir, "git rev-parse HEAD");
        let series =
            json!({"base_commit": home.checkout.base_commit, "commits": [mail]}).to_string();
        std::fs::write(home.path("out/replacement.json"), &series).unwrap();
        let change = home.collect(&policy, &config::Commit::default());
        assert_eq!(change.dropped, None);
        assert_eq!(sh(&home.checkout.dir, "git rev-parse HEAD"), head);
        assert_eq!(
            std::fs::read_to_string(home.path("safe-outputs/replacement.json")).unwrap(),
            series
        );
        assert!(!home.path("safe-outputs/base.json").exists());
        let verdict = home.verdict(&policy);
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert_eq!(
            verdict.patch.unwrap().commit_files,
            Some(vec![vec!["a.txt".into()]])
        );
    }

    /// What `$(git format-patch ...)` leaves: the mail without its final
    /// newline, which `git am` calls corrupt at apply.
    #[test]
    fn a_replacement_mail_without_its_final_newline_is_normalized_at_capture() {
        let (home, policy, mail) = replacement_home();
        let series =
            json!({"base_commit": home.checkout.base_commit, "commits": [mail.trim_end()]});
        std::fs::write(home.path("out/replacement.json"), series.to_string()).unwrap();
        let change = home.collect(&policy, &config::Commit::default());
        assert!(change.dropped.is_none());
        let captured: crate::check::replacement::Replacement = serde_json::from_slice(
            &std::fs::read(home.path("safe-outputs/replacement.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(captured.commits[0], mail);
    }

    #[test]
    fn untracked_binary_litter_does_not_spoil_the_handback() {
        let home = Home::new();
        let policy = policy(Kind::Branch, pull_requests());
        std::fs::write(home.checkout.dir.join("a.txt"), "changed\n").unwrap();
        std::fs::write(home.checkout.dir.join("new.txt"), "new text\n").unwrap();
        std::fs::create_dir(home.checkout.dir.join("__pycache__")).unwrap();
        let litter = "__pycache__/module.pyc";
        std::fs::write(home.checkout.dir.join(litter), b"compiled\0python").unwrap();
        std::fs::write(home.path(AGENT_OUTCOME), r#"{"summary":"Partial work."}"#).unwrap();
        let harness = harness(Outcome::Budget, Some("max-requests"));
        let change = home.collect_with_harness(&policy, &config::Commit::default(), Some(&harness));
        assert!(
            change.outcome["stopped_early"]
                .as_str()
                .unwrap()
                .contains("limit")
        );
        assert_eq!(change.dropped, None);
        assert_eq!(change.outcome[OMITTED_BINARY_FILES], json!([litter]));
        assert!(
            change.outcome["summary"]
                .as_str()
                .unwrap()
                .contains("omitted 1")
        );
        let saved: Value =
            serde_json::from_slice(&std::fs::read(home.path("results/outcome.json")).unwrap())
                .unwrap();
        assert_eq!(saved, change.outcome);
        assert!(home.checkout.dir.join(litter).exists());
        let verdict = home.verdict(&policy);
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert_eq!(verdict.patch.unwrap().files, ["a.txt", "new.txt"]);
    }

    /// A run cut off before it wrote an outcome has no summary to add the
    /// note to, and the pull request keeps its default title.
    #[test]
    fn omitted_litter_does_not_title_the_pull_request() {
        let home = Home::new();
        let policy = policy(Kind::Branch, pull_requests());
        std::fs::write(home.checkout.dir.join("a.txt"), "changed\n").unwrap();
        std::fs::write(home.checkout.dir.join("cache.pyc"), b"compiled\0python").unwrap();
        let change = home.collect(&policy, &config::Commit::default());
        assert_eq!(change.outcome[OMITTED_BINARY_FILES], json!(["cache.pyc"]));
        assert!(change.outcome.get("summary").is_none());
        let verdict = home.verdict(&policy);
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert_eq!(
            verdict.items[0]["title"],
            default_pull_request(&Object::default(), RUN_ID).title
        );
        assert_eq!(verdict.patch.unwrap().files, ["a.txt"]);
    }

    #[test]
    fn binary_litter_alone_does_not_create_a_pull_request() {
        let home = Home::new();
        let policy = policy(Kind::Branch, pull_requests());
        std::fs::write(home.checkout.dir.join("cache.pyc"), b"compiled\0python").unwrap();
        let change = home.collect(&policy, &config::Commit::default());
        assert!(change.patch.is_null());
        assert_eq!(change.dropped, None);
        assert_eq!(change.outcome[OMITTED_BINARY_FILES], json!(["cache.pyc"]));
        assert!(!home.path("safe-outputs").exists());
    }

    #[test]
    fn tracked_binary_changes_are_not_silently_omitted() {
        let home = Home::new();
        let policy = policy(Kind::Branch, pull_requests());
        std::fs::write(home.checkout.dir.join("a.txt"), b"changed\0binary").unwrap();
        let change = home.collect(&policy, &config::Commit::default());
        assert!(change.outcome.get(OMITTED_BINARY_FILES).is_none());
        assert!(!home.verdict(&policy).ok);
    }

    #[test]
    fn binary_additions_use_literal_paths_and_preserve_staged_files() {
        for name in ["cache.pyc", "tab\tname", "line\nname", ":(glob)*", "-cache"] {
            for staged in [false, true] {
                let home = Home::new();
                let policy = policy(Kind::Branch, pull_requests());
                std::fs::write(home.checkout.dir.join("a.txt"), "changed\n").unwrap();
                std::fs::write(home.checkout.dir.join(name), b"compiled\0binary").unwrap();
                // A matching-looking text filename must never be reset along
                // with the binary, even when its name contains pathspec magic.
                std::fs::write(home.checkout.dir.join("keep.txt"), "keep\n").unwrap();
                if staged {
                    sh(&home.checkout.dir, "git add --all");
                }
                let change = home.collect(&policy, &config::Commit::default());
                assert_eq!(change.dropped, None, "{name:?}, staged={staged}");
                assert!(home.checkout.dir.join(name).exists());
                let verdict = home.verdict(&policy);
                if staged {
                    assert!(change.outcome.get(OMITTED_BINARY_FILES).is_none());
                    assert!(!verdict.ok, "{name:?}: {:?}", verdict.errors);
                } else {
                    assert_eq!(change.outcome[OMITTED_BINARY_FILES], json!([name]));
                    assert!(verdict.ok, "{name:?}: {:?}", verdict.errors);
                    assert_eq!(verdict.patch.unwrap().files, ["a.txt", "keep.txt"]);
                }
            }
        }
    }

    #[test]
    fn larger_mixed_set_omits_only_untracked_binaries() {
        let home = Home::new();
        let policy = policy(Kind::Branch, pull_requests());
        let mut expected = Vec::new();
        for i in 0..512 {
            for (kind, contents) in [
                ("binary", b"compiled\0binary".as_slice()),
                ("text", b"text\n"),
            ] {
                let name = format!("{kind}-{i:04}");
                std::fs::write(home.checkout.dir.join(&name), contents).unwrap();
                if kind == "binary" {
                    expected.push(name);
                }
            }
        }
        sh(&home.checkout.dir, "git add -- binary-0000 text-0000");
        expected.remove(0);
        let change = home.collect(&policy, &config::Commit::default());
        assert_eq!(change.dropped, None);
        assert_eq!(change.outcome[OMITTED_BINARY_FILES], json!(expected));
        let remaining = sh(&home.checkout.dir, "git ls-tree --name-only HEAD");
        let mut expected_remaining = vec!["a.txt".to_owned(), "binary-0000".to_owned()];
        expected_remaining.extend((0..512).map(|i| format!("text-{i:04}")));
        assert_eq!(remaining.lines().collect::<Vec<_>>(), expected_remaining);
    }

    /// The checkout's git configuration is the agent's, and so is the
    /// sandbox user's own. It does not choose who the commit is by; and
    /// what it can do to the patch gets the patch refused, not accepted
    /// as something else.
    #[test]
    fn the_checkouts_configuration_does_not_choose_the_author() {
        let policy = policy(Kind::Branch, pull_requests());
        let commit = config::Commit {
            author: Some("A Bot <bot@example.com>".into()),
            trailers: Vec::new(),
        };
        let identity = "git config author.name Evil && git config author.email evil@example.org && \
            git config committer.name Evil && git config committer.email evil@example.org && \
            git config user.name Evil && git config user.email evil@example.org && \
            git config commit.cleanup strip && git config commit.gpgsign true && \
            mkdir -p .git/hooks && printf '#!/bin/sh\\nexit 1\\n' > .git/hooks/pre-commit && \
            chmod +x .git/hooks/pre-commit && echo two >> a.txt";
        let home = Home::new();
        sh(&home.checkout.dir, identity);
        let change = home.collect(&policy, &commit);
        assert_eq!(change.dropped, None, "{}", change.patch);
        let patch =
            std::fs::read_to_string(home.path("safe-outputs/aw-agent-run-42.patch")).unwrap();
        assert!(
            patch.contains("\nFrom: A Bot <bot@example.com>\n"),
            "{patch}"
        );
        assert!(!patch.contains("Evil"), "{patch}");
        assert!(home.verdict(&policy).ok);

        // Nor does what it would have `format-patch` add to the mail:
        // applied, the commit is still the configured author's, of now,
        // with the request's subject, and nobody signed it off.
        let hostile = [
            "git config format.headers 'From: Evil <evil@example.org>\nDate: Thu, 1 Jan 1970 00:00:00 +0000\n'",
            "git config format.from 'Evil <evil@example.org>'",
            "git config format.signoff true",
            "git config format.subjectPrefix EVIL && git config format.numbered true && \
             git config format.attach true && git config format.thread true && \
             git config format.to evil@example.org && git config format.cc evil@example.org && \
             git config format.useAutoBase whenAble",
        ];
        for settings in hostile {
            let home = Home::new();
            sh(
                &home.checkout.dir,
                &format!("{settings} && echo two >> a.txt"),
            );
            std::fs::write(
                home.path(AGENT_OUTPUTS),
                "{\"type\":\"create_pull_request\",\"title\":\"T\",\"body\":\"B\"}\n",
            )
            .unwrap();
            let change = home.collect(&policy, &commit);
            assert_eq!(change.dropped, None, "{settings}");
            let verdict = home.verdict(&policy);
            assert!(verdict.ok, "{settings}: {:?}", verdict.errors);
            let applied = home.path("applied");
            sh(
                home.dir.path(),
                &format!(
                    "git clone -q work/r applied && cd applied && git checkout -q {} && \
                     git -c user.name=apply -c user.email=apply@example.invalid am -q --3way \
                     ../safe-outputs/aw-agent-run-42.patch",
                    home.checkout.base_commit
                ),
            );
            let log = sh(&applied, "git log -1 --format='%an <%ae>|%ad|%s|%b'");
            let fields: Vec<&str> = log.trim().split('|').collect();
            assert_eq!(fields[0], "A Bot <bot@example.com>", "{settings}: {log}");
            assert!(!fields[1].contains("1970"), "{settings}: {log}");
            assert_eq!(&fields[2..], ["T", "B"], "{settings}: {log}");
        }
    }

    /// A checkout git cannot read is not taken for one with no change:
    /// neither one without its repository, nor one whose index is
    /// damaged, where only the listing of changes fails.
    #[test]
    fn a_checkout_git_cannot_read_is_said_to_be() {
        let policy = policy(Kind::Branch, pull_requests());
        for damage in ["rm -rf .git", "printf garbage > .git/index"] {
            let home = Home::new();
            sh(
                &home.checkout.dir,
                &format!("echo two >> a.txt && {damage}"),
            );
            let change = home.collect(&policy, &config::Commit::default());
            assert_eq!(
                change.dropped.as_deref(),
                Some("git cannot read the checkout any more"),
                "{damage}"
            );
            assert!(!home.path("safe-outputs").exists(), "{damage}");
        }
    }

    /// What is not handed back, and why the summary says so.
    #[test]
    fn changes_that_are_not_handed_back() {
        let pull = policy(Kind::Branch, pull_requests());
        let noop_only = policy(Kind::Branch, json!({"noop": {"max": 1}}));
        let analysis = policy(Kind::Analysis, json!({"noop": {"max": 1}}));
        let mut small = pull.clone();
        small.max_patch_bytes = 64;
        let noop = "{\"type\":\"noop\",\"message\":\"m\"}\n";
        // (the case, the policy, the agent's requests, whether it changes
        // a file, why the change was dropped, the files handed back)
        type Case<'a> = (
            &'a str,
            &'a Policy,
            &'a str,
            bool,
            Option<&'a str>,
            &'a [&'a str],
        );
        let cases: &[Case] = &[
            ("nothing at all", &pull, "", false, None, &[]),
            (
                "only a request",
                &pull,
                noop,
                false,
                None,
                &["outputs.jsonl"],
            ),
            (
                "pull requests are not allowed",
                &noop_only,
                noop,
                true,
                Some("changes dropped: create_pull_request is not an allowed output"),
                &["outputs.jsonl"],
            ),
            ("an analysis run", &analysis, "", true, None, &[]),
            (
                "an analysis run's request",
                &analysis,
                noop,
                true,
                None,
                &["outputs.jsonl"],
            ),
            (
                "a change over the cap",
                &small,
                noop,
                true,
                Some("the change is over 64 bytes"),
                &[],
            ),
        ];
        for (name, policy, requests, changes, dropped, handed_back) in cases {
            let home = Home::new();
            if *changes {
                sh(&home.checkout.dir, "echo two >> a.txt");
            }
            if !requests.is_empty() {
                std::fs::write(home.path(AGENT_OUTPUTS), requests).unwrap();
            }
            let change = home.collect(policy, &config::Commit::default());
            assert_eq!(change.dropped.as_deref(), *dropped, "{name}");
            assert_eq!(change.patch["error"].as_str(), *dropped, "{name}");
            assert_eq!(change.files.is_empty(), !changes, "{name}");
            let mut names: Vec<String> = std::fs::read_dir(home.path("safe-outputs"))
                .map(|entries| {
                    entries
                        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            names.sort();
            assert_eq!(names, *handed_back, "{name}");
        }
    }

    /// The agent's own commits are part of the change, and a tree it
    /// committed and then put back hands back nothing.
    #[test]
    fn commits_of_the_agent_are_part_of_the_change() {
        let policy = policy(Kind::Branch, pull_requests());
        let commit = "git -c user.name=a -c user.email=a@example.invalid commit -q -am";
        let home = Home::new();
        sh(
            &home.checkout.dir,
            &format!("echo two >> a.txt && {commit} Mine"),
        );
        let change = home.collect(&policy, &config::Commit::default());
        assert!(change.files.is_empty());
        assert!(change.patch["bytes"].as_u64().is_some(), "{}", change.patch);
        let verdict = home.verdict(&policy);
        assert!(verdict.ok, "{:?}", verdict.errors);
        assert_eq!(verdict.patch.unwrap().files, ["a.txt"]);

        let home = Home::new();
        sh(
            &home.checkout.dir,
            &format!("echo two >> a.txt && {commit} Mine && echo one > a.txt && {commit} Back"),
        );
        let change = home.collect(&policy, &config::Commit::default());
        assert_eq!(change.patch, Value::Null);
        assert_eq!(change.dropped, None);
    }

    /// A link where a hand-back file should be is not read, whatever it
    /// names; neither is a file over the cap, or one that is no object.
    #[test]
    fn files_that_are_not_taken() {
        let policy = policy(Kind::Branch, pull_requests());
        let home = Home::new();
        let elsewhere = home.path("elsewhere.json");
        std::fs::write(&elsewhere, "{\"summary\": \"LINKED-CONTENT\"}\n").unwrap();
        symlink(&elsewhere, home.path(AGENT_OUTCOME)).unwrap();
        symlink(&elsewhere, home.path(AGENT_OUTPUTS)).unwrap();
        let change = home.collect(&policy, &config::Commit::default());
        assert_eq!(change.outcome, json!({}));
        assert!(!home.path("safe-outputs").exists());
        assert_eq!(
            std::fs::read_to_string(home.path("results/outcome.json")).unwrap(),
            "{}\n"
        );

        // (the outcome file, the outcome taken)
        let big = format!("{{\"summary\": \"{}\"}}", "x".repeat(MAX_OUTCOME_BYTES));
        let cases = [
            (big.as_str(), json!({})),
            ("[1, 2]", json!({})),
            ("not json", json!({})),
            ("{\"summary\": \"s\"}", json!({"summary": "s"})),
        ];
        for (text, want) in cases {
            let home = Home::new();
            std::fs::write(home.path(AGENT_OUTCOME), text).unwrap();
            let change = home.collect(&policy, &config::Commit::default());
            assert_eq!(change.outcome, want, "{}", &text[..text.len().min(40)]);
        }
    }
}
