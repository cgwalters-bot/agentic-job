//! `agentic-job applied`: apply.yml's guard against applying twice what
//! check accepted, before gh-aw's handlers run.
//!
//! A re-run of apply applies check's accepted outputs again, and the
//! handlers would post each comment, issue and pull request again. Each is
//! named by this run, its place and a digest: sha256 over the artifact
//! prefix, NUL, the request as JavaScript's `JSON.stringify` writes it,
//! and for a pull request NUL and the checked patch. The name goes last in
//! the body, which the handlers' step hides in what it posts; a request
//! whose name the token's own user already posted is left out
//! (`skipped.json`), the others are applied. Only the last name in a body
//! counts, and check refuses requests holding one.
//!
//! A close found applied closes what is still open, without a second
//! comment: the handlers comment before they close. An issue someone
//! reopened stays open. A push found already applied, as one commit with
//! the checked tree on the pinned head, is left out; a replacement series
//! is pushed here with a lease and never reaches the handler.
//!
//! Before anything is written, a close_issue naming a pull request or a
//! transferred issue refuses the run, and so does a reply to a review
//! comment off the run's pull request and a pull request without a fork.
//! A redirect (a renamed repository, a transferred issue) is not
//! followed with the token, unlike octokit, which followed it: it refuses
//! the run.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Value, json};

use super::github::{GH_TOKEN_ENV, Github, is_repo};
use super::{ADD_COMMENT, CLOSE_ISSUE, CLOSE_PULL_REQUEST, CREATE_ISSUE, owner};
use crate::exit::Exit;
use crate::files;
use crate::policy::{CREATE_PULL_REQUEST, PUSH_TO_PULL_REQUEST_BRANCH, REPLY_TO_REVIEW_COMMENT};

/// Where the fork and the pull requests are, as the handlers name them.
const GITHUB: &str = "https://github.com";

/// The author of what the job token posts.
const JOB_TOKEN_AUTHOR: &str = "github-actions[bot]";

/// The requests that leave something a re-run finds by its name.
const NAMED: [&str; 5] = [
    ADD_COMMENT,
    CLOSE_ISSUE,
    CLOSE_PULL_REQUEST,
    CREATE_ISSUE,
    CREATE_PULL_REQUEST,
];

/// The pull request's branch as the trial fetched it.
const FETCHED: &str = "refs/agentic-job/target-base";

/// The most of agent_output.json, config.json and report.json read: check's
/// own bound on the collector's result.
const MAX_JSON: u64 = 4 << 20;

/// The most of a checked patch read: a pull request whose patch is larger
/// refuses the run.
const MAX_PATCH_BYTES: u64 = 64 << 20;

/// A page of 100 comments of up to 65,536 characters each.
pub(super) const MAX_PAGE_BYTES: u64 = 32 << 20;

const SUMMARY_HEADING: &str = "Already applied by an earlier attempt, so left out";

/// The names in a posted body, hidden as the handlers' step hides them.
static POSTED_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<!-- (agentic-job-applied: [0-9]+/[0-9]+/[0-9a-f]{16}) -->")
        .expect("a valid pattern")
});

static DIGITS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]+$").expect("a valid pattern"));

#[derive(Debug, clap::Args)]
pub struct Args {
    /// GH_AW_TMP: agent_output.json, rewritten, config.json, the checked patch and skipped.json, written
    #[arg(long, value_name = "DIR")]
    pub dir: PathBuf,
    /// check's report.json
    #[arg(long, value_name = "FILE")]
    pub report: PathBuf,
    /// The repository pull requests and issues are opened in
    #[arg(long)]
    pub output_repo: String,
    /// The repository the run worked on, which closes and pushes go to
    #[arg(long)]
    pub repo: String,
    /// The repository of the run's item, which comments go to
    #[arg(long)]
    pub item_repo: String,
    /// The policy's comment target: the run's item number, or none
    #[arg(long, default_value = "", allow_hyphen_values = true)]
    pub comment_target: String,
    /// The policy's branch prefix, which the handler puts before a pull request's branch
    #[arg(long, default_value = "", allow_hyphen_values = true)]
    pub branch_prefix: String,
    /// The policy's artifact prefix, which every name digests
    #[arg(long, default_value = "", allow_hyphen_values = true)]
    pub artifact_prefix: String,
    /// Where a pull request's branch is pushed: the fork step's repository, empty for none
    #[arg(long, default_value = "")]
    pub fork: String,
    /// The branch of the pull request a push goes to
    #[arg(long, default_value = "")]
    pub base: String,
    /// The tree the trial built from the checked patch
    #[arg(long, default_value = "")]
    pub tree: String,
    /// The head the trial rebuilt a replacement series as
    #[arg(long, default_value = "")]
    pub replacement_head: String,
    /// Whether GH_TOKEN is SAFE_OUTPUTS_PAT rather than the job token
    #[arg(long, action = clap::ArgAction::Set)]
    pub token_is_pat: bool,
}

/// A JSON value as JavaScript's `JSON.parse` reads one: keys in their
/// order, a repeated key's last value in its first place, every number a
/// double. [`Js::stringify`] writes it as `JSON.stringify` does, array
/// indices first, which is
/// what a name digests.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Js {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Js>),
    Object(Vec<(String, Js)>),
}

impl<'de> Deserialize<'de> for Js {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsVisitor;

        impl<'de> Visitor<'de> for JsVisitor {
            type Value = Js;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON")
            }

            fn visit_unit<E>(self) -> Result<Js, E> {
                Ok(Js::Null)
            }

            fn visit_bool<E>(self, value: bool) -> Result<Js, E> {
                Ok(Js::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Js, E> {
                Ok(Js::Number(value as f64))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Js, E> {
                Ok(Js::Number(value as f64))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Js, E> {
                Ok(Js::Number(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Js, E> {
                Ok(Js::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Js, E> {
                Ok(Js::String(value))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Js, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Js::Array(values))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Js, A::Error> {
                let mut object = Js::Object(Vec::new());
                while let Some((key, value)) = map.next_entry::<String, Js>()? {
                    object.set(&key, value);
                }
                Ok(object)
            }
        }

        deserializer.deserialize_any(JsVisitor)
    }
}

impl Js {
    /// The value of KEY, of an object.
    pub(super) fn get(&self, key: &str) -> Option<&Js> {
        match self {
            Js::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Sets KEY in its place, or last, as `{...object, key}` does.
    fn set(&mut self, key: &str, value: Js) {
        if let Js::Object(entries) = self {
            match entries.iter_mut().find(|(k, _)| k == key) {
                Some((_, old)) => *old = value,
                None => entries.push((key.to_owned(), value)),
            }
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Js::String(text) => Some(text),
            _ => None,
        }
    }

    fn of(entries: &[(&str, Js)]) -> Js {
        Js::Object(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        )
    }

    /// A forge's answer: its keys' order is not digested.
    fn from_value(value: &Value) -> Js {
        match value {
            Value::Null => Js::Null,
            Value::Bool(value) => Js::Bool(*value),
            Value::Number(number) => Js::Number(number.as_f64().unwrap_or(f64::NAN)),
            Value::String(text) => Js::String(text.clone()),
            Value::Array(values) => Js::Array(values.iter().map(Js::from_value).collect()),
            Value::Object(entries) => Js::Object(
                entries
                    .iter()
                    .map(|(key, value)| (key.clone(), Js::from_value(value)))
                    .collect(),
            ),
        }
    }

    /// The JSON a request sends.
    fn to_value(&self) -> Value {
        match self {
            Js::Null => Value::Null,
            Js::Bool(value) => Value::Bool(*value),
            Js::Number(number) => serde_json::from_str(&js_number(*number)).unwrap_or(Value::Null),
            Js::String(text) => Value::String(text.clone()),
            Js::Array(values) => Value::Array(values.iter().map(Js::to_value).collect()),
            Js::Object(entries) => Value::Object(
                entries
                    .iter()
                    .map(|(key, value)| (key.clone(), value.to_value()))
                    .collect(),
            ),
        }
    }

    /// `JSON.stringify` of the value.
    pub(super) fn stringify(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Js::Null => out.push_str("null"),
            Js::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Js::Number(number) if number.is_finite() => out.push_str(&js_number(*number)),
            Js::Number(_) => out.push_str("null"),
            // serde_json escapes what `JSON.stringify` does, the same way.
            Js::String(text) => out.push_str(&Value::String(text.clone()).to_string()),
            Js::Array(values) => {
                out.push('[');
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    value.write(out);
                }
                out.push(']');
            }
            Js::Object(entries) => {
                // JavaScript keeps an object's array indices first, in
                // their order, and its other keys after them as they came.
                let mut entries: Vec<_> = entries.iter().collect();
                entries.sort_by_key(|(key, _)| array_index(key).unwrap_or(u32::MAX));
                out.push('{');
                for (i, (key, value)) in entries.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String(key.clone()).to_string());
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// KEY as an array index, which JavaScript orders an object's keys by:
/// the canonical decimal of a number below 2^32 - 1.
fn array_index(key: &str) -> Option<u32> {
    let canonical = key == "0" || (!key.starts_with('0') && key.len() <= 10);
    key.parse::<u32>()
        .ok()
        .filter(|index| canonical && key.bytes().all(|b| b.is_ascii_digit()) && *index < u32::MAX)
}

/// JavaScript's `String(value)`; None is `undefined`.
fn js_string(value: Option<&Js>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Js::Null) => "null".to_owned(),
        Some(Js::Bool(value)) => value.to_string(),
        Some(Js::Number(number)) => js_number(*number),
        Some(Js::String(text)) => text.clone(),
        Some(Js::Array(values)) => values
            .iter()
            .map(|value| match value {
                Js::Null => String::new(),
                value => js_string(Some(value)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Js::Object(_)) => "[object Object]".to_owned(),
    }
}

/// JavaScript's `String(value)` of a forge's answer.
fn value_string(value: Option<&Value>) -> String {
    js_string(value.map(Js::from_value).as_ref())
}

/// JavaScript's `Number.prototype.toString()`: the shortest digits that
/// read back as NUMBER, placed as ECMA-262's Number::toString places them.
fn js_number(number: f64) -> String {
    if number.is_nan() {
        return "NaN".to_owned();
    }
    if number.is_infinite() {
        return if number > 0.0 {
            "Infinity"
        } else {
            "-Infinity"
        }
        .to_owned();
    }
    if number == 0.0 {
        return "0".to_owned();
    }
    let sign = if number < 0.0 { "-" } else { "" };
    // Rust writes the shortest round-tripping digits too: `1.25e-7`.
    let scientific = format!("{:e}", number.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let digits = mantissa.replace('.', "");
    let k = digits.len() as i64;
    let n = exponent.parse::<i64>().unwrap_or(0) + 1;
    let zeros = |count: i64| "0".repeat(count.max(0) as usize);
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", zeros(n - k))
    } else if 0 < n && n <= 21 {
        let (whole, fraction) = digits.split_at(n as usize);
        format!("{whole}.{fraction}")
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", zeros(-n))
    } else {
        let e = n - 1;
        let e = if e >= 0 {
            format!("+{e}")
        } else {
            e.to_string()
        };
        match digits.split_at(1) {
            (first, "") => format!("{first}e{e}"),
            (first, rest) => format!("{first}.{rest}e{e}"),
        }
    };
    format!("{sign}{body}")
}

/// What JavaScript takes for true.
fn truthy(value: Option<&Js>) -> bool {
    match value {
        None | Some(Js::Null) => false,
        Some(Js::Bool(value)) => *value,
        Some(Js::Number(number)) => *number != 0.0 && !number.is_nan(),
        Some(Js::String(text)) => !text.is_empty(),
        Some(Js::Array(_) | Js::Object(_)) => true,
    }
}

/// VALUE as octokit puts a parameter in a path: `encodeURIComponent` of
/// its `String()`.
fn param(value: Option<&Js>) -> String {
    js_string(value)
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => char::from(b).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// JavaScript's `Number(value)`, for an id the request names: a number,
/// or text of one.
fn js_to_number(value: Option<&Js>) -> f64 {
    match value {
        Some(Js::Number(number)) => *number,
        Some(Js::String(text)) if text.trim().is_empty() => 0.0,
        Some(Js::String(text)) => text
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|_| {
                text.trim()
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b"+-.eE".contains(&b))
            })
            .unwrap_or(f64::NAN),
        Some(Js::Null) => 0.0,
        Some(Js::Bool(value)) => f64::from(u8::from(*value)),
        _ => f64::NAN,
    }
}

/// The name a request is applied under: RUN, its INDEX among the run's
/// requests, and the first 16 hex digits of sha256 over PREFIX, NUL, the
/// request as `JSON.stringify` writes it, and for a pull request NUL and
/// its PATCH. An input and JSON hold no NUL, so they cannot run into each
/// other.
pub(super) fn name(
    prefix: &str,
    run: &str,
    index: usize,
    item: &Js,
    patch: Option<&[u8]>,
) -> String {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(prefix.as_bytes());
    hash.update(b"\0");
    hash.update(item.stringify().as_bytes());
    if let Some(patch) = patch {
        hash.update(b"\0");
        hash.update(patch);
    }
    let digest: String = hash.finish().as_ref()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("agentic-job-applied: {run}/{index}/{digest}")
}

/// The local git the guard reads and a replacement series is pushed with.
pub(super) trait Workspace {
    /// The parents (`%P`) and tree of [`FETCHED`].
    fn fetched(&self) -> Result<(String, String)>;

    /// `agentic-job replacement push`.
    fn push_replacement(
        &self,
        remote: &str,
        branch: &str,
        original: &str,
        replacement: &str,
    ) -> Result<()>;
}

/// The job's checkout, the working directory.
struct Checkout;

impl Workspace for Checkout {
    fn fetched(&self) -> Result<(String, String)> {
        let here = Path::new(".");
        let parents = super::replacement::git(here, &["show", "-s", "--format=%P", FETCHED])?;
        let tree = super::replacement::git(here, &["rev-parse", &format!("{FETCHED}^{{tree}}")])?;
        Ok((parents, tree))
    }

    fn push_replacement(
        &self,
        remote: &str,
        branch: &str,
        original: &str,
        replacement: &str,
    ) -> Result<()> {
        super::replacement::push(Path::new("."), remote, branch, original, replacement)
    }
}

/// What the guard decided, for the files it rewrites.
#[derive(Debug)]
pub(super) struct Decided {
    /// agent_output.json with what is left to apply, each named.
    pub output: Js,
    /// skipped.json's entries.
    pub skipped: Vec<Js>,
}

/// The run the guard works for.
pub(super) struct Guard<'a> {
    pub github: &'a Github,
    pub workspace: &'a dyn Workspace,
    pub args: &'a Args,
    /// `GITHUB_RUN_ID`.
    pub run: &'a str,
    /// Whose posts count as applied: the token's user, if it has one.
    pub me: Option<&'a str>,
}

fn read_regular(path: &Path, max: u64) -> Result<Vec<u8>> {
    files::read_regular(path, max).with_context(|| format!("reading {}", path.display()))
}

fn read_js(path: &Path) -> Result<Js> {
    serde_json::from_slice(&read_regular(path, MAX_JSON)?)
        .with_context(|| format!("parsing {}", path.display()))
}

/// The user GITHUB's token posts as: the job token's bot, or the user
/// `GET /user` names for a PAT. A PAT it does not name (an app's token)
/// has no one, and nothing posted counts as applied.
fn identity(github: &Github, pat: bool) -> Option<String> {
    if github.configured() {
        return None;
    }
    if !pat {
        return Some(JOB_TOKEN_AUTHOR.to_owned());
    }
    github
        .get("/user")
        .ok()
        .and_then(|user| user["login"].as_str().map(str::to_owned))
}

impl Guard<'_> {
    /// Whether FOUND is ME's, with NAME the last name in its body.
    fn marked(&self, found: &Value, name: &str, role: super::roles::Role) -> bool {
        self.github.owns(role, found, self.me)
            && POSTED_NAME_RE
                .captures_iter(found["body"].as_str().unwrap_or_default())
                .last()
                .is_some_and(|last| &last[1] == name)
    }

    /// The checked patch a pull request applies.
    fn patch(&self) -> Result<Vec<u8>> {
        let report = read_js(&self.args.report)?;
        let file = report.get("patch").and_then(|patch| patch.get("file"));
        if !truthy(file) {
            bail!("a pull request is to be opened, and check accepted no patch");
        }
        let file = js_string(file);
        let base = Path::new(&file)
            .file_name()
            .with_context(|| format!("the patch file {file:?} has no name"))?;
        read_regular(&self.args.dir.join(base), MAX_PATCH_BYTES)
    }

    fn api_repo(&self, repo: &str) -> String {
        format!("{}/repos/{repo}", self.github.api_url()).to_lowercase()
    }

    /// Issues and pull requests share numbers, and gh-aw's close_issue
    /// handler closes and comments on a pull request through the issues
    /// API without looking; check cannot tell them apart. So a close_issue
    /// naming a pull request refuses the run, before anything is applied,
    /// rather than let it close what the bounds only grant
    /// close_pull_request for. So does one whose issue was transferred:
    /// the API follows it to the other repository. Returns each issue by
    /// its request's index.
    fn issues(&self, items: &[Js]) -> Result<BTreeMap<usize, Value>> {
        let repo = &self.args.repo;
        let mut issues = BTreeMap::new();
        for (index, item) in items.iter().enumerate() {
            if item.get("type").and_then(Js::as_str) != Some(CLOSE_ISSUE) {
                continue;
            }
            let number = item.get("issue_number");
            let data = self
                .github
                .get(&format!("/repos/{repo}/issues/{}", param(number)))?;
            let shown = js_string(number);
            ensure!(
                !truthy(Some(&Js::from_value(&data["pull_request"]))),
                "a close_issue names #{shown}, which is a pull request"
            );
            ensure!(
                value_string(data.get("repository_url")).to_lowercase() == self.api_repo(repo),
                "a close_issue names #{shown}, which is not an issue of {repo}"
            );
            issues.insert(index, data);
        }
        Ok(issues)
    }

    /// gh-aw's reply handler posts to the replies URL of the run's pull
    /// request without looking up the comment it names, which check
    /// cannot either. So a reply to a comment on another pull request, or
    /// in another repository, refuses the run, before anything is
    /// applied, whatever the forge would make of it.
    fn replies(&self, items: &[Js]) -> Result<()> {
        let Args {
            item_repo,
            comment_target,
            ..
        } = self.args;
        let pull = format!("{}/pulls/{comment_target}", self.api_repo(item_repo));
        for item in items {
            if item.get("type").and_then(Js::as_str) != Some(REPLY_TO_REVIEW_COMMENT) {
                continue;
            }
            let id = item.get("comment_id");
            let data = self
                .github
                .for_role(super::roles::Role::Review)?
                .get(&format!(
                    "/repos/{item_repo}/pulls/comments/{}",
                    js_number(js_to_number(id))
                ))?;
            ensure!(
                value_string(data.get("pull_request_url")).to_lowercase() == pull.to_lowercase(),
                "a reply_to_pull_request_review_comment names comment {}, which is not on pull \
                 request #{comment_target} of {item_repo}",
                js_string(id)
            );
        }
        Ok(())
    }

    /// Decides what of the requests is left to apply, setting the step's
    /// outputs with OUTPUT as it goes; closes what an earlier attempt
    /// commented on and did not close, and pushes a replacement series.
    pub(super) fn decide(
        &self,
        output: &mut dyn FnMut(&str, &str) -> Result<()>,
    ) -> Result<Decided> {
        let args = self.args;
        let mut document = read_js(&args.dir.join("agent_output.json"))?;
        let Some(Js::Array(items)) = document.get("items") else {
            bail!("agent_output.json holds no items");
        };
        let items = items.clone();
        let issues = self.issues(&items)?;
        self.replies(&items)?;
        let is_type = |item: &Js, kind: &str| item.get("type").and_then(Js::as_str) == Some(kind);
        // A pull request's name holds the patch, which must be there; and
        // the handler opens one only from the fork the fork step chose.
        let patch = if items.iter().any(|item| is_type(item, CREATE_PULL_REQUEST)) {
            let patch = self.patch()?;
            ensure!(
                !args.fork.is_empty(),
                "a pull request is to be opened, and there is no fork to open it from"
            );
            Some(patch)
        } else {
            None
        };
        let pull_url = |config: &Js| {
            format!(
                "{GITHUB}/{}/pull/{}",
                args.output_repo,
                js_string(config.get("target"))
            )
        };
        let (mut kept, mut skipped) = (Vec::new(), Vec::new());
        for (index, item) in items.iter().enumerate() {
            let kind = item.get("type").and_then(Js::as_str).unwrap_or_default();
            if kind == PUSH_TO_PULL_REQUEST_BRANCH {
                let report = read_js(&args.report)?;
                let config = read_js(&args.dir.join("config.json"))?;
                let config = config.get(PUSH_TO_PULL_REQUEST_BRANCH).unwrap_or(&Js::Null);
                let head = config.get("head").and_then(Js::as_str);
                let applied = if truthy(report.get("patch").and_then(|p| p.get("commit_files"))) {
                    self.workspace.push_replacement(
                        &format!("{GITHUB}/{}", args.fork),
                        &args.base,
                        head.unwrap_or_default(),
                        &args.replacement_head,
                    )?;
                    true
                } else {
                    // The fork was checked and fetched before the trial.
                    // Like the post-push check, require exactly one parent
                    // and the checked tree: an unrelated advance is not
                    // applied.
                    let (parents, tree) = self.workspace.fetched()?;
                    head == Some(parents.as_str()) && tree == args.tree
                };
                if applied {
                    skipped.push(Js::of(&[
                        ("type", Js::String(kind.to_owned())),
                        ("url", Js::String(pull_url(config))),
                    ]));
                } else {
                    kept.push(item.clone());
                }
                continue;
            }
            if !NAMED.contains(&kind) {
                kept.push(item.clone());
                continue;
            }
            let digested = if kind == CREATE_PULL_REQUEST {
                patch.as_deref()
            } else {
                None
            };
            let name = name(&args.artifact_prefix, self.run, index, item, digested);
            let found = self.find(index, item, kind, &name, &issues, output)?;
            match found {
                Some(found) => {
                    let mut entry = Js::of(&[
                        ("type", Js::String(kind.to_owned())),
                        ("name", Js::String(name)),
                    ]);
                    if let Some(url) = found.get("html_url") {
                        entry.set("url", Js::from_value(url));
                    }
                    skipped.push(entry);
                }
                None => {
                    let body = match item.get("body") {
                        None | Some(Js::Null) => String::new(),
                        body => js_string(body),
                    };
                    let mut item = item.clone();
                    item.set("body", Js::String(format!("{body}\n\n{name}")));
                    kept.push(item);
                }
            }
        }
        document.set("items", Js::Array(kept));
        Ok(Decided {
            output: document,
            skipped,
        })
    }

    /// What an earlier attempt posted for ITEM, of KIND, under NAME.
    fn find(
        &self,
        index: usize,
        item: &Js,
        kind: &str,
        name: &str,
        issues: &BTreeMap<usize, Value>,
        output: &mut dyn FnMut(&str, &str) -> Result<()>,
    ) -> Result<Option<Value>> {
        let args = self.args;
        let role = super::roles::Role::output(kind);
        let github = self.github.for_role(role)?;
        let marked = |found: &&Value| self.marked(found, name, role);
        let found = match kind {
            ADD_COMMENT => {
                let target = if DIGITS_RE.is_match(&args.comment_target) {
                    args.comment_target.clone()
                } else {
                    js_string(item.get("item_number"))
                };
                if !DIGITS_RE.is_match(&target) {
                    return Ok(None);
                }
                let number = js_number(target.parse::<f64>().unwrap_or(f64::NAN));
                github
                    .issue_comments(&args.item_repo, &number)?
                    .iter()
                    .find(marked)
                    .cloned()
            }
            CLOSE_PULL_REQUEST => {
                // Its handler comments again on a pull request already
                // closed. The handler comments before it closes, so an
                // attempt can stop between the two: close what is still
                // open, as the handler would (its configuration has no
                // filters), without a second comment.
                let number = param(item.get("pull_request_number"));
                let found = github
                    .issue_comments(&args.repo, &number)?
                    .iter()
                    .find(marked)
                    .cloned();
                if found.is_some() {
                    let pull = format!("/repos/{}/pulls/{number}", args.repo);
                    if github.get(&pull)?["state"] != "closed" {
                        github.send("PATCH", &pull, Some(&json!({"state": "closed"})))?;
                    }
                }
                found
            }
            CLOSE_ISSUE => {
                // The same for an issue: its handler comments again on one
                // already closed. Check held it to the run's repository. An
                // issue someone reopened is left open, even one reopened
                // before this run: a re-run does not overrule a person.
                let number = param(item.get("issue_number"));
                let found = github
                    .issue_comments(&args.repo, &number)?
                    .iter()
                    .find(marked)
                    .cloned();
                let issue = issues.get(&index).unwrap_or(&Value::Null);
                if found.is_some()
                    && issue["state"] != "closed"
                    && issue["state_reason"] != "reopened"
                {
                    let reason = match item.get("state_reason") {
                        None | Some(Js::Null) => json!("completed"),
                        Some(reason) => reason.to_value(),
                    };
                    github.send(
                        "PATCH",
                        &format!("/repos/{}/issues/{number}", args.repo),
                        Some(&json!({"state": "closed", "state_reason": reason})),
                    )?;
                }
                found
            }
            CREATE_PULL_REQUEST => {
                // The branch is this run's, checked before; the handler
                // names it so, in the fork.
                let branch = item
                    .get("branch")
                    .and_then(Js::as_str)
                    .context("a create_pull_request names no branch")?;
                let prefix = super::publish::normalize_branch(&args.branch_prefix);
                let branch = if !prefix.is_empty() && !branch.starts_with(&prefix) {
                    format!("{prefix}{branch}")
                } else {
                    branch.to_owned()
                };
                let head = format!("{}:{branch}", owner(&args.fork));
                let found = github
                    .pulls(&args.output_repo, &head)?
                    .into_iter()
                    .find(|pull| {
                        self.marked(pull, name, role)
                            && (pull["state"] == "open"
                                || truthy(Some(&Js::from_value(&pull["merged_at"]))))
                    });
                if let Some(found) = &found {
                    output("pull-request-number", &value_string(found.get("number")))?;
                    output("pull-request-url", &value_string(found.get("html_url")))?;
                }
                found
            }
            _ => {
                // gh-aw finds its own marked issues the same way; search
                // lags seconds behind.
                let query = format!("repo:{} is:issue in:body \"{name}\"", args.output_repo);
                github.search_issues(&query)?.iter().find(marked).cloned()
            }
        };
        Ok(found)
    }
}

/// The step summary's list of what was left out, as `core.summary` writes
/// a heading and a list.
fn summary(skipped: &[Js]) -> String {
    let items: String = skipped
        .iter()
        .map(|entry| {
            format!(
                "<li>{}: {}</li>",
                js_string(entry.get("type")),
                js_string(entry.get("url"))
            )
        })
        .collect();
    format!("<h3>{SUMMARY_HEADING}</h3>\n<ul>{items}</ul>\n")
}

/// Appends TEXT to the file the environment variable VAR names, if any.
fn append(var: &str, text: &str) -> Result<bool> {
    let Some(path) = std::env::var_os(var).filter(|path| !path.is_empty()) else {
        return Ok(false);
    };
    let path = PathBuf::from(path);
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// Sets the step output NAME to VALUE, one line.
fn set_output(name: &str, value: &str) -> Result<()> {
    ensure!(
        !value.contains(['\n', '\r']),
        "the output {name} is not one line"
    );
    let line = format!("{name}={value}\n");
    if !append("GITHUB_OUTPUT", &line)? {
        print!("{line}");
    }
    Ok(())
}

/// A refusal is the step's annotation, as github-script's was, and fails it.
pub fn run(args: &Args) -> Result<Exit> {
    match guard(args) {
        Ok(()) => Ok(Exit::Success),
        Err(err) => {
            println!(
                "::error::{}",
                crate::run::enter::one_line(&format!("{err:#}"))
            );
            Ok(Exit::Failure)
        }
    }
}

fn guard(args: &Args) -> Result<()> {
    for repo in [&args.output_repo, &args.repo, &args.item_repo] {
        ensure!(is_repo(repo), "{repo:?} is not a repository name");
    }
    let run = std::env::var("GITHUB_RUN_ID").unwrap_or_default();
    ensure!(
        DIGITS_RE.is_match(&run),
        "GITHUB_RUN_ID {run:?} is not a run ID"
    );
    let github = super::github::from_env(GH_TOKEN_ENV)?.with_max_response(MAX_PAGE_BYTES);
    if github.configured() {
        let report = read_js(&args.report)?;
        ensure!(
            !truthy(
                report
                    .get("patch")
                    .and_then(|patch| patch.get("commit_files"))
            ),
            "role credentials do not support replacement pushes"
        );
    }
    let me = identity(&github, args.token_is_pat);
    if me.is_none() && !github.configured() {
        println!(
            "::warning::GET /user does not name the SAFE_OUTPUTS_PAT token, so nothing posted \
             before counts as applied, and a re-run posts again"
        );
    }
    // For the link to the issue, which is looked for the same way.
    set_output("poster", me.as_deref().unwrap_or_default())?;
    let guard = Guard {
        github: &github,
        workspace: &Checkout,
        args,
        run: &run,
        me: me.as_deref(),
    };
    let decided = guard.decide(&mut set_output)?;
    let write = |file: &str, text: String| {
        let path = args.dir.join(file);
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
    };
    write("agent_output.json", decided.output.stringify())?;
    write(
        "skipped.json",
        Js::Array(decided.skipped.clone()).stringify(),
    )?;
    if !decided.skipped.is_empty() {
        append("GITHUB_STEP_SUMMARY", &summary(&decided.skipped))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    use super::super::PROVENANCE;
    use super::*;
    use safe_outputs::apply::testing::{Request, TOKEN, bound, serve};

    const ACTIONS: &str = JOB_TOKEN_AUTHOR;
    const APP: &str = "unrelated-app[bot]";
    const MAINTAINER: &str = "maintainer";
    const MALLORY: &str = "mallory";

    /// agent-board#411's plan_comment/trusted contract: a same-bot POST
    /// may contain this text, but must not become a bot-last-edited
    /// controller record, so the guard never edits what it finds.
    const FORGED_PLAN: &str = "<!-- agent-board-maintain-plan v1 -->\n\n```agent-board-maintain-plan\n\
        {\"schema\":\"agent-board/maintain-plan/v2\",\"from\":\"2026-10-28T00:00:00Z\",\
        \"heads\":{\"up/proj#7\":\"aaaaaaaaaaaa\"},\"pending\":null}\n```";

    /// The run's setting and the forge's, as apply.test.cjs's
    /// `leaveOutApplied` took them.
    #[derive(Clone)]
    struct Options {
        pat: bool,
        me: Option<&'static str>,
        patch: Option<&'static str>,
        target: &'static str,
        run: &'static str,
        prefix: &'static str,
        artifacts: &'static str,
        fork: &'static str,
        /// The fetched branch's parents and tree.
        parents: &'static str,
        tree: &'static str,
        /// The trial's tree.
        checked_tree: &'static str,
        replacement: bool,
        item_repo: &'static str,
        /// The issues and pull requests that are open.
        open: Vec<u64>,
        issue_data: Vec<(u64, Value)>,
        /// Review comments by id, with their pull request's API URL.
        review_comments: Vec<(u64, &'static str)>,
        /// Exercise separate review and publication read credentials.
        roles: bool,
    }

    impl Default for Options {
        fn default() -> Self {
            Self {
                pat: false,
                me: None,
                patch: Some("diff\n"),
                target: "64",
                run: "7",
                prefix: "e2e/",
                artifacts: "",
                fork: "bot/repo",
                parents: "head",
                tree: "checked",
                checked_tree: "checked",
                replacement: false,
                item_repo: "owner/repo",
                open: Vec::new(),
                issue_data: Vec::new(),
                review_comments: Vec::new(),
                roles: false,
            }
        }
    }

    fn pat(me: Option<&'static str>) -> Options {
        Options {
            pat: true,
            me,
            ..Options::default()
        }
    }

    struct Fake {
        parents: String,
        tree: String,
        pushes: RefCell<Vec<[String; 4]>>,
    }

    impl Workspace for Fake {
        fn fetched(&self) -> Result<(String, String)> {
            Ok((self.parents.clone(), self.tree.clone()))
        }

        fn push_replacement(
            &self,
            remote: &str,
            branch: &str,
            original: &str,
            replacement: &str,
        ) -> Result<()> {
            self.pushes
                .borrow_mut()
                .push([remote, branch, original, replacement].map(str::to_owned));
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Outcome {
        kept: Vec<Value>,
        skipped: Vec<Value>,
        outputs: Vec<(String, String)>,
        summary: String,
        /// What was asked of the forge, as `kind detail`.
        queries: Vec<String>,
        pushes: Vec<[String; 4]>,
        /// What was written to the forge: request line and body.
        updates: Vec<(String, Value)>,
    }

    fn decode(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    fn param_of(query: &str, key: &str) -> String {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
            .map(decode)
            .unwrap_or_default()
    }

    /// Runs the guard on ITEMS against a forge holding POSTED, each with
    /// `on` (the item a comment is on), `head` (a pull request's) or
    /// `issue` (one search finds), by whoever `user` names.
    fn guard(items: &[Value], posted: &[Value], o: &Options) -> Result<Outcome> {
        let dir = tempfile::tempdir().unwrap();
        let write = |file: &str, value: &Value| {
            std::fs::write(dir.path().join(file), value.to_string()).unwrap()
        };
        write("agent_output.json", &json!({"items": items, "errors": []}));
        write(
            "config.json",
            &json!({"push_to_pull_request_branch": {"target": "42", "head": "head"}}),
        );
        let file = format!("aw-agent-run-{}.patch", o.run);
        let patch = o.patch.map(|patch| {
            std::fs::write(dir.path().join(&file), patch).unwrap();
            let mut patch = json!({"file": file});
            if o.replacement {
                patch["commit_files"] = json!([["a.txt"]]);
            }
            patch
        });
        write("report.json", &json!({"patch": patch}));

        let queries = Arc::new(Mutex::new(Vec::new()));
        let updates = Arc::new(Mutex::new(Vec::new()));
        // The forge answers with its own API's address, for `API` here.
        let address = Arc::new(Mutex::new(String::new()));
        let (seen, written, at) = (queries.clone(), updates.clone(), address.clone());
        let posted = posted.to_vec();
        let o2 = o.clone();
        let (server, _requests) = serve(usize::MAX, move |request: &Request| {
            let api = |url: &str| url.replacen("API", &at.lock().unwrap(), 1);
            let line = request.line.trim_end_matches(" HTTP/1.1");
            let (method, path) = line.split_once(' ').unwrap();
            let (path, query) = path.split_once('?').unwrap_or((path, ""));
            if o2.roles {
                let review_read = path.contains("/comments");
                let role = if review_read {
                    "REVIEW_TOKEN"
                } else {
                    "PUBLICATION_TOKEN"
                };
                let token = ["fake", role, "credential"].join("-");
                assert_eq!(request.authorization, format!("Bearer {token}"));
            }
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            let ask = |text: String| seen.lock().unwrap().push(text);
            let open = |n: &str| o2.open.iter().any(|o| o.to_string() == n);
            let answer = match (method, parts.as_slice()) {
                ("GET", ["user"]) => match o2.me {
                    Some(me) => json!({"login": me}),
                    None => return (403, json!({"message": "Forbidden"}).to_string()),
                },
                ("GET", ["repos", owner, repo, "issues", n, "comments"]) => {
                    // One page, as octokit asks for the first.
                    assert_eq!(query, "per_page=100");
                    ask(format!("comments {owner}/{repo} {n}"));
                    json!(
                        posted
                            .iter()
                            .filter(|p| p["on"].as_u64() == n.parse().ok())
                            .collect::<Vec<_>>()
                    )
                }
                ("GET", ["repos", "owner", "source", "issues", n]) => {
                    ask(format!("issue {n}"));
                    let mut issue = json!({"state": if open(n) { "open" } else { "closed" },
                        "state_reason": null, "repository_url": "API/repos/owner/source"});
                    if let Some((_, data)) = o2.issue_data.iter().find(|(i, _)| i.to_string() == *n)
                    {
                        for (key, value) in data.as_object().unwrap() {
                            issue[key] = value.clone();
                        }
                    }
                    if let Some(url) = issue["repository_url"].as_str() {
                        issue["repository_url"] = json!(api(url));
                    }
                    issue
                }
                ("GET", ["repos", "owner", "repo", "pulls"]) => {
                    let head = param_of(query, "head");
                    assert!(query.ends_with("&state=all&per_page=100"), "{query}");
                    ask(format!("pulls {head}"));
                    json!(
                        posted
                            .iter()
                            .filter(|p| p["head"] == head.as_str())
                            .collect::<Vec<_>>()
                    )
                }
                ("GET", ["repos", "owner", "source", "pulls", n]) => {
                    ask(format!("pull {n}"));
                    json!({"state": if open(n) { "open" } else { "closed" }})
                }
                ("GET", ["repos", owner, repo, "pulls", "comments", id]) => {
                    ask(format!("review comment {owner}/{repo} {id}"));
                    match o2
                        .review_comments
                        .iter()
                        .find(|(i, _)| i.to_string() == *id)
                    {
                        Some((_, url)) => json!({"pull_request_url": api(url)}),
                        None => return (404, json!({"message": "Not Found"}).to_string()),
                    }
                }
                ("GET", ["search", "issues"]) => {
                    let q = param_of(query, "q");
                    ask(format!("search {q}"));
                    let hidden = Regex::new("<!-- (.*) -->").unwrap();
                    let items: Vec<_> = posted
                        .iter()
                        .filter(|p| {
                            p["issue"] == true
                                && hidden
                                    .captures(p["body"].as_str().unwrap())
                                    .is_some_and(|c| q.contains(&c[1]))
                        })
                        .collect();
                    json!({"items": items})
                }
                ("PATCH", ["repos", "owner", "source", kind, n]) => {
                    let state = request.body["state"].as_str().unwrap();
                    let reason = request.body["state_reason"]
                        .as_str()
                        .map(|reason| format!(" {reason}"))
                        .unwrap_or_default();
                    ask(format!("update {n} {state}{reason}"));
                    written
                        .lock()
                        .unwrap()
                        .push((format!("PATCH {kind} {n}"), request.body.clone()));
                    json!({})
                }
                _ => {
                    return (
                        404,
                        json!({"message": format!("unexpected {line}")}).to_string(),
                    );
                }
            };
            (200, answer.to_string())
        });
        let github = Github::new(&server, TOKEN.to_owned(), PROVENANCE).unwrap();
        let github = if o.roles { bound(github) } else { github };
        *address.lock().unwrap() = github.api_url().to_owned();
        let args = Args {
            dir: dir.path().to_owned(),
            report: dir.path().join("report.json"),
            output_repo: "owner/repo".into(),
            repo: "owner/source".into(),
            item_repo: o.item_repo.into(),
            comment_target: o.target.into(),
            branch_prefix: o.prefix.into(),
            artifact_prefix: o.artifacts.into(),
            fork: o.fork.into(),
            base: "agent-run-7".into(),
            tree: o.checked_tree.into(),
            replacement_head: "replacement-head".into(),
            token_is_pat: o.pat,
        };
        let workspace = Fake {
            parents: o.parents.into(),
            tree: o.tree.into(),
            pushes: RefCell::default(),
        };
        let me = identity(&github, o.pat);
        let guard = Guard {
            github: &github,
            workspace: &workspace,
            args: &args,
            run: o.run,
            me: me.as_deref(),
        };
        let mut outputs = Vec::new();
        let decided = guard.decide(&mut |name, value| {
            outputs.push((name.to_owned(), value.to_owned()));
            Ok(())
        });
        // Every refusal comes before anything is written.
        if decided.is_err() {
            assert!(updates.lock().unwrap().is_empty());
            assert!(workspace.pushes.borrow().is_empty());
        }
        let decided = decided?;
        let Some(Js::Array(kept)) = decided.output.get("items") else {
            panic!("no items");
        };
        assert_eq!(decided.output.get("errors"), Some(&Js::Array(Vec::new())));
        let summary = if decided.skipped.is_empty() {
            String::new()
        } else {
            summary(&decided.skipped)
        };
        let queries = queries.lock().unwrap().clone();
        let updates = updates.lock().unwrap().clone();
        Ok(Outcome {
            kept: kept.iter().map(Js::to_value).collect(),
            skipped: decided.skipped.iter().map(Js::to_value).collect(),
            outputs,
            summary,
            queries,
            pushes: workspace.pushes.into_inner(),
            updates,
        })
    }

    fn ok(items: &[Value], posted: &[Value], o: &Options) -> Outcome {
        guard(items, posted, o).unwrap()
    }

    fn refusal(items: &[Value], posted: &[Value], o: &Options) -> String {
        format!("{:#}", guard(items, posted, o).unwrap_err())
    }

    fn comment(body: &str) -> Value {
        json!({"type": "add_comment", "body": body})
    }

    #[test]
    fn review_ownership_reads_use_review_credentials() {
        let options = Options {
            roles: true,
            ..Options::default()
        };
        let item = comment("result");
        let first = ok(std::slice::from_ref(&item), &[], &options);
        assert_eq!(first.kept.len(), 1);
        for (id, accepted) in [(7, true), (8, false)] {
            let posted = json!({"on": 64, "user": {"id": id},
                "body": sent(first.kept[0]["body"].as_str().unwrap()),
                "html_url": "https://github.com/owner/repo/issues/64#issuecomment-1"});
            let rerun = ok(std::slice::from_ref(&item), &[posted], &options);
            assert_eq!(rerun.skipped.len(), usize::from(accepted));
        }
        let reply = json!({"type": REPLY_TO_REVIEW_COMMENT, "comment_id": 99, "body": "reply"});
        let options = Options {
            review_comments: vec![(99, "API/repos/owner/repo/pulls/64")],
            ..options
        };
        assert_eq!(ok(&[reply], &[], &options).kept.len(), 1);
    }

    fn pull() -> Value {
        json!({"type": "create_pull_request", "title": "t", "body": "change", "branch": "agent-run-7"})
    }

    /// The name the guard put in a body it kept: its last line.
    fn name_in(item: &Value) -> String {
        item["body"]
            .as_str()
            .unwrap()
            .rsplit('\n')
            .next()
            .unwrap()
            .to_owned()
    }

    /// What the handlers send, after their request hook hides the last
    /// name on a line of its own.
    fn sent(body: &str) -> String {
        let name =
            Regex::new(r"\n\n(agentic-job-applied: [0-9]+/[0-9]+/[0-9a-f]{16})(\n|$)").unwrap();
        match name.captures_iter(body).last() {
            Some(found) => {
                let whole = found.get(1).unwrap();
                format!(
                    "{}<!-- {} -->{}",
                    &body[..whole.start()],
                    whole.as_str(),
                    &body[whole.end()..]
                )
            }
            None => body.to_owned(),
        }
    }

    fn posted_comment(on: u64, user: &str, body: &str, url: &str) -> Value {
        json!({"on": on, "user": {"login": user}, "body": sent(body), "html_url": url})
    }

    #[test]
    fn advisory_replay_after_a_lost_response_uses_the_existing_owned_marker() {
        let advisory = safe_outputs::advisory::Advisory {
            repo: "owner/repo".into(),
            pull: 64,
            base: "main".into(),
            head: "a".repeat(40),
        };
        let request = json!({"type":"add_comment","repo":advisory.repo,"item_number":64,"body":"Suggested rewrite."});
        let options = Options::default();
        let first = ok(std::slice::from_ref(&request), &[], &options);
        assert_eq!(first.kept.len(), 1);
        // The server accepted POST, but the writer lost its response and
        // made no local success record. Only the owned remote marker counts.
        let body = advisory
            .body(&sent(first.kept[0]["body"].as_str().unwrap()))
            .unwrap();
        for (author, expected) in [(ACTIONS, 0), (MALLORY, 1)] {
            let posted = posted_comment(
                64,
                author,
                &body,
                "https://github.com/owner/repo/issues/64#issuecomment-1",
            );
            let replay = ok(std::slice::from_ref(&request), &[posted], &options);
            assert_eq!(replay.kept.len(), expected);
        }
        // If POST did not land, a rerun may post; it must perform the fresh
        // head/base check again in the native writer, not trust local state.
        assert_eq!(ok(&[request], &[], &options).kept.len(), 1);
    }

    /// Recorded from apply.yml's script with node: the artifact prefix,
    /// the request as written, the patch, `JSON.stringify` of the parsed
    /// request, and the digest in its name.
    #[test]
    fn names_match_the_script() {
        let cases: &[(&str, &str, Option<&str>, &str, &str)] = &[
            (
                "",
                r#"{"type":"add_comment","body":"first"}"#,
                None,
                r#"{"type":"add_comment","body":"first"}"#,
                "0b49454c3537eff8",
            ),
            (
                "dispatch-triage-",
                r#"{"type":"add_comment","body":"first"}"#,
                None,
                r#"{"type":"add_comment","body":"first"}"#,
                "8a3ad922127eeafa",
            ),
            (
                "",
                r#"{"type":"create_pull_request","title":"t","body":"change","branch":"agent-run-7"}"#,
                Some("diff\n"),
                r#"{"type":"create_pull_request","title":"t","body":"change","branch":"agent-run-7"}"#,
                "b40e5f4c8c0efec2",
            ),
            (
                "e2e/",
                r#"{"type":"create_pull_request","title":"t","body":"change","branch":"agent-run-7"}"#,
                Some("other\n"),
                r#"{"type":"create_pull_request","title":"t","body":"change","branch":"agent-run-7"}"#,
                "bf58fa74ef677a35",
            ),
            // Keys in their order, not sorted.
            (
                "",
                r#"{"body":"b","type":"close_issue","issue_number":12,"state_reason":"not_planned"}"#,
                None,
                r#"{"body":"b","type":"close_issue","issue_number":12,"state_reason":"not_planned"}"#,
                "abb3cd88362ee949",
            ),
            // Numbers as JavaScript prints them.
            (
                "",
                r#"{"type":"add_comment","item_number":1.50,"n":[1e21,1e-7,0.000001,-0,123456789012345678901,2.5e-3,100,1E2],"body":"x"}"#,
                None,
                r#"{"type":"add_comment","item_number":1.5,"n":[1e+21,1e-7,0.000001,0,123456789012345680000,0.0025,100,100],"body":"x"}"#,
                "28981257ff7879eb",
            ),
            // Escapes as JavaScript writes them.
            (
                "",
                r#"{"type":"add_comment","body":"tab\t nl\n \u0001 \u001f \u007f \"q\" \\ \/   é 😀 😀","x":{"z":null,"a":[true,false,{}],"b":[]}}"#,
                None,
                "{\"type\":\"add_comment\",\"body\":\"tab\\t nl\\n \\u0001 \\u001f \u{7f} \\\"q\\\" \\\\ / \u{2028} é 😀 😀\",\"x\":{\"z\":null,\"a\":[true,false,{}],\"b\":[]}}",
                "dae708c6d3624980",
            ),
            // A repeated key's last value, in its first place.
            (
                "",
                r#"{"type":"add_comment","body":"one","body":"two","a":1}"#,
                None,
                r#"{"type":"add_comment","body":"two","a":1}"#,
                "b9f90dcce1b553ad",
            ),
            // Array indices first, in their order.
            (
                "",
                r#"{"type":"add_comment","body":"x","10":1,"2":2,"01":3,"4294967295":4,"4294967294":5,"-1":6,"1.5":7}"#,
                None,
                r#"{"2":2,"10":1,"4294967294":5,"type":"add_comment","body":"x","01":3,"4294967295":4,"-1":6,"1.5":7}"#,
                "c6742bfb1f56b78d",
            ),
        ];
        for (prefix, text, patch, stringified, digest) in cases {
            let item: Js = serde_json::from_str(text).unwrap();
            assert_eq!(item.stringify(), *stringified, "{text}");
            assert_eq!(
                name(prefix, "7", 3, &item, patch.map(str::as_bytes)),
                format!("agentic-job-applied: 7/3/{digest}"),
                "{text}"
            );
        }
        for (number, text) in [
            (0.1 + 0.2, "0.30000000000000004"),
            (-1.5e-7, "-1.5e-7"),
            (1e21, "1e+21"),
            (123e20, "1.23e+22"),
            (1e20, "100000000000000000000"),
            (f64::NAN, "NaN"),
        ] {
            assert_eq!(js_number(number), text);
        }
    }

    #[test]
    fn a_replacement_is_pushed_with_the_leased_applier_and_never_reaches_the_handler() {
        let item = json!({"type": "push_to_pull_request_branch", "branch": "agent-run-7"});
        let options = Options {
            replacement: true,
            ..Options::default()
        };
        let result = ok(&[item], &[], &options);
        assert_eq!(
            result.pushes,
            [[
                "https://github.com/bot/repo",
                "agent-run-7",
                "head",
                "replacement-head"
            ]
            .map(str::to_owned)]
        );
        assert_eq!(result.kept, Vec::<Value>::new());
        assert_eq!(
            result.skipped,
            [
                json!({"type": "push_to_pull_request_branch", "url": "https://github.com/owner/repo/pull/42"})
            ]
        );
    }

    #[test]
    fn a_re_run_leaves_out_only_a_push_already_holding_the_checked_tree_on_the_pinned_head() {
        let push = json!({"type": "push_to_pull_request_branch", "branch": "p/agent-run-7"});
        let with = |parents, tree, checked_tree| Options {
            parents,
            tree,
            checked_tree,
            ..Options::default()
        };
        for (what, options, applied) in [
            ("already applied", with("head", "checked", "checked"), true),
            ("unchanged head", with("older", "before", "checked"), false),
            ("another change", with("head", "other", "checked"), false),
            ("another parent", with("other", "checked", "checked"), false),
            (
                "merge commit",
                with("head other", "checked", "checked"),
                false,
            ),
            ("no trial tree", with("head", "checked", ""), false),
        ] {
            let result = ok(&[push.clone(), comment("first")], &[], &options);
            assert_eq!(result.skipped.len(), usize::from(applied), "{what}");
            assert_eq!(
                result.kept.iter().any(|item| item["type"] == push["type"]),
                !applied,
                "{what}"
            );
            // Leaving out the push does not move the next output's name.
            assert!(
                name_in(result.kept.last().unwrap()).starts_with("agentic-job-applied: 7/1/"),
                "{what}"
            );
            if applied {
                assert_eq!(
                    result.skipped,
                    [json!({"type": push["type"], "url": "https://github.com/owner/repo/pull/42"})]
                );
                assert!(result.summary.contains("Already applied"), "{what}");
            }
        }
    }

    #[test]
    fn nothing_applied_yet_names_every_created_thing_and_passes_the_rest() {
        let items = [
            comment("first"),
            pull(),
            json!({"type": "create_issue", "title": "i", "body": "b"}),
            json!({"type": "add_labels", "labels": ["x"]}),
            json!({"type": "update_project", "project": "p", "fields": {"Status": "Done"}}),
            json!({"type": "noop", "message": "n"}),
        ];
        let result = ok(&items, &[], &Options::default());
        assert_eq!(result.skipped, Vec::<Value>::new());
        assert_eq!(result.summary, "");
        assert_eq!(result.kept.len(), items.len());
        let name = Regex::new(r"^agentic-job-applied: 7/([0-9])/[0-9a-f]{16}$").unwrap();
        for (index, (kept, item)) in result.kept.iter().zip(&items).enumerate() {
            if index < 3 {
                let body = kept["body"].as_str().unwrap();
                let (asked, named) = body.rsplit_once("\n\n").unwrap();
                assert_eq!(asked, item["body"]);
                assert_eq!(&name.captures(named).unwrap()[1], index.to_string());
                let mut unnamed = kept.clone();
                unnamed["body"] = item["body"].clone();
                assert_eq!(&unnamed, item);
            } else {
                // Labelling and setting a field again leave the forge as it was.
                assert_eq!(kept, item);
            }
        }
        let kinds: Vec<_> = result
            .queries
            .iter()
            .map(|q| q.split(' ').next().unwrap())
            .collect();
        assert_eq!(kinds, ["comments", "pulls", "search"]);
        assert_eq!(result.queries[1], "pulls bot:e2e/agent-run-7");
    }

    #[test]
    fn the_name_is_stable_across_attempts_and_differs_by_run_call_place_and_content() {
        let named = |item: Value, run, artifacts| {
            let options = Options {
                run,
                artifacts,
                ..Options::default()
            };
            name_in(&ok(&[item], &[], &options).kept[0])
        };
        let first = || comment("first");
        assert_eq!(named(first(), "7", ""), named(first(), "7", ""));
        assert_eq!(
            named(first(), "7", "dispatch-triage-"),
            named(first(), "7", "dispatch-triage-")
        );
        assert_ne!(named(first(), "7", ""), named(first(), "8", ""));
        assert_ne!(
            named(first(), "7", "dispatch-triage-"),
            named(first(), "7", "dispatch-research-")
        );
        assert_ne!(named(first(), "7", ""), named(first(), "7", "full-"));
        assert_ne!(named(first(), "7", ""), named(comment("other"), "7", ""));
        let both = ok(&[first(), first()], &[], &Options::default()).kept;
        assert_ne!(name_in(&both[0]), name_in(&both[1]));
    }

    /// CI run 38018010779: the triage and research calls of one run post
    /// the same comment on the same issue; the second was taken for
    /// applied. A verdict must also stay the first line of what is posted.
    #[test]
    fn calls_of_one_run_are_told_apart_and_the_first_line_is_kept() {
        let output = comment("Triage: ready.");
        let with = |artifacts| Options {
            artifacts,
            ..Options::default()
        };
        let triage = ok(
            std::slice::from_ref(&output),
            &[],
            &with("dispatch-triage-"),
        )
        .kept[0]
            .clone();
        let posted = [posted_comment(
            64,
            ACTIONS,
            triage["body"].as_str().unwrap(),
            "u",
        )];
        let research = ok(
            std::slice::from_ref(&output),
            &posted,
            &with("dispatch-research-"),
        );
        assert_eq!(research.skipped, Vec::<Value>::new());
        assert_eq!(research.kept.len(), 1);
        assert_eq!(
            ok(&[output], &posted, &with("dispatch-triage-")).kept.len(),
            0
        );
        for body in [
            "VERDICT: APPROVE\nREASON: Scripted dispatch tests wiring.\nReviewed SHA: 0123",
            "**Partial work.** The run was stopped at its timeout before the task was done; \
             this is what it handed back.\n\nrest",
        ] {
            let kept = ok(&[comment(body)], &[], &Options::default()).kept;
            let posted = sent(&format!(
                "{}\n\n> footer",
                kept[0]["body"].as_str().unwrap()
            ));
            assert!(
                posted.starts_with(&format!("{body}\n\n<!-- agentic-job-applied: 7/0/")),
                "{posted}"
            );
        }
    }

    /// Who posted the named comment, and with which token apply runs: the
    /// job token, a PAT /user names, or a SAFE_OUTPUTS_PAT /user does not
    /// name, as an app's.
    #[test]
    fn only_the_tokens_own_posts_count() {
        let job = Options::default;
        for (what, user, token, left) in [
            ("the job token, with the job token", ACTIONS, job(), true),
            ("an unrelated bot, with the job token", APP, job(), false),
            ("a commenter, with the job token", MALLORY, job(), false),
            (
                "a user called github-actions, with the job token",
                "github-actions",
                job(),
                false,
            ),
            (
                "the PAT, with the PAT",
                MAINTAINER,
                pat(Some(MAINTAINER)),
                true,
            ),
            (
                "an unrelated bot, with a PAT",
                APP,
                pat(Some(MAINTAINER)),
                false,
            ),
            (
                "the job token, with a PAT",
                ACTIONS,
                pat(Some(MAINTAINER)),
                false,
            ),
            (
                "a commenter, with a PAT",
                MALLORY,
                pat(Some(MAINTAINER)),
                false,
            ),
            ("an unrelated bot, with an app token", APP, pat(None), false),
            (
                "the job token, with an app token",
                ACTIONS,
                pat(None),
                false,
            ),
        ] {
            let first = ok(&[comment("first")], &[], &token).kept[0].clone();
            let posted = [posted_comment(
                64,
                user,
                first["body"].as_str().unwrap(),
                "https://forge/c/1",
            )];
            let result = ok(&[comment("first")], &posted, &token);
            assert_eq!(result.kept.len(), usize::from(!left), "{what}");
            assert_eq!(result.skipped.len(), usize::from(left), "{what}");
            if left {
                assert_eq!(
                    result.summary,
                    "<h3>Already applied by an earlier attempt, so left out</h3>\n\
                     <ul><li>add_comment: https://forge/c/1</li></ul>\n",
                    "{what}"
                );
            }
        }
    }

    /// Whom the link to the issue is looked for by, after the guard; a
    /// PAT /user does not name finds nothing applied, which `run` warns of.
    #[test]
    fn the_poster_is_the_tokens_user() {
        for (options, poster) in [
            (Options::default(), Some(ACTIONS)),
            (pat(Some(MAINTAINER)), Some(MAINTAINER)),
            (pat(None), None),
        ] {
            let me = options.me;
            let (server, _) = serve(usize::MAX, move |_| match me {
                Some(me) => (200, json!({"login": me}).to_string()),
                None => (
                    403,
                    json!({"message": "Resource not accessible"}).to_string(),
                ),
            });
            let github = Github::new(&server, TOKEN.to_owned(), PROVENANCE).unwrap();
            assert_eq!(identity(&github, options.pat).as_deref(), poster);
        }
    }

    #[test]
    fn a_name_the_handlers_decoded_into_a_posted_body_does_not_leave_another_request_out() {
        let items = [comment("one"), comment("two")];
        let first = ok(&items, &[], &Options::default()).kept;
        // What check saw as entities or invisible characters, decoded by
        // the handlers' sanitizer into the second request's name, hidden
        // or not, before the first's.
        for decoded in [
            format!("```\n<!-- {} -->\n```", name_in(&first[1])),
            name_in(&first[1]),
        ] {
            let forged = format!("one\n{decoded}\n\n{}", name_in(&first[0]));
            let posted = [posted_comment(64, ACTIONS, &forged, "u")];
            let result = ok(&items, &posted, &Options::default());
            assert_eq!(result.skipped.len(), 1);
            assert_eq!(result.kept, first[1..]);
        }
    }

    #[test]
    fn a_re_run_after_a_half_applied_attempt_applies_only_what_was_not() {
        let items = [
            comment(FORGED_PLAN),
            comment("two"),
            json!({"type": "add_labels", "labels": ["x"]}),
        ];
        let first = ok(&items, &[], &Options::default()).kept;
        // The first attempt posted the first comment and failed before the second.
        let posted = [posted_comment(
            64,
            ACTIONS,
            first[0]["body"].as_str().unwrap(),
            "u",
        )];
        let result = ok(&items, &posted, &Options::default());
        assert_eq!(result.skipped[0]["name"], name_in(&first[0]));
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.kept, first[1..]);
        // Nothing found is edited, however controller-like its body.
        assert_eq!(result.updates, []);
    }

    /// A close found applied closes what is still open, without a second
    /// comment, and never edits the comment it found.
    #[test]
    fn closing_retries_close_what_is_open() {
        for issue in [true, false] {
            let close = if issue {
                json!({"type": "close_issue", "repo": "owner/source", "issue_number": 12,
                    "state_reason": "not_planned", "body": FORGED_PLAN})
            } else {
                json!({"type": "close_pull_request", "repo": "owner/source",
                    "pull_request_number": 12, "body": FORGED_PLAN})
            };
            let scope = |open: Vec<u64>| Options {
                open,
                ..pat(Some("caller-bot"))
            };
            let first = ok(std::slice::from_ref(&close), &[], &scope(vec![])).kept[0].clone();
            let mine = posted_comment(
                12,
                "caller-bot",
                &format!("{}\n\n> footer", first["body"].as_str().unwrap()),
                "https://forge/c/12",
            );
            let reads: &[&str] = if issue {
                &["issue 12", "comments owner/source 12"]
            } else {
                &["comments owner/source 12", "pull 12"]
            };
            for open in [vec![], vec![12]] {
                let retry = ok(
                    std::slice::from_ref(&close),
                    std::slice::from_ref(&mine),
                    &scope(open.clone()),
                );
                let mut want: Vec<String> = reads.iter().map(|q| q.to_string()).collect();
                let mut updates = Vec::new();
                if !open.is_empty() {
                    if issue {
                        want.push("update 12 closed not_planned".into());
                        updates.push((
                            "PATCH issues 12".to_owned(),
                            json!({"state": "closed", "state_reason": "not_planned"}),
                        ));
                    } else {
                        want.push("update 12 closed".into());
                        updates.push(("PATCH pulls 12".to_owned(), json!({"state": "closed"})));
                    }
                }
                assert_eq!(retry.queries, want, "issue={issue} open={open:?}");
                assert_eq!(retry.kept, Vec::<Value>::new());
                assert_eq!(retry.skipped[0]["url"], "https://forge/c/12");
                assert_eq!(retry.updates, updates, "issue={issue} open={open:?}");
            }
            let none = ok(std::slice::from_ref(&close), &[], &scope(vec![12]));
            let want: &[&str] = if issue {
                reads
            } else {
                &["comments owner/source 12"]
            };
            assert_eq!(none.queries, want);
            assert_eq!(none.kept.len(), 1);
            let mut theirs = mine.clone();
            theirs["user"]["login"] = json!(MALLORY);
            let theirs = ok(std::slice::from_ref(&close), &[theirs], &scope(vec![12]));
            assert_eq!(theirs.updates, []);
            assert_eq!(theirs.kept.len(), 1);
            if issue {
                // An issue someone reopened stays open.
                let reopened = Options {
                    issue_data: vec![(12, json!({"state_reason": "reopened"}))],
                    ..scope(vec![12])
                };
                let reopened = ok(
                    std::slice::from_ref(&close),
                    std::slice::from_ref(&mine),
                    &reopened,
                );
                assert_eq!(reopened.queries, reads);
                assert_eq!(reopened.kept, Vec::<Value>::new());
                // A close without a reason closes as completed.
                let mut plain = close.clone();
                plain.as_object_mut().unwrap().remove("state_reason");
                let first = ok(&[plain.clone()], &[], &scope(vec![])).kept[0].clone();
                let half = posted_comment(
                    12,
                    "caller-bot",
                    first["body"].as_str().unwrap(),
                    "https://forge/c/12",
                );
                let half = ok(&[plain], &[half], &scope(vec![12]));
                assert_eq!(half.queries.last().unwrap(), "update 12 closed completed");
            }
        }
    }

    #[test]
    fn a_comment_is_looked_for_where_it_goes_and_not_where_none_can_be_found() {
        let mut item = comment("first");
        item["item_number"] = json!(12);
        let at = |target| Options {
            target,
            ..Options::default()
        };
        assert_eq!(
            ok(&[item.clone()], &[], &at("triggering")).queries,
            ["comments owner/repo 12"]
        );
        assert_eq!(
            ok(&[item], &[], &at("64")).queries,
            ["comments owner/repo 64"]
        );
        let nowhere = ok(&[comment("first")], &[], &at("*"));
        assert_eq!(nowhere.queries, Vec::<String>::new());
        assert_eq!(nowhere.kept.len(), 1);
        // On an item in another repository, it is looked for there.
        let tracker = Options {
            item_repo: "owner/tracker",
            ..Options::default()
        };
        let first = ok(&[comment("first")], &[], &tracker).kept[0].clone();
        let posted = [posted_comment(
            64,
            ACTIONS,
            first["body"].as_str().unwrap(),
            "https://forge/tracker/c/1",
        )];
        let result = ok(&[comment("first")], &posted, &tracker);
        assert_eq!(result.queries, ["comments owner/tracker 64"]);
        assert_eq!(result.kept.len(), 0);
        assert_eq!(result.skipped[0]["url"], "https://forge/tracker/c/1");
    }

    /// policy.yml's `branch-prefix` input is not held to a branch name, so
    /// the prefix is normalized as gh-aw's handler normalizes it.
    #[test]
    fn the_pull_request_is_looked_for_from_the_branch_gh_aw_names_in_the_fork() {
        let prefixed = |prefix| Options {
            prefix,
            ..Options::default()
        };
        assert_eq!(
            ok(&[pull()], &[], &prefixed("bot run/")).queries,
            ["pulls bot:bot-run/agent-run-7"]
        );
        assert_eq!(
            ok(&[pull()], &[], &prefixed("")).queries,
            ["pulls bot:agent-run-7"]
        );
        // Never the output repository's own branch, which an earlier
        // version pushed to.
        let first = ok(&[pull()], &[], &Options::default()).kept[0].clone();
        let posted = [json!({"head": "owner:e2e/agent-run-7", "state": "open",
            "user": {"login": ACTIONS}, "body": sent(first["body"].as_str().unwrap()),
            "html_url": "u"})];
        assert_eq!(
            ok(&[pull()], &posted, &Options::default()).skipped,
            Vec::<Value>::new()
        );
    }

    #[test]
    fn a_pull_request_from_the_runs_branch_is_left_out_while_open_or_merged() {
        for (state, merged, left) in [
            ("open", Value::Null, true),
            ("closed", json!("2026-10-01T00:00:00Z"), true),
            ("closed", Value::Null, false),
        ] {
            let first = ok(&[pull()], &[], &Options::default()).kept[0].clone();
            let posted = json!({"head": "bot:e2e/agent-run-7", "state": state,
                "merged_at": merged, "number": 39, "user": {"login": ACTIONS},
                "body": sent(first["body"].as_str().unwrap()),
                "html_url": "https://forge/pull/39"});
            for (patch, same) in [("diff\n", true), ("other\n", false)] {
                let options = Options {
                    patch: Some(patch),
                    ..Options::default()
                };
                let result = ok(&[pull()], std::slice::from_ref(&posted), &options);
                // A different patch with the same request is applied as
                // new: the handler then stops at the branch already there.
                let left = left && same;
                assert_eq!(result.kept.len(), usize::from(!left), "{state} {merged}");
                let urls: Vec<_> = result.skipped.iter().map(|s| s["url"].clone()).collect();
                assert_eq!(
                    urls,
                    if left {
                        vec![json!("https://forge/pull/39")]
                    } else {
                        vec![]
                    }
                );
                let outputs: Vec<(String, String)> = if left {
                    vec![
                        ("pull-request-number".into(), "39".into()),
                        ("pull-request-url".into(), "https://forge/pull/39".into()),
                    ]
                } else {
                    vec![]
                };
                assert_eq!(result.outputs, outputs, "{state} {merged} {patch:?}");
            }
        }
    }

    #[test]
    fn an_issue_an_earlier_attempt_opened_is_found_by_its_name() {
        let issue = json!({"type": "create_issue", "title": "i", "body": "b"});
        let first = ok(std::slice::from_ref(&issue), &[], &Options::default()).kept[0].clone();
        let posted = [json!({"issue": true, "user": {"login": ACTIONS},
            "body": sent(first["body"].as_str().unwrap()), "html_url": "https://forge/issues/5"})];
        let result = ok(&[issue], &posted, &Options::default());
        assert_eq!(result.kept.len(), 0);
        assert_eq!(result.skipped[0]["url"], "https://forge/issues/5");
        assert!(
            Regex::new(r#"^search repo:owner/repo is:issue in:body "agentic-job-applied: 7/0/[0-9a-f]{16}"$"#)
                .unwrap()
                .is_match(&result.queries[0]),
            "{:?}",
            result.queries
        );
    }

    #[test]
    fn a_pull_requests_name_holds_the_checked_patch_and_a_comments_does_not() {
        let named = |item: Value, patch| {
            let options = Options {
                patch: Some(patch),
                ..Options::default()
            };
            name_in(&ok(&[item], &[], &options).kept[0])
        };
        assert_eq!(named(pull(), "diff\n"), named(pull(), "diff\n"));
        assert_ne!(named(pull(), "diff\n"), named(pull(), "other\n"));
        assert_eq!(
            named(comment("first"), "diff\n"),
            named(comment("first"), "other\n")
        );
    }

    /// Refused before anything is written: a pull request without a checked
    /// patch or a fork, a close_issue naming a pull request or an issue
    /// transferred elsewhere, and a reply off the run's pull request.
    #[test]
    fn refusals() {
        let no_patch = Options {
            patch: None,
            ..Options::default()
        };
        let no_fork = Options {
            fork: "",
            ..Options::default()
        };
        assert!(refusal(&[pull()], &[], &no_patch).contains("check accepted no patch"));
        assert_eq!(ok(&[comment("first")], &[], &no_patch).kept.len(), 1);
        assert!(refusal(&[pull()], &[], &no_fork).contains("no fork"));
        assert_eq!(ok(&[comment("first")], &[], &no_fork).kept.len(), 1);
        // Even after a half-closed pull request the script would have
        // closed first: the harness holds every refusal to no write.
        let close =
            json!({"type": "close_pull_request", "pull_request_number": 12, "body": "Done."});
        let half = Options {
            open: vec![12],
            ..no_fork.clone()
        };
        let first = ok(std::slice::from_ref(&close), &[], &half).kept[0].clone();
        let posted = [posted_comment(
            12,
            ACTIONS,
            first["body"].as_str().unwrap(),
            "u",
        )];
        assert_eq!(
            ok(std::slice::from_ref(&close), &posted, &half)
                .updates
                .len(),
            1
        );
        assert!(refusal(&[close, pull()], &posted, &half).contains("no fork"));

        let swept = json!({"type": "add_comment", "body": "Swept."});
        let issue = json!({"type": "close_issue", "repo": "owner/source", "issue_number": 12, "body": "Done."});
        let mut pull_as_issue = issue.clone();
        pull_as_issue["issue_number"] = json!(13);
        let source = |issue_data: Vec<(u64, Value)>| Options {
            open: vec![12, 13],
            issue_data,
            ..Options::default()
        };
        let err = refusal(
            &[swept.clone(), issue.clone(), pull_as_issue],
            &[],
            &source(vec![(13, json!({"pull_request": {"url": "u"}}))]),
        );
        assert!(
            err.contains("a close_issue names #13, which is a pull request"),
            "{err}"
        );
        // A transferred issue: the API answers with the issue in its new
        // repository.
        for url in [
            json!("API/repos/owner/elsewhere"),
            json!("API/repos/owner/source-x"),
            Value::Null,
        ] {
            let data = json!({"repository_url": url});
            let err = refusal(std::slice::from_ref(&issue), &[], &source(vec![(12, data)]));
            assert!(
                err.contains("a close_issue names #12, which is not an issue of owner/source"),
                "{url}: {err}"
            );
        }
        let cased = ok(
            std::slice::from_ref(&issue),
            &[],
            &source(vec![(
                12,
                json!({"repository_url": "API/repos/Owner/Source"}),
            )]),
        );
        assert_eq!(cased.kept.len(), 1);

        let reply = json!({"type": "reply_to_pull_request_review_comment", "comment_id": 1001, "body": "Fixed."});
        let item = Options {
            item_repo: "owner/item",
            review_comments: vec![
                (1001, "API/repos/Owner/Item/pulls/64"),
                (1002, "API/repos/owner/item/pulls/65"),
                (1003, "API/repos/owner/other/pulls/64"),
                (1004, "API/repos/owner/item/pulls/640"),
            ],
            ..Options::default()
        };
        let fine = ok(std::slice::from_ref(&reply), &[], &item);
        assert_eq!(fine.kept, std::slice::from_ref(&reply));
        assert_eq!(fine.queries, ["review comment owner/item 1001"]);
        for id in [1002, 1003, 1004, 1005] {
            let mut other = reply.clone();
            other["comment_id"] = json!(id);
            let err = refusal(&[swept.clone(), other], &[], &item);
            let want = if id == 1005 {
                "HTTP 404".to_owned()
            } else {
                format!("names comment {id}, which is not on pull request #64 of owner/item")
            };
            assert!(err.contains(&want), "{id}: {err}");
        }
    }
}
