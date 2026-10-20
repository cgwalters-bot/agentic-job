//! `agentic-job apply`: publish what `check` accepted to a forge that is
//! not GitHub, from a job of its own that holds the write token. GitHub's
//! apply is still gh-aw's handlers in apply.yml; this is the first slice
//! of moving publishing behind [`Publisher`] (#1346), for Forgejo, and
//! for two outputs only: `add_comment` and `create_pull_request`.
//!
//! The input is the check job's upload: check's `report.json` and the
//! patch beside it. That upload went through a machine other than the
//! agent's, but apply holds it to the policy again rather than take the
//! report's word: the same counts, types, destinations, marker, handler
//! limits and patch rules check applies, and a patch that is byte for
//! byte the size check reported. Everything is decided before the first
//! write ([`plan`]), so a refusal leaves the forge as it was.

pub mod forgejo;
mod mentions;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::check::{self, PatchReading, handler_limits};
use crate::exit::Exit;
use crate::files;
use crate::policy::{CREATE_PULL_REQUEST, PatchRules, Policy};

/// Check's verdict, as the check job uploads it.
pub const REPORT_FILE: &str = "report.json";

/// The environment variable holding the forge's token: never an
/// argument, which any user of the machine can read in `/proc`.
pub const TOKEN_ENV: &str = "FORGEJO_TOKEN";

const ADD_COMMENT: &str = "add_comment";

/// What this publishes. Anything else is refused, not left out: a run
/// whose closing or labelling is silently dropped looks done when it is
/// not.
const SUPPORTED: &[&str] = &[ADD_COMMENT, CREATE_PULL_REQUEST];

/// check's own bound on the collector's result, which the report repeats.
const MAX_REPORT_BYTES: u64 = 4 << 20;

/// The longest run link the footer takes.
const MAX_RUN_URL: usize = 2048;

/// A branch git and the forge both take as written, that cannot be read
/// as an option or a path out of `refs/heads/`.
static BRANCH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$").expect("a valid pattern"));

static COMMIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{40}$").expect("a valid pattern"));

/// What Forgejo reads as a work-in-progress pull request: it has no draft
/// flag, and refuses to merge one whose title starts so (its default
/// `WORK_IN_PROGRESS_PREFIXES`).
pub const DRAFT_PREFIX: &str = "WIP: ";

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Forge {
    Forgejo,
}

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The forge to publish to
    #[arg(long, value_enum)]
    pub forge: Forge,
    /// The forge's address, without `/api/v1`
    #[arg(long, value_name = "URL")]
    pub server: String,
    /// The repository to publish to: the policy's
    #[arg(long, value_name = "OWNER/NAME")]
    pub repo: String,
    /// The policy.json that `check` checked against
    #[arg(long, value_name = "FILE")]
    pub policy: PathBuf,
    /// The check job's upload: its report.json and the patch it accepted
    #[arg(long, value_name = "DIR")]
    pub checked: PathBuf,
    /// The issue or pull request a comment goes to, from the caller
    #[arg(long, value_name = "NUMBER", value_parser = clap::value_parser!(u64).range(1..))]
    pub comment_target: Option<u64>,
    /// The run's page, linked from the footer of what is posted
    #[arg(long, value_name = "URL")]
    pub run_url: String,
    /// The fork a pull request's branch is pushed to: the policy's `push_repo`
    #[arg(long, value_name = "OWNER/NAME")]
    pub push_repo: Option<String>,
    /// Open the PR for this exact previously pushed commit, without pushing again
    #[arg(long, value_name = "SHA")]
    pub recover_pushed_commit: Option<String>,
}

/// One write, everything about it decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Comment { issue: u64, body: String },
    PullRequest(PullRequest),
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
    pub patch: Vec<u8>,
    /// The paths the patch names, as check read them: the only paths the
    /// pushed commit may change.
    pub files: Vec<String>,
}

/// The writes a forge does for apply. Each returns the URL of what it made.
pub trait Publisher {
    fn comment(&self, issue: u64, body: &str) -> Result<String>;
    /// Pushes the patch to a new branch of the fork and opens a pull
    /// request from it.
    fn open_pull_request(&self, pr: &PullRequest) -> Result<String>;
}

/// Where the trusted caller has apply publish.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub repo: &'a str,
    pub push_repo: Option<&'a str>,
    pub comment_target: Option<u64>,
    pub run_url: &'a str,
}

/// check's [`check::Verdict`], read back. Unknown fields (warnings,
/// memory) are check's and decide nothing here.
#[derive(Debug, Deserialize)]
struct Report {
    ok: bool,
    errors: Vec<String>,
    items: Vec<Map<String, Value>>,
    patch: Option<ReportPatch>,
    #[serde(default)]
    checkpoint: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ReportPatch {
    file: String,
    bytes: usize,
    base_commit: String,
    files: Vec<String>,
    #[serde(default)]
    commit_files: Option<Value>,
}

/// Decides every write, or refuses with every reason found.
pub fn plan(checked: &Path, policy: &Policy, target: &Target<'_>) -> Result<Vec<Op>, Vec<String>> {
    let mut errors = Vec::new();
    if !target.repo.eq_ignore_ascii_case(&policy.repo) {
        errors.push(format!(
            "apply publishes to {}, and the policy is for {}",
            target.repo, policy.repo
        ));
    }
    if let Err(err) = footer(target.run_url) {
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
        if !SUPPORTED.contains(&output) {
            errors.push(format!(
                "an output of type {output:?}, which apply does not publish to Forgejo"
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
        errors.extend(check::redirections_to(item, policy, comment));
        errors.extend(handler_limits::refusals(item));
        if check::map_holds_marker(item) {
            errors.push(format!("a {output} holding the marker apply writes"));
        }
        let text = |key: &str| item.get(key).and_then(Value::as_str);
        match output {
            ADD_COMMENT => match (target.comment_target, text("body")) {
                (None, _) => errors.push(
                    "an add_comment, and the caller gave no --comment-target for it".to_owned(),
                ),
                (_, None) => errors.push("an add_comment without a body".to_owned()),
                (Some(issue), Some(body)) => ops.push(Op::Comment {
                    issue,
                    body: with_footer(&mentions::filter(body, "forgejo"), target.run_url),
                }),
            },
            CREATE_PULL_REQUEST => match pull_request(checked, policy, &report, item, target) {
                Ok(pr) => ops.push(Op::PullRequest(pr)),
                Err(err) => errors.push(format!("{err:#}")),
            },
            _ => {}
        }
    }
    let carried = report
        .items
        .iter()
        .any(|item| check::item_type(item) == CREATE_PULL_REQUEST);
    if report.patch.is_some() && !carried {
        errors.push("a patch without a create_pull_request".to_owned());
    }
    if errors.is_empty() {
        // The pull request first: its push makes the last checks, against
        // the repository (base commit, applied paths, a new branch), and a
        // refusal there is to leave no comment pointing at nothing.
        ops.sort_by_key(|op| matches!(op, Op::Comment { .. }));
        Ok(ops)
    } else {
        Err(errors)
    }
}

fn read_report(checked: &Path) -> Result<Report> {
    let path = checked.join(REPORT_FILE);
    let bytes = files::read_regular(&path, MAX_REPORT_BYTES)
        .with_context(|| format!("check's report {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not check's report", path.display()))
}

/// The pull request of `item`, with its patch read again and held to the
/// policy's rules, as check held it.
fn pull_request(
    checked: &Path,
    policy: &Policy,
    report: &Report,
    item: &Map<String, Value>,
    target: &Target<'_>,
) -> Result<PullRequest> {
    // The branch goes to a fork, never the target, whose own CI would run
    // it with the target's secrets; and to the fork the bounds name, not
    // one the caller's command line or the hand-back chose.
    let push_repo = target
        .push_repo
        .context("a create_pull_request, and the caller gave no --push-repo for its branch")?;
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
    let text = |key: &str| {
        item.get(key)
            .and_then(Value::as_str)
            .with_context(|| format!("a create_pull_request without a {key}"))
    };
    let (title, body, branch) = (text("title")?, text("body")?, text("branch")?);
    anyhow::ensure!(
        BRANCH_RE.is_match(branch)
            && !branch.contains("..")
            && !branch.contains("//")
            && !branch.ends_with(['/', '.'])
            && !branch.ends_with(".lock")
            && branch != policy.base,
        "a create_pull_request for branch {branch:?}, which apply does not push"
    );
    let pr_rules = policy
        .safe_outputs
        .create_pull_request
        .as_ref()
        .context("a create_pull_request, which the policy does not allow")?;
    let patch = report
        .patch
        .as_ref()
        .context("a create_pull_request, and check accepted no patch")?;
    anyhow::ensure!(
        patch.commit_files.is_none(),
        "a replacement series, which apply does not push to Forgejo"
    );
    let name = check::patch_file_name(branch);
    anyhow::ensure!(
        patch.file == name,
        "check accepted the patch {:?}, and the pull request's is {name}",
        patch.file
    );
    anyhow::ensure!(
        COMMIT_RE.is_match(&patch.base_commit),
        "check's base commit {:?} is not a commit id",
        patch.base_commit
    );
    // `name` is one plain file name: `patch_file_name` takes out `/`.
    let bytes = files::read_regular(&checked.join(&name), policy.max_patch_bytes)
        .with_context(|| format!("the patch {name}"))?;
    anyhow::ensure!(
        bytes.len() == patch.bytes,
        "the patch {name} is {} bytes, and check read {}",
        bytes.len(),
        patch.bytes
    );
    let rules = PatchRules {
        commit_author: policy.commit_author.as_deref(),
        ..pr_rules.rules()
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
    // Complete work under `ready_when_complete` opens ready, as on
    // GitHub; anything else a draft.
    let draft = pr_rules.draft && !(pr_rules.ready_when_complete && report.checkpoint.is_none());
    Ok(PullRequest {
        base: policy.base.clone(),
        base_commit: patch.base_commit.clone(),
        push_repo: push_repo.to_owned(),
        private: policy.private,
        branch: branch.to_owned(),
        title: if draft {
            format!("{DRAFT_PREFIX}{title}")
        } else {
            title.to_owned()
        },
        body: with_footer(&mentions::filter(body, "forgejo"), target.run_url),
        patch: bytes,
        files,
    })
}

/// The OWNER of OWNER/NAME.
fn owner(repo: &str) -> &str {
    repo.split_once('/').map_or(repo, |(owner, _)| owner)
}

/// gh-aw's footer, adapted: the run a post came from, so that a reader
/// can find its log and what it was asked. The link is the caller's.
fn footer(run_url: &str) -> Result<String> {
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
    Ok(format!("> Generated by [agentic-job]({run_url})"))
}

/// BODY with the footer: before its trailer block if it ends in one, so
/// that the block stays its last lines byte for byte (a merger may read
/// `Closes #N` and `Key: value` trailers only there), after it otherwise.
fn with_footer(body: &str, run_url: &str) -> String {
    // `plan` refuses before any write when the link is not one.
    let footer = footer(run_url).unwrap_or_default();
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

/// Makes the writes in order. A failure after the first write names what
/// was already made, so that whoever runs it again knows.
pub fn publish(ops: &[Op], publisher: &dyn Publisher) -> Result<Vec<String>> {
    let mut made = Vec::new();
    for op in ops {
        let url = match op {
            Op::Comment { issue, body } => publisher.comment(*issue, body),
            Op::PullRequest(pr) => publisher.open_pull_request(pr),
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

pub fn run(args: &Args) -> Result<Exit> {
    if let Some(commit) = &args.recover_pushed_commit {
        anyhow::ensure!(
            COMMIT_RE.is_match(commit),
            "--recover-pushed-commit requires a full commit SHA"
        );
    }
    let policy = Policy::load(&args.policy)?;
    let token = std::env::var(TOKEN_ENV).unwrap_or_default();
    anyhow::ensure!(!token.is_empty(), "{TOKEN_ENV} is not set");
    let publisher = match args.forge {
        Forge::Forgejo => {
            forgejo::Forgejo::new(&args.server, &policy.repo, token, &policy.allow_http)?
                .recovering(args.recover_pushed_commit.clone())
        }
    };
    let target = Target {
        repo: &args.repo,
        push_repo: args.push_repo.as_deref(),
        comment_target: args.comment_target,
        run_url: &args.run_url,
    };
    let ops = match plan(&args.checked, &policy, &target) {
        Ok(ops) => ops,
        Err(errors) => {
            for error in errors {
                eprintln!("error: {}", crate::run::enter::one_line(&error));
            }
            return Ok(Exit::Failure);
        }
    };
    for url in publish(&ops, &publisher)? {
        println!("{url}");
    }
    Ok(Exit::Success)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use serde_json::json;

    use super::*;
    use crate::check::BASE_COMMIT_HEADER;
    use crate::policy::OutputLimit;

    const BASE: &str = "1111111111111111111111111111111111111111";
    const BRANCH: &str = "agent-run-7";
    const PATCH_NAME: &str = "aw-agent-run-7.patch";
    const RUN: &str = "https://forge.example/o/r/actions/runs/7";
    const PUSH_REPO: &str = "bot/bootc";

    pub(super) fn policy() -> Policy {
        let mut policy = crate::policy::tests::policy();
        policy.push_repo = Some(PUSH_REPO.to_owned());
        policy.safe_outputs.others.insert(
            ADD_COMMENT.to_owned(),
            OutputLimit {
                max: 1,
                ..OutputLimit::default()
            },
        );
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

    pub(super) fn target(comment_target: Option<u64>) -> Target<'static> {
        Target {
            repo: "bootc-dev/bootc",
            push_repo: Some(PUSH_REPO),
            comment_target,
            run_url: RUN,
        }
    }

    #[test]
    fn filters_every_planned_body() {
        let mut comment = comment_item();
        let mut pr = pull_request_item();
        for item in [&mut comment, &mut pr] {
            item["body"] = json!("@user @org/team !12 `@code` user@example.com");
        }
        let dir = checked(&[comment, pr]);
        let ops = plan(dir.path(), &policy(), &target(Some(64))).unwrap();
        for op in ops {
            let body = match op {
                Op::Comment { body, .. } => body,
                Op::PullRequest(pr) => pr.body,
            };
            assert!(body.starts_with(
                "@\u{200b}user @\u{200b}org/team !\u{200b}12 `@code` user@example.com"
            ));
        }
    }

    #[test]
    fn accepted() {
        let dir = checked(&[comment_item(), pull_request_item()]);
        let ops = plan(dir.path(), &policy(), &target(Some(64))).unwrap();
        let footer = format!("\n\n> Generated by [agentic-job]({RUN})");
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
    }

    /// The footer goes before a trailer block at the end of a body, which
    /// stays its last lines byte for byte, and after the body otherwise.
    #[test]
    fn footer_placement() {
        let footer = format!("> Generated by [agentic-job]({RUN})");
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
            assert_eq!(with_footer(body, RUN), want, "{body:?}");
        }

        // A pull request's body and a comment's alike.
        let body = format!("Why.\n\n{generated}\nCloses #5");
        let dir = checked(&[
            json!({"type": "add_comment", "body": body}),
            json!({"type": "create_pull_request", "title": "Fix it", "body": body, "branch": BRANCH}),
        ]);
        let ops = plan(dir.path(), &policy(), &target(Some(64))).unwrap();
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
                &[json!({"type": "noop", "message": "x"})],
                none,
                "\"noop\", which apply does not publish",
            ),
            (
                &[json!({"type": "close_issue", "body": "x"})],
                none,
                "\"close_issue\", which apply does not publish",
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
            let errors = plan(dir.path(), &policy, &target).unwrap_err();
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
            let ops = plan(dir.path(), &policy, &target(None)).unwrap();
            let Op::PullRequest(pr) = &ops[0] else {
                panic!("{ops:?}")
            };
            assert_eq!(pr.title, title);
        }
    }

    #[derive(Default)]
    struct Recording {
        calls: RefCell<Vec<String>>,
        fail_at: Option<usize>,
    }

    impl Publisher for Recording {
        fn comment(&self, issue: u64, _: &str) -> Result<String> {
            self.call(format!("comment {issue}"))
        }
        fn open_pull_request(&self, pr: &PullRequest) -> Result<String> {
            self.call(format!("pull {}", pr.branch))
        }
    }

    impl Recording {
        fn call(&self, what: String) -> Result<String> {
            let mut calls = self.calls.borrow_mut();
            anyhow::ensure!(self.fail_at != Some(calls.len()), "refused");
            calls.push(what.clone());
            Ok(format!("url of {what}"))
        }
    }

    #[test]
    fn publishes_in_order_and_names_what_was_made() {
        let dir = checked(&[comment_item(), pull_request_item()]);
        let ops = plan(dir.path(), &policy(), &target(Some(64))).unwrap();
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
}
