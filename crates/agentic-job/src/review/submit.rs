//! review.yml's submit and status jobs: the checked verdict as the pull
//! request's review, and as the commit status `review`. Both run the policy
//! job's binary of the pinned source, never the reviewed head, and read no
//! agent text but check's accepted upload: the verdict is one of two words
//! check set, and the head is the one policy admitted.

use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use serde::Serialize;
use serde_json::{Value, json};

use super::verdict::{self, Verdict, escape, inline_section, one_line, positive};
use super::{REVIEW_COMMENT, SHA};

const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RESPONSE: u64 = 16 << 20;
// Pages of 100: more open pull requests, comments, reviews or files than
// this fail the job rather than decide on part of them.
const PER_PAGE: usize = 100;
const MAX_PAGES: usize = 30;
const DEFAULT_API: &str = "https://api.github.com";
const DEFAULT_SERVER: &str = "https://github.com";
// The job token's user, which posts what this job and apply post.
const BOT: &str = "github-actions[bot]";
// Who else may have posted apply's comment: the PAT's user has write access.
const WRITERS: [&str; 3] = ["OWNER", "MEMBER", "COLLABORATOR"];
// Why GitHub refused a submission, from its response body, never its
// headers or URL: one line, bounded, as an annotation is.
const REFUSAL_MESSAGE_MAX: usize = 400;
const REFUSAL_ERRORS_MAX: usize = 250;
static APPLIED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<!-- agentic-job-applied: (\d+)/\d+/[0-9a-f]{16} -->").expect("valid pattern")
});
static HUNK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@").expect("valid pattern")
});
static RUN_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[1-9][0-9]*$").expect("valid pattern"));

/// What the jobs ask of GitHub's REST API, PATH under it.
pub trait Api {
    fn get(&self, path: &str) -> Result<Value>;
    fn post(&self, path: &str, body: &Value) -> Result<Value>;

    /// Every page of the list at PATH.
    fn list(&self, path: &str) -> Result<Vec<Value>> {
        let mut all = Vec::new();
        let join = if path.contains('?') { '&' } else { '?' };
        for page in 1..=MAX_PAGES {
            let got = self.get(&format!("{path}{join}per_page={PER_PAGE}&page={page}"))?;
            let Value::Array(items) = got else {
                bail!("GET {path}: the response is not a list");
            };
            let last = items.len() < PER_PAGE;
            all.extend(items);
            if last {
                return Ok(all);
            }
        }
        bail!("GET {path}: more than {MAX_PAGES} pages")
    }
}

/// GitHub's answer to a request it refused.
#[derive(Debug)]
pub struct Refused {
    status: u16,
    /// Its message and errors, where the body is the usual JSON object.
    why: Option<(String, String)>,
}

impl Refused {
    fn new(status: u16, body: &str) -> Self {
        let why = serde_json::from_str::<Value>(body)
            .ok()
            .filter(Value::is_object)
            .map(|data| {
                let message = one_line(
                    data["message"].as_str().unwrap_or_default(),
                    REFUSAL_MESSAGE_MAX,
                );
                let errors = match &data["errors"] {
                    errors @ Value::Array(_) => one_line(&errors.to_string(), REFUSAL_ERRORS_MAX),
                    _ => String::new(),
                };
                (message, errors)
            });
        Self { status, why }
    }

    /// Why, as `message; errors: [...]`, or empty.
    fn reason(&self) -> String {
        let Some((message, errors)) = &self.why else {
            return String::new();
        };
        let errors = (!errors.is_empty()).then(|| format!("errors: {errors}"));
        [Some(message.clone()).filter(|m| !m.is_empty()), errors]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("; ")
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason() {
            reason if reason.is_empty() => write!(f, "status {}", self.status),
            reason => write!(f, "status {} ({reason})", self.status),
        }
    }
}

impl std::error::Error for Refused {}

/// The REST API with the job's token (GH_TOKEN), at GITHUB_API_URL.
pub struct Github {
    api: String,
    token: String,
    http: ureq::Agent,
}

impl Github {
    pub fn from_env(env: &dyn Fn(&str) -> String) -> Result<Self> {
        let token = env("GH_TOKEN");
        ensure!(!token.is_empty(), "GH_TOKEN must hold the job's token");
        let api = match env("GITHUB_API_URL") {
            api if api.is_empty() => DEFAULT_API.to_owned(),
            api => api.trim_end_matches('/').to_owned(),
        };
        // The token goes nowhere but the forge's API, over TLS.
        ensure!(api.starts_with("https://"), "GITHUB_API_URL must be https");
        let http = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();
        Ok(Self { api, token, http })
    }

    fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let url = format!("{}/{path}", self.api);
        let authorization = format!("Bearer {}", self.token);
        let response = match body {
            Some(body) => self
                .http
                .post(&url)
                .header("Authorization", &authorization)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", env!("CARGO_PKG_NAME"))
                .header("Content-Type", "application/json")
                .send(body.to_string().as_bytes()),
            None => self
                .http
                .get(&url)
                .header("Authorization", &authorization)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", env!("CARGO_PKG_NAME"))
                .call(),
        };
        let mut response = response.with_context(|| format!("{method} {path}"))?;
        let status = response.status();
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE)
            .read_to_string()
            .with_context(|| format!("{method} {path}"))?;
        if !status.is_success() {
            return Err(anyhow::Error::new(Refused::new(status.as_u16(), &text)))
                .with_context(|| format!("{method} {path}"));
        }
        serde_json::from_str(&text)
            .with_context(|| format!("{method} {path}: the response is not JSON"))
    }
}

impl Api for Github {
    fn get(&self, path: &str) -> Result<Value> {
        self.send("GET", path, None)
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.send("POST", path, Some(body))
    }
}

/// A workflow command's message, kept to its one line.
fn annotate(kind: &str, message: &str) {
    let message = message
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A");
    println!("::{kind}::{message}");
}

/// The reviewed pull request and head, from the job's environment.
struct Run {
    repo: String,
    pull: u64,
    head: String,
}

impl Run {
    fn read(env: &dyn Fn(&str) -> String) -> Result<Self> {
        let head = env("HEAD_SHA");
        let pull = positive(&Value::String(env("PULL")));
        let (Some(pull), true) = (pull, SHA.is_match(&head)) else {
            bail!("Review status requires a pull request number and an exact head SHA");
        };
        let repo = env("GITHUB_REPOSITORY");
        ensure!(
            super::REPO.is_match(&repo),
            "GITHUB_REPOSITORY must be OWNER/NAME"
        );
        Ok(Self { repo, pull, head })
    }
}

/// The status for one finished run, or why it sets none.
#[derive(Debug, PartialEq)]
enum Status {
    Skip(String),
    Set {
        state: &'static str,
        description: &'static str,
    },
}

/// The commit status `review`, from the jobs' results and the open pull
/// requests at the reviewed head. Success needs a checked APPROVE that was
/// posted, as the submitted review or else apply's comment. A status
/// belongs to the commit, so it is set only when the triggering pull
/// request is the one open there (docs/review.md).
fn review_status(env: &dyn Fn(&str) -> String, run: &Run, open: &[u64]) -> Status {
    if open != [run.pull] {
        let open = open
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let open = if open.is_empty() { "none".into() } else { open };
        return Status::Skip(format!(
            "No review status on {}: its open pull requests are {open}, not only #{}",
            run.head, run.pull
        ));
    }
    let posted = !env("REVIEW_URL").is_empty()
        || (env("APPLY_RESULT") == "success" && !env("RESULT_URL").is_empty());
    let (state, description) = if env("CHECK_RESULT") != "success" || !posted {
        ("failure", "The review did not post; see the workflow run")
    } else {
        match env("VERDICT").as_str() {
            "APPROVE" => ("success", "The review approved this commit"),
            "CHANGES" => ("failure", "The review asked for changes"),
            _ => ("failure", "The review did not approve this commit"),
        }
    };
    Status::Set { state, description }
}

/// Sets the status `review` on the head, after listing the open pull
/// requests there.
pub fn report_status(env: &dyn Fn(&str) -> String, api: &dyn Api) -> Result<()> {
    // Validated before the head goes into any request.
    let run = Run::read(env)?;
    let pulls = api.list(&format!("repos/{}/pulls?state=open", run.repo))?;
    let open: Vec<u64> = pulls
        .iter()
        .filter(|pull| pull["head"]["sha"] == run.head.as_str())
        .filter_map(|pull| pull["number"].as_u64())
        .collect();
    match review_status(env, &run, &open) {
        Status::Skip(why) => annotate("notice", &why),
        Status::Set { state, description } => {
            api.post(
                &format!("repos/{}/statuses/{}", run.repo, run.head),
                &json!({"context": "review", "state": state, "description": description,
                    "target_url": env("RUN_URL")}),
            )?;
        }
    }
    Ok(())
}

const LEFT: usize = 0;
const RIGHT: usize = 1;

/// For each side of a file, each line of its diff with the hunk it is in.
type Sides = [HashMap<u64, usize>; 2];

/// The lines a review comment can sit on, from the pull request's files as
/// the API lists them. A file without a `patch` (binary, or too large for
/// the API to show) has none.
fn diff_lines(files: &[Value]) -> HashMap<String, Sides> {
    let mut lines = HashMap::new();
    for file in files {
        let (Some(name), Some(patch)) = (file["filename"].as_str(), file["patch"].as_str()) else {
            continue;
        };
        let mut sides: Sides = Default::default();
        let (mut left, mut right, mut hunk) = (0, 0, None);
        for line in patch.split('\n') {
            if let Some(start) = HUNK.captures(line) {
                left = start[1].parse().unwrap_or_default();
                right = start[2].parse().unwrap_or_default();
                hunk = Some(hunk.map_or(0, |h| h + 1));
                continue;
            }
            // A context line is never empty (it starts with a space): this
            // is the end of a patch that ends in a newline.
            let Some(hunk) = hunk.filter(|_| !line.is_empty() && !line.starts_with('\\')) else {
                continue;
            };
            if !line.starts_with('-') {
                sides[RIGHT].insert(right, hunk);
                right += 1;
            }
            if !line.starts_with('+') {
                sides[LEFT].insert(left, hunk);
                left += 1;
            }
        }
        lines.insert(name.to_owned(), sides);
    }
    lines
}

/// A review comment, as the API takes it; its JSON, in this order, is
/// also what the review's digest is of.
#[derive(Debug, PartialEq, Serialize)]
struct Comment {
    path: String,
    line: u64,
    side: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_side: Option<&'static str>,
    body: String,
}

/// The review comment for an inline finding, or `None` where GitHub would
/// refuse its anchor and with it the whole review: a path or line outside
/// the diff, or lines across hunks.
fn review_comment(lines: &HashMap<String, Sides>, item: &Value) -> Option<Comment> {
    let (index, side) = if item["side"] == "LEFT" {
        (LEFT, "LEFT")
    } else {
        (RIGHT, "RIGHT")
    };
    let line = positive(&item["line"])?;
    let start = positive(&item["start_line"]).unwrap_or(line);
    let path = item["path"].as_str()?;
    let hunks = &lines.get(path)?[index];
    let hunk = hunks.get(&line)?;
    (hunks.get(&start) == Some(hunk)).then(|| Comment {
        path: path.to_owned(),
        line,
        side,
        start_line: (start < line).then_some(start),
        start_side: (start < line).then_some(side),
        body: item["body"].as_str().unwrap_or_default().to_owned(),
    })
}

/// The visible footer gh-aw's handler puts on a comment (messages_footer.cjs,
/// "> Generated by [workflow](run) for #N"), which a submitted review would
/// otherwise lack: without it a reader of an approval cannot get to the job
/// that made it (#592). Everything in it is this job's own context, never
/// agent output, so the review text cannot choose where it points; a footer
/// the text imitates comes before this one, which is last. As with gh-aw's
/// own footer, text that leaves a <details> or code fence open can still
/// fold this footer away or show it as code, under an imitation above it;
/// the raw body still ends with this one. It links the agent job where its
/// ID is known, else the run, and names the head the verdict is for, as the
/// review's commit_id binds it.
fn footer(env: &dyn Fn(&str) -> String, run_url: &str, run: &Run) -> String {
    let job = env("AGENT_JOB");
    let link = if RUN_ID.is_match(&job) {
        format!("{run_url}/job/{job}")
    } else {
        run_url.to_owned()
    };
    // A workflow's name is the repository's; it is kept to plain
    // characters so that it neither ends the link text nor mentions anyone.
    let name: String = env("GITHUB_WORKFLOW")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || " _.:()-".contains(c) {
                c
            } else {
                ' '
            }
        })
        .collect();
    let name = match name.trim() {
        "" => "review",
        name => name,
    };
    format!(
        "> Generated by [{name}]({link}) for #{} at {}",
        run.pull, run.head
    )
}

fn sha256_hex(text: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, text.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Where a posted review or comment is, from what the API answered: its
/// `html_url` where that is one plain line on the server, else made from
/// its ID. It goes into $GITHUB_OUTPUT, where a newline would add an output.
fn posted_url(server: &str, data: &Value, fallback: impl FnOnce(u64) -> String) -> Result<String> {
    match data["html_url"].as_str() {
        Some(url)
            if url.starts_with(&format!("{server}/"))
                && !url.chars().any(|c| c.is_whitespace() || c.is_control()) =>
        {
            Ok(url.to_owned())
        }
        _ => Ok(fallback(
            data["id"].as_u64().context("the response names no id")?,
        )),
    }
}

/// With real reviews on, the verdict is posted once, as the pull request's
/// review, and apply posts no comment (#583); its URL, or empty where
/// nothing was submitted. OUTPUT is check's accepted output, read from
/// check's upload in this run, so what is submitted is exactly what check
/// and the collector's sanitizing passed, never text read back from the
/// forge. Nothing submitted (off, a noop, a run stopped at a limit, a moved
/// head, a failed submission) leaves the comment to apply as before.
pub fn submit(env: &dyn Fn(&str) -> String, output: &Value, api: &dyn Api) -> Result<String> {
    if env("REAL_REVIEWS") != "true" {
        return Ok(String::new());
    }
    // Validated before any API call.
    let run = Run::read(env)?;
    // apply-partial is false for a review (`review task`): a run stopped at
    // a limit is not applied, so it is not submitted either.
    let checked = env("VERDICT");
    if env("CHECK_RESULT") != "success"
        || env("AGENT_EXIT") != "0"
        || !matches!(checked.as_str(), "APPROVE" | "CHANGES")
    {
        return Ok(String::new());
    }
    let verdict = verdict::check_outputs(output, &run.pull.to_string())?;
    ensure!(
        Verdict::word(verdict) == checked,
        "Checked output does not match the checked verdict"
    );
    let run_id = env("GITHUB_RUN_ID");
    ensure!(
        RUN_ID.is_match(&run_id),
        "Review submission requires this run's ID"
    );
    let (repo, pull) = (&run.repo, run.pull);
    let current = api.get(&format!("repos/{repo}/pulls/{pull}"))?;
    if current["state"] != "open" || current["head"]["sha"] != run.head.as_str() {
        annotate(
            "notice",
            "No review submitted: the reviewed head is no longer current",
        );
        return Ok(String::new());
    }
    let server = match env("GITHUB_SERVER_URL") {
        server if server.is_empty() => DEFAULT_SERVER.to_owned(),
        server => server.trim_end_matches('/').to_owned(),
    };
    // The run marker gh-aw's handler ends a comment with (generate_footer.cjs).
    // agent-board's poll (board-forge/src/poll.rs, cited_run) needs exactly
    // one, with its run URL, to tie the review to this run.
    let run_url = format!("{server}/{repo}/actions/runs/{run_id}");
    let marker = format!(
        "<!-- gh-aw-agentic-workflow: review, id: {run_id}, workflow_id: agentic-job, run: {run_url} -->"
    );
    let footer = footer(env, &run_url, &run);
    // Inline findings go in the same review, as its comments, where their
    // lines are in the diff of the head just read, and the rest in its
    // body, so a bad anchor loses nothing and fails nothing. The files are
    // read only to place comments, never to decide whether to approve
    // (#540). At the same head the split, and so the body, is the same on
    // a re-run.
    let items = output["items"].as_array().map_or(&[][..], Vec::as_slice);
    let inline: Vec<&Value> = items
        .iter()
        .filter(|i| i["type"] == REVIEW_COMMENT)
        .collect();
    let lines = if inline.is_empty() {
        HashMap::new()
    } else {
        diff_lines(&api.list(&format!("repos/{repo}/pulls/{pull}/files"))?)
    };
    let placed: Vec<Option<Comment>> = inline.iter().map(|i| review_comment(&lines, i)).collect();
    let unplaced = inline
        .iter()
        .zip(&placed)
        .filter(|(_, p)| p.is_none())
        .map(|(i, _)| *i);
    let anchored: Vec<&Comment> = placed.iter().flatten().collect();
    let text = items
        .iter()
        .find(|i| i["type"] == "add_comment")
        .and_then(|i| i["body"].as_str())
        .context("the checked output has no verdict comment")?;
    // The anchored comments are not in the body text, so their digest is,
    // to make them part of the review's identity below: a re-run at this
    // head whose verdict is the same but whose inline findings differ is
    // another review, not the earlier one found again with these lost.
    let digest = if anchored.is_empty() {
        String::new()
    } else {
        let comments = serde_json::to_string(&anchored)?;
        format!(
            "<!-- agentic-job-review-comments: {} -->\n\n",
            sha256_hex(&comments)
        )
    };
    let body = format!(
        "{text}{}\n\n{footer}\n\n{digest}{marker}",
        inline_section(unplaced)
    );
    let (event, state) = match verdict {
        Some(Verdict::Approve) => ("APPROVE", "APPROVED"),
        _ => ("REQUEST_CHANGES", "CHANGES_REQUESTED"),
    };
    // A re-run of failed jobs after a failed submission, whose verdict
    // apply then posted as the comment, must not post it again as the
    // review. Apply names each comment it posts by run, last in the body
    // (its `agentic-job-applied` name, which check refuses in agent
    // output). Only a comment by the job token's bot or someone with write
    // access counts, as with the PAT: a commenter quoting the name must not
    // turn the review back into a comment.
    let comments = api.list(&format!("repos/{repo}/issues/{pull}/comments"))?;
    let applied = comments.iter().any(|c| {
        (c["user"]["login"] == BOT || WRITERS.iter().any(|w| c["author_association"] == *w))
            && c["body"]
                .as_str()
                .and_then(|body| APPLIED.captures_iter(body).last())
                .is_some_and(|name| name[1] == run_id)
    });
    if applied {
        annotate(
            "notice",
            "No review submitted: an earlier attempt of this run posted the verdict as a comment",
        );
        return Ok(String::new());
    }
    // Nor is a review submitted twice: after a re-run, or a submission
    // whose response was lost. Only the same review counts, at this head
    // with this verdict and body; a re-run of all jobs submits its own,
    // whose footer links its own agent job, and pollers take it as the
    // latest.
    let review_url = |data: &Value| {
        posted_url(&server, data, |id| {
            format!("{server}/{repo}/pull/{pull}#pullrequestreview-{id}")
        })
    };
    let earlier = || -> Result<Option<String>> {
        let reviews = api.list(&format!("repos/{repo}/pulls/{pull}/reviews"))?;
        reviews
            .iter()
            .find(|r| {
                r["user"]["login"] == BOT
                    && r["commit_id"] == run.head.as_str()
                    && r["state"] == state
                    && r["body"] == body.as_str()
            })
            .map(review_url)
            .transpose()
    };
    if let Some(found) = earlier()? {
        return Ok(found);
    }
    // commit_id prevents a racing push from making this an approval of new
    // code; stale-review dismissal in the branch ruleset is also required.
    // An APPROVE is submitted whatever files the pull request changes, the
    // workflows and this review's own files included (#540): whether it
    // suffices to merge is the merge policy and GitHub's code-owner rule
    // (docs/review.md), and the required ci and workflow-ingress checks
    // stay its deterministic guard.
    let mut review = json!({"commit_id": run.head, "event": event, "body": body});
    if !anchored.is_empty() {
        review["comments"] = serde_json::to_value(&anchored)?;
    }
    let error = match api.post(&format!("repos/{repo}/pulls/{pull}/reviews"), &review) {
        Ok(data) => return review_url(&data),
        Err(error) => error,
    };
    // Posted all the same, the review is not to be posted again as the
    // comment.
    if let Ok(Some(posted)) = earlier() {
        return Ok(posted);
    }
    let Some(refused) = error.downcast_ref::<Refused>() else {
        return Err(error);
    };
    annotate("error", &format!("Submitting the review failed: {refused}"));
    if refused.status != 422 {
        return Err(error);
    }
    // GitHub refused the submission (a locked conversation, for example):
    // the verdict is posted as the plain comment apply would otherwise
    // post, saying the review could not be submitted and why, so the pull
    // request does not sit blocked with no explanation. Its URL counts as
    // posted for the status, and apply posts nothing beside it.
    let why = match &refused.why {
        Some((message, _)) if !message.is_empty() => format!(" ({})", escape(message)),
        _ => String::new(),
    };
    let comment = format!(
        "{text}{}\n\nThe review could not be submitted: GitHub refused it with status 422{why}.\n\n{footer}\n\n{marker}",
        inline_section(inline)
    );
    let data = api.post(
        &format!("repos/{repo}/issues/{pull}/comments"),
        &json!({"body": comment}),
    )?;
    posted_url(&server, &data, |id| {
        format!("{server}/{repo}/pull/{pull}#issuecomment-{id}")
    })
}

/// Appends `review-url=URL` to the step's $GITHUB_OUTPUT.
pub fn write_output(path: &Path, url: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(file, "review-url={url}").with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RUN: &str = "https://github.com/owner/repo/actions/runs/77";
    const MARKER: &str = "<!-- gh-aw-agentic-workflow: review, id: 77, workflow_id: agentic-job, run: https://github.com/owner/repo/actions/runs/77 -->";
    const REVIEW_URL: &str = "https://github.com/owner/repo/pull/12#pullrequestreview-5";
    const COMMENT_URL: &str = "https://github.com/owner/repo/issues/12#issuecomment-9";

    fn footer() -> String {
        format!("> Generated by [review]({RUN}/job/91) for #12 at {HEAD}")
    }

    fn trailer() -> String {
        format!("{}\n\n{MARKER}", footer())
    }

    fn environment(changes: &[(&str, &str)]) -> HashMap<String, String> {
        let mut env: HashMap<String, String> = [
            ("REAL_REVIEWS", "true"),
            ("PULL", "12"),
            ("HEAD_SHA", HEAD),
            ("CHECK_RESULT", "success"),
            ("AGENT_EXIT", "0"),
            ("VERDICT", "APPROVE"),
            ("GITHUB_REPOSITORY", "owner/repo"),
            ("GITHUB_RUN_ID", "77"),
            ("GITHUB_WORKFLOW", "review"),
            ("AGENT_JOB", "91"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        for (key, value) in changes {
            env.insert((*key).to_owned(), (*value).to_owned());
        }
        env
    }

    fn checked(body: &str) -> Value {
        json!({"items": [{"type": "add_comment", "body": body}], "errors": []})
    }

    /// GitHub as the tests need it: what it lists, and what was posted.
    #[derive(Default)]
    struct Fake {
        sha: Option<&'static str>,
        closed: bool,
        comments: Vec<Value>,
        reviews: RefCell<Vec<Value>>,
        files: Vec<Value>,
        pulls: Vec<Value>,
        /// What the review submission fails with, and whether it posted.
        refuse: Option<(u16, &'static str, bool)>,
        posted: RefCell<Vec<(String, Value)>>,
    }

    impl Api for Fake {
        fn get(&self, path: &str) -> Result<Value> {
            let path = path.split('?').next().unwrap();
            Ok(match path {
                "repos/owner/repo/pulls/12" => json!({
                    "state": if self.closed { "closed" } else { "open" },
                    "head": {"sha": self.sha.unwrap_or(HEAD)}}),
                "repos/owner/repo/issues/12/comments" => json!(self.comments),
                "repos/owner/repo/pulls/12/reviews" => json!(*self.reviews.borrow()),
                "repos/owner/repo/pulls/12/files" => json!(self.files),
                "repos/owner/repo/pulls" | "repos/o/r/pulls" => json!(self.pulls),
                _ => panic!("unexpected GET {path}"),
            })
        }

        fn post(&self, path: &str, body: &Value) -> Result<Value> {
            if path.ends_with("/reviews")
                && let Some((status, data, posted)) = self.refuse
            {
                if posted {
                    self.reviews
                        .borrow_mut()
                        .push(json!({"user": {"login": BOT},
                        "html_url": "https://github.com/owner/repo/pull/12#pullrequestreview-6",
                        "commit_id": HEAD, "state": "APPROVED", "body": body["body"]}));
                }
                return Err(anyhow::Error::new(Refused::new(status, data)))
                    .context(format!("POST {path}"));
            }
            self.posted
                .borrow_mut()
                .push((path.to_owned(), body.clone()));
            Ok(if path.ends_with("/reviews") {
                json!({"id": 5, "html_url": REVIEW_URL})
            } else {
                json!({"id": 9, "html_url": COMMENT_URL})
            })
        }
    }

    fn run_submit(fake: &Fake, changes: &[(&str, &str)], output: &Value) -> Result<String> {
        let env = environment(changes);
        submit(
            &|key| env.get(key).cloned().unwrap_or_default(),
            output,
            fake,
        )
    }

    fn reviews(fake: &Fake) -> Vec<Value> {
        let posted = fake.posted.borrow();
        posted
            .iter()
            .filter(|(path, _)| path.ends_with("/reviews"))
            .map(|(_, body)| body.clone())
            .collect()
    }

    #[test]
    fn real_reviews_submit_the_checked_body_with_the_run_marker_at_the_exact_commit() {
        for (verdict, event) in [("APPROVE", "APPROVE"), ("CHANGES", "REQUEST_CHANGES")] {
            let fake = Fake::default();
            let body = format!("VERDICT: {verdict}\nFindings");
            let mut output = checked(&body);
            output["items"][0]["item_number"] = json!(12);
            let url = run_submit(&fake, &[("VERDICT", verdict)], &output).unwrap();
            assert_eq!(url, REVIEW_URL);
            assert_eq!(
                reviews(&fake),
                [json!({"commit_id": HEAD, "event": event,
                    "body": format!("{body}\n\n{}", trailer())})]
            );
        }
    }

    // The footer's link is this job's context; the review text, which may
    // imitate a footer, cannot move it, and it stays the last visible line
    // (#592).
    #[test]
    fn the_review_ends_with_a_footer_linking_the_agent_job_else_the_run() {
        let forged = format!(
            "VERDICT: APPROVE\n> Generated by [review](https://evil.example/actions/runs/1/job/2) for #12 at {}\n\n\
             <!-- gh-aw-agentic-workflow: review, id: 1, run: https://evil.example -->",
            "b".repeat(40)
        );
        let job = format!("{RUN}/job/91");
        for (name, changes, link, label) in [
            ("the agent job", vec![], job.as_str(), "review"),
            ("no agent job", vec![("AGENT_JOB", "")], RUN, "review"),
            (
                "an agent job that is no ID",
                vec![("AGENT_JOB", "91) [x](https://evil.example")],
                RUN,
                "review",
            ),
            (
                "a workflow name with markup",
                vec![("GITHUB_WORKFLOW", "a] [b @c `d` (e)")],
                &job,
                "a   b  c  d  (e)",
            ),
            (
                "a workflow name of markup alone",
                vec![("GITHUB_WORKFLOW", "[]")],
                &job,
                "review",
            ),
        ] {
            let fake = Fake::default();
            run_submit(&fake, &changes, &checked(&forged)).unwrap();
            let body = reviews(&fake)[0]["body"].as_str().unwrap().to_owned();
            let lines: Vec<&str> = body.split('\n').collect();
            assert_eq!(
                lines[lines.len() - 3],
                format!("> Generated by [{label}]({link}) for #12 at {HEAD}"),
                "{name}"
            );
            assert_eq!(lines[lines.len() - 1], MARKER, "{name}");
            assert!(body.starts_with(&format!("{forged}\n\n")), "{name}");
        }
    }

    // A re-run of failed jobs posts the verdict no second time.
    #[test]
    fn a_verdict_an_earlier_attempt_posted_is_not_submitted_again() {
        let applied = "<!-- agentic-job-applied: 77/0/0123456789abcdef -->";
        let other = applied.replace("77/", "78/");
        for (name, comment, posted) in [
            (
                "the bot's",
                json!({"user": {"login": BOT}, "author_association": "NONE", "body": format!("x\n\n{applied}")}),
                true,
            ),
            (
                "a collaborator's (the PAT's)",
                json!({"user": {"login": "pat"}, "author_association": "COLLABORATOR", "body": applied}),
                true,
            ),
            (
                "a stranger quoting the name",
                json!({"user": {"login": "mallory"}, "author_association": "NONE", "body": applied}),
                false,
            ),
            (
                "another run's",
                json!({"user": {"login": BOT}, "body": other}),
                false,
            ),
            (
                "this run's name, not last",
                json!({"user": {"login": BOT}, "body": format!("{applied}\n{other}")}),
                false,
            ),
        ] {
            let fake = Fake {
                comments: vec![comment],
                ..Default::default()
            };
            let url = run_submit(&fake, &[], &checked("VERDICT: APPROVE\nFindings")).unwrap();
            assert_eq!(url.is_empty(), posted, "{name}");
            assert_eq!(reviews(&fake).len(), usize::from(!posted), "{name}");
        }
        let earlier = json!({"user": {"login": BOT}, "html_url": "https://github.com/owner/repo/pull/12#pullrequestreview-4",
            "commit_id": HEAD, "state": "APPROVED", "body": format!("VERDICT: APPROVE\nFindings\n\n{}", trailer())});
        let fake = Fake {
            reviews: RefCell::new(vec![earlier.clone()]),
            ..Default::default()
        };
        let url = run_submit(&fake, &[], &checked("VERDICT: APPROVE\nFindings")).unwrap();
        assert_eq!(url, earlier["html_url"]);
        assert!(reviews(&fake).is_empty());
        // Its URL goes into $GITHUB_OUTPUT: one that is not one plain line
        // on the server is made from its ID instead.
        let mut odd = earlier.clone();
        odd["html_url"] = json!("https://github.com/x\nreview-url=https://evil.example");
        odd["id"] = json!(4);
        let fake = Fake {
            reviews: RefCell::new(vec![odd]),
            ..Default::default()
        };
        let url = run_submit(&fake, &[], &checked("VERDICT: APPROVE\nFindings")).unwrap();
        assert_eq!(url, earlier["html_url"]);
        // Only the same review: another author, head, verdict or body is
        // another review, which is submitted.
        for (key, value) in [
            ("user", json!({"login": "mallory"})),
            ("commit_id", json!("b".repeat(40))),
            ("state", json!("CHANGES_REQUESTED")),
            ("body", json!("VERDICT: APPROVE\nOther findings")),
        ] {
            let mut other = earlier.clone();
            other[key] = value;
            let fake = Fake {
                reviews: RefCell::new(vec![other]),
                ..Default::default()
            };
            let url = run_submit(&fake, &[], &checked("VERDICT: APPROVE\nFindings")).unwrap();
            assert_eq!(url, REVIEW_URL, "{key}");
        }
    }

    // A submission whose response was lost is not posted again as the
    // comment; a 422 refusal (a locked conversation, for example) is posted
    // as the comment, saying why (#1287); other failures fail the run.
    #[test]
    fn a_failed_submission_counts_if_posted_else_a_422_is_the_comment() {
        let output = checked("VERDICT: APPROVE\nFindings");
        let lost = Fake {
            refuse: Some((502, "", true)),
            ..Default::default()
        };
        let url = run_submit(&lost, &[], &output).unwrap();
        assert_eq!(
            url,
            "https://github.com/owner/repo/pull/12#pullrequestreview-6"
        );
        assert!(lost.posted.borrow().is_empty());

        let errors = r#"{"message": "lock prevents review", "errors": [{"code": "custom"}]}"#;
        for (data, why) in [
            (errors, " (lock prevents review)"),
            ("{}", ""),
            ("lock prevents review", ""),
            (
                r#"{"message": "a [link](x) @user"}"#,
                r" (a \[link\]\(x\) \@user)",
            ),
        ] {
            let fake = Fake {
                refuse: Some((422, data, false)),
                ..Default::default()
            };
            assert_eq!(run_submit(&fake, &[], &output).unwrap(), COMMENT_URL);
            let posted = fake.posted.borrow();
            assert_eq!(posted.len(), 1);
            assert_eq!(posted[0].0, "repos/owner/repo/issues/12/comments");
            assert_eq!(
                posted[0].1["body"],
                format!(
                    "VERDICT: APPROVE\nFindings\n\nThe review could not be submitted: GitHub refused it with status 422{why}.\n\n{}",
                    trailer()
                )
            );
        }
        assert_eq!(
            Refused::new(422, errors).to_string(),
            r#"status 422 (lock prevents review; errors: [{"code":"custom"}])"#
        );

        let denied = Fake {
            refuse: Some((
                403,
                r#"{"message": "Resource not accessible by integration"}"#,
                false,
            )),
            ..Default::default()
        };
        let err = run_submit(&denied, &[], &output).unwrap_err();
        assert!(
            format!("{err:#}").contains("status 403 (Resource not accessible by integration)"),
            "{err:#}"
        );
        assert!(denied.posted.borrow().is_empty());
    }

    // An empty result is what lets apply post the comment instead.
    #[test]
    fn off_incomplete_runs_noops_and_stale_heads_submit_nothing() {
        let output = checked("VERDICT: APPROVE\nFindings");
        for changes in [
            ("REAL_REVIEWS", ""),
            ("REAL_REVIEWS", "false"),
            ("CHECK_RESULT", "failure"),
            ("AGENT_EXIT", "3"),
            ("AGENT_EXIT", "124"),
            ("AGENT_EXIT", ""),
            ("VERDICT", ""),
        ] {
            let fake = Fake::default();
            assert_eq!(
                run_submit(&fake, &[changes], &output).unwrap(),
                "",
                "{changes:?}"
            );
            assert!(fake.posted.borrow().is_empty());
        }
        for fake in [
            Fake {
                sha: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                ..Default::default()
            },
            Fake {
                closed: true,
                ..Default::default()
            },
        ] {
            assert_eq!(run_submit(&fake, &[], &output).unwrap(), "");
            assert!(fake.posted.borrow().is_empty());
        }
    }

    #[test]
    fn the_checked_output_must_match_the_checked_verdict_and_pull_request() {
        for (output, error) in [
            (checked("VERDICT: CHANGES"), "does not match"),
            (checked("Findings only"), "must start with VERDICT"),
            (
                json!({"items": [{"type": "add_comment", "body": "VERDICT: APPROVE", "item_number": 13}]}),
                "triggering pull request",
            ),
            (json!({"items": [{"type": "noop"}]}), "does not match"),
            (json!({"items": []}), "exactly one"),
        ] {
            let fake = Fake::default();
            let err = run_submit(&fake, &[], &output).unwrap_err().to_string();
            assert!(err.contains(error), "{err}");
            assert!(fake.posted.borrow().is_empty());
        }
        for changes in [
            ("HEAD_SHA", "main"),
            ("PULL", "0"),
            ("GITHUB_RUN_ID", "7 -->"),
            ("GITHUB_RUN_ID", ""),
            ("GITHUB_REPOSITORY", "owner/repo/../x"),
        ] {
            let fake = Fake::default();
            assert!(
                run_submit(&fake, &[changes], &checked("VERDICT: APPROVE")).is_err(),
                "{changes:?}"
            );
            assert!(fake.posted.borrow().is_empty());
        }
    }

    // Inline findings are the review's own comments where GitHub can anchor
    // them, and its body's otherwise, so no anchor fails the submission
    // (#516).
    #[test]
    fn inline_comments_are_placed_where_the_diff_has_their_lines_else_in_the_body() {
        let files = vec![
            json!({"filename": "src/a.rs", "patch": "@@ -1,3 +1,4 @@\n one\n-two\n+TWO\n+three\n four\n@@ -20,2 +21,2 @@ fn x()\n x\n-y\n+Y\n\\ No newline at end of file"}),
            json!({"filename": "bin.png"}),
        ];
        let inline = |fields: Value| {
            let mut item = json!({"type": REVIEW_COMMENT, "body": format!("finding {}", fields["line"].as_str().map_or_else(|| fields["line"].to_string(), str::to_owned))});
            item.as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            item
        };
        let items = vec![
            inline(json!({"path": "src/a.rs", "line": 3})),
            json!({"type": "add_comment", "body": "VERDICT: CHANGES\nFindings"}),
            inline(
                json!({"path": "src/a.rs", "line": 2, "side": "LEFT", "pull_request_number": 12}),
            ),
            inline(json!({"path": "src/a.rs", "line": "4", "start_line": "2"})),
            inline(json!({"path": "src/a.rs", "line": 21, "start_line": 21})),
            inline(json!({"path": "src/a.rs", "line": 22, "start_line": 4})), // across hunks
            inline(json!({"path": "src/a.rs", "line": 5})),                   // outside the diff
            // The base's line 3 is "four", line 4 of the head.
            inline(json!({"path": "src/a.rs", "line": 3, "side": "LEFT"})),
            inline(json!({"path": "src/a.rs", "line": 22, "side": "LEFT"})),
            inline(json!({"path": "other.rs", "line": 1})),
            inline(json!({"path": "bin.png", "line": 1})),
        ];
        let text = "VERDICT: CHANGES\nFindings\n\n### Inline findings\n\
            \n**src/a.rs, lines 4-22**\n\nfinding 22\n\
            \n**src/a.rs, line 5**\n\nfinding 5\n\
            \n**src/a.rs, line 22 of the base**\n\nfinding 22\n\
            \n**other.rs, line 1**\n\nfinding 1\n\
            \n**bin.png, line 1**\n\nfinding 1\n";
        let comments = json!([
            {"path": "src/a.rs", "line": 3, "side": "RIGHT", "body": "finding 3"},
            {"path": "src/a.rs", "line": 2, "side": "LEFT", "body": "finding 2"},
            {"path": "src/a.rs", "line": 4, "side": "RIGHT", "start_line": 2, "start_side": "RIGHT", "body": "finding 4"},
            {"path": "src/a.rs", "line": 21, "side": "RIGHT", "body": "finding 21"},
            {"path": "src/a.rs", "line": 3, "side": "LEFT", "body": "finding 3"},
        ]);
        // The digest is of the comments' JSON as the JavaScript this
        // replaces wrote it, keys in this order, so a re-run across the
        // port finds the same review.
        let ordered = r#"[{"path":"src/a.rs","line":3,"side":"RIGHT","body":"finding 3"},{"path":"src/a.rs","line":2,"side":"LEFT","body":"finding 2"},{"path":"src/a.rs","line":4,"side":"RIGHT","start_line":2,"start_side":"RIGHT","body":"finding 4"},{"path":"src/a.rs","line":21,"side":"RIGHT","body":"finding 21"},{"path":"src/a.rs","line":3,"side":"LEFT","body":"finding 3"}]"#;
        let digest = format!(
            "<!-- agentic-job-review-comments: {} -->",
            sha256_hex(ordered)
        );
        let body = format!("{text}\n\n{}\n\n{digest}\n\n{MARKER}", footer());
        let output = json!({"items": items, "errors": []});
        let changes = [("VERDICT", "CHANGES")];
        let fake = Fake {
            files: files.clone(),
            ..Default::default()
        };
        run_submit(&fake, &changes, &output).unwrap();
        assert_eq!(
            reviews(&fake),
            [
                json!({"commit_id": HEAD, "event": "REQUEST_CHANGES", "body": body, "comments": comments})
            ]
        );
        // The same split on a re-run: the review it submitted is the one found.
        let earlier = json!({"user": {"login": BOT}, "html_url": "https://github.com/owner/repo/pull/12#pullrequestreview-4",
            "commit_id": HEAD, "state": "CHANGES_REQUESTED", "body": body});
        let again = Fake {
            files: files.clone(),
            reviews: RefCell::new(vec![earlier.clone()]),
            ..Default::default()
        };
        assert_eq!(
            run_submit(&again, &changes, &output).unwrap(),
            earlier["html_url"]
        );
        // But the same text with other anchored findings is another review.
        let mut moved = output.clone();
        moved["items"][4]["body"] = json!("other finding");
        let other = Fake {
            files: files.clone(),
            reviews: RefCell::new(vec![earlier]),
            ..Default::default()
        };
        assert_eq!(run_submit(&other, &changes, &moved).unwrap(), REVIEW_URL);
        assert_eq!(reviews(&other)[0]["comments"][3]["body"], "other finding");
        // A patch's trailing newline is no line to comment on.
        let trailing = Fake {
            files: vec![json!({"filename": "src/a.rs", "patch": "@@ -1 +1,2 @@\n-a\n+b\n+c\n"})],
            ..Default::default()
        };
        let output = json!({"items": [items[1].clone(), inline(json!({"path": "src/a.rs", "line": 3})), inline(json!({"path": "src/a.rs", "line": 2}))]});
        run_submit(&trailing, &changes, &output).unwrap();
        let review = &reviews(&trailing)[0];
        assert_eq!(
            review["comments"],
            json!([{"path": "src/a.rs", "line": 2, "side": "RIGHT", "body": "finding 2"}])
        );
        assert!(
            review["body"]
                .as_str()
                .unwrap()
                .contains("**src/a.rs, line 3**")
        );
        // Should GitHub still refuse an anchor, the verdict is posted as the
        // comment with every finding folded in: nothing is lost.
        let refused = Fake {
            files,
            refuse: Some((422, r#"{"message": "Line could not be resolved"}"#, false)),
            ..Default::default()
        };
        let output = json!({"items": items});
        assert_eq!(
            run_submit(&refused, &changes, &output).unwrap(),
            COMMENT_URL
        );
        let posted = refused.posted.borrow();
        let comment = posted[0].1["body"].as_str().unwrap();
        assert!(comment.starts_with("VERDICT: CHANGES\nFindings\n\n### Inline findings\n"));
        for finding in [
            "finding 3",
            "finding 2",
            "finding 4",
            "finding 21",
            "finding 22",
            "finding 5",
            "finding 1",
        ] {
            assert!(comment.contains(finding), "{finding}");
        }
        assert!(
            comment.contains("GitHub refused it with status 422 (Line could not be resolved).")
        );
        assert!(comment.ends_with(&format!("\n\n{}", trailer())));
    }

    #[test]
    fn the_review_status_maps_each_run_to_one_state_only_for_the_one_open_pull_request() {
        let approved = [
            ("PULL", "147"),
            ("HEAD_SHA", HEAD),
            ("GITHUB_REPOSITORY", "o/r"),
            ("CHECK_RESULT", "success"),
            ("VERDICT", "APPROVE"),
            ("APPLY_RESULT", "success"),
            (
                "RESULT_URL",
                "https://github.com/o/r/pull/147#issuecomment-1",
            ),
            ("REVIEW_URL", ""),
        ];
        let set = |state, description| Status::Set { state, description };
        let approve = set("success", "The review approved this commit");
        let not_posted = set("failure", "The review did not post; see the workflow run");
        let skip = |open: &str| {
            Status::Skip(format!(
                "No review status on {HEAD}: its open pull requests are {open}, not only #147"
            ))
        };
        for (name, changes, open, expected) in [
            ("approved", vec![], vec![147], approve),
            (
                "changes",
                vec![("VERDICT", "CHANGES")],
                vec![147],
                set("failure", "The review asked for changes"),
            ),
            (
                "noop",
                vec![("VERDICT", "")],
                vec![147],
                set("failure", "The review did not approve this commit"),
            ),
            (
                "check failed",
                vec![("CHECK_RESULT", "failure")],
                vec![147],
                not_posted,
            ),
            (
                "check skipped",
                vec![("CHECK_RESULT", "skipped"), ("VERDICT", "")],
                vec![147],
                set("failure", "The review did not post; see the workflow run"),
            ),
            (
                "apply failed",
                vec![("APPLY_RESULT", "failure")],
                vec![147],
                set("failure", "The review did not post; see the workflow run"),
            ),
            (
                "no comment posted",
                vec![("RESULT_URL", "")],
                vec![147],
                set("failure", "The review did not post; see the workflow run"),
            ),
            (
                "submitted as the review, apply skipped",
                vec![
                    ("APPLY_RESULT", "skipped"),
                    ("RESULT_URL", ""),
                    ("REVIEW_URL", "https://x/1"),
                ],
                vec![147],
                set("success", "The review approved this commit"),
            ),
            (
                "submitted, check failed",
                vec![("CHECK_RESULT", "failure"), ("REVIEW_URL", "https://x/1")],
                vec![147],
                set("failure", "The review did not post; see the workflow run"),
            ),
            ("no open pull request", vec![], vec![], skip("none")),
            (
                "two open pull requests",
                vec![],
                vec![147, 148],
                skip("147, 148"),
            ),
            ("another pull request", vec![], vec![148], skip("148")),
        ] {
            let env: HashMap<&str, &str> = approved.iter().copied().chain(changes).collect();
            let env = |key: &str| env.get(key).copied().unwrap_or_default().to_owned();
            let run = Run::read(&env).unwrap();
            assert_eq!(review_status(&env, &run, &open), expected, "{name}");
        }
        for (key, value) in [
            ("HEAD_SHA", "A".repeat(40)),
            ("HEAD_SHA", format!("{HEAD}\n")),
            ("HEAD_SHA", String::new()),
            ("PULL", "0".into()),
            ("PULL", "01".into()),
            ("PULL", "147;".into()),
            ("PULL", "9007199254740992".into()),
        ] {
            let env: HashMap<&str, &str> = approved
                .iter()
                .copied()
                .chain([(key, value.as_str())])
                .collect();
            let env = |key: &str| env.get(key).copied().unwrap_or_default().to_owned();
            let fake = Fake::default();
            let err = report_status(&env, &fake).unwrap_err().to_string();
            assert!(err.contains("exact head SHA"), "{key}={value:?}: {err}");
        }
    }

    #[test]
    fn the_review_status_is_posted_only_after_the_open_pull_requests_are_listed() {
        let env: HashMap<&str, &str> = [
            ("GITHUB_REPOSITORY", "o/r"),
            ("PULL", "147"),
            ("HEAD_SHA", HEAD),
            ("CHECK_RESULT", "success"),
            ("VERDICT", "APPROVE"),
            ("APPLY_RESULT", "success"),
            ("RESULT_URL", "https://x/1"),
            ("RUN_URL", "https://x/run"),
        ]
        .into();
        let env = |key: &str| env.get(key).copied().unwrap_or_default().to_owned();
        let pull = |number: u64, sha: &str| json!({"number": number, "head": {"sha": sha}});
        let fake = Fake {
            pulls: vec![pull(147, HEAD), pull(150, &"b".repeat(40))],
            ..Default::default()
        };
        report_status(&env, &fake).unwrap();
        assert_eq!(
            *fake.posted.borrow(),
            [(
                format!("repos/o/r/statuses/{HEAD}"),
                json!({"context": "review", "state": "success",
                "description": "The review approved this commit", "target_url": "https://x/run"})
            )]
        );
        let fake = Fake {
            pulls: vec![pull(147, HEAD), pull(148, HEAD)],
            ..Default::default()
        };
        report_status(&env, &fake).unwrap();
        assert!(fake.posted.borrow().is_empty());
    }

    #[test]
    fn lists_are_read_to_their_last_page_and_bounded() {
        struct Pages(usize);
        impl Api for Pages {
            fn get(&self, path: &str) -> Result<Value> {
                let page: usize = path.rsplit("page=").next().unwrap().parse().unwrap();
                let size = if page < self.0 { PER_PAGE } else { 1 };
                Ok(json!(vec![page; size]))
            }
            fn post(&self, _: &str, _: &Value) -> Result<Value> {
                unreachable!()
            }
        }
        assert_eq!(
            Pages(3).list("x?state=open").unwrap().len(),
            2 * PER_PAGE + 1
        );
        assert!(Pages(MAX_PAGES + 1).list("x").is_err());
    }
}
