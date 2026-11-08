//! `agentic-job status`: the one status comment of a run on its item,
//! written when the run starts (policy.yml's notify job) and edited when
//! it ends (apply.yml's conclude job), or a refused review's (review.yml).
//!
//! The comment is found by a marker at its end, and only among the
//! comments of the token's own user, so that a marker someone copied
//! cannot redirect the edit; a caller's comment named by id
//! (`STATUS_COMMENT`) is edited only where it is that user's, on this
//! item. The lookup is bounded and fails rather than post a duplicate,
//! and a slower older run does not overwrite a newer run's status.
//!
//! It reads the environment the workflow steps set: `REPO`, `ITEM`,
//! `TEXT`, `GITHUB_RUN_ID`, and optionally `STATUS_COMMENT`, `COST`,
//! `NO_RESULT_REASON` and `STATUS_TOKEN` (the caller's SAFE_OUTPUTS_PAT,
//! else `GH_TOKEN`, the job token). It prints the comment's `id=`.

use std::io::Write as _;

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

use super::github::{GH_TOKEN_ENV, Github, is_repo};
use crate::exit::Exit;

pub const MARKER: &str = "<!-- agentic-job-status -->";

/// The pages of 100 comments looked through for the marked one.
pub const MAX_PAGES: u32 = 20;

const PER_PAGE: usize = 100;

/// A page of 100 comments of up to 65,536 characters each.
const MAX_PAGE_BYTES: u64 = 32 << 20;

/// The author of what the job token posts.
const JOB_TOKEN_AUTHOR: &str = "github-actions[bot]";

const STATUS_TOKEN_ENV: &str = "STATUS_TOKEN";

/// Conservative UTF-8 byte budget below GitHub's 65,536-character limit.
/// Counts the complete rendered body, including caller markers, quoting,
/// escaping, cost and run markers. Bytes also bound UTF-16 units and scalars.
pub const MAX_BODY_BYTES: usize = 60_000;

fn check_body(body: &str) -> Result<()> {
    ensure!(
        body.len() <= MAX_BODY_BYTES,
        "status comment exceeds the {MAX_BODY_BYTES}-byte total body budget (including caller markers)"
    );
    Ok(())
}

#[derive(Debug, clap::Args)]
pub struct Args {}

/// The status comment's body: TEXT, the no-result REASON (the JSON string
/// apply exported, decoded only here, after crossing job outputs), and
/// the agent's COST where it is in the run action's grammar, then the
/// run's marker and the status marker.
pub fn body(text: &str, reason: Option<&str>, cost: Option<&str>, run: &str) -> Result<String> {
    let reason = match reason {
        Some(reason) => {
            let reason: String =
                serde_json::from_str(reason).context("NO_RESULT_REASON is not a JSON string")?;
            format!(" Its reason:\n\n{reason}")
        }
        None => String::new(),
    };
    let cost = cost
        .filter(|cost| is_cost(cost))
        .map(|cost| format!("\n\n<!-- agentic-job-cost: {run} {cost} -->"))
        .unwrap_or_default();
    let body = format!("{text}{reason}{cost}\n\n<!-- agentic-job-run: {run} -->\n\n{MARKER}");
    check_body(&body)?;
    Ok(body)
}

/// `usd=N partial=B`, N a decimal of at most 16 digits on either side of
/// its point: nothing that can end the HTML comment it goes in.
fn is_cost(cost: &str) -> bool {
    let digits =
        |text: &str| (1..=16).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit());
    let Some((usd, partial)) = cost
        .strip_prefix("usd=")
        .and_then(|rest| rest.split_once(" partial="))
    else {
        return false;
    };
    let usd = match usd.split_once('.') {
        Some((whole, fraction)) => digits(whole) && digits(fraction),
        None => digits(usd),
    };
    usd && matches!(partial, "true" | "false")
}

/// Whether BODY ends with the marker of a run later than RUN.
fn newer(body: &str, run: &str) -> bool {
    let Some(rest) = body.strip_suffix(&format!(" -->\n\n{MARKER}")) else {
        return false;
    };
    let Some((_, previous)) = rest.rsplit_once("\n\n<!-- agentic-job-run: ") else {
        return false;
    };
    is_number(previous) && (previous.len(), previous) > (run.len(), run)
}

fn is_number(text: &str) -> bool {
    text.starts_with(|c: char| ('1'..='9').contains(&c)) && text.bytes().all(|b| b.is_ascii_digit())
}

/// Whether LINE is a caller's own HTML comment, kept above the status: one
/// comment alone on the line, and not one of this tool's markers or a
/// maintain controller record. Keeping a run-supplied maintain marker would
/// give it bot-last-edited provenance (agent-board#411), even though the
/// status replacement discards its fenced heads.
fn is_caller_marker(line: &str) -> bool {
    let Some(inner) = line.strip_prefix("<!--") else {
        return false;
    };
    !inner.trim_start().starts_with("agentic-job-")
        && !inner.trim_start().starts_with("agent-board-maintain-plan")
        && !line.contains(['\r', '\u{2028}', '\u{2029}'])
        && inner.find("-->").is_some_and(|end| end + 3 == inner.len())
}

/// One run's status for one item.
pub struct Status {
    pub repo: String,
    pub item: String,
    pub run: String,
    pub body: String,
    /// The caller's comment for the item, by id.
    pub comment: Option<String>,
    /// `add` keeps a separate status per run, still edited at completion.
    pub add: bool,
    /// Fixed classification from checked outputs or check's refusal verdict.
    pub notice: bool,
}

impl Status {
    /// The status the environment (GET) describes.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let repo = get("REPO").unwrap_or_default();
        let item = get("ITEM").unwrap_or_default();
        ensure!(
            is_repo(&repo) && is_number(&item),
            "status requires a caller repository and numeric item"
        );
        let run = get("GITHUB_RUN_ID").unwrap_or_default();
        ensure!(is_number(&run), "status requires a numeric Actions run ID");
        let mode = get("STATUS_COMMENT_MODE").unwrap_or_else(|| "edit".into());
        ensure!(
            matches!(mode.as_str(), "edit" | "add"),
            "status-comment-mode must be edit or add"
        );
        let notice = get("ACTIONABLE_NOTICE").unwrap_or_default();
        ensure!(
            matches!(
                notice.as_str(),
                "" | "operator-question" | "decision" | "review"
            ),
            "invalid actionable notice classification"
        );
        let body = body(
            &get("TEXT").unwrap_or_default(),
            get("NO_RESULT_REASON").as_deref(),
            get("COST").as_deref(),
            &run,
        )?;
        Ok(Self {
            repo,
            item,
            run,
            body,
            comment: get("STATUS_COMMENT"),
            add: mode == "add",
            notice: !notice.is_empty(),
        })
    }

    /// Writes the status with GITHUB as AUTHOR, and returns the comment
    /// it is in. SUMMARY is told why a comment named by id was not used.
    pub fn upsert(
        &self,
        github: &Github,
        author: &str,
        summary: &mut dyn FnMut(&str),
    ) -> Result<Value> {
        let repo = &self.repo;
        check_body(&self.body)?;
        if let Some(comment) = self.named(github, author, summary) {
            return self.edit(github, &comment);
        }
        for page in 1..=MAX_PAGES {
            let comments = github.send(
                "GET",
                &format!(
                    "/repos/{repo}/issues/{}/comments?per_page={PER_PAGE}&page={page}",
                    self.item
                ),
                None,
            )?;
            let comments = comments.as_array().context("the comments are not a list")?;
            let found = comments.iter().find(|comment| {
                github.owns(super::roles::Role::Status, comment, Some(author))
                    && comment["body"].as_str().is_some_and(|body| {
                        body.ends_with(&format!("\n\n{MARKER}"))
                            && (!self.add
                                || body.contains(&format!(
                                    "\n\n<!-- agentic-job-run: {} -->",
                                    self.run
                                )))
                    })
            });
            if let Some(found) = found {
                return self.edit(github, found);
            }
            if comments.len() < PER_PAGE {
                return github.send(
                    "POST",
                    &format!("/repos/{repo}/issues/{}/comments", self.item),
                    Some(&json!({"body": self.body})),
                );
            }
        }
        bail!("status comment lookup exceeded {MAX_PAGES} pages; refusing to create a duplicate")
    }

    /// Always update status first. A notice cannot become a status target, and
    /// retries find only an owned exact run marker on this fixed item. The
    /// workflow serializes this lookup/write with the status upsert.
    pub fn publish(
        &self,
        github: &Github,
        author: &str,
        summary: &mut dyn FnMut(&str),
    ) -> Result<Value> {
        let status = self.upsert(github, author, summary)?;
        if !self.notice || newer(status["body"].as_str().unwrap_or_default(), &self.run) {
            return Ok(status);
        }
        let marker = format!("<!-- agentic-job-notice: {} -->", self.run);
        for page in 1..=MAX_PAGES {
            let comments = github.send(
                "GET",
                &format!(
                    "/repos/{}/issues/{}/comments?per_page={PER_PAGE}&page={page}",
                    self.repo, self.item
                ),
                None,
            )?;
            let comments = comments.as_array().context("the comments are not a list")?;
            if comments.iter().any(|comment| {
                github.owns(super::roles::Role::Status, comment, Some(author))
                    && comment["body"].as_str().is_some_and(|body| {
                        newer(body, &self.run) || body.ends_with(&format!("\n\n{marker}"))
                    })
            }) {
                return Ok(status);
            }
            if comments.len() < PER_PAGE {
                let body = format!(
                    "{}\n\n{marker}",
                    self.body
                        .strip_suffix(MARKER)
                        .context("status body has no marker")?
                        .trim_end()
                );
                check_body(&body)?;
                github.send(
                    "POST",
                    &format!("/repos/{}/issues/{}/comments", self.repo, self.item),
                    Some(&json!({"body": body})),
                )?;
                return Ok(status);
            }
        }
        bail!("actionable notice lookup exceeded {MAX_PAGES} pages; refusing to create a duplicate")
    }

    /// The caller's comment for the item (`STATUS_COMMENT`), when it is
    /// one the status may edit: AUTHOR's, on this repository's item.
    /// Otherwise None, and the status goes in the marked comment, so a
    /// dispatcher's id can neither edit someone else's words nor move the
    /// status to another item.
    fn named(&self, github: &Github, author: &str, summary: &mut dyn FnMut(&str)) -> Option<Value> {
        let id = self.comment.as_deref()?;
        if !is_number(id) {
            summary(
                "Status comment: STATUS_COMMENT is not a comment id; using the marked status comment.",
            );
            return None;
        }
        let repo = &self.repo;
        let Ok(comment) = github.send("GET", &format!("/repos/{repo}/issues/comments/{id}"), None)
        else {
            summary(&format!(
                "Status comment: comment {id} could not be read; using the marked status comment."
            ));
            return None;
        };
        let at = format!("/repos/{}/issues/{}", repo.to_lowercase(), self.item);
        let here = comment["issue_url"]
            .as_str()
            .is_some_and(|url| url.to_lowercase().ends_with(&at));
        if !github.owns(super::roles::Role::Status, &comment, Some(author)) || !here {
            summary(&format!(
                "Status comment: comment {id} is not {author}'s on {repo}#{}; using the marked \
                 status comment.",
                self.item
            ));
            return None;
        }
        Some(comment)
    }

    /// Edits COMMENT to hold the status, after the caller's opening
    /// markers: a named comment, once written, is also a marked one a
    /// later run without the id may find. A newer run's is left as it is.
    fn edit(&self, github: &Github, comment: &Value) -> Result<Value> {
        let old = comment["body"].as_str().unwrap_or_default();
        if newer(old, &self.run) {
            return Ok(comment.clone());
        }
        let kept: Vec<_> = old
            .split('\n')
            .map(|line| line.strip_suffix('\r').unwrap_or(line))
            .take_while(|line| is_caller_marker(line))
            .collect();
        let body = if kept.is_empty() {
            self.body.clone()
        } else {
            format!("{}\n\n{}", kept.join("\n"), self.body)
        };
        let id = comment["id"].as_u64().context("the comment has no id")?;
        check_body(&body)?;
        github.send(
            "PATCH",
            &format!("/repos/{}/issues/comments/{id}", self.repo),
            Some(&json!({"body": body})),
        )
    }
}

pub fn run(_args: &Args) -> Result<Exit> {
    let get = |key: &str| std::env::var(key).ok().filter(|value| !value.is_empty());
    let mut summary = |message: &str| {
        let written = get("GITHUB_STEP_SUMMARY").map(|path| {
            std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .and_then(|mut file| writeln!(file, "{message}"))
        });
        if !matches!(written, Some(Ok(()))) {
            eprintln!("{message}");
        }
    };
    let status = Status::from_env(get)?;
    let configured = get(super::roles::BINDINGS_ENV).is_some();
    let personal = configured || get(STATUS_TOKEN_ENV).is_some();
    let caller = get("GITHUB_REPOSITORY").unwrap_or_else(|| status.repo.clone());
    if !personal && !status.repo.eq_ignore_ascii_case(&caller) {
        summary(
            "Status comment skipped: cross-repository target requires the caller-supplied \
             SAFE_OUTPUTS_PAT.",
        );
        return Ok(Exit::Success);
    }
    let token = if personal {
        STATUS_TOKEN_ENV
    } else {
        GH_TOKEN_ENV
    };
    let github = super::github::from_role_env(super::roles::Role::Status, token)?
        .with_max_response(MAX_PAGE_BYTES);
    // The credential's identity plus the marker keeps copied markers from
    // redirecting edits.
    let author = if configured {
        "configured status identity".to_owned()
    } else if personal {
        github
            .login()
            .context("the status token has no authenticated user identity")?
    } else {
        JOB_TOKEN_AUTHOR.to_owned()
    };
    let comment = status.publish(&github, &author, &mut summary)?;
    if let Some(id) = comment["id"].as_u64() {
        println!("id={id}");
    }
    Ok(Exit::Success)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use safe_outputs::apply::testing::forge;

    const LIST: &str = "GET /repos/o/r/issues/7/comments?per_page=100&page=";
    const NAMED: &str = "GET /repos/o/r/issues/comments/5";
    const POST: &str = "POST /repos/o/r/issues/7/comments";
    const TAG: &str = "<!-- tag: {\"round\":2} -->";

    fn status(run: &str, comment: &str) -> Status {
        let env = BTreeMap::from([
            ("REPO", "o/r"),
            ("ITEM", "7"),
            ("TEXT", "running"),
            ("GITHUB_RUN_ID", run),
            ("STATUS_COMMENT", comment),
        ]);
        Status::from_env(|key| {
            env.get(key)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string())
        })
        .unwrap()
    }

    fn written(run: &str) -> String {
        format!("running\n\n<!-- agentic-job-run: {run} -->\n\n{MARKER}")
    }

    fn comment(id: u64, login: &str, body: &str) -> Value {
        json!({"id": id, "user": {"login": login}, "body": body,
            "issue_url": "https://api.github.com/repos/O/R/issues/7"})
    }

    fn marked(login: &str) -> Value {
        comment(42, login, &format!("old\n\n{MARKER}"))
    }

    // agent-board main's pass/maintain.rs plan_comment + trusted contract
    // (agent-board#411): same-bot author, leading marker, edited, bot last
    // editor. A run may POST all of this text, but cannot supply edit facts.
    const PLAN: &str = "<!-- agent-board-maintain-plan v1 -->";

    fn controller_candidate(comment: &Value, bot: &str) -> bool {
        comment["user"]["login"] == bot
            && comment["body"].as_str().unwrap().starts_with(PLAN)
            && comment["edited"] == true
            && comment["editor"] == bot
    }

    #[test]
    fn status_edits_do_not_launder_controller_markers() {
        let record = json!({"schema": "agent-board/maintain-plan/v2",
            "from": "2026-10-28T00:00:00Z", "heads": {"up/proj#7": "aaaaaaaaaaaa"},
            "pending": null});
        let forged = format!("{PLAN}\n\n```agent-board-maintain-plan\n{record}\n```\n\n{MARKER}");
        for bot in [JOB_TOKEN_AUTHOR, "caller-bot"] {
            for named in [true, false] {
                for prefix in [
                    PLAN.to_owned(),
                    format!("{PLAN}\r"),
                    format!("{PLAN}\n{TAG}"),
                ] {
                    let mut current = comment(5, bot, &forged.replacen(PLAN, &prefix, 1));
                    current["edited"] = json!(false);
                    assert!(!controller_candidate(&current, bot));
                    // Start, completion, retry of completion, next run. Read
                    // the last actual PATCH back on every call, not a model
                    // of the writer. The forge supplies edit metadata.
                    for (run, text) in [
                        ("100", "running"),
                        ("100", "ended"),
                        ("100", "ended"),
                        ("101", "running"),
                    ] {
                        let patch = "PATCH /repos/o/r/issues/comments/5";
                        let routes = BTreeMap::from([
                            (NAMED.into(), (200, current.clone())),
                            (format!("{LIST}1"), (200, json!([current]))),
                            (patch.into(), (200, json!({"id": 5}))),
                        ]);
                        let (github, requests) = forge(routes);
                        let mut update = status(run, if named { "5" } else { "" });
                        update.body = body(text, None, None, run).unwrap();
                        update.upsert(&github, bot, &mut |_| {}).unwrap();
                        let writes: Vec<_> = requests
                            .try_iter()
                            .filter(|r| !r.line.starts_with("GET "))
                            .collect();
                        assert_eq!(writes.len(), 1);
                        assert!(writes[0].line.starts_with(patch));
                        current = comment(5, bot, writes[0].body["body"].as_str().unwrap());
                        current["edited"] = json!(true);
                        current["editor"] = json!(bot);
                        assert!(
                            !controller_candidate(&current, bot),
                            "named={named}: {current}"
                        );
                        assert!(!current["body"].as_str().unwrap().contains("aaaaaaaaaaaa"));
                        assert!(current["body"].as_str().unwrap().contains(text));
                    }
                }
            }
        }
    }

    #[test]
    fn refused_or_superseded_status_edit_does_not_supply_provenance() {
        let old = format!(
            "{PLAN}\n\n```agent-board-maintain-plan\n{{\"heads\":{{\"up/proj#7\":\"aaaaaaaaaaaa\"}}}}\n```\n\n{}",
            written("101")
        );
        for (what, bot, response, newer) in [
            ("a newer run is untouched", JOB_TOKEN_AUTHOR, 200, true),
            ("a failed edit is untouched", JOB_TOKEN_AUTHOR, 403, false),
            (
                "another author's marker is not edited",
                "mallory",
                200,
                false,
            ),
        ] {
            let mut original = comment(5, bot, &old);
            original["edited"] = json!(false);
            let (github, requests) = forge(BTreeMap::from([
                (NAMED.into(), (200, original.clone())),
                (format!("{LIST}1"), (200, json!([original.clone()]))),
                (
                    "PATCH /repos/o/r/issues/comments/5".into(),
                    (response, json!({"id": 5})),
                ),
                (POST.into(), (201, json!({"id": 6}))),
            ]));
            let result = status(if newer { "100" } else { "102" }, "5").upsert(
                &github,
                JOB_TOKEN_AUTHOR,
                &mut |_| {},
            );
            assert_eq!(result.is_ok(), response == 200, "{what}");
            let writes: Vec<_> = requests
                .try_iter()
                .filter(|r| !r.line.starts_with("GET "))
                .collect();
            assert_eq!(writes.len(), usize::from(!newer), "{what}");
            if bot == "mallory" {
                assert!(writes[0].line.starts_with(POST));
                assert!(!writes[0].body["body"].as_str().unwrap().starts_with(PLAN));
            }
            // Neither a skipped nor an HTTP-refused PATCH changes the forge's
            // original author/editor facts. A fresh retry must re-read it.
            assert!(!controller_candidate(&original, JOB_TOKEN_AUTHOR), "{what}");
        }
    }

    #[test]
    fn writes() {
        let status_100 = written("100");
        type Routes = BTreeMap<String, (u16, Value)>;
        let page = |routes: &mut Routes, n: u32, comments: Value| {
            routes.insert(format!("{LIST}{n}"), (200, comments));
        };
        let named = |routes: &mut Routes, body: &str| {
            routes.insert(NAMED.into(), (200, comment(5, JOB_TOKEN_AUTHOR, body)));
        };
        let full = json!(vec![marked("mallory"); PER_PAGE]);
        // (what, STATUS_COMMENT, the forge, what is written where, how
        // often the summary is told why a named comment was not used)
        type Case<'a> = (
            &'a str,
            &'a str,
            Box<dyn Fn(&mut Routes) + 'a>,
            Option<(&'a str, String)>,
            usize,
        );
        let cases: Vec<Case> = vec![
            (
                "a new item",
                "",
                Box::new(|r| page(r, 1, json!([]))),
                Some((POST, status_100.clone())),
                0,
            ),
            (
                "a later run",
                "",
                Box::new(|r| page(r, 1, json!([marked(JOB_TOKEN_AUTHOR)]))),
                Some(("PATCH /repos/o/r/issues/comments/42", status_100.clone())),
                0,
            ),
            // A marker someone else copied does not redirect the edit.
            (
                "a copied marker",
                "",
                Box::new(|r| page(r, 1, json!([marked("mallory")]))),
                Some((POST, status_100.clone())),
                0,
            ),
            (
                "a quoted marker",
                "",
                Box::new(|r| {
                    page(
                        r,
                        1,
                        json!([comment(42, JOB_TOKEN_AUTHOR, &format!("{MARKER}\nquoted"))]),
                    )
                }),
                Some((POST, status_100.clone())),
                0,
            ),
            (
                "a later page",
                "",
                Box::new(move |r| {
                    page(r, 1, full.clone());
                    page(r, 2, json!([marked(JOB_TOKEN_AUTHOR)]));
                }),
                Some(("PATCH /repos/o/r/issues/comments/42", status_100.clone())),
                0,
            ),
            // A slower older run does not replace a newer run's status.
            (
                "a newer run's",
                "",
                Box::new(|r| {
                    page(
                        r,
                        1,
                        json!([comment(
                            42,
                            JOB_TOKEN_AUTHOR,
                            &format!("done\n\n<!-- agentic-job-run: 101 -->\n\n{MARKER}")
                        )]),
                    )
                }),
                None,
                0,
            ),
            (
                "a named comment",
                "5",
                Box::new(|r| named(r, "fix round 2")),
                Some(("PATCH /repos/o/r/issues/comments/5", status_100.clone())),
                0,
            ),
            (
                "a named comment's markers",
                "5",
                Box::new(|r| named(r, &format!("{TAG}\nfix round 2"))),
                Some((
                    "PATCH /repos/o/r/issues/comments/5",
                    format!("{TAG}\n\n{status_100}"),
                )),
                0,
            ),
            (
                "a named comment's markers across updates",
                "5",
                Box::new(|r| {
                    named(
                        r,
                        &format!(
                            "{TAG}\r\n<!-- more: 1 -->\n\nfailed\n\n<!-- agentic-job-run: 99 -->\n\n{MARKER}"
                        ),
                    )
                }),
                Some((
                    "PATCH /repos/o/r/issues/comments/5",
                    format!("{TAG}\n<!-- more: 1 -->\n\n{status_100}"),
                )),
                0,
            ),
            (
                "a named comment of markers only",
                "5",
                Box::new(|r| named(r, TAG)),
                Some((
                    "PATCH /repos/o/r/issues/comments/5",
                    format!("{TAG}\n\n{status_100}"),
                )),
                0,
            ),
            (
                "visible text beside a marker",
                "5",
                Box::new(|r| named(r, &format!("<!-- a --> shown <!-- b -->\n{TAG}"))),
                Some(("PATCH /repos/o/r/issues/comments/5", status_100.clone())),
                0,
            ),
            (
                "a named comment of a newer run",
                "5",
                Box::new(|r| {
                    named(
                        r,
                        &format!("{TAG}\n\nrunning\n\n<!-- agentic-job-run: 101 -->\n\n{MARKER}"),
                    )
                }),
                None,
                0,
            ),
            // A dispatcher's id can neither edit someone else's words nor
            // move the status to another item.
            (
                "a named comment of another author",
                "5",
                Box::new(|r| {
                    r.insert(NAMED.into(), (200, comment(5, "mallory", "fix")));
                    page(r, 1, json!([]));
                }),
                Some((POST, status_100.clone())),
                1,
            ),
            (
                "a named comment on another item",
                "5",
                Box::new(|r| {
                    let mut other = comment(5, JOB_TOKEN_AUTHOR, "fix");
                    other["issue_url"] = json!("https://api.github.com/repos/o/r/issues/8");
                    r.insert(NAMED.into(), (200, other));
                    page(r, 1, json!([]));
                }),
                Some((POST, status_100.clone())),
                1,
            ),
            (
                "a named comment in another repository",
                "5",
                Box::new(|r| {
                    let mut other = comment(5, JOB_TOKEN_AUTHOR, "fix");
                    other["issue_url"] = json!("https://api.github.com/repos/o/other/issues/7");
                    r.insert(NAMED.into(), (200, other));
                    page(r, 1, json!([]));
                }),
                Some((POST, status_100.clone())),
                1,
            ),
            (
                "a named comment that is missing",
                "5",
                Box::new(|r| page(r, 1, json!([]))),
                Some((POST, status_100.clone())),
                1,
            ),
            (
                "an id that is not one",
                "5/../../8",
                Box::new(|r| page(r, 1, json!([]))),
                Some((POST, status_100.clone())),
                1,
            ),
            // The marked comment keeps the caller's markers too.
            (
                "an id that cannot be read, beside a marked comment",
                "6",
                Box::new(|r| {
                    page(
                        r,
                        1,
                        json!([comment(
                            5,
                            JOB_TOKEN_AUTHOR,
                            &format!("{TAG}\n\nfailed\n\n<!-- agentic-job-run: 99 -->\n\n{MARKER}")
                        )]),
                    )
                }),
                Some((
                    "PATCH /repos/o/r/issues/comments/5",
                    format!("{TAG}\n\n{status_100}"),
                )),
                1,
            ),
        ];
        for (what, id, routes, want, told) in cases {
            let mut answers = Routes::new();
            routes(&mut answers);
            answers.insert(POST.into(), (201, json!({"id": 1})));
            for id in [5, 42] {
                answers.insert(
                    format!("PATCH /repos/o/r/issues/comments/{id}"),
                    (200, json!({"id": id})),
                );
            }
            let (github, requests) = forge(answers);
            let mut summary = Vec::new();
            status("100", id)
                .upsert(&github, JOB_TOKEN_AUTHOR, &mut |message| {
                    summary.push(message.to_owned())
                })
                .unwrap_or_else(|err| panic!("{what}: {err:#}"));
            let writes: Vec<_> = requests
                .try_iter()
                .filter(|request| !request.line.starts_with("GET "))
                .map(|request| {
                    (
                        request.line.trim_end_matches(" HTTP/1.1").to_owned(),
                        request.body,
                    )
                })
                .collect();
            let want: Vec<_> = want
                .into_iter()
                .map(|(line, body)| (line.to_owned(), json!({"body": body})))
                .collect();
            assert_eq!(writes, want, "{what}");
            assert_eq!(summary.len(), told, "{what}: {summary:?}");
        }
    }

    /// A lookup that finds no end posts nothing, rather than a duplicate.
    #[test]
    fn the_lookup_is_bounded() {
        let mut routes = BTreeMap::new();
        for page in 1..=MAX_PAGES + 1 {
            routes.insert(
                format!("{LIST}{page}"),
                (200, json!(vec![marked("mallory"); PER_PAGE])),
            );
        }
        let (github, requests) = forge(routes);
        let err = status("100", "")
            .upsert(&github, JOB_TOKEN_AUTHOR, &mut |_| {})
            .unwrap_err();
        assert!(format!("{err:#}").contains("exceeded 20 pages"), "{err:#}");
        assert_eq!(requests.try_iter().count(), MAX_PAGES as usize);
    }

    #[test]
    fn full_runs_and_conclude_retries_keep_status_and_notices_separate() {
        for (add, actionable) in [(false, false), (false, true), (true, false), (true, true)] {
            let mut comments: Vec<Value> = Vec::new();
            for run in ["100", "101"] {
                for phase in ["started", "finished", "finished"] {
                    let mut routes = BTreeMap::from([
                        (format!("{LIST}1"), (200, json!(comments))),
                        (POST.into(), (201, json!({"id": comments.len() + 1}))),
                    ]);
                    for comment in &comments {
                        let id = comment["id"].as_u64().unwrap();
                        routes.insert(
                            format!("PATCH /repos/o/r/issues/comments/{id}"),
                            (200, json!({"id": id})),
                        );
                    }
                    let (github, requests) = forge(routes);
                    let mut update = status(run, "");
                    update.add = add;
                    update.notice = actionable && phase == "finished";
                    update.body = body(phase, None, None, run).unwrap();
                    update
                        .publish(&github, JOB_TOKEN_AUTHOR, &mut |_| {})
                        .unwrap();
                    for request in requests.try_iter().filter(|r| !r.line.starts_with("GET ")) {
                        let text = request.body["body"].as_str().unwrap();
                        if request.line.starts_with("POST ") {
                            comments.push(comment(
                                comments.len() as u64 + 1,
                                JOB_TOKEN_AUTHOR,
                                text,
                            ));
                        } else {
                            let id: u64 = request
                                .line
                                .split("/comments/")
                                .nth(1)
                                .unwrap()
                                .split(' ')
                                .next()
                                .unwrap()
                                .parse()
                                .unwrap();
                            comments.iter_mut().find(|c| c["id"] == id).unwrap()["body"] =
                                json!(text);
                        }
                    }
                }
            }
            let statuses: Vec<_> = comments
                .iter()
                .filter(|c| c["body"].as_str().unwrap().ends_with(MARKER))
                .collect();
            assert_eq!(statuses.len(), if add { 2 } else { 1 });
            assert!(
                statuses
                    .iter()
                    .all(|c| c["body"].as_str().unwrap().starts_with("finished"))
            );
            assert_eq!(
                comments.len() - statuses.len(),
                if actionable { 2 } else { 0 }
            );
        }
    }

    #[test]
    fn notices_require_owned_markers_and_bounded_lookup_and_skip_stale_runs() {
        let notice = "done\n\n<!-- agentic-job-notice: 100 -->";
        for (login, stale, full, posts, ok) in [
            (JOB_TOKEN_AUTHOR, false, false, 0, true),
            ("mallory", false, false, 1, true),
            ("mallory", true, false, 0, true),
            ("mallory", false, true, 0, false),
        ] {
            let current = comment(
                5,
                JOB_TOKEN_AUTHOR,
                &written(if stale { "101" } else { "100" }),
            );
            let mut routes = BTreeMap::from([
                (NAMED.into(), (200, current)),
                (
                    "PATCH /repos/o/r/issues/comments/5".into(),
                    (200, json!({"id": 5})),
                ),
                (POST.into(), (201, json!({"id": 6}))),
            ]);
            for page in 1..=MAX_PAGES {
                routes.insert(
                    format!("{LIST}{page}"),
                    (
                        200,
                        if full {
                            json!(vec![comment(6, login, notice); PER_PAGE])
                        } else {
                            json!([comment(6, login, notice)])
                        },
                    ),
                );
            }
            let (github, requests) = forge(routes);
            let mut update = status("100", "5");
            update.notice = true;
            assert_eq!(
                update
                    .publish(&github, JOB_TOKEN_AUTHOR, &mut |_| {})
                    .is_ok(),
                ok
            );
            let requests: Vec<_> = requests.try_iter().collect();
            assert_eq!(
                requests
                    .iter()
                    .filter(|r| r.line.starts_with("POST "))
                    .count(),
                posts
            );
            assert!(requests.len() <= MAX_PAGES as usize + 2);
        }
    }

    #[test]
    fn add_mode_keeps_run_status_but_does_not_page_after_a_newer_run() {
        let old = comment(5, JOB_TOKEN_AUTHOR, &written("100"));
        let newer = comment(6, JOB_TOKEN_AUTHOR, &written("101"));
        let (github, requests) = forge(BTreeMap::from([
            (format!("{LIST}1"), (200, json!([old, newer]))),
            (
                "PATCH /repos/o/r/issues/comments/5".into(),
                (200, json!({"id": 5})),
            ),
        ]));
        let mut update = status("100", "");
        update.add = true;
        update.notice = true;
        update
            .publish(&github, JOB_TOKEN_AUTHOR, &mut |_| {})
            .unwrap();
        let writes: Vec<_> = requests
            .try_iter()
            .filter(|r| !r.line.starts_with("GET "))
            .collect();
        assert_eq!(writes.len(), 1);
        assert!(
            writes[0]
                .line
                .starts_with("PATCH /repos/o/r/issues/comments/5")
        );
    }

    #[test]
    fn total_body_budget_includes_preserved_markers() {
        let overhead = body("", None, Some("usd=1 partial=false"), "100")
            .unwrap()
            .len();
        for (extra, ok) in [(0, true), (1, false)] {
            let text = "x".repeat(MAX_BODY_BYTES - overhead + extra);
            assert_eq!(
                body(&text, None, Some("usd=1 partial=false"), "100").is_ok(),
                ok
            );
        }
        let mut update = status("100", "5");
        update.body = body(&"😀".repeat(14_000), None, None, "100").unwrap();
        let old = format!("<!-- {} -->\n\nold", "x".repeat(5000));
        let (github, requests) = forge(BTreeMap::from([(
            NAMED.into(),
            (200, comment(5, JOB_TOKEN_AUTHOR, &old)),
        )]));
        assert!(
            update
                .upsert(&github, JOB_TOKEN_AUTHOR, &mut |_| {})
                .unwrap_err()
                .to_string()
                .contains("including caller markers")
        );
        assert!(requests.try_iter().all(|r| r.line.starts_with("GET ")));
    }

    #[test]
    fn the_request() {
        for (key, value, want) in [
            ("ITEM", "", "numeric item"),
            ("ITEM", "*", "numeric item"),
            ("ITEM", "0", "numeric item"),
            ("ITEM", "$(exit 9)", "numeric item"),
            ("REPO", "o/r/x", "caller repository"),
            ("GITHUB_RUN_ID", "1e3", "numeric Actions run ID"),
            ("NO_RESULT_REASON", "> not JSON", "not a JSON string"),
            ("STATUS_COMMENT_MODE", "EDIT", "must be edit or add"),
            ("STATUS_COMMENT_MODE", "5", "must be edit or add"),
            ("ACTIONABLE_NOTICE", "true", "invalid actionable"),
            ("ACTIONABLE_NOTICE", "review\nid=5", "invalid actionable"),
        ] {
            let env = BTreeMap::from([
                ("REPO", "o/r"),
                ("ITEM", "7"),
                ("GITHUB_RUN_ID", "100"),
                (key, value),
            ]);
            let err = Status::from_env(|key| env.get(key).map(|value| value.to_string()))
                .err()
                .unwrap_or_else(|| panic!("{key}={value}"));
            assert!(format!("{err:#}").contains(want), "{key}={value}: {err:#}");
        }
        assert_eq!(
            body(
                "ended",
                Some(r#""> a\n> b""#),
                Some("usd=1.5 partial=false"),
                "100"
            )
            .unwrap(),
            format!(
                "ended Its reason:\n\n> a\n> b\n\n<!-- agentic-job-cost: 100 usd=1.5 partial=false -->\
                 \n\n<!-- agentic-job-run: 100 -->\n\n{MARKER}"
            )
        );
    }
}
