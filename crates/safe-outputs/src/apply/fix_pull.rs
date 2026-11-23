//! Publish a checked fix PR text replacement without a wildcard handler.

use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};

use super::github::{Github, same};
use crate::check::fix_pull;
use crate::contract::{FixPullRequest, Policy};

#[derive(Debug, Clone)]
pub(super) struct Request {
    repo: String,
    number: u64,
    branch: String,
    head: String,
    scope: FixPullRequest,
    title: String,
    body: String,
}

impl Request {
    pub(super) fn new(item: &Map<String, Value>, policy: &Policy) -> Result<Self> {
        let (title, body) = fix_pull::request(item, policy)?;
        let push =
            fix_pull::scope(policy, fix_pull::UPDATE).context("missing checked fix PR target")?;
        Ok(Self {
            repo: policy.repo.clone(),
            number: push
                .target
                .parse()
                .context("invalid checked fix PR number")?,
            branch: policy.base.clone(),
            head: push.head.clone(),
            scope: push
                .fix_pull_request
                .clone()
                .context("missing checked fix PR scope")?,
            title: title.to_owned(),
            body: body.to_owned(),
        })
    }
}

pub(super) fn publish(github: &Github, request: &Request, server: &str) -> Result<Value> {
    let Request {
        repo,
        number,
        branch,
        head,
        scope,
        title,
        body,
    } = request;
    ensure!(
        same(&github.get("/user")?["login"], &scope.author),
        "the applying identity is not the configured fix PR author"
    );
    let path = format!("/repos/{repo}/pulls/{number}");
    let current = github.get(&path)?;
    ensure!(
        current["number"].as_u64() == Some(*number)
            && current["state"] == "open"
            && same(&current["base"]["repo"]["full_name"], repo)
            && same(&current["user"]["login"], &scope.author)
            && current["head"]["sha"] == *head
            && current["head"]["ref"] == *branch
            && super::push::pull_snapshot_digest(&current) == scope.snapshot_digest,
        "the checked fix PR is no longer open at the pinned head, author, destination and text"
    );

    let original = current["body"].as_str().unwrap_or_default();
    // New directives are forbidden. Refuse instead of silently removing an
    // existing merge side effect, even when the new prose omits the directive.
    ensure!(
        !fix_pull::has_closing_directive(original),
        "the original PR body contains a closing directive; update it manually to preserve the linkage"
    );
    let mut body = super::mentions::filter(body, "github");
    for line in original.lines().filter(|line| {
        fix_pull::MARKERS.iter().any(|marker| {
            line.strip_prefix("<!-- ")
                .and_then(|text| text.strip_prefix(marker))
                .is_some_and(|text| {
                    text.starts_with(": ")
                        && text.ends_with(" -->")
                        && !text[..text.len() - 4].contains("-->")
                })
        })
    }) {
        body.push_str("\n\n");
        body.push_str(line);
    }
    ensure!(
        body.encode_utf16().count() <= 65_536,
        "replacement plus retained metadata exceeds GitHub's body limit"
    );
    let title = super::mentions::filter(title, "github");
    // GitHub has no atomic expected-head or text precondition for this PATCH.
    github.send("PATCH", &path, Some(&json!({"title": title, "body": body})))?;
    Ok(
        json!({"url": format!("{server}/{repo}/pull/{number}"), "number": number,
        "repo": repo, "contextType": "pull_request", "metadata": {"scoped_fix_pr": true}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::testing::{Request as ApiRequest, TOKEN, serve};

    #[test]
    fn fix_pr_update_refuses_drift_and_existing_closing_linkage_before_writing() {
        let mut policy = crate::check::fixtures::push_policy();
        let push = policy
            .safe_outputs
            .push_to_pull_request_branch
            .as_mut()
            .unwrap();
        let author = "example-bot";
        let marker = "<!-- agentic-job-applied: 12/0/c9e78349c4eb1d84 -->";
        let current = json!({"state":"open", "number":42, "user":{"login":author},
            "head":{"sha":push.head, "ref":policy.base},
            "base":{"ref":"main", "repo":{"full_name":policy.repo}},
            "title":"Previous title", "body":format!("Previous description\n\n{marker}")});
        push.fix_pull_request = Some(FixPullRequest {
            author: author.into(),
            snapshot_digest: super::super::push::pull_snapshot_digest(&current),
        });
        let item = json!({"type":fix_pull::UPDATE,"repo":policy.repo,"pull_request_number":42,
            "title":"Narrowed the scope","body":"New description"});
        for change in [
            "none",
            "closed",
            "head",
            "branch",
            "author",
            "text",
            "base repo",
            "base branch",
            "number",
            "actor",
            "linked",
        ] {
            let mut live = current.clone();
            let mut request = Request::new(item.as_object().unwrap(), &policy).unwrap();
            let mut actor = author;
            match change {
                "closed" => live["state"] = json!("closed"),
                "head" => live["head"]["sha"] = json!("b".repeat(40)),
                "branch" => live["head"]["ref"] = json!("other-fix"),
                "author" => live["user"]["login"] = json!("other"),
                "text" => live["body"] = json!("Other description"),
                "base repo" => live["base"]["repo"]["full_name"] = json!("example/other"),
                "base branch" => live["base"]["ref"] = json!("release"),
                "number" => live["number"] = json!(43),
                "actor" => actor = "other",
                "linked" => {
                    live["body"] = json!(format!("Previous description\n\nCloses #31\n\n{marker}"));
                    request.scope.snapshot_digest = super::super::push::pull_snapshot_digest(&live);
                }
                _ => {}
            }
            let pull = format!("/repos/{}/pulls/42", policy.repo);
            let (server, calls) = serve(usize::MAX, move |req: &ApiRequest| {
                match req.line.as_str() {
                    "GET /user HTTP/1.1" => (200, json!({"login":actor}).to_string()),
                    line if line == format!("GET {pull} HTTP/1.1") => (200, live.to_string()),
                    line if line == format!("PATCH {pull} HTTP/1.1") => (200, "{}".into()),
                    line => panic!("unexpected request: {line}"),
                }
            });
            let github =
                Github::new(&server, TOKEN.into(), crate::apply::testing::PROVENANCE).unwrap();
            let result = publish(&github, &request, "https://github.com");
            let calls: Vec<_> = calls.try_iter().collect();
            if change == "none" {
                assert_eq!(
                    result.unwrap()["url"],
                    format!("https://github.com/{}/pull/42", policy.repo)
                );
                assert_eq!(calls.len(), 3);
                assert_eq!(
                    calls[2].body,
                    json!({"title":"Narrowed the scope",
                    "body":format!("New description\n\n{marker}")})
                );
            } else {
                let error = result.expect_err(change);
                if change == "linked" {
                    assert!(error.to_string().contains("preserve the linkage"));
                }
                assert!(calls.iter().all(|req| req.line.starts_with("GET ")));
            }
        }
    }
}
