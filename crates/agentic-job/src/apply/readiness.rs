//! Draft state after a verified push. A run dispatched before an operator
//! adds `hold` must not make that pull request eligible for merging.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

use super::github::{GH_TOKEN_ENV, is_repo};
use crate::exit::Exit;
use crate::files;

const MAX_JSON: u64 = 4 << 20;
const PUSH: &str = "push_to_pull_request_branch";

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Trusted apply directory holding config.json, agent_output.json and applied.json
    #[arg(long)]
    pub dir: PathBuf,
    /// The output repository
    #[arg(long)]
    pub repo: String,
    /// Whether the run completed, as apply's completion step decided
    #[arg(long, action = clap::ArgAction::Set)]
    pub ready: bool,
}

fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_slice(&files::read_regular(path, MAX_JSON)?)
        .with_context(|| format!("parsing {}", path.display()))
}

pub fn run(args: &Args) -> Result<Exit> {
    finish(args, |repo, target, ready| {
        let github = super::github::from_env(GH_TOKEN_ENV)?;
        transition(repo, target, ready, |method, path, body| {
            if path == "/graphql" {
                let body = body.context("missing draft mutation")?;
                github.graphql(
                    body["query"].as_str().context("missing draft query")?,
                    body["variables"].clone(),
                )
            } else {
                github.request(method, path, body)
            }
        })
    })?;
    Ok(Exit::Success)
}

fn finish(args: &Args, transition: impl FnOnce(&str, u64, bool) -> Result<Value>) -> Result<()> {
    let config = read_json(&args.dir.join("config.json"))?;
    if config[PUSH]["ready_when_complete"] != true {
        return Ok(());
    }
    let outputs = read_json(&args.dir.join("agent_output.json"))?;
    let applied_path = args.dir.join("applied.json");
    let mut applied = read_json(&applied_path)?;
    let pushed = |items: &Value| {
        items
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["type"] == PUSH))
    };
    if !["made", "already_applied"]
        .iter()
        .any(|key| pushed(&applied[*key]))
        && !pushed(&outputs["items"])
    {
        return Ok(());
    }
    let target = config[PUSH]["target"]
        .as_str()
        .and_then(|target| target.parse::<u64>().ok())
        .filter(|target| *target > 0)
        .context("the push names no pull request")?;
    ensure!(is_repo(&args.repo), "invalid output repository");
    let readiness = transition(&args.repo, target, args.ready)?;
    if let Some(reason) = readiness["reason"].as_str() {
        println!("{reason}; the push remains applied");
    }
    applied["readiness"] = readiness;
    std::fs::write(&applied_path, serde_json::to_vec_pretty(&applied)?)?;
    Ok(())
}

#[derive(Deserialize)]
struct Pull {
    node_id: String,
    draft: bool,
    labels: Vec<Label>,
}

#[derive(Deserialize)]
struct Label {
    name: String,
}

fn transition(
    repo: &str,
    target: u64,
    ready: bool,
    mut send: impl FnMut(&str, &str, Option<&Value>) -> Result<Value>,
) -> Result<Value> {
    // This fresh read includes all labels, not a paginated labels list or
    // the policy job's snapshot. Nothing else is written before mark-ready.
    let pull = send("GET", &format!("/repos/{repo}/pulls/{target}"), None)
        .and_then(|value| Ok(serde_json::from_value::<Pull>(value)?));
    let pull = match pull {
        Ok(pull) => pull,
        Err(_) if ready => {
            return Ok(json!({"reason": "Left draft: pull request labels could not be read"}));
        }
        Err(error) => return Err(error).context("reading pull request draft state"),
    };
    if ready
        && pull
            .labels
            .iter()
            .any(|label| label.name.eq_ignore_ascii_case("hold"))
    {
        return Ok(json!({"reason": "Left draft: pull request has a hold label"}));
    }
    let draft = !ready;
    if pull.draft != draft {
        let mutation = if ready {
            "markPullRequestReadyForReview"
        } else {
            "convertPullRequestToDraft"
        };
        send(
            "POST",
            "/graphql",
            Some(&json!({
                "query": format!("mutation($id: ID!) {{ {mutation}(input: {{pullRequestId: $id}}) {{ pullRequest {{ isDraft }} }} }}"),
                "variables": {"id": pull.node_id},
            })),
        )?;
    }
    Ok(json!({"draft": draft}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_readiness() {
        for (labels, ready, draft, mutation, reason) in [
            (
                Some(json!([])),
                true,
                true,
                Some("markPullRequestReadyForReview"),
                None,
            ),
            (
                Some(json!([{"name": "hold"}])),
                true,
                true,
                None,
                Some("hold label"),
            ),
            (
                Some(json!([{"name": "HOLD"}])),
                true,
                true,
                None,
                Some("hold label"),
            ),
            (None, true, true, None, Some("could not be read")),
            (
                Some(Value::Null),
                true,
                true,
                None,
                Some("could not be read"),
            ),
            (
                Some(json!([{"name": "review"}])),
                true,
                true,
                Some("markPullRequestReadyForReview"),
                None,
            ),
            (Some(json!([])), true, false, None, None),
            (
                Some(json!([])),
                false,
                false,
                Some("convertPullRequestToDraft"),
                None,
            ),
            (Some(json!([])), false, true, None, None),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let args = Args {
                dir: dir.path().to_owned(),
                repo: "owner/repo".into(),
                ready,
            };
            let applied = json!({"made": [{"type": PUSH}], "already_applied": []});
            for (name, value) in [
                (
                    "config.json",
                    json!({PUSH: {"ready_when_complete": true, "target": "42"}}),
                ),
                ("agent_output.json", json!({"items": [{"type": PUSH}]})),
                ("applied.json", applied.clone()),
            ] {
                std::fs::write(dir.path().join(name), serde_json::to_vec(&value).unwrap()).unwrap();
            }
            let mut calls = Vec::new();
            finish(&args, |repo, target, ready| {
                transition(repo, target, ready, |method, path, body| {
                    calls.push((method.to_owned(), path.to_owned(), body.cloned()));
                    if method == "GET" {
                        assert_eq!(path, "/repos/owner/repo/pulls/42");
                        let labels = labels.clone().context("read failed")?;
                        Ok(json!({"node_id": "PR_node", "draft": draft, "labels": labels}))
                    } else {
                        Ok(json!({}))
                    }
                })
            })
            .unwrap();
            assert_eq!(calls.len(), if mutation.is_some() { 2 } else { 1 });
            if let Some(mutation) = mutation {
                assert_eq!(calls[1].0, "POST");
                assert_eq!(calls[1].1, "/graphql");
                let body = calls[1].2.as_ref().unwrap();
                assert!(body["query"].as_str().unwrap().contains(mutation));
                assert_eq!(body["variables"]["id"], "PR_node");
            }
            let result = read_json(&dir.path().join("applied.json")).unwrap();
            assert_eq!(result["made"], applied["made"]);
            if let Some(reason) = reason {
                assert!(
                    result["readiness"]["reason"]
                        .as_str()
                        .unwrap()
                        .contains(reason)
                );
            } else {
                assert_eq!(result["readiness"]["draft"], !ready);
            }
        }
    }

    #[test]
    fn readiness_is_off_without_opt_in_or_a_push() {
        // A replacement series never reaches the handler: the guard
        // records it as made, or as applied by an earlier attempt.
        for (opted, pushed, recorded) in [
            (false, true, None),
            (true, false, None),
            (true, false, Some("already_applied")),
            (true, false, Some("made")),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut applied = json!({"made": [], "already_applied": []});
            if let Some(key) = recorded {
                applied[key] = json!([{"type": PUSH}]);
            }
            for (name, value) in [
                (
                    "config.json",
                    json!({PUSH: {"ready_when_complete": opted, "target": "42"}}),
                ),
                (
                    "agent_output.json",
                    json!({"items": if pushed { vec![json!({"type": PUSH})] } else { vec![] }}),
                ),
                ("applied.json", applied.clone()),
            ] {
                std::fs::write(dir.path().join(name), serde_json::to_vec(&value).unwrap()).unwrap();
            }
            let mut called = false;
            finish(
                &Args {
                    dir: dir.path().to_owned(),
                    repo: "owner/repo".into(),
                    ready: true,
                },
                |_, _, _| {
                    called = true;
                    Ok(json!({"draft": false}))
                },
            )
            .unwrap();
            assert_eq!(called, opted && recorded.is_some(), "{recorded:?}");
        }
    }
}
