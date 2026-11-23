//! Read-only admission of a dispatch's explicit `pr:N` base.

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::{BASE_RE, COMMIT_RE, PULL_NUMBER_RE, StackBase, context, is_login, owner};

pub(super) fn resolve(
    repo: &str,
    number: &str,
    author: &str,
    read: &mut dyn FnMut(&str) -> Result<Value>,
) -> Result<(String, StackBase)> {
    // A submitter can open a PR from someone else's visible branch. Require
    // both the trusted bot's authorship and a head it or the target owns.
    ensure!(
        is_login(author),
        "pr:N bases require a caller-configured stack author"
    );
    ensure!(
        context::valid_repo(repo) && PULL_NUMBER_RE.is_match(number),
        "expected pr:N with a positive pull request number in the target repository"
    );
    let target = read(&format!("repos/{repo}"))?;
    let pull = read(&format!("repos/{repo}/pulls/{number}"))?;
    let same =
        |value: &Value, name: &str| value.as_str().is_some_and(|s| s.eq_ignore_ascii_case(name));
    ensure!(
        context::public_repo(&target)
            && same(&target["full_name"], repo)
            && pull["number"].as_u64().map(|n| n.to_string()).as_deref() == Some(number)
            && pull["state"] == "open"
            && same(&pull["base"]["repo"]["full_name"], repo)
            && target["default_branch"]
                .as_str()
                .is_some_and(|branch| !branch.is_empty() && pull["base"]["ref"] == branch),
        "stack base must be an open pull request to the public target's default branch"
    );
    ensure!(
        same(&pull["user"]["login"], author),
        "stack base pull request #{number} was not opened by {author}"
    );
    let head = &pull["head"];
    let head_repo = &head["repo"];
    let name = head_repo["full_name"]
        .as_str()
        .filter(|name| context::valid_repo(name) && !name.ends_with(".git"))
        .context("stack base pull request has no valid head repository")?;
    ensure!(
        head_repo["private"] == false
            && (name.eq_ignore_ascii_case(repo)
                || (head_repo["fork"] == true
                    && owner(name).eq_ignore_ascii_case(author)
                    && same(&head_repo["owner"]["login"], author))),
        "stack base head must be in the target repository or {author}'s public fork"
    );
    let branch = head["ref"]
        .as_str()
        .filter(|branch| {
            BASE_RE.is_match(branch)
                && !branch.contains("..")
                && safe_outputs::apply::publish::normalize_branch(branch) == *branch
        })
        .context("stack base pull request has no valid head branch")?;
    let commit = head["sha"]
        .as_str()
        .filter(|sha| COMMIT_RE.is_match(sha))
        .context("stack base pull request has no valid head commit")?;
    Ok((
        branch.into(),
        StackBase {
            repo: name.into(),
            commit: commit.into(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stack_base_admission() {
        const REPO: &str = "example-org/project";
        const BOT: &str = "example-bot";
        const FORK: &str = "example-bot/a-renamed-fork";
        const BRANCH: &str = "dispatch/implement/agent-run-42";
        let sha = "a".repeat(40);
        let target = json!({"full_name": REPO, "private": false, "visibility": "public", "default_branch": "trunk"});
        let pull = json!({"number": 12, "state": "open", "user": {"login": BOT},
            "base": {"ref": "trunk", "repo": {"full_name": REPO}},
            "head": {"ref": BRANCH, "sha": sha, "repo": {
                "full_name": FORK, "private": false, "fork": true, "owner": {"login": BOT}
            }}
        });
        for (path, value, want) in [
            ("/head/repo/full_name", json!(FORK), Ok(FORK)),
            ("/head/repo/full_name", json!(REPO), Ok(REPO)),
            (
                "/user/login",
                json!("someone-else"),
                Err("was not opened by example-bot"),
            ),
            (
                "/head/repo/full_name",
                json!("someone-else/project"),
                Err("public fork"),
            ),
            ("/head/repo/private", json!(true), Err("public fork")),
            ("/base/ref", json!("next"), Err("default branch")),
            (
                "/state",
                json!("closed"),
                Err("must be an open pull request"),
            ),
        ] {
            let mut pull = pull.clone();
            *pull.pointer_mut(path).unwrap() = value;
            let resolved = resolve(REPO, "12", BOT, &mut |path| match path {
                "repos/example-org/project" => Ok(target.clone()),
                "repos/example-org/project/pulls/12" => Ok(pull.clone()),
                _ => panic!("unexpected read {path}"),
            });
            match want {
                Ok(repo) => assert_eq!(
                    resolved.unwrap(),
                    (
                        BRANCH.into(),
                        StackBase {
                            repo: repo.into(),
                            commit: sha.clone()
                        }
                    )
                ),
                Err(text) => assert!(
                    resolved.unwrap_err().to_string().contains(text),
                    "{path}: {text}"
                ),
            }
        }
        assert!(resolve(REPO, "12", "", &mut |_| panic!("no API read before opt-in")).is_err());
    }
}
