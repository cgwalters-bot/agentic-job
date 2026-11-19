//! Fixture-only admission for additional input, not a dispatch or output interface.
//! An item could disclose private content, including via a PR from another repo.
//! Check each source as public context; never accept identity or pins from its text.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;

use super::{Bounds, COMMIT_RE, ContextRepo, Forge, PULL_NUMBER_RE, check_clone_url, context};

const MAX_ATTACHMENTS: usize = 8;

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "kebab-case")]
enum Kind {
    Issue,
    PullRequest,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "lowercase")]
enum Mode {
    Read,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    kind: Kind,
    #[serde(rename = "mode")]
    _mode: Mode,
    repo: String,
    number: u64,
}

/// Input identity only. Neither variant contains a branch or a write grant.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadAttachment {
    Issue {
        repo: String,
        number: u64,
    },
    PullRequest {
        repo: String,
        number: u64,
        head: ContextRepo,
    },
}

/// Resolve the complete list or return no identities. `read` supplies trusted
/// GitHub REST metadata, not worker output. No workflow calls this function.
pub fn admit(
    text: &str,
    caller: &Bounds,
    organization: Option<&Bounds>,
    read: &mut dyn FnMut(&str) -> Result<Value>,
) -> Result<Vec<ReadAttachment>> {
    ensure!(
        text.len() <= context::MAX_REQUEST,
        "attachment request exceeds 16 KiB"
    );
    let entries: Vec<&serde_json::value::RawValue> =
        serde_json::from_str(text).context("invalid read attachment list")?;
    ensure!(
        entries.len() <= MAX_ATTACHMENTS,
        "at most {MAX_ATTACHMENTS} attachments"
    );
    let mut seen = BTreeSet::new();
    let mut requests = Vec::with_capacity(entries.len());
    for entry in entries {
        // A positional tuple isn't a declaration of named fields. Parse the
        // original object, not a Value, so duplicate keys are refused too.
        ensure!(
            entry.get().starts_with('{'),
            "expected an attachment object"
        );
        let request: Request =
            serde_json::from_str(entry.get()).context("invalid read attachment")?;
        ensure!(
            context::valid_repo(&request.repo)
                && PULL_NUMBER_RE.is_match(&request.number.to_string()),
            "invalid attachment identity"
        );
        ensure!(
            seen.insert((request.repo.to_ascii_lowercase(), request.number)),
            "duplicate attachment identity"
        );
        requests.push(request);
    }

    let bounds = std::iter::once(caller).chain(organization);
    for bound in bounds.clone() {
        bound.validate()?;
        ensure!(
            bound.forge() == Forge::Github,
            "attachments require GitHub metadata"
        );
    }
    // Public context need not be a write repository. Both sets of clone bounds
    // still apply, including to a PR head whose host differs from its base's.
    let repository =
        |name: &str, read: &mut dyn FnMut(&str) -> Result<Value>| -> Result<(String, String)> {
            ensure!(context::valid_repo(name), "invalid attachment repository");
            let metadata = read(&format!("repos/{name}"))?;
            let repo = metadata["full_name"]
                .as_str()
                .filter(|s| s.eq_ignore_ascii_case(name))
                .context("attachment repository identity mismatch")?;
            ensure!(
                context::public_repo(&metadata),
                "attachment repository is not confirmed public"
            );
            let url = metadata["clone_url"]
                .as_str()
                .context("missing attachment clone URL")?;
            check_clone_url(url)?;
            for bound in bounds.clone() {
                ensure!(
                    bound.clone_url_problem(url, repo).is_none(),
                    "attachment clone URL outside bounds"
                );
            }
            Ok((repo.to_owned(), url.to_owned()))
        };
    requests
        .into_iter()
        .map(|request| {
            let (repo, clone_url) = repository(&request.repo, read)?;
            let web = clone_url.strip_suffix(".git").unwrap_or(&clone_url);
            let (api, page) = match request.kind {
                Kind::Issue => ("issues", "issues"),
                Kind::PullRequest => ("pulls", "pull"),
            };
            let item = read(&format!("repos/{repo}/{api}/{}", request.number))?;
            let number = item["number"]
                .as_u64()
                .filter(|&n| n == request.number)
                .context("attachment number mismatch")?;
            ensure!(
                item["html_url"]
                    .as_str()
                    .is_some_and(|url| url.eq_ignore_ascii_case(&format!("{web}/{page}/{number}"))),
                "attachment item identity mismatch"
            );
            Ok(match request.kind {
                Kind::Issue => {
                    ensure!(
                        item.get("pull_request").is_none(),
                        "expected an issue, not a pull request"
                    );
                    ReadAttachment::Issue { repo, number }
                }
                Kind::PullRequest => {
                    ensure!(
                        item["base"]["repo"]["full_name"]
                            .as_str()
                            .is_some_and(|base| base.eq_ignore_ascii_case(&repo)),
                        "attachment base repository mismatch"
                    );
                    let head = item["head"]["sha"]
                        .as_str()
                        .filter(|sha| COMMIT_RE.is_match(sha))
                        .context("invalid attachment head commit")?
                        .to_owned();
                    let name = item["head"]["repo"]["full_name"]
                        .as_str()
                        .context("missing attachment head repository")?;
                    let (head_repo, clone_url) = repository(name, read)?;
                    ReadAttachment::PullRequest {
                        repo,
                        number,
                        head: ContextRepo {
                            repo: head_repo,
                            clone_url,
                            commit: head,
                            public: true,
                        },
                    }
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
