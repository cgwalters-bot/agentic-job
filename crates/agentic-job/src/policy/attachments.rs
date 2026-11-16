//! Experimental attachment admission, not a dispatch or publication interface.
//!
//! The concrete threat is a requested attachment granting writes outside the
//! caller's repositories, output limits or push branches. Resolve identities on
//! the read-only policy machine, and compile writes through ordinary policy
//! admission. No workflow consumes this result yet; it is not a checked receipt
//! and must not be used to authorize publication.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Bounds, Compile, Kind, Policy, Request, admits_repo, intersect};
use safe_outputs::apply::ADD_COMMENT;
use safe_outputs::contract::{BASE_RE, COMMIT_RE, PULL_NUMBER_RE, REPO_RE, dotted};
use safe_outputs::{Forge, PUSH_TO_PULL_REQUEST_BRANCH};

/// Hard ceilings before parsing or reading forge metadata.
pub const MAX_ATTACHMENTS: usize = 8;
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Read,
    Write,
}

/// A caller's request, never producer output. Unknown kinds and keys refuse.
/// File and artifact attachments have no authority until separately implemented.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Attachment {
    Issue {
        repo: String,
        number: u64,
        mode: Mode,
    },
    PullRequest {
        repo: String,
        number: u64,
        mode: Mode,
    },
    Branch {
        repo: String,
        branch: String,
        mode: Mode,
    },
}

impl Attachment {
    pub fn repo(&self) -> &str {
        match self {
            Self::Issue { repo, .. }
            | Self::PullRequest { repo, .. }
            | Self::Branch { repo, .. } => repo,
        }
    }

    pub fn mode(&self) -> Mode {
        match self {
            Self::Issue { mode, .. }
            | Self::PullRequest { mode, .. }
            | Self::Branch { mode, .. } => *mode,
        }
    }
}

/// Metadata resolved at admission, not full input context. A later workflow must
/// fetch comments/diffs and bind these identities into check/apply artifacts.
#[derive(Debug)]
pub struct Admitted {
    pub attachment: Attachment,
    /// Repository containing the pinned head, distinct from a PR's target. None
    /// for a read-mode PR: fetch its head from the target's `refs/pull/N/head`.
    pub head_repo: Option<String>,
    /// Exact checkout commit for a PR or branch; issues have no checkout.
    pub head: Option<String>,
    /// The existing policy for permitted operations on this write target.
    /// Per-target policies do not grant extra outputs to the overall run.
    pub write_policy: Option<Policy>,
}

/// Resolve an explicit attachment list under both caller and organization bounds.
/// An empty list performs no reads and enables nothing. The callback must be a
/// bounded, read-only GitHub API reader, like `policy::context`'s reader; paths
/// have no leading slash. This function does not fetch content or acquire tokens.
///
/// There is no branch-push safe output, so write-mode branches refuse. PR writes
/// require explicit `own_author` bounds as well as branch admission. A fork head
/// must independently fit repository bounds, so admitting an upstream PR alone
/// does not authorize a push to its author's repository. Public reads use the
/// existing context authority: clone hosts remain bounded, but write repository
/// bounds do not restrict reading. A read-mode PR may come from any author's
/// fork, even a deleted one (#3692). An upstream PR outside write repository
/// bounds may receive only an `own_author` push, never a comment, as for ordinary
/// continuation admission (#3162). The compiled write policies stay within every
/// bounds file's `max_outputs` and per-type `max`.
/// Apply must still repeat its live ownership, protected/default-branch and lease
/// checks. This groundwork deliberately cannot replace those checks.
pub fn admit(
    text: &str,
    bounds: &Bounds,
    organization: Option<&Bounds>,
    job_token: bool,
    read: &mut dyn FnMut(&str) -> Result<Value>,
) -> Result<Vec<Admitted>> {
    ensure!(
        text.len() <= MAX_REQUEST_BYTES,
        "attachments input exceeds 16 KiB"
    );
    let attachments: Vec<Attachment> = if text.is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(text).context("invalid attachments list")?
    };
    ensure!(
        attachments.len() <= MAX_ATTACHMENTS,
        "at most {MAX_ATTACHMENTS} attachments"
    );
    if attachments.is_empty() {
        return Ok(Vec::new());
    }
    let all_bounds: Vec<_> = std::iter::once(bounds).chain(organization).collect();
    for bounds in &all_bounds {
        bounds.validate()?;
        ensure!(
            bounds.forge() == Forge::Github,
            "attachment admission currently requires GitHub bounds"
        );
    }
    let mut seen = BTreeSet::new();
    // Validate the entire request before reading metadata, including duplicates
    // across modes. A second read declaration must not conceal a write target.
    for attachment in &attachments {
        let repo = attachment.repo();
        ensure!(
            REPO_RE.is_match(repo) && !dotted(repo),
            "invalid attachment repository"
        );
        let identity = match attachment {
            Attachment::Issue { number, .. } | Attachment::PullRequest { number, .. } => {
                ensure!(
                    PULL_NUMBER_RE.is_match(&number.to_string()),
                    "invalid attachment item number"
                );
                // GitHub shares issue and PR numbers: both spellings are one target.
                format!("{}#{number}", repo.to_ascii_lowercase())
            }
            Attachment::Branch { branch, mode, .. } => {
                ensure!(
                    BASE_RE.is_match(branch) && !branch.contains(".."),
                    "invalid attachment branch"
                );
                ensure!(
                    *mode == Mode::Read,
                    "write-mode branch attachments have no safe-output operation"
                );
                format!("{}@{branch}", repo.to_ascii_lowercase())
            }
        };
        ensure!(seen.insert(identity), "duplicate attachment target");
    }
    let admitted = attachments
        .into_iter()
        .map(|attachment| {
            let repo = attachment.repo();
            // As for public context, reads need no write-repository admission.
            // PR writes compile below through the existing own_author exception;
            // other writes still need every bounds file to list the target.
            let mut listed = true;
            if attachment.mode() == Mode::Write {
                for bounds in &all_bounds {
                    listed &= admits_repo(&bounds.repos, repo, read)?;
                }
                ensure!(
                    listed || matches!(attachment, Attachment::PullRequest { .. }),
                    "attachment repository is outside bounds"
                );
            }
            let metadata = read(&format!("repos/{repo}"))?;
            ensure!(
                same(&metadata["full_name"], repo)
                    && metadata["private"] == false
                    && metadata["visibility"] == "public",
                "attachment repository must match and be public"
            );
            let clone_url = metadata["clone_url"]
                .as_str()
                .context("attachment repository has no clone URL")?;
            for bounds in &all_bounds {
                ensure!(
                    bounds.clone_url_problem(clone_url, repo).is_none(),
                    "attachment clone URL is outside bounds"
                );
            }
            let (head_repo, head, write_policy) = match &attachment {
                Attachment::Issue { number, mode, .. } => {
                    let issue = read(&format!("repos/{repo}/issues/{number}"))?;
                    ensure!(
                        issue["number"].as_u64() == Some(*number)
                            && issue.get("pull_request").is_none()
                            && metadata["url"].is_string()
                            && issue["repository_url"] == metadata["url"],
                        "attachment is not the requested issue"
                    );
                    let policy = if *mode == Mode::Write {
                        Some(compile(
                            &all_bounds,
                            &Request {
                                repo,
                                clone_url,
                                base: default_branch(&metadata)?,
                                kind: Kind::Analysis,
                                outputs: "add_comment",
                                max_outputs: "1",
                                job_token,
                                pull_request: None,
                                pull_author: None,
                                output_repo: Some(repo),
                                item_repo: None,
                                private: false,
                            },
                            read,
                        )?)
                    } else {
                        None
                    };
                    (None, None, policy)
                }
                Attachment::PullRequest { number, mode, .. } => {
                    let pull = read(&format!("repos/{repo}/pulls/{number}"))?;
                    ensure!(
                        pull["number"].as_u64() == Some(*number)
                            && same(&pull["base"]["repo"]["full_name"], repo),
                        "attachment is not the requested pull request"
                    );
                    let head = commit(&pull["head"]["sha"])?;
                    // A read head is fetched from the target's pull ref, so its
                    // repository, which may be deleted or outside bounds, is
                    // never consulted.
                    if *mode == Mode::Read {
                        return Ok(Admitted {
                            attachment,
                            head_repo: None,
                            head: Some(head),
                            write_policy: None,
                        });
                    }
                    let head_repo = pull["head"]["repo"]["full_name"]
                        .as_str()
                        .filter(|name| REPO_RE.is_match(name) && !dotted(name))
                        .context("attachment PR has no valid head repository")?;
                    // Re-read the head repository rather than trusting the embedded
                    // PR object. Cross-repository heads must be public forks of
                    // the target.
                    let head_metadata = read(&format!("repos/{head_repo}"))?;
                    ensure!(
                        same(&head_metadata["full_name"], head_repo)
                            && head_metadata["private"] == false
                            && head_metadata["visibility"] == "public"
                            && (head_repo.eq_ignore_ascii_case(repo)
                                || (head_metadata["fork"] == true
                                    && same(&head_metadata["parent"]["full_name"], repo))),
                        "attachment head must be the target or its public fork"
                    );
                    let policy = {
                        ensure!(
                            pull["state"] == "open",
                            "write attachment requires an open PR"
                        );
                        for bounds in &all_bounds {
                            ensure!(
                                admits_repo(&bounds.repos, head_repo, read)?,
                                "attachment head repository is outside bounds"
                            );
                        }
                        let head_clone = head_metadata["clone_url"]
                            .as_str()
                            .context("attachment head has no clone URL")?;
                        for bounds in &all_bounds {
                            ensure!(
                                bounds.clone_url_problem(head_clone, head_repo).is_none(),
                                "attachment head clone URL is outside bounds"
                            );
                        }
                        let author = pull["user"]["login"]
                            .as_str()
                            .context("attachment PR has no author")?;
                        for bounds in &all_bounds {
                            ensure!(
                                bounds
                                    .outputs()
                                    .get(PUSH_TO_PULL_REQUEST_BRANCH)
                                    .and_then(|limit| limit.own_author.as_deref())
                                    .is_some_and(|own| own.eq_ignore_ascii_case(author)),
                                "write attachment PR requires its author in own_author bounds"
                            );
                        }
                        Some(compile(
                            &all_bounds,
                            &Request {
                                repo,
                                clone_url,
                                base: pull["head"]["ref"]
                                    .as_str()
                                    .context("attachment PR has no branch")?,
                                kind: Kind::Branch,
                                // own_author grants only a push outside repos,
                                // not authority to post upstream. Taking the
                                // intersection here cannot recover comments
                                // denied by either bounds file.
                                outputs: if listed {
                                    "push_to_pull_request_branch,add_comment"
                                } else {
                                    "push_to_pull_request_branch"
                                },
                                max_outputs: if listed { "2" } else { "1" },
                                job_token,
                                pull_request: Some((&number.to_string(), &head)),
                                pull_author: Some(author),
                                output_repo: Some(repo),
                                item_repo: None,
                                private: false,
                            },
                            read,
                        )?)
                    };
                    (Some(head_repo.to_owned()), Some(head), policy)
                }
                Attachment::Branch { branch, .. } => {
                    let reference = read(&format!(
                        "repos/{repo}/git/ref/heads/{}",
                        branch.replace('/', "%2F")
                    ))?;
                    ensure!(
                        reference["ref"] == format!("refs/heads/{branch}")
                            && reference["object"]["type"] == "commit",
                        "attachment branch did not resolve to its exact commit ref"
                    );
                    (
                        Some(repo.to_owned()),
                        Some(commit(&reference["object"]["sha"])?),
                        None,
                    )
                }
            };
            Ok(Admitted {
                attachment,
                head_repo,
                head,
                write_policy,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    // Each write policy is compiled alone, so cap what they grant together.
    let policies: Vec<_> = admitted
        .iter()
        .filter_map(|admitted| admitted.write_policy.as_ref())
        .collect();
    let total: u32 = policies.iter().map(|policy| policy.max_outputs).sum();
    let pushes: u32 = policies
        .iter()
        .filter_map(|policy| policy.safe_outputs.push_to_pull_request_branch.as_ref())
        .map(|push| push.max)
        .sum();
    let comments: u32 = policies
        .iter()
        .filter_map(|policy| policy.safe_outputs.others.get(ADD_COMMENT))
        .map(|limit| limit.max)
        .sum();
    for bounds in &all_bounds {
        ensure!(
            total <= bounds.max_outputs,
            "write attachments grant {total} outputs, more than max_outputs {}",
            bounds.max_outputs
        );
        for (output, granted) in [
            (ADD_COMMENT, comments),
            (PUSH_TO_PULL_REQUEST_BRANCH, pushes),
        ] {
            let max = bounds.outputs().get(output).map_or(0, |limit| limit.max);
            ensure!(
                granted <= max,
                "write attachments grant {granted} {output} outputs, more than its max {max}"
            );
        }
    }
    Ok(admitted)
}

fn compile(
    bounds: &[&Bounds],
    request: &Request<'_>,
    read: &mut dyn FnMut(&str) -> Result<Value>,
) -> Result<Policy> {
    let mut policies = bounds
        .iter()
        .map(|bounds| bounds.compile_with(request, read));
    let mut policy = policies
        .next()
        .context("missing attachment bounds")?
        .map_err(|errors| anyhow::anyhow!("attachment write refused: {}", errors.join("; ")))?;
    for other in policies {
        policy = other
            .and_then(|other| intersect(policy, other))
            .map_err(|errors| anyhow::anyhow!("attachment write refused: {}", errors.join("; ")))?;
    }
    Ok(policy)
}

fn same(value: &Value, expected: &str) -> bool {
    value
        .as_str()
        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

fn commit(value: &Value) -> Result<String> {
    value
        .as_str()
        .filter(|sha| COMMIT_RE.is_match(sha))
        .map(str::to_owned)
        .context("attachment has no exact commit SHA")
}

fn default_branch(metadata: &Value) -> Result<&str> {
    metadata["default_branch"]
        .as_str()
        .context("attachment repository has no default branch")
}
