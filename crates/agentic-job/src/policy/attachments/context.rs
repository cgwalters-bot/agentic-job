//! Bounded public attachment context, not publication authority.
//!
//! Admission runs first, with the same bounded reader as the content reads.
//! Source identities are checked again after fetching context: a moving PR head
//! or base, or branch, refuses rather than mixing code revisions. Forge text and
//! CI results are mutable observations, not an atomic snapshot or instructions.
//! Nothing consumes this API in dispatch, run, check or apply yet.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;

use super::{Admitted, Attachment, Bounds, admit, commit};

/// These limits cover admission and content together, not each attachment alone.
pub const MAX_CONTEXT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_READS: usize = 256;
pub const MAX_PAGES: usize = 10;
const PAGE_SIZE: usize = 100;

/// A downstream checkout must fetch `git_ref` from `clone_url` and verify HEAD
/// equals `commit` before exposing it to an agent. For a PR it must also fetch
/// `base_commit`, so it can obtain the complete diff and commit graph locally,
/// without depending on the forge's truncated files/compare APIs.
#[derive(Debug, Serialize)]
pub struct Checkout {
    pub clone_url: String,
    pub git_ref: String,
    pub commit: String,
    pub base_commit: Option<String>,
}

/// REST review comments retain `in_reply_to_id` for replies, but do not contain
/// thread resolution/outdated state. A future workflow must fetch that separately
/// before claiming full review-thread context. These fields grant no write route.
#[derive(Debug, Serialize)]
pub struct PullContext {
    pub reviews: Vec<Value>,
    pub review_comments: Vec<Value>,
    pub check_runs: Vec<Value>,
    pub statuses: Vec<Value>,
}

/// Raw forge JSON is untrusted data. This is deliberately not deserializable as
/// a policy or checked receipt; it must never authorize a write or be appended to
/// trusted task prose without the event context's sanitizing/fencing boundary.
#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub attachment: Attachment,
    pub checkout: Option<Checkout>,
    /// The issue or PR object, including title and body; branch ref otherwise.
    pub item: Value,
    pub comments: Vec<Value>,
    pub pull: Option<PullContext>,
}

/// Admission and context from the same resolution, for a future trusted policy
/// producer. Keep these together rather than admitting a second time after
/// fetching context: that could authorize writes to a different head.
///
/// Only `admitted` is policy metadata; `snapshot` remains untrusted forge text.
/// Serialization is for transport through a trusted producer's artifact channel,
/// not a signature or a checked receipt. No consumer accepts this as publication
/// authority, and it deliberately has no deserializer from producer output.
#[derive(Debug, Serialize)]
pub struct Resolved {
    pub admitted: Admitted,
    pub snapshot: Snapshot,
}

/// Resolve and read all declared attachments, including writes (which imply
/// read), or return no context on any failure. READ has the same read-only,
/// bounded HTTP-reader contract as `admit`. It must cap response bytes *before*
/// parsing JSON; the limits here additionally bound accumulated parsed content.
/// REST pagination is explicit and refuses at its cap, never silently truncates.
pub fn snapshot(
    text: &str,
    bounds: &Bounds,
    organization: Option<&Bounds>,
    job_token: bool,
    read: &mut dyn FnMut(&str) -> Result<Value>,
) -> Result<Vec<Snapshot>> {
    Ok(resolve(text, bounds, organization, job_token, read)?
        .into_iter()
        .map(|resolved| resolved.snapshot)
        .collect())
}

/// Like `snapshot`, but retain the exact admission that produced each snapshot.
/// Nothing is returned unless every attachment passes admission, content reads,
/// revision rechecks and the shared limits. The serialized admission and context
/// together also fit the context byte ceiling.
pub fn resolve(
    text: &str,
    bounds: &Bounds,
    organization: Option<&Bounds>,
    job_token: bool,
    read: &mut dyn FnMut(&str) -> Result<Value>,
) -> Result<Vec<Resolved>> {
    let mut reader = Reader {
        read,
        bytes: 0,
        calls: 0,
    };
    // Keep exactly the metadata admission checked, rather than resolving a ref
    // again and accidentally accepting a different head for the content read.
    let mut metadata = BTreeMap::new();
    let admitted = admit(text, bounds, organization, job_token, &mut |path| {
        let value = reader.get(path)?;
        metadata.insert(path.to_owned(), value.clone());
        Ok(value)
    })?;
    let mut resolved = Vec::new();
    for admitted in admitted {
        let repo = admitted.attachment.repo();
        let root = format!("repos/{repo}");
        let clone_url = metadata[&root]["clone_url"]
            .as_str()
            .context("admitted attachment has no clone URL")?
            .to_owned();
        let (item, comments, checkout, pull) = match &admitted.attachment {
            Attachment::Issue { number, .. } => {
                let path = format!("{root}/issues/{number}");
                let item = metadata[&path].clone();
                let comments = reader.pages(&format!("{path}/comments"), None)?;
                (item, comments, None, None)
            }
            Attachment::PullRequest { number, .. } => {
                let path = format!("{root}/pulls/{number}");
                let item = metadata[&path].clone();
                let head = admitted
                    .head
                    .as_deref()
                    .context("admitted PR has no head")?;
                let base = commit(&item["base"]["sha"])?;
                let comments = reader.pages(&format!("{root}/issues/{number}/comments"), None)?;
                let reviews = reader.pages(&format!("{path}/reviews"), None)?;
                let review_comments = reader.pages(&format!("{path}/comments"), None)?;
                let check_runs = reader.pages(
                    &format!("{root}/commits/{head}/check-runs?filter=all"),
                    Some("check_runs"),
                )?;
                ensure!(
                    check_runs.iter().all(|check| check["head_sha"] == head),
                    "attachment check run is not for the pinned head"
                );
                let statuses = reader.pages(&format!("{root}/commits/{head}/statuses"), None)?;
                let latest = reader.get(&path)?;
                ensure!(
                    latest["number"].as_u64() == Some(*number)
                        && super::same(&latest["base"]["repo"]["full_name"], repo)
                        && latest["head"]["sha"] == head
                        && latest["base"]["sha"] == base,
                    "attachment PR changed while reading context"
                );
                let checkout = Checkout {
                    clone_url,
                    git_ref: format!("refs/pull/{number}/head"),
                    commit: head.to_owned(),
                    base_commit: Some(base),
                };
                (
                    item,
                    comments,
                    Some(checkout),
                    Some(PullContext {
                        reviews,
                        review_comments,
                        check_runs,
                        statuses,
                    }),
                )
            }
            Attachment::Branch { branch, .. } => {
                let path = format!("{root}/git/ref/heads/{}", branch.replace('/', "%2F"));
                let item = metadata[&path].clone();
                let head = admitted
                    .head
                    .as_deref()
                    .context("admitted branch has no head")?;
                let latest = reader.get(&path)?;
                ensure!(
                    latest["ref"] == format!("refs/heads/{branch}")
                        && latest["object"]["type"] == "commit"
                        && latest["object"]["sha"] == head,
                    "attachment branch changed while reading context"
                );
                (
                    item,
                    Vec::new(),
                    Some(Checkout {
                        clone_url,
                        git_ref: format!("refs/heads/{branch}"),
                        commit: head.to_owned(),
                        base_commit: None,
                    }),
                    None,
                )
            }
        };
        resolved.push(Resolved {
            snapshot: Snapshot {
                attachment: admitted.attachment.clone(),
                item,
                comments,
                checkout,
                pull,
            },
            admitted,
        });
    }
    ensure!(
        serde_json::to_vec(&resolved)?.len() <= MAX_CONTEXT_BYTES,
        "serialized attachment context exceeds 8 MiB"
    );
    Ok(resolved)
}

struct Reader<'a> {
    read: &'a mut dyn FnMut(&str) -> Result<Value>,
    bytes: usize,
    calls: usize,
}

impl Reader<'_> {
    fn get(&mut self, path: &str) -> Result<Value> {
        ensure!(
            self.calls < MAX_READS,
            "attachment context exceeds read limit"
        );
        self.calls += 1;
        let value = (self.read)(path)?;
        let bytes = serde_json::to_vec(&value)?.len();
        ensure!(
            bytes <= MAX_RESPONSE_BYTES,
            "attachment context response exceeds 1 MiB"
        );
        self.bytes += bytes;
        ensure!(
            self.bytes <= MAX_CONTEXT_BYTES,
            "attachment context exceeds 8 MiB"
        );
        Ok(value)
    }

    fn pages(&mut self, path: &str, key: Option<&str>) -> Result<Vec<Value>> {
        let mut rows = Vec::new();
        let mut total = None;
        let separator = if path.contains('?') { '&' } else { '?' };
        for page in 1..=MAX_PAGES {
            let value = self.get(&format!(
                "{path}{separator}per_page={PAGE_SIZE}&page={page}"
            ))?;
            if key.is_some() {
                let count = value["total_count"]
                    .as_u64()
                    .context("attachment context page has no total count")?;
                ensure!(
                    total.is_none_or(|total| total == count),
                    "attachment context total changed while paging"
                );
                total = Some(count);
            }
            let list = key.map_or(&value, |key| &value[key]);
            let list = list
                .as_array()
                .context("attachment context page is not a list")?;
            ensure!(
                list.len() <= PAGE_SIZE,
                "attachment context page exceeds 100 rows"
            );
            rows.extend(list.iter().cloned());
            if list.len() < PAGE_SIZE {
                ensure!(
                    total.is_none_or(|total| total == rows.len() as u64),
                    "attachment context page is incomplete"
                );
                return Ok(rows);
            }
        }
        anyhow::bail!("attachment context pagination exceeds {MAX_PAGES} pages")
    }
}
