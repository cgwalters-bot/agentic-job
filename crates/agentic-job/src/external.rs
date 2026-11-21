//! Caller-owned dispatch correlation. API digests provide transfer integrity,
//! not provenance; only the record and all the run identity checks do that.
//! No dispatch, cancellation, credential creation or publication happens here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::exit::Exit;
use crate::policy::{COMMIT_RE, MAX_EXTERNAL_FILES, Policy, is_sha256_digest};

const MAX_RECORD: u64 = 64 << 10;
// Room for a full record, 256 names and their digests, and the receipt
// envelope, while leaving room below Linux's per-environment-string limit
// for policy.yml to pass the JSON to its shell step.
const MAX_RECEIPT: u64 = 120 << 10;
const MAX_PAGE: u64 = 4 << 20;
const MAX_ARCHIVE: u64 = 128 << 20;
const MAX_PAGES: usize = 10;
const APPEAR_SECONDS: i64 = 600;
const MAX_LIFETIME_SECONDS: i64 = 330 * 60;
const POLL: Duration = Duration::from_secs(15);

/// Where the artifact API's redirect may send the download in production:
/// anywhere over HTTPS, without the API credential.
const STORAGE: &str = "https://";

mod gitlab;

#[cfg(test)]
mod tests;

/// The CI system of the caller and the producer it dispatched.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Caller {
    #[default]
    Github,
    Gitlab,
}

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The record's CI system: a GitHub Actions run, or a GitLab pipeline
    /// on the caller's own instance
    #[arg(long, value_enum, default_value_t)]
    pub forge: Caller,
    /// Caller-owned record, never downloaded from the external run
    #[arg(long)]
    pub record: PathBuf,
    /// New ZIP file for the raw hand-back; no external checked policy is consumed
    #[arg(long)]
    pub archive: PathBuf,
    /// New directory for bounded, flat, regular raw hand-back files
    #[arg(long)]
    pub outputs: PathBuf,
    /// New caller-side receipt, including the matched run and both artifacts
    #[arg(long)]
    pub receipt: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct ReleaseArgs {
    #[arg(long)]
    pub policy: PathBuf,
    #[arg(long)]
    pub report: PathBuf,
    /// Trusted check.yml detection output, not an external report field
    #[arg(long, default_value = "")]
    pub detection_result: String,
}

/// Apply-only retries keep their original record and idempotency names, but
/// another run or an earlier attempt cannot reuse the caller's policy.
pub fn caller_policy(policy: &Policy) -> Result<()> {
    if let Some(external) = &policy.external {
        if let Some(caller) = &external.gitlab {
            return gitlab::caller_env(
                &caller.server,
                caller.caller_project_id,
                external.caller_run_id,
            )
            .context("external policy belongs to another caller pipeline");
        }
        ensure!(
            std::env::var("GITHUB_REPOSITORY")? == external.caller_repository
                && std::env::var("GITHUB_RUN_ID")?.parse::<u64>()? == external.caller_run_id
                && std::env::var("GITHUB_RUN_ATTEMPT")?.parse::<u64>()? >= external.caller_attempt,
            "external policy belongs to another caller run/attempt"
        );
    }
    Ok(())
}

pub fn release(args: &ReleaseArgs) -> Result<Exit> {
    use crate::policy::Load;
    let policy = Policy::load(&args.policy)?;
    caller_policy(&policy)?;
    let report: Value =
        serde_json::from_slice(&crate::files::read_regular(&args.report, MAX_PAGE)?)?;
    authorize(&policy, &report, &args.detection_result)?;
    Ok(Exit::Success)
}

fn authorize(policy: &Policy, report: &Value, detection: &str) -> Result<()> {
    policy.publishable()?;
    if let Some(external) = &policy.external {
        ensure!(
            detection == "success",
            "external apply requires successful trusted detection (not skipped/absent)"
        );
        ensure!(
            report["ok"] == true,
            "external apply requires successful trusted check"
        );
        if !report["patch"].is_null() {
            ensure!(
                report["patch"]["base_commit"] == external.base_commit,
                "external apply base differs from trusted record"
            );
        }
        for item in report["items"]
            .as_array()
            .context("missing checked items")?
        {
            if item["type"] == "create_pull_request" {
                ensure!(
                    item["branch"] == format!("agent-run-{}", external.run_id),
                    "external apply branch differs from trusted record"
                );
            }
        }
    }
    Ok(())
}

/// Trusted input, constructed and retained only by the caller before dispatch.
/// Times are UTC RFC3339; IDs are API numeric identities, not display names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub dispatch_id: String,
    pub caller_repository: String,
    pub caller_run_id: u64,
    pub caller_attempt: u64,
    pub profile_commit: String,
    pub target_repository: String,
    pub target_branch: String,
    pub base_commit: String,
    pub item: u64,
    pub kind: String,
    pub repository: String,
    pub repository_id: u64,
    pub workflow: String,
    pub reference: String,
    pub commit: String,
    pub triggering_actor_id: u64,
    pub agentic_job: String,
    pub actions: String,
    /// Caller-selected OWNER/REPO/.github/workflows/FILE.yml identities.
    pub actions_workflow: String,
    pub policy_workflow: String,
    pub check_workflow: String,
    pub artifact_prefix: String,
    /// Exact API job names fixed by the pinned external caller/wrapper.
    pub check_job: String,
    pub detect_job: String,
    pub dispatched_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
    pub returned_run_id: Option<u64>,
}

impl Record {
    pub fn load(path: &Path) -> Result<Self> {
        let record: Self = serde_json::from_slice(&crate::files::read_regular(path, MAX_RECORD)?)?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        ensure!(hex(&self.dispatch_id, 32), "invalid dispatch ID");
        ensure!(
            self.kind == "implement",
            "external correlation supports only implement"
        );
        for repo in [
            &self.caller_repository,
            &self.repository,
            &self.target_repository,
        ] {
            ensure!(
                crate::apply::github::is_repo(repo),
                "invalid record repository"
            );
        }
        for sha in [
            &self.profile_commit,
            &self.base_commit,
            &self.commit,
            &self.agentic_job,
            &self.actions,
        ] {
            ensure!(
                COMMIT_RE.is_match(sha),
                "record requires full lowercase commit pins"
            );
        }
        ensure!(
            self.caller_run_id > 0
                && self.caller_attempt > 0
                && self.repository_id > 0
                && self.triggering_actor_id > 0
                && self.item > 0
                && self.returned_run_id != Some(0),
            "record IDs must be positive"
        );
        ensure!(
            self.workflow.starts_with(".github/workflows/")
                && self.workflow.ends_with(".yml")
                && !self.workflow[18..].contains('/')
                && self
                    .workflow
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"./_-".contains(&b)),
            "invalid workflow path"
        );
        for text in [
            &self.reference,
            &self.target_branch,
            &self.check_job,
            &self.detect_job,
        ] {
            ensure!(
                !text.is_empty() && text.len() <= 256 && !text.chars().any(char::is_control),
                "invalid record ref/job"
            );
        }
        ensure!(
            self.check_job != self.detect_job,
            "check and detect must be distinct jobs"
        );
        let mut workflows = std::collections::BTreeSet::new();
        for path in [
            &self.actions_workflow,
            &self.policy_workflow,
            &self.check_workflow,
        ] {
            let (repo, file) = path
                .split_once("/.github/workflows/")
                .context("invalid reusable workflow identity")?;
            ensure!(
                crate::apply::github::is_repo(repo)
                    && file.ends_with(".yml")
                    && !file.is_empty()
                    && file
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    && workflows.insert(path),
                "invalid or duplicate reusable workflow identity"
            );
        }
        ensure!(
            self.artifact_prefix.len() <= 128
                && self
                    .artifact_prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid artifact prefix"
        );
        let lifetime = (self.deadline - self.dispatched_at).num_seconds();
        ensure!(
            (1..=MAX_LIFETIME_SECONDS).contains(&lifetime),
            "external lifetime must be at most 330 minutes"
        );
        Ok(())
    }

    /// Prevent a receipt/record from a different caller run being replayed.
    pub fn caller(&self, repo: &str, run: u64, attempt: u64) -> Result<()> {
        ensure!(
            self.caller_repository == repo
                && self.caller_run_id == run
                && self.caller_attempt == attempt,
            "dispatch record belongs to another caller run/attempt"
        );
        Ok(())
    }

    pub fn caller_env(&self) -> Result<()> {
        self.caller(
            &std::env::var("GITHUB_REPOSITORY").context("missing caller repository")?,
            std::env::var("GITHUB_RUN_ID")?.parse()?,
            std::env::var("GITHUB_RUN_ATTEMPT")?.parse()?,
        )
    }

    pub fn policy(&self, policy: &Policy) -> Result<()> {
        target(policy, &self.target_repository, &self.target_branch)
    }
}

fn target(policy: &Policy, repository: &str, branch: &str) -> Result<()> {
    ensure!(
        policy.repo == repository
            && policy.base == branch
            && policy.kind == crate::policy::Kind::Branch
            && policy.safe_outputs.push_to_pull_request_branch.is_none()
            && policy.secondary_pull_request.is_none(),
        "external record requires its exact implement target/base, without push or secondary target"
    );
    Ok(())
}

/// The caller-owned receipt at PATH, of either CI system, checked against
/// this caller and POLICY's target and reduced to what check and apply keep.
/// A GitHub record has no `forge` field, and refuses one.
pub fn admit(path: &Path, policy: &Policy) -> Result<crate::policy::ExternalRun> {
    let bytes = crate::files::read_regular(path, MAX_RECEIPT)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    if value["record"]["forge"] == gitlab::FORGE {
        return gitlab::Receipt::parse(&bytes)?.admit(policy);
    }
    let receipt = Receipt::load(path)?;
    receipt.record.caller_env()?;
    receipt.record.policy(policy)?;
    Ok(crate::policy::ExternalRun {
        caller_repository: receipt.record.caller_repository,
        caller_run_id: receipt.record.caller_run_id,
        caller_attempt: receipt.record.caller_attempt,
        repository: receipt.record.repository,
        run_id: receipt.run_id,
        base_commit: receipt.record.base_commit,
        raw_digest: receipt.raw.digest,
        files: receipt.files,
        gitlab: None,
    })
}

fn hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// BYTES' digest as the Actions API and the receipt write one.
fn sha256(bytes: &[u8]) -> String {
    let hex: String = digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// A name the raw archive may hold: a flat hand-back file, never a path.
fn is_raw_member(name: &str) -> bool {
    crate::check::is_handback_file(name) && !name.contains(['/', '\\'])
}

/// A receipt's FILES: raw member names, each with a digest.
fn manifest(files: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        files.len() <= MAX_EXTERNAL_FILES
            && files
                .iter()
                .all(|(name, digest)| is_raw_member(name) && is_sha256_digest(digest)),
        "invalid external receipt file manifest"
    );
    Ok(())
}

/// The members' digests by name, as a receipt's manifest holds them.
fn digests(files: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, String> {
    files
        .iter()
        .map(|(name, content)| (name.clone(), sha256(content)))
        .collect()
}

/// The outputs directory check reads, its file names PRESENT and the
/// CONTENTS it accepted by name, held to the receipt's MANIFEST: the same
/// names, each with the digest fetch wrote. A substituted, changed,
/// dropped or added file refuses the hand-back, as does a receipt from
/// another fetch. A file check refused to read is refused by that alone.
pub fn bound(
    present: &BTreeSet<&str>,
    contents: &BTreeMap<String, Vec<u8>>,
    manifest: &BTreeMap<String, String>,
) -> Result<()> {
    let receipted: BTreeSet<&str> = manifest.keys().map(String::as_str).collect();
    let missing: Vec<_> = receipted.difference(present).copied().collect();
    ensure!(
        missing.is_empty(),
        "files of the external receipt are missing from the outputs: {}",
        missing.join(", ")
    );
    let extra: Vec<_> = present.difference(&receipted).copied().collect();
    ensure!(
        extra.is_empty(),
        "files not in the external receipt: {}",
        extra.join(", ")
    );
    for (name, content) in contents {
        ensure!(
            manifest.get(name) == Some(&sha256(content)),
            "{name} differs from the external receipt's digest"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub id: u64,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub record: Record,
    pub run_id: u64,
    pub attempt: u64,
    pub checked: Artifact,
    pub raw: Artifact,
    /// The extracted raw files by name, each with its digest: what check
    /// binds the outputs directory to, so that nothing between fetch and
    /// check can substitute, change, drop or add a file.
    pub files: BTreeMap<String, String>,
}

impl Receipt {
    pub fn load(path: &Path) -> Result<Self> {
        let receipt: Self =
            serde_json::from_slice(&crate::files::read_regular(path, MAX_RECEIPT)?)?;
        receipt.record.validate()?;
        ensure!(
            receipt.run_id > 0
                && receipt.attempt == 1
                && receipt.checked.id > 0
                && receipt.raw.id > 0
                && receipt.checked.id != receipt.raw.id,
            "invalid external receipt identities"
        );
        for artifact in [&receipt.checked, &receipt.raw] {
            ensure!(
                is_sha256_digest(&artifact.digest),
                "invalid API artifact digest"
            );
        }
        manifest(&receipt.files)?;
        if let Some(id) = receipt.record.returned_run_id {
            ensure!(
                receipt.run_id == id,
                "receipt disagrees with returned run ID"
            );
        }
        Ok(receipt)
    }
}

/// A small read-only transport/clock boundary, also used by offline fixtures.
trait Actions {
    fn now(&self) -> DateTime<Utc>;
    fn get(&mut self, path: &str) -> Result<Value>;
    fn download(&mut self, path: &str) -> Result<Vec<u8>>;
    fn wait(&mut self, until: DateTime<Utc>);
}

fn timely(record: &Record, now: DateTime<Utc>) -> Result<()> {
    window(record.dispatched_at, record.deadline, now)
}

fn window(dispatched_at: DateTime<Utc>, deadline: DateTime<Utc>, now: DateTime<Utc>) -> Result<()> {
    ensure!(
        now >= dispatched_at - chrono::Duration::seconds(120) && now < deadline,
        "external dispatch deadline passed or clock predates dispatch"
    );
    Ok(())
}

/// The rows of a paginated list, under KEY, or the whole answer if empty.
fn pages(api: &mut impl Actions, path: &str, key: &str) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    for page in 1..=MAX_PAGES {
        let sep = if path.contains('?') { '&' } else { '?' };
        let value = api.get(&format!("{path}{sep}per_page=100&page={page}"))?;
        let rows = if key.is_empty() { &value } else { &value[key] };
        let rows = rows.as_array().context("Actions API omitted list")?;
        ensure!(rows.len() <= 100, "Actions API page exceeds limit");
        result.extend(rows.iter().cloned());
        if rows.len() < 100 {
            return Ok(result);
        }
    }
    anyhow::bail!("Actions API pagination exceeds {MAX_PAGES} pages")
}

fn identity(run: &Value, record: &Record) -> Result<u64> {
    let id = run["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("missing run ID")?;
    ensure!(
        record.returned_run_id.is_none_or(|expected| expected == id),
        "wrong returned run ID"
    );
    ensure!(
        run["repository"]["id"] == record.repository_id
            && run["repository"]["full_name"] == record.repository
            && run["event"] == "workflow_dispatch"
            && run["path"] == record.workflow
            && run["head_branch"] == record.reference
            && run["head_sha"] == record.commit
            && run["triggering_actor"]["id"] == record.triggering_actor_id
            && run["run_attempt"] == 1,
        "external run repository/workflow/ref/head/actor/attempt mismatch"
    );
    let title = run["display_title"].as_str().context("missing run name")?;
    ensure!(
        title.ends_with(&format!(" [{}]", record.dispatch_id)),
        "external run dispatch ID mismatch"
    );
    let created: DateTime<Utc> = run["created_at"]
        .as_str()
        .context("missing creation time")?
        .parse()?;
    ensure!(
        created >= record.dispatched_at - chrono::Duration::seconds(120)
            && created <= record.dispatched_at + chrono::Duration::seconds(APPEAR_SECONDS)
            && created < record.deadline,
        "external run creation outside dispatch window"
    );
    let refs = run["referenced_workflows"]
        .as_array()
        .context("missing reusable workflow pins")?;
    for (path, sha) in [
        (record.actions_workflow.as_str(), &record.actions),
        (record.policy_workflow.as_str(), &record.agentic_job),
        (record.check_workflow.as_str(), &record.agentic_job),
    ] {
        let matching: Vec<_> = refs
            .iter()
            .filter(|r| {
                r["path"]
                    .as_str()
                    .is_some_and(|p| p.split('@').next() == Some(path))
            })
            .collect();
        ensure!(
            matching.len() == 1 && matching[0]["sha"] == *sha,
            "missing, duplicate or wrong reusable workflow pin for {path}"
        );
    }
    Ok(id)
}

fn matched(api: &mut impl Actions, record: &Record) -> Result<Option<u64>> {
    let workflow = record
        .workflow
        .rsplit('/')
        .next()
        .context("workflow filename")?;
    let created = format!(
        ">={}",
        (record.dispatched_at - chrono::Duration::seconds(120)).to_rfc3339()
    );
    let encoded: String = created
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let path = format!(
        "/repos/{}/actions/workflows/{workflow}/runs?event=workflow_dispatch&created={encoded}",
        record.repository
    );
    let suffix = format!(" [{}]", record.dispatch_id);
    let runs = pages(api, &path, "workflow_runs")?;
    let candidates: Vec<_> = runs
        .iter()
        .filter(|run| {
            run["display_title"]
                .as_str()
                .is_some_and(|name| name.ends_with(&suffix))
        })
        .collect();
    ensure!(
        candidates.len() <= 1,
        "multiple external runs match dispatch ID"
    );
    candidates
        .first()
        .map(|run| identity(run, record))
        .transpose()
}

fn artifacts(api: &mut impl Actions, record: &Record, run_id: u64) -> Result<(Artifact, Artifact)> {
    let path = format!("/repos/{}/actions/runs/{run_id}", record.repository);
    let jobs = pages(api, &format!("{path}/attempts/1/jobs"), "jobs")?;
    for name in [&record.check_job, &record.detect_job] {
        let jobs: Vec<_> = jobs.iter().filter(|job| job["name"] == *name).collect();
        ensure!(
            jobs.len() == 1
                && jobs[0]["run_id"] == run_id
                && jobs[0]["run_attempt"] == 1
                && jobs[0]["status"] == "completed"
                && jobs[0]["conclusion"] == "success",
            "external check/detect job absent, ambiguous, skipped or failed: {name}"
        );
    }
    let all = pages(api, &format!("{path}/artifacts"), "artifacts")?;
    let mut find = |suffix: &str| -> Result<Artifact> {
        let name = format!("{}{suffix}", record.artifact_prefix);
        let matches: Vec<_> = all.iter().filter(|a| a["name"] == name).collect();
        ensure!(
            matches.len() == 1,
            "missing or duplicate external artifact {name}"
        );
        let a = matches[0];
        ensure!(
            a["expired"] == false
                && a["workflow_run"]["id"] == run_id
                && a["workflow_run"]["head_sha"] == record.commit
                && a["workflow_run"]["head_branch"] == record.reference,
            "external artifact run mismatch or expired"
        );
        let id = a["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .context("missing artifact ID")?;
        let digest = a["digest"]
            .as_str()
            .context("missing API digest")?
            .to_owned();
        ensure!(is_sha256_digest(&digest), "invalid API digest");
        // The ID endpoint must agree with the run's list, not just its name.
        ensure!(
            api.get(&format!(
                "/repos/{}/actions/artifacts/{id}",
                record.repository
            ))? == *a,
            "artifact metadata changed"
        );
        Ok(Artifact { id, digest })
    };
    let checked = find("checked-outputs")?;
    let raw = find("safe-outputs")?;
    ensure!(
        checked.id != raw.id,
        "raw and checked artifacts have the same ID"
    );
    Ok((checked, raw))
}

/// What fetch verified: the receipt, the raw archive it names, and the
/// archive's members, which the receipt's manifest digests.
#[derive(Debug)]
struct Fetched<R = Receipt> {
    receipt: R,
    archive: Vec<u8>,
    files: BTreeMap<String, Vec<u8>>,
}

fn fetch(api: &mut impl Actions, record: &Record) -> Result<Fetched> {
    record.validate()?;
    timely(record, api.now())?;
    if let Some(id) = record.returned_run_id {
        let run = api.get(&format!("/repos/{}/actions/runs/{id}", record.repository))?;
        ensure!(
            identity(&run, record)? == id,
            "returned run identity mismatch"
        );
    }
    // The run must have been created within ten minutes of dispatch, which
    // `identity` holds it to; a reader queued past them still finds such a
    // run, and only stops waiting for one to appear, until the deadline.
    let appearance = record.dispatched_at + chrono::Duration::seconds(APPEAR_SECONDS);
    let run_id = loop {
        timely(record, api.now())?;
        if let Some(id) = matched(api, record)? {
            break id;
        }
        ensure!(
            api.now() < appearance,
            "no external run appeared within ten minutes"
        );
        api.wait(record.deadline.min(appearance));
    };
    let path = format!("/repos/{}/actions/runs/{run_id}", record.repository);
    loop {
        timely(record, api.now())?;
        let run = api.get(&path)?;
        ensure!(identity(&run, record)? == run_id, "run identity changed");
        if run["status"] == "completed" {
            ensure!(
                run["conclusion"] == "success",
                "external run did not succeed"
            );
            break;
        }
        api.wait(record.deadline);
    }
    let (checked, raw) = artifacts(api, record, run_id)?;
    let bytes = api.download(&format!(
        "/repos/{}/actions/artifacts/{}/zip",
        record.repository, raw.id
    ))?;
    ensure!(
        bytes.len() as u64 <= MAX_ARCHIVE,
        "raw artifact exceeds archive limit"
    );
    ensure!(
        raw.digest == sha256(&bytes),
        "raw artifact API digest mismatch"
    );
    let files = members(&bytes)?;
    // Re-list as well as re-read after download: a late duplicate or rerun
    // must not be released. Artifacts carry run IDs, not attempt IDs.
    ensure!(
        matched(api, record)? == Some(run_id),
        "external match changed at release"
    );
    ensure!(
        artifacts(api, record, run_id)? == (checked.clone(), raw.clone()),
        "external artifacts changed at release"
    );
    let run = api.get(&path)?;
    ensure!(
        identity(&run, record)? == run_id
            && run["status"] == "completed"
            && run["conclusion"] == "success",
        "external identity changed at release"
    );
    timely(record, api.now())?;
    let receipt = Receipt {
        record: record.clone(),
        run_id,
        attempt: 1,
        checked,
        raw,
        files: digests(&files),
    };
    Ok(Fetched {
        receipt,
        archive: bytes,
        files,
    })
}

struct Api {
    root: String,
    token: String,
    deadline: DateTime<Utc>,
    /// What a storage redirect must start with: [`STORAGE`], or a
    /// fixture's loopback address.
    storage: String,
    accept: &'static str,
}

const GITHUB_ACCEPT: &str = "application/vnd.github+json";

impl Api {
    fn request(
        &self,
        url: &str,
        authenticated: bool,
        max: u64,
    ) -> Result<(u16, Option<String>, Vec<u8>)> {
        let remaining = (self.deadline - Utc::now())
            .to_std()
            .context("external API deadline passed")?;
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(remaining.min(Duration::from_secs(15))))
            .max_redirects(0)
            .http_status_as_error(false)
            .build();
        let agent = ureq::Agent::new_with_config(config);
        let mut request = agent
            .get(url)
            .header("Accept", self.accept)
            .header("User-Agent", "agentic-job");
        if authenticated {
            request = request.header("Authorization", format!("Bearer {}", self.token));
        }
        let mut response = request.call().context("reading external Actions API")?;
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = response.body_mut().with_config().limit(max).read_to_vec()?;
        Ok((status, location, bytes))
    }
}

impl Actions for Api {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn get(&mut self, path: &str) -> Result<Value> {
        let (status, _, bytes) = self.request(&format!("{}{path}", self.root), true, MAX_PAGE)?;
        ensure!(
            status == 200,
            "Actions metadata request failed with HTTP {status}"
        );
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn download(&mut self, path: &str) -> Result<Vec<u8>> {
        let (status, location, bytes) =
            self.request(&format!("{}{path}", self.root), true, MAX_ARCHIVE)?;
        if status == 200 {
            return Ok(bytes);
        }
        ensure!(status == 302, "artifact download failed with HTTP {status}");
        let url = location.context("artifact API omitted redirect")?;
        ensure!(
            url.starts_with(&self.storage),
            "artifact redirect must go to storage over HTTPS"
        );
        // Never send the API credential to blob storage (or follow another redirect).
        let (status, _, bytes) = self.request(&url, false, MAX_ARCHIVE)?;
        ensure!(
            status == 200,
            "artifact storage download failed with HTTP {status}"
        );
        Ok(bytes)
    }

    fn wait(&mut self, until: DateTime<Utc>) {
        if let Ok(remaining) = (until - Utc::now()).to_std() {
            std::thread::sleep(POLL.min(remaining));
        }
    }
}

pub fn run(args: &Args) -> Result<Exit> {
    if args.forge == Caller::Gitlab {
        return gitlab::run(args);
    }
    let record = Record::load(&args.record)?;
    record.caller_env()?;
    timely(&record, Utc::now())?;
    let root =
        std::env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".to_owned());
    ensure!(
        root.starts_with("https://"),
        "external Actions API must use HTTPS"
    );
    let token = std::env::var("GH_TOKEN").context("read-only GH_TOKEN is required")?;
    ensure!(!token.is_empty(), "read-only GH_TOKEN is required");
    let mut api = Api {
        root: root.trim_end_matches('/').to_owned(),
        token,
        deadline: record.deadline,
        storage: STORAGE.to_owned(),
        accept: GITHUB_ACCEPT,
    };
    run_with(args, &record, &mut api)
}

fn run_with(args: &Args, record: &Record, api: &mut impl Actions) -> Result<Exit> {
    let fetched = fetch(api, record)?;
    write(args, &fetched.archive, &fetched.files, &fetched.receipt)
}

/// Write the outputs, the ARCHIVE and, last, the RECEIPT that authorizes
/// them, for either CI system. A refusal writes nothing.
fn write(
    args: &Args,
    archive: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
    receipt: &impl Serialize,
) -> Result<Exit> {
    let receipt = serde_json::to_vec(receipt)?;
    ensure!(
        receipt.len() as u64 <= MAX_RECEIPT,
        "external receipt exceeds {MAX_RECEIPT} bytes"
    );
    write_members(&args.outputs, files)?;
    // No partially verified result is written, and existing files are never replaced.
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.archive)?;
    file.write_all(archive)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.receipt)?;
    output.write_all(&receipt)?;
    Ok(Exit::Success)
}

/// Bound the physical directory before zip allocates its index or deduplicates
/// names. Raw hand-backs need only single-disk, non-ZIP64 archives. Requiring
/// the directory to end at the footer also excludes ZIP64 and offset repair.
fn raw_directory_entries(bytes: &[u8]) -> Result<usize> {
    const FOOTER: usize = 22;
    const HEADER: usize = 46;
    ensure!(
        bytes.len() as u64 <= MAX_ARCHIVE,
        "raw archive exceeds 128 MiB"
    );
    let end = bytes
        .len()
        .checked_sub(FOOTER)
        .context("missing ZIP footer")?;
    let end = (end.saturating_sub(u16::MAX as usize)..=end)
        .rev()
        .find(|&offset| {
            bytes[offset..].starts_with(b"PK\x05\x06")
                && offset
                    + FOOTER
                    + u16::from_le_bytes([bytes[offset + 20], bytes[offset + 21]]) as usize
                    == bytes.len()
        })
        .context("missing ZIP footer")?;
    let footer = &bytes[end..];
    let short = |offset| u16::from_le_bytes([footer[offset], footer[offset + 1]]) as usize;
    let word = |offset| {
        u32::from_le_bytes([
            footer[offset],
            footer[offset + 1],
            footer[offset + 2],
            footer[offset + 3],
        ]) as usize
    };
    ensure!(
        short(4) == 0 && short(6) == 0 && short(8) == short(10),
        "multi-disk ZIP refused"
    );
    let count = short(10);
    ensure!(
        count <= MAX_EXTERNAL_FILES,
        "raw artifact has more than {MAX_EXTERNAL_FILES} files"
    );
    let start = word(16);
    ensure!(
        start.checked_add(word(12)) == Some(end),
        "invalid or ZIP64 raw directory"
    );
    let mut directory = bytes
        .get(start..end)
        .context("invalid raw directory bounds")?;
    let mut names = std::collections::BTreeSet::new();
    let mut seen = 0;
    while !directory.is_empty() {
        seen += 1;
        ensure!(
            seen <= MAX_EXTERNAL_FILES,
            "raw artifact has more than {MAX_EXTERNAL_FILES} files"
        );
        ensure!(
            directory.len() >= HEADER && directory.starts_with(b"PK\x01\x02"),
            "invalid raw directory entry"
        );
        let short =
            |offset| u16::from_le_bytes([directory[offset], directory[offset + 1]]) as usize;
        let name_end = HEADER + short(28);
        let entry_end = name_end + short(30) + short(32);
        let name = directory
            .get(HEADER..name_end)
            .context("truncated raw directory name")?;
        ensure!(names.insert(name), "duplicate raw archive path");
        directory = directory
            .get(entry_end..)
            .context("truncated raw directory entry")?;
    }
    ensure!(seen == count, "raw directory entry count mismatch");
    Ok(count)
}

/// The raw archive's members by name, the whole archive validated before
/// any is returned.
fn members(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    use std::io::Read;
    let entries = raw_directory_entries(bytes)?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    ensure!(
        archive.len() == entries,
        "raw archive paths were deduplicated"
    );
    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let name = file.name().to_owned();
        ensure!(
            is_raw_member(&name)
                && file
                    .unix_mode()
                    .is_none_or(|m| m & 0o170000 == 0 || m & 0o170000 == 0o100000),
            "raw archive contains unexpected path/type"
        );
        total = total
            .checked_add(file.size())
            .context("raw archive size overflow")?;
        ensure!(total <= MAX_ARCHIVE, "expanded raw archive exceeds 128 MiB");
        let mut content = Vec::new();
        file.by_ref()
            .take(MAX_ARCHIVE + 1)
            .read_to_end(&mut content)?;
        ensure!(
            content.len() as u64 == file.size(),
            "raw archive member size mismatch"
        );
        ensure!(
            files.insert(name, content).is_none(),
            "duplicate raw archive path"
        );
    }
    Ok(files)
}

/// FILES as the new directory OUTPUTS: flat names and contents alone; no
/// paths, modes, symlinks or directories selected by the external
/// producer are restored.
fn write_members(outputs: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    std::fs::create_dir(outputs)?;
    for (name, content) in files {
        std::fs::write(outputs.join(name), content)?;
    }
    Ok(())
}
