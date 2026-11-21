//! The GitLab CI form of caller-owned correlation (specs/gitlab-caller.md):
//! a caller pipeline's record of the producer pipeline it created, held to
//! the GitLab API before and again after the agent job's archive is fetched
//! by job ID. GitLab publishes no artifact digest, so the receipt's is the
//! fetcher's own: it names the bytes received, not where they came from.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    Actions, Api, Args, MAX_ARCHIVE, MAX_LIFETIME_SECONDS, MAX_RECORD, hex, pages, window,
};
use crate::exit::Exit;
use crate::policy::{COMMIT_RE, ExternalRun, Forge, GitlabCaller, Policy};

#[cfg(test)]
mod tests;

/// The record's and the receipt's `forge`.
pub const FORGE: &str = "gitlab";

const API: &str = "/api/v4";
const ACCEPT: &str = "application/json";
/// A token that can read the caller's and the producer's pipelines and
/// jobs, and nothing more: never the publisher's.
const TOKEN: &str = "GITLAB_READ_TOKEN";
const SERVER_ENV: &str = "CI_SERVER_URL";
const PROJECT_ENV: &str = "CI_PROJECT_ID";
const PIPELINE_ENV: &str = "CI_PIPELINE_ID";
/// The pipeline variables that pin the producer's agentic-job binary.
const RELEASE_VARIABLE: &str = "AGENTIC_JOB_RELEASE";
const SHA256_VARIABLE: &str = "AGENTIC_JOB_SHA256";
const MAX_VARIABLES: usize = 100;
const MAX_VARIABLE_VALUE: usize = 10_000;
const MAX_CONFIG_PATH: usize = 1024;
/// The clock skew allowed between the dispatch job and GitLab.
const SKEW_SECONDS: i64 = 120;
const SUCCESS: &str = "success";
/// Pipeline statuses that may still end in success; any other refuses.
const ACTIVE: &[&str] = &[
    "created",
    "waiting_for_resource",
    "preparing",
    "pending",
    "running",
    "scheduled",
    "manual",
];

/// Trusted input, written by the caller's dispatch job when it created the
/// producer pipeline, and never sent to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub forge: String,
    pub server: String,
    pub caller_project: String,
    pub caller_project_id: u64,
    pub caller_pipeline_id: u64,
    pub caller_job_id: u64,
    pub profile_commit: String,
    pub kind: String,
    pub target_repository: String,
    pub target_branch: String,
    pub base_commit: String,
    pub item: u64,
    pub project: String,
    pub project_id: u64,
    pub reference: String,
    pub commit: String,
    /// Empty for GitLab's default `.gitlab-ci.yml`.
    pub ci_config_path: String,
    pub pipeline_id: u64,
    pub user_id: u64,
    pub variables: BTreeMap<String, String>,
    pub agentic_job: String,
    pub agent_job: String,
    pub check_job: String,
    pub detect_job: String,
    pub dispatched_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
}

impl Record {
    fn load(path: &Path) -> Result<Self> {
        let record: Self = serde_json::from_slice(&crate::files::read_regular(path, MAX_RECORD)?)?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.forge == FORGE,
            "GitLab record requires forge {FORGE:?}"
        );
        ensure!(
            GitlabCaller::is_server(&self.server),
            "invalid GitLab server URL"
        );
        ensure!(
            self.kind == "implement",
            "external correlation supports only implement"
        );
        for path in [&self.caller_project, &self.project, &self.target_repository] {
            ensure!(Forge::Gitlab.is_repo(path), "invalid record project path");
        }
        for sha in [
            &self.profile_commit,
            &self.base_commit,
            &self.commit,
            &self.agentic_job,
        ] {
            ensure!(
                COMMIT_RE.is_match(sha),
                "record requires full lowercase commit pins"
            );
        }
        ensure!(
            [
                self.caller_project_id,
                self.caller_pipeline_id,
                self.caller_job_id,
                self.project_id,
                self.pipeline_id,
                self.user_id,
                self.item,
            ]
            .iter()
            .all(|id| *id > 0),
            "record IDs must be positive"
        );
        for text in [
            &self.reference,
            &self.target_branch,
            &self.agent_job,
            &self.check_job,
            &self.detect_job,
        ] {
            ensure!(
                !text.is_empty() && text.len() <= 256 && !text.chars().any(char::is_control),
                "invalid record ref/job"
            );
        }
        ensure!(
            BTreeSet::from([&self.agent_job, &self.check_job, &self.detect_job]).len() == 3,
            "agent, check and detect must be distinct jobs"
        );
        ensure!(
            self.ci_config_path.len() <= MAX_CONFIG_PATH
                && !self.ci_config_path.chars().any(char::is_control),
            "invalid CI configuration path"
        );
        ensure!(
            self.variables.len() <= MAX_VARIABLES
                && self.variables.iter().all(|(key, value)| {
                    !key.is_empty()
                        && key.len() <= 255
                        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                        && value.len() <= MAX_VARIABLE_VALUE
                        && !value.contains('\0')
                }),
            "invalid pipeline variables"
        );
        ensure!(
            self.variables
                .get(RELEASE_VARIABLE)
                .is_some_and(|release| !release.is_empty())
                && self
                    .variables
                    .get(SHA256_VARIABLE)
                    .is_some_and(|sha| hex(sha, 64)),
            "pipeline variables must pin {RELEASE_VARIABLE} and {SHA256_VARIABLE}"
        );
        let lifetime = (self.deadline - self.dispatched_at).num_seconds();
        ensure!(
            (1..=MAX_LIFETIME_SECONDS).contains(&lifetime),
            "external lifetime must be at most 330 minutes"
        );
        Ok(())
    }

    fn timely(&self, now: DateTime<Utc>) -> Result<()> {
        window(self.dispatched_at, self.deadline, now)
    }
}

/// The fetcher-computed identity of the agent job's archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    pub size: u64,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub record: Record,
    pub agent_job_id: u64,
    pub check_job_id: u64,
    pub detect_job_id: u64,
    pub raw: Archive,
}

impl Receipt {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let receipt: Self = serde_json::from_slice(bytes)?;
        receipt.record.validate()?;
        ensure!(
            BTreeSet::from([
                receipt.agent_job_id,
                receipt.check_job_id,
                receipt.detect_job_id
            ])
            .len()
                == 3
                && receipt.agent_job_id > 0
                && receipt.check_job_id > 0
                && receipt.detect_job_id > 0
                && receipt.raw.size <= MAX_ARCHIVE
                && receipt
                    .raw
                    .digest
                    .strip_prefix("sha256:")
                    .is_some_and(|d| hex(d, 64)),
            "invalid external receipt identities"
        );
        Ok(receipt)
    }

    /// Hold the receipt to this caller pipeline and POLICY's target.
    pub fn admit(self, policy: &Policy) -> Result<ExternalRun> {
        let record = self.record;
        caller_env(
            &record.server,
            record.caller_project_id,
            record.caller_pipeline_id,
        )?;
        super::target(policy, &record.target_repository, &record.target_branch)?;
        Ok(ExternalRun {
            caller_repository: record.caller_project,
            caller_run_id: record.caller_pipeline_id,
            caller_attempt: 1,
            repository: record.project,
            run_id: record.pipeline_id,
            base_commit: record.base_commit,
            raw_digest: self.raw.digest,
            gitlab: Some(GitlabCaller {
                server: record.server,
                caller_project_id: record.caller_project_id,
            }),
        })
    }
}

/// This job runs in the record's caller pipeline. GitLab keeps a pipeline's
/// ID across job retries, so later caller jobs may reuse the record, and
/// another pipeline cannot.
pub fn caller_env(server: &str, project_id: u64, pipeline_id: u64) -> Result<()> {
    let var = |name: &str| std::env::var(name).with_context(|| format!("missing {name}"));
    ensure!(
        var(SERVER_ENV)? == server
            && var(PROJECT_ENV)?.parse::<u64>()? == project_id
            && var(PIPELINE_ENV)?.parse::<u64>()? == pipeline_id,
        "dispatch record belongs to another caller pipeline"
    );
    Ok(())
}

fn jobs_path(project_id: u64, pipeline_id: u64) -> String {
    format!("/projects/{project_id}/pipelines/{pipeline_id}/jobs?include_retried=true")
}

/// The dispatch job ran once. A retried one may have created a second
/// producer pipeline with a fresh record, and GitLab apply has no re-run
/// guard to stop a second draft.
fn caller(api: &mut impl Actions, record: &Record) -> Result<()> {
    let jobs = pages(
        api,
        &jobs_path(record.caller_project_id, record.caller_pipeline_id),
        "",
    )?;
    let dispatch: Vec<_> = jobs
        .iter()
        .filter(|job| job["id"] == record.caller_job_id)
        .collect();
    ensure!(
        dispatch.len() == 1 && dispatch[0]["pipeline"]["id"] == record.caller_pipeline_id,
        "dispatch job is not in the caller pipeline"
    );
    let name = &dispatch[0]["name"];
    ensure!(
        name.is_string() && jobs.iter().filter(|job| job["name"] == *name).count() == 1,
        "dispatch job was retried"
    );
    Ok(())
}

/// Steps 2 to 4 of the re-derivation: the producer project and its CI
/// configuration path, the pipeline and its variables. Returns the
/// pipeline's status.
fn pipeline(api: &mut impl Actions, record: &Record) -> Result<String> {
    let project = api.get(&format!("/projects/{}", record.project_id))?;
    // GitLab omits the key from a reader without `read_code`: that is no
    // evidence of the default, which it returns as null or empty.
    let config = match project.get("ci_config_path") {
        None => bail!("producer project omits ci_config_path; the read token needs read_code"),
        Some(Value::Null) => "",
        Some(path) => path.as_str().context("invalid ci_config_path")?,
    };
    ensure!(
        project["id"] == record.project_id
            && project["path_with_namespace"] == record.project
            && config == record.ci_config_path,
        "producer project ID, path or CI configuration path mismatch"
    );
    let path = format!(
        "/projects/{}/pipelines/{}",
        record.project_id, record.pipeline_id
    );
    let pipeline = api.get(&path)?;
    ensure!(
        pipeline["id"] == record.pipeline_id
            && pipeline["project_id"] == record.project_id
            && pipeline["sha"] == record.commit
            && pipeline["ref"] == record.reference
            && pipeline["tag"] == false
            && pipeline["source"] == "api"
            && pipeline["user"]["id"] == record.user_id
            && (pipeline["yaml_errors"].is_null() || pipeline["yaml_errors"] == ""),
        "producer pipeline project/sha/ref/source/user mismatch or YAML errors"
    );
    let created: DateTime<Utc> = pipeline["created_at"]
        .as_str()
        .context("missing pipeline creation time")?
        .parse()?;
    ensure!(
        created >= record.dispatched_at - chrono::Duration::seconds(SKEW_SECONDS)
            && created < record.deadline,
        "producer pipeline creation outside dispatch window"
    );
    // GitLab sets these only at creation: the exact set the record names.
    let variables = api.get(&format!("{path}/variables"))?;
    let variables = variables
        .as_array()
        .context("GitLab API omitted pipeline variables")?;
    let mut seen = BTreeSet::new();
    ensure!(
        variables.len() == record.variables.len()
            && variables.iter().all(|variable| {
                variable["variable_type"] == "env_var"
                    && variable["key"].as_str().is_some_and(|key| {
                        seen.insert(key)
                            && record
                                .variables
                                .get(key)
                                .is_some_and(|value| variable["value"] == *value)
                    })
            }),
        "producer pipeline variables differ from the record"
    );
    pipeline["status"]
        .as_str()
        .map(str::to_owned)
        .context("missing pipeline status")
}

/// The agent, check and detect jobs, each the only one of its name with
/// its retries, with the agent job's archive size.
#[derive(Debug, PartialEq, Eq)]
struct Jobs {
    agent: u64,
    check: u64,
    detect: u64,
    size: u64,
}

fn jobs(api: &mut impl Actions, record: &Record) -> Result<Jobs> {
    let all = pages(api, &jobs_path(record.project_id, record.pipeline_id), "")?;
    let find = |name: &str| -> Result<&Value> {
        let named: Vec<_> = all.iter().filter(|job| job["name"] == name).collect();
        ensure!(named.len() == 1, "producer job missing or retried: {name}");
        let job = named[0];
        ensure!(
            job["status"] == SUCCESS
                && job["pipeline"]["id"] == record.pipeline_id
                && job["pipeline"]["sha"] == record.commit
                && job["pipeline"]["ref"] == record.reference
                && job["user"]["id"] == record.user_id
                && job["erased_at"].is_null(),
            "producer job failed, erased or from another pipeline/user: {name}"
        );
        Ok(job)
    };
    let id = |job: &Value| {
        job["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .context("missing job ID")
    };
    let agent = find(&record.agent_job)?;
    let check = id(find(&record.check_job)?)?;
    let detect = id(find(&record.detect_job)?)?;
    if let Some(expiry) = agent["artifacts_expire_at"].as_str() {
        ensure!(
            expiry.parse::<DateTime<Utc>>()? > api.now(),
            "agent job archive expired"
        );
    }
    let size = agent["artifacts_file"]["size"]
        .as_u64()
        .context("agent job has no archive")?;
    ensure!(size <= MAX_ARCHIVE, "raw artifact exceeds archive limit");
    Ok(Jobs {
        agent: id(agent)?,
        check,
        detect,
        size,
    })
}

fn fetch(api: &mut impl Actions, record: &Record) -> Result<(Receipt, Vec<u8>)> {
    record.validate()?;
    record.timely(api.now())?;
    caller(api, record)?;
    loop {
        record.timely(api.now())?;
        let status = pipeline(api, record)?;
        if status == SUCCESS {
            break;
        }
        if !ACTIVE.contains(&status.as_str()) {
            bail!("producer pipeline did not succeed: {status}");
        }
        api.wait(record.deadline);
    }
    let found = jobs(api, record)?;
    let bytes = api.download(&format!(
        "/projects/{}/jobs/{}/artifacts",
        record.project_id, found.agent
    ))?;
    ensure!(
        bytes.len() as u64 <= MAX_ARCHIVE,
        "raw artifact exceeds archive limit"
    );
    ensure!(
        bytes.len() as u64 == found.size,
        "raw artifact size differs from the job's listed archive"
    );
    // Re-derive after download: a retry or a changed setting since must
    // not be released.
    ensure!(
        pipeline(api, record)? == SUCCESS && jobs(api, record)? == found,
        "producer pipeline or jobs changed at release"
    );
    // The caller can retry dispatch without changing the first producer.
    caller(api, record)?;
    record.timely(api.now())?;
    let computed = digest(&SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok((
        Receipt {
            record: record.clone(),
            agent_job_id: found.agent,
            check_job_id: found.check,
            detect_job_id: found.detect,
            raw: Archive {
                size: found.size,
                digest: format!("sha256:{computed}"),
            },
        },
        bytes,
    ))
}

pub fn run(args: &Args) -> Result<Exit> {
    let record = Record::load(&args.record)?;
    caller_env(
        &record.server,
        record.caller_project_id,
        record.caller_pipeline_id,
    )?;
    record.timely(Utc::now())?;
    let token = std::env::var(TOKEN).with_context(|| format!("read-only {TOKEN} is required"))?;
    ensure!(!token.is_empty(), "read-only {TOKEN} is required");
    let (receipt, bytes) = fetch(&mut api(&record.server, token, record.deadline), &record)?;
    super::write(args, &bytes, &receipt)
}

fn api(server: &str, token: String, deadline: DateTime<Utc>) -> Api {
    Api {
        root: format!("{server}{API}"),
        token,
        deadline,
        accept: ACCEPT,
    }
}
