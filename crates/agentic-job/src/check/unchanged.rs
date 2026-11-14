//! Inert unchanged candidates. The producer's clean-tree/completion declaration
//! is not independent evidence; only the pinned Actions results below are.

use anyhow::{Context, Result, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::policy::Continuation;

pub const FILE: &str = "unchanged-candidate.json";
pub const MAX_BYTES: u64 = 16 << 10;
const MAX_API_BYTES: u64 = 1 << 20;
const CHECKOUT: &str = "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub complete: bool,
    pub done: String,
    pub left: String,
    pub next: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub identity: Continuation,
    pub checkpoint: Checkpoint,
    pub stopped_early: Value,
}

impl Candidate {
    pub fn validate(&self, identity: &Continuation) -> Result<()> {
        ensure!(
            &self.identity == identity,
            "unchanged candidate identity mismatch"
        );
        ensure!(
            identity.verification.is_some(),
            "unchanged candidate without trusted verification"
        );
        ensure!(
            self.stopped_early.is_null(),
            "unchanged outcome stopped early"
        );
        ensure!(
            self.checkpoint.complete
                && !self.checkpoint.done.trim().is_empty()
                && self.checkpoint.left.trim().is_empty()
                && self.checkpoint.next.trim().is_empty()
                && self.checkpoint.done.len() <= 4096,
            "unchanged checkpoint must be explicitly complete with nothing left"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Checked {
    pub identity: Continuation,
    pub disposition: &'static str,
    pub verified_jobs: Vec<String>,
}

/// Six bounded GETs, no pagination, redirects, retries, downloads or execution.
/// A Link header or count mismatch refuses rather than silently truncating.
pub fn verify(identity: &Continuation) -> Result<Checked> {
    let root = std::env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".into());
    ensure!(
        root.starts_with("https://") || root.starts_with("http://127.0.0.1:"),
        "unsupported verification API origin"
    );
    let token = std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .context("independent verification requires a read-only API token")?;
    ensure!(!token.is_empty(), "empty verification API token");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    verify_with(identity, |path| {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .context("verification deadline exceeded")?;
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_global(Some(remaining.min(std::time::Duration::from_secs(10))))
                .max_redirects(0)
                .build(),
        );
        let mut response = agent
            .get(format!("{}{path}", root.trim_end_matches('/')))
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "agentic-job")
            .call()?;
        ensure!(
            response.status().as_u16() == 200 && !response.headers().contains_key("link"),
            "unavailable or paginated verification metadata"
        );
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_API_BYTES)
            .read_to_vec()?;
        Ok(serde_json::from_slice(&bytes)?)
    })
}

fn verify_with(
    identity: &Continuation,
    mut get: impl FnMut(&str) -> Result<Value>,
) -> Result<Checked> {
    let spec = identity
        .verification
        .as_ref()
        .context("missing trusted verification")?;
    spec.validate(identity)?;
    let prefix = format!("/repos/{}", spec.repository);
    let path = format!("{prefix}/actions/runs/{}", spec.run_id);
    let run = get(&path)?;
    ensure!(
        run["id"] == spec.run_id
            && run["run_attempt"] == spec.attempt
            && run["repository"]["full_name"] == spec.repository
            && run["head_repository"]["full_name"] == identity.repository
            && run["event"] == "push"
            && run["head_sha"] == spec.source
            && run["path"] == spec.workflow
            && run["status"] == "completed"
            && run["conclusion"] == "success",
        "verifier identity/source/result mismatch"
    );
    // For push, GitHub executes the workflow from this pushed commit. Unlike
    // pull_request_target's REST head_sha, it authenticates the workflow source
    // as well as the tested head. A current PR read binds that commit to the
    // separately admitted PR; the push need not have originated from a PR.
    let pull = get(&format!("{prefix}/pulls/{}", identity.pull_request))?;
    ensure!(
        pull["number"] == identity.pull_request
            && pull["state"] == "open"
            && pull["head"]["sha"] == identity.head
            && pull["head"]["repo"]["full_name"] == identity.repository
            && pull["base"]["repo"]["full_name"] == identity.repository,
        "stale or unsupported tested tree"
    );
    let source = get(&format!(
        "{prefix}/contents/{}?ref={}",
        spec.workflow, spec.source
    ))?;
    ensure!(
        source["type"] == "file"
            && source["path"] == spec.workflow
            && source["encoding"] == "base64",
        "unreadable verifier workflow"
    );
    let encoded = source["content"]
        .as_str()
        .context("missing workflow content")?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded.replace('\n', ""))?;
    // JSON is a YAML subset. Deliberately refuse general YAML, aliases and
    // duplicate fields until their executed semantics can be authenticated.
    let workflow: Value = serde_json::from_slice(&bytes)
        .context("verifier workflow must use the supported JSON subset of YAML")?;
    ensure!(
        bytes == serde_json::to_vec_pretty(&workflow)?,
        "workflow must be canonical pretty JSON without duplicate fields or trailing newline"
    );
    workflow_semantics(&workflow, identity)?;
    let jobs = get(&format!(
        "{path}/attempts/{}/jobs?per_page=100",
        spec.attempt
    ))?;
    let rows = jobs["jobs"].as_array().context("missing verifier jobs")?;
    ensure!(
        rows.len() <= 100 && jobs["total_count"].as_u64() == Some(rows.len() as u64),
        "truncated verifier jobs"
    );
    for name in &spec.required_jobs {
        let matches: Vec<_> = rows.iter().filter(|job| job["name"] == *name).collect();
        ensure!(
            matches.len() == 1,
            "missing or ambiguous required job {name}"
        );
        let job = matches[0];
        ensure!(
            job["run_id"] == spec.run_id
                && job["run_attempt"] == spec.attempt
                && job["head_sha"] == spec.source
                && job["status"] == "completed"
                && job["conclusion"] == "success",
            "required job {name} did not succeed on the admitted attempt"
        );
        let steps = job["steps"].as_array().context("missing job steps")?;
        let defined = workflow["jobs"][name]["steps"]
            .as_array()
            .context("missing defined steps")?;
        ensure!(
            steps.len() >= defined.len()
                && steps.len() <= defined.len() + 4
                && steps
                    .iter()
                    .all(|step| step["status"] == "completed" && step["conclusion"] == "success"),
            "skipped or failed verifier steps"
        );
        for expected in defined {
            let count = steps
                .iter()
                .filter(|step| step["name"] == expected["name"])
                .count();
            ensure!(
                count == 1,
                "missing or ambiguous executed verification step"
            );
        }
    }
    // Close rerun/head races; the trusted artifact layer separately admits the
    // producer attempt. Never accept an earlier verifier attempt after a rerun.
    ensure!(
        get(&path)? == run,
        "verifier run changed during verification"
    );
    ensure!(
        get(&format!("{prefix}/pulls/{}", identity.pull_request))? == pull,
        "tested pull request changed during verification"
    );
    Ok(Checked {
        identity: identity.clone(),
        disposition: "unchanged-verified",
        verified_jobs: spec.required_jobs.clone(),
    })
}

fn workflow_semantics(workflow: &Value, identity: &Continuation) -> Result<()> {
    let spec = identity
        .verification
        .as_ref()
        .context("missing verification")?;
    let object = workflow.as_object().context("invalid workflow")?;
    ensure!(
        object
            .keys()
            .all(|key| ["name", "on", "permissions", "jobs"].contains(&key.as_str()))
            && workflow["on"] == "push",
        "unsupported workflow event/semantics"
    );
    let jobs = workflow["jobs"]
        .as_object()
        .context("missing workflow jobs")?;
    ensure!(
        jobs.len() == spec.required_jobs.len(),
        "workflow jobs differ from required set"
    );
    for name in &spec.required_jobs {
        let job = jobs
            .get(name)
            .and_then(Value::as_object)
            .context("missing required workflow job")?;
        ensure!(
            job.keys().all(
                |key| ["name", "runs-on", "steps", "timeout-minutes", "permissions"]
                    .contains(&key.as_str())
            ) && job.get("name").is_none_or(|value| value == name),
            "unsupported required job semantics"
        );
        let steps = job
            .get("steps")
            .and_then(Value::as_array)
            .context("missing workflow steps")?;
        ensure!(
            steps.len() >= 2,
            "verifier needs checkout and verification steps"
        );
        let expected = serde_json::json!({"name": "Establish tested tree", "uses": CHECKOUT, "with": {
            "repository": "${{ github.repository }}", "ref": "${{ github.sha }}", "persist-credentials": false}});
        ensure!(
            steps[0] == expected,
            "push verifier must first checkout the authenticated event repository/SHA without credentials"
        );
        let mut names = std::collections::BTreeSet::from(["Establish tested tree"]);
        for step in &steps[1..] {
            let object = step.as_object().context("invalid verification step")?;
            ensure!(
                object
                    .keys()
                    .all(|key| ["name", "run", "shell"].contains(&key.as_str()))
                    && step["run"]
                        .as_str()
                        .is_some_and(|text| !text.trim().is_empty())
                    && step["name"]
                        .as_str()
                        .is_some_and(|name| !name.is_empty() && names.insert(name)),
                "unsupported conditional, action, unnamed or continued-error verification step"
            );
        }
        // Remaining semantics are reviewed and pinned by the trusted caller,
        // not inferred from a check name. No producer-provided source is run here.
    }
    Ok(())
}
