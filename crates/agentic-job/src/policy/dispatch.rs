//! Read-only dispatch admission, before agent setup. This is a snapshot,
//! not a lock: two dispatches can still race after their listings.
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

fn target(inputs: &Value) -> Result<Option<(String, String)>> {
    // Only item dispatchers expose this contract. Generic callers may use
    // arbitrary item labels and resolve repo/kind in their workflow instead.
    let Some(kind) = inputs.get("kind").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Some(item) = inputs.get("item").and_then(Value::as_str) else {
        return Ok(None);
    };
    let repo = inputs["item-repo"]
        .as_str()
        .filter(|s| !s.is_empty())
        .or_else(|| inputs["repo"].as_str())
        .unwrap_or_default();
    ensure!(
        super::REPO_RE.is_match(repo) && super::PULL_NUMBER_RE.is_match(item),
        "::error::invalid dispatch target {repo}#{item}; expected OWNER/NAME#N"
    );
    Ok(Some((format!("{repo}#{item}"), kind.to_owned())))
}

fn conflict<'a>(runs: &'a [Value], id: u64, item: &str, kind: &str) -> Option<&'a Value> {
    runs.iter().find(|run| {
        run["id"].as_u64() != Some(id)
            && matches!(
                run["status"].as_str(),
                Some("queued" | "in_progress" | "pending" | "waiting" | "requested")
            )
            && run["display_title"].as_str().is_some_and(|title| {
                let mut words = title.split_whitespace();
                words.next() == Some(kind)
                    && words.next().is_some_and(|s| s.eq_ignore_ascii_case(item))
            })
    })
}

fn api(endpoint: &str) -> Result<Value> {
    let output = std::process::Command::new("gh")
        .args(["api", endpoint])
        .output()
        .context("listing dispatch runs")?;
    ensure!(
        output.status.success(),
        "::error::could not read dispatch runs: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).context("parsing dispatch runs")
}

pub(super) fn admission(dedupe: bool) -> Result<()> {
    if std::env::var("GITHUB_EVENT_NAME").ok().as_deref() != Some("workflow_dispatch") {
        return Ok(());
    }
    let event: Value = serde_json::from_slice(&std::fs::read(
        std::env::var("GITHUB_EVENT_PATH").context("GITHUB_EVENT_PATH")?,
    )?)?;
    let Some((item, kind)) = target(&event["inputs"])? else {
        return Ok(());
    };
    if !dedupe {
        return Ok(());
    }
    let repo = std::env::var("GITHUB_REPOSITORY").context("GITHUB_REPOSITORY")?;
    let id: u64 = std::env::var("GITHUB_RUN_ID")
        .context("GITHUB_RUN_ID")?
        .parse()?;
    let current = api(&format!("repos/{repo}/actions/runs/{id}"))?;
    let workflow = current["workflow_id"]
        .as_u64()
        .context("run has no workflow_id")?;
    // GitHub caps filtered run searches at 1,000. Refuse on overflow rather
    // than silently admitting a duplicate outside our bounded snapshot.
    for status in ["queued", "in_progress", "pending", "waiting", "requested"] {
        for page in 1..=10 {
            let listing = api(&format!(
                "repos/{repo}/actions/workflows/{workflow}/runs?status={status}&per_page=100&page={page}"
            ))?;
            ensure!(
                listing["total_count"].as_u64().is_some_and(|n| n <= 1000),
                "::error::too many dispatch runs to deduplicate"
            );
            let runs = listing["workflow_runs"]
                .as_array()
                .context("missing workflow_runs")?;
            if let Some(other) = conflict(runs, id, &item, &kind) {
                bail!(
                    "::error::dispatch {kind} {item} already in flight: {}",
                    other["html_url"].as_str().context("run has no URL")?
                );
            }
            if runs.len() < 100 {
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn listings() {
        for (id, status, title, refused) in [
            (2, "in_progress", "triage a/b#3", true),
            (2, "queued", "triage A/B#3", true),
            (2, "in_progress", "review a/b#3", false),
            (2, "completed", "triage a/b#3", false),
            (1, "in_progress", "triage a/b#3", false),
            (2, "queued", "triage a/b#30", false),
        ] {
            assert_eq!(
                conflict(
                    &[json!({"id":id,"status":status,"display_title":title})],
                    1,
                    "a/b#3",
                    "triage"
                )
                .is_some(),
                refused,
                "{title} {status}"
            );
        }
    }

    #[test]
    fn targets() {
        assert!(target(&json!({"item":"example"})).unwrap().is_none());
        for (repo, item, valid) in [
            ("a/b", "3", true),
            ("GraphQL:", "3", false),
            ("a/b", "0", false),
            ("a/b", "GraphQL:", false),
        ] {
            assert_eq!(
                target(&json!({"repo":repo,"item":item,"kind":"triage"})).is_ok(),
                valid
            );
        }
    }
}
