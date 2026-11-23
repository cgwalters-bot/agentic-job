//! A fix can change its own PR's metadata instead of pushing a patch.
//! Validate both before and after the lossy collector, and again at apply.

use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde_json::{Map, Value};

use crate::contract::{Policy, Push};

pub const UPDATE: &str = "update_pull_request";

pub const MARKERS: [&str; 4] = [
    super::APPLIED_MARKER,
    "gh-aw-workflow-id",
    "gh-aw-agentic-workflow",
    "gh-aw-execution",
];

// A PR body can close other issues on merge. This intentionally rejects
// even quoted closing syntax; no Markdown context from an agent is trusted.
static CLOSING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)[:\s*_`~\[\(<\\]+(?:(?:[\w./-]+)?#[0-9]+|https?://[^\s<>]+/(?:issues|pull)/[0-9]+)")
        .expect("valid closing directive pattern")
});

static DIGEST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-f0-9]{64}$").expect("valid digest pattern"));

pub(crate) fn has_closing_directive(body: &str) -> bool {
    CLOSING.is_match(body)
}

pub fn scope<'a>(policy: &'a Policy, output: &str) -> Option<&'a Push> {
    policy
        .safe_outputs
        .push_to_pull_request_branch
        .as_ref()
        .filter(|push| output == UPDATE && push.fix_pull_request.is_some())
}

pub(crate) fn request<'a>(
    item: &'a Map<String, Value>,
    policy: &Policy,
) -> Result<(&'a str, &'a str)> {
    let output = super::item_type(item);
    let push = scope(policy, output).context("no scoped fix PR authority for this request")?;
    ensure!(
        push.fix_pull_request
            .as_ref()
            .and_then(|fix| fix.snapshot_digest.as_deref())
            .is_some_and(|digest| DIGEST.is_match(digest)),
        "scoped PR text replacement requires a trusted snapshot with no existing closing directives; report the needed edit instead"
    );
    let number = item.get("pull_request_number");
    ensure!(
        number.and_then(Value::as_str) == Some(push.target.as_str())
            || number
                .and_then(Value::as_u64)
                .is_some_and(|n| n.to_string() == push.target),
        "scoped {output} must name the policy's pull_request_number"
    );
    ensure!(
        item.get("repo")
            .and_then(Value::as_str)
            .is_some_and(|repo| repo.eq_ignore_ascii_case(&policy.repo)),
        "scoped {output} must target the policy's repository"
    );
    ensure!(
        item.keys().all(|key| matches!(
            key.as_str(),
            "type" | "repo" | "pull_request_number" | "body" | "title" | "operation"
        )),
        "scoped {output} has unsupported fields"
    );
    let body = item
        .get("body")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .context("scoped PR text replacement requires a nonempty body")?;
    let safe_text = |text: &str| {
        let lower = text.to_ascii_lowercase();
        !MARKERS.iter().any(|marker| lower.contains(marker))
    };
    ensure!(
        safe_text(body),
        "scoped {output} body contains reserved metadata"
    );
    ensure!(
        item.get("operation").is_none_or(|op| op == "replace"),
        "scoped PR text changes must replace the title and body"
    );
    let title = item
        .get("title")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty() && !text.contains(char::is_control))
        .context("scoped PR text changes require a nonempty, single-line title")?;
    ensure!(
        safe_text(title),
        "scoped {output} title contains reserved metadata"
    );
    ensure!(
        !has_closing_directive(body),
        "scoped PR text replacement contains a closing directive"
    );
    Ok((title, body))
}
