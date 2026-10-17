//! The job shape `workflows check` requires of one workflow file, ported
//! from workflow-compiler's `src/shape.rs` and the lints of its
//! `lib/gha.ncl` (cgwalters-forge/workflow-compiler, main). There they held
//! for compiled output; here they hold for a file written by hand.
//!
//! Every job either calls the reusable workflow, which holds the agent,
//! the check and the apply job, or secures its own host with secure-host
//! before its untrusted steps. Steps before secure-host run with the
//! runner user's root, and every step runs with the job's token, so the
//! rest keeps both from being handed away: what runs is pinned, text
//! others wrote is not spliced into a script, checkout leaves no token on
//! disk, and no agent runs outside the sandbox.
//!
//! Script expressions use a closed allowlist of direct property references;
//! unknown contexts and expression syntax are refused rather than interpreted.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

/// The reusable workflow, which a caller names at a commit.
pub const REUSABLE_WORKFLOW: &str = "cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml";

/// The action that hardens a job's host, at its old path and at its
/// standalone path in cgwalters-forge/actions (tracker#674); both take the
/// same inputs.
const SECURE_HOST_ACTIONS: &[&str] = &[
    "cgwalters-forge/agentic-job/secure-host",
    "cgwalters-forge/actions/secure-host",
];

/// Actions that may run before secure-host, while the runner's user still
/// has root: GitHub's own, which the runner image already trusts, for
/// fetching the source and installing toolchains. Any other action there
/// could leave a root process or a sudo rule behind that secure-host does
/// not undo.
const BEFORE_SECURE_HOST: &[&str] = &[
    "actions/cache",
    "actions/cache/restore",
    "actions/checkout",
    "actions/download-artifact",
    "actions/setup-dotnet",
    "actions/setup-go",
    "actions/setup-java",
    "actions/setup-node",
    "actions/setup-python",
];

/// Actions that run a coding agent on the runner, with the job's token
/// and files; only the reusable workflow's agent job runs one, in the
/// sandbox, with its outputs checked on another machine.
const AGENT_ACTIONS: &[&str] = &[
    "cgwalters-forge/agentic-job/prepare",
    "cgwalters-forge/agentic-job/run",
    "anthropics/claude-code-action",
    "anthropics/claude-code-base-action",
    "google-github-actions/run-gemini-cli",
    "openai/codex-action",
];

/// The keys these rules read, in jobs and steps. GitHub's own spelling is
/// lowercase; another one is refused rather than guessed at.
const KEYS: &[&str] = &[
    "defaults",
    "shell",
    "working-directory",
    "container",
    "continue-on-error",
    "env",
    "if",
    "jobs",
    "name",
    "permissions",
    "run",
    "services",
    "steps",
    "strategy",
    "uses",
    "with",
];

const CHECKOUT: &str = "actions/checkout";
const GITHUB_SCRIPT: &str = "actions/github-script";

const PIN_INSTEAD: &str = "name it by a full 40-hex commit, with the tag in a comment";
const CALL_INSTEAD: &str = "call cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@COMMIT, which runs the agent in the sandbox";

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("a valid pattern")
}

/// owner/repo[/path]@<40 hex>: a tag or branch can be moved, a commit can't.
static PINNED: LazyLock<Regex> =
    LazyLock::new(|| re(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$"));
// Match the entire expression, not just a safe-looking substring. No
// operators, functions, indexing or unknown properties are admitted.
static SAFE_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i-u)^(runner\.(os|arch|name|temp|tool_cache|debug|environment)|github\.(sha|run_id|run_number|run_attempt|repository|repository_id|repository_owner_id)|steps\.[a-z_][a-z0-9_-]*\.(outcome|conclusion)|job\.status)$",
    )
});
static MATRIX_PROPERTY: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i-u)^matrix\.[a-z_][a-z0-9_-]*$"));
static AGENT_COMMAND: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u:\b)agentic-job\s+run(?-u:\b)"));
/// The `secrets` context, as a whole word in an expression.
static SECRETS: LazyLock<Regex> = LazyLock::new(|| re(r"(?i-u)\bsecrets\b"));
static STATUS_FUNCTION: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i-u)\b(always|failure|cancelled|success)\s*\("));

fn is_secure_host(step: &Value) -> bool {
    step.get("uses")
        .and_then(Value::as_str)
        .is_some_and(|u| SECURE_HOST_ACTIONS.contains(&action_of(u).as_str()))
}

fn is_checkout(step: &Value) -> bool {
    step.get("uses")
        .and_then(Value::as_str)
        .is_some_and(|u| action_of(u) == CHECKOUT)
}

/// Whether `v` reads the `secrets` context in any expression, including an
/// `if:`, which is an expression without `${{ }}`. A word `secrets` inside
/// a string literal of an expression is refused too, rather than parsed,
/// and so is one anywhere after the first `${{`: a quoted `}}` does not end
/// an expression, so cutting at the first one would miss
/// `${{ format('}}', secrets.T) }}`.
fn reads_secrets(v: &Value) -> bool {
    match v {
        Value::String(s) => s
            .split_once("${{")
            .is_some_and(|(_, rest)| SECRETS.is_match(rest)),
        Value::Array(a) => a.iter().any(reads_secrets),
        Value::Object(o) => map_reads_secrets(o),
        _ => false,
    }
}

fn map_reads_secrets(map: &Map<String, Value>) -> bool {
    map.iter().any(|(key, value)| {
        (key == "if" && value.as_str().is_some_and(|s| SECRETS.is_match(s))) || reads_secrets(value)
    })
}

/// Inputs and expression-context properties are case-insensitive on GitHub.
fn folded_get<'a>(value: Option<&'a Value>, name: &str) -> Option<&'a Value> {
    value?
        .as_object()?
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value))
}

fn folded_duplicate(map: &Map<String, Value>) -> Option<&str> {
    let mut seen = std::collections::BTreeSet::new();
    map.keys()
        .find(|key| !seen.insert(key.to_ascii_lowercase()))
        .map(String::as_str)
}

/// GitHub adds success() only when no status function occurs. Without an
/// expression parser, accept only the standalone success() status guard;
/// even a positive success() elsewhere could be bypassed by an OR branch.
fn may_run_without_success(condition: &Value) -> bool {
    let Some(text) = condition.as_str() else {
        return !condition.is_boolean();
    };
    let text = text.trim();
    let text = text
        .strip_prefix("${{")
        .and_then(|s| s.strip_suffix("}}"))
        .unwrap_or(text)
        .trim();
    STATUS_FUNCTION.is_match(text) && !text.eq_ignore_ascii_case("success()")
}

fn may_ignore_failure(value: &Value) -> bool {
    !matches!(value, Value::Bool(false)) && value.as_str() != Some("false")
}

/// One refusal: where, what, and what to write instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub job: Option<String>,
    /// "step N", with the step's name or action when it has one.
    pub step: Option<String>,
    pub what: String,
    pub instead: String,
}

/// The `${{ }}` expressions in `v`, each up to the end of `v`.
fn expressions(v: &str) -> impl Iterator<Item = &str> {
    v.split("${{").skip(1)
}

fn allowed_script(e: &str, literal_matrix: bool) -> bool {
    let Some((inner, _)) = e.split_once("}}") else {
        return false;
    };
    let inner = inner.trim();
    SAFE_SCRIPT.is_match(inner) || (literal_matrix && MATRIX_PROPERTY.is_match(inner))
}

/// How an expression reads in a message: up to its `}}`, shortened.
fn shown(e: &str) -> String {
    let inner: String = e
        .split("}}")
        .next()
        .unwrap_or(e)
        .trim()
        .chars()
        .take(80)
        .collect();
    format!("${{{{ {inner} }}}}")
}

/// The action an `owner/repo[/path]@ref` names, lowercased as GitHub
/// compares owners and repositories.
fn action_of(uses: &str) -> String {
    uses.split('@').next().unwrap_or(uses).to_ascii_lowercase()
}

/// Every string in `v`, however deep.
fn strings(v: &Value) -> Vec<&str> {
    match v {
        Value::String(s) => vec![s],
        Value::Array(a) => a.iter().flat_map(strings).collect(),
        Value::Object(o) => o.values().flat_map(strings).collect(),
        _ => vec![],
    }
}

/// A key of `map` that is one of [`KEYS`] in another case.
fn miscased(map: &Map<String, Value>) -> Option<&str> {
    map.keys()
        .map(String::as_str)
        .find(|k| KEYS.contains(&k.to_ascii_lowercase().as_str()) && !KEYS.contains(k))
}

/// Why the secure-host step at `step` might leave the runner's user its
/// root or not run at all, if it might.
fn weakened(step: &Map<String, Value>) -> Option<String> {
    if step.contains_key("if") || step.contains_key("continue-on-error") {
        return Some("has `if:` or `continue-on-error:`, so the job may go on without it".into());
    }
    let with = step.get("with")?;
    let Some(inputs) = with.as_object() else {
        return Some("has non-map `with:` inputs that cannot be checked".into());
    };
    for (key, value) in inputs {
        if !safe_hardening_input(key, value) {
            return Some(format!(
                "sets `{key}` outside the closed hardening-input allowlist"
            ));
        }
    }
    None
}

/// Classified against secure-host/action.yml, which forwards to
/// cgwalters-forge/actions/secure-host, and the old action a commit before
/// the forward names. Only `check: true` means the same to both: the old
/// action's `lock`, `egress`, `deny-runner-metadata` and `build` fail the
/// forwarder, and at an old commit their admitted values were its defaults
/// or a choice of how to get the binary. Files, identities, service lists,
/// replacement binaries and images cannot be verified here; even a config
/// with an explicit lock can redirect that lock to another account. Refuse
/// them rather than trusting their contents or an expression that might
/// select them.
fn safe_hardening_input(key: &str, value: &Value) -> bool {
    let true_value = matches!(value, Value::Bool(true)) || value.as_str() == Some("true");
    key.eq_ignore_ascii_case("check") && true_value
}

/// Execution surfaces from GitHub's workflow syntax. `*` names a service;
/// github-script's input is conditional, unlike Docker entrypoint/args.
const EXECUTION_FIELDS: &[(&str, &str)] = &[
    ("step", "run"),
    ("step", "shell"),
    ("step", "working-directory"),
    ("step", "uses"),
    ("script", "with.script"),
    ("step", "with.entrypoint"),
    ("step", "with.args"),
    ("job", "uses"),
    ("job", "defaults.run.shell"),
    ("job", "defaults.run.working-directory"),
    ("workflow", "defaults.run.shell"),
    ("workflow", "defaults.run.working-directory"),
    ("job", "container"),
    ("job", "container.image"),
    ("job", "container.options"),
    ("job", "services.*.image"),
    ("job", "services.*.options"),
];

fn field_values<'a>(value: &'a Value, path: &str) -> Vec<&'a Value> {
    if path.is_empty() {
        return vec![value];
    }
    let (key, rest) = path.split_once('.').unwrap_or((path, ""));
    if key == "*" {
        return value
            .as_object()
            .into_iter()
            .flat_map(|m| m.values())
            .flat_map(|v| field_values(v, rest))
            .collect();
    }
    folded_get(Some(value), key)
        .into_iter()
        .flat_map(|v| field_values(v, rest))
        .collect()
}

/// One closed rule for every execution surface, including those otherwise
/// refused by the host-shape rules. Never follow env aliases into code.
fn execution_problems(value: &Value, scope: &str, literal_matrix: bool) -> Vec<String> {
    let mut problems = Vec::new();
    for &(at, path) in EXECUTION_FIELDS {
        if at != scope
            && !(at == "script"
                && scope == "step"
                && value
                    .get("uses")
                    .and_then(Value::as_str)
                    .is_some_and(|u| action_of(u) == GITHUB_SCRIPT))
        {
            continue;
        }
        for v in field_values(value, path) {
            // `container` has a shorthand string as well as a map.
            if path == "container" && v.is_object() {
                continue;
            }
            if !v.is_string() {
                problems.push(format!("has non-string execution field `{path}`"));
                continue;
            }
            for code in strings(v) {
                if let Some(e) =
                    expressions(code).find(|e| path == "uses" || !allowed_script(e, literal_matrix))
                {
                    problems.push(format!(
                        "expands {} into `{path}` outside the closed safe-context allowlist",
                        shown(e)
                    ));
                }
            }
        }
    }
    let known_step = [
        "id",
        "if",
        "name",
        "uses",
        "run",
        "working-directory",
        "shell",
        "with",
        "env",
        "continue-on-error",
        "timeout-minutes",
    ];
    let maps = if scope == "step" {
        vec![(value, known_step.as_slice(), "step")]
    } else {
        field_values(value, "defaults")
            .into_iter()
            .map(|v| (v, &["run"][..], "defaults"))
            .chain(
                field_values(value, "defaults.run")
                    .into_iter()
                    .map(|v| (v, &["shell", "working-directory"][..], "defaults.run")),
            )
            .collect()
    };
    for (v, known, at) in maps {
        if let Some(map) = v.as_object() {
            for key in map.keys().filter(|k| {
                !known.contains(&k.as_str())
                    && !(scope == "step" && known.contains(&k.to_ascii_lowercase().as_str()))
            }) {
                problems.push(format!("has unknown or miscased `{at}` key `{key}`"));
            }
        } else {
            problems.push(format!("has non-map `{at}`"));
        }
    }
    problems
}

/// The problems of `workflow`, a parsed workflow file.
pub fn check_workflow(workflow: &Value) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut add = |job: Option<&str>, step: Option<&str>, what: String, instead: &str| {
        problems.push(Problem {
            job: job.map(str::to_owned),
            step: step.map(str::to_owned),
            what,
            instead: instead.to_owned(),
        });
    };
    let Some(jobs) = workflow.get("jobs").and_then(Value::as_object) else {
        add(
            None,
            None,
            "has no map of jobs".into(),
            "write a workflow with a `jobs:` map",
        );
        return problems;
    };
    if let Some(key) = workflow.as_object().and_then(miscased) {
        add(
            None,
            None,
            format!("spells `{key}` in a case these rules do not read"),
            "write the key in lowercase",
        );
    }
    for what in execution_problems(workflow, "workflow", false) {
        add(
            None,
            None,
            what,
            "use literal defaults or a direct allowlisted context; remove unknown keys",
        );
    }
    for (name, job) in jobs {
        let job_name = Some(name.as_str());
        let literal_matrix = folded_get(job.get("strategy"), "matrix")
            .is_some_and(|m| m.is_object() && strings(m).iter().all(|s| !s.contains("${{")));
        for what in execution_problems(job, "job", literal_matrix) {
            add(
                job_name,
                None,
                what,
                "use literal execution fields or a direct allowlisted context; uses must be literal",
            );
        }
        let Some(job) = job.as_object() else {
            add(
                job_name,
                None,
                "is not a map".into(),
                "write the job as a map",
            );
            continue;
        };
        if let Some(key) = miscased(job) {
            add(
                job_name,
                None,
                format!("spells `{key}` in a case these rules do not read"),
                "write the key in lowercase",
            );
        }
        if !job.get("permissions").is_some_and(Value::is_object) {
            add(
                job_name,
                None,
                "has no `permissions:` map of its own, so it gets the workflow's or the repository's default".into(),
                "give the job a `permissions:` map of only what it needs, `{}` for none",
            );
        }
        if let Some(uses) = job.get("uses") {
            let uses = uses.as_str().unwrap_or("");
            if action_of(uses) != REUSABLE_WORKFLOW {
                add(
                    job_name,
                    None,
                    format!(
                        "calls {uses}, which neither is the reusable workflow nor runs secure-host"
                    ),
                    "call cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@COMMIT, or write the steps in a job that runs secure-host",
                );
            } else if !PINNED.is_match(uses) {
                add(
                    job_name,
                    None,
                    format!("calls {uses}, a ref that can move"),
                    PIN_INSTEAD,
                );
            }
            continue;
        }
        let steps: &[Value] = job
            .get("steps")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice);
        let secure_host = steps.iter().position(is_secure_host);
        let Some(secure_host) = secure_host else {
            add(
                job_name,
                None,
                "neither runs secure-host nor calls the reusable workflow".into(),
                "add a step `uses: cgwalters-forge/actions/secure-host@COMMIT` (or cgwalters-forge/agentic-job/secure-host@COMMIT) before the job's untrusted steps, or call cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@COMMIT",
            );
            continue;
        };
        for key in ["container", "services"] {
            if job.contains_key(key) {
                add(
                    job_name,
                    None,
                    format!(
                        "has `{key}:`, which fails once secure-host has stopped the container daemon"
                    ),
                    "install and run what it provides in steps of the job",
                );
            }
        }
        // The two-job pattern (tracker#674): the job that runs untrusted
        // steps holds nothing worth stealing. An OIDC request token mints
        // tokens for any audience, and a secret in its env or inputs is
        // readable by every later step, all of which run as one user.
        if let Some((key, _)) = job
            .get("permissions")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .find(|(k, v)| k.eq_ignore_ascii_case("id-token") && v.as_str() != Some("none"))
        {
            add(
                job_name,
                None,
                format!(
                    "grants `{key}`, so its untrusted steps can mint OIDC tokens for any audience"
                ),
                "request OIDC tokens in a separate job that runs none of this job's code",
            );
        }
        // A workflow-level `env:` reaches every job.
        if map_reads_secrets(job) || workflow.get("env").is_some_and(reads_secrets) {
            add(
                job_name,
                None,
                "reads `secrets`, which every step after secure-host can then read".into(),
                "use secrets only in a separate job that runs none of this job's code, passing it artifacts as data",
            );
        }
        if job.get("continue-on-error").is_some_and(may_ignore_failure) {
            add(
                job_name,
                None,
                "may ignore a hardening failure with job `continue-on-error:`".into(),
                "omit `continue-on-error:` or set it to false",
            );
        }
        for env in [workflow.get("env"), job.get("env")] {
            if let Some(key) = env.and_then(Value::as_object).and_then(folded_duplicate) {
                add(
                    job_name,
                    None,
                    format!("has case-folded duplicate env key `{key}`"),
                    "give every env key a unique case-insensitive name",
                );
            }
        }
        // Once a checkout has fetched the tree, which may be anyone's, any
        // other step before secure-host could run its code with root and
        // leave a root process or sudo rule behind that secure-host does
        // not undo.
        let first_checkout = steps.iter().position(is_checkout);
        for (i, step) in steps.iter().enumerate() {
            let step_value = step;
            let checkout = is_checkout(step_value);
            let after_checkout = first_checkout.is_some_and(|c| c < i) && i < secure_host;
            let Some(step) = step.as_object() else {
                add(
                    job_name,
                    Some(&format!("step {}", i + 1)),
                    "is not a map".into(),
                    "write the step as a map",
                );
                continue;
            };
            let label = step
                .get("name")
                .or_else(|| step.get("uses"))
                .and_then(Value::as_str)
                .or_else(|| {
                    let run = step.get("run").and_then(Value::as_str)?;
                    run.lines().next()
                })
                .map(|n| n.chars().take(60).collect::<String>())
                .map_or_else(
                    || format!("step {}", i + 1),
                    |n| format!("step {} ({n})", i + 1),
                );
            let at = Some(label.as_str());
            for key in ["with", "env"] {
                if let Some(duplicate) = step
                    .get(key)
                    .and_then(Value::as_object)
                    .and_then(folded_duplicate)
                {
                    add(
                        job_name,
                        at,
                        format!("has case-folded duplicate `{key}` key `{duplicate}`"),
                        "give every key a unique case-insensitive name",
                    );
                }
            }
            if i > secure_host && step.get("if").is_some_and(may_run_without_success) {
                add(
                    job_name,
                    at,
                    "may run when hardening did not succeed".into(),
                    "omit the condition, use only `success()`, or use a condition without status functions so GitHub adds success()",
                );
            }
            if i < secure_host
                && step
                    .get("continue-on-error")
                    .is_some_and(may_ignore_failure)
            {
                add(
                    job_name,
                    at,
                    "may silently ignore a failure before secure-host with `continue-on-error:`"
                        .into(),
                    "omit `continue-on-error:` or set it to false",
                );
            }
            if let Some(key) = miscased(step) {
                add(
                    job_name,
                    at,
                    format!("spells `{key}` in a case these rules do not read"),
                    "write the key in lowercase",
                );
            }
            if is_secure_host(step_value)
                && let Some(why) = weakened(step)
            {
                add(
                    job_name,
                    at,
                    format!("runs secure-host but {why}"),
                    "run it unconditionally; omit inputs or use only lock, egress, deny-runner-metadata and check set to true, and build set to true or false; unchecked config files are refused",
                );
            }
            if after_checkout && !checkout {
                add(
                    job_name,
                    at,
                    "runs after checkout but before secure-host, with root and the checked-out tree".into(),
                    "move it after the secure-host step, or before the checkout",
                );
            }
            let uses = step.get("uses").and_then(Value::as_str);
            let action = uses.map(action_of);
            if let Some(uses) = uses {
                if uses.starts_with("docker://") {
                    add(
                        job_name,
                        at,
                        format!(
                            "runs the Docker action {uses}, which fails once secure-host has stopped the container daemon"
                        ),
                        "install and run the tool in a `run:` step",
                    );
                } else if uses.starts_with("./") {
                    if i < secure_host {
                        add(
                            job_name,
                            at,
                            format!("runs the local action {uses} with root, before secure-host"),
                            "move it after the secure-host step",
                        );
                    }
                } else if !PINNED.is_match(uses) {
                    add(
                        job_name,
                        at,
                        format!("uses {uses}, a ref that can move"),
                        PIN_INSTEAD,
                    );
                } else if i < secure_host
                    && !BEFORE_SECURE_HOST.contains(&action.as_deref().unwrap_or(""))
                {
                    add(
                        job_name,
                        at,
                        format!(
                            "runs {uses} with root, before secure-host, and it is not one of GitHub's checkout, cache, download-artifact or setup actions"
                        ),
                        "move it after the secure-host step, where it runs without root",
                    );
                }
            }
            let run = step.get("run").and_then(Value::as_str);
            if action.as_deref().is_some_and(|a| {
                AGENT_ACTIONS
                    .iter()
                    .any(|agent| a == *agent || a.starts_with(&format!("{agent}/")))
            }) || run.is_some_and(|r| AGENT_COMMAND.is_match(r))
            {
                add(
                    job_name,
                    at,
                    "runs an agent outside the reusable workflow, on the runner with the job's token".into(),
                    CALL_INSTEAD,
                );
            }
            if action.as_deref() == Some(CHECKOUT) {
                let persist = folded_get(step.get("with"), "persist-credentials");
                if !matches!(persist, Some(Value::Bool(false)))
                    && persist.and_then(Value::as_str) != Some("false")
                {
                    add(
                        job_name,
                        at,
                        "checks out without `persist-credentials: false`, which leaves the job's token in .git/config".into(),
                        "add `with: {persist-credentials: false}`",
                    );
                }
            }
            for what in execution_problems(step_value, "step", literal_matrix) {
                add(
                    job_name,
                    at,
                    what,
                    "pass the value through the step's `env:` and use the quoted shell variable instead of `${{ env.* }}` (process.env in github-script)",
                );
            }
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflows::yaml;

    const PIN: &str = "0123456789abcdef0123456789abcdef01234567";
    const SECURE_HOST: &str = "cgwalters-forge/agentic-job/secure-host";

    #[test]
    fn secure_host_inputs_fail_closed() {
        for input in [
            "runner-user: decoy, lock: true, check: false",
            "runner-user: decoy",
            "check: false",
            "lock: false",
            "egress: false",
            "deny-runner-metadata: false",
            "config: host.toml, lock: true",
            "egress-policy: policy.toml",
            "stop-services: ssh",
            "sandbox-user: runner",
            "script: setup.sh",
            "binary: /tmp/decoy",
            "build: '${{ inputs.build }}'",
            "lock: true",
            "egress: true",
            "deny-runner-metadata: true",
            "build: true",
            "build: false",
            "image-archive: image.tar",
            "unknown: true",
        ] {
            // Both paths, so that neither can come to admit more inputs.
            for action in SECURE_HOST_ACTIONS {
                let text = workflow(&format!(
                    "permissions: {{}}\nsteps:\n  - run: sudo useradd --create-home decoy\n  - uses: {action}@PIN\n    with: {{{input}}}\n  - run: echo untrusted"
                ));
                assert!(
                    !check_workflow(&yaml::parse(&text).unwrap()).is_empty(),
                    "{text}"
                );
            }
        }
        for key in ["lock", "check", "egress", "deny-runner-metadata", "build"] {
            for value in [
                "true",
                "'true'",
                "false",
                "'false'",
                "''",
                "null",
                "[]",
                "{}",
                "'TRUE'",
                "'${{ inputs.value }}'",
            ] {
                let text = workflow(&format!(
                    "permissions: {{}}\nsteps:\n  - uses: {SECURE_HOST}@PIN\n    with: {{{key}: {value}}}"
                ));
                let allowed = key == "check" && ["true", "'true'"].contains(&value);
                assert_eq!(
                    check_workflow(&yaml::parse(&text).unwrap()).is_empty(),
                    allowed,
                    "{text}"
                );
            }
        }
        for action in [
            "someone/agentic-job/secure-host@PIN",
            "cgwalters-forge/agentic-job/secure-host@main",
        ] {
            let text = workflow(&format!("permissions: {{}}\nsteps:\n  - uses: {action}"));
            assert!(
                !check_workflow(&yaml::parse(&text).unwrap()).is_empty(),
                "{text}"
            );
        }
        for with in ["null", "[]", "'lock: true'"] {
            let text = workflow(&format!(
                "permissions: {{}}\nsteps:\n  - uses: {SECURE_HOST}@PIN\n    with: {with}"
            ));
            assert!(
                !check_workflow(&yaml::parse(&text).unwrap()).is_empty(),
                "{text}"
            );
        }
        let text = workflow(&format!(
            "permissions: {{}}\nsteps:\n  - uses: {SECURE_HOST}@PIN\n  - uses: {SECURE_HOST}@PIN\n    with: {{runner-user: decoy}}"
        ));
        assert!(!check_workflow(&yaml::parse(&text).unwrap()).is_empty());
    }

    #[test]
    fn every_execution_surface_fails_closed() {
        fn set(value: &mut Value, path: &str, text: &str) {
            let (key, rest) = path.split_once('.').unwrap_or((path, ""));
            let key = if key == "*" { "db" } else { key };
            if !value.is_object() {
                *value = serde_json::json!({});
            }
            if rest.is_empty() {
                value[key] = Value::String(text.into());
            } else {
                set(&mut value[key], rest, text);
            }
        }

        for &(scope, path) in EXECUTION_FIELDS {
            for (expression, literal_matrix, safe) in [
                ("github.event.issue.title", true, false),
                ("env.COPIED", true, false),
                ("matrix.command", false, false),
                ("matrix.command", true, true),
                ("github.sha", false, true),
            ] {
                let mut fixture = serde_json::json!({});
                if scope == "script" {
                    fixture["uses"] = Value::String(format!("{GITHUB_SCRIPT}@{PIN}"));
                }
                set(&mut fixture, path, &format!("${{{{ {expression} }}}}"));
                let problems = execution_problems(
                    &fixture,
                    if scope == "script" { "step" } else { scope },
                    literal_matrix,
                );
                assert_eq!(
                    problems.is_empty(),
                    safe && path != "uses",
                    "{scope}.{path}: {fixture}: {problems:?}"
                );
            }
        }
        for (scope, path) in [
            ("step", "future-code"),
            ("job", "defaults.future"),
            ("job", "defaults.run.future"),
            ("workflow", "defaults.future"),
            ("workflow", "defaults.run.future"),
        ] {
            let mut fixture = serde_json::json!({});
            set(&mut fixture, path, "echo unsafe");
            assert!(!execution_problems(&fixture, scope, false).is_empty());
        }
        let text = workflow(&format!(
            "permissions: {{}}\ndefaults: {{run: {{shell: \"bash -c '${{{{ github.event.issue.title }}}}' {{0}}\"}}}}\nsteps:\n  - uses: {SECURE_HOST}@PIN\n  - run: echo harmless"
        ));
        assert!(
            check_workflow(&yaml::parse(&text).unwrap())
                .iter()
                .any(|p| p.what.contains("defaults.run.shell"))
        );
    }

    /// A workflow of one job with `job` as its body, `@PIN` standing for a
    /// commit.
    fn workflow(job: &str) -> String {
        let job: String = job.lines().map(|l| format!("    {l}\n")).collect();
        format!(
            "on: push\njobs:\n  build:\n{}",
            job.replace("@PIN", &format!("@{PIN}"))
        )
    }

    const GOOD: &str = "\
permissions: {contents: read}
runs-on: ubuntu-26.04
steps:
  - uses: actions/setup-node@PIN
  - run: sudo apt-get install -y just
  - uses: actions/checkout@PIN
    with: {persist-credentials: false}
  - uses: cgwalters-forge/agentic-job/secure-host@PIN
  - uses: Swatinem/rust-cache@PIN
  - uses: ./local-action
  - env: {TITLE: '${{ github.event.issue.title }}'}
    run: echo \"$TITLE\" ${{ github.sha }} ${{ job.status }}
";

    /// Each fixture, and a phrase of each problem it must have; none for
    /// a job that passes.
    const CASES: &[(&str, &[&str])] = &[
        (GOOD, &[]),
        (
            "permissions: {}\nuses: cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@PIN\nwith: {task: '${{ inputs.task }}'}",
            &[],
        ),
        (
            "permissions: {}\nuses: CGWalters-Forge/agentic-job/.github/workflows/agentic-job.yml@main",
            &["a ref that can move"],
        ),
        (
            "permissions: {}\nuses: ./.github/workflows/agentic-job.yml",
            &["neither is the reusable workflow"],
        ),
        (
            "permissions: {}\nuses: someone/agentic-job/.github/workflows/agentic-job.yml@PIN",
            &["neither is the reusable workflow"],
        ),
        (
            "uses: cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@PIN",
            &["no `permissions:` map"],
        ),
        (
            "permissions: read-all\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN",
            &["no `permissions:` map"],
        ),
        (
            "permissions: {}\nsteps:\n  - run: make",
            &["neither runs secure-host"],
        ),
        ("permissions: {}", &["neither runs secure-host"]),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@v1",
            &["(cgwalters-forge/agentic-job/secure-host@v1) uses"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: Swatinem/rust-cache@PIN\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN",
            &["runs Swatinem/rust-cache@"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: ./setup\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN",
            &["local action ./setup with root"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n  - uses: actions/upload-artifact@v4",
            &["actions/upload-artifact@v4, a ref that can move"],
        ),
        (
            "permissions: {}\ncontainer: fedora\nservices: {db: {image: postgres}}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n  - uses: docker://alpine@sha256:00",
            &["`container:`", "`services:`", "Docker action"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: actions/checkout@PIN\n  - uses: actions/checkout@PIN\n    with: {persist-credentials: 'true'}\n  - uses: actions/checkout@PIN\n    with: {persist-credentials: '${{ inputs.p }}'}\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN",
            &["step 1 (actions/checkout@", "step 2 (", "step 3 ("],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n  - run: echo ${{ github.event.pull_request.title }}\n  - run: echo ${{ github.head_ref }}\n  - run: echo ${{ inputs.x }}\n  - run: echo ${{ needs.a.outputs.b }}\n  - run: echo ${{ toJSON(github) }}\n  - run: echo ${{ GITHUB . EVENT . comment.body }}",
            &[
                "github.event.pull_request.title",
                "github.head_ref",
                "inputs.x",
                "needs.a.outputs.b",
                "toJSON(github)",
                "GITHUB . EVENT . comment.body",
            ],
        ),
        (
            "permissions: {}\nenv: {T: '${{ github.event.issue.title }}'}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n  - run: echo ${{ env.t }}\n  - run: echo ${{ toJSON(env) }}\n  - env: {T: fixed}\n    run: echo ${{ env.T }}\n  - uses: actions/github-script@PIN\n    with: {script: 'core.info(\"${{ github.event.comment.body }}\")'}",
            &["env.t", "toJSON(env)", "env.T", "github.event.comment.body"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n  - uses: cgwalters-forge/agentic-job/run@PIN\n  - uses: anthropics/claude-code-action@PIN\n  - run: agentic-job run --policy p.json",
            &[
                "(cgwalters-forge/agentic-job/run@",
                "(anthropics/claude-code-action@",
                "(agentic-job run",
            ],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n    with: {lock: false}\n  - uses: actions/checkout@PIN\n    if: false\n    with: {persist-credentials: false}",
            &["sets `lock` outside"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n    if: github.event_name == 'push'",
            &["`if:` or `continue-on-error:`"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n    continue-on-error: true",
            &["`if:` or `continue-on-error:`"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n    with: {config: host.toml}",
            &["sets `config` outside"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n    with: {config: host.toml, lock: 'true'}",
            &["sets `config` outside"],
        ),
        (
            "permissions: {}\nenv: {A: '${{ github.event.issue.title }}'}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n  - env: {B: '${{ env.A }}'}\n    run: echo ${{ env.B }}",
            &["env.B"],
        ),
        (
            "permissions: {}\nstrategy: {matrix: {t: '${{ fromJSON(needs.a.outputs.l) }}'}}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n  - run: echo ${{ matrix.t }}",
            &["matrix.t"],
        ),
        (
            "permissions: {}\nstrategy: {matrix: {t: [a, b]}}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n  - run: echo ${{ matrix.t }}",
            &[],
        ),
        (
            "Permissions: {}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n  - Uses: evil/x@v1\n    name: x",
            &[
                "spells `Permissions`",
                "no `permissions:` map",
                "step 2 (x) spells `Uses`",
            ],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n  - uses: Anthropics/claude-code-action/base@PIN",
            &["runs an agent"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: CGWalters-Forge/actions/secure-host@PIN\n    with: {check: true}\n  - run: make",
            &[],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: someone/actions/secure-host@PIN\n  - run: make",
            &["neither runs secure-host"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/actions/secure-host@PIN\n  - run: make",
            &[],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/actions/secure-host@v1\n  - run: make",
            &["(cgwalters-forge/actions/secure-host@v1) uses"],
        ),
        // Lookalikes of the new path: another repository of the owner, a
        // sibling or nested action, and the repository's root action.
        (
            "permissions: {}\nsteps:\n  - uses: cgwalters-forge/actions-fork/secure-host@PIN\n  - uses: cgwalters-forge/actions/secure-host-x@PIN\n  - uses: cgwalters-forge/actions/secure-host/x@PIN\n  - uses: cgwalters-forge/actions@PIN\n  - run: make",
            &[
                "neither runs secure-host nor calls the reusable workflow: add a step `uses: cgwalters-forge/actions/secure-host@COMMIT` (or cgwalters-forge/agentic-job/secure-host@COMMIT)",
            ],
        ),
        // The checker is not told which repository it checks, so not even
        // the repository that defines secure-host may name it by local
        // path: there it takes an exemption.
        (
            "permissions: {}\nsteps:\n  - uses: ./secure-host\n  - run: make",
            &["neither runs secure-host"],
        ),
        (
            "permissions: {}\nsteps:\n  - uses: actions/checkout@PIN\n    with: {persist-credentials: false}\n  - run: make deps\n  - uses: actions/setup-go@PIN\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN",
            &[
                "step 2 (make deps) runs after checkout",
                "step 3 (actions/setup-go@",
            ],
        ),
        (
            "permissions: {contents: read, id-token: none}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN\n  - run: cat secrets.md",
            &[],
        ),
        (
            "permissions: {contents: read, id-token: write}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN",
            &["grants `id-token`"],
        ),
        (
            "permissions: {ID-TOKEN: read}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN",
            &["grants `ID-TOKEN`"],
        ),
        (
            "permissions: {id-token: ~}\nsteps:\n  - uses: cgwalters-forge/agentic-job/secure-host@PIN",
            &["grants `id-token`"],
        ),
    ];

    #[test]
    fn hardening_bypasses() {
        for (job_extra, before, after, refused) in [
            ("", "", "if: success()", false),
            ("", "", "if: '${{ SUCCESS() }}'", false),
            ("", "", "if: github.ref == 'refs/heads/main'", false),
            ("", "", "continue-on-error: true", false),
            (
                "",
                "  - run: exit 1\n    continue-on-error: true\n",
                "",
                true,
            ),
            (
                "",
                "  - run: exit 1\n    continue-on-error: '${{ inputs.ignore }}'\n",
                "",
                true,
            ),
            (
                "",
                "  - run: echo ok\n    continue-on-error: false\n",
                "",
                false,
            ),
            ("continue-on-error: true\n", "", "", true),
            ("continue-on-error: false\n", "", "", false),
            ("env: {A: safe, a: unsafe}\n", "", "", true),
        ] {
            let text = workflow(&format!(
                "permissions: {{}}\n{job_extra}steps:\n{before}  - uses: {SECURE_HOST}@PIN\n  - run: echo ok\n    {after}"
            ));
            let problems = check_workflow(&yaml::parse(&text).unwrap());
            assert_eq!(!problems.is_empty(), refused, "{text}: {problems:?}");
        }
        for (step, want) in [
            ("with: {LOCK: false}", "sets `LOCK`"),
            ("with: {Config: host.toml}", "sets `Config`"),
            ("with: {lock: true, LOCK: false}", "case-folded duplicate"),
        ] {
            let text = workflow(&format!(
                "permissions: {{}}\nsteps:\n  - uses: {SECURE_HOST}@PIN\n    {step}"
            ));
            let problems = check_workflow(&yaml::parse(&text).unwrap());
            assert!(
                problems.iter().any(|p| p.what.contains(want)),
                "{text}: {problems:?}"
            );
        }
        for condition in [
            "always()",
            "failure()",
            "cancelled()",
            "!cancelled()",
            "${{ success() || always() }}",
            "${{ ! failure() }}",
            "${{ ALWAYS () }}",
        ] {
            let text = workflow(&format!(
                "permissions: {{}}\nsteps:\n  - run: exit 1\n  - uses: {SECURE_HOST}@PIN\n  - if: '{condition}'\n    run: ./untrusted-code"
            ));
            let problems = check_workflow(&yaml::parse(&text).unwrap());
            assert!(
                problems
                    .iter()
                    .any(|p| p.what.contains("hardening did not succeed")),
                "{text}: {problems:?}"
            );
        }
        for (extra, want) in [
            (
                "  - uses: actions/github-script@PIN\n    with: {Script: 'core.info(\"${{ github.event.comment.body }}\")'}",
                "expands",
            ),
            (
                "  - uses: actions/checkout@PIN\n    with: {persist-credentials: false, PERSIST-CREDENTIALS: true}",
                "case-folded duplicate",
            ),
            (
                "  - env: {TITLE: safe, title: '${{ inputs.title }}'}\n    run: echo ok",
                "case-folded duplicate",
            ),
        ] {
            let text = workflow(&format!(
                "permissions: {{}}\nsteps:\n  - uses: {SECURE_HOST}@PIN\n{extra}"
            ));
            let problems = check_workflow(&yaml::parse(&text).unwrap());
            assert!(
                problems.iter().any(|p| p.what.contains(want)),
                "{text}: {problems:?}"
            );
        }
        let text = workflow(&format!(
            "permissions: {{}}\nsteps:\n  - uses: actions/checkout@PIN\n    with: {{PERSIST-CREDENTIALS: false}}\n  - uses: {SECURE_HOST}@PIN\n    with: {{Check: true}}"
        ));
        assert!(check_workflow(&yaml::parse(&text).unwrap()).is_empty());
    }

    #[test]
    fn secrets_are_refused() {
        for (workflow_env, step, refused) in [
            ("", "run: echo ok", false),
            ("", "run: cat secrets.md", false),
            ("", "env: {secrets: x}\n    run: echo \"$secrets\"", false),
            (
                "",
                "env: {T: '${{ secrets.TOKEN }}'}\n    run: echo ok",
                true,
            ),
            (
                "",
                "env: {T: '${{ SECRETS.token }}'}\n    run: echo ok",
                true,
            ),
            (
                "",
                "env: {T: '${{ toJSON(secrets) }}'}\n    run: echo ok",
                true,
            ),
            (
                "",
                "uses: someone/x@PIN\n    with: {token: 'x ${{ secrets[''T''] }}'}",
                true,
            ),
            ("", "if: secrets.TOKEN != ''\n    run: echo ok", true),
            (
                "",
                "env: {T: \"${{ format('}}', secrets.TOKEN) }}\"}\n    run: echo ok",
                true,
            ),
            ("env: {T: '${{ secrets.TOKEN }}'}\n", "run: echo ok", true),
            ("env: {T: '${{ github.sha }}'}\n", "run: echo ok", false),
        ] {
            let text = format!(
                "{workflow_env}{}",
                workflow(&format!(
                    "permissions: {{}}\nsteps:\n  - uses: {SECURE_HOST}@PIN\n  - {step}"
                ))
            );
            let problems = check_workflow(&yaml::parse(&text).unwrap());
            assert_eq!(
                problems.iter().any(|p| p.what.contains("reads `secrets`")),
                refused,
                "{text}: {problems:?}"
            );
            assert_eq!(problems.is_empty(), !refused, "{text}: {problems:?}");
        }
        let text = workflow(&format!(
            "permissions: {{}}\nenv: {{T: '${{{{ secrets.T }}}}'}}\nsteps:\n  - uses: {SECURE_HOST}@PIN"
        ));
        assert!(!check_workflow(&yaml::parse(&text).unwrap()).is_empty());
    }

    #[test]
    fn job_shapes() {
        for (job, wants) in CASES {
            let text = workflow(job);
            let problems = check_workflow(&yaml::parse(&text).unwrap());
            let lines: Vec<String> = problems
                .iter()
                .map(|p| {
                    format!(
                        "{} {}: {}",
                        p.step.as_deref().unwrap_or(""),
                        p.what,
                        p.instead
                    )
                })
                .collect();
            assert_eq!(lines.len(), wants.len(), "{job}\n{lines:#?}");
            for want in *wants {
                assert!(
                    lines.iter().any(|l| l.contains(want)),
                    "{job}\nno problem has {want:?}: {lines:#?}"
                );
            }
            for p in &problems {
                assert_eq!(p.job.as_deref(), Some("build"));
                assert!(!p.instead.is_empty());
            }
        }
    }

    #[test]
    fn whole_workflow_problems() {
        for (text, want) in [
            ("on: push\n", "no map of jobs"),
            ("on: push\njobs: [a]\n", "no map of jobs"),
            ("on: push\njobs:\n  a: x\n", "is not a map"),
        ] {
            let problems = check_workflow(&yaml::parse(text).unwrap());
            assert_eq!(problems.len(), 1, "{text}: {problems:?}");
            assert!(problems[0].what.contains(want), "{text}: {problems:?}");
        }
    }

    #[test]
    fn script_allowlist() {
        let allowed = [
            "runner.os",
            "runner.arch",
            "runner.name",
            "runner.temp",
            "runner.tool_cache",
            "runner.debug",
            "runner.environment",
            "github.sha",
            "github.run_id",
            "github.run_number",
            "github.run_attempt",
            "github.repository",
            "github.repository_id",
            "github.repository_owner_id",
            "steps.build.outcome",
            "steps.build.conclusion",
            "job.status",
            "matrix.target",
        ];
        let refused = [
            "env.TITLE",
            "secrets.TOKEN",
            "vars.COMMAND",
            "steps.build.outputs.code",
            "github.ref",
            "github.actor",
            "github.workspace",
            "runner.unknown",
            "job.unknown",
            "strategy.job-index",
            "matrix",
            "toJSON(matrix)",
            "github.sha || inputs.code",
            "github['sha']",
            "github.sha }} ${{ inputs.code",
        ];
        for (context, safe) in allowed
            .into_iter()
            .map(|s| (s, true))
            .chain(refused.into_iter().map(|s| (s, false)))
        {
            for script in [false, true] {
                let step = if script {
                    format!(
                        "uses: actions/github-script@PIN\n    with:\n      script: |\n        core.info(\"${{{{ {context} }}}}\")"
                    )
                } else {
                    format!("run: echo ${{{{ {context} }}}}")
                };
                let text = workflow(&format!(
                    "permissions: {{}}\nstrategy: {{matrix: {{target: [linux]}}}}\nsteps:\n  - uses: {SECURE_HOST}@PIN\n  - {step}"
                ));
                let problems = check_workflow(&yaml::parse(&text).unwrap());
                assert_eq!(problems.is_empty(), safe, "{text}: {problems:?}");
            }
        }
        let shadow = format!(
            "env: {{TITLE: '${{{{ github.event.issue.title }}}}'}}\n{}",
            workflow(&format!(
                "permissions: {{}}\nsteps:\n  - uses: {SECURE_HOST}@PIN\n  - env: {{TITLE: safe, COPIED: '${{{{ env.TITLE }}}}'}}\n    run: echo \"${{{{ env.COPIED }}}}\""
            ))
        );
        let problems = check_workflow(&yaml::parse(&shadow).unwrap());
        assert_eq!(problems.len(), 1);
        assert!(problems[0].what.contains("env.COPIED"));
        for (e, want) in [
            (" github.event.issue.title }}", true),
            (" github.event.pull_request.number }}", true),
            (" GITHUB.EVENT.number }}", true),
            (" github.head_ref }}", true),
            (" toJSON(github) }}", true),
            (" inputs.x }}", true),
            (" needs.a.outputs.b }}", true),
            (" needs.a.result }}", true),
            (" github.sha }}", false),
        ] {
            assert_eq!(!allowed_script(e, false), want, "{e}");
        }
    }

    #[test]
    fn repository_scripts_use_safe_contexts() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for entry in std::fs::read_dir(root.join(".github/workflows")).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            let workflow = yaml::parse(&text).unwrap();
            for (name, job) in workflow["jobs"].as_object().unwrap() {
                let literal_matrix = folded_get(job.get("strategy"), "matrix").is_some_and(|m| {
                    m.is_object() && strings(m).iter().all(|s| !s.contains("${{"))
                });
                for step in job["steps"].as_array().into_iter().flatten() {
                    let script = step["uses"]
                        .as_str()
                        .is_some_and(|s| action_of(s) == GITHUB_SCRIPT)
                        .then(|| folded_get(step.get("with"), "script"))
                        .flatten()
                        .and_then(Value::as_str);
                    for code in step["run"].as_str().into_iter().chain(script) {
                        for e in expressions(code) {
                            assert!(
                                allowed_script(e, literal_matrix),
                                "{} job {name}: {}",
                                path.display(),
                                shown(e)
                            );
                        }
                    }
                }
            }
        }
    }
}
