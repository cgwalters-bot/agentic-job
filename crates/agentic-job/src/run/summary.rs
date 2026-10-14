//! `summary.json` (`agent-run-summary/v1`) and `summary.md`: what a run
//! came to, from its recorded session (`acp.jsonl` and `harness.json`),
//! what `run` measured, the agent's `outcome.json` and the inference
//! proxy's record of the run.
//!
//! The schema is the old tree's (`bot-harness summary`), field for field:
//! `bot-runs` and whoever else reads a run's summary keep working. It is
//! built from the redacted copies of the session's files, so nothing gets
//! into it that the transcript does not have.

use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};

use super::handback::OMITTED_BINARY_FILES;
use super::inference::RECORD_SCHEMA;
use crate::session::digest::{Digest, Dir, cut};
use crate::session::{Outcome, Record, RunResult};

pub const SCHEMA: &str = "agent-run-summary/v1";
pub const SUMMARY_FILE: &str = "summary.json";
pub const MARKDOWN_FILE: &str = "summary.md";
/// `tokens_source`: counted by the inference proxy, which saw every
/// request, or reported by the agent itself, which is only its word.
const TOKENS_PRAXIS: &str = "praxis";
const TOKENS_UNVERIFIED: &str = "unverified";
/// The fields of the proxy's record that the summary keeps: numbers and
/// fixed words only, fit for a footer on a pull request.
const PRAXIS_FIELDS: &[&str] = &["schema", "state", "requests", "unmetered", "tokens"];
/// At most this many of the slowest tool calls are listed.
const MAX_SLOWEST: usize = 10;
/// The fields `--meta` gives: on GitHub the run's id, attempt and URL,
/// the caller's own name for the run, and the size of its machine.
pub const META_FIELDS: &[&str] = &["run_id", "run_attempt", "run_url", "item", "cores"];

/// What `run` measured or was configured with.
#[derive(Debug, Clone)]
pub struct Measured {
    pub context: Vec<Value>,
    /// The `--meta` file.
    pub meta: Value,
    pub repo: String,
    pub base: String,
    /// `branch` or `analysis`.
    pub workflow: &'static str,
    pub agent: String,
    /// The model asked for, if the agent does not say which it runs.
    pub model: Option<String>,
    pub started_at: String,
    pub finished_at: String,
    pub duration_s: u64,
    pub aic_budget: Option<f64>,
    pub aic_pricing: &'static str,
    /// The paths the agent changed.
    pub files: Vec<String>,
    /// `{base, bytes}`, `{base, error}` or null.
    pub patch: Value,
    /// Requests the egress proxy refused, per host.
    pub egress_denied: Vec<Value>,
    /// What of the agent's own logs the transcript has
    /// (`agent_log::collect`), or null.
    pub agent_logs: Value,
    pub redactions: usize,
}

/// Reads a JSON Lines file; lines that are not what is asked for are
/// skipped.
pub fn read_jsonl<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut out = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.with_context(|| format!("reading {}", path.display()))?;
        if let Ok(value) = serde_json::from_str(&line) {
            out.push(value);
        }
    }
    Ok(out)
}

/// Replays a recorded session through the digest.
pub fn replay(records: &[Record]) -> Digest {
    let mut digest = Digest::new();
    for record in records {
        if let Some(msg) = &record.msg {
            digest.feed(record.ts, record.dir, msg);
        }
    }
    digest.finish();
    digest
}

/// Token counts from the proxy's record of the run: what the provider
/// reported for every request, which the agent cannot under-report.
/// `input` is the uncached part; the proxy has no cache-write count.
fn praxis_tokens(record: &Value) -> Value {
    let tokens = &record["tokens"];
    json!({
        "input": tokens["input"],
        "output": tokens["output"],
        "cache_read": tokens["cache_read"],
        "cache_write": null,
    })
}

/// The part of the proxy's record that the summary keeps, or null if it
/// is not one.
fn praxis_summary(record: &Value) -> Value {
    if record["schema"] != RECORD_SCHEMA {
        return Value::Null;
    }
    let fields: Map<String, Value> = PRAXIS_FIELDS
        .iter()
        .map(|key| ((*key).to_owned(), record[*key].clone()))
        .collect();
    Value::Object(fields)
}

/// Token counts from the `session/prompt` response (a draft ACP field).
fn acp_usage(usage: &Value) -> Value {
    json!({
        "input": usage["inputTokens"],
        "output": usage["outputTokens"],
        "cache_read": usage["cachedReadTokens"],
        "cache_write": usage["cachedWriteTokens"],
    })
}

pub struct Inputs<'a> {
    pub records: &'a [Record],
    /// None when the session left no result.
    pub result: Option<&'a RunResult>,
    pub measured: &'a Measured,
    /// The agent's `outcome.json`.
    pub outcome: &'a Value,
    /// The inference proxy's record of the run, if it gave one.
    pub usage: Option<&'a Value>,
}

pub fn summarize(inputs: &Inputs) -> Value {
    let digest = replay(inputs.records);
    let measured = inputs.measured;
    let result = inputs.result.map_or(Outcome::Failure, |r| r.result);
    let message = inputs.result.and_then(|r| r.message.clone());

    let praxis = inputs.usage.map_or(Value::Null, praxis_summary);
    let (tokens, source) = match &digest.usage {
        _ if !praxis.is_null() => (praxis_tokens(&praxis), json!(TOKENS_PRAXIS)),
        Some(usage) => (acp_usage(usage), json!(TOKENS_UNVERIFIED)),
        None => (
            json!({"input": null, "output": null, "cache_read": null, "cache_write": null}),
            Value::Null,
        ),
    };

    // Per tool: calls, errors, seconds.
    let mut tools: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    for call in &digest.calls {
        let tool = tools.entry(call.display_name()).or_default();
        tool.0 += 1;
        tool.1 += u64::from(call.error == Some(true));
        tool.2 += call.duration_s.unwrap_or(0);
    }
    let tools: Map<String, Value> = tools
        .into_iter()
        .map(|(name, (calls, errors, secs))| {
            (
                name,
                json!({"calls": calls, "errors": errors, "duration_s": secs}),
            )
        })
        .collect();
    let mut timed: Vec<_> = digest
        .calls
        .iter()
        .filter(|call| call.duration_s.is_some())
        .collect();
    timed.sort_by_key(|call| std::cmp::Reverse(call.duration_s));
    let slowest: Vec<Value> = timed
        .iter()
        .take(MAX_SLOWEST)
        .map(|call| {
            json!({"tool": call.display_name(), "summary": call.summary, "duration_s": call.duration_s})
        })
        .collect();

    let mut failures: Vec<Value> = digest
        .calls
        .iter()
        .filter(|call| call.error == Some(true))
        .map(|call| {
            let message = format!(
                "{}: {}",
                call.display_name(),
                call.message.as_deref().unwrap_or("")
            );
            json!({"kind": "tool_error", "message": cut(&message)})
        })
        .collect();
    let why = |default: &str| cut(message.as_deref().unwrap_or(default));
    match result {
        Outcome::Timeout => {
            failures.push(json!({"kind": "timeout", "message": why("the agent hit the timeout")}));
        }
        Outcome::Budget => {
            failures.push(json!({"kind": "budget", "message": why("the agent went over budget")}));
        }
        Outcome::Failure | Outcome::Cancelled => {
            failures.push(json!({"kind": "agent_exit", "message": why("the agent failed")}));
        }
        Outcome::Success => {}
    }

    let tests: Vec<Value> = inputs.outcome["tests"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|test| test.is_object())
        .map(|test| {
            let command = match &test["command"] {
                Value::String(command) => cut(command),
                other => cut(&other.to_string()),
            };
            // Numbers or nothing: a reader that checks the types drops
            // every test for one that has a word here.
            let number = |key: &str| Some(&test[key]).filter(|v| v.is_number()).cloned();
            json!({"command": command, "exit_code": number("exit_code"), "duration_s": number("duration_s")})
        })
        .collect();

    let mut s = Map::new();
    s.insert("schema".into(), json!(SCHEMA));
    for key in META_FIELDS {
        s.insert((*key).into(), measured.meta[*key].clone());
    }
    s.insert("repo".into(), json!(measured.repo));
    s.insert("context".into(), json!(measured.context));
    s.insert("base".into(), json!(measured.base));
    s.insert("workflow".into(), json!(measured.workflow));
    s.insert("agent".into(), json!(measured.agent));
    s.insert("started_at".into(), json!(measured.started_at));
    // The first task dispatched to the agent, after clone and registration.
    let first_step = inputs.records.iter().find(|record| {
        matches!(record.dir, Dir::Send)
            && record
                .msg
                .as_ref()
                .is_some_and(|msg| msg["method"] == "session/prompt")
    });
    s.insert(
        "agent_first_step_at".into(),
        json!(first_step.map(|record| record.ts)),
    );
    s.insert("finished_at".into(), json!(measured.finished_at));
    s.insert("duration_s".into(), json!(measured.duration_s));
    // A whole number as one, as the old tree had it.
    let aic_budget = measured.aic_budget.map(|budget| {
        if budget.fract() == 0.0 && budget >= 0.0 && budget < u32::MAX.into() {
            json!(budget as u64)
        } else {
            json!(budget)
        }
    });
    s.insert("aic_budget".into(), json!(aic_budget));
    s.insert("aic_pricing".into(), json!(measured.aic_pricing));
    s.insert("files".into(), json!(measured.files));
    s.insert("patch".into(), measured.patch.clone());
    if let Some(omitted) = inputs.outcome.get(OMITTED_BINARY_FILES) {
        s.insert(OMITTED_BINARY_FILES.into(), omitted.clone());
    }
    s.insert("egress_denied".into(), json!(measured.egress_denied));
    s.insert("agent_logs".into(), measured.agent_logs.clone());
    s.insert("redactions".into(), json!(measured.redactions));
    // The model the agent says the session runs, else the one asked for.
    let model = digest.model.clone().or_else(|| measured.model.clone());
    s.insert("model".into(), json!(model));
    s.insert("result".into(), json!(result.as_str()));
    // The old tree counted turns in the log of a proxy on the runner,
    // which is gone; the field stays for its readers.
    s.insert("turns".into(), Value::Null);
    s.insert("tokens".into(), tokens);
    s.insert("tokens_source".into(), source);
    s.insert("praxis".into(), praxis);
    // USD to AIC (1 AIC = $0.01), to a tenth.
    let aic = digest.cost_usd.map(|usd| (usd * 1000.0).round() / 10.0);
    s.insert("aic".into(), json!(aic));
    s.insert("tools".into(), Value::Object(tools));
    s.insert("slowest".into(), json!(slowest));
    s.insert("failures".into(), json!(failures));
    s.insert("tests".into(), json!(tests));
    s.insert(
        "outcome".into(),
        json!({"status": null, "url": null, "why": null}),
    );
    s.insert("acp_protocol".into(), json!(digest.protocol_version));
    s.insert("agent_version".into(), json!(digest.agent));
    s.insert("stop_reason".into(), json!(digest.stop_reason));
    // The run's limits: whether one stopped it before the task was done,
    // whether the agent then handed back (so that its change is a partial
    // one to continue, not a failure), and what it was told on the way.
    let stopped_early = matches!(result, Outcome::Timeout | Outcome::Budget);
    s.insert("stopped_early".into(), json!(stopped_early));
    s.insert(
        "handed_back".into(),
        json!(inputs.result.is_some_and(|r| r.handed_back)),
    );
    // Whether the agent ended its turn without the output the run
    // requires and was reminded of it once.
    s.insert(
        "reminded".into(),
        json!(inputs.result.is_some_and(|r| r.reminded)),
    );
    s.insert("notices".into(), json!(digest.notices));
    s.insert("limits".into(), json!(inputs.result.map(|r| &r.limits)));
    let denied: Vec<Value> = digest
        .denied
        .iter()
        .map(|denial| json!({"tool": denial.tool, "summary": denial.summary, "rule": denial.rule}))
        .collect();
    s.insert(
        "permissions".into(),
        json!({"allowed": digest.allowed, "denied": denied}),
    );
    Value::Object(s)
}

/// "1.2M", "40k" or "386"; "?" when unknown.
fn human_count(v: &Value) -> String {
    match v.as_u64() {
        None => "?".to_owned(),
        Some(n) if n >= 1_000_000 => format!("{}M", (n / 100_000) as f64 / 10.0),
        Some(n) if n >= 1000 => format!("{}k", n / 1000),
        Some(n) => n.to_string(),
    }
}

/// "42m", "1h05m" or "12s"; "?" when unknown.
fn human_duration(v: &Value) -> String {
    match v.as_u64() {
        None => "?".to_owned(),
        Some(s) if s >= 3600 => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
        Some(s) if s >= 60 => format!("{}m", s / 60),
        Some(s) => format!("{s}s"),
    }
}

/// A value as inline code, safe in a cell of a Markdown table: the agent
/// chooses tool names and titles, so they are never rendered as Markdown.
fn code(v: &Value) -> String {
    let s = v.as_str().map_or_else(|| v.to_string(), str::to_owned);
    format!("`{}`", s.replace('`', "'").replace('|', "\\|"))
}

fn text(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

fn row(cells: &[String]) -> String {
    format!("| {} |", cells.join(" | "))
}

/// Cost is the agent's estimate, not the inference proxy's token count.
pub fn cost_line(s: &Value) -> String {
    let number = |key: &str| {
        s[key]
            .as_f64()
            .filter(|n| n.is_finite() && *n >= 0.0)
            .map_or_else(|| "unknown".to_owned(), |n| n.to_string())
    };
    format!(
        "Cost: {} AIC (agent-reported, unverified); budget: {} AIC.",
        number("aic"),
        number("aic_budget")
    )
}

/// The run's `summary.md` from its `summary.json`.
pub fn markdown(s: &Value) -> String {
    let or = |v: &Value, d: &str| if v.is_null() { d.to_owned() } else { text(v) };
    // What `--meta` named the run and its machine, where it did: the
    // caller's own words, kept to the line they are on.
    let named = |v: &Value| cut(&text(v));
    let mut out = vec![
        format!(
            "## Agent run: {} on {} ({})",
            if s["item"].is_null() {
                named(&s["run_id"])
            } else {
                named(&s["item"])
            },
            text(&s["repo"]),
            text(&s["base"])
        ),
        String::new(),
        format!(
            "{}/{}{}: **{}**",
            text(&s["agent"]),
            // The agent's own name for it.
            if s["model"].is_null() {
                "default".to_owned()
            } else {
                code(&json!(named(&s["model"])))
            },
            if s["cores"].is_null() {
                String::new()
            } else {
                format!(", {} cores", named(&s["cores"]))
            },
            text(&s["result"])
        ),
        String::new(),
        cost_line(s),
        String::new(),
        row(&["Duration", "Turns", "Tokens in/out", "Est. AIC"].map(str::to_owned)),
        "|---|---|---|---|".to_owned(),
        row(&[
            human_duration(&s["duration_s"]),
            or(&s["turns"], "?"),
            format!(
                "{} / {}{}",
                human_count(&s["tokens"]["input"]),
                human_count(&s["tokens"]["output"]),
                if s["tokens_source"] == TOKENS_UNVERIFIED {
                    " (agent-reported, unverified)"
                } else {
                    ""
                }
            ),
            format!(
                "{} of {} ({})",
                or(&s["aic"], "?"),
                or(&s["aic_budget"], "?"),
                text(&s["aic_pricing"])
            ),
        ]),
    ];
    if s["stopped_early"] == true {
        let handed_back = if s["handed_back"] == true {
            "the agent handed back, so its change is a partial one to continue"
        } else {
            "the agent didn't hand back, so its change is whatever the working tree held"
        };
        out.extend([String::new(), format!("Stopped at a limit: {handed_back}.")]);
    }
    if s["reminded"] == true {
        out.extend([
            String::new(),
            "The agent ended its turn without its required output and was reminded once."
                .to_owned(),
        ]);
    }
    let log_dir = || {
        code(&json!(cut(s["agent_logs"]["dir"]
            .as_str()
            .unwrap_or_default())))
    };
    if s["agent_logs"]["missing"] == true {
        out.extend([
            String::new(),
            format!("The agent left no log in {}.", log_dir()),
        ]);
    } else if s["agent_logs"]["error"].is_string() {
        out.extend([
            String::new(),
            format!("The agent's logs in {} could not be read.", log_dir()),
        ]);
    }
    if let Some(context) = s["context"].as_array().filter(|items| !items.is_empty()) {
        out.extend([String::new(), "Reference context:".to_owned()]);
        for item in context {
            let state = match item["clean"].as_bool() {
                Some(true) => "",
                Some(false) => " (edited during the run)",
                None => " (state unknown)",
            };
            out.push(format!(
                "- {} at {}: {}{state}",
                code(&item["repo"]),
                code(&item["commit"]),
                code(&item["path"])
            ));
        }
    }
    if let Some(error) = s["patch"]["error"].as_str() {
        out.extend([
            String::new(),
            format!("No change handed back: {}", code(&json!(cut(error)))),
        ]);
    }
    let p = &s["praxis"];
    if p.is_object() {
        out.extend([
            String::new(),
            format!(
                "Inference: praxis run {}, {} tokens ({} cached), {} metered request(s), {} without usage.",
                text(&p["state"]),
                human_count(&p["tokens"]["total"]),
                human_count(&p["tokens"]["cache_read"]),
                text(&p["requests"]),
                text(&p["unmetered"])
            ),
        ]);
    }
    if let Some(tools) = s["tools"].as_object().filter(|t| !t.is_empty()) {
        out.extend([
            String::new(),
            "| Tool | Calls | Errors | Time |".to_owned(),
            "|---|---|---|---|".to_owned(),
        ]);
        let mut tools: Vec<_> = tools.iter().collect();
        tools.sort_by_key(|(_, t)| std::cmp::Reverse(t["calls"].as_u64()));
        for (name, t) in tools {
            out.push(row(&[
                code(&json!(name)),
                text(&t["calls"]),
                text(&t["errors"]),
                human_duration(&t["duration_s"]),
            ]));
        }
    }
    let list = |key: &str| s[key].as_array().filter(|a| !a.is_empty());
    if let Some(slowest) = list("slowest") {
        out.extend([
            String::new(),
            "Slowest tool calls:".to_owned(),
            String::new(),
        ]);
        out.extend(slowest.iter().map(|c| {
            format!(
                "- {} {}: {}",
                human_duration(&c["duration_s"]),
                code(&c["tool"]),
                code(&c["summary"])
            )
        }));
    }
    if let Some(failures) = list("failures") {
        out.extend([String::new(), "Failures:".to_owned(), String::new()]);
        out.extend(
            failures
                .iter()
                .map(|f| format!("- {}: {}", text(&f["kind"]), code(&f["message"]))),
        );
    }
    if let Some(denied) = s["permissions"]["denied"]
        .as_array()
        .filter(|a| !a.is_empty())
    {
        out.extend([
            String::new(),
            "Denied by the policy:".to_owned(),
            String::new(),
        ]);
        out.extend(denied.iter().map(|d| {
            format!(
                "- {}: {} ({})",
                code(&d["tool"]),
                code(&d["summary"]),
                d["rule"]
                    .as_str()
                    .map_or("default".to_owned(), |r| format!("rule {r}"))
            )
        }));
    }
    if let Some(tests) = list("tests") {
        out.extend([String::new(), "Tests:".to_owned(), String::new()]);
        out.extend(tests.iter().map(|t| {
            format!(
                "- {}: exit {}",
                code(&t["command"]),
                or(&t["exit_code"], "?")
            )
        }));
    }
    if let Some(denied) = list("egress_denied") {
        let domains: Vec<String> = denied
            .iter()
            .map(|d| {
                format!(
                    "{} ({})",
                    code(&json!(cut(&text(&d["domain"])))),
                    text(&d["count"])
                )
            })
            .collect();
        out.extend([
            String::new(),
            format!("Denied egress: {}", domains.join(", ")),
        ]);
    }
    if let Some(n) = s["redactions"].as_u64().filter(|n| *n > 0) {
        out.extend([String::new(), format!("Redacted {n} string(s).")]);
    }
    out.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Limits;
    use crate::session::digest::Dir;

    fn measured() -> Measured {
        Measured {
            context: Vec::new(),
            meta: json!({
                "run_id": 1, "run_attempt": 1, "run_url": "https://example.com/1",
                "item": "PVTI_x", "cores": 4, "not_copied": "x",
            }),
            repo: "o/r".into(),
            base: "main".into(),
            workflow: "branch",
            agent: "claude".into(),
            model: Some("m-default".into()),
            started_at: "2026-09-25T00:00:00Z".into(),
            finished_at: "2026-09-25T00:01:00Z".into(),
            duration_s: 60,
            aic_budget: Some(500.0),
            aic_pricing: "mock",
            files: vec!["FAKE.md".into()],
            patch: json!({"base": "abc", "bytes": 10}),
            egress_denied: Vec::new(),
            agent_logs: json!({"dir": "~/logs", "files": 1, "omitted_files": 0, "truncated": false}),
            redactions: 2,
        }
    }

    fn rec(ts: f64, dir: Dir, msg: Value) -> Record {
        Record {
            ts,
            dir,
            msg: Some(msg),
            line: None,
        }
    }

    fn result(outcome: Outcome, message: Option<&str>, handed_back: bool) -> RunResult {
        RunResult {
            schema: crate::session::RESULT_SCHEMA.into(),
            agent: "claude".into(),
            command: Vec::new(),
            result: outcome,
            stop_reason: None,
            message: message.map(str::to_owned),
            started_at: String::new(),
            finished_at: String::new(),
            duration_s: 60,
            limits: Limits {
                timeout_s: 600,
                ..Limits::default()
            },
            handed_back,
            reminded: false,
        }
    }

    fn initialize() -> [Record; 1] {
        [rec(
            0.0,
            Dir::Send,
            json!({"jsonrpc": "2.0", "id": 0, "method": "initialize"}),
        )]
    }

    #[test]
    fn cost_is_not_verified_or_invented() {
        for (aic, expected) in [
            (json!(2.5), "2.5"),
            (Value::Null, "unknown"),
            (json!(-1), "unknown"),
            (json!("free"), "unknown"),
        ] {
            assert_eq!(
                cost_line(&json!({"aic": aic})),
                format!("Cost: {expected} AIC (agent-reported, unverified); budget: unknown AIC.")
            );
        }
    }

    #[test]
    fn human_units() {
        for (n, count, duration) in [
            (json!(null), "?", "?"),
            (json!(12), "12", "12s"),
            (json!(386), "386", "6m"),
            (json!(40_500), "40k", "11h15m"),
            (json!(3_900), "3k", "1h05m"),
            (json!(1_234_567), "1.2M", "342h56m"),
            (json!(2_000_000), "2M", "555h33m"),
        ] {
            assert_eq!(
                (human_count(&n), human_duration(&n)),
                (count.into(), duration.into()),
                "{n}"
            );
        }
    }

    /// The old tree's text, for a summary as the old tree wrote one.
    #[test]
    fn markdown_summary() {
        let s = json!({
            "item": "PVTI_x", "repo": "o/r", "base": "main", "agent": "fake", "model": null,
            "cores": 4, "result": "failure", "duration_s": 75, "turns": null,
            "tokens": {"input": 1500, "output": null}, "aic": 1.0, "aic_budget": 500,
            "aic_pricing": "mock", "outcome": {"url": null},
            "tools": {"Read": {"calls": 1, "errors": 0, "duration_s": 0},
                      "Bash": {"calls": 2, "errors": 1, "duration_s": 3}},
            "slowest": [{"tool": "Bash", "summary": "a | b `c`", "duration_s": 3}],
            "failures": [{"kind": "tool_error", "message": "Bash: boom"}],
            "permissions": {"allowed": 2, "denied": [{"tool": "Bash", "summary": "git push", "rule": "no-push"}]},
            "tests": [], "egress_denied": [{"domain": "evil.example", "count": 2}], "redactions": 1,
            "patch": {"base": "abc", "error": "the change is over 64 bytes"},
        });
        assert_eq!(
            markdown(&s),
            "## Agent run: PVTI_x on o/r (main)

fake/default, 4 cores: **failure**

Cost: 1 AIC (agent-reported, unverified); budget: 500 AIC.

| Duration | Turns | Tokens in/out | Est. AIC |
|---|---|---|---|
| 1m | ? | 1k / ? | 1.0 of 500 (mock) |

No change handed back: `the change is over 64 bytes`

| Tool | Calls | Errors | Time |
|---|---|---|---|
| `Bash` | 2 | 1 | 3s |
| `Read` | 1 | 0 | 0s |

Slowest tool calls:

- 3s `Bash`: `a \\| b 'c'`

Failures:

- tool_error: `Bash: boom`

Denied by the policy:

- `Bash`: `git push` (rule no-push)

Denied egress: `evil.example` (2)

Redacted 1 string(s).
"
        );
        // A caller that names neither the run nor its machine.
        let bare = markdown(
            &json!({"run_id": 7, "repo": "o/r", "base": "main", "agent": "fake",
            "result": "success", "aic_pricing": "mock"}),
        );
        assert!(
            bare.starts_with("## Agent run: 7 on o/r (main)\n\nfake/default: **success**\n"),
            "{bare}"
        );
    }

    /// What the caller's `--meta` names stays on the line it is put on.
    #[test]
    fn names_from_the_caller_stay_on_their_line() {
        let md = markdown(&json!({"item": "x\n# A heading", "cores": "8\n\nmore",
            "repo": "o/r", "base": "main", "agent": "fake", "result": "success"}));
        assert!(
            md.starts_with("## Agent run: x # A heading on o/r (main)\n"),
            "{md}"
        );
        assert!(
            md.contains("\nfake/default, 8  more cores: **success**\n"),
            "{md}"
        );
    }

    #[test]
    fn a_session_without_a_result_is_a_failure() {
        let records = initialize();
        let measured = measured();
        let s = summarize(&Inputs {
            records: &records,
            result: None,
            measured: &measured,
            outcome: &json!({}),
            usage: None,
        });
        assert_eq!(s["result"], "failure");
        assert_eq!(s["failures"][0]["kind"], "agent_exit");
        assert_eq!(s["model"], "m-default");
        assert!(markdown(&s).contains("\nclaude/`m-default`, 4 cores: **failure**\n"));
        assert_eq!(s["tokens"]["input"], Value::Null);
        assert_eq!(s["tokens_source"], Value::Null);
        assert_eq!(s["turns"], Value::Null);
        assert_eq!(s["limits"], Value::Null);
        assert_eq!(s["handed_back"], false);
    }

    #[test]
    fn context_pins_and_paths_reach_both_summaries() {
        let mut measured = measured();
        measured.context = vec![
            json!({"repo": "owner/reference", "commit": "a".repeat(40), "path": "/home/agent/work/context/owner/reference", "clean": true}),
            json!({"repo": "owner/edited", "commit": "b".repeat(40), "path": "/home/agent/work/context/owner/edited", "clean": false}),
        ];
        let s = summarize(&Inputs {
            records: &initialize(),
            result: None,
            measured: &measured,
            outcome: &json!({}),
            usage: None,
        });
        assert_eq!(s["context"], json!(measured.context));
        let md = markdown(&s);
        assert!(md.contains("Reference context:"));
        assert!(md.contains("`/home/agent/work/context/owner/reference`\n"));
        assert!(md.contains("`/home/agent/work/context/owner/edited` (edited during the run)"));
        assert!(md.contains(&format!("`{}`", "a".repeat(40))));
    }

    #[test]
    fn what_was_measured_and_named_is_in_the_summary() {
        let records = initialize();
        let measured = measured();
        // (how the session ended, stopped early, the kind of its failure)
        let cases = [
            (result(Outcome::Success, None, false), false, None),
            (
                result(Outcome::Timeout, Some("hit the timeout"), true),
                true,
                Some(("timeout", "hit the timeout")),
            ),
            (
                result(Outcome::Budget, None, false),
                true,
                Some(("budget", "the agent went over budget")),
            ),
            (
                result(Outcome::Cancelled, Some("refusal"), false),
                false,
                Some(("agent_exit", "refusal")),
            ),
        ];
        for (result, stopped_early, failure) in cases {
            let s = summarize(&Inputs {
                records: &records,
                result: Some(&result),
                measured: &measured,
                outcome: &json!({"tests": [
                    {"command": "git log", "exit_code": 0, "duration_s": 0}, "junk",
                    {"command": ["a", 1], "exit_code": "0 | **x**", "duration_s": {"s": 1}},
                ]}),
                usage: None,
            });
            let name = result.result.as_str();
            assert_eq!(s["schema"], SCHEMA);
            assert_eq!(s["result"], name);
            assert_eq!(s["stopped_early"], stopped_early, "{name}");
            assert_eq!(s["handed_back"], result.handed_back, "{name}");
            assert_eq!(s["limits"]["timeout_s"], 600, "{name}");
            let failures: Vec<_> = s["failures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| (f["kind"].as_str().unwrap(), f["message"].as_str().unwrap()))
                .collect();
            assert_eq!(failures, failure.into_iter().collect::<Vec<_>>(), "{name}");
            assert_eq!(
                s["tests"],
                json!([
                    {"command": "git log", "exit_code": 0, "duration_s": 0},
                    {"command": "[\"a\",1]", "exit_code": null, "duration_s": null},
                ])
            );
            assert!(
                markdown(&s).contains("- `[\"a\",1]`: exit ?\n"),
                "{}",
                markdown(&s)
            );
            // The budget is a whole number, and reads as one.
            assert_eq!(s["aic_budget"].to_string(), "500");
            assert!(markdown(&s).contains(" of 500 (mock)"), "{}", markdown(&s));
            // Every field the old tree's summary took from its supervisor.
            for key in [
                "run_id",
                "run_attempt",
                "run_url",
                "item",
                "repo",
                "base",
                "workflow",
                "agent",
                "cores",
                "started_at",
                "finished_at",
                "duration_s",
                "aic_budget",
                "aic_pricing",
                "files",
                "patch",
                "egress_denied",
                "agent_logs",
                "redactions",
            ] {
                assert!(!s[key].is_null(), "{name}: {key}");
            }
            assert_eq!(s["item"], "PVTI_x");
            assert_eq!(s["workflow"], "branch");
            assert_eq!(s["patch"]["bytes"], 10);
            assert!(s.get("not_copied").is_none());
        }
    }

    /// A reminder, and an agent's log that was not there, are said.
    #[test]
    fn a_reminder_and_a_missing_log_are_said() {
        let records = initialize();
        let mut measured = measured();
        let reminded = RunResult {
            reminded: true,
            ..result(Outcome::Failure, Some("no output"), false)
        };
        for (result, logs, said) in [
            (
                result(Outcome::Success, None, false),
                measured.agent_logs.clone(),
                false,
            ),
            (
                reminded,
                json!({"dir": "~/.claude/debug", "missing": true}),
                true,
            ),
        ] {
            measured.agent_logs = logs;
            let s = summarize(&Inputs {
                records: &records,
                result: Some(&result),
                measured: &measured,
                outcome: &json!({}),
                usage: None,
            });
            assert_eq!(s["reminded"], said);
            let md = markdown(&s);
            assert_eq!(md.contains("was reminded once"), said, "{md}");
            assert_eq!(
                md.contains("The agent left no log in `~/.claude/debug`."),
                said,
                "{md}"
            );
        }
    }

    #[test]
    fn the_proxys_record_gives_the_tokens_and_a_footer_safe_summary() {
        let records = initialize();
        let record = json!({
            "schema": RECORD_SCHEMA, "repository": "o/r", "run_id": 1, "run_attempt": 1,
            "repository_id": 7, "check_run_id": 9, "workflow_ref": "o/r/.github/workflows/agent.yml@refs/heads/main",
            "state": "finished", "registered_at_unix": 1, "expires_at_unix": 2, "finished_at_unix": 2,
            "requests": 3, "unmetered": 1,
            "tokens": {"input": 400, "cache_read": 600, "output": 50, "reasoning": 20, "total": 1050},
            "models": {"gpt-test": {"input": 400, "cache_read": 600, "output": 50, "reasoning": 20, "total": 1050}},
        });
        let measured = measured();
        let summarize_with = |usage| {
            summarize(&Inputs {
                records: &records,
                result: None,
                measured: &measured,
                outcome: &json!({}),
                usage,
            })
        };
        let s = summarize_with(Some(&record));
        assert_eq!(s["tokens_source"], TOKENS_PRAXIS);
        assert_eq!(
            s["tokens"],
            json!({"input": 400, "output": 50, "cache_read": 600, "cache_write": null})
        );
        assert_eq!(s["praxis"]["tokens"]["total"], 1050);
        assert_eq!(s["praxis"]["unmetered"], 1);
        // Only numbers and fixed words: no names, refs or model ids.
        for key in [
            "repository",
            "workflow_ref",
            "models",
            "run_id",
            "check_run_id",
        ] {
            assert!(s["praxis"].get(key).is_none(), "{key}");
        }
        let md = markdown(&s);
        assert!(
            md.contains("Inference: praxis run finished, 1k tokens (600 cached), 3 metered request(s), 1 without usage."),
            "{md}"
        );
        // Anything else is not a record.
        let s = summarize_with(Some(&json!({"schema": "other/v1"})));
        assert_eq!(s["praxis"], Value::Null);
        assert_eq!(s["tokens_source"], Value::Null);
        assert!(!markdown(&s).contains("Inference:"));
    }

    /// The agent's own count is used only as its word, and a session's
    /// tools, cost and model are read from its transcript.
    #[test]
    fn a_session_is_read_from_its_transcript() {
        let update = |update: Value| {
            json!({"jsonrpc": "2.0", "method": "session/update",
                "params": {"sessionId": "s", "update": update}})
        };
        let records = [
            rec(
                0.0,
                Dir::Send,
                json!({"jsonrpc": "2.0", "id": 0, "method": "initialize"}),
            ),
            rec(
                0.1,
                Dir::Recv,
                json!({"jsonrpc": "2.0", "id": 0, "result": {
                "protocolVersion": 1, "agentInfo": {"name": "an-agent", "version": "1.2"}}}),
            ),
            rec(
                0.5,
                Dir::Recv,
                json!({"jsonrpc": "2.0", "method": "session/prompt"}),
            ),
            rec(
                1.0,
                Dir::Send,
                json!({"jsonrpc": "2.0", "id": 1, "method": "session/prompt",
                "params": {"sessionId": "s", "prompt": [{"type": "text", "text": "go"}]}}),
            ),
            rec(
                2.0,
                Dir::Recv,
                update(json!({"sessionUpdate": "tool_call", "toolCallId": "t",
                "title": "Bash", "kind": "execute", "status": "pending",
                "rawInput": {"command": "false"}})),
            ),
            rec(
                5.0,
                Dir::Recv,
                update(json!({"sessionUpdate": "tool_call_update",
                "toolCallId": "t", "status": "failed",
                "content": [{"type": "content", "content": {"type": "text", "text": "boom"}}]})),
            ),
            rec(
                5.5,
                Dir::Recv,
                update(json!({"sessionUpdate": "usage_update", "used": 0,
                "size": 0, "cost": {"amount": 0.123, "currency": "USD"}})),
            ),
            rec(
                6.0,
                Dir::Recv,
                json!({"jsonrpc": "2.0", "id": 1, "result": {
                "stopReason": "end_turn",
                "usage": {"inputTokens": 10, "outputTokens": 5, "cachedReadTokens": 2}}}),
            ),
        ];
        let measured = measured();
        let done = result(Outcome::Success, None, false);
        let s = summarize(&Inputs {
            records: &records,
            result: Some(&done),
            measured: &measured,
            outcome: &json!({}),
            usage: None,
        });
        assert_eq!(s["acp_protocol"], 1, "{s:#}");
        assert_eq!(s["agent_first_step_at"], 1.0);
        assert_eq!(s["agent_version"], "an-agent 1.2");
        assert_eq!(s["stop_reason"], "end_turn");
        assert_eq!(s["tokens_source"], TOKENS_UNVERIFIED);
        assert_eq!(s["tokens"]["output"], 5);
        assert_eq!(s["aic"], 12.3);
        assert_eq!(
            s["tools"],
            json!({"Bash": {"calls": 1, "errors": 1, "duration_s": 3}})
        );
        assert_eq!(s["slowest"][0]["duration_s"], 3);
        assert_eq!(s["failures"][0]["kind"], "tool_error");
        assert!(markdown(&s).contains("(agent-reported, unverified)"));
    }
}
