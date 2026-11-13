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

use super::agent::Kind;
use super::handback::OMITTED_BINARY_FILES;
use super::inference::RECORD_SCHEMA;
use super::prices::{Prices, Tokens};
use crate::session::budget::AIC_PER_USD;
use crate::session::digest::{Digest, Dir, EDIT_KINDS, cut};
use crate::session::provider::Class;
use crate::session::{Outcome, Record, RunResult, STALLED};

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
/// `cost.source`: the proxy's token counts at the pinned list prices, or
/// the agent's own figure, which is only its word.
const COST_METERED: &str = "metered";
const COST_AGENT: &str = "agent-reported, unverified";
/// The `aic_pricing` of agents whose own cost is at list prices: Claude
/// Code's, and the fake agent's made-up one. opencode's is not: it has
/// no prices for the proxy's provider.
const AGENT_LIST_PRICINGS: &[&str] = &["api-equivalent", "mock"];
/// `cost.usd` is kept to a hundredth of a cent.
const USD_ROUNDING: f64 = 10_000.0;
/// At most this many models are priced and listed in `cost.models`; a
/// figure without the rest is partial.
const MAX_COST_MODELS: usize = 16;
/// `cost.prices`, a date: `2026-10-24`.
const PRICES_DATE_CHARS: usize = 10;
/// At most this many of the slowest tool calls are listed.
const MAX_SLOWEST: usize = 10;
/// `cache_warning`: an OpenAI run (opencode's) that read less than this
/// share of its input from the prompt cache over more than
/// [`CACHE_WARNING_AFTER`] metered requests. Each request resends the
/// whole conversation, so a stable prefix is mostly cache reads after the
/// first few; Claude Code's runs read 97% from it on 28 October 2026
/// (#2209).
const CACHE_WARNING_RATIO: f64 = 0.5;
/// The requests before which a cold cache is expected.
const CACHE_WARNING_AFTER: u64 = 3;
/// `cache_ratio` is kept to a hundredth.
const RATIO_ROUNDING: f64 = 100.0;
/// The fields `--meta` gives: on GitHub the run's id, attempt and URL,
/// the caller's own name for the run, and the size of its machine.
pub const META_FIELDS: &[&str] = &["run_id", "run_attempt", "run_url", "item", "cores"];
/// The address prepare's `inference-address` gave the broker's name, in
/// `--meta` and the summary only where it was given: the check job has
/// the policy's URL, and sees here the host the run used in its place.
pub const META_INFERENCE_ADDRESS: &str = "inference_address";
/// The kinds of the one failure in `failures[]` that says how a run that
/// did not succeed ended (a `tool_error` is a tool's, not the run's):
/// the fixed words `run/action.yml` lets through as its `failure-class`
/// output, and `apply.yml`'s `conclude` into the status comment. A caller
/// requeues on the first three inference kinds, which a wait may clear,
/// and not on `inference_quota` or `inference_unauthorized`. The action
/// lets no other word out of `summary.json`; [`CONTROL_UNREACHABLE`] is
/// its own.
pub const FAILURE_KINDS: [&str; 9] = [
    "timeout",
    "budget",
    "stall",
    "agent_exit",
    "inference_rate_limited",
    "inference_overloaded",
    "inference_unreachable",
    "inference_quota",
    "inference_unauthorized",
];
/// The one `failure-class` that is the run action's own and never in
/// `summary.json`: `sandbox check` before `run` exited 4, failing only to
/// reach a host outside the runner (#3225), so the agent never started.
/// `conclude` takes it beside [`FAILURE_KINDS`]; a caller may requeue on
/// it a bounded number of times, as a host whose own way out is broken
/// fails the same way.
pub const CONTROL_UNREACHABLE: &str = "control_unreachable";

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
    /// The same, for the secondary pull request's repository.
    pub secondary_patch: Value,
    /// Why the memory directory was not handed back.
    pub memory_dropped: Option<String>,
    /// Why the agent's requests file was not handed back.
    pub requests_dropped: Option<String>,
    /// Requests the egress proxy refused, per host.
    pub egress_denied: Vec<Value>,
    /// What of the agent's own logs the transcript has
    /// (`agent_log::collect`), or null.
    pub agent_logs: Value,
    /// The same of the child agent's session and logs, for a run that
    /// has one, or null.
    pub child_logs: Value,
    pub redactions: usize,
}

/// `summary.json`'s list of the strings shaped like a credential in the
/// hand-back, by place (`upload::Staging::shape_warnings`); absent if none.
pub const SECRET_SHAPED: &str = "secret_shaped";

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

/// The run's cost at API list prices: the proxy's token counts by the
/// model upstream named (the record's `models`), each at its rates in the
/// price table, never at a model the agent names. Without one priced,
/// the agent's own figure where that is a list price too (`aic_pricing`),
/// else null. A metered figure is `partial`, a lower bound, when a model
/// is unpriced or a response's usage never arrived (`unmetered`).
fn list_cost(record: Option<&Value>, agent_usd: Option<f64>, pricing: &str) -> Value {
    let prices = Prices::builtin().ok();
    list_cost_with_prices(record, agent_usd, pricing, prices.as_ref())
}

fn list_cost_with_prices(
    record: Option<&Value>,
    agent_usd: Option<f64>,
    pricing: &str,
    prices: Option<&Prices>,
) -> Value {
    let round = |usd: f64| (usd * USD_ROUNDING).round() / USD_ROUNDING;
    let by_model = record.and_then(|r| r["models"].as_object());
    let mut models = Map::new();
    let mut estimated_models = Map::new();
    let mut total = 0.0;
    // Fails closed: an `unmetered` that is not a count may hide usage.
    let mut partial = record.is_some_and(|r| r["unmetered"].as_u64() != Some(0))
        || by_model.is_some_and(|m| m.len() > MAX_COST_MODELS);
    for (name, tokens) in by_model.into_iter().flatten().take(MAX_COST_MODELS) {
        let count = |key: &str| tokens[key].as_u64();
        let cost = (|| {
            let tokens = Tokens {
                input: count("input")?,
                cached: count("cache_read")?,
                output: count("output")?,
            };
            let rates = prices?.rates(name)?;
            if rates.estimate {
                estimated_models.insert(cut(name), json!(rates.basis));
            }
            Some(rates.cost(tokens))
        })();
        partial |= cost.is_none();
        total += cost.unwrap_or(0.0);
        models.insert(cut(name), json!(cost.map(round)));
    }
    let priced = models.values().any(|usd| !usd.is_null());
    let (usd, source) = match agent_usd {
        _ if priced => (Some(total), json!(COST_METERED)),
        Some(usd) if AGENT_LIST_PRICINGS.contains(&pricing) => (Some(usd), json!(COST_AGENT)),
        _ => (None, Value::Null),
    };
    json!({
        "usd": usd.map(round), "basis": "list", "source": source,
        "prices": prices.map(|p| &p.date),
        "partial": priced && partial,
        "estimated": !estimated_models.is_empty(),
        "estimated_models": estimated_models,
        "models": if priced { Value::Object(models) } else { Value::Null },
    })
}

/// The share of the run's input tokens read from the prompt cache: null
/// without both counts, or without input. Not rounded: `cache_ratio` is.
fn cache_ratio(tokens: &Value) -> Option<f64> {
    let cached = tokens["cache_read"].as_u64()?;
    let all = tokens["input"]
        .as_u64()?
        .checked_add(cached)
        .filter(|all| *all > 0)?;
    Some(cached as f64 / all as f64)
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
    // A run that ended on a model provider's failure is filed under its
    // class, whatever the exit it then came to: that, not the agent's
    // words, is what a caller decides on. Not so for a run whose agent
    // then handed back: that is a partial result at a limit (`timeout`,
    // `budget`), to continue rather than to repeat, and the class stays
    // in `provider_error`. So is a run the provider stopped that handed
    // back its working tree all the same (`RunResult::stopped_by_provider`).
    // Words that fit no class (`other`) leave it the agent's failure, as
    // before.
    let provider = inputs
        .result
        .filter(|r| !r.handed_back && !r.provider_stopped())
        .and_then(|r| r.provider_error)
        .and_then(Class::kind);
    let ended = |default: &'static str, message: String| {
        let mut failure = json!({"kind": provider.unwrap_or(default), "message": message});
        if let (Some(_), Some(r)) = (provider, inputs.result) {
            failure["resends"] = json!(r.resends);
            failure["waited_s"] = json!(r.resend_wait_s);
        }
        failure
    };
    match result {
        Outcome::NoRequests => {
            failures.push(json!({"kind": "stall", "message": why("the agent made no model request within the first five minutes")}));
        }
        Outcome::Timeout => {
            failures.push(ended("timeout", why("the agent hit the timeout")));
        }
        Outcome::Budget => {
            failures.push(ended("budget", why("the agent went over budget")));
        }
        // A stalled turn is the agent's model request hanging, not the
        // agent's own mistake: a retry may do.
        Outcome::Failure if inputs.result.is_some_and(RunResult::failed_stalled) => {
            failures.push(ended("stall", why(STALLED)));
        }
        Outcome::Failure | Outcome::Cancelled => {
            failures.push(ended("agent_exit", why("the agent failed")));
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
    if let Some(address) = measured.meta.get(META_INFERENCE_ADDRESS) {
        s.insert(META_INFERENCE_ADDRESS.into(), address.clone());
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
    if !measured.secondary_patch.is_null() {
        s.insert("secondary_patch".into(), measured.secondary_patch.clone());
    }
    if let Some(why) = &measured.memory_dropped {
        s.insert("memory_dropped".into(), json!(why));
    }
    if let Some(why) = &measured.requests_dropped {
        s.insert("requests_dropped".into(), json!(why));
    }
    if let Some(omitted) = inputs.outcome.get(OMITTED_BINARY_FILES) {
        s.insert(OMITTED_BINARY_FILES.into(), omitted.clone());
    }
    s.insert("egress_denied".into(), json!(measured.egress_denied));
    s.insert("agent_logs".into(), measured.agent_logs.clone());
    if !measured.child_logs.is_null() {
        s.insert("child_logs".into(), measured.child_logs.clone());
    }
    s.insert("redactions".into(), json!(measured.redactions));
    // The model the agent says the session runs, else the one asked for.
    let model = digest.model.clone().or_else(|| measured.model.clone());
    s.insert("model".into(), json!(model));
    s.insert("result".into(), json!(result.as_str()));
    // The old tree counted turns in the log of a proxy on the runner,
    // which is gone; the field stays for its readers.
    s.insert("turns".into(), Value::Null);
    let ratio = cache_ratio(&tokens);
    // Only the proxy's count of requests: the agent's word does not say
    // how many turns its tokens were spread over.
    let cache_warning = measured.agent == Kind::Opencode.as_str()
        && praxis["requests"]
            .as_u64()
            .is_some_and(|n| n > CACHE_WARNING_AFTER)
        && ratio.is_some_and(|ratio| ratio < CACHE_WARNING_RATIO);
    s.insert("tokens".into(), tokens);
    s.insert("tokens_source".into(), source);
    s.insert(
        "cache_ratio".into(),
        json!(ratio.map(|ratio| (ratio * RATIO_ROUNDING).round() / RATIO_ROUNDING)),
    );
    s.insert("cache_warning".into(), json!(cache_warning));
    s.insert("praxis".into(), praxis);
    // USD to AIC (1 AIC = $0.01), to a tenth.
    let aic = digest.cost_usd.map(|usd| (usd * 1000.0).round() / 10.0);
    s.insert("aic".into(), json!(aic));
    let record = inputs
        .usage
        .filter(|record| record["schema"] == RECORD_SCHEMA);
    s.insert(
        "cost".into(),
        list_cost(record, digest.cost_usd, measured.aic_pricing),
    );
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
    // How often the task's turn stalled, and was sent again after one.
    s.insert(
        "stalls".into(),
        json!(inputs.result.map_or(0, |r| r.stalls)),
    );
    s.insert(
        "stall_retries".into(),
        json!(inputs.result.map_or(0, |r| r.stall_retries)),
    );
    // The model provider's failure the run ended on, if one, and how often
    // the task was sent again after one it got past, waiting how long.
    s.insert(
        "provider_error".into(),
        json!(inputs.result.and_then(|r| r.provider_error)),
    );
    s.insert(
        "resends".into(),
        json!(inputs.result.map_or(0, |r| r.resends)),
    );
    s.insert(
        "resend_wait_s".into(),
        json!(inputs.result.map_or(0, |r| r.resend_wait_s)),
    );
    // The model the agent was switched to on an overload, which `model`
    // then names too: the pool the rest of the run drew on.
    s.insert(
        "fallback_model".into(),
        json!(inputs.result.and_then(|r| r.fallback_model.as_deref())),
    );
    s.insert("notices".into(), json!(digest.notices));
    // The links of the updates of the run's item the agent was sent.
    s.insert("updates".into(), json!(digest.updates));
    // A change made without one finished call of an edit kind that did not fail
    // (ACP's for Claude Code's Edit/Write, opencode's edit and Vibe's
    // write_file) was made through the shell: slower, harder to review in
    // the transcript, and a sign the agent's prompt or tools have drifted
    // (#853). It is a hint, not a verdict: a run whose files a child agent
    // or a code generator changed is flagged too.
    let shell_edits = !measured.files.is_empty()
        && !digest
            .calls
            .iter()
            .any(|call| EDIT_KINDS.contains(&call.kind.as_str()) && call.error == Some(false));
    s.insert("shell_edits".into(), json!(shell_edits));
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
pub(super) fn human_count(v: &Value) -> String {
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

/// An https URL as a Markdown autolink, anything else as inline code.
fn link(v: &Value) -> String {
    match v.as_str() {
        Some(url)
            if url.starts_with("https://")
                && url
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && !b"<>`".contains(&b)) =>
        {
            format!("<{url}>")
        }
        _ => code(v),
    }
}

fn text(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

fn row(cells: &[String]) -> String {
    format!("| {} |", cells.join(" | "))
}

/// Dollars to the cent, or `?`.
fn usd(v: &Value) -> String {
    v.as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0)
        .map_or_else(|| "?".to_owned(), |n| format!("${n:.2}"))
}

/// The run's cost at list prices and where it comes from. The budget
/// still holds the agent's own figure, in AIC (hundredths of a dollar),
/// as the session reads it.
pub fn cost_line(s: &Value) -> String {
    let cost = &s["cost"];
    // `audit` prints this line from a downloaded summary: only a date of
    // its words, never text that could be a CI command.
    let date = cost["prices"]
        .as_str()
        .filter(|d| {
            d.len() <= PRICES_DATE_CHARS && d.bytes().all(|b| b.is_ascii_digit() || b == b'-')
        })
        .unwrap_or("?");
    let source = if cost["source"] == COST_METERED {
        format!("metered tokens, prices of {date}")
    } else if cost["source"] == COST_AGENT {
        COST_AGENT.to_owned()
    } else {
        "unpriced".to_owned()
    };
    let at_least = if cost["partial"] == true {
        "at least "
    } else {
        ""
    };
    let budget = s["aic_budget"].as_f64().map(|aic| json!(aic / AIC_PER_USD));
    let estimate = if cost["estimated"] == true {
        "est. "
    } else {
        ""
    };
    format!(
        "Cost: {at_least}{estimate}{} at API list prices ({source}); budget: {}, capping the agent's own figure.",
        usd(&cost["usd"]),
        usd(budget.as_ref().unwrap_or(&Value::Null))
    )
}

/// The run's `summary.md` from its `summary.json`.
pub(super) fn isolation_notice(s: &Value) -> &'static str {
    if s["host_isolation"] == "external" {
        "Host isolation: **external** — declared by caller; not proved by agentic-job. This is producer-reported provenance, not a check attestation.\n"
    } else {
        ""
    }
}

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
        row(&["Duration", "Turns", "Tokens in/out", "List cost"].map(str::to_owned)),
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
                "{}{}",
                if s["cost"]["estimated"] == true {
                    "est. "
                } else {
                    ""
                },
                usd(&s["cost"]["usd"])
            ),
        ]),
    ];
    if s["host_isolation"] == "external" {
        out.insert(2, "Host isolation: **external** — declared by caller; not proved by agentic-job. This is producer-reported provenance, not a check attestation.\n".to_owned());
    }
    if let Some(models) = s["cost"]["estimated_models"]
        .as_object()
        .filter(|m| !m.is_empty())
    {
        let names = models
            .keys()
            .take(MAX_COST_MODELS)
            .map(|name| code(&json!(cut(name))))
            .collect::<Vec<_>>()
            .join(", ");
        out.extend([String::new(), format!("Estimated models: {names}.")]);
    }
    if s["stopped_early"] == true {
        let handed_back = if s["handed_back"] == true {
            "the agent handed back, so its change is a partial one to continue"
        } else {
            "the agent didn't hand back, so its change is whatever the working tree held"
        };
        // The model provider's failure, if the run ended on one, stopped
        // it or came before the limit that did.
        let by_provider = s["provider_error"]
            .as_str()
            .is_some_and(|class| class != Class::Other.as_str());
        let stopped = if by_provider {
            "Stopped early after the model provider's failure"
        } else {
            "Stopped at a limit"
        };
        out.extend([String::new(), format!("{stopped}: {handed_back}.")]);
    }
    if s["reminded"] == true {
        out.extend([
            String::new(),
            "The agent ended its turn without its required output and was reminded once."
                .to_owned(),
        ]);
    }
    if let Some(stalls) = s["stalls"].as_u64().filter(|n| *n > 0) {
        out.extend([
            String::new(),
            format!(
                "The agent's turn stalled {stalls} time(s), with nothing from it for its stall \
                 timeout; the task was sent again {} time(s).",
                s["stall_retries"].as_u64().unwrap_or(0)
            ),
        ]);
    }
    if let Some(resends) = s["resends"].as_u64().filter(|n| *n > 0) {
        out.extend([
            String::new(),
            format!(
                "The model provider failed the agent's request {resends} time(s) in a way a wait \
                 may clear; the task was sent again after each, after {}s of waiting in all.",
                s["resend_wait_s"].as_u64().unwrap_or(0)
            ),
        ]);
    }
    if !s["fallback_model"].is_null() {
        out.extend([
            String::new(),
            format!(
                "The model provider stayed overloaded, so the agent was switched to the fallback \
                 model {}.",
                code(&json!(named(&s["fallback_model"])))
            ),
        ]);
    }
    if let Some(updates) = s["updates"].as_array().filter(|u| !u.is_empty()) {
        out.extend([
            String::new(),
            "Updates of the run's item sent to the agent while it worked:".to_owned(),
            String::new(),
        ]);
        out.extend(updates.iter().map(|url| format!("- {}", link(url))));
    }
    if s["shell_edits"] == true {
        out.extend([
            String::new(),
            "Warning: edited through the shell. The agent changed files without one call \
             of its edit tools."
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
    if let Some(error) = s["memory_dropped"].as_str() {
        out.extend([
            String::new(),
            format!("No memory handed back: {}", code(&json!(cut(error)))),
        ]);
    }
    if let Some(error) = s["requests_dropped"].as_str() {
        out.extend([
            String::new(),
            format!("No requests handed back: {}", code(&json!(cut(error)))),
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
    if let Some(ratio) = s["cache_ratio"].as_f64() {
        let percent = (ratio * 100.0).round();
        out.extend([
            String::new(),
            format!(
                "Prompt cache: {percent}% of input tokens read from cache{}.",
                if s["tokens_source"] == TOKENS_UNVERIFIED {
                    " (agent-reported, unverified)"
                } else {
                    ""
                }
            ),
        ]);
        if s["cache_warning"] == true {
            out.extend([
                String::new(),
                format!(
                    "Warning: this OpenAI run read only {percent}% of its input from the prompt \
                     cache, under {}% after more than {} requests: something before the new \
                     turn changes between requests, or they are not routed to the same cache.",
                    CACHE_WARNING_RATIO * 100.0,
                    CACHE_WARNING_AFTER
                ),
            ]);
        }
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
        out.extend(failures.iter().map(|f| {
            let tried = match f["resends"].as_u64() {
                Some(0) => " (the task was not sent again)".to_owned(),
                Some(n) => format!(
                    " (the task was sent again {n} time(s), after {}s of waiting)",
                    text(&f["waited_s"])
                ),
                None => String::new(),
            };
            format!("- {}: {}{tried}", text(&f["kind"]), code(&f["message"]))
        }));
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
    if let Some(found) = list(SECRET_SHAPED) {
        out.extend([
            String::new(),
            "Secret-shaped strings handed back (kept: the run holds no credential of their \
             shape; check that each is a fixture):"
                .to_owned(),
            String::new(),
        ]);
        out.extend(found.iter().map(|w| format!("- {}", text(w))));
    }
    if let Some(n) = s["redactions"].as_u64().filter(|n| *n > 0) {
        out.extend([String::new(), format!("Redacted {n} string(s).")]);
    }
    if let Some(n) = s["handback_replacements"].as_u64() {
        out.extend([
            String::new(),
            format!("Replaced {n} inference address or agent-facing token occurrence(s) in the hand-back."),
        ]);
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
            secondary_patch: Value::Null,
            memory_dropped: None,
            requests_dropped: None,
            egress_denied: Vec::new(),
            agent_logs: json!({"dir": "~/logs", "files": 1, "omitted_files": 0, "truncated": false}),
            child_logs: Value::Null,
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
            stalls: 0,
            stall_retries: 0,
            provider_error: None,
            resends: 0,
            resend_wait_s: 0,
            fallback_model: None,
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
        for (cost, budget, expected) in [
            (
                json!({"usd": 0.7912, "source": COST_METERED, "prices": "2026-10-24"}),
                json!(500),
                "$0.79 at API list prices (metered tokens, prices of 2026-10-24); budget: $5.00",
            ),
            (
                json!({"usd": 0.5, "source": COST_METERED, "prices": "2026-10-24", "partial": true}),
                json!(500),
                "at least $0.50 at API list prices (metered tokens, prices of 2026-10-24); budget: $5.00",
            ),
            (
                json!({"usd": 1, "source": COST_METERED, "prices": "\n::error::x"}),
                json!(500),
                "$1.00 at API list prices (metered tokens, prices of ?); budget: $5.00",
            ),
            (
                json!({"usd": 2.5, "source": COST_AGENT}),
                Value::Null,
                "$2.50 at API list prices (agent-reported, unverified); budget: ?",
            ),
            (
                json!({"usd": null, "source": null}),
                json!(100),
                "? at API list prices (unpriced); budget: $1.00",
            ),
            (
                json!({"usd": -1, "source": "free"}),
                json!("x"),
                "? at API list prices (unpriced); budget: ?",
            ),
            (
                Value::Null,
                Value::Null,
                "? at API list prices (unpriced); budget: ?",
            ),
        ] {
            assert_eq!(
                cost_line(&json!({"cost": cost, "aic_budget": budget})),
                format!("Cost: {expected}, capping the agent's own figure.")
            );
        }
    }

    /// The proxy's tokens at the pinned list prices, else the agent's
    /// figure only where it is a list price too.
    #[test]
    fn list_cost_sources() {
        let date = Prices::builtin().unwrap().date;
        let tokens = json!({"input": 1_000_000, "cache_read": 2_000_000, "output": 100_000});
        let unpriced = json!({"devstral-2": tokens});
        for (record, agent, pricing, want) in [
            // gpt-5.5: $5 + 2 × $0.50 + 0.1 × $30; claude-opus-5-5:
            // $4 + 2 × $0.20 + 0.1 × $20.
            (
                Some(json!({"unmetered": 0,
                    "models": {"gpt-5.5": tokens, "claude-opus-5-5": tokens}})),
                Some(0.0),
                "subscription",
                json!({"usd": 15.4, "source": COST_METERED, "partial": false,
                    "models": {"gpt-5.5": 9.0, "claude-opus-5-5": 6.4}}),
            ),
            // A model the table lacks, or a response without usage: a
            // lower bound.
            (
                Some(json!({"unmetered": 0, "models": {"gpt-5.5": tokens, "devstral-2": tokens}})),
                None,
                "unpriced",
                json!({"usd": 9.0, "source": COST_METERED, "partial": true,
                    "models": {"gpt-5.5": 9.0, "devstral-2": null}}),
            ),
            (
                Some(json!({"unmetered": 1, "models": {"gpt-5.5": tokens}})),
                None,
                "subscription",
                json!({"usd": 9.0, "source": COST_METERED, "partial": true,
                    "models": {"gpt-5.5": 9.0}}),
            ),
            // No count of responses without usage is no proof there were none.
            (
                Some(json!({"models": {"gpt-5.5": tokens}})),
                None,
                "subscription",
                json!({"usd": 9.0, "source": COST_METERED, "partial": true,
                    "models": {"gpt-5.5": 9.0}}),
            ),
            // Nothing priced: Claude Code's own list-price figure.
            (
                Some(json!({"models": unpriced})),
                Some(1.25),
                "api-equivalent",
                json!({"usd": 1.25, "source": COST_AGENT, "partial": false, "models": null}),
            ),
            (
                Some(json!({"tokens": tokens})),
                Some(1.25),
                "api-equivalent",
                json!({"usd": 1.25, "source": COST_AGENT, "partial": false, "models": null}),
            ),
            // opencode's own figure is no list price.
            (
                None,
                Some(0.0),
                "subscription",
                json!({"usd": null, "source": null, "partial": false, "models": null}),
            ),
            (
                Some(json!({"models": {"gpt-5.5": {"input": 1, "output": 1}}})),
                None,
                "api-equivalent",
                json!({"usd": null, "source": null, "partial": false, "models": null}),
            ),
        ] {
            let mut want = want;
            want["basis"] = json!("list");
            want["prices"] = json!(date);
            want["estimated"] = json!(false);
            want["estimated_models"] = json!({});
            assert_eq!(
                list_cost(record.as_ref(), agent, pricing),
                want,
                "{record:?}"
            );
        }
    }

    #[test]
    fn estimated_cost_and_rendering() {
        let prices = Prices::parse(
            "date = '2026-10-29'\n[models]\n\
             published = { input = 2.0, cached-input = 0.1, output = 10.0 }\n\
             assumed = { input = 2.0, cached-input = 0.1, output = 10.0, estimate = true, basis = 'nearest published tier: published' }"
        ).unwrap();
        let tokens = json!({"input": 1_000_000, "cache_read": 2_000_000, "output": 100_000});
        for (models, total, partial, estimated) in [
            (json!({"published": tokens}), 3.2, false, false),
            (json!({"provider/assumed": tokens}), 3.2, false, true),
            (
                json!({"published": tokens, "provider/assumed": tokens}),
                6.4,
                false,
                true,
            ),
            (
                json!({"published": tokens, "provider/assumed": tokens, "unknown": tokens}),
                6.4,
                true,
                true,
            ),
        ] {
            let record = json!({"unmetered": 0, "models": models});
            let cost =
                list_cost_with_prices(Some(&record), Some(0.0), "subscription", Some(&prices));
            assert_eq!(cost["usd"], total);
            assert_eq!(cost["source"], COST_METERED);
            assert_eq!(cost["partial"], partial);
            assert_eq!(cost["estimated"], estimated);
            assert_eq!(
                cost["estimated_models"],
                if estimated {
                    json!({"provider/assumed": "nearest published tier: published"})
                } else {
                    json!({})
                }
            );
            let summary = json!({"cost": cost});
            let rendered = markdown(&summary);
            assert_eq!(rendered.contains("est. $"), estimated, "{rendered}");
            assert_eq!(
                rendered.contains("Estimated models: `provider/assumed`."),
                estimated
            );
            assert_eq!(cost_line(&summary).contains("est. $"), estimated);
        }
        // An estimated rate with missing token counts contributes nothing.
        let record = json!({"unmetered": 0, "models": {"assumed": {"input": 1}}});
        let cost = list_cost_with_prices(Some(&record), None, "subscription", Some(&prices));
        assert!(cost["usd"].is_null());
        assert_eq!(cost["estimated"], false);
        assert_eq!(cost["estimated_models"], json!({}));
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
            "cost": {"usd": 0.01, "basis": "list", "source": COST_AGENT},
            "tools": {"Read": {"calls": 1, "errors": 0, "duration_s": 0},
                      "Bash": {"calls": 2, "errors": 1, "duration_s": 3}},
            "slowest": [{"tool": "Bash", "summary": "a | b `c`", "duration_s": 3}],
            "failures": [{"kind": "tool_error", "message": "Bash: boom"}],
            "permissions": {"allowed": 2, "denied": [{"tool": "Bash", "summary": "git push", "rule": "no-push"}]},
            "tests": [], "egress_denied": [{"domain": "evil.example", "count": 2}], "redactions": 1,
            "handback_replacements": 3,
            "patch": {"base": "abc", "error": "the change is over 64 bytes"},
            "requests_dropped": "~/out/safe-outputs.jsonl is not a regular file",
            "secret_shaped": ["safe-outputs/aw-x.patch, line 3: matches `AKIA[0-9A-Z]{16}`"],
        });
        assert_eq!(
            markdown(&s),
            "## Agent run: PVTI_x on o/r (main)

fake/default, 4 cores: **failure**

Cost: $0.01 at API list prices (agent-reported, unverified); budget: $5.00, capping the agent's own figure.

| Duration | Turns | Tokens in/out | List cost |
|---|---|---|---|
| 1m | ? | 1k / ? | $0.01 |

No change handed back: `the change is over 64 bytes`

No requests handed back: `~/out/safe-outputs.jsonl is not a regular file`

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

Secret-shaped strings handed back (kept: the run holds no credential of their shape; check that each is a fixture):

- safe-outputs/aw-x.patch, line 3: matches `AKIA[0-9A-Z]{16}`

Redacted 1 string(s).

Replaced 3 inference address or agent-facing token occurrence(s) in the hand-back.
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

    /// The updates of the run's item the agent was sent are links, and
    /// only an https URL is rendered as one.
    #[test]
    fn updates_are_links() {
        let run = json!({"repo": "o/r", "base": "main", "agent": "fake", "result": "success"});
        let mut with = run.clone();
        with["updates"] = json!([
            "https://github.com/o/r/issues/1#issuecomment-2",
            "javascript:alert(1)",
            "https://x/a b",
            "https://x/<b>"
        ]);
        let md = markdown(&with);
        assert!(
            md.contains(
                "\n- <https://github.com/o/r/issues/1#issuecomment-2>\n- `javascript:alert(1)`\n\
                 - `https://x/a b`\n- `https://x/<b>`\n"
            ),
            "{md}"
        );
        assert!(!markdown(&run).contains("Updates of the run's item"));
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

    /// A session that failed instead of returning a result is summed up
    /// from the result `run` writes in its place: a failure that says
    /// why, on one line.
    #[test]
    fn a_session_that_ended_in_an_internal_error_says_why() {
        let started = chrono::Utc::now();
        let err = anyhow::anyhow!("disk full\nno space").context("writing harness.json");
        let result = RunResult::internal_error(
            "fake".into(),
            Limits::default(),
            &err,
            started,
            started + chrono::Duration::seconds(7),
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(crate::session::RESULT_FILE),
            serde_json::to_string_pretty(&result).unwrap(),
        )
        .unwrap();
        let loaded = RunResult::load(dir.path()).unwrap();
        let (records, measured) = (initialize(), measured());
        let s = summarize(&Inputs {
            records: &records,
            result: Some(&loaded),
            measured: &measured,
            outcome: &json!({}),
            usage: None,
        });
        assert_eq!(s["result"], "failure");
        assert_eq!(s["handed_back"], false);
        assert_eq!(s["failures"][0]["kind"], "agent_exit");
        assert_eq!(
            s["failures"][0]["message"],
            "internal error: writing harness.json: disk full no space"
        );
        assert_eq!(loaded.duration_s, 7);
        assert!(markdown(&s).contains("internal error: writing harness.json"));
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
                result(Outcome::NoRequests, None, false),
                false,
                Some((
                    "stall",
                    "the agent made no model request within the first five minutes",
                )),
            ),
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
            (
                RunResult {
                    stalls: 2,
                    stall_retries: 1,
                    ..result(Outcome::Failure, Some("the agent stalled: twice"), false)
                },
                false,
                Some(("stall", "the agent stalled: twice")),
            ),
            // A failure after a stall that a retry got past is the agent's.
            (
                RunResult {
                    stalls: 1,
                    stall_retries: 1,
                    ..result(Outcome::Failure, Some("the agent stopped: refusal"), false)
                },
                false,
                Some(("agent_exit", "the agent stopped: refusal")),
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
            assert_eq!(
                (s["stalls"].as_u64(), s["stall_retries"].as_u64()),
                (
                    Some(result.stalls.into()),
                    Some(result.stall_retries.into())
                ),
                "{name}"
            );
            assert_eq!(
                markdown(&s).contains(&format!(
                    "stalled {} time(s), with nothing from it for its stall timeout; the task \
                     was sent again {} time(s).",
                    result.stalls, result.stall_retries
                )),
                result.stalls > 0,
                "{name}"
            );
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
            assert!(markdown(&s).contains("budget: $5.00,"), "{}", markdown(&s));
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
            // Only a run with a child agent says what of it was taken.
            assert!(s.get("child_logs").is_none());
            // Only a run whose broker was given an address says which.
            assert!(s.get(META_INFERENCE_ADDRESS).is_none());
        }
        let mut given = measured.clone();
        given.meta[META_INFERENCE_ADDRESS] = json!("100.64.0.1");
        let s = summarize(&Inputs {
            records: &initialize(),
            result: None,
            measured: &given,
            outcome: &Value::Null,
            usage: None,
        });
        assert_eq!(s[META_INFERENCE_ADDRESS], "100.64.0.1");
    }

    /// A run that ended on a model provider's failure is filed under its
    /// class, whatever it then came to, with the resends and the wait;
    /// one whose error fit no class, or that got past the failure, is
    /// filed as before. Every kind is one of `FAILURE_KINDS`.
    #[test]
    fn a_providers_failure_is_filed_under_its_class() {
        let records = initialize();
        let measured = measured();
        let ended = |outcome, message: &str, class, resends, waited| RunResult {
            provider_error: class,
            resends,
            resend_wait_s: waited,
            ..result(outcome, Some(message), false)
        };
        // A run whose agent handed back after the failure is a partial
        // result at a limit, not an inference failure to repeat.
        let handed_back = RunResult {
            handed_back: true,
            ..ended(
                Outcome::Timeout,
                "hit the timeout, after session/prompt failed: Rate limit exceeded; the agent handed back",
                Some(Class::RateLimited),
                1,
                10,
            )
        };
        // (the result, the kind, the resends said in the summary)
        let cases = [
            (
                ended(
                    Outcome::Failure,
                    "the agent exited (exit status: 0) after the provider rate-limited a request",
                    Some(Class::RateLimited),
                    3,
                    70,
                ),
                "inference_rate_limited",
                Some("(the task was sent again 3 time(s), after 70s of waiting)"),
            ),
            (
                ended(
                    Outcome::Budget,
                    "the agent's turn ended on an error; the agent handed back",
                    Some(Class::Overloaded),
                    0,
                    0,
                ),
                "inference_overloaded",
                Some("(the task was not sent again)"),
            ),
            (
                ended(
                    Outcome::Timeout,
                    "hit the timeout, after session/prompt failed: connection refused",
                    Some(Class::Unreachable),
                    1,
                    10,
                ),
                "inference_unreachable",
                Some("(the task was sent again 1 time(s), after 10s of waiting)"),
            ),
            (
                ended(
                    Outcome::Failure,
                    "the model provider refused the agent's request: usage limit reached",
                    Some(Class::Quota),
                    0,
                    0,
                ),
                "inference_quota",
                Some("(the task was not sent again)"),
            ),
            (
                ended(
                    Outcome::Failure,
                    "session/prompt failed: invalid x-api-key",
                    Some(Class::Unauthorized),
                    0,
                    0,
                ),
                "inference_unauthorized",
                Some("(the task was not sent again)"),
            ),
            (
                ended(
                    Outcome::Failure,
                    "session/prompt failed: Internal error",
                    Some(Class::Other),
                    0,
                    0,
                ),
                "agent_exit",
                None,
            ),
            (
                ended(Outcome::Failure, "the agent failed", None, 2, 30),
                "agent_exit",
                None,
            ),
            (handed_back, "timeout", None),
            // Nor one the provider stopped that handed back its tree.
            (
                ended(
                    Outcome::Failure,
                    "session/prompt failed: API Error: 529 Overloaded",
                    Some(Class::Overloaded),
                    6,
                    250,
                )
                .stopped_by_provider()
                .unwrap(),
                "budget",
                None,
            ),
        ];
        for (result, kind, tried) in cases {
            let s = summarize(&Inputs {
                records: &records,
                result: Some(&result),
                measured: &measured,
                outcome: &json!({}),
                usage: None,
            });
            let failure = &s["failures"][0];
            assert_eq!(failure["kind"], kind, "{result:?}");
            assert!(FAILURE_KINDS.contains(&kind), "{kind}");
            assert_eq!(
                failure.get("resends").is_some(),
                tried.is_some(),
                "{result:?}"
            );
            assert_eq!(s["provider_error"], json!(result.provider_error));
            assert_eq!(s["resends"], result.resends);
            assert_eq!(s["resend_wait_s"], result.resend_wait_s);
            let md = markdown(&s);
            let line = md
                .lines()
                .find(|l| l.starts_with(&format!("- {kind}: ")))
                .unwrap_or_else(|| panic!("{md}"));
            match tried {
                Some(tried) => assert!(line.ends_with(tried), "{line}"),
                None => assert!(line.ends_with('`'), "{line}"),
            }
            assert_eq!(
                md.contains("The model provider failed the agent's request"),
                result.resends > 0,
                "{md}"
            );
            // A run stopped early after the provider's failure is not
            // said to have been stopped at a limit.
            let early = s["stopped_early"] == true;
            let by_provider = result.provider_error.is_some_and(|c| c.kind().is_some());
            assert_eq!(
                md.contains("\nStopped early after the model provider's failure: "),
                early && by_provider,
                "{md}"
            );
            assert_eq!(
                md.contains("\nStopped at a limit: "),
                early && !by_provider,
                "{md}"
            );
        }
        // A run that got past the failure and ended well files none.
        let passed = RunResult {
            resends: 1,
            resend_wait_s: 10,
            ..result(Outcome::Success, None, false)
        };
        let s = summarize(&Inputs {
            records: &records,
            result: Some(&passed),
            measured: &measured,
            outcome: &json!({}),
            usage: None,
        });
        assert_eq!(s["failures"], json!([]));
        assert_eq!(s["provider_error"], Value::Null);
        assert!(markdown(&s).contains(
            "failed the agent's request 1 time(s) in a way a wait may clear; the task \
                 was sent again after each, after 10s of waiting in all."
        ));
        assert_eq!(s["fallback_model"], Value::Null);
        assert!(!markdown(&s).contains("fallback model"));
        // One that got past it on the fallback model says so.
        let switched = RunResult {
            fallback_model: Some("opus".to_owned()),
            ..passed
        };
        let s = summarize(&Inputs {
            records: &records,
            result: Some(&switched),
            measured: &measured,
            outcome: &json!({}),
            usage: None,
        });
        assert_eq!(s["fallback_model"], "opus");
        assert!(markdown(&s).contains(
            "The model provider stayed overloaded, so the agent was switched to the fallback \
             model `opus`."
        ));
        for class in Class::ALL {
            if let Some(kind) = class.kind() {
                assert!(FAILURE_KINDS.contains(&kind), "{kind}");
            }
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
        assert_eq!(s["cache_ratio"], 0.6);
        assert!(
            md.contains("Prompt cache: 60% of input tokens read from cache."),
            "{md}"
        );
        // Anything else is not a record.
        let s = summarize_with(Some(&json!({"schema": "other/v1"})));
        assert_eq!(s["praxis"], Value::Null);
        assert_eq!(s["tokens_source"], Value::Null);
        assert_eq!(s["cache_ratio"], Value::Null);
        let md = markdown(&s);
        assert!(!md.contains("Inference:"));
        assert!(!md.contains("Prompt cache:"));
    }

    /// An OpenAI run past its first turns that reads little from the
    /// prompt cache is warned about. The first case is a review run of 28
    /// October (40897324729), the second about Claude's share then.
    #[test]
    fn a_low_openai_cache_share_is_warned_about() {
        const WARNING: &str = "Warning: this OpenAI run read only";
        /// Agent, requests, uncached and cached input, share, warned.
        type Case = (&'static str, Option<u64>, u64, u64, f64, bool);
        let cases: &[Case] = &[
            ("opencode", Some(64), 5_185_347, 1_857_664, 0.26, true),
            ("opencode", Some(64), 300_000, 6_700_000, 0.96, false),
            // At or before the third request, a cold cache is expected.
            ("opencode", Some(3), 900, 100, 0.1, false),
            ("opencode", Some(4), 900, 100, 0.1, true),
            ("opencode", Some(4), 500, 500, 0.5, false),
            // The share is compared before it is rounded.
            ("opencode", Some(4), 5050, 4950, 0.5, true),
            // No count of requests from the proxy, no warning.
            ("opencode", None, 900, 100, 0.1, false),
            // Claude's and Vibe's runs get the share, not the warning.
            ("claude", Some(64), 900, 100, 0.1, false),
            ("vibe", Some(64), 900, 100, 0.1, false),
        ];
        let records = initialize();
        for &(agent, requests, input, cached, ratio, warned) in cases {
            let record = json!({
                "schema": RECORD_SCHEMA, "state": "finished", "requests": requests, "unmetered": 0,
                "tokens": {"input": input, "cache_read": cached, "output": 1, "total": input + cached + 1},
            });
            let measured = Measured {
                agent: agent.into(),
                ..measured()
            };
            let s = summarize(&Inputs {
                records: &records,
                result: None,
                measured: &measured,
                outcome: &json!({}),
                usage: Some(&record),
            });
            let case = format!("{agent} {requests:?} {input} {cached}");
            assert_eq!(s["cache_ratio"], ratio, "{case}");
            assert_eq!(s["cache_warning"], warned, "{case}");
            let md = markdown(&s);
            assert_eq!(md.contains(WARNING), warned, "{case}: {md}");
        }
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
        let measured = Measured {
            agent: "opencode".into(),
            ..measured()
        };
        let done = result(Outcome::Success, None, false);
        let s = summarize(&Inputs {
            records: &records,
            result: Some(&done),
            measured: &measured,
            outcome: &json!({}),
            usage: None,
        });
        // The agent's share is given as its word, and warns of nothing.
        assert_eq!(s["cache_ratio"], 0.17);
        assert_eq!(s["cache_warning"], false);
        assert!(markdown(&s).contains(
            "Prompt cache: 17% of input tokens read from cache (agent-reported, unverified)."
        ));
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

    /// A change with no finished call of an edit kind that did not fail is
    /// flagged; a change made with one, or no change at all, is not.
    #[test]
    fn shell_edits_are_flagged() {
        const WARNING: &str = "edited through the shell";
        const OK: &str = "completed";
        const FAILED: &str = "failed";
        const PENDING: &str = "in_progress";
        for (calls, files, flagged) in [
            (&[("execute", OK)][..], &["a.rs"][..], true),
            (&[], &["a.rs"], true),
            (&[("read", OK), ("execute", OK)], &["a.rs"], true),
            (&[("edit", FAILED), ("execute", OK)], &["a.rs"], true),
            (&[("execute", OK), ("edit", PENDING)], &["a.rs"], true),
            (&[("execute", OK), ("edit", OK)], &["a.rs"], false),
            (&[("edit", FAILED), ("edit", OK)], &["a.rs"], false),
            (&[("edit", OK)], &["a.rs", "b.rs"], false),
            (&[("delete", OK)], &["a.rs"], false),
            (&[("move", OK)], &["a.rs", "b.rs"], false),
            (&[("execute", OK)], &[], false),
            (&[], &[], false),
        ] {
            let mut records = Vec::from(initialize());
            records.extend(calls.iter().enumerate().map(|(i, (kind, status))| {
                rec(
                    1.0,
                    Dir::Recv,
                    json!({"jsonrpc": "2.0", "method": "session/update",
                    "params": {"sessionId": "s", "update": {"sessionUpdate": "tool_call",
                    "toolCallId": format!("t{i}"), "title": "T", "kind": kind,
                    "status": status}}}),
                )
            }));
            let mut measured = measured();
            measured.files = files.iter().map(|f| (*f).to_owned()).collect();
            let s = summarize(&Inputs {
                records: &records,
                result: Some(&result(Outcome::Success, None, false)),
                measured: &measured,
                outcome: &json!({}),
                usage: None,
            });
            assert_eq!(s["shell_edits"], flagged, "{calls:?} {files:?}");
            assert_eq!(markdown(&s).contains(WARNING), flagged, "{calls:?}");
        }
    }
}
