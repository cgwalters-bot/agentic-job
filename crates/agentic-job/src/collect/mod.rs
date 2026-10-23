//! `agentic-job collect`: what gh-aw's collector (`collect_ndjson_output.cjs`
//! at the commit check.yml pins) makes of a hand-back's `outputs.jsonl`:
//! check.yml's collector wherever it takes every type the policy allows,
//! and a caller's off GitHub, which has no `actions/github-script` to run
//! gh-aw's in. It writes the `{items, errors}` that `check --collected` reads.
//!
//! The requests it takes are those of [`TYPES`], each validated and its
//! text sanitized as gh-aw's collector does for that type ([`sanitize`]).
//! Any other type is an error, even where the policy allows it: passed on
//! unvalidated, it would reach an applier unsanitized. Only `handback
//! check`, which applies nothing, passes one on ([`Unported::PassOn`]). Fixtures that
//! gh-aw's collector wrote, on the same lines and configuration, hold the
//! two to the same result (`tests/data/collect`).
//!
//! Where the two differ, this mostly refuses more: a line that is not
//! JSON is not repaired, nor is JSON that serde_json cannot hold (a lone
//! surrogate, a number past f64, nesting past 128); a whole number written
//! `1.0` stays a float, which `check` refuses where it wants a number. A
//! numeric entity for a lone surrogate becomes U+FFFD. Otherwise they
//! differ only where JavaScript and Rust read text apart and no renderer
//! does: U+2028 and U+2029 as line ends, a carriage return just before the
//! fence that balancing adds. Like gh-aw's, it leaves mentions in what is
//! posted (`add_comment`, `create_pull_request`) to the applier, which
//! knows who may be mentioned there, and it does not add gh-aw's
//! incomplete report to a result without requests, which `check` would
//! drop.
//!
//! It is also what `handback check` validates the requests with in the
//! session, and check.yml's collector for a policy whose types are all
//! [`TYPES`], so the agent is told of a field error in the words the
//! check job refuses it in. [`field_guide`] tells it the fields.

pub(crate) mod markdown;
mod sanitize;

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Serialize;
#[cfg(test)]
use serde_json::json;
use serde_json::{Map, Value};

use self::sanitize::{is_js_space, js_trim};
use crate::check::{MAX_OUTPUTS_BYTES, OUTPUTS_FILE};
use crate::exit::Exit;
use crate::files::{self, ReadError};
use crate::policy::Policy;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The policy.json that `policy` printed for this run
    #[arg(long, value_name = "FILE")]
    pub policy: PathBuf,
    /// The directory holding the handed-back outputs
    #[arg(long, value_name = "DIR", required_unless_present = "unported")]
    pub outputs: Option<PathBuf>,
    /// Where to write what was collected, which `check --collected` reads
    #[arg(long, value_name = "FILE", required_unless_present = "unported")]
    pub collected: Option<PathBuf>,
    /// Collect nothing: print, a line each, the types the policy allows
    /// that this does not validate, for which gh-aw's collector is needed
    #[arg(long, conflicts_with_all = ["outputs", "collected"])]
    pub unported: bool,
}

/// What [`collect`] does with a request of a type the policy allows and
/// [`TYPES`] does not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unported {
    /// Refuse it: passed on, it would reach an applier unsanitized.
    Refuse,
    /// Pass it on as it is, for `handback check`, where nothing is
    /// applied and the check job's collector validates it later.
    PassOn,
}

/// What the collector made of the requests: those it took, sanitized,
/// and why it refused the others.
#[derive(Debug, Default, PartialEq, Serialize)]
pub struct Collected {
    pub items: Vec<Map<String, Value>>,
    pub errors: Vec<String>,
}

/// The longest text gh-aw's validator gives a sanitized field without a
/// `maxLength` of its own (`MAX_BODY_LENGTH`).
const MAX_BODY_LENGTH: usize = 65_000;

/// What an output type's field must be, in the terms of gh-aw's
/// `validation.json`, which [`Rule::to_json`] writes it in.
#[derive(Debug)]
enum Rule {
    /// A string, sanitized to at most its length where that is set.
    Text {
        required: bool,
        sanitize: bool,
        max_length: Option<usize>,
    },
    /// One of these strings, in any case.
    Choice(&'static [&'static str]),
    /// A string matching this pattern once trimmed.
    Pattern(&'static LazyLock<Regex>),
    Flag,
    /// `optionalPositiveInteger`: a number, or a string JavaScript's
    /// `parseInt` reads as one.
    PositiveInteger,
    /// `issueOrPRNumber`: a number or a string, taken as it is.
    IssueOrPrNumber,
    /// Strings, each sanitized to at most this length.
    TextList(usize),
}

#[derive(Debug)]
struct Field {
    name: &'static str,
    rule: Rule,
}

/// An output type the collector takes: its default count and fields, as
/// gh-aw's `validation.json` has them, in its order (a test holds them
/// to it), and whether its mentions are left to the applier.
#[derive(Debug)]
struct OutputType {
    name: &'static str,
    default_max: u32,
    defers_mentions: bool,
    fields: &'static [Field],
}

static TEMPORARY_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^#?aw_[A-Za-z0-9_]{3,12}$").expect("a valid pattern"));

const fn text(name: &'static str, max_length: usize) -> Field {
    Field {
        name,
        rule: Rule::Text {
            required: false,
            sanitize: true,
            max_length: Some(max_length),
        },
    }
}

const fn required_text(name: &'static str, max_length: usize) -> Field {
    Field {
        name,
        rule: Rule::Text {
            required: true,
            sanitize: true,
            max_length: Some(max_length),
        },
    }
}

/// A string passed on as it is, its `maxLength` unused (gh-aw applies it
/// only when sanitizing).
const fn raw_text(name: &'static str, max_length: usize) -> Field {
    Field {
        name,
        rule: Rule::Text {
            required: false,
            sanitize: false,
            max_length: Some(max_length),
        },
    }
}

const fn field(name: &'static str, rule: Rule) -> Field {
    Field { name, rule }
}

/// The output types that are collected.
const TYPES: &[OutputType] = &[
    OutputType {
        name: "add_comment",
        default_max: 1,
        defers_mentions: true,
        fields: &[
            required_text("body", MAX_BODY_LENGTH),
            field("comment_id", Rule::PositiveInteger),
            field("item_number", Rule::IssueOrPrNumber),
            field("pr", Rule::IssueOrPrNumber),
            field("pr_number", Rule::IssueOrPrNumber),
            raw_text("reply_to_id", 256),
            raw_text("repo", 256),
            field("target", Rule::Choice(&["status"])),
            field("temporary_id", Rule::Pattern(&TEMPORARY_ID_RE)),
        ],
    },
    OutputType {
        name: "create_pull_request",
        default_max: 1,
        defers_mentions: true,
        fields: &[
            text("base", 128),
            required_text("body", MAX_BODY_LENGTH),
            required_text("branch", 256),
            field("dependencies", Rule::TextList(256)),
            field("draft", Rule::Flag),
            field("labels", Rule::TextList(128)),
            raw_text("repo", 256),
            field("stack_position", Rule::PositiveInteger),
            text("stack_root", 256),
            field("temporary_id", Rule::Pattern(&TEMPORARY_ID_RE)),
            required_text("title", 128),
        ],
    },
    OutputType {
        name: "noop",
        default_max: 2,
        defers_mentions: false,
        fields: &[required_text("message", MAX_BODY_LENGTH)],
    },
    OutputType {
        name: "missing_tool",
        default_max: 20,
        defers_mentions: false,
        fields: &[
            text("alternatives", 512),
            required_text("reason", 256),
            text("tool", 128),
        ],
    },
    OutputType {
        name: "missing_data",
        default_max: 20,
        defers_mentions: false,
        fields: &[
            text("alternatives", 256),
            text("context", 256),
            text("data_type", 128),
            text("reason", 256),
        ],
    },
];

/// The `noop` messages gh-aw takes for an agent trying the tool out, and
/// drops without counting (`intent_probe.cjs`).
const PROBE_MESSAGES: &[&str] = &[
    "test",
    "testing",
    "test no base",
    "probe",
    "placeholder",
    "dummy",
    "temp",
    "temporary",
    "todo",
    "tbd",
    "wip",
    "example",
];

impl Rule {
    /// The rule as gh-aw's `validation.json` writes it.
    #[cfg(test)]
    fn to_json(&self) -> Value {
        match self {
            Self::Text {
                required,
                sanitize,
                max_length,
            } => {
                let mut rule = Map::new();
                if *required {
                    rule.insert("required".into(), true.into());
                }
                rule.insert("type".into(), "string".into());
                if *sanitize {
                    rule.insert("sanitize".into(), true.into());
                }
                if let Some(max) = max_length {
                    rule.insert("maxLength".into(), (*max).into());
                }
                Value::Object(rule)
            }
            Self::Choice(choices) => json!({"type": "string", "enum": choices}),
            Self::Pattern(re) => json!({"type": "string", "pattern": re.as_str()}),
            Self::Flag => json!({"type": "boolean"}),
            Self::PositiveInteger => json!({"optionalPositiveInteger": true}),
            Self::IssueOrPrNumber => json!({"issueOrPRNumber": true}),
            Self::TextList(max) => json!({
                "type": "array", "itemType": "string", "itemSanitize": true, "itemMaxLength": max
            }),
        }
    }

    /// What the rule wants, for the agent: [`field_guide`].
    fn describe(&self) -> String {
        match self {
            // The length is kept to only where the text is sanitized.
            Self::Text {
                required,
                sanitize,
                max_length,
            } => {
                let mut what = "string".to_owned();
                if *required {
                    what.push_str(", required");
                }
                if let (true, Some(max)) = (sanitize, max_length) {
                    what.push_str(&format!(", cut to {max} characters"));
                }
                what
            }
            Self::Choice(choices) => format!("one of: {}", choices.join(", ")),
            Self::Pattern(re) => format!("string matching `{}`", re.as_str()),
            Self::Flag => "boolean".to_owned(),
            Self::PositiveInteger => "positive integer".to_owned(),
            Self::IssueOrPrNumber => "number or string".to_owned(),
            Self::TextList(max) => format!("list of strings, each cut to {max} characters"),
        }
    }

    /// How gh-aw names the rule where a value got past it unconverted.
    fn kind(&self) -> &'static str {
        match self {
            Self::Text { .. } | Self::Choice(_) | Self::Pattern(_) => "type=string",
            Self::Flag => "type=boolean",
            Self::PositiveInteger => "optionalPositiveInteger",
            Self::IssueOrPrNumber => "issueOrPRNumber",
            Self::TextList(_) => "type=array",
        }
    }
}

/// The type of a JSON value as JavaScript's `typeof` names it.
fn js_type(value: &Value) -> &'static str {
    match value {
        Value::Null | Value::Array(_) | Value::Object(_) => "object",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
    }
}

/// Whether JavaScript takes VALUE for true.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|n| n != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// A number as JavaScript writes it, near enough for an error message.
fn js_number(n: f64) -> String {
    if n == n.trunc() && n.abs() < 1e21 {
        format!("{}", n as i128)
    } else {
        format!("{n}")
    }
}

/// JavaScript's `parseInt(text, 10)`: the digits after any whitespace and
/// a sign, up to the first other character.
fn js_parse_int(text: &str) -> Option<f64> {
    let text = text.trim_start_matches(is_js_space);
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let digits = &digits[..digits.bytes().take_while(u8::is_ascii_digit).count()];
    let value: f64 = digits.parse().ok()?;
    Some(if negative { -value } else { value })
}

impl Field {
    /// Whether VALUE, blank, means the field was left out: for a field
    /// that is not free text (`isBlankOptionalField`).
    fn blank_means_absent(&self, value: &Value) -> bool {
        let blank = value.as_str().is_some_and(|s| js_trim(s).is_empty());
        let free_text = matches!(self.rule, Rule::Text { .. }) && self.name != "stack_root";
        blank && !free_text && !matches!(self.rule, Rule::Text { required: true, .. })
    }

    /// VALUE as gh-aw's `validateField` passes it on, if at all, for a
    /// request of type OF on line LINE.
    fn validate(
        &self,
        value: Option<&Value>,
        of: &OutputType,
        line: usize,
        keeps_link: &dyn Fn(&str) -> bool,
    ) -> Result<Option<Value>, String> {
        let (name, type_name) = (self.name, of.name);
        let at = format!("Line {line}: {type_name} '{name}'");
        let required = matches!(self.rule, Rule::Text { required: true, .. });
        let missing = || format!("Line {line}: {type_name} requires a '{name}' field (string)");
        let value = match value {
            None | Some(Value::Null) if required => return Err(missing()),
            None | Some(Value::Null) => return Ok(None),
            Some(value) => value,
        };
        let sanitize =
            |text: &str, max: usize| sanitize::sanitize(text, max, !of.defers_mentions, keeps_link);
        let number_or_string = || match value {
            Value::Number(_) | Value::String(_) => Ok(()),
            _ => Err(format!("{at} must be a number or string")),
        };
        let string = || {
            value.as_str().ok_or_else(|| {
                if required {
                    missing()
                } else {
                    format!("{at} must be a string")
                }
            })
        };
        match &self.rule {
            Rule::Text {
                sanitize: wanted,
                max_length,
                ..
            } => {
                let text = string()?;
                if required && js_trim(text).is_empty() {
                    return Err(missing());
                }
                if *wanted {
                    let max = max_length.unwrap_or(MAX_BODY_LENGTH);
                    Ok(Some(sanitize(&markdown::unfence(text), max).into()))
                } else {
                    Ok(Some(text.into()))
                }
            }
            Rule::Choice(choices) => {
                let text = string()?.to_lowercase();
                match choices.iter().find(|choice| choice.to_lowercase() == text) {
                    Some(choice) => Ok(Some((*choice).into())),
                    None if choices.len() == 2 => {
                        Err(format!("{at} must be '{}' or '{}'", choices[0], choices[1]))
                    }
                    None => Err(format!("{at} must be one of: {}", choices.join(", "))),
                }
            }
            Rule::Pattern(re) => {
                let text = string()?;
                if re.is_match(js_trim(text)) {
                    Ok(Some(text.into()))
                } else {
                    Err(format!("{at} must match pattern {}", re.as_str()))
                }
            }
            Rule::Flag => match value {
                Value::Bool(_) => Ok(Some(value.clone())),
                _ => Err(format!("{at} must be a boolean")),
            },
            Rule::PositiveInteger => {
                number_or_string()?;
                let (parsed, shown) = match value {
                    Value::String(s) => (js_parse_int(s), s.clone()),
                    _ => {
                        let n = value.as_f64().unwrap_or(f64::NAN);
                        (Some(n), js_number(n))
                    }
                };
                match parsed {
                    Some(n) if n > 0.0 && n == n.trunc() && n.is_finite() => {
                        // Whole, as JavaScript writes it, not `5.0`.
                        Ok(Some(if n < 2f64.powi(53) {
                            (n as u64).into()
                        } else {
                            n.into()
                        }))
                    }
                    _ => Err(format!(
                        "{at} must be a valid positive integer (got: {shown})"
                    )),
                }
            }
            Rule::IssueOrPrNumber => {
                number_or_string()?;
                Ok(Some(value.clone()))
            }
            Rule::TextList(max) => {
                let Value::Array(entries) = value else {
                    return Err(format!("{at} must be an array"));
                };
                entries
                    .iter()
                    .map(|entry| {
                        entry.as_str().map(|s| sanitize(s, *max).into()).ok_or_else(|| {
                            format!("Line {line}: {type_name} {name} array must contain only strings")
                        })
                    })
                    .collect::<Result<Vec<Value>, _>>()
                    .map(|list| Some(Value::Array(list)))
            }
        }
    }
}

impl OutputType {
    /// ITEM, from line LINE, as gh-aw's `validateItem` passes it on: its
    /// type and its fields, each validated, and nothing else.
    fn validate(
        &self,
        item: &Map<String, Value>,
        line: usize,
        keeps_link: &dyn Fn(&str) -> bool,
    ) -> Result<Map<String, Value>, String> {
        let mut validated = Map::new();
        validated.insert("type".into(), self.name.into());
        let mut first_error = None;
        for field in self.fields {
            let value = item
                .get(field.name)
                .filter(|value| !field.blank_means_absent(value));
            match field.validate(value, self, line, keeps_link) {
                Ok(Some(valid)) => {
                    validated.insert(field.name.into(), valid);
                }
                Ok(None) => {
                    if let Some(value) = value {
                        first_error.get_or_insert_with(|| {
                            format!(
                                "Line {line}: {} '{}' validation ({}) accepted {} but did not \
                                 produce a normalized value",
                                self.name,
                                field.name,
                                field.rule.kind(),
                                js_type(value)
                            )
                        });
                    }
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        if item.contains_key("data") {
            return Err(format!(
                "Line {line}: {} 'data' is not enabled (set safe-outputs.data in workflow \
                 frontmatter)",
                self.name
            ));
        }
        Ok(validated)
    }
}

/// The fields of the output type NAME, as [`collect`] validates them, for
/// the agent's guide: `` `body` (string, required, …), `item_number`
/// (number or string) ``. None for a type it does not validate.
pub fn field_guide(name: &str) -> Option<String> {
    let of = TYPES.iter().find(|of| of.name == name)?;
    let fields: Vec<String> = of
        .fields
        .iter()
        .map(|field| format!("`{}` ({})", field.name, field.rule.describe()))
        .collect();
    Some(fields.join(", "))
}

/// The types POLICY allows that [`collect`] does not validate.
pub fn unported(policy: &Policy) -> Vec<&str> {
    policy
        .safe_outputs
        .types()
        .filter(|name| !TYPES.iter().any(|of| of.name == *name))
        .collect()
}

/// The configuration the collector is given for POLICY: its
/// `safe_outputs`, with its secondary pull request's `max` added to
/// `create_pull_request`'s, since the collector counts a pull request of
/// either repository alike; `check` counts each against its own.
pub fn config(policy: &Policy) -> Result<Map<String, Value>> {
    let Value::Object(mut config) = serde_json::to_value(&policy.safe_outputs)? else {
        bail!("the policy's safe_outputs is not an object");
    };
    if let Some(secondary) = &policy.secondary_pull_request
        && let Some(Value::Object(pull)) = config.get_mut("create_pull_request")
    {
        let max = pull.get("max").and_then(Value::as_u64).unwrap_or(0);
        pull.insert("max".into(), (max + u64::from(secondary.max)).into());
    }
    Ok(config)
}

/// What [`collect`] makes of the `outputs.jsonl` in OUTPUTS under
/// POLICY: none at all if there is none, as gh-aw's collector takes a
/// missing file.
pub fn collect_dir(outputs: &Path, policy: &Policy, unported: Unported) -> Result<Collected> {
    let path = outputs.join(OUTPUTS_FILE);
    let text = match files::read_regular(&path, MAX_OUTPUTS_BYTES) {
        Ok(bytes) => {
            String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))?
        }
        Err(ReadError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => bail!("{} {err}", path.display()),
    };
    Ok(collect(
        &text,
        &config(policy)?,
        &|host| policy.keeps_link_to(host),
        unported,
    ))
}

/// Whether a `noop`'s MESSAGE is an agent trying the tool out.
fn is_probe(message: Option<&Value>) -> bool {
    let Some(Value::String(message)) = message else {
        return false;
    };
    let words: Vec<&str> = message
        .split(is_js_space)
        .filter(|w| !w.is_empty())
        .collect();
    PROBE_MESSAGES.contains(&words.join(" ").to_lowercase().as_str())
}

/// What gh-aw's collector makes of TEXT, the lines of an `outputs.jsonl`,
/// under CONFIG, the policy's `safe_outputs` as its `config.json`, with
/// https links kept to the hosts KEEPS_LINK takes.
pub fn collect(
    text: &str,
    config: &Map<String, Value>,
    keeps_link: &dyn Fn(&str) -> bool,
    unported: Unported,
) -> Collected {
    let config: Map<String, Value> = config
        .iter()
        .map(|(name, value)| (name.replace('-', "_"), value.clone()))
        .collect();
    let mut collected = Collected::default();
    for (index, line) in js_trim(text).split('\n').enumerate() {
        let line_text = js_trim(line);
        if line_text.is_empty() {
            continue;
        }
        let taken = &collected.items;
        match request(index + 1, line_text, &config, taken, keeps_link, unported) {
            Ok(Some(item)) => collected.items.push(item),
            Ok(None) => {}
            Err(error) => collected.errors.push(error),
        }
    }
    collected
}

/// The request on line LINE, TEXT, validated, if it is not dropped, or
/// why it is refused, given the requests TAKEN before it.
fn request(
    line: usize,
    text: &str,
    config: &Map<String, Value>,
    taken: &[Map<String, Value>],
    keeps_link: &dyn Fn(&str) -> bool,
    unported: Unported,
) -> Result<Option<Map<String, Value>>, String> {
    let item: Map<String, Value> = match serde_json::from_str(text) {
        Ok(Value::Object(item)) => item,
        Ok(_) => return Err(format!("Line {line}: Missing required 'type' field")),
        Err(err) => return Err(format!("Line {line}: Invalid JSON - {err}")),
    };
    let kind = match item.get("type") {
        Some(Value::String(kind)) if !kind.is_empty() => kind.replace('-', "_"),
        Some(kind) if truthy(kind) => {
            return Err(format!(
                "Line {line}: Invalid JSON - 'type' is not a string"
            ));
        }
        _ => return Err(format!("Line {line}: Missing required 'type' field")),
    };
    let Some(limits) = config.get(&kind).filter(|limits| truthy(limits)) else {
        let expected: Vec<&str> = config.keys().map(String::as_str).collect();
        return Err(format!(
            "Line {line}: Unexpected output type '{kind}'. Expected one of: {}",
            expected.join(", ")
        ));
    };
    if kind == "noop" && is_probe(item.get("message")) {
        return Ok(None);
    }
    let of = TYPES.iter().find(|of| of.name == kind);
    let max = limits
        .get("max")
        .filter(|max| truthy(max))
        .and_then(Value::as_f64)
        .unwrap_or_else(|| of.map_or(1.0, |of| f64::from(of.default_max)));
    let count = taken.iter().filter(|item| item["type"] == kind).count();
    if count as f64 >= max {
        return Err(format!(
            "Line {line}: Too many items of type '{kind}'. Maximum allowed: {}.",
            js_number(max)
        ));
    }
    let Some(of) = of else {
        if unported == Unported::PassOn {
            let mut item = item;
            item.insert("type".into(), kind.into());
            return Ok(Some(item));
        }
        let known: Vec<&str> = TYPES.iter().map(|of| of.name).collect();
        return Err(format!(
            "Line {line}: Unsupported output type '{kind}': agentic-job collect validates only {}",
            known.join(", ")
        ));
    };
    of.validate(&item, line, keeps_link).map(Some)
}

pub fn run(args: &Args) -> Result<Exit> {
    let policy = Policy::load(&args.policy)?;
    let (Some(outputs), Some(path)) = (&args.outputs, &args.collected) else {
        for name in unported(&policy) {
            println!("{name}");
        }
        return Ok(Exit::Success);
    };
    let collected = collect_dir(outputs, &policy, Unported::Refuse)?;
    let json = serde_json::to_string(&collected).context("writing what was collected")?;
    std::fs::write(path, json + "\n").with_context(|| format!("writing {}", path.display()))?;
    for error in &collected.errors {
        eprintln!("error: {}", crate::run::enter::one_line(error));
    }
    Ok(if collected.errors.is_empty() {
        Exit::Success
    } else {
        Exit::Failure
    })
}

#[cfg(test)]
mod tests;
