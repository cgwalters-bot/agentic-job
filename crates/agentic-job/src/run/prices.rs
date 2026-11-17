//! A run's cost at API list prices, from the token counts the inference
//! proxy metered and the pinned price table (`prices.toml`).
//!
//! The agent's own figure is not used where this one exists: opencode
//! prices a model from its configuration's `cost`, which the run's
//! provider at the proxy has none of, so it reports nothing for a run
//! served by a subscription, and whatever an agent reports is its word.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

const TABLE: &str = include_str!("prices.toml");
/// Prices are per this many tokens.
const PER_TOKENS: f64 = 1_000_000.0;
/// The length of a date suffix of a model's name (`-20251101`).
const DATE_DIGITS: usize = 8;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    date: String,
    models: BTreeMap<String, Rates>,
}

/// USD per million tokens.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Rates {
    pub input: f64,
    pub cached_input: f64,
    pub output: f64,
    #[serde(default)]
    pub estimate: bool,
    pub basis: Option<String>,
}

/// Token counts as the proxy's record has them: `input` without the
/// cached part, and `output` with any reasoning.
#[derive(Debug, Clone, Copy)]
pub struct Tokens {
    pub input: u64,
    pub cached: u64,
    pub output: u64,
}

impl Rates {
    pub fn cost(&self, tokens: Tokens) -> f64 {
        (tokens.input as f64 * self.input
            + tokens.cached as f64 * self.cached_input
            + tokens.output as f64 * self.output)
            / PER_TOKENS
    }
}

#[derive(Debug)]
pub struct Prices {
    /// When the providers published these prices.
    pub date: String,
    rates: BTreeMap<String, Rates>,
}

impl Prices {
    pub fn builtin() -> Result<Self> {
        Self::parse(TABLE)
    }

    pub(super) fn parse(text: &str) -> Result<Self> {
        let table: Table = toml::from_str(text).context("parsing the price table")?;
        let mut rates = BTreeMap::new();
        for (name, rate) in table.models {
            ensure!(
                !rate.estimate
                    || rate.basis.as_deref().is_some_and(|basis| {
                        !basis.trim().is_empty() && !basis.contains(['\n', '\r'])
                    }),
                "the price table's {name:?} estimate requires a nonempty one-line basis"
            );
            ensure!(
                [rate.input, rate.cached_input, rate.output]
                    .iter()
                    .all(|n| n.is_finite() && *n >= 0.0),
                "the price table's {name:?} has a price that is not a number of dollars"
            );
            ensure!(
                rates.insert(key(&name), rate).is_none(),
                "the price table names {name:?} twice"
            );
        }
        Ok(Self {
            date: table.date,
            rates,
        })
    }

    /// The rates of MODEL, if the table has it.
    pub fn rates(&self, model: &str) -> Option<&Rates> {
        self.rates.get(&key(model))
    }
}

/// A model's name as the table is looked up by: the part after the
/// provider (`praxis/`), without Claude Code's context suffix (`[1m]`)
/// or a date (Anthropic's `-20251101`, OpenAI's `-2025-08-07`), lower
/// case, dots as dashes (GitHub's `claude-sonnet-4.5`). Never a prefix:
/// `gpt-5` is not `gpt-5-mini`.
fn key(model: &str) -> String {
    let name = model.rsplit('/').next().unwrap_or(model);
    let name = name.split('[').next().unwrap_or(name);
    let name = name.to_ascii_lowercase().replace('.', "-");
    let parts: Vec<&str> = name.split('-').collect();
    let digits = |part: &str, n: usize| part.len() == n && part.bytes().all(|b| b.is_ascii_digit());
    let keep = match parts.as_slice() {
        [.., year, month, day] if digits(year, 4) && digits(month, 2) && digits(day, 2) => {
            parts.len() - 3
        }
        [.., date] if digits(date, DATE_DIGITS) => parts.len() - 1,
        _ => parts.len(),
    };
    parts[..keep].join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup() {
        let prices = Prices::builtin().unwrap();
        assert_eq!(prices.date, "2026-11-17");
        let gpt = prices.rates("gpt-5.5");
        for (model, want) in [
            ("gpt-5.5", gpt),
            ("praxis/gpt-5.5", gpt),
            ("GPT-5-5", gpt),
            ("gpt-5.5-mini", None),
            ("gpt-5", prices.rates("gpt-5")),
            ("claude-sonnet-4.5", prices.rates("claude-sonnet-4-5")),
            (
                "anthropic/claude-sonnet-4-5-20250929",
                prices.rates("claude-sonnet-4-5"),
            ),
            ("claude-opus-4-6[1m]", prices.rates("claude-opus-4-6")),
            ("gpt-5-2025-08-07", prices.rates("gpt-5")),
            ("gpt-5-mini-2025-08-07", prices.rates("gpt-5-mini")),
            ("gpt-5-08-07", None),
            ("opus", None),
            ("", None),
            ("devstral-2", None),
        ] {
            assert_eq!(prices.rates(model), want, "{model}");
        }
        assert!(gpt.is_some());
        assert_ne!(prices.rates("gpt-5"), None);
    }

    /// The gpt-6.x models as runs report them: with the provider prefix
    /// and the published dotted name, or dashed.
    #[test]
    fn run_models() {
        let prices = Prices::builtin().unwrap();
        let rates = |input, cached_input, output| {
            Some(Rates {
                input,
                cached_input,
                output,
                estimate: false,
                basis: None,
            })
        };
        for (model, want) in [
            ("praxis/gpt-6.2-astra", rates(8.0, 0.40, 40.0)),
            ("gpt-6-2-astra", rates(8.0, 0.40, 40.0)),
            ("praxis/gpt-6.2-sol", rates(2.0, 0.10, 10.0)),
            ("gpt-6-2-sol", rates(2.0, 0.10, 10.0)),
            ("praxis/gpt-6.1-sol", rates(2.0, 0.10, 10.0)),
            ("gpt-6-1-sol", rates(2.0, 0.10, 10.0)),
            ("praxis/gpt-6-astra", rates(10.0, 1.0, 50.0)),
            ("praxis/gpt-6-luna", rates(0.10, 0.01, 0.50)),
            ("gpt-6.1-sol-mini", None),
            ("gpt-6", None),
        ] {
            assert_eq!(prices.rates(model), want.as_ref(), "{model}");
        }
    }

    #[test]
    fn cost() {
        let prices = Prices::builtin().unwrap();
        let rates = prices.rates("gpt-5.5").unwrap();
        let tokens = Tokens {
            input: 1_000_000,
            cached: 2_000_000,
            output: 100_000,
        };
        // $5 + 2 × $0.50 + 0.1 × $30.
        assert!((rates.cost(tokens) - 9.0).abs() < 1e-9);
    }

    #[test]
    fn estimates_require_basis() {
        for (fields, accepted) in [
            ("", true),
            (", estimate = false", true),
            (", estimate = true", false),
            (", estimate = true, basis = ''", false),
            (", estimate = true, basis = '   '", false),
            (", estimate = true, basis = \"line\\nline\"", false),
            (", estimate = true, basis = \"line\\rline\"", false),
            (
                ", estimate = true, basis = 'nearest published tier: gpt-6.1-sol'",
                true,
            ),
        ] {
            let text = format!(
                "date = 'x'\n[models]\na = {{ input = 2.0, cached-input = 0.1, output = 10.0{fields} }}"
            );
            let parsed = Prices::parse(&text);
            assert_eq!(parsed.is_ok(), accepted, "{fields}: {parsed:?}");
            if let Ok(prices) = parsed {
                let rate = prices.rates("a").unwrap();
                assert_eq!(rate.estimate, fields.contains("true"));
            }
        }
    }

    #[test]
    fn refused_tables() {
        for (text, want) in [
            (
                "date = \"x\"\n[models]\n\"a.1\" = { input = 1.0, cached-input = 0.1, output = 2.0 }\n\
                 \"a-1\" = { input = 1.0, cached-input = 0.1, output = 2.0 }\n",
                "names \"a.1\" twice",
            ),
            (
                "date = \"x\"\n[models]\na = { input = -1.0, cached-input = 0.1, output = 2.0 }\n",
                "not a number of dollars",
            ),
            (
                "date = \"x\"\n[models]\na = { input = 1.0, output = 2.0 }\n",
                "parsing the price table",
            ),
        ] {
            let err = format!("{:#}", Prices::parse(text).unwrap_err());
            assert!(err.contains(want), "{err}");
        }
    }
}
