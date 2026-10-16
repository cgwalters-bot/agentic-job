//! The limits gh-aw's handlers hold a request to only when apply runs
//! them, after the session: a comment of more than 50 links was refused
//! there whole, when the agent could no longer shorten it (#963).
//! `handback check` holds the requests to them in the session, with the
//! handler's own error.
//!
//! The limits, their errors and what is added to a comment before the
//! handler checks it again (gh-aw's footer, and apply.yml's marker and a
//! partial run's note, at their longest) are `handler-limits.json`, which
//! `safe-outputs/validation.mjs` reads out of the handlers' code at the
//! pinned commit and apply.yml, and CI regenerates to compare. What it
//! does not copy is how each is counted, [`Measure`]; the generator fails
//! when the code that counts changes. A request is measured as written,
//! before gh-aw's sanitizer, which keeps https links
//! (docs/safe-outputs.md).

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value};

const LIMITS_JSON: &str = include_str!("handler-limits.json");

static LIMITS: LazyLock<Vec<Limit>> =
    LazyLock::new(|| serde_json::from_str(LIMITS_JSON).expect("valid handler limits"));

/// A link as `comment_limit_helpers.cjs` counts one,
/// `/https?:\/\/[^\s]+/g`, with JavaScript's `\s` spelled out: Rust's
/// also has U+0085 and lacks U+FEFF.
static LINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"https?://[^\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]+",
    )
    .expect("a valid pattern")
});

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Limit {
    #[serde(rename = "type")]
    output: String,
    field: String,
    measure: Measure,
    max: usize,
    /// What apply and gh-aw's footer add to the measure before the handler
    /// checks the limit a second time.
    footer: usize,
    /// The handler's error, with `{max}` and `{got}` for the limit and the
    /// count.
    message: String,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Measure {
    /// A string's length in UTF-16 code units, as JavaScript's `length`.
    Length,
    /// The links in a string, as [`LINK_RE`] finds them.
    Links,
    /// The items of an array.
    Count,
    /// The distinct non-empty strings of an array, trimmed. `create_issue.cjs`
    /// also sanitizes and cuts each to 64 characters first, which can only
    /// make two the same: a request that differs only there is refused
    /// here and not at apply, never the other way.
    Distinct,
}

impl Measure {
    fn of(self, value: &Value) -> Option<usize> {
        match (self, value) {
            (Self::Length, Value::String(text)) => Some(text.encode_utf16().count()),
            (Self::Links, Value::String(text)) => Some(LINK_RE.find_iter(text).count()),
            (Self::Count, Value::Array(items)) => Some(items.len()),
            (Self::Distinct, Value::Array(items)) => Some(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .collect::<BTreeSet<_>>()
                    .len(),
            ),
            _ => None,
        }
    }
}

/// The errors gh-aw's handler would refuse REQUEST with at apply, in its
/// words: as written, or else with what apply and its footer add, which is
/// said. A field of
/// another shape is the collector's to refuse.
pub fn refusals(request: &Map<String, Value>) -> Vec<String> {
    let output = request.get("type").and_then(Value::as_str);
    LIMITS
        .iter()
        .filter(|limit| Some(limit.output.as_str()) == output)
        .filter_map(|limit| {
            let written = limit.measure.of(request.get(&limit.field)?)?;
            let error = |got: usize| {
                limit
                    .message
                    .replace("{max}", &limit.max.to_string())
                    .replace("{got}", &got.to_string())
            };
            if written > limit.max {
                Some(error(written))
            } else if written + limit.footer > limit.max {
                Some(format!(
                    "{} (apply and gh-aw's footer add {} of those)",
                    error(written + limit.footer),
                    limit.footer
                ))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn refused(request: Value) -> Vec<String> {
        refusals(request.as_object().unwrap())
    }

    fn links(count: usize) -> String {
        (0..count)
            .map(|n| format!("- [source {n}](https://example.com/{n})\n"))
            .collect()
    }

    #[test]
    fn the_generated_limits_are_read() {
        assert_eq!(LIMITS.len(), 4);
        for limit in LIMITS.iter() {
            assert!(limit.message.contains("{max}") && limit.message.contains("{got}"));
        }
    }

    /// The comment apply refused in tracker's run 38950333437.
    #[test]
    fn a_comment_of_58_links_is_refused_in_the_handlers_words() {
        assert_eq!(
            refused(json!({"type": "add_comment", "body": links(58)})),
            [
                "E008: Comment contains 58 links, maximum is 50. Reduce the number of URLs to 50 \
              or fewer."
            ]
        );
    }

    #[test]
    fn each_limit_is_held_at_its_boundary() {
        let long = "é".repeat(65536 - 1842);
        let cases: &[(Value, &[&str])] = &[
            // With the footer's 4 links.
            (json!({"type": "add_comment", "body": links(46)}), &[]),
            (json!({"type": "add_comment", "body": links(47)}), &["E008"]),
            (json!({"type": "add_comment", "body": links(51)}), &["E008"]),
            // As the handler's pattern counts them: from the scheme to a
            // space, in code too; Markdown's closing parenthesis is in it.
            (
                json!({"type": "add_comment", "body": "`https://a.example` http://b.example) https:// x"}),
                &[],
            ),
            (json!({"type": "add_comment", "body": long}), &[]),
            (
                json!({"type": "add_comment", "body": format!("{long}x")}),
                &["E006"],
            ),
            (
                json!({"type": "add_comment", "body": "🦀".repeat(32769)}),
                &["E006"],
            ),
            (
                json!({"type": "add_comment", "body": format!("{long}x{}", links(51))}),
                &["E006", "E008"],
            ),
            // Only the type a limit is of.
            (json!({"type": "create_issue", "body": links(51)}), &[]),
            (
                json!({"type": "create_issue", "labels": vec!["a"; 11]}),
                &[],
            ),
            (
                json!({"type": "create_issue", "labels": (0..10).map(|n| format!(" {n} ")).chain(["0".into(), String::new()]).collect::<Vec<_>>()}),
                &[],
            ),
            (
                json!({"type": "create_issue", "labels": (0..11).map(|n| n.to_string()).collect::<Vec<_>>()}),
                &["E003"],
            ),
            // Counted as given, the same or not.
            (json!({"type": "add_labels", "labels": vec!["a"; 10]}), &[]),
            (
                json!({"type": "add_labels", "labels": vec!["a"; 11]}),
                &["E003"],
            ),
            // A field of another shape is the collector's to refuse.
            (json!({"type": "add_comment", "body": [links(51)]}), &[]),
        ];
        for (request, codes) in cases {
            let found = refused(request.clone());
            let found: Vec<&str> = found.iter().map(|error| &error[..4]).collect();
            assert_eq!(&found, codes, "{request}");
        }
    }

    /// Within the limit as written, over it with gh-aw's footer: the
    /// error of the handler's second check, and why.
    #[test]
    fn the_footer_is_counted_and_said() {
        assert_eq!(
            refused(json!({"type": "add_comment", "body": links(50)})),
            [
                "E008: Comment contains 54 links, maximum is 50. Reduce the number of URLs to 50 \
              or fewer. (apply and gh-aw's footer add 4 of those)"
            ]
        );
    }

    #[test]
    fn the_message_names_the_field_and_both_numbers() {
        let labels: Vec<String> = (0..12).map(|n| n.to_string()).collect();
        assert_eq!(
            refused(json!({"type": "create_issue", "labels": labels})),
            ["E003: Cannot add more than 10 labels (received 12)"]
        );
    }
}
