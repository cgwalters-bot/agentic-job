//! The review's checked output: one verdict comment or a noop, and the
//! inline findings beside a verdict (#516), and the text apply posts when
//! nothing was submitted as the review. check.yml validates with
//! `review verdict`, and uploads `review fold`'s output for apply, which
//! runs no binary; review.yml's submit job checks again before it submits.

use std::sync::LazyLock;

use anyhow::{Result, bail, ensure};
use regex::Regex;
use serde_json::{Map, Value};

use super::{MAX_SAFE_INTEGER, REVIEW_COMMENT, REVIEW_COMMENTS_MAX};

// Folded into one body, as apply posts them when nothing was submitted, the
// verdict and its findings stay under GitHub's 65536-character limit for a
// comment or review body, with room for the footer and markers added after.
// Counted in UTF-16 units, as GitHub and the JavaScript this replaces count.
const REVIEW_BODY_MAX: usize = 60000;
const REVIEW_PATH_MAX: usize = 1024;
// A refusal's reason, before it is escaped.
const REFUSAL_MAX: usize = 1000;
const INLINE_FIELDS: [&str; 7] = [
    "type",
    "path",
    "line",
    "start_line",
    "side",
    "body",
    "pull_request_number",
];
const COMMENT_FIELDS: [&str; 3] = ["type", "body", "item_number"];
// One word, then the end of the line, a space or a stop.
static VERDICT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^VERDICT: (APPROVE|CHANGES|REJECT)(?:$|[\s.,;:])").expect("valid pattern")
});
// A first line naming both is no verdict.
static BOTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)APPROVE.*(CHANGES|REJECT)|(CHANGES|REJECT).*APPROVE").expect("valid pattern")
});
static CONTROL_RUNS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\x00-\x20\x7f]+").expect("valid pattern"));

/// The checked verdict, for the `review` status: APPROVE or CHANGES.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Verdict {
    Approve,
    Changes,
}

impl Verdict {
    pub fn word(verdict: Option<Self>) -> &'static str {
        match verdict {
            Some(Self::Approve) => "APPROVE",
            Some(Self::Changes) => "CHANGES",
            None => "",
        }
    }
}

/// A positive safe integer, as a JSON number or its decimal string.
pub(super) fn positive(value: &Value) -> Option<u64> {
    let text = match value {
        Value::Number(n) => n.as_u64()?.to_string(),
        Value::String(s) => s.clone(),
        _ => return None,
    };
    let n = text.parse::<u64>().ok()?;
    (n > 0 && n <= MAX_SAFE_INTEGER && n.to_string() == text).then_some(n)
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Markdown and mention characters, escaped so agent or event text stays
/// inert where it is shown.
pub(super) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if r"\`*_{}[]()<>!#|~@".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// TEXT on one line with runs of controls and spaces as one space, trimmed,
/// at most MAX characters.
pub(super) fn one_line(text: &str, max: usize) -> String {
    CONTROL_RUNS
        .replace_all(text, " ")
        .trim()
        .chars()
        .take(max)
        .collect()
}

/// What review.yml's refusal job posts. Policy reasons can name event
/// fields: they are kept inert and on one line, so a refusal cannot turn a
/// PR-controlled name into Markdown or a mention.
pub fn refusal_text(reason: &str) -> String {
    let text = escape(&one_line(reason, REFUSAL_MAX));
    let text = if text.is_empty() {
        "no reason supplied"
    } else {
        &text
    };
    format!("Review refused by policy: {text}")
}

fn items(output: &Value) -> &[Value] {
    output["items"].as_array().map_or(&[], Vec::as_slice)
}

fn is_inline(item: &Value) -> bool {
    item["type"] == REVIEW_COMMENT
}

/// One inline finding: a line, or lines, of the triggering pull request's
/// diff. Check (src/check) already holds it to that pull request; here it
/// also names no repository, and has only fields the review can carry.
fn check_inline(item: &Map<String, Value>, number: u64) -> Result<()> {
    let present = |key: &str| item.get(key);
    let line = present("line").and_then(positive);
    let path = present("path").and_then(Value::as_str).unwrap_or_default();
    let valid = item.keys().all(|key| INLINE_FIELDS.contains(&key.as_str()))
        && present("body")
            .and_then(Value::as_str)
            .is_some_and(|body| !body.trim().is_empty())
        && !path.is_empty()
        && utf16_len(path) <= REVIEW_PATH_MAX
        && !path.chars().any(|c| c < ' ' || c == '\x7f')
        && line.is_some()
        && present("start_line")
            .is_none_or(|start| positive(start).is_some_and(|s| Some(s) <= line))
        && present("side").is_none_or(|side| side == "LEFT" || side == "RIGHT")
        && present("pull_request_number").is_none_or(|n| positive(n) == Some(number));
    ensure!(
        valid,
        "Review inline comment must be a body on a path and line of the triggering pull request"
    );
    Ok(())
}

/// Where an inline finding was, as plain text: a path is agent text that
/// gh-aw does not sanitize, so it is kept inert, as a refusal's reason is,
/// and can neither mention anyone nor become markup.
fn anchor(item: &Value) -> String {
    let line = positive(&item["line"]).unwrap_or_default();
    let lines = match positive(&item["start_line"]) {
        Some(start) if start < line => format!("lines {start}-{line}"),
        _ => format!("line {line}"),
    };
    let base = if item["side"] == "LEFT" {
        " of the base"
    } else {
        ""
    };
    format!(
        "{}, {lines}{base}",
        escape(item["path"].as_str().unwrap_or_default())
    )
}

/// Inline findings that are not inline comments, appended to the verdict's
/// body after its first line, which stays VERDICT:.
pub(super) fn inline_section<'a>(items: impl IntoIterator<Item = &'a Value>) -> String {
    let found: String = items
        .into_iter()
        .map(|item| {
            format!(
                "\n**{}**\n\n{}\n",
                anchor(item),
                item["body"].as_str().unwrap_or_default()
            )
        })
        .collect();
    if found.is_empty() {
        found
    } else {
        format!("\n\n### Inline findings\n{found}")
    }
}

/// The verdict, or `None` for a noop, which approves nothing. REJECT, which
/// briefs written before CHANGES still ask for, is read as CHANGES. Inline
/// comments may come with a verdict comment, never with a noop, which
/// apply would not post.
pub fn check_outputs(output: &Value, number: &str) -> Result<Option<Verdict>> {
    let Some(number) = positive(&Value::String(number.to_owned())) else {
        bail!("Review target must be a pull request number");
    };
    let (inline, others): (Vec<&Value>, Vec<&Value>) =
        items(output).iter().partition(|i| is_inline(i));
    let [item] = others[..] else {
        bail!("Review must return exactly one comment or noop");
    };
    ensure!(
        inline.len() <= REVIEW_COMMENTS_MAX,
        "Review may return at most {REVIEW_COMMENTS_MAX} inline comments"
    );
    if item["type"] == "noop" {
        ensure!(
            inline.is_empty(),
            "Review inline comments need a verdict comment, not a noop"
        );
        return Ok(None);
    }
    for comment in &inline {
        let Some(comment) = comment.as_object() else {
            bail!("Review inline comment must be an object");
        };
        check_inline(comment, number)?;
    }
    // gh-aw recognizes aliases and editing/reply routes. The handler's
    // trusted configuration fixes the target. A redundant item_number
    // cannot redirect the comment; aliases and editing/reply routes
    // remain forbidden.
    let body = item["body"].as_str();
    let valid = item["type"] == "add_comment"
        && body.is_some()
        && item.as_object().is_some_and(|fields| {
            fields
                .keys()
                .all(|key| COMMENT_FIELDS.contains(&key.as_str()))
                && fields
                    .get("item_number")
                    .is_none_or(|n| positive(n) == Some(number))
        });
    ensure!(
        valid,
        "Review output must be a comment on the triggering pull request"
    );
    let body = body.unwrap_or_default();
    let line = body.split('\n').next().unwrap_or_default();
    let verdict = VERDICT.captures(line).map(|c| c[1].to_owned());
    let Some(verdict) = verdict.filter(|_| !BOTH.is_match(line)) else {
        bail!("Review comment must start with VERDICT: APPROVE or VERDICT: CHANGES");
    };
    ensure!(
        utf16_len(body) + utf16_len(&inline_section(inline)) <= REVIEW_BODY_MAX,
        "Review comment and inline comments together must be at most {REVIEW_BODY_MAX} characters"
    );
    Ok(Some(if verdict == "APPROVE" {
        Verdict::Approve
    } else {
        Verdict::Changes
    }))
}

/// What apply posts when nothing was submitted: the verdict comment with
/// every inline finding in its body, and no review comments beside it, so
/// they are neither lost nor posted as a second review without a verdict.
pub fn fold(mut output: Value) -> Value {
    let section = inline_section(items(&output).iter().filter(|i| is_inline(i)));
    if section.is_empty() {
        return output;
    }
    if let Some(items) = output["items"].as_array_mut() {
        items.retain(|item| !is_inline(item));
        for item in items.iter_mut() {
            if item["type"] == "add_comment"
                && let Some(body) = item["body"].as_str()
            {
                item["body"] = Value::String(format!("{body}{section}"));
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn check(item: Value) -> Result<&'static str> {
        check_outputs(&json!({"items": [item]}), "147").map(Verdict::word)
    }

    fn comment(body: &str) -> Value {
        json!({"type": "add_comment", "body": body})
    }

    #[test]
    fn only_one_verdict_comment_on_this_pull_request_or_a_noop_passes() {
        for (body, verdict) in [
            ("VERDICT: APPROVE", "APPROVE"),
            ("VERDICT: APPROVE\nLooks right.", "APPROVE"),
            ("VERDICT: APPROVE. Looks right.", "APPROVE"),
            (
                "VERDICT: APPROVE, no blockers\n\n## Follow-ups\n\n- nit: b.rs:7",
                "APPROVE",
            ),
            ("VERDICT: CHANGES: one blocker", "CHANGES"),
            ("VERDICT: CHANGES — one finding", "CHANGES"),
            // Briefs written before CHANGES ask for REJECT and a REASON line.
            ("VERDICT: REJECT\nREASON: Breaks the build.", "CHANGES"),
        ] {
            assert_eq!(check(comment(body)).unwrap(), verdict, "{body}");
        }
        assert_eq!(
            check(json!({"type": "noop", "message": "None."})).unwrap(),
            ""
        );
        for body in [
            "APPROVE",
            "VERDICT: approve",
            "VERDICT: REJECTED",
            "VERDICT: REJECT, or APPROVE",
            "VERDICT: APPROVE unless REJECT",
            "VERDICT: APPROVE-ish",
            "VERDICT: APPROVE?",
            "VERDICT: APPROVE|CHANGES",
            "VERDICT: CHANGES, or APPROVE if you like",
            " VERDICT: APPROVE",
            "Summary\nVERDICT: APPROVE",
        ] {
            assert!(check(comment(body)).is_err(), "{body}");
        }
        for number in [json!(147), json!("147")] {
            let item =
                json!({"type": "add_comment", "body": "VERDICT: APPROVE", "item_number": number});
            assert_eq!(check(item).unwrap(), "APPROVE");
        }
        // A redundant item_number cannot redirect the comment, nor can an
        // alias or a reply route.
        for number in [
            json!(148),
            json!("148"),
            json!(null),
            json!(false),
            json!([147]),
            json!("0147"),
            json!("147\n"),
            json!(0),
            json!(1.47),
            json!(9_007_199_254_740_992_u64),
        ] {
            let item =
                json!({"type": "add_comment", "body": "VERDICT: APPROVE", "item_number": number});
            let err = check(item).unwrap_err().to_string();
            assert!(err.contains("triggering pull request"), "{number}: {err}");
        }
        for key in [
            "issue_number",
            "pull_request_number",
            "repo",
            "comment_id",
            "reply_to_id",
            "target",
            "temporary_id",
        ] {
            let item = json!({"type": "add_comment", "body": "VERDICT: APPROVE", key: "147"});
            assert!(check(item).is_err(), "{key}");
        }
        assert!(check(json!({"type": "create_pull_request"})).is_err());
        for items in [
            json!([]),
            json!([{"type": "noop"}, {"type": "noop"}]),
            json!(null),
        ] {
            let err = check_outputs(&json!({"items": items}), "147").unwrap_err();
            assert!(err.to_string().contains("exactly one"), "{items}");
        }
        for target in ["", "0", "*", "01"] {
            assert!(
                check_outputs(&json!({"items": [comment("VERDICT: APPROVE")]}), target).is_err()
            );
        }
    }

    #[test]
    fn inline_comments_come_with_a_verdict_bounded_and_on_this_pull_request() {
        let inline = |fields: Value| {
            let mut item = json!({"type": REVIEW_COMMENT, "path": "src/a.rs", "line": 3, "body": "blocker: x"});
            item.as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            item
        };
        let verdict = comment("VERDICT: CHANGES\nOne blocker.");
        for (name, comments, ok) in [
            ("one", vec![inline(json!({}))], true),
            (
                "a line as a string",
                vec![inline(json!({"line": "4"}))],
                true,
            ),
            (
                "a range on the base side",
                vec![inline(json!({"start_line": 1, "side": "LEFT"}))],
                true,
            ),
            (
                "a range of one line",
                vec![inline(json!({"start_line": 3}))],
                true,
            ),
            (
                "this pull request",
                vec![inline(json!({"pull_request_number": "147"}))],
                true,
            ),
            ("ten", vec![inline(json!({})); 10], true),
            ("eleven", vec![inline(json!({})); 11], false),
            (
                "another pull request",
                vec![inline(json!({"pull_request_number": 148}))],
                false,
            ),
            (
                "another repository",
                vec![inline(json!({"repo": "o/other"}))],
                false,
            ),
            (
                "a reply route",
                vec![inline(json!({"in_reply_to": 1}))],
                false,
            ),
            ("no body", vec![inline(json!({"body": " "}))], false),
            ("no path", vec![inline(json!({"path": ""}))], false),
            (
                "a path with a newline",
                vec![inline(json!({"path": "a\n@user"}))],
                false,
            ),
            (
                "a long path",
                vec![inline(json!({"path": "a".repeat(1025)}))],
                false,
            ),
            ("line zero", vec![inline(json!({"line": 0}))], false),
            (
                "a fractional line",
                vec![inline(json!({"line": 1.5}))],
                false,
            ),
            (
                "a null start",
                vec![inline(json!({"start_line": null}))],
                false,
            ),
            (
                "a range ending before it starts",
                vec![inline(json!({"start_line": 4}))],
                false,
            ),
            (
                "another side",
                vec![inline(json!({"side": "right"}))],
                false,
            ),
            (
                "folded past the bound",
                vec![inline(json!({"body": "x".repeat(60000)}))],
                false,
            ),
            ("not an object", vec![json!(REVIEW_COMMENT)], false),
        ] {
            let mut items = vec![verdict.clone()];
            items.extend(comments);
            let got = check_outputs(&json!({"items": items}), "147");
            assert_eq!(got.is_ok(), ok, "{name}: {got:?}");
        }
        // A noop is posted nowhere: its findings would be lost.
        let noop = json!({"items": [{"type": "noop"}, inline(json!({}))]});
        assert!(
            check_outputs(&noop, "147")
                .unwrap_err()
                .to_string()
                .contains("not a noop")
        );
    }

    #[test]
    fn apply_posts_inline_findings_in_the_verdict_comment_not_beside_it() {
        let output = json!({"items": [
            {"type": REVIEW_COMMENT, "path": "src/[a]_@b.rs", "line": 3, "body": "nit: one"},
            comment("VERDICT: APPROVE\nFindings"),
            {"type": REVIEW_COMMENT, "path": "b.rs", "line": 9, "start_line": 7, "side": "LEFT", "body": "important: two"},
        ], "errors": []});
        let folded = fold(output);
        assert_eq!(
            folded,
            json!({"items": [comment("VERDICT: APPROVE\nFindings\n\n### Inline findings\n\
                \n**src/\\[a\\]\\_\\@b.rs, line 3**\n\nnit: one\n\
                \n**b.rs, lines 7-9 of the base**\n\nimportant: two\n")], "errors": []})
        );
        assert_eq!(
            check_outputs(&folded, "147").unwrap(),
            Some(Verdict::Approve)
        );
        let noop = json!({"items": [{"type": "noop"}]});
        assert_eq!(fold(noop.clone()), noop);
    }

    #[test]
    fn a_refusal_reason_is_one_inert_bounded_line() {
        let reason = "the bounds do not allow forks";
        assert_eq!(
            refusal_text(reason),
            format!("Review refused by policy: {reason}")
        );
        assert_eq!(
            refusal_text("a\n\r@user [link](url)"),
            r"Review refused by policy: a \@user \[link\]\(url\)"
        );
        assert_eq!(
            refusal_text(" \n"),
            "Review refused by policy: no reason supplied"
        );
        assert!(refusal_text(&"a".repeat(2000)).len() < 1100);
    }
}
