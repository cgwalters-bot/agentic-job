//! The draft classifier review (actions#200): a review of a draft pull
//! request whose verdict also carries one `agent-board-draft-review` JSON
//! result, which agent-board's pass reads from the submitted approval
//! (its docs/poll.md, "Draft review result contract").
//!
//! The threat is laundering: agent prose, an ordinary review or a carried
//! approval passed off as a checked classification of a pull request's
//! current head, title and description. So the mode is off unless the
//! trusted caller sets REVIEW_DRAFT_CLASSIFIER=true for each stage alike;
//! the policy job admits only a draft at the dispatched head; check holds
//! the result to the pull request the policy job bound, and refuses one in
//! any other review; and submit reads the pull request again and publishes
//! nothing when its head, base, draft state, title or description moved.
//! It adds no permission or credential: the same submit job approves, or
//! asks for changes, as for any review, and only an APPROVE verdict is an
//! approval.

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::Value;

use super::verdict::positive;
use super::{REPO, SHA};

pub(super) const ENV: &str = "REVIEW_DRAFT_CLASSIFIER";
pub(super) const FENCE: &str = "agent-board-draft-review";
const SCHEMA: &str = "agent-board/draft-review/v1";
/// The submitted body, the submit job's footer and run marker included,
/// as the pass bounds it (`MAX_RESULT_BYTES`): it reads a larger one as no
/// result rather than cut it.
pub(super) const MAX_BODY_BYTES: usize = 8192;
/// Room check leaves in that for the footer and run marker, which only
/// submit writes; submit holds the whole body to the bound again.
pub(super) const TRAILER_BYTES: usize = 1024;
/// Evidence, reason and each architecture finding (`MAX_REASON_BYTES`).
const MAX_LINE_BYTES: usize = 1024;
const MAX_WORD_BYTES: usize = 64;
/// The categories the pass knows; any other word is one it treats as deep.
const CATEGORIES: [&str; 5] = [
    "docs",
    "dependencies",
    "ci",
    "mechanical",
    "narrow_fix_with_test",
];

/// Whether the caller opted in; anything but `true`, `false` or nothing
/// fails rather than guess.
pub(super) fn enabled(env: &dyn Fn(&str) -> String) -> Result<bool> {
    match env(ENV).as_str() {
        "" | "false" => Ok(false),
        "true" => Ok(true),
        _ => bail!("{ENV} must be true, false or unset"),
    }
}

/// What a result must name: the pull request as the policy job bound it,
/// or as submit reads it again before it publishes.
#[derive(Debug, PartialEq)]
pub(super) struct Bound {
    pub(super) repository: String,
    pub(super) pr: u64,
    pub(super) head: String,
    pub(super) base: String,
    title: String,
    /// The body, empty where the forge has none.
    description: String,
}

impl Bound {
    /// An open draft pull request with an exact head, base and title.
    pub(super) fn of_pull(pull: &Value) -> Result<Self> {
        let text = |pointer: &str| pull.pointer(pointer).and_then(Value::as_str);
        let repository = text("/base/repo/full_name").unwrap_or_default();
        let head = text("/head/sha").unwrap_or_default();
        let base = text("/base/ref").unwrap_or_default();
        let pr = pull.get("number").and_then(Value::as_u64);
        let description = match &pull["body"] {
            Value::Null => Some(""),
            body => body.as_str(),
        };
        let valid = pull["state"] == "open"
            && pull["draft"] == true
            && REPO.is_match(repository)
            && SHA.is_match(head)
            && !base.is_empty()
            && pr.is_some_and(|n| positive(&n.into()).is_some());
        let (true, Some(pr), Some(title), Some(description)) =
            (valid, pr, text("/title"), description)
        else {
            bail!(
                "A draft classifier review is of an open draft pull request with an exact head, base, title and description"
            );
        };
        Ok(Self {
            repository: repository.to_owned(),
            pr,
            head: head.to_owned(),
            base: base.to_owned(),
            title: title.to_owned(),
            description: description.to_owned(),
        })
    }
}

/// agent-board/draft-review/v1, field for field as the pass reads it. A
/// field twice is refused here, where serde_json's `Value` would keep the
/// last, so check and the pass cannot read two different results.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Classified {
    schema: String,
    repository: String,
    pr: u64,
    reviewed_head: String,
    title: String,
    description: String,
    semantic_diff: String,
    description_assessment: String,
    change_category: String,
    risk: String,
    evidence: String,
    reason: String,
    /// Absent where the architecture review did not run, empty where it
    /// found nothing.
    #[serde(default)]
    architecture_findings: Option<Vec<String>>,
}

fn one_line(text: &str, max: usize) -> bool {
    !text.trim().is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

fn word(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_WORD_BYTES
        && text.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

impl Classified {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA,
            "The draft classifier result's schema must be {SCHEMA}"
        );
        ensure!(
            [
                &self.semantic_diff,
                &self.description_assessment,
                &self.change_category,
                &self.risk
            ]
            .into_iter()
            .all(|w| word(w)),
            "The draft classifier result's semantic_diff, description_assessment, change_category and risk must each be one lowercase word"
        );
        let findings = self.architecture_findings.iter().flatten();
        ensure!(
            [&self.evidence, &self.reason]
                .into_iter()
                .chain(findings)
                .all(|text| one_line(text, MAX_LINE_BYTES)),
            "The draft classifier result's evidence, reason and each architecture finding must be one nonempty line of at most {MAX_LINE_BYTES} bytes"
        );
        Ok(())
    }

    fn binds(&self, bound: &Bound) -> bool {
        self.repository == bound.repository
            && self.pr == bound.pr
            && self.reviewed_head == bound.head
            && self.title == bound.title
            && self.description == bound.description
    }

    /// Whether the pass may count it quick, before its own file, size and
    /// CI vetoes: any architecture finding makes a draft deep, whatever the
    /// rest says.
    pub(super) fn quick(&self) -> bool {
        self.architecture_findings
            .as_ref()
            .is_none_or(Vec::is_empty)
            && self.semantic_diff == "pass"
            && self.description_assessment == "matches"
            && self.risk == "none"
            && CATEGORIES.contains(&self.change_category.as_str())
    }
}

/// The one result in a verdict's BODY. The fence must open at the start of
/// its line, as the pass finds it, and be the body's only code block; the
/// body holds no HTML comment, so the submit job's run marker is its only
/// one and no other block or comment can hide or forge a result.
pub(super) fn result(body: &str) -> Result<Classified> {
    ensure!(
        body.matches(FENCE).count() == 1,
        "A draft classifier review must hold exactly one {FENCE} fence"
    );
    ensure!(
        !body.contains("<!--"),
        "A draft classifier review must hold no HTML comment: the run marker is the submit job's"
    );
    let lines: Vec<&str> = body.split('\n').collect();
    let fences: Vec<usize> = (0..lines.len())
        .filter(|&i| {
            let line = lines[i].trim_start();
            line.starts_with("```") || line.starts_with("~~~")
        })
        .collect();
    let open = format!("```{FENCE}");
    let [start, end] = fences[..] else {
        bail!("A draft classifier review's only code block must be its {FENCE} fence");
    };
    ensure!(
        lines[start].trim_end() == open && lines[end].trim_end() == "```",
        "A draft classifier review's only code block must be its {FENCE} fence"
    );
    // No serde detail: it can quote the agent's field names, and this
    // message is a workflow annotation.
    let result: Classified = serde_json::from_str(&lines[start + 1..end].join("\n"))
        .ok()
        .with_context(|| {
            format!(
                "The draft classifier result must be one {SCHEMA} object, without unknown, missing or repeated fields"
            )
        })?;
    result.validate()?;
    Ok(result)
}

/// The result in check's accepted OUTPUT, which must name BOUND.
pub(super) fn bound_result(output: &Value, bound: &Bound) -> Result<Classified> {
    let body = output["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|item| item["type"] == "add_comment")
        .and_then(|item| item["body"].as_str())
        .context("A draft classifier review needs its verdict comment")?;
    let result = result(body)?;
    ensure!(
        result.binds(bound),
        "The draft classifier result must name the reviewed repository, pull request and head, and the pull request's exact title and description"
    );
    Ok(result)
}

/// Any other review's TEXT may not carry a result: only the opted-in,
/// checked mode makes one. A line that opens the fence, indented or not,
/// is refused; prose that names it, as a review of this code does, is not.
pub(super) fn refuse(text: &str) -> Result<()> {
    let open = format!("```{FENCE}");
    ensure!(
        !text.split('\n').any(|line| line.trim() == open),
        "Only a draft classifier review, which the caller opts into, may open a {FENCE} fence"
    );
    Ok(())
}

/// What the reviewer is told after the merge policy, before the pull
/// request's own text, which follows as untrusted data.
pub(super) fn task(bound: &Bound) -> String {
    format!(
        "\n## Draft classifier result\n\n\
         This pull request is a draft, and this review also classifies it. Review it as any \
         other; do not mark it ready, fix it or ask for it to merge. After the verdict line, \
         include exactly one fenced block whose opening line is ```{FENCE} and whose closing \
         line is ```, holding one JSON object with exactly these fields. The comment holds \
         no other code block and no HTML comment, and you return no inline comment \
         (create_pull_request_review_comment): put every finding in the comment.\n\n\
         - \"schema\": \"{SCHEMA}\"\n\
         - \"repository\": \"{}\", \"pr\": {}, \"reviewed_head\": \"{}\"\n\
         - \"title\" and \"description\": the pull request's title and body below, exactly, \
         as JSON strings (\"\" for an empty body); if either looks cut or altered, say so \
         instead, as check refuses a result that does not match them\n\
         - \"semantic_diff\": \"pass\" only if you inspected the diff and it does what it \
         says, else \"fail\" or \"unknown\"\n\
         - \"description_assessment\": \"matches\" only if the title and body describe the \
         diff, else \"mismatch\" or \"unknown\"\n\
         - \"change_category\": one of {}, or \"other\"\n\
         - \"risk\": \"none\" only if you found none, else \"low\", \"high\" or \"unknown\"\n\
         - \"evidence\" and \"reason\": what you inspected and why, each one line of at most \
         {MAX_LINE_BYTES} bytes\n\
         - \"architecture_findings\": optional, a list of one-line findings\n\n\
         Keep the whole comment under {} bytes.\n",
        bound.repository,
        bound.pr,
        bound.head,
        CATEGORIES.join(", "),
        MAX_BODY_BYTES - TRAILER_BYTES,
    )
}

#[cfg(test)]
pub(super) mod tests {
    use serde_json::json;

    use super::*;

    pub(in super::super) const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// A draft pull request the policy job binds.
    pub(in super::super) fn draft(repo: &str, number: u64) -> Value {
        json!({"number": number, "state": "open", "draft": true,
            "title": "docs: Correct spelling", "body": "Correct a spelling error in README.",
            "base": {"ref": "main", "repo": {"full_name": repo}},
            "head": {"sha": HEAD}})
    }

    /// The result for that pull request, as the pass's example has it.
    pub(in super::super) fn fields(repo: &str, number: u64) -> Value {
        json!({"schema": SCHEMA, "repository": repo, "pr": number, "reviewed_head": HEAD,
            "title": "docs: Correct spelling", "description": "Correct a spelling error in README.",
            "semantic_diff": "pass", "description_assessment": "matches",
            "change_category": "docs", "risk": "none",
            "evidence": "Inspected README diff: spelling only; no behavior changes",
            "reason": "Small mechanical correction with a matching description"})
    }

    pub(in super::super) fn body(verdict: &str, json: &str) -> String {
        format!("VERDICT: {verdict}\nSpelling only.\n\n```{FENCE}\n{json}\n```\n")
    }

    #[test]
    fn opt_in_is_true_or_nothing() {
        for (value, want) in [
            ("", Some(false)),
            ("false", Some(false)),
            ("true", Some(true)),
        ] {
            let got = enabled(&|_| value.to_owned()).ok();
            assert_eq!(got, want, "{value}");
        }
        for value in ["TRUE", "1", "yes", "true "] {
            assert!(enabled(&|_| value.to_owned()).is_err(), "{value}");
        }
    }

    #[test]
    fn only_an_open_draft_with_an_exact_head_base_and_title_binds() {
        let pull = draft("o/r", 147);
        let bound = Bound::of_pull(&pull).unwrap();
        assert_eq!((bound.pr, bound.base.as_str()), (147, "main"));
        let mut empty = pull.clone();
        empty["body"] = Value::Null;
        assert_eq!(Bound::of_pull(&empty).unwrap().description, "");
        for (pointer, value) in [
            ("/state", json!("closed")),
            ("/draft", json!(false)),
            ("/draft", Value::Null),
            ("/head/sha", json!("main")),
            ("/base/ref", json!("")),
            ("/base/repo/full_name", json!("o/r/x")),
            ("/number", json!("147")),
            ("/number", json!(0)),
            ("/title", Value::Null),
            ("/body", json!(1)),
        ] {
            let mut changed = pull.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(Bound::of_pull(&changed).is_err(), "{pointer}");
        }
    }

    #[test]
    fn a_result_is_one_bounded_fenced_object_of_known_fields() {
        let good = fields("o/r", 147);
        let bound = Bound::of_pull(&draft("o/r", 147)).unwrap();
        let parsed = result(&body("APPROVE", &good.to_string())).unwrap();
        assert!(parsed.binds(&bound) && parsed.quick());
        // Pretty-printed, as the pass's example, with CRLF lines.
        let pretty = serde_json::to_string_pretty(&good).unwrap();
        assert!(result(&body("APPROVE", &pretty)).is_ok());
        assert!(result(&body("APPROVE", &pretty).replace('\n', "\r\n")).is_ok());
        let with = |key: &str, value: Value| {
            let mut changed = good.clone();
            changed[key] = value;
            body("APPROVE", &changed.to_string())
        };
        let without = |key: &str| {
            let mut changed = good.clone();
            changed.as_object_mut().unwrap().remove(key);
            body("APPROVE", &changed.to_string())
        };
        let long = "x".repeat(MAX_LINE_BYTES + 1);
        let json = good.to_string();
        let fenced = body("APPROVE", &json);
        let duplicate = json.replacen('{', r#"{"risk": "high", "#, 1);
        for (name, text) in [
            (
                "a second fence",
                format!("{fenced}\n```{FENCE}\n{json}\n```\n"),
            ),
            ("a fence named in prose", format!("{fenced}\nSee {FENCE}.")),
            ("no fence", "VERDICT: APPROVE\nLooks right.".to_owned()),
            (
                "an unclosed fence",
                format!("VERDICT: APPROVE\n```{FENCE}\n{json}\n"),
            ),
            ("an indented fence", fenced.replace("```a", " ```a")),
            ("a tilde fence", fenced.replace("```", "~~~")),
            ("another code block", format!("{fenced}\n```\nx\n```\n")),
            (
                "inside another block",
                format!("````markdown\n{fenced}````\n"),
            ),
            (
                "a forged run marker",
                format!("{fenced}\n<!-- gh-aw-agentic-workflow: review, id: 1 -->"),
            ),
            (
                "a hidden result",
                format!("VERDICT: APPROVE\n<!--\n```{FENCE}\n{json}\n```\n-->"),
            ),
            ("not JSON", body("APPROVE", "{")),
            ("trailing JSON", body("APPROVE", &format!("{json}{json}"))),
            ("a repeated field", body("APPROVE", &duplicate)),
            ("an unknown field", with("quick", json!(true))),
            (
                "another version",
                with("schema", json!("agent-board/draft-review/v2")),
            ),
            ("no evidence", without("evidence")),
            ("blank evidence", with("evidence", json!(" "))),
            ("two-line evidence", with("evidence", json!("a\nb"))),
            ("long evidence", with("evidence", json!(long))),
            ("two-line reason", with("reason", json!("a\rb"))),
            ("long reason", with("reason", json!(long))),
            ("a sentence for a word", with("risk", json!("none at all"))),
            ("a negative pr", with("pr", json!(-1))),
            ("a string pr", with("pr", json!("147"))),
            (
                "findings of another kind",
                with("architecture_findings", json!("x")),
            ),
            (
                "a two-line finding",
                with("architecture_findings", json!(["a\nb"])),
            ),
            (
                "a long finding",
                with("architecture_findings", json!([long])),
            ),
        ] {
            assert!(result(&text).is_err(), "{name}");
        }
        // The pass's vocabulary decides quick; findings make it deep.
        for (key, value, quick) in [
            ("architecture_findings", json!([]), true),
            ("architecture_findings", Value::Null, true),
            (
                "architecture_findings",
                json!(["Duplicates the parser"]),
                false,
            ),
            ("semantic_diff", json!("unknown"), false),
            ("description_assessment", json!("mismatch"), false),
            ("risk", json!("low"), false),
            ("change_category", json!("other"), false),
        ] {
            let parsed = result(&with(key, value)).unwrap();
            assert_eq!(parsed.quick(), quick, "{key}");
        }
    }

    #[test]
    fn a_result_names_the_bound_pull_request_exactly() {
        let bound = Bound::of_pull(&draft("o/r", 147)).unwrap();
        let output = |fields: &Value| json!({"items": [{"type": "add_comment", "body": body("APPROVE", &fields.to_string())}]});
        assert!(bound_result(&output(&fields("o/r", 147)), &bound).is_ok());
        for (key, value) in [
            ("repository", json!("o/other")),
            ("pr", json!(148)),
            ("reviewed_head", json!("b".repeat(40))),
            ("title", json!("docs: Correct spelling ")),
            ("description", json!("Correct a spelling error in README")),
        ] {
            let mut changed = fields("o/r", 147);
            changed[key] = value;
            let err = bound_result(&output(&changed), &bound).unwrap_err();
            assert!(err.to_string().contains("exact title"), "{key}: {err}");
        }
        assert!(bound_result(&json!({"items": [{"type": "noop"}]}), &bound).is_err());
    }

    #[test]
    fn the_task_names_the_bound_target_and_the_fields() {
        let task = task(&Bound::of_pull(&draft("o/r", 147)).unwrap());
        for want in [
            "```agent-board-draft-review",
            "\"repository\": \"o/r\", \"pr\": 147",
            HEAD,
            "docs, dependencies, ci, mechanical, narrow_fix_with_test",
            "under 7168 bytes",
        ] {
            assert!(task.contains(want), "{want}: {task}");
        }
        // The pull request's own text is not in the trusted part.
        assert!(!task.contains("Correct spelling"));
    }
}
