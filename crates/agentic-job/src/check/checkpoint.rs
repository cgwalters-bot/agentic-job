//! A checkpoint: what an agent that did not finish says of its work, so
//! that its pull request stays a draft and someone, or a continuation
//! run, can pick it up. It is a fenced block in the pull request's body
//! (or a push's message), shown as it is written rather than hidden:
//!
//! ````text
//! ```checkpoint
//! {"reason": "budget", "done": "...", "left": "...", "next": "..."}
//! ```
//! ````
//!
//! Only a policy whose bounds set `ready_when_complete` reads one, and
//! there it decides whether apply opens the pull request ready for review
//! or as a draft. So it is read strictly: a block that is malformed, or
//! one of two, is refused rather than taken for complete work, which
//! would open ready what the agent meant to leave a draft.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

/// The line that opens a checkpoint, alone on it.
pub const FENCE: &str = "```checkpoint";
/// The line that closes it.
const CLOSE: &str = "```";
/// Why the work stopped: the run's spending budget, its time, its request
/// or task cap, or the agent's own judgment that it is not done.
pub const REASONS: &[&str] = &["budget", "runtime", "cap", "incomplete"];
/// The largest checkpoint, its JSON between the fences.
pub const MAX_BYTES: usize = 8 << 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// One of [`REASONS`].
    pub reason: String,
    /// What is done.
    pub done: String,
    /// What is left.
    pub left: String,
    /// How to continue.
    pub next: String,
}

impl Checkpoint {
    /// The block, as a body holds it.
    pub fn markdown(&self) -> String {
        // Serializing four strings cannot fail.
        let json = serde_json::to_string(self).unwrap_or_default();
        format!("{FENCE}\n{json}\n{CLOSE}")
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            REASONS.contains(&self.reason.as_str()),
            "reason {:?} is not one of {}",
            self.reason,
            REASONS.join(", ")
        );
        for (key, value) in [
            ("done", &self.done),
            ("left", &self.left),
            ("next", &self.next),
        ] {
            ensure!(!value.trim().is_empty(), "{key} is empty");
        }
        Ok(())
    }
}

/// The checkpoint TEXT holds, if it holds one. Any line that starts like
/// the fence counts as one, so that a near miss (`~~~` aside) is refused
/// rather than ignored.
pub fn find(text: &str) -> Result<Option<Checkpoint>> {
    let mut lines = text.lines();
    let mut found = None;
    while let Some(line) = lines.next() {
        let line = line.trim();
        if !line.starts_with(FENCE) {
            continue;
        }
        ensure!(found.is_none(), "more than one checkpoint");
        ensure!(line == FENCE, "a checkpoint fence with more on its line");
        let mut json = String::new();
        let mut closed = false;
        for line in lines.by_ref() {
            if line.trim() == CLOSE {
                closed = true;
                break;
            }
            json.push_str(line);
            json.push('\n');
            if json.len() > MAX_BYTES {
                bail!("a checkpoint over {MAX_BYTES} bytes");
            }
        }
        ensure!(closed, "a checkpoint without its closing fence");
        let checkpoint: Checkpoint = serde_json::from_str(&json).context(
            "a checkpoint that is not a JSON object of reason, done, left and next, all strings",
        )?;
        checkpoint
            .validate()
            .context("a checkpoint that does not say why the work stopped and what is left")?;
        found = Some(checkpoint);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str =
        r#"{"reason": "budget", "done": "the parser", "left": "tests", "next": "add tests"}"#;

    #[test]
    fn checkpoints_are_read_strictly() {
        let block = |json: &str| format!("Did some.\n\n{FENCE}\n{json}\n```\n");
        let good = Checkpoint {
            reason: "budget".into(),
            done: "the parser".into(),
            left: "tests".into(),
            next: "add tests".into(),
        };
        type Want<'a> = Result<Option<&'a Checkpoint>, &'a str>;
        let cases: &[(&str, String, Want<'_>)] = &[
            ("none", "Done.\n\n```json\n{}\n```".into(), Ok(None)),
            ("one", block(GOOD), Ok(Some(&good))),
            (
                "indented",
                format!("  {FENCE}\n{GOOD}\n  ```"),
                Ok(Some(&good)),
            ),
            ("its own markdown", good.markdown(), Ok(Some(&good))),
            (
                "two",
                format!("{}{}", block(GOOD), block(GOOD)),
                Err("more than one checkpoint"),
            ),
            (
                "a fence with more",
                format!("{FENCE} json\n{GOOD}\n```"),
                Err("more on its line"),
            ),
            (
                "unclosed",
                format!("{FENCE}\n{GOOD}\n"),
                Err("closing fence"),
            ),
            ("not JSON", block("budget"), Err("not a JSON object")),
            (
                "an unknown key",
                block(
                    r#"{"reason": "budget", "done": "a", "left": "b", "next": "c", "draft": false}"#,
                ),
                Err("not a JSON object"),
            ),
            (
                "a missing key",
                block(r#"{"reason": "budget", "done": "a", "left": "b"}"#),
                Err("not a JSON object"),
            ),
            (
                "another reason",
                block(r#"{"reason": "bored", "done": "a", "left": "b", "next": "c"}"#),
                Err("does not say why"),
            ),
            (
                "an empty field",
                block(r#"{"reason": "cap", "done": "a", "left": " ", "next": "c"}"#),
                Err("does not say why"),
            ),
            (
                "too large",
                block(&format!(
                    r#"{{"reason": "cap", "done": "{}", "left": "b", "next": "c"}}"#,
                    "a\n".repeat(MAX_BYTES)
                )),
                Err("over 8192 bytes"),
            ),
        ];
        for (name, text, want) in cases {
            match (find(text), want) {
                (Ok(got), Ok(want)) => assert_eq!(got.as_ref(), *want, "{name}"),
                (Err(err), Err(want)) => {
                    assert!(format!("{err:#}").contains(want), "{name}: {err:#}")
                }
                (got, want) => panic!("{name}: {got:?}, wanted {want:?}"),
            }
        }
    }
}
