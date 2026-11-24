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

use std::io::{Seek, Write};
use std::process::{Command, Stdio};

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

/// Read the push request before collection can truncate its checkpoint,
/// framed as the collector frames it.
pub(super) fn push_declares_open(outputs: &[u8]) -> Result<bool> {
    for request in safe_outputs::decode::decode(outputs)? {
        if request.kind.replace('-', "_") == crate::policy::PUSH_TO_PULL_REQUEST_BRANCH
            && let Some(message) = request.object.get("message").and_then(|m| m.as_str())
            && find(message)
                .context("the original push request's checkpoint")?
                .is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The last commit's checkpoint after git separates the message from the diff.
/// Only call on a series already bounded and validated by replacement check.
pub(super) fn replacement_head(content: &[u8]) -> Result<Option<Checkpoint>> {
    let series: super::replacement::Replacement = serde_json::from_slice(content)?;
    let mail = series.commits.last().context("empty replacement series")?;
    let scratch = tempfile::tempdir()?;
    let body = scratch.path().join("message");
    let mut input = tempfile::tempfile()?;
    input.write_all(mail.as_bytes())?;
    input.rewind()?;
    // Parse the same plain mail as git am, without importing a repository or
    // applying the patch. A fence in the diff or diffstat is not a checkpoint.
    let output = Command::new("git")
        .args(["mailinfo", "--no-scissors", "--encoding=UTF-8"])
        .arg(&body)
        .arg("/dev/null")
        .current_dir(scratch.path())
        .env_clear()
        .envs(std::env::var_os("PATH").map(|path| ("PATH", path)))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .envs(
            scratch
                .path()
                .parent()
                .map(|p| ("GIT_CEILING_DIRECTORIES", p)),
        )
        .stdin(input)
        .stderr(Stdio::null())
        .output()
        .context("running git mailinfo")?;
    ensure!(
        output.status.success(),
        "git mailinfo failed ({})",
        output.status
    );
    let headers = std::str::from_utf8(&output.stdout).context("mail metadata is not UTF-8")?;
    let subject = headers
        .lines()
        .find_map(|line| line.strip_prefix("Subject: "))
        .unwrap_or_default();
    let body = crate::files::read_regular(&body, mail.len() as u64)?;
    ensure!(
        !body.contains(&0) && !subject.contains('\0'),
        "NUL in the commit message"
    );
    let body = std::str::from_utf8(&body).context("commit message is not UTF-8")?;
    find(&format!("{subject}\n\n{body}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str =
        r#"{"reason": "budget", "done": "the parser", "left": "tests", "next": "add tests"}"#;

    #[test]
    fn push_requests_are_framed_as_the_collector_frames_them() {
        let line = |kind: &str, message: String| {
            serde_json::json!({"type": kind, "message": message}).to_string()
        };
        let open = format!("Partial.\n\n{FENCE}\n{GOOD}\n```");
        let cases: &[(&str, String, Result<bool, &str>)] = &[
            (
                "plain",
                line("push_to_pull_request_branch", "Done.".into()),
                Ok(false),
            ),
            (
                "open",
                line("push_to_pull_request_branch", open.clone()),
                Ok(true),
            ),
            (
                "dashed",
                line("push-to-pull-request-branch", open.clone()),
                Ok(true),
            ),
            (
                "other type",
                line("create_pull_request", open.clone()),
                Ok(false),
            ),
            (
                "leading BOM",
                format!(
                    "\u{feff}{}",
                    line("push_to_pull_request_branch", open.clone())
                ),
                Ok(true),
            ),
            (
                "malformed",
                line("push_to_pull_request_branch", format!("{open}\n\n{open}")),
                Err("more than one checkpoint"),
            ),
            ("not JSON", "{".into(), Err("not JSON")),
        ];
        for (name, outputs, want) in cases {
            match (push_declares_open(format!("{outputs}\n").as_bytes()), want) {
                (Ok(got), Ok(want)) => assert_eq!(got, *want, "{name}"),
                (Err(err), Err(want)) => {
                    assert!(format!("{err:#}").contains(want), "{name}: {err:#}");
                }
                (got, _) => panic!("{name}: {got:?}"),
            }
        }
    }

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
