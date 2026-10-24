//! The transcript: every line that crosses the agent's standard streams,
//! written down as it passes.
//!
//! The [`Tap`] is the one place all of the agent's traffic goes through.
//! It records each message in `acp.jsonl`, feeds the digest (which makes
//! the condensed log and counts what the limits need), stops the session
//! when the agent reports spending over the budget, counts the
//! compactions of the agent's context it reports or shows, and passes
//! the agent's messages on to whatever clients are attached.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;

use super::budget::{Limits, Repeats, Stop};
use super::clients::Clients;
use super::compaction::Compactions;
use super::digest::{Digest, Dir};
use super::provider::{self, Class};

/// The files a session writes to its output directory.
pub const ACP_LOG: &str = "acp.jsonl";
pub const STDERR_LOG: &str = "agent-stderr.log";

/// One line of `acp.jsonl`: a JSON-RPC message as it crossed the stream,
/// parsed (so re-serialized, with its keys in order), or the raw line if
/// it wasn't JSON.
#[derive(Debug, Serialize, Deserialize)]
pub struct Record {
    pub ts: f64,
    pub dir: Dir,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msg: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<String>,
}

/// Where the condensed log goes: one line per event, for the job's log.
pub type Log = Box<dyn Write + Send>;

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Sees every line on the agent's standard streams.
pub(super) struct Tap {
    inner: Mutex<Inner>,
    limits: Limits,
    stop: watch::Sender<Option<Stop>>,
    clients: Clients,
    /// `AgentSpec::provider_error`.
    provider_error: Option<String>,
    /// How many compactions of the agent's context have finished.
    compacted: watch::Sender<u64>,
    /// How many messages have come from the agent.
    heard: watch::Sender<u64>,
}

struct Inner {
    acp: BufWriter<File>,
    stderr: BufWriter<File>,
    log: Log,
    digest: Digest,
    compactions: Compactions,
    /// The last thing the agent said on its standard error.
    last_stderr: Option<String>,
    /// The last words of a model provider's failure the agent let out in
    /// the current turn, on its standard error or in a message that
    /// starts with its `provider-error` words, and their class: what an
    /// agent that then dies died of, more often than its last line says.
    /// Forgotten when the next turn is sent.
    provider_failure: Option<(Class, String)>,
    /// The first write error; the run fails with it.
    error: Option<String>,
}

impl Inner {
    fn note(&mut self, r: std::io::Result<()>) {
        if let Err(e) = r {
            self.error
                .get_or_insert_with(|| format!("writing the transcript: {e}"));
        }
    }

    fn log(&mut self, lines: &[String]) {
        // The job log is best effort; the transcript has everything.
        for line in lines {
            let _ = writeln!(self.log, "{}", crate::workflow_commands::escaped(line));
        }
        let _ = self.log.flush();
    }
}

/// Stops the session for WHY, unless it is being stopped already.
pub(super) fn set_stop(stop: &watch::Sender<Option<Stop>>, why: Stop) {
    stop.send_if_modified(|s| {
        let first = s.is_none();
        if first {
            *s = Some(why);
        }
        first
    });
}

impl Tap {
    pub fn create(
        out: &Path,
        log: Log,
        limits: Limits,
        stop: watch::Sender<Option<Stop>>,
        clients: Clients,
        provider_error: Option<String>,
    ) -> Result<Self> {
        let open = |name: &str| -> Result<BufWriter<File>> {
            let path = out.join(name);
            Ok(BufWriter::new(
                File::create(&path).with_context(|| format!("creating {}", path.display()))?,
            ))
        };
        Ok(Self {
            inner: Mutex::new(Inner {
                acp: open(ACP_LOG)?,
                stderr: open(STDERR_LOG)?,
                log,
                digest: Digest::new(),
                compactions: Compactions::default(),
                last_stderr: None,
                provider_failure: None,
                error: None,
            }),
            limits,
            stop,
            clients,
            provider_error,
            compacted: watch::Sender::new(0),
            heard: watch::Sender::new(0),
        })
    }

    /// A panic while the lock was held loses nothing a later line needs.
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A protocol line, to the agent (`Dir::Send`) or from it.
    pub fn message(&self, dir: Dir, line: &str) {
        let ts = now();
        let msg = serde_json::from_str::<Value>(line).ok();
        let record = Record {
            ts,
            dir,
            line: msg.is_none().then(|| line.to_owned()),
            msg,
        };
        let mut inner = self.inner();
        let r = serde_json::to_writer(&mut inner.acp, &record)
            .map_err(std::io::Error::from)
            .and_then(|()| writeln!(inner.acp))
            .and_then(|()| inner.acp.flush());
        inner.note(r);
        let Some(msg) = &record.msg else { return };
        let lines = inner.digest.feed(ts, dir, msg);
        inner.log(&lines);
        // A failure the agent let out before this turn is not what a
        // later turn ends on: a line of an earlier turn that recovered
        // would otherwise file an unrelated crash as the provider's.
        if dir == Dir::Send && msg["method"] == "session/prompt" {
            inner.provider_failure = None;
        }
        // A message that says the provider refused, remembered for an
        // agent that dies after saying so (`provider_failure`).
        if dir == Dir::Recv
            && let Some(prefix) = self.provider_error.as_deref()
            && let Some(said) = inner
                .digest
                .last_message()
                .filter(|s| s.starts_with(prefix))
        {
            let said = said.to_owned();
            inner.provider_failure = Some((provider::classify(&said), said));
        }
        if let Some(stop) = inner.digest.cost_usd.and_then(|c| self.limits.overspent(c)) {
            set_stop(&self.stop, stop);
        }
        if dir == Dir::Recv {
            self.heard.send_modify(|n| *n = n.wrapping_add(1));
            if msg["method"] == "session/update" {
                let update = &msg["params"]["update"];
                if inner
                    .compactions
                    .update(update)
                    .is_some_and(|seen| seen.finished(update))
                {
                    self.compacted.send_modify(|n| *n += 1);
                }
            }
            self.clients.relay(msg);
        }
    }

    /// The count of finished compactions of the agent's context, which
    /// changes with each.
    pub fn compactions(&self) -> watch::Receiver<u64> {
        self.compacted.subscribe()
    }

    /// The count of messages from the agent, which changes with each.
    pub fn heard(&self) -> watch::Receiver<u64> {
        self.heard.subscribe()
    }

    /// Whether a tool call the agent started has not finished: a quiet
    /// agent may be waiting for it rather than for its model.
    pub fn tool_running(&self) -> bool {
        self.inner().digest.tool_running()
    }

    /// A line of the agent's standard error.
    pub fn stderr(&self, line: &str) {
        let mut inner = self.inner();
        let r = writeln!(inner.stderr, "{line}").and_then(|()| inner.stderr.flush());
        inner.note(r);
        if !line.trim().is_empty() {
            inner.last_stderr = Some(line.to_owned());
            // Only words that fit a class: the agent's stack trace after
            // them is not what the provider said.
            let class = provider::classify(line);
            if class != Class::Other {
                inner.provider_failure = Some((class, line.to_owned()));
            }
        }
    }

    /// Lines of the session's own for the condensed log.
    pub fn log(&self, lines: &[String]) {
        self.inner().log(lines);
    }

    /// The subagent tasks the agent has started.
    pub fn tasks(&self) -> usize {
        self.inner().digest.tasks
    }

    /// The agent's latest run of identical tool calls.
    pub fn repeats(&self) -> Repeats {
        self.inner().digest.repeats
    }

    /// What the agent said its turn ended with, if that is that the
    /// provider refused its model request (`AgentSpec::provider_error`).
    pub fn refusal(&self) -> Option<String> {
        let prefix = self.provider_error.as_deref()?;
        let inner = self.inner();
        let said = inner.digest.last_message()?;
        said.starts_with(prefix).then(|| said.to_owned())
    }

    /// The last line the agent wrote to its standard error: of an agent
    /// that died, usually why.
    pub fn last_stderr(&self) -> Option<String> {
        self.inner().last_stderr.clone()
    }

    /// The last model provider's failure the agent let out, by class and
    /// in its words (`Inner::provider_failure`); none if it let out none.
    pub fn provider_failure(&self) -> Option<(Class, String)> {
        self.inner().provider_failure.clone()
    }

    /// Ends the transcript: the digest's last lines are logged, and what
    /// it knows of how the session went is returned.
    pub fn finish(&self) -> Finished {
        let mut inner = self.inner();
        let lines = inner.digest.finish();
        inner.log(&lines);
        Finished {
            stop_reason: inner.digest.stop_reason.clone(),
            agent_error: inner.digest.error.is_some(),
            write_error: inner.error.take(),
        }
    }
}

/// What the transcript knows at the end of a session.
pub(super) struct Finished {
    /// The stop reason of the last turn the agent answered.
    pub stop_reason: Option<String>,
    /// The condensed log already says why a request to the agent failed.
    pub agent_error: bool,
    /// The transcript could not be written.
    pub write_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_logs_are_escaped_but_transcripts_keep_original_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("job.log");
        let (stop, _) = watch::channel(None);
        let tap = Tap::create(
            dir.path(),
            Box::new(File::create(&path).unwrap()),
            Limits::default(),
            stop,
            Clients::none(),
            None,
        )
        .unwrap();
        let lines = [
            "prefix ::set-output name=a::b",
            "::::add-mask::hidden\r\n##[error]forged",
        ]
        .map(str::to_owned);
        tap.log(&lines);
        for line in &lines {
            tap.stderr(line);
        }
        let shown = std::fs::read_to_string(path).unwrap();
        assert!(!shown.contains("::") && !shown.contains("##["), "{shown}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(STDERR_LOG)).unwrap(),
            format!("{}\n", lines.join("\n")),
        );
    }

    /// A turn whose last message starts with the agent's provider-error
    /// words, after any leading blanks, ended on a refusal; nothing else
    /// does, and nothing at all for an agent with no such words.
    #[test]
    fn refusal() {
        // (the agent's words, what it said last, what was refused)
        let cases = [
            (Some("API Error:"), "API Error: 429", Some("API Error: 429")),
            (
                Some("API Error:"),
                "  API Error: 429",
                Some("API Error: 429"),
            ),
            (Some("API Error:"), "Done. API Error: 429", None),
            (Some("API Error:"), "api error: 429", None),
            (None, "API Error: 429", None),
        ];
        for (words, said, want) in cases {
            let dir = tempfile::tempdir().unwrap();
            let (stop, _) = watch::channel(None);
            let tap = Tap::create(
                dir.path(),
                Box::new(std::io::sink()),
                Limits::default(),
                stop,
                Clients::none(),
                words.map(str::to_owned),
            )
            .unwrap();
            let chunk = serde_json::json!({"jsonrpc": "2.0", "method": "session/update",
                "params": {"sessionId": "s", "update": {"sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": said}}}});
            let prompt = r#"{"jsonrpc": "2.0", "id": 1, "method": "session/prompt", "params": {}}"#;
            let end = r#"{"jsonrpc": "2.0", "id": 1, "result": {"stopReason": "end_turn"}}"#;
            tap.message(Dir::Send, prompt);
            tap.message(Dir::Recv, &chunk.to_string());
            tap.message(Dir::Recv, end);
            assert_eq!(tap.refusal().as_deref(), want, "{said:?}");
        }
    }
}
