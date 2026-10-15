//! What the driver tells its caller of the child's session: the ACP
//! messages it exchanged, condensed to numbered events that never change
//! once listed, so that `events --since N` misses and repeats nothing.
//!
//! Streamed text (a message, the model's thinking) is one event from its
//! first chunk to the next update of another kind, the end of the turn,
//! or the caller asking for events, whichever comes first: a message
//! still streaming when asked for is cut there and goes on in the next.
//!
//! Compaction is an event of its own. Vibe 2.26.1 reports one as a tool
//! call titled "Compacting context", then "Context compacted" (and its
//! `/compact` command as "Compacting conversation history..."), so a tool
//! call whose title starts with "compact" or ends with "compacted" is
//! taken for one, and so are the later updates of the same call. An agent that does
//! not say so is caught by what it reports of its context: a
//! `usage_update` whose `used` falls below half of the last one, with no
//! reported compaction between them, is an inferred compaction.

use serde_json::{Map, Value, json};

use crate::session::vibe;

/// The most events kept, and the most bytes of them; later ones are
/// counted, not kept. The child's whole transcript is on disk
/// regardless. The bytes keep the answer to `events` within what the
/// command reads, even with every character escaped.
const MAX_EVENTS: usize = 50_000;
const MAX_BYTES: usize = 32 << 20;
/// The most characters of streamed text in one event.
const MAX_TEXT: usize = 64 << 10;
/// The most characters of a tool call's input or output in one event.
const MAX_TOOL_TEXT: usize = 2048;
/// How a compaction's title starts or ends, lowercased.
const COMPACTION_START: &str = "compact";
const COMPACTION_END: &str = "compacted";
/// A context that falls to below 1/COMPACTION_DROP of its last reported
/// size was compacted.
const COMPACTION_DROP: u64 = 2;

const MESSAGE_CHUNK: &str = "agent_message_chunk";
const THOUGHT_CHUNK: &str = "agent_thought_chunk";

/// TEXT cut to at most MAX characters, marked where it was cut.
fn clip(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        None => text.to_owned(),
        Some((end, _)) => format!("{}…[cut]", &text[..end]),
    }
}

/// The text blocks of a tool call's `content`, joined.
fn content_text(content: &Value) -> String {
    let blocks = content.as_array().map(Vec::as_slice).unwrap_or_default();
    let texts: Vec<&str> = blocks
        .iter()
        .filter_map(|block| block["content"]["text"].as_str())
        .collect();
    texts.join("\n")
}

/// A JSON value as the text an event shows of it.
fn shown(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) => Some(clip(text, MAX_TOOL_TEXT)),
        other => Some(clip(&other.to_string(), MAX_TOOL_TEXT)),
    }
}

fn is_compaction(title: &str) -> bool {
    let title = title.trim().to_lowercase();
    title.starts_with(COMPACTION_START) || title.ends_with(COMPACTION_END)
}

/// The events of one child session.
#[derive(Debug, Default)]
pub struct Events {
    list: Vec<Value>,
    /// The bytes of them, as JSON.
    bytes: usize,
    /// Events not kept for want of room.
    dropped: u64,
    /// Streamed text not yet an event: its kind, text and characters.
    pending: Option<(&'static str, String, usize)>,
    /// The tool calls that are compactions, by id.
    compactions: Vec<String>,
    /// The context's size at the last `usage_update`.
    last_used: Option<u64>,
    /// A compaction was reported since then.
    compacted: bool,
}

impl Events {
    pub fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, ts: f64, kind: &str, fields: Value) {
        if self.list.len() >= MAX_EVENTS || self.bytes >= MAX_BYTES {
            self.dropped += 1;
            return;
        }
        let mut event = Map::new();
        event.insert("n".into(), json!(self.list.len()));
        event.insert("ts".into(), json!(ts));
        event.insert("kind".into(), json!(kind));
        if let Value::Object(fields) = fields {
            event.extend(fields.into_iter().filter(|(_, v)| !v.is_null()));
        }
        let event = Value::Object(event);
        self.bytes += event.to_string().len();
        self.list.push(event);
    }

    /// Makes the streamed text so far an event.
    pub fn flush(&mut self, ts: f64) {
        if let Some((kind, text, _)) = self.pending.take() {
            self.push(ts, kind, json!({"text": text}));
        }
    }

    fn stream(&mut self, ts: f64, kind: &'static str, text: &str) {
        if self.pending.as_ref().is_some_and(|(k, _, _)| *k != kind) {
            self.flush(ts);
        }
        let (_, pending, chars) = self.pending.get_or_insert((kind, String::new(), 0));
        // Kept to the limit and marked once: the rest is in the transcript.
        let room = MAX_TEXT.saturating_sub(*chars);
        if room > 0 {
            let kept = clip(text, room);
            *chars += kept.chars().count();
            pending.push_str(&kept);
        }
    }

    /// The caller's prompt, as sent.
    pub fn prompt(&mut self, ts: f64, text: &str) {
        self.flush(ts);
        self.push(ts, "prompt", json!({"text": clip(text, MAX_TEXT)}));
    }

    /// A `session/update` notification's `update`.
    pub fn update(&mut self, ts: f64, update: &Value) {
        if let Some((kind, text)) = vibe::chunk(update) {
            match kind {
                MESSAGE_CHUNK => self.stream(ts, "message", &text),
                THOUGHT_CHUNK => self.stream(ts, "thinking", &text),
                // The prompt, echoed: already an event.
                _ => {}
            }
            return;
        }
        let id = update["toolCallId"].as_str().unwrap_or_default();
        let title = update["title"].as_str();
        let status = update["status"].as_str();
        let known = !id.is_empty() && self.compactions.iter().any(|c| c == id);
        match update["sessionUpdate"].as_str().unwrap_or_default() {
            "tool_call" | "tool_call_update" if known || title.is_some_and(is_compaction) => {
                self.flush(ts);
                if !known && !id.is_empty() {
                    self.compactions.push(id.to_owned());
                }
                self.compacted = true;
                self.push(
                    ts,
                    "compaction",
                    json!({"id": id, "title": title, "status": status, "inferred": false}),
                );
            }
            "tool_call" => {
                self.flush(ts);
                self.push(
                    ts,
                    "tool_call",
                    json!({"id": id, "title": title, "tool_kind": update["kind"],
                        "status": status, "input": shown(&update["rawInput"])}),
                );
            }
            // Only how it ended: the progress between is in the transcript.
            "tool_call_update" if matches!(status, Some("completed" | "failed")) => {
                self.flush(ts);
                let text = content_text(&update["content"]);
                let output = if text.is_empty() {
                    shown(&update["rawOutput"])
                } else {
                    Some(clip(&text, MAX_TOOL_TEXT))
                };
                self.push(
                    ts,
                    "tool_result",
                    json!({"id": id, "title": title, "status": status, "output": output}),
                );
            }
            "usage_update" => {
                let used = update["used"].as_u64();
                if let (Some(before), Some(after)) = (self.last_used, used)
                    && !self.compacted
                    && after.saturating_mul(COMPACTION_DROP) < before
                {
                    self.flush(ts);
                    self.push(
                        ts,
                        "compaction",
                        json!({"inferred": true, "used_before": before, "used_after": after,
                            "size": update["size"]}),
                    );
                }
                if used.is_some() {
                    self.last_used = used;
                    self.compacted = false;
                }
            }
            _ => {}
        }
    }

    /// A permission request of the child's and how it was answered.
    pub fn permission(&mut self, ts: f64, title: Option<&str>, decision: &str) {
        self.flush(ts);
        self.push(
            ts,
            "permission",
            json!({"title": title, "decision": decision}),
        );
    }

    /// The end of a turn: its stop reason, or the error it was answered
    /// with.
    pub fn turn_end(&mut self, ts: f64, stop_reason: Option<&str>, error: Option<&str>) {
        self.flush(ts);
        self.push(
            ts,
            "turn_end",
            json!({"stop_reason": stop_reason, "error": error}),
        );
    }

    /// The child's process ended, as STATUS says.
    pub fn exit(&mut self, ts: f64, status: &str) {
        self.flush(ts);
        self.push(ts, "exit", json!({"status": status}));
    }

    /// The events from the Nth on, after the streamed text so far, and
    /// the number to ask from next time.
    pub fn since(&mut self, ts: f64, n: usize) -> Value {
        self.flush(ts);
        let events = self.list.get(n..).unwrap_or_default();
        json!({"events": events, "next": self.list.len(), "dropped": self.dropped})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(kind: &str, text: &str) -> Value {
        json!({"sessionUpdate": kind, "content": {"type": "text", "text": text}})
    }

    fn kinds(events: &mut Events) -> Vec<String> {
        events.since(0.0, 0)["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["kind"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Streamed chunks are one event until another kind of update, and
    /// asking for events cuts a message where it stood.
    #[test]
    fn streamed_text() {
        let mut events = Events::new();
        events.prompt(0.0, "go");
        events.update(1.0, &chunk(MESSAGE_CHUNK, "Hel"));
        events.update(1.0, &chunk(MESSAGE_CHUNK, "lo"));
        events.update(2.0, &chunk(THOUGHT_CHUNK, "hmm"));
        // Vibe's thinking, as its legacy runtime sends it.
        let repr =
            "{'type': 'thinking', 'thinking': [{'type': 'text', 'text': ' more'}], 'closed': True}";
        events.update(2.0, &chunk(MESSAGE_CHUNK, repr));
        events.update(3.0, &chunk(MESSAGE_CHUNK, "Done"));
        let got = events.since(4.0, 1);
        assert_eq!(got["next"], 4);
        let texts: Vec<(&str, &str)> = got["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["kind"].as_str().unwrap(), e["text"].as_str().unwrap()))
            .collect();
        assert_eq!(
            texts,
            [
                ("message", "Hello"),
                ("thinking", "hmm more"),
                ("message", "Done")
            ]
        );
        events.update(5.0, &chunk(MESSAGE_CHUNK, " again"));
        let got = events.since(6.0, 4);
        assert_eq!(got["events"][0]["text"], " again");
        assert_eq!(got["events"][0]["n"], 4);
        assert_eq!(events.since(6.0, 99)["events"], json!([]));
    }

    /// Compaction is an event whether the agent reports it or its
    /// context only shrinks.
    #[test]
    fn compactions() {
        // (the updates, the compaction events' `inferred`)
        let tool = |kind: &str, id: &str, title: &str, status: &str| {
            json!({"sessionUpdate": kind, "toolCallId": id, "title": title,
                "kind": "think", "status": status})
        };
        let usage =
            |used: u64| json!({"sessionUpdate": "usage_update", "used": used, "size": 32768});
        let cases: Vec<(Vec<Value>, Vec<bool>)> = vec![
            // Vibe 2.26.1's automatic compaction: the update has no title
            // that says so, but its id does.
            (
                vec![
                    usage(24000),
                    tool("tool_call", "c1", "Compacting context", "in_progress"),
                    json!({"sessionUpdate": "tool_call_update", "toolCallId": "c1",
                        "title": "Context compacted", "status": "completed"}),
                    usage(3000),
                ],
                vec![false, false],
            ),
            // Its /compact command.
            (
                vec![tool(
                    "tool_call",
                    "c2",
                    "Compacting conversation history...",
                    "in_progress",
                )],
                vec![false],
            ),
            // Not said: inferred from the context.
            (vec![usage(24000), usage(11999)], vec![true]),
            (vec![usage(24000), usage(12000), usage(30000)], vec![]),
            (vec![usage(100), usage(10)], vec![true]),
            (vec![usage(10)], vec![]),
            // An ordinary tool call is not one.
            (
                vec![tool("tool_call", "t", "Read compactor.rs", "completed")],
                vec![],
            ),
            (
                vec![tool("tool_call_update", "f", "Compaction failed", "failed")],
                vec![false],
            ),
            (vec![tool("tool_call", "t", "bash", "completed")], vec![]),
            // An update without an id is no later update of a compaction.
            (
                vec![
                    tool("tool_call", "", "Compacting context", "in_progress"),
                    tool("tool_call_update", "", "bash", "completed"),
                ],
                vec![false],
            ),
        ];
        for (updates, want) in cases {
            let mut events = Events::new();
            for update in &updates {
                events.update(1.0, update);
            }
            let all = events.since(2.0, 0);
            let got: Vec<bool> = all["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| e["kind"] == "compaction")
                .map(|e| e["inferred"].as_bool().unwrap())
                .collect();
            assert_eq!(got, want, "{updates:?}");
        }
    }

    #[test]
    fn tool_calls_and_their_ends() {
        let mut events = Events::new();
        events.update(
            1.0,
            &json!({"sessionUpdate": "tool_call", "toolCallId": "t1", "title": "bash",
                "kind": "execute", "status": "pending", "rawInput": {"command": "ls"}}),
        );
        events.update(
            1.0,
            &json!({"sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "in_progress"}),
        );
        events.update(
            2.0,
            &json!({"sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "completed",
                "content": [{"type": "content", "content": {"type": "text", "text": "a\nb"}}]}),
        );
        events.permission(3.0, Some("git push"), "deny");
        events.turn_end(4.0, Some("end_turn"), None);
        events.exit(5.0, "exit status: 3");
        let all = events.since(6.0, 0);
        assert_eq!(all["events"][0]["input"], r#"{"command":"ls"}"#);
        assert_eq!(all["events"][1]["output"], "a\nb");
        assert_eq!(all["events"][2]["decision"], "deny");
        assert_eq!(all["events"][3]["stop_reason"], "end_turn");
        assert!(all["events"][3].get("error").is_none());
        assert_eq!(
            kinds(&mut events),
            ["tool_call", "tool_result", "permission", "turn_end", "exit"]
        );
    }

    #[test]
    fn bounded() {
        let mut events = Events::new();
        let long = "x".repeat(MAX_TEXT + 10);
        events.update(0.0, &chunk(MESSAGE_CHUNK, &long));
        events.update(0.0, &chunk(MESSAGE_CHUNK, "more"));
        let all = events.since(0.0, 0);
        let text = all["events"][0]["text"].as_str().unwrap();
        assert!(text.ends_with("…[cut]") && text.chars().count() == MAX_TEXT + 6);
        for _ in 0..MAX_EVENTS + 3 {
            events.exit(0.0, "x");
        }
        let all = events.since(0.0, MAX_EVENTS);
        assert_eq!(all["next"], MAX_EVENTS);
        assert_eq!(all["dropped"], 4);
        assert_eq!(clip("äöü", 2), "äö…[cut]");
        // However few the events, their bytes are bounded too.
        let mut events = Events::new();
        for _ in 0..(MAX_BYTES / MAX_TEXT) + 10 {
            events.update(0.0, &chunk(MESSAGE_CHUNK, &long));
            events.exit(0.0, "x");
        }
        let all = events.since(0.0, 0);
        assert!(all["dropped"].as_u64().unwrap() > 0);
        assert!(all.to_string().len() < MAX_BYTES + 2 * MAX_TEXT + 1024);
        assert_eq!(clip("äö", 2), "äö");
    }
}
