//! Telling a compaction of an agent's context from its session updates,
//! for the session (which restates the task after one) and for
//! `acp-drive`'s events alike.
//!
//! Vibe 2.26.1 reports one as a tool call titled "Compacting context",
//! then "Context compacted" (and its `/compact` command as "Compacting
//! conversation history..."), so a tool call whose title starts with
//! "compact" or ends with "compacted" is taken for one, and so are the
//! later updates of the same call. An agent that does not say so is
//! caught by what it reports of its context: a `usage_update` whose
//! `used` falls below half of the last one, with no reported compaction
//! between them, is an inferred compaction.

use serde_json::Value;

/// How a compaction's title starts or ends, lowercased.
const COMPACTION_START: &str = "compact";
const COMPACTION_END: &str = "compacted";
/// A context that falls to below 1/COMPACTION_DROP of its last reported
/// size was compacted.
const COMPACTION_DROP: u64 = 2;

fn is_compaction(title: &str) -> bool {
    let title = title.trim().to_lowercase();
    title.starts_with(COMPACTION_START) || title.ends_with(COMPACTION_END)
}

/// What an update says of a compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// An update of a tool call the agent reports as one.
    Reported,
    /// The context fell from BEFORE to AFTER, with none reported.
    Inferred { before: u64, after: u64 },
}

impl Seen {
    /// Whether the compaction is over with UPDATE, the one it was seen
    /// in: the context is the compacted one from then on.
    pub fn finished(self, update: &Value) -> bool {
        match self {
            Seen::Reported => update["status"] == "completed",
            Seen::Inferred { .. } => true,
        }
    }
}

/// The compactions of one session, as its updates come.
#[derive(Debug, Default)]
pub struct Compactions {
    /// The tool calls that are compactions, by id.
    ids: Vec<String>,
    /// The context's size at the last `usage_update`.
    last_used: Option<u64>,
    /// A compaction was reported since then.
    reported: bool,
}

impl Compactions {
    /// What a `session/update` notification's UPDATE says of a
    /// compaction; `None` when it is none.
    pub fn update(&mut self, update: &Value) -> Option<Seen> {
        match update["sessionUpdate"].as_str().unwrap_or_default() {
            "tool_call" | "tool_call_update" => {
                let id = update["toolCallId"].as_str().unwrap_or_default();
                let known = !id.is_empty() && self.ids.iter().any(|c| c == id);
                if !known && !update["title"].as_str().is_some_and(is_compaction) {
                    return None;
                }
                if !known && !id.is_empty() {
                    self.ids.push(id.to_owned());
                }
                self.reported = true;
                Some(Seen::Reported)
            }
            "usage_update" => {
                let used = update["used"].as_u64();
                let seen = match (self.last_used, used) {
                    (Some(before), Some(after))
                        if !self.reported && after.saturating_mul(COMPACTION_DROP) < before =>
                    {
                        Some(Seen::Inferred { before, after })
                    }
                    _ => None,
                };
                if used.is_some() {
                    self.last_used = used;
                    self.reported = false;
                }
                seen
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A reported compaction is over when its tool call completes, an
    /// inferred one when it is seen. (Which updates are compactions at all
    /// is `acp_drive::events`' case table.)
    #[test]
    fn when_a_compaction_is_over() {
        let mut compactions = Compactions::default();
        let tool = |kind: &str, title: &str, status: &str| json!({"sessionUpdate": kind, "toolCallId": "c1", "title": title, "status": status});
        // (the update, whether it is one, whether that one is over)
        let cases = [
            (
                tool("tool_call", "Compacting context", "in_progress"),
                true,
                false,
            ),
            (tool("tool_call_update", "bash", "in_progress"), true, false),
            (
                tool("tool_call_update", "Context compacted", "completed"),
                true,
                true,
            ),
            (
                json!({"sessionUpdate": "usage_update", "used": 24000}),
                false,
                false,
            ),
            (
                json!({"sessionUpdate": "usage_update", "used": 3000}),
                true,
                true,
            ),
        ];
        for (update, is_one, over) in cases {
            let seen = compactions.update(&update);
            assert_eq!(seen.is_some(), is_one, "{update}");
            assert_eq!(seen.is_some_and(|s| s.finished(&update)), over, "{update}");
        }
    }
}
