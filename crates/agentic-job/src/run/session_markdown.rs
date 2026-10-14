//! Trusted rendering of the already redacted ACP transcript. Claude's runner
//! uses claude-agent-acp, not native stream-json; never read sandbox session files.

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde_json::Value;

use super::log::Shared;
use super::{summary, upload::Staging};
use crate::session::Record;
use crate::session::digest::Dir;

const OUTPUT_BYTES: usize = 8192;
const ARG_BYTES: usize = 240;
// The action appends setup accounting after the run's summary.
const SUMMARY_BYTES: usize = (1 << 20) - 4096;
const NOTICE: &str = "\nSession shortened to fit GitHub's summary limit. Full Markdown: `session.md` in the [**agent-run** artifact](#artifacts) (with the configured artifact prefix).\n";

struct Block {
    assistant: bool,
    markdown: String,
}

pub(super) struct Session {
    pub full: String,
    blocks: Vec<Block>,
}

// Transcript text is hostile: HTML escaping alone still permits Markdown links,
// images and fences. Encode punctuation so it remains prose without markup.
fn redacted(text: &str, redactor: &Shared) -> String {
    // Never concatenate around a control: that could reconstruct a credential
    // and hide its punctuation from the upload gate. Normalize before redacting
    // in case a literal credential itself contains spaces.
    let normalized: String = text
        .chars()
        .map(|c| {
            if c.is_control() && !matches!(c, '\n' | '\t') {
                ' '
            } else {
                c
            }
        })
        .collect();
    // Joining streamed chunks can reconstruct a secret split across JSON lines.
    redactor.with(|r| r.redact(&normalized).into_owned())
}

fn escape(text: &str, redactor: &Shared) -> String {
    let text = redacted(text, redactor);
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_punctuation() {
            out.push_str(&format!("&#{};", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

fn prefix(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn bounded(text: &str, max: usize, redactor: &Shared) -> String {
    let text = redacted(text, redactor);
    let shown = prefix(&text, max);
    let mut out = escape(shown, redactor);
    if shown.len() < text.len() {
        out.push_str(&format!("\n[{} bytes omitted]", text.len() - shown.len()));
    }
    out
}

fn texts(content: &Value) -> String {
    content.as_array().map_or_else(
        || content["text"].as_str().unwrap_or_default().to_owned(),
        |blocks| {
            blocks
                .iter()
                .filter_map(|b| b["content"]["text"].as_str().or(b["text"].as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        },
    )
}

struct Tool {
    block: usize,
    start: Option<f64>,
    end: Option<f64>,
    fields: Value,
}

impl Session {
    pub fn preview(&self, limit: usize) -> String {
        if self.full.len() <= limit {
            return self.full.clone();
        }
        if limit < NOTICE.len() {
            return String::new();
        }
        let mut selected: Vec<Option<String>> = vec![None; self.blocks.len()];
        let mut remaining = limit - NOTICE.len();
        let assistants = self.blocks.iter().filter(|b| b.assistant).count();
        let assistant_bytes: usize = self
            .blocks
            .iter()
            .filter(|b| b.assistant)
            .map(|b| b.markdown.len())
            .sum();
        let share = if assistant_bytes > remaining {
            remaining / assistants.max(1)
        } else {
            remaining
        };
        // Every assistant message gets space. If their prose alone exceeds the
        // cap, abbreviate it rather than silently dropping an expensive turn.
        for (i, block) in self.blocks.iter().enumerate().filter(|(_, b)| b.assistant) {
            let budget = share.min(remaining);
            let markdown = if block.markdown.len() <= budget {
                block.markdown.clone()
            } else {
                let marker = "\n[Assistant prose shortened; see session.md]\n";
                if budget < marker.len() {
                    continue;
                }
                // Assistant blocks contain only a generated heading and encoded
                // prose, never HTML tags; don't cut inside an encoded entity.
                let mut head = prefix(&block.markdown, budget - marker.len());
                if let Some(i) = head.rfind('&')
                    && !head[i..].contains(';')
                {
                    head = &head[..i];
                }
                format!("{head}{marker}")
            };
            remaining -= markdown.len();
            selected[i] = Some(markdown);
        }
        // Then alternate head and tail, retaining chronology in the result.
        for i in (0..self.blocks.len()).flat_map(|i| [i, self.blocks.len() - 1 - i]) {
            if selected[i].is_none() && self.blocks[i].markdown.len() <= remaining {
                selected[i] = Some(self.blocks[i].markdown.clone());
                remaining -= self.blocks[i].markdown.len();
            }
        }
        let mut out = NOTICE.to_owned();
        for markdown in selected.into_iter().flatten() {
            out.push_str(&markdown);
        }
        out
    }
}

pub(super) fn render(records: &[Record], redactor: &Shared) -> Session {
    let mut blocks = vec![Block {
        assistant: false,
        markdown: "\n## Agent session\n".to_owned(),
    }];
    let mut tools: HashMap<String, Tool> = HashMap::new();
    let mut prose: Option<(String, String)> = None;
    let mut message_id = Value::Null;
    let flush = |prose: &mut Option<(String, String)>, blocks: &mut Vec<Block>| {
        if let Some((kind, text)) = prose.take() {
            let markdown = if kind == "Reasoning" {
                format!(
                    "\n<details><summary>Reasoning</summary>\n\n{}\n\n</details>\n",
                    escape(&text, redactor)
                )
            } else {
                format!("\n### {kind}\n\n{}\n", escape(&text, redactor))
            };
            blocks.push(Block {
                assistant: kind == "Assistant",
                markdown,
            });
        }
    };
    for record in records {
        let Some(msg) = &record.msg else { continue };
        if record.dir == Dir::Send && msg["method"] == "session/prompt" {
            flush(&mut prose, &mut blocks);
            blocks.push(Block {
                assistant: false,
                markdown: format!(
                    "\n### User\n\n{}\n",
                    escape(&texts(&msg["params"]["prompt"]), redactor)
                ),
            });
            continue;
        }
        if record.dir != Dir::Recv {
            continue;
        }
        let u = &msg["params"]["update"];
        let kind = u["sessionUpdate"].as_str().unwrap_or_default();
        if matches!(
            kind,
            "agent_message_chunk" | "agent_thought_chunk" | "user_message_chunk"
        ) {
            let label = match kind {
                "agent_message_chunk" => "Assistant",
                "agent_thought_chunk" => "Reasoning",
                _ => "User",
            };
            if prose.as_ref().is_some_and(|(k, _)| k != label)
                || (!u["messageId"].is_null() && u["messageId"] != message_id)
            {
                flush(&mut prose, &mut blocks);
            }
            message_id = u["messageId"].clone();
            let (_, text) = prose.get_or_insert_with(|| (label.to_owned(), String::new()));
            text.push_str(u["content"]["text"].as_str().unwrap_or_default());
            continue;
        }
        flush(&mut prose, &mut blocks);
        message_id = Value::Null;
        if matches!(kind, "tool_call" | "tool_call_update") {
            let Some(id) = u["toolCallId"].as_str() else {
                continue;
            };
            let tool = tools.entry(id.to_owned()).or_insert_with(|| {
                let block = blocks.len();
                blocks.push(Block {
                    assistant: false,
                    markdown: String::new(),
                });
                Tool {
                    block,
                    start: (kind == "tool_call").then_some(record.ts),
                    end: None,
                    fields: serde_json::json!({}),
                }
            });
            if let Some(fields) = u.as_object() {
                for (key, value) in fields {
                    if !value.is_null() {
                        tool.fields[key] = value.clone();
                    }
                }
            }
            if matches!(u["status"].as_str(), Some("completed" | "failed")) {
                tool.end.get_or_insert(record.ts);
            }
        } else if kind == "usage_update" || !msg["result"]["usage"].is_null() {
            let usage = if kind == "usage_update" {
                u
            } else {
                &msg["result"]["usage"]
            };
            blocks.push(Block {
                assistant: false,
                markdown: format!(
                    "\nReported usage (agent-reported; may be cumulative): {}\n",
                    bounded(&usage.to_string(), OUTPUT_BYTES, redactor)
                ),
            });
        }
    }
    flush(&mut prose, &mut blocks);
    for tool in tools.values() {
        let f = &tool.fields;
        let name = f["_meta"]["claudeCode"]["toolName"]
            .as_str()
            .or(f["title"].as_str())
            .unwrap_or("Tool");
        let duration = tool.start.zip(tool.end).map_or_else(
            || "unknown duration".to_owned(),
            |(start, end)| format!("{:.1}s", (end - start).max(0.0)),
        );
        let status = f["status"].as_str().unwrap_or("in progress");
        let output = texts(&f["content"]);
        let exit = f["rawOutput"]["exit_code"]
            .as_i64()
            .or(f["rawOutput"]["metadata"]["exit"].as_i64())
            .or_else(|| {
                output
                    .lines()
                    .next()?
                    .strip_prefix("Exit code ")?
                    .parse()
                    .ok()
            })
            .map_or_else(|| "exit unknown".to_owned(), |code| format!("exit {code}"));
        blocks[tool.block].markdown = format!(
            "\n<details><summary>{} — {duration}, {}, {exit}</summary>\n\nArguments: {}\n\n<pre>{}</pre>\n\n</details>\n",
            bounded(name, ARG_BYTES, redactor),
            bounded(status, ARG_BYTES, redactor),
            bounded(&f["rawInput"].to_string(), ARG_BYTES, redactor),
            bounded(&output, OUTPUT_BYTES, redactor)
        );
    }
    let full = blocks.iter().map(|b| b.markdown.as_str()).collect();
    Session { full, blocks }
}

/// Writes only runner-owned staging files; the existing upload gate still checks
/// all three outputs. No renderer or agent code executes in the applying job.
pub(super) fn write(
    staging: &Staging,
    records: &[Record],
    redactor: &Shared,
    enabled: bool,
    accounting: &mut Value,
) -> Result<()> {
    let rendered = enabled.then(|| render(records, redactor));
    accounting["redactions"] = redactor.count().into();
    let mut markdown = summary::markdown(accounting);
    if let Some(session) = rendered {
        // An already oversized accounting table must not consume the session's
        // entire budget. Its complete data remains in summary.json.
        if markdown.len() > SUMMARY_BYTES / 2 {
            markdown = "## Agent run\n\nAccounting tables exceed the display budget; see `summary.json` in the [agent-run artifact](#artifacts).\n".to_owned();
        }
        let remaining = SUMMARY_BYTES.saturating_sub(markdown.len());
        markdown.push_str(&session.preview(remaining));
        std::fs::write(staging.run().join("session.md"), session.full)
            .context("writing session.md")?;
    }
    std::fs::write(
        staging.run().join(summary::SUMMARY_FILE),
        format!("{accounting}\n"),
    )
    .context("writing summary.json")?;
    std::fs::write(staging.run().join(summary::MARKDOWN_FILE), markdown)
        .context("writing summary.md")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(ts: f64, update: Value) -> Record {
        serde_json::from_value(json!({"ts": ts, "dir": "recv", "msg": {"method": "session/update", "params": {"update": update}}})).unwrap()
    }

    #[test]
    fn prose_tools_reasoning_and_hostile_markup() {
        let records = vec![
            record(
                0.0,
                json!({"sessionUpdate":"agent_message_chunk","content":{"text":"hello "}}),
            ),
            record(
                0.1,
                json!({"sessionUpdate":"agent_message_chunk","content":{"text":"world </details> ![x](https://evil)"}}),
            ),
            record(
                1.0,
                json!({"sessionUpdate":"agent_thought_chunk","content":{"text":"secret <script>"}}),
            ),
            record(
                2.0,
                json!({"sessionUpdate":"tool_call","toolCallId":"t","title":"Bash","rawInput":{"command":"`bad`"}}),
            ),
            record(
                5.0,
                json!({"sessionUpdate":"tool_call_update","toolCallId":"t","status":"failed","rawOutput":{"exit_code":7},"content":[{"type":"content","content":{"text":"</details>```"}}]}),
            ),
        ];
        let s = render(
            &records,
            &Shared::new(crate::redact::Redactor::new::<&str>([]).unwrap()),
        );
        assert!(s.full.contains("hello world"));
        assert!(s.full.contains("Reasoning</summary>"));
        assert!(s.full.contains("3.0s, failed, exit 7"));
        assert!(!s.full.contains("<script>"));
        assert!(!s.full.contains("![x]"));
        assert!(!s.full.contains("```"));
        assert_eq!(s.full.matches("</details>").count(), 2);
        assert_eq!(s.preview(s.full.len()), s.full);
    }

    #[test]
    fn preview_is_bounded_and_retains_assistant_prose() {
        let records = vec![
            record(
                0.0,
                json!({"sessionUpdate":"agent_message_chunk","content":{"text":"keep me"}}),
            ),
            record(
                1.0,
                json!({"sessionUpdate":"tool_call","toolCallId":"t","title":"Bash","content":[{"text":"é".repeat(10000)}]}),
            ),
        ];
        let s = render(
            &records,
            &Shared::new(crate::redact::Redactor::new::<&str>([]).unwrap()),
        );
        assert!(s.full.contains("11808 bytes omitted"));
        let preview = s.preview(500);
        assert!(preview.len() <= 500);
        assert!(preview.contains("keep me"));
        assert!(preview.contains("session.md"));
        assert_eq!(
            preview.matches("<details>").count(),
            preview.matches("</details>").count()
        );
        assert!(s.preview(1).is_empty());
    }

    #[test]
    fn defaults_off_and_can_be_enabled_in_owned_configuration() {
        for (text, enabled) in [
            ("", false),
            ("render-session = true", true),
            ("render-session = false", false),
        ] {
            let agent: crate::config::Agent = toml::from_str(text).unwrap();
            assert_eq!(agent.render_session, enabled);
        }
    }

    #[test]
    fn redacts_secrets_reconstructed_from_streamed_chunks() {
        let redactor = Shared::new(crate::redact::Redactor::new(["split-secret-value"]).unwrap());
        let records = vec![
            record(
                0.0,
                json!({"sessionUpdate":"agent_message_chunk","content":{"text":"split-secret-"}}),
            ),
            record(
                0.1,
                json!({"sessionUpdate":"agent_message_chunk","content":{"text":"value"}}),
            ),
        ];
        let s = render(&records, &redactor);
        assert!(s.full.contains("REDACTED"));
        assert!(!s.full.contains("split"));
        assert_eq!(redactor.count(), 1);
    }

    #[test]
    fn oversized_assistant_and_escaped_output_never_exceed_summary_budget() {
        let redactor = Shared::new(crate::redact::Redactor::new::<&str>([]).unwrap());
        let records = vec![record(
            0.0,
            json!({"sessionUpdate":"agent_message_chunk","content":{"text":"<&é".repeat(100000)}}),
        )];
        let s = render(&records, &redactor);
        let preview = s.preview(1024);
        assert!(preview.len() <= 1024);
        assert!(preview.contains("### Assistant"));
        assert!(preview.contains("Assistant prose shortened"));
        assert!(!preview.contains("<&"));
        assert!(s.full.len() > 1024);
    }

    #[test]
    fn retains_head_tail_all_assistants_and_unknown_tool_state() {
        let redactor = Shared::new(crate::redact::Redactor::new::<&str>([]).unwrap());
        let mut records = vec![record(
            0.0,
            json!({"sessionUpdate":"agent_message_chunk","content":{"text":"first"}}),
        )];
        for i in 0..10 {
            records.push(record(i as f64, json!({"sessionUpdate":"tool_call","toolCallId":i.to_string(),"title":"Terminal","content":[{"text":"x".repeat(8192)}]})));
            records.push(record(i as f64, json!({"sessionUpdate":"agent_message_chunk","content":{"text":format!("assistant {i}")}})));
        }
        let s = render(&records, &redactor);
        assert!(
            s.full
                .contains("unknown duration, in progress, exit unknown")
        );
        let preview = s.preview(20000);
        assert!(preview.len() <= 20000);
        assert!(preview.contains("first"));
        for i in 0..10 {
            assert!(preview.contains(&format!("assistant {i}")));
        }
        assert_eq!(preview.matches("<details>").count(), 2);
        assert_eq!(
            preview.matches("<details>").count(),
            preview.matches("</details>").count()
        );
    }

    // Decode exactly the renderer's generated entities, as a browser would.
    fn decoded(markdown: &str) -> String {
        let mut out = String::new();
        let mut rest = markdown;
        while let Some((head, tail)) = rest.split_once("&#") {
            out.push_str(head);
            let (number, after) = tail.split_once(';').unwrap();
            out.push(char::from_u32(number.parse().unwrap()).unwrap());
            rest = after;
        }
        out.push_str(rest);
        out
    }

    #[test]
    fn controls_cannot_reconstruct_credentials_in_any_rendered_field() {
        let secret = format!("ghp_{}", "a".repeat(40));
        let redactor =
            Shared::new(crate::redact::Redactor::new([&secret, "literal with spaces"]).unwrap());
        for hostile in [
            format!("gh\0p_{}", "a".repeat(40)),
            "literal\0with spaces".to_owned(),
        ] {
            let records = vec![
                record(
                    0.0,
                    json!({"sessionUpdate":"agent_message_chunk","content":{"text":hostile}}),
                ),
                record(
                    1.0,
                    json!({"sessionUpdate":"agent_thought_chunk","content":{"text":hostile}}),
                ),
                record(
                    2.0,
                    json!({"sessionUpdate":"tool_call","toolCallId":"t","title":hostile,"rawInput":{"command":hostile},"content":[{"text":hostile}]}),
                ),
            ];
            let session = render(&records, &redactor);
            let visible = decoded(&session.full);
            assert!(!visible.contains(&secret));
            assert!(!visible.contains("literal with spaces"));
            assert!(!redactor.with(|r| r.finds(visible.as_bytes())));
        }
    }

    #[test]
    fn duration_uses_first_completion_and_never_invents_a_missing_start() {
        let redactor = Shared::new(crate::redact::Redactor::new::<&str>([]).unwrap());
        let records = vec![
            record(
                2.0,
                json!({"sessionUpdate":"tool_call","toolCallId":"t","title":"Bash"}),
            ),
            record(
                5.0,
                json!({"sessionUpdate":"tool_call_update","toolCallId":"t","status":"completed"}),
            ),
            record(
                20.0,
                json!({"sessionUpdate":"tool_call_update","toolCallId":"t","status":"completed"}),
            ),
            record(
                30.0,
                json!({"sessionUpdate":"tool_call_update","toolCallId":"missing","status":"completed"}),
            ),
        ];
        let session = render(&records, &redactor);
        assert!(session.full.contains("3.0s, completed"));
        assert!(!session.full.contains("18.0s"));
        assert!(session.full.contains("unknown duration, completed"));
    }

    #[test]
    fn staged_summaries_pass_the_gate_and_publish_only_opted_in_sessions() {
        for enabled in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let staging = Staging::create(dir.path()).unwrap();
            let redactor =
                Shared::new(crate::redact::Redactor::new(["split-secret-value"]).unwrap());
            let records = vec![
                record(
                    0.0,
                    json!({"sessionUpdate":"agent_message_chunk","content":{"text":"split-secret-"}}),
                ),
                record(
                    0.1,
                    json!({"sessionUpdate":"agent_message_chunk","content":{"text":"value"}}),
                ),
            ];
            let mut accounting = json!({"redactions": 0});
            write(&staging, &records, &redactor, enabled, &mut accounting).unwrap();
            staging
                .check(
                    super::super::upload::Gate {
                        ended: true,
                        fake_agent: false,
                    },
                    &redactor,
                )
                .unwrap();
            staging
                .publish(dir.path(), &std::sync::atomic::AtomicBool::new(false))
                .unwrap();
            let run = dir.path().join("run");
            assert_eq!(run.join("session.md").exists(), enabled);
            let markdown = std::fs::read_to_string(run.join("summary.md")).unwrap();
            assert_eq!(markdown.contains("### Assistant"), enabled);
            assert!(markdown.len() <= SUMMARY_BYTES);
            let summary: Value =
                serde_json::from_slice(&std::fs::read(run.join("summary.json")).unwrap()).unwrap();
            assert_eq!(summary["redactions"], usize::from(enabled));
            if enabled {
                assert!(markdown.contains("Redacted 1 string(s)."));
            }
        }
    }

    #[test]
    fn oversized_accounting_cannot_exhaust_the_session_budget() {
        let dir = tempfile::tempdir().unwrap();
        let staging = Staging::create(dir.path()).unwrap();
        let redactor = Shared::new(crate::redact::Redactor::new::<&str>([]).unwrap());
        let records = vec![record(
            0.0,
            json!({"sessionUpdate":"agent_message_chunk","content":{"text":"keep assistant"}}),
        )];
        let mut accounting = json!({"tests": [{"command": "x".repeat(1 << 20), "exit_code": 0}]});
        write(&staging, &records, &redactor, true, &mut accounting).unwrap();
        let markdown = std::fs::read_to_string(staging.run().join("summary.md")).unwrap();
        assert!(markdown.len() <= SUMMARY_BYTES);
        assert!(markdown.contains("Accounting tables exceed"));
        assert!(markdown.contains("keep assistant"));
        assert!(
            std::fs::metadata(staging.run().join("summary.json"))
                .unwrap()
                .len()
                > (1 << 20)
        );
    }
}
