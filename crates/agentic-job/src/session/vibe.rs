//! Vibe's thinking over ACP. Its legacy runtime sends each chunk of the
//! model's reasoning as an `agent_message_chunk` whose text is the Python
//! repr of the chunk:
//!
//! ```text
//! {'type': 'thinking', 'thinking': [{'type': 'text', 'text': 'Let'}], 'closed': True}
//! ```
//!
//! [`chunk`] reads such a chunk as the `agent_thought_chunk` other agents
//! send, with its text, so the condensed log and the rendered session
//! treat it as they treat theirs. Only that literal shape is read: a
//! message that merely looks like it otherwise stays a message.

use std::borrow::Cow;

use serde_json::Value;

const MESSAGE: &str = "agent_message_chunk";
const THOUGHT: &str = "agent_thought_chunk";
/// How deep a literal may nest: a thinking chunk is three levels.
const MAX_DEPTH: usize = 8;

/// The kind and text of UPDATE, a message or thought chunk, with Vibe's
/// thinking read as a thought; `None` for any other update.
pub fn chunk(update: &Value) -> Option<(&str, Cow<'_, str>)> {
    let kind = update["sessionUpdate"].as_str()?;
    let text = update["content"]["text"].as_str().unwrap_or_default();
    if kind == MESSAGE
        && let Some(thought) = thinking(text)
    {
        return Some((THOUGHT, Cow::Owned(thought)));
    }
    matches!(kind, MESSAGE | THOUGHT | "user_message_chunk").then_some((kind, Cow::Borrowed(text)))
}

/// The text of TEXT if it is the repr of a thinking chunk.
fn thinking(text: &str) -> Option<String> {
    let text = text.trim();
    if !text.starts_with("{'type': 'thinking'") {
        return None;
    }
    let mut parser = Parser { rest: text };
    let value = parser.value(0)?;
    if !parser.rest.trim_start().is_empty() {
        return None;
    }
    let Literal::Dict(fields) = value else {
        return None;
    };
    let field = |name: &str| fields.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let Some(Literal::List(parts)) = field("thinking") else {
        return None;
    };
    let mut out = String::new();
    for part in parts {
        let Literal::Dict(part) = part else {
            return None;
        };
        if let Some((_, Literal::Str(t))) = part.iter().find(|(k, _)| k == "text") {
            out.push_str(t);
        }
    }
    Some(out)
}

/// A Python literal, as far as a repr of the chunk has them.
enum Literal {
    Str(String),
    List(Vec<Literal>),
    Dict(Vec<(String, Literal)>),
    /// True, False, None or a number.
    Other,
}

struct Parser<'a> {
    rest: &'a str,
}

impl Parser<'_> {
    fn skip_space(&mut self) {
        self.rest = self.rest.trim_start();
    }

    fn eat(&mut self, token: char) -> bool {
        self.skip_space();
        match self.rest.strip_prefix(token) {
            Some(rest) => {
                self.rest = rest;
                true
            }
            None => false,
        }
    }

    fn value(&mut self, depth: usize) -> Option<Literal> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.skip_space();
        match self.rest.chars().next()? {
            '{' => self.dict(depth),
            '[' => self.list(depth),
            '\'' | '"' => self.string().map(Literal::Str),
            _ => {
                let end = self
                    .rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || "+-.".contains(c)))
                    .unwrap_or(self.rest.len());
                let word = &self.rest[..end];
                let known = matches!(word, "True" | "False" | "None")
                    || (!word.is_empty() && word.parse::<f64>().is_ok());
                self.rest = &self.rest[end..];
                known.then_some(Literal::Other)
            }
        }
    }

    fn list(&mut self, depth: usize) -> Option<Literal> {
        self.eat('[');
        let mut items = Vec::new();
        if self.eat(']') {
            return Some(Literal::List(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            if self.eat(']') {
                return Some(Literal::List(items));
            }
            if !self.eat(',') {
                return None;
            }
        }
    }

    fn dict(&mut self, depth: usize) -> Option<Literal> {
        self.eat('{');
        let mut fields = Vec::new();
        if self.eat('}') {
            return Some(Literal::Dict(fields));
        }
        loop {
            self.skip_space();
            let key = self.string()?;
            if !self.eat(':') {
                return None;
            }
            fields.push((key, self.value(depth + 1)?));
            if self.eat('}') {
                return Some(Literal::Dict(fields));
            }
            if !self.eat(',') {
                return None;
            }
        }
    }

    /// A string literal as Python's repr writes one.
    fn string(&mut self) -> Option<String> {
        let mut chars = self.rest.char_indices();
        let (_, quote) = chars.next().filter(|(_, q)| matches!(q, '\'' | '"'))?;
        let mut out = String::new();
        while let Some((i, c)) = chars.next() {
            match c {
                c if c == quote => {
                    self.rest = &self.rest[i + c.len_utf8()..];
                    return Some(out);
                }
                '\\' => {
                    let (_, escaped) = chars.next()?;
                    let mut hex = |n: usize| {
                        let digits: String = (0..n)
                            .filter_map(|_| chars.next().map(|(_, c)| c))
                            .collect();
                        u32::from_str_radix(&digits, 16)
                            .ok()
                            .and_then(char::from_u32)
                    };
                    out.push(match escaped {
                        '\\' | '\'' | '"' => escaped,
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        'x' => hex(2)?,
                        'u' => hex(4)?,
                        'U' => hex(8)?,
                        _ => return None,
                    });
                }
                c => out.push(c),
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn thinking_chunks() {
        let cases = [
            (
                r"{'type': 'thinking', 'thinking': [{'type': 'text', 'text': 'Let'}], 'closed': True}",
                Some("Let"),
            ),
            (
                r#"{'type': 'thinking', 'thinking': [{'type': 'text', 'text': " me see what's"}, {'type': 'text', 'text': ' there:\n\t\\ \x07 é \U0001f600'}], 'closed': False}"#,
                Some(" me see what's there:\n\t\\ \u{7} é 😀"),
            ),
            (
                "{'type': 'thinking', 'thinking': [], 'closed': None, 'n': -1.5}",
                Some(""),
            ),
            // Not that shape: a message that only starts like one, one
            // with more after it, and one that is no literal.
            ("{'type': 'thinking' is how Vibe says it", None),
            ("{'type': 'thinking', 'thinking': []} and then", None),
            ("{'type': 'thinking', 'thinking': 'text'}", None),
            ("{'type': 'thinking', 'thinking': [{'text': '\\q'}]}", None),
            ("{'type': 'thinking', 'thinking': [{'text': 'open", None),
            ("Just text.", None),
        ];
        for (text, want) in cases {
            assert_eq!(thinking(text).as_deref(), want, "{text}");
        }
        let deep = format!(
            "{{'type': 'thinking', 'x': {}{}}}",
            "[".repeat(50),
            "]".repeat(50)
        );
        assert_eq!(thinking(&deep), None);
    }

    #[test]
    fn chunks() {
        let message = |text: &str| json!({"sessionUpdate": MESSAGE, "content": {"type": "text", "text": text}});
        let thought =
            r"{'type': 'thinking', 'thinking': [{'type': 'text', 'text': 'Hmm'}], 'closed': True}";
        assert_eq!(
            chunk(&message(thought)),
            Some((THOUGHT, Cow::Owned("Hmm".to_owned())))
        );
        assert_eq!(chunk(&message("Done.")), Some((MESSAGE, "Done.".into())));
        assert_eq!(
            chunk(&json!({"sessionUpdate": THOUGHT, "content": {"text": thought}})),
            Some((THOUGHT, thought.into()))
        );
        assert_eq!(chunk(&json!({"sessionUpdate": "plan"})), None);
    }
}
