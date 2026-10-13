//! A workflow file as data. The parser's events are read one at a time
//! into a [`Value`], not through its loader, which recurses once per level
//! of nesting and copies an alias's node however often it is used: a file
//! of a few kilobytes could otherwise exhaust the stack or the memory.
//! Here nesting is capped and anchors, aliases and tags are refused.

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value};
use yaml_rust2::parser::{Event, Parser};
use yaml_rust2::scanner::{Scanner, TScalarStyle, TokenType};

/// Far more than a workflow needs; jobs, steps and `with` are four deep.
const MAX_DEPTH: usize = 64;

/// Scalars, sequences and mappings in one file, and the bytes of their
/// text, keys included. The text of a file is at most 1 MiB.
const MAX_NODES: usize = 100_000;
const MAX_BYTES: usize = 8 << 20;

/// What a tree holds: nodes, and bytes of text.
#[derive(Debug, Clone, Copy, Default)]
struct Size {
    nodes: usize,
    bytes: usize,
}

impl Size {
    fn add(&mut self, nodes: usize, bytes: usize) {
        self.nodes = self.nodes.saturating_add(nodes);
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

/// A sequence or mapping still being read.
enum Open {
    Sequence(Vec<Value>),
    Mapping(Map<String, Value>, Option<String>),
}

/// A plain scalar's value as YAML's core schema reads it, as far as these
/// checks care: null and booleans; everything else, numbers too, is text.
fn scalar(text: String, style: TScalarStyle) -> Value {
    if style != TScalarStyle::Plain {
        return Value::String(text);
    }
    match text.as_str() {
        "" | "~" | "null" | "Null" | "NULL" => Value::Null,
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        _ => Value::String(text),
    }
}

/// The one document in `text`. Mapping keys are scalars, each once in
/// its mapping, as GitHub requires.
pub fn parse(text: &str) -> Result<Value> {
    // Inspect tokens before the parser resolves aliases (including unknown ones).
    for token in Scanner::new(text.chars()) {
        let feature = match token.1 {
            TokenType::Anchor(_) => "anchors",
            TokenType::Alias(_) => "aliases",
            TokenType::Tag(..) => "tags",
            _ => continue,
        };
        bail!(
            "at line {}: YAML {feature} are not supported",
            token.0.line()
        );
    }
    let mut parser = Parser::new_from_str(text);
    let mut open: Vec<Open> = Vec::new();
    let mut read = Size::default();
    let mut documents = 0usize;
    let mut root = None;
    loop {
        let (event, mark) = parser.next_token().map_err(anyhow::Error::new)?;
        let at = || format!("at line {}", mark.line());
        match &event {
            Event::Alias(_) => bail!("{}: YAML aliases are not supported", at()),
            Event::Scalar(_, _, anchor, tag)
            | Event::SequenceStart(anchor, tag)
            | Event::MappingStart(anchor, tag) => {
                ensure!(*anchor == 0, "{}: YAML anchors are not supported", at());
                ensure!(tag.is_none(), "{}: YAML tags are not supported", at());
            }
            _ => {}
        }
        // A key of the innermost open mapping is its text, not a node.
        if let Some(Open::Mapping(_, key @ None, ..)) = open.last_mut() {
            match event {
                Event::Scalar(text, style, ..) => {
                    ensure!(text != "<<", "{}: YAML merge keys are not supported", at());
                    ensure!(
                        style != TScalarStyle::Plain
                            || matches!(
                                yaml_rust2::Yaml::from_str(&text),
                                yaml_rust2::Yaml::String(_)
                            ),
                        "{}: non-string mapping keys are not supported",
                        at()
                    );
                    read.add(0, text.len());
                    *key = Some(text);
                    continue;
                }
                Event::MappingEnd => {}
                _ => bail!("{}: a mapping key is not a plain value", at()),
            }
        }
        let value = match event {
            Event::Nothing | Event::StreamStart | Event::DocumentEnd => continue,
            Event::StreamEnd => break,
            Event::DocumentStart => {
                documents += 1;
                ensure!(documents == 1, "{}: a second YAML document", at());
                continue;
            }
            Event::Alias(_) => unreachable!("aliases refused above"),
            Event::Scalar(text, style, ..) => {
                let size = Size {
                    nodes: 1,
                    bytes: text.len(),
                };
                read.add(size.nodes, size.bytes);
                scalar(text, style)
            }
            Event::SequenceStart(..) | Event::MappingStart(..) => {
                ensure!(
                    open.len() < MAX_DEPTH,
                    "{}: nested over {MAX_DEPTH} deep",
                    at()
                );
                open.push(if matches!(event, Event::SequenceStart(..)) {
                    Open::Sequence(Vec::new())
                } else {
                    Open::Mapping(Map::new(), None)
                });
                read.add(1, 0);
                continue;
            }
            Event::SequenceEnd | Event::MappingEnd => match open.pop() {
                Some(Open::Sequence(items)) => Value::Array(items),
                Some(Open::Mapping(map, None)) => Value::Object(map),
                _ => bail!("{}: an unbalanced end of a collection", at()),
            },
        };
        ensure!(
            read.nodes <= MAX_NODES && read.bytes <= MAX_BYTES,
            "{}: over {MAX_NODES} nodes or {MAX_BYTES} bytes of text",
            at()
        );
        match open.last_mut() {
            None => root = Some(value),
            Some(Open::Sequence(items, ..)) => items.push(value),
            Some(Open::Mapping(map, key, ..)) => {
                let key = key.take().context("a mapping value without a key")?;
                ensure!(
                    !map.contains_key(&key),
                    "{}: the key {key:?} twice in one mapping",
                    at()
                );
                map.insert(key, value);
            }
        }
    }
    root.context("no YAML document")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn documents_read_as_github_reads_them() {
        let cases: &[(&str, Value)] = &[
            (
                "on: push\njobs:\n  a: {x: 1, y: 'false', z: false, n: ~}\n",
                json!({"on": "push", "jobs": {"a": {"x": "1", "y": "false", "z": false, "n": null}}}),
            ),
            ("- 'true'\n- |\n  x\n", json!(["true", "x\n"])),
        ];
        for (text, want) in cases {
            assert_eq!(&parse(text).unwrap(), want, "{text}");
        }
    }

    #[test]
    fn hostile_documents_are_refused() {
        let composed = format!(
            "a0: &a0 x\na1: &a1 {}*a0{}\na2: &a2 {}*a1{}\n",
            "[".repeat(62),
            "]".repeat(62),
            "[".repeat(62),
            "]".repeat(62),
        );
        let many = format!("[{}]", "x,".repeat(MAX_NODES));
        let long = "x".repeat(MAX_BYTES + 1);
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        let block_deep: String = (0..100).map(|i| format!("{}k:\n", " ".repeat(i))).collect();
        let cases: &[(&str, &str)] = &[
            (&composed, "anchors"),
            (&many, "nodes"),
            (&long, "bytes"),
            ("a: &p value\n", "at line 1: YAML anchors"),
            ("a: *p\n", "at line 1: YAML aliases"),
            ("{12: value}\n", "non-string"),
            ("a: {<<: {b: c}}\n", "at line 1: YAML merge keys"),
            ("a: !!str true\n", "at line 1: YAML tags"),
            ("{true: value}\n", "non-string"),
            (&deep, "nested"),
            (&block_deep, "nested"),
            ("a: 1\na: 2\n", "twice"),
            ("{[a]: 1}\n", "key"),
            ("a: 1\n---\nb: 2\n", "second"),
            ("a: *nowhere\n", ""),
            ("a: [\n", ""),
            ("", "no YAML document"),
        ];
        for (text, want) in cases {
            let err = format!("{:#}", parse(text).unwrap_err());
            assert!(err.contains(want), "{text:.40}: {err}");
        }
    }
}
