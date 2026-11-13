//! Bounded Markdown documents, independent of the caller's topic or repository.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::collect::sanitize::sanitize;

pub const TYPE: &str = "document";
pub const MAX_BYTES: usize = 46_000;
pub const MAX_FILES: usize = 10;
pub const MAX_SUMMARY_LINE: usize = 200;

/// Trusted authority for gist updates and visibility. Secret gists are not private.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default)]
    pub public: bool,
    #[serde(default)]
    pub gist_ids: Vec<String>,
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.gist_ids.len() <= 100, "document: at most 100 gist IDs");
        ensure!(
            self.gist_ids.iter().all(|id| is_id(id)),
            "document: invalid gist ID"
        );
        Ok(())
    }
}

pub fn is_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    #[serde(rename = "type")]
    kind: String,
    pub title: String,
    pub files: BTreeMap<String, String>,
    pub summary: [String; 3],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gist_id: Option<String>,
}

impl Document {
    pub fn parse(item: &Map<String, Value>) -> Result<Self> {
        let document: Self = serde_json::from_value(Value::Object(item.clone())).context(
            "document: expected title, Markdown files, three summary lines and optional gist_id",
        )?;
        ensure!(document.kind == TYPE, "document: invalid type");
        ensure!(
            !document.title.trim().is_empty()
                && document.title.len() <= 128
                && !document.title.chars().any(char::is_control),
            "document: title must be 1–128 bytes without controls"
        );
        ensure!(
            !document.files.is_empty() && document.files.len() <= MAX_FILES,
            "document: requires 1–{MAX_FILES} Markdown files"
        );
        let mut bytes = document.title.len();
        for (name, content) in &document.files {
            ensure!(
                name.len() <= 128
                    && name.ends_with(".md")
                    && name.len() > 3
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                    && !name.starts_with('.'),
                "document: invalid Markdown filename"
            );
            ensure!(!content.trim().is_empty(), "document: empty file");
            bytes += name.len() + content.len();
        }
        for line in &document.summary {
            ensure!(
                !line.trim().is_empty()
                    && line.len() <= MAX_SUMMARY_LINE
                    && !line.chars().any(char::is_control),
                "document: summary requires three nonempty lines of at most {MAX_SUMMARY_LINE} bytes"
            );
            bytes += line.len();
        }
        ensure!(
            bytes <= MAX_BYTES,
            "document: content exceeds {MAX_BYTES} bytes"
        );
        ensure!(
            document.gist_id.as_deref().is_none_or(is_id),
            "document: invalid gist_id"
        );
        // Scan before sanitizing: removing controls must not conceal a key.
        let text = serde_json::to_string(item)?;
        let private_key = ["PRIVATE", "KEY-----"].join(" ");
        ensure!(
            !text.contains(&private_key),
            "document: private key refused"
        );
        Ok(document)
    }

    pub fn authorize(&self, settings: &Settings) -> Result<()> {
        settings.validate()?;
        ensure!(
            self.gist_id
                .as_ref()
                .is_none_or(|id| settings.gist_ids.contains(id)),
            "document: gist_id is not allowed by caller policy"
        );
        Ok(())
    }
}

/// Reuse comment sanitization, including its URL policy, for every text field.
pub fn collect(
    item: &Map<String, Value>,
    keeps_link: &dyn Fn(&str) -> bool,
) -> Result<Map<String, Value>> {
    let mut document = Document::parse(item)?;
    let clean = |text: &str| sanitize(text, MAX_BYTES, true, keeps_link);
    document.title = clean(&document.title);
    for content in document.files.values_mut() {
        *content = clean(content);
    }
    for line in &mut document.summary {
        *line = clean(line);
    }
    let value = serde_json::to_value(document)?;
    let map = value.as_object().context("document object")?.clone();
    Document::parse(&map)?;
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn request() -> Map<String, Value> {
        json!({"type": "document", "title": "Findings", "files": {"findings.md": "# Findings\n\nEvidence."}, "summary": ["Added evidence.", "Corrected a claim.", "Recorded open questions."]}).as_object().unwrap().clone()
    }

    #[test]
    fn document_create_update_and_authority() {
        let mut item = request();
        Document::parse(&item)
            .unwrap()
            .authorize(&Settings::default())
            .unwrap();
        item.insert("gist_id".into(), json!("abc123"));
        let document = Document::parse(&item).unwrap();
        assert!(document.authorize(&Settings::default()).is_err());
        document
            .authorize(&Settings {
                gist_ids: vec!["abc123".into()],
                ..Settings::default()
            })
            .unwrap();
    }

    #[test]
    fn document_size_and_secret_refusal() {
        let mut item = request();
        let overhead = Document::parse(&item).unwrap();
        let used = overhead.title.len()
            + "findings.md".len()
            + overhead.summary.iter().map(String::len).sum::<usize>();
        item["files"]["findings.md"] = json!("x".repeat(MAX_BYTES - used));
        assert!(Document::parse(&item).is_ok());
        item["files"]["findings.md"] = json!("x".repeat(MAX_BYTES - used + 1));
        assert!(Document::parse(&item).is_err());
        item["files"]["findings.md"] = json!(["-----BEGIN", "RSA PRIVATE", "KEY-----"].join(" "));
        assert!(
            format!("{:#}", collect(&item, &|_| true).unwrap_err()).contains("private key refused")
        );
    }

    #[test]
    fn document_fields_and_urls() {
        for (key, value) in [
            ("public", json!(true)),
            ("owner", json!("someone")),
            ("files", json!({"../notes.md": "text"})),
            ("files", json!({"script.sh": "text"})),
            ("summary", json!(["one", "two"])),
            ("summary", json!(["one\ntwo", "three", "four"])),
            ("gist_id", json!("../abc")),
        ] {
            let mut item = request();
            item.insert(key.into(), value);
            assert!(Document::parse(&item).is_err(), "{key}");
        }
        let mut item = request();
        item["files"]["findings.md"] =
            json!("https://allowed.example/proof https://other.example/proof @someone");
        let clean = collect(&item, &|host| host == "allowed.example").unwrap();
        let content = clean["files"]["findings.md"].as_str().unwrap();
        assert!(content.contains("https://allowed.example/proof"));
        assert!(!content.contains("https://other.example/proof"));
        assert!(content.contains("`@someone`"));
    }
}
