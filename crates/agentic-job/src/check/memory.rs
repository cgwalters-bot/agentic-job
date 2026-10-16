//! The agent's memory (#119) is notes in flat text files, which a later
//! run will be given back. So nothing of it may be a path, a link, a
//! script or text that hides what it says behind control characters, and
//! all of it stays small. `run` packs `~/memory/` into this file and
//! holds it to the same check before it hands it back.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use anyhow::{Result, anyhow, ensure};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::error::Category;

use crate::policy::Memory as Rules;

pub const MEMORY_FILE: &str = "memory.json";

/// What JSON may make of the contents: at most six bytes a character, as
/// `\u0067`, where `run` writes two at most (a quote, a newline). Each
/// file adds its name and punctuation, and the whole a little more.
const JSON_GROWTH: u64 = 6;
const JSON_PER_FILE: u64 = 64 + 8;
const JSON_OVERHEAD: u64 = 4 << 10;

/// Without the name, which a JSON escape may have hidden from the scan.
const GIVEN_TWICE: &str = "a memory file name is given twice";

static NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$").expect("a valid pattern"));

/// `memory.json`: every file of the directory by name, an empty map for
/// an empty directory.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryFiles {
    #[serde(deserialize_with = "unique")]
    pub files: BTreeMap<String, String>,
}

/// A map in which no name is given twice: JSON parsers keep one or the
/// other, so what is checked here and what is stored could differ.
fn unique<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map of file names to text")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut files = BTreeMap::new();
            while let Some((name, text)) = map.next_entry::<String, String>()? {
                if files.contains_key(&name) {
                    return Err(serde::de::Error::custom(GIVEN_TWICE));
                }
                files.insert(name, text);
            }
            Ok(files)
        }
    }

    deserializer.deserialize_map(Visitor)
}

/// What the report says of it: counts, never the contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryInfo {
    pub files: usize,
    pub bytes: u64,
}

/// The most `memory.json` may hold under RULES.
pub fn max_json_bytes(rules: &Rules) -> u64 {
    rules.max_bytes * JSON_GROWTH + u64::from(rules.max_files) * JSON_PER_FILE + JSON_OVERHEAD
}

/// Whether NAME may name a memory file under RULES: flat, not hidden, not
/// an option, and with one of the extensions as written (`.MD` is not).
pub fn check_name(name: &str, rules: &Rules) -> Result<()> {
    ensure!(
        NAME_RE.is_match(name) && !name.contains(".."),
        "memory file name {name:?} is not a plain file name"
    );
    let extension = name.rsplit_once('.').map(|(_, extension)| extension);
    ensure!(
        extension.is_some_and(|extension| rules.extensions.iter().any(|ok| ok == extension)),
        "memory file {name:?} has none of the extensions {}",
        rules.extensions.join(", ")
    );
    Ok(())
}

pub fn check(content: &[u8], rules: &Rules) -> Result<MemoryInfo> {
    // Serde quotes the value it refuses, decoded, where `check` scanned the
    // escaped bytes: say where the file is wrong, never what it holds. Its
    // other errors are fixed text.
    let memory: MemoryFiles =
        serde_json::from_slice(content).map_err(|err| match err.classify() {
            Category::Data if !err.to_string().starts_with(GIVEN_TWICE) => anyhow!(
                "{MEMORY_FILE} is not a map of file names to text, at line {} column {}",
                err.line(),
                err.column()
            ),
            _ => err.into(),
        })?;
    ensure!(
        memory.files.len() <= rules.max_files as usize,
        "{} memory files, over {}",
        memory.files.len(),
        rules.max_files
    );
    let mut bytes = 0;
    for (name, text) in &memory.files {
        // `check` scans the file as it is, where `\u0067hp_` hides `ghp_`
        // from it; a later run is given the names and the text, decoded.
        // First, and without the name, which the reasons below quote.
        ensure!(
            !crate::redact::is_secret_shaped(name.as_bytes())
                && !crate::redact::is_secret_shaped(text.as_bytes()),
            "a memory file holds a secret-shaped string"
        );
        check_name(name, rules)?;
        let size = text.len() as u64;
        ensure!(
            size <= rules.max_file_bytes,
            "memory file {name:?} is {size} bytes, over {}",
            rules.max_file_bytes
        );
        // Text a reader sees as it is: no terminal escapes, no NUL.
        ensure!(
            !text
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')),
            "memory file {name:?} holds a control character"
        );
        bytes += size;
    }
    ensure!(
        bytes <= rules.max_bytes,
        "memory is {bytes} bytes, over {}",
        rules.max_bytes
    );
    Ok(MemoryInfo {
        files: memory.files.len(),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rules() -> Rules {
        Rules {
            max_files: 2,
            max_file_bytes: 10,
            max_bytes: 15,
            extensions: vec!["md".into(), "txt".into()],
        }
    }

    #[test]
    fn what_memory_is_accepted() {
        let files = |names: &[(&str, &str)]| json!({"files": names.iter().copied().collect::<BTreeMap<_, _>>()});
        // (the case, memory.json, the files and bytes, or what refuses it)
        type Case<'a> = (&'a str, serde_json::Value, Result<(usize, u64), &'a str>);
        let cases: &[Case] = &[
            (
                "two files",
                files(&[("notes.md", "a\nb\tc\r\n"), ("log.txt", "x")]),
                Ok((2, 8)),
            ),
            ("empty", json!({"files": {}}), Ok((0, 0))),
            (
                "an unknown field",
                json!({"files": {}, "branch": "x"}),
                Err("not a map of file names to text, at line 1 column 20"),
            ),
            (
                "not an object",
                json!(["notes.md"]),
                Err("not a map of file names"),
            ),
            (
                "not text",
                json!({"files": {"a.md": 1}}),
                Err("not a map of file names"),
            ),
            ("not JSON", json!("{"), Err("not a map of file names")),
            (
                "a path",
                files(&[("a/b.md", "")]),
                Err("not a plain file name"),
            ),
            ("dots", files(&[("..md", "")]), Err("not a plain file name")),
            (
                "hidden",
                files(&[(".notes.md", "")]),
                Err("not a plain file name"),
            ),
            (
                "an option",
                files(&[("-n.md", "")]),
                Err("not a plain file name"),
            ),
            (
                "65 characters",
                files(&[(&format!("{}.md", "a".repeat(62)), "")]),
                Err("not a plain file name"),
            ),
            (
                "64 characters",
                files(&[(&format!("{}.md", "a".repeat(61)), "")]),
                Ok((1, 0)),
            ),
            (
                "an upper-case extension",
                files(&[("notes.MD", "")]),
                Err("none of the extensions"),
            ),
            (
                "a script",
                files(&[("run.sh", "")]),
                Err("none of the extensions"),
            ),
            (
                "no extension",
                files(&[("notes", "")]),
                Err("none of the extensions"),
            ),
            (
                "one file too many",
                files(&[("a.md", ""), ("b.md", ""), ("c.md", "")]),
                Err("3 memory files, over 2"),
            ),
            (
                "a file too big",
                files(&[("a.md", "12345678901")]),
                Err("11 bytes, over 10"),
            ),
            (
                "too much in all",
                files(&[("a.md", "1234567890"), ("b.md", "123456")]),
                Err("memory is 16 bytes, over 15"),
            ),
            ("NUL", files(&[("a.md", "a\0b")]), Err("control character")),
            (
                "an escape",
                files(&[("a.md", "\u{1b}[2J")]),
                Err("control character"),
            ),
        ];
        let escaped = format!(
            r#"{{"files": {{"a.md": "\u0067hp_{}"}}}}"#,
            "a1B2".repeat(9)
        );
        assert!(!crate::redact::is_secret_shaped(escaped.as_bytes()));
        let roomy = Rules {
            max_file_bytes: 100,
            max_bytes: 100,
            ..rules()
        };
        let err = check(escaped.as_bytes(), &roomy).unwrap_err();
        assert!(format!("{err:#}").contains("secret-shaped"), "{err:#}");
        let name = format!(r#"{{"files": {{"\u0067hp_{}": ""}}}}"#, "a1B2".repeat(9));
        let err = check(name.as_bytes(), &roomy).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "a memory file holds a secret-shaped string"
        );
        let twice = br#"{"files": {"a.md": "1", "a.md": "2"}}"#;
        let err = check(twice, &rules()).unwrap_err();
        assert!(format!("{err:#}").contains("given twice"), "{err:#}");
        // Refused before the secret check, by Serde, which quotes the
        // decoded value: no reason may repeat it.
        let secret = format!(r"\u0067hp_{}", "a1B2".repeat(9));
        for malformed in [
            format!(r#"{{"files": "{secret}"}}"#),
            format!(r#"{{"files": {{}}, "{secret}": 1}}"#),
            format!(r#"{{"files": {{"{secret}": "", "{secret}": ""}}}}"#),
            format!(r#"{{"files": {{"a.md": ["{secret}"]}}}}"#),
        ] {
            assert!(!crate::redact::is_secret_shaped(malformed.as_bytes()));
            let err = format!("{:#}", check(malformed.as_bytes(), &roomy).unwrap_err());
            assert!(!err.contains("hp_"), "{malformed}: {err}");
        }
        for (name, memory, want) in cases {
            let got = check(memory.to_string().as_bytes(), &rules());
            match (got, want) {
                (Ok(info), Ok((files, bytes))) => {
                    assert_eq!((info.files, info.bytes), (*files, *bytes), "{name}");
                }
                (Err(err), Err(want)) => {
                    assert!(format!("{err:#}").contains(want), "{name}: {err:#}");
                }
                (got, _) => panic!("{name}: {got:?}"),
            }
        }
    }
}
