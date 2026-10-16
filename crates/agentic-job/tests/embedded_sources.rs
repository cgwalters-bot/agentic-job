//! Nothing is built in from outside what a release's source digest covers
//! (`BUILT_FROM` in secure-host/binary.mjs): a file included from anywhere
//! else could change the binary without changing the digest callers verify.
//!
//! Every `include!`, `include_str!` and `include_bytes!` under `crates/` is
//! found by its tokens, not its lines, so a call rustfmt wrapped or one in
//! an attribute is still seen, and one in a comment or string is not. Its
//! argument must be one plain string literal: a path built by `concat!`,
//! `env!` or a macro's variable cannot be resolved here, so it is refused.
#![allow(clippy::unwrap_used)]

use std::path::{Component, Path, PathBuf};

/// What the digest covers that the build may include, from the root.
const INCLUDABLE_DIRS: &[&str] = &["crates", "egress", "skills"];
const INCLUDABLE_FILES: &[&str] = &["workflow/review.md"];
const INCLUDE_MACROS: &[&str] = &["include", "include_str", "include_bytes"];

#[derive(Debug, PartialEq)]
enum Token {
    Ident(String),
    Punct(char),
    /// A string literal's text, `None` for one with escapes or a prefix
    /// (`b`, `c`): no path this check admits needs either.
    Str(Option<String>),
    Other,
}

fn is_ident(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// Enough of Rust's lexer to tell code from comments, strings and
/// character literals. It never fails: an unterminated item ends the file.
fn tokens(source: &str) -> Vec<Token> {
    let s: Vec<char> = source.chars().collect();
    let at = |i: usize| s.get(i).copied();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(c) = at(i) {
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && at(i + 1) == Some('/') {
            while at(i).is_some_and(|c| c != '\n') {
                i += 1;
            }
        } else if c == '/' && at(i + 1) == Some('*') {
            let mut depth = 0;
            while i < s.len() {
                if at(i) == Some('/') && at(i + 1) == Some('*') {
                    depth += 1;
                    i += 2;
                } else if at(i) == Some('*') && at(i + 1) == Some('/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if c == '"' {
            let (text, end) = quoted(&s, i + 1);
            out.push(Token::Str(text));
            i = end;
        } else if c == '\'' {
            // A character literal, or a lifetime or label.
            if at(i + 1) == Some('\\') {
                // Past the escaped character, which may be a quote.
                i += 3;
                while at(i).is_some_and(|c| c != '\'') {
                    i += 1;
                }
                i += 1;
                out.push(Token::Other);
            } else if at(i + 2) == Some('\'') {
                i += 3;
                out.push(Token::Other);
            } else {
                i += 1;
                while at(i).is_some_and(is_ident) {
                    i += 1;
                }
                out.push(Token::Other);
            }
        } else if is_ident(c) {
            let start = i;
            while at(i).is_some_and(is_ident) {
                i += 1;
            }
            let word: String = s[start..i].iter().collect();
            let hashes = s[i..].iter().take_while(|&&c| c == '#').count();
            match (word.as_str(), at(i), at(i + hashes)) {
                ("r" | "br" | "cr", _, Some('"')) => {
                    let close: Vec<char> = std::iter::once('"')
                        .chain(std::iter::repeat_n('#', hashes))
                        .collect();
                    let body = i + hashes + 1;
                    let end = s[body..]
                        .windows(close.len())
                        .position(|w| w == close.as_slice())
                        .map_or(s.len(), |p| body + p);
                    let text = (word == "r").then(|| s[body..end].iter().collect());
                    out.push(Token::Str(text));
                    i = (end + close.len()).min(s.len());
                }
                ("b" | "c", Some('"'), _) => {
                    out.push(Token::Str(None));
                    i = quoted(&s, i + 1).1;
                }
                ("b", Some('\''), _) => {
                    out.push(Token::Other);
                    i += 1;
                    while at(i).is_some_and(|c| c != '\'') {
                        i += if at(i) == Some('\\') { 2 } else { 1 };
                    }
                    i += 1;
                }
                // A raw identifier, `r#include_str`, names the macro too.
                ("r", Some('#'), _) if at(i + 1).is_some_and(is_ident) => {
                    let start = i + 1;
                    i = start;
                    while at(i).is_some_and(is_ident) {
                        i += 1;
                    }
                    out.push(Token::Ident(s[start..i].iter().collect()));
                }
                _ => out.push(Token::Ident(word)),
            }
        } else {
            out.push(Token::Punct(c));
            i += 1;
        }
    }
    out
}

/// The text of the string literal whose body starts at `start`, `None`
/// if it has an escape, and the index just past its closing quote.
fn quoted(s: &[char], start: usize) -> (Option<String>, usize) {
    let mut i = start;
    let mut escaped = false;
    while let Some(&c) = s.get(i) {
        match c {
            '\\' => {
                escaped = true;
                i += 2;
            }
            '"' => break,
            _ => i += 1,
        }
    }
    let end = i.min(s.len());
    let text = (!escaped).then(|| s[start..end].iter().collect());
    (text, (i + 1).min(s.len()))
}

/// The path of each include in SOURCE, or why one cannot be resolved.
fn includes(source: &str) -> Vec<Result<String, String>> {
    let tokens = tokens(source);
    let mut found = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let Token::Ident(name) = token else { continue };
        if !INCLUDE_MACROS.contains(&name.as_str()) || tokens.get(i + 1) != Some(&Token::Punct('!'))
        {
            continue;
        }
        let close = match tokens.get(i + 2) {
            Some(Token::Punct('(')) => ')',
            Some(Token::Punct('[')) => ']',
            Some(Token::Punct('{')) => '}',
            _ => {
                found.push(Err(format!("{name}! without arguments")));
                continue;
            }
        };
        let rest = &tokens[(i + 3).min(tokens.len())..];
        let close = Token::Punct(close);
        found.push(match rest {
            [Token::Str(Some(path)), next, ..]
                if *next == close
                    || (*next == Token::Punct(',') && rest.get(2) == Some(&close)) =>
            {
                // Only `.rs` files are scanned, so what `include!` compiles
                // must be one, or its own includes would go unchecked.
                if name == "include" && !path.ends_with(".rs") {
                    Err(format!("include! of {path:?}, not a .rs file"))
                } else {
                    Ok(path.clone())
                }
            }
            _ => Err(format!("{name}! of something but one plain string literal")),
        });
    }
    found
}

/// Refuses PATH, included from a file in DIR (both from the root), unless
/// it stays in what the digest covers.
fn admit(dir: &Path, path: &str) -> Result<(), String> {
    let mut resolved = PathBuf::new();
    for part in dir.join(path).components() {
        match part {
            Component::Normal(part) => resolved.push(part),
            Component::CurDir => {}
            Component::ParentDir if resolved.pop() => {}
            _ => return Err(format!("{path:?} leaves the repository")),
        }
    }
    let covered = INCLUDABLE_DIRS.iter().any(|d| resolved.starts_with(d))
        || INCLUDABLE_FILES.iter().any(|f| resolved == Path::new(f));
    covered
        .then_some(())
        .ok_or_else(|| format!("{path:?} is {resolved:?}, outside what the digest covers"))
}

/// Every refusal for SOURCE, a file at FILE from the root.
fn refusals(file: &Path, source: &str) -> Vec<String> {
    let dir = file.parent().unwrap();
    includes(source)
        .into_iter()
        .filter_map(|found| found.and_then(|path| admit(dir, &path)).err())
        .map(|why| format!("{}: {why}", file.display()))
        .collect()
}

/// The `.rs` files under DIR, without following symbolic links.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let path = entry.path();
        if kind.is_dir() {
            rust_files(&path, out);
        } else if kind.is_file() && path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn nothing_is_built_in_from_outside_the_digest() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    let mut refused = Vec::new();
    let mut seen = 0;
    for file in &files {
        let source = std::fs::read_to_string(file).unwrap();
        let file = file.strip_prefix(&root).unwrap();
        seen += includes(&source).len();
        refused.extend(refusals(file, &source));
    }
    // The walk found this crate's includes, so a broken walk cannot pass.
    assert!(seen >= 10, "only {seen} includes found");
    assert!(refused.is_empty(), "{refused:#?}");
}

#[test]
fn includes_are_found_by_tokens_and_resolved() {
    let file = Path::new("crates/x.rs");
    for (source, refused) in [
        (
            r#"const A: &str = include_str!("../skills/a/SKILL.md");"#,
            false,
        ),
        (
            r#"const A: &str = include_str!("../workflow/review.md");"#,
            false,
        ),
        (
            r#"const A: &[u8] = include_bytes!("../egress/policy.toml",);"#,
            false,
        ),
        (r#"const A: &str = include_str!("agents.toml");"#, false),
        (r#"const A: &str = include_str!(r"../egress/x");"#, false),
        (r#"const A: &str = include_str!("../README.md");"#, true),
        (r#"const A: &str = include_str!("../workflow/x.md");"#, true),
        (r#"const A: &str = include_str!("../../outside");"#, true),
        (r#"const A: &str = include_str!("/etc/passwd");"#, true),
        (
            r#"const A: &str = include_str!("../skills/../README.md");"#,
            true,
        ),
        (r#"const A: &str = include_str!("\x2e./README.md");"#, true),
        // Built by concat!, so not resolvable here, even when it would pass.
        (
            r#"const A: &str = include_str!(concat!("../", "README.md"));"#,
            true,
        ),
        (
            r#"const A: &str = include_str!(concat!("../", "egress/x"));"#,
            true,
        ),
        (r#"const A: &str = include_str!(env!("X"));"#, true),
        ("macro_rules! m { ($p:expr) => { include_str!($p) } }", true),
        // Wrapped by rustfmt, with spaces, other delimiters or a path.
        (
            "const A: &str =\n    include_str!(\n        \"../README.md\"\n    );",
            true,
        ),
        (r#"const A: &str = include_str !  ["../README.md"];"#, true),
        (
            r#"const A: &str = std::include_str!{"../README.md"};"#,
            true,
        ),
        (r#"const A: &str = r#include_str!("../README.md");"#, true),
        (r#"#[doc = include_str!("../README.md")] struct S;"#, true),
        (r#"include!("../build/x.rs");"#, true),
        (r#"include!("gen.rs");"#, false),
        (r#"include!("gen.in");"#, true),
        (
            r#"const Q: [char; 2] = ['\'', '"']; include!("../x");"#,
            true,
        ),
        // Not code: comments, strings and character literals.
        (r#"// include_str!("../README.md")"#, false),
        (r#"/* /* */ include_str!("../README.md") */"#, false),
        (
            r#"const A: &str = "include_str!(\"../README.md\")";"#,
            false,
        ),
        (
            r##"const A: &str = r#"include_str!("../README.md")"#;"##,
            false,
        ),
        (r#"const Q: char = '"'; const B: &str = "x";"#, false),
        (r#"fn f<'a>(x: &'a str) {} const B: &str = "'";"#, false),
        (r#"fn include() {} fn g() { include(); }"#, false),
    ] {
        let found = refusals(file, source);
        assert_eq!(!found.is_empty(), refused, "{source}: {found:?}");
    }
}
