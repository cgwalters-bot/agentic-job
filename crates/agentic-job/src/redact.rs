//! Secret-shaped strings: what `check` refuses in a hand-back, and what
//! `run` replaces in everything it logs or uploads.
//!
//! This is a safety net and not the defence: the agent's environment holds
//! no credential worth leaking beyond its own run token. The patterns are
//! shapes, so they also match strings that only look like a credential.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use regex::bytes::Regex as BytesRegex;

use crate::files::{self, ReadError};

/// What a secret is replaced with.
pub const REPLACEMENT: &str = "[REDACTED]";

/// Shorter literals would redact ordinary words.
const MIN_LITERAL_BYTES: usize = 8;

/// The largest file `redact_tree` rewrites; a bigger one is not a log.
const MAX_REDACTED_BYTES: u64 = 1 << 30;

/// The shapes, in the syntax of the `regex` crate. One list for redacting
/// and for refusing, so that nothing the check refuses is uploaded as it is.
const PATTERNS: &[&str] = &[
    // GitHub: personal, OAuth, server, user and refresh tokens
    r"gh[posur]_[A-Za-z0-9_]{20,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    // Anthropic, then OpenAI and the many that copied its prefix
    r"sk-ant-[A-Za-z0-9_-]{20,}",
    r"sk-[A-Za-z0-9_-]{20,}",
    // Tailscale
    r"tskey-[A-Za-z0-9-]{10,}",
    // praxis-credential-broker's run tokens
    r"praxis-run-[0-9a-f]{64}",
    // JWTs, such as a CI system's identity tokens
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*",
    // A whole PEM block, also when a JSON string holds it with escaped
    // newlines; an unterminated one is cut at the end of the line.
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:(?s:.)*?-----END [A-Z0-9 ]*PRIVATE KEY-----|[^\n]*)",
    // GitLab, AWS key ids, Google API keys, Slack
    r"glpat-[A-Za-z0-9_-]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z_-]{35}",
    r"xox[abprs]-[A-Za-z0-9-]{10,}",
];

fn alternation<S: AsRef<str>>(parts: impl IntoIterator<Item = S>) -> String {
    parts
        .into_iter()
        .map(|part| format!("(?:{})", part.as_ref()))
        .collect::<Vec<_>>()
        .join("|")
}

/// The patterns over bytes: a hand-back need not be UTF-8.
static SECRET_SHAPED: LazyLock<BytesRegex> = LazyLock::new(|| {
    BytesRegex::new(&format!("(?-u){}", alternation(PATTERNS)))
        .expect("the built-in patterns are valid")
});

/// Whether `bytes` holds a string shaped like a credential.
pub fn is_secret_shaped(bytes: &[u8]) -> bool {
    SECRET_SHAPED.is_match(bytes)
}

/// Replaces secrets in text: the literal values it was given, and the
/// patterns. It counts what it replaced, so a caller can tell whether
/// anything was found.
#[derive(Debug)]
pub struct Redactor {
    rule: Regex,
    /// The same rule over bytes, for content that is not text.
    bytes: BytesRegex,
    count: usize,
}

impl Redactor {
    /// A redactor for the patterns and for `literals`, the values of the
    /// credentials the caller itself holds.
    pub fn new<S: AsRef<str>>(literals: impl IntoIterator<Item = S>) -> Result<Self, regex::Error> {
        let literals: BTreeSet<String> = literals
            .into_iter()
            .map(|literal| literal.as_ref().to_owned())
            .filter(|literal| literal.len() >= MIN_LITERAL_BYTES)
            .collect();
        // Longest first: of two literals, one within the other, the whole
        // of the longer is replaced.
        let mut literals: Vec<String> = literals.into_iter().collect();
        literals.sort_by_key(|literal| std::cmp::Reverse(literal.len()));
        let literals: Vec<String> = literals.iter().map(|l| regex::escape(l)).collect();
        let rule = alternation(
            literals
                .iter()
                .map(String::as_str)
                .chain(PATTERNS.iter().copied()),
        );
        Ok(Self {
            bytes: BytesRegex::new(&format!("(?-u){rule}"))?,
            rule: Regex::new(&rule)?,
            count: 0,
        })
    }

    /// Whether `bytes` holds a secret this would replace in text: one of
    /// its literals, or a string shaped like a credential. For what
    /// cannot be redacted, a patch or a file that is not text.
    pub fn finds(&self, bytes: &[u8]) -> bool {
        self.bytes.is_match(bytes)
    }

    /// `text` with every secret replaced by [`REPLACEMENT`].
    pub fn redact<'t>(&mut self, text: &'t str) -> Cow<'t, str> {
        let count = &mut self.count;
        self.rule.replace_all(text, |_: &regex::Captures<'_>| {
            *count += 1;
            REPLACEMENT
        })
    }

    /// How many secrets were replaced so far.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Redacts every UTF-8 text file under `path` in place, and removes
    /// links and anything else that is neither a file nor a directory,
    /// since those could name something outside the tree. Other files are
    /// left as they are.
    ///
    /// The tree must be the caller's own, with nobody else writing to it:
    /// a directory swapped for a link while this runs would be followed.
    pub fn redact_tree(&mut self, path: &Path) -> io::Result<()> {
        let kind = std::fs::symlink_metadata(path)?.file_type();
        if kind.is_dir() {
            for entry in std::fs::read_dir(path)? {
                self.redact_tree(&entry?.path())?;
            }
            return Ok(());
        }
        if !kind.is_file() {
            return std::fs::remove_file(path);
        }
        let content = match files::read_regular(path, MAX_REDACTED_BYTES) {
            Ok(content) => content,
            Err(ReadError::Io(err)) => return Err(err),
            // Became a link since the look above, or is too big to be text
            // this wrote: not something to upload.
            Err(ReadError::NotRegular | ReadError::TooBig { .. }) => {
                return std::fs::remove_file(path);
            }
        };
        let Ok(text) = std::str::from_utf8(&content) else {
            return Ok(());
        };
        match self.redact(text) {
            Cow::Borrowed(_) => Ok(()),
            Cow::Owned(redacted) => files::overwrite_regular(path, redacted.as_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    /// A token of `prefix` and 40 more characters, put together here so
    /// that this file holds no secret-shaped string itself.
    fn token(prefix: &str) -> String {
        format!("{prefix}{}", "a1B2".repeat(10))
    }

    #[test]
    fn shapes() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----";
        let jwt = format!("eyJ{0}.eyJ{0}.sig", "abcdefghij");
        let cases: &[(&str, String, bool)] = &[
            ("a GitHub token", token("ghp_"), true),
            ("a GitHub Actions job token", token("ghs_"), true),
            ("a GitHub refresh token", token("ghr_"), true),
            ("a fine-grained GitHub token", token("github_pat_"), true),
            ("an Anthropic key", token("sk-ant-"), true),
            ("an OpenAI key", token("sk-"), true),
            ("a Tailscale key", token("tskey-"), true),
            (
                "a run token",
                format!("praxis-run-{}", "0f".repeat(32)),
                true,
            ),
            ("a JWT", jwt, true),
            ("a private key", pem.to_owned(), true),
            (
                "a GitLab token",
                format!("glpat-{}", "a1B2".repeat(6)),
                true,
            ),
            ("an AWS key id", format!("AKIA{}", "A1B2".repeat(4)), true),
            ("a Google API key", format!("AIza{}", "a".repeat(35)), true),
            ("a Slack token", "xoxb-1234567890".to_owned(), true),
            (
                "prose",
                "the token ghp_ is short for GitHub personal".to_owned(),
                false,
            ),
            (
                "a short run token",
                format!("praxis-run-{}", "0f".repeat(31)),
                false,
            ),
            ("a commit", "0f".repeat(20), false),
        ];
        let mut redactor = Redactor::new::<&str>([]).unwrap();
        for (name, text, secret) in cases {
            let text = format!("before {text} after");
            assert_eq!(is_secret_shaped(text.as_bytes()), *secret, "{name}");
            let before = redactor.count();
            let redacted = redactor.redact(&text);
            assert_eq!(redactor.count() - before, usize::from(*secret), "{name}");
            if *secret {
                assert_eq!(redacted, format!("before {REPLACEMENT} after"), "{name}");
            }
        }
    }

    /// Build output is left as it is, and a secret in it is still replaced
    /// (#401: the span lost there was gh-aw's URL filtering, not this).
    #[test]
    fn build_output() {
        let job = token("ghs_");
        let registered = "registered-run-secret";
        let metadata = r#"{"packages":[{"name":"agentic-job","version":"0.0.3","id":"path+file:///home/u/agentic-job/crates/agentic-job#0.0.3","license":"MIT OR Apache-2.0","license_file":null}]}"#;
        let cases: &[(&str, String, String)] = &[
            ("cargo metadata", metadata.to_owned(), metadata.to_owned()),
            (
                "the job token in a package id",
                metadata.replace("/home/u", &format!("/{job}")),
                metadata.replace("/home/u", &format!("/{REPLACEMENT}")),
            ),
            (
                "a registered secret in a git URL",
                format!("Updating git repository `https://x:{registered}@example.com/a`"),
                format!("Updating git repository `https://x:{REPLACEMENT}@example.com/a`"),
            ),
        ];
        let mut redactor = Redactor::new([registered]).unwrap();
        for (name, text, want) in cases {
            assert_eq!(redactor.finds(text.as_bytes()), text != want, "{name}");
            assert_eq!(redactor.redact(text), *want, "{name}");
        }
    }

    #[test]
    fn github_job_token_is_redacted_from_public_run_files() {
        let dir = tempfile::tempdir().unwrap();
        let secret = token("ghs_");
        let names = [
            "transcript.jsonl",
            "condensed.log",
            "summary.md",
            "outcome.json",
        ];
        for name in names {
            std::fs::write(dir.path().join(name), format!("before {secret} after\n")).unwrap();
        }

        // Shape redaction must work even without registering the token as
        // a literal: the job token is not an inference registration token.
        let mut redactor = Redactor::new::<&str>([]).unwrap();
        assert!(redactor.finds(secret.as_bytes()));
        redactor.redact_tree(dir.path()).unwrap();
        for name in names {
            assert_eq!(
                std::fs::read_to_string(dir.path().join(name)).unwrap(),
                format!("before {REPLACEMENT} after\n"),
                "{name}"
            );
        }
        assert_eq!(redactor.count(), names.len());
    }

    #[test]
    fn bytes_that_are_not_text_are_still_searched() {
        let mut bytes = vec![0xff, 0x00, 0xfe];
        bytes.extend_from_slice(token("ghp_").as_bytes());
        bytes.push(0xff);
        assert!(is_secret_shaped(&bytes));
    }

    #[test]
    fn an_unterminated_private_key_is_cut_at_the_line() {
        let mut redactor = Redactor::new::<&str>([]).unwrap();
        let text = "key: -----BEGIN RSA PRIVATE KEY-----MIIE\nnext line\n";
        assert_eq!(
            redactor.redact(text),
            format!("key: {REPLACEMENT}\nnext line\n")
        );
        // As a JSON string holds it.
        let text = r#"{"k":"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"}"#;
        assert_eq!(
            redactor.redact(text),
            format!(r#"{{"k":"{REPLACEMENT}\n"}}"#)
        );
    }

    #[test]
    fn literals() {
        let mut redactor = Redactor::new([
            "hunter2-and-more",
            "hunter2-and-more-still",
            "short",
            "a.b*c(d)e",
        ])
        .unwrap();
        let cases = [
            ("x hunter2-and-more y", "x [REDACTED] y"),
            // The longer literal wins over the one it starts with.
            ("x hunter2-and-more-still y", "x [REDACTED] y"),
            // Too short to be a literal.
            ("a short word", "a short word"),
            // A literal is not a pattern.
            ("a.b*c(d)e aXbbc(d)e", "[REDACTED] aXbbc(d)e"),
        ];
        for (text, want) in cases {
            assert_eq!(redactor.redact(text), want);
        }
        assert_eq!(redactor.count(), 3);
        // A literal is found in bytes that are not text, as a shape is,
        // and finding counts nothing.
        let mut bytes = vec![0xff, 0x00];
        bytes.extend_from_slice("hunter2-and-more caf\u{e9}".as_bytes());
        assert!(redactor.finds(&bytes));
        assert!(!is_secret_shaped(&bytes));
        assert!(redactor.finds(format!("x {} y", token("ghp_")).as_bytes()));
        assert!(!redactor.finds(b"a short word, a.b*c(d)X"));
        assert_eq!(redactor.count(), 3);
    }

    #[test]
    fn a_literal_that_is_not_ascii_is_found_in_bytes() {
        let redactor = Redactor::new(["pass\u{e9}-w\u{f6}rd-long"]).unwrap();
        assert!(redactor.finds("the pass\u{e9}-w\u{f6}rd-long here".as_bytes()));
        assert!(!redactor.finds("the passe-word-long here".as_bytes()));
    }

    #[test]
    fn tree() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);
        let secret = token("ghp_");
        std::fs::create_dir(path("sub")).unwrap();
        std::fs::write(path("sub/log"), format!("a {secret} b\n")).unwrap();
        std::fs::write(path("clean"), "nothing here\n").unwrap();
        let mut binary = vec![0xff, 0xfe];
        binary.extend_from_slice(secret.as_bytes());
        std::fs::write(path("binary"), &binary).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), format!("{secret}\n")).unwrap();
        symlink(outside.path(), path("link")).unwrap();

        let mut redactor = Redactor::new::<&str>([]).unwrap();
        redactor.redact_tree(dir.path()).unwrap();

        assert_eq!(redactor.count(), 1);
        assert_eq!(
            std::fs::read_to_string(path("sub/log")).unwrap(),
            "a [REDACTED] b\n"
        );
        assert_eq!(
            std::fs::read_to_string(path("clean")).unwrap(),
            "nothing here\n"
        );
        // Not text, so left alone; the link is gone and its target untouched.
        assert_eq!(std::fs::read(path("binary")).unwrap(), binary);
        assert!(std::fs::symlink_metadata(path("link")).is_err());
        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            format!("{secret}\n")
        );
    }
}
