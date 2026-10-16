//! Secret-shaped strings: what `run` replaces in everything it logs or
//! uploads, and what `check` and `run` report or refuse in a hand-back.
//!
//! This is a safety net and not the defence: the agent's environment holds
//! no credential worth leaking beyond its own run token. The patterns are
//! shapes, so they also match strings that only look like a credential: a
//! fake key in a test fixture cost three runs all their work (#720, #918).
//! So a hand-back is refused only for what is surely a leak, a value the
//! run itself holds ([`Redactor::find_line_in`]) or a private key
//! ([`is_private_key`]), which cannot be a harmless fixture; any other
//! shape is a warning ([`shaped_lines`]), by line and never by string.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use std::sync::LazyLock;

use regex::bytes::Regex as BytesRegex;

use crate::files::{self, ReadError};

/// What a secret is replaced with.
pub const REPLACEMENT: &str = "[REDACTED]";

/// Shorter literals would redact ordinary words.
const MIN_LITERAL_BYTES: usize = 8;

/// The largest file `redact_tree` rewrites; a bigger one is not a log.
const MAX_REDACTED_BYTES: u64 = 1 << 30;

/// How much of a file is read at a time to be searched.
const CHUNK_BYTES: usize = 1 << 16;

/// The bounds in the PEM pattern: of the label before `PRIVATE KEY`, and
/// of what is between the two lines. A 16384-bit RSA key is about 13 KiB.
const PEM_LABEL_BYTES: usize = 32;
const PEM_BODY_BYTES: usize = 1 << 14;

/// The longest PEM block the pattern matches whole: its body, and two
/// lines of at most `-----BEGIN ` (the longer), a label and `PRIVATE KEY-----`.
const MAX_PEM_BYTES: usize =
    PEM_BODY_BYTES + 2 * ("-----BEGIN ".len() + PEM_LABEL_BYTES + "PRIVATE KEY-----".len());

/// The most shapes [`shaped_lines`] reports: enough to find each, and a
/// bound on what an agent's hand-back can put in a summary.
pub const MAX_SHAPE_WARNINGS: usize = 32;

/// A whole PEM private key block, also when a JSON string holds it with
/// escaped newlines; an unterminated one, or one over MAX_PEM_BYTES, is
/// cut at the end of the line, and `Redactor::redact_stream` replaces the
/// rest of one with a last line. The only match that spans lines, so the
/// bound is what streaming has to look ahead (see `stream`).
pub const PRIVATE_KEY: &str = r"-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----(?:(?s:.){0,16384}?-----END [A-Z0-9 ]{0,32}PRIVATE KEY-----|[^\n]*)";

/// The shapes, in the syntax of the `regex` crate. Redacted in what `run`
/// logs, and warned about in a hand-back.
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
    PRIVATE_KEY,
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

/// The last line of a PEM block, as the PEM pattern has it.
static PEM_END: LazyLock<BytesRegex> = LazyLock::new(|| {
    BytesRegex::new(&format!(
        "(?-u)-----END [A-Z0-9 ]{{0,{PEM_LABEL_BYTES}}}PRIVATE KEY-----"
    ))
    .expect("the built-in patterns are valid")
});

/// Whether a match is the PEM pattern's first line without the rest of
/// its block: one with no last line within the bound.
fn is_pem_without_end(found: &[u8]) -> bool {
    found.starts_with(b"-----BEGIN ") && !PEM_END.is_match(found)
}

/// Each pattern by itself, to name the one that matched.
static EACH_SHAPE: LazyLock<Vec<(&'static str, BytesRegex)>> = LazyLock::new(|| {
    PATTERNS
        .iter()
        .map(|&pattern| {
            let regex = BytesRegex::new(&format!("(?-u){pattern}"))
                .expect("the built-in patterns are valid");
            (pattern, regex)
        })
        .collect()
});

static PRIVATE_KEY_RE: LazyLock<BytesRegex> = LazyLock::new(|| {
    BytesRegex::new(&format!("(?-u){PRIVATE_KEY}")).expect("the built-in patterns are valid")
});

/// Whether `bytes` holds a string shaped like a credential.
pub fn is_secret_shaped(bytes: &[u8]) -> bool {
    SECRET_SHAPED.is_match(bytes)
}

/// Whether `bytes` holds the first line of a PEM private key.
pub fn is_private_key(bytes: &[u8]) -> bool {
    PRIVATE_KEY_RE.is_match(bytes)
}

/// The line of each string shaped like a credential in `input`, read in
/// pieces, with a pattern it matches: at most [`MAX_SHAPE_WARNINGS`].
pub fn shaped_lines(input: impl Read) -> io::Result<Vec<(usize, &'static str)>> {
    let mut line = 1;
    let mut found = Vec::new();
    stream(&SECRET_SHAPED, MAX_PEM_BYTES, input, |bytes, secret| {
        if secret {
            let pattern = secret_shapes(bytes).first().copied().unwrap_or(PRIVATE_KEY);
            found.push((line, pattern));
            if found.len() == MAX_SHAPE_WARNINGS {
                return Ok(false);
            }
        }
        line += bytes.iter().filter(|&&b| b == b'\n').count();
        Ok(true)
    })?;
    Ok(found)
}

/// The patterns that match in `bytes`, for telling an agent what to fix:
/// the pattern names the shape and not the string, which may be real.
pub fn secret_shapes(bytes: &[u8]) -> Vec<&'static str> {
    EACH_SHAPE
        .iter()
        .filter(|(_, regex)| regex.is_match(bytes))
        .map(|(pattern, _)| *pattern)
        .collect()
}

/// Hands `piece` all of `input`, in order, as the text between matches of
/// `rule` and the matches themselves (`true`), until it returns false.
///
/// The pieces are exactly those of one search of the whole input, with
/// memory for the longest line and `overlap`. That holds because no
/// pattern looks behind or ahead of its match, and only a match of at
/// most `overlap` bytes spans a newline. The input is searched in a
/// buffer, and a match before a cut after a newline at least `overlap`
/// bytes before the buffer's end is final: one that would need more input
/// is longer than `overlap`, so it cannot span the newline, and starts
/// after the cut. A match found across the cut is short enough to be
/// final, so the cut moves to its end.
fn stream(
    rule: &BytesRegex,
    overlap: usize,
    mut input: impl Read,
    mut piece: impl FnMut(&[u8], bool) -> io::Result<bool>,
) -> io::Result<()> {
    let mut buf = Vec::new();
    loop {
        // Doubling the buffer while no line ends early enough searches a
        // long line a few times and not once for each chunk.
        let want = CHUNK_BYTES.max(buf.len());
        let read = (&mut input).take(want as u64).read_to_end(&mut buf)?;
        let end = read < want;
        let mut cut = if end {
            buf.len()
        } else {
            buf[..buf.len().saturating_sub(overlap)]
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(0, |newline| newline + 1)
        };
        let mut done = 0;
        for found in rule.find_iter(&buf) {
            if found.start() >= cut {
                break;
            }
            cut = cut.max(found.end());
            if !piece(&buf[done..found.start()], false)? || !piece(found.as_bytes(), true)? {
                return Ok(());
            }
            done = found.end();
        }
        if !piece(&buf[done..cut], false)? || end {
            return Ok(());
        }
        buf.drain(..cut);
    }
}

/// Whether bytes given in pieces are UTF-8.
#[derive(Debug, Default)]
struct Utf8 {
    /// The start of a character the last piece did not finish.
    pending: Vec<u8>,
    invalid: bool,
}

impl Utf8 {
    /// Takes the next piece: whether the bytes are still UTF-8 so far.
    fn feed(&mut self, mut bytes: &[u8]) -> bool {
        while !self.invalid && !self.pending.is_empty() {
            let Some((&first, rest)) = bytes.split_first() else {
                return true;
            };
            self.pending.push(first);
            bytes = rest;
            match std::str::from_utf8(&self.pending) {
                Ok(_) => self.pending.clear(),
                Err(err) => self.invalid = err.error_len().is_some(),
            }
        }
        if !self.invalid {
            match std::str::from_utf8(bytes) {
                Ok(_) => {}
                Err(err) if err.error_len().is_none() => {
                    self.pending = bytes[err.valid_up_to()..].to_vec();
                }
                Err(_) => self.invalid = true,
            }
        }
        !self.invalid
    }

    /// Whether all of it was UTF-8.
    fn is_text(&self) -> bool {
        !self.invalid && self.pending.is_empty()
    }
}

/// Replaces secrets in text: the literal values it was given, and the
/// patterns. It counts what it replaced, so a caller can tell whether
/// anything was found.
#[derive(Debug)]
pub struct Redactor {
    /// Over bytes, for content that is not text, and since the bounds in
    /// the patterns count bytes.
    bytes: BytesRegex,
    /// The literals and [`PRIVATE_KEY`]: what is refused where it cannot
    /// be redacted.
    refused: BytesRegex,
    /// What [`stream`] needs to look ahead: the longest match that spans
    /// a newline.
    overlap: usize,
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
        let overlap = literals.first().map_or(0, String::len).max(MAX_PEM_BYTES);
        let literals: Vec<String> = literals.iter().map(|l| regex::escape(l)).collect();
        let rule = alternation(
            literals
                .iter()
                .map(String::as_str)
                .chain(PATTERNS.iter().copied()),
        );
        let refused = alternation(literals.iter().map(String::as_str).chain([PRIVATE_KEY]));
        Ok(Self {
            bytes: BytesRegex::new(&format!("(?-u){rule}"))?,
            refused: BytesRegex::new(&format!("(?-u){refused}"))?,
            overlap,
            count: 0,
        })
    }

    /// Whether `bytes` holds a secret this would replace in text: one of
    /// its literals, or a string shaped like a credential. For what
    /// cannot be redacted, a patch or a file that is not text.
    pub fn finds(&self, bytes: &[u8]) -> bool {
        self.bytes.is_match(bytes)
    }

    /// The line of the first of its literals or private key in `input`,
    /// read in pieces: a location to report where the string itself may
    /// not be shown. Other shapes are [`shaped_lines`]'s to report.
    pub fn find_line_in(&self, input: impl Read) -> io::Result<Option<usize>> {
        let mut line = 1;
        let mut found = None;
        stream(&self.refused, self.overlap, input, |bytes, secret| {
            if secret {
                found = Some(line);
                return Ok(false);
            }
            line += bytes.iter().filter(|&&b| b == b'\n').count();
            Ok(true)
        })?;
        Ok(found)
    }

    /// `text` with every secret replaced by [`REPLACEMENT`].
    pub fn redact<'t>(&mut self, text: &'t str) -> Cow<'t, str> {
        let mut redacted = io::Cursor::new(Vec::new());
        match self.redact_stream(text.as_bytes(), &mut redacted) {
            Ok(None) => Cow::Borrowed(text),
            Ok(Some(found)) => {
                self.count += found;
                let end = usize::try_from(redacted.position()).unwrap_or(usize::MAX);
                let mut redacted = redacted.into_inner();
                redacted.truncate(end);
                // Every match starts and ends at an ASCII byte or the end
                // of a literal, so this is still UTF-8.
                Cow::Owned(String::from_utf8_lossy(&redacted).into_owned())
            }
            // Memory is neither read nor written with an error; were it,
            // none of the text would be shown.
            Err(_) => {
                self.count += 1;
                Cow::Borrowed(REPLACEMENT)
            }
        }
    }

    /// Copies `input` to `output` with every secret replaced, if `input`
    /// is UTF-8 and holds a secret: how many it replaced, or `None` and
    /// `output` partly written. The count is the caller's to add. What
    /// `output` holds past its position at the end is not part of it.
    ///
    /// A PEM block whose last line is beyond the pattern's bound, a big
    /// key or one with much space, is replaced whole as one search of the
    /// unbounded pattern would: the pattern replaces its first line, and
    /// what follows is written for an unterminated block, then written
    /// over when the last line comes. A key is not left to be put back
    /// together from its body, and nothing is held in memory for it.
    fn redact_stream(
        &self,
        input: impl Read,
        mut output: impl Write + Seek,
    ) -> io::Result<Option<usize>> {
        let mut text = Utf8::default();
        let mut found = 0;
        // Where such a block's first line was replaced, and how many
        // secrets were replaced since: what its last line takes back.
        let mut pem: Option<(u64, usize)> = None;
        let mut pem_tail = Vec::new();
        stream(&self.bytes, self.overlap, input, |mut bytes, secret| {
            if !text.feed(bytes) {
                return Ok(false);
            }
            if let Some((start, within)) = pem {
                // Literals can divide an END marker into several pieces.
                // Search the original bytes, including secret pieces, with
                // enough history for any marker that crosses their boundary.
                let previous = pem_tail.len();
                pem_tail.extend_from_slice(bytes);
                if let Some(end) = PEM_END.find(&pem_tail) {
                    let end = end.end() - previous;
                    pem = None;
                    pem_tail.clear();
                    found -= within;
                    output.seek(io::SeekFrom::Start(start))?;
                    if secret {
                        return Ok(true);
                    }
                    bytes = &bytes[end..];
                } else {
                    let keep = "-----END ".len() + PEM_LABEL_BYTES + "PRIVATE KEY-----".len() - 1;
                    if pem_tail.len() > keep {
                        pem_tail.drain(..pem_tail.len() - keep);
                    }
                    if secret {
                        pem = Some((start, within + 1));
                    }
                }
            }
            if secret {
                found += 1;
                output.write_all(REPLACEMENT.as_bytes())?;
                if pem.is_none() && is_pem_without_end(bytes) {
                    pem_tail.clear();
                    pem = Some((output.stream_position()?, 0));
                }
            } else {
                output.write_all(bytes)?;
            }
            Ok(true)
        })?;
        output.flush()?;
        Ok((text.is_text() && found > 0).then_some(found))
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
        let input = match files::open_regular(path, MAX_REDACTED_BYTES) {
            Ok(input) => input,
            Err(ReadError::Io(err)) => return Err(err),
            // Became a link since the look above, or is too big to be text
            // this wrote: not something to upload.
            Err(ReadError::NotRegular | ReadError::TooBig { .. }) => {
                return std::fs::remove_file(path);
            }
        };
        // Unnamed and beside the file: nobody walking the tree sees it.
        let mut redacted = tempfile::tempfile_in(path.parent().unwrap_or(Path::new(".")))?;
        let found = match self.redact_stream(input, io::BufWriter::new(&mut redacted)) {
            Ok(found) => found,
            // Grew past the cap while it was read.
            Err(err) if err.kind() == io::ErrorKind::FileTooLarge => {
                return std::fs::remove_file(path);
            }
            Err(err) => return Err(err),
        };
        let Some(found) = found else {
            return Ok(());
        };
        let end = redacted.stream_position()?;
        redacted.set_len(end)?;
        redacted.rewind()?;
        files::overwrite_regular(path, redacted)?;
        self.count += found;
        Ok(())
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
            // A secret is named by at least one pattern, and nothing else is.
            assert_eq!(
                !secret_shapes(text.as_bytes()).is_empty(),
                *secret,
                "{name}"
            );
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

    /// A key over the pattern's bound is replaced whole, and what is left
    /// passes the upload gate's search: no line of its body survives.
    #[test]
    fn a_private_key_over_the_bound_is_replaced_whole() {
        let line = |edge: &str| format!("-----{edge} RSA PRIVATE KEY-----");
        let body = vec!["MIIE".repeat(16); PEM_BODY_BYTES / 64 + 1].join("\n");
        let cases = [
            ("big", format!("{}\n{body}\n{}", line("BEGIN"), line("END"))),
            (
                "spaced",
                format!(
                    "{}{}MIIE\n{}",
                    line("BEGIN"),
                    " ".repeat(PEM_BODY_BYTES),
                    line("END")
                ),
            ),
            (
                "big, with a token in it",
                format!(
                    "{}\n{}\n{body}\n{}",
                    line("BEGIN"),
                    token("ghp_"),
                    line("END")
                ),
            ),
            (
                "big and wrapped in CRLF",
                format!(
                    "{}\r\n{}\r\n{}",
                    line("BEGIN"),
                    body.replace('\n', "\r\n"),
                    line("END")
                ),
            ),
        ];
        let dir = tempfile::tempdir().unwrap();
        let mut redactor = Redactor::new::<&str>([]).unwrap();
        for (name, pem) in &cases {
            let path = dir.path().join("log");
            std::fs::write(&path, format!("before\n{pem}\nafter {}\n", token("ghp_"))).unwrap();
            let before = redactor.count();
            redactor.redact_tree(&path).unwrap();
            let redacted = std::fs::read(&path).unwrap();
            assert_eq!(
                redacted,
                format!("before\n{REPLACEMENT}\nafter {REPLACEMENT}\n").as_bytes(),
                "{name}"
            );
            assert_eq!(redactor.count() - before, 2, "{name}");
            assert_eq!(
                redactor.find_line_in(&redacted[..]).unwrap(),
                None,
                "{name}"
            );
            // Text redacted in memory is the same.
            let text = format!("before\n{pem}\nafter\n");
            assert_eq!(
                redactor.redact(&text),
                format!("before\n{REPLACEMENT}\nafter\n"),
                "{name}"
            );
        }
    }

    /// The bounds `stream` relies on are the ones in the pattern.
    #[test]
    fn the_pem_pattern_has_its_bounds() {
        let pem = PATTERNS
            .iter()
            .find(|pattern| pattern.contains("PRIVATE KEY"))
            .unwrap();
        assert_eq!(pem.matches(&format!("{{0,{PEM_LABEL_BYTES}}}")).count(), 2);
        assert!(pem.contains(&format!("(?s:.){{0,{PEM_BODY_BYTES}}}?")));
        // No other pattern can span a newline.
        for pattern in PATTERNS.iter().filter(|pattern| *pattern != pem) {
            assert!(
                !pattern.contains("(?s") && !pattern.contains("[^"),
                "{pattern}"
            );
        }
    }

    /// Streamed redaction is byte for byte one search of the whole text,
    /// wherever a secret falls against the buffer's end or its cut.
    #[test]
    fn streamed_as_whole() {
        let literal = "a-literal-the-run-holds";
        // Put together here, as `token` is.
        let line = |edge: &str, label: &str| format!("-----{edge} {label}PRIVATE KEY-----");
        let pem = |newline: &str, lines: usize| {
            let body = vec!["MIIE".repeat(16); lines].join(newline);
            let (begin, end) = (line("BEGIN", "RSA "), line("END", "RSA "));
            format!("{begin}{newline}{body}{newline}{end}")
        };
        let unterminated = format!(
            "{}\n{}",
            line("BEGIN", ""),
            vec!["MIIE".repeat(16); 20].join("\n")
        );
        let cases: &[(&str, String)] = &[
            ("a GitHub token", token("ghp_")),
            (
                "a JWT",
                format!("eyJ{0}.eyJ{0}.sig", "abcdefghij".repeat(20)),
            ),
            ("a literal", literal.to_owned()),
            ("a PEM", pem("\n", 40)),
            (
                "a PEM with escaped newlines inside JSON",
                format!(r#"{{"key":"{}\n"}}"#, pem(r"\n", 40)),
            ),
            ("an unterminated PEM", unterminated.clone()),
            (
                "an unterminated PEM inside JSON",
                format!(r#"{{"key":"{}"}}"#, unterminated.replace('\n', r"\n")),
            ),
            ("a PEM over the bound", pem("\n", PEM_BODY_BYTES / 64 + 1)),
            ("no secret, in characters of two bytes", "\u{e9}".repeat(40)),
        ];
        let redactor = Redactor::new([literal, "END RSA "]).unwrap();
        // Independent whole-input oracle: the original, unbounded PEM
        // pattern consumes a complete block before literals in its body/end.
        let whole_rule =
            BytesRegex::new(&redactor.bytes.as_str().replace("{0,16384}?", "*?")).unwrap();
        // Lines of characters of more than a byte, so that pieces split them.
        let filler = "filler caf\u{e9} line\n".repeat(2 * CHUNK_BYTES / 16);
        let boundary = |at: usize| {
            (0..=at)
                .rev()
                .find(|&at| filler.is_char_boundary(at))
                .unwrap()
        };
        for (name, secret) in cases {
            // The first cut, and the end of the first buffer.
            for anchor in [CHUNK_BYTES - redactor.overlap, CHUNK_BYTES] {
                let step = (secret.len() / 8).max(1);
                let around = (anchor.saturating_sub(secret.len() + 64)..anchor + 64).step_by(step);
                let ends = [anchor - secret.len(), anchor - secret.len() + 1, anchor - 1];
                for at in around.chain(ends) {
                    let at = boundary(at);
                    let text = format!("{}{secret}{}", &filler[..at], &filler[at..]);
                    let count = whole_rule.find_iter(text.as_bytes()).count();
                    let whole = whole_rule.replace_all(text.as_bytes(), REPLACEMENT.as_bytes());
                    let mut streamed = io::Cursor::new(Vec::new());
                    let found = redactor
                        .redact_stream(text.as_bytes(), &mut streamed)
                        .unwrap();
                    let end = usize::try_from(streamed.position()).unwrap();
                    let mut streamed = streamed.into_inner();
                    streamed.truncate(end);
                    let at = format!("{name} at {at}");
                    assert_eq!(found, (count > 0).then_some(count), "{at}");
                    if count > 0 {
                        assert!(streamed == whole.as_ref(), "{at}");
                    }
                    let line_of = |rule: &BytesRegex| {
                        rule.find(text.as_bytes())
                            .map(|found| 1 + text[..found.start()].matches('\n').count())
                    };
                    assert_eq!(
                        redactor.find_line_in(text.as_bytes()).unwrap(),
                        line_of(&redactor.refused),
                        "{at}"
                    );
                    assert_eq!(
                        shaped_lines(text.as_bytes()).unwrap().first().map(|f| f.0),
                        line_of(&SECRET_SHAPED),
                        "{at}"
                    );
                }
            }
        }
        // Not text, wherever the byte that is not falls.
        for at in [CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1] {
            let mut bytes = format!("{}{}", &filler[..boundary(at)], token("ghp_")).into_bytes();
            bytes.insert(boundary(at), 0xff);
            assert_eq!(
                redactor
                    .redact_stream(&bytes[..], io::Cursor::new(Vec::new()))
                    .unwrap(),
                None
            );
        }
    }

    #[test]
    fn oversized_pem_with_literal_in_end_marker() {
        for literal in ["END RSA ", "PRIVATE KEY", "-----END RSA PRIVATE KEY-----"] {
            let begin = format!("-----{} RSA PRIVATE KEY-----", "BEGIN");
            let end = format!("-----{} RSA PRIVATE KEY-----", "END");
            for body in [
                "body material\n".repeat(CHUNK_BYTES / 4),
                "x".repeat(3 * CHUNK_BYTES),
            ] {
                let input = format!("before\n{begin}\n{body}\n{end}\nafter\n");
                let expected = format!("before\n{REPLACEMENT}\nafter\n");
                let mut redactor = Redactor::new([literal]).unwrap();
                assert!(redactor.redact(&input) == expected, "{literal}");
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("transcript");
                std::fs::write(&path, &input).unwrap();
                redactor.redact_tree(dir.path()).unwrap();
                let output = std::fs::read(&path).unwrap();
                assert!(output == expected.as_bytes(), "{literal}");
                assert_eq!(redactor.find_line_in(output.as_slice()).unwrap(), None);
            }
        }
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
        // What is refused is a literal, not a shape that is no literal.
        let lines = format!("one\ntwo {} y\nthree hunter2-and-more\n", token("ghp_"));
        assert_eq!(redactor.find_line_in(lines.as_bytes()).unwrap(), Some(3));
        assert_eq!(redactor.find_line_in(&b"one\ntwo\n"[..]).unwrap(), None);
        assert!(!redactor.finds(b"a short word, a.b*c(d)X"));
        assert_eq!(redactor.count(), 3);
    }

    /// A hand-back is refused for a value the run holds and for a private
    /// key, and only warned about for any other shape, by line.
    #[test]
    fn refused_or_warned() {
        let run_token = token("ghs_");
        let redactor = Redactor::new([run_token.as_str()]).unwrap();
        let pem = format!(
            "-----BEGIN RSA {0}-----\nabc\n-----END RSA {0}-----\n",
            "PRIVATE KEY"
        );
        let fixture = format!("one\nkey = \"{}\"\n", token("ghp_"));
        // (the case, the text, the line refused, the lines warned)
        let cases: &[(&str, String, Option<usize>, &[usize])] = &[
            ("a fake key in a fixture", fixture.clone(), None, &[2]),
            (
                "the run's own token",
                format!("{fixture}three {run_token}\n"),
                Some(3),
                &[2, 3],
            ),
            (
                "a private key",
                format!("{fixture}{pem}after\n"),
                Some(3),
                &[2, 3],
            ),
            ("nothing", "one\ntwo\n".to_owned(), None, &[]),
        ];
        for (name, text, refused, warned) in cases {
            assert_eq!(
                redactor.find_line_in(text.as_bytes()).unwrap(),
                *refused,
                "{name}"
            );
            let lines: Vec<usize> = shaped_lines(text.as_bytes())
                .unwrap()
                .into_iter()
                .map(|(line, _)| line)
                .collect();
            assert_eq!(lines, *warned, "{name}");
            assert_eq!(
                is_private_key(text.as_bytes()),
                text.contains(&pem),
                "{name}"
            );
        }
        assert_eq!(
            shaped_lines(fixture.as_bytes()).unwrap(),
            [(2, r"gh[posur]_[A-Za-z0-9_]{20,}")]
        );
        let many = format!("{}\n", token("ghp_")).repeat(MAX_SHAPE_WARNINGS + 5);
        assert_eq!(
            shaped_lines(many.as_bytes()).unwrap().len(),
            MAX_SHAPE_WARNINGS
        );
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
