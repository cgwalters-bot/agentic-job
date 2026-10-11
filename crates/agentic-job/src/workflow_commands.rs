//! Keep untrusted log text from becoming GitHub Actions workflow commands.

use std::io::Write;

/// The most one [`Escaping`] write passes on: half of Linux's `PIPE_BUF`,
/// so that the escaped bytes, at most twice as many, go into a pipe in one
/// atomic write that no other writer's bytes can split.
pub(crate) const ESCAPING_CHUNK: usize = 2048;

/// Stands for an unknown byte, such as another writer's on the same pipe.
/// Never part of UTF-8; a raw 0xff byte only costs an extra space.
const UNKNOWN: u8 = 0xff;

/// Breaks `::` and `##[` with a space, also where they span two calls on
/// one stream. The runner only reads a command at the start of a line, after
/// leading whitespace (`TryParseV2` after `TrimStart`); breaking them anywhere
/// is what keeps it complete: with neither left anywhere, no filter,
/// reordering or interleaving of whole lines downstream can form one, and
/// there is no runner state (such as a `stop-commands` token) to leave behind.
#[derive(Debug, Default)]
pub(crate) struct Escaper {
    last: [u8; 2],
}

impl Escaper {
    /// Whether a space goes before `byte`, given what came before it.
    fn space_before(&mut self, byte: u8) -> bool {
        let space = match byte {
            b':' => matches!(self.last[1], b':' | UNKNOWN),
            b'[' => matches!(self.last, [b'#' | UNKNOWN, b'#' | UNKNOWN]),
            _ => false,
        };
        self.last = [if space { b' ' } else { self.last[1] }, byte];
        space
    }

    /// `bytes`, escaped, appended to `shown`. No UTF-8 assumption: the bytes
    /// matched are ASCII, which never occurs inside a multibyte sequence.
    fn push(&mut self, bytes: &[u8], shown: &mut Vec<u8>) {
        for &byte in bytes {
            if self.space_before(byte) {
                shown.push(b' ');
            }
            shown.push(byte);
        }
    }
}

/// A writer that passes on what it is given through one [`Escaper`], in one
/// write of its own per call. Another writer to the same pipe can only put
/// its bytes between two calls, so each call starts as if after an unknown
/// `::` or `##`: concurrent `sandbox exec`s, or stdout and stderr through
/// `2>&1`, cannot join their halves of one either.
pub(crate) struct Escaping<W: Write> {
    writer: W,
    escaper: Escaper,
    shown: Vec<u8>,
}

impl<W: Write> Escaping<W> {
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer,
            escaper: Escaper::default(),
            shown: Vec::new(),
        }
    }
}

impl<W: Write> Write for Escaping<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let bytes = &bytes[..bytes.len().min(ESCAPING_CHUNK)];
        self.escaper.last = [UNKNOWN; 2];
        self.shown.clear();
        self.escaper.push(bytes, &mut self.shown);
        self.writer.write_all(&self.shown)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

/// `text` with both command syntaxes broken; see [`Escaper`].
pub(crate) fn escaped(text: &str) -> String {
    let mut escaper = Escaper::default();
    let mut shown = String::with_capacity(text.len());
    for c in text.chars() {
        // Other characters only need to reset the state.
        if escaper.space_before(u8::try_from(c).unwrap_or(0)) {
            shown.push(' ');
        }
        shown.push(c);
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_breaks_both_syntaxes() {
        for (text, expected) in [
            ("::set-output name=a::b", ": :set-output name=a: :b"),
            ("::::add-mask::x\r\n", ": : : :add-mask: :x\r\n"),
            ("prefix ##[error]x", "prefix ## [error]x"),
            ("###[x] #[y] ##x", "### [x] #[y] ##x"),
            // Only the two syntaxes: URLs, times and single `#` stay.
            ("https://x/#a 12:34", "https://x/#a 12:34"),
            ("é::ü##[", "é: :ü## ["),
        ] {
            assert_eq!(escaped(text), expected);
            assert_eq!(escaped(expected), expected, "idempotent");
        }
    }

    /// Writes are where other writers' bytes may land: escaping is
    /// conservative there, so no two writes join into a command, whoever
    /// made them, and a write never outgrows one atomic pipe write.
    #[test]
    fn writes_cannot_join_into_a_command() {
        let has_command =
            |log: &[u8]| log.windows(2).any(|w| w == b"::") || log.windows(3).any(|w| w == b"##[");
        for chunks in [
            &["\n:", ":add-mask:", ":x\n"][..],
            &["#", "#", "[error]"],
            &["x#", "#[error]"],
            &["##", "[error]"],
            &[":", ":", ":", ":set-output name=a:", ":b"],
        ] {
            let mut log = Vec::new();
            // Each chunk from a different writer, or all from one.
            for chunk in chunks {
                Escaping::new(&mut log).write_all(chunk.as_bytes()).unwrap();
            }
            let mut one = Escaping::new(Vec::new());
            for chunk in chunks {
                one.write_all(chunk.as_bytes()).unwrap();
            }
            for log in [&log, &one.writer] {
                assert!(!has_command(log), "{}", String::from_utf8_lossy(log));
            }
        }
        let big = vec![b':'; ESCAPING_CHUNK + 1];
        let mut shown = Escaping::new(Vec::new());
        assert_eq!(shown.write(&big).unwrap(), ESCAPING_CHUNK);
        assert!(shown.writer.len() <= 2 * ESCAPING_CHUNK);
    }
}
