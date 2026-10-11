//! The condensed transcript on its way to the job's log and to
//! `condensed.log`: a line per event of the session, with the agent's
//! words in it.
//!
//! Two things are done to every line. Secrets are replaced: the values
//! this process holds (the agent can read its run token) and everything
//! shaped like a credential ([`crate::redact`]). And the line is made
//! unable to act as a command to the CI system that shows the log:
//! GitHub's runner reads a line starting with `::name::` or `##[name]`,
//! after leading whitespace, as a command (`add-mask`, `stop-commands`,
//! `error`), whoever printed it; both are broken up mid-line too.

use std::fs::File;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, PoisonError};

use super::enter::one_line;
use crate::redact::Redactor;

/// The redactor of a run, shared by its log and by whatever redacts its
/// files afterwards, so that there is one count of what was replaced.
#[derive(Debug, Clone)]
pub struct Shared(Arc<Mutex<Redactor>>);

impl Shared {
    pub fn new(redactor: Redactor) -> Self {
        Self(Arc::new(Mutex::new(redactor)))
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut Redactor) -> T) -> T {
        f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    pub fn count(&self) -> usize {
        self.with(|redactor| redactor.count())
    }
}

/// LINE as it may be shown in a job's log: redacted, on one line, and no
/// command to the runner.
pub fn shown(redactor: &Shared, line: &str) -> String {
    one_line(&redactor.with(|redactor| redactor.redact(line).into_owned()))
}

/// A writer that passes on whole lines, each as [`shown`], to the job's
/// log and to a file.
pub struct Condensed<W: Write> {
    log: W,
    file: File,
    redactor: Shared,
    /// The line being written, until its newline.
    line: Vec<u8>,
}

impl<W: Write> Condensed<W> {
    pub fn new(log: W, file: File, redactor: Shared) -> Self {
        Self {
            log,
            file,
            redactor,
            line: Vec::new(),
        }
    }

    fn emit(&mut self, line: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(line);
        let clean = format!("{}\n", shown(&self.redactor, text.trim_end_matches('\n')));
        // The file first: it is what is uploaded, and a log nobody reads
        // any more must not cost it a line.
        let filed = self.file.write_all(clean.as_bytes());
        self.log.write_all(clean.as_bytes())?;
        filed
    }
}

impl<W: Write> Write for Condensed<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.line.extend_from_slice(buf);
        while let Some(end) = self.line.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.line.drain(..=end).collect();
            self.emit(&line)?;
        }
        Ok(buf.len())
    }

    /// What is held of an unfinished line stays held: a secret may be
    /// half written.
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.log.flush()
    }
}

impl<W: Write> Drop for Condensed<W> {
    fn drop(&mut self) {
        let rest = std::mem::take(&mut self.line);
        if !rest.is_empty() {
            let _ = self.emit(&rest);
        }
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Buffer {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn redactor() -> Shared {
        Shared::new(Redactor::new(["praxis-run-abcdef", "short"]).unwrap())
    }

    #[test]
    fn secrets_are_replaced_even_when_written_in_pieces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("condensed.log");
        let (out, redactor) = (Buffer::default(), redactor());
        let token = format!("gh{}_{}", "p", "a1B2".repeat(10));
        let mut log = Condensed::new(out.clone(), File::create(&path).unwrap(), redactor.clone());
        for piece in [
            "the token is praxis-run-",
            "abcdef, twice: praxis-run-abcdef\nand ",
            &format!("{token} is a shape, short is not\nno newline, praxis-run-abcdef"),
        ] {
            log.write_all(piece.as_bytes()).unwrap();
            log.flush().unwrap();
        }
        let two = "the token is [REDACTED], twice: [REDACTED]\n\
                   and [REDACTED] is a shape, short is not\n";
        assert_eq!(out.text(), two);
        drop(log);
        let all = format!("{two}no newline, [REDACTED]\n");
        assert_eq!(out.text(), all);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), all);
        assert_eq!(redactor.count(), 4);
    }

    /// Whatever the agent has a line say, the runner is given no command.
    #[test]
    fn no_line_is_a_command_to_the_runner() {
        let redactor = redactor();
        // (the line, as shown)
        let cases = [
            ("» plain words", "» plain words"),
            ("::add-mask::x", ": :add-mask: :x"),
            ("  \t::stop-commands::t", "   : :stop-commands: :t"),
            ("\u{a0}::error::x", "\u{a0}: :error: :x"),
            ("» ##[error]x ##[add-mask]y", "» ## [error]x ## [add-mask]y"),
            (
                "» a\r::warning::b\n::error::c",
                "» a : :warning: :b : :error: :c",
            ),
            ("» a\u{1b}[2K\u{8}::notice::b", "» a [2K : :notice: :b"),
            ("» mid ::error:: line", "» mid : :error: : line"),
            ("» ::::add-mask::x", "» : : : :add-mask: :x"),
        ];
        for (line, want) in cases {
            let got = shown(&redactor, line);
            assert_eq!(got, want, "{line:?}");
            assert!(!got.contains("::"), "{got:?}");
            assert!(!got.contains("##["), "{got:?}");
            assert!(!got.contains(['\n', '\r']), "{got:?}");
        }
    }
}
