//! What a run leaves under `--out` to be uploaded, and the gate it has to
//! pass to get there.
//!
//! Everything is put together in a directory of `run`'s own, under
//! `OUT/work`, and moved to where a workflow uploads it from only once
//! all of this holds:
//!
//! - **the run was ended at the inference proxy.** Until then its token
//!   may be live, and the agent could read its token: nothing that might
//!   quote it is published while it still buys anything;
//! - **no secret is left** in the results, the transcript or the
//!   hand-back: none of the values the run holds, and no private key.
//!   The first two were redacted, as far as they are text, of those and
//!   of anything else shaped like a credential; the hand-back cannot be (a
//!   patch with a string replaced no longer applies), so a secret there,
//!   or in a file that is not text, fails the run. Any other shape in the
//!   hand-back is most likely a test fixture, since the run holds no
//!   credential but its own: it is a warning ([`Staging::shape_warnings`]);
//! - **the redaction did something** in a run of the fake agent, whose
//!   session prints a credential-shaped string so that this can be asked.
//!
//! A run that does not pass leaves nothing where uploads are taken from:
//! `OUT/run`, `OUT/transcript.tar.zst` and `OUT/safe-outputs` exist only
//! for a run whose results may be public. Whether the target is public
//! at all is the workflow's to check, which can ask the forge.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail, ensure};

use super::log::Shared;
use crate::files::{self, ReadError};
use crate::redact;

/// Under `--out`: the run's summary, its condensed log and the agent's
/// outcome; the transcript; and what the agent handed back, if anything.
pub const RUN_DIR: &str = "run";
pub const TRANSCRIPT_FILE: &str = "transcript.tar.zst";
pub const SAFE_OUTPUTS_DIR: &str = "safe-outputs";
/// Under `OUT/work`: where those are put together.
const STAGING_DIR: &str = "staging";
const TRANSCRIPT_DIR: &str = "transcript";
/// The largest file that is published.
const MAX_FILE_BYTES: u64 = 1 << 30;
/// zstd's default level.
const COMPRESSION_LEVEL: i32 = 3;
const FILE_MODE: u32 = 0o644;

/// Where a run's results are put together.
#[derive(Debug, Clone)]
pub struct Staging {
    root: PathBuf,
}

/// What the gate is told about the run.
#[derive(Debug, Clone, Copy)]
pub struct Gate {
    /// Whether the run's token is known to be dead, or was never one this
    /// run could end.
    pub ended: bool,
    /// Whether the agent is the scripted one.
    pub fake_agent: bool,
}

/// The places under OUT that a workflow uploads from.
fn published(out: &Path) -> [PathBuf; 3] {
    [RUN_DIR, TRANSCRIPT_FILE, SAFE_OUTPUTS_DIR].map(|name| out.join(name))
}

/// Refuses an `--out` that already holds a run's results: what is
/// uploaded from there must be this run's and have passed this run's
/// gate.
pub fn refuse_earlier_results(out: &Path) -> Result<()> {
    for path in published(out) {
        ensure!(
            std::fs::symlink_metadata(&path).is_err(),
            "{} exists: --out must not hold the results of an earlier run",
            path.display()
        );
    }
    Ok(())
}

/// Removes PATH, a file or a directory, if it is there.
fn remove(path: impl AsRef<Path>) {
    let path = path.as_ref();
    if std::fs::remove_dir_all(path).is_err() {
        let _ = std::fs::remove_file(path);
    }
}

impl Staging {
    /// An empty staging directory under WORK, which is private to this
    /// user: what is put here is not redacted yet.
    pub fn create(work: &Path) -> Result<Self> {
        let root = work.join(STAGING_DIR);
        // A run that never started may be tried again with the same OUT.
        match std::fs::remove_dir_all(&root) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                return Err(err).with_context(|| format!("removing {}", root.display()));
            }
            _ => {}
        }
        let staging = Self { root };
        for dir in [staging.run(), staging.transcript()] {
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        Ok(staging)
    }

    pub fn run(&self) -> PathBuf {
        self.root.join(RUN_DIR)
    }

    pub fn transcript(&self) -> PathBuf {
        self.root.join(TRANSCRIPT_DIR)
    }

    /// Made by whoever has something to hand back.
    pub fn safe_outputs(&self) -> PathBuf {
        self.root.join(SAFE_OUTPUTS_DIR)
    }

    /// Replaces secrets in the results and the transcript, in place.
    /// The hand-back is left as it is.
    pub fn redact(&self, redactor: &Shared) -> Result<()> {
        for dir in [self.run(), self.transcript()] {
            redactor
                .with(|redactor| redactor.redact_tree(&dir))
                .with_context(|| format!("redacting {}", dir.display()))?;
        }
        Ok(())
    }

    /// The files of DIR, by name. Anything that is not a regular file is
    /// an error: all of this was written here.
    fn files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
        let mut found = Vec::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(found),
            Err(err) => return Err(err).with_context(|| format!("reading {}", dir.display())),
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
            let name = entry
                .file_name()
                .into_string()
                .ok()
                .with_context(|| format!("a file name in {} is not UTF-8", dir.display()))?;
            found.push((name, entry.path()));
        }
        found.sort();
        Ok(found)
    }

    /// Opened to be read in pieces, up to [`MAX_FILE_BYTES`].
    fn open(path: &Path) -> Result<files::Regular> {
        match files::open_regular(path, MAX_FILE_BYTES) {
            Ok(file) => Ok(file),
            Err(ReadError::Io(err)) => {
                Err(err).with_context(|| format!("reading {}", path.display()))
            }
            Err(err) => bail!("{} {err}", path.display()),
        }
    }

    /// The gate: an error says why nothing of this run may be uploaded.
    /// REDACTOR is the run's, which knows the secrets the run holds and
    /// how many it replaced.
    pub fn check(&self, gate: Gate, redactor: &Shared) -> Result<()> {
        ensure!(
            gate.ended,
            "the run was not ended at the inference proxy, so its token may still be live"
        );
        for (label, dir) in [
            (RUN_DIR, self.run()),
            (TRANSCRIPT_DIR, self.transcript()),
            (SAFE_OUTPUTS_DIR, self.safe_outputs()),
        ] {
            for (name, path) in Self::files(&dir)? {
                let file = Self::open(&path)?;
                let found = redactor
                    .with(|redactor| redactor.find_line_in(file))
                    .with_context(|| format!("reading {}", path.display()))?;
                // The line and not the string: this error is published.
                if let Some(line) = found {
                    bail!(
                        "a secret of the run's or a private key {} {label}/{name}, line {line}",
                        if label == SAFE_OUTPUTS_DIR {
                            "is in what the agent handed back,"
                        } else {
                            "survived redaction in"
                        }
                    );
                }
            }
        }
        ensure!(
            !gate.fake_agent || redactor.count() > 0,
            "the redaction replaced nothing in a run of the fake agent, whose session prints a \
             secret-shaped string"
        );
        Ok(())
    }

    /// Where the hand-back holds a string shaped like a credential that
    /// [`Staging::check`] does not refuse, by file, line and pattern and
    /// never by the string: for the run's summary.
    pub fn shape_warnings(&self) -> Result<Vec<String>> {
        let mut warnings = Vec::new();
        for (name, path) in Self::files(&self.safe_outputs())? {
            let found = redact::shaped_lines(Self::open(&path)?)
                .with_context(|| format!("reading {}", path.display()))?;
            for (line, pattern) in found {
                if warnings.len() == redact::MAX_SHAPE_WARNINGS {
                    return Ok(warnings);
                }
                warnings.push(format!(
                    "{SAFE_OUTPUTS_DIR}/{name}, line {line}: matches `{pattern}`"
                ));
            }
        }
        Ok(warnings)
    }

    /// Packs the transcript into FILE.
    fn pack(&self, file: &Path) -> Result<()> {
        let failed = || format!("writing {}", file.display());
        let out = std::fs::File::create(file).with_context(failed)?;
        let encoder = zstd::Encoder::new(out, COMPRESSION_LEVEL).with_context(failed)?;
        let mut archive = tar::Builder::new(encoder);
        for (name, path) in Self::files(&self.transcript())? {
            let mut file = Self::open(&path)?;
            let size = file.size();
            let mut header = tar::Header::new_gnu();
            header.set_size(size);
            header.set_mode(FILE_MODE);
            header.set_mtime(
                std::fs::metadata(&path)
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |since| since.as_secs()),
            );
            header.set_cksum();
            // As many bytes as the header says, or the archive is corrupt.
            let mut content = (&mut file).take(size);
            archive
                .append_data(&mut header, &name, &mut content)
                .with_context(failed)?;
            ensure!(
                content.limit() == 0 && file.read(&mut [0])? == 0,
                "{} changed size while it was packed",
                path.display()
            );
        }
        let encoder = archive.into_inner().with_context(failed)?;
        encoder.finish().with_context(failed)?;
        Ok(())
    }

    /// Moves the results to where they are uploaded from. Only after
    /// [`Staging::check`], and not once STOPPED is set: a run that was
    /// told to stop publishes nothing.
    pub fn publish(&self, out: &Path, stopped: &AtomicBool) -> Result<()> {
        refuse_earlier_results(out)?;
        let [run, transcript, safe_outputs] = published(out);
        // Packed beside its place and moved there whole, so that a
        // transcript half written is never what is uploaded.
        let packed = self.root.join(TRANSCRIPT_FILE);
        self.pack(&packed)?;
        let moves = [
            (self.run(), run, true),
            (packed, transcript, true),
            (
                self.safe_outputs(),
                safe_outputs,
                !Self::files(&self.safe_outputs())?.is_empty(),
            ),
        ];
        // Packing takes its time; the moves take none.
        ensure!(!stopped.load(Ordering::SeqCst), "the run was stopped");
        let mut moved = Vec::new();
        for (from, to, wanted) in moves {
            if !wanted {
                continue;
            }
            if let Err(err) = std::fs::rename(&from, &to) {
                // All of a run's results or none: what is there to
                // upload must not be a part of them.
                for path in moved {
                    remove(path);
                }
                return Err(err)
                    .with_context(|| format!("moving {} to {}", from.display(), to.display()));
            }
            moved.push(to);
        }
        Ok(())
    }

    /// Takes back what [`Staging::publish`] moved, for a run that was
    /// stopped while it published.
    pub fn withdraw(out: &Path) {
        for path in published(out) {
            remove(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::redact::Redactor;

    fn token() -> String {
        format!("gh{}_{}", "p", "a1B2".repeat(10))
    }

    /// The first line of a private key, put together so that this file
    /// holds none.
    fn private_key() -> String {
        format!("-----BEGIN {}-----", "PRIVATE KEY")
    }

    struct Out {
        dir: tempfile::TempDir,
        staging: Staging,
    }

    impl Out {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let work = dir.path().join("work");
            std::fs::create_dir(&work).unwrap();
            let staging = Staging::create(&work).unwrap();
            std::fs::write(staging.run().join("summary.json"), "{}\n").unwrap();
            std::fs::write(staging.transcript().join("acp.jsonl"), "{\"a\":1}\n").unwrap();
            std::fs::write(staging.transcript().join("harness.json"), "{}\n").unwrap();
            Self { dir, staging }
        }

        fn out(&self) -> &Path {
            self.dir.path()
        }

        fn hand_back(&self, name: &str, content: &str) {
            std::fs::create_dir_all(self.staging.safe_outputs()).unwrap();
            std::fs::write(self.staging.safe_outputs().join(name), content).unwrap();
        }

        fn names(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(self.out())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }
    }

    /// A run nobody stopped.
    static GO: AtomicBool = AtomicBool::new(false);

    const OPEN: Gate = Gate {
        ended: true,
        fake_agent: false,
    };

    /// A run's redactor that holds one literal and replaced N strings.
    fn redactor(replaced: usize) -> Shared {
        let shared = Shared::new(Redactor::new([LITERAL]).unwrap());
        for _ in 0..replaced {
            shared.with(|redactor| redactor.redact(LITERAL).into_owned());
        }
        shared
    }

    /// A secret the run holds that has no shape.
    const LITERAL: &str = "the-run-holds-this";

    fn unpack(file: &Path) -> Vec<(String, String)> {
        let decoder = zstd::Decoder::new(std::fs::File::open(file).unwrap()).unwrap();
        let mut archive = tar::Archive::new(decoder);
        archive
            .entries()
            .unwrap()
            .map(|entry| {
                let mut entry = entry.unwrap();
                let mut content = String::new();
                entry.read_to_string(&mut content).unwrap();
                (entry.path().unwrap().display().to_string(), content)
            })
            .collect()
    }

    #[test]
    fn a_run_that_passes_is_published() {
        let out = Out::new();
        out.hand_back("outputs.jsonl", "{\"type\":\"noop\"}\n");
        out.staging.check(OPEN, &redactor(0)).unwrap();
        out.staging.publish(out.out(), &GO).unwrap();
        assert_eq!(
            out.names(),
            ["run", "safe-outputs", "transcript.tar.zst", "work"]
        );
        assert_eq!(
            unpack(&out.out().join(TRANSCRIPT_FILE)),
            [
                ("acp.jsonl".to_owned(), "{\"a\":1}\n".to_owned()),
                ("harness.json".to_owned(), "{}\n".to_owned()),
            ]
        );
        assert!(out.out().join("run/summary.json").is_file());
        assert!(out.out().join("safe-outputs/outputs.jsonl").is_file());
        // And not a second time over the first.
        let again = Staging::create(&out.out().join("work")).unwrap();
        let err = again.publish(out.out(), &GO).unwrap_err();
        assert!(format!("{err:#}").contains("earlier run"), "{err:#}");
        assert!(refuse_earlier_results(out.out()).is_err());
    }

    #[test]
    fn a_run_that_was_stopped_publishes_nothing() {
        let out = Out::new();
        let err = out
            .staging
            .publish(out.out(), &AtomicBool::new(true))
            .unwrap_err();
        assert!(format!("{err:#}").contains("was stopped"), "{err:#}");
        assert_eq!(out.names(), ["work"]);
    }

    /// With nothing handed back there is no directory to upload.
    #[test]
    fn nothing_handed_back_is_no_directory() {
        for empty_dir in [false, true] {
            let out = Out::new();
            if empty_dir {
                std::fs::create_dir(out.staging.safe_outputs()).unwrap();
            }
            out.staging.check(OPEN, &redactor(0)).unwrap();
            out.staging.publish(out.out(), &GO).unwrap();
            assert_eq!(out.names(), ["run", "transcript.tar.zst", "work"]);
            Staging::withdraw(out.out());
            assert_eq!(out.names(), ["work"]);
        }
    }

    #[test]
    fn what_the_gate_refuses() {
        type Arrange = fn(&Out);
        // (the case, what is wrong, the gate, redactions, the refusal)
        let cases: [(&str, Arrange, Gate, usize, &str); 7] = [
            (
                "a run still live at the proxy",
                |_| {},
                Gate {
                    ended: false,
                    ..OPEN
                },
                1,
                "was not ended at the inference proxy",
            ),
            (
                "a private key in the hand-back",
                |out| {
                    out.hand_back(
                        "aw-agent-run-1.patch",
                        &format!("@@ -1 +1 @@\n+{}\n", private_key()),
                    );
                },
                OPEN,
                1,
                "is in what the agent handed back, safe-outputs/aw-agent-run-1.patch, line 2",
            ),
            (
                "a private key in bytes that are not text",
                |out| {
                    let mut bytes = vec![0xff, 0xfe];
                    bytes.extend_from_slice(private_key().as_bytes());
                    std::fs::write(out.staging.run().join("condensed.log"), bytes).unwrap();
                },
                OPEN,
                1,
                "survived redaction in run/condensed.log",
            ),
            (
                "a secret of the run's own, which has no shape, in the hand-back",
                |out| out.hand_back("outputs.jsonl", &format!("{{\"k\":\"{LITERAL}\"}}\n")),
                OPEN,
                1,
                "is in what the agent handed back, safe-outputs/outputs.jsonl",
            ),
            (
                "the same in a log that is not text, which redaction skips",
                |out| {
                    let mut bytes = vec![0xff];
                    bytes.extend_from_slice(LITERAL.as_bytes());
                    std::fs::write(out.staging.transcript().join("agent-stderr.log"), bytes)
                        .unwrap();
                },
                OPEN,
                1,
                "survived redaction in transcript/agent-stderr.log",
            ),
            (
                "a link among the results",
                |out| symlink("/etc/passwd", out.staging.run().join("outcome.json")).unwrap(),
                OPEN,
                1,
                "outcome.json is not a regular file",
            ),
            (
                "a fake agent's run with nothing redacted",
                |_| {},
                Gate {
                    fake_agent: true,
                    ..OPEN
                },
                0,
                "replaced nothing in a run of the fake agent",
            ),
        ];
        for (name, arrange, gate, redactions, want) in cases {
            let out = Out::new();
            arrange(&out);
            let err = out
                .staging
                .check(gate, &redactor(redactions))
                .expect_err(name);
            assert!(format!("{err:#}").contains(want), "{name}: {err:#}");
        }
    }

    /// Redaction is what makes a transcript with a secret pass, and it
    /// leaves the hand-back alone.
    #[test]
    fn redaction_covers_results_and_transcript_only() {
        let out = Out::new();
        let line = format!("the agent printed {}\n", token());
        std::fs::write(out.staging.transcript().join("acp.jsonl"), &line).unwrap();
        std::fs::write(out.staging.run().join("condensed.log"), &line).unwrap();
        out.hand_back("outputs.jsonl", &line);
        symlink("/etc/passwd", out.staging.transcript().join("planted")).unwrap();
        let redactor = Shared::new(Redactor::new::<&str>([]).unwrap());
        out.staging.redact(&redactor).unwrap();
        assert_eq!(redactor.count(), 2);
        assert_eq!(
            std::fs::read_to_string(out.staging.transcript().join("acp.jsonl")).unwrap(),
            "the agent printed [REDACTED]\n"
        );
        assert!(!out.staging.transcript().join("planted").exists());
        assert_eq!(
            std::fs::read_to_string(out.staging.safe_outputs().join("outputs.jsonl")).unwrap(),
            line
        );
        // Left as it is, and a warning, not a refusal: the run holds no
        // credential of that shape.
        out.staging.check(OPEN, &redactor).unwrap();
        assert_eq!(
            out.staging.shape_warnings().unwrap(),
            ["safe-outputs/outputs.jsonl, line 1: matches `gh[posur]_[A-Za-z0-9_]{20,}`"]
        );
    }

    /// A fake key in a test fixture passes with a warning by line, and
    /// the run's own secret beside it is still refused.
    #[test]
    fn a_fixture_shaped_like_a_key_is_a_warning() {
        let out = Out::new();
        let patch = format!("@@ -1,2 +1,3 @@\n one\n+let key = \"{}\";\n two\n", token());
        out.hand_back("aw-agent-run-1.patch", &patch);
        out.staging.check(OPEN, &redactor(1)).unwrap();
        assert_eq!(
            out.staging.shape_warnings().unwrap(),
            ["safe-outputs/aw-agent-run-1.patch, line 3: matches `gh[posur]_[A-Za-z0-9_]{20,}`"]
        );
        out.hand_back("outputs.jsonl", &format!("{{\"k\":\"{LITERAL}\"}}\n"));
        let err = out.staging.check(OPEN, &redactor(1)).unwrap_err();
        assert!(
            format!("{err:#}").contains("safe-outputs/outputs.jsonl, line 1"),
            "{err:#}"
        );
    }

    #[test]
    fn staging_starts_empty_every_time() {
        let out = Out::new();
        assert!(out.staging.run().join("summary.json").exists());
        let again = Staging::create(&out.out().join("work")).unwrap();
        assert!(!again.run().join("summary.json").exists());
        assert!(again.transcript().is_dir());
    }
}
