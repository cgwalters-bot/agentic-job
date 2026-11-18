//! A one-way stop for accidental publication, not an isolation boundary.
//!
//! The marker has one place, the agent's handback root (`out` in the
//! runner home), and one reader, `run`, which decides once, at its end,
//! whether the run is a stop (exit 5). The run action turns that into a
//! positive `outcome` that every public job requires; nothing after `run`
//! looks for a marker.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::files::{self, ReadError};

pub(crate) const FILE: &str = "security-sensitive-stop";
pub(crate) const HOME_VAR: &str = "AGENTIC_JOB_HANDBACK_HOME";
const RECORD: &[u8] = b"security-sensitive-stop-v1\n";
const POLL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    Marked,
    Invalid,
}

impl Stop {
    pub(crate) fn diagnostic(self) -> &'static str {
        match self {
            Self::Marked => {
                "Security-sensitive stop: public handback suppressed; private submission is unavailable."
            }
            Self::Invalid => "Invalid security-sensitive stop marker: public handback suppressed.",
        }
    }
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.diagnostic())
    }
}

impl std::error::Error for Stop {}

pub(crate) fn read(dir: &Path) -> Option<Stop> {
    match files::read_regular(&dir.join(FILE), RECORD.len() as u64) {
        Ok(bytes) if bytes == RECORD => Some(Stop::Marked),
        Err(ReadError::Io(err)) if err.kind() == ErrorKind::NotFound => None,
        _ => Some(Stop::Invalid),
    }
}

pub(crate) fn refuse(dir: &Path) -> Result<()> {
    if let Some(stop) = read(dir) {
        return Err(stop.into());
    }
    Ok(())
}

/// Install the fixed marker without overwriting anything. Persist atomically
/// so concurrent readers don't mistake a partially written record for invalid.
pub(crate) fn mark(dir: &Path) -> Result<()> {
    let install = || -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(RECORD)?;
        match tmp.persist_noclobber(dir.join(FILE)) {
            Ok(_) => Ok(()),
            Err(err)
                if err.error.kind() == ErrorKind::AlreadyExists
                    && read(dir) == Some(Stop::Marked) =>
            {
                Ok(())
            }
            Err(_) => bail!("could not install security-sensitive stop marker"),
        }
    };
    // Do not retain causes: an invalid marker never supplies diagnostics.
    install()
        .ok()
        .context("could not install security-sensitive stop marker")
}

/// Once seen, neither removing the marker nor changing its contents clears it.
#[derive(Debug)]
pub(crate) struct Latch {
    dir: PathBuf,
    stopped: OnceLock<Stop>,
}

impl Latch {
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            stopped: OnceLock::new(),
        }
    }

    pub(crate) fn observe(&self) -> Option<Stop> {
        if let Some(stop) = self.stopped.get() {
            return Some(*stop);
        }
        if let Some(stop) = read(&self.dir) {
            self.stopped.get_or_init(|| stop);
        }
        self.stopped.get().copied()
    }

    pub(crate) fn check(&self) -> Result<()> {
        match self.observe() {
            Some(stop) => Err(stop.into()),
            None => Ok(()),
        }
    }

    pub(crate) async fn wait(&self) -> Stop {
        loop {
            if let Some(stop) = self.observe() {
                return stop;
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_stop_marker_is_bounded_and_sticky() {
        for (bytes, expected) in [
            (Some(RECORD), Stop::Marked),
            (Some(&b""[..]), Stop::Invalid),
            (
                Some(&b"synthetic marker payload that must not be quoted"[..]),
                Stop::Invalid,
            ),
            (None, Stop::Invalid),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let latch = Latch::new(dir.path().into());
            assert_eq!(latch.observe(), None);
            let path = dir.path().join(FILE);
            match bytes {
                Some(bytes) => std::fs::write(&path, bytes).unwrap(),
                None => std::os::unix::fs::symlink("missing", &path).unwrap(),
            }
            assert_eq!(
                refuse(dir.path()).unwrap_err().to_string(),
                expected.diagnostic()
            );
            assert_eq!(latch.observe(), Some(expected));
            std::fs::remove_file(path).unwrap();
            assert_eq!(latch.observe(), Some(expected));
        }
    }
}
