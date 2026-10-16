//! The egress proxy's log of what the sandbox user reached and what it
//! was refused, for the transcript and the summary. The proxy and its
//! log are `sandbox setup`'s; `run` only reads the part of the log that
//! is this run's, from where it stood when the run began: what came
//! before is `sandbox check`'s probes.
//!
//! The log is root's and the proxy's, so it is read through
//! [`crate::sandbox::root::Root`], as everything root does for a run. A
//! machine without the proxy has no log, and the transcript then has no
//! `access.log`.

use std::collections::BTreeMap;
use std::io::{BufRead, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

pub use crate::sandbox::egress::ACCESS_LOG;
use crate::sandbox::root::Root;
/// What the log is called in the transcript, as in the old tree.
pub const TRANSCRIPT_NAME: &str = "access.log";
/// The most of the log one run's transcript takes.
const MAX_LOG_BYTES: u64 = 256 << 20;
const DECISION_DENY: &str = "deny";

/// The size of LOG now, to take later only what was added since. Zero
/// without one. The proxy's log is root's: ROOT is asked for its size
/// where this process may not read it.
pub fn offset(log: &Path, root: Root) -> u64 {
    match std::fs::metadata(log) {
        Ok(meta) => meta.len(),
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            root.egress_log_size().ok().flatten().unwrap_or(0)
        }
        Err(_) => 0,
    }
}

/// Copies what READER gives, up to the cap, to DEST.
fn copy(reader: impl Read, dest: &Path) -> Result<u64> {
    let mut out =
        std::fs::File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
    let copied = std::io::copy(&mut reader.take(MAX_LOG_BYTES), &mut out)
        .and_then(|copied| out.flush().map(|()| copied))
        .with_context(|| format!("writing {}", dest.display()))?;
    Ok(copied)
}

/// Copies LOG from byte OFFSET on to DEST. Returns whether there is a
/// log at all.
pub fn collect(log: &Path, offset: u64, dest: &Path, root: Root) -> Result<bool> {
    match std::fs::File::open(log) {
        Ok(mut file) => {
            file.seek(SeekFrom::Start(offset))
                .with_context(|| format!("reading {}", log.display()))?;
            copy(file, dest)?;
            return Ok(true);
        }
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
        // The proxy's own directory: only root looks into it.
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {}
        Err(err) => return Err(err).with_context(|| format!("reading {}", log.display())),
    }
    if root.egress_log_size()?.is_none() {
        return Ok(false);
    }
    let mut child = root.egress_log(offset)?;
    let copied = child
        .stdout
        .take()
        .context("the log's reader has no output")
        .and_then(|stdout| copy(stdout, dest));
    // More of it than is taken is not waited for.
    let capped = !matches!(copied, Ok(copied) if copied < MAX_LOG_BYTES);
    if capped {
        let _ = child.kill();
    }
    let status = child.wait().context("waiting for the log's reader")?;
    copied?;
    ensure!(
        status.success() || capped,
        "reading {} as root failed ({status})",
        log.display()
    );
    Ok(true)
}

/// `summary.json`'s `egress_denied`: the requests the proxy refused, per
/// host, the most refused first.
pub fn denied(log: impl BufRead) -> Vec<Value> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for line in log.split(b'\n').map_while(Result::ok) {
        let Ok(entry) = serde_json::from_slice::<Value>(&line) else {
            continue;
        };
        if let (Some(DECISION_DENY), Some(host)) =
            (entry["decision"].as_str(), entry["host"].as_str())
        {
            *counts.entry(host.to_owned()).or_default() += 1;
        }
    }
    let mut counts: Vec<_> = counts.into_iter().collect();
    // Among hosts refused as often, by name, which the map gave.
    counts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    counts
        .into_iter()
        .map(|(domain, count)| json!({"domain": domain, "count": count}))
        .collect()
}

/// As [`denied`], of the copy of the log at PATH; nothing without one.
pub fn denied_in(path: &Path) -> Vec<Value> {
    std::fs::File::open(path)
        .map(|file| denied(std::io::BufReader::new(file)))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_counted_per_host() {
        let log = concat!(
            "{\"decision\":\"deny\",\"host\":\"b.example\",\"method\":\"POST\"}\n",
            "{\"decision\":\"allow\",\"host\":\"ok.example\"}\n",
            "not json\n",
            "{\"decision\":\"deny\",\"host\":\"a.example\"}\n",
            "{\"decision\":\"deny\",\"host\":\"z.example\"}\n",
            "{\"decision\":\"deny\",\"host\":7}\n",
            "\u{ff}\u{fe}\n",
            "{\"decision\":\"deny\",\"host\":\"z.example\"}",
        );
        assert_eq!(
            denied(log.as_bytes()),
            [
                json!({"domain": "z.example", "count": 2}),
                json!({"domain": "a.example", "count": 1}),
                json!({"domain": "b.example", "count": 1}),
            ]
        );
        assert!(denied(&b""[..]).is_empty());
        assert!(denied_in(Path::new("/nonexistent/access.log")).is_empty());
    }

    /// Only what the log gained since the run began is the run's.
    #[test]
    fn the_log_is_taken_from_where_it_stood() {
        let dir = tempfile::tempdir().unwrap();
        let (log, dest) = (
            dir.path().join("access.jsonl"),
            dir.path().join("access.log"),
        );
        let root = Root::Sudo;
        assert_eq!(offset(&log, root), 0);
        assert!(!collect(&log, 0, &dest, root).unwrap());
        assert!(!dest.exists());

        let before = "{\"decision\":\"deny\",\"host\":\"probe.example\"}\n";
        let during = "{\"decision\":\"deny\",\"host\":\"run.example\"}\n";
        std::fs::write(&log, before).unwrap();
        let from = offset(&log, root);
        assert_eq!(from, u64::try_from(before.len()).unwrap());
        std::fs::write(&log, format!("{before}{during}")).unwrap();
        assert!(collect(&log, from, &dest, root).unwrap());
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), during);
        assert_eq!(
            denied_in(&dest),
            [json!({"domain": "run.example", "count": 1})]
        );
        // A log that was replaced by a shorter one gives nothing.
        std::fs::write(&log, "x").unwrap();
        assert!(collect(&log, from, &dest, root).unwrap());
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "");
    }
}
