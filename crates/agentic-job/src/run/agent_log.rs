//! The agent's own log files, added to the transcript beside its standard
//! error: an agent may say only there why it ended as it did (#607).
//!
//! The directory and its files are the agent's, so they are read as the
//! sandbox user ([`Runner`]), as the hand-back is: no link is followed,
//! and what is read is bounded. Only files written since the session
//! started are taken, so that a log an earlier run or the machine's
//! image left is not passed off as this run's. They go into one file of
//! the transcript, which is redacted with the rest of it.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use super::enter::Runner;

/// The transcript's file of the agent's logs.
pub const TRANSCRIPT_NAME: &str = "agent-logs.txt";
/// The transcript's files of the run's child agent (`acp-drive`): its
/// ACP transcript and standard error, and its own logs.
pub const CHILD_SESSION_NAME: &str = "child-session.txt";
pub const CHILD_LOGS_NAME: &str = "child-logs.txt";
/// The most log files taken, the newest.
const MAX_FILES: usize = 16;
/// The most of one file taken, its end.
const MAX_FILE_BYTES: usize = 4 << 20;
/// The most of all of them taken.
const MAX_TOTAL_BYTES: usize = 16 << 20;
/// The most the listing of the directory may write.
const MAX_LISTING_BYTES: usize = 256 << 10;
const READ_TIMEOUT_S: &str = "30";
/// Lists the regular files directly in the directory `$1`, each as its
/// modification time, size and name, NUL-terminated; exits 3 if `$1` is
/// no directory, or a link to one.
const LIST_SCRIPT: &str = r#"test ! -L "$1" && test -d "$1" || exit 3
exec find "$1" -mindepth 1 -maxdepth 1 -type f -printf '%T@ %s %f\0'"#;
/// The status of LIST_SCRIPT for a directory that is not there.
const NO_DIRECTORY: i32 = 3;
/// Reads at most the last `$2` bytes of the regular file `$1`.
const TAIL_SCRIPT: &str = r#"test ! -L "$1" && test -f "$1" && exec tail -c "$2" -- "$1""#;

/// One log file the directory lists.
#[derive(Debug, PartialEq)]
struct Listed {
    modified: f64,
    size: u64,
    name: String,
}

/// The files of a listing by LIST_SCRIPT, modified at SINCE (seconds since
/// the epoch) or later, the newest MAX_FILES of them, oldest first.
fn parse_listing(listing: &[u8], since: f64) -> (Vec<Listed>, usize) {
    let mut files: Vec<Listed> = listing
        .split(|&b| b == 0)
        .filter_map(|entry| {
            let entry = std::str::from_utf8(entry).ok()?;
            let mut parts = entry.splitn(3, ' ');
            let modified = parts.next()?.parse::<f64>().ok()?;
            let size = parts.next()?.parse().ok()?;
            let name = parts.next()?;
            let plain = !name.is_empty() && name != "." && name != ".." && !name.contains('/');
            (plain && modified >= since).then(|| Listed {
                modified,
                size,
                name: name.to_owned(),
            })
        })
        .collect();
    files.sort_by(|a, b| a.modified.total_cmp(&b.modified).then(a.name.cmp(&b.name)));
    let omitted = files.len().saturating_sub(MAX_FILES);
    (files.split_off(omitted), omitted)
}

/// Writes the logs in DIR (under HOME) written since SINCE to the
/// transcript's file TO, as RUNNER reads them, and says for
/// the summary what was taken: a directory that is not there is said to
/// be missing, not an error, as is one that could not be read.
pub fn collect(
    runner: &dyn Runner,
    home: &Path,
    dir: &str,
    since: f64,
    to: &Path,
) -> Result<Value> {
    let shown = format!("~/{dir}");
    let path = home.join(dir);
    let Some(path_text) = path.to_str() else {
        return Ok(json!({"dir": shown, "missing": true}));
    };
    let listing = runner.run(
        &[
            "timeout",
            READ_TIMEOUT_S,
            "sh",
            "-c",
            LIST_SCRIPT,
            "sh",
            path_text,
        ],
        b"",
        MAX_LISTING_BYTES,
    );
    let listing = match listing {
        Ok(out) if out.success() => out.stdout,
        Ok(out) if out.status.code() == Some(NO_DIRECTORY) => {
            return Ok(json!({"dir": shown, "missing": true}));
        }
        _ => return Ok(json!({"dir": shown, "error": "the directory could not be listed"})),
    };
    let (files, omitted) = parse_listing(&listing, since);
    let mut sections = Vec::new();
    let mut left = MAX_TOTAL_BYTES;
    let mut cut = false;
    // Newest first, so that the log that says how the run ended is the
    // one kept when they are too big together; written oldest first.
    for file in files.iter().rev() {
        let max = left.min(MAX_FILE_BYTES);
        let file_path = path.join(&file.name);
        let Some(file_text) = file_path.to_str() else {
            continue;
        };
        let read = runner.run(
            &[
                "timeout",
                READ_TIMEOUT_S,
                "sh",
                "-c",
                TAIL_SCRIPT,
                "sh",
                file_text,
                &max.to_string(),
            ],
            b"",
            max,
        );
        let Ok(out) = read.map(|out| out.success().then_some(out.stdout)) else {
            continue;
        };
        let Some(content) = out else { continue };
        let read_bytes = content.len();
        let truncated = u64::try_from(read_bytes).unwrap_or(u64::MAX) < file.size;
        cut |= truncated;
        // As text: what is not UTF-8 would escape the redaction, and a cut
        // may fall inside a character.
        let content = String::from_utf8_lossy(&content);
        // A name of the agent's choosing, on its line.
        let name: String = file
            .name
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect();
        let mut section = format!(
            "==> {name}{} <==\n{content}",
            if truncated {
                format!(" (its last {read_bytes} of {} bytes)", file.size)
            } else {
                String::new()
            }
        );
        if !section.ends_with('\n') {
            section.push('\n');
        }
        sections.push(section);
        left = left.saturating_sub(read_bytes);
        if left == 0 {
            break;
        }
    }
    let taken = sections.len();
    if taken > 0 {
        sections.reverse();
        std::fs::write(to, sections.concat())
            .with_context(|| format!("writing {}", to.display()))?;
    }
    Ok(json!({
        "dir": shown,
        "files": taken,
        "omitted_files": omitted + files.len() - taken,
        "truncated": cut,
    }))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::run::enter::Unconfined;

    #[test]
    fn listings() {
        let listing =
            b"10.5 3 old.log\x0020.0 7 new log.txt\x0030.0 1 a/b\x005.0 2 stale.log\x00garbage\x00";
        let (files, omitted) = parse_listing(listing, 10.0);
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["old.log", "new log.txt"]);
        assert_eq!(omitted, 0);
        let many: Vec<u8> = (0..MAX_FILES + 2)
            .flat_map(|i| format!("{}.0 1 f{i:02}\0", 100 + i).into_bytes())
            .collect();
        let (files, omitted) = parse_listing(&many, 0.0);
        assert_eq!(omitted, 2);
        assert_eq!(files.len(), MAX_FILES);
        assert_eq!(files[0].name, "f02");
    }

    /// The logs a stub agent wrote are taken, as text, without following
    /// a link, and the end of one that is too long.
    #[test]
    fn logs_are_collected() {
        let home = tempfile::tempdir().unwrap();
        let transcript = tempfile::tempdir().unwrap();
        let secret = home.path().join("secret");
        std::fs::write(&secret, "SECRET-OF-THE-RUNNER\n").unwrap();
        let dir = home.path().join("logs");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("agent.log"), "connection reset by peer\n").unwrap();
        let mut long = vec![b'x'; MAX_FILE_BYTES];
        long.extend_from_slice(b"\xff the end\n");
        std::fs::write(dir.join("long.log"), &long).unwrap();
        symlink(&secret, dir.join("linked.log")).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/deeper.log"), "not taken\n").unwrap();

        let got = collect(
            &Unconfined,
            home.path(),
            "logs",
            0.0,
            &transcript.path().join(TRANSCRIPT_NAME),
        )
        .unwrap();
        assert_eq!(
            got,
            json!({"dir": "~/logs", "files": 2, "omitted_files": 0, "truncated": true})
        );
        let text = std::fs::read_to_string(transcript.path().join(TRANSCRIPT_NAME)).unwrap();
        assert!(
            text.contains("==> agent.log <==\nconnection reset by peer\n"),
            "{text}"
        );
        assert!(text.contains("==> long.log (its last "), "{}", &text[..200]);
        assert!(text.ends_with("\u{fffd} the end\n"));
        assert!(!text.contains("SECRET-OF-THE-RUNNER"));
        assert!(!text.contains("not taken"));

        // Only what was written since the session started.
        let later = collect(
            &Unconfined,
            home.path(),
            "logs",
            4e9,
            &transcript.path().join(TRANSCRIPT_NAME),
        )
        .unwrap();
        assert_eq!(later["files"], 0);
    }

    /// Too much together, the newest are kept, and written oldest first.
    #[test]
    fn the_newest_logs_are_kept() {
        let home = tempfile::tempdir().unwrap();
        let transcript = tempfile::tempdir().unwrap();
        let dir = home.path().join("logs");
        std::fs::create_dir(&dir).unwrap();
        let start = std::time::SystemTime::now() - std::time::Duration::from_secs(100);
        let count = MAX_TOTAL_BYTES / MAX_FILE_BYTES + 2;
        for i in 0..count {
            let file = std::fs::File::create(dir.join(format!("{i}.log"))).unwrap();
            file.set_len(u64::try_from(MAX_FILE_BYTES).unwrap())
                .unwrap();
            let when = start + std::time::Duration::from_secs(u64::try_from(i).unwrap());
            file.set_modified(when).unwrap();
        }
        let got = collect(
            &Unconfined,
            home.path(),
            "logs",
            0.0,
            &transcript.path().join(TRANSCRIPT_NAME),
        )
        .unwrap();
        let kept = MAX_TOTAL_BYTES / MAX_FILE_BYTES;
        assert_eq!(got["files"], kept);
        assert_eq!(got["omitted_files"], count - kept);
        let text = std::fs::read_to_string(transcript.path().join(TRANSCRIPT_NAME)).unwrap();
        let names: Vec<&str> = text
            .lines()
            .filter_map(|line| line.strip_prefix("==> "))
            .collect();
        let want: Vec<String> = (count - kept..count)
            .map(|i| format!("{i}.log <=="))
            .collect();
        assert_eq!(names, want);
    }

    #[test]
    fn a_missing_directory_is_said_to_be() {
        let home = tempfile::tempdir().unwrap();
        let transcript = tempfile::tempdir().unwrap();
        symlink(home.path(), home.path().join("linked")).unwrap();
        for dir in ["absent", "linked"] {
            let got = collect(
                &Unconfined,
                home.path(),
                dir,
                0.0,
                &transcript.path().join(TRANSCRIPT_NAME),
            )
            .unwrap();
            assert_eq!(got, json!({"dir": format!("~/{dir}"), "missing": true}));
        }
        assert!(!transcript.path().join(TRANSCRIPT_NAME).exists());
    }
}
