//! What secure-host's passing `sandbox check --record` leaves for the
//! next check in the same job, so that `run` does not repeat the probes
//! secure-host made a moment before on the same host.
//!
//! A record is good for one check: the next check consumes it, whether
//! it takes it or not, and `run` removes it before it lets the agent
//! run anything, since what the agent leaves behind
//! (a process, a container) is what the probes would find. No other check
//! writes one.
//!
//! The record is the runner's user's, in the job's temporary directory:
//! the sandbox user cannot write there, which the probes of the check
//! that wrote it proved (the runner's home and `RUNNER_TEMP` are closed
//! to it), and a record is taken only where those probes look: a file of
//! this user's, in a directory of its own. It names the job and the
//! binary that probed, and holds the configuration the probes passed
//! against, so a record from another job, another build (with other
//! probes) or another configuration is not taken; GitHub also empties
//! that directory at the start of every job.

use std::fs;
use std::hash::Hasher;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::files;

/// The file, in the directory `TEMP_VAR` names.
pub const FILE_NAME: &str = "agentic-job-sandbox-checked";

const TEMP_VAR: &str = "RUNNER_TEMP";

/// What says which job this is: GitHub's names for the run, its attempt
/// and the job in it.
const JOB_VARS: &[&str] = &["GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB"];

/// The configuration is a few KiB; anything much larger is not a record.
const MAX_BYTES: u64 = 1 << 20;

const MODE_PRIVATE: u32 = 0o600;

/// Write permission for the group or others.
const MODE_OTHERS_WRITE: u32 = 0o022;

/// The executable this process runs.
const SELF_EXE: &str = "/proc/self/exe";

/// Where the record of this job is, and what it says for `binary` (see
/// [`binary`]) and `config`: `None` outside a CI job that names its
/// temporary directory and itself, where there is no telling one job from
/// the next.
pub fn for_job(
    env: impl Fn(&str) -> Option<String>,
    binary: &str,
    config: &str,
) -> Option<(PathBuf, Vec<u8>)> {
    let path = path(&env)?;
    let mut content = String::new();
    for name in JOB_VARS {
        let value = env(name).filter(|value| !value.is_empty() && !value.contains('\n'))?;
        content.push_str(&format!("{name}={value}\n"));
    }
    content.push_str(&format!("binary={binary}\n\n"));
    content.push_str(config);
    Some((path, content.into_bytes()))
}

/// Where the record of a job is: `None` without an absolute temporary
/// directory.
pub fn path(env: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let dir = env(TEMP_VAR).filter(|dir| dir.starts_with('/'))?;
    Some(Path::new(&dir).join(FILE_NAME))
}

/// The version and a fingerprint of this executable's bytes: two builds
/// of one version may probe differently. Not a cryptographic digest: the
/// sandbox user cannot write the record at all, and this only keeps a
/// job that mixes builds from taking another's.
pub fn binary() -> Result<String> {
    let mut file = fs::File::open(SELF_EXE).with_context(|| format!("opening {SELF_EXE}"))?;
    let mut hasher = std::hash::DefaultHasher::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("reading {SELF_EXE}"))?;
        if read == 0 {
            break;
        }
        hasher.write(&buffer[..read]);
    }
    Ok(format!(
        "{} {:016x}",
        env!("CARGO_PKG_VERSION"),
        hasher.finish()
    ))
}

/// Whether `path` holds exactly `content`, in a directory that only this
/// user can write in and in a file of its own. Anything else, a link, a
/// file that cannot be read, or a directory of another's (where the
/// check's probes did not look: they probe the work directories that are
/// the runner's) included, is no record.
pub fn holds(path: &Path, content: &[u8]) -> bool {
    let me = rustix::process::geteuid().as_raw();
    let private = |path: &Path| {
        fs::symlink_metadata(path)
            .is_ok_and(|meta| meta.uid() == me && meta.mode() & MODE_OTHERS_WRITE == 0)
    };
    path.parent()
        .is_some_and(|dir| dir.is_absolute() && private(dir))
        && private(path)
        && files::read_regular(path, MAX_BYTES).is_ok_and(|found| found == content)
}

/// Whether `path` holds `content` (see [`holds`]), and removes it either
/// way: a record vouches for the one check that reads it next.
pub fn take(path: &Path, content: &[u8]) -> Result<bool> {
    let held = holds(path, content);
    clear(path)?;
    Ok(held)
}

/// Removes the record, before probes whose outcome is not known yet.
pub fn clear(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(err) if err.kind() != ErrorKind::NotFound => {
            Err(err).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}

/// Writes the record after probes that all passed. A new file, never
/// through a link someone left in its place.
pub fn write(path: &Path, content: &[u8]) -> Result<()> {
    clear(path)?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(MODE_PRIVATE)
        .open(path)
        .and_then(|mut file| file.write_all(content))
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        |name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    const JOB: &[(&str, &str)] = &[
        ("RUNNER_TEMP", "/w/_temp"),
        ("GITHUB_RUN_ID", "7"),
        ("GITHUB_RUN_ATTEMPT", "1"),
        ("GITHUB_JOB", "agent"),
    ];

    #[test]
    fn a_record_names_its_job() {
        let (path, content) = for_job(env(JOB), "0.1 ab", "[sandbox]\n").unwrap();
        assert_eq!(path, Path::new("/w/_temp").join(FILE_NAME));
        assert_eq!(
            String::from_utf8(content).unwrap(),
            "GITHUB_RUN_ID=7\nGITHUB_RUN_ATTEMPT=1\nGITHUB_JOB=agent\nbinary=0.1 ab\n\n[sandbox]\n"
        );
        // Without any of these there is no telling this job from another.
        for (missing, replaced) in [
            ("RUNNER_TEMP", None),
            ("RUNNER_TEMP", Some("relative")),
            ("GITHUB_RUN_ID", None),
            ("GITHUB_RUN_ATTEMPT", Some("")),
            ("GITHUB_JOB", Some("agent\nGITHUB_JOB=other")),
        ] {
            let vars: Vec<(&str, &str)> = JOB
                .iter()
                .filter_map(|&(key, value)| {
                    if key != missing {
                        Some((key, value))
                    } else {
                        replaced.map(|other| (key, other))
                    }
                })
                .collect();
            assert!(
                for_job(env(&vars), "0.1 ab", "").is_none(),
                "{missing} {replaced:?}"
            );
        }
    }

    #[test]
    fn only_the_same_job_and_configuration_match() {
        let dir = tempfile::tempdir().unwrap();
        let temp = dir.path().to_str().unwrap();
        let vars = |job: &'static str| -> Vec<(&str, &str)> {
            vec![
                ("RUNNER_TEMP", temp),
                ("GITHUB_RUN_ID", "7"),
                ("GITHUB_RUN_ATTEMPT", "1"),
                ("GITHUB_JOB", job),
            ]
        };
        let job = vars("agent");
        let (path, content) = for_job(env(&job), "0.1 ab", "a = 1\n").unwrap();
        assert!(!holds(&path, &content));
        write(&path, &content).unwrap();
        assert!(holds(&path, &content));
        let other_config = for_job(env(&job), "0.1 ab", "a = 2\n").unwrap().1;
        let other_binary = for_job(env(&job), "0.1 cd", "a = 1\n").unwrap().1;
        let other = vars("other");
        let other_job = for_job(env(&other), "0.1 ab", "a = 1\n").unwrap().1;
        for content in [other_config, other_binary, other_job] {
            assert!(!holds(&path, &content));
        }
        // Written again, the record replaces the old one.
        write(&path, &content).unwrap();
        assert!(holds(&path, &content));
        clear(&path).unwrap();
        assert!(!holds(&path, &content));
        clear(&path).unwrap();
        // Taken once, a record is gone: the check after the one that took
        // it probes again.
        write(&path, &content).unwrap();
        for held in [true, false] {
            assert_eq!(take(&path, &content).unwrap(), held);
            assert!(!holds(&path, &content));
        }
        // One that does not match is consumed too.
        write(&path, &content).unwrap();
        assert!(!take(&path, b"other").unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn the_record_is_in_the_jobs_temporary_directory() {
        for (temp, path) in [
            (
                Some("/w/_temp"),
                Some("/w/_temp/agentic-job-sandbox-checked"),
            ),
            (Some("relative"), None),
            (Some(""), None),
            (None, None),
        ] {
            let vars: Vec<(&str, &str)> =
                temp.map(|temp| ("RUNNER_TEMP", temp)).into_iter().collect();
            assert_eq!(super::path(env(&vars)), path.map(PathBuf::from), "{temp:?}");
        }
    }

    #[test]
    fn the_binary_is_named_by_its_version_and_bytes() {
        let binary = binary().unwrap();
        assert_eq!(binary, super::binary().unwrap());
        let (version, fingerprint) = binary.split_once(' ').unwrap();
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
        assert_eq!(fingerprint.len(), 16, "{fingerprint}");
    }

    #[test]
    fn a_link_is_no_record_and_is_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let (target, path) = (dir.path().join("target"), dir.path().join(FILE_NAME));
        fs::write(&target, b"record").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(!holds(&path, b"record"));
        write(&path, b"new").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"record");
        assert!(holds(&path, b"new"));
    }

    #[test]
    fn a_directory_others_can_write_in_holds_no_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        write(&path, b"record").unwrap();
        for (mode, held) in [
            (0o700, true),
            (0o775, false),
            (0o1777, false),
            (0o755, true),
        ] {
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(holds(&path, b"record"), held, "{mode:o}");
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(!holds(&path, b"record"));
    }
}
