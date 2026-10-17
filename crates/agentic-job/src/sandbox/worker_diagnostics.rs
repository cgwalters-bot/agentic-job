//! The .NET diagnostic sockets of GitHub's `Runner.Worker`
//! (`sandbox.unlink-worker-diagnostics`).
//!
//! The .NET runtime binds `dotnet-diagnostic-PID-KEY-socket` in its
//! temporary directory at startup, mode 0600, for its own user. Every
//! step runs as that user, so without this any step could connect and
//! have the Worker dump its memory, with every secret of the job in it,
//! or load a library into it: Yama, which checks only ptrace attaches,
//! does not see a socket. `DOTNET_EnableDiagnostics=0` would have to be
//! in the Worker's environment when it started, which is before any step;
//! the runtime binds the socket once and never again
//! (dotnet/runtime `ds-ipc-pal-socket.c`), so setup unlinks it, and no
//! step can name it afterwards. Opening the Worker's descriptor through
//! `/proc` does not connect to a socket, and taking it with `pidfd_getfd`
//! is a ptrace attach to an ancestor, which Yama refuses.

use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};

/// The Worker's name in `/proc/PID/comm`: one Worker runs each job.
pub const WORKER_COMM: &str = "Runner.Worker";

/// Every bound Unix socket of this network namespace, with the path it
/// was bound to, still listed after the path is unlinked.
const PROC_NET_UNIX: &str = "/proc/net/unix";

/// More than a runner's host lists by far: past it the listing is
/// refused, not read in part.
const MAX_NET_UNIX_BYTES: u64 = 16 << 20;

const SOCKET_PREFIX: &str = "dotnet-diagnostic-";

const SOCKET_SUFFIX: &str = "-socket";

/// The pids of the processes named [`WORKER_COMM`] that this user sees.
fn worker_pids() -> Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc").context("listing /proc")? {
        let entry = entry.context("listing /proc")?;
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse().ok()) else {
            continue;
        };
        // A process that ended, or is hidden, is no Worker of ours.
        if fs::read_to_string(entry.path().join("comm")).is_ok_and(|c| c.trim_end() == WORKER_COMM)
        {
            pids.push(pid);
        }
    }
    Ok(pids)
}

/// The paths in `net_unix` (`/proc/net/unix`) that are the diagnostic
/// sockets of one of `pids`. The path is the last column and the only
/// one with a `/` in it; an abstract name is not a path.
fn socket_paths(net_unix: &str, pids: &[u32]) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = net_unix
        .lines()
        .filter_map(|line| line.find(" /").map(|at| &line[at + 1..]))
        .filter(|path| {
            let name = path.rsplit('/').next().unwrap_or_default();
            name.strip_prefix(SOCKET_PREFIX)
                .and_then(|rest| rest.strip_suffix(SOCKET_SUFFIX))
                .and_then(|rest| rest.split_once('-'))
                .is_some_and(|(pid, key)| {
                    !key.is_empty()
                        && key.bytes().all(|b| b.is_ascii_digit())
                        && pid.parse().is_ok_and(|pid| pids.contains(&pid))
                })
        })
        .map(PathBuf::from)
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// The Workers' diagnostic sockets that a step could still connect to:
/// those whose path is still a socket.
pub fn linked_sockets() -> Result<Vec<PathBuf>> {
    let pids = worker_pids()?;
    if pids.is_empty() {
        return Ok(Vec::new());
    }
    let mut text = String::new();
    File::open(PROC_NET_UNIX)
        .with_context(|| format!("opening {PROC_NET_UNIX}"))?
        .take(MAX_NET_UNIX_BYTES + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("reading {PROC_NET_UNIX}"))?;
    ensure!(
        text.len() as u64 <= MAX_NET_UNIX_BYTES,
        "{PROC_NET_UNIX} is over {MAX_NET_UNIX_BYTES} bytes"
    );
    let mut linked = Vec::new();
    for path in socket_paths(&text, &pids) {
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_socket() => linked.push(path),
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err).with_context(|| format!("looking at {}", path.display())),
        }
    }
    Ok(linked)
}

/// Unlinks every Worker's diagnostic socket; the Worker keeps listening
/// on a socket no one can name.
pub fn unlink() -> Result<()> {
    let linked = linked_sockets()?;
    for path in &linked {
        fs::remove_file(path).with_context(|| format!("unlinking {}", path.display()))?;
    }
    println!(
        "Unlinked {} .NET diagnostic socket(s) of {WORKER_COMM}: sandbox.unlink-worker-diagnostics",
        linked.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_workers_diagnostic_socket_is_taken() {
        let head = "0000000000000000: 00000002 00000000 00010000 0001 01 ";
        let cases = [
            ("12345 /tmp/dotnet-diagnostic-2041-98765-socket", true),
            ("    7 /tmp/x/dotnet-diagnostic-2041-1-socket", true),
            // Another process's, or a name the runtime does not make.
            ("12345 /tmp/dotnet-diagnostic-2042-98765-socket", false),
            ("12345 /tmp/dotnet-diagnostic-2041--socket", false),
            ("12345 /tmp/dotnet-diagnostic-2041-9a-socket", false),
            ("12345 /tmp/dotnet-diagnostic-2041-1-socket.bak", false),
            ("12345 /tmp/dotnet-diagnostic-20410-1-socket", false),
            ("12345 /tmp/my-dotnet-diagnostic-2041-1-socket", false),
            // An abstract name, and a socket with no name.
            ("12345 @dotnet-diagnostic-2041-1-socket", false),
            ("12345", false),
        ];
        for (rest, taken) in cases {
            let line = format!("{head}{rest}");
            let got = socket_paths(&format!("Num RefCount Protocol\n{line}\n"), &[2041, 7]);
            assert_eq!(!got.is_empty(), taken, "{line}");
        }
        let twice = format!("{head}1 /tmp/dotnet-diagnostic-7-2-socket\n").repeat(2);
        assert_eq!(
            socket_paths(&twice, &[7]),
            [PathBuf::from("/tmp/dotnet-diagnostic-7-2-socket")]
        );
        assert!(socket_paths(&twice, &[]).is_empty());
    }
}
