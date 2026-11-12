//! The probes of the runner's own user: that `sandbox setup` took root
//! away from it, and left it the helper and nothing else.
//!
//! The runner's user is the one every step after setup runs as, the
//! supervisor included, so it is the one a flaw in the supervisor would
//! hand to the agent. These probes try, as that user, each way it had to
//! root before the lock, and some it never should have had.

use std::io::ErrorKind;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use super::{Checker, Want};
use crate::host;
use crate::setup::{self, RootGroup};

/// Where the kernel lists a process's groups.
const PROC_STATUS: &str = "/proc/self/status";

/// pkexec refuses a caller whose parent is PID 1, so it is tried from a
/// shell, as an agent would. The `&&` keeps the shell from replacing
/// itself with it.
const PKEXEC_FROM_A_SHELL: &str = "pkexec true && true";

/// The file only root and its group read, which is what membership of
/// `shadow` opens.
const SHADOW: &str = "/etc/shadow";

/// Where the block devices are listed.
const SYS_BLOCK: &str = "/sys/block";

/// The names of the groups with ids GIDS, from the user database.
fn group_names(gids: &[u32]) -> Vec<String> {
    gids.iter()
        .map(|gid| {
            let out = Command::new("getent")
                .args(["group", &gid.to_string()])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output();
            match out {
                Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .to_owned(),
                _ => gid.to_string(),
            }
        })
        .collect()
}

/// The `Groups:` line of a process's status, as gids.
fn groups_in(status: &str) -> Vec<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .map(|line| {
            line.split_whitespace()
                .filter_map(|gid| gid.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The lines of `sudo -l` that are rules: those in parentheses, after
/// the heading, with their spacing normalized.
pub(crate) fn sudo_rules(listing: &str) -> Vec<String> {
    listing
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('('))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

/// Whether connecting to the Unix socket at PATH is refused, for want of
/// a listener or of permission alike. A refusal is what the probes want;
/// a connection is what they must not get.
fn socket_closed(path: &str) -> bool {
    match UnixStream::connect(path) {
        Ok(_) => false,
        Err(err) => matches!(
            err.kind(),
            ErrorKind::NotFound | ErrorKind::ConnectionRefused | ErrorKind::PermissionDenied
        ),
    }
}

impl Checker<'_> {
    /// The runner's user: no sudo but the helper's one rule, no polkit
    /// action, no `su`, and nothing left of the groups that are root by
    /// another name.
    pub(super) fn runner_privileges(&mut self) -> Result<()> {
        let runner = self.runner.name.clone();
        let got = host::succeeds(Command::new("sudo").args(["-n", "true"]));
        self.report.expect(
            Want::Fail,
            "runner-sudo",
            format!("{runner} has no sudo but the helper"),
            got,
        );
        // sudo's own answer to the question, before running anything:
        // `-l COMMAND` succeeds only for a command the rules allow.
        let truth = host::find_program("true").context("no true on this host")?;
        let got = host::succeeds(Command::new("sudo").args(["-n", "-l"]).arg(&truth));
        self.report.expect(
            Want::Fail,
            "runner-sudo-list",
            format!("sudo says {runner} may not run {}", truth.display()),
            got,
        );
        // sudo lists every rule that matches, the image's grant among
        // them; the last one listed is the one that counts, so what must
        // hold is that the listing ends with the deny rule and the helper's.
        let listing = Command::new("sudo")
            .args(["-n", "-l"])
            .stdin(Stdio::null())
            .output()
            .context("running sudo -l")?;
        let rules = sudo_rules(&String::from_utf8_lossy(&listing.stdout));
        let want = setup::runner_sudo_rules();
        self.report.expect(
            Want::Succeed,
            "runner-sudo-rules",
            format!(
                "sudo's rules for {runner} end with the deny rule and the helper's (it lists: {})",
                if rules.is_empty() {
                    "nothing".to_owned()
                } else {
                    rules.join("; ")
                }
            ),
            listing.status.success() && rules.ends_with(&want),
        );

        if host::has_program("pkexec") {
            let got = host::succeeds(Command::new("sh").args(["-c", PKEXEC_FROM_A_SHELL]));
            self.report.expect(
                Want::Fail,
                "runner-pkexec",
                format!("{runner} is refused by polkit (pkexec)"),
                got,
            );
        }
        // run0 is polkit's too: the helper runs it as root, and the runner's
        // user must not get it any other way.
        let got = host::succeeds(Command::new("run0").args(["--no-ask-password", "true"]));
        self.report.expect(
            Want::Fail,
            "runner-run0",
            format!("{runner} is refused by polkit (run0)"),
            got,
        );

        if host::has_program("su") {
            self.report.expect(
                Want::Succeed,
                "runner-su-control",
                "su is a program that runs (control)",
                host::succeeds(Command::new("su").arg("--version")),
            );
            // With no terminal and no input there is no password to give,
            // and root's is locked besides.
            let got = host::succeeds(Command::new("su").args(["-c", "true", "root"]));
            self.report.expect(
                Want::Fail,
                "runner-su",
                format!("{runner} can't become root with su"),
                got,
            );
        }

        self.runner_groups()
    }

    /// What the groups the runner's processes carry open, closed: a
    /// process keeps its groups whatever the user database says later,
    /// so the lock closes what each group leads to, and this tries it.
    fn runner_groups(&mut self) -> Result<()> {
        let runner = self.runner.name.clone();
        let status = std::fs::read_to_string(PROC_STATUS)
            .with_context(|| format!("reading {PROC_STATUS}"))?;
        let groups = group_names(&groups_in(&status));
        self.report.expect(
            Want::Succeed,
            "runner-groups-control",
            format!("{runner} lists its groups ({})", groups.join(" ")),
            !groups.is_empty(),
        );
        let root_groups: Vec<&RootGroup> = setup::ROOT_GROUPS
            .iter()
            .filter(|group| groups.iter().any(|name| name == group.name))
            .collect();
        let needs_socket_control = root_groups.iter().any(|group| !group.sockets.is_empty());
        if needs_socket_control {
            // A listener of ours, which the runner's user must reach: the
            // same attempt the probes expect to fail.
            let path = format!("/tmp/secure-host-{}-runner.sock", self.canary);
            let listener = UnixListener::bind(&path).context("listening on a socket in /tmp")?;
            let reached = !socket_closed(&path);
            drop(listener);
            let _ = std::fs::remove_file(&path);
            self.report.expect(
                Want::Succeed,
                "runner-socket-control",
                format!("{runner} connects to a Unix socket opened for it (control)"),
                reached,
            );
        }
        for group in root_groups {
            let open: Vec<&str> = group
                .sockets
                .iter()
                .copied()
                .filter(|socket| !socket_closed(socket))
                .collect();
            let mut failed = !open.is_empty();
            let mut what = if open.is_empty() {
                format!(
                    "{runner} is in {}, and {} is closed to it",
                    group.name, group.grants
                )
            } else {
                format!(
                    "{runner} is in {}, and connects to {}",
                    group.name,
                    open.join(", ")
                )
            };
            if group.name == setup::DISK_GROUP {
                let writable = block_devices_writable()?;
                failed = failed || !writable.is_empty();
                what = if writable.is_empty() {
                    format!(
                        "{runner} is in {}, and can't write a block device",
                        group.name
                    )
                } else {
                    format!(
                        "{runner} is in {}, and can write {}",
                        group.name,
                        writable.join(", ")
                    )
                };
            }
            if group.name == setup::SHADOW_GROUP {
                let readable = std::fs::read(SHADOW).is_ok();
                failed = failed || readable;
                what = format!(
                    "{runner} is in {}, and {} read {SHADOW}",
                    group.name,
                    if readable { "can" } else { "can't" }
                );
            }
            self.report.expect(
                Want::Fail,
                &format!("runner-group:{}", group.name),
                what,
                failed,
            );
        }
        let read_only: Vec<&String> = groups
            .iter()
            .filter(|name| setup::READ_ONLY_GROUPS.contains(&name.as_str()))
            .collect();
        if !read_only.is_empty() {
            let names: Vec<&str> = read_only.iter().map(|name| name.as_str()).collect();
            self.report.note(&format!(
                "{runner} is in {}, which reads the host's logs: not root, and left as it is",
                names.join(", ")
            ));
        }
        Ok(())
    }
}

/// The block devices this process can open for writing.
fn block_devices_writable() -> Result<Vec<String>> {
    let Ok(entries) = std::fs::read_dir(SYS_BLOCK) else {
        return Ok(Vec::new());
    };
    let mut writable = Vec::new();
    for entry in entries.flatten() {
        let device = Path::new("/dev").join(entry.file_name());
        let is_block =
            std::fs::metadata(&device).is_ok_and(|meta| meta.file_type().is_block_device());
        if is_block
            && std::fs::OpenOptions::new()
                .write(true)
                .open(&device)
                .is_ok()
        {
            writable.push(device.display().to_string());
        }
    }
    Ok(writable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudo_listings_are_read_as_rules() {
        let listing = "Matching Defaults entries for runner on host:\n    env_reset, secure_path=/usr/bin\n\nUser runner may run the following commands on host:\n    (ALL : ALL) !ALL\n    (root) NOPASSWD: /usr/local/libexec/agentic-job   helper *\n";
        assert_eq!(
            sudo_rules(listing),
            [
                "(ALL : ALL) !ALL",
                "(root) NOPASSWD: /usr/local/libexec/agentic-job helper *"
            ]
        );
        assert!(sudo_rules("Sorry, user runner may not run sudo on host.\n").is_empty());
    }

    #[test]
    fn groups_of_a_status_file() {
        let status = "Name:\tcat\nUid:\t1001\t1001\t1001\t1001\nGid:\t1001\nGroups:\t4 27 118 1001 \nNStgid:\t5\n";
        assert_eq!(groups_in(status), [4, 27, 118, 1001]);
        assert!(groups_in("Name:\tcat\n").is_empty());
        assert!(groups_in("Groups:\t\n").is_empty());
    }

    #[test]
    fn a_socket_nobody_listens_on_is_closed() {
        assert!(socket_closed("/nonexistent/agentic-job.sock"));
    }
}
