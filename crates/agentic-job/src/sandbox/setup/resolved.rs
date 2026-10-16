//! `sandbox.close-resolved`: systemd-resolved answers any local user over
//! its Varlink socket and the system bus, and asks upstream as itself, so
//! the network rules on the sandbox user's uids do not stop it sending
//! names out (`<data>.attacker.example`) around the egress proxy. Its stub
//! on loopback's port 53 is closed by those rules already.
//!
//! Both ways in are closed by who may connect, not by uid ranges, so
//! that the sandbox user's subordinate uids in a container, which have
//! no names, are refused as well: the sockets lose other users' access
//! (the runner's too: they are resolved's own and its group's), and a bus
//! policy refuses calls to resolved by default and allows them to root
//! and the runner's user. Both are set up where resolved is not running
//! yet as well, since the bus or a socket would start it, and drop-ins
//! keep the sockets closed when they are made again. Glibc's lookups through nsswitch's
//! `dns` go to the stub and need neither (Ubuntu's runner image has no
//! `resolve` there).

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};

use super::{MODE_FILE, install_file};
use crate::sandbox::host;

pub const UNIT: &str = "systemd-resolved.service";

/// Where resolved's Varlink sockets are, beside its `resolv.conf` files,
/// which every user still reads.
const SOCKET_DIR: &str = "/run/systemd/resolve";

pub const VARLINK_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve";

pub const BUS_NAME: &str = "org.freedesktop.resolve1";

/// After the packages' policies in `/usr/share/dbus-1/system.d`, so that
/// its default-context deny comes after resolved's own allow, and the
/// last matching rule wins; user policies apply after every default.
pub const BUS_POLICY: &str = "/etc/dbus-1/system.d/agentic-job-resolved.conf";

/// The upstream servers resolved's stub forwards to.
pub const UPSTREAM_RESOLV_CONF: &str = "/run/systemd/resolve/resolv.conf";

const OTHER_ACCESS: u32 = 0o007;

/// Where the drop-ins that keep resolved's sockets closed go: above the
/// packages' units, so a restart, by setup's own package installs or
/// anything else, makes them again without other users' access.
const DROP_IN_DIR: &str = "/etc/systemd/system";

const DROP_IN: &str = "agentic-job-close-resolved.conf";

/// Whether resolved is running or can start. Inactive is not
/// absent: a call on the bus or a connection to one of its sockets
/// starts it.
pub fn startable() -> Result<bool> {
    let state = host::run(Command::new("systemctl").args([
        "show",
        "--property=LoadState,ActiveState",
        "--",
        UNIT,
    ]))
    .context("inspecting systemd-resolved state")?;
    needs_closure(&state)
}

fn needs_closure(state: &str) -> Result<bool> {
    let property = |name| state.lines().find_map(|line| line.strip_prefix(name));
    let load = property("LoadState=").context("missing resolved LoadState")?;
    let active = property("ActiveState=").context("missing resolved ActiveState")?;
    ensure!(
        !load.is_empty() && !active.is_empty(),
        "empty resolved state"
    );
    // A mask prevents activation, but does not stop an existing instance.
    Ok(!matches!(load, "not-found" | "masked") || !matches!(active, "inactive" | "failed"))
}

fn require_socket_activation(version: &str) -> Result<()> {
    ensure!(
        super::systemd_version(version).is_some_and(|v| v >= 258),
        "sandbox.close-resolved requires systemd 258 or newer: older resolved publishes its own Varlink socket before permissions can be restricted"
    );
    Ok(())
}

/// The bus policy that leaves resolved to root and `runner`.
pub fn bus_policy(runner: &str) -> Result<String> {
    // It goes into XML: a name of the portable set needs no escaping.
    ensure!(
        !runner.is_empty()
            && runner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        "the runner user {runner:?} cannot be named in a bus policy"
    );
    Ok(format!(
        r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<!-- agentic-job sandbox setup: sandbox.close-resolved -->
<busconfig>
  <policy context="default">
    <deny send_destination="{BUS_NAME}"/>
  </policy>
  <policy user="root">
    <allow send_destination="{BUS_NAME}"/>
  </policy>
  <policy user="{runner}">
    <allow send_destination="{BUS_NAME}"/>
  </policy>
</busconfig>
"#
    ))
}

/// The drop-in that keeps a socket unit's mode, `mode` (`0666`), without
/// other users' access.
fn socket_drop_in(mode: &str) -> Result<String> {
    let mode = u32::from_str_radix(mode, 8)
        .ok()
        .filter(|mode| *mode <= super::MODE_BITS)
        .with_context(|| format!("reading the socket mode {mode:?}"))?;
    Ok(format!(
        "# agentic-job sandbox setup: sandbox.close-resolved\n[Socket]\nSocketMode={:04o}\n",
        mode & !OTHER_ACCESS
    ))
}

fn install_drop_in(unit: &str, content: &str) -> Result<()> {
    let dir = Path::new(DROP_IN_DIR).join(format!("{unit}.d"));
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    install_file(&dir.join(DROP_IN), content.as_bytes(), MODE_FILE, None)
}

/// Closes resolved's bus name to every user but root and `runner`, and
/// its sockets to every user but root, wherever it may run, now and
/// when it or its sockets start again.
pub fn close(runner: &str) -> Result<()> {
    if !startable()? {
        println!(
            "sandbox.close-resolved: {UNIT} is absent or masked and stopped, so there is nothing to close"
        );
        return Ok(());
    }
    let version = host::run(Command::new("systemctl").arg("--version"))?;
    require_socket_activation(&version)?;
    install_file(
        Path::new(BUS_POLICY),
        bus_policy(runner)?.as_bytes(),
        MODE_FILE,
        None,
    )?;
    // Answered once the bus has read the policy, dbus-daemon and
    // dbus-broker alike. The bus checks it before it activates the
    // service, so a call does not start resolved either.
    host::run(Command::new("busctl").args([
        "call",
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "ReloadConfig",
    ]))
    .context("reloading the system bus's policy")?;
    let triggers = host::run(Command::new("systemctl").args([
        "show",
        "--property=TriggeredBy",
        "--value",
        "--",
        UNIT,
    ]))?;
    for socket in triggers
        .split_whitespace()
        .filter(|u| u.ends_with(".socket"))
    {
        let mode = host::run(Command::new("systemctl").args([
            "show",
            "--property=SocketMode",
            "--value",
            "--",
            socket,
        ]))?;
        install_drop_in(socket, &socket_drop_in(&mode)?)?;
    }
    host::run(Command::new("systemctl").arg("daemon-reload"))?;
    // The sockets there now keep their inodes until they are made again.
    let mut closed = Vec::new();
    let entries = match fs::read_dir(SOCKET_DIR) {
        Ok(entries) => entries.collect::<std::io::Result<Vec<_>>>(),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err),
    }
    .with_context(|| format!("reading {SOCKET_DIR}"))?;
    for entry in entries {
        let path = entry.path();
        // Not followed: a socket in resolved's own directory, or nothing.
        let meta =
            fs::symlink_metadata(&path).with_context(|| format!("reading {}", path.display()))?;
        if meta.file_type().is_socket() {
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(meta.mode() & !OTHER_ACCESS & super::MODE_BITS),
            )
            .with_context(|| format!("closing {}", path.display()))?;
            closed.push(path.display().to_string());
        }
    }
    println!(
        "{UNIT} answers only root and {runner} on the bus ({BUS_NAME}), and only root at its sockets in {SOCKET_DIR} ({}), also when it starts again",
        closed.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_lifecycle_states() {
        for (load, active, want) in [
            ("loaded", "inactive", true),
            ("loaded", "active", true),
            ("masked", "active", true),
            ("masked", "activating", true),
            ("masked", "inactive", false),
            ("not-found", "inactive", false),
        ] {
            assert_eq!(
                needs_closure(&format!("LoadState={load}\nActiveState={active}\n")).unwrap(),
                want
            );
        }
        for state in ["", "LoadState=loaded", "LoadState=\nActiveState=inactive"] {
            assert!(needs_closure(state).is_err(), "{state:?}");
        }
    }

    #[test]
    fn refuses_racy_daemon_created_sockets() {
        for (version, allowed) in [(257, false), (258, true), (259, true)] {
            assert_eq!(
                require_socket_activation(&format!("systemd {version}")).is_ok(),
                allowed
            );
        }
        assert!(require_socket_activation("").is_err());
    }

    #[test]
    fn bus_policy_names_only_plain_users() {
        let policy = bus_policy("runner").unwrap();
        assert!(policy.contains(r#"<policy user="runner">"#), "{policy}");
        assert!(
            policy.contains(&format!(r#"<deny send_destination="{BUS_NAME}"/>"#)),
            "{policy}"
        );
        for bad in ["", "a\"b", "a<b", "a b", "a&b"] {
            assert!(bus_policy(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn socket_modes_lose_other_access() {
        let cases = [
            ("0666", Some("0660")),
            ("0600", Some("0600")),
            ("666", Some("0660")),
            ("", None),
            ("0o666", None),
            ("17777", None),
        ];
        for (mode, want) in cases {
            let got = socket_drop_in(mode).ok();
            let want = want.map(|mode| format!("\n[Socket]\nSocketMode={mode}\n"));
            assert_eq!(
                got.as_deref()
                    .and_then(|text| text.find('\n').map(|i| &text[i..])),
                want.as_deref(),
                "{mode:?}"
            );
        }
    }
}
