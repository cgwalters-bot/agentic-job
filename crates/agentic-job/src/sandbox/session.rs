//! Root holds a duplicate of the bridge listener until serve is revoked.
//! The control socket closes even if the supervisor is killed. In that case,
//! or if reaping failed, the sandbox still cannot take over the serve target.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, ensure};

use super::helper::{Direct, Exec};
use super::root::Root;
use crate::session::bridge::PORT;

const STEP_SECONDS: &str = "30";
const CLEANUP_GRACE: Duration = Duration::from_secs(40);
const RETRY: Duration = Duration::from_secs(1);
const READY: u8 = 1;

pub(crate) struct Guard {
    // Dropping this socket asks root to revoke serve, including on early errors.
    control: UnixStream,
    child: Child,
}

impl Guard {
    pub(crate) fn start(listener: &TcpListener) -> Result<Self> {
        let (mut control, child_control) = UnixStream::pair()?;
        control.set_read_timeout(Some(CLEANUP_GRACE))?;
        let child = Root::session_serve_command()
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(
                listener.try_clone()?,
            )))
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(child_control)))
            // The guard must not share the supervisor's process group.
            .process_group(0)
            .spawn()
            .context("starting the trusted session serve guard")?;
        let mut ready = [0];
        control
            .read_exact(&mut ready)
            .context("starting tailscale serve")?;
        ensure!(
            ready == [READY],
            "the session serve guard did not become ready"
        );
        Ok(Self { control, child })
    }

    pub(crate) async fn close(mut self) -> Result<()> {
        self.control.shutdown(std::net::Shutdown::Both)?;
        let deadline = tokio::time::Instant::now() + CLEANUP_GRACE;
        loop {
            if let Some(status) = self.child.try_wait()? {
                ensure!(status.success(), "the session serve guard failed: {status}");
                return Ok(());
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "revoking tailscale serve timed out; root is retaining the bridge port"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// Only the fixed endpoint is configurable here. Stdin is the already bound
/// listener; stdout is a private lifetime/acknowledgement socket, not a log.
pub(super) fn serve() -> Result<()> {
    let listener = TcpListener::from(rustix::io::dup(std::io::stdin().as_fd())?);
    ensure!(
        listener.local_addr()? == (Ipv4Addr::LOCALHOST, PORT).into(),
        "session serve needs the loopback bridge listener"
    );
    let control = UnixStream::from(rustix::io::dup(std::io::stdout().as_fd())?);
    // Verify the control descriptor before publishing an endpoint.
    control
        .peer_addr()
        .context("session serve needs a control socket")?;
    let target = format!("http://127.0.0.1:{PORT}");
    serve_with(
        listener,
        control,
        || serve_command(&["--bg", "--yes", "--https=443", &target]),
        || serve_command(&["--https=443", "off"]),
    )
}

fn serve_with(
    listener: TcpListener,
    mut control: UnixStream,
    start: impl FnOnce() -> Result<()>,
    revoke: impl FnMut() -> Result<()>,
) -> Result<()> {
    let started = start();
    if started.is_ok() && control.write_all(&[READY]).is_ok() {
        let _ = control.read(&mut [0]);
    }
    // Never release the listener on a cleanup error. Root retries, outliving
    // the supervisor if necessary; no sandbox process can signal this guard.
    revoke_while_holding(listener, revoke);
    started
}

fn serve_command(args: &[&str]) -> Result<()> {
    let mut argv = vec![
        "timeout",
        "--kill-after=5",
        STEP_SECONDS,
        "tailscale",
        "serve",
    ];
    argv.extend_from_slice(args);
    let out = Direct.command(&argv)?.stdin(Stdio::null()).output()?;
    ensure!(
        out.status.success(),
        "tailscale serve: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

fn revoke_while_holding(listener: TcpListener, mut revoke: impl FnMut() -> Result<()>) {
    while let Err(error) = revoke() {
        // A closed CI log pipe must not panic and release the listener.
        let _ = writeln!(
            std::io::stderr().lock(),
            "session: cannot revoke serve; retaining the bridge port: {error:#}"
        );
        std::thread::sleep(RETRY);
    }
    drop(listener);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_eof_revokes_before_releasing_the_port() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let guard_listener = listener.try_clone().unwrap();
        let (mut supervisor, control) = UnixStream::pair().unwrap();
        let (revoking, revoked) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let guard = std::thread::spawn(move || {
            serve_with(
                guard_listener,
                control,
                || Ok(()),
                || {
                    revoking.send(()).unwrap();
                    released.recv().unwrap();
                    Ok(())
                },
            )
            .unwrap();
        });
        let mut ready = [0];
        supervisor.read_exact(&mut ready).unwrap();
        assert_eq!(ready, [READY]);
        // A killed supervisor or cancelled future drops both descriptors;
        // failed reaping means a would-be agent listener may still be alive.
        drop(listener);
        drop(supervisor);
        revoked.recv_timeout(CLEANUP_GRACE).unwrap();
        assert!(TcpListener::bind(address).is_err());
        release.send(()).unwrap();
        guard.join().unwrap();
        assert!(TcpListener::bind(address).is_ok());
    }

    #[test]
    fn failed_cleanup_keeps_a_surviving_agent_from_binding() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        // The supervisor's listener is gone, as after a crash or failed reap.
        let guard_listener = listener.try_clone().unwrap();
        drop(listener);
        let mut attempts = 0;
        revoke_while_holding(guard_listener, || {
            assert!(TcpListener::bind(address).is_err());
            attempts += 1;
            if attempts == 1 {
                anyhow::bail!("scripted revocation failure after a reap failure");
            }
            Ok(())
        });
        assert_eq!(attempts, 2);
        assert!(TcpListener::bind(address).is_ok());
    }
}
