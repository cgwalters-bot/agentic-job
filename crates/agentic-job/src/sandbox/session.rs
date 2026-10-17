//! Root holds a duplicate of the bridge listener until serve is revoked.
//! The control socket closes even if the supervisor is killed. In that case,
//! or if reaping failed, the sandbox still cannot take over the serve target.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Output, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, ensure};

use super::helper::{Direct, Exec};
use super::root::Root;
use crate::session::bridge::PORT;

const STEP_SECONDS: &str = "30";
const CLEANUP_GRACE: Duration = Duration::from_secs(40);
const RETRY: Duration = Duration::from_secs(1);
/// Revocations to try before only holding the port; each is bounded too.
const REVOKE_ATTEMPTS: u32 = 10;
/// `timeout`'s statuses when the command ran out of time, then also out
/// of `--kill-after`.
const TIMED_OUT: [i32; 2] = [124, 137];
const READY: u8 = 1;
pub(super) const HTTPS_DISABLED: &str =
    "the tailnet has HTTPS certificates disabled; enable them in the admin console";

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
        // The guard closes the socket on a failed start, after logging why.
        control.read_exact(&mut ready).context(
            "starting tailscale serve; the session serve guard's error, if any, is above",
        )?;
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
        || serve_command(&["--bg", "--yes", "--https=443", &target]).and_then(|out| started(&out)),
        || serve_command(&["--https=443", "off"]).and_then(|out| revoked(&out)),
    )
}

fn serve_with(
    listener: TcpListener,
    mut control: UnixStream,
    start: impl FnOnce() -> Result<()>,
    revoke: impl FnMut() -> Result<()>,
) -> Result<()> {
    let started = start();
    match &started {
        Ok(()) => {
            if control.write_all(&[READY]).is_ok() {
                let _ = control.read(&mut [0]);
            }
        }
        // Log now, since cleanup may never end, and let the supervisor fail
        // at once instead of timing out on a read with no cause. Shut the
        // socket down rather than drop it: `serve` duplicated it from stdout,
        // which still holds it open. A failure leaves only the read timeout.
        Err(error) => {
            log(&format!("session: {error:#}"));
            let _ = control.shutdown(std::net::Shutdown::Both);
        }
    }
    revoke_while_holding(listener, revoke);
    started
}

fn serve_command(args: &[&str]) -> Result<Output> {
    let mut argv = vec![
        "timeout",
        "--kill-after=5",
        STEP_SECONDS,
        "tailscale",
        "serve",
    ];
    argv.extend_from_slice(args);
    Direct
        .command(&argv)?
        .stdin(Stdio::null())
        .output()
        .context("running tailscale serve")
}

fn started(out: &Output) -> Result<()> {
    // Tailscale waits for the HTTPS node capability, which a tailnet with
    // HTTPS certificates disabled never grants; setup checks this first, so
    // this is for a tailnet changed in between.
    let hint = if out
        .status
        .code()
        .is_some_and(|code| TIMED_OUT.contains(&code))
    {
        format!("; it timed out after {STEP_SECONDS}s, as it does when {HTTPS_DISABLED}")
    } else {
        String::new()
    };
    ensure!(
        out.status.success(),
        "tailscale serve failed ({}){hint}: {}",
        out.status,
        printed(out)
    );
    Ok(())
}

fn revoked(out: &Output) -> Result<()> {
    // A start that failed or timed out may have added no handler: off
    // already. Only Tailscale's own refusal counts, since anything looser
    // could release the port while serve still forwards to it.
    let absent = String::from_utf8_lossy(&out.stderr).lines().any(|line| {
        let line = line.trim();
        line.starts_with("error:") && line.ends_with(": handler does not exist")
    });
    ensure!(
        out.status.success() || absent,
        "tailscale serve off failed ({}): {}",
        out.status,
        printed(out)
    );
    Ok(())
}

/// What the command printed: Tailscale explains a missing capability on
/// standard output, and errors on standard error.
fn printed(out: &Output) -> String {
    [&out.stdout, &out.stderr]
        .map(|stream| String::from_utf8_lossy(stream).trim().to_owned())
        .into_iter()
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn revoke_while_holding(listener: TcpListener, mut revoke: impl FnMut() -> Result<()>) {
    revoke_bounded(&mut revoke);
    drop(listener);
}

/// Returns once serve is off; after REVOKE_ATTEMPTS failures, never: serve
/// may still forward the tailnet to the bridge port, so releasing it would
/// let a surviving sandbox process take over the endpoint. No sandbox
/// process can signal this guard; the host's end kills it.
fn revoke_bounded(revoke: &mut impl FnMut() -> Result<()>) {
    for attempt in 1..=REVOKE_ATTEMPTS {
        match revoke() {
            Ok(()) => return,
            Err(error) => log(&format!(
                "session: cannot revoke serve (attempt {attempt} of {REVOKE_ATTEMPTS}); \
                 retaining the bridge port: {error:#}"
            )),
        }
        std::thread::sleep(RETRY);
    }
    log("session: giving up revoking serve; retaining the bridge port until this guard ends");
    loop {
        std::thread::park();
    }
}

fn log(message: &str) {
    // A closed CI log pipe must not panic and release the listener.
    let _ = writeln!(std::io::stderr().lock(), "{message}");
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

    fn output(code: i32, stdout: &str, stderr: &str) -> Output {
        use std::os::unix::process::ExitStatusExt;
        Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn serve_errors_carry_the_status_output_and_cause() {
        assert!(started(&output(0, "", "")).is_ok());
        for (code, stdout, stderr, wanted) in [
            (
                1,
                "",
                "error: bad port\n",
                "exit status: 1): error: bad port",
            ),
            (1, "", "", "exit status: 1): "),
            (124, "", "", "the tailnet has HTTPS certificates disabled"),
            (137, "", "", "the tailnet has HTTPS certificates disabled"),
            (
                124,
                "enable HTTPS at URL\n",
                "",
                "admin console: enable HTTPS at URL",
            ),
        ] {
            let error = format!("{:#}", started(&output(code, stdout, stderr)).unwrap_err());
            assert!(error.contains(wanted), "{error}");
            assert_eq!(error.contains("HTTPS certificates"), code != 1, "{error}");
        }
    }

    #[test]
    fn revoking_a_handler_that_does_not_exist_is_done() {
        for (code, stderr, done) in [
            (0, "", true),
            (
                1,
                "error: failed to remove web serve: handler does not exist\n",
                true,
            ),
            (
                1,
                "error: failed to remove web serve: permission denied\n",
                false,
            ),
            (
                1,
                "dial unix /run/tailscale/tailscaled.sock: socket does not exist\n",
                false,
            ),
            (1, "error: serve config does not exist\n", false),
            (124, "", false),
        ] {
            assert_eq!(revoked(&output(code, "", stderr)).is_ok(), done, "{stderr}");
        }
    }

    #[test]
    fn a_failed_start_closes_the_control_socket_at_once() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (mut supervisor, control) = UnixStream::pair().unwrap();
        // Production's stdout still holds the guard's end open.
        let stdout = control.try_clone().unwrap();
        let (release, released) = std::sync::mpsc::channel();
        let guard = std::thread::spawn(move || {
            serve_with(
                listener,
                control,
                || anyhow::bail!("scripted start failure"),
                || {
                    released.recv().unwrap();
                    Ok(())
                },
            )
        });
        // EOF while revocation is still pending, not a read timeout.
        supervisor.set_read_timeout(Some(CLEANUP_GRACE)).unwrap();
        assert_eq!(supervisor.read(&mut [0]).unwrap(), 0);
        release.send(()).unwrap();
        assert!(guard.join().unwrap().is_err());
        drop(stdout);
    }
}
