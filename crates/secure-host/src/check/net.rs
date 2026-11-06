//! The probes of the runner's network: the cloud metadata service, and
//! the egress proxy's write rules under `egress.write-policy`.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};

use super::{Checker, Want};
use crate::proxy::policy::{Policy, Request};
use crate::{egress, host};

const METADATA_URL: &str = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";

/// The metadata service at its IPv6 address (EC2's), refused to the
/// runner's uids with `sandbox.deny-runner-metadata`; `-g` keeps curl from
/// reading the brackets as a glob.
const METADATA_V6: &[&str] = &["-g", "http://[fd00:ec2::254]/latest/meta-data/"];

/// With the write policy: hosts that serve a read of `/` and would take a
/// write to it, in order of preference. The probes use the first the
/// installed policy admits a read of and refuses that write to, so that a
/// domain allowlist is probed as it is rather than having to admit a
/// host for the check; github.com follows example.com since an allowlist
/// has it more often than not. Not api.github.com, whose unauthenticated
/// rate limit a hosted runner's shared address can exhaust.
const CONTROL_HOSTS: &[&str] = &["example.com", "github.com"];

/// The header the proxy puts on every refusal of its own, lowercase.
const DENIED_HEADER: &str = "x-egress-denied:";

/// Fail-closed launch variant of the existing write-policy probe. A blocked
/// unrelated TCP port does not stop direct HTTP(S) writes: require a live
/// read control and the proxy's own refusal on both transparent listeners.
/// No policy host means no evidence, not a skipped successful check.
pub fn runner_write_readiness() -> Result<()> {
    let policy = egress::installed_policy()?.with_runner_writes()?;
    write_readiness(&policy, kernel_ipv6_disabled(), readiness_request)
}

/// The only missing-family exception: IPv6 disabled at boot, not just a
/// missing route, interface sysctl, failed DNS lookup or refused remote port.
/// The read-only module parameter and a failed AF_INET6 socket creation are
/// independent evidence. Unknown evidence keeps the dual-stack requirement.
pub fn kernel_ipv6_disabled() -> bool {
    let Ok(bytes) = ipv6_boot_parameter() else {
        return false;
    };
    ipv6_disabled_evidence(&bytes, || {
        std::net::TcpListener::bind("[::1]:0").map(|_| ())
    })
}

fn ipv6_boot_parameter() -> Result<Vec<u8>> {
    let parameter = std::path::Path::new("/sys/module/ipv6/parameters/disable");
    crate::host::roots_alone(parameter)?;
    // Sysfs reports a page-sized attribute, not its short textual value.
    // Accommodate up to a 64-KiB page while keeping both stat and read caps.
    crate::files::read_regular(parameter, 64 * 1024).map_err(Into::into)
}

fn ipv6_disabled_evidence(parameter: &[u8], socket: impl FnOnce() -> std::io::Result<()>) -> bool {
    matches!(parameter.trim_ascii(), b"Y" | b"1")
        && socket().is_err_and(|err| {
            err.raw_os_error() == Some(rustix::io::Errno::AFNOSUPPORT.raw_os_error())
        })
}

fn write_readiness(
    policy: &Policy,
    ipv6_disabled: bool,
    mut request: impl FnMut(&[&str]) -> Result<String>,
) -> Result<()> {
    let host = control_host(policy)
        .context("runner write-policy readiness has no admitted read/refused POST control host")?;
    let https = format!("https://{host}/");
    // A failed read, missing curl, timeout, or origin refusal cannot count
    // as enforcement. Do not print curl's output or response headers.
    for family in ["--ipv4", "--ipv6"] {
        if family == "--ipv6" && ipv6_disabled {
            continue;
        }
        request(&direct(&[family, "--fail", &https]))
            .context("runner write-policy address-family read positive control failed")?;
        for url in [format!("http://{host}/"), https.clone()] {
            let headers = request(&direct(&[
                family,
                "-D",
                "-",
                "-X",
                "POST",
                "-d",
                "egress-check",
                &url,
            ]))
            .context("runner write-policy POST probe failed")?;
            ensure!(
                refused_by_proxy(&headers),
                "runner write-policy POST lacks the proxy's refusal"
            );
        }
    }
    Ok(())
}

/// Bounded time and bounded captured response, with neither inherited
/// credentials/proxy variables nor the user's curl settings.
fn readiness_request(argv: &[&str]) -> Result<String> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(argv[0])
        .arg("--disable")
        .args(&argv[1..])
        .env_clear()
        .env("PATH", crate::host::root_path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("running write-policy readiness curl")?;
    capture_response(&mut child)
}

fn capture_response(child: &mut std::process::Child) -> Result<String> {
    use std::io::Read;

    const MAX_RESPONSE: u64 = 64 * 1024;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .context("opening readiness response pipe")?
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > MAX_RESPONSE {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("write-policy readiness response unreadable or oversized");
    }
    let status = child
        .wait()
        .context("waiting for write-policy readiness curl")?;
    ensure!(status.success(), "write-policy readiness curl failed");
    String::from_utf8(bytes).context("write-policy readiness response is not UTF-8")
}

impl Checker<'_> {
    /// `sandbox.deny-runner-metadata`: the runner's user, the agent's,
    /// can't reach the metadata service at either address.
    pub(super) fn runner_metadata(&mut self) -> Result<()> {
        let runner = self.runner.name.clone();
        let metadata = metadata_request();
        let metadata_v6 = direct(METADATA_V6);
        let requests = [&metadata, &metadata_v6];
        let results = super::concurrently(&requests, |argv| super::runner_reaches(argv));
        let mut results = results.into_iter();
        let v4 = results.next().expect("two metadata results");
        let v6 = results.next().expect("two metadata results");
        self.report_runner_metadata(&runner, v4, v6);
        Ok(())
    }

    /// Whether `runner` reached the metadata service at its two addresses.
    fn report_runner_metadata(&mut self, runner: &str, v4: bool, v6: bool) {
        self.report.expect(
            Want::Fail,
            "runner-metadata",
            format!(
                "{runner} can't reach the instance metadata service (host.deny-runner-metadata)"
            ),
            v4,
        );
        self.report.expect(
            Want::Fail,
            "runner-metadata-v6",
            format!("{runner} can't reach the instance metadata service over IPv6 (host.deny-runner-metadata)"),
            v6,
        );
        self.report.note(&format!(
            "{runner} is refused the instance metadata service as well, so the probes of it have no control"
        ));
    }

    /// `egress.write-policy`: the runner's user, this process, with no
    /// proxy in its environment, reads a host but is refused a POST to it
    /// by the proxy itself, whose header an origin's refusal lacks. Where
    /// the installed policy admits a read of none of [`CONTROL_HOSTS`],
    /// the read has no host to be made on and is skipped; the POST, where
    /// [`control_urls`] has one, still shows the proxy holds the runner's
    /// user.
    pub(super) fn runner_write_policy(&mut self) -> Result<()> {
        let runner = self.runner.name.clone();
        let (read, post) = control_urls(&egress::installed_policy()?.with_runner_writes()?);
        if let Some(read) = read {
            let argv = control_request(&read);
            let report = &self.report;
            let reached = retried(
                std::thread::sleep,
                || try_reach(&argv),
                |line| report.note(&format!("write-policy-read: {line}")),
            );
            self.report.expect_reach(
                "write-policy-read",
                format!("{runner} reads {read} with no proxy set (egress.write-policy)"),
                reached,
            );
        } else {
            self.report.note(&format!(
                "the egress policy admits a read of none of {CONTROL_HOSTS:?} that it refuses a POST to, so write-policy-read is skipped"
            ));
        }
        let Some(url) = post else {
            self.report.note(&format!(
                "the egress policy refuses none of {CONTROL_HOSTS:?} either, so write-policy-post is skipped too"
            ));
            return Ok(());
        };
        let argv = direct(&["-D", "-", "-X", "POST", "-d", "egress-check", &url]);
        self.report.expect(
            Want::Succeed,
            "write-policy-post",
            format!("the egress proxy refuses {runner} a POST to {url} (egress.write-policy)"),
            refused_by_proxy(&super::runner_stdout(&argv)),
        );
        Ok(())
    }
}

/// The URL the write-policy probes read, if any, and the one they POST
/// to, if any, under `policy`. With no control host the POST goes over
/// plain HTTP to the first of [`CONTROL_HOSTS`] outside the allowlist,
/// which then shows only that the proxy holds the runner's user: the
/// transparent listener drops a TLS connection to such a host without a
/// response, but answers a plain request with its own refusal. With no
/// such host either (all admitted, but a write rule takes a POST to
/// each), there is nothing to probe.
fn control_urls(policy: &Policy) -> (Option<String>, Option<String>) {
    if let Some(host) = control_host(policy) {
        let url = format!("https://{host}/");
        return (Some(url.clone()), Some(url));
    }
    let refused = CONTROL_HOSTS
        .iter()
        .find(|host| !policy.connect(host).allowed);
    (None, refused.map(|host| format!("http://{host}/")))
}

/// The first of [`CONTROL_HOSTS`] that `policy` admits a read of `/` on
/// and refuses a POST to it.
fn control_host(policy: &Policy) -> Option<&'static str> {
    CONTROL_HOSTS.iter().copied().find(|host| {
        let request = |method| Request {
            method,
            host,
            path: "/",
            has_body: method == "POST",
            ..Request::default()
        };
        policy.connect(host).allowed
            && policy.request(&request("GET")).allowed
            && !policy.request(&request("POST")).allowed
    })
}

const CURL: &[&str] = &["curl", "-sS", "-o", "/dev/null"];

const NO_PROXY: &[&str] = &["--noproxy", "*"];

/// Not through the egress proxy, whatever the environment says.
fn direct<'a>(args: &[&'a str]) -> Vec<&'a str> {
    [CURL, &["-m", "30"], NO_PROXY, args].concat()
}

/// How many times a control that reaches a host outside this one tries
/// before it fails the check: a forge's or CDN's brief outage made such
/// controls fail whole runs that would have worked (agentic-job#3225).
const CONTROL_TRIES: u32 = 3;

/// The wait before the first retry, doubled before each one after it.
const CONTROL_BACKOFF: Duration = Duration::from_secs(5);

/// Each try's limit in seconds: with the waits, 45 seconds at most in all.
const CONTROL_MAX_TIME: &str = "10";

/// The most of curl's error message a failed try logs.
const MAX_DETAIL: usize = 200;

/// A control's read of `url`, not through the egress proxy, printing the
/// HTTP status, which names an origin's failure in the log.
fn control_request(url: &str) -> Vec<&str> {
    let limit = ["-m", CONTROL_MAX_TIME, "-w", "%{http_code}"];
    [CURL, &limit, NO_PROXY, &["--fail", url]].concat()
}

/// Whether `attempt` succeeded within [`CONTROL_TRIES`], `sleep`ing a
/// growing backoff between tries and `log`ging why each failed one did.
fn retried(
    mut sleep: impl FnMut(Duration),
    mut attempt: impl FnMut() -> Result<(), String>,
    mut log: impl FnMut(&str),
) -> bool {
    let mut wait = CONTROL_BACKOFF;
    for n in 1..=CONTROL_TRIES {
        let Err(why) = attempt() else {
            return true;
        };
        log(&format!("try {n} of {CONTROL_TRIES} failed: {why}"));
        if n < CONTROL_TRIES {
            sleep(wait);
            wait *= 2;
        }
    }
    false
}

/// Runs the curl `argv` as the runner's user, this process: why it
/// failed, if it did, as [`failure`] says.
fn try_reach(argv: &[&str]) -> Result<(), String> {
    let output = host::command(argv)
        .and_then(|mut command| Ok(command.stdin(Stdio::null()).output()?))
        .map_err(|err| format!("not run: {err:#}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(failure(
        output.status.code(),
        &String::from_utf8_lossy(&output.stdout),
        stderr.lines().next().unwrap_or_default(),
    ))
}

/// A failed curl's class, from its exit `code` and the HTTP status it
/// printed, then its own message, cut to [`MAX_DETAIL`]: so a log tells a
/// name that did not resolve, a refused or dropped connection, a broken
/// TLS handshake and an origin's error status apart.
fn failure(code: Option<i32>, status: &str, detail: &str) -> String {
    let class = match code {
        None => "killed".to_owned(),
        Some(6) => "dns".to_owned(),
        Some(7) => "connect".to_owned(),
        Some(28) => "timeout".to_owned(),
        Some(22) => format!("http {}", status.trim()),
        Some(35 | 51 | 53 | 54 | 58 | 59 | 60 | 64 | 66 | 77 | 80 | 82 | 83 | 90 | 91) => {
            "tls".to_owned()
        }
        Some(52 | 55 | 56) => "transfer".to_owned(),
        Some(_) => "other".to_owned(),
    };
    let detail: String = detail.chars().take(MAX_DETAIL).collect();
    match code {
        Some(code) => format!("{class} (curl exit {code}: {detail})"),
        None => format!("{class} ({detail})"),
    }
}

/// The metadata service at its IPv4 address, not through the egress
/// proxy: what the runner's user must not reach with
/// `sandbox.deny-runner-metadata`.
pub(crate) fn metadata_request() -> Vec<&'static str> {
    direct(&["-H", "Metadata:true", METADATA_URL])
}

/// Whether response headers are the egress proxy's own refusal: a 403
/// with its header, which an origin's 403 lacks.
fn refused_by_proxy(headers: &str) -> bool {
    let status = headers.lines().any(|line| {
        let mut words = line.split_whitespace();
        words
            .next()
            .is_some_and(|version| version.starts_with("HTTP/"))
            && words.next() == Some("403")
    });
    let marked = headers
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with(DENIED_HEADER));
    status && marked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_live_read_and_both_proxy_refusals() {
        let policy = Policy::parse(
            include_str!("../../../../egress/policy.toml"),
            crate::proxy::policy::ECOSYSTEMS,
        )
        .unwrap()
        .with_runner_writes()
        .unwrap();
        let denied = "HTTP/1.1 403 Forbidden\r\nx-egress-denied: policy\r\n\r\n";
        for broken in [None, Some(0), Some(1), Some(2), Some(3), Some(4), Some(5)] {
            let mut requests = Vec::new();
            let result = write_readiness(&policy, false, |argv| {
                let index = requests.len();
                requests.push(argv.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
                ensure!(broken != Some(index), "fixture connection failed");
                Ok(if index % 3 == 0 { "" } else { denied }.to_owned())
            });
            assert_eq!(result.is_ok(), broken.is_none(), "{result:?}");
            if broken.is_none() {
                assert_eq!(requests.len(), 6);
                assert!(requests[0].contains(&"--fail".to_owned()));
                assert!(requests[1].last().unwrap().starts_with("http://"));
                assert!(requests[2].last().unwrap().starts_with("https://"));
                assert!(
                    requests[..3]
                        .iter()
                        .all(|args| args.contains(&"--ipv4".to_owned()))
                );
                assert!(
                    requests[3..]
                        .iter()
                        .all(|args| args.contains(&"--ipv6".to_owned()))
                );
            }
            for argv in requests {
                assert!(argv.windows(2).any(|pair| pair == ["--noproxy", "*"]));
            }
        }
        let closed = Policy::parse(
            "[egress]\nmode = 'allowlist'\nallow = []\n",
            crate::proxy::policy::ECOSYSTEMS,
        )
        .unwrap();
        assert!(write_readiness(&closed, false, |_| panic!("no control host")).is_err());
        for origin in ["HTTP/2 200\r\n", "HTTP/1.1 403 Forbidden\r\n"] {
            assert!(write_readiness(&policy, false, |_| Ok(origin.to_owned())).is_err());
        }
        let mut count = 0;
        write_readiness(&policy, true, |argv| {
            assert!(argv.contains(&"--ipv4"));
            let response = if count == 0 { "" } else { denied };
            count += 1;
            Ok(response.to_owned())
        })
        .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn missing_ipv6_requires_boot_disable_and_socket_family_refusal() {
        for parameter in ["Y\n", "1\n", "N\n", "0\n", "", "unknown"] {
            for errno in [
                None,
                Some(rustix::io::Errno::AFNOSUPPORT),
                Some(rustix::io::Errno::NETUNREACH),
                Some(rustix::io::Errno::CONNREFUSED),
                Some(rustix::io::Errno::ACCESS),
            ] {
                assert_eq!(
                    ipv6_disabled_evidence(parameter.as_bytes(), || match errno {
                        None => Ok(()),
                        Some(errno) => Err(std::io::Error::from_raw_os_error(errno.raw_os_error())),
                    }),
                    matches!(parameter, "Y\n" | "1\n")
                        && errno == Some(rustix::io::Errno::AFNOSUPPORT),
                    "{parameter:?}: {errno:?}"
                );
            }
        }
    }

    #[test]
    fn boot_parameter_reader_accepts_sysfs_attribute_size() {
        let path = std::path::Path::new("/sys/module/ipv6/parameters/disable");
        match std::fs::read(path) {
            Ok(expected) => assert_eq!(ipv6_boot_parameter().unwrap(), expected),
            Err(_) => assert!(!kernel_ipv6_disabled()),
        }
    }

    #[test]
    fn oversized_stream_is_stopped_before_capture_can_grow() {
        let mut child = std::process::Command::new("yes")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        assert!(
            capture_response(&mut child)
                .unwrap_err()
                .to_string()
                .contains("oversized")
        );
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn the_proxys_refusal_and_an_origins() {
        let ours = "HTTP/1.1 200 Connection established\r\n\r\nHTTP/2 403 \r\ncontent-type: text/plain\r\nX-Egress-Denied: a write to an endpoint not in the write allowlist\r\n\r\n";
        assert!(refused_by_proxy(ours));
        let cases = [
            "HTTP/1.1 403 Forbidden\r\nserver: origin\r\n\r\n",
            "HTTP/1.1 200 OK\r\nx-egress-denied: no\r\n\r\n",
            "HTTP/1.1 502 Bad Gateway\r\n\r\n",
            "",
        ];
        for headers in cases {
            assert!(!refused_by_proxy(headers), "{headers:?}");
        }
    }

    /// The write policy's control is a host the policy admits a read of
    /// and refuses a POST to, never one the check adds.
    #[test]
    fn the_write_policys_control_is_one_the_policy_admits() {
        use crate::proxy::policy::ECOSYSTEMS;
        let allow = |domains: &str| format!("[egress]\nmode = \"allowlist\"\nallow = {domains}\n");
        let post_anywhere = "[[write]]\nname = \"all\"\nhosts = [\"github.com\"]\nmethods = [\"POST\"]\npaths = [\"/**\"]\n";
        let example_too = "[\"github.com\", \"example.com\"]";
        // (policy, the URL read, the URL POSTed to)
        let cases = [
            (
                include_str!("../../../../egress/policy.toml").to_owned(),
                Some("https://example.com/"),
                Some("https://example.com/"),
            ),
            (
                allow("[\"github\"]"),
                Some("https://github.com/"),
                Some("https://github.com/"),
            ),
            // github.com takes a POST to /, so it can't show a refusal;
            // a plain request to example.com gets the proxy's own.
            (
                format!("{post_anywhere}{}", allow("[\"github.com\"]")),
                None,
                Some("http://example.com/"),
            ),
            (
                allow("[\"pypi.org\", \"notexample.com\"]"),
                None,
                Some("http://example.com/"),
            ),
            (
                allow("[\"pypi.org\", \"example.com\"]"),
                Some("https://example.com/"),
                Some("https://example.com/"),
            ),
            (allow("[]"), None, Some("http://example.com/")),
            // Both admitted, and both take a POST: nothing to probe.
            (
                format!(
                    "{post_anywhere}{}{}",
                    post_anywhere
                        .replace("\"all\"", "\"all of example\"")
                        .replace("github.com", "example.com"),
                    allow(example_too)
                ),
                None,
                None,
            ),
        ];
        for (text, read, post) in cases {
            let policy = Policy::parse(&text, ECOSYSTEMS)
                .unwrap()
                .with_runner_writes()
                .unwrap();
            let (got_read, got_post) = control_urls(&policy);
            assert_eq!(
                (got_read.as_deref(), got_post.as_deref()),
                (read, post),
                "{text}"
            );
        }
    }

    /// A control fails only after its last try, waiting a growing backoff
    /// between tries and logging each failure.
    #[test]
    fn a_control_retries_before_it_fails() {
        let secs = Duration::from_secs;
        // (the try that succeeds, if any) -> (reached, waits, log lines)
        let cases = [
            (Some(1), true, vec![], 0),
            (Some(2), true, vec![secs(5)], 1),
            (Some(3), true, vec![secs(5), secs(10)], 2),
            (None, false, vec![secs(5), secs(10)], 3),
        ];
        for (succeeds, reached, waits, lines) in cases {
            let (mut tries, mut slept, mut logged) = (0, Vec::new(), Vec::new());
            let got = retried(
                |wait| slept.push(wait),
                || {
                    tries += 1;
                    if Some(tries) == succeeds {
                        Ok(())
                    } else {
                        Err("connect (curl exit 7: refused)".to_owned())
                    }
                },
                |line| logged.push(line.to_owned()),
            );
            assert_eq!(got, reached, "{succeeds:?}");
            assert_eq!(slept, waits, "{succeeds:?}");
            assert_eq!(logged.len(), lines, "{succeeds:?}");
            assert!(tries <= CONTROL_TRIES, "{succeeds:?}");
        }
        let mut logged = Vec::new();
        retried(
            |_| {},
            || Err("dns".to_owned()),
            |line| logged.push(line.to_owned()),
        );
        assert_eq!(logged[2], "try 3 of 3 failed: dns");
    }

    #[test]
    fn a_failed_try_names_its_class() {
        let long = "x".repeat(MAX_DETAIL + 50);
        let cut = format!("other (curl exit 3: {})", "x".repeat(MAX_DETAIL));
        let cases = [
            (
                Some(6),
                "000",
                "Could not resolve host: example.com",
                "dns (curl exit 6: Could not resolve host: example.com)",
            ),
            (
                Some(7),
                "000",
                "Failed to connect",
                "connect (curl exit 7: Failed to connect)",
            ),
            (
                Some(28),
                "000",
                "timed out",
                "timeout (curl exit 28: timed out)",
            ),
            (
                Some(22),
                "504",
                "The requested URL returned error: 504",
                "http 504 (curl exit 22: The requested URL returned error: 504)",
            ),
            (
                Some(35),
                "000",
                "handshake",
                "tls (curl exit 35: handshake)",
            ),
            (
                Some(60),
                "000",
                "certificate",
                "tls (curl exit 60: certificate)",
            ),
            (Some(56), "000", "reset", "transfer (curl exit 56: reset)"),
            (None, "", "", "killed ()"),
            (Some(3), "000", long.as_str(), cut.as_str()),
        ];
        for (code, status, detail, want) in cases {
            assert_eq!(failure(code, status, detail), want, "{code:?}");
        }
    }

    /// The metadata requests go around any proxy the environment names,
    /// whose refusal would otherwise stand in for the rule on the uid.
    #[test]
    fn runner_requests_bypass_a_configured_proxy() {
        for argv in [
            metadata_request(),
            direct(METADATA_V6),
            control_request("https://example.com/"),
        ] {
            assert!(
                argv.windows(2).any(|pair| pair == ["--noproxy", "*"]),
                "{argv:?}"
            );
        }
    }
}
