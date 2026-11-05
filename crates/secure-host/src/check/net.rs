//! The probes of the runner's network: the cloud metadata service, and
//! the egress proxy's write rules under `egress.write-policy`.

use anyhow::Result;

use super::{Checker, Want};

const METADATA_URL: &str = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";

/// The metadata service at its IPv6 address (EC2's), refused to the
/// runner's uids with `sandbox.deny-runner-metadata`; `-g` keeps curl from
/// reading the brackets as a glob.
const METADATA_V6: &[&str] = &["-g", "http://[fd00:ec2::254]/latest/meta-data/"];

/// With the write policy: a write the proxy must refuse, on a host that
/// would take it.
const WRITE_URL: &str = "https://example.com/";

/// The header the proxy puts on every refusal of its own, lowercase.
const DENIED_HEADER: &str = "x-egress-denied:";

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
                "{runner} can't reach the instance metadata service (sandbox.deny-runner-metadata)"
            ),
            v4,
        );
        self.report.expect(
            Want::Fail,
            "runner-metadata-v6",
            format!("{runner} can't reach the instance metadata service over IPv6 (sandbox.deny-runner-metadata)"),
            v6,
        );
        self.report.note(&format!(
            "{runner} is refused the instance metadata service as well, so the probes of it have no control"
        ));
    }

    /// `egress.write-policy`: the runner's user, this process, with no
    /// proxy in its environment, reads a host but is refused a POST to it
    /// by the proxy itself, whose header an origin's refusal lacks.
    pub(super) fn runner_write_policy(&mut self) {
        let runner = self.runner.name.clone();
        let read = direct(&["--fail", WRITE_URL]);
        self.report.expect(
            Want::Succeed,
            "write-policy-read",
            format!("{runner} reads {WRITE_URL} with no proxy set (egress.write-policy)"),
            super::runner_reaches(&read),
        );
        let post = direct(&["-D", "-", "-X", "POST", "-d", "egress-check", WRITE_URL]);
        self.report.expect(
            Want::Succeed,
            "write-policy-post",
            format!(
                "the egress proxy refuses {runner} a POST to {WRITE_URL} (egress.write-policy)"
            ),
            refused_by_proxy(&super::runner_stdout(&post)),
        );
    }
}

const CURL: &[&str] = &["curl", "-sS", "-m", "30", "-o", "/dev/null"];

/// Not through the egress proxy, whatever the environment says.
fn direct<'a>(args: &[&'a str]) -> Vec<&'a str> {
    [CURL, &["--noproxy", "*"], args].concat()
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

    /// The metadata requests go around any proxy the environment names,
    /// whose refusal would otherwise stand in for the rule on the uid.
    #[test]
    fn runner_requests_bypass_a_configured_proxy() {
        for argv in [metadata_request(), direct(METADATA_V6)] {
            assert!(
                argv.windows(2).any(|pair| pair == ["--noproxy", "*"]),
                "{argv:?}"
            );
        }
    }
}
