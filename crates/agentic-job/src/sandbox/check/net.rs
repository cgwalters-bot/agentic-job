//! The probes of the network: the cloud metadata service, the egress
//! proxy and the tailnet filter, from the host and from a rootless
//! container.

use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::Result;

use super::{Attempt, CONTAINER_UID, Checker, Want};
use crate::sandbox::enter::Output;
use crate::sandbox::{egress, host, network};

const METADATA_URL: &str = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";

/// The metadata service at its IPv6 address (EC2's), which only
/// `sandbox.deny-runner-metadata` names; `-g` keeps curl from reading
/// the brackets as a glob.
const METADATA_V6: &[&str] = &["-g", "http://[fd00:ec2::254]/latest/meta-data/"];

/// Azure's WireServer, which serves the VM's configuration.
const WIRESERVER: &str = "168.63.129.16";

const WIRESERVER_URL: &str = "http://168.63.129.16/?comp=versions";

/// The WireServer is also Azure's resolver, and the Azure guest agent's
/// firewall, which drops every user but root's new connections to its
/// HTTP port, leaves its DNS port to all: the address's control where the
/// HTTP one has none.
const WIRESERVER_DNS_PORT: u16 = 53;

/// It is the VM's own host and answers at once where it answers at all.
/// Where it does not (a hosted runner drops the packets), waiting out
/// the whole of a request's time for the control added half a minute to
/// every run.
const WIRESERVER_CONNECT_SECONDS: &str = "5";

/// With the egress proxy: a write it must refuse, on a host that would
/// take it; a push; and a repository to fetch from.
const WRITE_URL: &str = "https://example.com/";

const PUSH_URL: &str = "https://github.com/bootc-dev/bootc.git/git-receive-pack";

const FETCH_REPO: &str = "https://github.com/bootc-dev/bootc";

const PUBLIC_DNS: &str = "8.8.8.8";

const DNS_PORT: u16 = 53;

const HTTPS_PORT: u16 = 443;

/// What the toolchains fetch through the proxy: a crate and an npm
/// package.
const CARGO_TOML: &str = "[package]\nname = \"egress-check\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"1\"\n";

const NPM_PACKAGE: &str = "is-number";

const EGRESS_WORK: &str = "egress-check";

// The helper's stdin cannot necessarily be reopened through /dev/stdin by
// Podman. Materialize it before invoking the builder instead.
const BUILD_SCRIPT: &str = "d=$(mktemp -d) || exit; trap 'rm -rf -- \"$d\"' EXIT; cat > \"$d/Containerfile\" || exit; podman build --network=none --pull=never -q -t \"$1\" -f \"$d/Containerfile\" \"$d\"";

/// Where a container sees the proxy's certificate authority, and the
/// mount that puts it there.
const CONTAINER_CA: &str = "/run/egress-ca.pem";

/// The header the proxy puts on every refusal of its own, lowercase.
const DENIED_HEADER: &str = "x-egress-denied:";

/// Another port on a direct endpoint's host, which the tailnet's own
/// rules may allow and the sandbox user must not reach: SSH, which most
/// hosts listen on.
const OTHER_TAILNET_PORT: u16 = 22;

/// tailscaled's own address: its DNS, which answers for every node, and
/// its web ports.
const QUAD100: &[&str] = &["100.100.100.100", "fd7a:115c:a1e0::53"];

const QUAD100_PORTS: &[u16] = &[53, 80, 8080];

fn metadata_attempts(user: &str, metadata: &[&str]) -> [Attempt; 2] {
    [
        Attempt::control(
            "metadata-control",
            "the instance metadata service",
            metadata,
        ),
        Attempt::refused(
            "metadata",
            format!("{user} can't reach the instance metadata service"),
            metadata,
        ),
    ]
}

impl Checker<'_> {
    /// The network as the sandbox user has it, on the host and from a
    /// rootless container: no cloud metadata service, and then what the
    /// egress proxy and the direct endpoints add.
    pub(super) fn network(&mut self) -> Result<()> {
        let user = self.user().to_owned();
        let url = self.config.sandbox.check.control_url.clone();
        let image = self.config.sandbox.check.container_image.clone();
        let egress = self.config.egress.proxy;
        let got = self.sandbox_succeeds(&curl(&[&url]))?;
        self.report.expect(
            Want::Succeed,
            "network-control",
            format!("{user} reaches {url} (control)"),
            got,
        );
        let metadata = direct(&["-H", "Metadata:true", METADATA_URL]);
        if self.config.sandbox.deny_runner_metadata {
            // The runner's user is the control everywhere else, and here
            // it is refused too: the probes say less, and say so.
            let runner = self.runner.name.clone();
            // Independent read-only requests with the same timeouts as before.
            // Overlap the negative metadata probes instead of paying each
            // dropped packet's timeout in series. No control is omitted.
            let metadata_v6 = direct(METADATA_V6);
            let requests = [&metadata, &metadata_v6, &metadata];
            let results = super::concurrently(&[0, 1, 2], |&index| {
                let name = ["runner-metadata", "runner-metadata-v6", "metadata"][index];
                crate::sandbox::timed::stage("check", name, || {
                    if index == 2 {
                        self.sandbox_succeeds(requests[index])
                    } else {
                        Ok(super::runner_reaches(requests[index]))
                    }
                })
            });
            let mut results = results.into_iter();
            let got = results.next().expect("three metadata results")?;
            self.report.expect(
                Want::Fail,
                "runner-metadata",
                format!("{runner} can't reach the instance metadata service (sandbox.deny-runner-metadata)"),
                got,
            );
            let got = results.next().expect("three metadata results")?;
            self.report.expect(
                Want::Fail,
                "runner-metadata-v6",
                format!("{runner} can't reach the instance metadata service over IPv6 (sandbox.deny-runner-metadata)"),
                got,
            );
            self.report.note(&format!(
                "{runner} is refused the instance metadata service as well, so the probes of it have no control"
            ));
            let got = results.next().expect("three metadata results")?;
            self.report.expect(
                Want::Fail,
                "metadata",
                format!("{user} can't reach the instance metadata service"),
                got,
            );
        } else {
            // Independent, read-only requests. The runner's control need
            // not consume its timeout before the sandbox makes its attempt.
            self.attempts(&metadata_attempts(&user, &metadata))?;
        }
        if !self.has_podman() {
            self.report
                .note("no podman on this host, so no container to probe from");
        } else {
            let got = self.sandbox_succeeds(&["podman", "pull", "-q", &image])?;
            self.report.expect(
                Want::Succeed,
                "container-pull",
                format!("{user} pulls {image}"),
                got,
            );
            let tag = format!("localhost/agentic-job-view:{}", self.canary);
            let recipe = format!("FROM {image}\nRUN true\n");
            let built = self.sandbox_diagnosed(
                "container-build",
                &["sh", "-c", BUILD_SCRIPT, "sh", &tag],
                recipe.as_bytes(),
            )?;
            let ran = if built {
                self.sandbox_diagnosed(
                    "container-built-run",
                    &[
                        "podman",
                        "run",
                        "--pull=never",
                        "--rm",
                        "--network=none",
                        &tag,
                        "true",
                    ],
                    b"",
                )?
            } else {
                self.report
                    .note("container-built-run: not run because container-build failed");
                false
            };
            let _ = self.sandbox(&["podman", "rmi", "-f", &tag], b"");
            self.report.expect(
                Want::Succeed,
                "container-build",
                "rootless Podman builds in the sandbox",
                built,
            );
            self.report.expect(
                Want::Succeed,
                "container-built-run",
                if built {
                    "rootless Podman runs the built image"
                } else {
                    "build prerequisite failed; built image cannot be tested"
                },
                ran,
            );
            // The control shows the container and its curl work, so the
            // refusal after it is the filter on subordinate uids.
            let through_proxy = self.proxy_url();
            let via: Vec<&str> = if egress {
                vec!["--cacert", CONTAINER_CA, "-x", &through_proxy]
            } else {
                Vec::new()
            };
            let got = self.in_container(&curl(&[via.as_slice(), &[url.as_str()]].concat()))?;
            self.report.expect(
                Want::Succeed,
                "container-control",
                format!("a container as subordinate uid {CONTAINER_UID} reaches {url} (control)"),
                got,
            );
            let got = self.in_container(&metadata)?;
            self.report.expect(
                Want::Fail,
                "container-metadata",
                format!(
                    "a container as subordinate uid {CONTAINER_UID} can't reach the instance metadata service"
                ),
                got,
            );
        }
        if egress {
            self.timed("egress", |this| this.egress())?;
        }
        if self.config.egress.write_policy {
            self.timed("write-policy", |this| this.write_policy())?;
        }
        if !self.config.egress.direct.is_empty() {
            self.timed("tailnet", |this| this.tailnet())?;
        }
        Ok(())
    }

    fn proxy_url(&self) -> String {
        egress::proxy_url()
    }

    /// The egress proxy: the toolchains fetch through it, it refuses
    /// writes to unlisted endpoints (with its own header, so the refusal
    /// is the proxy's), going around it fails, and it reaches nothing the
    /// sandbox may not, from a container either.
    fn egress(&mut self) -> Result<()> {
        let user = self.user().to_owned();
        let url = self.config.sandbox.check.control_url.clone();
        let proxy = self.proxy_url();
        let host_name = url_host(&url).to_owned();
        let work = format!("{}/{EGRESS_WORK}", self.entry.home().display());
        let refused = |output: Output| refused_by_proxy(&String::from_utf8_lossy(&output.stdout));

        let got = self.sandbox_succeeds(&proxied(&["--proxy", &proxy, &url]))?;
        self.report.expect(
            Want::Succeed,
            "egress-read",
            format!("{user} reads {url} through the egress proxy"),
            got,
        );
        self.sandbox(&["rm", "-rf", &work], b"")?;
        if self.sandbox_has("cargo")? {
            let manifest = format!("{work}/crate/Cargo.toml");
            self.sandbox(&["mkdir", "-p", &format!("{work}/crate/src")], b"")?;
            self.sandbox(&["tee", &manifest], CARGO_TOML.as_bytes())?;
            self.sandbox(
                &["tee", &format!("{work}/crate/src/main.rs")],
                b"fn main() {}\n",
            )?;
            let got = self.sandbox_succeeds(&["cargo", "fetch", "--manifest-path", &manifest])?;
            self.report.expect(
                Want::Succeed,
                "egress-cargo",
                format!("{user} fetches a crate with cargo"),
                got,
            );
        } else {
            self.report
                .note("no cargo for the sandbox user, so no crate to fetch");
        }
        if self.sandbox_has("npm")? {
            let prefix = format!("{work}/npm");
            self.sandbox(&["mkdir", "-p", &prefix], b"")?;
            let got = self.sandbox_succeeds(&[
                "npm",
                "install",
                "--no-fund",
                "--prefix",
                &prefix,
                NPM_PACKAGE,
            ])?;
            self.report.expect(
                Want::Succeed,
                "egress-npm",
                format!("{user} installs {NPM_PACKAGE} with npm"),
                got,
            );
        } else {
            self.report
                .note("no npm for the sandbox user, so no package to install");
        }
        self.sandbox(&["rm", "-rf", &work], b"")?;
        let got =
            self.sandbox_succeeds(&["timeout", "60", "git", "ls-remote", FETCH_REPO, "HEAD"])?;
        self.report.expect(
            Want::Succeed,
            "egress-git",
            format!("{user} fetches from git (POST git-upload-pack)"),
            got,
        );

        let post = head(&["-X", "POST", "-d", "egress-check", WRITE_URL]);
        let got = refused(self.sandbox(&post, b"")?);
        self.report.expect(
            Want::Succeed,
            "egress-post",
            format!("the proxy refuses a POST to {WRITE_URL}"),
            got,
        );
        let got = refused(self.sandbox(&head(&["-X", "POST", "-d", "0000", PUSH_URL]), b"")?);
        self.report.expect(
            Want::Succeed,
            "egress-push",
            "the proxy refuses a git push (POST git-receive-pack)",
            got,
        );
        let fronted = head(&["-H", "Host: example.com", &url]);
        let got = refused(self.sandbox(&fronted, b"")?);
        self.report.expect(
            Want::Succeed,
            "egress-fronting",
            "the proxy refuses a Host header naming another host than the connection's (domain fronting)",
            got,
        );

        // The refusals, made together: each waits mostly on its own way
        // into the sandbox, and one that is not refused fails the check
        // as it would alone.
        let around = direct(&[&url]);
        let mut attempts = vec![Attempt::refused(
            "egress-direct",
            format!("{user} can't reach {url} around the proxy"),
            &around,
        )];
        // The address, looked up here: the sandbox user cannot.
        let address = (host_name.as_str(), HTTPS_PORT)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.find(SocketAddr::is_ipv4))
            .map(|addr| addr.ip().to_string());
        match address {
            Some(address) => {
                let probe = tcp_probe(&address, HTTPS_PORT);
                let probe: Vec<&str> = probe.iter().map(String::as_str).collect();
                attempts.extend([
                    Attempt::control(
                        "egress-tcp-control",
                        format!("{address}:{HTTPS_PORT}"),
                        &probe,
                    ),
                    Attempt::refused(
                        "egress-tcp",
                        format!(
                            "{user} can't open a TCP connection to {address}:{HTTPS_PORT} around the proxy"
                        ),
                        &probe,
                    ),
                ]);
            }
            None => self.report.expect(
                Want::Succeed,
                "egress-tcp-control",
                format!("{} resolves {host_name} (control)", self.runner.name),
                false,
            ),
        }
        let resolve = ["getent", "hosts", host_name.as_str()];
        let dns = tcp_probe(PUBLIC_DNS, DNS_PORT);
        let dns: Vec<&str> = dns.iter().map(String::as_str).collect();
        let wireserver_dns = tcp_probe(WIRESERVER, WIRESERVER_DNS_PORT);
        let wireserver_dns: Vec<&str> = wireserver_dns.iter().map(String::as_str).collect();
        let wireserver = direct(&[
            "--connect-timeout",
            WIRESERVER_CONNECT_SECONDS,
            WIRESERVER_URL,
        ]);
        attempts.extend([
            Attempt::control(
                "egress-resolve-control",
                format!("a resolver for {host_name}"),
                &resolve,
            ),
            Attempt::refused(
                "egress-resolve",
                format!("{user} can't resolve names (getent hosts)"),
                &resolve,
            ),
            Attempt::control(
                "egress-dns-control",
                format!("{PUBLIC_DNS}:{DNS_PORT}"),
                &dns,
            ),
            Attempt::refused(
                "egress-dns",
                format!("{user} can't reach a public DNS server ({PUBLIC_DNS}:{DNS_PORT})"),
                &dns,
            ),
            Attempt::control("egress-wireserver-control", "the WireServer", &wireserver),
            Attempt::control(
                "egress-wireserver-dns-control",
                format!("the WireServer at {WIRESERVER}:{WIRESERVER_DNS_PORT}"),
                &wireserver_dns,
            ),
            Attempt::refused(
                "egress-wireserver-dns",
                format!(
                    "{user} can't open a TCP connection to the WireServer at {WIRESERVER}:{WIRESERVER_DNS_PORT}"
                ),
                &wireserver_dns,
            ),
            Attempt::refused(
                "egress-wireserver",
                format!("{user} can't reach the WireServer"),
                &wireserver,
            ),
            Attempt::refused(
                "egress-proxy-metadata",
                "the proxy doesn't reach the instance metadata service",
                &proxied(&["-H", "Metadata:true", METADATA_URL]),
            ),
            Attempt::refused(
                "egress-proxy-wireserver",
                "the proxy doesn't reach the WireServer",
                &proxied(&[WIRESERVER_URL]),
            ),
        ]);
        for endpoint in &self.config.egress.direct {
            attempts.push(Attempt::refused(
                "egress-proxy-direct",
                format!("the proxy doesn't reach {endpoint} on the tailnet"),
                &proxied(&["--proxy", &proxy, "--noproxy", "", endpoint]),
            ));
        }
        let image = self.config.sandbox.check.container_image.clone();
        if self.has_podman() {
            let own_network = [&["podman", "run", "--rm", image.as_str()][..], &around].concat();
            attempts.extend([
                Attempt::refused_in_container(
                    "egress-container-direct",
                    format!(
                        "a container as subordinate uid {CONTAINER_UID} can't reach {url} around the proxy"
                    ),
                    &self.container(&around),
                ),
                Attempt::refused_in_container(
                    "egress-container-own-network",
                    format!("a container on its own network can't reach {url}"),
                    &own_network,
                ),
            ]);
        }
        self.attempts(&attempts)?;

        if self.has_podman() {
            let post = head(&[
                "--cacert",
                CONTAINER_CA,
                "-x",
                &proxy,
                "-X",
                "POST",
                "-d",
                "x",
                WRITE_URL,
            ]);
            let got = refused(self.sandbox(&self.container(&post), b"")?);
            self.report.expect(
                Want::Succeed,
                "egress-container-post",
                format!(
                    "a container as subordinate uid {CONTAINER_UID} on the host's network is refused a POST too"
                ),
                got,
            );
        }
        Ok(())
    }

    /// `egress.write-policy`: the runner's user, this process, with no
    /// proxy in its environment, reads a host but is refused a POST to it
    /// by the proxy itself, whose header an origin's refusal lacks; and
    /// the sandbox user cannot reach the listener that serves the
    /// runner, whose rules are wider than its own.
    fn write_policy(&mut self) -> Result<()> {
        let runner = self.runner.name.clone();
        let user = self.user().to_owned();
        let read = direct(&["--fail", WRITE_URL]);
        self.report.expect(
            Want::Succeed,
            "write-policy-read",
            format!("{runner} reads {WRITE_URL} with no proxy set (egress.write-policy)"),
            super::runner_reaches(&read),
        );
        let post = [
            CURL,
            &[
                "--noproxy",
                "*",
                "-D",
                "-",
                "-X",
                "POST",
                "-d",
                "egress-check",
                WRITE_URL,
            ],
        ]
        .concat();
        self.report.expect(
            Want::Succeed,
            "write-policy-post",
            format!(
                "the egress proxy refuses {runner} a POST to {WRITE_URL} (egress.write-policy)"
            ),
            refused_by_proxy(&super::runner_stdout(&post)),
        );
        let address = egress::PROXY_HOST.to_string();
        let listener = tcp_probe(&address, egress::TRANSPARENT_PORT);
        let listener: Vec<&str> = listener.iter().map(String::as_str).collect();
        let what = format!(
            "the runner's listener at {address}:{}",
            egress::TRANSPARENT_PORT
        );
        self.attempts(&[
            Attempt::control("write-policy-listener-control", &what, &listener),
            Attempt::refused(
                "write-policy-listener",
                format!("{user} can't reach {what}"),
                &listener,
            ),
        ])
    }

    /// Whether the sandbox user has `program` on its path.
    fn sandbox_has(&self, program: &str) -> Result<bool> {
        self.sandbox_succeeds(&["sh", "-c", "command -v \"$1\" >/dev/null", "sh", program])
    }

    /// The tailnet filter: the direct endpoints are reachable, and
    /// nothing else there, over IPv4 or IPv6, tailscaled's own address
    /// (its DNS included) or this node's, whether dialed directly or
    /// through tailscaled. Where the runner's user reaches a target, that
    /// is shown as a control; once the tailnet's own rules are narrowed
    /// to the endpoint's port, only this node's addresses have one.
    fn tailnet(&mut self) -> Result<()> {
        let user = self.user().to_owned();
        let status = self
            .root
            .tailscale_status()
            .unwrap_or(serde_json::Value::Null);
        let endpoints = network::direct(&self.config.egress)?;
        // The URL as the configuration has it: an https endpoint is not
        // spoken to in plain HTTP.
        for (endpoint, url) in endpoints.into_iter().zip(self.config.egress.direct.clone()) {
            let host_v4 = endpoint.host.to_string();
            let reached = host::command(&direct(&[&url]))
                .map(|mut command| host::succeeds(&mut command))
                .unwrap_or(false);
            self.report.expect(
                Want::Succeed,
                "tailnet-direct-control",
                if reached {
                    format!("{} reaches {url} (control)", self.runner.name)
                } else {
                    format!("control failed: the runner cannot reach {url}; check the proxy and its network")
                },
                reached,
            );
            if !reached {
                continue;
            }
            // Any HTTP response will do: the point is the connection.
            let got = self.sandbox_succeeds(&curl(&[&url]))?;
            self.report.expect(
                Want::Succeed,
                "tailnet-direct",
                format!("{user} reaches {url} on the tailnet"),
                got,
            );
            if self.has_podman() {
                let got = self.in_container(&curl(&[&url]))?;
                self.report.expect(
                    Want::Succeed,
                    "tailnet-container-direct",
                    format!(
                        "a container as subordinate uid {CONTAINER_UID} reaches {url} on the tailnet"
                    ),
                    got,
                );
            }
            let host_v6 = tailnet_v6(&status, &host_v4);
            let mut targets = vec![(host_v4.clone(), OTHER_TAILNET_PORT)];
            if let Some(v6) = host_v6 {
                targets.extend([(v6.clone(), endpoint.port), (v6, OTHER_TAILNET_PORT)]);
            }
            targets.extend(QUAD100.iter().flat_map(|addr| {
                QUAD100_PORTS
                    .iter()
                    .map(move |&port| ((*addr).to_owned(), port))
            }));
            targets.extend(self_peerapi(&status));
            // Made together, and reported in this order: see `egress`.
            let mut attempts = Vec::new();
            for (addr, port) in targets {
                let target = if addr.contains(':') {
                    format!("[{addr}]:{port}")
                } else {
                    format!("{addr}:{port}")
                };
                let probe = tcp_probe(&addr, port);
                let probe: Vec<&str> = probe.iter().map(String::as_str).collect();
                attempts.extend([
                    Attempt::control(format!("tailnet-control:{target}"), &target, &probe),
                    Attempt::refused(
                        format!("tailnet:{target}"),
                        format!("{user} can't reach {target}"),
                        &probe,
                    ),
                ]);
                if self.has_podman() {
                    attempts.push(Attempt::refused_in_container(
                        format!("tailnet-container:{target}"),
                        format!(
                            "a container as subordinate uid {CONTAINER_UID} can't reach {target}"
                        ),
                        &self.container(&probe),
                    ));
                }
            }
            let port = OTHER_TAILNET_PORT.to_string();
            attempts.push(Attempt::refused(
                "tailnet-nc",
                format!("{user} can't dial {host_v4}:{port} through tailscaled (tailscale nc)"),
                &["timeout", "10", "tailscale", "nc", &host_v4, &port],
            ));
            self.attempts(&attempts)?;
        }
        Ok(())
    }
}

const CURL: &[&str] = &["curl", "-sS", "-m", "30", "-o", "/dev/null"];

fn curl<'a>(args: &[&'a str]) -> Vec<&'a str> {
    [CURL, args].concat()
}

/// Not through the egress proxy, whatever the environment says.
fn direct<'a>(args: &[&'a str]) -> Vec<&'a str> {
    [CURL, &["--noproxy", "*"], args].concat()
}

/// Through it, failing on an error status: the proxy answers 502 when it
/// cannot connect.
fn proxied<'a>(args: &[&'a str]) -> Vec<&'a str> {
    [CURL, &["--fail"], args].concat()
}

/// A request whose response headers are printed.
fn head<'a>(args: &[&'a str]) -> Vec<&'a str> {
    [CURL, &["-D", "-"], args].concat()
}

/// A command that opens a plain TCP connection, whatever the service
/// speaks.
fn tcp_probe(addr: &str, port: u16) -> Vec<String> {
    [
        "timeout",
        "10",
        "bash",
        "-c",
        r#"exec 3<>"/dev/tcp/$1/$2""#,
        "probe",
        addr,
        &port.to_string(),
    ]
    .iter()
    .map(|&arg| arg.to_owned())
    .collect()
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

/// The host of an http or https URL.
pub(super) fn url_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    host.rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(host, |(host, _)| host)
}

/// The tailnet IPv6 address of the peer whose IPv4 address is `addr`.
fn tailnet_v6(status: &serde_json::Value, addr: &str) -> Option<String> {
    status.get("Peer")?.as_object()?.values().find_map(|peer| {
        let ips: Vec<&str> = peer
            .get("TailscaleIPs")?
            .as_array()?
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        ips.contains(&addr).then(|| {
            ips.iter()
                .find(|ip| ip.contains(':'))
                .map(|&ip| ip.to_owned())
        })?
    })
}

/// The address and port of this node's own peer API, which is reached
/// over loopback.
fn self_peerapi(status: &serde_json::Value) -> Vec<(String, u16)> {
    status
        .get("Self")
        .and_then(|own| own.get("PeerAPIURL"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|url| {
            let rest = url.split_once("://")?.1;
            let authority = rest.split('/').next()?;
            let (host, port) = authority.rsplit_once(':')?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            Some((host.to_owned(), port.parse().ok()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_materializes_recipe_and_propagates_builder_status() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        for status in [0, 42] {
            // A shell function stands in for Podman without an executable
            // fixture. It verifies the recipe is a real file, not stdin.
            let mock = format!(
                "podman() {{ test \"$1\" = build || return 90; shift; while test \"$1\" != -f; do shift; done; shift; test -f \"$1\" || return 91; test \"$(cat \"$1\")\" = 'FROM test-image\nRUN true' || return 92; test \"$1\" = \"$2/Containerfile\" || return 93; return {status}; }}; {BUILD_SCRIPT}"
            );
            let mut child = Command::new("sh")
                .args(["-c", &mock, "sh", "localhost/test"])
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"FROM test-image\nRUN true\n")
                .unwrap();
            assert_eq!(child.wait().unwrap().code(), Some(status));
        }
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

    #[test]
    fn hosts_of_urls() {
        let cases = [
            ("https://github.com/", "github.com"),
            ("http://example.com:8080/a?b", "example.com"),
            ("https://user@example.org", "example.org"),
            ("http://100.101.102.103:18080/v1", "100.101.102.103"),
        ];
        for (url, host) in cases {
            assert_eq!(url_host(url), host, "{url}");
        }
    }

    #[test]
    fn tailscale_status_fields() {
        let status: serde_json::Value = serde_json::from_str(
            r#"{"Self": {"PeerAPIURL": ["http://100.72.1.2:37098", "http://[fd7a:115c:a1e0::1]:39316"]},
                "Peer": {"a": {"TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::9"]},
                         "b": {"TailscaleIPs": ["100.64.0.7"]}}}"#,
        )
        .unwrap();
        assert_eq!(
            tailnet_v6(&status, "100.101.102.103").as_deref(),
            Some("fd7a:115c:a1e0::9")
        );
        assert_eq!(tailnet_v6(&status, "100.64.0.7"), None);
        assert_eq!(tailnet_v6(&status, "100.64.0.8"), None);
        assert_eq!(
            self_peerapi(&status),
            [
                ("100.72.1.2".to_owned(), 37098),
                ("fd7a:115c:a1e0::1".to_owned(), 39316)
            ]
        );
        assert!(self_peerapi(&serde_json::Value::Null).is_empty());
    }
}
