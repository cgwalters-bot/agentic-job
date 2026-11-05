//! The probes of the network: the cloud metadata service, the egress
//! proxy, the tailnet filter and a session's bridge, from the host and
//! from a rootless container.

use std::net::{IpAddr, SocketAddr, TcpListener, ToSocketAddrs};

use anyhow::{Context, Result, ensure};

use super::{Attempt, CONTAINER_UID, Checker, Want};
use crate::enter::Output;
use crate::proxy::policy::{Policy, Request};
use crate::{egress, host, network};

const METADATA_URL: &str = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";

/// The metadata service at its IPv6 address (EC2's), refused to the
/// sandbox's uids always and to the runner's with
/// `sandbox.deny-runner-metadata`, which alone probes it; `-g` keeps curl
/// from reading the brackets as a glob.
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
/// every run. This is the refusal's bound; the control has the shorter
/// one of every control ([`super::CONTROL_LIMIT`]).
const WIRESERVER_CONNECT_SECONDS: &str = "5";

/// With the egress proxy: a write it must refuse, on a host that would
/// take it; and a push.
const WRITE_URL: &str = "https://example.com/";

const PUSH_URL: &str = "https://github.com/bootc-dev/bootc.git/git-receive-pack";

/// What `cargo fetch` and `npm install` read through the proxy: crates.io's
/// sparse index and its downloads, and npm's registry, which also serves
/// the tarballs. npm's audit POST is left out: its refusal is a warning,
/// not a failed install.
const CARGO_READS: &[&str] = &[
    "https://index.crates.io/config.json",
    "https://static.crates.io/",
];

const NPM_READS: &[&str] = &["https://registry.npmjs.org/is-number"];

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

/// Where a session's bridge listens, and where `tailscale serve` passes
/// its client on from, at the node's own tailnet addresses.
const BRIDGE_HOST: &str = "127.0.0.1";

const SERVE_PORT: u16 = HTTPS_PORT;

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

/// A request of a probe's that the egress policy refuses, which the
/// proxy itself must then refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Refusal {
    method: &'static str,
    url: String,
}

/// What the probes that fetch through the egress proxy expect of the
/// policy it enforces: for each, `None` where the policy admits every
/// request the probe makes, which must then succeed, or the first it
/// refuses. A tight allowlist is tested as it is, rather than having to
/// admit the hosts of a fixed fetch for the check to pass.
#[derive(Debug, PartialEq, Eq)]
struct Expected {
    git: Option<Refusal>,
    cargo: Option<Refusal>,
    npm: Option<Refusal>,
}

/// [`Expected`] of `policy`, `git` fetching from `fetch_repo`. An error
/// where `policy` refuses a read of `control_url`: it is the control of
/// the probes that expect a connection to fail, and one the proxy
/// refuses too would make those refusals show nothing.
fn expected(policy: &Policy, control_url: &str, fetch_repo: &str) -> Result<Expected> {
    ensure!(
        first_refused(policy, &[("GET", control_url.to_owned())]).is_none(),
        "the egress policy refuses a read of [sandbox.check] control-url {control_url:?}, the \
         control of the egress probes: name a URL the policy admits"
    );
    // `git ls-remote` over smart HTTP: the refs advertised, and with
    // protocol version 2, git's default, a POST that lists them.
    let repo = fetch_repo.trim_end_matches('/');
    let git = [
        ("GET", format!("{repo}/info/refs?service=git-upload-pack")),
        ("POST", format!("{repo}/git-upload-pack")),
    ];
    let reads = |urls: &[&str]| -> Vec<(&'static str, String)> {
        urls.iter().map(|&url| ("GET", url.to_owned())).collect()
    };
    Ok(Expected {
        git: first_refused(policy, &git),
        cargo: first_refused(policy, &reads(CARGO_READS)),
        npm: first_refused(policy, &reads(NPM_READS)),
    })
}

/// The first of `requests`, each a method and a URL, that `policy`
/// refuses, whether at the tunnel or at the request itself.
fn first_refused(policy: &Policy, requests: &[(&'static str, String)]) -> Option<Refusal> {
    requests
        .iter()
        .find(|(method, url)| {
            let host = url_host(url);
            let request = Request {
                method,
                host,
                path: url_path(url),
                has_body: *method != "GET",
                ..Request::default()
            };
            !(policy.connect(host).allowed && policy.request(&request).allowed)
        })
        .map(|(method, url)| Refusal {
            method,
            url: url.clone(),
        })
}

/// The probes that pull or run an image, which `[sandbox.check]
/// containers = false` skips: those of the egress proxy and the tailnet
/// where they are made at all.
fn skipped_containers(egress: bool, tailnet: bool, session: bool) -> Vec<&'static str> {
    let mut ids = vec![
        "container-pull",
        "container-build",
        "container-built-run",
        "container-control",
        "container-metadata",
    ];
    if egress {
        ids.extend([
            "egress-container-direct",
            "egress-container-own-network",
            "egress-container-post",
        ]);
    }
    if tailnet {
        ids.extend(["tailnet-container-direct", "tailnet-container:*"]);
    }
    if session {
        ids.push("session-bridge-container");
    }
    ids
}

/// What of a session's bridge the sandbox user must not reach: the
/// bridge on loopback, and the node's own tailnet addresses (`status`'s
/// `Self`), from which serve passes a client on, at the bridge's port,
/// where the check holds a listener as a control, and at serve's. None
/// without `[session] listen`.
fn bridge_targets(port: Option<u16>, status: &serde_json::Value) -> Vec<(String, u16)> {
    let Some(port) = port else {
        return Vec::new();
    };
    let own = status
        .get("Self")
        .and_then(|own| own.get("TailscaleIPs"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .flat_map(|addr| {
            [port, SERVE_PORT]
                .into_iter()
                .map(move |port| (addr.to_owned(), port))
        });
    std::iter::once((BRIDGE_HOST.to_owned(), port))
        .chain(own)
        .collect()
}

/// A listener of the runner's user at `addr`:`port`, the control of a
/// probe of it. Every check runs before `run` binds the bridge, so
/// something already listening there is no bridge but whatever would be
/// handed serve's connections: an error, not a control.
fn hold(addr: &str, port: u16) -> Result<TcpListener> {
    let ip: IpAddr = addr
        .parse()
        .with_context(|| format!("{addr:?} is not an IP address"))?;
    TcpListener::bind((ip, port)).with_context(|| {
        format!(
            "listening at {}, where a session's bridge is to listen",
            socket_text(addr, port)
        )
    })
}

fn socket_text(addr: &str, port: u16) -> String {
    if addr.contains(':') {
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    }
}

impl Checker<'_> {
    /// Whether the probes run containers: there is podman, and
    /// `[sandbox.check] containers` leaves them on.
    fn runs_containers(&self) -> bool {
        self.config.sandbox.check.containers && self.has_podman()
    }

    /// The network as the sandbox user has it, on the host and from a
    /// rootless container: no cloud metadata service, and then what the
    /// egress proxy and the direct endpoints add.
    pub(super) fn network(&mut self) -> Result<()> {
        let user = self.user()?.to_owned();
        let url = self.config.sandbox.check.control_url.clone();
        let image = self.config.sandbox.check.container_image.clone();
        let egress = self.config.egress.proxy;
        let tailnet = !self.config.egress.direct.is_empty();
        // Before any probe: a policy that cannot be read, or that refuses
        // the control, stops the check rather than skipping probes.
        let expected = if egress {
            let policy = egress::installed_policy()?;
            Some(expected(
                &policy,
                &url,
                &self.config.sandbox.check.fetch_repo,
            )?)
        } else {
            None
        };
        let got = self.sandbox_succeeds(&curl(&[&url]))?;
        self.report.expect(
            Want::Succeed,
            "network-control",
            format!("{user} reaches {url} (control)"),
            got,
        );
        let metadata = metadata_request();
        if self.config.sandbox.deny_runner_metadata() {
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
                crate::timed::stage("check", name, || {
                    if index == 2 {
                        self.sandbox_succeeds(requests[index])
                    } else {
                        Ok(super::runner_reaches(requests[index]))
                    }
                })
            });
            let mut results = results.into_iter();
            let v4 = results.next().expect("three metadata results")?;
            let v6 = results.next().expect("three metadata results")?;
            self.report_runner_metadata(&runner, v4, v6);
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
        } else if !self.config.sandbox.check.containers {
            self.report.note(&format!(
                "[sandbox.check] containers = false: not run, not passed: {}; the sandbox user \
                 can still run rootless Podman, whose subordinate uids' network goes unprobed",
                skipped_containers(egress, tailnet, self.config.session_port.is_some()).join(", ")
            ));
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
        if let Some(expected) = &expected {
            self.timed("egress", |this| this.egress(expected))?;
        }
        if self.config.egress.write_policy {
            self.timed("write-policy", |this| this.write_policy())?;
        }
        if tailnet {
            self.timed("tailnet", |this| this.tailnet())?;
        }
        if let Some(port) = self.config.session_port {
            self.timed("session-bridge", |this| this.session_bridge(port))?;
        } else {
            self.report
                .note("no [session] listen, so no session bridge to probe");
        }
        Ok(())
    }

    /// A session's bridge, which lets in whoever `Tailscale-User-Login`
    /// names: the sandbox user reaching it, on loopback or through serve
    /// at the node's own tailnet address, could name the operator and
    /// prompt the session it runs in. The runner's user holds a listener
    /// at each target on the bridge's port, the control; serve's port has
    /// none to show, and a note says so. The loopback control must hold:
    /// without it, the bridge's refusal shows nothing.
    fn session_bridge(&mut self, port: u16) -> Result<()> {
        let user = self.user()?.to_owned();
        let status = self
            .root
            .tailscale_status()
            .unwrap_or(serde_json::Value::Null);
        let targets = bridge_targets(Some(port), &status);
        // Setup serves a session only on the tailnet: without its
        // addresses, half of what the rules refuse would go unprobed.
        self.report.expect(
            Want::Succeed,
            "session-bridge-tailnet",
            "tailscale status gives this node's tailnet addresses, which serve passes a client on from",
            targets.len() > 1,
        );
        // Held until the attempts are made. Serve passes clients on to
        // loopback only, so a failure to listen there stops the check; at
        // a tailnet address it leaves that probe without a control.
        let mut listeners = Vec::new();
        for (addr, port) in targets
            .iter()
            .filter(|(_, target_port)| *target_port == port)
        {
            match hold(addr, *port) {
                Ok(listener) => listeners.push(listener),
                Err(err) if addr != BRIDGE_HOST => self.report.note(&format!("{err:#}")),
                Err(err) => return Err(err),
            }
        }
        let bridge = socket_text(BRIDGE_HOST, port);
        let probe = tcp_probe(BRIDGE_HOST, port);
        let probe: Vec<&str> = probe.iter().map(String::as_str).collect();
        self.report.expect(
            Want::Succeed,
            "session-bridge-control",
            format!("{} reaches {bridge} (control)", self.runner.name),
            super::runner_reaches(&probe),
        );
        let mut attempts = Vec::new();
        for (addr, port) in &targets {
            let target = socket_text(addr, *port);
            let probe = tcp_probe(addr, *port);
            let probe: Vec<&str> = probe.iter().map(String::as_str).collect();
            if target != bridge {
                attempts.push(Attempt::control(
                    format!("session-bridge-control:{target}"),
                    &target,
                    &probe,
                ));
            }
            attempts.push(Attempt::refused(
                format!("session-bridge:{target}"),
                format!("{user} can't reach a session's bridge at {target}"),
                &probe,
            ));
        }
        if self.runs_containers() {
            attempts.push(Attempt::refused_in_container(
                "session-bridge-container",
                format!(
                    "a container as subordinate uid {CONTAINER_UID} can't reach a session's bridge at {bridge}"
                ),
                &self.container(&probe),
            ));
        }
        self.attempts(&attempts)?;
        drop(listeners);
        Ok(())
    }

    /// `sandbox.deny-runner-metadata` alone, where there is no sandbox
    /// user to probe beside it (`sandbox.create-user = false`).
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

    fn proxy_url(&self) -> String {
        egress::proxy_url()
    }

    /// The egress proxy: the toolchains fetch through it, it refuses
    /// writes to unlisted endpoints (with its own header, so the refusal
    /// is the proxy's), going around it fails, and it reaches nothing the
    /// sandbox may not, from a container either. A fetch the policy does
    /// not admit (`expected`) is expected to meet the proxy's refusal.
    fn egress(&mut self, expected: &Expected) -> Result<()> {
        let user = self.user()?.to_owned();
        let url = self.config.sandbox.check.control_url.clone();
        let proxy = self.proxy_url();
        let host_name = url_host(&url).to_owned();
        let work = format!("{}/{EGRESS_WORK}", self.entry()?.home().display());
        let refused = |output: Output| refused_by_proxy(&String::from_utf8_lossy(&output.stdout));

        let got = self.sandbox_succeeds(&proxied(&["--proxy", &proxy, &url]))?;
        self.report.expect(
            Want::Succeed,
            "egress-read",
            format!("{user} reads {url} through the egress proxy"),
            got,
        );
        self.sandbox(&["rm", "-rf", &work], b"")?;
        if let Some(refusal) = &expected.cargo {
            self.expect_refusal("egress-cargo-refused", "cargo", refusal)?;
        } else if self.sandbox_has("cargo")? {
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
        if let Some(refusal) = &expected.npm {
            self.expect_refusal("egress-npm-refused", "npm", refusal)?;
        } else if self.sandbox_has("npm")? {
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
        if let Some(refusal) = &expected.git {
            self.expect_refusal("egress-git-refused", "git", refusal)?;
        } else {
            let repo = &self.config.sandbox.check.fetch_repo;
            // `--` keeps the repository an operand, whatever it says.
            let got =
                self.sandbox_succeeds(&["timeout", "60", "git", "ls-remote", "--", repo, "HEAD"])?;
            self.report.expect(
                Want::Succeed,
                "egress-git",
                format!("{user} fetches from {repo} with git (POST git-upload-pack)"),
                got,
            );
        }

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
                &head(&["-H", "Metadata:true", METADATA_URL]),
            )
            .reached_when(proxy_reached),
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
        if self.runs_containers() {
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

        if self.runs_containers() {
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
        let user = self.user()?.to_owned();
        self.runner_write_policy();
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

    /// The runner's half of [`Self::write_policy`], which needs no
    /// sandbox user.
    pub(super) fn runner_write_policy(&mut self) {
        let runner = self.runner.name.clone();
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
    }

    /// That the proxy itself refuses the sandbox user `refusal`, the
    /// request of the `tool` probe's that the policy does not admit: in
    /// place of the fetch, which would only fail, the probe then shows
    /// the policy is the one enforced. It needs curl, not `tool`.
    fn expect_refusal(&mut self, id: &str, tool: &str, refusal: &Refusal) -> Result<()> {
        let Refusal { method, url } = refusal;
        let argv = if *method == "GET" {
            head(&[url])
        } else {
            head(&["-X", method, "-d", "0000", url])
        };
        let got = refused_by_proxy(&String::from_utf8_lossy(&self.sandbox(&argv, b"")?.stdout));
        self.report.expect(
            Want::Succeed,
            id,
            format!(
                "the proxy refuses {tool}'s {method} {url}, which the egress policy does not admit"
            ),
            got,
        );
        Ok(())
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
        let user = self.user()?.to_owned();
        let status = self
            .root
            .tailscale_status()
            .unwrap_or(serde_json::Value::Null);
        let endpoints = network::direct(self.config.egress)?;
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
            if self.runs_containers() {
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
            let mut in_container = Vec::new();
            for (addr, port) in &targets {
                let target = socket_text(addr, *port);
                let probe = tcp_probe(addr, *port);
                let probe: Vec<&str> = probe.iter().map(String::as_str).collect();
                attempts.extend([
                    Attempt::control(format!("tailnet-control:{target}"), &target, &probe),
                    Attempt::refused(
                        format!("tailnet:{target}"),
                        format!("{user} can't reach {target}"),
                        &probe,
                    ),
                ]);
                in_container.push(Attempt::refused_in_container(
                    format!("tailnet-container:{target}"),
                    format!("a container as subordinate uid {CONTAINER_UID} can't reach {target}"),
                    &[],
                ));
            }
            let port = OTHER_TAILNET_PORT.to_string();
            attempts.push(Attempt::refused(
                "tailnet-nc",
                format!("{user} can't dial {host_v4}:{port} through tailscaled (tailscale nc)"),
                &["timeout", "10", "tailscale", "nc", &host_v4, &port],
            ));
            if !self.runs_containers() {
                self.attempts(&attempts)?;
                continue;
            }
            // One container-lane slot for the whole group. Use the same
            // scheduler so it reserves one of the bounded pool's workers
            // and never overlaps another podman start.
            attempts.push(Attempt::refused_in_container(
                "tailnet-container",
                "the tailnet targets",
                &[],
            ));
            let mut results = super::in_order(&attempts, |attempt| {
                if attempt.kind == super::AttemptKind::RefusedInContainer {
                    self.tcp_refusals_in_one_container(&targets)
                } else {
                    Ok(vec![self.make(attempt)?])
                }
            })?;
            let contained = results.pop().expect("one container group");
            attempts.pop();
            let made: Vec<bool> = results.into_iter().flatten().collect();
            let runner = self.runner.name.clone();
            self.report.attempts(&runner, &attempts, &made)?;
            self.report.attempts(&runner, &in_container, &contained)?;
        }
        Ok(())
    }

    /// Whether a rootless container reaches each of `targets`, all tried
    /// at once from one container: one podman start in place of one each,
    /// which made one after another were most of the tailnet's probes'
    /// time. Each keeps [`tcp_probe`]'s timeout. `Err`, as for any
    /// refusal in a container, where the session or podman did not get to
    /// the probes, and where any probe has no result or did not start.
    fn tcp_refusals_in_one_container(&self, targets: &[(String, u16)]) -> Result<Vec<bool>> {
        let id = "tailnet-container";
        let ports: Vec<String> = targets.iter().map(|(_, port)| port.to_string()).collect();
        let mut argv = vec![
            "sh",
            "-c",
            TCP_PROBES_SCRIPT,
            "sh",
            TCP_PROBE_SECONDS,
            TCP_PROBE_SCRIPT,
        ];
        for ((addr, _), port) in targets.iter().zip(&ports) {
            argv.extend([addr.as_str(), port.as_str()]);
        }
        let named: Vec<String> = targets
            .iter()
            .map(|(addr, port)| socket_text(addr, *port))
            .collect();
        let attempt = Attempt::refused_in_container(id, id, &[]);
        crate::timed::stage("check", id, || {
            let output = self.refusal_output(&attempt, &self.container(&argv))?;
            tcp_probe_results(
                id,
                output.status.code(),
                &String::from_utf8_lossy(&output.stdout),
                &named,
            )
        })
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

/// The metadata service at its IPv4 address, not through the egress
/// proxy: what the sandbox user and, with `sandbox.deny-runner-metadata`,
/// the runner's user must not reach.
pub(crate) fn metadata_request() -> Vec<&'static str> {
    direct(&["-H", "Metadata:true", METADATA_URL])
}

/// Through it, failing on an error status: the Rust proxy answers 403 for
/// a private/local destination, or 502 when an allowed connection fails.
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
        TCP_PROBE_SECONDS,
        "bash",
        "-c",
        TCP_PROBE_SCRIPT,
        "probe",
        addr,
        &port.to_string(),
    ]
    .iter()
    .map(|&arg| arg.to_owned())
    .collect()
}

const TCP_PROBE_SECONDS: &str = "10";

const TCP_PROBE_SCRIPT: &str = r#"exec 3<>"/dev/tcp/$1/$2""#;

/// [`tcp_probe`] of each address and port pair after its timeout and
/// script, all at once: a line of the pair's index and its status for
/// each, in the order they end.
const TCP_PROBES_SCRIPT: &str = r#"s=$1 p=$2; shift 2; i=0
while [ "$#" -ge 2 ]; do
  (timeout "$s" bash -c "$p" probe "$1" "$2"; echo "$i $?") &
  i=$((i + 1)); shift 2
done
wait"#;

/// Whether each probe of [`TCP_PROBES_SCRIPT`], one for each of `targets`
/// in order, connected, from its output. A probe with no line, or two, or
/// one whose command did not start, is an error: its refusal would prove
/// nothing.
fn tcp_probe_results(
    id: &str,
    status: Option<i32>,
    stdout: &str,
    targets: &[String],
) -> Result<Vec<bool>> {
    ensure!(
        super::started(status),
        "{id}: podman did not start the container (exit {status:?})"
    );
    let mut codes: Vec<Option<i32>> = vec![None; targets.len()];
    for line in stdout.lines() {
        let (index, code) = line.split_once(' ').with_context(|| {
            format!(
                "{id}: targets {}: unexpected output {line:?}",
                targets.join(", ")
            )
        })?;
        let index = index
            .parse::<usize>()
            .ok()
            .filter(|&i| i < targets.len())
            .with_context(|| {
                format!(
                    "{id}: targets {}: unexpected probe index in {line:?}",
                    targets.join(", ")
                )
            })?;
        let code = code
            .parse::<u8>()
            .with_context(|| format!("{id}:{}: malformed result {line:?}", targets[index]))?;
        let slot = &mut codes[index];
        ensure!(slot.is_none(), "{id}:{}: two results", targets[index]);
        *slot = Some(i32::from(code));
    }
    codes
        .into_iter()
        .zip(targets)
        .map(|(code, target)| {
            let code = code.with_context(|| {
                format!("{id}:{target}: no result, so its refusal proves nothing")
            })?;
            ensure!(
                super::started(Some(code)),
                "{id}:{target}: the probe did not run (exited {code}): its refusal proves nothing"
            );
            Ok(code == 0)
        })
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

/// Whether a request through the egress proxy, its response headers
/// printed ([`head`]), reached its destination: any answer but the
/// proxy's own, which is its refusal or a 502 for a connection it could
/// not open. Azure's metadata service answers a throttled or transient
/// request with 429, 410 or 500, which `--fail` read as the proxy's
/// refusal: with the proxy's rules removed, the probe once held in a
/// tenth of a second where a reach took twice that. No answer at all,
/// the proxy's or another's, reached nothing; the exit status, curl's
/// timeout after the headers included, is not asked.
fn proxy_reached(output: &Output) -> bool {
    let headers = String::from_utf8_lossy(&output.stdout);
    let status = headers.lines().rev().find_map(|line| {
        let mut words = line.split_whitespace();
        words
            .next()
            .is_some_and(|version| version.starts_with("HTTP/"))
            .then(|| words.next())?
    });
    match status {
        None | Some(PROXY_FAILED_STATUS) => false,
        Some(_) => !refused_by_proxy(&headers),
    }
}

/// The status both egress proxies answer with when the connection they
/// were to open failed.
const PROXY_FAILED_STATUS: &str = "502";

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

/// The path of an http or https URL, with its query: `/` where it has
/// none.
fn url_path(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.find(['/', '?', '#']).map_or("/", |at| &rest[at..])
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

    /// The probes made at once report each under its own index: a
    /// listener reached, a closed port refused.
    #[test]
    fn tcp_probes_at_once_report_each_target() {
        let listener = hold("127.0.0.1", 0).unwrap();
        let open = listener.local_addr().unwrap().port().to_string();
        let closed = hold("127.0.0.1", 0)
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
            .to_string();
        let output = std::process::Command::new("sh")
            .args([
                "-c",
                TCP_PROBES_SCRIPT,
                "sh",
                TCP_PROBE_SECONDS,
                TCP_PROBE_SCRIPT,
                "127.0.0.1",
                &closed,
                "127.0.0.1",
                &open,
                "127.0.0.1",
                &closed,
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            tcp_probe_results(
                "t",
                output.status.code(),
                &stdout,
                &["a".into(), "b".into(), "c".into()]
            )
            .unwrap(),
            [false, true, false]
        );
    }

    /// A control is cut short; the refusals beside it keep their longer
    /// timeouts.
    #[test]
    fn controls_are_bounded_below_their_refusals() {
        use super::super::{CONTROL_LIMIT, bounded_control};
        let seconds = |arg: &str| arg.parse::<u32>().unwrap();
        let control = seconds(CONTROL_LIMIT.last().unwrap());
        for refusal in [TCP_PROBE_SECONDS, WIRESERVER_CONNECT_SECONDS] {
            assert!(control < seconds(refusal), "{refusal}");
        }
        let probe = tcp_probe("192.0.2.1", 22);
        let probe: Vec<&str> = probe.iter().map(String::as_str).collect();
        let bounded = bounded_control(&probe);
        assert_eq!(bounded[..CONTROL_LIMIT.len()], *CONTROL_LIMIT);
        assert_eq!(bounded[CONTROL_LIMIT.len()..], probe);
        assert_eq!(TCP_PROBE_SECONDS, "10");
        assert_eq!(WIRESERVER_CONNECT_SECONDS, "5");
        // Exercise the outer deadline, not just its command construction:
        // a control can connect, fail, or stall, without a sandbox session.
        for (argv, code) in [
            (&["true"][..], 0),
            (&["false"][..], 1),
            (&["sleep", "30"][..], 124),
        ] {
            let bounded = bounded_control(argv);
            let status = std::process::Command::new(bounded[0])
                .args(&bounded[1..])
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(code), "{argv:?}");
        }
    }

    #[test]
    fn tcp_probe_results_fail_closed() {
        type Expected<'a> = Result<&'a [bool], &'a str>;

        let cases: &[(&str, i32, usize, Expected<'_>)] = &[
            ("", 0, 0, Ok(&[])),
            ("1 1\n0 0\n", 0, 2, Ok(&[true, false])),
            ("1 124\n0 1\n", 0, 2, Ok(&[false, false])),
            ("0 124\n", 0, 1, Ok(&[false])),
            ("", 0, 1, Err("t:a: no result")),
            ("0 1\n", 0, 2, Err("t:b: no result")),
            ("0 1\n0 1\n", 0, 1, Err("t:a: two results")),
            ("2 1\n", 0, 2, Err("targets a, b: unexpected probe index")),
            (
                "0 127\n",
                0,
                1,
                Err("t:a: the probe did not run (exited 127)"),
            ),
            ("0 125\n", 0, 1, Err("t:a: the probe did not run")),
            ("0 1 extra\n", 0, 1, Err("t:a: malformed result")),
            ("0 -1\n", 0, 1, Err("t:a: malformed result")),
            ("0 256\n", 0, 1, Err("t:a: malformed result")),
            ("refused\n", 0, 1, Err("targets a: unexpected output")),
            ("0 1\n", 125, 1, Err("podman did not start")),
            ("0 1\n", 126, 1, Err("podman did not start")),
            ("0 1\n", 127, 1, Err("podman did not start")),
        ];
        let names = ["a".to_owned(), "b".to_owned()];
        for (stdout, status, count, want) in cases {
            match (
                tcp_probe_results("t", Some(*status), stdout, &names[..*count]),
                want,
            ) {
                (Ok(got), Ok(want)) => assert_eq!(&got, want, "{stdout:?}"),
                (Err(err), Err(want)) => assert!(err.to_string().contains(want), "{err:#}"),
                (got, _) => panic!("{stdout:?}: {got:?}"),
            }
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

    /// An error status of the destination's still reached it: what made
    /// `egress-proxy-metadata` pass with the proxy's rules removed.
    #[test]
    fn what_reached_through_the_proxy() {
        use std::os::unix::process::ExitStatusExt;

        let cases = [
            (
                "HTTP/1.1 200 OK\r\nserver: IMDS/150.870.65.1854\r\n\r\n",
                true,
            ),
            ("HTTP/1.1 429 Too many requests\r\n\r\n", true),
            ("HTTP/1.1 410 Gone\r\n\r\n", true),
            ("HTTP/1.1 500 Internal Server Error\r\n\r\n", true),
            ("HTTP/1.1 403 Forbidden\r\nserver: origin\r\n\r\n", true),
            (
                "HTTP/1.1 502 Bad Gateway\r\nServer: mitmproxy 11.1.3\r\n\r\n",
                false,
            ),
            (
                "HTTP/1.1 403 Forbidden\r\nx-egress-denied: a private or local address\r\n\r\n",
                false,
            ),
            ("", false),
        ];
        // curl's timeout (28) after the headers came, as an exit status.
        let timed_out = 28 << 8;
        for (headers, want) in cases {
            for status in [0, timed_out] {
                let output = Output {
                    status: std::process::ExitStatus::from_raw(status),
                    stdout: headers.as_bytes().to_vec(),
                    stderr: Vec::new(),
                };
                assert_eq!(proxy_reached(&output), want, "{headers:?} {status}");
            }
        }
    }

    #[test]
    fn hosts_and_paths_of_urls() {
        let cases = [
            ("https://github.com/", "github.com", "/"),
            ("http://example.com:8080/a?b", "example.com", "/a?b"),
            ("https://user@example.org", "example.org", "/"),
            ("https://example.org?q", "example.org", "?q"),
            ("http://100.101.102.103:18080/v1", "100.101.102.103", "/v1"),
        ];
        for (url, host, path) in cases {
            assert_eq!(url_host(url), host, "{url}");
            assert_eq!(url_path(url), path, "{url}");
        }
    }

    /// Each probe through the proxy follows the policy it enforces: what
    /// the policy admits must succeed, what it does not must meet the
    /// proxy's refusal, and a control it refuses stops the check.
    #[test]
    fn egress_probes_follow_the_policy() {
        use crate::proxy::policy::ECOSYSTEMS;
        let shipped = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../egress/policy.toml"),
        )
        .unwrap();
        // An allowlist that admits no GitHub host.
        let allowlist = "[egress]\nmode = \"allowlist\"\nallow = [\"rust\", \"registry.npmjs.org\", \"example.org\"]\n";
        let reads_anywhere = "[egress]\nmode = \"reads-anywhere\"\n";
        let repo = "https://github.com/bootc-dev/bootc";
        let git_post = Refusal {
            method: "POST",
            url: format!("{repo}/git-upload-pack"),
        };
        let git_get = Refusal {
            method: "GET",
            url: format!("{repo}/info/refs?service=git-upload-pack"),
        };
        let npm = Refusal {
            method: "GET",
            url: NPM_READS[0].to_owned(),
        };
        // (policy, control URL, fetched repository, what it expects or
        // the error).
        let cases: &[(&str, &str, &str, Result<Expected, &str>)] = &[
            (
                &shipped,
                "https://github.com/",
                repo,
                Ok(Expected {
                    git: None,
                    cargo: None,
                    npm: None,
                }),
            ),
            // A fetch from a host without the write rule.
            (
                &shipped,
                "https://github.com/",
                "https://git.example.org/a/b/",
                Ok(Expected {
                    git: Some(Refusal {
                        method: "POST",
                        url: "https://git.example.org/a/b/git-upload-pack".to_owned(),
                    }),
                    cargo: None,
                    npm: None,
                }),
            ),
            (
                reads_anywhere,
                "https://github.com/",
                repo,
                Ok(Expected {
                    git: Some(git_post),
                    cargo: None,
                    npm: None,
                }),
            ),
            (
                allowlist,
                "https://example.org/",
                repo,
                Ok(Expected {
                    git: Some(git_get),
                    cargo: None,
                    npm: None,
                }),
            ),
            (
                "[egress]\nmode = \"allowlist\"\nallow = [\"crates.io\", \"example.org\"]\n",
                "https://www.example.org/",
                repo,
                Ok(Expected {
                    git: Some(Refusal {
                        method: "GET",
                        url: format!("{repo}/info/refs?service=git-upload-pack"),
                    }),
                    cargo: None,
                    npm: Some(npm),
                }),
            ),
            (
                allowlist,
                "https://github.com/",
                repo,
                Err("control-url \"https://github.com/\""),
            ),
            (
                allowlist,
                "https://notexample.org/",
                repo,
                Err("control-url \"https://notexample.org/\""),
            ),
        ];
        for (policy, control, fetch, want) in cases {
            let parsed = Policy::parse(policy, ECOSYSTEMS).unwrap();
            let got = expected(&parsed, control, fetch);
            match (got, want) {
                (Ok(got), Ok(want)) => assert_eq!(&got, want, "{policy} {control} {fetch}"),
                (Err(err), Err(want)) => {
                    assert!(err.to_string().contains(want), "{err:#}");
                }
                (got, _) => panic!("{policy} {control} {fetch}: {got:?}"),
            }
        }
    }

    #[test]
    fn containers_off_names_every_probe_that_runs_one() {
        let base = [
            "container-pull",
            "container-build",
            "container-built-run",
            "container-control",
            "container-metadata",
        ];
        let egress = [
            "egress-container-direct",
            "egress-container-own-network",
            "egress-container-post",
        ];
        let tailnet = ["tailnet-container-direct", "tailnet-container:*"];
        let session = ["session-bridge-container"];
        for (with_egress, with_tailnet, with_session) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (true, true, false),
            (false, false, true),
            (true, true, true),
        ] {
            let want: Vec<&str> = base
                .iter()
                .chain(egress.iter().filter(|_| with_egress))
                .chain(tailnet.iter().filter(|_| with_tailnet))
                .chain(session.iter().filter(|_| with_session))
                .copied()
                .collect();
            assert_eq!(
                skipped_containers(with_egress, with_tailnet, with_session),
                want
            );
        }
    }

    /// The bridge's probes follow the configuration and the node's own
    /// tailnet addresses: none without a session, loopback alone without
    /// the tailnet, and each own address at the bridge's and serve's ports.
    #[test]
    fn session_bridge_probes_follow_the_configuration() {
        let up: serde_json::Value = serde_json::from_str(
            r#"{"Self": {"TailscaleIPs": ["100.72.1.2", "fd7a:115c:a1e0::1"]},
                "Peer": {"a": {"TailscaleIPs": ["100.101.102.103"]}}}"#,
        )
        .unwrap();
        let no_addresses: serde_json::Value =
            serde_json::from_str(r#"{"Self": {"TailscaleIPs": []}}"#).unwrap();
        let null = serde_json::Value::Null;
        let loopback = ("127.0.0.1", 7790);
        let cases = [
            (None, &up, &[][..]),
            (None, &null, &[]),
            (Some(7790), &null, &[loopback]),
            (Some(7790), &no_addresses, &[loopback]),
            (
                Some(7790),
                &up,
                &[
                    loopback,
                    ("100.72.1.2", 7790),
                    ("100.72.1.2", 443),
                    ("fd7a:115c:a1e0::1", 7790),
                    ("fd7a:115c:a1e0::1", 443),
                ],
            ),
        ];
        for (listen, status, want) in cases {
            let want: Vec<(String, u16)> = want
                .iter()
                .map(|&(addr, port)| (addr.to_owned(), port))
                .collect();
            assert_eq!(bridge_targets(listen, status), want, "{listen:?} {status}");
        }
        assert_eq!(
            socket_text("fd7a:115c:a1e0::1", 443),
            "[fd7a:115c:a1e0::1]:443"
        );
        assert_eq!(socket_text("127.0.0.1", 7790), "127.0.0.1:7790");
    }

    /// A port something already listens at is no control: whatever holds
    /// it would be handed serve's connections.
    #[test]
    fn a_bridge_control_is_a_listener_of_the_checks_own() {
        let first = hold("127.0.0.1", 0).unwrap();
        let port = first.local_addr().unwrap().port();
        let err = hold("127.0.0.1", port).unwrap_err();
        assert!(
            err.to_string()
                .starts_with(&format!("listening at 127.0.0.1:{port}, where")),
            "{err:#}"
        );
        let err = hold("bridge", port).unwrap_err();
        assert!(err.to_string().contains("not an IP address"), "{err:#}");
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
