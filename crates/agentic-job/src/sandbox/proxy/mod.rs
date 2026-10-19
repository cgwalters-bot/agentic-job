//! The egress proxy in Rust: `sandbox egress-proxy`, which `sandbox
//! setup` starts by default, and mitmproxy in its place with
//! `egress.rust-proxy = false` (docs/sandbox.md).
//!
//! It does what `egress/addon.py` has mitmproxy do. It listens for proxy
//! requests: a plain HTTP request in absolute form, or a CONNECT, which
//! it refuses unless [`policy::Policy::connect`] allows the host. In an
//! allowed tunnel it ends TLS with a certificate its own authority signs
//! for the name the client asked for ([`tls`]), or reads plain HTTP; and
//! anything that is not HTTP/1.1 there fails to parse and ends the
//! connection, as mitmproxy's does with raw TCP off, so no other
//! protocol passes unseen. Every request is then decided by
//! [`policy::Policy::request`] against the host the connection goes to,
//! which is the CONNECT's or the URL's, never the Host header's.
//! Before any policy, the sandbox user is refused the destinations of
//! `--refuse` ([`Refused`]), by name and by address.
//!
//! A refusal is a 403 with the reason in `X-Egress-Denied`. An allowed
//! request is sent on to the real server, over TLS checked against
//! Mozilla's roots when the client's was; the proxy connects only once a
//! request is allowed, and the response streams back unread. The access
//! log is `addon.py`'s, line for line: method, host, port, path without
//! the query string, decision, never headers or bodies.

pub mod policy;
pub mod tls;

use std::convert::Infallible;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::{Body as _, Incoming};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::exit::Exit;
use policy::{Decision, Policy};
use tls::Authority;

/// On every refusal, so clients and checks can tell it from the server's.
pub const DENIED_HEADER: &str = "X-Egress-Denied";

/// Why a destination of `--refuse` is refused, before any policy.
pub const REFUSED_DESTINATION: &str =
    "the destination is one only the runner may reach (inference.front's broker)";

/// Longest path kept in the log, in characters.
const MAX_LOGGED_PATH: usize = 200;

/// Connections from the sandbox user served at once; more wait to be
/// accepted. Each holds a few file descriptors and, in a tunnel, one to
/// the server.
const MAX_CONNECTIONS: usize = 1024;

/// How long a client has to send a request's headers, or its first byte
/// in a tunnel.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a TLS handshake, or a connection to a server, may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a server has to answer an allowed request with its
/// response's headers, and how long an upgraded connection may pass
/// nothing either way: past them it is closed, so that a peer that stalls
/// does not keep one of [`MAX_CONNECTIONS`] for ever. Generous, for a
/// server that answers only once it has a large upload, or a long
/// completion.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

const UPGRADED_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// The first byte of a TLS record that carries a handshake: what a
/// client sends first in a tunnel when it speaks TLS.
const TLS_HANDSHAKE: u8 = 0x16;

const HTTP_PORT: u16 = 80;

const HTTPS_PORT: u16 = 443;

const SCHEME_HTTP: &str = "http";

const SCHEME_HTTPS: &str = "https";

/// The access log's decisions.
const ALLOW: &str = "allow";

const DENY: &str = "deny";

/// Headers addressed to the proxy, which the server never sees: a
/// credential for the proxy must not reach every host the client asks.
const PROXY_HEADERS: &[&str] = &["proxy-connection", "proxy-authorization"];

/// Why redirected TLS that names no server is refused: the proxy would
/// have no name to decide on or to connect to.
const NO_SERVER_NAME: &str = "TLS without a server name";

/// The protocol a WebSocket is upgraded to, in `Upgrade`.
const WEBSOCKET: &str = "websocket";

type Body = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The address to listen on
    #[arg(long)]
    pub listen: SocketAddr,
    /// policy.toml: the write rules and the optional domain allowlist
    #[arg(long)]
    pub policy: PathBuf,
    /// The threat feed: domains refused, one per line
    #[arg(long)]
    pub denylist: Option<PathBuf>,
    /// The access log, appended as JSON lines
    #[arg(long)]
    pub log: Option<PathBuf>,
    /// The proxy's own directory, where its authority's key is kept
    #[arg(long)]
    pub state_dir: PathBuf,
    /// Also take connections the network rules redirect here
    /// (`egress.write-policy`), decided with the runner's own writes
    /// added to the policy
    #[arg(long)]
    pub transparent: Option<SocketAddr>,
    /// HOST:PORT ([ADDRESS]:PORT for IPv6) the sandbox user is refused,
    /// whatever the policy says: by name, and at every address the proxy
    /// would connect to for it (`inference.front`'s broker)
    #[arg(long = "refuse", value_name = "HOST:PORT")]
    pub refuse: Vec<String>,
}

pub fn run(args: &Args) -> Result<Exit> {
    let policy = Policy::load(&args.policy, args.denylist.as_deref())?;
    let refused = Refused::parse(&args.refuse)?;
    let authority = Authority::load_or_create(&args.state_dir)?;
    let log = args
        .log
        .as_ref()
        .map(|path| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("opening {}", path.display()))
        })
        .transpose()?;
    let mut proxy = Proxy::new(
        policy,
        authority,
        tls::client_config(tls::mozilla_roots())?,
        log,
    )?;
    proxy.refused = refused;
    let proxy = Arc::new(proxy);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(async {
        // What the names resolve to now, kept should they later not.
        proxy.refused_addresses().await;
        let listener = TcpListener::bind(args.listen)
            .await
            .with_context(|| format!("listening on {}", args.listen))?;
        // Both bound before either serves, so that setup, which waits
        // for the first, never finds the proxy up without the second.
        let Some(transparent) = args.transparent else {
            return proxy.serve(listener, false).await;
        };
        let redirected = TcpListener::bind(transparent)
            .await
            .with_context(|| format!("listening on {transparent}"))?;
        tokio::try_join!(
            proxy.clone().serve(listener, false),
            proxy.serve(redirected, true)
        )
        .map(|_| ())
    })?;
    Ok(Exit::Success)
}

/// Where the requests of one client connection go: the CONNECT's host
/// and port, or the URL's.
#[derive(Debug, Clone)]
struct Target {
    scheme: &'static str,
    host: String,
    port: u16,
    /// The TLS server name the client asked for, in a tunnel.
    sni: Option<String>,
    /// Whether the connection came to the transparent listener, whose
    /// requests are decided by [`Proxy::runner_policy`].
    transparent: bool,
    /// The client connection's place among [`MAX_CONNECTIONS`], held
    /// by whatever outlives hyper's serving it: a tunnel, an upgrade.
    slot: Slot,
}

type Slot = Arc<OwnedSemaphorePermit>;

/// One access log line, as `addon.py` writes it.
struct Entry<'a> {
    decision: &'a str,
    reason: &'a str,
    method: &'a str,
    scheme: &'a str,
    host: &'a str,
    port: u16,
    path: &'a str,
    status: Option<u16>,
    error: Option<&'a str>,
}

/// S as Python's `json.dumps` writes it: escaped as JSON, and anything
/// not ASCII as `\uXXXX`.
fn py_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in serde_json::Value::from(s).to_string().chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

impl Entry<'_> {
    /// The line, keys in `addon.py`'s order and with `json.dumps`'s
    /// separators, so that the two proxies' logs read alike.
    fn line(&self, time: &str) -> String {
        let string = |value: &str| py_json_string(value);
        let path: String = self
            .path
            .split('?')
            .next()
            .unwrap_or_default()
            .chars()
            .take(MAX_LOGGED_PATH)
            .collect();
        format!(
            "{{\"time\": {}, \"decision\": {}, \"reason\": {}, \"method\": {}, \"scheme\": {}, \
             \"host\": {}, \"port\": {}, \"path\": {}, \"status\": {}, \"error\": {}}}",
            string(time),
            string(self.decision),
            string(self.reason),
            string(self.method),
            string(self.scheme),
            string(self.host),
            self.port,
            string(&path),
            self.status
                .map_or("null".to_owned(), |status| status.to_string()),
            self.error.map_or("null".to_owned(), string),
        )
    }
}

fn full(text: String) -> Body {
    Full::new(Bytes::from(text))
        .map_err(|never| match never {})
        .boxed()
}

fn empty() -> Body {
    Empty::new().map_err(|never| match never {}).boxed()
}

fn text_response(status: StatusCode, text: String) -> Response<Body> {
    let mut response = Response::new(full(text));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// Whether HEADERS announce a body.
fn has_body_headers(headers: &HeaderMap) -> bool {
    let length = headers
        .get(header::CONTENT_LENGTH)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).trim().to_owned())
        .unwrap_or_default();
    !(length.is_empty() || length == "0") || headers.contains_key(header::TRANSFER_ENCODING)
}

/// Whether HEADERS' `Upgrade` names a WebSocket and nothing else: in a
/// request, what the policy takes for a WebSocket; in a 101, what the
/// server switched to. An offer of several protocols is not one, so a
/// server cannot pick another of them for a WebSocket's write rule.
fn only_websocket(headers: &HeaderMap) -> bool {
    let mut protocols = headers
        .get_all(header::UPGRADE)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .map(|protocol| {
            String::from_utf8_lossy(protocol)
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|protocol| !protocol.is_empty());
    protocols
        .next()
        .is_some_and(|protocol| protocol == WEBSOCKET)
        && protocols.next().is_none()
}

/// A stream that gives BYTE before what INNER gives: the byte the proxy
/// read to tell TLS from plain HTTP in a tunnel.
struct Prefixed<S> {
    byte: Option<u8>,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() > 0
            && let Some(byte) = self.byte.take()
        {
            buf.put_slice(&[byte]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A stream that notes in LAST when a byte last went through it.
struct Watched<S> {
    inner: S,
    last: Arc<Mutex<tokio::time::Instant>>,
}

impl<S> Watched<S> {
    fn touch(&self) {
        *lock(&self.last) = tokio::time::Instant::now();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.touch();
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(poll, Poll::Ready(Ok(written)) if written > 0) {
            self.touch();
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Passes bytes both ways between A and B until both have ended, or
/// neither has moved a byte for IDLE.
async fn bridge<A, B>(a: A, b: B, idle: Duration)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let last = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let mut a = Watched {
        inner: a,
        last: last.clone(),
    };
    let mut b = Watched {
        inner: b,
        last: last.clone(),
    };
    let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
    tokio::pin!(copy);
    loop {
        let deadline = *lock(&last) + idle;
        tokio::select! {
            _ = &mut copy => return,
            () = tokio::time::sleep_until(deadline) => {
                if lock(&last).elapsed() >= idle {
                    return;
                }
            }
        }
    }
}

/// The destinations of `--refuse`, which the sandbox user's requests may
/// not reach whatever the policy allows: under `inference.front` the
/// broker, where the agent would otherwise register runs of its own. A
/// request is refused when it names one's host (or an address of it in
/// any of its spellings), and a connection when any address the proxy
/// resolved for it is one's, so that another name for the broker, or a
/// name that resolves to it only when the proxy connects, is refused
/// too. Each is refused at every port, not only its own: a server there
/// may serve the broker at another. The port given is where the name is
/// resolved. The runner's own connections (the transparent listener) are
/// not held to this; `inference.front` refuses `egress.write-policy`.
#[derive(Debug, Default)]
struct Refused {
    /// Each destination's host, normalized, an address canonical
    /// ([`std::net::IpAddr::to_canonical`]), and its port.
    destinations: Vec<(String, u16)>,
    /// Every address a destination has been seen at: its own if it is an
    /// address, and each one its name has resolved to here. An address
    /// stays refused when the name later resolves elsewhere, or not at
    /// all.
    addresses: Mutex<std::collections::HashSet<std::net::IpAddr>>,
}

/// ADDRESS's IP as one spelling: an IPv4-mapped IPv6 address as IPv4.
fn canonical(address: SocketAddr) -> std::net::IpAddr {
    address.ip().to_canonical()
}

impl Refused {
    /// From `--refuse`'s HOST:PORT or [ADDRESS]:PORT.
    fn parse(given: &[String]) -> Result<Self> {
        let mut refused = Self::default();
        for text in given {
            let (host, port) = match text.parse::<SocketAddr>() {
                Ok(address) => {
                    let ip = canonical(address);
                    lock(&refused.addresses).insert(ip);
                    (ip.to_string(), address.port())
                }
                Err(_) => {
                    let (host, port) = text
                        .rsplit_once(':')
                        .with_context(|| format!("--refuse {text:?}: not HOST:PORT"))?;
                    let host = policy::normalize_host(host);
                    let port = port
                        .parse::<u16>()
                        .ok()
                        .filter(|&port| port != 0)
                        .with_context(|| format!("--refuse {text:?}: a bad port"))?;
                    if host.is_empty() || host.contains([':', '[', ']', '/']) {
                        bail!("--refuse {text:?}: not HOST:PORT");
                    }
                    (host, port)
                }
            };
            refused.destinations.push((host, port));
        }
        Ok(refused)
    }

    /// Whether HOST, as a request names it, is a destination's.
    fn names(&self, host: &str) -> bool {
        let host = policy::normalize_host(host);
        let address = host
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical());
        self.destinations.iter().any(|(refused, _)| {
            *refused == host
                || address.is_some_and(|ip| refused.parse::<std::net::IpAddr>().ok() == Some(ip))
        })
    }

    /// The names among the destinations, with their ports.
    fn names_to_resolve(&self) -> Vec<(String, u16)> {
        self.destinations
            .iter()
            .filter(|(host, _)| host.parse::<std::net::IpAddr>().is_err())
            .cloned()
            .collect()
    }
}

/// A connection refused because an address it would go to is one of
/// [`Refused`]'s.
#[derive(Debug)]
struct RefusedAddress(SocketAddr);

impl std::fmt::Display for RefusedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is a refused destination's address", self.0)
    }
}

impl std::error::Error for RefusedAddress {}

/// A client connection's connection to its server, kept for its next
/// request: in a tunnel every request goes to the same place.
type Upstream = Arc<tokio::sync::Mutex<Option<SendRequest<Body>>>>;

struct Proxy {
    policy: Policy,
    /// The policy with the runner's own writes
    /// ([`Policy::with_runner_writes`]), for the transparent listener's
    /// connections alone.
    runner_policy: Policy,
    /// `--refuse`: refused to the sandbox user before any policy.
    refused: Refused,
    authority: Authority,
    upstream_tls: Arc<ClientConfig>,
    log: Option<Mutex<File>>,
    /// [`MAX_CONNECTIONS`], [`RESPONSE_TIMEOUT`] and
    /// [`UPGRADED_IDLE_TIMEOUT`], which the tests make smaller.
    max_connections: usize,
    response_timeout: Duration,
    idle_timeout: Duration,
    /// The tests' names under `.test` (RFC 6761, never resolved), each
    /// with its subdomains, and the loopback port each stands for; any
    /// other name is loopback's closed port 1, never DNS.
    #[cfg(test)]
    origins: Vec<(String, u16)>,
}

impl Proxy {
    fn new(
        policy: Policy,
        authority: Authority,
        upstream_tls: Arc<ClientConfig>,
        log: Option<File>,
    ) -> Result<Self> {
        Ok(Self {
            runner_policy: policy.with_runner_writes()?,
            policy,
            refused: Refused::default(),
            authority,
            upstream_tls,
            log: log.map(Mutex::new),
            max_connections: MAX_CONNECTIONS,
            response_timeout: RESPONSE_TIMEOUT,
            idle_timeout: UPGRADED_IDLE_TIMEOUT,
            #[cfg(test)]
            origins: Vec::new(),
        })
    }

    fn policy_for(&self, target: &Target) -> &Policy {
        if target.transparent {
            &self.runner_policy
        } else {
            &self.policy
        }
    }

    /// Serves LISTENER's clients: proxy requests, or with TRANSPARENT
    /// connections redirected to it ([`Self::transparent`]).
    async fn serve(self: Arc<Self>, listener: TcpListener, transparent: bool) -> Result<()> {
        let slots = Arc::new(Semaphore::new(self.max_connections));
        loop {
            let slot = Arc::new(slots.clone().acquire_owned().await?);
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(err) => {
                    // Out of file descriptors, say: the next may work.
                    eprintln!("egress proxy: accepting a connection: {err}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let proxy = self.clone();
            if transparent {
                tokio::spawn(proxy.transparent(stream, slot));
            } else {
                tokio::spawn(proxy.client(stream, slot));
            }
        }
    }

    fn record(&self, entry: &Entry<'_>) {
        let Some(log) = &self.log else {
            return;
        };
        let time = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let line = format!("{}\n", entry.line(&time));
        let mut file = lock(log);
        if let Err(err) = file.write_all(line.as_bytes()) {
            eprintln!("egress proxy: writing the access log: {err}");
        }
    }

    fn denied(&self, entry: Entry<'_>) -> Response<Body> {
        let reason = entry.reason;
        self.record(&Entry {
            decision: DENY,
            status: Some(StatusCode::FORBIDDEN.as_u16()),
            ..entry
        });
        let mut response = text_response(
            StatusCode::FORBIDDEN,
            format!("refused by the egress proxy: {reason}\n"),
        );
        // Every reason is the policy's own text or a rule's name, which a
        // header can hold; one that could not is still a refusal.
        let value =
            HeaderValue::from_str(reason).unwrap_or_else(|_| HeaderValue::from_static("refused"));
        response.headers_mut().insert(DENIED_HEADER, value);
        response
    }

    /// One connection from the sandbox user: proxy requests.
    async fn client(self: Arc<Self>, stream: TcpStream, slot: Slot) {
        let proxy = self.clone();
        let service = service_fn(move |request| {
            let (proxy, slot) = (proxy.clone(), slot.clone());
            async move { Ok::<_, Infallible>(proxy.outer(request, slot).await) }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await;
    }

    async fn outer(self: Arc<Self>, request: Request<Incoming>, slot: Slot) -> Response<Body> {
        if request.method() == Method::CONNECT {
            return self.connect(request, slot).await;
        }
        let uri = request.uri();
        let (Some(scheme), Some(host)) = (uri.scheme_str(), uri.host()) else {
            return text_response(
                StatusCode::BAD_REQUEST,
                "the egress proxy takes proxy requests: a URL with its host, or CONNECT\n"
                    .to_owned(),
            );
        };
        let scheme = match scheme {
            SCHEME_HTTP => SCHEME_HTTP,
            SCHEME_HTTPS => SCHEME_HTTPS,
            _ => {
                return text_response(
                    StatusCode::BAD_REQUEST,
                    format!("the egress proxy does not speak {scheme}\n"),
                );
            }
        };
        let default_port = if scheme == SCHEME_HTTPS {
            HTTPS_PORT
        } else {
            HTTP_PORT
        };
        let target = Target {
            scheme,
            host: bare_host(host),
            port: uri.port_u16().unwrap_or(default_port),
            sni: None,
            slot,
            transparent: false,
        };
        self.forward(request, &target, None).await
    }

    async fn connect(self: Arc<Self>, request: Request<Incoming>, slot: Slot) -> Response<Body> {
        let Some(authority) = request.uri().authority() else {
            return text_response(
                StatusCode::BAD_REQUEST,
                "CONNECT needs a host and a port\n".to_owned(),
            );
        };
        let host = bare_host(authority.host());
        let port = authority.port_u16().unwrap_or(HTTPS_PORT);
        // A name is resolved only once the policy would let the tunnel
        // open: a refused one is never looked up.
        let decision = match self.refused.names(&host) {
            true => Decision::deny(REFUSED_DESTINATION),
            false => self.policy.connect(&host),
        };
        let decision = if decision.allowed && self.resolves_refused(&host, port).await {
            Decision::deny(REFUSED_DESTINATION)
        } else {
            decision
        };
        if !decision.allowed {
            return self.denied(Entry {
                decision: DENY,
                reason: &decision.reason,
                method: Method::CONNECT.as_str(),
                // mitmproxy's, for a CONNECT.
                scheme: "",
                host: &host,
                port,
                path: "",
                status: None,
                error: None,
            });
        }
        tokio::spawn(async move {
            if let Ok(upgraded) = hyper::upgrade::on(request).await {
                self.tunnel(TokioIo::new(upgraded), host, port, slot).await;
            }
        });
        Response::new(empty())
    }

    /// What goes through an allowed CONNECT: TLS, which the proxy ends,
    /// or plain HTTP.
    async fn tunnel<S>(self: Arc<Self>, stream: S, host: String, port: u16, slot: Slot)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Some((first, stream)) = first_byte(stream).await else {
            return;
        };
        if first != TLS_HANDSHAKE {
            let target = Target {
                scheme: SCHEME_HTTP,
                host,
                port,
                sni: None,
                slot,
                transparent: false,
            };
            return self.inner(stream, target).await;
        }
        let Some(start) = start_tls(stream).await else {
            return;
        };
        let sni = start.client_hello().server_name().map(str::to_owned);
        let Some(tls) = self
            .finish_tls(start, sni.as_deref().unwrap_or(&host))
            .await
        else {
            return;
        };
        let target = Target {
            scheme: SCHEME_HTTPS,
            host,
            port,
            sni,
            slot,
            transparent: false,
        };
        self.inner(tls, target).await;
    }

    /// A connection the network rules redirected from one of the runner's
    /// processes (`egress.write-policy`): TLS, decided by the server name
    /// it asks for and sent on to that name's port 443, or plain HTTP,
    /// each request by its Host header, to that host's port (80 unless it
    /// names one). The address and port the client dialed are not asked
    /// of the kernel (`SO_ORIGINAL_DST` needs unsafe code): the rules
    /// redirect only ports 80 and 443, and the proxy connects where the
    /// name it decided on resolves, never to the address dialed, so a
    /// name cannot front for an address. TLS without a name, to an
    /// address, is refused.
    async fn transparent(self: Arc<Self>, stream: TcpStream, slot: Slot) {
        let Some((first, stream)) = first_byte(stream).await else {
            return;
        };
        if first != TLS_HANDSHAKE {
            return self.redirected_http(stream, slot).await;
        }
        let Some(start) = start_tls(stream).await else {
            return;
        };
        let host = start.client_hello().server_name().map(bare_host);
        let decision = host.as_deref().map_or_else(
            || Decision::deny(NO_SERVER_NAME),
            |host| self.runner_policy.connect(host),
        );
        let (Some(host), true) = (&host, decision.allowed) else {
            self.record(&Entry {
                decision: DENY,
                reason: &decision.reason,
                method: Method::CONNECT.as_str(),
                scheme: "",
                host: host.as_deref().unwrap_or_default(),
                port: HTTPS_PORT,
                path: "",
                status: None,
                error: None,
            });
            return;
        };
        let Some(tls) = self.finish_tls(start, host).await else {
            return;
        };
        let target = Target {
            scheme: SCHEME_HTTPS,
            sni: Some(host.clone()),
            host: host.clone(),
            port: HTTPS_PORT,
            slot,
            transparent: true,
        };
        self.inner(tls, target).await;
    }

    /// Plain HTTP redirected from the runner: each request goes where
    /// its one Host header says.
    async fn redirected_http<S>(self: Arc<Self>, stream: S, slot: Slot)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let proxy = self.clone();
        let service = service_fn(move |request: Request<Incoming>| {
            let (proxy, slot) = (proxy.clone(), slot.clone());
            async move {
                let mut hosts = request.headers().get_all(header::HOST).iter();
                let authority = match (hosts.next(), hosts.next()) {
                    (Some(host), None) => host
                        .to_str()
                        .ok()
                        .and_then(|host| host.parse::<hyper::http::uri::Authority>().ok()),
                    _ => None,
                };
                let Some(authority) = authority else {
                    return Ok::<_, Infallible>(text_response(
                        StatusCode::BAD_REQUEST,
                        "the egress proxy needs one Host header to know where a redirected request goes\n"
                            .to_owned(),
                    ));
                };
                let target = Target {
                    scheme: SCHEME_HTTP,
                    host: bare_host(authority.host()),
                    port: authority.port_u16().unwrap_or(HTTP_PORT),
                    sni: None,
                    slot,
                    transparent: true,
                };
                Ok(proxy.forward(request, &target, None).await)
            }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await;
    }

    /// Ends the TLS that START began with a certificate for NAME.
    async fn finish_tls<S>(
        &self,
        start: tokio_rustls::StartHandshake<S>,
        name: &str,
    ) -> Option<tokio_rustls::server::TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let config = match self.authority.server_config(name) {
            Ok(config) => config,
            Err(err) => {
                eprintln!("egress proxy: {err:#}");
                return None;
            }
        };
        timeout(HANDSHAKE_TIMEOUT, start.into_stream(config))
            .await
            .ok()?
            .ok()
    }

    /// The requests in a tunnel, each to TARGET.
    async fn inner<S>(self: Arc<Self>, stream: S, target: Target)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let target = Arc::new(target);
        let upstream = Upstream::default();
        let proxy = self.clone();
        let service = service_fn(move |request| {
            let (proxy, target, upstream) = (proxy.clone(), target.clone(), upstream.clone());
            async move { Ok::<_, Infallible>(proxy.forward(request, &target, Some(&upstream)).await) }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await;
    }

    /// Decides REQUEST to TARGET, and sends it on if it is allowed.
    async fn forward(
        &self,
        request: Request<Incoming>,
        target: &Target,
        upstream: Option<&Upstream>,
    ) -> Response<Body> {
        let method = request.method().as_str().to_owned();
        let path = request
            .uri()
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .to_owned();
        let headers = request.headers();
        let hosts: Vec<String> = headers
            .get_all(header::HOST)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect();
        let websocket = only_websocket(headers);
        let has_body = has_body_headers(headers) || !request.body().is_end_stream();
        let decision = if !target.transparent && self.refused.names(&target.host) {
            Decision::deny(REFUSED_DESTINATION)
        } else if hosts.len() > 1 {
            // Which one a server reads is its own choice: the one the
            // policy did not check would be a way to front.
            Decision::deny(policy::OTHER_HOST)
        } else {
            self.policy_for(target).request(&policy::Request {
                method: &method,
                host: &target.host,
                path: &path,
                host_header: hosts.first().map(String::as_str),
                sni: target.sni.as_deref(),
                has_body,
                websocket,
            })
        };
        let entry = Entry {
            decision: ALLOW,
            reason: &decision.reason,
            method: &method,
            scheme: target.scheme,
            host: &target.host,
            port: target.port,
            path: &path,
            status: None,
            error: None,
        };
        if !decision.allowed {
            return self.denied(entry);
        }
        match self.send(request, target, upstream, websocket).await {
            Ok(response) => {
                self.record(&Entry {
                    status: Some(response.status().as_u16()),
                    ..entry
                });
                response
            }
            Err(err) if err.downcast_ref::<RefusedAddress>().is_some() => self.denied(Entry {
                reason: REFUSED_DESTINATION,
                ..entry
            }),
            Err(err) => {
                let error = format!("{err:#}");
                self.record(&Entry {
                    error: Some(&error),
                    ..entry
                });
                text_response(StatusCode::BAD_GATEWAY, format!("egress proxy: {error}\n"))
            }
        }
    }

    /// Sends the allowed REQUEST to TARGET, on UPSTREAM's connection if
    /// it has one that is still open. Only a WEBSOCKET, which the policy
    /// took for a write, may be upgraded.
    async fn send(
        &self,
        mut request: Request<Incoming>,
        target: &Target,
        upstream: Option<&Upstream>,
        websocket: bool,
    ) -> Result<Response<Body>> {
        let upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
        let (mut parts, body) = request.into_parts();
        let origin_form = parts
            .uri
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .parse::<Uri>()
            .context("the request's path")?;
        parts.uri = origin_form;
        parts.version = Version::HTTP_11;
        for name in PROXY_HEADERS {
            parts.headers.remove(*name);
        }
        if !parts.headers.contains_key(header::HOST) {
            let default = if target.scheme == SCHEME_HTTPS {
                HTTPS_PORT
            } else {
                HTTP_PORT
            };
            let host = if target.host.contains(':') {
                format!("[{}]", target.host)
            } else {
                target.host.clone()
            };
            let host = if target.port == default {
                host
            } else {
                format!("{host}:{}", target.port)
            };
            parts
                .headers
                .insert(header::HOST, HeaderValue::from_str(&host)?);
        }
        let request = Request::from_parts(parts, body.boxed());

        let kept = match upstream {
            Some(upstream) => upstream.lock().await.take(),
            None => None,
        };
        let mut sender = match kept {
            Some(mut sender) => match sender.ready().await {
                Ok(()) => sender,
                Err(_) => self.open(target).await?,
            },
            None => self.open(target).await?,
        };
        let mut response = timeout(self.response_timeout, sender.send_request(request))
            .await
            .map_err(|_| anyhow!("timed out waiting for the response"))
            .and_then(|response| response.map_err(anyhow::Error::from))
            .with_context(|| format!("sending the request to {}", target.host))?;
        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            // Any other protocol (h2c, say) would pass both ways unread,
            // a read's request turned into a channel for writes: refused,
            // as mitmproxy without raw TCP refuses it.
            let Some(client) = upgrade else {
                bail!("the server switched protocols for a request that is not a WebSocket");
            };
            if !only_websocket(response.headers()) {
                bail!("the server switched to a protocol other than the WebSocket asked for");
            }
            // A WebSocket, which needed a write rule: the connection is
            // the client's alone now, both ways, unread.
            let server = hyper::upgrade::on(&mut response);
            let (slot, idle) = (target.slot.clone(), self.idle_timeout);
            tokio::spawn(async move {
                if let (Ok(client), Ok(server)) = tokio::join!(client, server) {
                    bridge(TokioIo::new(client), TokioIo::new(server), idle).await;
                }
                drop(slot);
            });
        } else if let Some(upstream) = upstream {
            *upstream.lock().await = Some(sender);
        }
        Ok(response.map(BodyExt::boxed))
    }

    /// A new connection to TARGET's server.
    async fn open(&self, target: &Target) -> Result<SendRequest<Body>> {
        let addrs = self.resolve(&target.host, target.port).await?;
        // Of the very addresses connected to below, so that no name
        // resolves to the broker after it was checked.
        if !target.transparent && !self.refused.destinations.is_empty() {
            let refused = self.refused_addresses().await;
            if let Some(addr) = addrs
                .iter()
                .find(|addr| refused.contains(&canonical(**addr)))
            {
                return Err(RefusedAddress(*addr).into());
            }
        }
        let mut last = None;
        let mut stream = None;
        for addr in addrs {
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(connected)) => {
                    stream = Some(connected);
                    break;
                }
                Ok(Err(err)) => last = Some(anyhow!(err)),
                Err(_) => last = Some(anyhow!("timed out")),
            }
        }
        let Some(stream) = stream else {
            let err = last.unwrap_or_else(|| anyhow!("no address"));
            return Err(err.context(format!("connecting to {}:{}", target.host, target.port)));
        };
        let _ = stream.set_nodelay(true);
        if target.scheme == SCHEME_HTTPS {
            let connector = tokio_rustls::TlsConnector::from(self.upstream_tls.clone());
            let name = tls::server_name(&target.host)?;
            let tls = timeout(HANDSHAKE_TIMEOUT, connector.connect(name, stream))
                .await
                .map_err(|_| anyhow!("timed out"))
                .and_then(|tls| tls.map_err(anyhow::Error::from))
                .with_context(|| format!("TLS with {}", target.host))?;
            handshake(tls).await
        } else {
            handshake(stream).await
        }
    }

    /// [`Refused::addresses`], with what each refused name resolves to
    /// now added. A name that does not resolve leaves what it resolved
    /// to before: the proxy cannot reach it by that name either.
    async fn refused_addresses(&self) -> std::collections::HashSet<std::net::IpAddr> {
        for (host, port) in self.refused.names_to_resolve() {
            if let Ok(addrs) = self.resolve(&host, port).await {
                lock(&self.refused.addresses).extend(addrs.into_iter().map(canonical));
            }
        }
        lock(&self.refused.addresses).clone()
    }

    /// Whether HOST at PORT resolves now to a refused destination's
    /// address: a tunnel to it is refused at once, as every connection
    /// through it would be ([`Self::open`] checks again).
    async fn resolves_refused(&self, host: &str, port: u16) -> bool {
        if self.refused.destinations.is_empty() {
            return false;
        }
        let Ok(addrs) = self.resolve(host, port).await else {
            return false;
        };
        let refused = self.refused_addresses().await;
        addrs.iter().any(|addr| refused.contains(&canonical(*addr)))
    }

    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        #[cfg(test)]
        if !self.origins.is_empty() {
            let port = self
                .origins
                .iter()
                .find(|(name, _)| host == name || host.ends_with(&format!(".{name}")))
                .map_or(1, |(_, port)| *port);
            return Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))]);
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .with_context(|| format!("resolving {host}"))?
            .collect();
        if addrs.is_empty() {
            bail!("{host} has no address");
        }
        Ok(addrs)
    }
}

/// STREAM's first byte, read within [`HEADER_READ_TIMEOUT`], and STREAM
/// with it put back.
async fn first_byte<S>(mut stream: S) -> Option<(u8, Prefixed<S>)>
where
    S: AsyncRead + Unpin,
{
    let mut first = [0; 1];
    match timeout(HEADER_READ_TIMEOUT, stream.read(&mut first)).await {
        Ok(Ok(1)) => Some((
            first[0],
            Prefixed {
                byte: Some(first[0]),
                inner: stream,
            },
        )),
        _ => None,
    }
}

/// The client's hello on STREAM, read within [`HANDSHAKE_TIMEOUT`].
async fn start_tls<S>(stream: S) -> Option<tokio_rustls::StartHandshake<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let acceptor =
        tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    timeout(HANDSHAKE_TIMEOUT, acceptor).await.ok()?.ok()
}

async fn handshake<S>(stream: S) -> Result<SendRequest<Body>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("starting HTTP with the server")?;
    tokio::spawn(connection.with_upgrades());
    Ok(sender)
}

/// HOST without the brackets of an IPv6 address, as mitmproxy logs it.
fn bare_host(host: &str) -> String {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned()
}

/// The proxy on a loopback port, in a thread of its own, with the policy
/// file TEXT and `--refuse` REFUSE: for tests elsewhere in the crate
/// that probe through it.
#[cfg(test)]
pub(crate) fn serve_for_tests(text: &str, refuse: &[String]) -> SocketAddr {
    let mut proxy = Proxy::new(
        Policy::parse(text, policy::ECOSYSTEMS).unwrap(),
        Authority::new(rcgen::KeyPair::generate().unwrap()).unwrap(),
        tls::client_config(tls::mozilla_roots()).unwrap(),
        None,
    )
    .unwrap();
    proxy.refused = Refused::parse(refuse).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = TcpListener::from_std(listener).unwrap();
            let _ = Arc::new(proxy).serve(listener, false).await;
        });
    });
    address
}

#[cfg(test)]
mod tests;
