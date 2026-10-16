//! The proxy on loopback, as `egress/test_live.py` runs mitmproxy: an
//! allowlist policy, and origins on loopback ports under names in
//! `.test`, which never resolve (RFC 6761), so the policy sees the names
//! a client asked for. Over that, what only a tunnel has: TLS on both
//! sides, the Host header and server name against the CONNECT's host,
//! writes, upgrades and what is not HTTP.

use std::sync::Mutex;

use http_body_util::Full;
use rcgen::{CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncWriteExt;

use super::*;

const POLICY: &str = r#"
[egress]
mode = "allowlist"
allow = ["allowed.test", "secure.test", "untrusted.test", "stalled.test"]

[[write]]
name = "test upload"
hosts = ["secure.test"]
methods = ["POST", "WEBSOCKET"]
paths = ["/upload", "/socket"]
"#;

/// The protocol an origin switches to on an upgrade, if not a WebSocket.
const SWITCH_TO: &str = "x-switch-to";

/// What an origin was asked for: method, path with its query, body.
#[derive(Default)]
struct Seen(Mutex<Vec<String>>);

impl Seen {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

/// Answers 200 with "hello"; a redirect when the path is
/// /redirect?to=URL; and an upgrade, to a WebSocket or to what
/// [`SWITCH_TO`] names, with an echo.
async fn answer(request: Request<Incoming>, seen: Arc<Seen>) -> Response<Full<Bytes>> {
    let method = request.method().to_string();
    let path = request.uri().path_and_query().unwrap().to_string();
    if request.headers().contains_key(header::UPGRADE) {
        let protocol = request
            .headers()
            .get(SWITCH_TO)
            .cloned()
            .unwrap_or(HeaderValue::from_static(WEBSOCKET));
        seen.0
            .lock()
            .unwrap()
            .push(format!("{method} {path} upgrade"));
        tokio::spawn(async move {
            let upgraded = hyper::upgrade::on(request).await.unwrap();
            let (mut read, mut write) = tokio::io::split(TokioIo::new(upgraded));
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        return Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, protocol)
            .body(Full::default())
            .unwrap();
    }
    let body = request.into_body().collect().await.unwrap().to_bytes();
    seen.0.lock().unwrap().push(
        format!("{method} {path} {}", String::from_utf8_lossy(&body))
            .trim_end()
            .to_owned(),
    );
    match path.strip_prefix("/redirect?to=") {
        Some(to) => Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, to)
            .body(Full::default())
            .unwrap(),
        None => Response::new(Full::new(Bytes::from_static(b"hello"))),
    }
}

async fn serve_origin<S>(stream: S, seen: Arc<Seen>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        let seen = seen.clone();
        async move { Ok::<_, Infallible>(answer(request, seen).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await;
}

/// An origin on a loopback port, over TLS with TLS's configuration.
async fn origin(tls: Option<Arc<rustls::ServerConfig>>) -> (u16, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Seen::default());
    let served = seen.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (seen, tls) = (served.clone(), tls.clone());
            tokio::spawn(async move {
                match tls {
                    Some(config) => {
                        if let Ok(stream) =
                            tokio_rustls::TlsAcceptor::from(config).accept(stream).await
                        {
                            serve_origin(stream, seen).await;
                        }
                    }
                    None => serve_origin(stream, seen).await,
                }
            });
        }
    });
    (port, seen)
}

fn test_ca() -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

/// A server configuration for NAME, signed by CA.
fn origin_tls(ca: &CertifiedIssuer<'static, KeyPair>, name: &str) -> Arc<rustls::ServerConfig> {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![name.to_owned()])
        .unwrap()
        .signed_by(&key, ca)
        .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Arc::new(
        rustls::ServerConfig::builder_with_provider(tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap(),
    )
}

fn roots(der: &CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    roots
}

struct Fixture {
    proxy: SocketAddr,
    /// The proxy's authority, which the client trusts.
    ca: CertificateDer<'static>,
    log: PathBuf,
    plain: Arc<Seen>,
    refused: Arc<Seen>,
    secure: Arc<Seen>,
    untrusted: Arc<Seen>,
    plain_port: u16,
    /// How many connections stalled.test, which never answers, took.
    stalled: Arc<std::sync::atomic::AtomicUsize>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// The fixture, with CONFIGURE's changes to the proxy.
    async fn start_with(configure: impl FnOnce(&mut Proxy)) -> Self {
        let origin_ca = test_ca();
        let (plain_port, plain) = origin(None).await;
        let (refused_port, refused) = origin(None).await;
        let (secure_port, secure) = origin(Some(origin_tls(&origin_ca, "secure.test"))).await;
        // Signed by an authority the proxy does not trust.
        let (untrusted_port, untrusted) =
            origin(Some(origin_tls(&test_ca(), "untrusted.test"))).await;
        let stalled_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stalled_port = stalled_listener.local_addr().unwrap().port();
        let stalled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let taken = stalled.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                held.push(stalled_listener.accept().await.unwrap());
                taken.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.jsonl");
        let authority = Authority::new(KeyPair::generate().unwrap()).unwrap();
        let ca = authority.ca_der().clone();
        let mut proxy = Proxy::new(
            Policy::parse(POLICY, policy::ECOSYSTEMS).unwrap(),
            authority,
            tls::client_config(roots(origin_ca.der())).unwrap(),
            Some(File::create(&log).unwrap()),
        );
        proxy.origins = vec![
            ("allowed.test".to_owned(), plain_port),
            ("refused.test".to_owned(), refused_port),
            ("secure.test".to_owned(), secure_port),
            ("untrusted.test".to_owned(), untrusted_port),
            ("stalled.test".to_owned(), stalled_port),
        ];
        configure(&mut proxy);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(Arc::new(proxy).serve(listener));
        Self {
            proxy: addr,
            ca,
            log,
            plain,
            refused,
            secure,
            untrusted,
            plain_port,
            stalled,
            _dir: dir,
        }
    }

    fn log_lines(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// A CONNECT to AUTHORITY: the open tunnel, or the refusal's status
    /// and `X-Egress-Denied`.
    async fn tunnel(&self, authority: &str) -> Result<TcpStream, (u16, String)> {
        let mut stream = TcpStream::connect(self.proxy).await.unwrap();
        stream
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1, "{head:?}");
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let status: u16 = head[9..12].parse().unwrap();
        if status == 200 {
            return Ok(stream);
        }
        let denied = head
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("x-egress-denied: ")
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        Err((status, denied))
    }

    /// TLS in a tunnel, asking for SNI and trusting the proxy's authority.
    async fn tls(
        &self,
        stream: TcpStream,
        sni: &str,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let config = rustls::ClientConfig::builder_with_provider(tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots(&self.ca))
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(tls::server_name(sni).unwrap(), stream)
            .await
            .unwrap()
    }
}

async fn client<S>(stream: S) -> SendRequest<Full<Bytes>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(connection.with_upgrades());
    sender
}

/// A response's status, `X-Egress-Denied` and body.
async fn send(
    sender: &mut SendRequest<Full<Bytes>>,
    request: Request<Full<Bytes>>,
) -> (u16, Option<String>, String) {
    sender.ready().await.unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let denied = response
        .headers()
        .get(DENIED_HEADER)
        .map(|value| value.to_str().unwrap().to_owned());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, denied, String::from_utf8_lossy(&body).into_owned())
}

fn request(method: &str, uri: &str, host: &str, body: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, host)
        .body(Full::new(Bytes::from(body.to_owned())))
        .unwrap()
}

/// `test_live.py`'s cases: plain HTTP proxy requests, and a client that
/// follows redirects through the proxy.
#[tokio::test]
async fn plain_requests_and_redirects() {
    let fixture = Fixture::start().await;
    // (URL, status, refused, what allowed.test and refused.test were asked)
    type Case = (
        &'static str,
        u16,
        bool,
        &'static [&'static str],
        &'static [&'static str],
    );
    let cases: [Case; 5] = [
        ("http://allowed.test/a", 200, false, &["GET /a"], &[]),
        ("http://sub.allowed.test/b", 200, false, &["GET /b"], &[]),
        ("http://refused.test/c", 403, true, &[], &[]),
        (
            "http://allowed.test/redirect?to=http://refused.test/d",
            403,
            true,
            &["GET /redirect?to=http://refused.test/d"],
            &[],
        ),
        (
            "http://allowed.test/redirect?to=http://allowed.test/e",
            200,
            false,
            &["GET /redirect?to=http://allowed.test/e", "GET /e"],
            &[],
        ),
    ];
    for (url, want_status, want_refused, allowed, refused) in cases {
        let mut url = url.to_owned();
        let (status, denied) = loop {
            let stream = TcpStream::connect(fixture.proxy).await.unwrap();
            let mut sender = client(stream).await;
            let host = url.parse::<Uri>().unwrap().host().unwrap().to_owned();
            let response = sender
                .send_request(request("GET", &url, &host, ""))
                .await
                .unwrap();
            if let Some(to) = response.headers().get(header::LOCATION) {
                url = to.to_str().unwrap().to_owned();
                continue;
            }
            let denied = response
                .headers()
                .get(DENIED_HEADER)
                .map(|value| value.to_str().unwrap().to_owned());
            break (response.status().as_u16(), denied);
        };
        assert_eq!(status, want_status, "{url}");
        assert_eq!(
            denied.as_deref() == Some(policy::NOT_ALLOWED),
            want_refused,
            "{url}: {denied:?}"
        );
        assert_eq!(fixture.plain.take(), allowed, "{url}");
        assert_eq!(fixture.refused.take(), refused, "{url}");
    }
}

/// HTTPS through a CONNECT: the proxy's certificate for the name asked
/// for, the server's checked, one connection kept for the next request,
/// and the log as `addon.py` writes it.
#[tokio::test]
async fn https_through_a_tunnel() {
    let fixture = Fixture::start().await;
    let stream = fixture.tunnel("secure.test:443").await.unwrap();
    let mut sender = client(fixture.tls(stream, "secure.test").await).await;
    for path in ["/a?token=secret", "/b"] {
        let (status, denied, body) =
            send(&mut sender, request("GET", path, "secure.test", "")).await;
        assert_eq!(
            (status, denied, body.as_str()),
            (200, None, "hello"),
            "{path}"
        );
    }
    let (status, _, _) = send(
        &mut sender,
        request("POST", "/upload", "secure.test", "data"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        fixture.secure.take(),
        ["GET /a?token=secret", "GET /b", "POST /upload data"]
    );
    let log = fixture.log_lines();
    assert_eq!(log.len(), 3);
    let first = &log[0];
    assert_eq!(first["decision"], "allow");
    assert_eq!(first["reason"], "read");
    assert_eq!(first["method"], "GET");
    assert_eq!(first["scheme"], "https");
    assert_eq!(first["host"], "secure.test");
    assert_eq!(first["port"], 443);
    // never the query string, where credentials travel
    assert_eq!(first["path"], "/a");
    assert_eq!(first["status"], 200);
    assert_eq!(first["error"], serde_json::Value::Null);
    assert_eq!(log[2]["reason"], "test upload");
}

/// The refusals a tunnel adds: its host, the Host header and the TLS
/// name against it, writes without a rule, and reads with a body.
#[tokio::test]
async fn refusals_in_and_of_tunnels() {
    let fixture = Fixture::start().await;
    assert_eq!(
        fixture.tunnel("refused.test:443").await.unwrap_err(),
        (403, policy::NOT_ALLOWED.to_owned())
    );
    let mut two_hosts = request("GET", "/", "secure.test", "");
    two_hosts
        .headers_mut()
        .append(header::HOST, HeaderValue::from_static("refused.test"));
    let mut with_body = request("GET", "/", "secure.test", "x");
    with_body
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
    let cases = [
        (
            "secure.test",
            request("GET", "/", "refused.test", ""),
            policy::OTHER_HOST,
        ),
        ("secure.test", two_hosts, policy::OTHER_HOST),
        (
            "allowed.test",
            request("GET", "/", "secure.test", ""),
            policy::OTHER_SNI,
        ),
        (
            "secure.test",
            request("POST", "/other", "secure.test", "x"),
            "POST to an endpoint not in the write allowlist",
        ),
        (
            "secure.test",
            request("PUT", "/upload", "secure.test", "x"),
            "PUT to an endpoint not in the write allowlist",
        ),
        (
            "secure.test",
            with_body,
            "a read with a body to an endpoint not in the write allowlist",
        ),
    ];
    for (sni, request, reason) in cases {
        let stream = fixture.tunnel("secure.test:443").await.unwrap();
        let mut sender = client(fixture.tls(stream, sni).await).await;
        let (status, denied, body) = send(&mut sender, request).await;
        assert_eq!((status, denied.as_deref()), (403, Some(reason)));
        assert_eq!(body, format!("refused by the egress proxy: {reason}\n"));
    }
    assert!(fixture.secure.take().is_empty());
    assert!(fixture.refused.take().is_empty());
    let log = fixture.log_lines();
    assert_eq!(log[0]["method"], "CONNECT");
    assert_eq!(log[0]["scheme"], "");
    assert_eq!(log[0]["path"], "");
    assert_eq!(log[0]["status"], 403);
    assert!(
        log.iter().all(|entry| entry["decision"] == "deny"),
        "{log:?}"
    );
}

/// Plain HTTP in a tunnel is read as HTTP too; anything else is not
/// passed on.
#[tokio::test]
async fn what_is_not_http_does_not_pass() {
    let fixture = Fixture::start().await;
    let authority = format!("allowed.test:{}", fixture.plain_port);
    let stream = fixture.tunnel(&authority).await.unwrap();
    let mut sender = client(stream).await;
    let (status, _, _) = send(&mut sender, request("GET", "/plain", &authority, "")).await;
    assert_eq!(status, 200);
    assert_eq!(fixture.plain.take(), ["GET /plain"]);

    let mut stream = fixture.tunnel(&authority).await.unwrap();
    stream
        .write_all(b"SSH-2.0-OpenSSH_9.9\r\nanything\r\n\r\n")
        .await
        .unwrap();
    let mut rest = Vec::new();
    let _ = timeout(Duration::from_secs(10), stream.read_to_end(&mut rest))
        .await
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&rest).contains("hello"),
        "{rest:?}"
    );
    assert!(fixture.plain.take().is_empty());
}

/// A server whose certificate does not check is not spoken to.
#[tokio::test]
async fn the_server_certificate_is_checked() {
    let fixture = Fixture::start().await;
    let stream = fixture.tunnel("untrusted.test:443").await.unwrap();
    let mut sender = client(fixture.tls(stream, "untrusted.test").await).await;
    let (status, denied, _) = send(&mut sender, request("GET", "/x", "untrusted.test", "")).await;
    assert_eq!((status, denied), (502, None));
    assert!(fixture.untrusted.take().is_empty());
    let log = fixture.log_lines();
    assert_eq!(log[0]["decision"], "allow");
    assert_eq!(log[0]["status"], serde_json::Value::Null);
    assert!(log[0]["error"].as_str().unwrap().contains("TLS"), "{log:?}");
}

/// A WebSocket is a write: with its rule it is upgraded and passes both
/// ways, without it refused.
#[tokio::test]
async fn websockets_need_a_write_rule() {
    let fixture = Fixture::start().await;
    let upgrade = |path: &str| {
        let mut request = request("GET", path, "secure.test", "");
        let headers = request.headers_mut();
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        request
    };
    let stream = fixture.tunnel("secure.test:443").await.unwrap();
    let mut sender = client(fixture.tls(stream, "secure.test").await).await;
    let (status, denied, _) = send(&mut sender, upgrade("/other")).await;
    assert_eq!(
        (status, denied.as_deref()),
        (
            403,
            Some("WEBSOCKET to an endpoint not in the write allowlist")
        )
    );

    let stream = fixture.tunnel("secure.test:443").await.unwrap();
    let mut sender = client(fixture.tls(stream, "secure.test").await).await;
    let mut response = sender.send_request(upgrade("/socket")).await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    let mut upgraded = TokioIo::new(hyper::upgrade::on(&mut response).await.unwrap());
    upgraded.write_all(b"ping").await.unwrap();
    let mut echo = [0; 4];
    upgraded.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
    assert_eq!(fixture.secure.take(), ["GET /socket upgrade"]);

    // A server that answers a WebSocket's offer with another protocol
    // is not passed through either.
    let stream = fixture.tunnel("secure.test:443").await.unwrap();
    let mut sender = client(fixture.tls(stream, "secure.test").await).await;
    let mut switched = upgrade("/socket");
    switched
        .headers_mut()
        .insert(SWITCH_TO, HeaderValue::from_static("h2c"));
    let (status, denied, body) = send(&mut sender, switched).await;
    assert_eq!((status, denied), (502, None), "{body}");
    assert!(body.contains("other than the WebSocket"), "{body}");
    assert_eq!(fixture.secure.take(), ["GET /socket upgrade"]);
}

/// A server that never answers, and an upgraded connection that passes
/// nothing, are closed in time, and give back their connection's slot.
#[tokio::test]
async fn stalled_connections_give_back_their_slots() {
    let fixture = Fixture::start_with(|proxy| {
        proxy.max_connections = 1;
        proxy.response_timeout = Duration::from_millis(300);
        proxy.idle_timeout = Duration::from_millis(300);
    })
    .await;
    let limit = Duration::from_secs(10);
    let get = |url: &str| request("GET", url, url.parse::<Uri>().unwrap().host().unwrap(), "");

    let mut sender = client(TcpStream::connect(fixture.proxy).await.unwrap()).await;
    let (status, _, body) = timeout(limit, send(&mut sender, get("http://stalled.test/x")))
        .await
        .unwrap();
    assert_eq!(status, 502, "{body}");
    assert!(
        body.contains("timed out waiting for the response"),
        "{body}"
    );
    assert_eq!(fixture.stalled.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(sender);

    let stream = timeout(limit, fixture.tunnel("secure.test:443"))
        .await
        .unwrap()
        .unwrap();
    let mut sender = client(fixture.tls(stream, "secure.test").await).await;
    let mut socket = request("GET", "/socket", "secure.test", "");
    let headers = socket.headers_mut();
    headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static(WEBSOCKET));
    let mut response = sender.send_request(socket).await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    let mut upgraded = TokioIo::new(hyper::upgrade::on(&mut response).await.unwrap());
    let mut rest = Vec::new();
    // Closed, if without TLS's close_notify: the bridge drops the stream.
    let _ = timeout(limit, upgraded.read_to_end(&mut rest))
        .await
        .unwrap();
    assert!(rest.is_empty(), "{rest:?}");
    drop((upgraded, sender));

    // The one slot is free again.
    let mut sender = client(
        timeout(limit, TcpStream::connect(fixture.proxy))
            .await
            .unwrap()
            .unwrap(),
    )
    .await;
    let (status, _, body) = timeout(limit, send(&mut sender, get("http://allowed.test/a")))
        .await
        .unwrap();
    assert_eq!((status, body.as_str()), (200, "hello"));
}

/// A host certificate is made again before it expires, and kept until
/// then.
#[test]
fn host_certificates_are_renewed_before_they_expire() {
    let authority = Authority::new(KeyPair::generate().unwrap()).unwrap();
    let today = chrono::Utc::now().date_naive();
    let first = authority.server_config_on("example.com", today).unwrap();
    let renew = tls::HOST_DAYS - tls::RENEW_DAYS;
    for (days, renewed) in [
        (0, false),
        (renew - 1, false),
        (renew, true),
        (tls::HOST_DAYS + 1, true),
    ] {
        let config = authority
            .server_config_on("example.com", today + chrono::Days::new(days))
            .unwrap();
        assert_eq!(!Arc::ptr_eq(&first, &config), renewed, "{days}");
    }
}

/// A read that asks for another protocol is a read, but a server that
/// switches to it is not passed through: what went both ways then would
/// be unread, writes included.
#[tokio::test]
async fn only_websockets_are_upgraded() {
    let fixture = Fixture::start().await;
    for upgrades in [
        &["h2c"][..],
        &["foo, websocket"],
        &["foo", "websocket"],
        &["websocket", "h2c"],
        &["websocket, h2c"],
    ] {
        let mut request = request("GET", "/", "secure.test", "");
        let headers = request.headers_mut();
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        for upgrade in upgrades {
            headers.append(header::UPGRADE, HeaderValue::from_static(upgrade));
        }
        // What a server would pick that the policy did not check.
        headers.insert(SWITCH_TO, HeaderValue::from_static("h2c"));
        let stream = fixture.tunnel("secure.test:443").await.unwrap();
        let mut sender = client(fixture.tls(stream, "secure.test").await).await;
        let (status, denied, body) = send(&mut sender, request).await;
        assert_eq!((status, denied), (502, None), "{upgrades:?}: {body}");
        assert!(body.contains("not a WebSocket"), "{body}");
    }
    assert_eq!(fixture.secure.take(), ["GET / upgrade"; 5]);
    let log = fixture.log_lines();
    assert!(
        log.iter()
            .all(|entry| entry["reason"] == "read" && entry["status"].is_null()),
        "{log:?}"
    );
}

#[test]
fn log_lines_read_as_addon_py_writes_them() {
    let entry = Entry {
        decision: DENY,
        reason: policy::NOT_ALLOWED,
        method: "GET",
        scheme: SCHEME_HTTPS,
        host: "Example.COM",
        port: 443,
        path: &format!("/caf\u{e9}/{}?token=x", "a".repeat(300)),
        status: Some(403),
        error: None,
    };
    let line = entry.line("2026-10-16T12:00:00Z");
    let path = format!("/caf\\u00e9/{}", "a".repeat(MAX_LOGGED_PATH - 6));
    assert_eq!(
        line,
        format!(
            "{{\"time\": \"2026-10-16T12:00:00Z\", \"decision\": \"deny\", \"reason\": \
             \"host is not in the domain allowlist\", \"method\": \"GET\", \"scheme\": \"https\", \
             \"host\": \"Example.COM\", \"port\": 443, \"path\": \"{path}\", \"status\": 403, \
             \"error\": null}}"
        )
    );
    let error = Entry {
        status: None,
        error: Some("a \"quoted\"\nline \u{1f600}"),
        ..entry
    };
    assert!(
        error
            .line("t")
            .ends_with("\"status\": null, \"error\": \"a \\\"quoted\\\"\\nline \\ud83d\\ude00\"}")
    );
}

#[test]
fn bodies_are_announced_by_length_or_chunking() {
    for (headers, want) in [
        (&[][..], false),
        (&[("content-length", "0")], false),
        (&[("content-length", "1")], true),
        (&[("transfer-encoding", "chunked")], true),
    ] {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(*name, HeaderValue::from_static(value));
        }
        assert_eq!(has_body_headers(&map), want, "{headers:?}");
    }
}

/// The authority's key is made once, private, and kept: a restart signs
/// with the key whose certificate setup published.
#[tokio::test]
async fn the_authority_is_kept() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let first = Authority::load_or_create(dir.path()).unwrap();
    let key = dir.path().join(tls::CA_KEY);
    let cert = dir.path().join(tls::CA_CERT);
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let published = std::fs::read_to_string(&cert).unwrap();
    assert!(published.starts_with("-----BEGIN CERTIFICATE-----"));
    let key_pem = std::fs::read_to_string(&key).unwrap();
    let second = Authority::load_or_create(dir.path()).unwrap();
    assert_eq!(std::fs::read_to_string(&key).unwrap(), key_pem);
    assert_eq!(std::fs::read_to_string(&cert).unwrap(), published);
    // What the second signs, for a name or an address, checks against
    // the certificate the first published.
    let client = rustls::ClientConfig::builder_with_provider(tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots(first.ca_der()))
        .with_no_client_auth();
    let client = tokio_rustls::TlsConnector::from(Arc::new(client));
    for name in ["example.com", "192.0.2.1"] {
        let (server_end, client_end) = tokio::io::duplex(1 << 16);
        let server = tokio_rustls::TlsAcceptor::from(second.server_config(name).unwrap());
        let (served, connected) = tokio::join!(
            server.accept(server_end),
            client.connect(tls::server_name(name).unwrap(), client_end)
        );
        served.unwrap();
        connected.unwrap();
    }
    std::fs::write(&key, "not a key").unwrap();
    assert!(Authority::load_or_create(dir.path()).is_err());
}
