//! `[mcp.NAME]` against a mock MCP server on loopback: the credential is
//! checked before the run starts, the proxy `run` serves takes the run's
//! token and puts the credential in its place, forwards only MCP's own
//! methods and the allowed tools, filters the tool list, does not follow
//! a redirect or pass on an answer over its limit, and admits nothing once
//! ended; and a session gives the proxy to an agent that takes HTTP MCP
//! servers, and fails with one that does not.

// clippy.toml lets test functions unwrap, but not the helpers they share.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentic_job::run::inference::{NEVER, Retry};
use agentic_job::run::mcp::{self, Credential, Local, Server};
use agentic_job::session::{self, Clients, HttpMcp, Launch, Limits, Options, Policy};
use serde_json::{Value, json};

const FAKE_AGENT: &str = env!("CARGO_BIN_EXE_fake-agent");
const QUICK: Retry = Retry {
    attempts: 2,
    delay: Duration::from_millis(10),
};
const SESSION_ID: &str = "mock-session-1";
/// The tools the mock lists, of which the run allows two.
const TOOLS: &[&str] = &["search", "get_issue", "delete_repo"];
const ALLOWED: &[&str] = &["get_issue", "search"];

/// Not shaped like any service's token, so nothing takes it for one.
fn credential() -> String {
    format!("{}-{}", "test-mcp-not-secret", "0123456789abcdef")
}

/// One request as the server saw it, header names in lower case.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

/// How the mock answers.
#[derive(Default, Clone)]
struct Behaviour {
    /// Answer `tools/list` as a stream of events.
    sse: bool,
    /// Answer `tools/call` with more than the proxy takes.
    oversize: bool,
    /// Answer everything with a redirect to this URL.
    redirect: Option<String>,
    /// Answer `tools/call` with the bearer it was sent, as a gateway that
    /// quotes the request might.
    echo: bool,
    /// Answer everything with this status and a JSON-RPC error that quotes
    /// the bearer it was sent, whatever it was.
    quoting: Option<u16>,
}

/// A streamable-HTTP MCP server that takes only `credential()`, and
/// answers a refused one with what it was given, as some services quote
/// a token they refuse.
#[derive(Clone)]
struct MockServer {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    behaviour: Arc<Mutex<Behaviour>>,
}

impl MockServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mock = Self {
            url: format!("http://{}/mcp", listener.local_addr().unwrap()),
            seen: Arc::default(),
            behaviour: Arc::default(),
        };
        let serving = mock.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let serving = serving.clone();
                std::thread::spawn(move || serving.answer(stream));
            }
        });
        mock
    }

    fn with(&self, change: impl FnOnce(&mut Behaviour)) -> &Self {
        change(&mut self.behaviour.lock().unwrap());
        self
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn methods(&self) -> Vec<String> {
        self.seen()
            .iter()
            .map(|seen| {
                seen.body["method"]
                    .as_str()
                    .map_or_else(|| seen.method.clone(), str::to_owned)
            })
            .collect()
    }

    fn answer(&self, mut stream: TcpStream) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        let method = first.split_whitespace().next().unwrap().to_owned();
        let mut headers = BTreeMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').unwrap();
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
        let length = headers
            .get("content-length")
            .map_or(0, |n| n.parse().unwrap());
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let given = headers
            .get("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::to_owned);
        self.seen.lock().unwrap().push(Seen {
            method: method.clone(),
            headers,
            body: body.clone(),
        });
        let behaviour = self.behaviour.lock().unwrap().clone();
        let tools: Vec<Value> = TOOLS.iter().map(|name| json!({"name": name})).collect();
        let id = body["id"].clone();
        let result = |result: Value| json!({"jsonrpc": "2.0", "id": id, "result": result});
        let (status, kind, extra, text) = if let Some(to) = behaviour.redirect {
            (
                307,
                "text/plain",
                format!("location: {to}\r\n"),
                String::new(),
            )
        } else if let Some(status) = behaviour.quoting {
            let message = format!("invalid token: {}", given.unwrap_or_default());
            let error =
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32001, "message": message}});
            (status, "application/json", String::new(), error.to_string())
        } else if given != Some(credential()) {
            let text = format!("invalid token: {}", given.unwrap_or_default());
            (401, "text/plain", String::new(), text)
        } else if method == "DELETE" {
            (200, "text/plain", String::new(), String::new())
        } else {
            match body["method"].as_str() {
                Some("initialize") => (
                    200,
                    "application/json",
                    format!("mcp-session-id: {SESSION_ID}\r\nset-cookie: account=1\r\n"),
                    result(json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mock", "version": "1"}}))
                    .to_string(),
                ),
                Some("notifications/initialized") => {
                    (202, "text/plain", String::new(), String::new())
                }
                Some("tools/list") if behaviour.sse => (
                    200,
                    "text/event-stream",
                    String::new(),
                    format!(
                        "event: message\ndata: {}\n\n",
                        result(json!({"tools": tools}))
                    ),
                ),
                Some("tools/list") => (
                    200,
                    "application/json",
                    String::new(),
                    result(json!({"tools": tools})).to_string(),
                ),
                Some("tools/call") if behaviour.echo => (
                    200,
                    "application/json",
                    format!("mcp-session-id: {}\r\n", credential()),
                    result(json!({"content": [{"type": "text",
                        "text": format!("you are {}", credential())}]}))
                    .to_string(),
                ),
                Some("tools/call") if behaviour.oversize => (
                    200,
                    "application/json",
                    String::new(),
                    "x".repeat(9 << 20),
                ),
                Some("tools/call") => (
                    200,
                    "application/json",
                    String::new(),
                    result(json!({"content": [{"type": "text",
                        "text": format!("called {} with {}", body["params"]["name"], body["params"]["arguments"])}]}))
                    .to_string(),
                ),
                _ => (400, "text/plain", String::new(), "unknown".to_owned()),
            }
        };
        let _ = write!(
            stream,
            "HTTP/1.1 {status} X\r\ncontent-type: {kind}\r\n{extra}content-length: {}\r\n\
             connection: close\r\n\r\n{text}",
            text.len()
        );
        let _ = stream.shutdown(Shutdown::Write);
    }
}

fn server(url: &str) -> Server {
    Server {
        name: "tracker".to_owned(),
        url: url.to_owned(),
        allowed: ALLOWED.iter().map(|tool| (*tool).to_owned()).collect(),
    }
}

fn start(mock: &MockServer) -> Local {
    Local::start(
        server(&mock.url),
        Credential::new(Some(&credential())).unwrap(),
    )
    .unwrap()
}

/// A request to the proxy as the agent makes it: the status, the answer's
/// headers and its text.
fn ask(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<(u16, BTreeMap<String, String>, String), ureq::Error> {
    let http: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .proxy(None)
        .build()
        .into();
    let mut request = ureq::http::Request::builder().method(method).uri(url);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = if body.is_empty() {
        http.run(request.body(()).unwrap())
    } else {
        http.run(request.body(body.to_owned()).unwrap())
    }?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap().to_owned()))
        .collect();
    let text = response.into_body().read_to_string()?;
    Ok((status, headers, text))
}

fn bearer(local: &Local) -> String {
    format!("Bearer {}", local.token().expose())
}

fn rpc(id: u64, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

/// The proxy answers only the run's token, only while the run lasts, and
/// only POST and DELETE on its one path.
#[test]
fn the_proxy_takes_the_run_token_and_nothing_else() {
    let mock = MockServer::start();
    let local = start(&mock);
    assert!(local.url().starts_with("http://127.0.0.1:"));
    assert!(local.token().expose().starts_with("agentic-job-mcp-"));
    let ping = rpc(1, "ping", json!({}));
    let wrong = format!("Bearer {}", credential());
    for headers in [vec![], vec![("authorization", wrong.as_str())]] {
        let (status, _, text) = ask(&local.url(), "POST", &headers, &ping).unwrap();
        assert_eq!(status, 401, "{headers:?}: {text}");
    }
    let token = bearer(&local);
    let auth = [("authorization", token.as_str())];
    let (status, headers, text) = ask(&local.url(), "GET", &auth, "").unwrap();
    assert_eq!(status, 405, "{text}");
    assert_eq!(headers["allow"], "POST, DELETE");
    let (status, _, _) = ask(&local.url(), "PUT", &auth, &ping).unwrap();
    assert_eq!(status, 405);
    let other = format!("{}other", local.url());
    let (status, _, _) = ask(&other, "POST", &auth, &ping).unwrap();
    assert_eq!(status, 404);
    assert!(mock.seen().is_empty(), "{:?}", mock.methods());

    let (status, _, _) = ask(&local.url(), "POST", &auth, &ping).unwrap();
    assert_eq!(status, 400, "the mock knows no ping, and answered it");
    assert_eq!(mock.methods(), ["ping"]);
    local.end();
    let after = ask(&local.url(), "POST", &auth, &ping);
    assert!(
        !matches!(after, Ok((status, ..)) if status != 401),
        "{after:?}"
    );
    assert_eq!(mock.methods(), ["ping"]);
}

/// What the proxy does not forward never reaches the server, and is
/// answered as a JSON-RPC error.
#[test]
fn what_is_not_allowed_never_reaches_the_server() {
    let mock = MockServer::start();
    let local = start(&mock);
    let token = bearer(&local);
    let auth = [("authorization", token.as_str())];
    for (body, want) in [
        (format!("[{}]", rpc(1, "tools/list", json!({}))), "a batch"),
        (
            rpc(2, "resources/read", json!({"uri": "file:///etc/passwd"})),
            "resources/read is not forwarded",
        ),
        (
            rpc(3, "prompts/list", json!({})),
            "prompts/list is not forwarded",
        ),
        (
            rpc(
                4,
                "tools/call",
                json!({"name": "delete_repo", "arguments": {}}),
            ),
            "is not one the run allows",
        ),
        (
            json!({"jsonrpc": "2.0", "id": "s1", "result": {}}).to_string(),
            "an answer to no ping",
        ),
    ] {
        let (status, headers, text) = ask(&local.url(), "POST", &auth, &body).unwrap();
        assert_eq!(status, 403, "{body}: {text}");
        assert!(text.contains(want), "{body}: {text}");
        if !body.starts_with('[') {
            assert_eq!(headers["content-type"], "application/json");
            let error: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                error["id"],
                serde_json::from_str::<Value>(&body).unwrap()["id"]
            );
        }
    }
    assert!(mock.seen().is_empty(), "{:?}", mock.methods());
    assert_eq!(local.calls(), 0);
}

/// An allowed call reaches the server with the credential in place of the
/// run's token and none of the agent's other headers; the session the
/// server keeps goes both ways, and the tool list loses what is not
/// allowed, whether it comes as JSON or as a stream.
#[test]
fn the_proxy_puts_the_credential_in_place_of_the_run_token() {
    let mock = MockServer::start();
    let local = start(&mock);
    let token = bearer(&local);
    let agent = [
        ("authorization", token.as_str()),
        ("x-api-key", "the agent's"),
        ("cookie", "the agent's"),
        ("x-forwarded-for", "the agent's"),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    let init = rpc(1, "initialize", json!({"protocolVersion": "2025-06-18"}));
    let (status, headers, text) = ask(&local.url(), "POST", &agent, &init).unwrap();
    assert_eq!(status, 200, "{text}");
    assert_eq!(headers["mcp-session-id"], SESSION_ID);
    assert!(!headers.contains_key("set-cookie"), "{headers:?}");
    assert!(!text.contains(&credential()));

    let session = [agent.as_slice(), &[("mcp-session-id", SESSION_ID)]].concat();
    for sse in [false, true] {
        mock.with(|b| b.sse = sse);
        let (status, headers, text) = ask(
            &local.url(),
            "POST",
            &session,
            &rpc(2, "tools/list", json!({})),
        )
        .unwrap();
        assert_eq!(status, 200, "{text}");
        let json = if sse {
            assert!(headers["content-type"].starts_with("text/event-stream"));
            let data = text
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .unwrap();
            serde_json::from_str::<Value>(data).unwrap()
        } else {
            serde_json::from_str::<Value>(&text).unwrap()
        };
        let names: Vec<&str> = json["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["search", "get_issue"], "sse {sse}");
    }

    let call = rpc(
        3,
        "tools/call",
        json!({"name": "search", "arguments": {"q": "x"}}),
    );
    let (status, _, text) = ask(&local.url(), "POST", &session, &call).unwrap();
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("called \\\"search\\\""), "{text}");
    assert_eq!(local.calls(), 1);
    // What quotes the credential reaches the agent without it.
    mock.with(|b| b.echo = true);
    let (status, headers, text) = ask(&local.url(), "POST", &session, &call).unwrap();
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("you are [the credential]"), "{text}");
    assert_eq!(headers["mcp-session-id"], "[the credential]");
    assert!(!text.contains(&credential()), "{text}");
    mock.with(|b| b.echo = false);
    let (status, _, _) = ask(&local.url(), "DELETE", &session, "").unwrap();
    assert_eq!(status, 200);

    let seen = mock.seen();
    assert_eq!(
        mock.methods(),
        [
            "initialize",
            "tools/list",
            "tools/list",
            "tools/call",
            "tools/call",
            "DELETE"
        ]
    );
    for seen in &seen {
        assert_eq!(
            seen.headers["authorization"],
            format!("Bearer {}", credential())
        );
        for header in ["x-api-key", "cookie", "x-forwarded-for"] {
            assert!(!seen.headers.contains_key(header), "{header}: {seen:?}");
        }
        assert_eq!(seen.headers["mcp-protocol-version"], "2025-06-18");
        assert!(!format!("{seen:?}").contains(local.token().expose()));
    }
    assert!(!seen[0].headers.contains_key("mcp-session-id"));
    assert!(
        seen[1..]
            .iter()
            .all(|seen| seen.headers["mcp-session-id"] == SESSION_ID)
    );
    assert_eq!(
        seen[3].body["params"],
        json!({"name": "search", "arguments": {"q": "x"}})
    );
    assert_eq!(local.calls(), 2);
}

/// An answer over the proxy's limit, and a redirect, which would take the
/// credential elsewhere, end in the proxy's own refusal.
#[test]
fn oversize_answers_and_redirects_are_refused() {
    let mock = MockServer::start();
    let local = start(&mock);
    let token = bearer(&local);
    let auth = [("authorization", token.as_str())];
    let call = rpc(1, "tools/call", json!({"name": "search", "arguments": {}}));
    mock.with(|b| b.oversize = true);
    let (status, _, text) = ask(&local.url(), "POST", &auth, &call).unwrap();
    assert_eq!(status, 502, "{text}");
    assert!(text.contains("could not be read whole"), "{text}");

    let elsewhere = MockServer::start();
    mock.with(|b| b.redirect = Some(elsewhere.url.clone()));
    let (status, headers, text) = ask(&local.url(), "POST", &auth, &call).unwrap();
    assert_eq!(status, 502, "{text}");
    assert!(text.contains("redirect"), "{text}");
    assert!(!headers.contains_key("location"));
    assert!(elsewhere.seen().is_empty());
}

/// The check before the run takes a credential the server takes and every
/// allowed tool it has; it refuses the rest, without the credential.
#[test]
fn the_credential_is_checked_before_the_run() {
    let mock = MockServer::start();
    let good = Credential::new(Some(&credential())).unwrap();
    mcp::check(&server(&mock.url), &good, QUICK, NEVER).unwrap();
    assert_eq!(
        mock.methods(),
        [
            "initialize",
            "notifications/initialized",
            "tools/list",
            "DELETE"
        ]
    );

    let wrong = Credential::new(Some(&format!("{}-{}", "test-mcp-not-secret", "fedcba"))).unwrap();
    let err = format!(
        "{:#}",
        mcp::check(&server(&mock.url), &wrong, QUICK, NEVER).unwrap_err()
    );
    assert!(
        err.contains("refused the credential in AGENTIC_JOB_MCP_TOKEN (HTTP 401"),
        "{err}"
    );
    assert!(err.contains("secret MCP_TOKEN"), "{err}");
    assert!(err.contains("[the credential]"), "{err}");
    assert!(!err.contains(wrong.expose()), "{err}");

    let mut typo = server(&mock.url);
    typo.allowed.insert("serach".to_owned());
    let err = format!("{:#}", mcp::check(&typo, &good, QUICK, NEVER).unwrap_err());
    assert!(err.contains("has no tool serach"), "{err}");
    assert!(
        err.contains("lists: delete_repo, get_issue, search"),
        "{err}"
    );

    let gone = format!(
        "http://{}/mcp",
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    );
    let err = format!(
        "{:#}",
        mcp::check(&server(&gone), &good, QUICK, NEVER).unwrap_err()
    );
    assert!(err.contains("cannot reach the MCP server tracker"), "{err}");

    // A credential with `"` and `\` in it, quoted back in JSON, escaped:
    // the check's message has it in neither form.
    let odd = Credential::new(Some(&format!(
        "{}\"{}\\{}",
        "test-mcp", "not", "secret-0123"
    )))
    .unwrap();
    let escaped = serde_json::to_string(odd.expose()).unwrap();
    let escaped = &escaped[1..escaped.len() - 1];
    assert_ne!(escaped, odd.expose());
    for (status, want) in [
        (401, "refused the credential"),
        (200, "did not answer initialize with a result"),
    ] {
        mock.with(|behaviour| behaviour.quoting = Some(status));
        let err = format!(
            "{:#}",
            mcp::check(&server(&mock.url), &odd, QUICK, NEVER).unwrap_err()
        );
        assert!(err.contains(want), "{err}");
        assert!(err.contains("[the credential]"), "{err}");
        assert!(!err.contains(odd.expose()), "{err}");
        assert!(!err.contains(escaped), "{err}");
    }
}

/// A session with the fake agent and SERVERS: its result, its message,
/// what the agent said, and the `session/new` it was sent.
fn session_with(mode: &str, servers: Vec<HttpMcp>) -> (Value, String, Value) {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("script.json");
    std::fs::write(
        &script,
        r#"[{"mcp": {"tool": "search", "arguments": {"q": "x"}}}, {"say": "Done."}]"#,
    )
    .unwrap();
    let registry = format!(
        "[fake]\ncommand = {}\nnotices = true\n",
        json!([FAKE_AGENT, mode, script.to_str().unwrap()])
    );
    let out = dir.path().join("out");
    let options = Options {
        name: "fake".to_owned(),
        agent: session::agents::parse(&registry, "fake").unwrap(),
        model: None,
        fallback_model: None,
        config_options: Vec::new(),
        cwd: dir.path().to_owned(),
        prompt: "Call the tool.\n".to_owned(),
        out: out.clone(),
        permissions: Policy::allow_all(),
        limits: Limits {
            timeout_s: 60,
            budget_aic: Some(100.0),
            ..Limits::default()
        },
        requests: None,
        launch: Launch::Direct,
        clients: Clients::none(),
        bridge: None,
        log: Box::new(std::io::sink()),
        output: None,
        restate: None,
        mcp_servers: servers,
        watch: None,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(session::run(options)).unwrap();
    let result: Value =
        serde_json::from_str(&std::fs::read_to_string(out.join(session::RESULT_FILE)).unwrap())
            .unwrap();
    let records: Vec<Value> = std::fs::read_to_string(out.join(session::ACP_LOG))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let said: String = records
        .iter()
        .filter(|r| r["msg"]["params"]["update"]["sessionUpdate"] == "agent_message_chunk")
        .filter_map(|r| r["msg"]["params"]["update"]["content"]["text"].as_str())
        .collect();
    let new = records
        .iter()
        .find(|r| r["msg"]["method"] == "session/new")
        .map_or(Value::Null, |r| r["msg"]["params"].clone());
    (result, said, new)
}

/// The agent is given the proxy in `session/new`, with the run's token,
/// and its call reaches the server with the credential, which the agent
/// never saw; without a server `session/new` names none.
#[test]
fn a_session_gives_the_agent_the_proxy() {
    let mock = MockServer::start();
    let local = start(&mock);
    let given = HttpMcp {
        name: "tracker".to_owned(),
        url: local.url(),
        headers: vec![("Authorization".to_owned(), bearer(&local))],
    };
    let (result, said, new) = session_with("script", vec![given]);
    assert_eq!(result["result"], "success", "{result}");
    assert_eq!(
        new["mcpServers"],
        json!([{"type": "http", "name": "tracker", "url": local.url(),
            "headers": [{"name": "Authorization", "value": bearer(&local)}]}])
    );
    assert!(!new.to_string().contains(&credential()));
    assert!(
        said.contains("MCP tools: search, get_issue; search: HTTP 200: called"),
        "{said}"
    );
    let calls: Vec<Seen> = mock
        .seen()
        .into_iter()
        .filter(|seen| seen.body["method"] == "tools/call")
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].headers["authorization"],
        format!("Bearer {}", credential())
    );
    assert_eq!(local.calls(), 1);

    let (result, said, new) = session_with("script", Vec::new());
    assert_eq!(result["result"], "success", "{result}");
    assert_eq!(new["mcpServers"], json!([]));
    assert!(said.contains("no HTTP server was given"), "{said}");
}

/// An agent that does not take MCP servers over HTTP fails before its
/// first prompt, rather than running without the tools.
#[test]
fn an_agent_without_http_mcp_fails_setup() {
    let given = HttpMcp {
        name: "tracker".to_owned(),
        url: "http://127.0.0.1:9/".to_owned(),
        headers: Vec::new(),
    };
    let (result, said, new) = session_with("no-mcp", vec![given]);
    assert_eq!(result["result"], "failure", "{result}");
    let message = result["message"].as_str().unwrap_or_default();
    assert!(message.contains("mcpCapabilities.http"), "{result}");
    assert!(message.contains("tracker"), "{result}");
    assert_eq!(new, Value::Null, "session/new was sent");
    assert!(said.is_empty(), "{said}");
    // The same agent with no server runs.
    let (result, _, _) = session_with("no-mcp", Vec::new());
    assert_eq!(result["result"], "success", "{result}");
}
