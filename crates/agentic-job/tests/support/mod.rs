//! A mock inference proxy: praxis-credential-broker's run API as its
//! handlers define it (`POST /v1/runs` with an identity token or a name,
//! `GET` and `DELETE /v1/runs/self` with the run token), and beside it
//! the endpoint a CI system gives a job to ask for its identity token.
//!
//! It keeps the broker's rules that the client's behaviour depends on:
//! the same identity token registers the same run again, with a new
//! token that replaces the old one; a name registers once; a registration
//! without proof is refused unless the policy admits it. It records every
//! request, and can be told to fail the next registrations.

// Each test binary uses its own part of this, and clippy.toml lets only
// test functions unwrap.
#![allow(dead_code, clippy::unwrap_used)]

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use agentic_job::config::Provider;
use serde_json::{Value, json};

pub const AUDIENCE: &str = "mock-proxy";
/// What stands in for the CI system's `ACTIONS_ID_TOKEN_REQUEST_TOKEN`.
pub const REQUEST_BEARER: &str = "mock-oidc-request-bearer";
pub const RECORD_SCHEMA: &str = "praxis-run-usage/v2";
const RUNS: &str = "/v1/runs";
const RUN_SELF: &str = "/v1/runs/self";
const OIDC: &str = "/oidc";
/// The broker's model routes for Claude Code, opencode and Vibe.
pub const MODEL_ROUTES: [&str; 3] = [
    "/anthropic/v1/messages",
    "/v1/responses",
    "/mistral/v1/chat/completions",
];
/// Where Forgejo points ACTIONS_ID_TOKEN_REQUEST_URL: its ROOT_URL
/// (with any sub-path) and this, then `?placeholder=true`
/// (forgejo/forgejo v17.0.0, services/actions/task.go).
pub const FORGEJO_OIDC: &str = "/api/actions/_apis/pipelines/workflows/42/idtoken";
/// How long an answered client gets to close its side.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a registered run lives.
const RUN_SECS: u64 = 6 * 3600;

/// One request as the proxy saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Lower-case names.
    pub headers: BTreeMap<String, String>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    fn bearer(&self) -> Option<&str> {
        self.header("authorization")?.strip_prefix("Bearer ")
    }
}

/// What the next registration, or ending with [`Proxy::fail_endings`],
/// gets in place of an answer.
#[derive(Debug, Clone)]
pub enum Fault {
    /// A refusal, with its text.
    Status(u16, &'static str),
    /// A redirect to this path, which would register the run if it were
    /// followed.
    Redirect(&'static str),
    /// The run is registered and the reply is lost.
    LostReply,
    /// The connection is closed before the request is looked at.
    Closed,
    /// The reply comes only after this long.
    Slow(Duration),
}

#[derive(Debug, Clone)]
struct Run {
    /// What registered it: an identity token, or a name.
    key: String,
    token: String,
    record: Value,
    state: &'static str,
    requests: u64,
}

#[derive(Default)]
struct State {
    requests: Vec<Request>,
    faults: VecDeque<Fault>,
    runs: Vec<Run>,
    issued: u32,
    /// Whether the policy admits registrations without proof.
    unproven: bool,
    /// Whether the run API exists at all.
    no_run_api: bool,
    /// Faults for the next `DELETE`s.
    end_faults: VecDeque<Fault>,
    /// A proxy that will not let go of a run.
    keeps_runs_active: bool,
    run_secs: Option<u64>,
    /// A proxy whose usage records are of a schema the client does not
    /// know.
    odd_records: bool,
}

/// The proxy, listening on a port of the loopback address.
#[derive(Clone)]
pub struct Proxy {
    pub url: String,
    state: Arc<Mutex<State>>,
}

fn answer(stream: &mut TcpStream, status: u16, body: &str) {
    answer_with(stream, status, "", body);
}

/// As [`answer`], with HEADERS, each line ending in CRLF.
fn answer_with(stream: &mut TcpStream, status: u16, headers: &str, body: &str) {
    let kind = if body.starts_with('{') {
        "application/json"
    } else if body.starts_with("data:") {
        "text/event-stream"
    } else {
        "text/plain"
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} X\r\n{headers}content-type: {kind}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    // Closing with something of the request unread (the end of an empty
    // chunked body, for one) resets the connection, and the client may
    // then never see the answer: wait for it to close its side.
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(DRAIN_TIMEOUT));
    let _ = std::io::copy(stream, &mut std::io::sink());
}

fn read_request(stream: &TcpStream) -> Option<Request> {
    let mut lines = BufReader::new(stream).lines();
    let first = lines.next()?.ok()?;
    let mut parts = first.split(' ');
    let (method, path) = (parts.next()?.to_owned(), parts.next()?.to_owned());
    let headers = lines
        .map_while(Result::ok)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    Some(Request {
        method,
        path,
        headers,
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl State {
    fn new_token(&mut self) -> String {
        self.issued += 1;
        format!("praxis-run-{:064x}", self.issued)
    }

    fn record(run: &Run) -> Value {
        let mut record = run.record.clone();
        record["state"] = json!(run.state);
        record["requests"] = json!(run.requests);
        record
    }

    /// `POST /v1/runs`: the status and body.
    fn register(&mut self, request: &Request) -> (u16, String) {
        let name = request.header("x-run-id");
        let (key, mut record) = match (request.bearer(), name) {
            (Some(jwt), _) if jwt.starts_with(&format!("jwt.{AUDIENCE}.")) => (
                jwt.to_owned(),
                json!({"proof": "github-oidc", "run_id": 7, "run_attempt": 1}),
            ),
            (Some(_), _) => return (401, "invalid OIDC token\n".into()),
            (None, _) if !self.unproven => return (401, "OIDC token required\n".into()),
            (None, Some(name))
                if !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) =>
            {
                (
                    format!("name:{name}"),
                    json!({"proof": "none", "run": name}),
                )
            }
            (None, _) => return (400, "invalid x-run-id\n".into()),
        };
        let token = self.new_token();
        let proven = record["proof"] == "github-oidc";
        match self.runs.iter_mut().find(|run| run.key == key) {
            // The same identity token gets the same run and a new token.
            Some(run) if proven && run.state == "active" => run.token = token.clone(),
            Some(_) => return (409, "run already registered\n".into()),
            None => {
                let now = unix_now();
                record["schema"] = if self.odd_records {
                    json!("praxis-run-usage/v9")
                } else {
                    json!(RECORD_SCHEMA)
                };
                record["registered_at_unix"] = json!(now);
                record["expires_at_unix"] = json!(now + self.run_secs.unwrap_or(RUN_SECS));
                record["unmetered"] = json!(0);
                self.runs.push(Run {
                    key: key.clone(),
                    token: token.clone(),
                    record,
                    state: "active",
                    requests: 0,
                });
            }
        }
        let run = self.runs.iter().find(|run| run.key == key).unwrap();
        (
            201,
            json!({"token": token, "usage": Self::record(run)}).to_string(),
        )
    }

    /// `GET` and `DELETE /v1/runs/self`.
    fn own(&mut self, request: &Request) -> (u16, String) {
        let ending = request.method == "DELETE";
        let keep = self.keeps_runs_active;
        let Some(run) = request
            .bearer()
            .and_then(|token| self.runs.iter_mut().find(|run| run.token == token))
        else {
            return (401, "client authentication required\n".into());
        };
        if ending && !keep {
            run.state = "finished";
        }
        (200, Self::record(run).to_string())
    }

    /// A model request on one of the broker's routes: answered with a
    /// stream for a live run's token, in its own header or as the bearer.
    /// Not counted: [`Proxy::serve_requests`] sets the broker's count.
    fn model(&self, request: &Request) -> (u16, String) {
        let token = request.header("x-run-token").or_else(|| request.bearer());
        let live = self
            .runs
            .iter()
            .any(|run| run.state == "active" && Some(run.token.as_str()) == token);
        if live {
            (200, ANSWER.to_owned())
        } else {
            (401, "invalid run token\n".into())
        }
    }

    fn handle(&mut self, request: &Request) -> (u16, String) {
        let path = request.path.split('?').next().unwrap_or_default();
        match (request.method.as_str(), path) {
            ("POST", path) if MODEL_ROUTES.contains(&path) => self.model(request),
            ("GET", OIDC | FORGEJO_OIDC) if request.bearer() == Some(REQUEST_BEARER) => {
                let audience = request.path.split("audience=").nth(1).unwrap_or_default();
                self.issued += 1;
                let jwt = format!("jwt.{audience}.{}", self.issued);
                (200, json!({"value": jwt}).to_string())
            }
            ("GET", OIDC | FORGEJO_OIDC) => (401, "bad request bearer\n".into()),
            (_, RUNS | RUN_SELF) if self.no_run_api => (404, "not found\n".into()),
            ("POST", RUNS) => self.register(request),
            ("GET" | "DELETE", RUN_SELF) => self.own(request),
            (_, RUNS | RUN_SELF) => (405, "method not allowed\n".into()),
            _ => (404, "not found\n".into()),
        }
    }
}

impl Proxy {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = Self {
            url: format!("http://{}", listener.local_addr().unwrap()),
            state: Arc::default(),
        };
        let state = Arc::clone(&proxy.state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    let Some(request) = read_request(&stream) else {
                        return;
                    };
                    let (fault, (status, body)) = {
                        let mut state = state.lock().unwrap();
                        state.requests.push(request.clone());
                        let fault = match request.method.as_str() {
                            "POST" => state.faults.pop_front(),
                            "DELETE" => state.end_faults.pop_front(),
                            _ => None,
                        };
                        let answer = match &fault {
                            Some(Fault::Status(status, text)) => (*status, (*text).to_owned()),
                            Some(Fault::Redirect(_)) => (307, String::new()),
                            Some(Fault::Closed) => (0, String::new()),
                            _ => state.handle(&request),
                        };
                        (fault, answer)
                    };
                    match fault {
                        Some(Fault::LostReply | Fault::Closed) => {}
                        Some(Fault::Redirect(path)) => {
                            answer_with(&mut stream, status, &format!("location: {path}\r\n"), "");
                        }
                        Some(Fault::Slow(delay)) => {
                            std::thread::sleep(delay);
                            answer(&mut stream, status, &body);
                        }
                        _ => answer(&mut stream, status, &body),
                    }
                });
            }
        });
        proxy
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    /// Where a job asks for its identity token.
    pub fn oidc_url(&self) -> String {
        format!("{}{OIDC}?api-version=2", self.url)
    }

    pub fn admit_unproven(&self) -> &Self {
        self.state().unproven = true;
        self
    }

    pub fn without_run_api(&self) -> &Self {
        self.state().no_run_api = true;
        self
    }

    pub fn run_secs(&self, secs: u64) -> &Self {
        self.state().run_secs = Some(secs);
        self
    }

    pub fn fail_registrations(&self, faults: impl IntoIterator<Item = Fault>) -> &Self {
        self.state().faults.extend(faults);
        self
    }

    pub fn fail_endings(&self, faults: impl IntoIterator<Item = Fault>) -> &Self {
        self.state().end_faults.extend(faults);
        self
    }

    pub fn odd_records(&self) -> &Self {
        self.state().odd_records = true;
        self
    }

    pub fn keep_runs_active(&self) -> &Self {
        self.state().keeps_runs_active = true;
        self
    }

    /// Forgets every run, as the broker does when it restarts.
    pub fn restart(&self) {
        self.state().runs.clear();
    }

    /// Counts N more model requests for every active run.
    pub fn serve_requests(&self, n: u64) {
        for run in &mut self.state().runs {
            if run.state == "active" {
                run.requests += n;
            }
        }
    }

    pub fn requests(&self) -> Vec<Request> {
        self.state().requests.clone()
    }

    /// The requests so far as `METHOD PATH` lines, without queries.
    pub fn seen(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|r| {
                let path = r.path.split('?').next().unwrap_or_default();
                format!("{} {path}", r.method)
            })
            .collect()
    }

    /// The states of the runs, in the order they registered.
    pub fn run_states(&self) -> Vec<&'static str> {
        self.state().runs.iter().map(|run| run.state).collect()
    }

    /// The tokens that admit a request now.
    pub fn live_tokens(&self) -> Vec<String> {
        let state = self.state();
        let live = state.runs.iter().filter(|run| run.state == "active");
        live.map(|run| run.token.clone()).collect()
    }
}

/// Not shaped like any provider's key, so nothing takes it for one.
pub fn key() -> String {
    format!("{}-{}", "test-key-not-secret", "0123456789abcdef")
}

pub const ANSWER: &str = "data: {\"type\":\"message_stop\"}\n\n";

/// One request as the provider saw it, header names in lower case.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// A provider that takes only `key()`: its model list answers 200 with
/// it and 401 without, echoing what it was given, as some providers
/// quote part of a key they refuse; a model request answers with a
/// stream, a cookie of the account's, and its request id.
#[derive(Clone)]
pub struct MockProvider {
    pub url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn credential(provider: Provider, headers: &BTreeMap<String, String>) -> Option<String> {
    match provider {
        Provider::Anthropic => headers.get("x-api-key").cloned(),
        Provider::Openai => headers
            .get("authorization")?
            .strip_prefix("Bearer ")
            .map(str::to_owned),
        // GitHub's API wants its integration id beside the token.
        Provider::Github => headers
            .get("authorization")?
            .strip_prefix("Bearer ")
            .filter(|_| {
                headers.get("copilot-integration-id").map(String::as_str)
                    == Some("agentic-workflows")
            })
            .map(str::to_owned),
    }
}

impl MockProvider {
    pub fn start(provider: Provider) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mock = Self {
            url: format!("http://{}", listener.local_addr().unwrap()),
            seen: Arc::default(),
        };
        let seen = Arc::clone(&mock.seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let seen = Arc::clone(&seen);
                std::thread::spawn(move || answer_provider(provider, stream, &seen));
            }
        });
        mock
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn answer_provider(provider: Provider, mut stream: TcpStream, seen: &Mutex<Vec<Seen>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    let mut parts = first.split_whitespace();
    let (method, target) = (
        parts.next().unwrap().to_owned(),
        parts.next().unwrap().to_owned(),
    );
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
    let given = credential(provider, &headers);
    seen.lock().unwrap().push(Seen {
        method: method.clone(),
        target,
        headers,
        body,
    });
    let (status, kind, extra, text) = match (method.as_str(), given == Some(key())) {
        // As GitHub's API answers a job token without the permission.
        (_, false) if provider == Provider::Github => (
            403,
            "text/plain",
            "",
            "forbidden: the GitHub App installation access token does not have the \
             \"Copilot Requests\" permission"
                .to_owned(),
        ),
        (_, false) => (
            401,
            "application/json",
            "",
            format!(
                "{{\"error\":\"invalid key: {}\"}}",
                given.unwrap_or_default()
            ),
        ),
        ("GET", true) => (200, "application/json", "", "{\"data\":[]}".to_owned()),
        _ => (
            200,
            "text/event-stream",
            "set-cookie: account=1\r\nrequest-id: req_1\r\n",
            ANSWER.to_owned(),
        ),
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} X\r\ncontent-type: {kind}\r\n{extra}content-length: {}\r\n\
         connection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.shutdown(Shutdown::Write);
}
