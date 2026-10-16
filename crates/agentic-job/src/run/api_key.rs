//! `register = "api-key"`: the inference proxy for a caller who has a
//! provider's API key and no broker. `run` serves it itself, on a port of
//! the loopback address, as the runner's user, whose memory and
//! environment the sandbox user cannot read. The agent gets that address
//! and a token made for the run, as it would from a broker; the proxy
//! takes the token, puts the key in its place and forwards the request to
//! the provider. So the key is in no file, variable or answer the sandbox
//! user can read, and a prompt injection cannot send it anywhere.
//!
//! Like a broker's run API, the proxy counts the run's model requests,
//! which is what `limits.max-requests` reads, and refuses those past that
//! cap itself; once the run is ended the token admits nothing. Unlike a
//! broker, nothing outside the job caps what the key spends: the
//! provider's own limits on the key do.
//!
//! The provider must not reach the network for the agent either: a tool
//! the provider runs (web search or fetch, code execution, an MCP server
//! it calls) would carry what the agent read in the sandbox past the
//! egress filter. So a model request may offer the model only tools the
//! agent runs itself.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value, json};

use super::agent::RUN_TOKEN_HEADER;
use super::inference::Token;
use crate::config::Provider;

/// The variable of `run`'s own environment that holds the key. The
/// workflow sets it on the one step that runs `run`, from a secret.
pub const API_KEY_VAR: &str = "AGENTIC_JOB_INFERENCE_KEY";
/// What a key may consist of: it goes into a header as it is.
const KEY_LEN: std::ops::RangeInclusive<usize> = 16..=4096;
/// Where the proxy listens: a port of loopback the kernel picks, which
/// the sandbox user reaches without the egress proxy (`NO_PROXY`).
const LISTEN: &str = "127.0.0.1:0";
/// Bounds on what the agent sends: a request's head, its body (a long
/// conversation with its tool results is a few MiB), the connections it
/// holds at once (subagents in parallel), and how long it may take to
/// send a request or read an answer.
const MAX_HEAD_BYTES: u64 = 64 << 10;
const MAX_HEADERS: usize = 100;
const MAX_BODY_BYTES: usize = 32 << 20;
const MAX_CONNECTIONS: usize = 32;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);
/// The longest a whole answer of the provider may take, streamed or not.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// The version of the Anthropic API the check of the key asks for; the
/// agent's own requests carry theirs.
const ANTHROPIC_VERSION: &str = "2023-06-01";
/// What GitHub's Copilot API needs beside the token. A job token is a
/// GitHub App's, and the API refuses one whose integration id is not
/// one it allows for that App (HTTP 400); this is gh-aw's, which it
/// sends for every engine it routes there, the job token's included
/// (gh-aw-firewall `containers/api-proxy/providers/copilot.js`). It
/// also decides which of the account's models the API offers.
const GITHUB_INTEGRATION: (&str, &str) = ("copilot-integration-id", "agentic-workflows");
/// The version of the model list the check of the key asks for, as gh-aw
/// does.
const GITHUB_API_VERSION: (&str, &str) = ("x-github-api-version", "2026-07-01");
/// The headers of the agent's request not passed on: those of this
/// connection, and every credential, the run token's included.
const DROPPED_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    RUN_TOKEN_HEADER,
    // Set by the proxy for GitHub: the agent does not choose another.
    GITHUB_INTEGRATION.0,
    "cookie",
    "proxy-authorization",
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "content-length",
    // The body sent is the JSON the proxy checked, written out again.
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "accept-encoding",
];
/// The headers of the provider's answer passed back: what clients read
/// to parse it and to back off. Nothing else, so no cookie or anything
/// else of the account's.
const KEPT_ANSWER_HEADERS: &[&str] = &[
    "content-type",
    "retry-after",
    "request-id",
    "x-request-id",
    "x-should-retry",
];
const RUN_TOKEN_PREFIX: &str = "agentic-job-run-";
/// The tool types of a model request the agent runs itself: Anthropic's
/// tools without a type and both APIs' `custom`, OpenAI's `function`, and
/// Anthropic's client tools of a fixed schema, named by type and dated
/// version (`bash_20250124`, not the server's `bash_code_execution`). Every other type is one the provider runs, at its
/// own end of the network; a new one is refused until it is named here.
const CLIENT_TOOL_TYPES: &[&str] = &["function", "custom"];
const CLIENT_TOOL_PREFIXES: &[&str] = &["bash_", "text_editor_", "computer_"];
/// Fields of a model request that have the provider reach out for the
/// agent, or bring in tools from elsewhere: Anthropic's MCP connector
/// and code execution container, the web search of OpenAI's chat
/// completions, a prompt stored at OpenAI, which may name tools, and the
/// plugins of OpenRouter's compatible API, whose `web` plugin searches,
/// and its fallback `models`, which would escape the check of `model`.
const PROVIDER_NETWORK_FIELDS: &[&str] = &[
    "mcp_servers",
    "container",
    "web_search_options",
    "prompt",
    "plugins",
    "models",
];
/// Parts of the names of models that search the web with every request,
/// whatever it asks for: OpenAI's search and deep research models
/// (`gpt-4o-search-preview`, `o3-deep-research`), Perplexity's `sonar`
/// and OpenRouter's `:online` variants. Matched without case. A name is
/// a provider's choice, so this list cannot be complete: see
/// docs/inference.md.
const SEARCHING_MODELS: &[&str] = &["search", "sonar", ":online"];

/// A provider's API key. It is never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(text: &str) -> Result<Self> {
        let text = text.trim();
        ensure!(
            !text.is_empty(),
            "{API_KEY_VAR} is empty: pass the provider's key as the workflow's secret \
             INFERENCE_API_KEY"
        );
        ensure!(
            KEY_LEN.contains(&text.len()) && text.bytes().all(|b| b.is_ascii_graphic()),
            "{API_KEY_VAR} is not an API key: it must be {} to {} printable ASCII characters \
             without spaces",
            KEY_LEN.start(),
            KEY_LEN.end()
        );
        Ok(Self(text.to_owned()))
    }

    /// From `run`'s environment; `None` where it is not set.
    pub fn from_env() -> Option<String> {
        std::env::var(API_KEY_VAR).ok()
    }

    /// The key, for the requests that carry it and the redaction.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey(..)")
    }
}

/// The headers that carry KEY to PROVIDER with every request.
pub fn credential(provider: Provider, key: &ApiKey) -> Vec<(&'static str, String)> {
    let bearer = ("authorization", format!("Bearer {}", key.expose()));
    match provider {
        Provider::Anthropic => vec![("x-api-key", key.expose().to_owned())],
        Provider::Openai => vec![bearer],
        Provider::Github => vec![bearer, (GITHUB_INTEGRATION.0, GITHUB_INTEGRATION.1.into())],
    }
}

/// The headers a check of KEY at PROVIDER sends.
pub fn check_headers(provider: Provider, key: &ApiKey) -> Vec<(&'static str, String)> {
    let mut headers = credential(provider, key);
    match provider {
        Provider::Anthropic => headers.push(("anthropic-version", ANTHROPIC_VERSION.to_owned())),
        Provider::Github => headers.push((GITHUB_API_VERSION.0, GITHUB_API_VERSION.1.into())),
        Provider::Openai => {}
    }
    headers
}

/// The provider's list of models, under its root: what the key is checked
/// against before the run starts, as a broker's registration would be.
pub const fn models_path(provider: Provider) -> &'static str {
    match provider {
        Provider::Anthropic => "/v1/models",
        Provider::Openai | Provider::Github => "/models",
    }
}

/// The model requests of PROVIDER's API, under its root. GitHub's serves
/// the Anthropic and the OpenAI ones at the same root, and the checks of
/// a request's content go by its path.
const fn model_paths(provider: Provider) -> &'static [&'static str] {
    match provider {
        Provider::Anthropic => &["/v1/messages", "/v1/messages/count_tokens"],
        Provider::Openai => &["/responses", "/chat/completions"],
        Provider::Github => &[
            "/v1/messages",
            "/v1/messages/count_tokens",
            "/responses",
            "/chat/completions",
        ],
    }
}

/// Whether the proxy forwards METHOD PATH (without its query): the model
/// requests the agents make and the list of models, nothing else of the
/// key's account. Not the batch API, whose one request runs many that
/// the count, and so the request cap, would see as one; not the files
/// API, whose uploads stay at the provider after the run; not the
/// account's administration.
fn forwarded(provider: Provider, method: &str, path: &str) -> bool {
    let models = models_path(provider);
    match method {
        "POST" => model_paths(provider).contains(&path),
        "GET" => {
            path == models
                || path
                    .strip_prefix(models)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .is_some_and(|id| {
                        !id.is_empty()
                            && !id.starts_with('.')
                            && id
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
                    })
        }
        _ => false,
    }
}

/// A token for the run: what the agent shows the proxy in place of the
/// key. Fresh for each run, and good only while the run lasts.
fn run_token() -> Result<Token> {
    token_with(RUN_TOKEN_PREFIX)
}

/// A fresh token of PREFIX and 32 random bytes in hex.
pub(super) fn token_with(prefix: &str) -> Result<Token> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .context("reading /dev/urandom for the run's token")?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Token::new(&format!("{prefix}{hex}"))
}

/// Compares in time that does not depend on where the two differ: any
/// local user can try tokens at the port.
pub(super) fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

struct State {
    provider: Provider,
    /// The provider's root, without a trailing slash.
    upstream: String,
    key: ApiKey,
    token: Token,
    http: ureq::Agent,
    /// The cap on the run's model requests, `limits.max-requests`.
    max_requests: Option<u64>,
    admission: Mutex<Admission>,
}

/// What decides whether a connection is served and a request forwarded,
/// under one lock, so that ending the run cannot cross either: once
/// `end` has it, no request is counted or forwarded again.
#[derive(Default)]
struct Admission {
    ended: bool,
    /// The model requests forwarded, or being forwarded.
    requests: u64,
    /// The connections being served, by number, so that ending the run
    /// can cut them off, a body still on its way included.
    open: BTreeMap<u64, TcpStream>,
    next: u64,
}

impl State {
    fn admission(&self) -> MutexGuard<'_, Admission> {
        self.admission
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Admits a request to be forwarded, and counts it when COUNTED: the
    /// count is reserved before it is sent, so that requests sent at once
    /// cannot pass the cap together.
    fn admit(&self, counted: bool) -> Result<(), Refusal> {
        let mut admission = self.admission();
        ensure_ok(!admission.ended, || {
            Refusal(401, "the run has ended".into())
        })?;
        if counted {
            if let Some(cap) = self.max_requests {
                // 403, not 429: a client would only try again.
                ensure_ok(admission.requests < cap, || {
                    Refusal(
                        403,
                        format!("the run has made its {cap} model request(s), limits.max-requests"),
                    )
                })?;
            }
            admission.requests += 1;
        }
        Ok(())
    }
}

/// The proxy, serving until it is ended or dropped.
pub struct Local {
    address: SocketAddr,
    state: Arc<State>,
}

/// A refusal of the proxy's own: a status and why.
pub(super) struct Refusal(pub(super) u16, pub(super) String);

impl Local {
    /// Listens on loopback and serves the run, forwarding to the provider
    /// at UPSTREAM with KEY at most MAX_REQUESTS model requests.
    pub fn start(
        provider: Provider,
        upstream: &str,
        key: ApiKey,
        max_requests: Option<u64>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(LISTEN).context("listening on loopback")?;
        let address = listener.local_addr().context("the proxy's own address")?;
        let http = ureq::Agent::config_builder()
            .timeout_global(Some(UPSTREAM_TIMEOUT))
            .http_status_as_error(false)
            // Not through a proxy the job's environment names: the key
            // would pass through it.
            .proxy(None)
            // The key is not sent after an answer that says to go
            // elsewhere.
            .max_redirects(0)
            .build()
            .into();
        let state = Arc::new(State {
            provider,
            upstream: upstream.trim_end_matches('/').to_owned(),
            key,
            token: run_token()?,
            http,
            max_requests,
            admission: Mutex::default(),
        });
        let serving = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (number, held) = {
                    let mut admission = serving.admission();
                    if admission.ended {
                        return;
                    }
                    let Ok(handle) = stream.try_clone() else {
                        continue;
                    };
                    let (number, held) = (admission.next, admission.open.len());
                    admission.next += 1;
                    admission.open.insert(number, handle);
                    (number, held)
                };
                let state = Arc::clone(&serving);
                std::thread::spawn(move || {
                    serve(&state, stream, held);
                    state.admission().open.remove(&number);
                });
            }
        });
        Ok(Self { address, state })
    }

    /// The root the agent is given, in place of the provider's.
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    pub fn token(&self) -> &Token {
        &self.state.token
    }

    pub fn requests(&self) -> u64 {
        self.state.admission().requests
    }

    /// The run as a broker's usage record would describe it, for the
    /// session's count and the run's summary.
    pub fn record(&self, schema: &str) -> Value {
        let state = if self.state.admission().ended {
            "ended"
        } else {
            "active"
        };
        json!({
            "schema": schema,
            "proof": "api-key",
            "run": "local",
            "provider": self.state.provider.as_str(),
            "state": state,
            "requests": self.requests(),
            "unmetered": 0,
        })
    }

    /// Ends the run: from now on the token admits nothing, the port is
    /// closed, and every connection is cut off, so a request whose body
    /// was still arriving is never sent.
    pub fn end(&self) {
        let open = {
            let mut admission = self.state.admission();
            if std::mem::replace(&mut admission.ended, true) {
                return;
            }
            std::mem::take(&mut admission.open)
        };
        for stream in open.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        // Wakes the loop that accepts, which then returns.
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_secs(1));
    }
}

impl Drop for Local {
    fn drop(&mut self) {
        self.end();
    }
}

/// Answers one connection: one request, then it is closed.
fn serve(state: &State, mut stream: TcpStream, held: usize) {
    let _ = stream.set_read_timeout(Some(CLIENT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CLIENT_TIMEOUT));
    let outcome = if held >= MAX_CONNECTIONS {
        Err(Refusal(
            503,
            format!("the run's inference proxy holds {MAX_CONNECTIONS} connections already"),
        ))
    } else {
        forward(state, &stream)
    };
    if let Err(Refusal(status, why)) = outcome {
        let body = format!("refused by the run's inference proxy: {why}\n");
        let _ = write!(
            stream,
            "HTTP/1.1 {status} {}\r\ncontent-type: text/plain; charset=utf-8\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{body}",
            reason(status),
            body.len()
        );
    }
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

pub(super) fn reason(status: u16) -> &'static str {
    ureq::http::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("Status")
}

/// The agent's request: its method, target and headers, names in lower
/// case.
pub(super) struct Head {
    pub(super) method: String,
    pub(super) target: String,
    pub(super) headers: Vec<(String, String)>,
}

impl Head {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn bad(why: impl Into<String>) -> Refusal {
    Refusal(400, why.into())
}

pub(super) fn read_head(reader: &mut impl BufRead) -> Result<Head, Refusal> {
    let mut limited = reader.take(MAX_HEAD_BYTES);
    let mut line = || -> Result<String, Refusal> {
        let mut bytes = Vec::new();
        limited
            .read_until(b'\n', &mut bytes)
            .map_err(|err| bad(format!("reading the request: {err}")))?;
        ensure_ok(bytes.ends_with(b"\n"), || {
            bad(format!(
                "the request's head is cut off, or over {MAX_HEAD_BYTES} bytes"
            ))
        })?;
        let text = String::from_utf8(bytes).map_err(|_| bad("the request's head is not UTF-8"))?;
        Ok(text.trim_end_matches(['\r', '\n']).to_owned())
    };
    let first = line()?;
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("not an HTTP request"));
    };
    ensure_ok(version.starts_with("HTTP/1."), || bad("not HTTP/1"))?;
    let mut headers = Vec::new();
    loop {
        let line = line()?;
        if line.is_empty() {
            break;
        }
        ensure_ok(headers.len() < MAX_HEADERS, || {
            bad(format!("over {MAX_HEADERS} headers"))
        })?;
        let (name, value) = line
            .split_once(':')
            .filter(|(name, _)| {
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            .ok_or_else(|| bad("a malformed header"))?;
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok(Head {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
    })
}

pub(super) fn ensure_ok(held: bool, refusal: impl FnOnce() -> Refusal) -> Result<(), Refusal> {
    if held { Ok(()) } else { Err(refusal()) }
}

/// The run token the agent sent: in the broker's own header, or as the
/// credential its client sends by itself.
fn shown_token(head: &Head) -> Option<&str> {
    head.header(RUN_TOKEN_HEADER)
        .or_else(|| head.header("authorization")?.strip_prefix("Bearer "))
        .or_else(|| head.header("x-api-key"))
}

/// Reads the agent's request, checks it, and forwards it; an `Err` is the
/// proxy's own refusal, which has not reached the provider.
fn forward(state: &State, stream: &TcpStream) -> Result<(), Refusal> {
    let mut reader = BufReader::new(stream);
    let head = read_head(&mut reader)?;
    let token = state.token.expose().as_bytes();
    ensure_ok(
        shown_token(&head).is_some_and(|shown| same(shown.as_bytes(), token)),
        || Refusal(401, "no valid run token".into()),
    )?;
    // Checked again, with the count, once the body is in.
    state.admit(false)?;
    let path = head.target.split('?').next().unwrap_or_default();
    ensure_ok(forwarded(state.provider, &head.method, path), || {
        Refusal(
            403,
            format!(
                "{} {path} is not a model request of the {} API",
                head.method,
                state.provider.as_str()
            ),
        )
    })?;
    ensure_ok(head.header("transfer-encoding").is_none(), || {
        Refusal(411, "a chunked body: send its length".into())
    })?;
    let length = match head.header("content-length") {
        None => 0,
        Some(length) => length
            .parse::<usize>()
            .map_err(|_| bad("a malformed content-length"))?,
    };
    ensure_ok(length <= MAX_BODY_BYTES, || {
        Refusal(413, format!("a body of over {MAX_BODY_BYTES} bytes"))
    })?;
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .map_err(|err| bad(format!("reading the request's body: {err}")))?;
    let counted = head.method == "POST";
    if counted {
        body = client_tools_only(path, &body)?;
    }

    let mut request = ureq::http::Request::builder()
        .method(head.method.as_str())
        .uri(format!("{}{}", state.upstream, head.target));
    for (name, value) in &head.headers {
        if !DROPPED_HEADERS.contains(&name.as_str()) {
            request = request.header(name, value);
        }
    }
    if counted {
        request = request.header("content-type", "application/json");
    }
    for (name, value) in credential(state.provider, &state.key) {
        request = request.header(name, value);
    }
    // Counted before it is sent: a request whose answer is lost may still
    // have been answered, and paid for.
    state.admit(counted)?;
    let answer = if body.is_empty() {
        request.body(()).map(|request| state.http.run(request))
    } else {
        request.body(body).map(|request| state.http.run(request))
    }
    .map_err(|err| bad(format!("the request cannot be forwarded: {err}")))?
    .map_err(|err| {
        Refusal(
            502,
            format!("the provider at {} did not answer: {err}", state.upstream),
        )
    })?;
    // From here the answer is the provider's: whatever fails ends the
    // connection, and the client sees a body cut short.
    let _ = pass_back(stream, answer);
    Ok(())
}

/// Refuses a model request that has the provider reach the network for
/// the agent: one that offers the model a tool the provider runs, names
/// a field or a model that does, or content the provider fetches. Refused,
/// not changed: the agent learns why. Returns the body to send, written
/// out again from what was checked, so that a provider that reads the
/// bytes otherwise (the first of duplicate keys, say) sees the same.
fn client_tools_only(path: &str, body: &[u8]) -> Result<Vec<u8>, Refusal> {
    let refused = |why: String| Refusal(403, why);
    let request = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|request| match request {
            Value::Object(request) => Some(request),
            _ => None,
        })
        .ok_or_else(|| bad("a model request's body is not a JSON object"))?;
    if let Some(field) = PROVIDER_NETWORK_FIELDS
        .iter()
        .find(|field| request.contains_key(**field))
    {
        return Err(refused(format!(
            "`{field}` has the provider reach the network for the agent, outside the egress \
             filter"
        )));
    }
    if let Some(model) = request.get("model").and_then(Value::as_str) {
        let lower = model.to_ascii_lowercase();
        ensure_ok(
            !SEARCHING_MODELS.iter().any(|marker| lower.contains(marker)),
            || {
                refused(format!(
                    "the model {model:?} searches the web with the request, outside the egress \
                     filter"
                ))
            },
        )?;
    }
    content_of(path, &request)?;
    let tools = match request.get("tools") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(tools)) => tools.as_slice(),
        Some(_) => return Err(bad("`tools` is not a list")),
    };
    for tool in tools {
        let kind = match tool.get("type") {
            None | Some(Value::Null) if tool.is_object() => None,
            Some(Value::String(kind)) => Some(kind.as_str()),
            _ => return Err(bad("a tool that is not an object with a string `type`")),
        };
        let client = kind.is_none_or(|kind| {
            CLIENT_TOOL_TYPES.contains(&kind)
                || CLIENT_TOOL_PREFIXES.iter().any(|prefix| {
                    kind.strip_prefix(prefix).is_some_and(|version| {
                        !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit())
                    })
                })
        });
        ensure_ok(client, || {
            refused(format!(
                "the tool type {:?} is run by the provider, which would reach the network for \
                 the agent outside the egress filter",
                kind.unwrap_or_default()
            ))
        })?;
    }
    serde_json::to_vec(&request).map_err(|err| bad(format!("writing the request out: {err}")))
}

/// Refuses content the provider would fetch for the agent: an image,
/// document or file named by URL, or by an id at the provider, which the
/// run cannot have uploaded (the files API is not forwarded). Content is
/// read by the shapes of PATH's API, at every depth it nests (a tool's
/// result, a document's content), and a block of a type not named here is
/// refused, so that a new kind of content cannot open a way out. Inline
/// data (base64, a `data:` URL, text) passes, and so does what the model
/// wrote itself, such as a tool call's input, which the provider does not
/// fetch whatever it holds.
fn content_of(path: &str, request: &Map<String, Value>) -> Result<(), Refusal> {
    let list = |field: &str| match request.get(field) {
        None | Some(Value::Null) => Ok(&[][..]),
        Some(Value::Array(items)) => Ok(items.as_slice()),
        Some(_) => Err(bad(format!("`{field}` is not a list"))),
    };
    match path {
        "/responses" => {
            for field in ["instructions", "input"] {
                if !request.get(field).is_some_and(Value::is_string) {
                    for item in list(field)? {
                        responses_item(object(item)?)?;
                    }
                }
            }
        }
        "/chat/completions" => {
            for message in list("messages")? {
                blocks(object(message)?.get("content"), chat_part)?;
            }
        }
        _ => {
            blocks(request.get("system"), messages_block)?;
            for message in list("messages")? {
                blocks(object(message)?.get("content"), messages_block)?;
            }
        }
    }
    Ok(())
}

fn object(value: &Value) -> Result<&Map<String, Value>, Refusal> {
    value
        .as_object()
        .ok_or_else(|| bad("an item of a model request's content is not an object"))
}

/// The type of a content block.
fn kind(block: &Map<String, Value>) -> Result<&str, Refusal> {
    block
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("a content block without a string `type`"))
}

fn unknown(kind: &str) -> Refusal {
    Refusal(
        403,
        format!(
            "a content block of type {kind:?} is not one the proxy knows the provider does not \
             fetch, outside the egress filter"
        ),
    )
}

fn fetched(what: &str) -> Refusal {
    Refusal(
        403,
        format!(
            "{what} has the provider fetch it, outside the egress filter: send the content \
             inline"
        ),
    )
}

/// Content as the APIs take it: absent, text, or a list of blocks.
fn blocks(
    content: Option<&Value>,
    block: fn(&Map<String, Value>) -> Result<(), Refusal>,
) -> Result<(), Refusal> {
    match content {
        None | Some(Value::Null | Value::String(_)) => Ok(()),
        Some(Value::Array(items)) => items.iter().try_for_each(|item| block(object(item)?)),
        Some(_) => Err(bad("content that is neither text nor a list of blocks")),
    }
}

/// Whether a URL the agent sent is its content inline.
fn inline(url: Option<&Value>) -> bool {
    url.is_none_or(|url| url.as_str().is_some_and(|url| url.starts_with("data:")))
}

/// A block of Anthropic's Messages API.
fn messages_block(block: &Map<String, Value>) -> Result<(), Refusal> {
    match kind(block)? {
        "text" | "thinking" | "redacted_thinking" | "tool_use" => Ok(()),
        "tool_result" => blocks(block.get("content"), messages_block),
        kind @ ("image" | "document") => {
            let source = block
                .get("source")
                .and_then(Value::as_object)
                .ok_or_else(|| bad(format!("an {kind} without a `source` object")))?;
            match source.get("type").and_then(Value::as_str) {
                Some("base64" | "text") => Ok(()),
                Some("content") => blocks(source.get("content"), messages_block),
                other => Err(fetched(&format!(
                    "an {kind} from a source of type {:?}",
                    other.unwrap_or_default()
                ))),
            }
        }
        other => Err(unknown(other)),
    }
}

/// An item of the input of OpenAI's Responses API.
fn responses_item(item: &Map<String, Value>) -> Result<(), Refusal> {
    // A message may leave its type out.
    match item.get("type").map_or(Some("message"), Value::as_str) {
        Some("message") => blocks(item.get("content"), responses_part),
        Some("function_call" | "custom_tool_call" | "reasoning") => Ok(()),
        Some("function_call_output" | "custom_tool_call_output") => {
            blocks(item.get("output"), responses_part)
        }
        Some(other) => Err(unknown(other)),
        None => Err(bad("an input item without a string `type`")),
    }
}

/// A part of a message's content in OpenAI's Responses API.
fn responses_part(part: &Map<String, Value>) -> Result<(), Refusal> {
    match kind(part)? {
        "input_text" | "output_text" | "refusal" => Ok(()),
        kind @ ("input_image" | "input_file") => ensure_ok(
            inline(part.get("image_url"))
                && inline(part.get("file_data"))
                && !part.contains_key("file_url")
                && !part.contains_key("file_id"),
            || fetched(&format!("an {kind} not sent as a data: URL")),
        ),
        other => Err(unknown(other)),
    }
}

/// A part of a message's content in OpenAI's chat completions.
fn chat_part(part: &Map<String, Value>) -> Result<(), Refusal> {
    match kind(part)? {
        "text" | "refusal" | "input_audio" => Ok(()),
        "image_url" => ensure_ok(
            part.get("image_url")
                .and_then(Value::as_object)
                .is_some_and(|image| image.get("url").is_some_and(|url| inline(Some(url)))),
            || fetched("an image_url by URL"),
        ),
        "file" => ensure_ok(
            part.get("file")
                .and_then(Value::as_object)
                .is_some_and(|file| inline(file.get("file_data")) && !file.contains_key("file_id")),
            || fetched("a file not sent as a data: URL"),
        ),
        other => Err(unknown(other)),
    }
}

/// Writes the provider's answer to the agent as it arrives, in chunks.
fn pass_back(
    mut stream: &TcpStream,
    answer: ureq::http::Response<ureq::Body>,
) -> std::io::Result<()> {
    let status = answer.status().as_u16();
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in answer.headers() {
        if let (true, Ok(value)) = (KEPT_ANSWER_HEADERS.contains(&name.as_str()), value.to_str()) {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    head.push_str("transfer-encoding: chunked\r\nconnection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    let mut body = answer.into_body().into_reader();
    let mut buffer = vec![0; 16 << 10];
    loop {
        let n = body.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        write!(stream, "{n:x}\r\n")?;
        stream.write_all(&buffer[..n])?;
        stream.write_all(b"\r\n")?;
        stream.flush()?;
    }
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let key = "test-key-not-secret_0123";
        assert_eq!(ApiKey::new(&format!(" {key}\n")).unwrap().expose(), key);
        assert_eq!(format!("{:?}", ApiKey::new(key).unwrap()), "ApiKey(..)");
        for (bad, want) in [
            ("", "is empty"),
            ("  \n", "is empty"),
            ("short", "is not an API key"),
            ("a key with spaces in it", "is not an API key"),
            ("test-key-not-secret\r\nx-injected: 1", "is not an API key"),
        ] {
            let err = ApiKey::new(bad).unwrap_err().to_string();
            assert!(err.contains(want), "{bad:?}: {err}");
            assert!(err.contains(API_KEY_VAR), "{bad:?}: {err}");
        }
    }

    /// Model requests and the model list pass; batches, files and the
    /// account's administration do not.
    #[test]
    fn what_is_forwarded() {
        use Provider::{Anthropic, Github, Openai};
        let cases = [
            (Anthropic, "POST", "/v1/messages", true),
            (Anthropic, "POST", "/v1/messages/count_tokens", true),
            (Anthropic, "GET", "/v1/models", true),
            (Anthropic, "GET", "/v1/models/claude-x-1", true),
            (Anthropic, "POST", "/v1/messages/batches", false),
            (Anthropic, "POST", "/v1/files", false),
            (Anthropic, "GET", "/v1/messages", false),
            (Anthropic, "DELETE", "/v1/models", false),
            (Anthropic, "GET", "/v1/models/", false),
            (Anthropic, "GET", "/v1/models/a/b", false),
            (Anthropic, "GET", "/v1/models/../organizations", false),
            (Anthropic, "GET", "/v1/models/..", false),
            (Anthropic, "POST", "/v1/organizations/api_keys", false),
            (Anthropic, "POST", "/v1/messages/", false),
            (Anthropic, "POST", "/responses", false),
            (Openai, "POST", "/responses", true),
            (Openai, "POST", "/chat/completions", true),
            (Openai, "GET", "/models", true),
            (Openai, "GET", "/models/gpt-x", true),
            (Openai, "POST", "/batches", false),
            (Openai, "POST", "/files", false),
            (Openai, "POST", "/v1/messages", false),
            (Github, "POST", "/v1/messages", true),
            (Github, "POST", "/chat/completions", true),
            (Github, "POST", "/responses", true),
            (Github, "GET", "/models", true),
            (Github, "GET", "/v1/models", false),
            (Github, "POST", "/v1/messages/batches", false),
            (Github, "POST", "/files", false),
            (Github, "POST", "/models/session", false),
            (Github, "POST", "/auto", false),
        ];
        for (provider, method, path, want) in cases {
            assert_eq!(
                forwarded(provider, method, path),
                want,
                "{provider:?} {method} {path}"
            );
        }
    }

    /// Tools the agent runs pass; any the provider runs, and fields that
    /// have it reach out, do not, whatever the API.
    #[test]
    fn provider_side_tools() {
        let cases = [
            (r#"{}"#, Ok(())),
            (r#"{"tools":null}"#, Ok(())),
            (r#"{"tools":[]}"#, Ok(())),
            (r#"{"tools":[{"name":"Read","input_schema":{}}]}"#, Ok(())),
            (r#"{"tools":[{"type":"custom","name":"x"}]}"#, Ok(())),
            (r#"{"tools":[{"type":"function","name":"x"}]}"#, Ok(())),
            (
                r#"{"tools":[{"type":"bash_20250124","name":"bash"}]}"#,
                Ok(()),
            ),
            (
                r#"{"tools":[{"type":"text_editor_20250728","name":"e"}]}"#,
                Ok(()),
            ),
            (
                r#"{"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}"#,
                Err(403),
            ),
            (
                r#"{"tools":[{"type":"web_search_20250305","name":"web_search"}]}"#,
                Err(403),
            ),
            (
                r#"{"tools":[{"type":"code_execution_20250825"}]}"#,
                Err(403),
            ),
            (
                r#"{"tools":[{"type":"mcp_toolset","mcp_server_name":"x"}]}"#,
                Err(403),
            ),
            (
                r#"{"tools":[{"name":"Read"},{"type":"mcp","server_url":"https://x.invalid","require_approval":"never"}]}"#,
                Err(403),
            ),
            (r#"{"tools":[{"type":"web_search"}]}"#, Err(403)),
            (r#"{"tools":[{"type":"file_search"}]}"#, Err(403)),
            (r#"{"tools":[{"type":"code_interpreter"}]}"#, Err(403)),
            (
                r#"{"tools":[{"type":"bash_code_execution_20250825"}]}"#,
                Err(403),
            ),
            (r#"{"tools":[{"type":"bash_"}]}"#, Err(403)),
            (
                r#"{"tools":[{"type":"text_editor_code_execution_20250825"}]}"#,
                Err(403),
            ),
            (r#"{"tools":[{"type":"computer_20250124"}]}"#, Ok(())),
            (r#"{"models":["perplexity/sonar"]}"#, Err(403)),
            (r#"{"model":"claude-x-1","tools":[]}"#, Ok(())),
            (r#"{"model":"gpt-4o-search-preview"}"#, Err(403)),
            (r#"{"model":"o3-Deep-Research"}"#, Err(403)),
            (r#"{"model":"openai/gpt-5:online"}"#, Err(403)),
            (r#"{"model":"perplexity/sonar-pro"}"#, Err(403)),
            (r#"{"plugins":[{"id":"web"}]}"#, Err(403)),
            (r#"{"tools":[{"type":"Function"}]}"#, Err(403)),
            (
                r#"{"mcp_servers":[{"type":"url","url":"https://x.invalid"}]}"#,
                Err(403),
            ),
            (r#"{"container":"c"}"#, Err(403)),
            (r#"{"web_search_options":{}}"#, Err(403)),
            (r#"{"prompt":{"id":"pmpt_1"}}"#, Err(403)),
            (r#"{"tools":{"type":"function"}}"#, Err(400)),
            (r#"{"tools":["function"]}"#, Err(400)),
            (r#"{"tools":[{"type":1}]}"#, Err(400)),
            (r#"[]"#, Err(400)),
            ("", Err(400)),
            ("not json", Err(400)),
        ];
        for (body, want) in cases {
            let got = client_tools_only("/v1/messages", body.as_bytes())
                .map(drop)
                .map_err(|Refusal(status, _)| status);
            assert_eq!(got, want, "{body}");
        }
    }

    /// Content passes inline, and is refused where the provider would
    /// fetch it (by URL or by an id at the provider) or where its type is
    /// not one the proxy knows, at any depth and in each API.
    #[test]
    fn content_sources() {
        const MESSAGES: &str = "/v1/messages";
        const RESPONSES: &str = "/responses";
        const CHAT: &str = "/chat/completions";
        let cases = [
            (
                MESSAGES,
                r#"{"system":"s","messages":[{"role":"user","content":"hi"}]}"#,
                Ok(()),
            ),
            (
                MESSAGES,
                r#"{"system":[{"type":"text","text":"s"}],"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}},{"type":"document","source":{"type":"text","data":"https://example.com is plain text"}}]}]}"#,
                Ok(()),
            ),
            // What the model wrote is not fetched, whatever it names.
            (
                MESSAGES,
                r#"{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"t","signature":"x"},{"type":"tool_use","id":"t","name":"WebFetch","input":{"url":"https://example.com","type":"url"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"ok"},{"type":"document","source":{"type":"content","content":[{"type":"text","text":"t"}]}}]}]}]}"#,
                Ok(()),
            ),
            (
                MESSAGES,
                r#"{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://x.invalid/leak"}}]}]}"#,
                Err(403),
            ),
            (
                MESSAGES,
                r#"{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"url","url":"https://x.invalid/a.pdf"}}]}]}"#,
                Err(403),
            ),
            (
                MESSAGES,
                r#"{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"file","file_id":"file_1"}}]}]}"#,
                Err(403),
            ),
            (
                MESSAGES,
                r#"{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"document","source":{"type":"content","content":[{"type":"image","source":{"type":"url","url":"https://x.invalid/deep"}}]}}]}]}]}"#,
                Err(403),
            ),
            (
                MESSAGES,
                r#"{"system":[{"type":"image","source":{"type":"url","url":"https://x.invalid/s"}}],"messages":[]}"#,
                Err(403),
            ),
            (
                MESSAGES,
                r#"{"messages":[{"role":"user","content":[{"type":"container_upload","file_id":"file_1"}]}]}"#,
                Err(403),
            ),
            (
                MESSAGES,
                r#"{"messages":[{"role":"user","content":[{"type":"some_future_block"}]}]}"#,
                Err(403),
            ),
            (
                MESSAGES,
                r#"{"messages":[{"role":"user","content":[{"type":"image"}]}]}"#,
                Err(400),
            ),
            (
                MESSAGES,
                r#"{"messages":[{"role":"user","content":[{"text":"x"}]}]}"#,
                Err(400),
            ),
            (
                MESSAGES,
                r#"{"messages":[{"role":"user","content":1}]}"#,
                Err(400),
            ),
            (MESSAGES, r#"{"messages":{}}"#, Err(400)),
            (MESSAGES, r#"{"messages":["hi"]}"#, Err(400)),
            (RESPONSES, r#"{"instructions":"s","input":"hi"}"#, Ok(())),
            (
                RESPONSES,
                r#"{"input":[{"role":"user","content":[{"type":"input_text","text":"t"},{"type":"input_image","image_url":"data:image/png;base64,AAAA"},{"type":"input_file","filename":"a.pdf","file_data":"data:application/pdf;base64,AAAA"}]},{"type":"reasoning","summary":[],"encrypted_content":"x"},{"type":"function_call","call_id":"c","name":"f","arguments":"{\"url\":\"https://example.com\"}"},{"type":"function_call_output","call_id":"c","output":[{"type":"input_text","text":"ok"}]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"t","annotations":[]}]}]}"#,
                Ok(()),
            ),
            (
                RESPONSES,
                r#"{"input":[{"role":"user","content":[{"type":"input_image","image_url":"https://x.invalid/leak"}]}]}"#,
                Err(403),
            ),
            (
                RESPONSES,
                r#"{"input":[{"role":"user","content":[{"type":"input_image","image_url":"DATA:,x"}]}]}"#,
                Err(403),
            ),
            (
                RESPONSES,
                r#"{"input":[{"role":"user","content":[{"type":"input_image","file_id":"file_1"}]}]}"#,
                Err(403),
            ),
            (
                RESPONSES,
                r#"{"input":[{"role":"user","content":[{"type":"input_file","file_url":"https://x.invalid/a.pdf"}]}]}"#,
                Err(403),
            ),
            (
                RESPONSES,
                r#"{"input":[{"role":"user","content":[{"type":"input_file","file_id":"file_1"}]}]}"#,
                Err(403),
            ),
            (
                RESPONSES,
                r#"{"input":[{"role":"user","content":[{"type":"input_file","file_data":"https://x.invalid/a.pdf"}]}]}"#,
                Err(403),
            ),
            (
                RESPONSES,
                r#"{"input":[{"type":"function_call_output","call_id":"c","output":[{"type":"input_image","image_url":"https://x.invalid/deep"}]}]}"#,
                Err(403),
            ),
            (
                RESPONSES,
                r#"{"instructions":[{"role":"system","content":[{"type":"input_file","file_url":"https://x.invalid/i"}]}]}"#,
                Err(403),
            ),
            (
                RESPONSES,
                r#"{"input":[{"type":"item_reference","id":"msg_1"}]}"#,
                Err(403),
            ),
            (
                RESPONSES,
                r#"{"input":[{"role":"user","content":[{"type":"input_video","url":"https://x.invalid/v"}]}]}"#,
                Err(403),
            ),
            (RESPONSES, r#"{"input":[{"type":1}]}"#, Err(400)),
            (RESPONSES, r#"{"input":3}"#, Err(400)),
            (
                CHAT,
                r#"{"messages":[{"role":"system","content":"s"},{"role":"assistant","content":null,"tool_calls":[]},{"role":"user","content":[{"type":"text","text":"t"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}},{"type":"file","file":{"file_data":"data:application/pdf;base64,AAAA"}}]}]}"#,
                Ok(()),
            ),
            (
                CHAT,
                r#"{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x.invalid/leak"}}]}]}"#,
                Err(403),
            ),
            (
                CHAT,
                r#"{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{}}]}]}"#,
                Err(403),
            ),
            (
                CHAT,
                r#"{"messages":[{"role":"user","content":[{"type":"file","file":{"file_id":"file_1"}}]}]}"#,
                Err(403),
            ),
            (
                CHAT,
                r#"{"messages":[{"role":"user","content":[{"type":"file","file":{"filename":"a.pdf","file_data":"https://x.invalid/a.pdf"}}]}]}"#,
                Err(403),
            ),
            (
                CHAT,
                r#"{"messages":[{"role":"user","content":[{"type":"video_url","video_url":{"url":"https://x.invalid/v"}}]}]}"#,
                Err(403),
            ),
        ];
        for (path, body, want) in cases {
            let got = client_tools_only(path, body.as_bytes())
                .map(drop)
                .map_err(|Refusal(status, _)| status);
            assert_eq!(got, want, "{path} {body}");
        }
    }

    /// The body sent is the JSON that was checked: of duplicate keys, a
    /// provider that would read the first sees only the last, as the check
    /// did.
    #[test]
    fn duplicate_keys_are_sent_as_checked() {
        let body = r#"{"tools":[{"type":"web_search"}],"tools":[],"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://x.invalid"},"type":"text","text":"hi"}]}]}"#;
        let sent = client_tools_only("/v1/messages", body.as_bytes())
            .ok()
            .unwrap();
        let sent: Value = serde_json::from_slice(&sent).unwrap();
        assert_eq!(
            sent,
            json!({"tools": [], "messages": [{"role": "user", "content": [
                {"type": "text", "source": {"type": "url", "url": "https://x.invalid"}, "text": "hi"}
            ]}]})
        );
    }

    #[test]
    fn heads() {
        let read = |text: &str| read_head(&mut text.as_bytes());
        let head = read(
            "POST /v1/messages?beta=true HTTP/1.1\r\nHost: x\r\nX-Run-Token: abc\r\n\
             Content-Length: 2\r\n\r\n{}",
        )
        .ok()
        .unwrap();
        assert_eq!(head.method, "POST");
        assert_eq!(head.target, "/v1/messages?beta=true");
        assert_eq!(head.header("x-run-token"), Some("abc"));
        assert_eq!(shown_token(&head), Some("abc"));
        let bearer = read("GET /models HTTP/1.1\r\nAuthorization: Bearer xyz\r\n\r\n")
            .ok()
            .unwrap();
        assert_eq!(shown_token(&bearer), Some("xyz"));
        let long = format!(
            "GET / HTTP/1.1\r\nx: {}\r\n\r\n",
            "a".repeat(usize::try_from(MAX_HEAD_BYTES).unwrap())
        );
        let many = format!(
            "GET / HTTP/1.1\r\n{}\r\n",
            "x: 1\r\n".repeat(MAX_HEADERS + 1)
        );
        for bad in [
            "",
            "GET /\r\n\r\n",
            "GET / HTTP/2\r\n\r\n",
            "GET / HTTP/1.1\r\n",
            "GET / HTTP/1.1\r\nno colon\r\n\r\n",
            "GET / HTTP/1.1\r\nbad name: x\r\n\r\n",
            &long,
            &many,
        ] {
            assert!(read(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn tokens_are_compared_whole() {
        assert!(same(b"abc", b"abc"));
        assert!(!same(b"abc", b"abd"));
        assert!(!same(b"abc", b"ab"));
        assert!(!same(b"", b"a"));
        let (a, b) = (run_token().unwrap(), run_token().unwrap());
        assert_ne!(a, b);
        assert!(a.expose().starts_with(RUN_TOKEN_PREFIX));
    }
}
