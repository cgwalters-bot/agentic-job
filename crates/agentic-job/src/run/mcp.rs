//! `[mcp.NAME]`: a remote MCP server the agent calls with a credential it
//! never holds. `run` serves the agent a proxy for it, on a port of the
//! loopback address, as the runner's user, as it serves the inference
//! proxy of `register = "api-key"` ([`super::api_key`]). The agent gets
//! that address and a token made for the run in `session/new`; the proxy
//! takes the token, puts the credential from the workflow's secret
//! [`SECRET`] in its place, and forwards the message to the server.
//!
//! The proxy forwards MCP's own methods and the tools `allowed` names,
//! nothing else: no resources, prompts or completions, no batch, and an
//! answer to a request of the server's only where that was a ping. It
//! takes every tool `allowed` does not name out of the server's list, and
//! refuses a call of one, so the server need not enforce the list itself.
//! It does not follow a redirect, and it refuses everything once the run
//! has ended.
//!
//! No program of the caller's runs outside the sandbox: the server is
//! remote. It is reached by `run`, not through the egress filter, so what
//! the agent sends through an allowed tool's arguments reaches the server
//! whatever the filter says (docs/mcp.md).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use serde_json::{Value, json};

use super::api_key::{self, Refusal, ensure_ok, read_head, reason, same};
use super::inference::{Attempt, Retry, Stopped, Token};
use crate::config;

/// The variable of `run`'s own environment that holds the server's
/// credential. The workflow sets it on the one step that runs `run`, from
/// the secret [`SECRET`].
pub const TOKEN_VAR: &str = "AGENTIC_JOB_MCP_TOKEN";
/// The one secret `mcp.NAME.secret` may name: the reusable workflow
/// declares each secret it takes, and cannot look one up by a name.
pub const SECRET: &str = "MCP_TOKEN";
/// How many `[mcp.*]` tables a run takes, while there is one secret.
pub const MAX_SERVERS: usize = 1;
/// Bounds on `[mcp.NAME]`: the name's length, how many tools `allowed`
/// names and how long each may be, and the URL's length.
const MAX_NAME_CHARS: usize = 32;
const MAX_ALLOWED: usize = 64;
const MAX_TOOL_CHARS: usize = 64;
const MAX_URL_BYTES: usize = 2048;
/// What a credential may consist of: it goes into a header as it is.
const CREDENTIAL_LEN: RangeInclusive<usize> = 16..=4096;
/// Where the proxy listens, as the inference proxy of `api-key` does.
const LISTEN: &str = "127.0.0.1:0";
/// The one path it serves.
const PATH: &str = "/";
const RUN_TOKEN_PREFIX: &str = "agentic-job-mcp-";
/// Bounds on what the agent sends: a message's body, the connections it
/// holds at once, and how long it may take to send a request or read an
/// answer.
const MAX_BODY_BYTES: usize = 4 << 20;
const MAX_CONNECTIONS: usize = 32;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);
/// The largest answer of the server's passed back: it is read whole, to
/// be checked before the agent sees any of it.
const MAX_ANSWER_BYTES: u64 = 8 << 20;
/// The longest a tool call may take at the server.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// The longest each request of the check before the run may take.
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);
/// The headers of streamable HTTP passed on both ways: the session the
/// server keeps, and the version of MCP the client speaks.
const SESSION_HEADER: &str = "mcp-session-id";
const VERSION_HEADER: &str = "mcp-protocol-version";
/// What a client of streamable HTTP accepts.
const ACCEPT: &str = "application/json, text/event-stream";
const JSON_TYPE: &str = "application/json";
const SSE_TYPE: &str = "text/event-stream";
/// The version of MCP the check before the run asks for.
const CHECK_VERSION: &str = "2025-06-18";
/// How many pages of the tool list the check reads.
const MAX_LIST_PAGES: usize = 16;
/// How much of a refusal's text an error quotes.
const MAX_DETAIL_CHARS: usize = 300;
/// What stands in for the credential in what the server wrote; the
/// api-key proxy and the check of a key use it for the key too.
pub(super) const CUT: &str = "[the credential]";
/// The methods the proxy forwards besides `tools/call`: those of the
/// protocol itself and the list of tools.
const FORWARDED: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "notifications/cancelled",
    "ping",
    LIST,
];
const LIST: &str = "tools/list";
const CALL: &str = "tools/call";
/// The one request of the server's the agent may answer.
const PING: &str = "ping";
/// JSON-RPC's codes for a refusal.
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// `[mcp.NAME]`, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub name: String,
    pub url: String,
    pub allowed: BTreeSet<String>,
}

fn name_ok(name: &str) -> bool {
    name.len() <= MAX_NAME_CHARS
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

fn tool_ok(tool: &str) -> bool {
    (1..=MAX_TOOL_CHARS).contains(&tool.len())
        && tool
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// Refuses a URL the credential should not go to: one that is not https,
/// that names a user, or that has a fragment.
fn check_url(name: &str, url: &str) -> Result<()> {
    let refused = |why: &str| anyhow!("mcp.{name}.url: {url:?} {why}");
    if url.len() > MAX_URL_BYTES {
        return Err(refused(&format!("is over {MAX_URL_BYTES} bytes")));
    }
    if !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(refused(
            "has a space, a control or a non-ASCII character in it",
        ));
    }
    // The credential goes with every request, so only to a server TLS
    // has checked. Plain http is refused even to loopback: the sandbox
    // shares it, and a process of the agent's that takes the port once a
    // local server has let it go would be sent the credential.
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(refused(&if url.starts_with("http://") {
            format!(
                "would carry {SECRET} in the clear, to whatever holds that address: it must be \
                 https, even to loopback"
            )
        } else {
            "is not an https URL".to_owned()
        }));
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(refused("has no host"));
    }
    if authority.contains('@') {
        return Err(refused(&format!(
            "names a user: the credential is the secret {SECRET}"
        )));
    }
    if url.contains('#') {
        return Err(refused("has a fragment"));
    }
    url.parse::<ureq::http::Uri>()
        .map_err(|err| refused(&format!("is not a URL: {err}")))?;
    Ok(())
}

impl Server {
    /// The server TABLES configure, checked; `None` for a run with none.
    pub fn from_config(tables: &BTreeMap<String, config::Mcp>) -> Result<Option<Self>> {
        ensure!(
            tables.len() <= MAX_SERVERS,
            "[mcp]: {} servers are configured, and a run serves at most {MAX_SERVERS} for now, \
             with the one secret {SECRET} (#120)",
            tables.len()
        );
        let Some((name, table)) = tables.iter().next() else {
            return Ok(None);
        };
        ensure!(
            name_ok(name),
            "[mcp.{name:?}]: a server's name is a lower-case letter, then up to {} lower-case \
             letters, digits, _ and -",
            MAX_NAME_CHARS - 1
        );
        ensure!(
            table.secret == SECRET,
            "mcp.{name}.secret: {:?} is not a secret the workflow passes on: the one there is \
             is {SECRET} (#120)",
            table.secret
        );
        check_url(name, &table.url)?;
        ensure!(
            !table.allowed.is_empty(),
            "mcp.{name}.allowed is empty: name each tool the agent may call"
        );
        ensure!(
            table.allowed.len() <= MAX_ALLOWED,
            "mcp.{name}.allowed names {} tools, over {MAX_ALLOWED}",
            table.allowed.len()
        );
        let mut allowed = BTreeSet::new();
        for tool in &table.allowed {
            ensure!(
                tool_ok(tool),
                "mcp.{name}.allowed: {tool:?} is not a tool's name: 1 to {MAX_TOOL_CHARS} \
                 letters, digits and _.-, without wildcards"
            );
            ensure!(
                allowed.insert(tool.clone()),
                "mcp.{name}.allowed: {tool:?} is named twice"
            );
        }
        Ok(Some(Self {
            name: name.clone(),
            url: table.url.clone(),
            allowed,
        }))
    }
}

/// The server's credential. It is never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential(String);

impl Credential {
    /// From TEXT, `run`'s environment's [`TOKEN_VAR`]: a run with an
    /// MCP server and no credential for it does not start.
    pub fn new(text: Option<&str>) -> Result<Self> {
        let text = text.map(str::trim).unwrap_or_default();
        ensure!(
            !text.is_empty(),
            "{TOKEN_VAR} is empty: an [mcp] server needs its credential as the workflow's secret \
             {SECRET}"
        );
        ensure!(
            CREDENTIAL_LEN.contains(&text.len()) && text.bytes().all(|b| b.is_ascii_graphic()),
            "{TOKEN_VAR} is not a credential: it must be {} to {} printable ASCII characters \
             without spaces",
            CREDENTIAL_LEN.start(),
            CREDENTIAL_LEN.end()
        );
        Ok(Self(text.to_owned()))
    }

    /// From `run`'s environment; `None` where it is not set.
    pub fn from_env() -> Option<String> {
        std::env::var(TOKEN_VAR).ok()
    }

    /// The credential, for the requests that carry it and the redaction.
    pub fn expose(&self) -> &str {
        &self.0
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.0)
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential(..)")
    }
}

/// An HTTP client that goes to the server itself: not through a proxy
/// the job's environment names, which the credential would pass through,
/// and not after an answer that says to go elsewhere.
fn client(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .proxy(None)
        .max_redirects(0)
        .build()
        .into()
}

/// A refusal of the proxy's own, and the id of the JSON-RPC request it
/// answers with its error code, where it answers one.
struct Refused {
    status: u16,
    why: String,
    rpc: Option<(Value, i64)>,
}

impl From<Refusal> for Refused {
    fn from(Refusal(status, why): Refusal) -> Self {
        Self {
            status,
            why,
            rpc: None,
        }
    }
}

fn refused(status: u16, why: impl Into<String>) -> Refused {
    Refused {
        status,
        why: why.into(),
        rpc: None,
    }
}

/// What the agent sent, as far as the answer depends on it.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    /// `tools/list`, whose answer is filtered.
    List,
    /// `tools/call` of this tool, which is logged.
    Call(String),
    /// Anything else forwarded.
    Other,
}

/// The JSON-RPC id an answer to a ping of the server's names, as a key.
fn id_key(id: &Value) -> String {
    id.to_string()
}

/// Checks the agent's message BODY: one JSON-RPC message, of a method
/// that is forwarded, a call of an ALLOWED tool, or the answer to one of
/// the server's PINGS, which it takes. Returns the body to send, written
/// out again from what was checked, so that a server that reads the
/// bytes otherwise (the first of duplicate keys, say) sees the same.
fn check_message(
    allowed: &BTreeSet<String>,
    pings: &mut BTreeSet<String>,
    body: &[u8],
) -> Result<(Vec<u8>, Sent), Refused> {
    let message: Value =
        serde_json::from_slice(body).map_err(|_| refused(400, "the body is not JSON"))?;
    let map = match &message {
        Value::Object(map) => map,
        Value::Array(_) => {
            return Err(refused(
                403,
                "a batch of JSON-RPC messages: the proxy forwards one at a time",
            ));
        }
        _ => return Err(refused(400, "the body is not a JSON-RPC message")),
    };
    let id = map.get("id").cloned().unwrap_or(Value::Null);
    let rpc = |status, code, why: String| Refused {
        status,
        why,
        rpc: Some((id.clone(), code)),
    };
    if map.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(rpc(
            400,
            INVALID_REQUEST,
            "not a JSON-RPC 2.0 message".into(),
        ));
    }
    let sent = match map.get("method") {
        Some(Value::String(method)) if method == CALL => {
            match map
                .get("params")
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
            {
                Some(tool) if allowed.contains(tool) => Sent::Call(tool.to_owned()),
                Some(tool) => {
                    return Err(rpc(
                        403,
                        INVALID_PARAMS,
                        format!("the tool {tool:?} is not one the run allows"),
                    ));
                }
                None => {
                    return Err(rpc(
                        400,
                        INVALID_PARAMS,
                        "a tools/call without a name".into(),
                    ));
                }
            }
        }
        Some(Value::String(method)) if method == LIST => Sent::List,
        Some(Value::String(method)) if FORWARDED.contains(&method.as_str()) => Sent::Other,
        Some(Value::String(method)) => {
            return Err(rpc(
                403,
                METHOD_NOT_FOUND,
                format!("{method} is not forwarded: only tools and MCP's own methods are"),
            ));
        }
        Some(_) => {
            return Err(rpc(
                400,
                INVALID_REQUEST,
                "a method that is not a string".into(),
            ));
        }
        // An answer, which the server only gets to a ping it sent.
        None => {
            if !(map.contains_key("result") || map.contains_key("error"))
                || !pings.remove(&id_key(&id))
            {
                return Err(rpc(
                    403,
                    INVALID_REQUEST,
                    "an answer to no ping of the server's: the agent answers no other request \
                     of its"
                        .into(),
                ));
            }
            Sent::Other
        }
    };
    let body = serde_json::to_vec(&message)
        .map_err(|err| refused(400, format!("writing the message out: {err}")))?;
    Ok((body, sent))
}

/// Takes every tool ALLOWED does not name out of the result of MESSAGE,
/// an answer to `tools/list`, and of each message of a batch.
fn filter_tools(allowed: &BTreeSet<String>, message: &mut Value) {
    match message {
        Value::Array(messages) => {
            for message in messages {
                filter_tools(allowed, message);
            }
        }
        Value::Object(map) => {
            if let Some(Value::Array(tools)) = map
                .get_mut("result")
                .and_then(|result| result.get_mut("tools"))
            {
                tools.retain(|tool| {
                    tool.get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| allowed.contains(name))
                });
            }
        }
        _ => {}
    }
}

/// Notes the id of every ping of the server's in MESSAGE, which the agent
/// may then answer.
fn note_pings(pings: &mut BTreeSet<String>, message: &Value) {
    match message {
        Value::Array(messages) => {
            for message in messages {
                note_pings(pings, message);
            }
        }
        Value::Object(map) => {
            if let (Some(PING), Some(id)) =
                (map.get("method").and_then(Value::as_str), map.get("id"))
            {
                pings.insert(id_key(id));
            }
        }
        _ => {}
    }
}

/// An event of a stream of server-sent events: its lines but its data,
/// and its data.
struct Event<'a> {
    lines: Vec<&'a str>,
    data: Option<String>,
}

/// TEXT's lines, each ending in CRLF, LF or a lone CR, as the format of
/// server-sent events has them: a client that takes a lone CR for the end
/// of a line must not see a line here that this reads as another.
/// A byte-order mark that starts the stream is not part of its first line.
fn sse_lines(text: &str) -> impl Iterator<Item = &str> {
    text.strip_prefix('\u{feff}')
        .unwrap_or(text)
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .flat_map(|line| line.split('\r'))
}

fn events(text: &str) -> Vec<Event<'_>> {
    let mut events = Vec::new();
    let mut event = Event {
        lines: Vec::new(),
        data: None,
    };
    for line in sse_lines(text) {
        if line.is_empty() {
            if !event.lines.is_empty() || event.data.is_some() {
                events.push(std::mem::replace(
                    &mut event,
                    Event {
                        lines: Vec::new(),
                        data: None,
                    },
                ));
            }
            continue;
        }
        match line.strip_prefix("data:") {
            Some(data) => {
                let data = data.strip_prefix(' ').unwrap_or(data);
                match &mut event.data {
                    Some(have) => {
                        have.push('\n');
                        have.push_str(data);
                    }
                    None => event.data = Some(data.to_owned()),
                }
            }
            None => event.lines.push(line),
        }
    }
    if !event.lines.is_empty() || event.data.is_some() {
        events.push(event);
    }
    events
}

/// The messages of a server's answer: its JSON, or the JSON of each event
/// of its stream. What is neither is no message.
fn messages(content_type: Option<&str>, body: &[u8]) -> Vec<Value> {
    match media_type(content_type).as_deref() {
        Some(JSON_TYPE) => serde_json::from_slice(body).into_iter().collect(),
        Some(SSE_TYPE) => std::str::from_utf8(body)
            .map(|text| {
                events(text)
                    .iter()
                    .filter_map(|event| serde_json::from_str(event.data.as_deref()?).ok())
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn media_type(content_type: Option<&str>) -> Option<String> {
    content_type.map(|kind| {
        kind.split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
    })
}

/// The server's answer BODY, of STATUS, to what the agent SENT, as the
/// agent gets it: as the server wrote it, but that every ping of the
/// server's in it is noted in PINGS, and in an answer to `tools/list` each
/// tool not ALLOWED is gone. That answer is written out again from what
/// was read; one that cannot be read is refused rather than passed on
/// unfiltered, unless it is a refusal that is neither JSON nor a stream
/// (an expired session's 404, for one).
fn for_agent(
    allowed: &BTreeSet<String>,
    pings: &mut BTreeSet<String>,
    sent: &Sent,
    (status, content_type): (u16, Option<&str>),
    body: Vec<u8>,
) -> Result<Vec<u8>, Refused> {
    for message in messages(content_type, &body) {
        note_pings(pings, &message);
    }
    if *sent != Sent::List || body.is_empty() {
        return Ok(body);
    }
    let unreadable = || {
        refused(
            502,
            "the MCP server's tool list cannot be read to filter it",
        )
    };
    match media_type(content_type).as_deref() {
        Some(JSON_TYPE) => {
            let mut message: Value = serde_json::from_slice(&body).map_err(|_| unreadable())?;
            filter_tools(allowed, &mut message);
            serde_json::to_vec(&message).map_err(|_| unreadable())
        }
        Some(SSE_TYPE) => {
            let text = std::str::from_utf8(&body).map_err(|_| unreadable())?;
            let mut out = String::new();
            for event in events(text) {
                for line in &event.lines {
                    out.push_str(line);
                    out.push('\n');
                }
                if let Some(data) = &event.data {
                    let mut message: Value =
                        serde_json::from_str(data).map_err(|_| unreadable())?;
                    filter_tools(allowed, &mut message);
                    out.push_str(&format!("data: {message}\n"));
                }
                out.push('\n');
            }
            Ok(out.into_bytes())
        }
        _ if !(200..300).contains(&status) => Ok(body),
        _ => Err(unreadable()),
    }
}

struct State {
    server: Server,
    credential: Credential,
    /// The ways an answer may quote it, cut out of every answer.
    quoted: Vec<Vec<u8>>,
    token: Token,
    http: ureq::Agent,
    admission: Mutex<Admission>,
}

/// What decides whether a connection is served and a message forwarded,
/// under one lock, so that ending the run cannot cross either.
#[derive(Default)]
struct Admission {
    ended: bool,
    /// The tool calls forwarded.
    calls: u64,
    /// The pings of the server's passed to the agent and not answered.
    pings: BTreeSet<String>,
    /// The connections being served, by number, so that ending the run
    /// can cut them off.
    open: BTreeMap<u64, TcpStream>,
    next: u64,
}

impl State {
    fn admission(&self) -> MutexGuard<'_, Admission> {
        self.admission
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn admit(&self) -> Result<(), Refused> {
        if self.admission().ended {
            return Err(refused(401, "the run has ended"));
        }
        Ok(())
    }
}

/// The proxy, serving until it is ended or dropped.
pub struct Local {
    address: SocketAddr,
    state: Arc<State>,
}

impl Local {
    /// Listens on loopback and serves the agent SERVER, with CREDENTIAL.
    pub fn start(server: Server, credential: Credential) -> Result<Self> {
        let listener =
            TcpListener::bind(LISTEN).map_err(|err| anyhow!("listening on loopback: {err}"))?;
        let address = listener
            .local_addr()
            .map_err(|err| anyhow!("the MCP proxy's own address: {err}"))?;
        let state = Arc::new(State {
            server,
            quoted: quoted(credential.expose()),
            credential,
            token: api_key::token_with(RUN_TOKEN_PREFIX)?,
            http: client(UPSTREAM_TIMEOUT),
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

    /// The URL the agent is given, in place of the server's.
    pub fn url(&self) -> String {
        format!("http://{}{PATH}", self.address)
    }

    pub fn token(&self) -> &Token {
        &self.state.token
    }

    pub fn server(&self) -> &Server {
        &self.state.server
    }

    /// The tool calls forwarded so far.
    pub fn calls(&self) -> u64 {
        self.state.admission().calls
    }

    /// Ends the run: from now on the token admits nothing, the port is
    /// closed, and every connection is cut off.
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
        Err(refused(
            503,
            format!("the run's MCP proxy holds {MAX_CONNECTIONS} connections already"),
        ))
    } else {
        forward(state, &stream)
    };
    if let Err(Refused { status, why, rpc }) = outcome {
        let why = format!("refused by the run's MCP proxy: {why}");
        let (kind, body) = match rpc {
            Some((id, code)) => (
                JSON_TYPE,
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": why}})
                    .to_string(),
            ),
            None => ("text/plain; charset=utf-8", format!("{why}\n")),
        };
        let allow = if status == 405 {
            "allow: POST, DELETE\r\n"
        } else {
            ""
        };
        let _ = write!(
            stream,
            "HTTP/1.1 {status} {}\r\ncontent-type: {kind}\r\n{allow}content-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            reason(status),
            body.len()
        );
    }
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

/// Reads the agent's request, checks it, forwards it, and passes the
/// answer back; an `Err` is the proxy's own refusal, which has not reached
/// the server.
fn forward(state: &State, mut stream: &TcpStream) -> Result<(), Refused> {
    let mut reader = BufReader::new(stream);
    let head = read_head(&mut reader)?;
    let token = state.token.expose().as_bytes();
    ensure_ok(
        head.header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|shown| same(shown.as_bytes(), token)),
        || Refusal(401, "no valid run token".into()),
    )?;
    state.admit()?;
    if head.target != PATH {
        return Err(refused(404, format!("the proxy serves only {PATH}")));
    }
    match head.method.as_str() {
        "POST" | "DELETE" => {}
        // Streamable HTTP lets a server refuse the stream a GET asks for.
        "GET" => {
            return Err(refused(
                405,
                "the proxy opens no stream of the server's: send each message with POST",
            ));
        }
        method => return Err(refused(405, format!("{method} is not MCP's"))),
    }
    ensure_ok(head.header("transfer-encoding").is_none(), || {
        Refusal(411, "a chunked body: send its length".into())
    })?;
    let length = match head.header("content-length") {
        None => 0,
        Some(length) => length
            .parse::<usize>()
            .map_err(|_| refused(400, "a malformed content-length"))?,
    };
    if length > MAX_BODY_BYTES {
        return Err(refused(
            413,
            format!("a body of over {MAX_BODY_BYTES} bytes"),
        ));
    }
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .map_err(|err| refused(400, format!("reading the request's body: {err}")))?;
    let post = head.method == "POST";
    let (body, sent) = if post {
        check_message(&state.server.allowed, &mut state.admission().pings, &body)?
    } else {
        (Vec::new(), Sent::Other)
    };

    // No header of the agent's but MCP's own two: the credential is the
    // proxy's, and the rest is this connection's.
    let mut request = ureq::http::Request::builder()
        .method(head.method.as_str())
        .uri(&state.server.url)
        .header("authorization", state.credential.bearer())
        .header("accept", ACCEPT);
    for name in [SESSION_HEADER, VERSION_HEADER] {
        if let Some(value) = head.header(name) {
            request = request.header(name, value);
        }
    }
    {
        let mut admission = state.admission();
        if admission.ended {
            return Err(refused(401, "the run has ended"));
        }
        if matches!(sent, Sent::Call(_)) {
            admission.calls += 1;
        }
    }
    let answer = if post {
        request
            .header("content-type", JSON_TYPE)
            .body(body)
            .map(|request| state.http.run(request))
    } else {
        request
            .body(Vec::new())
            .map(|request| state.http.run(request))
    }
    .map_err(|err| refused(400, format!("the request cannot be forwarded: {err}")))?
    .map_err(|err| {
        refused(
            502,
            format!("the MCP server {} did not answer: {err}", state.server.name),
        )
    })?;
    let status = answer.status().as_u16();
    if let Sent::Call(tool) = &sent {
        eprintln!(
            "MCP server {}: called {tool}: HTTP {status}",
            state.server.name
        );
    }
    if (300..400).contains(&status) {
        return Err(refused(
            502,
            format!(
                "the MCP server answered with a redirect (HTTP {status}), which is not followed"
            ),
        ));
    }
    let header = |name: &str| {
        answer
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let (content_type, session) = (header("content-type"), header(SESSION_HEADER));
    let body = answer
        .into_body()
        .into_with_config()
        .limit(MAX_ANSWER_BYTES)
        .read_to_vec()
        .map_err(|err| {
            refused(
                502,
                format!(
                    "the MCP server's answer could not be read whole, at most \
                     {MAX_ANSWER_BYTES} bytes: {err}"
                ),
            )
        })?;
    let body = for_agent(
        &state.server.allowed,
        &mut state.admission().pings,
        &sent,
        (status, content_type.as_deref()),
        body,
    )?;
    // A server, or a gateway before it, that quotes the request it was
    // sent would hand the agent the credential.
    let secret = &state.quoted;
    let body = cut(body, secret);
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in [("content-type", &content_type), (SESSION_HEADER, &session)] {
        if let Some(value) = value {
            let value =
                String::from_utf8_lossy(&cut(value.as_bytes().to_vec(), secret)).into_owned();
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    head.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    ));
    // From here the answer is the server's: a failure only cuts it short.
    let _ = stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(&body));
    Ok(())
}

/// The ways a server may quote SECRET: as it is, and inside a JSON
/// string, where serializers escape `"` and `\`, some `/`, and some (Go's)
/// `<`, `>` and `&`.
pub(super) fn quoted(secret: &str) -> Vec<Vec<u8>> {
    let json = serde_json::to_string(secret).unwrap_or_default();
    let json = json
        .strip_prefix('"')
        .and_then(|json| json.strip_suffix('"'))
        .unwrap_or(secret);
    let slash = json.replace('/', "\\/");
    let html = json
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    let mut forms: Vec<Vec<u8>> = Vec::new();
    for form in [secret, json, &slash, &html] {
        if !form.is_empty() && !forms.iter().any(|have| have == form.as_bytes()) {
            forms.push(form.as_bytes().to_vec());
        }
    }
    forms
}

/// BYTES with every one of FORMS in them replaced by [`CUT`]. Give it
/// the whole text: a form across the end of a part would be missed, and
/// its start left in.
pub(super) fn cut(bytes: Vec<u8>, forms: &[Vec<u8>]) -> Vec<u8> {
    forms.iter().fold(bytes, |bytes, form| {
        let mut out = Vec::with_capacity(bytes.len());
        let mut rest = bytes.as_slice();
        while let Some(at) = rest.windows(form.len()).position(|window| window == form) {
            out.extend_from_slice(&rest[..at]);
            out.extend_from_slice(CUT.as_bytes());
            rest = &rest[at + form.len()..];
        }
        out.extend_from_slice(rest);
        out
    })
}

/// One answer of the server's to the check.
struct Reply {
    status: u16,
    content_type: Option<String>,
    session: Option<String>,
    body: Vec<u8>,
}

impl Reply {
    /// The start of its text, with CREDENTIAL cut out of it, as it is
    /// and JSON-escaped, before it is cut short: `run` prints this before
    /// its redaction is set up.
    fn detail(&self, credential: &Credential) -> String {
        String::from_utf8_lossy(&cut(self.body.clone(), &quoted(credential.expose())))
            .trim()
            .chars()
            .take(MAX_DETAIL_CHARS)
            .collect()
    }

    /// The answer to the request of ID.
    fn answer(&self, id: u64) -> Option<Value> {
        messages(self.content_type.as_deref(), &self.body)
            .into_iter()
            .flat_map(|message| match message {
                Value::Array(messages) => messages,
                message => vec![message],
            })
            .find(|message| {
                message.get("id") == Some(&json!(id)) && message.get("method").is_none()
            })
    }
}

/// Checks CREDENTIAL with SERVER before the run starts, as a key is
/// checked with its provider: it must initialize a session, list tools,
/// and have every tool `allowed` names. A refusal, or a server that cannot
/// be reached after RETRY, is a run that never started.
pub fn check(
    server: &Server,
    credential: &Credential,
    retry: Retry,
    stopped: Stopped,
) -> Result<()> {
    let http = client(CHECK_TIMEOUT);
    let tools = retry.run(stopped, |_| list_tools(&http, server, credential))?;
    let missing: Vec<&str> = server
        .allowed
        .iter()
        .filter(|tool| !tools.contains(*tool))
        .map(String::as_str)
        .collect();
    ensure!(
        missing.is_empty(),
        "the MCP server {} has no tool {} that mcp.{}.allowed names (it lists: {})",
        server.name,
        missing.join(", "),
        server.name,
        if tools.is_empty() {
            "none".to_owned()
        } else {
            tools.into_iter().collect::<Vec<_>>().join(", ")
        }
    );
    eprintln!(
        "MCP server {}: the credential in {TOKEN_VAR} was taken; the agent may call {}",
        server.name,
        server
            .allowed
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

/// One try of the check: the names of the server's tools.
fn list_tools(
    http: &ureq::Agent,
    server: &Server,
    credential: &Credential,
) -> Attempt<BTreeSet<String>> {
    let at = format!("the MCP server {} at {}", server.name, server.url);
    let send = |message: Option<Value>, session: Option<&str>, version: Option<&str>| {
        let mut request = ureq::http::Request::builder()
            .method(if message.is_some() { "POST" } else { "DELETE" })
            .uri(&server.url)
            .header("authorization", credential.bearer())
            .header("accept", ACCEPT)
            .header("content-type", JSON_TYPE);
        for (name, value) in [(SESSION_HEADER, session), (VERSION_HEADER, version)] {
            if let Some(value) = value {
                request = request.header(name, value);
            }
        }
        let body = message.map_or_else(Vec::new, |message| message.to_string().into_bytes());
        let answer = request
            .body(body)
            .map_err(|err| err.to_string())
            .and_then(|request| http.run(request).map_err(|err| err.to_string()))?;
        let header = |name: &str| {
            answer
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let (status, content_type, session) = (
            answer.status().as_u16(),
            header("content-type"),
            header(SESSION_HEADER),
        );
        let body = answer
            .into_body()
            .into_with_config()
            .limit(MAX_ANSWER_BYTES)
            .read_to_vec()
            .map_err(|err| err.to_string())?;
        Ok::<_, String>(Reply {
            status,
            content_type,
            session,
            body,
        })
    };
    // What an answer that is no success means for the check.
    let judge = |what: &str, reply: &Reply| -> Option<Attempt<BTreeSet<String>>> {
        let detail = reply.detail(credential);
        Some(match reply.status {
            200..=299 => return None,
            401 | 403 => Attempt::Failed(format!(
                "{at} refused the credential in {TOKEN_VAR} (HTTP {}: {detail}): is the \
                 workflow's secret {SECRET} a token of this server's, and still valid?",
                reply.status
            )),
            status @ (429 | 500..) => Attempt::Again(format!("{what} with {at}: HTTP {status}")),
            status => Attempt::Failed(format!("{what} with {at} failed (HTTP {status}: {detail})")),
        })
    };
    let initialize = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": CHECK_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "agentic-job", "version": env!("CARGO_PKG_VERSION")},
    }});
    let reply = match send(Some(initialize), None, None) {
        Ok(reply) => reply,
        Err(err) => return Attempt::Again(format!("cannot reach {at} ({err})")),
    };
    if let Some(attempt) = judge("initializing a session", &reply) {
        return attempt;
    }
    let Some(version) = reply.answer(1).and_then(|answer| {
        answer
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }) else {
        return Attempt::Failed(format!(
            "{at} did not answer initialize with a result: {}",
            reply.detail(credential)
        ));
    };
    let session = reply.session;
    let session = session.as_deref();
    let version = Some(version.as_str());
    let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    match send(Some(initialized), session, version) {
        Ok(reply) => {
            if let Some(attempt) = judge("initializing a session", &reply) {
                return attempt;
            }
        }
        Err(err) => return Attempt::Again(format!("cannot reach {at} ({err})")),
    }
    let mut tools = BTreeSet::new();
    let mut cursor: Option<String> = None;
    for page in 0..MAX_LIST_PAGES {
        let id = 2 + page as u64;
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |cursor| json!({"cursor": cursor}));
        let list = json!({"jsonrpc": "2.0", "id": id, "method": LIST, "params": params});
        let reply = match send(Some(list), session, version) {
            Ok(reply) => reply,
            Err(err) => return Attempt::Again(format!("cannot reach {at} ({err})")),
        };
        if let Some(attempt) = judge("listing tools", &reply) {
            return attempt;
        }
        let Some(result) = reply
            .answer(id)
            .and_then(|answer| answer.get("result").cloned())
        else {
            return Attempt::Failed(format!(
                "{at} did not answer tools/list with a result: {}",
                reply.detail(credential)
            ));
        };
        tools.extend(
            result
                .get("tools")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|tool| tool.get("name")?.as_str().map(str::to_owned)),
        );
        cursor = result
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    if session.is_some() {
        // The session is the check's alone: what the server says to its
        // end changes nothing.
        let _ = send(None, session, version);
    }
    Attempt::Done(tools)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> BTreeSet<String> {
        ["get_issue", "search"].map(str::to_owned).into()
    }

    /// Only MCP's own methods, calls of allowed tools and answers to the
    /// server's pings pass, one message at a time.
    #[test]
    fn what_the_agent_may_send() {
        let cases = [
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                Ok(Sent::Other),
            ),
            (
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                Ok(Sent::Other),
            ),
            (
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#,
                Ok(Sent::Other),
            ),
            (
                r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
                Ok(Sent::Other),
            ),
            (
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}"#,
                Ok(Sent::List),
            ),
            (
                r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search","arguments":{"q":"x"}}}"#,
                Ok(Sent::Call("search".into())),
            ),
            (
                r#"{"jsonrpc":"2.0","id":"p1","result":{}}"#,
                Ok(Sent::Other),
            ),
            (r#"{"jsonrpc":"2.0","id":"p1","result":{}}"#, Err(403)),
            (r#"{"jsonrpc":"2.0","id":7,"result":{}}"#, Err(403)),
            (
                r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"delete_repo"}}"#,
                Err(403),
            ),
            (
                r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"Search"}}"#,
                Err(403),
            ),
            (
                r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{}}"#,
                Err(400),
            ),
            (
                r#"{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"file:///x"}}"#,
                Err(403),
            ),
            (
                r#"{"jsonrpc":"2.0","id":6,"method":"resources/list"}"#,
                Err(403),
            ),
            (
                r#"{"jsonrpc":"2.0","id":6,"method":"prompts/get"}"#,
                Err(403),
            ),
            (
                r#"{"jsonrpc":"2.0","id":6,"method":"completion/complete"}"#,
                Err(403),
            ),
            (
                r#"{"jsonrpc":"2.0","id":6,"method":"logging/setLevel"}"#,
                Err(403),
            ),
            (r#"{"jsonrpc":"2.0","id":6,"method":1}"#, Err(400)),
            (r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#, Err(403)),
            (r#"{"id":1,"method":"ping"}"#, Err(400)),
            (r#""ping""#, Err(400)),
            ("not json", Err(400)),
        ];
        let mut pings: BTreeSet<String> = [id_key(&json!("p1"))].into();
        for (body, want) in cases {
            let got = check_message(&allowed(), &mut pings, body.as_bytes())
                .map(|(_, sent)| sent)
                .map_err(|refused| refused.status);
            assert_eq!(got, want, "{body}");
        }
    }

    /// A refusal of a request answers it with a JSON-RPC error, and the
    /// body sent is the JSON that was checked.
    #[test]
    fn refusals_answer_the_request_and_bodies_are_sent_as_checked() {
        let mut pings = BTreeSet::new();
        let Err(refusal) = check_message(
            &allowed(),
            &mut pings,
            br#"{"jsonrpc":"2.0","id":9,"method":"prompts/list"}"#,
        ) else {
            panic!("prompts/list was forwarded");
        };
        assert_eq!(refusal.rpc, Some((json!(9), METHOD_NOT_FOUND)));
        let duplicate = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"},"params":{"name":"search"}}"#;
        let (body, sent) = check_message(&allowed(), &mut pings, duplicate)
            .ok()
            .unwrap();
        assert_eq!(sent, Sent::Call("search".into()));
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["params"], json!({"name": "search"}));
    }

    /// The tool list loses every tool not allowed, as JSON and as a
    /// stream; other answers pass as they are, and a ping in one may be
    /// answered.
    #[test]
    fn answers() {
        let list = r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"search"},{"name":"delete_repo"},{"title":"no name"}]}}"#;
        let mut pings = BTreeSet::new();
        let json = for_agent(
            &allowed(),
            &mut pings,
            &Sent::List,
            (200, Some("application/json")),
            list.into(),
        )
        .ok()
        .unwrap();
        let json: Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(json["result"]["tools"], json!([{"name": "search"}]));

        let stream = format!(
            "event: message\r\nid: 1\r\ndata: {{\"jsonrpc\":\"2.0\",\"id\":\"p\",\"method\":\"ping\"}}\r\n\r\n: comment\nevent: message\ndata: {}\n\n",
            list
        );
        let sse = for_agent(
            &allowed(),
            &mut pings,
            &Sent::List,
            (200, Some("text/event-stream; charset=utf-8")),
            stream.into(),
        )
        .ok()
        .unwrap();
        let sse = String::from_utf8(sse).unwrap();
        assert!(!sse.contains("delete_repo"), "{sse}");
        assert!(sse.contains("event: message\nid: 1\ndata: {"), "{sse}");
        let got = messages(Some(SSE_TYPE), sse.as_bytes());
        assert_eq!(got.len(), 2, "{sse}");
        assert_eq!(got[1]["result"]["tools"], json!([{"name": "search"}]));
        assert!(pings.contains(&id_key(&json!("p"))));

        // Not a tool list: passed as it is.
        let call =
            br#"{"jsonrpc":"2.0","id":4,"result":{"tools":[{"name":"delete_repo"}]}}"#.to_vec();
        let same = for_agent(
            &allowed(),
            &mut pings,
            &Sent::Other,
            (200, Some("application/json")),
            call.clone(),
        )
        .ok()
        .unwrap();
        assert_eq!(same, call);
        // A tool list that cannot be read is not passed on unfiltered.
        for (kind, body) in [
            (Some("application/json"), "{not json"),
            (Some("text/plain"), list),
            (None, list),
            (Some("text/event-stream"), "data: {not json\n\n"),
        ] {
            let got = for_agent(
                &allowed(),
                &mut pings,
                &Sent::List,
                (200, kind),
                body.into(),
            );
            assert_eq!(
                got.map_err(|refused| refused.status).err(),
                Some(502),
                "{kind:?} {body}"
            );
        }
        // A lone CR ends a line too: the tool list after one is filtered.
        let cr = format!("event: message\rdata: {list}\n\n");
        let sse = for_agent(
            &allowed(),
            &mut pings,
            &Sent::List,
            (200, Some(SSE_TYPE)),
            cr.into(),
        )
        .ok()
        .unwrap();
        let sse = String::from_utf8(sse).unwrap();
        assert!(!sse.contains("delete_repo"), "{sse}");
        assert!(sse.starts_with("event: message\ndata: {"), "{sse}");
        // Nor does a byte-order mark before the first line hide it.
        let bom = format!("\u{feff}data: {list}\n\n");
        let sse = for_agent(
            &allowed(),
            &mut pings,
            &Sent::List,
            (200, Some(SSE_TYPE)),
            bom.into(),
        )
        .ok()
        .unwrap();
        let sse = String::from_utf8(sse).unwrap();
        assert!(!sse.contains("delete_repo"), "{sse}");
        let expired = for_agent(
            &allowed(),
            &mut pings,
            &Sent::List,
            (404, Some("text/plain")),
            b"no session".to_vec(),
        );
        assert_eq!(expired.ok().unwrap(), b"no session");
    }

    #[test]
    fn the_credential_is_cut_out() {
        let secret = quoted("test-mcp-not-secret");
        assert_eq!(secret.len(), 1);
        for (bytes, want) in [
            (&b"no secret"[..], &b"no secret"[..]),
            (b"test-mcp-not-secret", b"[the credential]"),
            (
                b"a test-mcp-not-secret b test-mcp-not-secret",
                b"a [the credential] b [the credential]",
            ),
            (b"test-mcp-not-secre", b"test-mcp-not-secre"),
        ] {
            assert_eq!(cut(bytes.to_vec(), &secret), want);
        }
        // Quoted inside JSON, however a serializer escapes it.
        let secret = quoted(r#"a"b\c/d<e>f&g-0123456789"#);
        for quote in [
            r#"a"b\c/d<e>f&g-0123456789"#,
            r#"a\"b\\c/d<e>f&g-0123456789"#,
            r#"a\"b\\c\/d<e>f&g-0123456789"#,
            r#"a\"b\\c/d\u003ce\u003ef\u0026g-0123456789"#,
        ] {
            let text = format!("{{\"echo\":\"{quote}\"}}");
            assert_eq!(
                cut(text.into_bytes(), &secret),
                b"{\"echo\":\"[the credential]\"}",
                "{quote}"
            );
        }
    }

    #[test]
    fn credentials() {
        let text = format!("{}-{}", "test-mcp-not-secret", "0123456789abcdef");
        let credential = Credential::new(Some(&format!(" {text}\n"))).unwrap();
        assert_eq!(credential.expose(), text);
        assert_eq!(format!("{credential:?}"), "Credential(..)");
        for bad in [
            None,
            Some(""),
            Some(" \n"),
            Some("short"),
            Some("with a space in it 0123"),
        ] {
            let err = Credential::new(bad).unwrap_err().to_string();
            assert!(err.contains(TOKEN_VAR), "{bad:?}: {err}");
        }
    }
}
