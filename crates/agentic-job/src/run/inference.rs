//! The run's side of the inference proxy: announce the run and get its
//! token, read the proxy's count of the run's model requests while the
//! agent works, and end the run so the token admits nothing more.
//!
//! `github-oidc` and `plain` speak praxis-credential-broker's run API
//! (its INTERNALS.md, "Run tokens"): `POST /v1/runs`, then `GET` and
//! `DELETE /v1/runs/self` with the token. `github-oidc` sends the job's
//! identity token, which the sandbox user cannot get, so the agent cannot
//! register a run of its own. `plain` sends a name and no proof, and is
//! for a client with no identity token. `token-file` has no run API: the
//! token is read from a file, nothing counts the run's requests and
//! nothing ends it.
//!
//! The old tree's `praxis.mjs` took a proxy without the run API (404) as
//! one that needs no token, and ran the agent uncapped. Here a run that
//! cannot announce itself does not start.
//!
//! The token is held in memory only. It reaches the sandbox user in one
//! file of the agent's configuration (`super::agent`) and nowhere else.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use tokio::sync::watch;

use crate::config::{self, Register};

/// The proxy's run API, under its root.
const RUNS_PATH: &str = "/v1/runs";
const RUN_SELF_PATH: &str = "/v1/runs/self";
/// Where the proxy serves each API, unless the configuration says.
const ANTHROPIC_PATH: &str = "/anthropic";
const OPENAI_PATH: &str = "/v1";
/// Names the run of a registration without proof.
const RUN_ID_HEADER: &str = "x-run-id";
const AUTHORIZATION: &str = "authorization";
/// The usage record the run API answers with.
pub const RECORD_SCHEMA: &str = "praxis-run-usage/v2";
const STATE_ACTIVE: &str = "active";
/// The variables GitHub gives a job with `id-token: write`: all the
/// binary knows of GitHub.
pub const OIDC_URL_VAR: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
pub const OIDC_TOKEN_VAR: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// How much of an answer is read: a usage record is a few hundred bytes.
const MAX_BODY_BYTES: u64 = 1 << 20;
/// How much of a refusal's text goes into an error.
const MAX_DETAIL_CHARS: usize = 200;
/// How often the run's request count is fetched while the agent runs:
/// several subagents at once make a request every few seconds between them.
pub const COUNT_INTERVAL: Duration = Duration::from_secs(5);
/// How many counts in a row may be missing before the job's log says so.
const MISSED_COUNTS_BEFORE_WARNING: u32 = 6;
/// The answer of a proxy that has the run API but no policy for it.
const NOT_CONFIGURED: &str = "run registration is not configured";
/// What a token may consist of. It is written into a header and into
/// JSON, so nothing that could end either.
const TOKEN_LEN: std::ops::RangeInclusive<usize> = 16..=4096;
/// The longest name the proxy takes for a run registered without proof.
const MAX_RUN_NAME: usize = 128;

/// A run token. It is never printed: `Debug` and `Display` do not show it.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    pub fn new(text: &str) -> Result<Self> {
        let text = text.trim();
        ensure!(
            TOKEN_LEN.contains(&text.len())
                && text
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._~+/=-".contains(&b)),
            "not a token: it must be {} to {} letters, digits and ._~+/=-",
            TOKEN_LEN.start(),
            TOKEN_LEN.end()
        );
        Ok(Self(text.to_owned()))
    }

    /// The token itself, for the one file it is written to and the
    /// requests that carry it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

/// How the run gets its token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    GithubOidc { audience: String },
    Plain,
    TokenFile { path: PathBuf },
}

impl Mode {
    pub fn register(&self) -> Register {
        match self {
            Self::GithubOidc { .. } => Register::GithubOidc,
            Self::Plain => Register::Plain,
            Self::TokenFile { .. } => Register::TokenFile,
        }
    }

    /// Whether the proxy counts the run's requests and can end it.
    pub fn has_run_api(&self) -> bool {
        !matches!(self, Self::TokenFile { .. })
    }
}

/// The `[inference]` table, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The proxy's root, without a trailing slash.
    pub url: String,
    pub mode: Mode,
    pub anthropic_url: String,
    pub openai_url: String,
}

/// An http or https URL with no credentials, query or fragment, without
/// its trailing slashes.
fn base_url(key: &str, url: &str) -> Result<String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"));
    let host = rest.map(|rest| rest.split('/').next().unwrap_or_default());
    ensure!(
        host.is_some_and(|host| !host.is_empty() && !host.contains('@'))
            && !url.contains(|c: char| c.is_whitespace() || c.is_control() || "?#\"\\".contains(c)),
        "inference.{key}: {url:?} is not an http or https URL without credentials, query or \
         fragment"
    );
    Ok(url.trim_end_matches('/').to_owned())
}

impl Endpoint {
    /// `None` for a configuration with no proxy. A proxy without a mode is
    /// refused: `plain` is never what leaving `register` out means.
    pub fn from_config(inference: &config::Inference) -> Result<Option<Self>> {
        let config::Inference {
            url,
            register,
            audience,
            token_file,
            anthropic_url,
            openai_url,
        } = inference;
        if url.is_empty() {
            ensure!(
                register.is_none()
                    && audience.is_none()
                    && token_file.is_none()
                    && anthropic_url.is_none()
                    && openai_url.is_none(),
                "inference.url is not set, and the rest of [inference] means nothing without it"
            );
            return Ok(None);
        }
        let url = base_url("url", url)?;
        let Some(register) = register else {
            bail!(
                "inference.register is not set: say \"github-oidc\", \"plain\" or \
                 \"token-file\". There is no default, since \"plain\" lets whoever reaches the \
                 proxy register a run"
            );
        };
        let unused = |key: &str, set: bool| {
            ensure!(
                !set,
                "inference.{key} is set, which register = {:?} does not use",
                register.as_str()
            );
            Ok(())
        };
        let mode = match register {
            Register::GithubOidc => {
                unused("token-file", token_file.is_some())?;
                let audience = audience.as_deref().unwrap_or_default();
                // It goes into the query of the token request as it is.
                ensure!(
                    !audience.is_empty()
                        && audience
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b)),
                    "inference.audience: register = \"github-oidc\" needs the audience the proxy \
                     expects, of letters, digits and ._:/-"
                );
                Mode::GithubOidc {
                    audience: audience.to_owned(),
                }
            }
            Register::Plain => {
                unused("audience", audience.is_some())?;
                unused("token-file", token_file.is_some())?;
                Mode::Plain
            }
            Register::TokenFile => {
                unused("audience", audience.is_some())?;
                let path = token_file.clone().unwrap_or_default();
                ensure!(
                    path.is_absolute(),
                    "inference.token-file: register = \"token-file\" needs the absolute path of \
                     the file that holds the token"
                );
                Mode::TokenFile { path }
            }
        };
        let or_under = |key: &str, set: &Option<String>, path: &str| match set {
            Some(set) => base_url(key, set),
            None => Ok(format!("{url}{path}")),
        };
        Ok(Some(Self {
            anthropic_url: or_under("anthropic-url", anthropic_url, ANTHROPIC_PATH)?,
            openai_url: or_under("openai-url", openai_url, OPENAI_PATH)?,
            url,
            mode,
        }))
    }
}

/// What lets this process ask for the job's identity token.
#[derive(Clone)]
pub struct OidcRequest {
    pub url: String,
    pub bearer: String,
}

impl OidcRequest {
    /// From the job's environment, if it has `id-token: write`.
    pub fn from_env() -> Option<Self> {
        let var = |name| std::env::var(name).ok().filter(|v| !v.is_empty());
        Some(Self {
            url: var(OIDC_URL_VAR)?,
            bearer: var(OIDC_TOKEN_VAR)?,
        })
    }
}

/// Who the run says it is.
#[derive(Clone, Default)]
pub struct Identity {
    /// For `github-oidc`.
    pub oidc: Option<OidcRequest>,
    /// For `plain`: the run's identifier, from `--meta`.
    pub name: Option<String>,
}

/// How often, and how far apart, a request to the proxy is tried.
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    pub attempts: u32,
    pub delay: Duration,
}

impl Default for Retry {
    /// The old tree's: a proxy that is restarting is back within seconds.
    fn default() -> Self {
        Self {
            attempts: 4,
            delay: Duration::from_secs(3),
        }
    }
}

/// One try of something that may be worth another.
enum Attempt<T> {
    Done(T),
    Again(String),
    Failed(String),
}

/// Whether whoever asked for the request no longer wants it.
pub type Stopped<'a> = &'a dyn Fn() -> bool;

/// For a request nobody stops.
pub const NEVER: Stopped<'static> = &|| false;

impl Retry {
    /// Tries until an attempt settles it, the tries are used up, or
    /// STOPPED says to go no further: a registration that is retried for
    /// minutes after its run was told to stop would leave a run at the
    /// proxy that nobody ends.
    fn run<T>(self, stopped: Stopped, mut attempt: impl FnMut(u32) -> Attempt<T>) -> Result<T> {
        let mut last = String::from("no attempt was made");
        for n in 0..self.attempts.max(1) {
            if n > 0 {
                std::thread::sleep(self.delay);
            }
            ensure!(!stopped(), "stopped; the last try said: {last}");
            match attempt(n) {
                Attempt::Done(value) => return Ok(value),
                Attempt::Again(why) => last = why,
                Attempt::Failed(why) => bail!(why),
            }
        }
        bail!(last)
    }
}

/// An answer: its status and the start of its text.
struct Answer {
    status: u16,
    text: String,
}

impl Answer {
    fn detail(&self) -> String {
        self.text.trim().chars().take(MAX_DETAIL_CHARS).collect()
    }

    fn json(&self) -> Option<Value> {
        serde_json::from_str(&self.text).ok()
    }

    /// Whether a refusal may be gone at the next try.
    fn transient(&self) -> bool {
        match self.status {
            503 => !self.text.starts_with(NOT_CONFIGURED),
            status => status >= 500 || status == 429,
        }
    }
}

fn http() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(HTTP_TIMEOUT))
        // A refusal is an answer to read, not an error.
        .http_status_as_error(false)
        // Not through a proxy the job's environment names (HTTP_PROXY
        // and the like, which ureq would take): the run token and the
        // job's identity token would pass through it, in the clear for
        // a proxy without TLS.
        .proxy(None)
        // The run API redirects nowhere, and a token is not sent after
        // an answer that says it does.
        .max_redirects(0)
        .build()
        .into()
}

/// The requests the run API and the identity token take: none has a
/// body.
#[derive(Debug, Clone, Copy)]
enum Method {
    Get,
    Post,
    Delete,
}

/// Sends a request with no body; `Err` is a failure to get any answer.
fn send(
    agent: &ureq::Agent,
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
) -> Result<Answer, String> {
    // The builders differ in type by whether the method takes a body.
    macro_rules! with_headers {
        ($request:expr) => {
            headers.iter().fold($request, |request, (name, value)| {
                request.header(*name, *value)
            })
        };
    }
    let response = match method {
        Method::Get => with_headers!(agent.get(url)).call(),
        Method::Delete => with_headers!(agent.delete(url)).call(),
        // An empty body with its length, not a chunked one.
        Method::Post => with_headers!(agent.post(url)).send_empty(),
    };
    let mut response = response.map_err(|err| err.to_string())?;
    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .read_to_string()
        .map_err(|err| err.to_string())?;
    Ok(Answer { status, text })
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// A usage record of the run API, kept as the proxy sent it for the run's
/// summary.
#[derive(Debug, Clone, PartialEq)]
pub struct Record(Value);

impl Record {
    fn parse(value: Value) -> Option<Self> {
        (value.get("schema").and_then(Value::as_str) == Some(RECORD_SCHEMA)).then_some(Self(value))
    }

    pub fn as_json(&self) -> &Value {
        &self.0
    }

    fn count(&self, key: &str) -> Option<u64> {
        self.0.get(key).and_then(Value::as_u64)
    }

    pub fn state(&self) -> &str {
        self.0
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    pub fn expires_at_unix(&self) -> Option<u64> {
        self.count("expires_at_unix")
    }

    /// The model requests the proxy answered for the run: those it
    /// metered, and those answered without usage.
    pub fn model_requests(&self) -> Option<u64> {
        self.count("requests")?
            .checked_add(self.0.get("unmetered").map_or(Some(0), Value::as_u64)?)
    }

    /// What names the run in the proxy's own records, for the log.
    fn name(&self) -> String {
        let field = |key: &str| match self.0.get(key) {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Number(n)) => Some(n.to_string()),
            _ => None,
        };
        match (field("run"), field("run_id"), field("run_attempt")) {
            (Some(name), ..) => name,
            (None, Some(id), Some(attempt)) => format!("{id}/{attempt}"),
            (None, Some(id), None) => id,
            _ => String::from("(unnamed)"),
        }
    }
}

/// A run the proxy knows, or a token it was given for one.
pub struct Run {
    http: ureq::Agent,
    url: String,
    token: Token,
    register: Register,
    /// What the proxy said of the run when it registered.
    registered: Option<Record>,
}

/// How ending a run went.
#[derive(Debug, Clone, PartialEq)]
pub enum Ended {
    /// The token admits nothing more. No record if the proxy no longer
    /// knows the run.
    Ended(Option<Record>),
    /// `token-file`: there is nothing to end, and the token lives as long
    /// as the proxy lets it.
    NoRunApi,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The name a registration without proof asks for at its Nth try. The
/// proxy keeps a name it registered, and nothing tells the caller whose
/// reply was lost from any other: a later try needs a new one.
fn plain_name(name: &str, attempt: u32) -> Result<String> {
    let name = match attempt {
        0 => name.to_owned(),
        n => format!("{name}.retry{n}"),
    };
    ensure!(
        !name.is_empty()
            && name.len() <= MAX_RUN_NAME
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "the run's identifier {name:?} cannot name it at the proxy: 1 to {MAX_RUN_NAME} letters, \
         digits and ._-"
    );
    Ok(name)
}

/// Why a registration answered like this failed, for whoever reads the
/// job's log.
fn refusal(endpoint: &Endpoint, answer: &Answer) -> String {
    let at = format!("the inference proxy at {}", endpoint.url);
    let detail = answer.detail();
    let status = answer.status;
    match (status, &endpoint.mode) {
        (404, _) => format!(
            "{at} has no run API (HTTP 404 from {RUNS_PATH}), so the run cannot announce itself \
             and does not start: is inference.url the proxy's root? A proxy without the run API \
             is used with register = \"token-file\""
        ),
        (503, _) if detail.starts_with(NOT_CONFIGURED) => {
            format!("{at} has no policy for registering runs (HTTP 503: {detail})")
        }
        (401, Mode::GithubOidc { audience }) => format!(
            "{at} rejected the job's identity token (HTTP 401: {detail}): its audience is \
             {audience:?}, which the proxy's must match, and it must be issued after the proxy \
             started"
        ),
        (401, Mode::Plain) => format!(
            "{at} does not register runs without proof (HTTP 401: {detail}): it needs an \
             identity token (register = \"github-oidc\"), or its policy must admit unproven runs"
        ),
        (403, Mode::GithubOidc { .. }) => format!(
            "{at} refused to register runs of this workflow (HTTP 403: {detail}): its policy \
             must admit it"
        ),
        (409, _) => format!(
            "{at} refused to register this run again (HTTP 409: {detail}): it is registered \
             already, or has ended"
        ),
        _ => format!("registering the run with {at} failed (HTTP {status}: {detail})"),
    }
}

/// Asks the CI system for the job's identity token.
fn identity_token(http: &ureq::Agent, request: &OidcRequest, audience: &str) -> Attempt<String> {
    let separator = if request.url.contains('?') { '&' } else { '?' };
    let url = format!("{}{separator}audience={audience}", request.url);
    let answer = match send(
        http,
        Method::Get,
        &url,
        &[(AUTHORIZATION, &bearer(&request.bearer))],
    ) {
        Ok(answer) => answer,
        Err(err) => return Attempt::Again(format!("asking for the identity token: {err}")),
    };
    let value = answer
        .json()
        .and_then(|json| json.get("value")?.as_str().map(str::to_owned))
        .filter(|value| !value.is_empty());
    match (answer.status, value) {
        (200, Some(value)) => Attempt::Done(value),
        (200, None) => Attempt::Failed("the identity token response holds no token".into()),
        (status, _) if answer.transient() => {
            Attempt::Again(format!("asking for the identity token: HTTP {status}"))
        }
        (status, _) => Attempt::Failed(format!("asking for the identity token: HTTP {status}")),
    }
}

impl Run {
    /// Announces the run and gets its token, or reads the given one.
    ///
    /// TIMEOUT_S is the agent's timeout, to warn of a run that expires at
    /// the proxy before it. STOPPED ends the retries early. Every failure
    /// is one of a run that has not started: nothing was spent and trying
    /// again is safe.
    pub fn register(
        endpoint: &Endpoint,
        identity: &Identity,
        retry: Retry,
        timeout_s: u64,
        stopped: Stopped,
    ) -> Result<Self> {
        let http = http();
        let run = |token, registered| Self {
            http: http.clone(),
            url: endpoint.url.clone(),
            token,
            register: endpoint.mode.register(),
            registered,
        };
        let proof = match &endpoint.mode {
            Mode::TokenFile { path } => {
                let token = read_token_file(path)?;
                eprintln!(
                    "warning: inference with a given token ({}): the proxy has no run API, so \
                     nothing counts this run's model requests, nothing ends it, and the token \
                     lives as long as the proxy lets it",
                    path.display()
                );
                return Ok(run(token, None));
            }
            Mode::GithubOidc { audience } => {
                let request = identity.oidc.as_ref().with_context(|| {
                    format!(
                        "register = \"github-oidc\" needs {OIDC_URL_VAR} and {OIDC_TOKEN_VAR}: \
                         the job needs the permission id-token: write"
                    )
                })?;
                Some(retry.run(stopped, |_| identity_token(&http, request, audience))?)
            }
            Mode::Plain => None,
        };
        let name = match &endpoint.mode {
            Mode::Plain => Some(identity.name.as_deref().context(
                "register = \"plain\" needs the run's identifier: --meta has no \"run_id\"",
            )?),
            _ => None,
        };
        let runs = format!("{}{RUNS_PATH}", endpoint.url);
        // After a try that got no answer the proxy may hold the name.
        let mut lost = 0;
        let (token, record) = retry.run(stopped, |_| {
            // The same identity token every time: the proxy answers it
            // with the same run and a new token, so a lost reply costs
            // nothing.
            let header = match (&proof, name) {
                (Some(jwt), _) => (AUTHORIZATION, bearer(jwt)),
                (None, Some(name)) => match plain_name(name, lost) {
                    Ok(name) => (RUN_ID_HEADER, name),
                    Err(err) => return Attempt::Failed(format!("{err:#}")),
                },
                (None, None) => return Attempt::Failed("nothing identifies the run".into()),
            };
            let answer = match send(&http, Method::Post, &runs, &[(header.0, &header.1)]) {
                Ok(answer) => answer,
                Err(err) => {
                    lost += 1;
                    return Attempt::Again(format!(
                        "cannot reach the inference proxy at {} ({err}): is this machine on its \
                         network?",
                        endpoint.url
                    ));
                }
            };
            if answer.status != 201 {
                let why = refusal(endpoint, &answer);
                return if answer.transient() {
                    Attempt::Again(why)
                } else {
                    Attempt::Failed(why)
                };
            }
            let json = answer.json().unwrap_or_default();
            let token = json.get("token").and_then(Value::as_str).map(Token::new);
            match token {
                Some(Ok(token)) => {
                    Attempt::Done((token, json.get("usage").cloned().and_then(Record::parse)))
                }
                _ => Attempt::Failed(format!(
                    "the inference proxy at {} registered the run and returned no token",
                    endpoint.url
                )),
            }
        })?;
        match &record {
            Some(record) => {
                eprintln!(
                    "Registered run {} at the inference proxy ({})",
                    record.name(),
                    endpoint.mode.register().as_str()
                );
                // The proxy's own lifetime for a run may be shorter than
                // the agent's timeout.
                let deadline = unix_now().saturating_add(timeout_s);
                if record.expires_at_unix().is_some_and(|at| at < deadline) {
                    eprintln!(
                        "warning: the run expires at the proxy before the agent's timeout of \
                         {timeout_s}s: its last model requests will be refused"
                    );
                }
            }
            None => eprintln!(
                "warning: the inference proxy registered the run without a {RECORD_SCHEMA} record"
            ),
        }
        Ok(run(token, record))
    }

    pub fn token(&self) -> &Token {
        &self.token
    }

    pub fn register_mode(&self) -> Register {
        self.register
    }

    /// Whether the proxy counts this run's requests and can end it.
    pub fn has_run_api(&self) -> bool {
        self.register != Register::TokenFile
    }

    pub fn registered(&self) -> Option<&Record> {
        self.registered.as_ref()
    }

    /// The model requests the proxy had counted for the run when it
    /// registered it. `None` means the proxy gave no count the session's
    /// cap could read: that cap would then never bind.
    pub fn counted_at_registration(&self) -> Option<u64> {
        self.registered.as_ref()?.model_requests()
    }

    fn own(&self, method: Method) -> Result<Answer, String> {
        send(
            &self.http,
            method,
            &format!("{}{RUN_SELF_PATH}", self.url),
            &[(AUTHORIZATION, &bearer(self.token.expose()))],
        )
    }

    /// The run's usage so far, or `None` when the proxy has none to give
    /// right now: the count is advisory, so nothing here is an error.
    pub fn usage(&self) -> Option<Record> {
        if !self.has_run_api() {
            return None;
        }
        let answer = self.own(Method::Get).ok()?;
        (answer.status == 200)
            .then(|| answer.json())
            .flatten()
            .and_then(Record::parse)
    }

    /// Keeps a channel at the number of model requests the proxy has
    /// answered for the run, subagents' included: what the session's cap
    /// on them reads, since ACP reports none. A count that cannot be
    /// fetched leaves the last one. `None` for a run nothing counts.
    pub fn count(
        self: &Arc<Self>,
        every: Duration,
    ) -> Option<(watch::Receiver<Option<u64>>, Counter)> {
        if !self.has_run_api() {
            return None;
        }
        let (count, requests) = watch::channel(self.counted_at_registration());
        let (stop, stopped) = mpsc::channel::<()>();
        let run = Arc::clone(self);
        // A thread, not a task: the request blocks.
        std::thread::spawn(move || {
            let mut missed = 0u32;
            loop {
                match run.usage().and_then(|record| record.model_requests()) {
                    Some(n) => {
                        count.send_replace(Some(n));
                        missed = 0;
                    }
                    None => missed += 1,
                }
                // Said once per outage: the cap is reading a count that
                // no longer moves.
                if missed == MISSED_COUNTS_BEFORE_WARNING {
                    eprintln!(
                        "warning: the inference proxy has given no count of this run's model \
                         requests {missed} times in a row: the cap on them still reads {:?}",
                        *count.borrow()
                    );
                }
                if !matches!(
                    stopped.recv_timeout(every),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    return;
                }
            }
        });
        Some((requests, Counter { _stop: stop }))
    }

    /// Ends the run, so its token admits nothing more, and returns the
    /// final record. Ending it again returns the same record.
    ///
    /// Until this succeeds the token may still be live, and nothing the
    /// run produced may be uploaded.
    pub fn end(&self, retry: Retry) -> Result<Ended> {
        if !self.has_run_api() {
            return Ok(Ended::NoRunApi);
        }
        const LIVE: &str = "its token may still be live until the run expires";
        retry.run(NEVER, |_| {
            let answer = match self.own(Method::Delete) {
                Ok(answer) => answer,
                Err(err) => {
                    return Attempt::Again(format!(
                        "cannot reach the inference proxy at {} to end the run ({err}); {LIVE}",
                        self.url
                    ));
                }
            };
            // The proxy answers 401 only for a token it does not know, by
            // the lookup that admits inference: the token admits nothing.
            // It keeps runs in memory and forgets them when it restarts.
            if answer.status == 401 {
                eprintln!(
                    "warning: the inference proxy at {} no longer knows this run's token (HTTP \
                     401; did it restart?), so the token admits nothing, but there is no usage \
                     record of the run",
                    self.url
                );
                return Attempt::Done(Ended::Ended(None));
            }
            let why = |what: String| format!("ending the run at the proxy failed: {what}; {LIVE}");
            if answer.status != 200 {
                let why = why(format!("HTTP {}", answer.status));
                return if answer.transient() {
                    Attempt::Again(why)
                } else {
                    Attempt::Failed(why)
                };
            }
            match answer.json().and_then(Record::parse) {
                Some(record) if record.state() != STATE_ACTIVE => {
                    eprintln!(
                        "Ended run {} at the inference proxy ({}): {} model request(s)",
                        record.name(),
                        record.state(),
                        record.model_requests().unwrap_or_default()
                    );
                    Attempt::Done(Ended::Ended(Some(record)))
                }
                Some(_) => Attempt::Failed(why("the proxy still has the run active".into())),
                None => Attempt::Failed(why(format!("the answer is no {RECORD_SCHEMA} record"))),
            }
        })
    }
}

/// Stops the counting of a run's requests when dropped.
pub struct Counter {
    _stop: mpsc::Sender<()>,
}

fn read_token_file(path: &Path) -> Result<Token> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading the token file {}", path.display()))?;
    Token::new(&text).with_context(|| format!("in the token file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn inference(text: &str) -> config::Inference {
        config::Config::parse(&format!("[inference]\n{text}"))
            .unwrap_or_else(|err| panic!("{text:?}: {err:#}"))
            .inference
    }

    #[test]
    fn endpoints() {
        const URL: &str = "url = \"http://proxy.example:18080/\"\n";
        let oidc = Endpoint::from_config(&inference(&format!(
            "{URL}register = \"github-oidc\"\naudience = \"praxis-credential-broker\""
        )))
        .unwrap()
        .unwrap();
        assert_eq!(
            oidc,
            Endpoint {
                url: "http://proxy.example:18080".into(),
                mode: Mode::GithubOidc {
                    audience: "praxis-credential-broker".into()
                },
                anthropic_url: "http://proxy.example:18080/anthropic".into(),
                openai_url: "http://proxy.example:18080/v1".into(),
            }
        );
        let given = Endpoint::from_config(&inference(&format!(
            "{URL}register = \"token-file\"\ntoken-file = \"/run/token\"\n\
             anthropic-url = \"https://llm.example\"\nopenai-url = \"https://llm.example/openai/v1/\""
        )))
        .unwrap()
        .unwrap();
        assert_eq!(given.anthropic_url, "https://llm.example");
        assert_eq!(given.openai_url, "https://llm.example/openai/v1");
        assert!(!given.mode.has_run_api());
        let plain = Endpoint::from_config(&inference(&format!("{URL}register = \"plain\"")))
            .unwrap()
            .unwrap();
        assert_eq!(plain.mode, Mode::Plain);
        assert_eq!(Endpoint::from_config(&inference("")).unwrap(), None);
    }

    /// A configuration that names no mode is refused, and so is one whose
    /// keys belong to another mode: neither may quietly mean `plain`.
    #[test]
    fn endpoints_that_are_refused() {
        const URL: &str = "url = \"http://proxy.example:18080\"\n";
        let cases = [
            (URL.to_owned(), "inference.register is not set"),
            (
                "register = \"plain\"".to_owned(),
                "inference.url is not set",
            ),
            ("audience = \"x\"".to_owned(), "inference.url is not set"),
            (
                format!("{URL}register = \"github-oidc\""),
                "needs the audience",
            ),
            (
                format!("{URL}register = \"github-oidc\"\naudience = \"a b\""),
                "needs the audience",
            ),
            (
                format!("{URL}register = \"github-oidc\"\naudience = \"a&b=c\""),
                "needs the audience",
            ),
            (
                format!("{URL}register = \"plain\"\naudience = \"x\""),
                "inference.audience is set",
            ),
            (
                format!("{URL}register = \"plain\"\ntoken-file = \"/t\""),
                "inference.token-file is set",
            ),
            (
                format!("{URL}register = \"token-file\""),
                "needs the absolute path",
            ),
            (
                format!("{URL}register = \"token-file\"\ntoken-file = \"token\""),
                "needs the absolute path",
            ),
            (
                "url = \"proxy.example:18080\"\nregister = \"plain\"".to_owned(),
                "not an http or https URL",
            ),
            (
                "url = \"http://user:pw@proxy.example\"\nregister = \"plain\"".to_owned(),
                "not an http or https URL",
            ),
            (
                "url = \"http://proxy.example/?x=1\"\nregister = \"plain\"".to_owned(),
                "not an http or https URL",
            ),
            (
                "url = \"ftp://proxy.example\"\nregister = \"plain\"".to_owned(),
                "not an http or https URL",
            ),
            (
                format!("{URL}register = \"plain\"\nanthropic-url = \"x\""),
                "inference.anthropic-url",
            ),
        ];
        for (text, want) in cases {
            let err = Endpoint::from_config(&inference(&text)).expect_err(&text);
            assert!(format!("{err:#}").contains(want), "{text:?}: {err:#}");
        }
    }

    #[test]
    fn tokens() {
        let good = format!("praxis-run-{}", "a".repeat(64));
        assert_eq!(Token::new(&format!("{good}\n")).unwrap().expose(), good);
        assert_eq!(format!("{:?}", Token::new(&good).unwrap()), "Token(..)");
        for bad in [
            "",
            "short",
            "sixteen characters or more with spaces",
            "a-token-then\r\nx-injected: header",
            "a-token-then\"-a-quote",
        ] {
            assert!(Token::new(bad).is_err(), "{bad:?} was taken as a token");
        }
    }

    #[test]
    fn records() {
        let record = |json: Value| Record::parse(json);
        let proven = record(json!({
            "schema": RECORD_SCHEMA, "proof": "github-oidc", "run_id": 7, "run_attempt": 2,
            "state": "active", "expires_at_unix": 100, "requests": 3, "unmetered": 2,
        }))
        .unwrap();
        assert_eq!(proven.name(), "7/2");
        assert_eq!(proven.model_requests(), Some(5));
        assert_eq!(proven.expires_at_unix(), Some(100));
        assert_eq!(proven.state(), "active");
        let unproven = record(json!({"schema": RECORD_SCHEMA, "run": "a-name", "requests": 1}));
        let unproven = unproven.unwrap();
        assert_eq!(unproven.name(), "a-name");
        assert_eq!(unproven.model_requests(), Some(1));
        // A count that is no count is none, not zero.
        let odd = record(json!({"schema": RECORD_SCHEMA, "requests": -1})).unwrap();
        assert_eq!(odd.model_requests(), None);
        let odd = record(json!({"schema": RECORD_SCHEMA, "requests": 1, "unmetered": "x"}));
        assert_eq!(odd.unwrap().model_requests(), None);
        assert_eq!(record(json!({"schema": "praxis-run-usage/v1"})), None);
        assert_eq!(record(json!([])), None);
    }

    #[test]
    fn plain_names() {
        assert_eq!(plain_name("37558571698-1", 0).unwrap(), "37558571698-1");
        assert_eq!(plain_name("run", 2).unwrap(), "run.retry2");
        for bad in ["", "a name", "a/b", &"x".repeat(MAX_RUN_NAME + 1)] {
            assert!(plain_name(bad, 0).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn retries_stop_at_the_first_answer_that_settles_it() {
        let quick = Retry {
            attempts: 3,
            delay: Duration::ZERO,
        };
        let mut tries = 0;
        let got = quick.run(NEVER, |n| {
            tries += 1;
            if n < 2 {
                Attempt::Again("not yet".into())
            } else {
                Attempt::Done(n)
            }
        });
        assert_eq!((got.unwrap(), tries), (2, 3));
        let mut tries = 0;
        let got: Result<()> = quick.run(NEVER, |_| {
            tries += 1;
            Attempt::Again(format!("try {tries}"))
        });
        assert_eq!((got.unwrap_err().to_string().as_str(), tries), ("try 3", 3));
        let mut tries = 0;
        let got: Result<()> = quick.run(NEVER, |_| {
            tries += 1;
            Attempt::Failed("refused".into())
        });
        assert_eq!(
            (got.unwrap_err().to_string().as_str(), tries),
            ("refused", 1)
        );
        // Told to stop, it tries no more, and says what the last try did.
        let tries = std::cell::Cell::new(0);
        let got: Result<()> = quick.run(&|| tries.get() > 0, |_| {
            tries.set(tries.get() + 1);
            Attempt::Again("not yet".into())
        });
        assert_eq!(tries.get(), 1);
        let err = got.unwrap_err().to_string();
        assert_eq!(err, "stopped; the last try said: not yet");
    }
}
