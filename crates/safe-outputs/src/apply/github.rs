//! GitHub's REST API and git, with one token: what GitHub's publishing
//! ([`super::publish`]) and a caller's own GitHub commands ask the forge,
//! in place of apply.yml's github-script steps. The caller gives the API's
//! address, the token and its [`Provenance`]; nothing here reads the
//! environment.

use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};

use super::git::{self, Git, Push};
use super::roles::{Credential, Role};
use super::{
    BranchPush, Close, CommitStatus, LabelChange, Made, NewIssue, Op, Provenance, Publisher,
    PullRequest, owner,
};

/// The runner's variable naming the API, which a caller reads.
pub const API_URL_VAR: &str = "GITHUB_API_URL";

/// The API without [`API_URL_VAR`].
pub const DEFAULT_API: &str = "https://api.github.com";

/// How often, and how far apart, git is asked whether a fork is there:
/// the forge makes it in the background.
pub const FORK_TRIES: u32 = 30;

const FORK_WAIT: Duration = Duration::from_secs(10);

/// How gh-aw's handler retries opening a pull request after a transient
/// failure (its `RATE_LIMIT_RETRY_CONFIG`): up to five more times, the
/// wait doubling from [`RETRY_WAIT`] up to [`MAX_RETRY_WAIT`]. Its jitter
/// and its reading of `Retry-After` are left out.
const PULL_REQUEST_RETRIES: u32 = 5;

const RETRY_WAIT: Duration = Duration::from_secs(30);

const MAX_RETRY_WAIT: Duration = Duration::from_secs(240);

/// The most pages of a list read: 10,000 entries.
const MAX_PAGES: u32 = 100;

const PER_PAGE: usize = 100;

/// The GraphQL API's path, under the REST API's address.
const GRAPHQL: &str = "/graphql";

/// The statuses gh-aw's `isTransientError` retries.
const TRANSIENT_STATUSES: [u16; 7] = [408, 425, 429, 500, 502, 503, 504];

/// What in a refusal's message gh-aw's `isTransientError` retries.
const TRANSIENT_MESSAGES: &[&str] = &[
    "unexpected html response",
    "network",
    "timeout",
    "econnreset",
    "enotfound",
    "etimedout",
    "econnrefused",
    "socket hang up",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
    "rate limit",
    "abuse detection",
    "too many requests",
    "temporarily unavailable",
    "no server is currently available",
];

/// What in a message gh-aw's `isRateLimitError` calls a rate limit.
const RATE_LIMIT_MESSAGES: &[&str] = &["rate limit", "abuse detection", "too many requests"];

/// Whether A and B name the same repository or login: GitHub's names
/// ignore case.
pub fn same(a: &Value, b: &str) -> bool {
    a.as_str().is_some_and(|a| a.eq_ignore_ascii_case(b))
}

/// Whether NAME is `owner/repo` as GitHub spells one, and so a path of
/// two segments under `/repos/`.
pub fn is_repo(name: &str) -> bool {
    crate::Forge::Github.is_repo(name)
}

/// TEXT as one path segment of a URL, `/` kept: a branch name the forge
/// gave, which may hold `#`, `%` or `?`.
pub fn segment(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// TEXT as one value of a URL's query: everything but letters, digits
/// and `-._~` escaped.
fn query(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The URL a `link` header gives as `rel="next"`.
fn next_link(link: &str) -> Option<&str> {
    link.split(',').find_map(|part| {
        let (url, params) = part.trim().split_once(';')?;
        params
            .split(';')
            .any(|param| param.trim() == "rel=\"next\"")
            .then(|| url.trim().strip_prefix('<')?.strip_suffix('>'))
            .flatten()
    })
}

/// GitHub's REST API and git, with one token.
#[derive(Clone)]
pub struct Github {
    api: String,
    token: String,
    http: ureq::Agent,
    /// The most an answer may hold.
    max_response: u64,
    /// Between asking git whether the fork is there.
    pub fork_wait: Duration,
    /// Before the first retry of a transient failure.
    pub retry_wait: Duration,
    /// The `X-GitHub-Api-Version` asked for, if not the forge's default.
    api_version: Option<&'static str>,
    /// The user agent, [`Provenance::name`], and who commits a push
    /// that does not say, [`Provenance::committer`].
    provenance: Provenance<'static>,
    /// Given the warning before each retry, to show as the caller's log
    /// shows untrusted text; by default nobody.
    warn: fn(&str),
    roles: Option<std::collections::BTreeMap<Role, Credential>>,
    role: Role,
}

/// A request the forge refused: its status and its message, as octokit
/// words one (its `toErrorMessage`), so that what is reported matches
/// what gh-aw's handlers report.
#[derive(Debug)]
pub struct Refused {
    pub status: u16,
    pub message: String,
    /// The answer's `errors`, which name the field each is about.
    pub errors: Vec<Value>,
}

/// A request [`Github::request_retrying`] gave up on, worded as gh-aw's
/// `withRetry` words it, with the forge's last refusal.
#[derive(Debug)]
pub struct Retried {
    message: String,
    pub refused: Option<Refused>,
}

impl std::fmt::Display for Retried {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Retried {}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Refused {}

/// A request the forge did not answer in full: the connection failed or
/// timed out.
#[derive(Debug)]
struct Unanswered(String);

impl std::fmt::Display for Unanswered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unanswered {}

/// Whether gh-aw's `isTransientError` retries ERR: no answer, or a
/// refusal of a transient status or message.
pub fn is_transient(err: &anyhow::Error) -> bool {
    if err.is::<Unanswered>() {
        return true;
    }
    err.downcast_ref::<Refused>().is_some_and(|refused| {
        let message = refused.message.trim_start().to_lowercase();
        TRANSIENT_STATUSES.contains(&refused.status)
            || message.starts_with("<!doctype html")
            || TRANSIENT_MESSAGES
                .iter()
                .any(|pattern| message.contains(pattern))
    })
}

/// The error gh-aw's `withRetry` throws (its `enhanceError`) when OPERATION
/// failed with ERR after RETRIES retries: what its handler reports, and
/// what its manager quotes in the comments after a pull request that
/// failed. A 403 its `x-ratelimit-remaining` header alone calls a rate
/// limit is not told apart here, nor one of fewer than three retries at
/// most (MAX).
fn retry_failure(err: &anyhow::Error, operation: &str, retries: u32, max: u32) -> String {
    let original = format!("{err:#}");
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let rate_limit = max >= 3
        && (err
            .downcast_ref::<Refused>()
            .is_some_and(|refused| refused.status == 429)
            || RATE_LIMIT_MESSAGES
                .iter()
                .any(|pattern| original.to_lowercase().contains(pattern)));
    let (code, failed, retryable, suggestion) = if !is_transient(err) {
        (
            "ERR_API",
            format!("(attempt {})", retries + 1),
            false,
            "This error cannot be resolved by retrying. Please check the error details and fix \
             the underlying issue.",
        )
    } else if rate_limit {
        (
            "E010 RATE_LIMIT_EXCEEDED",
            format!("after {retries} retry attempts"),
            true,
            "RATE_LIMIT_EXCEEDED: GitHub API rate limit persisted after 3 retries.",
        )
    } else {
        (
            "ERR_API",
            format!("after {retries} retry attempts"),
            true,
            "All retry attempts exhausted. This may be a persistent issue. Check GitHub status or \
             try again later.",
        )
    };
    format!(
        "{code}: [{timestamp}] {operation} failed {failed}\n\nOriginal error: {original}\n\
         Retryable: {retryable}\nSuggestion: {suggestion}"
    )
}

impl Refused {
    /// The refusal TEXT says, which a forge's JSON error words with
    /// `message`, any `errors` and a `documentation_url`.
    fn of(status: u16, text: &str) -> Self {
        let errors = serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|data| data.get("errors").and_then(Value::as_array).cloned())
            .unwrap_or_default();
        let message = match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(data)) => match data.get("message") {
                Some(message) => {
                    let message = message
                        .as_str()
                        .map_or_else(|| message.to_string(), str::to_owned);
                    let errors = data.get("errors").and_then(Value::as_array).map(|errors| {
                        let errors: Vec<String> = errors.iter().map(Value::to_string).collect();
                        format!(": {}", errors.join(", "))
                    });
                    let documentation = data
                        .get("documentation_url")
                        .map(|url| format!(" - {}", url.as_str().unwrap_or_default()));
                    format!(
                        "{message}{}{}",
                        errors.unwrap_or_default(),
                        documentation.unwrap_or_default()
                    )
                }
                None => format!("Unknown error: {}", Value::Object(data)),
            },
            _ => text.to_owned(),
        };
        Self {
            status,
            message,
            errors,
        }
    }
}

impl Github {
    /// API is GitHub's REST API, `https://api.github.com` or a server's;
    /// PROVENANCE names the caller to it and commits a push.
    pub fn new(api: &str, token: String, provenance: Provenance<'static>) -> Result<Self> {
        let api = api.trim_end_matches('/');
        ensure!(
            api.starts_with("https://") || is_loopback_http(api),
            "{API_URL_VAR} requires HTTPS"
        );
        let http = ureq::Agent::config_builder()
            .timeout_global(Some(super::forgejo::TIMEOUT))
            .proxy(None)
            // The token is not to follow a redirect anywhere.
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();
        Ok(Self {
            api: api.to_owned(),
            token,
            http,
            max_response: super::forgejo::MAX_RESPONSE,
            fork_wait: FORK_WAIT,
            retry_wait: RETRY_WAIT,
            api_version: None,
            provenance,
            warn: |_| {},
            roles: None,
            role: Role::Publication,
        })
    }

    /// The API's address.
    pub fn api_url(&self) -> &str {
        &self.api
    }

    /// Asks for VERSION of the API, as `X-GitHub-Api-Version`.
    pub fn with_api_version(mut self, version: &'static str) -> Self {
        self.api_version = Some(version);
        self
    }

    /// Gives WARN the warning before each retry, which holds the forge's
    /// words: WARN shows it as the caller's log shows untrusted text.
    pub fn warning_with(mut self, warn: fn(&str)) -> Self {
        self.warn = warn;
        self
    }

    /// Gives each role its own credential, in place of the one token; the
    /// caller reads them ([`super::roles::read`]).
    pub fn with_roles(mut self, bindings: std::collections::BTreeMap<Role, Credential>) -> Self {
        self.roles = Some(bindings);
        self
    }

    pub fn for_role(&self, role: Role) -> Result<Self> {
        let mut client = self.clone();
        if let Some(bindings) = &self.roles {
            let credential = bindings.get(&role).context("caller role is not bound")?;
            ensure!(
                !credential.token.is_empty(),
                "{} is missing for configured role",
                role.token_env()
            );
            client.token.clone_from(&credential.token);
            client.role = role;
        }
        Ok(client)
    }

    pub fn check_identity(&self) -> Result<()> {
        let expected = &self.roles.as_ref().context("no role bindings")?[&self.role].identity;
        // Installation tokens need not implement GET /user. GraphQL's viewer
        // is a User even for an installation: its typename cannot prove Bot
        // identity. If viewer is unavailable, fail closed.
        let viewer = self.graphql(
            "query { viewer { databaseId __typename login } }",
            json!({}),
        )?;
        ensure!(
            viewer["viewer"]["databaseId"].as_u64() == Some(expected.actor_id),
            "{} has the wrong authenticated actor identity",
            self.role.token_env()
        );
        if let Some(app_id) = expected.app_id {
            let login = viewer["viewer"]["login"]
                .as_str()
                .context("authenticated viewer has no login")?;
            let slug = login.strip_suffix("[bot]").context(
                "configured App roles require an installation bot; user App tokens are not supported",
            )?;
            ensure!(
                !slug.is_empty() && slug.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "authenticated Bot has no App slug"
            );
            let actor = self.get(&format!("/users/{}", query(login)))?;
            ensure!(
                actor["id"].as_u64() == Some(expected.actor_id) && actor["type"] == "Bot",
                "{} has the wrong App bot identity",
                self.role.token_env()
            );
            let app = self.get(&format!("/apps/{slug}"))?;
            ensure!(
                app["id"].as_u64() == Some(app_id),
                "{} has the wrong App identity",
                self.role.token_env()
            );
        }
        Ok(())
    }

    pub fn configured(&self) -> bool {
        self.roles.is_some()
    }

    pub fn owns(&self, role: Role, object: &Value, legacy: Option<&str>) -> bool {
        match &self.roles {
            Some(bindings) => bindings[&role].identity.owns(object),
            None => legacy.is_some_and(|login| object["user"]["login"] == login),
        }
    }

    /// Takes answers of up to MAX bytes.
    pub fn with_max_response(mut self, max: u64) -> Self {
        self.max_response = max;
        self
    }

    /// Sends METHOD with BODY to PATH under the API, and returns the
    /// answer's status and text.
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, String)> {
        self.call_linked(method, path, body)
            .map(|(status, text, _)| (status, text))
    }

    /// [`Self::call`], with the answer's `link` header.
    fn call_linked(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, String, Option<String>)> {
        // A server's GraphQL API is beside its REST API at `/api/v3`, as
        // octokit's `graphql` finds it.
        let url = match (path, self.api.strip_suffix("/api/v3")) {
            (GRAPHQL, Some(server)) => format!("{server}/api{GRAPHQL}"),
            _ => format!("{}{path}", self.api),
        };
        let authorization = format!("Bearer {}", self.token);
        let version = self.api_version.unwrap_or_default();
        let request = |builder: ureq::RequestBuilder<ureq::typestate::WithBody>| {
            let builder = if version.is_empty() {
                builder
            } else {
                builder.header("x-github-api-version", version)
            };
            builder
                .header("authorization", &authorization)
                .header("accept", "application/vnd.github+json")
                .header("user-agent", self.provenance.name)
                .header("content-type", "application/json")
                .send(body.map(Value::to_string).unwrap_or_default().as_bytes())
        };
        let response = match method {
            "GET" => {
                let builder = self.http.get(&url);
                let builder = if version.is_empty() {
                    builder
                } else {
                    builder.header("x-github-api-version", version)
                };
                builder
                    .header("authorization", &authorization)
                    .header("accept", "application/vnd.github+json")
                    .header("user-agent", self.provenance.name)
                    .call()
            }
            "POST" => request(self.http.post(&url)),
            "PUT" => request(self.http.put(&url)),
            "PATCH" => request(self.http.patch(&url)),
            "DELETE" => {
                let builder = self.http.delete(&url);
                let builder = if version.is_empty() {
                    builder
                } else {
                    builder.header("x-github-api-version", version)
                };
                builder
                    .header("authorization", &authorization)
                    .header("accept", "application/vnd.github+json")
                    .header("user-agent", self.provenance.name)
                    .call()
            }
            _ => bail!("{method} is not a method this sends"),
        };
        let mut response = response.map_err(|err| {
            Unanswered(format!("{method} {path}: {}", self.shown(&err.to_string())))
        })?;
        let status = response.status().as_u16();
        let link = response
            .headers()
            .get("link")
            .and_then(|link| link.to_str().ok())
            .map(str::to_owned);
        match response
            .body_mut()
            .with_config()
            .limit(self.max_response)
            .read_to_string()
        {
            Ok(text) => Ok((status, self.scrub(&text), link)),
            Err(err) => bail!("{method} {path}: {}", self.shown(&err.to_string())),
        }
    }

    /// Sends METHOD with BODY to PATH under the API, and returns the JSON
    /// of a successful answer (null for none).
    pub fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let (status, text) = self.call(method, path, body)?;
        ensure!(
            (200..300).contains(&status),
            "{method} {path}: HTTP {status}: {}",
            self.shown(&text)
        );
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text)
            .with_context(|| format!("{method} {path}: the response is not JSON"))
    }

    /// Sends METHOD with BODY to PATH under the API, and returns the JSON
    /// of a successful answer (null for none); a refusal is [`Refused`].
    pub fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let (status, text) = self.call(method, path, body)?;
        if !(200..300).contains(&status) {
            let refused = Refused::of(status, &text);
            return Err(refused.into());
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text)
            .with_context(|| format!("{method} {path}: the response is not JSON"))
    }

    /// [`Self::request`], tried again after a transient failure as gh-aw's
    /// handlers try OPERATION (opening a pull request, adding labels)
    /// again; a failure is worded as its `withRetry` words one.
    pub fn request_retrying(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        operation: &str,
    ) -> Result<Value> {
        self.request_retrying_up_to(method, path, body, operation, PULL_REQUEST_RETRIES)
    }

    /// [`Self::request_retrying`], at most MAX times again; a failure is
    /// [`Retried`].
    pub fn request_retrying_up_to(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        operation: &str,
        max: u32,
    ) -> Result<Value> {
        let mut wait = self.retry_wait;
        let mut retries = 0;
        loop {
            match self.request(method, path, body) {
                Err(err) if retries < max && is_transient(&err) => {
                    retries += 1;
                    (self.warn)(&format!(
                        "{method} {path} failed ({err:#}); retry {retries}/{max} in {}s",
                        wait.as_secs()
                    ));
                    std::thread::sleep(wait);
                    wait = (wait * 2).min(MAX_RETRY_WAIT);
                }
                Err(err) => {
                    let message = retry_failure(&err, operation, retries, max);
                    return Err(Retried {
                        message,
                        refused: err.downcast::<Refused>().ok(),
                    }
                    .into());
                }
                answer => return answer,
            }
        }
    }

    /// Sends QUERY with VARIABLES to the GraphQL API, as octokit's
    /// `graphql` does, and returns the answer's `data`; one with `errors`
    /// is an error.
    pub fn graphql(&self, query: &str, variables: Value) -> Result<Value> {
        let answer = self.request(
            "POST",
            GRAPHQL,
            Some(&json!({"query": query, "variables": variables})),
        )?;
        if let Some(errors) = answer["errors"]
            .as_array()
            .filter(|errors| !errors.is_empty())
        {
            let messages: Vec<&str> = errors
                .iter()
                .filter_map(|error| error["message"].as_str())
                .collect();
            bail!(
                "Request failed due to following response errors:\n - {}",
                self.shown(&messages.join("\n - "))
            );
        }
        Ok(answer["data"].clone())
    }

    /// GETs PATH, and returns the JSON of a successful answer.
    pub fn get(&self, path: &str) -> Result<Value> {
        self.send("GET", path, None)
    }

    /// GETs PATH, or None where the forge answers that there is nothing
    /// there (404). Any other failure is an error.
    pub fn get_optional(&self, path: &str) -> Result<Option<Value>> {
        let (status, text) = self.call("GET", path, None)?;
        if status == 404 {
            return Ok(None);
        }
        ensure!(
            (200..300).contains(&status),
            "GET {path}: HTTP {status}: {}",
            self.shown(&text)
        );
        serde_json::from_str(&text)
            .map(Some)
            .with_context(|| format!("GET {path}: the response is not JSON"))
    }

    pub fn shown(&self, text: &str) -> String {
        self.scrub(text).chars().take(git::SHOWN_CHARS).collect()
    }

    fn secrets(&self) -> Vec<String> {
        let mut secrets = vec![self.token.clone()];
        if let Some(bindings) = &self.roles {
            secrets.extend(bindings.values().map(|credential| credential.token.clone()));
        }
        let encoded: Vec<_> = secrets
            .iter()
            .flat_map(|token| {
                [
                    BASE64.encode(token),
                    BASE64.encode(format!("x-access-token:{token}")),
                ]
            })
            .collect();
        secrets.extend(encoded);
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets
    }

    fn scrub(&self, text: &str) -> String {
        self.secrets()
            .iter()
            .filter(|secret| !secret.is_empty())
            .fold(text.to_owned(), |text, secret| {
                text.replace(secret, "[token]")
            })
    }

    /// Git with the token, as GitHub's git takes it.
    pub fn git(&self) -> Git<'_> {
        let basic = BASE64.encode(format!("x-access-token:{}", self.token));
        Git {
            authorization: format!("Basic {basic}"),
            token: &self.token,
            extra_secrets: self.secrets(),
            committer: self.provenance.committer,
        }
    }

    /// Every entry of the list at PATH, 100 a page, as octokit's
    /// `paginate` reads it: the next page is the one the answer's `link`
    /// header names, which has to be under the API, up to [`MAX_PAGES`].
    fn pages(&self, path: &str) -> Result<Vec<Value>> {
        let separator = if path.contains('?') { '&' } else { '?' };
        let mut next = Some(format!("{path}{separator}per_page={PER_PAGE}"));
        let mut all = Vec::new();
        for _ in 0..MAX_PAGES {
            let Some(path) = next.take() else {
                return Ok(all);
            };
            let (status, text, link) = self.call_linked("GET", &path, None)?;
            ensure!(
                (200..300).contains(&status),
                "GET {path}: HTTP {status}: {}",
                self.shown(&text)
            );
            let answer: Value = serde_json::from_str(&text)
                .with_context(|| format!("GET {path}: the response is not JSON"))?;
            let entries = answer
                .as_array()
                .with_context(|| format!("GET {path}: the answer is not a list"))?;
            all.extend(entries.iter().cloned());
            if let Some(url) = link.as_deref().and_then(next_link) {
                let rest = url
                    .strip_prefix(&self.api)
                    .filter(|rest| rest.starts_with('/'))
                    .with_context(|| {
                        format!("GET {path}: the next page {url:?} is not the API's")
                    })?;
                next = Some(rest.to_owned());
            }
        }
        ensure!(next.is_none(), "GET {path}: more than {MAX_PAGES} pages");
        Ok(all)
    }

    /// The comments on issue or pull request NUMBER of REPO.
    pub fn issue_comments(&self, repo: &str, number: &str) -> Result<Vec<Value>> {
        self.pages(&format!("/repos/{repo}/issues/{number}/comments"))
    }

    /// The pull requests of REPO from HEAD (`owner:branch`), in any state.
    pub fn pulls(&self, repo: &str, head: &str) -> Result<Vec<Value>> {
        self.pages(&format!(
            "/repos/{repo}/pulls?head={}&state=all",
            query(head)
        ))
    }

    /// The first page of 100 issues and pull requests QUERY finds; an
    /// answer without its list is an error, not an empty one.
    pub fn search_issues(&self, query_text: &str) -> Result<Vec<Value>> {
        let path = format!("/search/issues?q={}&per_page={PER_PAGE}", query(query_text));
        self.get(&path)?["items"]
            .as_array()
            .cloned()
            .with_context(|| format!("GET {path}: the answer holds no items"))
    }

    /// The user the token is of, as `GET /user` names it: the identity
    /// whose fork apply pushes to. The job token names nobody.
    pub fn login(&self) -> Result<String> {
        self.send("GET", "/user", None)?["login"]
            .as_str()
            .filter(|login| !login.is_empty())
            .map(str::to_owned)
            .context("GET /user names nobody: SAFE_OUTPUTS_PAT must be a user's token")
    }

    /// ME's own fork of REPO, made or found, with Actions off, that git
    /// reaches at its name under SERVER. Its CI is what a push with a
    /// user's token would start, with the fork's secrets: nothing is
    /// pushed unless the forge says Actions are off there. The repository
    /// itself, or another of its owner's, is never pushed to: there its
    /// CI would run the agent's code with the repository's secrets. Nor
    /// is OWN_REPO, the run's own, should it be ME's fork of REPO: its
    /// Actions are its own CI.
    pub fn fork(&self, me: &str, repo: &str, own_repo: &str, server: &str) -> Result<String> {
        ensure!(
            !me.eq_ignore_ascii_case(owner(repo)),
            "{me} owns {repo} and has no fork of it to push to"
        );
        let fork = self.send(
            "POST",
            &format!("/repos/{repo}/forks"),
            Some(&json!({"default_branch_only": true})),
        )?;
        let name = fork["full_name"].as_str().unwrap_or_default().to_owned();
        ensure!(
            fork["fork"] == Value::Bool(true)
                && same(&fork["owner"]["login"], me)
                && owner(&name).eq_ignore_ascii_case(me)
                && (same(&fork["parent"]["full_name"], repo) || {
                    // GitHub keeps one fork per account per network. An existing
                    // fork can have a different parent when REPO is itself a fork.
                    let target = self.get(&format!("/repos/{repo}"))?;
                    let source = if target["fork"] == Value::Bool(true) {
                        target["source"]["full_name"].as_str()
                    } else {
                        Some(repo)
                    };
                    source.is_some_and(|source| {
                        !source.is_empty() && same(&fork["source"]["full_name"], source)
                    })
                }),
            "the forge answered a fork of {repo} for {me} with {name:?}, which is not {me}'s own fork of it"
        );
        ensure!(
            !name.eq_ignore_ascii_case(own_repo),
            "{me}'s fork of {repo} is {own_repo}, the run's own repository, which this does not \
             push to"
        );
        let remote = format!("{server}/{name}.git");
        let dir = tempfile::tempdir().context("making a directory for git")?;
        let git = self.git();
        for attempt in 1.. {
            let heads = git.run(dir.path(), &["ls-remote", "--heads", &remote], None);
            if heads.is_ok_and(|heads| heads.contains("\trefs/heads/")) {
                break;
            }
            ensure!(
                attempt < FORK_TRIES,
                "the fork {name} is still not there after {attempt} tries"
            );
            std::thread::sleep(self.fork_wait);
        }
        let permissions = format!("/repos/{name}/actions/permissions");
        let enabled = self
            .send("PUT", &permissions, Some(&json!({"enabled": false})))
            .and_then(|_| self.send("GET", &permissions, None))
            .map(|answer| answer["enabled"].as_bool());
        if !matches!(enabled, Ok(Some(false))) {
            bail!(
                "Actions could not be turned off on the fork {name}, which a push with {me}'s \
                 token would run workflows in: turn them off there, and give SAFE_OUTPUTS_PAT \
                 the repo scope (or a fine-grained token Administration: write on the fork)"
            );
        }
        Ok(name)
    }
}

/// Who commits a pull request's patch: the job's git identity, as
/// apply.yml's `Configure git` gives it to gh-aw's handler.
pub const ACTIONS_COMMITTER: (&str, &str) = (
    "github-actions[bot]",
    "41898282+github-actions[bot]@users.noreply.github.com",
);

/// [`Publisher`] for GitHub, writing what gh-aw's handlers write: a
/// comment on the run's item, and a pull request in the output repository
/// from its branch, pushed to the head repository apply.yml's fork step
/// chose (the token's fork with Actions off, or the repository itself
/// only where it says so). Nothing here chooses where a branch goes.
///
/// Callers make one with [`super::publish::publisher`], which refuses a
/// git server that is not https.
pub struct GithubPublisher {
    pub(super) github: Github,
    /// Where git finds `OWNER/NAME.git`.
    pub(super) git: String,
    /// The repository comments go to: the run's item's.
    pub(super) item_repo: String,
    /// The repository a pull request is opened in: the output repository.
    pub(super) repo: String,
}

/// What GitHub leaves to gh-aw's handlers: refused before any write.
const GH_AW_PUBLISHES: &str =
    "on GitHub only comments and pull requests are published here; the rest is gh-aw's";

impl Publisher for GithubPublisher {
    fn preflight(&self, op: &Op) -> Result<()> {
        ensure!(
            matches!(op, Op::Comment { .. } | Op::PullRequest(_)),
            GH_AW_PUBLISHES
        );
        Ok(())
    }

    fn comment(&self, issue: u64, body: &str) -> Result<Made> {
        let path = format!("/repos/{}/issues/{issue}/comments", self.item_repo);
        let answer = self
            .github
            .request("POST", &path, Some(&json!({"body": body})))?;
        Made::from_answer(&answer, "POST", &path)
    }

    fn open_pull_request(&self, pr: &PullRequest) -> Result<Made> {
        // The handler names a branch of the repository itself without its
        // owner, and leaves out `head_repo`.
        let own = pr.push_repo.eq_ignore_ascii_case(&self.repo);
        self.github
            .for_role(Role::ForkPush)?
            .git()
            .push(
                &Push {
                    from: &format!("{}/{}.git", self.git, self.repo),
                    base: &pr.base,
                    base_commit: &pr.base_commit,
                    to: &format!("{}/{}.git", self.git, pr.push_repo),
                    branch: &pr.branch,
                    patch: &pr.patch,
                    files: &pr.files,
                    head: None,
                    committer: Some(ACTIONS_COMMITTER),
                    at_author_date: false,
                    max_changed_kb: None,
                },
                None,
            )
            .context("Failed to push changes")?;
        let mut body = json!({"title": pr.title, "body": pr.body});
        if own {
            body["head"] = json!(pr.branch);
        } else {
            body["head"] = json!(format!("{}:{}", owner(&pr.push_repo), pr.branch));
            body["head_repo"] = json!(pr.push_repo);
        }
        body["base"] = json!(pr.base);
        body["draft"] = json!(pr.draft);
        let path = format!("/repos/{}/pulls", self.repo);
        let operation = format!("create pull request in {}", self.repo);
        let answer = self
            .github
            .request_retrying("POST", &path, Some(&body), &operation)?;
        Made::from_answer(&answer, "POST", &path)
    }

    fn create_issue(&self, _: &NewIssue) -> Result<String> {
        bail!(GH_AW_PUBLISHES)
    }

    fn push_to_branch(&self, _: &BranchPush) -> Result<String> {
        bail!(GH_AW_PUBLISHES)
    }

    fn status(&self, _: &CommitStatus) -> Result<String> {
        bail!(GH_AW_PUBLISHES)
    }

    fn change_labels(&self, _: &LabelChange) -> Result<String> {
        bail!(GH_AW_PUBLISHES)
    }

    fn close(&self, _: &Close) -> Result<String> {
        bail!(GH_AW_PUBLISHES)
    }
}

/// A plain HTTP address on a literal loopback address: the tests' forge.
fn is_loopback_http(api: &str) -> bool {
    api.strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .and_then(|authority| authority.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|address| address.ip().is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::testing::{PROVENANCE, TOKEN, bound, forge};

    #[test]
    fn role_credentials_fail_closed_and_check_numeric_identity() {
        for (id, login, rest_id, kind, app, expected_app, accepted) in [
            (7, "trusted", 7, "User", None, None, true),
            (8, "trusted", 8, "User", None, None, false),
            (7, "trusted[bot]", 7, "Bot", Some(42), Some(42), true),
            (7, "trusted[bot]", 7, "Bot", Some(43), Some(42), false),
            (7, "trusted[bot]", 7, "User", Some(42), Some(42), false),
            (7, "trusted[bot]", 8, "Bot", Some(42), Some(42), false),
            (7, "trusted", 7, "User", Some(42), Some(42), false),
        ] {
            let routes = [
                (
                    "POST /graphql".to_owned(),
                    (
                        200,
                        json!({"data": {"viewer": {
                    "databaseId": id, "__typename": "User", "login": login}}}),
                    ),
                ),
                ("GET /apps/trusted".to_owned(), (200, json!({"id": app}))),
                (
                    "GET /users/trusted%5Bbot%5D".to_owned(),
                    (200, json!({"id": rest_id, "type": kind})),
                ),
            ];
            let (github, requests) = forge(routes.into_iter().collect());
            let mut github = bound(github);
            github
                .roles
                .as_mut()
                .unwrap()
                .get_mut(&Role::Publication)
                .unwrap()
                .identity
                .app_id = expected_app;
            assert_eq!(
                github.check_identity().is_ok(),
                accepted,
                "{id}/{kind}/{app:?}/{expected_app:?}"
            );
            assert!(
                requests
                    .try_iter()
                    .all(|r| r.line.starts_with("GET ") || r.line.starts_with("POST /graphql "))
            );
        }
        let mut github = bound(
            Github::new(
                "http://127.0.0.1:1",
                ["legacy", "stronger"].join("-"),
                PROVENANCE,
            )
            .unwrap(),
        );
        for role in Role::ALL {
            assert!(
                github
                    .for_role(role)
                    .unwrap()
                    .token
                    .contains(role.token_env())
            );
            github
                .roles
                .as_mut()
                .unwrap()
                .get_mut(&role)
                .unwrap()
                .token
                .clear();
            assert!(github.for_role(role).is_err());
        }
    }

    #[test]
    fn every_role_secret_and_encoded_credential_is_scrubbed() {
        let github = bound(Github::new("http://127.0.0.1:1", String::new(), PROVENANCE).unwrap());
        for credential in github.roles.as_ref().unwrap().values() {
            for secret in [
                credential.token.clone(),
                BASE64.encode(&credential.token),
                BASE64.encode(format!("x-access-token:{}", credential.token)),
            ] {
                assert_eq!(
                    github.scrub(&format!("before {secret} after")),
                    "before [token] after"
                );
                assert_eq!(git::shown(&github.git().secrets(), &secret), "[token]");
            }
        }
    }

    #[test]
    fn names() {
        for (name, repo) in [
            ("o/r", true),
            ("O-1/r.x_y", true),
            ("o", false),
            ("o/r/x", false),
            ("/r", false),
            ("o/..", false),
            ("o/r?x", false),
            ("o/r\n", false),
        ] {
            assert_eq!(is_repo(name), repo, "{name:?}");
        }
        assert_eq!(segment("fix/a b#%?"), "fix/a%20b%23%25%3F");
    }

    /// A list is read on as its `link` header says, only under the API and
    /// only so far.
    #[test]
    fn pages_follow_the_link_header() {
        use std::sync::{Arc, Mutex};

        use crate::apply::testing::serve_with_headers;

        for (next, want) in [
            ("{API}/l?per_page=100&page=2", Ok(vec![1, 2])),
            (
                "https://elsewhere.example/l?page=2",
                Err("is not the API's"),
            ),
            ("{API}/l?per_page=100", Err("more than 100 pages")),
        ] {
            let api = Arc::new(Mutex::new(String::new()));
            let at = api.clone();
            let (server, requests) = serve_with_headers(usize::MAX, move |request| {
                let next = next.replace("{API}", &at.lock().unwrap());
                let link = format!("link: <{next}>; rel=\"next\", <{next}>; rel=\"last\"\r\n");
                match request.line.split(' ').nth(1).unwrap() {
                    "/l?per_page=100" => (200, link, "[1]".into()),
                    _ => (200, String::new(), "[2]".into()),
                }
            });
            *api.lock().unwrap() = server.clone();
            let github = Github::new(&server, TOKEN.to_owned(), PROVENANCE).unwrap();
            let got = github
                .pages("/l")
                .map(|all| all.iter().map(|n| n.as_u64().unwrap()).collect::<Vec<_>>());
            match want {
                Ok(want) => assert_eq!(got.unwrap(), want),
                Err(want) => {
                    let err = format!("{:#}", got.unwrap_err());
                    assert!(err.contains(want), "{next}: {err}");
                }
            }
            assert!(
                requests.try_iter().all(|r| r.line.starts_with("GET /l?")),
                "{next}"
            );
        }
        assert_eq!(next_link(r#"<a>; rel="prev", <b>; rel="next""#), Some("b"));
        assert_eq!(next_link(r#"<a>; rel="last""#), None);
    }

    /// What gh-aw's handler retries is tried again, at most
    /// [`PULL_REQUEST_RETRIES`] times; anything else is not.
    #[test]
    fn retries() {
        for (status, message, tries) in [
            (502, "injected failure", 1 + PULL_REQUEST_RETRIES),
            (429, "slow down", 1 + PULL_REQUEST_RETRIES),
            (
                403,
                "You have exceeded a secondary rate limit",
                1 + PULL_REQUEST_RETRIES,
            ),
            (422, "A pull request already exists", 1),
            (404, "Not Found", 1),
        ] {
            let routes = [("POST /x".to_owned(), (status, json!({"message": message})))];
            let (github, requests) = forge(routes.into_iter().collect());
            let err = github
                .request_retrying("POST", "/x", None, "create pull request in o/r")
                .unwrap_err()
                .to_string();
            let (code, failed, retryable) = match tries {
                1 => ("ERR_API", "(attempt 1)", false),
                _ if status == 502 => ("ERR_API", "after 5 retry attempts", true),
                _ => ("E010 RATE_LIMIT_EXCEEDED", "after 5 retry attempts", true),
            };
            assert!(err.starts_with(&format!("{code}: [")), "{err}");
            assert!(
                err.contains(&format!(
                    "] create pull request in o/r failed {failed}\n\nOriginal error: {message}\n\
                     Retryable: {retryable}\nSuggestion: "
                )),
                "{err}"
            );
            assert_eq!(requests.try_iter().count(), tries as usize, "{status}");
        }
        let github = Github::new("http://127.0.0.1:1", TOKEN.to_owned(), PROVENANCE).unwrap();
        assert!(is_transient(&github.call("GET", "/", None).unwrap_err()));
    }
}
