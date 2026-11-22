//! Launch one Testing Farm request for a run and fetch its hand-back, the
//! [later layer](../../../specs/gitlab-caller.md#testing-farm-as-a-later-layer)
//! of the GitLab caller. The API token authenticates the launcher's calls
//! only: it is never part of the request, so the guest cannot read it.
//! The hand-back is untrusted data held to `external`'s archive bounds;
//! the caller's own check reads it. While a request may be live its ID is
//! kept in a file, so that a cleanup step can cancel it after the job is
//! stopped. Nothing here ran against a live Testing Farm.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::exit::Exit;
use crate::external::{MAX_ARCHIVE, members};
use crate::policy::COMMIT_RE;

const MAX_REQUEST: u64 = 64 << 10;
const MAX_RESPONSE: u64 = 1 << 20;
/// A UUID and a newline, with room to spare.
const MAX_ID_FILE: u64 = 64;
/// The external correlation's lifetime bound, which the fetching caller holds
/// its producer pipeline to.
const MAX_MINUTES: u64 = 330;
const MAX_VARIABLES: usize = 64;
const MAX_TEXT: usize = 256;
const MAX_VALUE: usize = 4096;
const POLL: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// A passed request's hand-back is fetched after the deadline if need be:
/// up to 128 MiB, and nothing is left running to cancel.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);
const TOKEN_ENV: &str = "TESTING_FARM_API_TOKEN";
/// The prefix of the variables Testing Farm's reserve test reads. A reserved
/// guest keeps the agent's workspace reachable over SSH after the job.
const RESERVATION: &str = "TF_RESERVATION";

#[cfg(test)]
mod tests;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Caller-owned request settings, never taken from the guest
    #[arg(long)]
    pub request: PathBuf,
    /// Empty output directory for the validated hand-back files
    #[arg(long)]
    pub output: PathBuf,
    /// New file in trusted job-private state, for `testing-farm-cancel`
    #[arg(long)]
    pub id: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct CancelArgs {
    /// The same caller-owned request settings the launcher read
    #[arg(long)]
    pub request: PathBuf,
    /// The launcher's trusted job-private ID file; nothing is sent if absent
    #[arg(long)]
    pub id: PathBuf,
}

/// What the caller asks Testing Farm to run. There is no field for secrets,
/// reservation, tmt arguments or a webhook: the request carries only these.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The HTTPS root of Testing Farm's API, the token's only destination.
    /// Caller-owned, not an environment variable a pipeline could override.
    pub api: String,
    /// The plan repository's HTTPS URL
    pub url: String,
    /// The plan repository's full commit
    #[serde(rename = "ref")]
    pub reference: String,
    /// The tmt plan's name, as `/plans/NAME`
    pub plan: String,
    pub compose: String,
    pub arch: String,
    /// Minutes, both the request's pipeline timeout and the launcher's
    /// own deadline, after which it cancels the request
    pub timeout: u64,
    /// Plain variables for the guest; it can read every one
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    /// The HTTPS root of Testing Farm's artifact storage
    pub artifacts: String,
    /// The hand-back ZIP's path under the request's artifacts
    pub handback: String,
}

impl Request {
    pub fn load(path: &Path) -> Result<Self> {
        let request: Self =
            serde_json::from_slice(&crate::files::read_regular(path, MAX_REQUEST)?)?;
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<()> {
        for url in [&self.api, &self.url, &self.artifacts] {
            ensure!(
                url.starts_with("https://")
                    && url.len() <= MAX_TEXT
                    && !url.ends_with('/')
                    && !url.chars().any(|c| c.is_whitespace() || c.is_control()),
                "Testing Farm URLs must be HTTPS without a trailing slash: {url:?}"
            );
        }
        ensure!(
            COMMIT_RE.is_match(&self.reference),
            "Testing Farm plan ref must be a full lowercase commit"
        );
        ensure!(
            self.plan.starts_with('/') && name(&self.plan, b"/._-"),
            "invalid tmt plan name {:?}",
            self.plan
        );
        for text in [&self.compose, &self.arch] {
            ensure!(
                name(text, b"._-"),
                "invalid Testing Farm compose or arch {text:?}"
            );
        }
        ensure!(
            (1..=MAX_MINUTES).contains(&self.timeout),
            "Testing Farm timeout must be 1 to {MAX_MINUTES} minutes"
        );
        ensure!(
            self.variables.len() <= MAX_VARIABLES,
            "more than {MAX_VARIABLES} Testing Farm variables"
        );
        for (key, value) in &self.variables {
            ensure!(
                name(key, b"_")
                    && !key.starts_with(|c: char| c.is_ascii_digit())
                    && value.len() <= MAX_VALUE
                    && !value.contains('\0'),
                "invalid Testing Farm variable {key:?}"
            );
            ensure!(
                !key.to_ascii_uppercase().starts_with(RESERVATION),
                "Testing Farm reservation is refused: {key}"
            );
        }
        ensure!(
            name(&self.handback, b"/._-")
                && self
                    .handback
                    .split('/')
                    .all(|part| !matches!(part, "" | "." | "..")),
            "invalid hand-back path {:?}",
            self.handback
        );
        Ok(())
    }

    /// The request body: exactly the caller's fields, nothing from the
    /// launcher's environment.
    fn body(&self) -> Value {
        json!({
            "test": {"fmf": {"url": self.url, "ref": self.reference, "name": self.plan_pattern()}},
            "environments": [{
                "arch": self.arch,
                "os": {"compose": self.compose},
                "variables": self.variables,
            }],
            "settings": {"pipeline": {"timeout": self.timeout}},
        })
    }

    /// tmt searches plan names with `test.fmf.name` as a regular expression,
    /// so the literal name is escaped and anchored: `/plans/agent` must not
    /// also select `/plans/agent-reserve`.
    fn plan_pattern(&self) -> String {
        format!("^{}$", regex::escape(&self.plan))
    }
}

/// TEXT is non-empty, bounded, and ASCII alphanumeric or one of EXTRA.
fn name(text: &str, extra: &[u8]) -> bool {
    !text.is_empty()
        && text.len() <= MAX_TEXT
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// Testing Farm's request IDs are UUIDs; anything else could change the
/// path it is put into.
fn is_request_id(id: &str) -> bool {
    id.split('-').map(str::len).eq([8, 4, 4, 4, 12])
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
}

/// The Testing Farm API and artifact storage, and a monotonic clock: also
/// offline fixtures.
trait Farm {
    fn now(&self) -> Instant;
    fn submit(&mut self, body: &Value) -> Result<Value>;
    fn status(&mut self, id: &str) -> Result<Value>;
    fn cancel(&mut self, id: &str) -> Result<()>;
    fn download(&mut self, url: &str) -> Result<Vec<u8>>;
    fn wait(&mut self, until: Instant);
}

/// Submit REQUEST, wait for it until DEADLINE and return the validated
/// hand-back files. ID_FILE holds the ID from when it is known until Testing Farm
/// reports the request ended or this cancelled it. A request that is still
/// live when this refuses is cancelled.
fn launch(
    farm: &mut impl Farm,
    request: &Request,
    token: &str,
    deadline: Instant,
    id_file: &Path,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let body = request.body();
    ensure!(
        !token.is_empty() && !body.to_string().contains(token),
        "the Testing Farm token must not be part of the request"
    );
    let response = farm.submit(&body)?;
    let id = response["id"]
        .as_str()
        .filter(|id| is_request_id(id))
        .context("Testing Farm returned no request ID")?
        .to_owned();
    let recorded = write_new(id_file, format!("{id}\n").as_bytes());
    // Recorded first and best-effort: a closed stdout must not stop cleanup.
    let _ = writeln!(std::io::stdout(), "Testing Farm request {id}");
    let mut terminal = false;
    let written = recorded.is_ok();
    let error = match recorded.and_then(|()| finish(farm, request, &id, deadline, &mut terminal)) {
        Ok(files) => {
            forget(id_file);
            return Ok(files);
        }
        Err(error) if terminal => {
            forget(id_file);
            return Err(error);
        }
        Err(error) => error,
    };
    match farm.cancel(&id) {
        Ok(()) => {
            if written {
                forget(id_file);
            }
            Err(error.context(format!(
                "requested cancellation of Testing Farm request {id}"
            )))
        }
        Err(cancel) => Err(error.context(format!(
            "cancelling Testing Farm request {id} failed too: {cancel:#}"
        ))),
    }
}

/// The request ended or its cancellation was accepted, so a cleanup step
/// has nothing to cancel.
fn forget(id_file: &Path) {
    if let Err(error) = std::fs::remove_file(id_file) {
        eprintln!("warning: removing {}: {error}", id_file.display());
    }
}

/// Wait for request ID to pass, then download and bound its hand-back.
/// TERMINAL says whether Testing Farm reported that the request ended.
/// A live snapshot decides the deadline only if its read started at or
/// after it. A pre-deadline read may return a stale live state after it.
fn finish(
    farm: &mut impl Farm,
    request: &Request,
    id: &str,
    deadline: Instant,
    terminal: &mut bool,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let status = loop {
        let started = farm.now();
        let status = farm.status(id)?;
        ensure!(status["id"] == id, "Testing Farm returned another request");
        match status["state"].as_str() {
            Some("new" | "queued" | "running") => {
                ensure!(
                    started < deadline,
                    "Testing Farm request {id} did not finish within {} minutes",
                    request.timeout
                );
                farm.wait(deadline);
            }
            Some("complete") => {
                *terminal = true;
                let overall = status["result"]["overall"].as_str().unwrap_or("absent");
                ensure!(
                    overall == "passed",
                    "Testing Farm request {id} did not pass: {overall:.64}"
                );
                break status;
            }
            Some(state @ ("error" | "canceled")) => {
                *terminal = true;
                bail!("Testing Farm request {id} ended {state}");
            }
            // Not ended yet: the launcher's own DELETE follows, and the ID
            // stays recorded unless that is accepted.
            Some("cancel-requested") => bail!("Testing Farm request {id} is being cancelled"),
            state => bail!("unknown Testing Farm request state {state:.64?}"),
        }
    };
    // The response names the request's artifacts. They are fetched only
    // from the request's own directory in the caller's storage.
    let expected = format!("{}/{id}", request.artifacts);
    let reported = status["run"]["artifacts"].as_str().unwrap_or("nothing");
    ensure!(
        reported.strip_suffix('/').unwrap_or(reported) == expected,
        "Testing Farm reported artifacts at {reported:.256}, not {expected}"
    );
    let bytes = farm.download(&format!("{expected}/{}", request.handback))?;
    ensure!(
        bytes.len() as u64 <= MAX_ARCHIVE,
        "Testing Farm hand-back exceeds {MAX_ARCHIVE} bytes"
    );
    members(&bytes).context("Testing Farm hand-back")
}

struct Api {
    root: String,
    token: String,
    deadline: Instant,
    roots: ureq::tls::RootCerts,
    proxy: Option<ureq::Proxy>,
}

impl Api {
    /// ureq's own TLS roots and proxy settings; only tests substitute theirs.
    fn new(request: &Request, token: String, deadline: Instant) -> Self {
        Self {
            root: request.api.clone(),
            token,
            deadline,
            roots: ureq::tls::RootCerts::WebPki,
            proxy: ureq::Proxy::try_from_env(),
        }
    }

    /// METHOD on URL, with the token only for an API call, never for
    /// artifact storage.
    fn call(&self, method: Method, url: &str, max: u64) -> Result<Vec<u8>> {
        // The status read that decides the deadline, and a cancel, must
        // still go out once it has passed.
        let timeout = match method {
            Method::Status | Method::Cancel => HTTP_TIMEOUT,
            Method::Download => DOWNLOAD_TIMEOUT,
            Method::Submit(_) => self
                .deadline
                .checked_duration_since(Instant::now())
                .context("Testing Farm deadline passed")?
                .min(HTTP_TIMEOUT),
        };
        let tls = ureq::tls::TlsConfig::builder().root_certs(self.roots.clone());
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(tls.build())
            .proxy(self.proxy.clone())
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();
        let authorization = format!("Bearer {}", self.token);
        let response = match method {
            Method::Submit(body) => agent
                .post(url)
                .header("Authorization", &authorization)
                .header("Content-Type", "application/json")
                .header("User-Agent", env!("CARGO_PKG_NAME"))
                .send(body.to_string().as_bytes()),
            Method::Status => agent
                .get(url)
                .header("Authorization", &authorization)
                .header("User-Agent", env!("CARGO_PKG_NAME"))
                .call(),
            Method::Cancel => agent
                .delete(url)
                .header("Authorization", &authorization)
                .header("User-Agent", env!("CARGO_PKG_NAME"))
                .call(),
            Method::Download => agent
                .get(url)
                .header("User-Agent", env!("CARGO_PKG_NAME"))
                .call(),
        };
        let what = format!("{} {url}", method.name());
        let mut response = response.with_context(|| what.clone())?;
        let status = response.status();
        let bytes = response
            .body_mut()
            .with_config()
            .limit(max)
            .read_to_vec()
            .with_context(|| what.clone())?;
        ensure!(
            status.is_success(),
            "{what} failed with HTTP {}",
            status.as_u16()
        );
        Ok(bytes)
    }

    fn json(&self, method: Method, path: &str) -> Result<Value> {
        let url = format!("{}{path}", self.root);
        let name = method.name();
        let bytes = self.call(method, &url, MAX_RESPONSE)?;
        serde_json::from_slice(&bytes).with_context(|| format!("{name} {url} is not JSON"))
    }
}

enum Method<'a> {
    Submit(&'a Value),
    Status,
    Cancel,
    Download,
}

impl Method<'_> {
    fn name(&self) -> &'static str {
        match self {
            Self::Submit(_) => "POST",
            Self::Status | Self::Download => "GET",
            Self::Cancel => "DELETE",
        }
    }
}

impl Farm for Api {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn submit(&mut self, body: &Value) -> Result<Value> {
        self.json(Method::Submit(body), "/v0.1/requests")
    }

    fn status(&mut self, id: &str) -> Result<Value> {
        self.json(Method::Status, &format!("/v0.1/requests/{id}"))
    }

    fn cancel(&mut self, id: &str) -> Result<()> {
        let url = format!("{}/v0.1/requests/{id}", self.root);
        self.call(Method::Cancel, &url, MAX_RESPONSE).map(drop)
    }

    fn download(&mut self, url: &str) -> Result<Vec<u8>> {
        // One byte more than allowed, so that an oversized hand-back is refused.
        self.call(Method::Download, url, MAX_ARCHIVE + 1)
    }

    fn wait(&mut self, until: Instant) {
        std::thread::sleep(POLL.min(until.saturating_duration_since(Instant::now())));
    }
}

fn token() -> Result<String> {
    std::env::var(TOKEN_ENV).with_context(|| format!("{TOKEN_ENV} is required"))
}

pub fn run(args: &Args) -> Result<Exit> {
    let request = Request::load(&args.request)?;
    let token = token()?;
    let deadline = Instant::now() + Duration::from_secs(request.timeout * 60);
    let mut api = Api::new(&request, token.clone(), deadline);
    run_with(args, &request, &mut api, &token, deadline)
}

/// Launch, then write only the validated flat members. GitLab archives the
/// output files itself. The job must upload artifacts only on script success.
fn run_with(
    args: &Args,
    request: &Request,
    farm: &mut impl Farm,
    token: &str,
    deadline: Instant,
) -> Result<Exit> {
    ensure!(
        !exists(&args.id)?,
        "{} must not exist yet",
        args.id.display()
    );
    let mut entries = std::fs::read_dir(&args.output)
        .with_context(|| format!("reading output directory {}", args.output.display()))?;
    ensure!(
        entries.next().transpose()?.is_none(),
        "output directory {} must be empty",
        args.output.display()
    );
    let files = launch(farm, request, token, deadline, &args.id)?;
    ensure!(!files.is_empty(), "Testing Farm hand-back is empty");
    for (name, bytes) in files {
        write_new(&args.output.join(name), &bytes)?;
    }
    Ok(Exit::Success)
}

/// Cancel the request in the launcher's ID file, for a cleanup step that
/// runs when the job is cancelled or times out. The file must come from
/// job-private state, not from checkout or restored files. If absent, there
/// is no known request to cancel.
pub fn cancel(args: &CancelArgs) -> Result<Exit> {
    let request = Request::load(&args.request)?;
    let mut api = Api::new(&request, token()?, Instant::now());
    cancel_with(&mut api, &args.id)
}

fn cancel_with(farm: &mut impl Farm, id_file: &Path) -> Result<Exit> {
    if !exists(id_file)? {
        println!("No Testing Farm request to cancel");
        return Ok(Exit::Success);
    }
    let bytes = crate::files::read_regular(id_file, MAX_ID_FILE)
        .with_context(|| format!("reading {}", id_file.display()))?;
    let id = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
        .filter(|id| is_request_id(id))
        .with_context(|| format!("{} holds no Testing Farm request ID", id_file.display()))?;
    farm.cancel(id)?;
    // Testing Farm accepted the cancellation; no guest destruction is observed.
    println!("Requested cancellation of Testing Farm request {id}");
    forget(id_file);
    Ok(Exit::Success)
}

fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("checking {}", path.display())),
    }
}

/// Publish BYTES at PATH, which must not exist, only after the write succeeds.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating a file beside {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.persist_noclobber(path)
        .with_context(|| format!("creating {} (must not exist)", path.display()))?;
    Ok(())
}
