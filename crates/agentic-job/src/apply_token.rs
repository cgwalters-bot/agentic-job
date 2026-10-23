//! `agentic-job check-apply-token`: with `require-safe-outputs-pat`, the
//! policy call asks the forge about SAFE_OUTPUTS_PAT before the agent
//! runs, so that a wrong secret costs a minute instead of a whole session:
//! apply would only refuse it after. Not a control, as apply checks the
//! token again. It runs in a job of its own that runs nothing from the
//! event and that the agent's machine never sees; it reads, and writes
//! nothing, and never prints the token or the forge's answer.

use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

use crate::exit::Exit;

const TOKEN_VAR: &str = "SAFE_OUTPUTS_PAT";
const API_URL_VAR: &str = "GITHUB_API_URL";
const DEFAULT_API: &str = "https://api.github.com";
const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RESPONSE: u64 = 1024 * 1024;

const FIX: &str = "store a classic PAT of a bot account that does not own the output repository, \
    with the repo scope, as SAFE_OUTPUTS_PAT (in the apply environment, if any), and pass it: \
    `secrets: SAFE_OUTPUTS_PAT: ${{ secrets.SAFE_OUTPUTS_PAT }}`";

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The repository apply writes to, OWNER/NAME
    #[arg(long, value_name = "REPO")]
    pub output_repo: String,
}

/// What the forge answered a GET: its status, its `x-oauth-scopes`
/// header, if any, and its JSON body (null when not JSON).
pub struct Answer {
    pub status: u16,
    pub scopes: Option<String>,
    pub body: Value,
}

pub fn run(args: &Args) -> Result<Exit> {
    // A secret the caller did not pass reads as empty in Actions, like an
    // unset one: the two cannot be told apart, nor need be.
    let token = std::env::var(TOKEN_VAR).unwrap_or_default();
    let http: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        // Never forward the token to a redirect target.
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let login = check(&args.output_repo, &token, &mut |path| {
        let api = std::env::var(API_URL_VAR).unwrap_or_else(|_| DEFAULT_API.into());
        ensure!(api.starts_with("https://"), "{API_URL_VAR} requires HTTPS");
        get(&http, &api, &token, path)
    })?;
    eprintln!("{TOKEN_VAR} is {}'s", crate::run::enter::one_line(&login));
    Ok(Exit::Success)
}

/// The login of `token`, refused unless it may apply to `repo`; `get`
/// reads an API path with it. Nothing is asked without a token.
pub fn check(
    repo: &str,
    token: &str,
    get: &mut dyn FnMut(&str) -> Result<Answer>,
) -> Result<String> {
    let parts: Vec<_> = repo.split('/').collect();
    ensure!(
        parts.len() == 2
            && parts.iter().all(|part| !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))),
        "the apply token check needs the output repository, OWNER/NAME"
    );
    ensure!(!token.is_empty(), "{TOKEN_VAR} is missing or empty: {FIX}");
    let user = get("user")?;
    ensure!(
        (200..300).contains(&user.status),
        "{TOKEN_VAR} names no user (GET /user answered {}): {FIX}",
        user.status
    );
    let login = user.body["login"]
        .as_str()
        .filter(|login| !login.is_empty())
        .with_context(|| format!("{TOKEN_VAR} names no user: {FIX}"))?;
    // Apply opens a pull request from the token's fork, and an owner has
    // none; a caller whose repository accepts owner branches does not opt in.
    if login.eq_ignore_ascii_case(parts[0]) {
        bail!(
            "{TOKEN_VAR} is {login}'s, who owns {repo} and has no fork of it to open a pull request from: {FIX}"
        );
    }
    // A classic PAT lists its scopes; a fine-grained one lists none, and
    // what it may do is not asked here.
    if let Some(scopes) = &user.scopes {
        ensure!(
            scopes
                .split(',')
                .any(|scope| matches!(scope.trim(), "repo" | "public_repo")),
            "{TOKEN_VAR} of {login} has the scopes {scopes:?}, not repo, which apply needs to fork {repo} and push: {FIX}"
        );
    }
    let read = get(&format!("repos/{repo}"))?;
    ensure!(
        (200..300).contains(&read.status),
        "{TOKEN_VAR} of {login} cannot read {repo} ({}): {FIX}",
        read.status
    );
    Ok(login.to_owned())
}

fn get(http: &ureq::Agent, api: &str, token: &str, path: &str) -> Result<Answer> {
    let mut response = http
        .get(format!("{}/{path}", api.trim_end_matches('/')))
        .header("authorization", format!("Bearer {token}"))
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "agentic-job")
        .call()
        .with_context(|| format!("GET /{path} failed"))?;
    let scopes = response
        .headers()
        .get("x-oauth-scopes")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE)
        .read_to_string()
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null);
    Ok(Answer {
        status: response.status().as_u16(),
        scopes,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A forge that answers GET /user with `status`, `login` and `scopes`,
    /// and the output repository with `read`.
    fn forge<'a>(
        status: u16,
        login: &str,
        scopes: Option<&str>,
        read: u16,
        asked: &'a mut Vec<String>,
    ) -> impl FnMut(&str) -> Result<Answer> + 'a {
        let (login, scopes) = (login.to_owned(), scopes.map(str::to_owned));
        move |path| {
            asked.push(path.to_owned());
            Ok(match path {
                "user" => Answer {
                    status,
                    scopes: scopes.clone(),
                    body: serde_json::json!({ "login": login }),
                },
                _ => Answer {
                    status: read,
                    scopes: None,
                    body: Value::Null,
                },
            })
        }
    }

    #[test]
    fn refusals_name_the_secret_and_the_fix() {
        let repo = "owner/repo";
        for (name, repo, token, status, login, scopes, read, refusal) in [
            (
                "missing",
                repo,
                "",
                200,
                "bot",
                Some("repo"),
                200,
                "is missing or empty",
            ),
            (
                "no output repository",
                "",
                "t",
                200,
                "bot",
                Some("repo"),
                200,
                "needs the output repository",
            ),
            (
                "not a user's",
                repo,
                "t",
                401,
                "bot",
                Some("repo"),
                200,
                "names no user (GET /user answered 401)",
            ),
            (
                "no login",
                repo,
                "t",
                200,
                "",
                Some("repo"),
                200,
                "names no user",
            ),
            (
                "the owner's",
                repo,
                "t",
                200,
                "Owner",
                Some("repo"),
                200,
                "is Owner's, who owns owner/repo",
            ),
            (
                "without repo",
                repo,
                "t",
                200,
                "bot",
                Some("read:org, workflow"),
                200,
                "has the scopes \"read:org, workflow\", not repo",
            ),
            (
                "without scopes",
                repo,
                "t",
                200,
                "bot",
                Some(""),
                200,
                "has the scopes \"\", not repo",
            ),
            (
                "unable to read",
                repo,
                "t",
                200,
                "bot",
                Some("repo"),
                404,
                "cannot read owner/repo (404)",
            ),
        ] {
            let mut asked = Vec::new();
            let error = check(
                repo,
                token,
                &mut forge(status, login, scopes, read, &mut asked),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains(refusal), "{name}: {error}");
            assert!(
                error.ends_with(FIX) || refusal.contains("output repository"),
                "{name}: {error}"
            );
            // Nothing is asked of the forge without a token.
            if token.is_empty() || repo.is_empty() {
                assert!(asked.is_empty(), "{name}");
            }
        }
    }

    #[test]
    fn a_bot_token_that_can_apply_is_accepted() {
        for scopes in [Some("repo, workflow"), Some("public_repo"), None] {
            let mut asked = Vec::new();
            let login = check(
                "owner/repo",
                "t",
                &mut forge(200, "bot", scopes, 200, &mut asked),
            );
            assert_eq!(login.unwrap(), "bot", "{scopes:?}");
            assert_eq!(asked, ["user", "repos/owner/repo"]);
        }
    }
}
