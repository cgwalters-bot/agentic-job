//! Resolve a dispatcher's context request on the read-only policy machine,
//! before any agent starts: each ref to a commit, and each repository
//! confirmed public through the forge API. Anything unexpected refuses.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Deserialize;
use serde_json::Value;

use super::{BASE_RE, ContextRepo, MAX_CONTEXT_REPOS, REPO_RE};

/// The most a context request may hold.
pub const MAX_REQUEST: usize = 16384;
/// The most one metadata response may hold.
const MAX_RESPONSE: u64 = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);
const API_URL_VAR: &str = "GITHUB_API_URL";
const DEFAULT_API: &str = "https://api.github.com";
const TOKEN_VAR: &str = "GH_TOKEN";

/// One requested repository: `ref` is a branch, tag or commit, and the
/// default branch when left out.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    repo: String,
    #[serde(rename = "ref", default, deserialize_with = "present")]
    reference: Option<String>,
}

/// A `ref` that is there is a string: `null` is refused, not the default branch.
fn present<'de, D: serde::Deserializer<'de>>(value: D) -> Result<Option<String>, D::Error> {
    String::deserialize(value).map(Some)
}

/// The repositories of `text`, resolved through `read`, which takes an
/// API path and returns its JSON. Empty text is no context.
pub fn resolve(
    text: &str,
    read: &mut dyn FnMut(&str) -> Result<Value>,
) -> Result<Vec<ContextRepo>> {
    ensure!(text.len() <= MAX_REQUEST, "context input exceeds 16 KiB");
    let items: Vec<Item> = match text {
        "" => Vec::new(),
        text => serde_json::from_str(text).context(
            "context entries must contain OWNER/REPO and an optional branch, tag or SHA ref",
        )?,
    };
    ensure!(
        items.len() <= MAX_CONTEXT_REPOS,
        "at most {MAX_CONTEXT_REPOS} context repositories"
    );
    let mut seen = std::collections::BTreeSet::new();
    for item in &items {
        ensure!(
            REPO_RE.is_match(&item.repo)
                && item
                    .repo
                    .split('/')
                    .all(|part| !part.starts_with(['.', '-']))
                && item.reference.as_deref().is_none_or(|reference| {
                    BASE_RE.is_match(reference) && !reference.contains("..")
                }),
            "context entries must contain OWNER/REPO and an optional branch, tag or SHA ref"
        );
        ensure!(
            seen.insert(item.repo.to_ascii_lowercase()),
            "duplicate context repository {:?}",
            item.repo
        );
    }
    items
        .into_iter()
        .map(|item| {
            let repo = read(&format!("repos/{}", item.repo))?;
            // Everything about a run is published: admission alone must not
            // publish private source through the prompt or the transcript.
            if repo["private"] != false || repo["visibility"] != "public" {
                bail!(
                    "context repository cannot be confirmed public; private runs are refused because run evidence can disclose source. See docs/private-repositories.md in the agentic-job source"
                );
            }
            let reference = match item.reference {
                Some(reference) => reference,
                None => repo["default_branch"]
                    .as_str()
                    .filter(|branch| !branch.is_empty() && branch.len() <= 200)
                    .context("missing default branch")?
                    .to_owned(),
            };
            let commit = read(&format!(
                "repos/{}/commits/{}",
                item.repo,
                reference.replace('/', "%2F")
            ))?;
            let commit = commit["sha"]
                .as_str()
                .filter(|sha| super::COMMIT_RE.is_match(sha))
                .context("invalid context commit")?;
            Ok(ContextRepo {
                clone_url: repo["clone_url"]
                    .as_str()
                    .context("missing clone URL")?
                    .to_owned(),
                repo: item.repo,
                commit: commit.to_owned(),
                public: true,
            })
        })
        .collect()
}

/// Reads API paths from `GITHUB_API_URL` with `GH_TOKEN`, the read-only
/// job token; both are looked up only when a path is read.
pub fn forge() -> impl FnMut(&str) -> Result<Value> {
    let http = agent();
    move |path| {
        let api = std::env::var(API_URL_VAR).unwrap_or_else(|_| DEFAULT_API.into());
        ensure!(api.starts_with("https://"), "{API_URL_VAR} requires HTTPS");
        let token = std::env::var(TOKEN_VAR)
            .ok()
            .filter(|token| !token.is_empty())
            .with_context(|| format!("{TOKEN_VAR} is required to resolve context"))?;
        read(&http, &api, &token, path)
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        // Never forward the credential to a redirect target.
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into()
}

fn read(http: &ureq::Agent, api: &str, token: &str, path: &str) -> Result<Value> {
    // No response text in the error: it is the forge's, not ours to log.
    let unreadable = || anyhow!("cannot read context metadata: {path}");
    let mut response = http
        .get(format!("{}/{path}", api.trim_end_matches('/')))
        .header("authorization", format!("Bearer {token}"))
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "agentic-job")
        .call()
        .map_err(|_| unreadable())?;
    ensure!(response.status().is_success(), unreadable());
    let text = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE)
        .read_to_string()
        .map_err(|_| unreadable())?;
    serde_json::from_str(&text).map_err(|_| unreadable())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn public() -> Value {
        json!({"private": false, "visibility": "public", "default_branch": "main",
            "clone_url": "https://github.com/owner/repo"})
    }

    #[test]
    fn refs_resolve_once_to_commits() {
        assert!(
            resolve("", &mut |_| panic!("no request"))
                .unwrap()
                .is_empty()
        );
        assert!(
            resolve("[]", &mut |_| panic!("no request"))
                .unwrap()
                .is_empty()
        );
        for (reference, path) in [
            (None, "main"),
            (Some("topic/branch"), "topic%2Fbranch"),
            (Some(SHA), SHA),
        ] {
            let mut item = json!({"repo": "owner/repo"});
            if let Some(reference) = reference {
                item["ref"] = reference.into();
            }
            let mut calls = Vec::new();
            let resolved = resolve(&json!([item]).to_string(), &mut |path| {
                calls.push(path.to_owned());
                Ok(if calls.len() == 1 {
                    public()
                } else {
                    json!({"sha": SHA})
                })
            })
            .unwrap();
            assert_eq!(
                calls,
                [
                    "repos/owner/repo".to_owned(),
                    format!("repos/owner/repo/commits/{path}")
                ]
            );
            assert_eq!(
                resolved,
                [ContextRepo {
                    repo: "owner/repo".into(),
                    clone_url: "https://github.com/owner/repo".into(),
                    commit: SHA.into(),
                    public: true,
                }]
            );
        }
    }

    /// What the dispatcher wrote is refused before any request, and what
    /// the forge says refuses unless it confirms a public repository.
    #[test]
    fn refusals() {
        let mut requests = vec![
            "{}".to_owned(),
            "null".to_owned(),
            "[null]".to_owned(),
            r#"["owner/repo"]"#.to_owned(),
            json!(vec![json!({"repo": "owner/repo"}); 9]).to_string(),
            " ".repeat(MAX_REQUEST + 1),
            r#"[{"repo":"owner/repo","public":true}]"#.to_owned(),
            r#"[{"repo":"owner/repo","ref":null}]"#.to_owned(),
            r#"[{"repo":"owner/repo"},{"repo":"OWNER/REPO"}]"#.to_owned(),
        ];
        for repo in [
            "../repo",
            "owner/..",
            "-owner/repo",
            "owner/repo/extra",
            "owner/repo\n",
        ] {
            requests.push(json!([{"repo": repo}]).to_string());
        }
        for reference in ["--evil", "../main", "a/../b", "", "a b"] {
            requests.push(json!([{"repo": "owner/repo", "ref": reference}]).to_string());
        }
        for request in requests {
            assert!(
                resolve(&request, &mut |_| panic!("{request:?} reached the API")).is_err(),
                "{request:?}"
            );
        }
        let one = r#"[{"repo":"owner/repo"}]"#;
        for metadata in [
            json!({}),
            json!({"private": true, "visibility": "private"}),
            json!({"private": false, "visibility": "internal"}),
            json!({"private": true, "visibility": "public"}),
            json!({"visibility": "public"}),
            json!({"private": false}),
        ] {
            let error = resolve(one, &mut |_| Ok(metadata.clone())).unwrap_err();
            assert!(
                error.to_string().contains("private runs are refused"),
                "{error}"
            );
        }
        for (repo, commit) in [
            (public(), json!({"sha": "main"})),
            (public(), json!({})),
            (
                json!({"private": false, "visibility": "public"}),
                json!({"sha": SHA}),
            ),
        ] {
            let mut calls = 0;
            assert!(
                resolve(one, &mut |_| {
                    calls += 1;
                    Ok(if calls == 1 {
                        repo.clone()
                    } else {
                        commit.clone()
                    })
                })
                .is_err()
            );
        }
        assert!(resolve(one, &mut |path| Err(anyhow!("cannot read {path}"))).is_err());
    }

    #[test]
    fn a_failed_read_or_a_redirect_refuses() {
        use std::io::{Read, Write};
        for (status, body, ok) in [
            (200, r#"{"sha":"x"}"#, true),
            (302, r#"{"sha":"x"}"#, false),
            (404, "{}", false),
            (200, "not json", false),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = [0; 4096];
                let mut request = String::new();
                while !request.contains("\r\n\r\n") {
                    let n = stream.read(&mut bytes).unwrap();
                    assert!(n > 0);
                    request.push_str(std::str::from_utf8(&bytes[..n]).unwrap());
                }
                assert!(request.starts_with("GET /repos/owner/repo HTTP/1.1\r\n"));
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer fixture-token\r\n")
                );
                write!(stream, "HTTP/1.1 {status} Test\r\nLocation: http://127.0.0.1:1/never\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            });
            let result = read(
                &agent(),
                &format!("http://{address}"),
                "fixture-token",
                "repos/owner/repo",
            );
            assert_eq!(result.is_ok(), ok, "HTTP {status} {body:?}");
            server.join().unwrap();
        }
    }
}
