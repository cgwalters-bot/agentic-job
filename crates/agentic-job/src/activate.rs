//! Consume command labels only on the trusted activation machine.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};

use crate::event::{Decision, ItemKind};
use crate::exit::Exit;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The policy job's event.json, never an agent-produced artifact
    #[arg(long)]
    pub decision: PathBuf,
    /// The workflow repository, OWNER/NAME
    #[arg(long)]
    pub repository: String,
}

/// Return the sole write this decision authorizes. Discussion numbers must
/// never reach the issues API: they occupy a separate namespace.
pub fn label_path(decision: &Decision, repository: &str) -> Result<Option<String>> {
    if !decision.admitted {
        return Ok(None);
    }
    ensure!(
        !decision
            .item
            .as_ref()
            .is_some_and(|item| item.kind == ItemKind::Discussion),
        "Discussion notification and output routing are not supported"
    );
    let Some(label) = decision
        .command
        .as_deref()
        .filter(|label| !label.is_empty())
    else {
        return Ok(None);
    };
    if decision.action.as_deref() != Some("labeled") {
        return Ok(None);
    }
    let item = decision
        .item
        .as_ref()
        .context("Label activation requires an issue or pull request identity")?;
    ensure!(
        item.number > 0 && item.number <= 9_007_199_254_740_991,
        "Label activation requires an issue or pull request identity"
    );
    let parts: Vec<_> = repository.split('/').collect();
    ensure!(
        parts.len() == 2
            && parts.iter().all(|part| !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))),
        "activation requires OWNER/NAME"
    );
    // Encode the entire label as one path segment, including slash and percent.
    let label: String = label.bytes().map(|b| format!("%{b:02X}")).collect();
    Ok(Some(format!(
        "repos/{repository}/issues/{}/labels/{label}",
        item.number
    )))
}

pub fn run(args: &Args) -> Result<Exit> {
    let decision: Decision = serde_json::from_slice(&crate::files::read_regular(
        &args.decision,
        4 * 1024 * 1024,
    )?)?;
    if let Some(path) = label_path(&decision, &args.repository)? {
        // One bounded request, no retries. Do not print API response text as
        // workflow commands on this write-capable machine.
        let api =
            std::env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".into());
        ensure!(api.starts_with("https://"), "GITHUB_API_URL requires HTTPS");
        let token =
            std::env::var("GH_TOKEN").context("GH_TOKEN is required for command-label removal")?;
        ensure!(!token.is_empty(), "GH_TOKEN is empty");
        remove_label(&api, &token, &path)?;
    }
    Ok(Exit::Success)
}

fn remove_label(api: &str, token: &str, path: &str) -> Result<()> {
    let http: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        // Never forward the write credential to a redirect target.
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let response = http
        .delete(format!("{}/{path}", api.trim_end_matches('/')))
        .header("authorization", format!("Bearer {token}"))
        .header("user-agent", "agentic-job")
        .call()
        .map_err(|_| {
            anyhow::anyhow!("command-label removal request failed; agent execution is blocked")
        })?;
    ensure!(
        response.status().is_success(),
        "command-label removal failed (HTTP {}); agent execution is blocked",
        response.status().as_u16()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn discussion_namespace_and_invalid_numbers_cannot_authorize_issue_writes() {
        let value = serde_json::json!({
            "schema": crate::event::SCHEMA, "admitted": true, "reason": "label",
            "event": "issues", "action": "labeled", "actor": "alice", "role": "write",
            "item": {"kind": "issue", "number": 12, "url": null},
            "command": "agent/review%", "base": null, "head": null,
            "concurrency": "issue-12", "react_to": null
        });
        for (kind, number, admitted, valid) in [
            ("issue", 12, true, true),
            ("pull_request", 12, true, true),
            ("discussion", 12, true, false),
            ("issue", 0, true, false),
            ("issue", 9_007_199_254_740_992_u64, true, false),
            ("discussion", 12, false, true),
        ] {
            let mut input = value.clone();
            input["item"]["kind"] = kind.into();
            input["item"]["number"] = number.into();
            input["admitted"] = admitted.into();
            let decision: Decision = serde_json::from_value(input).unwrap();
            let result = label_path(&decision, "owner/repo");
            assert_eq!(result.is_ok(), valid, "{kind}/{number}/{admitted}");
            if valid {
                assert_eq!(result.unwrap(), admitted.then(|| "repos/owner/repo/issues/12/labels/%61%67%65%6E%74%2F%72%65%76%69%65%77%25".into()));
            }
        }
    }

    #[test]
    fn removal_errors_and_redirects_block_execution_without_forwarding_credentials() {
        for status in [204, 302, 403, 404, 500] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
                assert!(
                    request.starts_with(
                        "DELETE /repos/owner/repo/issues/12/labels/review HTTP/1.1\r\n"
                    )
                );
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer fixture-token\r\n")
                );
                write!(stream, "HTTP/1.1 {status} Test\r\nLocation: http://127.0.0.1:1/never\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            });
            let result = remove_label(
                &format!("http://{address}"),
                "fixture-token",
                "repos/owner/repo/issues/12/labels/review",
            );
            assert_eq!(result.is_ok(), status == 204, "HTTP {status}");
            if status != 204 {
                assert!(format!("{:#}", result.unwrap_err()).contains(&format!("HTTP {status}")));
            }
            server.join().unwrap();
        }
    }
}
