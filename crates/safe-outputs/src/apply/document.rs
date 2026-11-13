//! Gist writes use only the applying account, never a request-selected owner.

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::github::{Github, is_repo};
use super::roles::Role;
use crate::contract::{COMMIT_RE, is_login};
use crate::document::{Document, Settings, is_id};

pub(super) fn publish(
    github: &Github,
    document: &Document,
    settings: &Settings,
    repo: &str,
    issue: u64,
) -> Result<Value> {
    document.authorize(settings)?;
    ensure!(
        is_repo(repo) && issue > 0,
        "document: invalid comment destination"
    );
    let actor = github.request("GET", "/user", None)?;
    let actor_id = actor["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("document: authenticated user ID")?;
    let login = actor["login"]
        .as_str()
        .filter(|login| is_login(login))
        .context("document: authenticated user login")?;
    let files: serde_json::Map<String, Value> = document
        .files
        .iter()
        .map(|(name, content)| (name.clone(), json!({"content": content})))
        .collect();
    let mut body = json!({"description": document.title, "files": files});
    let (method, path) = if let Some(id) = &document.gist_id {
        let path = format!("/gists/{id}");
        let prior = github.request("GET", &path, None)?;
        ensure!(
            prior["id"] == *id && prior["owner"]["id"].as_u64() == Some(actor_id),
            "document: gist is not owned by applying account"
        );
        ensure!(
            prior["public"].as_bool() == Some(settings.public),
            "document: existing gist visibility differs from policy"
        );
        ("PATCH", path)
    } else {
        body["public"] = json!(settings.public);
        ("POST", "/gists".into())
    };
    // No write retries: a lost response may already have created a revision.
    let answer = github.request(method, &path, Some(&body))?;
    let id = answer["id"]
        .as_str()
        .filter(|id| is_id(id))
        .context("document: gist response ID")?;
    ensure!(
        document
            .gist_id
            .as_deref()
            .is_none_or(|expected| expected == id)
            && answer["owner"]["id"].as_u64() == Some(actor_id)
            && answer["public"].as_bool() == Some(settings.public),
        "document: unexpected gist response"
    );
    let revision = answer["history"][0]["version"]
        .as_str()
        .filter(|revision| COMMIT_RE.is_match(revision))
        .context("document: gist response revision")?;
    let url = format!("https://gist.github.com/{login}/{id}");
    let revision_url = format!("{url}/{revision}");
    let comment = format!(
        "[Document]({revision_url})\n\n{}",
        document.summary.join("\n")
    );
    let posted = github.for_role(Role::Review).and_then(|review| {
        review.request(
            "POST",
            &format!("/repos/{repo}/issues/{issue}/comments"),
            Some(&json!({"body": comment})),
        )
    });
    let mut result = json!({"id": id, "url": url, "revision": revision, "metadata": {"revision": revision}, "comment_posted": posted.is_ok()});
    if let Err(err) = posted {
        // Preserve the durable URL/revision even if the follow-up comment failed.
        result["comment_error"] = json!(format!("{err:#}"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::testing::forge;

    fn document(id: Option<&str>) -> Document {
        serde_json::from_value(json!({"type": "document", "title": "Findings", "files": {"findings.md": "Updated evidence."}, "summary": ["Added evidence.", "Corrected a claim.", "Recorded questions."], "gist_id": id})).unwrap()
    }

    fn gist(public: bool, owner: u64) -> Value {
        json!({"id": "abc123", "owner": {"id": owner}, "public": public, "history": [{"version": "a".repeat(40)}]})
    }

    #[test]
    fn document_create_and_update() {
        for update in [false, true] {
            let mut routes = std::collections::BTreeMap::from([
                (
                    "GET /user".into(),
                    (200, json!({"id": 7, "login": "example-bot"})),
                ),
                (
                    "POST /repos/example-org/example/issues/7/comments".into(),
                    (201, json!({"id": 10})),
                ),
            ]);
            if update {
                routes.insert("GET /gists/abc123".into(), (200, gist(false, 7)));
                routes.insert("PATCH /gists/abc123".into(), (200, gist(false, 7)));
            } else {
                routes.insert("POST /gists".into(), (201, gist(false, 7)));
            }
            let (github, requests) = forge(routes);
            let settings = Settings {
                gist_ids: vec!["abc123".into()],
                ..Settings::default()
            };
            let result = publish(
                &github,
                &document(update.then_some("abc123")),
                &settings,
                "example-org/example",
                7,
            )
            .unwrap();
            assert_eq!(result["url"], "https://gist.github.com/example-bot/abc123");
            assert_eq!(result["revision"], "a".repeat(40));
            let sent: Vec<_> = requests.try_iter().collect();
            let write = &sent[if update { 2 } else { 1 }];
            assert_eq!(
                write.body["files"]["findings.md"]["content"],
                "Updated evidence."
            );
            if update {
                assert!(write.body.get("public").is_none());
            } else {
                assert_eq!(write.body["public"], false);
            }
            let comments: Vec<_> = sent
                .iter()
                .filter(|request| request.line.contains("/comments"))
                .collect();
            assert_eq!(comments.len(), 1);
            let body = comments[0].body["body"].as_str().unwrap();
            assert!(body.contains(&format!("abc123/{}", "a".repeat(40))));
            assert_eq!(body.lines().count(), 5);
        }
    }

    #[test]
    fn document_update_refuses_other_owner_or_visibility_before_write() {
        for (public, owner) in [(false, 8), (true, 7)] {
            let (github, requests) = forge(std::collections::BTreeMap::from([
                (
                    "GET /user".into(),
                    (200, json!({"id": 7, "login": "example-bot"})),
                ),
                ("GET /gists/abc123".into(), (200, gist(public, owner))),
            ]));
            let settings = Settings {
                gist_ids: vec!["abc123".into()],
                ..Settings::default()
            };
            assert!(
                publish(
                    &github,
                    &document(Some("abc123")),
                    &settings,
                    "example-org/example",
                    7
                )
                .is_err()
            );
            assert!(
                requests
                    .try_iter()
                    .all(|request| request.line.starts_with("GET "))
            );
        }
    }

    #[test]
    fn document_retains_revision_when_comment_fails() {
        let (github, _) = forge(std::collections::BTreeMap::from([
            (
                "GET /user".into(),
                (200, json!({"id": 7, "login": "example-bot"})),
            ),
            ("POST /gists".into(), (201, gist(false, 7))),
        ]));
        let result = publish(
            &github,
            &document(None),
            &Settings::default(),
            "example-org/example",
            7,
        )
        .unwrap();
        assert_eq!(result["comment_posted"], false);
        assert!(result["revision"].is_string());
        assert!(result["comment_error"].is_string());
    }

    #[test]
    fn document_retains_revision_when_review_credentials_are_missing() {
        use super::super::roles::{Credential, Identity};
        use std::collections::BTreeMap;

        for bindings in [
            BTreeMap::new(),
            BTreeMap::from([(
                Role::Review,
                Credential {
                    identity: Identity {
                        actor_id: 7,
                        app_id: None,
                    },
                    token: String::new(),
                },
            )]),
        ] {
            let (github, requests) = forge(BTreeMap::from([
                (
                    "GET /user".into(),
                    (200, json!({"id": 7, "login": "example-bot"})),
                ),
                ("POST /gists".into(), (201, gist(false, 7))),
            ]));
            let result = publish(
                &github.with_roles(bindings),
                &document(None),
                &Settings::default(),
                "example-org/example",
                7,
            )
            .unwrap();
            assert_eq!(result["url"], "https://gist.github.com/example-bot/abc123");
            assert_eq!(result["revision"], "a".repeat(40));
            assert_eq!(result["comment_posted"], false);
            assert!(result["comment_error"].is_string());
            let sent: Vec<_> = requests.try_iter().collect();
            assert_eq!(sent.len(), 2);
            assert!(
                sent.iter()
                    .all(|request| !request.line.contains("/comments"))
            );
        }
    }
}
