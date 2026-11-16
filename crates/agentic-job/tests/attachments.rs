//! Public admission boundary tests; all forge reads use local metadata fixtures.

use agentic_job::policy::Bounds;
use agentic_job::policy::attachments::{MAX_ATTACHMENTS, MAX_REQUEST_BYTES, Mode, admit};
use anyhow::Result;
use safe_outputs::bounds::{Organization, RepoRule};
use serde_json::{Value, json};

const REPO: &str = "example-org/example";
const FORK: &str = "example-bot/example";
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn bounds() -> Bounds {
    let bounds: Bounds = toml::from_str(
        r#"
hosts = ["github.com"]
repos = ["example-org/example", "example-bot/example"]
bases = ["main"]
max_outputs = 3
max_patch_bytes = 1048576
max_patch_files = 50
[github.outputs]
add_comment = { max = 1 }
push_to_pull_request_branch = { max = 1, branches = ["bot/**"], own_author = "example-bot" }
"#,
    )
    .expect("valid fixture bounds");
    bounds.validate().expect("fixture bounds pass validation");
    bounds
}

fn metadata(path: &str) -> Result<Value> {
    Ok(match path {
        "repos/example-org/example" | "repos/example-bot/example" => {
            let repo = path
                .strip_prefix("repos/")
                .expect("matched repository path");
            json!({"full_name": repo, "private": false, "visibility": "public",
                "default_branch": "main", "clone_url": format!("https://github.com/{repo}"),
                "url": format!("https://api.github.com/repos/{repo}"),
                "fork": repo == FORK, "parent": {"full_name": REPO}})
        }
        "repos/example-org/example/issues/7" => json!({"number": 7,
            "repository_url": format!("https://api.github.com/repos/{REPO}")}),
        "repos/example-org/example/pulls/8" => json!({"number": 8, "state": "open",
            "user": {"login": "example-bot"}, "base": {"repo": {"full_name": REPO}},
            "head": {"ref": "bot/topic", "sha": SHA, "repo": {"full_name": FORK}}}),
        "repos/example-org/example/git/ref/heads/topic%2Fbranch" => json!({
            "ref": "refs/heads/topic/branch", "object": {"type": "commit", "sha": SHA}}),
        _ => panic!("unexpected forge read: {path}"),
    })
}

fn request(kind: &str, mode: &str) -> String {
    let mut attachment = json!({"kind": kind, "mode": mode, "repo": REPO});
    if kind == "branch" {
        attachment["branch"] = "topic/branch".into();
    } else {
        attachment["number"] = if kind == "issue" { 7 } else { 8 }.into();
    }
    json!([attachment]).to_string()
}

#[test]
fn kind_mode_and_repository_bounds_matrix() {
    for kind in ["issue", "pull-request", "branch"] {
        for mode in ["read", "write"] {
            for inside in [false, true] {
                let mut bounds = bounds();
                if !inside {
                    bounds.repos = vec!["other-org/other".into()];
                }
                let result = admit(&request(kind, mode), &bounds, None, false, &mut metadata);
                let allowed = mode == "read" || (inside && kind != "branch");
                assert_eq!(
                    result.is_ok(),
                    allowed,
                    "{kind} {mode} inside={inside}: {result:?}"
                );
                if let Ok(admitted) = result {
                    assert_eq!(admitted.len(), 1);
                    assert_eq!(
                        admitted[0].attachment.mode(),
                        if mode == "read" {
                            Mode::Read
                        } else {
                            Mode::Write
                        }
                    );
                    assert_eq!(
                        admitted[0].head.as_deref(),
                        (kind != "issue").then_some(SHA)
                    );
                    assert_eq!(
                        admitted[0].head_repo.as_deref(),
                        match kind {
                            "issue" => None,
                            "pull-request" => (mode == "write").then_some(FORK),
                            _ => Some(REPO),
                        }
                    );
                    assert_eq!(admitted[0].write_policy.is_some(), mode == "write");
                }
            }
        }
    }
}

#[test]
fn compiled_write_policies_retain_existing_limits() {
    let bounds = bounds();
    let admitted = admit(
        &request("pull-request", "write"),
        &bounds,
        None,
        false,
        &mut metadata,
    )
    .unwrap();
    let policy = admitted[0].write_policy.as_ref().unwrap();
    policy.validate().unwrap();
    assert_eq!(policy.repo, REPO);
    assert_eq!(policy.base, "bot/topic");
    assert_eq!(policy.max_patch_bytes, bounds.max_patch_bytes);
    assert_eq!(policy.max_outputs, 2);
    let push = policy
        .safe_outputs
        .push_to_pull_request_branch
        .as_ref()
        .unwrap();
    assert_eq!(push.target, "8");
    assert_eq!(push.max_patch_files, bounds.max_patch_files);
    assert_eq!(push.head, SHA);
}

#[test]
fn same_repository_head_uses_existing_push_policy() {
    let admitted = admit(
        &request("pull-request", "write"),
        &bounds(),
        Some(&bounds()),
        false,
        &mut |path| {
            assert_ne!(path, format!("repos/{FORK}"));
            let mut response = metadata(path)?;
            if path.ends_with("/pulls/8") {
                response["head"]["repo"]["full_name"] = REPO.into();
            }
            Ok(response)
        },
    )
    .unwrap();
    assert_eq!(admitted[0].head_repo.as_deref(), Some(REPO));
    let policy = admitted[0].write_policy.as_ref().unwrap();
    policy.validate().unwrap();
    let push = policy
        .safe_outputs
        .push_to_pull_request_branch
        .as_ref()
        .unwrap();
    assert_eq!(policy.repo, REPO);
    assert_eq!(policy.base, "bot/topic");
    assert_eq!(push.target, "8");
    assert_eq!(push.head, SHA);
    // This is admission, not evidence of apply's required owner-branch opt-in.
    assert_eq!(push.author, None);
}

#[test]
fn public_reads_reuse_context_authority_not_write_repository_bounds() {
    let mut outside = bounds();
    outside.repos = vec!["other-org/other".into()];
    for kind in ["issue", "pull-request", "branch"] {
        for (caller, organization) in [
            (&outside, None),
            (&bounds(), Some(&outside)),
            (&outside, Some(&outside)),
        ] {
            let admitted = admit(
                &request(kind, "read"),
                caller,
                organization,
                true,
                &mut metadata,
            )
            .unwrap_or_else(|error| panic!("{kind}: {error:#}"));
            assert!(admitted[0].write_policy.is_none());
        }
    }
}

#[test]
fn public_reads_still_require_public_metadata_and_admitted_clone_hosts() {
    for kind in ["issue", "pull-request", "branch"] {
        for (field, value) in [
            ("full_name", json!("other/repo")),
            ("private", json!(true)),
            ("private", Value::Null),
            ("visibility", json!("private")),
            ("visibility", Value::Null),
            (
                "clone_url",
                json!("https://untrusted.example/example-org/example"),
            ),
        ] {
            let result = admit(
                &request(kind, "read"),
                &bounds(),
                None,
                false,
                &mut |path| {
                    let mut response = metadata(path)?;
                    if path == format!("repos/{REPO}") {
                        response[field] = value.clone();
                    }
                    Ok(response)
                },
            );
            assert!(result.is_err(), "{kind} {field}: {result:?}");
        }
        let mut restricted = bounds();
        restricted.hosts = vec!["other.example".into()];
        for (caller, organization) in [(&restricted, None), (&bounds(), Some(&restricted))] {
            let result = admit(
                &request(kind, "read"),
                caller,
                organization,
                false,
                &mut metadata,
            );
            assert!(result.is_err(), "{kind}: {result:?}");
        }
    }
}

#[test]
fn own_author_admits_an_upstream_push_without_upstream_comments() {
    let mut fork_only = bounds();
    fork_only.repos = vec![FORK.into()];
    fork_only.max_outputs = 1;
    fork_only
        .github
        .as_mut()
        .unwrap()
        .outputs
        .types
        .remove("add_comment");
    for (caller, organization) in [
        (&fork_only, None),
        (&bounds(), Some(&fork_only)),
        (&fork_only, Some(&bounds())),
    ] {
        let admitted = admit(
            &request("pull-request", "write"),
            caller,
            organization,
            false,
            &mut metadata,
        )
        .unwrap();
        let policy = admitted[0].write_policy.as_ref().unwrap();
        policy.validate().unwrap();
        assert_eq!(admitted[0].head_repo.as_deref(), Some(FORK));
        assert_eq!(policy.repo, REPO);
        assert_eq!(policy.max_outputs, 1);
        assert!(policy.safe_outputs.others.is_empty());
        let push = policy
            .safe_outputs
            .push_to_pull_request_branch
            .as_ref()
            .unwrap();
        assert_eq!(push.author.as_deref(), Some("example-bot"));
        assert_eq!(push.head, SHA);
    }
    assert!(
        admit(
            &request("issue", "write"),
            &fork_only,
            None,
            false,
            &mut metadata,
        )
        .is_err()
    );
}

#[test]
fn upstream_push_does_not_recover_denied_author_branch_or_head_authority() {
    let mut fork_only = bounds();
    fork_only.repos = vec![FORK.into()];
    for change in ["author", "branch", "head", "organization-rule"] {
        let mut restricted = fork_only.clone();
        match change {
            "head" => restricted.repos = vec![REPO.into()],
            "organization-rule" => {
                // As for ordinary continuation, an organization policy never
                // recovers an unlisted target through own_author.
                restricted.repos = vec![RepoRule::Organization(Organization {
                    org: "example-bot".into(),
                    forks: false,
                    properties: Default::default(),
                    topics: Vec::new(),
                })];
            }
            _ => {
                let push = restricted
                    .github
                    .as_mut()
                    .unwrap()
                    .outputs
                    .types
                    .get_mut("push_to_pull_request_branch")
                    .unwrap();
                if change == "author" {
                    push.own_author = Some("other-bot".into());
                } else {
                    push.branches = vec!["bot/other".into()];
                }
            }
        }
        for (caller, organization) in [
            (&restricted, None),
            (&fork_only, Some(&restricted)),
            (&restricted, Some(&fork_only)),
        ] {
            let result = admit(
                &request("pull-request", "write"),
                caller,
                organization,
                false,
                &mut metadata,
            );
            assert!(result.is_err(), "{change}: {result:?}");
        }
    }
}

#[test]
fn organization_bounds_only_narrow_admission() {
    let caller = bounds();
    for kind in ["issue", "pull-request", "branch"] {
        for mode in ["read", "write"] {
            let mut organization = bounds();
            organization.repos = vec!["other-org/other".into()];
            assert_eq!(
                admit(
                    &request(kind, mode),
                    &caller,
                    Some(&organization),
                    false,
                    &mut metadata
                )
                .is_ok(),
                mode == "read"
            );
        }
    }
    let mut organization = bounds();
    organization.max_patch_bytes = 1024;
    organization.max_patch_files = 2;
    let admitted = admit(
        &request("pull-request", "write"),
        &caller,
        Some(&organization),
        false,
        &mut metadata,
    )
    .unwrap();
    let policy = admitted[0].write_policy.as_ref().unwrap();
    assert_eq!(policy.max_patch_bytes, 1024);
    assert_eq!(
        policy
            .safe_outputs
            .push_to_pull_request_branch
            .as_ref()
            .unwrap()
            .max_patch_files,
        2
    );
    for (key, value) in [
        ("branches", json!(["bot/other"])),
        ("own_author", json!("another-bot")),
    ] {
        let mut organization = bounds();
        let limit = organization
            .github
            .as_mut()
            .unwrap()
            .outputs
            .types
            .get_mut("push_to_pull_request_branch")
            .unwrap();
        match key {
            "branches" => limit.branches = serde_json::from_value(value).unwrap(),
            _ => limit.own_author = serde_json::from_value(value).unwrap(),
        }
        assert!(
            admit(
                &request("pull-request", "write"),
                &caller,
                Some(&organization),
                false,
                &mut metadata
            )
            .is_err()
        );
    }
}

#[test]
fn writes_do_not_bypass_output_or_head_repository_bounds() {
    for change in [
        "no-comments",
        "no-push",
        "no-author",
        "head-outside",
        "branches",
    ] {
        let mut bounds = bounds();
        let limits = &mut bounds.github.as_mut().unwrap().outputs.types;
        match change {
            "no-comments" => {
                limits.remove("add_comment");
            }
            "no-push" => {
                limits.remove("push_to_pull_request_branch");
            }
            "no-author" => {
                limits
                    .get_mut("push_to_pull_request_branch")
                    .unwrap()
                    .own_author = None
            }
            "head-outside" => bounds.repos = vec![REPO.into()],
            "branches" => {
                limits
                    .get_mut("push_to_pull_request_branch")
                    .unwrap()
                    .branches = vec!["bot/other".into()]
            }
            _ => unreachable!(),
        }
        assert!(
            admit(
                &request("pull-request", "write"),
                &bounds,
                None,
                false,
                &mut metadata
            )
            .is_err(),
            "{change}"
        );
        // Read mode grants no write policy, even without those capabilities.
        assert!(
            admit(
                &request("pull-request", "read"),
                &bounds,
                None,
                true,
                &mut metadata
            )
            .is_ok(),
            "{change}"
        );
    }
    assert!(
        admit(
            &request("pull-request", "write"),
            &bounds(),
            None,
            true,
            &mut metadata
        )
        .is_err()
    );
    assert!(
        admit(
            &request("issue", "write"),
            &bounds(),
            None,
            true,
            &mut metadata
        )
        .is_ok()
    );
}

#[test]
fn read_heads_never_consult_the_head_repository() {
    // Another author's fork outside bounds, or a deleted one, may be read but
    // never written: a read head comes from the target's pull ref.
    for head_repo in [json!({"full_name": "example-other/example"}), Value::Null] {
        let mut other_head = |path: &str| -> Result<Value> {
            assert!(
                path != format!("repos/{FORK}") && !path.contains("example-other"),
                "read-mode admission read the head repository: {path}"
            );
            let mut response = metadata(path)?;
            if path.ends_with("/pulls/8") {
                response["head"]["repo"] = head_repo.clone();
                response["user"]["login"] = "example-other".into();
            }
            Ok(response)
        };
        let admitted = admit(
            &request("pull-request", "read"),
            &bounds(),
            Some(&bounds()),
            false,
            &mut other_head,
        )
        .unwrap();
        assert_eq!(admitted[0].head.as_deref(), Some(SHA));
        assert_eq!(admitted[0].head_repo, None);
        assert!(admitted[0].write_policy.is_none());
    }
    let result = admit(
        &request("pull-request", "write"),
        &bounds(),
        None,
        false,
        &mut |path| {
            let mut response = metadata(path)?;
            if path.ends_with("/pulls/8") {
                response["head"]["repo"] = Value::Null;
            }
            Ok(response)
        },
    );
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn write_attachments_share_the_run_output_limit() {
    let issue: Value = serde_json::from_str(&request("issue", "write")).unwrap();
    let pull: Value = serde_json::from_str(&request("pull-request", "write")).unwrap();
    let branch: Value = serde_json::from_str(&request("branch", "read")).unwrap();
    let text = json!([issue[0], pull[0], branch[0]]).to_string();
    // The issue's policy grants a comment; the PR's grants a push and up to
    // two comments, its own max_outputs. Together: three outputs.
    let comments = |max| {
        let mut bounds = bounds();
        let limits = &mut bounds.github.as_mut().unwrap().outputs.types;
        limits.get_mut("add_comment").unwrap().max = max;
        bounds
    };
    assert_eq!(
        admit(&text, &comments(3), None, false, &mut metadata)
            .unwrap()
            .len(),
        3
    );
    let mut total = comments(3);
    total.max_outputs = 2;
    for (caller, organization) in [
        (&total, None),
        (&comments(3), Some(&total)),
        // Too few comments for 1 + 1, or for 1 + 2.
        (&bounds(), None),
        (&comments(3), Some(&bounds())),
        (&comments(2), None),
    ] {
        let result = admit(&text, caller, organization, false, &mut metadata);
        assert!(result.is_err(), "{result:?}");
    }
}

#[test]
fn malformed_or_oversized_lists_refuse_before_forge_reads() {
    let one: Value = serde_json::from_str(&request("issue", "read")).unwrap();
    let mut cases = vec!["null".into(), "{}".into(), "[null]".into(), " ".repeat(MAX_REQUEST_BYTES + 1),
        json!(vec![one[0].clone(); MAX_ATTACHMENTS + 1]).to_string(),
        json!([one[0].clone(), one[0].clone()]).to_string(),
        r#"[{"kind":"issue","repo":"example-org/example","number":7,"mode":"read","mode":"write"}]"#.into()];
    for (key, value) in [
        ("kind", json!("file")),
        ("mode", json!("admin")),
        ("mode", Value::Null),
        ("repo", json!("../example")),
        ("repo", json!("owner/repo/extra")),
        ("number", json!(0)),
        ("number", json!(1_000_000_000)),
        ("number", json!("7")),
        ("head", json!(SHA)),
    ] {
        let mut bad = one.clone();
        bad[0][key] = value;
        cases.push(bad.to_string());
    }
    let mut duplicate = one[0].clone();
    duplicate["repo"] = REPO.to_ascii_uppercase().into();
    duplicate["kind"] = "pull-request".into();
    duplicate["mode"] = "write".into();
    cases.push(json!([one[0], duplicate]).to_string());
    for text in cases {
        assert!(
            admit(&text, &bounds(), None, false, &mut |_| panic!(
                "invalid request reached forge: {text}"
            ))
            .is_err(),
            "{text}"
        );
    }
    for text in ["", "[]"] {
        assert!(
            admit(text, &bounds(), None, false, &mut |_| panic!(
                "empty list reached forge"
            ))
            .unwrap()
            .is_empty()
        );
    }
}

#[test]
fn forged_or_missing_metadata_is_not_authority() {
    for (kind, path, pointer, value) in [
        (
            "issue",
            "repos/example-org/example/issues/7",
            "/pull_request",
            json!({}),
        ),
        (
            "issue",
            "repos/example-org/example/issues/7",
            "/repository_url",
            json!("https://api.github.com/repos/other/repo"),
        ),
        (
            "pull-request",
            "repos/example-org/example/pulls/8",
            "/number",
            json!(9),
        ),
        (
            "pull-request",
            "repos/example-org/example/pulls/8",
            "/state",
            json!("closed"),
        ),
        (
            "pull-request",
            "repos/example-org/example/pulls/8",
            "/user/login",
            json!("other-author"),
        ),
        (
            "pull-request",
            "repos/example-org/example/pulls/8",
            "/head/sha",
            json!("main"),
        ),
        (
            "pull-request",
            "repos/example-bot/example",
            "/fork",
            json!(false),
        ),
        (
            "pull-request",
            "repos/example-bot/example",
            "/parent/full_name",
            json!("other/repo"),
        ),
        (
            "pull-request",
            "repos/example-bot/example",
            "/private",
            json!(true),
        ),
        (
            "issue",
            "repos/example-org/example",
            "/visibility",
            json!("private"),
        ),
        (
            "issue",
            "repos/example-org/example",
            "/clone_url",
            json!("https://untrusted.example/example-org/example"),
        ),
    ] {
        let result = admit(
            &request(kind, "write"),
            &bounds(),
            None,
            false,
            &mut |requested| {
                let mut response = metadata(requested)?;
                if requested == path {
                    response
                        .pointer_mut(pointer)
                        .map(|field| *field = value.clone())
                        .unwrap_or_else(|| {
                            response["pull_request"] = value.clone();
                        });
                }
                Ok(response)
            },
        );
        assert!(result.is_err(), "{path} {pointer}: {result:?}");
    }
    for kind in ["issue", "pull-request", "branch"] {
        assert!(
            admit(
                &request(kind, "read"),
                &bounds(),
                None,
                false,
                &mut |_| anyhow::bail!("metadata unavailable")
            )
            .is_err()
        );
    }
}
