use super::*;
use crate::policy::tests::{bounds, policy};
use serde_json::json;

const REPO: &str = "Source/Project";
const HEAD: &str = "Contributor/Fork";
const SHA: &str = "1111111111111111111111111111111111111111";

fn request(kind: &str, number: u64) -> Value {
    json!({"kind":kind,"mode":"read","repo":"source/project","number":number})
}

fn metadata(path: &str) -> Result<Value> {
    let repo = match path {
        "repos/source/project" => REPO,
        "repos/contributor/fork" => HEAD,
        "repos/Source/Project/issues/1" => {
            return Ok(json!({"number":1,"html_url":"https://github.com/Source/Project/issues/1"}));
        }
        "repos/Source/Project/pulls/2" => {
            return Ok(
                json!({"number":2,"html_url":"https://github.com/Source/Project/pull/2","base":{"repo":{"full_name":REPO}},"head":{"repo":{"full_name":"contributor/fork"},"sha":SHA}}),
            );
        }
        _ => anyhow::bail!("no fixture at {path}"),
    };
    Ok(
        json!({"full_name":repo,"private":false,"visibility":"public","clone_url":format!("https://github.com/{repo}.git")}),
    )
}

#[test]
fn read_inputs_are_not_output_targets() {
    let primary = ("example-org/items", 11);
    let policy = policy();
    let requests = json!([request("issue", 1), request("pull-request", 2)]);
    let inputs = admit(
        &requests.to_string(),
        &bounds(),
        Some(&bounds()),
        &mut metadata,
    )
    .unwrap();
    assert_eq!(
        inputs,
        [
            ReadAttachment::Issue {
                repo: REPO.into(),
                number: 1
            },
            ReadAttachment::PullRequest {
                repo: REPO.into(),
                number: 2,
                head: ContextRepo {
                    repo: HEAD.into(),
                    clone_url: format!("https://github.com/{HEAD}.git"),
                    commit: SHA.into(),
                    public: true
                }
            }
        ]
    );
    let mut targets = vec![(primary.0, primary.1, true)];
    for input in &inputs {
        match input {
            ReadAttachment::Issue { repo, number } => targets.push((repo, *number, false)),
            ReadAttachment::PullRequest { repo, number, head } => targets.extend([
                (repo.as_str(), *number, false),
                (head.repo.as_str(), *number, false),
            ]),
        }
    }
    for (repo, number, accepted) in targets {
        let output = json!({"type":"add_comment","repo":repo,"item_number":number});
        assert_eq!(
            safe_outputs::check::redirections_to(
                output.as_object().unwrap(),
                &policy,
                Some(primary),
                &crate::check::Apply
            )
            .is_empty(),
            accepted
        );
        let output = json!({"type":"create_pull_request","repo":repo});
        assert!(
            !safe_outputs::check::redirections_to(
                output.as_object().unwrap(),
                &policy,
                Some(primary),
                &crate::check::Apply
            )
            .is_empty()
        );
    }
}

#[test]
fn invalid_requests_make_no_reads() {
    let bounds = bounds();
    let no_read = &mut |_: &str| panic!("unexpected metadata read");
    assert!(admit("[]", &bounds, None, no_read).unwrap().is_empty());
    let issue = request("issue", 1);
    for (key, value) in [
        ("kind", json!("branch")),
        ("kind", json!({"issue":null})),
        ("mode", json!({"read":null})),
        ("mode", json!("write")),
        ("mode", Value::Null),
        ("head", json!(SHA)),
        ("repo", json!("../project")),
        ("number", json!(0)),
        ("number", json!("1")),
    ] {
        let mut bad = issue.clone();
        bad[key] = value;
        assert!(admit(&json!([bad]).to_string(), &bounds, None, no_read).is_err());
    }
    for bad in [
        json!([issue, request("pull-request", 1)]),
        json!([["issue", "read", "source/project", 1]]),
        json!(
            (1..=MAX_ATTACHMENTS + 1)
                .map(|n| request("issue", n as u64))
                .collect::<Vec<_>>()
        ),
        json!([{"repo":REPO,"number":1,"kind":"issue"}]),
        Value::Null,
    ] {
        assert!(admit(&bad.to_string(), &bounds, None, no_read).is_err());
    }
}

#[test]
fn mismatched_missing_or_private_metadata_refuses_the_list() {
    let list = json!([request("issue", 1), request("pull-request", 2)]).to_string();
    let issue = "repos/Source/Project/issues/1";
    let pr = "repos/Source/Project/pulls/2";
    let target = "repos/source/project";
    let head = "repos/contributor/fork";
    for (path, field, bad) in [
        (issue, "/number", json!(2)),
        (
            issue,
            "/html_url",
            json!("https://github.com/Other/Repo/issues/1"),
        ),
        (pr, "/base/repo/full_name", json!(HEAD)),
        (pr, "/head/sha", json!("main")),
        (pr, "/head/repo", Value::Null),
        (target, "/private", json!(true)),
        (target, "/full_name", json!(HEAD)),
        (head, "/visibility", Value::Null),
        (head, "/full_name", json!(REPO)),
        (
            head,
            "/clone_url",
            json!("https://github.com/Source/Project"),
        ),
    ] {
        let result = admit(&list, &bounds(), None, &mut |p| {
            let mut value = metadata(p)?;
            if p == path {
                *value.pointer_mut(field).unwrap() = bad.clone();
            }
            Ok(value)
        });
        assert!(result.is_err(), "accepted {path}{field}: {bad}");
    }
    for missing in [target, issue, pr, head] {
        assert!(
            admit(&list, &bounds(), None, &mut |p| {
                ensure!(p != missing, "not found");
                metadata(p)
            })
            .is_err()
        );
    }
    assert!(
        admit(&list, &bounds(), None, &mut |p| {
            let mut v = metadata(p)?;
            if p == issue {
                v["pull_request"] = json!({});
            }
            Ok(v)
        })
        .is_err()
    );
}

#[test]
fn both_bounds_check_the_head_clone_url() {
    let narrow = bounds();
    let mut broad = bounds();
    broad.hosts.push("mirror.example".into());
    let list = json!([request("pull-request", 2)]).to_string();
    for (caller, org, accepted) in [
        (&broad, &broad, true),
        (&broad, &narrow, false),
        (&narrow, &broad, false),
    ] {
        let result = admit(&list, caller, Some(org), &mut |p| {
            let mut v = metadata(p)?;
            if p == "repos/contributor/fork" {
                v["clone_url"] = json!(format!("https://mirror.example/{HEAD}"));
            }
            Ok(v)
        });
        assert_eq!(result.is_ok(), accepted);
        if let Ok(inputs) = result {
            assert!(
                matches!(&inputs[..], [ReadAttachment::PullRequest {head,..}] if head.clone_url == format!("https://mirror.example/{HEAD}"))
            );
        }
    }
}
