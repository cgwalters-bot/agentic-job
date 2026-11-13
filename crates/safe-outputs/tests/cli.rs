#![cfg(feature = "clap")]
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tempfile::TempDir;

struct Fixture {
    dir: TempDir,
    api: String,
    writes: Arc<Mutex<Vec<String>>>,
}

impl Fixture {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let writes = Arc::new(Mutex::new(Vec::new()));
        let requests = writes.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut bytes = Vec::new();
                let mut buf = [0; 4096];
                loop {
                    let n = stream.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|n| n.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                let body = if request.starts_with("GET /api/v4/projects/") {
                    if request.contains("/issues/7 ") {
                        json!({"iid":7,"project_id":1,"state":"opened","labels":[],"web_url":"https://gitlab.example/group/subgroup/project/-/issues/7"})
                    } else {
                        json!({"id":1,"path_with_namespace":"group/subgroup/project","visibility":"public"})
                    }
                } else {
                    json!({"html_url":"https://github.com/owner/repo/issues/7#issuecomment-1","id":1,"noteable_iid":7})
                }.to_string();
                requests.lock().unwrap().push(request);
                write!(
                    stream,
                    "HTTP/1.1 201 Created\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let fixture = Self {
            dir: tempfile::tempdir().unwrap(),
            api,
            writes,
        };
        fixture.context(json!({"add_comment":{"max":1}, "create_issue":{"max":1}}));
        fixture
    }

    fn context(&self, outputs: Value) {
        std::fs::write(
            self.dir.path().join("context.json"),
            json!({
                "repo":"owner/repo", "item":7, "max_outputs":2,
                "api_url":self.api, "outputs":outputs
            })
            .to_string(),
        )
        .unwrap();
    }

    fn input(&self, text: &str) {
        std::fs::write(self.dir.path().join("outputs.jsonl"), text).unwrap();
    }

    fn run(&self, subcommand: &str) -> Output {
        self.run_forge(subcommand, "github")
    }

    fn run_forge(&self, subcommand: &str, forge: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_safe-outputs"))
            .current_dir(self.dir.path())
            .env_clear()
            .env("SAFE_OUTPUTS_TOKEN", "loopback-test-token")
            .args([
                subcommand,
                "--forge",
                forge,
                "--context",
                "context.json",
                "--input",
                "outputs.jsonl",
                "--checked",
                "checked.json",
            ])
            .output()
            .unwrap()
    }

    fn assert_ok(&self, command: &str) {
        let result = self.run(command);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

fn gitlab_context(f: &Fixture, outputs: Value) -> Value {
    json!({
        "policy": {
            "forge":"gitlab", "repo":"group/subgroup/project",
            "clone_url": format!("{}/group/subgroup/project", f.api),
            "base":"main", "kind":"analysis", "max_outputs":3,
            "max_patch_bytes":1048576, "safe_outputs":outputs, "contract":1
        },
        "server":f.api, "item":7, "item_kind":"issue",
        "run_url":"https://ci.example/runs/1"
    })
}

fn write_context(f: &Fixture, context: &Value) {
    std::fs::write(f.dir.path().join("context.json"), context.to_string()).unwrap();
}

fn assert_gitlab_ok(f: &Fixture, command: &str) {
    let result = f.run_forge(command, "gitlab");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn standalone_gitlab_note_uses_shared_publisher() {
    let f = Fixture::new();
    write_context(&f, &gitlab_context(&f, json!({"add_comment":{"max":1}})));
    f.input(r#"{"type":"add_comment","repo":"group/subgroup/project","body":"@all\n/close"}"#);
    assert_gitlab_ok(&f, "check");
    assert!(f.writes.lock().unwrap().is_empty());
    assert_gitlab_ok(&f, "apply");
    let writes = f.writes.lock().unwrap();
    assert_eq!(writes.len(), 5);
    assert!(writes[0].starts_with("GET /api/v4/projects/group%2Fsubgroup%2Fproject "));
    assert!(
        writes[4].starts_with("POST /api/v4/projects/1/issues/7/notes "),
        "{}",
        writes[4]
    );
    assert!(writes[4].contains("Generated by [safe-outputs]"));
    assert!(!writes[4].contains("@all"));
}

#[test]
fn standalone_gitlab_refuses_invalid_batches_offline() {
    for (mut outputs, input) in [
        (
            json!({"add_labels":{"max":1,"allowed":["triage"]}}),
            json!({"type":"add_labels","repo":"group/subgroup/project","item_number":7,"labels":["triage"]}),
        ),
        (
            json!({"add_labels":{"max":1,"allowed":["triage"]}}),
            json!({"type":"add_labels","repo":"group/subgroup/project","issue_number":7,"labels":["release"]}),
        ),
        (
            json!({"create_discussion":{"max":1,"category":"Reports"}}),
            json!({"type":"create_discussion","title":"No","body":"Unsupported"}),
        ),
        (
            json!({"add_comment":{"max":1}}),
            json!({"type":"add_comment","repo":"other/project","body":"No"}),
        ),
        (
            json!({"create_pull_request_review_comment":{"max":1}}),
            json!({"type":"create_pull_request_review_comment","repo":"group/subgroup/project","pull_request_number":7,"path":"src/x","line":1,"body":"No head"}),
        ),
        (
            json!({}),
            json!({"type":"add_comment","body":"Second exceeds the count bound"}),
        ),
    ] {
        let f = Fixture::new();
        outputs["add_comment"] = json!({"max":1});
        write_context(&f, &gitlab_context(&f, outputs));
        f.input(&format!(
            "{}\n{input}",
            json!({"type":"add_comment","body":"First"})
        ));
        assert!(!f.run_forge("check", "gitlab").status.success());
        assert!(!f.dir.path().join("checked.json").exists());
        assert!(f.writes.lock().unwrap().is_empty());
    }
}

#[test]
fn gitlab_receipt_binds_forge_and_context() {
    let f = Fixture::new();
    let mut context = gitlab_context(&f, json!({"noop":{"max":1}}));
    write_context(&f, &context);
    f.input(r#"{"type":"noop","message":"No changes"}"#);
    assert_gitlab_ok(&f, "check");
    assert_gitlab_ok(&f, "apply");
    assert!(!f.run("apply").status.success());
    context["item_kind"] = json!("pull-request");
    write_context(&f, &context);
    assert!(!f.run_forge("apply", "gitlab").status.success());
    assert!(f.writes.lock().unwrap().is_empty());
}

fn patch_fixture(f: &Fixture, file: &str) -> String {
    let base = "1".repeat(40);
    std::fs::write(
        f.dir.path().join("base.json"),
        json!({"repo":"group/subgroup/project","ref":"main","commit":base}).to_string(),
    )
    .unwrap();
    let patch = format!(
        "From {base} Mon Sep 17 00:00:00 2001\nX-GH-AW-Base-Commit: {base}\n\
         From: agent <agent@localhost>\nDate: Tue, 6 Oct 2026 21:02:35 -0400\n\
         Subject: [PATCH] Change things\n\n---\n {file} | 1 +\n\n\
         diff --git a/{file} b/{file}\nnew file mode 100644\nindex 0000000..587be6b\n\
         --- /dev/null\n+++ b/{file}\n@@ -0,0 +1 @@\n+x\n"
    );
    std::fs::write(f.dir.path().join("aw-agent-run-1.patch"), &patch).unwrap();
    patch
}

#[test]
fn gitlab_patch_receipt_binds_all_inputs_and_rejects_protected_paths() {
    for file in ["src/x", ".gitlab-ci.yml"] {
        let f = Fixture::new();
        let mut context = gitlab_context(
            &f,
            json!({"create_pull_request":{
                "max":1,"protected_files":[],"protect_top_level_dot_folders":true,
                "protected_files_policy":"blocked","draft":true,"max_patch_size":1024,"max_patch_files":10
            }}),
        );
        context["policy"]["kind"] = json!("branch");
        context["policy"]["push_repo"] = json!("bot/project");
        write_context(&f, &context);
        f.input(
            r#"{"type":"create_pull_request","title":"Fix","body":"Why","branch":"agent-run-1"}"#,
        );
        let patch = patch_fixture(&f, file);
        if file.starts_with('.') {
            assert!(!f.run_forge("check", "gitlab").status.success());
            continue;
        }
        assert_gitlab_ok(&f, "check");
        std::fs::write(
            f.dir.path().join("aw-agent-run-1.patch"),
            patch.replace("+x\n", "+y\n"),
        )
        .unwrap();
        let result = f.run_forge("apply", "gitlab");
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("checked input or trusted context changed")
        );
        std::fs::write(f.dir.path().join("aw-agent-run-1.patch"), &patch).unwrap();
        std::fs::write(
            f.dir.path().join("base.json"),
            json!({"repo":"group/subgroup/project","ref":"main","commit":"2".repeat(40)})
                .to_string(),
        )
        .unwrap();
        assert!(!f.run_forge("apply", "gitlab").status.success());
        assert!(f.writes.lock().unwrap().is_empty());
    }
}

#[test]
fn gitlab_check_accepts_supported_nonpatch_operations() {
    for (kind, bounds, fields) in [
        (
            "create_issue",
            json!({"max":1}),
            json!({"title":"Follow-up","body":"A follow-up with enough detail."}),
        ),
        (
            "close_issue",
            json!({"max":1}),
            json!({"issue_number":7,"body":"Done"}),
        ),
        (
            "close_pull_request",
            json!({"max":1}),
            json!({"pull_request_number":7,"body":"Done"}),
        ),
        (
            "add_labels",
            json!({"max":1,"allowed":["triage"]}),
            json!({"issue_number":7,"labels":["triage"]}),
        ),
        (
            "remove_labels",
            json!({"max":1,"allowed":["triage"]}),
            json!({"pull_request_number":7,"labels":["triage"]}),
        ),
        ("noop", json!({"max":1}), json!({"message":"Done"})),
        (
            "missing_tool",
            json!({"max":1}),
            json!({"tool":"compiler","reason":"Not installed"}),
        ),
        (
            "missing_data",
            json!({"max":1}),
            json!({"reason":"No input"}),
        ),
    ] {
        let f = Fixture::new();
        let mut outputs = json!({});
        outputs[kind] = bounds;
        write_context(&f, &gitlab_context(&f, outputs));
        let mut item = fields;
        item["type"] = json!(kind);
        item["repo"] = json!("group/subgroup/project");
        f.input(&item.to_string());
        let result = f.run_forge("check", "gitlab");
        assert!(
            result.status.success(),
            "{kind}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(f.writes.lock().unwrap().is_empty());
    }
}

#[test]
fn gitlab_outputs_are_off_by_default() {
    let f = Fixture::new();
    write_context(&f, &gitlab_context(&f, json!({})));
    f.input(r#"{"type":"add_comment","body":"Not authorized"}"#);
    assert!(!f.run_forge("check", "gitlab").status.success());
    assert!(!f.dir.path().join("checked.json").exists());
    assert!(f.writes.lock().unwrap().is_empty());
}

#[test]
fn gitlab_patch_planning_supports_forks_and_explicit_own_branch_bounds() {
    for push in [false, true] {
        for destination in ["fork", "own", "unauthorized"] {
            let f = Fixture::new();
            let mut rules = json!({
                "max":1,"protected_files":[],"protect_top_level_dot_folders":true,
                "protected_files_policy":"blocked","max_patch_size":1024,"max_patch_files":10
            });
            let (kind, fields) = if push {
                rules["target"] = json!("7");
                rules["head"] = json!("1".repeat(40));
                ("push_to_pull_request_branch", json!({"message":"Fix it"}))
            } else {
                rules["draft"] = json!(true);
                (
                    "create_pull_request",
                    json!({"title":"Fix it","body":"Reason for the change"}),
                )
            };
            let mut outputs = json!({});
            outputs[kind] = rules;
            if destination == "own" {
                outputs["own_branch_repos"] = json!([["group/subgroup/project"]]);
            }
            let mut context = gitlab_context(&f, outputs);
            context["policy"]["kind"] = json!("branch");
            context["item_kind"] = json!("pull-request");
            if push {
                context["policy"]["base"] = json!("agent-run-1");
            }
            if destination == "fork" {
                context["policy"]["push_repo"] = json!("bot/project");
            }
            write_context(&f, &context);
            let mut item = fields;
            item["type"] = json!(kind);
            item["branch"] = json!("agent-run-1");
            f.input(&item.to_string());
            patch_fixture(&f, "src/x");
            if push {
                std::fs::write(f.dir.path().join("base.json"), json!({"repo":"group/subgroup/project","ref":"agent-run-1","commit":"1".repeat(40)}).to_string()).unwrap();
            }
            let result = f.run_forge("check", "gitlab");
            assert_eq!(
                result.status.success(),
                destination != "unauthorized",
                "{kind} {destination}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                f.dir.path().join("checked.json").exists(),
                destination != "unauthorized"
            );
            assert!(f.writes.lock().unwrap().is_empty());
        }
    }
}

const COMMENT: &str =
    r#"{"type":"add_comment","repo":"owner/repo","item_number":7,"body":"Deterministic proof."}"#;

#[test]
fn valid_comment_without_run_or_ci_environment() {
    let f = Fixture::new();
    f.input(COMMENT);
    f.assert_ok("check");
    assert!(f.writes.lock().unwrap().is_empty());
    f.assert_ok("apply");
    let writes = f.writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert!(writes[0].starts_with("POST /repos/owner/repo/issues/7/comments "));
    assert!(writes[0].contains(r#""body":"Deterministic proof.""#));
}

#[test]
fn invalid_inputs_never_write() {
    for input in [
        "{bad".to_owned(),
        "x".repeat(1024 * 1024 + 1),
        COMMENT.replace("owner/repo", "other/repo"),
        COMMENT.replace(":7", ":8"),
        COMMENT.replace("item_number", "issue_number"),
        format!("{COMMENT}\n{COMMENT}\n{COMMENT}"),
        format!("{}{}", "\n".repeat(1001), COMMENT),
    ] {
        let f = Fixture::new();
        f.input(&input);
        assert!(!f.run("check").status.success());
        assert!(!f.run("apply").status.success());
        assert!(!f.dir.path().join("checked.json").exists());
        assert!(f.writes.lock().unwrap().is_empty());
    }
}

#[test]
fn changed_content_or_context_never_writes() {
    for change_context in [false, true] {
        let f = Fixture::new();
        f.input(COMMENT);
        f.assert_ok("check");
        if change_context {
            f.context(json!({"add_comment":{"max":2}}));
        } else {
            f.input(&COMMENT.replace("proof", "changed"));
        }
        assert!(!f.run("apply").status.success());
        assert!(f.writes.lock().unwrap().is_empty());
    }
}

#[test]
fn unsupported_operation_refuses_entire_batch_before_writing() {
    let f = Fixture::new();
    f.input(&format!("{COMMENT}\n{}", json!({"type":"create_issue", "repo":"owner/repo", "title":"Unsupported", "body":"This operation must make no writes."})));
    f.assert_ok("check");
    let result = f.run("apply");
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("unsupported standalone native operation")
    );
    assert!(f.writes.lock().unwrap().is_empty());
}
