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
        Self::with_merge_request_state("opened")
    }

    fn with_merge_request_state(state: &'static str) -> Self {
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
                    if request.contains("/labels?page=1&per_page=100 ") {
                        json!([{"name":"triage"}])
                    } else if request.contains("/labels?page=") {
                        json!([])
                    } else if request.contains("/merge_requests/7 ") {
                        json!({"iid":7,"project_id":1,"state":state,"labels":[],"web_url":"https://gitlab.example/group/subgroup/project/-/merge_requests/7"})
                    } else if request.contains("/issues/7 ") {
                        json!({"iid":7,"project_id":1,"state":"opened","labels":[],"web_url":"https://gitlab.example/group/subgroup/project/-/issues/7"})
                    } else {
                        json!({"id":1,"path_with_namespace":"group/subgroup/project","visibility":"public"})
                    }
                } else if request.starts_with("POST /api/v4/projects/1/issues ") {
                    json!({"iid":8,"web_url":"https://gitlab.example/group/subgroup/project/-/issues/8","labels":["triage"]})
                } else if request.starts_with("PUT /api/v4/projects/1/") {
                    json!({"state":"closed"})
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
        self.command(subcommand, forge)
            .env("SAFE_OUTPUTS_TOKEN", "loopback-test-token")
            .output()
            .unwrap()
    }

    fn command(&self, subcommand: &str, forge: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_safe-outputs"));
        command.current_dir(self.dir.path()).env_clear().args([
            subcommand,
            "--forge",
            forge,
            "--context",
            "context.json",
            "--input",
            "outputs.jsonl",
            "--checked",
            "checked.json",
        ]);
        command
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
fn standalone_gitlab_issue_uses_checked_labels_and_shared_publisher() {
    let f = Fixture::new();
    write_context(
        &f,
        &gitlab_context(&f, json!({"create_issue":{"max":1,"allowed":["triage"]}})),
    );
    f.input(r#"{"type":"create_issue","repo":"group/subgroup/project","title":"Follow-up","body":"Investigate this failure.","labels":["triage"]}"#);
    assert_gitlab_ok(&f, "check");
    assert!(f.writes.lock().unwrap().is_empty());
    assert_gitlab_ok(&f, "apply");

    let requests = f.writes.lock().unwrap();
    assert!(requests[0].starts_with("GET /api/v4/projects/group%2Fsubgroup%2Fproject "));
    let mutations: Vec<_> = requests.iter().filter(|r| !r.starts_with("GET ")).collect();
    assert_eq!(mutations.len(), 1, "{requests:#?}");
    assert!(mutations[0].starts_with("POST /api/v4/projects/1/issues "));
    let (_, body) = mutations[0].split_once("\r\n\r\n").unwrap();
    let body: Value = serde_json::from_str(body).unwrap();
    assert_eq!(body["title"], "Follow-up");
    assert_eq!(body["labels"], "triage");
    let description = body["description"].as_str().unwrap();
    assert!(description.starts_with("Investigate this failure."));
    assert!(description.contains("Generated by [safe-outputs]"));
}

#[test]
fn standalone_gitlab_missing_issue_label_refuses_before_any_batch_write() {
    let f = Fixture::new();
    write_context(
        &f,
        &gitlab_context(
            &f,
            json!({"add_comment":{"max":1},"create_issue":{"max":1,"allowed":["missing"]}}),
        ),
    );
    // The label is allowed by policy, but absent from the live project.
    // Even the valid note before the issue must not publish.
    f.input(concat!(
        "{\"type\":\"add_comment\",\"body\":\"A valid note.\"}\n",
        "{\"type\":\"create_issue\",\"title\":\"Follow-up\",\"body\":\"Investigate this failure.\",\"labels\":[\"missing\"]}"
    ));
    assert_gitlab_ok(&f, "check");
    assert!(f.writes.lock().unwrap().is_empty());
    let result = f.run_forge("apply", "gitlab");
    assert!(!result.status.success());
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains("has no label"), "{error}");
    assert!(error.contains("apply creates none"), "{error}");
    let requests = f.writes.lock().unwrap();
    assert!(!requests.is_empty());
    assert!(
        requests.iter().all(|r| r.starts_with("GET ")),
        "{requests:#?}"
    );
}

#[test]
fn standalone_gitlab_close_routes_by_request_kind() {
    for (operation, number_field, collection) in [
        ("close_issue", "issue_number", "issues"),
        (
            "close_pull_request",
            "pull_request_number",
            "merge_requests",
        ),
    ] {
        let f = Fixture::new();
        // The trusted comment target is an issue in both cases. An explicit
        // close target must use its own kind, not that default or just its iid.
        write_context(&f, &gitlab_context(&f, json!({operation:{"max":1}})));
        f.input(
            &json!({"type":operation,"repo":"group/subgroup/project",
            number_field:7,"body":"Done @all\n/merge"})
            .to_string(),
        );
        assert_gitlab_ok(&f, "check");
        assert!(f.writes.lock().unwrap().is_empty());
        let result = f.run_forge("apply", "gitlab");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let url = format!("https://gitlab.example/group/subgroup/project/-/{collection}/7");
        assert!(
            String::from_utf8_lossy(&result.stdout)
                .lines()
                .any(|line| line == url)
        );

        let requests = f.writes.lock().unwrap();
        let mutations: Vec<_> = requests.iter().filter(|r| !r.starts_with("GET ")).collect();
        assert_eq!(mutations.len(), 2, "{requests:#?}");
        assert!(
            mutations[0].starts_with(&format!("POST /api/v4/projects/1/{collection}/7/notes "))
        );
        assert!(mutations[1].starts_with(&format!("PUT /api/v4/projects/1/{collection}/7 ")));
        let body = |request: &str| -> Value {
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
        };
        assert_eq!(
            body(mutations[0]),
            json!({"body":
            "Done `@\u{200b}all`\n\u{200b}/merge\n\n> Generated by [safe-outputs](https://ci.example/runs/1)"})
        );
        assert_eq!(body(mutations[1]), json!({"state_event":"close"}));
    }
}

#[test]
fn standalone_gitlab_locked_close_refuses_before_any_batch_write() {
    let f = Fixture::with_merge_request_state("locked");
    write_context(
        &f,
        &gitlab_context(
            &f,
            json!({"add_comment":{"max":1},"close_pull_request":{"max":1}}),
        ),
    );
    f.input(concat!(
        "{\"type\":\"add_comment\",\"body\":\"Valid issue note\"}\n",
        "{\"type\":\"close_pull_request\",\"repo\":\"group/subgroup/project\",\"pull_request_number\":7,\"body\":\"Done\"}"
    ));
    assert_gitlab_ok(&f, "check");
    assert!(f.writes.lock().unwrap().is_empty());
    let result = f.run_forge("apply", "gitlab");
    assert!(!result.status.success());
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(
        error.contains("!7 is locked, which apply does not close"),
        "{error}"
    );
    let requests = f.writes.lock().unwrap();
    assert!(!requests.is_empty());
    assert!(
        requests.iter().all(|r| r.starts_with("GET ")),
        "{requests:#?}"
    );
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
fn gitlab_patch_files_are_bounded_regular_inputs_at_check_and_apply() {
    for push in [false, true] {
        for name in ["base.json", "aw-agent-run-1.patch"] {
            for damage in ["missing", "symlink", "directory", "oversized"] {
                let f = Fixture::new();
                let kind = if push {
                    "push_to_pull_request_branch"
                } else {
                    "create_pull_request"
                };
                let mut rules = json!({
                    "max":1,"protected_files":[],"protect_top_level_dot_folders":true,
                    "protected_files_policy":"blocked","max_patch_size":1024,"max_patch_files":10
                });
                if push {
                    rules["target"] = json!("7");
                    rules["head"] = json!("1".repeat(40));
                } else {
                    rules["draft"] = json!(true);
                }
                let mut context = gitlab_context(&f, json!({kind:rules}));
                context["policy"]["kind"] = json!("branch");
                context["policy"]["push_repo"] = json!("bot/project");
                let patch = patch_fixture(&f, "src/x");
                // Accept exactly the caller's patch byte bound before testing
                // its first refused byte. Base metadata has a fixed 64 KiB cap.
                context["policy"]["max_patch_bytes"] = json!(patch.len());
                if push {
                    context["policy"]["base"] = json!("agent-run-1");
                    std::fs::write(
                        f.dir.path().join("base.json"),
                        json!({"repo":"group/subgroup/project","ref":"agent-run-1","commit":"1".repeat(40)}).to_string(),
                    )
                    .unwrap();
                }
                write_context(&f, &context);
                f.input(&json!({"type":kind,"branch":"agent-run-1","title":"Fix","body":"Why","message":"Fix"}).to_string());
                let path = f.dir.path().join(name);
                let mut original = std::fs::read(&path).unwrap();
                if name == "base.json" {
                    original.resize(64 * 1024, b' ');
                    std::fs::write(&path, &original).unwrap();
                }
                assert_gitlab_ok(&f, "check");
                assert!(f.writes.lock().unwrap().is_empty());

                let outside = tempfile::tempdir().unwrap();
                match damage {
                    "missing" => std::fs::remove_file(&path).unwrap(),
                    "symlink" => {
                        // Identical bytes must still be refused: receipt
                        // equality is not a substitute for no-follow reads.
                        let target = outside.path().join("artifact");
                        std::fs::write(&target, &original).unwrap();
                        std::fs::remove_file(&path).unwrap();
                        std::os::unix::fs::symlink(&target, &path).unwrap();
                    }
                    "directory" => {
                        std::fs::remove_file(&path).unwrap();
                        std::fs::create_dir(&path).unwrap();
                    }
                    "oversized" => {
                        original.push(b' ');
                        std::fs::write(&path, original).unwrap();
                    }
                    _ => unreachable!(),
                }
                let error = match damage {
                    "missing" | "symlink" => "cannot open input as a no-follow file",
                    "directory" => "input is not a regular file",
                    "oversized" => "file exceeds byte limit",
                    _ => unreachable!(),
                };
                assert_patch_file_refused(&f, error, kind, name, damage);
            }
        }
    }
}

fn assert_patch_file_refused(f: &Fixture, error: &str, kind: &str, name: &str, damage: &str) {
    // Apply must re-read even after a valid receipt. A fresh check must not
    // issue a receipt for the same malformed artifact either.
    for command in ["apply", "check"] {
        if command == "check" {
            std::fs::remove_file(f.dir.path().join("checked.json")).unwrap();
        }
        let result = f.run_forge(command, "gitlab");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(!result.status.success(), "{command} {kind} {name} {damage}");
        assert!(
            stderr.contains(error),
            "{command} {kind} {name} {damage}: {stderr}"
        );
        assert!(f.writes.lock().unwrap().is_empty());
    }
    assert!(!f.dir.path().join("checked.json").exists());
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
fn checked_comment_destination_cannot_change_before_apply() {
    // Omit producer selectors so each changed context is independently valid:
    // refusal must come from receipt binding, not a conflicting item selector.
    for field in [
        "repo",
        "item",
        "api_url",
        "max_outputs",
        "outputs",
        "whitespace",
    ] {
        let f = Fixture::new();
        let other = Fixture::new();
        f.input(r#"{"type":"add_comment","body":"Daily assessment."}"#);
        f.assert_ok("check");
        assert!(f.writes.lock().unwrap().is_empty());
        let path = f.dir.path().join("context.json");
        let mut context: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        match field {
            "repo" => context[field] = json!("owner/other"),
            "item" => context[field] = json!(8),
            "api_url" => context[field] = json!(other.api),
            "max_outputs" => context[field] = json!(1),
            "outputs" => context[field] = json!({"add_comment":{"max":2}}),
            "whitespace" => {}
            _ => unreachable!(),
        }
        std::fs::write(&path, serde_json::to_string_pretty(&context).unwrap()).unwrap();
        let result = f.run("apply");
        assert!(!result.status.success(), "{field}");
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(
            error.contains("checked input or trusted context changed"),
            "{field}: {error}"
        );
        assert!(f.writes.lock().unwrap().is_empty(), "{field}");
        assert!(other.writes.lock().unwrap().is_empty(), "{field}");

        // A fresh check accepts the changed configuration, but does not publish.
        std::fs::remove_file(f.dir.path().join("checked.json")).unwrap();
        f.assert_ok("check");
        assert!(f.writes.lock().unwrap().is_empty(), "{field}");
        assert!(other.writes.lock().unwrap().is_empty(), "{field}");
    }
}

#[test]
fn unsupported_operation_refuses_entire_batch_before_writing() {
    for token in [None, Some("loopback-test-token")] {
        let f = Fixture::new();
        f.input(&format!("{COMMENT}\n{}", json!({"type":"create_issue", "repo":"owner/repo", "title":"Unsupported", "body":"This operation must make no writes."})));
        f.assert_ok("check");
        let mut command = f.command("apply", "github");
        if let Some(token) = token {
            command.env("SAFE_OUTPUTS_TOKEN", token);
        }
        let result = command.output().unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("unsupported standalone native operation")
        );
        assert!(f.writes.lock().unwrap().is_empty());
    }
}

#[test]
fn standalone_credentials_are_required_only_for_publication() {
    for forge in ["github", "gitlab"] {
        for token in [None, Some(""), Some(" \t\n")] {
            let f = Fixture::new();
            if forge == "gitlab" {
                write_context(&f, &gitlab_context(&f, json!({"add_comment":{"max":1}})));
            }
            f.input(r#"{"type":"add_comment","body":"A checked comment."}"#);
            let checked = f.command("check", forge).output().unwrap();
            assert!(checked.status.success(), "{forge}: {checked:?}");
            assert!(f.writes.lock().unwrap().is_empty());

            let mut command = f.command("apply", forge);
            // Ambient credentials must not turn an uncredentialed apply job
            // into a publisher. The CLI has exactly one explicit token source.
            for name in [
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GITLAB_TOKEN",
                "FORGEJO_TOKEN",
                "SAFE_OUTPUTS_PAT",
            ] {
                command.env(name, "ambient-test-token");
            }
            if let Some(token) = token {
                command.env("SAFE_OUTPUTS_TOKEN", token);
            }
            let result = command.output().unwrap();
            assert_eq!(result.status.code(), Some(1), "{forge}: {result:?}");
            let error = String::from_utf8_lossy(&result.stderr);
            let expected = if token.is_some() {
                "apply requires a nonempty SAFE_OUTPUTS_TOKEN"
            } else {
                "apply requires SAFE_OUTPUTS_TOKEN"
            };
            assert!(error.contains(expected), "{forge}: {error}");
            assert!(f.writes.lock().unwrap().is_empty(), "{forge}");

            // The same receipt remains usable with an explicit credential.
            let result = f.run_forge("apply", forge);
            assert!(result.status.success(), "{forge}: {result:?}");
            let requests = f.writes.lock().unwrap();
            assert_eq!(
                requests.iter().filter(|r| r.starts_with("POST ")).count(),
                1
            );
        }
    }
}

#[test]
fn standalone_reporting_only_batches_need_no_credentials_or_network() {
    for forge in ["github", "gitlab"] {
        let f = Fixture::new();
        let outputs = json!({"noop":{"max":1},"missing_tool":{"max":1},"missing_data":{"max":1}});
        if forge == "gitlab" {
            write_context(&f, &gitlab_context(&f, outputs));
        } else {
            write_context(
                &f,
                &json!({
                    "repo":"owner/repo", "item":7, "max_outputs":3,
                    "api_url":f.api, "outputs":outputs
                }),
            );
        }
        f.input(concat!(
            "{\"type\":\"noop\",\"message\":\"Nothing to change.\"}\n",
            "{\"type\":\"missing_tool\",\"tool\":\"compiler\",\"reason\":\"Not installed.\"}\n",
            "{\"type\":\"missing_data\",\"data_type\":\"build log\",\"reason\":\"Not available.\"}"
        ));
        for subcommand in ["check", "apply"] {
            let result = f.command(subcommand, forge).output().unwrap();
            assert!(result.status.success(), "{forge}/{subcommand}: {result:?}");
            assert!(f.writes.lock().unwrap().is_empty(), "{forge}/{subcommand}");
        }
    }
}

#[test]
fn standalone_comment_artifacts_require_bounded_regular_files() {
    for (name, limit) in [
        ("context.json", 64 * 1024),
        ("outputs.jsonl", 1024 * 1024),
        ("checked.json", 4096),
    ] {
        for replacement in ["at-limit", "oversized", "missing", "symlink", "directory"] {
            let f = Fixture::new();
            f.input(COMMENT);
            let path = f.dir.path().join(name);
            // Bind context/input padding before check. Receipt padding does not
            // change its parsed digests and is added after check creates it.
            if name != "checked.json" {
                let mut bytes = std::fs::read(&path).unwrap();
                bytes.resize(limit, b' ');
                std::fs::write(&path, bytes).unwrap();
            }
            f.assert_ok("check");
            assert!(f.writes.lock().unwrap().is_empty());
            if name == "checked.json" {
                let mut bytes = std::fs::read(&path).unwrap();
                bytes.resize(limit, b' ');
                std::fs::write(&path, bytes).unwrap();
            }
            let refusal = match replacement {
                "at-limit" => None,
                "oversized" => {
                    let mut bytes = std::fs::read(&path).unwrap();
                    bytes.push(b' ');
                    std::fs::write(&path, bytes).unwrap();
                    Some(format!("file exceeds byte limit {limit}"))
                }
                "missing" | "symlink" | "directory" => {
                    let saved = f.dir.path().join("saved.json");
                    std::fs::rename(&path, &saved).unwrap();
                    match replacement {
                        "symlink" => std::os::unix::fs::symlink(&saved, &path).unwrap(),
                        "directory" => std::fs::create_dir(&path).unwrap(),
                        _ => {}
                    }
                    Some(if replacement == "directory" {
                        "input is not a regular file".into()
                    } else {
                        "cannot open input as a no-follow file".into()
                    })
                }
                _ => unreachable!(),
            };
            // A prior valid receipt must not bypass either reader. Check does
            // not read receipts; only apply admits that artifact.
            if name != "checked.json"
                && let Some(refusal) = &refusal
            {
                let result = f.run("check");
                assert_eq!(result.status.code(), Some(1), "{name}/{replacement}");
                let error = String::from_utf8_lossy(&result.stderr);
                assert!(error.contains(refusal), "{error}");
            }
            let result = f.run("apply");
            assert_eq!(
                result.status.code(),
                Some(i32::from(refusal.is_some())),
                "{name}/{replacement}: {result:?}"
            );
            if let Some(refusal) = refusal {
                let error = String::from_utf8_lossy(&result.stderr);
                assert!(error.contains(&refusal), "{name}/{replacement}: {error}");
                assert!(f.writes.lock().unwrap().is_empty());
            } else {
                let requests = f.writes.lock().unwrap();
                assert_eq!(requests.len(), 1);
                assert!(requests[0].starts_with("POST /repos/owner/repo/issues/7/comments "));
                assert!(requests[0].contains(r#""body":"Deterministic proof.""#));
            }
        }
    }
}
