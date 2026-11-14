#![cfg(all(feature = "clap", feature = "test-support"))]
#![allow(clippy::unwrap_used)]

use std::process::{Command, Output};
use std::sync::mpsc::Receiver;

use safe_outputs::apply::testing::{Request, serve};
use serde_json::{Value, json};
use tempfile::TempDir;

const REPO: &str = "group/subgroup/project";
const BRANCH: &str = "agent-run-1";
const PROJECT: &str = "/api/v4/projects/group%2Fsubgroup%2Fproject";
const MR: &str = "GET /api/v4/projects/1/merge_requests/7 HTTP/1.1";

struct Fixture {
    dir: TempDir,
    requests: Receiver<Request>,
}

impl Fixture {
    fn new(field: &str, value: Value) -> Self {
        let head = "1".repeat(40);
        let mut mr = json!({
            "iid":7,"project_id":1,"target_project_id":1,"state":"opened",
            "source_project_id":2,"source_branch":BRANCH,"target_branch":"main",
            "sha":head,"web_url":format!("https://gitlab.example/{REPO}/-/merge_requests/7")
        });
        mr[field] = value;
        let (server, requests) = serve(64, move |request| {
            let route = request.line.trim_end_matches(" HTTP/1.1");
            let body = if route == format!("GET {PROJECT}") {
                json!({"id":1,"path_with_namespace":REPO,"visibility":"public"})
            } else if route == "GET /api/v4/projects/bot%2Fproject" {
                json!({"id":2,"path_with_namespace":"bot/project","visibility":"public",
                    "forked_from_project":{"id":1}})
            } else if request.line == MR {
                mr.clone()
            } else if route == format!("GET {PROJECT}/issues/7") {
                // A valid earlier note must not escape the later push preflight.
                json!({"iid":7,"project_id":1,"state":"opened","labels":[],
                    "web_url":format!("https://gitlab.example/{REPO}/-/issues/7")})
            } else if route == "POST /api/v4/projects/1/issues/7/notes" {
                json!({"id":1})
            } else {
                return (404, json!({"message":"Unexpected test route"}).to_string());
            };
            (200, body.to_string())
        });
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("context.json"),
            json!({
                "policy": {
                    "forge":"gitlab","repo":REPO,"push_repo":"bot/project",
                    "clone_url":format!("{server}/{REPO}"),"base":BRANCH,
                    "kind":"branch","max_outputs":2,"max_patch_bytes":1048576,"contract":1,
                    "safe_outputs": {
                        "add_comment":{"max":1},
                        "push_to_pull_request_branch": {
                            "max":1,"target":"7","head":head,"protected_files":[],
                            "protect_top_level_dot_folders":true,"protected_files_policy":"blocked",
                            "max_patch_size":1024,"max_patch_files":10
                        }
                    }
                },
                "server":server,"item":7,"item_kind":"issue","run_url":"https://ci.example/runs/1"
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("outputs.jsonl"),
            format!(
                "{}\n{}\n",
                json!({"type":"add_comment","body":"A valid issue note"}),
                json!({"type":"push_to_pull_request_branch","branch":BRANCH,"message":"Fix it"})
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("base.json"),
            json!({"repo":REPO,"ref":BRANCH,"commit":head}).to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join(format!("aw-{BRANCH}.patch")),
            format!(
                "From {head} Mon Sep 17 00:00:00 2001\nX-GH-AW-Base-Commit: {head}\n\
                 From: agent <agent@localhost>\nDate: Tue, 6 Oct 2026 21:02:35 -0400\n\
                 Subject: [PATCH] Change things\n\n---\n src/x | 1 +\n\n\
                 diff --git a/src/x b/src/x\nnew file mode 100644\nindex 0000000..587be6b\n\
                 --- /dev/null\n+++ b/src/x\n@@ -0,0 +1 @@\n+x\n"
            ),
        )
        .unwrap();
        Self { dir, requests }
    }

    fn run(&self, command: &str) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe-outputs"));
        cmd.current_dir(self.dir.path()).env_clear();
        if command == "apply" {
            cmd.env("SAFE_OUTPUTS_TOKEN", "loopback-test-token");
        }
        cmd.args([
            command,
            "--forge",
            "gitlab",
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
}

#[test]
fn push_target_changes_refuse_the_entire_batch_before_git() {
    for (field, value, expected) in [
        (
            "sha",
            json!("2".repeat(40)),
            "it moved, and is not pushed over",
        ),
        (
            "source_project_id",
            json!(3),
            "is from project 3:agent-run-1",
        ),
        (
            "source_project_id",
            Value::Null,
            "is from a deleted project:agent-run-1",
        ),
        ("source_branch", json!("main"), "is from project 2:main"),
        ("state", json!("merged"), "merge request !7 is not open"),
        (
            "target_project_id",
            json!(3),
            "!7 is not a merge request of",
        ),
        ("iid", json!(8), "!7 is not a merge request of"),
    ] {
        let f = Fixture::new(field, value);
        let checked = f.run("check");
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
        assert!(f.requests.try_recv().is_err(), "check must be offline");
        let applied = f.run("apply");
        assert!(!applied.status.success(), "{field}");
        let stderr = String::from_utf8_lossy(&applied.stderr);
        assert!(stderr.contains(expected), "{field}: {stderr}");
        let requests: Vec<_> = f.requests.try_iter().collect();
        assert!(requests.iter().any(|r| r.line == MR), "{requests:#?}");
        // Only API reads are allowed: neither an earlier note nor git's
        // info/refs or receive-pack may run when the live MR fails preflight.
        assert!(
            requests.iter().all(|r| r.line.starts_with("GET /api/v4/")),
            "{requests:#?}"
        );
        assert!(
            requests
                .iter()
                .all(|r| r.authorization == "Bearer loopback-test-token")
        );
    }
}
