#![cfg(all(feature = "clap", feature = "test-support"))]
#![allow(clippy::unwrap_used)]

use std::process::{Command, Output};
use std::sync::mpsc::Receiver;

use safe_outputs::apply::testing::{Request, TOKEN, serve};
use serde_json::{Value, json};
use tempfile::TempDir;

struct Fixture {
    dir: TempDir,
    context: Value,
    requests: Receiver<Request>,
}

impl Fixture {
    fn new(fault: &str) -> Self {
        let mut mr: Value = serde_json::from_str(include_str!("data/inline/gitlab.json")).unwrap();
        let mut diffs: Value =
            serde_json::from_str(include_str!("data/inline/gitlab-diffs.json")).unwrap();
        match fault {
            "stale" => mr["sha"] = json!("4".repeat(40)),
            "foreign" => mr["target_project_id"] = json!(2),
            "refs" => mr["diff_refs"]["start_sha"] = Value::Null,
            "collapsed" => diffs[0]["collapsed"] = json!(true),
            "truncated" => diffs[0]["diff"] = json!("@@ -1,3 +1,3 @@\n context\n"),
            "ok" => {}
            _ => panic!("unknown fault"),
        }
        let (server, requests) = serve(100, move |request| {
            let body = match request.line.trim_end_matches(" HTTP/1.1") {
                "GET /api/v4/projects/owner%2Fname" => {
                    json!({"id":1,"path_with_namespace":"owner/name","visibility":"public"})
                }
                "GET /api/v4/projects/1/merge_requests/9" => mr.clone(),
                "GET /api/v4/projects/1/merge_requests/9/diffs?page=1&per_page=100" => {
                    diffs.clone()
                }
                "POST /api/v4/projects/1/merge_requests/9/discussions" => {
                    return (
                        201,
                        json!({"id":"discussion","notes":[{"id":42}]}).to_string(),
                    );
                }
                _ => return (404, "{}".into()),
            };
            (200, body.to_string())
        });
        Self {
            dir: tempfile::tempdir().unwrap(),
            context: json!({
                "policy": {
                    "forge":"gitlab","contract":1,"repo":"owner/name",
                    "clone_url":format!("{server}/owner/name"),"base":"main",
                    "kind":"analysis","max_outputs":2,"max_patch_bytes":1048576,
                    "safe_outputs":{"create_pull_request_review_comment":{"max":2}}
                },
                "server":server,"item":9,"item_kind":"pull-request",
                "review_head":"2".repeat(40),"run_url":"https://ci.example/runs/1"
            }),
            requests,
        }
    }

    fn input(&self, items: &[Value]) {
        std::fs::write(
            self.dir.path().join("outputs.jsonl"),
            items
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
    }

    fn run(&self, command: &str) -> Output {
        std::fs::write(
            self.dir.path().join("context.json"),
            self.context.to_string(),
        )
        .unwrap();
        Command::new(env!("CARGO_BIN_EXE_safe-outputs"))
            .current_dir(self.dir.path())
            .env_clear()
            .env("SAFE_OUTPUTS_TOKEN", TOKEN)
            .args([
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

    fn ok(&self, command: &str) -> Output {
        let result = self.run(command);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        result
    }
}

fn finding(side: &str, line: u64) -> Value {
    json!({"type":"create_pull_request_review_comment","path":"src/x",
        "side":side,"line":line,"body":"Finding for @all\n/close"})
}

#[test]
fn standalone_inline_positions_and_sanitizing() {
    for (side, line, old, new) in [
        ("LEFT", 2, Some(2), None),
        ("RIGHT", 2, None, Some(2)),
        ("RIGHT", 1, Some(1), Some(1)),
    ] {
        let f = Fixture::new("ok");
        f.input(&[finding(side, line)]);
        f.ok("check");
        assert!(f.requests.try_iter().next().is_none());
        let result = f.ok("apply");
        assert!(String::from_utf8_lossy(&result.stdout).contains("merge_requests/9#note_42"));
        let requests: Vec<_> = f.requests.try_iter().collect();
        assert!(requests.iter().all(|r| !r.line.contains("/issues/")));
        let writes: Vec<_> = requests
            .iter()
            .filter(|r| !r.line.starts_with("GET "))
            .collect();
        assert_eq!(writes.len(), 1, "{requests:#?}");
        let write = writes[0];
        assert_eq!(
            write.line,
            "POST /api/v4/projects/1/merge_requests/9/discussions HTTP/1.1"
        );
        assert_eq!(write.authorization, format!("Bearer {TOKEN}"));
        let mut position = json!({"position_type":"text","old_path":"src/x","new_path":"src/x",
            "base_sha":"1".repeat(40),"start_sha":"3".repeat(40),"head_sha":"2".repeat(40)});
        if let Some(line) = old {
            position["old_line"] = json!(line);
        }
        if let Some(line) = new {
            position["new_line"] = json!(line);
        }
        assert_eq!(write.body["position"], position);
        let body = write.body["body"].as_str().unwrap();
        assert!(body.contains("Generated by [safe-outputs]"));
        assert!(!body.contains("@all"));
        assert!(!body.lines().any(|line| line.trim_start().starts_with('/')));
    }
}

#[test]
fn standalone_inline_live_refusals_preflight_the_whole_batch() {
    for (fault, second_line, expected) in [
        ("stale", 2, "head is stale"),
        ("foreign", 2, "not a merge request"),
        ("refs", 2, "lacks diff_refs"),
        ("collapsed", 2, "diff is unavailable"),
        ("truncated", 2, "truncated diff hunk"),
        ("ok", 99, "line is outside the diff"),
    ] {
        let f = Fixture::new(fault);
        // The first finding is valid when only the second line is absent.
        f.input(&[finding("RIGHT", 2), finding("RIGHT", second_line)]);
        f.ok("check");
        assert!(f.requests.try_iter().next().is_none());
        let result = f.run("apply");
        assert!(!result.status.success(), "{fault}");
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(error.contains(expected), "{fault}: {error}");
        let requests: Vec<_> = f.requests.try_iter().collect();
        assert!(!requests.is_empty());
        assert!(
            requests.iter().all(|r| r.line.starts_with("GET ")),
            "{requests:#?}"
        );
    }
}

#[test]
fn standalone_inline_requires_caller_authority_before_network() {
    for fault in ["disabled", "issue", "missing-head", "count"] {
        let mut f = Fixture::new("ok");
        match fault {
            "disabled" => f.context["policy"]["safe_outputs"] = json!({}),
            "issue" => f.context["item_kind"] = json!("issue"),
            "missing-head" => f.context["review_head"] = Value::Null,
            "count" => {
                f.context["policy"]["safe_outputs"]["create_pull_request_review_comment"]["max"] =
                    json!(1)
            }
            _ => unreachable!(),
        }
        f.input(&[finding("RIGHT", 2), finding("LEFT", 2)]);
        assert!(!f.run("check").status.success(), "{fault}");
        assert!(!f.dir.path().join("checked.json").exists());
        assert!(!f.run("apply").status.success(), "{fault}");
        assert!(f.requests.try_iter().next().is_none());
    }
}
