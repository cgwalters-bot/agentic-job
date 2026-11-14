#![cfg(all(feature = "clap", feature = "test-support"))]
#![allow(clippy::unwrap_used)]

use std::process::{Command, Output};
use std::sync::mpsc::Receiver;

use safe_outputs::apply::testing::{Request, serve};
use serde_json::{Value, json};
use tempfile::TempDir;

const REPO: &str = "group/subgroup/project";
const PROJECT: &str = "/api/v4/projects/group%2Fsubgroup%2Fproject";

struct Fixture {
    dir: TempDir,
    requests: Receiver<Request>,
}

impl Fixture {
    fn new(outputs: Value, initial: &[&str], available: &[&str]) -> Self {
        // Separate state for #7 and !7 catches routing by iid alone. Update
        // state on PUT so replay observes the effect of the first apply.
        let mut labels = [json!(initial), json!(initial)];
        let available = json!(available);
        let (server, requests) = serve(usize::MAX, move |request| {
            let asked = request.line.trim_end_matches(" HTTP/1.1");
            let body = if asked == format!("GET {PROJECT}") {
                json!({"id":1,"path_with_namespace":REPO,"visibility":"public"})
            } else if asked == "GET /api/v4/projects/1/labels?page=1&per_page=100" {
                available.clone()
            } else if asked == "GET /api/v4/projects/1/labels?page=2&per_page=100" {
                json!([])
            } else {
                let mut response = None;
                for (index, collection) in ["issues", "merge_requests"].iter().enumerate() {
                    let item = || {
                        json!({
                            "iid":7,"project_id":1,"state":"opened","labels":labels[index],
                            "web_url":format!("https://gitlab.example/{REPO}/-/{collection}/7")
                        })
                    };
                    if asked == format!("GET {PROJECT}/{collection}/7") {
                        response = Some(item());
                    } else if asked == format!("PUT /api/v4/projects/1/{collection}/7") {
                        let current = labels[index].as_array_mut().unwrap();
                        if let Some(add) = request.body["add_labels"].as_str() {
                            current.extend(add.split(',').map(|name| json!(name)));
                        }
                        if let Some(remove) = request.body["remove_labels"].as_str() {
                            current.retain(|name| !remove.split(',').any(|r| name == r));
                        }
                        response = Some(json!({"labels":labels[index]}));
                    } else if asked == format!("POST /api/v4/projects/1/{collection}/7/notes") {
                        response = Some(json!({"id":1}));
                    }
                }
                let Some(response) = response else {
                    return (404, json!({"message":"Unexpected test route"}).to_string());
                };
                response
            };
            (200, body.to_string())
        });
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("context.json"),
            json!({
                "policy": {
                    "forge":"gitlab", "repo":REPO,
                    "clone_url":format!("{server}/{REPO}"), "base":"main",
                    "kind":"analysis", "max_outputs":2, "max_patch_bytes":1048576,
                    "safe_outputs":outputs, "contract":1
                },
                // An MR label request must not inherit this issue target.
                "server":server, "item":7, "item_kind":"issue",
                "run_url":"https://ci.example/runs/1"
            })
            .to_string(),
        )
        .unwrap();
        Self { dir, requests }
    }

    fn input(&self, requests: &[Value]) {
        std::fs::write(
            self.dir.path().join("outputs.jsonl"),
            requests
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
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

    fn ok(&self, command: &str) -> Output {
        let result = self.run(command);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        result
    }

    fn offline_check(&self) {
        self.ok("check");
        assert!(self.requests.try_recv().is_err());
    }
}

#[test]
fn labels_route_by_kind_and_replay_without_mutation() {
    for (field, collection) in [
        ("issue_number", "issues"),
        ("pull_request_number", "merge_requests"),
    ] {
        for (operation, parameter, initial) in [
            ("add_labels", "add_labels", vec!["keep"]),
            ("remove_labels", "remove_labels", vec!["keep", "triage"]),
        ] {
            let f = Fixture::new(
                json!({operation:{"max":1,"allowed":["triage"]}}),
                &initial,
                &["keep", "triage"],
            );
            f.input(&[json!({"type":operation,"repo":REPO,field:7,"labels":["triage"]})]);
            f.offline_check();
            let result = f.ok("apply");
            let url = format!("https://gitlab.example/{REPO}/-/{collection}/7");
            assert!(
                String::from_utf8_lossy(&result.stdout)
                    .lines()
                    .any(|line| line == url)
            );
            let requests: Vec<_> = f.requests.try_iter().collect();
            let writes: Vec<_> = requests
                .iter()
                .filter(|r| !r.line.starts_with("GET "))
                .collect();
            assert_eq!(writes.len(), 1, "{requests:#?}");
            assert_eq!(
                writes[0].line,
                format!("PUT /api/v4/projects/1/{collection}/7 HTTP/1.1")
            );
            // Incremental fields must not replace unrelated labels.
            assert_eq!(writes[0].body, json!({parameter:"triage"}));
            assert!(
                requests
                    .iter()
                    .all(|r| r.authorization == "Bearer loopback-test-token")
            );

            f.ok("apply");
            let replay: Vec<_> = f.requests.try_iter().collect();
            assert!(!replay.is_empty());
            assert!(
                replay.iter().all(|r| r.line.starts_with("GET ")),
                "{replay:#?}"
            );
        }
    }
}

#[test]
fn label_side_effects_refuse_the_entire_batch() {
    for (initial, available, requested, error) in [
        (vec![], vec!["triage"], "missing", "apply creates none"),
        (
            vec!["priority::low"],
            vec!["priority::low", "priority::high"],
            "priority::high",
            "would remove",
        ),
    ] {
        let f = Fixture::new(
            json!({"add_comment":{"max":1},"add_labels":{"max":1,"allowed":[requested]}}),
            &initial,
            &available,
        );
        // The earlier valid note must not escape preflight of a later label
        // request, even though check admits that label under caller bounds.
        f.input(&[
            json!({"type":"add_comment","body":"A valid issue note"}),
            json!({"type":"add_labels","repo":REPO,"pull_request_number":7,"labels":[requested]}),
        ]);
        f.offline_check();
        let result = f.run("apply");
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains(error), "{stderr}");
        let requests: Vec<_> = f.requests.try_iter().collect();
        assert!(!requests.is_empty());
        assert!(
            requests.iter().all(|r| r.line.starts_with("GET ")),
            "{requests:#?}"
        );
    }
}
