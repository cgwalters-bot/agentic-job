//! Real GitLab API and fork push coverage. CI's `gitlab` job supplies a fresh
//! container; ordinary cargo test skips this test. No gitlab.com access.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

#[path = "support/forge.rs"]
mod support;
use support::{PROXY_VARS, assert_success, checked, checked_items};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");
/// GitLab's first reconfigure/migration is much slower than Forgejo's boot.
const STARTUP: Duration = Duration::from_secs(600);
const READY: Duration = Duration::from_secs(120);
/// `docker inspect` format of the container's state, for a startup failure.
const STATE: &str = "running {{.State.Running}}, exit {{.State.ExitCode}}, \
    OOMKilled {{.State.OOMKilled}}, error \"{{.State.Error}}\", finished {{.State.FinishedAt}}";
const TARGET: &str = "root/target";
const FORK: &str = "fixture-bot/target";
const RUN_URL: &str = "https://ci.example/runs/1";
/// `api` includes git-over-HTTP read/write as well as note/MR writes.
/// `write_repository` alone cannot publish notes or merge requests.
const SCOPES: &[&str] = &["api"];

struct GitLab {
    server: String,
    http: ureq::Agent,
}

impl GitLab {
    fn call(&self, token: &str, method: &str, path: &str, body: Option<&Value>) -> Value {
        let url = format!("{}/api/v4{path}", self.server);
        let response = match (method, body) {
            ("GET", None) => self
                .http
                .get(&url)
                .header("authorization", &format!("Bearer {token}"))
                .call(),
            ("POST", Some(body)) => self
                .http
                .post(&url)
                .header("authorization", &format!("Bearer {token}"))
                .header("content-type", "application/json")
                .send(body.to_string().as_bytes()),
            _ => panic!("unsupported fixture request"),
        };
        // Never print API bodies or transport errors: they could echo a token.
        let mut response =
            response.unwrap_or_else(|_| panic!("{method} {path}: transport failure"));
        assert!(
            response.status().is_success(),
            "{method} {path}: {}",
            response.status()
        );
        serde_json::from_str(&response.body_mut().read_to_string().unwrap()).unwrap()
    }

    fn get(&self, token: &str, path: &str) -> Value {
        self.call(token, "GET", path, None)
    }

    fn post(&self, token: &str, path: &str, body: Value) -> Value {
        self.call(token, "POST", path, Some(&body))
    }
}

fn bootstrap() -> (GitLab, String, String) {
    let server = std::env::var("AGENTIC_JOB_TEST_GITLAB").expect("set AGENTIC_JOB_TEST_GITLAB");
    let container = std::env::var("AGENTIC_JOB_TEST_GITLAB_CONTAINER")
        .expect("set AGENTIC_JOB_TEST_GITLAB_CONTAINER");
    let forge = GitLab {
        server,
        http: ureq::Agent::config_builder()
            .proxy(None)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(10)))
            .build()
            .into(),
    };
    // The port is published unchanged, so the server URL also reaches nginx
    // from inside the container.
    let readiness = format!("{}/-/readiness?all=1", forge.server.trim_end_matches('/'));
    let start = Instant::now();
    loop {
        // Monitoring endpoints admit container loopback, not the Docker
        // bridge address seen on a host-published port. Do not widen that
        // allowlist just to probe readiness.
        let ready = Command::new("docker")
            .args([
                "exec",
                &container,
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "--output",
                "/dev/null",
                &readiness,
            ])
            .output()
            .unwrap();
        if ready.status.success() {
            break;
        }
        // A failed reconfigure stops the container; waiting out STARTUP
        // would only hide why. CI's diagnostics steps print its log tail.
        let state = Command::new("docker")
            .args(["inspect", "--format", STATE, &container])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&state.stdout);
        assert!(
            stdout.starts_with("running true,"),
            "GitLab container stopped after {:.0}s: {} (inspect {}: {})",
            start.elapsed().as_secs_f64(),
            stdout.trim(),
            state.status,
            String::from_utf8_lossy(&state.stderr).trim()
        );
        assert!(
            start.elapsed() < STARTUP,
            "GitLab did not become ready within {STARTUP:?}: curl status {}, {}",
            ready.status,
            String::from_utf8_lossy(&ready.stderr)
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    eprintln!(
        "GitLab readiness wait: {:.1}s (container started before compilation)",
        start.elapsed().as_secs_f64()
    );
    // Rails generates throwaway credentials at runtime. Only this captured
    // stdout receives tokens; neither docker nor apply inherits a forge secret.
    let script = format!(
        r#"
require 'securerandom'
require 'json'
bot = User.new(username: 'fixture-bot', name: 'Fixture Bot', email: 'bot@example.org', password: SecureRandom.hex(24), confirmed_at: Time.now)
bot.skip_confirmation!
bot.assign_personal_namespace(Organizations::Organization.default_organization)
bot.save!
tokens = [User.find_by_username!('root'), bot].map do |user|
  token = user.personal_access_tokens.create!(name: 'apply-fixture', scopes: {scopes}, expires_at: Date.today + 1)
  raw = SecureRandom.hex(24)
  token.set_token(raw)
  token.save!
  raw
end
puts JSON.generate(tokens)
"#,
        scopes = serde_json::to_string(SCOPES).unwrap()
    );
    let mut child = Command::new("docker")
        .args(["exec", "-i", &container, "gitlab-rails", "runner", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "GitLab Rails bootstrap failed (output withheld to protect fixture tokens)"
    );
    let tokens: Vec<String> =
        serde_json::from_slice(&output.stdout).expect("Rails must return tokens as JSON");
    (forge, tokens[0].clone(), tokens[1].clone())
}

fn policy(forge: &GitLab, dir: &Path, name: &str, outputs: &str) -> PathBuf {
    let authority = forge.server.strip_prefix("http://").unwrap();
    let allow = dir.join(format!("{name}.toml"));
    std::fs::write(
        &allow,
        format!(
            r#"
hosts = ["{authority}"]
allow_http = ["{authority}"]
repos = ["{TARGET}"]
bases = ["main"]
max_outputs = 2
max_patch_bytes = 65536
max_patch_files = 10
[gitlab]
push_repo = "{FORK}"
[gitlab.outputs]
{outputs}
"#
        ),
    )
    .unwrap();
    let types: Vec<_> = outputs
        .lines()
        .filter_map(|line| line.split_once(" = ").map(|(name, _)| name))
        .collect();
    let output = Command::new(BIN)
        .args(["policy", "--allow"])
        .arg(allow)
        .args([
            "--repo",
            TARGET,
            "--clone-url",
            &format!("{}/{TARGET}", forge.server),
            "--base",
            "main",
            "--kind",
            "branch",
            "--outputs",
            &types.join(","),
            "--max-outputs",
            "max",
        ])
        .output()
        .unwrap();
    assert_success("policy", &output);
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, output.stdout).unwrap();
    path
}

fn apply(
    forge: &GitLab,
    policy: &Path,
    checked: &Path,
    token: &str,
    number: u64,
    kind: &str,
) -> Output {
    let mut command = Command::new(BIN);
    for name in PROXY_VARS {
        command.env_remove(name);
    }
    command
        .args([
            "apply",
            "--forge",
            "gitlab",
            "--server",
            &forge.server,
            "--repo",
            TARGET,
        ])
        .arg("--policy")
        .arg(policy)
        .arg("--checked")
        .arg(checked)
        .args([
            "--comment-target",
            &number.to_string(),
            "--comment-target-kind",
            kind,
            "--run-url",
            RUN_URL,
            "--push-repo",
            FORK,
        ])
        .env("GITLAB_TOKEN", token)
        .output()
        .unwrap()
}

fn wait_for(forge: &GitLab, token: &str, path: &str, ready: impl Fn(&Value) -> bool) -> Value {
    let start = Instant::now();
    loop {
        let value = forge.get(token, path);
        if ready(&value) {
            return value;
        }
        assert!(
            start.elapsed() < READY,
            "GitLab fixture did not settle: {path}"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
fn cached_branch_list_is_polled_until_push_appears() {
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let forge = GitLab {
        server: format!("http://{}", listener.local_addr().unwrap()),
        http: ureq::Agent::config_builder().proxy(None).build().into(),
    };
    let server = std::thread::spawn(move || {
        for names in [vec!["main"], vec!["agent-run", "main"]] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = BufReader::new(&mut stream);
            let mut line = String::new();
            request.read_line(&mut line).unwrap();
            assert!(line.starts_with("GET /api/v4/projects/2/repository/branches "));
            loop {
                line.clear();
                assert_ne!(request.read_line(&mut line).unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
            }
            let body = json!(
                names
                    .iter()
                    .map(|name| json!({"name": name}))
                    .collect::<Vec<_>>()
            )
            .to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    let branches = wait_for(&forge, "unused", "/projects/2/repository/branches", |v| {
        v.as_array().unwrap().len() == 2
    });
    assert_eq!(branches[0]["name"], "agent-run");
    assert_eq!(branches[1]["name"], "main");
    server.join().unwrap();
}

#[test]
fn protected_patch_is_refused_offline() {
    let forge = GitLab {
        server: "http://127.0.0.1:1".into(),
        http: ureq::Agent::new_with_defaults(),
    };
    let dir = tempfile::tempdir().unwrap();
    let publishing = policy(
        &forge,
        dir.path(),
        "publishing",
        "create_pull_request = { max = 1 }\nadd_comment = { max = 1 }",
    );
    let protected = dir.path().join("protected");
    checked(
        &protected,
        &"1".repeat(40),
        "agent-protected",
        ".gitlab-ci.yml",
        "@all\n/close\n",
    );
    let output = apply(&forge, &publishing, &protected, "unused", 1, "issue");
    assert_protected_refusal(&output, "unused");
}

fn assert_protected_refusal(output: &Output, token: &str) {
    // Apply's diagnostics should already redact the credential. Redact again
    // before displaying a bounded excerpt if the refusal changes in CI.
    let stderr: String = String::from_utf8_lossy(&output.stderr)
        .replace(token, "[REDACTED]")
        .chars()
        .take(4096)
        .collect();
    assert_eq!(output.status.code(), Some(1));
    // .gitlab-ci.yml is structurally protected by its .git prefix, before
    // the configurable protected-files check is reached.
    assert!(
        stderr.contains("\".gitlab-ci.yml\": protected path"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
#[ignore = "needs a GitLab CE container; CI's gitlab job runs it"]
fn apply_publishes_to_gitlab() {
    let (forge, admin, token) = bootstrap();
    let target = forge.post(&admin, "/projects", json!({"name": "target", "visibility": "public", "initialize_with_readme": true, "default_branch": "main"}));
    let id = target["id"].as_u64().unwrap();
    let project = format!("/projects/{id}");
    forge.post(&admin, &format!("{project}/repository/files/inline.txt"), json!({"branch": "main", "content": "before\ncontext\n", "commit_message": "Seed inline fixture"}));
    let issue = forge.post(
        &admin,
        &format!("{project}/issues"),
        json!({"title": "Something to fix"}),
    );
    let iid = issue["iid"].as_u64().unwrap();
    let fork = forge.post(
        &token,
        &format!("{project}/fork"),
        json!({"namespace": "fixture-bot"}),
    );
    let fork_id = fork["id"].as_u64().unwrap();
    wait_for(&forge, &token, &format!("/projects/{fork_id}"), |v| {
        v["import_status"] == "finished"
    });
    let main = forge.get(&token, &format!("{project}/repository/branches/main"));
    let base = main["commit"]["id"].as_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let publishing = policy(
        &forge,
        dir.path(),
        "publishing",
        "create_pull_request = { max = 1 }\nadd_comment = { max = 1 }",
    );
    let mention = "@all\n/close\n";
    let footer = format!("\n\n> Generated by [agentic-job]({RUN_URL})");
    let neutralized = "@\u{200b}all\n\u{200b}/close\n";

    let protected = dir.path().join("protected");
    checked(
        &protected,
        base,
        "agent-protected",
        ".gitlab-ci.yml",
        mention,
    );
    let output = apply(&forge, &publishing, &protected, &token, iid, "issue");
    assert_protected_refusal(&output, &token);
    for path in [
        format!("{project}/issues/{iid}/notes"),
        format!("{project}/merge_requests"),
    ] {
        assert!(forge.get(&token, &path).as_array().unwrap().is_empty());
    }
    for path in [project.clone(), format!("/projects/{fork_id}")] {
        let branches = forge.get(&token, &format!("{path}/repository/branches"));
        let branches = branches.as_array().unwrap();
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0]["name"], "main");
    }

    let accepted = dir.path().join("accepted");
    checked(&accepted, base, "agent-run", "src/x", mention);
    let output = apply(&forge, &publishing, &accepted, &token, iid, "issue");
    assert_success("apply GitLab", &output);
    let urls = String::from_utf8(output.stdout).unwrap();
    assert_eq!(urls.lines().count(), 2);
    let notes = forge.get(&token, &format!("{project}/issues/{iid}/notes"));
    let [note] = notes.as_array().unwrap().as_slice() else {
        panic!("expected one issue note")
    };
    assert_eq!(note["author"]["username"], "fixture-bot");
    assert_eq!(note["body"], format!("Done, {neutralized}.{footer}"));
    assert_eq!(
        forge.get(&token, &format!("{project}/issues/{iid}"))["state"],
        "opened"
    );
    let pulls = forge.get(&token, &format!("{project}/merge_requests"));
    let [pull] = pulls.as_array().unwrap().as_slice() else {
        panic!("expected one MR")
    };
    assert_eq!(pull["source_project_id"], fork_id);
    assert_eq!(pull["target_project_id"], id);
    assert_eq!(pull["author"]["username"], "fixture-bot");
    assert_eq!(pull["source_branch"], "agent-run");
    assert_eq!(pull["target_branch"], "main");
    assert_eq!(pull["title"], "Draft: Fix it");
    assert_eq!(pull["description"], format!("Why, {neutralized}.{footer}"));
    assert!(urls.lines().any(|url| pull["web_url"] == url));
    let branches = forge.get(&token, &format!("{project}/repository/branches"));
    assert_eq!(branches.as_array().unwrap().len(), 1);
    // The refusal check above primes GitLab's 30-second branch-list response
    // cache. A successful push does not invalidate that API cache immediately.
    let branches = wait_for(
        &forge,
        &token,
        &format!("/projects/{fork_id}/repository/branches"),
        |v| v.as_array().unwrap().len() == 2,
    );
    assert_eq!(branches.as_array().unwrap().len(), 2);
    assert_eq!(branches[0]["name"], "agent-run");
    assert_eq!(branches[1]["name"], "main");
    assert_eq!(branches[1]["commit"]["id"], base);
    let diffs = forge.get(
        &token,
        &format!("{project}/merge_requests/{}/diffs", pull["iid"]),
    );
    assert_eq!(diffs.as_array().unwrap().len(), 1);
    assert_eq!(diffs[0]["new_path"], "src/x");

    // Use the same minimum-scope bot PAT for fixture pushes and apply.
    support::git(
        dir.path(),
        "oauth2",
        &token,
        &["clone", &format!("{}/{FORK}.git", forge.server), "checkout"],
    );
    let checkout = dir.path().join("checkout");
    support::git(
        &checkout,
        "oauth2",
        &token,
        &["checkout", "-b", "inline-review", "origin/main"],
    );
    std::fs::write(checkout.join("inline.txt"), "after\ncontext\n").unwrap();
    support::git(
        &checkout,
        "oauth2",
        &token,
        &["commit", "-am", "Change inline fixture"],
    );
    support::git(
        &checkout,
        "oauth2",
        &token,
        &["push", "origin", "inline-review"],
    );
    let inline = forge.post(&token, &format!("/projects/{fork_id}/merge_requests"), json!({"source_branch": "inline-review", "target_branch": "main", "target_project_id": id, "title": "Inline fixture"}));
    let number = inline["iid"].as_u64().unwrap();
    let path = format!("{project}/merge_requests/{number}");
    let inline = wait_for(&forge, &token, &path, |v| {
        v["diff_refs"]["head_sha"].is_string()
    });
    let head = inline["diff_refs"]["head_sha"].as_str().unwrap();
    let publishing = policy(
        &forge,
        dir.path(),
        "inline",
        "create_pull_request_review_comment = { max = 1 }",
    );
    for side in ["RIGHT", "LEFT"] {
        let checked = dir.path().join(side);
        checked_items(
            &checked,
            &[
                json!({"type": "create_pull_request_review_comment", "repo": TARGET,
            "pull_request_number": number, "path": "inline.txt", "line": 1, "side": side, "body": "@all\n/close"}),
            ],
        );
        let report_path = checked.join("report.json");
        let mut report: Value =
            serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
        report["inline_target"] = json!({"repo": TARGET, "number": number, "head": head});
        std::fs::write(report_path, report.to_string()).unwrap();
        let output = apply(
            &forge,
            &publishing,
            &checked,
            &token,
            number,
            "pull-request",
        );
        assert_success("apply GitLab inline", &output);
    }
    let discussions = forge.get(&token, &format!("{path}/discussions"));
    let notes: Vec<_> = discussions
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|d| d["notes"].as_array().unwrap())
        .filter(|note| note["position"].is_object())
        .collect();
    assert_eq!(notes.len(), 2);
    for (side, key, absent) in [
        ("RIGHT", "new_line", "old_line"),
        ("LEFT", "old_line", "new_line"),
    ] {
        let note = notes
            .iter()
            .find(|note| note["position"][key] == 1)
            .unwrap_or_else(|| panic!("missing {side} comment"));
        assert!(note["position"][absent].is_null());
        assert_eq!(note["position"]["new_path"], "inline.txt");
        assert_eq!(note["position"]["old_path"], "inline.txt");
        assert_eq!(note["position"]["head_sha"], head);
        assert_eq!(note["author"]["username"], "fixture-bot");
        assert_eq!(note["body"], format!("{}{footer}", neutralized.trim_end()));
    }
    assert_eq!(forge.get(&token, &path)["state"], "opened");
}
