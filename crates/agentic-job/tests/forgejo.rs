//! `agentic-job apply` against a real Forgejo, where the unit tests of
//! `apply::forgejo` have recorded answers: the API, its token scopes and
//! the git push to a fork, as a release of the forge has them.
//!
//! Needs a fresh Forgejo at `AGENTIC_JOB_TEST_FORGEJO` (`http://127.0.0.1:3000`)
//! running in the container `AGENTIC_JOB_TEST_FORGEJO_CONTAINER`, where
//! `docker exec` makes its admin; a second run needs a new container.
//! CI's `forgejo` job starts one and runs:
//!
//! ```text
//! cargo test --test forgejo -- --ignored --nocapture
//! ```

// Helpers outside a #[test] function are still test code.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

#[path = "support/forge.rs"]
mod support;
use support::{PROXY_VARS, assert_success, checked_items};

const SERVER_VAR: &str = "AGENTIC_JOB_TEST_FORGEJO";
const CONTAINER_VAR: &str = "AGENTIC_JOB_TEST_FORGEJO_CONTAINER";

/// How long a starting server has to answer its health check.
const STARTUP: Duration = Duration::from_secs(120);

/// `admin` is a name Forgejo reserves.
const ADMIN: &str = "forge-admin";
const BOT: &str = "bot";
/// Fixtures of a throwaway server, not secrets.
const PASSWORD: &str = "test-password-not-secret";
/// What apply needs and no more: read the repositories, push the branch,
/// open the pull request, comment, create labelled issues and close items.
const SCOPES: &[&str] = &["write:repository", "write:issue"];

const NAME: &str = "target";
const RUN_URL: &str = "https://ci.example/runs/1";

/// One user's way in to the API.
enum Auth<'a> {
    Basic(&'a str),
    Token(&'a str),
}

struct Forge {
    server: String,
    http: ureq::Agent,
}

impl Forge {
    /// Sends METHOD to PATH under the API, with BODY, and returns the
    /// status and the JSON answer.
    fn call(&self, auth: &Auth, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
        let url = format!("{}/api/v1{path}", self.server);
        let authorization = match auth {
            Auth::Basic(user) => format!("Basic {}", STANDARD.encode(format!("{user}:{PASSWORD}"))),
            Auth::Token(token) => format!("token {token}"),
        };
        let response = match (method, body) {
            ("GET", None) => self
                .http
                .get(&url)
                .header("authorization", &authorization)
                .call(),
            ("PUT", Some(body)) => self
                .http
                .put(&url)
                .header("authorization", &authorization)
                .header("content-type", "application/json")
                .send(body.to_string().as_bytes()),
            ("POST", Some(body)) => self
                .http
                .post(&url)
                .header("authorization", &authorization)
                .header("content-type", "application/json")
                .send(body.to_string().as_bytes()),
            _ => panic!("{method} {path} with {body:?}"),
        };
        let mut response = response.unwrap_or_else(|err| panic!("{method} {path}: {err}"));
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    fn get(&self, auth: &Auth, path: &str) -> Value {
        let (status, answer) = self.call(auth, "GET", path, None);
        assert_eq!(status, 200, "GET {path}: {answer}");
        answer
    }

    fn post(&self, auth: &Auth, path: &str, body: &Value) -> Value {
        let (status, answer) = self.call(auth, "POST", path, Some(body));
        assert!(
            (200..300).contains(&status),
            "POST {path}: {status} {answer}"
        );
        answer
    }
}

/// A server that answers, with its admin made.
fn forge() -> Forge {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    let server = var(SERVER_VAR).trim_end_matches('/').to_owned();
    let container = var(CONTAINER_VAR);
    let http = ureq::Agent::config_builder()
        .proxy(None)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let forge = Forge { server, http };
    let start = Instant::now();
    loop {
        let healthy = forge
            .http
            .get(format!("{}/api/healthz", forge.server))
            .call()
            .is_ok_and(|response| response.status().is_success());
        if healthy {
            break;
        }
        assert!(
            start.elapsed() < STARTUP,
            "{} does not answer",
            forge.server
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    // The API makes no first admin; the server's own CLI does, as its
    // user, not root.
    let output = Command::new("docker")
        .args(["exec", "--user", "git", &container])
        .args(["forgejo", "admin", "user", "create", "--admin"])
        .args(["--username", ADMIN, "--password", PASSWORD])
        .args([
            "--email",
            "admin@example.org",
            "--must-change-password=false",
        ])
        .output()
        .unwrap();
    assert_success("forgejo admin user create", &output);
    forge
}

/// The bounds' outputs for a comment and a pull request.
const PUBLISHING: &str = r#"
create_pull_request = { max = 1 }
add_comment = { max = 1 }
"#;

/// The labels' bounds: `status/protected` blocked, and the label named
/// as `bug`'s ID not allowed.
const LABELLING: &str = r#"
add_labels = { max = 2, allowed = ["bug", "Docs", "docs", "status/triaged"], blocked = ["status/protected"] }
remove_labels = { max = 2, allowed = ["bug", "area/apply"], blocked = ["status/protected"] }
"#;

/// What `policy` writes in DIR as NAME for this server's target, from
/// bounds that name the bot's fork and allow OUTPUTS.
fn policy(forge: &Forge, dir: &Path, name: &str, outputs: &str) -> PathBuf {
    let authority = forge.server.strip_prefix("http://").unwrap();
    let bounds = format!(
        r#"
hosts = ["{authority}"]
allow_http = ["{authority}"]
repos = ["{ADMIN}/{NAME}"]
bases = ["main"]
max_outputs = 2
max_patch_bytes = 65536
max_patch_files = 10

[forgejo]
push_repo = "{BOT}/{NAME}"

[forgejo.outputs]
{outputs}"#
    );
    let allow = dir.join(format!("{name}.toml"));
    std::fs::write(&allow, bounds).unwrap();
    let types: Vec<&str> = outputs
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .map(|(output, _)| output)
        .collect();
    let output = Command::new(BIN)
        .arg("policy")
        .arg("--allow")
        .arg(&allow)
        .args(["--repo", &format!("{ADMIN}/{NAME}")])
        .args(["--clone-url", &format!("{}/{ADMIN}/{NAME}", forge.server)])
        .args(["--base", "main", "--kind", "branch"])
        .args(["--outputs", &types.join(",")])
        .args(["--max-outputs", "max"])
        .output()
        .unwrap();
    assert_success("agentic-job policy", &output);
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, &output.stdout).unwrap();
    path
}

/// A checked upload in DIR, as check's job leaves it: a comment, and a
/// pull request on BRANCH adding FILE on BASE, each mentioning the admin.
fn checked(dir: &Path, base: &str, branch: &str, file: &str) {
    support::checked(dir, base, branch, file, &format!("@{ADMIN}"));
}

/// The names of the labels of issue 1 of REPO, sorted.
fn labels(forge: &Forge, auth: &Auth, repo: &str) -> Vec<String> {
    let answer = forge.get(auth, &format!("/repos/{repo}/issues/1/labels"));
    let mut names: Vec<String> = answer
        .as_array()
        .unwrap()
        .iter()
        .map(|label| label["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

/// Runs apply as a caller's job does, without a proxy git would send the
/// loopback server's traffic to.
fn apply(forge: &Forge, policy: &Path, checked: &Path, token: &str) -> Output {
    apply_to(forge, policy, checked, token, 1)
}

fn apply_to(forge: &Forge, policy: &Path, checked: &Path, token: &str, number: u64) -> Output {
    let mut command = Command::new(BIN);
    for name in PROXY_VARS {
        command.env_remove(name);
    }
    command
        .args(["apply", "--forge", "forgejo", "--server", &forge.server])
        .args(["--repo", &format!("{ADMIN}/{NAME}")])
        .arg("--policy")
        .arg(policy)
        .arg("--checked")
        .arg(checked)
        .args([
            "--comment-target",
            &number.to_string(),
            "--run-url",
            RUN_URL,
        ])
        .args(["--push-repo", &format!("{BOT}/{NAME}")])
        .env("FORGEJO_TOKEN", token)
        .output()
        .unwrap()
}

/// Push fixture commits with the same scoped token apply uses.
fn git(dir: &Path, token: &str, args: &[&str]) {
    support::git(dir, BOT, token, args);
}

/// Exercise diff positions and the pending-review guard on the real API.
fn inline_reviews(forge: &Forge, dir: &Path, token: &str, footer: &str, neutralized: &str) {
    let bot = Auth::Token(token);
    let target = format!("{ADMIN}/{NAME}");
    let checkout = dir.join("inline-checkout");
    git(
        dir,
        token,
        &[
            "clone",
            &format!("{}/{target}.git", forge.server),
            "inline-checkout",
        ],
    );
    std::fs::write(checkout.join("inline.txt"), "before\ncontext\n").unwrap();
    git(&checkout, token, &["add", "inline.txt"]);
    git(&checkout, token, &["commit", "-m", "Seed inline fixture"]);
    git(&checkout, token, &["push", "origin", "main"]);
    git(&checkout, token, &["checkout", "-b", "inline-review"]);
    std::fs::write(checkout.join("inline.txt"), "after\ncontext\n").unwrap();
    git(
        &checkout,
        token,
        &["commit", "-am", "Change inline fixture"],
    );
    git(&checkout, token, &["push", "origin", "inline-review"]);
    // The admin opens it so the apply identity is a reviewer, not the author.
    let pull = forge.post(
        &Auth::Basic(ADMIN),
        &format!("/repos/{target}/pulls"),
        &json!({"title": "Inline fixture", "head": "inline-review", "base": "main"}),
    );
    let number = pull["number"].as_u64().unwrap();
    let head = pull["head"]["sha"].as_str().unwrap();
    let base = pull["base"]["sha"].as_str().unwrap();
    assert_ne!(base, head);
    assert_eq!(pull["merge_base"], base);
    let commits = Command::new("git")
        .current_dir(&checkout)
        .args(["rev-parse", "main", "inline-review"])
        .output()
        .unwrap();
    assert_success("git rev-parse fixture commits", &commits);
    assert_eq!(
        String::from_utf8(commits.stdout)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        [base, head]
    );
    let reviews_path = format!("/repos/{target}/pulls/{number}/reviews");
    let publishing = policy(
        forge,
        dir,
        "inline",
        "add_comment = { max = 1 }\ncreate_pull_request_review_comment = { max = 1 }\n",
    );
    let publish = |name: &str, head: &str, side: &str, line: u64, earlier_comment: bool| {
        let checked = dir.join(name);
        let mut items = Vec::new();
        if earlier_comment {
            items.push(json!({"type": "add_comment", "body": "Must not appear."}));
        }
        items.push(json!({
            "type": "create_pull_request_review_comment", "repo": target,
            "pull_request_number": number, "path": "inline.txt", "side": side,
            "line": line, "body": format!("{side} finding, @{ADMIN}.")
        }));
        checked_items(&checked, &items);
        let report_path = checked.join("report.json");
        let mut report: Value =
            serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
        report["inline_target"] = json!({"repo": target, "number": number, "head": head});
        std::fs::write(report_path, report.to_string()).unwrap();
        apply_to(forge, &publishing, &checked, token, number)
    };
    for (index, side) in ["RIGHT", "LEFT"].into_iter().enumerate() {
        let before = forge.get(&bot, &reviews_path);
        let output = publish(side, head, side, 1, false);
        assert_success("agentic-job apply inline", &output);
        let checked: Value =
            serde_json::from_slice(&std::fs::read(dir.join(side).join("report.json")).unwrap())
                .unwrap();
        let current = forge.get(&bot, &format!("/repos/{target}/pulls/{number}"));
        assert_eq!(current["head"]["sha"], head);
        assert_eq!(
            checked["inline_target"],
            json!({"repo": target, "number": number, "head": current["head"]["sha"]})
        );
        let reviews = forge.get(&bot, &reviews_path);
        let reviews = reviews.as_array().unwrap();
        assert_eq!(reviews.len(), index + 1);
        let review = reviews
            .iter()
            .find(|review| {
                !before
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|old| old["id"] == review["id"])
            })
            .unwrap();
        assert_eq!(review["state"], "COMMENT");
        assert_eq!(review["user"]["login"], BOT);
        // The submitted review binds the checked current head on BOTH sides,
        // independently of the blame-based commit returned for its comment.
        assert_eq!(review["commit_id"], head);
        let comments = forge.get(&bot, &format!("{reviews_path}/{}/comments", review["id"]));
        let [comment] = comments.as_array().unwrap().as_slice() else {
            panic!("{comments}")
        };
        assert_eq!(comment["path"], "inline.txt");
        assert_eq!(comment["pull_request_review_id"], review["id"]);
        // Observed on CI's pinned Forgejo v15.0.11: RIGHT added line ->
        // head, position=1/original_position=0; LEFT deleted line -> base,
        // position=0/original_position=1. services/pull/review.go's
        // CreateCodeCommentKnownReviewID uses LineBlame/ReverseLineBlame;
        // services/convert/pull_review.go exports CommitSHA and signed Line.
        // These equal head/base for THIS one-change fixture, not all PRs.
        // https://codeberg.org/forgejo/forgejo/src/tag/v15.0.11/services/pull/review.go
        assert_eq!(
            comment["commit_id"],
            if side == "RIGHT" { head } else { base }
        );
        assert_eq!(comment["position"], if side == "RIGHT" { 1 } else { 0 });
        assert_eq!(
            comment["original_position"],
            if side == "LEFT" { 1 } else { 0 }
        );
        assert_eq!(
            comment["body"],
            format!("{side} finding, {neutralized}.{footer}")
        );
    }

    // An earlier valid operation must not write when inline preflight refuses.
    // Snapshot review comments too: a pending review must remain unpublished.
    let snapshot = || {
        let reviews = forge.get(&bot, &reviews_path);
        let comments: Vec<_> = reviews
            .as_array()
            .unwrap()
            .iter()
            .map(|review| forge.get(&bot, &format!("{reviews_path}/{}/comments", review["id"])))
            .collect();
        let issue_comments = forge.get(&bot, &format!("/repos/{target}/issues/{number}/comments"));
        (reviews, comments, issue_comments)
    };
    let refuse = |name: &str, head: &str, line: u64, message: &str| {
        let before = snapshot();
        let output = publish(name, head, "RIGHT", line, true);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{output:?}"
        );
        assert!(output.stdout.is_empty(), "{output:?}");
        assert_eq!(snapshot(), before);
    };
    refuse("outside-diff", head, 100, "line is outside the diff");

    std::fs::write(checkout.join("inline.txt"), "new head\ncontext\n").unwrap();
    git(&checkout, token, &["commit", "-am", "Move inline head"]);
    git(&checkout, token, &["push", "origin", "inline-review"]);
    // PR synchronization after a push is asynchronous, and Forgejo marks the
    // earlier reviews stale only after moving the head (services/pull/pull.go,
    // ValidatePullRequest): wait for both, or a later snapshot sees the flip.
    let start = Instant::now();
    let current = loop {
        let current = forge.get(&bot, &format!("/repos/{target}/pulls/{number}"));
        let reviews = forge.get(&bot, &reviews_path);
        if current["head"]["sha"] != head
            && reviews
                .as_array()
                .unwrap()
                .iter()
                .all(|review| review["stale"] == true)
        {
            break current;
        }
        assert!(
            start.elapsed() < STARTUP,
            "PR head did not move, or its reviews did not go stale, after push"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    refuse("stale-inline", head, 1, "head is stale");
    let head = current["head"]["sha"].as_str().unwrap();
    let pending = forge.post(
        &bot,
        &reviews_path,
        &json!({"event": "PENDING", "body": "Unchecked draft review.", "commit_id": head, "comments": [{
            "path": "inline.txt", "new_position": 1, "old_position": 0,
            "body": "Unchecked draft must stay pending."
        }]}),
    );
    assert_eq!(pending["state"], "PENDING");
    assert_eq!(pending["user"]["login"], BOT);
    refuse(
        "pending-inline",
        head,
        1,
        "pending review by the apply identity",
    );
}

/// The names of REPO's branches.
fn branches(forge: &Forge, auth: &Auth, repo: &str) -> Vec<String> {
    let answer = forge.get(auth, &format!("/repos/{repo}/branches"));
    let mut names: Vec<String> = answer
        .as_array()
        .unwrap()
        .iter()
        .map(|branch| branch["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

#[test]
#[ignore = "needs a Forgejo container; CI's forgejo job runs it"]
fn apply_publishes_to_forgejo() {
    let forge = forge();
    let admin = Auth::Basic(ADMIN);
    forge.post(
        &admin,
        "/admin/users",
        &json!({"username": BOT, "email": "bot@example.org", "password": PASSWORD,
                "must_change_password": false}),
    );
    let token = forge.post(
        &Auth::Basic(BOT),
        &format!("/users/{BOT}/tokens"),
        &json!({"name": "apply", "scopes": SCOPES}),
    );
    let token = token["sha1"].as_str().unwrap();
    let bot = Auth::Token(token);
    let target = format!("{ADMIN}/{NAME}");
    let fork = format!("{BOT}/{NAME}");
    forge.post(
        &admin,
        "/user/repos",
        &json!({"name": NAME, "auto_init": true, "default_branch": "main"}),
    );
    let issue = forge.post(
        &admin,
        &format!("/repos/{target}/issues"),
        &json!({"title": "Something to fix"}),
    );
    assert_eq!(issue["number"], 1);
    forge.post(&bot, &format!("/repos/{target}/forks"), &json!({}));
    let main = forge.get(&admin, &format!("/repos/{target}/branches/main"));
    let base = main["commit"]["id"].as_str().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let publishing = policy(&forge, dir.path(), "publishing", PUBLISHING);
    let footer = format!("\n\n> Generated by [agentic-job]({RUN_URL})");
    let neutralized = format!("@\u{200b}{ADMIN}");

    // A patch to the forge's own CI configuration is protected: apply
    // refuses the whole hand-back before its first write.
    let protected = dir.path().join("protected");
    checked(&protected, base, "agent-run-1", ".forgejo/workflows/x.yml");
    let output = apply(&forge, &publishing, &protected, token);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("protected files: .forgejo/workflows/x.yml"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(branches(&forge, &bot, &fork), ["main"]);

    let accepted = dir.path().join("accepted");
    checked(&accepted, base, "agent-run-2", "src/x");
    let output = apply(&forge, &publishing, &accepted, token);
    assert_success("agentic-job apply", &output);
    let urls = String::from_utf8(output.stdout).unwrap();
    let urls: Vec<&str> = urls.lines().collect();
    assert_eq!(urls.len(), 2, "{urls:?}");

    // The comment, by the bot, with its mention neutralized and the footer.
    let comments = forge.get(&admin, &format!("/repos/{target}/issues/1/comments"));
    let [comment] = comments.as_array().unwrap().as_slice() else {
        panic!("{comments}")
    };
    assert_eq!(comment["user"]["login"], BOT);
    assert_eq!(comment["body"], format!("Done, {neutralized}.{footer}"));
    assert_eq!(comment["html_url"], urls[1]);

    // The pull request, from the fork's branch, never the target's.
    let pulls = forge.get(&admin, &format!("/repos/{target}/pulls?state=all"));
    let [pull] = pulls.as_array().unwrap().as_slice() else {
        panic!("{pulls}")
    };
    assert_eq!(pull["html_url"], urls[0]);
    assert_eq!(pull["user"]["login"], BOT);
    assert_eq!(pull["title"], "WIP: Fix it");
    assert_eq!(pull["body"], format!("Why, {neutralized}.{footer}"));
    assert_eq!(pull["head"]["repo"]["full_name"], fork.as_str());
    assert_eq!(pull["head"]["ref"], "agent-run-2");
    assert_eq!(pull["base"]["ref"], "main");
    let files = forge.get(
        &admin,
        &format!("/repos/{target}/pulls/{}/files", pull["number"]),
    );
    let files: Vec<&str> = files
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["filename"].as_str().unwrap())
        .collect();
    assert_eq!(files, ["src/x"]);
    assert_eq!(branches(&forge, &admin, &target), ["main"]);
    assert_eq!(branches(&forge, &admin, &fork), ["agent-run-2", "main"]);

    // Labels, where Forgejo's endpoints act on more than they name: a
    // removal takes a name before an ID, and an exclusive label replaces
    // the item's other of its scope. Neither may reach a blocked label.
    let mut ids = std::collections::HashMap::new();
    for (name, exclusive) in [
        ("bug", false),
        ("Docs", false),
        ("docs", false),
        ("status/triaged", true),
        ("status/protected", true),
        ("area/apply", false),
    ] {
        let label = forge.post(
            &admin,
            &format!("/repos/{target}/labels"),
            &json!({"name": name, "color": "#ee0701", "exclusive": exclusive}),
        );
        ids.insert(name, label["id"].clone());
    }
    // A blocked label named as the ID of an allowed one.
    let bug = ids["bug"].to_string();
    forge.post(
        &admin,
        &format!("/repos/{target}/labels"),
        &json!({"name": bug, "color": "#ee0701"}),
    );
    forge.post(
        &admin,
        &format!("/repos/{target}/issues/1/labels"),
        &json!({"labels": [bug, "bug", "status/protected", "area/apply"]}),
    );
    // Commenting needs no more, but labelling needs write access.
    let path = format!("/repos/{target}/collaborators/{BOT}");
    let (status, answer) = forge.call(&admin, "PUT", &path, Some(&json!({"permission": "write"})));
    assert_eq!(status, 204, "PUT {path}: {answer}");
    inline_reviews(&forge, dir.path(), token, &footer, &neutralized);
    let before = labels(&forge, &admin, &target);
    let labelling = policy(&forge, dir.path(), "labelling", LABELLING);
    let label = |name: &str, output: &str, names: &[&str]| -> Output {
        let checked = dir.path().join(name);
        let item = json!({"type": output, "repo": target, "item_number": 1, "labels": names});
        checked_items(&checked, &[item]);
        apply(&forge, &labelling, &checked, token)
    };

    let output = label("add-exclusive", "add_labels", &["status/triaged"]);
    // What the forge says refuses it as an error, before any write.
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("would remove status/protected"), "{stderr}");
    assert_eq!(labels(&forge, &admin, &target), before);

    // By name, its `/` encoded in one path segment.
    let output = label("remove-bug", "remove_labels", &["bug", "area/apply"]);
    assert_success("agentic-job apply remove_labels", &output);
    let mut want = vec![bug.clone(), "status/protected".to_owned()];
    want.sort();
    assert_eq!(labels(&forge, &admin, &target), want);

    let output = label("add-docs", "add_labels", &["Docs", "docs"]);
    assert_success("agentic-job apply add_labels", &output);
    want.extend(["Docs".to_owned(), "docs".to_owned()]);
    want.sort();
    assert_eq!(labels(&forge, &admin, &target), want);

    // Use the same scoped bot token for creation and closing, not the
    // bootstrap admin credential. Read back actual state and comments.
    let metadata = policy(
        &forge,
        dir.path(),
        "metadata",
        r#"
create_issue = { max = 1, allowed = ["bug", "status/triaged"] }
close_issue = { max = 1 }
close_pull_request = { max = 1 }
"#,
    );
    let creating = dir.path().join("create-issue");
    checked_items(
        &creating,
        &[json!({
            "type": "create_issue", "repo": target, "title": "Created by apply",
            "body": format!("Investigate, @{ADMIN}."), "labels": ["bug", "status/triaged"]
        })],
    );
    let output = apply(&forge, &metadata, &creating, token);
    assert_success("agentic-job apply create_issue", &output);
    let url = String::from_utf8(output.stdout).unwrap();
    let number: u64 = url.trim().rsplit('/').next().unwrap().parse().unwrap();
    let created = forge.get(&bot, &format!("/repos/{target}/issues/{number}"));
    assert_eq!(created["html_url"], url.trim());
    assert_eq!(created["user"]["login"], BOT);
    assert_eq!(created["title"], "Created by apply");
    assert_eq!(
        created["body"],
        format!("Investigate, {neutralized}.{footer}")
    );
    let mut names: Vec<_> = created["labels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|label| label["name"].as_str().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["bug", "status/triaged"]);

    let pull_number = pull["number"].as_u64().unwrap();
    let comments = |number| forge.get(&bot, &format!("/repos/{target}/issues/{number}/comments"));
    let issue_before = comments(number);
    let pull_before = comments(pull_number);
    for (name, wrong) in [
        (
            "close-issue-as-pull",
            json!({"type": "close_pull_request", "repo": target, "pull_request_number": number, "body": "Wrong kind."}),
        ),
        (
            "close-pull-as-issue",
            json!({"type": "close_issue", "repo": target, "issue_number": pull_number, "body": "Wrong kind."}),
        ),
    ] {
        let checked = dir.path().join(name);
        // An otherwise valid earlier operation must not write either.
        checked_items(
            &checked,
            &[
                json!({"type": "create_issue", "repo": target, "title": "Must not appear", "body": "Refused batch."}),
                wrong,
            ],
        );
        let before = forge.get(&bot, &format!("/repos/{target}/issues?state=all"));
        let output = apply(&forge, &metadata, &checked, token);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("not a"),
            "{output:?}"
        );
        assert_eq!(
            forge.get(&bot, &format!("/repos/{target}/issues?state=all")),
            before
        );
        assert_eq!(comments(number), issue_before);
        assert_eq!(comments(pull_number), pull_before);
    }

    let closing = dir.path().join("close-items");
    checked_items(
        &closing,
        &[
            json!({"type": "close_issue", "repo": target, "issue_number": number, "body": format!("Done, @{ADMIN}.")}),
            json!({"type": "close_pull_request", "repo": target, "pull_request_number": pull_number, "body": format!("Superseded, @{ADMIN}.")}),
        ],
    );
    let output = apply(&forge, &metadata, &closing, token);
    assert_success("agentic-job apply close issue and PR", &output);
    let closed_comments: Vec<_> = [(number, "Done"), (pull_number, "Superseded")]
        .into_iter()
        .map(|(number, reason)| {
            let state = forge.get(&bot, &format!("/repos/{target}/issues/{number}"));
            assert_eq!(state["state"], "closed");
            let posted = comments(number);
            let [comment] = posted.as_array().unwrap().as_slice() else {
                panic!("{posted}")
            };
            assert_eq!(comment["user"]["login"], BOT);
            assert_eq!(comment["body"], format!("{reason}, {neutralized}.{footer}"));
            posted
        })
        .collect();
    let output = apply(&forge, &metadata, &closing, token);
    assert_success("agentic-job apply close rerun", &output);
    assert_eq!(comments(number), closed_comments[0]);
    assert_eq!(comments(pull_number), closed_comments[1]);
}
