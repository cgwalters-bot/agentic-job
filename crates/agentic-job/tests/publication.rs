//! The publication corpus: what gh-aw's handlers, at the commit apply.yml
//! pins, send to GitHub and leave behind for each case of
//! `tests/data/publication/cases.json`. A second implementation of the
//! handlers would hold apply's write credentials, so it has to match this
//! record before it may replace them, and the record has to come from the
//! pinned code, not from what someone expects it to do.
//!
//! Each case runs apply.yml's steps: the one that writes the
//! handlers' configuration, then the guard that leaves out what an earlier
//! attempt applied (policy's binary, as apply.yml runs it), the check of
//! project fields and the one that runs gh-aw's handler manager, the last
//! two scripts read from apply.yml and run by the pinned
//! `actions/github-script` bundle. The request-editing steps before the guard
//! also run where applicable (folded review findings, a partial run's note,
//! and a pull request's issue link), recording their results. Its client
//! talks to a loopback forge here, which records every
//! request and keeps what was posted, so that a second attempt finds it;
//! git pushes go to bare repositories in a scratch directory. Nothing is
//! sent to a real forge. The forge's starting state, its failures and the
//! event the run is for (`event_name` and `event`, a dispatch with none
//! by default) are the case's input; everything in the golden files is
//! recorded.
//!
//! Each case is run again with the bounds routing its types of
//! [`NATIVE`] (or its `native` alone) to agentic-job's own handlers
//! (`agentic-job publish`), whose two steps then run before gh-aw's:
//! together they have to write what gh-aw's handlers alone did, in the
//! same order, and the same record of what was made. Without
//! the pinned checkouts, `routed_steps_publish_first_and_leave_the_rest`
//! runs those two steps alone, on the recorded guard's output.
//!
//! The run needs node, git, jq and bash, gh-aw's repository at apply.yml's
//! `github/gh-aw/actions/setup` pin in `AGENTIC_JOB_TEST_GH_AW` and
//! `actions/github-script` at apply.yml's pin in
//! `AGENTIC_JOB_TEST_GITHUB_SCRIPT`. It replaces gh-aw's fixed
//! `/tmp/gh-aw` for each case. CI's `publication` job runs it; `just
//! publication-corpus` fetches both pins and rewrites the golden files:
//!
//! ```text
//! cargo test --test publication -- --ignored
//! ```

// Helpers outside a #[test] function are still test code.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};

use agentic_job::check::BASE_COMMIT_HEADER;
use serde_json::{Map, Value, json};
use yaml_rust2::{Yaml, YamlLoader};

const GH_AW_VAR: &str = "AGENTIC_JOB_TEST_GH_AW";
const GITHUB_SCRIPT_VAR: &str = "AGENTIC_JOB_TEST_GITHUB_SCRIPT";
/// Set to rewrite the golden files instead of comparing with them.
const BLESS_VAR: &str = "AGENTIC_JOB_BLESS_PUBLICATION";

const SETUP_ACTION: &str = "github/gh-aw/actions/setup@";
const GITHUB_SCRIPT_ACTION: &str = "actions/github-script@";

/// gh-aw's fixed directory for a run's files (its constants.cjs).
const GH_AW_TMP: &str = "/tmp/gh-aw";

const CONFIG_STEP: &str = "Write the handlers' configuration";
const GUARD_STEP: &str = "Leave out what an earlier attempt applied";
const PROJECT_STEP: &str = "Check the project fields before anything is published";
const APPLY_STEP: &str = "Apply the outputs with gh-aw's handlers";
const ROUTE_STEP: &str = "Which outputs agentic-job publishes";
const PUBLISH_STEP: &str = "Publish the outputs routed to agentic-job";
const FOLD_STEP: &str = "Put a review's inline findings in its comment";
const PARTIAL_STEP: &str = "Mark what a partial run opens or posts";
const ISSUE_STEP: &str = "Say which issue a pull request is for";

/// The calling, output and item repository unless a case says otherwise.
const REPO: &str = "owner/repo";
/// Whom the token names, and the owner of the fork a pull request is from.
const POSTER: &str = "agentic-bot";
const FORK: &str = "agentic-bot/repo";
const RUN_ID: &str = "4242";
/// Not a credential: the loopback forge takes any token.
const TOKEN: &str = "publication-test-token";
/// Commit dates, so that a commit's ID is the same on every run.
const GIT_DATE: &str = "2026-01-01T00:00:00Z";
const SERVER: &str = "https://github.com";
/// Where the guard and the handlers' clients send requests, as recorded.
const API: &str = "{api}";
const WORK: &str = "{work}";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/publication")
}

fn apply_text() -> String {
    std::fs::read_to_string(root().join(".github/workflows/apply.yml")).unwrap()
}

/// The commit apply.yml pins ACTION at, the same at every use.
fn pin(text: &str, action: &str) -> String {
    let pins: Vec<&str> = text
        .match_indices(action)
        .map(|(at, _)| {
            text.get(at + action.len()..at + action.len() + 40)
                .unwrap_or_default()
        })
        .collect();
    assert!(!pins.is_empty(), "apply.yml does not use {action}");
    assert!(
        pins.iter().all(|pin| *pin == pins[0]),
        "apply.yml pins {action} at more than one commit: {pins:?}"
    );
    assert!(pins[0].bytes().all(|b| b.is_ascii_hexdigit()));
    pins[0].to_owned()
}

fn pins() -> Value {
    let text = apply_text();
    json!({
        "gh_aw": pin(&text, SETUP_ACTION),
        "github_script": pin(&text, GITHUB_SCRIPT_ACTION),
    })
}

fn cases() -> Vec<Value> {
    let text = std::fs::read_to_string(data().join("cases.json")).unwrap();
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn golden(name: &str) -> PathBuf {
    data().join(format!("{name}.json"))
}

/// The golden files were recorded at the commits apply.yml pins now, and
/// there is one for each case and no other: bumping a pin without
/// recording the corpus again fails here, without the pinned checkouts.
#[test]
fn corpus_is_recorded_at_apply_pins() {
    let pins = pins();
    let mut names: Vec<String> = cases()
        .iter()
        .map(|case| case["name"].as_str().unwrap().to_owned())
        .collect();
    for name in &names {
        let text = std::fs::read_to_string(golden(name))
            .unwrap_or_else(|e| panic!("{name}: no golden file ({e}); record the corpus"));
        let recorded: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            recorded["pins"], pins,
            "{name} was recorded at other pins than apply.yml's; record the corpus again"
        );
    }
    // CI checks the corpus out at commits of its own, which an update of
    // apply.yml's `uses:` lines does not change.
    let ci = std::fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    let ci = &YamlLoader::load_from_str(&ci).unwrap()[0];
    for (repository, key) in [
        ("github/gh-aw", "gh_aw"),
        ("actions/github-script", "github_script"),
    ] {
        let checkout = ci["jobs"]["publication"]["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .find(|step| step["with"]["repository"].as_str() == Some(repository))
            .unwrap_or_else(|| panic!("ci.yml's publication job checks out no {repository}"));
        assert_eq!(
            checkout["with"]["ref"].as_str(),
            pins[key].as_str(),
            "ci.yml's publication job checks {repository} out at another commit than apply.yml pins"
        );
    }
    names.push("cases".into());
    names.sort();
    let mut files: Vec<String> = std::fs::read_dir(data())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter_map(|name| name.strip_suffix(".json").map(str::to_owned))
        .collect();
    files.sort();
    assert_eq!(files, names, "a golden file without its case");
}

/// Regeneration must still exercise these paths, not bless a case that
/// accidentally stopped reaching its handler or its second attempt.
#[test]
fn recorded_followups_exercise_their_paths() {
    for name in ["push-rerun-trailers", "push-rerun-half-applied"] {
        let recorded = read_json(&golden(name));
        let attempts = recorded["attempts"].as_array().unwrap();
        assert_eq!(attempts.len(), 2, "{name}");
        assert!(
            !attempts[0]["pushed"].as_object().unwrap().is_empty(),
            "{name}"
        );
        assert_eq!(attempts[1]["pushed"], json!({}), "{name}");
        assert_eq!(attempts[1]["guard"]["items"], json!([]), "{name}");
        assert_eq!(
            attempts[1]["guard"]["skipped"][0]["type"], "push_to_pull_request_branch",
            "{name}"
        );
        if name == "push-rerun-half-applied" {
            assert!(
                attempts[0]["apply"]["annotations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|note| note.as_str().unwrap().contains("Failed to create comment"))
            );
        }
    }
    for (name, branch) in [
        ("push-rerun-trailers", "feature"),
        ("partial-pull-request-issue-trailers", "agent-run-4242"),
    ] {
        let recorded = read_json(&golden(name));
        let commit = &recorded["pushed"][format!("{FORK}:refs/heads/{branch}")][0];
        assert_eq!(commit["author"], "Agent <agent@example.invalid>");
        let message = commit["message"].as_str().unwrap();
        assert!(message.contains("\nGenerated-by: https://github.com/cgwalters/#llms\n"));
        assert!(message.contains("\nCo-authored-by: Contributor <contributor@example.invalid>"));
        assert!(!message.contains("Co-authored-by: github-actions"));
    }
    let recorded = read_json(&golden("handler-comment-pagination"));
    let requests = recorded["attempts"][0]["requests"].as_array().unwrap();
    assert!(
        requests.iter().any(|r| r["step"] == "apply"
            && r["path"].as_str().unwrap().ends_with("per_page=100&page=2"))
    );
    assert!(requests.iter().any(|r| r["step"] == "apply"
        && r["method"] == "PATCH"
        && r["path"] == "/repos/owner/repo/issues/comments/900"));
    for (name, edit_steps) in [
        (
            "partial-pull-request-issue-trailers",
            vec![PARTIAL_STEP, ISSUE_STEP],
        ),
        ("review-folded-findings-rerun", vec![FOLD_STEP]),
    ] {
        let recorded = read_json(&golden(name));
        for attempt in recorded["attempts"].as_array().unwrap() {
            let edits = attempt["edits"].as_array().unwrap();
            assert_eq!(
                edits
                    .iter()
                    .map(|edit| edit["step"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                edit_steps
            );
            assert!(edits.iter().all(|edit| edit["exit"] == 0));
        }
        assert_eq!(recorded["attempts"][1]["guard"]["items"], json!([]));
    }
}

/// The keys of a JSON object in the order they were sent.
struct Keys(Vec<String>);

impl<'de> serde::Deserialize<'de> for Keys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Keys;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Keys, A::Error> {
                let mut keys = vec![];
                while let Some(key) = map.next_key::<String>()? {
                    map.next_value::<serde::de::IgnoredAny>()?;
                    keys.push(key);
                }
                Ok(Keys(keys))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

/// One request as the forge saw it, with the order of its body's keys.
fn recorded_request(step: &str, method: &str, target: &str, body: &str, version: &str) -> Value {
    let mut entry = json!({
        "step": step,
        "method": method,
        "path": target,
        "api_version": version,
    });
    if !body.is_empty() {
        entry["body"] = serde_json::from_str(body).unwrap_or_else(|_| Value::String(body.into()));
        if let Ok(Keys(keys)) = serde_json::from_str(body) {
            entry["keys"] = json!(keys);
        }
    }
    entry
}

/// The lists the forge answers for with an empty one when a case seeds none.
const LISTS: &[&str] = &[
    "/collaborators",
    "/comments",
    "/files",
    "/issues",
    "/pulls",
    "/reviews",
];

/// A failure the forge answers with once, in the attempt named.
struct Fault {
    attempt: u64,
    method: String,
    path: String,
    status: u16,
}

/// What the loopback forge keeps: each resource as a JSON value under
/// its API path, a list (comments) or an object (an issue, a pull request).
/// A collection is its stored list, or the objects under `PATH/NUMBER`.
struct State {
    store: BTreeMap<String, Value>,
    next_id: u64,
    faults: Vec<Fault>,
    requests: Vec<Value>,
    step: String,
    attempt: u64,
    url: String,
}

struct Forge {
    state: Arc<Mutex<State>>,
    url: String,
}

struct Request {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: String,
}

fn read_request(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut first = String::new();
    reader.read_line(&mut first).ok()?;
    let mut parts = first.split_whitespace();
    let (method, target) = (parts.next()?.to_owned(), parts.next()?.to_owned());
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .map_or(0, |n| n.parse().unwrap());
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some(Request {
        method,
        target,
        headers,
        body: String::from_utf8(body).unwrap(),
    })
}

fn split_target(target: &str) -> (&str, BTreeMap<String, String>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key.to_owned(), decode(value))
        })
        .collect();
    (path, query)
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap()
}

/// `/repos/OWNER/REPO` of a repository API path.
fn repo_of(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/repos/")?;
    let mut parts = rest.splitn(3, '/');
    Some(format!("/repos/{}/{}", parts.next()?, parts.next()?))
}

impl State {
    fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// The next issue or pull request number of the repository at PATH.
    fn new_number(&self, repo: &str) -> u64 {
        let numbered = regex::Regex::new(r"^/repos/[^/]+/[^/]+/(issues|pulls)/(\d+)$").unwrap();
        self.store
            .keys()
            .filter(|key| key.starts_with(&format!("{repo}/")))
            .filter_map(|key| numbered.captures(key))
            .map(|c| c[2].parse::<u64>().unwrap())
            .max()
            .unwrap_or(0)
            + 1
    }

    fn children(&self, path: &str) -> Vec<Value> {
        let child = regex::Regex::new(&format!("^{}/\\d+$", regex::escape(path))).unwrap();
        let mut found: Vec<&Value> = self
            .store
            .iter()
            .filter(|(key, _)| child.is_match(key))
            .map(|(_, value)| value)
            .collect();
        found.sort_by_key(|value| value["number"].as_u64());
        found.into_iter().cloned().collect()
    }

    fn handle(&mut self, request: &Request) -> (u16, Vec<(String, String)>, Value) {
        let (path, query) = split_target(&request.target);
        let path = path.to_owned();
        let body: Value = if request.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&request.body).unwrap_or(Value::Null)
        };
        let not_found = (404, vec![], json!({"message": "Not Found"}));
        match request.method.as_str() {
            "GET" if path == "/user" => (200, vec![], json!({"login": POSTER, "id": 1})),
            "GET" if path == "/rate_limit" => {
                let core =
                    json!({"limit": 5000, "remaining": 4999, "used": 1, "reset": 1_767_225_600});
                (
                    200,
                    vec![],
                    json!({"resources": {"core": core}, "rate": core}),
                )
            }
            "GET" if path == "/search/issues" => {
                let q = query.get("q").cloned().unwrap_or_default();
                let phrase = q.split('"').nth(1).unwrap_or_default().to_owned();
                let items: Vec<Value> = self
                    .store
                    .iter()
                    .filter(|(key, value)| {
                        key.contains("/issues/")
                            && value.is_object()
                            && value["pull_request"].is_null()
                            && value["body"].as_str().is_some_and(|b| b.contains(&phrase))
                    })
                    .map(|(_, value)| value.clone())
                    .collect();
                (
                    200,
                    vec![],
                    json!({"total_count": items.len(), "incomplete_results": false, "items": items}),
                )
            }
            "GET" => {
                let list = match self.store.get(&path) {
                    Some(Value::Array(list)) => list.clone(),
                    Some(value) => return (200, vec![], value.clone()),
                    // An unseeded list is empty; anything else is not there,
                    // a branch's protection included.
                    None if LISTS.iter().any(|list| path.ends_with(list)) => self.children(&path),
                    None => return not_found,
                };
                let list: Vec<Value> = list
                    .into_iter()
                    .filter(|value| {
                        query.iter().all(|(key, want)| match key.as_str() {
                            "head" => value["head"]["label"].as_str() == Some(want),
                            "state" if want != "all" => value["state"].as_str() == Some(want),
                            _ => true,
                        })
                    })
                    .collect();
                let per_page: usize = query.get("per_page").map_or(30, |n| n.parse().unwrap());
                let page: usize = query.get("page").map_or(1, |n| n.parse().unwrap());
                let start = (page - 1) * per_page;
                let shown: Vec<Value> = list.iter().skip(start).take(per_page).cloned().collect();
                let mut headers = vec![];
                if start + per_page < list.len() {
                    let mut next: Vec<String> = query
                        .iter()
                        .filter(|(key, _)| key.as_str() != "page")
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect();
                    next.push(format!("page={}", page + 1));
                    headers.push((
                        "link".into(),
                        format!("<{}{path}?{}>; rel=\"next\"", self.url, next.join("&")),
                    ));
                }
                (200, headers, Value::Array(shown))
            }
            // A project's fields, as the seed's `/graphql/fields` lists them;
            // an issue's node ID, and its sub-issues, kept in the issue.
            "POST" if path == "/graphql" => {
                let query = body["query"].as_str().unwrap_or_default();
                let variables = &body["variables"];
                let data = if query.contains("projectV2(number:") {
                    json!({"organization": {"projectV2": {"id": "project"}}})
                } else if query.contains("fields(") {
                    let nodes = self.store.get("/graphql/fields").cloned();
                    json!({"node": {"fields": {"nodes": nodes.unwrap_or_else(|| json!([])),
                        "pageInfo": {"hasNextPage": false, "endCursor": null}}}})
                } else if query.contains("issue(number: $issueNumber)") {
                    let issue = format!(
                        "/repos/{}/{}/issues/{}",
                        variables["owner"].as_str().unwrap_or_default(),
                        variables["repo"].as_str().unwrap_or_default(),
                        variables["issueNumber"]
                    );
                    let Some(issue) = self.store.get(&issue) else {
                        return not_found;
                    };
                    json!({"repository": {"issue": {"id": issue["node_id"]}}})
                } else if query.contains("addSubIssue(") {
                    let node = |id: &Value| {
                        self.store
                            .iter()
                            .find(|(key, value)| {
                                key.contains("/issues/") && value["node_id"] == *id
                            })
                            .map(|(key, value)| (key.clone(), value["number"].clone()))
                    };
                    let (Some((parent, number)), Some((_, child))) =
                        (node(&variables["parentId"]), node(&variables["subIssueId"]))
                    else {
                        return not_found;
                    };
                    self.store
                        .entry(format!("{parent}/sub_issues"))
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"number": child}));
                    json!({"addSubIssue": {
                        "issue": {"id": variables["parentId"], "number": number},
                        "subIssue": {"id": variables["subIssueId"], "number": child}}})
                } else {
                    return not_found;
                };
                (200, vec![], json!({ "data": data }))
            }
            "POST" => self.create(&path, body),
            "PATCH" => {
                let Some(Value::Object(object)) = self.store.get_mut(&path) else {
                    return not_found;
                };
                for (key, value) in body.as_object().cloned().unwrap_or_default() {
                    object.insert(key, value);
                }
                let updated = Value::Object(object.clone());
                // An issue and a pull request of one number are one item.
                let twin = if path.contains("/pulls/") {
                    path.replace("/pulls/", "/issues/")
                } else {
                    path.replace("/issues/", "/pulls/")
                };
                if let Some(Value::Object(other)) = self.store.get_mut(&twin) {
                    for key in ["state", "state_reason", "title", "body"] {
                        if let Some(value) = updated.get(key) {
                            other.insert(key.into(), value.clone());
                        }
                    }
                }
                (200, vec![], updated)
            }
            "DELETE" => {
                let label =
                    regex::Regex::new(r"^(/repos/[^/]+/[^/]+/issues/\d+)/labels/(.+)$").unwrap();
                let Some(c) = label.captures(&path) else {
                    return not_found;
                };
                let name = decode(&c[2]);
                let Some(issue) = self.store.get_mut(&c[1]) else {
                    return not_found;
                };
                let labels = issue["labels"].as_array_mut().unwrap();
                let before = labels.len();
                labels.retain(|label| label["name"].as_str() != Some(&name));
                if labels.len() == before {
                    return not_found;
                }
                (200, vec![], issue["labels"].clone())
            }
            _ => not_found,
        }
    }

    /// POST PATH: a new comment, issue, pull request, label set or review.
    fn create(&mut self, path: &str, body: Value) -> (u16, Vec<(String, String)>, Value) {
        let not_found = (404, vec![], json!({"message": "Not Found"}));
        let Some(repo) = repo_of(path) else {
            return not_found;
        };
        let web = format!("{SERVER}{}", repo.trim_start_matches("/repos"));
        let user = json!({"login": POSTER, "type": "User"});
        let tail = &path[repo.len()..];
        let item = regex::Regex::new(r"^/(issues|pulls)/(\d+)(/.*)?$").unwrap();
        if tail == "/issues" || tail == "/pulls" {
            let number = self.new_number(&repo);
            let id = self.new_id();
            let mut object = body.as_object().cloned().unwrap_or_default();
            let kind = &tail[1..];
            object.extend([
                ("id".into(), json!(id)),
                ("node_id".into(), json!(format!("N_{id}"))),
                ("number".into(), json!(number)),
                ("state".into(), json!("open")),
                ("user".into(), user),
                (
                    "html_url".into(),
                    json!(format!(
                        "{web}/{}/{number}",
                        if kind == "pulls" { "pull" } else { kind }
                    )),
                ),
                (
                    "repository_url".into(),
                    json!(format!("{}{repo}", self.url)),
                ),
            ]);
            if kind == "issues" {
                let labels: Vec<Value> = object
                    .get("labels")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|name| json!({"name": name}))
                    .collect();
                object.insert("labels".into(), Value::Array(labels));
            } else {
                let head = object["head"].as_str().unwrap_or_default().to_owned();
                let (owner, branch) = head.split_once(':').unwrap_or((POSTER, &head));
                object.insert(
                    "head".into(),
                    json!({"ref": branch, "label": format!("{owner}:{branch}")}),
                );
                object.insert("merged_at".into(), Value::Null);
                let mut issue = object.clone();
                issue.insert("pull_request".into(), json!({}));
                self.store
                    .insert(format!("{repo}/issues/{number}"), Value::Object(issue));
            }
            let object = Value::Object(object);
            self.store
                .insert(format!("{repo}{tail}/{number}"), object.clone());
            self.store
                .insert(format!("{repo}/issues/{number}/comments"), json!([]));
            return (201, vec![], object);
        }
        let Some(c) = item.captures(tail) else {
            return not_found;
        };
        let number = &c[2];
        let issue = format!("{repo}/issues/{number}");
        match c.get(3).map(|m| m.as_str()) {
            Some("/comments") if &c[1] == "issues" => {
                if !self.store.contains_key(&issue) {
                    return not_found;
                }
                let id = self.new_id();
                let comment = json!({
                    "id": id,
                    "node_id": format!("IC_{id}"),
                    "body": body["body"],
                    "user": user,
                    "html_url": format!("{web}/issues/{number}#issuecomment-{id}"),
                    "issue_url": format!("{}{issue}", self.url),
                });
                self.store
                    .entry(format!("{issue}/comments"))
                    .or_insert_with(|| json!([]))
                    .as_array_mut()
                    .unwrap()
                    .push(comment.clone());
                (201, vec![], comment)
            }
            Some("/labels") => {
                let Some(object) = self.store.get_mut(&issue) else {
                    return not_found;
                };
                let labels = object["labels"].as_array_mut().unwrap();
                for name in body["labels"].as_array().cloned().unwrap_or_default() {
                    if !labels.iter().any(|label| label["name"] == name) {
                        labels.push(json!({"name": name}));
                    }
                }
                (200, vec![], object["labels"].clone())
            }
            // A review is kept with its comments, which it is read back by.
            Some("/reviews") if &c[1] == "pulls" => {
                let id = self.new_id();
                let pull = format!("{repo}/pulls/{number}");
                let review = json!({
                    "id": id,
                    "state": "COMMENTED",
                    "body": body["body"],
                    "commit_id": body["commit_id"],
                    "user": user,
                    "html_url": format!("{web}/pull/{number}#pullrequestreview-{id}"),
                });
                let mut comments = vec![];
                for comment in body["comments"].as_array().cloned().unwrap_or_default() {
                    let comment_id = self.new_id();
                    let mut comment = comment.as_object().cloned().unwrap_or_default();
                    comment.extend([
                        ("id".into(), json!(comment_id)),
                        ("pull_request_review_id".into(), json!(id)),
                        ("user".into(), user.clone()),
                        (
                            "html_url".into(),
                            json!(format!("{web}/pull/{number}#discussion_r{comment_id}")),
                        ),
                        (
                            "pull_request_url".into(),
                            json!(format!("{}{pull}", self.url)),
                        ),
                    ]);
                    comments.push(Value::Object(comment));
                }
                self.store
                    .insert(format!("{pull}/reviews/{id}/comments"), json!(comments));
                self.store
                    .entry(format!("{pull}/reviews"))
                    .or_insert_with(|| json!([]))
                    .as_array_mut()
                    .unwrap()
                    .push(review.clone());
                (200, vec![], review)
            }
            _ => not_found,
        }
    }
}

impl Forge {
    fn start(seed: &Value, faults: Vec<Fault>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let text = seed.to_string().replace(API, &url);
        let store = serde_json::from_str::<Map<String, Value>>(&text)
            .unwrap()
            .into_iter()
            .collect();
        let state = Arc::new(Mutex::new(State {
            store,
            next_id: 1000,
            faults,
            requests: vec![],
            step: String::new(),
            attempt: 1,
            url: url.clone(),
        }));
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let state = Arc::clone(&shared);
                std::thread::spawn(move || serve(stream, &state));
            }
        });
        Self { state, url }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }
}

fn serve(mut stream: TcpStream, state: &Mutex<State>) {
    let Some(request) = read_request(&stream) else {
        return;
    };
    let (status, headers, body) = {
        let mut state = state.lock().unwrap();
        let step = state.step.clone();
        let version = request
            .headers
            .get("x-github-api-version")
            .cloned()
            .unwrap_or_default();
        let entry = recorded_request(
            &step,
            &request.method,
            &request.target,
            &request.body,
            &version,
        );
        state.requests.push(entry);
        let attempt = state.attempt;
        let (path, _) = split_target(&request.target);
        let fault = state.faults.iter().position(|fault| {
            fault.attempt == attempt && fault.method == request.method && fault.path == path
        });
        match fault {
            Some(index) => {
                let fault = state.faults.remove(index);
                (fault.status, vec![], json!({"message": "injected failure"}))
            }
            None => state.handle(&request),
        }
    };
    let text = body.to_string();
    let mut head = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n",
        text.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(text.as_bytes());
}

fn step<'a>(doc: &'a Yaml, name: &str) -> &'a Yaml {
    doc["jobs"]["apply"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|step| step["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("apply.yml has no step {name:?}"))
}

/// The step's or job's environment whose values are not expressions:
/// those this file supplies itself.
fn literal_env(env: &Yaml) -> Vec<(String, String)> {
    env.as_hash()
        .map(|hash| {
            hash.iter()
                .filter_map(|(key, value)| {
                    let value = value.as_str()?;
                    (!value.contains("${{")).then(|| (key.as_str().unwrap().into(), value.into()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// What github-script's action.yml gives an input left unset.
fn script_defaults(github_script: &Path) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(github_script.join("action.yml")).unwrap();
    let doc = &YamlLoader::load_from_str(&text).unwrap()[0];
    doc["inputs"]
        .as_hash()
        .unwrap()
        .iter()
        .filter_map(|(name, input)| {
            let value = input["default"].as_str()?;
            (!value.contains("${{")).then(|| {
                (
                    format!("INPUT_{}", name.as_str().unwrap().to_uppercase()),
                    value.into(),
                )
            })
        })
        .collect()
}

/// The values of a GITHUB_OUTPUT or GITHUB_ENV file, as the runner reads them.
fn read_commands(file: &Path) -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(file).unwrap_or_default();
    let mut values = BTreeMap::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if let Some((name, delimiter)) = line.split_once("<<") {
            let mut value = vec![];
            for line in lines.by_ref() {
                if line == delimiter {
                    break;
                }
                value.push(line);
            }
            values.insert(name.into(), value.join("\n"));
        } else if let Some((name, value)) = line.split_once('=') {
            values.insert(name.into(), value.into());
        }
    }
    values
}

struct Paths {
    gh_aw: PathBuf,
    github_script: PathBuf,
}

/// One case's scratch: the runner's directories and the git server.
struct Scratch {
    dir: tempfile::TempDir,
}

impl Scratch {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn git(&self, dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(dir)
            .args(args)
            .envs(self.git_env())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn git_env(&self) -> Vec<(String, String)> {
        vec![
            (
                "GIT_CONFIG_GLOBAL".into(),
                self.path("gitconfig").display().to_string(),
            ),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_AUTHOR_DATE".into(), GIT_DATE.into()),
            ("GIT_COMMITTER_DATE".into(), GIT_DATE.into()),
            ("HOME".into(), self.path("home").display().to_string()),
        ]
    }

    /// The bare repository the forge's git URL for REPO leads to.
    fn server_repo(&self, repo: &str) -> PathBuf {
        self.path(&format!("server/{repo}.git"))
    }
}

/// Bare repositories for the output repository and the fork, with one
/// base commit on `main` and the case's branches; the workspace checked
/// out as apply.yml's checkout, `Configure git` and the base's fetch
/// leave it; and the patch the case's change makes, with check's report
/// naming it. Returns what the case's `{head:BRANCH}` and `{tree}` stand
/// for: a branch's commit, and the tree the patch makes. For NATIVE, the
/// patch and report are check's whole: with the base commit header, and
/// the size and paths `agentic-job publish` holds the patch to again.
fn prepare_git(scratch: &Scratch, case: &Value, native: bool) -> Vec<(String, String)> {
    let git = &case["git"];
    if git.is_null() {
        return vec![];
    }
    let seed = scratch.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    scratch.git(&seed, &["init", "--quiet", "--initial-branch=main"]);
    for (name, content) in git["files"].as_object().unwrap() {
        let file = seed.join(name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, content.as_str().unwrap()).unwrap();
    }
    commit_change(scratch, &seed, &json!({"message": "Base", "files": {}}));
    for (branch, change) in git["branches"].as_object().into_iter().flatten() {
        scratch.git(&seed, &["checkout", "--quiet", "-b", branch, "main"]);
        commit_change(scratch, &seed, change);
        scratch.git(&seed, &["checkout", "--quiet", "main"]);
    }
    for repo in [REPO, FORK] {
        let bare = scratch.server_repo(repo);
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        scratch.git(
            scratch.dir.path(),
            &[
                "clone",
                "--quiet",
                "--bare",
                seed.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );
    }
    // The agent's change, as a patch from its base: on main, or on the
    // branch of the pull request a push is for.
    let base = git["patch"]["base"].as_str().unwrap_or("main");
    scratch.git(&seed, &["checkout", "--quiet", "-b", "agent", base]);
    commit_change(scratch, &seed, &git["patch"]);
    // The applied marker hashes the patch bytes. Do not let the installed
    // Git version's mail signature change the recorded publication.
    let patch = Command::new("git")
        .current_dir(&seed)
        .args([
            "format-patch",
            "--no-signature",
            "--stdout",
            &format!("{base}..agent"),
        ])
        .envs(scratch.git_env())
        .output()
        .unwrap();
    assert!(patch.status.success());
    let branch = git["patch"]["branch"].as_str().unwrap();
    let file = format!("aw-{branch}.patch");
    std::fs::create_dir_all(scratch.path("download")).unwrap();
    let mut patch = String::from_utf8(patch.stdout).unwrap();
    let mut report = json!({"patch": {"file": file}});
    if native {
        let base_commit = scratch.git(&seed, &["rev-parse", base]);
        let (from, rest) = patch.split_once('\n').unwrap();
        patch = format!("{from}\n{BASE_COMMIT_HEADER}: {base_commit}\n{rest}");
        let mut files: Vec<&String> = git["patch"]["files"].as_object().unwrap().keys().collect();
        files.sort();
        report = json!({"ok": true, "errors": [], "items": case["items"], "patch": {
            "file": file, "bytes": patch.len(), "base_commit": base_commit, "files": files}});
    }
    std::fs::write(scratch.path("download").join(&file), &patch).unwrap();
    std::fs::write(scratch.path("download/report.json"), report.to_string()).unwrap();
    let workspace = scratch.path("workspace");
    scratch.git(
        scratch.dir.path(),
        &[
            "clone",
            "--quiet",
            &format!("{SERVER}/{REPO}"),
            workspace.to_str().unwrap(),
        ],
    );
    // The base as apply.yml fetches it: a push's from the fork.
    scratch.git(
        &workspace,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            &format!("{SERVER}/{}", if base == "main" { REPO } else { FORK }),
            &format!("+refs/heads/{base}:refs/agentic-job/target-base"),
        ],
    );
    let mut placeholders = vec![(
        "{tree}".to_owned(),
        scratch.git(&seed, &["rev-parse", "agent^{tree}"]),
    )];
    for name in scratch
        .git(
            &seed,
            &["for-each-ref", "--format=%(refname:short)", "refs/heads"],
        )
        .lines()
    {
        placeholders.push((
            format!("{{head:{name}}}"),
            scratch.git(&seed, &["rev-parse", name]),
        ));
    }
    for (key, value) in [
        ("user.name", "github-actions[bot]"),
        (
            "user.email",
            "41898282+github-actions[bot]@users.noreply.github.com",
        ),
        ("merge.renames", "false"),
        ("diff.renames", "false"),
        ("am.keepcr", "true"),
    ] {
        scratch.git(&workspace, &["config", key, value]);
    }
    placeholders
}

fn commit_change(scratch: &Scratch, dir: &Path, change: &Value) {
    for (name, content) in change["files"].as_object().unwrap() {
        let file = dir.join(name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, content.as_str().unwrap()).unwrap();
    }
    scratch.git(dir, &["add", "--all"]);
    scratch.git(
        dir,
        &[
            "-c",
            "user.name=Agent",
            "-c",
            "user.email=agent@example.invalid",
            "commit",
            "--quiet",
            "-m",
            change["message"].as_str().unwrap(),
        ],
    );
}

/// Each branch of the git server's repositories, as `REPO:REF` and its commit.
fn branches(scratch: &Scratch) -> BTreeMap<String, String> {
    let mut branches = BTreeMap::new();
    for repo in [REPO, FORK] {
        let bare = scratch.server_repo(repo);
        if !bare.exists() {
            continue;
        }
        let refs = scratch.git(
            &bare,
            &[
                "for-each-ref",
                "--format=%(refname) %(objectname)",
                "refs/heads",
            ],
        );
        for line in refs.lines() {
            let (name, commit) = line.split_once(' ').unwrap();
            branches.insert(format!("{repo}:{name}"), commit.to_owned());
        }
    }
    branches
}

/// What was pushed since BEFORE: each new commit of a branch that moved
/// or was made, with its author, committer, message and files.
fn pushed(scratch: &Scratch, before: &BTreeMap<String, String>) -> Value {
    let mut pushed = Map::new();
    for (branch, commit) in branches(scratch) {
        if before.get(&branch) == Some(&commit) {
            continue;
        }
        let (repo, _) = branch.split_once(':').unwrap();
        let bare = scratch.server_repo(repo);
        let since = before.get(&branch).map_or("main", String::as_str);
        let log = scratch.git(
            &bare,
            &[
                "log",
                "--format=%H",
                "--reverse",
                &format!("{since}..{commit}"),
            ],
        );
        let commits: Vec<Value> = log
            .lines()
            .map(|commit| {
                let show = |format: &str| {
                    scratch.git(
                        &bare,
                        &["show", "-s", &format!("--format={format}"), commit],
                    )
                };
                let files = scratch.git(
                    &bare,
                    &["diff-tree", "--no-commit-id", "--name-only", "-r", commit],
                );
                json!({
                    "author": show("%an <%ae>"),
                    "committer": show("%cn <%ce>"),
                    "message": show("%B"),
                    "files": files.lines().collect::<Vec<_>>(),
                })
            })
            .collect();
        pushed.insert(branch, Value::Array(commits));
    }
    Value::Object(pushed)
}

fn read_json(path: &Path) -> Value {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap(),
        Err(_) => Value::Null,
    }
}

fn read_jsonl(path: &Path) -> Value {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect(),
        Err(_) => Value::Null,
    }
}

/// The workflow commands a step printed: its errors and warnings.
fn annotations(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter(|line| line.starts_with("::error") || line.starts_with("::warning"))
        .map(str::to_owned)
        .collect()
}

/// Runs SCRIPT as the pinned github-script action would, with ENV, and
/// returns its exit status, outputs, annotations and step summary.
fn github_script(
    paths: &Paths,
    scratch: &Scratch,
    env: &[(String, String)],
    script: &str,
) -> (i32, BTreeMap<String, String>, Vec<String>, String) {
    let output_file = scratch.path("github-output");
    let summary = scratch.path("step-summary");
    std::fs::write(&output_file, "").unwrap();
    std::fs::write(&summary, "").unwrap();
    let output = Command::new("node")
        .arg(paths.github_script.join("dist/index.js"))
        .env_clear()
        .envs(env.iter().cloned())
        .envs(script_defaults(&paths.github_script))
        .env("INPUT_SCRIPT", script)
        .env("INPUT_GITHUB-TOKEN", TOKEN)
        .env("INPUT_DEBUG", "false")
        .env("GITHUB_OUTPUT", &output_file)
        .env("GITHUB_STEP_SUMMARY", &summary)
        .current_dir(scratch.path("workspace"))
        .output()
        .unwrap();
    if std::env::var_os("AGENTIC_JOB_TEST_VERBOSE").is_some() {
        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    (
        output.status.code().unwrap_or(-1),
        read_commands(&output_file),
        annotations(&output.stdout),
        std::fs::read_to_string(&summary).unwrap(),
    )
}

/// The types `agentic-job publish` handles.
const NATIVE: &[&str] = agentic_job::policy::NATIVE_OUTPUTS;

/// The types CASE's bounds route away from gh-aw's handlers: its
/// `native`, or else those of [`NATIVE`] it configures.
fn routed(case: &Value) -> Vec<&str> {
    match case["native"].as_array() {
        Some(types) => types
            .iter()
            .map(|output| output.as_str().unwrap())
            .collect(),
        None => NATIVE
            .iter()
            .copied()
            .filter(|output| case["config"].get(*output).is_some())
            .collect(),
    }
}

/// The policy check's upload holds for CASE where the bounds route its
/// [`routed`] types away from gh-aw's handlers; none route without one.
/// A push's base is its pull request's branch.
fn native_policy(case: &Value) -> Value {
    let routed = routed(case);
    if routed.is_empty() {
        return json!({});
    }
    json!({
        "repo": REPO,
        "clone_url": format!("{SERVER}/{REPO}"),
        "base": case["env"]["BASE"].as_str().unwrap_or("main"),
        "kind": "branch",
        "max_outputs": 5,
        "max_patch_bytes": 1_048_576,
        "safe_outputs": case["config"],
        "contract": agentic_job::policy::CONTRACT,
        "native_handlers": routed,
    })
}

/// Replaces gh-aw's directory TMP with this attempt's download of check's
/// outputs: the items, the configuration, the report and the patch, and
/// for NATIVE the policy routing types to `agentic-job publish`.
fn fresh_tmp(scratch: &Scratch, case: &Value, tmp: &Path, native: bool) {
    if tmp.exists() {
        std::fs::remove_dir_all(tmp).unwrap();
    }
    std::fs::create_dir_all(tmp).unwrap();
    if native {
        std::fs::write(tmp.join("policy.json"), native_policy(case).to_string()).unwrap();
    }
    std::fs::write(tmp.join("config.json"), case["config"].to_string()).unwrap();
    std::fs::write(
        tmp.join("agent_output.json"),
        json!({"items": case["items"], "errors": []}).to_string(),
    )
    .unwrap();
    std::fs::write(tmp.join("report.json"), json!({}).to_string()).unwrap();
    for entry in std::fs::read_dir(scratch.path("download"))
        .into_iter()
        .flatten()
    {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), tmp.join(entry.file_name())).unwrap();
    }
}

/// The forge's starting state: the repositories, then the case's
/// resources, and `filler` comments by someone else, to page through.
fn seed(case: &Value) -> Value {
    let mut seed = Map::new();
    for (repo, fork) in [(REPO, false), (FORK, true)] {
        let (owner, name) = repo.split_once('/').unwrap();
        seed.insert(
            format!("/repos/{repo}"),
            json!({
                "id": if fork { 78 } else { 77 },
                "node_id": format!("R_{repo}"),
                "name": name,
                "full_name": repo,
                "owner": {"login": owner, "type": "User"},
                "private": false,
                "fork": fork,
                "default_branch": "main",
                "html_url": format!("{SERVER}/{repo}"),
                "clone_url": format!("{SERVER}/{repo}.git"),
            }),
        );
    }
    for (path, value) in case["forge"].as_object().into_iter().flatten() {
        seed.insert(path.clone(), value.clone());
    }
    for (path, count) in case["filler"].as_object().into_iter().flatten() {
        let comments = seed
            .entry(path.clone())
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .unwrap();
        // Filler precedes any seeded match, so that the handler has to
        // reach the next page to find it.
        let filler = (1..=count.as_u64().unwrap()).map(|id| {
            json!({
                "id": id,
                "body": format!("Comment {id}."),
                "user": {"login": "someone-else", "type": "User"},
            })
        });
        comments.splice(0..0, filler);
    }
    Value::Object(seed)
}

/// Runs apply.yml's bash step NAME with ENV, its script edited by EDIT,
/// and returns its exit status, outputs and annotations.
fn bash_step(
    doc: &Yaml,
    scratch: &Scratch,
    name: &str,
    env: &[(String, String)],
    edit: impl Fn(&str) -> String,
) -> (i32, BTreeMap<String, String>, Vec<String>, String) {
    let step = step(doc, name);
    let output_file = scratch.path("github-output");
    let summary = scratch.path("step-summary");
    std::fs::write(&output_file, "").unwrap();
    std::fs::write(&summary, "").unwrap();
    let output = Command::new("bash")
        .args([
            "-eo",
            "pipefail",
            "-c",
            &edit(step["run"].as_str().unwrap()),
        ])
        .env_clear()
        .envs(env.iter().cloned())
        .envs(literal_env(&step["env"]))
        .env("GITHUB_OUTPUT", &output_file)
        .env("GITHUB_STEP_SUMMARY", &summary)
        .current_dir(scratch.path("workspace"))
        .output()
        .unwrap();
    if std::env::var_os("AGENTIC_JOB_TEST_VERBOSE").is_some() {
        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    (
        output.status.code().unwrap_or(-1),
        read_commands(&output_file),
        annotations(&output.stdout),
        std::fs::read_to_string(&summary).unwrap(),
    )
}

/// Runs apply.yml's steps that route requests to `agentic-job publish`
/// and run it, with its git server the bare repositories, and returns
/// whether it routed, how it ended, the requests it left gh-aw's handlers
/// and its error report.
fn publish_steps(
    doc: &Yaml,
    scratch: &Scratch,
    forge: &Forge,
    env: &[(String, String)],
    tmp: &Path,
) -> Value {
    forge.state().step = "publish".into();
    let (exit, outputs, ..) = bash_step(doc, scratch, ROUTE_STEP, env, str::to_owned);
    assert_eq!(exit, 0, "{ROUTE_STEP}");
    if outputs.get("native").map(String::as_str) != Some("true") {
        return json!({"routed": false});
    }
    let mut env = env.to_vec();
    env.push(("GH_TOKEN".into(), TOKEN.into()));
    let server = format!("file://{}", scratch.path("server").display());
    let (exit, outputs, annotations, _) = bash_step(doc, scratch, PUBLISH_STEP, &env, |script| {
        // Git's server alone, as gh-aw's handlers have it: the bare
        // repositories. The links it writes still name GITHUB_SERVER_URL.
        let from = r#"--server "$GITHUB_SERVER_URL""#;
        assert!(script.contains(from), "{PUBLISH_STEP}");
        script.replace(from, &format!("--server {server}"))
    });
    json!({
        "routed": true,
        "exit": exit,
        "outputs": outputs,
        "annotations": annotations,
        "remainder": read_json(&tmp.join("gh-aw-output.json"))["items"],
        "errors": read_json(&tmp.join("publish-errors.json")),
    })
}

/// Runs CASE as apply.yml would: with PATHS, gh-aw's steps in the pinned
/// checkouts, and without, the recorded guard's output in the guard's
/// place and no gh-aw step; with NATIVE, the bounds routing the case's
/// types of [`NATIVE`] to `agentic-job publish`, whose steps run before
/// gh-aw's (step `publish` of the requests). Its git server is the bare
/// repositories, as for gh-aw's handlers.
fn run_case(paths: Option<&Paths>, case: &Value, native: bool) -> Value {
    let name = case["name"].as_str().unwrap();
    let text = apply_text();
    let doc = &YamlLoader::load_from_str(&text).unwrap()[0];
    let scratch = Scratch {
        dir: tempfile::tempdir().unwrap(),
    };
    for dir in [
        "home",
        "runner-temp/gh-aw/actions",
        "runner-temp/apply-binary",
        "workspace",
        "server",
    ] {
        std::fs::create_dir_all(scratch.path(dir)).unwrap();
    }
    // As gh-aw's setup action copies its scripts.
    for entry in paths
        .map(|paths| std::fs::read_dir(paths.gh_aw.join("actions/setup/js")).unwrap())
        .into_iter()
        .flatten()
    {
        let entry = entry.unwrap();
        let file = entry.file_name().into_string().unwrap();
        if (file.ends_with(".cjs") && !file.ends_with(".test.cjs")) || file.ends_with(".json") {
            std::fs::copy(
                entry.path(),
                scratch.path("runner-temp/gh-aw/actions").join(&file),
            )
            .unwrap();
        }
    }
    // As apply.yml downloads policy's.
    std::fs::copy(
        env!("CARGO_BIN_EXE_agentic-job"),
        scratch.path("runner-temp/apply-binary/agentic-job"),
    )
    .unwrap();
    // gh-aw's handlers keep their files in its fixed directory; without
    // them, the steps are given one of the scratch's.
    let tmp = match paths {
        Some(_) => PathBuf::from(GH_AW_TMP),
        None => scratch.path("gh-aw"),
    };
    let recorded_guard = if paths.is_none() {
        read_json(&golden(name))
    } else {
        Value::Null
    };
    std::fs::write(
        scratch.path("gitconfig"),
        format!(
            "[url \"file://{}/\"]\n\tinsteadOf = {SERVER}/\n[init]\n\tdefaultBranch = main\n",
            scratch.path("server").display()
        ),
    )
    .unwrap();
    // The event apply was started by: a case's, or a dispatch's with nothing.
    let event = case.get("event").cloned().unwrap_or_else(|| json!({}));
    std::fs::write(scratch.path("event.json"), event.to_string()).unwrap();
    let mut text = case.to_string();
    for (placeholder, value) in prepare_git(&scratch, case, native) {
        text = text.replace(&placeholder, &value);
    }
    let case: &Value = &serde_json::from_str(&text).unwrap();
    let before = branches(&scratch);
    // apply-source, the sparse checkout of this repository's workflow/.
    let source = scratch.path("workspace/apply-source");
    std::fs::create_dir_all(&source).unwrap();
    std::os::unix::fs::symlink(root().join("workflow"), source.join("workflow")).unwrap();
    let faults = case["faults"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|fault| Fault {
            attempt: fault["attempt"].as_u64().unwrap_or(1),
            method: fault["method"].as_str().unwrap().into(),
            path: fault["path"].as_str().unwrap().into(),
            status: u16::try_from(fault["status"].as_u64().unwrap()).unwrap(),
        })
        .collect();
    let forge = Forge::start(&seed(case), faults);
    // What differs from one run to the next: the forge's port, the
    // scratch directory, the time and the handlers' random temporary IDs.
    let time = regex::Regex::new(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z").unwrap();
    let temporary = regex::Regex::new(r"\baw_[A-Za-z0-9]{8}\b").unwrap();
    let normalize = |value: Value| -> Value {
        let text = value
            .to_string()
            .replace(&forge.url, API)
            .replace(&scratch.dir.path().display().to_string(), WORK);
        let text = time.replace_all(&text, "{time}");
        serde_json::from_str(&temporary.replace_all(&text, "{temporary_id}")).unwrap()
    };

    let has_patch = !case["git"].is_null();
    // The project fields' step is recorded only where there is one to check.
    let has_project = case["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["type"] == "update_project");
    let mut vars: BTreeMap<String, String> = [
        ("OUTPUT_REPO", REPO),
        ("ITEM_REPO", REPO),
        ("REPO", REPO),
        ("BASE", "main"),
        ("ISSUE", ""),
        ("FORK", if has_patch { FORK } else { "" }),
        ("READY", ""),
        ("BRANCH_PREFIX", ""),
        ("PARTIAL", ""),
        ("TITLE_PREFIX", ""),
        ("COMMENT_TARGET", "7"),
        ("ARTIFACT_PREFIX", ""),
        ("TOKEN_IS_PAT", "true"),
        ("TREE", ""),
        ("REPLACEMENT_HEAD", ""),
        ("GH_AW_AGENT_OUTPUT", "/tmp/gh-aw/agent_output.json"),
        ("GH_AW_JOB_CHECK_RUN_ID", "9001"),
        ("GH_AW_WORKFLOW_NAME", "agentic-job"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect();
    let domains: Vec<String> = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../safe-outputs/src/top-level-domains.txt"),
    )
    .unwrap()
    .lines()
    .filter(|line| !line.starts_with('#'))
    .map(str::to_lowercase)
    .collect();
    vars.insert("GH_AW_ALLOWED_DOMAINS".into(), domains.join(","));
    for (key, value) in case["env"].as_object().into_iter().flatten() {
        vars.insert(key.clone(), value.as_str().unwrap().into());
    }

    let path = std::env::var("PATH").unwrap();
    let mut base: Vec<(String, String)> = scratch.git_env();
    base.extend(
        [
            ("PATH", path.as_str()),
            ("LANG", "C.UTF-8"),
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SERVER_URL", SERVER),
            ("GITHUB_API_URL", &forge.url),
            ("GITHUB_REPOSITORY", REPO),
            ("GITHUB_REPOSITORY_OWNER", "owner"),
            ("GITHUB_REPOSITORY_ID", "77"),
            ("GITHUB_RUN_ID", RUN_ID),
            ("GITHUB_RUN_NUMBER", "1"),
            ("GITHUB_JOB", "apply"),
            ("GITHUB_WORKFLOW", "agentic-job"),
            (
                "GITHUB_EVENT_NAME",
                case["event_name"].as_str().unwrap_or("workflow_dispatch"),
            ),
            ("GITHUB_SHA", &"a".repeat(40)),
            ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_ACTOR", "owner"),
        ]
        .map(|(key, value)| (key.to_owned(), value.to_owned())),
    );
    base.push((
        "GITHUB_GRAPHQL_URL".into(),
        format!("{}/graphql", forge.url),
    ));
    for (key, dir) in [
        ("RUNNER_TEMP", "runner-temp"),
        ("GITHUB_WORKSPACE", "workspace"),
        ("GITHUB_EVENT_PATH", "event.json"),
    ] {
        base.push((key.into(), scratch.path(dir).display().to_string()));
    }
    base.extend(literal_env(&doc["env"]));
    base.extend(literal_env(&doc["jobs"]["apply"]["env"]));
    base.extend(vars.iter().map(|(k, v)| (k.clone(), v.clone())));
    for (key, file) in [
        ("GH_AW_TMP", ""),
        ("REPORT", "/report.json"),
        ("MADE", "/safe-output-items.jsonl"),
        ("GH_AW_AGENT_OUTPUT", "/agent_output.json"),
    ] {
        base.push((key.into(), format!("{}{file}", tmp.display())));
    }

    let attempts = case["attempts"].as_u64().unwrap_or(1);
    let mut recorded = vec![];
    for attempt in 1..=attempts {
        let before_attempt = branches(&scratch);
        if has_patch {
            // A re-run has a fresh checkout and fetches the head again
            // before its trial and guard; do not keep the first attempt's
            // stale target-base ref (or its handler's working branch).
            let workspace = scratch.path("workspace");
            scratch.git(&workspace, &["checkout", "--quiet", "main"]);
            let base = &vars["BASE"];
            scratch.git(
                &workspace,
                &[
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    &format!("{SERVER}/{}", if base == "main" { REPO } else { FORK }),
                    &format!("+refs/heads/{base}:refs/agentic-job/target-base"),
                ],
            );
        }
        forge.state().attempt = attempt;
        fresh_tmp(&scratch, case, &tmp, native);
        let mut env = base.clone();
        env.push(("GITHUB_RUN_ATTEMPT".into(), attempt.to_string()));

        let config = step(doc, CONFIG_STEP);
        let github_env = scratch.path("github-env");
        std::fs::write(&github_env, "").unwrap();
        let configured = Command::new("bash")
            .args(["-euo", "pipefail", "-c", config["run"].as_str().unwrap()])
            .env_clear()
            .envs(env.iter().cloned())
            .envs(literal_env(&config["env"]))
            .env("GITHUB_ENV", &github_env)
            .output()
            .unwrap();
        assert!(
            configured.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&configured.stderr)
        );
        env.extend(read_commands(&github_env));

        let mut steps = Map::new();
        let mut edits = vec![];
        if paths.is_some() {
            if case["review"] == true {
                // check.yml produces this upload with policy's binary;
                // apply.yml moves it into place, rather than folding twice.
                let folded = Command::new(env!("CARGO_BIN_EXE_agentic-job"))
                    .args(["review", "fold"])
                    .arg(tmp.join("agent_output.json"))
                    .output()
                    .unwrap();
                assert!(folded.status.success(), "{name}: review fold");
                std::fs::write(tmp.join("folded.json"), folded.stdout).unwrap();
            }
            for (enabled, name) in [
                (case["review"] == true, FOLD_STEP),
                (!vars["PARTIAL"].is_empty(), PARTIAL_STEP),
                (has_patch, ISSUE_STEP),
            ] {
                if !enabled {
                    continue;
                }
                let (exit, outputs, annotations, summary) =
                    bash_step(doc, &scratch, name, &env, str::to_owned);
                edits.push(json!({
                    "step": name, "exit": exit, "outputs": outputs,
                    "annotations": annotations, "summary": summary,
                    "items": read_json(&tmp.join("agent_output.json"))["items"],
                }));
                assert_eq!(exit, 0, "{name}: request edit failed");
            }
        }
        for (label, step_name) in [("guard", GUARD_STEP), ("apply", APPLY_STEP)] {
            // A guard that fails skips the handlers, as a failed step does.
            if label == "apply" && steps["guard"]["exit"] != 0 {
                steps.insert(label.into(), Value::Null);
                continue;
            }
            let Some(paths) = paths else {
                // The recorded guard's output, without gh-aw's step.
                if label == "guard" {
                    let guard =
                        &recorded_guard["attempts"][usize::try_from(attempt).unwrap() - 1]["guard"];
                    let items = json!({"items": guard["items"], "errors": []});
                    std::fs::write(tmp.join("agent_output.json"), items.to_string()).unwrap();
                    steps.insert(label.into(), guard.clone());
                }
                continue;
            };
            if label == "apply" {
                // Before either publisher; one that fails skips agentic-job's.
                forge.state().step = "project".into();
                let script = step(doc, PROJECT_STEP)["with"]["script"].as_str().unwrap();
                let (exit, ..) = github_script(paths, &scratch, &env, script);
                let checked = if exit == 0 { "success" } else { "failure" };
                env.push(("PROJECT_CHECKED".into(), checked.into()));
                if has_project {
                    steps.insert("project".into(), json!({ "exit": exit }));
                }
                if native && exit == 0 {
                    let published = publish_steps(doc, &scratch, &forge, &env, &tmp);
                    if published["routed"] == true {
                        env.push((
                            "GH_AW_AGENT_OUTPUT".into(),
                            tmp.join("gh-aw-output.json").display().to_string(),
                        ));
                    }
                    steps.insert("publish".into(), published);
                }
            }
            forge.state().step = label.into();
            let (exit, outputs, annotations, summary) = if label == "guard" {
                // Policy's binary, given the token as GH_TOKEN.
                let mut env = env.clone();
                env.push(("GH_TOKEN".into(), TOKEN.into()));
                bash_step(doc, &scratch, step_name, &env, str::to_owned)
            } else {
                let step = step(doc, step_name);
                let mut step_env = env.clone();
                step_env.extend(literal_env(&step["env"]));
                github_script(
                    paths,
                    &scratch,
                    &step_env,
                    step["with"]["script"].as_str().unwrap(),
                )
            };
            let mut result = json!({
                "exit": exit,
                "outputs": outputs,
                "annotations": annotations,
                "summary": summary,
            });
            if label == "guard" {
                result["items"] = read_json(&tmp.join("agent_output.json"))["items"].clone();
                result["skipped"] = read_json(&tmp.join("skipped.json"));
            } else {
                result["made"] = read_jsonl(&tmp.join("safe-output-items.jsonl"));
                result["errors"] = read_json(&tmp.join("safe-output-errors.json"));
            }
            steps.insert(label.into(), result);
        }
        let index = usize::try_from(attempt).unwrap() - 1;
        // The recorded project fields' step, which agentic-job's waits for.
        let project = recorded_guard["attempts"][index]["project"]["exit"].as_i64();
        if paths.is_none() && native && steps["guard"]["exit"] == 0 && project.unwrap_or(0) == 0 {
            let published = publish_steps(doc, &scratch, &forge, &env, &tmp);
            steps.insert("publish".into(), published);
        }
        let requests = std::mem::take(&mut forge.state().requests);
        let mut attempt = json!({
            "handler_config": read_json(&tmp.join("handler-config.json")),
            "guard": steps["guard"],
            "apply": steps.get("apply").cloned().unwrap_or(Value::Null),
            "requests": requests,
        });
        if !edits.is_empty() {
            attempt["edits"] = json!(edits);
        }
        if has_patch {
            attempt["pushed"] = pushed(&scratch, &before_attempt);
        }
        for label in ["project", "publish"] {
            if let Some(result) = steps.get(label) {
                attempt[label] = result.clone();
            }
        }
        recorded.push(attempt);
    }
    normalize(json!({
        "pins": pins(),
        "case": name,
        "attempts": recorded,
        "pushed": pushed(&scratch, &before),
    }))
}

fn checkout(var: &str, want: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(var).unwrap_or_else(|| panic!("{var} must name the pinned checkout")),
    );
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .current_dir(&path)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{var}: git {args:?} failed");
        String::from_utf8(output.stdout).unwrap()
    };
    assert_eq!(
        git(&["rev-parse", "HEAD"]).trim(),
        want,
        "{var} is not at apply.yml's pin"
    );
    assert_eq!(
        git(&["status", "--porcelain", "--untracked-files=no"]),
        "",
        "{var} has changes to the pinned files"
    );
    path
}

/// Keep CI diagnostics useful without letting a large golden swamp the log.
fn drift_diff(expected: &Path, actual: &Path) -> String {
    const MAX_LINES: usize = 120;
    const MAX_BYTES: usize = 16 * 1024;
    let diff = Command::new("git")
        .args([
            "diff",
            "--no-index",
            "--no-ext-diff",
            "--no-color",
            "--unified=3",
            "--",
        ])
        .args([expected, actual])
        .output()
        .unwrap();
    assert!(
        matches!(diff.status.code(), Some(0 | 1)),
        "git diff: {}",
        String::from_utf8_lossy(&diff.stderr)
    );
    let text = String::from_utf8_lossy(&diff.stdout);
    let mut shown = String::new();
    for (at, line) in text.split_inclusive('\n').enumerate() {
        if at >= MAX_LINES || shown.len() + line.len() > MAX_BYTES {
            shown.push_str("\n[diff truncated; full actual file is saved at the path above]\n");
            break;
        }
        shown.push_str(line);
    }
    shown
}

#[test]
fn drift_diff_is_unified_and_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let expected = dir.path().join("expected.json");
    let actual = dir.path().join("actual.json");
    std::fs::write(&expected, "old\n").unwrap();
    std::fs::write(&actual, "new\n").unwrap();
    let diff = drift_diff(&expected, &actual);
    assert!(diff.contains("@@ -1 +1 @@\n-old\n+new\n"), "{diff}");
    for text in ["new\n".repeat(200), "x".repeat(32 * 1024)] {
        std::fs::write(&actual, text).unwrap();
        let diff = drift_diff(&expected, &actual);
        assert!(diff.contains("[diff truncated;"));
        assert!(diff.len() < 17 * 1024);
        assert!(diff.lines().count() <= 122);
    }
}

#[test]
#[ignore = "needs the pinned gh-aw and github-script checkouts; CI's publication job runs it"]
fn handlers_publish_as_recorded() {
    let pins = pins();
    let paths = Paths {
        gh_aw: checkout(GH_AW_VAR, pins["gh_aw"].as_str().unwrap()),
        github_script: checkout(GITHUB_SCRIPT_VAR, pins["github_script"].as_str().unwrap()),
    };
    let bless = std::env::var_os(BLESS_VAR).is_some();
    let only = std::env::var("AGENTIC_JOB_TEST_CASE").ok();
    let mut drifted = vec![];
    for case in cases() {
        let name = case["name"].as_str().unwrap();
        if only.as_deref().is_some_and(|only| only != name) {
            continue;
        }
        let got = run_case(Some(&paths), &case, false);
        let text = serde_json::to_string_pretty(&got).unwrap() + "\n";
        if bless {
            std::fs::write(golden(name), text).unwrap();
        } else if std::fs::read_to_string(golden(name)).ok().as_deref() != Some(&text) {
            let actual = std::env::temp_dir().join(format!("publication-{name}.json"));
            std::fs::write(&actual, &text).unwrap();
            eprintln!(
                "{name} (now: {})\n{}",
                actual.display(),
                drift_diff(&golden(name), &actual)
            );
            drifted.push(format!("{name} (now: {})", actual.display()));
            // A stale expectation must not hide its diff behind a routed
            // parity assertion against that same stale expectation.
            continue;
        }
        // Here, as each one's gh-aw_TMP is the one fixed directory.
        assert_routed_as_recorded(&run_case(Some(&paths), &case, true), &case);
    }
    assert!(
        drifted.is_empty(),
        "the pinned handlers no longer publish as recorded: {drifted:?}; \
         compare, and record again with {BLESS_VAR}=1 if the change is intended"
    );
}

/// The writes of REQUESTS made in STEPS, each with its method, path,
/// version, body and keys, in order.
fn writes(requests: &Value, steps: &[&str]) -> Vec<Value> {
    requests
        .as_array()
        .unwrap()
        .iter()
        .filter(|request| {
            steps.contains(&request["step"].as_str().unwrap()) && request["method"] != "GET"
        })
        .map(|request| {
            let mut request = request.clone();
            request.as_object_mut().unwrap().remove("step");
            request
        })
        .collect()
}

/// GOT, a run of NAME with `agentic-job publish` before gh-aw's handlers,
/// published what the recorded run of gh-aw's handlers alone did: the
/// same writes in the same order, the same commits, and the same record
/// of what was made.
fn assert_routed_as_recorded(got: &Value, case: &Value) {
    let name = case["name"].as_str().unwrap();
    let recorded = read_json(&golden(name));
    // The guard's name of a pull request digests its patch, which holds
    // check's base header here.
    let applied = regex::Regex::new(r"agentic-job-applied: \d+/\d+/[0-9a-f]{16}").unwrap();
    for (at, (got, recorded)) in got["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .zip(recorded["attempts"].as_array().unwrap())
        .enumerate()
    {
        let what = format!("{name}, attempt {} with agentic-job's handlers", at + 1);
        let writes = |requests: &Value, steps: &[&str]| {
            applied
                .replace_all(&json!(writes(requests, steps)).to_string(), "{applied}")
                .into_owned()
        };
        assert_eq!(
            writes(&got["requests"], &["publish", "apply"]),
            writes(&recorded["requests"], &["apply"]),
            "{what}: writes"
        );
        assert_eq!(
            got["apply"]["made"], recorded["apply"]["made"],
            "{what}: made"
        );
        // Each request was published once: gh-aw's step had the others.
        if got["publish"]["routed"] == true {
            let theirs: Vec<&Value> = got["guard"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|item| !routed(case).contains(&item["type"].as_str().unwrap()))
                .collect();
            assert_eq!(
                got["publish"]["remainder"],
                left(case, &theirs, recorded),
                "{what}: remainder"
            );
        }
    }
    assert_eq!(got["pushed"], recorded["pushed"], "{name}: pushed");
}

/// THEIRS, the requests CASE leaves gh-aw's handlers, as `agentic-job
/// publish` leaves them after the RECORDED attempt's failures: gh-aw's
/// handler manager starts each comment after a pull request that failed
/// with a warning, which only its step would know of otherwise.
fn left(case: &Value, theirs: &[&Value], recorded: &Value) -> Value {
    let failed = recorded["apply"]["errors"]["failures"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|failure| failure["type"] == "create_pull_request")
        .filter(|_| routed(case).contains(&"create_pull_request"));
    let mut theirs: Vec<Value> = theirs.iter().map(|item| (*item).clone()).collect();
    if let Some(failure) = failed {
        for item in theirs
            .iter_mut()
            .filter(|item| item["type"] == "add_comment")
        {
            item["body"] = json!(format!(
                "\n\n---\n> [!WARNING]\n> The `create_pull_request` operation failed: {}. \
                 The code changes were not applied.\n\n{}",
                failure["error"].as_str().unwrap(),
                item["body"].as_str().unwrap_or_default()
            ));
        }
    }
    json!(theirs)
}

/// apply.yml's steps route each case's types of [`NATIVE`] to `agentic-job
/// publish`, which publishes them as the recorded run of gh-aw's handlers
/// did, first, and leaves gh-aw's step the rest: run with the recorded
/// guard's output, without gh-aw's steps, against the loopback forge.
#[test]
fn routed_steps_publish_first_and_leave_the_rest() {
    for case in cases() {
        let name = case["name"].as_str().unwrap();
        let got = run_case(None, &case, true);
        let recorded = read_json(&golden(name));
        let routed = native_policy(&case) != json!({});
        for (at, (got, recorded)) in got["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .zip(recorded["attempts"].as_array().unwrap())
            .enumerate()
        {
            let what = format!("{name}, attempt {}", at + 1);
            let published = &got["publish"];
            // A guard or project fields' step that refused the run stops
            // it before either publisher.
            if recorded["guard"]["exit"] != 0
                || recorded["project"]["exit"].as_i64().unwrap_or(0) != 0
            {
                assert!(published.is_null(), "{what}");
                continue;
            }
            assert_eq!(published["routed"], json!(routed), "{what}");
            if !routed {
                assert!(writes(&got["requests"], &["publish"]).is_empty(), "{what}");
                continue;
            }
            let items = got["guard"]["items"].as_array().unwrap();
            let (ours, theirs): (Vec<&Value>, Vec<&Value>) = items
                .iter()
                .partition(|item| self::routed(&case).contains(&item["type"].as_str().unwrap()));
            assert_eq!(
                published["remainder"],
                left(&case, &theirs, recorded),
                "{what}: remainder"
            );
            // The routed requests come first, and so do their writes.
            let mine = writes(&got["requests"], &["publish"]);
            let all = writes(&recorded["requests"], &["apply"]);
            assert!(
                all.starts_with(&mine) && (ours.len() < items.len() || mine == all),
                "{what}: {mine:#?}\nnot the start of the recorded {all:#?}"
            );
            // It fails where one of its types failed gh-aw's handlers.
            let failed = recorded["apply"]["errors"]["failures"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|failure| ours.iter().any(|item| item["type"] == failure["type"]));
            assert_eq!(published["exit"], json!(i32::from(failed)), "{what}: exit");
        }
        if routed && !case["git"].is_null() {
            assert_eq!(got["pushed"], recorded["pushed"], "{name}: pushed");
        }
    }
}
