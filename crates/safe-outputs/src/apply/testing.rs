//! A mock forge and test repositories for the publishers' tests, and for
//! a caller's tests of its own adapters (feature `test-support`).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

use super::github::Github;
use super::roles::{Credential, Identity, Role};
use super::{BranchPush, Committer, Provenance, PullRequest};

/// The committer of the test pushes: a caller's, not agentic-job's.
pub const COMMITTER: (&str, &str) = ("example-ci", "ci@example.invalid");

/// The context of the test statuses.
pub const STATUS_CONTEXT: &str = "example-ci";

/// How the tests' caller names itself.
pub const PROVENANCE: Provenance<'static> = Provenance {
    name: "example-ci",
    status_context: STATUS_CONTEXT,
    committer: COMMITTER,
};

/// The token the tests' GitHub client sends.
pub const TOKEN: &str = "test-token-not-secret";

/// A forge that answers `METHOD PATH` with the status and JSON ROUTES
/// give it, and 404 for anything else, and a GitHub client of it whose
/// fork wait and retries take no time.
pub fn forge(routes: BTreeMap<String, (u16, Value)>) -> (Github, mpsc::Receiver<Request>) {
    let (server, requests) = serve(usize::MAX, move |request| {
        let asked = request.line.trim_end_matches(" HTTP/1.1");
        let (status, body) = routes.get(asked).cloned().unwrap_or((404, json!({})));
        (status, body.to_string())
    });
    let mut github = Github::new(&server, TOKEN.to_owned(), PROVENANCE).unwrap();
    github.fork_wait = Duration::ZERO;
    github.retry_wait = Duration::ZERO;
    (github, requests)
}

/// GITHUB with a separate credential for each role, all of one identity.
pub fn bound(github: Github) -> Github {
    github
        .with_roles(
            Role::ALL
                .into_iter()
                .map(|role| {
                    (
                        role,
                        Credential {
                            identity: Identity {
                                actor_id: 7,
                                app_id: None,
                            },
                            token: ["fake", role.token_env(), "credential"].join("-"),
                        },
                    )
                })
                .collect(),
        )
        .for_role(Role::Publication)
        .unwrap()
}

/// [`COMMITTER`], as an op holds it.
pub fn committer() -> Committer {
    Committer {
        name: COMMITTER.0.to_owned(),
        email: COMMITTER.1.to_owned(),
    }
}

/// What the mock forge was sent: the request line, the authorization
/// header and the body.
#[derive(Debug)]
pub struct Request {
    pub line: String,
    pub authorization: String,
    /// `X-GitHub-Api-Version`, empty without one.
    pub api_version: String,
    pub body: Value,
}

/// A forge that answers each request with STATUS and BODY in turn.
pub fn mock(answers: Vec<(u16, String)>) -> (String, mpsc::Receiver<Request>) {
    let mut answers = answers.into_iter();
    serve(answers.len(), move |_| answers.next().unwrap())
}

/// A forge that answers COUNT requests, each with the status and body
/// ANSWER gives for it.
pub fn serve(
    count: usize,
    mut answer: impl FnMut(&Request) -> (u16, String) + Send + 'static,
) -> (String, mpsc::Receiver<Request>) {
    serve_with_headers(count, move |request| {
        let (status, body) = answer(request);
        (status, String::new(), body)
    })
}

pub fn serve_with_headers(
    count: usize,
    mut answer: impl FnMut(&Request) -> (u16, String, String) + Send + 'static,
) -> (String, mpsc::Receiver<Request>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    let (sent, received) = mpsc::channel();
    std::thread::spawn(move || {
        for _ in 0..count {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let (mut authorization, mut api_version, mut length) =
                (String::new(), String::new(), 0);
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header == "\r\n" {
                    break;
                }
                let (name, value) = header.split_once(':').unwrap();
                match name.to_ascii_lowercase().as_str() {
                    "authorization" => authorization = value.trim().to_owned(),
                    "x-github-api-version" => api_version = value.trim().to_owned(),
                    "content-length" => length = value.trim().parse().unwrap(),
                    _ => {}
                }
            }
            let mut request = vec![0; length];
            reader.read_exact(&mut request).unwrap();
            let request = Request {
                line: line.trim().to_owned(),
                authorization,
                api_version,
                body: if request.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&request).unwrap()
                },
            };
            let (status, headers, body) = answer(&request);
            // A test that stopped listening has its answer already.
            let _ = sent.send(request);
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 {status} X\r\n{headers}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    (server, received)
}

/// The message of the patch's commit, with trailers a merger reads.
pub const MESSAGE: &str = "Change things\n\nWhy, at  length.\n\n\
    Generated-by: https://github.com/cgwalters/#llms\nCloses #5\n";

pub fn sh(dir: &Path, args: &[&str]) -> String {
    String::from_utf8(git_out(dir, args))
        .unwrap()
        .trim()
        .to_owned()
}

pub fn git_out(dir: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.org",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// A bare repository with one commit on main, an empty bare fork of
/// it, and the pull request of a patch on it adding `src/x` and a
/// line to the README. Every line ends with EOL.
pub fn repository_with(eol: &str) -> (tempfile::TempDir, PullRequest) {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    std::fs::create_dir(&work).unwrap();
    sh(&work, &["init", "-q"]);
    std::fs::write(work.join("README"), format!("hi{eol}")).unwrap();
    sh(&work, &["add", "README"]);
    sh(&work, &["commit", "-q", "-m", "Start"]);
    let base = sh(&work, &["rev-parse", "HEAD"]);
    std::fs::write(work.join("README"), format!("hi{eol}more{eol}")).unwrap();
    std::fs::create_dir(work.join("src")).unwrap();
    std::fs::write(work.join("src/x"), format!("x{eol}")).unwrap();
    sh(&work, &["add", "README", "src/x"]);
    let message = root.path().join("message");
    std::fs::write(&message, MESSAGE).unwrap();
    sh(&work, &["commit", "-q", "-F", message.to_str().unwrap()]);
    let patch = sh(&work, &["format-patch", "-1", "--stdout"]) + "\n";
    sh(&work, &["reset", "-q", "--hard", "HEAD~"]);
    let bare = root.path().join("owner/name.git");
    std::fs::create_dir_all(&bare).unwrap();
    sh(&bare, &["init", "-q", "--bare"]);
    sh(
        &work,
        &["push", "-q", bare.to_str().unwrap(), "HEAD:refs/heads/main"],
    );
    let fork = root.path().join("fork/name.git");
    std::fs::create_dir_all(&fork).unwrap();
    sh(&fork, &["init", "-q", "--bare"]);
    let pr = PullRequest {
        replay: None,
        base: "main".into(),
        base_commit: base,
        push_repo: "fork/name".into(),
        private: false,
        branch: "agent-run-7".into(),
        title: "WIP: Fix it".into(),
        body: "Why.".into(),
        draft: true,
        patch: patch.into_bytes(),
        files: vec!["README".into(), "src/x".into()],
        committer: committer(),
    };
    (root, pr)
}

pub fn repository() -> (tempfile::TempDir, PullRequest) {
    repository_with("\n")
}

/// The repository of [`repository`], whose fork holds pull request 9's
/// branch `agent-run-7` at the patch's base, and the push of the patch
/// on it.
pub fn pull_request_branch() -> (tempfile::TempDir, BranchPush) {
    let (root, pr) = repository();
    let fork = root.path().join("fork/name.git");
    sh(
        &root.path().join("owner/name.git"),
        &[
            "push",
            "-q",
            fork.to_str().unwrap(),
            "main:refs/heads/agent-run-7",
        ],
    );
    let push = BranchPush {
        number: 9,
        push_repo: pr.push_repo,
        private: false,
        branch: pr.branch,
        head: pr.base_commit,
        patch: pr.patch,
        files: pr.files,
        committer: pr.committer,
    };
    (root, push)
}
