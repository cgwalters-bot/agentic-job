use super::*;
use serde_json::json;
use std::io::Write;

const AGENT_JOB_ID: u64 = 201;

fn record() -> Record {
    Record {
        forge: FORGE.into(),
        server: "https://gitlab.example.com".into(),
        caller_project: "group/caller".into(),
        caller_project_id: 11,
        caller_pipeline_id: 5001,
        caller_job_id: 90001,
        profile_commit: "1".repeat(40),
        kind: "implement".into(),
        target_repository: "group/sub/project".into(),
        target_branch: "main".into(),
        base_commit: "2".repeat(40),
        item: 7,
        project: "group/producer".into(),
        project_id: 12,
        reference: "main".into(),
        commit: "3".repeat(40),
        ci_config_path: String::new(),
        pipeline_id: 5002,
        user_id: 42,
        variables: BTreeMap::from([
            (RELEASE_VARIABLE.into(), "v0.6.13".into()),
            (SHA256_VARIABLE.into(), "4".repeat(64)),
            ("AGENT_ISSUE_IID".into(), "7".into()),
        ]),
        agentic_job: "5".repeat(40),
        agent_job: "agent".into(),
        check_job: "check".into(),
        detect_job: "detect".into(),
        dispatched_at: "2026-11-13T10:00:00Z".parse().unwrap(),
        deadline: "2026-11-13T15:30:00Z".parse().unwrap(),
    }
}

fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, content) in files {
        zip.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

/// One change to the fixture's API answers.
type Change = Box<dyn Fn(&mut Fixture) + Send>;

struct Fixture {
    now: DateTime<Utc>,
    caller_jobs: Vec<Value>,
    project: Value,
    pipeline: Value,
    variables: Vec<Value>,
    jobs: Vec<Value>,
    bytes: Vec<u8>,
    /// Applied once, when the archive is downloaded.
    at_release: Option<Change>,
    /// A running pipeline succeeds at the next poll, rather than the
    /// fetch waiting out its deadline.
    succeed_on_wait: bool,
    downloads: Vec<String>,
}

impl Fixture {
    fn new(record: &Record, bytes: Vec<u8>) -> Self {
        let job = |id: u64, name: &str| {
            json!({
                "id": id, "name": name, "status": "success",
                "pipeline": {"id": record.pipeline_id, "project_id": record.project_id,
                             "sha": record.commit, "ref": record.reference},
                "user": {"id": record.user_id}, "erased_at": null,
                "artifacts_file": {"filename": "artifacts.zip", "size": bytes.len()},
                "artifacts_expire_at": "2026-11-20T10:00:00Z",
            })
        };
        Self {
            now: record.dispatched_at,
            caller_jobs: vec![
                json!({"id": 90000, "name": "prepare", "pipeline": {"id": record.caller_pipeline_id}}),
                json!({"id": record.caller_job_id, "name": "dispatch", "pipeline": {"id": record.caller_pipeline_id}}),
            ],
            project: json!({
                "id": record.project_id, "path_with_namespace": record.project,
                "ci_config_path": null,
            }),
            pipeline: json!({
                "id": record.pipeline_id, "project_id": record.project_id,
                "sha": record.commit, "ref": record.reference, "tag": false, "source": "api",
                "user": {"id": record.user_id}, "yaml_errors": null,
                "created_at": "2026-11-13T10:00:01Z", "status": "success",
            }),
            variables: record
                .variables
                .iter()
                .map(|(key, value)| json!({"key": key, "value": value, "variable_type": "env_var", "raw": false}))
                .collect(),
            jobs: vec![
                job(AGENT_JOB_ID, &record.agent_job),
                job(202, &record.check_job),
                job(203, &record.detect_job),
            ],
            bytes,
            at_release: None,
            succeed_on_wait: false,
            downloads: Vec::new(),
        }
    }
}

impl Actions for Fixture {
    fn now(&self) -> DateTime<Utc> {
        self.now
    }

    fn get(&mut self, path: &str) -> Result<Value> {
        Ok(match path.split_once('?').map_or(path, |(path, _)| path) {
            "/projects/11/pipelines/5001/jobs" => {
                ensure!(path.contains("include_retried=true"), "retries not listed");
                json!(self.caller_jobs)
            }
            "/projects/12" => self.project.clone(),
            "/projects/12/pipelines/5002" => self.pipeline.clone(),
            "/projects/12/pipelines/5002/variables" => json!(self.variables),
            "/projects/12/pipelines/5002/jobs" => {
                ensure!(path.contains("include_retried=true"), "retries not listed");
                json!(self.jobs)
            }
            _ => bail!("unexpected API route {path}"),
        })
    }

    fn download(&mut self, path: &str) -> Result<Vec<u8>> {
        self.downloads.push(path.into());
        if let Some(change) = self.at_release.take() {
            change(self);
        }
        Ok(self.bytes.clone())
    }

    fn wait(&mut self, until: DateTime<Utc>) {
        if self.succeed_on_wait {
            self.pipeline["status"] = SUCCESS.into();
            self.now += chrono::Duration::seconds(15);
        } else {
            self.now = until;
        }
    }
}

#[test]
fn recorded_pipeline_is_fetched_by_agent_job_id() {
    let record = record();
    let content = b"{\"type\":\"noop\",\"message\":\"Done\"}";
    let bytes = archive(&[("outputs.jsonl", content)]);
    let mut fixture = Fixture::new(&record, bytes.clone());
    let Fetched {
        receipt,
        archive: fetched,
        files,
    } = fetch(&mut fixture, &record).unwrap();
    assert_eq!(fetched, bytes);
    assert_eq!(files["outputs.jsonl"], content);
    assert_eq!(
        receipt.files,
        BTreeMap::from([("outputs.jsonl".to_owned(), sha256(content))])
    );
    assert_eq!(fixture.downloads, ["/projects/12/jobs/201/artifacts"]);
    assert_eq!(
        (
            receipt.agent_job_id,
            receipt.check_job_id,
            receipt.detect_job_id
        ),
        (201, 202, 203)
    );
    assert_eq!(receipt.raw.size, bytes.len() as u64);
    assert_eq!(receipt.raw.digest, sha256(&bytes));
    let parsed = Receipt::parse(&serde_json::to_vec(&receipt).unwrap()).unwrap();
    assert_eq!(parsed, receipt);
    // A running pipeline is polled until it succeeds, or the deadline.
    for succeeds in [true, false] {
        let mut fixture = Fixture::new(&record, bytes.clone());
        fixture.pipeline["status"] = "running".into();
        fixture.succeed_on_wait = succeeds;
        assert_eq!(fetch(&mut fixture, &record).is_ok(), succeeds);
    }
}

#[test]
fn http_transport_reads_the_v4_api_with_the_read_token() {
    use std::io::{BufRead, BufReader};
    let mut record = record();
    record.dispatched_at = Utc::now();
    record.deadline = record.dispatched_at + chrono::Duration::minutes(30);
    let bytes = archive(&[("outputs.jsonl", b"{\"type\":\"noop\",\"message\":\"Done\"}")]);
    let mut fixture = Fixture::new(&record, bytes.clone());
    fixture.pipeline["created_at"] = json!(record.dispatched_at);
    fixture.jobs[0]["artifacts_expire_at"] = json!(record.deadline);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    let (send, requests) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let target = line.split_whitespace().nth(1).unwrap().to_owned();
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                headers.push_str(&line.to_ascii_lowercase());
            }
            assert!(headers.contains("authorization: bearer read-only-fixture"));
            assert!(headers.contains("accept: application/json"));
            let path = target.strip_prefix(API).unwrap();
            let body = if path.ends_with("/artifacts") {
                fixture.download(path).unwrap()
            } else {
                serde_json::to_vec(&fixture.get(path).unwrap()).unwrap()
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            if send.send(target).is_err() {
                break;
            }
        }
    });
    let mut api = api(&server, "read-only-fixture".into(), record.deadline);
    let fetched = fetch(&mut api, &record).unwrap();
    assert_eq!(fetched.receipt.agent_job_id, AGENT_JOB_ID);
    assert_eq!(fetched.archive, bytes);
    let targets: Vec<_> = requests.try_iter().collect();
    assert!(targets.contains(
        &"/api/v4/projects/12/pipelines/5002/jobs?include_retried=true&per_page=100&page=1".into()
    ));
    assert_eq!(
        targets
            .iter()
            .filter(|t| *t == "/api/v4/projects/12/jobs/201/artifacts")
            .count(),
        1
    );
}

/// Every change refuses before the download, and again after it.
fn producer_changes(record: &Record) -> Vec<(String, Change)> {
    let mut changes: Vec<(String, Change)> = vec![
        (
            "another pipeline".into(),
            Box::new(|f| f.pipeline["id"] = 5003.into()),
        ),
        (
            "pipeline project".into(),
            Box::new(|f| f.pipeline["project_id"] = 13.into()),
        ),
        (
            "project ID".into(),
            Box::new(|f| f.project["id"] = 13.into()),
        ),
        (
            "project path".into(),
            Box::new(|f| f.project["path_with_namespace"] = "group/other".into()),
        ),
        (
            "ci_config_path".into(),
            Box::new(|f| f.project["ci_config_path"] = "ci.yml@group/other".into()),
        ),
        (
            "ci_config_path withheld".into(),
            Box::new(|f| {
                f.project.as_object_mut().unwrap().remove("ci_config_path");
            }),
        ),
        (
            "sha".into(),
            Box::new(|f| f.pipeline["sha"] = "f".repeat(40).into()),
        ),
        (
            "ref".into(),
            Box::new(|f| f.pipeline["ref"] = "other".into()),
        ),
        (
            "same-named tag".into(),
            Box::new(|f| f.pipeline["tag"] = true.into()),
        ),
        (
            "source".into(),
            Box::new(|f| f.pipeline["source"] = "web".into()),
        ),
        (
            "user".into(),
            Box::new(|f| f.pipeline["user"]["id"] = 43.into()),
        ),
        (
            "YAML errors".into(),
            Box::new(|f| f.pipeline["yaml_errors"] = "bad".into()),
        ),
        (
            "created before dispatch".into(),
            Box::new(|f| f.pipeline["created_at"] = "2026-11-13T09:00:00Z".into()),
        ),
        (
            "failed pipeline".into(),
            Box::new(|f| f.pipeline["status"] = "failed".into()),
        ),
        (
            "variable added".into(),
            Box::new(|f| {
                f.variables
                    .push(json!({"key": "EXTRA", "value": "1", "variable_type": "env_var"}))
            }),
        ),
        (
            "variable removed".into(),
            Box::new(|f| {
                f.variables.pop();
            }),
        ),
        (
            "variable changed".into(),
            Box::new(|f| f.variables[0]["value"] = "other".into()),
        ),
        (
            "variable type".into(),
            Box::new(|f| f.variables[0]["variable_type"] = "file".into()),
        ),
        (
            "variable duplicated".into(),
            Box::new(|f| {
                f.variables.pop();
                f.variables.push(f.variables[0].clone());
            }),
        ),
        (
            "expired archive".into(),
            Box::new(|f| f.jobs[0]["artifacts_expire_at"] = "2026-11-13T09:00:00Z".into()),
        ),
        (
            "no archive".into(),
            Box::new(|f| f.jobs[0]["artifacts_file"] = Value::Null),
        ),
        (
            "size mismatch".into(),
            Box::new(|f| f.jobs[0]["artifacts_file"]["size"] = 1.into()),
        ),
        (
            "deadline".into(),
            Box::new(|f| f.now += chrono::Duration::hours(6)),
        ),
    ];
    for (index, name) in [&record.agent_job, &record.check_job, &record.detect_job]
        .into_iter()
        .enumerate()
    {
        let job_changes: [(&str, Change); 7] = [
            (
                "retried",
                Box::new(move |f| {
                    let mut retry = f.jobs[index].clone();
                    retry["id"] = 300.into();
                    f.jobs.push(retry);
                }),
            ),
            (
                "missing",
                Box::new(move |f| {
                    f.jobs.remove(index);
                }),
            ),
            (
                "failed",
                Box::new(move |f| f.jobs[index]["status"] = "failed".into()),
            ),
            (
                "erased",
                Box::new(move |f| f.jobs[index]["erased_at"] = "2026-11-13T11:00:00Z".into()),
            ),
            (
                "played by another user",
                Box::new(move |f| f.jobs[index]["user"]["id"] = 43.into()),
            ),
            (
                "from another pipeline",
                Box::new(move |f| f.jobs[index]["pipeline"]["id"] = 5003.into()),
            ),
            (
                "on another sha",
                Box::new(move |f| f.jobs[index]["pipeline"]["sha"] = "f".repeat(40).into()),
            ),
        ];
        for (what, change) in job_changes {
            changes.push((format!("{name} {what}"), change));
        }
    }
    changes
}

#[test]
fn producer_mismatches_refuse_before_and_after_download() {
    let record = record();
    for at_release in [false, true] {
        for (what, change) in producer_changes(&record) {
            let mut fixture = Fixture::new(&record, archive(&[]));
            if at_release {
                fixture.at_release = Some(change);
            } else {
                change(&mut fixture);
            }
            assert!(
                fetch(&mut fixture, &record).is_err(),
                "{what}, at release: {at_release}"
            );
            if !at_release && what != "size mismatch" {
                assert!(fixture.downloads.is_empty(), "{what} downloaded");
            }
        }
    }
}

#[test]
fn caller_dispatch_job_must_be_in_its_pipeline_and_not_retried() {
    let record = record();
    let changes: [(&str, Change); 4] = [
        (
            "dispatch job was retried",
            Box::new(|f| {
                let mut retry = f.caller_jobs[1].clone();
                retry["id"] = 90002.into();
                f.caller_jobs.push(retry);
            }),
        ),
        (
            "dispatch job is not in the caller pipeline",
            Box::new(|f| f.caller_jobs[1]["id"] = 90009.into()),
        ),
        (
            "dispatch job is not in the caller pipeline",
            Box::new(|f| f.caller_jobs[1]["pipeline"]["id"] = 5009.into()),
        ),
        (
            "dispatch job was retried",
            Box::new(|f| f.caller_jobs[1]["name"] = Value::Null),
        ),
    ];
    for (expected, change) in changes {
        let mut fixture = Fixture::new(&record, archive(&[]));
        change(&mut fixture);
        assert_eq!(
            fetch(&mut fixture, &record).unwrap_err().to_string(),
            expected
        );
        assert!(fixture.downloads.is_empty());

        let mut fixture = Fixture::new(&record, archive(&[]));
        fixture.at_release = Some(change);
        assert_eq!(
            fetch(&mut fixture, &record).unwrap_err().to_string(),
            expected
        );
        assert_eq!(fixture.downloads.len(), 1);
    }
}

#[test]
fn a_gitlab_caller_admits_only_a_gitlab_target() {
    let mut policy = crate::policy::tests::policy();
    policy.secondary_pull_request = None;
    let github = ExternalRun {
        caller_repository: "owner/caller".into(),
        caller_run_id: 90,
        caller_attempt: 1,
        repository: "owner/external".into(),
        run_id: 7,
        base_commit: "2".repeat(40),
        raw_digest: format!("sha256:{}", "6".repeat(64)),
        files: BTreeMap::new(),
        gitlab: None,
    };
    policy.external = Some(github.clone());
    policy.validate().unwrap();
    let gitlab = GitlabCaller {
        server: "https://gitlab.example.com".into(),
        caller_project_id: 11,
    };
    for (what, caller) in [
        ("GitHub target", gitlab.clone()),
        (
            "plain HTTP server",
            GitlabCaller {
                server: "http://gitlab.example.com".into(),
                ..gitlab.clone()
            },
        ),
        (
            "zero project ID",
            GitlabCaller {
                caller_project_id: 0,
                ..gitlab
            },
        ),
    ] {
        policy.external = Some(ExternalRun {
            gitlab: Some(caller),
            ..github.clone()
        });
        assert!(policy.validate().is_err(), "{what}");
    }
}

#[test]
fn records_are_validated() {
    let valid = record();
    valid.validate().unwrap();
    let mut configured = valid.clone();
    configured.ci_config_path = "ci/agent.yml".into();
    configured.validate().unwrap();
    type Edit = fn(&mut Record);
    let changes: [(&str, Edit); 14] = [
        ("forge", |r| r.forge = "github".into()),
        ("CI config in another project", |r| {
            r.ci_config_path = ".gitlab-ci.yml@group/templates:main".into()
        }),
        ("remote CI config", |r| {
            r.ci_config_path = "https://example.com/ci.yml".into()
        }),
        ("plain HTTP server", |r| {
            r.server = "http://gitlab.example.com".into()
        }),
        ("server with a query", |r| {
            r.server = "https://gitlab.example.com/?x".into()
        }),
        ("server with a trailing slash", |r| {
            r.server = "https://gitlab.example.com/".into()
        }),
        ("kind", |r| r.kind = "fix".into()),
        ("project path", |r| r.project = "group/../other".into()),
        ("short commit", |r| r.commit = "3".repeat(7)),
        ("zero ID", |r| r.pipeline_id = 0),
        ("same job twice", |r| r.detect_job = r.check_job.clone()),
        ("no binary pin", |r| {
            r.variables.remove(SHA256_VARIABLE);
        }),
        ("bad variable key", |r| {
            r.variables.insert("BAD-KEY".into(), String::new());
        }),
        ("lifetime", |r| {
            r.deadline = r.dispatched_at + chrono::Duration::minutes(331)
        }),
    ];
    for (what, change) in changes {
        let mut wrong = valid.clone();
        change(&mut wrong);
        assert!(wrong.validate().is_err(), "{what}");
    }
    // A GitHub record field is refused, as a GitLab field is by GitHub's.
    let mut extra = serde_json::to_value(&valid).unwrap();
    extra["dispatch_id"] = "0".repeat(32).into();
    assert!(serde_json::from_value::<Record>(extra).is_err());
}
