use super::*;
use serde_json::json;
use std::io::Write;

fn record() -> Record {
    Record {
        dispatch_id: "0123456789abcdef0123456789abcdef".into(),
        caller_repository: "owner/caller".into(),
        caller_run_id: 90,
        caller_attempt: 1,
        profile_commit: "a".repeat(40),
        target_repository: "bootc-dev/bootc".into(),
        target_branch: "main".into(),
        base_commit: "b".repeat(40),
        item: 42,
        kind: "implement".into(),
        repository: "owner/external".into(),
        repository_id: 123,
        workflow: ".github/workflows/agent.yml".into(),
        reference: "main".into(),
        commit: "c".repeat(40),
        triggering_actor_id: 456,
        agentic_job: "d".repeat(40),
        actions: "e".repeat(40),
        actions_workflow: "example-org/wrapper/.github/workflows/run.yml".into(),
        policy_workflow: "example-org/tool/.github/workflows/policy.yml".into(),
        check_workflow: "example-org/tool/.github/workflows/check.yml".into(),
        artifact_prefix: "external-".into(),
        check_job: "agent / check / check".into(),
        detect_job: "agent / check / detect".into(),
        dispatched_at: "2026-11-09T12:00:00Z".parse().unwrap(),
        deadline: "2026-11-09T13:00:00Z".parse().unwrap(),
        returned_run_id: None,
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

struct Fixture {
    now: DateTime<Utc>,
    runs: Vec<Value>,
    run: Value,
    jobs: Vec<Value>,
    artifacts: Vec<Value>,
    bytes: Vec<u8>,
    downloaded: bool,
    release_attempt: bool,
    release_change: Option<(&'static str, Value)>,
    release_duplicate: bool,
    late_download: bool,
    paths: Vec<String>,
}

impl Fixture {
    fn new(record: &Record, bytes: Vec<u8>) -> Self {
        let run = json!({
            "id": 7, "repository": {"id":record.repository_id, "full_name":record.repository},
            "event":"workflow_dispatch", "path":record.workflow,
            "display_title":format!("Task [{}]", record.dispatch_id),
            "head_branch":record.reference, "head_sha":record.commit,
            "triggering_actor":{"id":record.triggering_actor_id}, "run_attempt":1,
            "created_at":record.dispatched_at, "status":"completed", "conclusion":"success",
            "referenced_workflows":[
                {"path":format!("{}@refs/heads/main", record.actions_workflow), "sha":record.actions},
                {"path":format!("{}@refs/heads/main", record.policy_workflow), "sha":record.agentic_job},
                {"path":format!("{}@refs/heads/main", record.check_workflow), "sha":record.agentic_job}
            ]
        });
        let sha = digest(&SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        Self {
            now: record.dispatched_at,
            runs: vec![run.clone()], run,
            jobs: [&record.check_job, &record.detect_job].into_iter().map(|name| json!({"name":name, "run_id":7,"run_attempt":1,"status":"completed","conclusion":"success"})).collect(),
            artifacts: ["checked-outputs", "safe-outputs"].into_iter().enumerate().map(|(i, suffix)| json!({"id":10+i,"name":format!("{}{suffix}",record.artifact_prefix), "expired":false,"digest":format!("sha256:{sha}"),"workflow_run":{"id":7,"head_sha":record.commit,"head_branch":record.reference}})).collect(),
            bytes, downloaded:false, release_attempt:false, release_duplicate:false, late_download:false,
            paths:Vec::new(), release_change:None,
        }
    }
}

impl Actions for Fixture {
    fn now(&self) -> DateTime<Utc> {
        self.now
    }

    fn get(&mut self, path: &str) -> Result<Value> {
        self.paths.push(path.into());
        ensure!(
            path.starts_with("/repos/owner/external/actions/"),
            "unexpected repository"
        );
        if path.contains("/workflows/") {
            let mut runs = self.runs.clone();
            if self.downloaded && self.release_duplicate {
                runs.push(self.run.clone());
            }
            return Ok(json!({"workflow_runs": runs}));
        }
        if path.ends_with("/runs/7") {
            let mut run = self.run.clone();
            if self.downloaded && self.release_attempt {
                run["run_attempt"] = 2.into();
            }
            if self.downloaded
                && let Some((pointer, value)) = &self.release_change
            {
                *run.pointer_mut(pointer).unwrap() = value.clone();
            }
            return Ok(run);
        }
        if path.contains("/attempts/1/jobs?") {
            return Ok(json!({"jobs":self.jobs}));
        }
        if path.contains("/runs/7/artifacts?") {
            return Ok(json!({"artifacts":self.artifacts}));
        }
        if let Some(id) = path.rsplit('/').next().and_then(|s| s.parse::<u64>().ok()) {
            return self
                .artifacts
                .iter()
                .find(|a| a["id"] == id)
                .cloned()
                .context("unknown artifact ID");
        }
        anyhow::bail!("unexpected API route {path}")
    }

    fn download(&mut self, path: &str) -> Result<Vec<u8>> {
        assert_eq!(path, "/repos/owner/external/actions/artifacts/11/zip");
        self.downloaded = true;
        if self.late_download {
            self.now += chrono::Duration::hours(2);
        }
        Ok(self.bytes.clone())
    }

    fn wait(&mut self, until: DateTime<Utc>) {
        self.now = until;
    }
}

#[test]
fn exact_match_and_returned_id_have_identical_checks() {
    for returned_run_id in [None, Some(7)] {
        let record = Record {
            returned_run_id,
            ..record()
        };
        let mut fixture = Fixture::new(&record, archive(&[]));
        let (receipt, bytes) = fetch(&mut fixture, &record).unwrap();
        assert_eq!(receipt.run_id, 7);
        assert_eq!(receipt.attempt, 1);
        assert_eq!(receipt.raw.id, 11);
        assert_eq!(receipt.checked.id, 10);
        assert_eq!(bytes, fixture.bytes);
        assert!(
            fixture
                .paths
                .iter()
                .any(|path| path.contains("created=%3E%3D"))
        );
        assert!(fixture.paths.iter().all(|path| !path.contains("latest")));
    }
}

#[test]
fn actions_http_transport_fetches_raw_by_id() {
    use std::io::{BufRead, BufReader};
    let mut record = record();
    record.dispatched_at = Utc::now();
    record.deadline = record.dispatched_at + chrono::Duration::minutes(30);
    let bytes = archive(&[("outputs.jsonl", b"{\"type\":\"noop\",\"message\":\"Done\"}")]);
    let mut fixture = Fixture::new(&record, bytes.clone());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let root = format!("http://{}", listener.local_addr().unwrap());
    let (send, requests) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let path = line.split_whitespace().nth(1).unwrap().to_owned();
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                headers.push_str(&line);
            }
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("authorization: bearer read-only-fixture")
            );
            let body = if path.ends_with("/zip") {
                fixture.download(&path).unwrap()
            } else {
                serde_json::to_vec(&fixture.get(&path).unwrap()).unwrap()
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            if send.send(path).is_err() {
                break;
            }
        }
    });
    let mut api = Api {
        root,
        token: "read-only-fixture".into(),
        deadline: record.deadline,
    };
    let (receipt, fetched) = fetch(&mut api, &record).unwrap();
    assert_eq!(receipt.raw.id, 11);
    assert_eq!(fetched, bytes);
    let paths: Vec<_> = requests.try_iter().collect();
    assert_eq!(paths.iter().filter(|p| p.ends_with("/zip")).count(), 1);
}

#[test]
fn identity_refusals_also_apply_at_release() {
    let record = record();
    for (pointer, wrong) in [
        ("/repository/id", json!(999)),
        ("/repository/full_name", json!("attacker/repo")),
        ("/event", json!("push")),
        ("/path", json!(".github/workflows/other.yml")),
        ("/head_branch", json!("other")),
        ("/head_sha", json!("f".repeat(40))),
        ("/triggering_actor/id", json!(999)),
        ("/run_attempt", json!(2)),
        ("/referenced_workflows/0/sha", json!("f".repeat(40))),
        ("/referenced_workflows/1/sha", json!("f".repeat(40))),
        ("/referenced_workflows/2/sha", json!("f".repeat(40))),
        ("/created_at", json!("2026-11-09T11:00:00Z")),
    ] {
        for at_release in [false, true] {
            let mut fixture = Fixture::new(&record, archive(&[]));
            if at_release {
                fixture.release_change = Some((pointer, wrong.clone()));
            } else {
                *fixture.run.pointer_mut(pointer).unwrap() = wrong.clone();
                fixture.runs = vec![fixture.run.clone()];
            }
            assert!(
                fetch(&mut fixture, &record).is_err(),
                "{pointer}, release={at_release}"
            );
        }
    }
    for duplicate_pin in [false, true] {
        let mut fixture = Fixture::new(&record, archive(&[]));
        let pins = fixture.run["referenced_workflows"].as_array_mut().unwrap();
        if duplicate_pin {
            pins.push(pins[0].clone());
        } else {
            pins.pop();
        }
        fixture.runs = vec![fixture.run.clone()];
        assert!(fetch(&mut fixture, &record).is_err());
    }
}

#[test]
fn ambiguity_failure_artifacts_digest_and_deadlines_refuse() {
    let record = record();
    for case in [
        "multiple",
        "none",
        "replay",
        "failed-run",
        "failed-check",
        "failed-detect",
        "skipped-detect",
        "absent-detect",
        "duplicate-job",
        "duplicate-raw",
        "duplicate-checked",
        "expired",
        "wrong-artifact-run",
        "wrong-digest",
        "missing-digest",
        "late",
        "rerun-release",
        "duplicate-release",
        "waiting-deadline",
    ] {
        let mut fixture = Fixture::new(&record, archive(&[]));
        match case {
            "multiple" => fixture.runs.push(fixture.run.clone()),
            "none" => fixture.runs.clear(),
            "replay" => {
                fixture.run["display_title"] = "Old [ffffffffffffffffffffffffffffffff]".into();
                fixture.runs = vec![fixture.run.clone()];
            }
            "failed-run" => fixture.run["conclusion"] = "failure".into(),
            "failed-check" => fixture.jobs[0]["conclusion"] = "failure".into(),
            "failed-detect" => fixture.jobs[1]["conclusion"] = "failure".into(),
            "skipped-detect" => fixture.jobs[1]["conclusion"] = "skipped".into(),
            "absent-detect" => {
                fixture.jobs.pop();
            }
            "duplicate-job" => fixture.jobs.push(fixture.jobs[0].clone()),
            "duplicate-raw" => fixture.artifacts.push(fixture.artifacts[1].clone()),
            "duplicate-checked" => fixture.artifacts.push(fixture.artifacts[0].clone()),
            "expired" => fixture.artifacts[1]["expired"] = true.into(),
            "wrong-artifact-run" => fixture.artifacts[1]["workflow_run"]["id"] = 8.into(),
            "wrong-digest" => fixture.bytes.push(0),
            "missing-digest" => fixture.artifacts[1]["digest"] = Value::Null,
            "late" => fixture.late_download = true,
            "rerun-release" => fixture.release_attempt = true,
            "duplicate-release" => fixture.release_duplicate = true,
            "waiting-deadline" => fixture.run["status"] = "in_progress".into(),
            _ => unreachable!(),
        }
        let error = fetch(&mut fixture, &record).unwrap_err();
        assert!(!error.to_string().is_empty(), "{case}");
    }
    let mut wrong = record.clone();
    wrong.returned_run_id = Some(8);
    assert!(fetch(&mut Fixture::new(&record, archive(&[])), &wrong).is_err());
    assert!(record.caller("owner/caller", 91, 1).is_err());
    assert!(record.caller("owner/caller", 90, 2).is_err());
    assert!(record.caller("other/caller", 90, 1).is_err());
    assert!(record.caller("owner/caller", 90, 1).is_ok());
}

#[test]
fn fetched_raw_passes_real_collect_check_git_trial_and_staged_apply() {
    use safe_outputs::apply::testing::{repository, sh};
    let (root, pr) = repository();
    let mut record = record();
    record.base_commit = pr.base_commit.clone();
    let patch = String::from_utf8(pr.patch).unwrap().replacen(
        "\nFrom: ",
        &format!(
            "\n{}: {}\nFrom: ",
            crate::check::BASE_COMMIT_HEADER,
            pr.base_commit
        ),
        1,
    );
    let item = json!({"type":"create_pull_request","title":"Change things","body":"Why.","branch":"agent-run-7"});
    let base = json!({"repo":record.target_repository,"ref":"main","commit":record.base_commit});
    let name = crate::check::patch_file_name("agent-run-7");
    let bytes = archive(&[
        ("outputs.jsonl", item.to_string().as_bytes()),
        ("base.json", base.to_string().as_bytes()),
        (&name, patch.as_bytes()),
    ]);
    let (receipt, bytes) = fetch(&mut Fixture::new(&record, bytes), &record).unwrap();
    let outputs = root.path().join("raw");
    extract(&bytes, &outputs).unwrap();
    let mut policy = crate::policy::tests::policy();
    policy.secondary_pull_request = None;
    policy.external = Some(crate::policy::ExternalRun {
        caller_repository: record.caller_repository.clone(),
        caller_run_id: 90,
        caller_attempt: 1,
        repository: record.repository.clone(),
        run_id: receipt.run_id,
        base_commit: record.base_commit.clone(),
        raw_digest: receipt.raw.digest,
    });
    policy.validate().unwrap();
    record.policy(&policy).unwrap();
    let policy_file = root.path().join("policy.json");
    std::fs::write(&policy_file, serde_json::to_vec(&policy).unwrap()).unwrap();
    let collected = root.path().join("collected.json");
    assert_eq!(
        crate::collect::run(&crate::collect::Args {
            policy: policy_file.clone(),
            outputs: outputs.clone(),
            collected: collected.clone()
        })
        .unwrap(),
        Exit::Success
    );
    let verdict = crate::check::check_run_outputs(&outputs, &collected, &policy, "90").unwrap();
    assert!(verdict.ok, "{:?}", verdict.errors);
    let report = serde_json::to_value(&verdict).unwrap();
    assert!(authorize(&policy, &report, "success").is_ok());
    for detection in ["", "skipped", "failure", "cancelled"] {
        assert!(authorize(&policy, &report, detection).is_err());
    }
    let mut wrong_report = report.clone();
    wrong_report["patch"]["base_commit"] = "f".repeat(40).into();
    assert!(authorize(&policy, &wrong_report, "success").is_err());
    let mut wrong_policy = policy.clone();
    wrong_policy.external.as_mut().unwrap().base_commit = "f".repeat(40);
    assert!(
        !crate::check::check_run_outputs(&outputs, &collected, &wrong_policy, "90")
            .unwrap()
            .ok
    );
    wrong_policy = policy.clone();
    wrong_policy.external.as_mut().unwrap().run_id = 8;
    assert!(
        !crate::check::check_run_outputs(&outputs, &collected, &wrong_policy, "90")
            .unwrap()
            .ok
    );
    // The real apply trial: exact base, git am (no target code/hooks), and
    // compare the resulting paths with check's. Nothing is pushed.
    let work = root.path().join("work");
    sh(
        &work,
        &["am", "--keep-cr", outputs.join(&name).to_str().unwrap()],
    );
    let changed = sh(
        &work,
        &[
            "diff",
            "--name-only",
            "--no-renames",
            &record.base_commit,
            "HEAD",
        ],
    );
    assert_eq!(
        changed.lines().collect::<Vec<_>>(),
        verdict
            .patch
            .as_ref()
            .unwrap()
            .files
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    // Execute apply.yml's actual staged step, not a simulated publisher.
    let checked = root.path().join("checked");
    std::fs::create_dir(&checked).unwrap();
    std::fs::write(
        checked.join("report.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    std::fs::write(
        checked.join("agent_output.json"),
        serde_json::to_vec(&json!({"items":verdict.items,"errors":[]})).unwrap(),
    )
    .unwrap();
    std::fs::write(
        checked.join("config.json"),
        serde_json::to_vec(&policy.safe_outputs).unwrap(),
    )
    .unwrap();
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/apply.yml"),
    )
    .unwrap();
    let yaml = yaml_rust2::YamlLoader::load_from_str(&source).unwrap();
    let step = yaml[0]["jobs"]["apply"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|s| s["name"].as_str() == Some("Show what would be applied"))
        .unwrap();
    let output = std::process::Command::new("bash")
        .args(["-e", "-o", "pipefail", "-c", step["run"].as_str().unwrap()])
        .env("GH_AW_TMP", &checked)
        .env("REPORT", checked.join("report.json"))
        .env("GITHUB_STEP_SUMMARY", root.path().join("summary"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn raw_archive_never_supplies_trusted_config_or_paths() {
    let root = tempfile::tempdir().unwrap();
    for name in [
        "policy.json",
        "config.json",
        "report.json",
        "../outputs.jsonl",
        "dir/outputs.jsonl",
    ] {
        assert!(
            extract(&archive(&[(name, b"{}")]), &root.path().join("raw")).is_err(),
            "{name}"
        );
        assert!(!root.path().join("raw").exists());
    }
}

#[test]
fn reusable_workflow_identities_are_caller_selected_and_fail_closed() {
    let expected = record();
    expected.validate().unwrap();
    for identity in [
        "",
        "example-org/tool/.github/workflows/check.yml@main",
        "bad/.github/workflows/check.yml",
        "example-org/tool/.github/workflows/../check.yml",
    ] {
        let mut wrong = expected.clone();
        wrong.actions_workflow = identity.into();
        assert!(wrong.validate().is_err(), "{identity}");
    }
    let mut wrong = expected.clone();
    wrong.actions_workflow = wrong.check_workflow.clone();
    assert!(wrong.validate().is_err());
    for field in ["actions_workflow", "policy_workflow", "check_workflow"] {
        let mut wrong = serde_json::to_value(&expected).unwrap();
        wrong[field] = json!("other-org/tool/.github/workflows/run.yml");
        let wrong: Record = serde_json::from_value(wrong).unwrap();
        wrong.validate().unwrap();
        assert!(fetch(&mut Fixture::new(&expected, archive(&[])), &wrong).is_err());
    }
}

#[test]
fn raw_directory_is_bounded_before_zip_indexes_or_deduplicates_it() {
    let valid = archive(&[("outputs.jsonl", b"{}")]);
    let end = valid.len() - 22;
    let start = u32::from_le_bytes(valid[end + 16..end + 20].try_into().unwrap()) as usize;
    let entry = &valid[start..end];
    for (copies, claimed, expected) in [
        (2, 2, "duplicate"),
        (257, 257, "more than 256"),
        (257, 1, "duplicate"),
        (1, 2, "count mismatch"),
    ] {
        let mut bytes = valid[..start].to_vec();
        for _ in 0..copies {
            bytes.extend_from_slice(entry);
        }
        let mut footer = valid[end..].to_vec();
        footer[8..10].copy_from_slice(&(claimed as u16).to_le_bytes());
        footer[10..12].copy_from_slice(&(claimed as u16).to_le_bytes());
        footer[12..16].copy_from_slice(&((entry.len() * copies) as u32).to_le_bytes());
        bytes.extend_from_slice(&footer);
        let root = tempfile::tempdir().unwrap();
        let outputs = root.path().join("raw");
        let error = extract(&bytes, &outputs).unwrap_err().to_string();
        assert!(error.contains(expected), "{copies}/{claimed}: {error}");
        assert!(!outputs.exists());
    }
    assert_eq!(raw_directory_entries(&valid).unwrap(), 1);
    for length in 0..valid.len() {
        assert!(raw_directory_entries(&valid[..length]).is_err());
    }
    let mut zip64 = valid.clone();
    zip64[end + 16..end + 20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(raw_directory_entries(&zip64).is_err());
}
