//! `workflows check` as a repository's check runs it: over a tree, with
//! its exemptions file. And the workflows' own steps and shapes.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use regex::Regex;

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");
const ERROR: i32 = 2;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A workflow basename or a repository-relative action, read at test time.
fn workflow(file: &str) -> String {
    let file = if file.contains('/') {
        root().join(file)
    } else {
        root().join(".github/workflows").join(file)
    };
    std::fs::read_to_string(file).unwrap()
}

/// The text of `name`, a job of `text`, up to the next job.
fn job<'a>(text: &'a str, name: &str) -> &'a str {
    let start = text
        .find(&format!("\n  {name}:\n"))
        .unwrap_or_else(|| panic!("no job {name}"))
        + 1;
    let rest = &text[start..];
    let end = Regex::new(r"\n  [a-z][\w-]*:\n")
        .unwrap()
        .find(rest)
        .map_or(rest.len(), |next| next.start() + 1);
    &rest[..end]
}

/// Workflows by basename, composite actions by repository-relative path.
fn definition(file: &str) -> yaml_rust2::Yaml {
    let text = workflow(file);
    yaml_rust2::YamlLoader::load_from_str(&text)
        .unwrap()
        .remove(0)
}

#[test]
fn ordinary_ubuntu_runners_use_current_image() {
    // Check owned definitions, not historical checker fixtures. Architecture
    // suffixes and special runner classes are deliberately outside this rule.
    let ordinary = Regex::new(r"^ubuntu-(latest|[0-9]+\.[0-9]+)$").unwrap();
    for entry in std::fs::read_dir(root().join(".github/workflows")).unwrap() {
        let path = entry.unwrap().path();
        if !matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("yml" | "yaml")
        ) {
            continue;
        }
        let file = path.file_name().unwrap().to_str().unwrap();
        let doc = definition(file);
        for (name, job) in doc["jobs"].as_hash().unwrap() {
            if let Some(label) = job["runs-on"].as_str()
                && ordinary.is_match(label)
            {
                assert_eq!(label, "ubuntu-26.04", "{file}: {name:?}");
            }
        }
    }
    for file in ["agentic-job.yml", "policy.yml"] {
        assert_eq!(
            definition(file)["on"]["workflow_call"]["inputs"]["runner"]["default"].as_str(),
            Some("\"ubuntu-26.04\""),
            "{file}: runner default"
        );
    }
}

fn steps(doc: &yaml_rust2::Yaml) -> Vec<&yaml_rust2::Yaml> {
    if let Some(jobs) = doc["jobs"].as_hash() {
        jobs.values()
            .flat_map(|job| job["steps"].as_vec().into_iter().flatten())
            .collect()
    } else {
        doc["runs"]["steps"].as_vec().unwrap().iter().collect()
    }
}

/// The one step of `doc` whose name, or else id, is `name`.
fn named_step<'a>(doc: &'a yaml_rust2::Yaml, name: &str) -> &'a yaml_rust2::Yaml {
    let mut found = steps(doc)
        .into_iter()
        .filter(|step| step["name"].as_str().or(step["id"].as_str()) == Some(name));
    let step = found.next().unwrap_or_else(|| panic!("no step {name:?}"));
    assert!(found.next().is_none(), "two steps {name:?}");
    step
}

#[test]
fn role_and_legacy_workflow_credential_expressions() {
    let doc = definition("apply.yml");
    let mut expressions = Vec::new();
    for step in doc["jobs"]["apply"]["steps"].as_vec().unwrap() {
        for (section, key, role) in [
            ("with", "token", "PUSH_TOKEN"),
            ("with", "github-token", "PUBLICATION_TOKEN"),
            ("env", "GH_TOKEN", "PUBLICATION_TOKEN"),
        ] {
            let Some(expression) = step[section][key].as_str() else {
                continue;
            };
            if !expression.contains("secrets.SAFE_OUTPUTS_PAT") {
                continue;
            }
            let role = if expression.contains("secrets.PUSH_TOKEN") {
                "PUSH_TOKEN"
            } else {
                role
            };
            expressions.push((expression.to_owned(), role));
        }
    }
    assert!(expressions.len() >= 4);
    for file in ["apply.yml", "policy.yml"] {
        for step in steps(&definition(file)) {
            if let Some(expression) = step["env"]["STATUS_TOKEN"].as_str() {
                expressions.push((expression.to_owned(), "STATUS_TOKEN"));
            }
        }
    }
    for (expression, role) in expressions {
        for configured in [false, true] {
            for pat in [None, Some(""), Some("legacy-credential")] {
                for selected in ["", "role-credential"] {
                    // Evaluate the actual Actions boolean selection, not a
                    // second implementation of it. No forge or credentials.
                    let expression = expression
                        .strip_prefix("${{ ")
                        .unwrap()
                        .strip_suffix(" }}")
                        .unwrap()
                        .replace("inputs.role-bindings", "inputs.bindings");
                    let data = serde_json::json!({
                        "bindings": if configured { "configured" } else { "" },
                        "secrets": {"SAFE_OUTPUTS_PAT": pat, role: selected},
                    });
                    let script = format!(
                        "const d=JSON.parse(process.argv[1]); const inputs=d, secrets=d.secrets, github={{token:'job-token'}}; process.stdout.write(JSON.stringify({expression}));"
                    );
                    let result = Command::new("node")
                        .args(["-e", &script, &data.to_string()])
                        .output()
                        .unwrap();
                    assert!(result.status.success(), "{result:?}");
                    let expected = if configured {
                        selected
                    } else if role == "STATUS_TOKEN" {
                        pat.unwrap_or("")
                    } else {
                        pat.filter(|pat| !pat.is_empty()).unwrap_or("job-token")
                    };
                    assert_eq!(
                        serde_json::from_slice::<String>(&result.stdout).unwrap(),
                        expected,
                        "{expression}: {data}"
                    );
                }
            }
        }
    }
}

#[test]
fn caller_role_credentials_stay_out_of_agent_and_check_jobs() {
    let wrapper = definition("agentic-job.yml");
    for secret in [
        "STATUS_TOKEN",
        "REVIEW_TOKEN",
        "PUSH_TOKEN",
        "PUBLICATION_TOKEN",
    ] {
        assert_eq!(
            wrapper["jobs"]["apply"]["secrets"][secret].as_str(),
            Some(format!("${{{{ secrets.{secret} }}}}").as_str())
        );
        for job in ["agent", "check"] {
            assert!(wrapper["jobs"][job]["secrets"][secret].is_badvalue());
        }
        if secret != "STATUS_TOKEN" {
            assert!(wrapper["jobs"]["policy"]["secrets"][secret].is_badvalue());
        }
    }
    for file in ["apply.yml", "policy.yml", "agentic-job.yml"] {
        let doc = definition(file);
        assert_eq!(
            doc["on"]["workflow_call"]["inputs"]["role-bindings"]["default"].as_str(),
            Some("")
        );
    }
    let apply = definition("apply.yml");
    let steps = apply["jobs"]["apply"]["steps"].as_vec().unwrap();
    let position = |name| {
        steps
            .iter()
            .position(|step| step["name"].as_str() == Some(name))
            .unwrap()
    };
    assert!(
        position("Check caller role credentials and routing")
            < position("Fork the output repository for the pull request")
    );
    let fork = named_step(&apply, "Fork the output repository for the pull request");
    assert!(
        fork["env"]["GH_TOKEN"]
            .as_str()
            .unwrap()
            .ends_with("|| secrets.PUSH_TOKEN }}")
    );
    for (file, step) in [
        ("apply.yml", "Tell the item how the run ended"),
        ("policy.yml", "Comment that the run started"),
    ] {
        // Match status invocations rather than presentation names, which may change.
        let doc = definition(file);
        let status: Vec<_> = self::steps(&doc)
            .into_iter()
            .filter(|step| step["env"]["STATUS_TOKEN"].as_str().is_some())
            .collect();
        assert_eq!(status.len(), 1, "{file}: {step}");
        assert_eq!(
            status[0]["env"]["STATUS_TOKEN"].as_str(),
            Some(
                "${{ inputs.role-bindings == '' && secrets.SAFE_OUTPUTS_PAT || inputs.role-bindings != '' && secrets.STATUS_TOKEN || '' }}"
            )
        );
        assert_eq!(
            status[0]["env"]["APPLY_ROLE_BINDINGS"].as_str(),
            Some("${{ inputs.role-bindings }}")
        );
    }
}

/// Runs the actual workflow or composite step, without job credentials or
/// user configuration from this process. Every invocation has a temporary HOME.
fn run_step(file: &str, name: &str, dir: &Path, env: &[(&str, &str)]) -> Output {
    let doc = definition(file);
    let script = named_step(&doc, name)["run"].as_str().unwrap();
    let mut command = Command::new("bash");
    command
        .args(["-eo", "pipefail", "-c", script])
        .current_dir(dir)
        .env_clear();
    command
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", dir);
    command.envs(env.iter().copied()).output().unwrap()
}

/// A stand-in for a command a step runs.
fn executable(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// The directory of the binary under test, as the steps' `JOB_DIR`.
fn bin_dir() -> &'static str {
    Path::new(BIN).parent().unwrap().to_str().unwrap()
}

/// The status comment keeps the agent's cost only in the run action's
/// grammar, which cannot end the HTML comment it goes in.
#[test]
fn status_cost_is_optional_and_bounded() {
    use agentic_job::apply::status::{MARKER, body};
    let long = format!("usd={} partial=false", "9".repeat(100));
    for (cost, wanted) in [
        ("usd=0 partial=false", true),
        ("usd=1.2345 partial=false", true),
        ("usd=2.5 partial=true", true),
        ("usd=-1 partial=false", false),
        ("usd=NaN partial=false", false),
        ("usd=1 partial=null", false),
        ("usd=1 partial=false\n", false),
        ("usd=1 partial=false --> forged", false),
        ("usd=1. partial=false", false),
        (long.as_str(), false),
    ] {
        let text = body("finished", None, Some(cost), "100").unwrap();
        let line = format!("<!-- agentic-job-cost: 100 {cost} -->");
        assert_eq!(text.contains("agentic-job-cost:"), wanted, "{cost:?}");
        assert_eq!(text.contains(&line), wanted, "{cost:?}");
        assert!(text.ends_with(&format!("<!-- agentic-job-run: 100 -->\n\n{MARKER}")));
    }
    assert!(
        !body("finished", None, None, "101")
            .unwrap()
            .contains("agentic-job-cost:")
    );
}

/// Without an event naming the item, policy.yml's notify job comments
/// only on a numeric comment target: never `*`, nothing, or shell text.
#[test]
fn notify_takes_only_a_numeric_target_without_an_event() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join(".github/workflows/policy.yml")).unwrap();
    let doc = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
    let script = doc["jobs"]["notify"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|step| step["name"].as_str() == Some("What to react to, and where to comment"))
        .unwrap()["run"]
        .as_str()
        .unwrap();
    for event in [None, Some(r#"{"item": null}"#)] {
        for target in ["7", "*", "", "0", "$(exit 9)"] {
            let dir = tempfile::tempdir().unwrap();
            let output = dir.path().join("output");
            std::fs::write(&output, "").unwrap();
            if let Some(event) = event {
                std::fs::write(dir.path().join("event.json"), event).unwrap();
            }
            let status = Command::new("bash")
                .args(["-eo", "pipefail", "-c", script])
                .env("JOB_DIR", dir.path())
                .env("TARGET", target)
                .env("GITHUB_OUTPUT", &output)
                .status()
                .unwrap();
            let numeric = target == "7";
            assert_eq!(status.success(), numeric, "{event:?} {target:?}");
            assert_eq!(
                std::fs::read_to_string(&output).unwrap(),
                if numeric { "item=7\nwhat=item\n" } else { "" },
                "{event:?} {target:?}"
            );
        }
    }
}

/// A task passed as `task-artifact` is downloaded before the mode check,
/// refused beside `task` or when empty, and becomes the policy's task.md;
/// the composed example passes its task that way, as CI's e2e-compose.
#[test]
fn policy_takes_the_task_as_an_artifact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join(".github/workflows/policy.yml")).unwrap();
    let doc = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
    let steps = doc["jobs"]["policy"]["steps"].as_vec().unwrap();
    let index = |name: &str| {
        steps
            .iter()
            .position(|step| step["name"].as_str() == Some(name))
            .unwrap()
    };
    let gate = index("Check the proposals mode");
    let download = steps
        .iter()
        .position(|step| step["with"]["name"].as_str() == Some("${{ inputs.task-artifact }}"))
        .unwrap();
    assert!(download < gate);
    assert_eq!(
        steps[download]["with"]["path"].as_str(),
        Some("${{ runner.temp }}/task-artifact")
    );
    let script = |index: usize| steps[index]["run"].as_str().unwrap();
    let write = index("Write the task and the run's settings");
    // [task, task-artifact, task.md in it, proposals, event, status]
    for (task, artifact, file, proposals, event, success) in [
        ("", "task", Some("run\n"), "", "false", true),
        ("", "$(exit 0)", Some("run\n"), "", "false", true),
        ("", "task", Some("run\n"), "", "true", true),
        ("run", "task", Some("run\n"), "", "false", false),
        ("", "task", Some(""), "", "false", false),
        ("", "task", Some(" \n"), "", "false", false),
        ("", "task", None, "", "false", false),
        ("", "task", None, "proposals", "false", false),
        ("run", "", None, "", "false", true),
        ("", "", None, "", "false", false),
        ("", "", None, "proposals", "false", true),
    ] {
        let case = format!("{task:?} {artifact:?} {file:?} {proposals:?} {event:?}");
        let dir = tempfile::tempdir().unwrap();
        if let Some(file) = file {
            std::fs::create_dir(dir.path().join("task-artifact")).unwrap();
            std::fs::write(dir.path().join("task-artifact/task.md"), file).unwrap();
        }
        let output = Command::new("bash")
            .args(["-eo", "pipefail", "-c", script(gate)])
            .env("RUNNER_TEMP", dir.path())
            .env("TASK", task)
            .env("TASK_ARTIFACT", artifact)
            .env("PROPOSALS", proposals)
            .env("EVENT", event)
            .env("REVIEW", "false")
            .env("PARTIAL", "false")
            .output()
            .unwrap();
        assert_eq!(output.status.success(), success, "{case}: {output:?}");
        if task.is_empty() && artifact.is_empty() && proposals.is_empty() {
            assert!(String::from_utf8_lossy(&output.stdout).contains("secret masker"));
        }
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("task-artifact")).unwrap();
    std::fs::write(dir.path().join("task-artifact/task.md"), "a task\n").unwrap();
    let status = Command::new("bash")
        .args(["-eo", "pipefail", "-c", script(write)])
        .env("RUNNER_TEMP", dir.path())
        .env("JOB_DIR", dir.path())
        .env("EVENT", "false")
        .env("TASK", "")
        .env("TASK_ARTIFACT", "task")
        .env("PROFILE", "")
        .env("ISSUE", "")
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("task.md")).unwrap(),
        "a task\n"
    );
    let compose =
        std::fs::read_to_string(root.join(".github/workflows/example-compose.yml")).unwrap();
    let compose = &yaml_rust2::YamlLoader::load_from_str(&compose).unwrap()[0];
    let upload = &compose["jobs"]["task"]["steps"][1]["with"];
    let policy = &compose["jobs"]["policy"];
    assert_eq!(policy["needs"].as_str(), Some("task"));
    assert_eq!(upload["name"].as_str(), Some("compose-task"));
    assert_eq!(upload["path"].as_str(), Some("task/task.md"));
    assert_eq!(
        policy["with"]["task-artifact"].as_str(),
        Some("compose-task")
    );
    assert!(policy["with"]["task"].is_badvalue());
}

#[test]
fn run_action_forwards_summary_cost_without_inventing_unknown_cost() {
    use serde_json::json;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let action = std::fs::read_to_string(root.join("run/action.yml")).unwrap();
    let line = action
        .lines()
        .find(|line| line.contains("jq -r '.cost |"))
        .unwrap()
        .trim();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("out/run")).unwrap();
    let mut produced = Vec::new();
    for (cost, expected) in [
        (
            json!({"usd": 1.2345, "partial": false}),
            "cost=usd=1.2345 partial=false\n",
        ),
        (
            json!({"usd": 0, "partial": true}),
            "cost=usd=0 partial=true\n",
        ),
        (json!({"usd": null, "partial": true}), ""),
        (json!({"usd": -1, "partial": false}), ""),
        (json!({"usd": "1\nforged=1", "partial": false}), ""),
        (json!({"usd": 1, "partial": null}), ""),
        (serde_json::Value::Null, ""),
        // What jq would otherwise print as a 17-digit fraction or an
        // exponent, which the status grammar refuses.
        (
            json!({"usd": 0.12345678901234567_f64, "partial": false}),
            "cost=usd=0.1235 partial=false\n",
        ),
        (
            json!({"usd": 0.0000001, "partial": true}),
            "cost=usd=0 partial=true\n",
        ),
        (
            json!({"usd": 0.29, "partial": false}),
            "cost=usd=0.29 partial=false\n",
        ),
        (
            json!({"usd": 123456789.98765, "partial": false}),
            "cost=usd=123456789.9877 partial=false\n",
        ),
        (json!({"usd": 1e12, "partial": false}), ""),
    ] {
        std::fs::write(
            dir.path().join("out/run/summary.json"),
            json!({"cost":cost}).to_string(),
        )
        .unwrap();
        let output_file = dir.path().join("outputs");
        std::fs::write(&output_file, "").unwrap();
        let output = Command::new("bash")
            .args(["-ec", line])
            .env("JOB_DIR", dir.path())
            .env("GITHUB_OUTPUT", &output_file)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(output_file).unwrap(),
            expected,
            "{cost}"
        );
        if let Some(value) = expected.strip_prefix("cost=") {
            produced.push(value.trim_end().to_owned());
        }
    }
    // Everything the producer forwards is a cost the status comment keeps.
    for cost in produced {
        let text = agentic_job::apply::status::body("finished", None, Some(&cost), "100").unwrap();
        assert!(
            text.contains(&format!("<!-- agentic-job-cost: 100 {cost} -->")),
            "{cost}"
        );
    }
    let agent = std::fs::read_to_string(root.join(".github/workflows/agent.yml")).unwrap();
    assert!(agent.contains("cost: ${{ steps.run.outputs.cost }}"));
    assert!(agent.contains("value: ${{ jobs.agent.outputs.cost }}"));
    let apply = std::fs::read_to_string(root.join(".github/workflows/apply.yml")).unwrap();
    assert!(apply.contains("COST: ${{ fromJSON(inputs.agent).outputs.cost }}"));
}

/// check.yml hands apply the patches check reported, each by its name:
/// the secondary pull request's apart, in `secondary/`, so that apply's
/// trial of the run's own patch, which takes the one `check` reported,
/// never applies it. Its request is left to `secondary-pull-request`, out
/// of the handlers' file, which would otherwise fail it.
#[test]
fn the_secondary_patch_is_handed_on_apart() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join(".github/workflows/check.yml")).unwrap();
    let doc = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
    let steps = doc["jobs"]["check"]["steps"].as_vec().unwrap();
    let step = |name: &str| {
        steps
            .iter()
            .find(|step| step["name"].as_str() == Some(name))
            .unwrap()
    };
    let script = step("Put the patch beside the ingested outputs")["run"]
        .as_str()
        .unwrap();
    let uploaded = steps
        .iter()
        .find(|step| step["id"].as_str() == Some("upload"))
        .unwrap()["with"]["path"]
        .as_str()
        .unwrap();
    for file in ["secondary/aw-*.patch", "replacement.json", "policy.json"] {
        assert!(uploaded.contains(&format!("${{{{ env.GH_AW_TMP }}}}/{file}\n")));
    }
    const OWN: &str = "aw-agent-run-7.patch";
    const TOOL: &str = "aw-o-tool-agentic-job-agent-run-7.patch";
    // A replacement series is reported, and read by apply, by this name.
    const SERIES: &str = "replacement.json";
    let own_request = serde_json::json!({"type": "create_pull_request", "title": "T"});
    let tool_request = serde_json::json!({"type": "create_pull_request", "repo": "o/tool"});
    let items = serde_json::json!([own_request, tool_request]);
    let secondary = serde_json::json!({"secondary_pull_request": {"repo": "o/tool"}});
    // (report, policy, the patch reported for the run's own request, whether
    // the secondary's is handed on, the requests the handlers get)
    for (report, policy, own, tool, handled) in [
        (
            serde_json::json!({"items": items, "patch": {"file": OWN},
                "secondary_patch": {"file": TOOL}}),
            &secondary,
            Some(OWN),
            true,
            serde_json::json!([own_request]),
        ),
        (
            serde_json::json!({"items": [tool_request], "secondary_patch": {"file": TOOL}}),
            &secondary,
            None,
            true,
            serde_json::json!([]),
        ),
        (
            serde_json::json!({"items": [own_request], "patch": {"file": OWN}}),
            &secondary,
            Some(OWN),
            false,
            serde_json::json!([own_request]),
        ),
        (
            serde_json::json!({"items": [], "patch": {"file": SERIES}}),
            &serde_json::json!({}),
            Some(SERIES),
            false,
            serde_json::json!([]),
        ),
        // Without a secondary in the policy, every request is the handlers'.
        (
            serde_json::json!({"items": items, "patch": {"file": OWN}}),
            &serde_json::json!({}),
            Some(OWN),
            false,
            items.clone(),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (job, tmp) = (dir.path().join("job"), dir.path().join("gh-aw"));
        std::fs::create_dir_all(job.join("safe-outputs")).unwrap();
        std::fs::create_dir(&tmp).unwrap();
        for name in [OWN, TOOL, SERIES] {
            std::fs::write(job.join("safe-outputs").join(name), name).unwrap();
        }
        std::fs::write(job.join("policy.json"), policy.to_string()).unwrap();
        std::fs::write(tmp.join("report.json"), report.to_string()).unwrap();
        let output = Command::new("bash")
            .args(["-e", "-c", script])
            .env("JOB_DIR", &job)
            .env("GH_AW_TMP", &tmp)
            .env("RUNNER_TEMP", dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for name in [OWN, SERIES] {
            assert_eq!(tmp.join(name).exists(), own == Some(name), "{report}");
        }
        assert!(!tmp.join(TOOL).exists(), "{report}");
        assert_eq!(tmp.join("secondary").join(TOOL).exists(), tool, "{report}");
        let output: serde_json::Value =
            serde_json::from_slice(&std::fs::read(tmp.join("agent_output.json")).unwrap()).unwrap();
        assert_eq!(output, serde_json::json!({"items": handled, "errors": []}));
        assert_eq!(
            std::fs::read_to_string(tmp.join("policy.json")).unwrap(),
            policy.to_string()
        );
    }
    // Apply's trial takes the one patch check reported for the run's own
    // request, not every file a glob matches.
    let apply = std::fs::read_to_string(root.join(".github/workflows/apply.yml")).unwrap();
    assert!(apply.contains(r#"am --keep-cr "$GH_AW_TMP/$(jq -er '.patch.file' "$REPORT")""#));
    assert!(!apply.contains("aw-*.patch"));
    let doc = &yaml_rust2::YamlLoader::load_from_str(&apply).unwrap()[0];
    let steps = doc["jobs"]["apply"]["steps"].as_vec().unwrap();
    let position = |name: &str| {
        steps
            .iter()
            .position(|step| step["name"].as_str() == Some(name))
            .unwrap()
    };
    let open = &steps[position("Open the secondary pull request")];
    assert!(position("Every output was applied") < position("Open the secondary pull request"));
    assert!(
        open["run"]
            .as_str()
            .unwrap()
            .contains("secondary-pull-request --policy \"$GH_AW_TMP/policy.json\"")
    );
    // A user's token, which can fork; never the job token in its place.
    assert_eq!(
        open["env"]["SAFE_OUTPUTS_PAT"].as_str(),
        Some("${{ secrets.SAFE_OUTPUTS_PAT }}")
    );
}

#[test]
fn workflow_budgets_convert_dollars_and_keep_explicit_legacy_aic() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for name in ["agentic-job", "policy"] {
        let text =
            std::fs::read_to_string(root.join(format!(".github/workflows/{name}.yml"))).unwrap();
        let doc = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
        let inputs = &doc["on"]["workflow_call"]["inputs"];
        assert_eq!(inputs["budget-usd"]["default"].as_str(), Some(""));
        assert_eq!(inputs["budget"]["default"].as_str(), Some("500"));
        if name == "policy" {
            assert!(text.contains("BUDGET: ${{ inputs.budget-usd == '' && inputs.budget || '' }}"));
            assert!(text.contains("BUDGET_USD: ${{ inputs.budget-usd }}"));
            assert!(text.contains("--integer limits.budget=\"$BUDGET\""));
            assert!(text.contains("--budget-usd \"$BUDGET_USD\""));
        } else {
            assert_eq!(
                doc["jobs"]["policy"]["with"]["budget"].as_str(),
                Some("${{ inputs.budget }}")
            );
            assert_eq!(
                doc["jobs"]["policy"]["with"]["budget-usd"].as_str(),
                Some("${{ inputs.budget-usd }}")
            );
        }
    }
    // Composed as the policy job does, from a file that caps at $1: an
    // unchanged caller, `budget: ""` included, keeps its cap.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.toml");
    std::fs::write(
        &file,
        "[agent]\nname = \"fake\"\n[limits]\ntimeout-minutes = 10\nbudget = 100\n",
    )
    .unwrap();
    for (usd, aic, expected) in [
        ("", "500", 500),
        ("", "", 100),
        ("", "300", 300),
        ("", "0", 0),
        ("2", "500", 200),
        ("0.5", "", 50),
        ("1.239", "900", 123),
    ] {
        let budget = if usd.is_empty() { aic } else { "" };
        let uncapped = if expected == 0 { "true" } else { "" };
        let output = Command::new(BIN)
            .arg("config")
            .arg("--from")
            .arg(&file)
            .args(["--boolean", &format!("limits.uncapped={uncapped}")])
            .args(["--integer", &format!("limits.budget={budget}")])
            .args(["--budget-usd", usd])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let table: toml::Table = toml::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
        assert_eq!(
            table["limits"]["budget"].as_integer(),
            Some(expected),
            "budget-usd {usd:?}, budget {aic:?}"
        );
    }
}

const PIN: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn prepare_requires_trusted_ids_before_download() {
    let dir = tempfile::tempdir().unwrap();
    for (binary, policy, ok) in [
        ("1", "2", true),
        ("", "2", false),
        ("1", "", false),
        ("0", "2", false),
        ("1,2", "3", false),
        ("1", "policy-name", false),
        ("$(exit 99)", "2", false),
    ] {
        let result = run_step(
            "prepare/action.yml",
            "Require trusted upload IDs",
            dir.path(),
            &[("BINARY", binary), ("POLICY", policy)],
        );
        assert_eq!(
            result.status.success(),
            ok,
            "{binary:?} {policy:?}: {result:?}"
        );
    }
    let doc = definition("prepare/action.yml");
    let steps = steps(&doc);
    let download = steps
        .iter()
        .position(|s| {
            s["uses"]
                .as_str()
                .is_some_and(|s| s.starts_with("actions/download-artifact@"))
        })
        .unwrap();
    assert!(
        steps
            .iter()
            .position(|s| s["name"].as_str() == Some("Require trusted upload IDs"))
            .unwrap()
            < download
    );
    assert_eq!(
        steps[download]["with"]["artifact-ids"].as_str(),
        Some("${{ inputs.binary-artifact-id }},${{ inputs.policy-artifact-id }}")
    );
    assert!(steps[download]["with"]["name"].is_badvalue());
}

#[test]
fn prepare_address_is_a_config_value_and_refusal_is_atomic() {
    use serde_json::json;
    for (address, ok) in [("100.64.0.1", true), ("--help", true), ("refused", false)] {
        let dir = tempfile::tempdir().unwrap();
        executable(
            &dir.path().join("agentic-job"),
            "#!/bin/bash\n[ \"$4\" != --inference-address=refused ] || exit 1\nprintf '%s\\n' \"$@\"\n",
        );
        std::fs::write(dir.path().join("config.toml"), "policy\n").unwrap();
        std::fs::write(dir.path().join("meta.json"), r#"{"item":"x"}"#).unwrap();
        let search = format!("{}:/usr/bin:/bin", dir.path().display());
        let result = run_step(
            "prepare/action.yml",
            "The inference broker's address",
            dir.path(),
            &[
                ("JOB_DIR", path(dir.path())),
                ("ADDRESS", address),
                ("PATH", &search),
            ],
        );
        assert_eq!(result.status.success(), ok, "{result:?}");
        let expected = if ok {
            format!(
                "config\n--from\n{}/config.toml\n--inference-address={address}\n",
                dir.path().display()
            )
        } else {
            "policy\n".into()
        };
        assert_eq!(
            std::fs::read_to_string(dir.path().join("config.toml")).unwrap(),
            expected
        );
        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("meta.json")).unwrap()).unwrap();
        assert_eq!(
            meta,
            if ok {
                json!({"item":"x", "inference_address":address})
            } else {
                json!({"item":"x"})
            }
        );
    }
    let doc = definition("prepare/action.yml");
    let step = named_step(&doc, "The inference broker's address");
    assert_eq!(
        step["if"].as_str(),
        Some("${{ inputs.inference-address != '' }}")
    );
    assert_eq!(
        step["env"]["ADDRESS"].as_str(),
        Some("${{ inputs.inference-address }}")
    );
}

#[test]
fn actions_refuse_source_skew_before_using_policy() {
    let dir = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", dir.path())
            .output()
            .unwrap()
    };
    assert!(git(&["init", "-q"]).status.success());
    assert!(
        git(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "source"
        ])
        .status
        .success()
    );
    let head = String::from_utf8(git(&["rev-parse", "HEAD"]).stdout).unwrap();
    let head = head.trim();
    let other = "b".repeat(40);
    let upper = head.to_uppercase();
    let newline = format!("{head}\n");
    let plain = tempfile::tempdir().unwrap();
    for (sha, action_ref, action_path, ok) in [
        (Some(head), "", dir.path(), true),
        (Some(other.as_str()), "", dir.path(), false),
        (Some(head), head, plain.path(), true),
        (Some(other.as_str()), head, plain.path(), false),
        (Some(head), other.as_str(), dir.path(), false),
        (Some(head), "", plain.path(), false),
        (Some(head), "main", plain.path(), false),
        (None, "", dir.path(), false),
        (Some(""), "", plain.path(), false),
        (Some(upper.as_str()), "", dir.path(), false),
        (Some(newline.as_str()), "", dir.path(), false),
    ] {
        let value = sha.map_or_else(
            || serde_json::json!({}),
            |sha| serde_json::json!({"source_sha":sha}),
        );
        std::fs::write(dir.path().join("run.json"), value.to_string()).unwrap();
        for file in ["prepare/action.yml", "run/action.yml"] {
            let result = run_step(
                file,
                "The policy call is this action's commit",
                dir.path(),
                &[
                    ("JOB_DIR", path(dir.path())),
                    ("ACTION_REF", action_ref),
                    ("GITHUB_ACTION_PATH", path(action_path)),
                    ("GIT_CEILING_DIRECTORIES", path(dir.path())),
                ],
            );
            assert_eq!(
                result.status.success(),
                ok,
                "{file} {sha:?} {action_ref}: {result:?}"
            );
        }
    }
}

#[test]
fn run_requires_locked_host_and_consistent_user_before_probing() {
    let doc = definition("run/action.yml");
    let guard = named_step(&doc, "Prove the host is secured")["run"]
        .as_str()
        .unwrap();
    let python = Regex::new("python3 -c '([^']+)'")
        .unwrap()
        .captures(guard)
        .unwrap()[1]
        .to_owned();
    // The configuration, by [host] and by its deprecated name [sandbox].
    for (config, ok) in [
        ("{}", true),
        (r#"{"host":{}}"#, true),
        (r#"{"host":{"lock-runner":true}}"#, true),
        (r#"{"host":{"lock-runner":false}}"#, false),
        (r#"{"host":{"lock-runner":"true"}}"#, false),
        (r#"{"sandbox":{}}"#, true),
        (r#"{"sandbox":{"lock-runner":true}}"#, true),
        (r#"{"sandbox":{"lock-runner":false}}"#, false),
        (r#"{"sandbox":{"lock-runner":"true"}}"#, false),
    ] {
        let replacement = format!("__import__('json').loads('{config}')");
        let code = python.replace(
            "tomllib.load(open(\"/etc/agentic-job/config.toml\", \"rb\"))",
            &replacement,
        );
        let result = Command::new("python3")
            .args(["-c", &code])
            .env_clear()
            .output()
            .unwrap();
        assert_eq!(result.status.success(), ok, "{config}: {result:?}");
    }
    // The sandbox user went with agentic-job#2989, home or not.
    let removed = "agent-user sandbox was removed with the sandbox user (agentic-job#2989): drop \
                   the input, the runner is the only agent user";
    for (user, home, message) in [
        ("runner", "", "agent-user runner requires runner-home"),
        ("sandbox", "/tmp/home", removed),
        ("sandbox", "", removed),
        ("", "/tmp/home", "agent-user must be runner"),
        ("root", "", "agent-user must be runner"),
        ("runner/home", "", "agent-user must be runner"),
        ("runner", "/tmp/home", ""),
    ] {
        let dir = tempfile::tempdir().unwrap();
        executable(
            &dir.path().join("python3"),
            "#!/bin/sh\necho lock >&2\nexit 1\n",
        );
        executable(
            &dir.path().join("agentic-job"),
            "#!/bin/sh\necho unexpected\nexit 99\n",
        );
        let search = format!("{}:/usr/bin:/bin", dir.path().display());
        let result = run_step(
            "run/action.yml",
            "Prove the host is secured",
            dir.path(),
            &[
                ("PATH", &search),
                ("AGENT_USER", user),
                ("RUNNER_HOME", home),
            ],
        );
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert_eq!(
            String::from_utf8_lossy(&result.stdout),
            if message.is_empty() {
                String::new()
            } else {
                format!("::error::{message}\n")
            }
        );
        assert_eq!(
            String::from_utf8_lossy(&result.stderr).contains("lock"),
            message.is_empty()
        );
    }
    assert_eq!(
        doc["inputs"]["agent-user"]["default"].as_str(),
        Some("runner")
    );
}

/// curl's mock refuses a token on argv and requires the authorization header
/// on stdin; it is shared by the scope and publication probes.
const MOCK_CURL: &str = r#"#!/bin/bash
read -r header
[ "$header" = "Authorization: Bearer $GH_TOKEN" ] || exit 8
case "$*" in *"$GH_TOKEN"*) exit 9 ;; esac
if [ -n "$HEADERS" ]; then printf '%s' "$HEADERS"; exit "$API_EXIT"; fi
if [ "${*: -1}" = "https://api.github.com/repos/$REPO" ]; then answer=$TARGET; else answer=$OTHER; fi
case "$answer" in
  public) echo '{"private":false,"visibility":"public"}' ;;
  private) echo '{"private":true,"visibility":"private"}' ;;
  unknown) echo '{"private":false,"visibility":"internal"}' ;;
esac
exit "$API_EXIT"
"#;

#[test]
fn run_refuses_classic_write_tokens_without_exposing_them() {
    for (token, headers, api_exit, ok) in [
        ("", "", "0", true),
        (
            "job-fixture",
            "HTTP/2 200\r\nx-ratelimit-limit: 5000\r\n",
            "0",
            true,
        ),
        (
            "classic-fixture",
            "HTTP/2 200\r\nx-oauth-scopes: \r\n",
            "0",
            true,
        ),
        (
            "classic-fixture",
            "HTTP/2 200\r\nX-OAuth-Scopes: read:org, read:user, user:email\r\n",
            "0",
            true,
        ),
        (
            "classic-fixture",
            "x-oauth-scopes: public_repo\r\n",
            "0",
            false,
        ),
        (
            "classic-fixture",
            "x-oauth-scopes: read:org, repo\r\n",
            "0",
            false,
        ),
        (
            "classic-fixture",
            "x-oauth-scopes: read:packages,write:packages\r\n",
            "0",
            false,
        ),
        ("classic-fixture", "x-oauth-scopes: gist\r\n", "0", false),
        ("classic-fixture", "x-oauth-scopes: *\r\n", "0", false),
        (
            "classic-fixture",
            "x-oauth-scopes: $(exit 0)\r\n",
            "0",
            false,
        ),
        ("classic-fixture", "", "22", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        executable(&dir.path().join("curl"), MOCK_CURL);
        let search = format!("{}:/usr/bin:/bin", dir.path().display());
        let result = run_step(
            "run/action.yml",
            "Refuse a GitHub token that can write",
            dir.path(),
            &[
                ("PATH", &search),
                ("GH_TOKEN", token),
                ("HEADERS", headers),
                ("API_EXIT", api_exit),
            ],
        );
        assert_eq!(result.status.success(), ok, "{headers:?}: {result:?}");
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            !log.contains("classic-fixture") && !log.contains("job-fixture"),
            "{log}"
        );
    }
}

#[test]
fn visibility_admission_and_publication_fail_closed() {
    // Target, other repositories, target/other API answers, policy private,
    // policy repo, caller, API status, upload acceptance, admission acceptance.
    for (repo, repos, target, other, private, policy_repo, caller, api_exit, upload, admission) in [
        (
            "owner/repo",
            "",
            "public",
            "public",
            false,
            "owner/repo",
            "owner/caller",
            "0",
            true,
            true,
        ),
        (
            "owner/repo",
            "owner/config",
            "public",
            "public",
            false,
            "owner/repo",
            "owner/caller",
            "0",
            true,
            true,
        ),
        (
            "owner/repo",
            "",
            "private",
            "public",
            false,
            "owner/repo",
            "owner/repo",
            "0",
            false,
            true,
        ),
        (
            "owner/repo",
            "",
            "private",
            "public",
            true,
            "owner/repo",
            "owner/repo",
            "0",
            true,
            true,
        ),
        (
            "owner/repo",
            "",
            "private",
            "public",
            true,
            "owner/other",
            "owner/repo",
            "0",
            false,
            true,
        ),
        (
            "owner/repo",
            "",
            "private",
            "public",
            true,
            "owner/repo",
            "owner/caller",
            "0",
            false,
            false,
        ),
        (
            "owner/repo",
            "",
            "unknown",
            "public",
            true,
            "owner/repo",
            "owner/repo",
            "0",
            false,
            false,
        ),
        (
            "owner/repo",
            "owner/config",
            "private",
            "private",
            true,
            "owner/repo",
            "owner/repo",
            "0",
            false,
            false,
        ),
        (
            "owner/repo",
            "owner/repo",
            "private",
            "private",
            true,
            "owner/repo",
            "owner/repo",
            "0",
            false,
            false,
        ),
        (
            "$(exit 99)",
            "",
            "public",
            "public",
            false,
            "$(exit 99)",
            "owner/caller",
            "0",
            false,
            false,
        ),
        (
            "",
            "",
            "public",
            "public",
            false,
            "",
            "owner/caller",
            "0",
            false,
            false,
        ),
        (
            " ",
            "",
            "public",
            "public",
            false,
            " ",
            "owner/caller",
            "0",
            false,
            false,
        ),
        (
            "owner/repo",
            "invalid",
            "public",
            "public",
            false,
            "owner/repo",
            "owner/caller",
            "0",
            false,
            false,
        ),
        (
            "owner/repo",
            "owner/config owner/item",
            "unknown",
            "unknown",
            false,
            "owner/repo",
            "owner/caller",
            "0",
            false,
            false,
        ),
        (
            "owner/repo",
            "owner/config owner/item",
            "",
            "",
            false,
            "owner/repo",
            "owner/caller",
            "0",
            false,
            false,
        ),
        (
            "owner/repo",
            "owner/config owner/item",
            "public",
            "public",
            false,
            "owner/repo",
            "owner/caller",
            "1",
            false,
            false,
        ),
        (
            "owner/repo",
            "owner/config owner/item",
            "private",
            "private",
            false,
            "owner/repo",
            "owner/caller",
            "0",
            false,
            false,
        ),
        (
            "owner/repo",
            "owner/config",
            "public",
            "private",
            false,
            "owner/repo",
            "owner/caller",
            "0",
            false,
            false,
        ),
    ] {
        for (file, name, ok) in [
            (
                "run/action.yml",
                "Check again that the repositories are public",
                upload,
            ),
            (
                "policy.yml",
                "Check that the repositories are public",
                admission,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            executable(&dir.path().join("curl"), MOCK_CURL);
            executable(
                &dir.path().join("gh"),
                "#!/bin/bash\nif [ \"$2\" = \"repos/$REPO\" ]; then printf '%s\\n' \"$TARGET\"; else printf '%s\\n' \"$OTHER\"; fi\nexit \"$API_EXIT\"\n",
            );
            std::fs::write(
                dir.path().join("policy.json"),
                serde_json::json!({"repo":policy_repo,"private":private}).to_string(),
            )
            .unwrap();
            let output = dir.path().join("output");
            std::fs::write(&output, "").unwrap();
            let search = format!("{}:/usr/bin:/bin", dir.path().display());
            let result = run_step(
                file,
                name,
                dir.path(),
                &[
                    ("PATH", &search),
                    ("GH_TOKEN", "fixture-token"),
                    ("REPO", repo),
                    ("REPOS", repos),
                    ("TARGET", target),
                    ("OTHER", other),
                    ("API_EXIT", api_exit),
                    ("JOB_DIR", path(dir.path())),
                    ("GITHUB_REPOSITORY", caller),
                    ("GITHUB_OUTPUT", path(&output)),
                ],
            );
            assert_eq!(
                result.status.success(),
                ok,
                "{file} {repo:?} {target} {other} {caller}: {result:?}"
            );
            if file == "policy.yml" {
                let marked = target == "private" && repo == caller && api_exit == "0";
                assert_eq!(
                    std::fs::read_to_string(&output).unwrap(),
                    if marked { "private=true\n" } else { "" }
                );
            }
            if !ok && repo == "owner/repo" && repos != "invalid" {
                assert!(
                    String::from_utf8_lossy(&result.stdout).contains("private runs are refused"),
                    "{result:?}"
                );
                assert!(
                    String::from_utf8_lossy(&result.stdout)
                        .contains("docs/private-repositories.md")
                );
            }
        }
    }
}

#[test]
fn runner_admission_precedes_setup_and_setup_is_isolated() {
    // Copy the script at test time into the source-checkout layout used by
    // the real steps, so neither the helper nor Python needs a source rewrite.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".agentic-job-source/workflow")).unwrap();
    std::fs::copy(
        root().join("workflow/runner-setup.py"),
        dir.path()
            .join(".agentic-job-source/workflow/runner-setup.py"),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join(".agentic-job")).unwrap();
    let home = dir.path().join("agent-home");
    let config = dir.path().join(".agentic-job/config.toml");
    let write_policy = "[egress]\nwrite-policy = true\n";
    let private = r#"{"private":true}"#;
    for (caller, policy, text, runner) in [
        ("false", "{}", "", true),
        ("false", r#"{"private":false}"#, "", true),
        ("false", "{}", write_policy, true),
        ("true", "{}", "", false),
        ("null", "{}", "", false),
        ("false", private, "", false),
        ("true", "{}", write_policy, false),
        ("null", "{}", write_policy, false),
        ("true", private, write_policy, false),
        ("false", private, write_policy, false),
        ("false", "{}", "[inference]\nregister = 'api-key'", false),
        (
            "false",
            "{}",
            "[mcp.server]\nurl = 'https://example.com'",
            false,
        ),
        ("false", "{}", "[session]\nlisten = true", false),
        ("false", "{}", "[setup]\npackages = []", true),
    ] {
        std::fs::write(&config, text).unwrap();
        std::fs::write(dir.path().join(".agentic-job/policy.json"), policy).unwrap();
        // The sandbox user went with agentic-job#2989, whatever the file.
        for (user, ok) in [
            ("runner", runner),
            ("sandbox", false),
            ("", false),
            ("root", false),
        ] {
            let result = run_step(
                "agent.yml",
                "Admit the runner-user configuration",
                dir.path(),
                &[
                    ("CALLER_PRIVATE", caller),
                    ("AGENT_USER", user),
                    ("AGENT_HOME", path(&home)),
                ],
            );
            assert_eq!(
                result.status.success(),
                ok,
                "{caller} {policy} {text} {user}: {result:?}"
            );
            assert!(!home.exists());
        }
    }
    for (text, script, code) in [
        ("[setup]\npackages = []", "", 0),
        (
            "[setup]\nscript = 'setup.sh'\n[host.env]\nTOOLCHAIN_OPTION = 'configured'",
            "#!/bin/sh\npwd > \"$HOME/pwd\"\nenv > \"$HOME/env\"\n",
            0,
        ),
        // The table's deprecated name, which `config` no longer writes.
        (
            "[setup]\nscript = 'setup.sh'\n[sandbox.env]\nTOOLCHAIN_OPTION = 'configured'",
            "#!/bin/sh\npwd > \"$HOME/pwd\"\nenv > \"$HOME/env\"\n",
            0,
        ),
        ("[setup]\nscript = 'setup.sh'", "#!/bin/sh\nexit 3\n", 3),
    ] {
        std::fs::write(&config, text).unwrap();
        std::fs::write(dir.path().join("setup.sh"), script).unwrap();
        let result = run_step(
            "agent.yml",
            "The setup script",
            dir.path(),
            &[
                ("RUNNER_TEMP", path(dir.path())),
                ("AGENT_HOME", path(&home)),
                ("JOB_CREDENTIAL", "must-not-reach-setup"),
            ],
        );
        assert_eq!(result.status.code(), Some(code), "{result:?}");
        if script.is_empty() {
            assert!(!home.exists());
        }
        if script.contains("pwd") {
            assert_eq!(
                std::fs::read_to_string(home.join("pwd")).unwrap().trim(),
                path(&home)
            );
            let env = std::fs::read_to_string(home.join("env")).unwrap();
            assert!(
                env.lines()
                    .any(|line| line == format!("HOME={}", home.display()))
            );
            assert!(
                env.lines()
                    .any(|line| line == "TOOLCHAIN_OPTION=configured")
            );
            assert!(!env.contains("JOB_CREDENTIAL") && !env.contains("RUNNER_TEMP"));
        }
    }
}

#[test]
fn documented_runner_configs_parse_and_obey_admission() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join(".agentic-job-source/workflow");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::copy(
        root().join("workflow/runner-setup.py"),
        source.join("runner-setup.py"),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join(".agentic-job")).unwrap();
    std::fs::write(dir.path().join(".agentic-job/policy.json"), "{}").unwrap();
    let config = dir.path().join(".agentic-job/config.toml");
    let home = dir.path().join("agent-home");
    for (file, admitted) in [("docs/interface.md", true), ("docs/mcp.md", false)] {
        let doc = std::fs::read_to_string(root().join(file)).unwrap();
        let example = doc
            .split_once("```toml\n")
            .unwrap()
            .1
            .split_once("```")
            .unwrap()
            .0;
        std::fs::write(&config, example).unwrap();
        // Parse through the real CLI, not only Python's TOML reader: schema
        // validity is distinct from permission to launch in runner mode.
        let parsed = Command::new(BIN)
            .args(["config", "--from"])
            .arg(&config)
            .output()
            .unwrap();
        assert!(parsed.status.success(), "{file}: {parsed:?}");
        std::fs::write(&config, parsed.stdout).unwrap();
        let result = run_step(
            "agent.yml",
            "Admit the runner-user configuration",
            dir.path(),
            &[
                ("CALLER_PRIVATE", "false"),
                ("AGENT_USER", "runner"),
                ("AGENT_HOME", path(&home)),
            ],
        );
        assert_eq!(result.status.success(), admitted, "{file}: {result:?}");
        if !admitted {
            assert!(
                String::from_utf8_lossy(&result.stderr).contains("[mcp.NAME]"),
                "{result:?}"
            );
        }
        assert!(!home.exists(), "admission must not perform setup");
    }
}

#[test]
fn run_uses_policy_binary_captures_exit_and_gates_partial_results() {
    for exit in [0, 1, 3, 4, 124] {
        let dir = tempfile::tempdir().unwrap();
        executable(
            &dir.path().join("agentic-job"),
            "#!/bin/bash\nprintf '%s\\n' \"$0\" \"$@\" > \"$RECORD\"\nexit \"$STATE\"\n",
        );
        // Artifact downloads do not preserve executable permissions.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.path().join("agentic-job"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let record = dir.path().join("record");
        let output = dir.path().join("output");
        let home = dir.path().join("agent-home");
        let result = run_step(
            "run/action.yml",
            "Run the agent",
            dir.path(),
            &[
                ("JOB_DIR", path(dir.path())),
                ("RUNNER_HOME", path(&home)),
                ("REVIEW_HEAD", "review-head"),
                ("STATE", &exit.to_string()),
                ("RECORD", path(&record)),
                ("GITHUB_OUTPUT", path(&output)),
                ("GITHUB_STEP_SUMMARY", path(&dir.path().join("summary"))),
            ],
        );
        assert!(result.status.success(), "{result:?}");
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            format!("exit={exit}\n")
        );
        let args = std::fs::read_to_string(record).unwrap();
        assert!(args.starts_with(&format!(
            "{}/agentic-job\nrun\n--runner-home\n{}\n",
            dir.path().display(),
            home.display()
        )));
        assert!(args.contains("--review-head\nreview-head\n"));
        for partial in ["false", "true"] {
            let gate = run_step(
                "run/action.yml",
                "The run's result",
                dir.path(),
                &[
                    ("JOB_DIR", path(dir.path())),
                    ("EXIT", &exit.to_string()),
                    ("PARTIAL", partial),
                    ("HANDED_BACK", "false"),
                    ("CLASS", ""),
                ],
            );
            assert_eq!(
                gate.status.success(),
                exit == 0 || partial == "true" && [3, 124].contains(&exit),
                "{exit} {partial}: {gate:?}"
            );
        }
    }
}

#[test]
fn run_only_publishes_scalar_budget_and_safe_secret_locations() {
    use serde_json::json;
    for (summary, over) in [
        (
            json!({"result":"success","aic":565.9,"aic_budget":500}),
            "565.9 of 500 AIC",
        ),
        (json!({"result":"success","aic":499.9,"aic_budget":500}), ""),
        (
            json!({"result":"success","aic":565.9,"aic_budget":null}),
            "",
        ),
        (
            json!({"result":"success","aic":"565.9 $(exit 9)","aic_budget":500}),
            "",
        ),
        (json!({"result":"budget","aic":565.9,"aic_budget":500}), ""),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("out/run")).unwrap();
        std::fs::write(dir.path().join("out/run/summary.json"), summary.to_string()).unwrap();
        executable(&dir.path().join("agentic-job"), "#!/bin/sh\nexit 0\n");
        let output = dir.path().join("output");
        let result = run_step(
            "run/action.yml",
            "Run the agent",
            dir.path(),
            &[
                ("JOB_DIR", path(dir.path())),
                ("GITHUB_OUTPUT", path(&output)),
                ("GITHUB_STEP_SUMMARY", path(&dir.path().join("summary"))),
            ],
        );
        assert!(result.status.success(), "{result:?}");
        let extra = if over.is_empty() {
            String::new()
        } else {
            format!("over-budget={over}\n")
        };
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            format!("exit=0\n{extra}")
        );
        assert_eq!(
            String::from_utf8_lossy(&result.stdout).contains(&format!(
                "::warning::the agent ended its turn over budget: spent {over}\n"
            )),
            !over.is_empty()
        );
    }
    // The agent's `stopped_early`, as a fixed word only (#3017).
    for (outcome, wanted) in [
        (
            Some(r#"{"stopped_early": "the hand-back cannot carry it"}"#),
            true,
        ),
        (Some(r#"{"stopped_early": true}"#), true),
        (Some(r#"{"stopped_early": null}"#), false),
        (Some(r#"{"stopped_early": ""}"#), false),
        (Some(r#"{"stopped_early": false}"#), false),
        (Some(r#"{"summary": "Done."}"#), false),
        (Some("not json"), false),
        (None, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("out/run")).unwrap();
        if let Some(outcome) = outcome {
            std::fs::write(dir.path().join("out/run/outcome.json"), outcome).unwrap();
        }
        executable(&dir.path().join("agentic-job"), "#!/bin/sh\nexit 0\n");
        let output = dir.path().join("output");
        let result = run_step(
            "run/action.yml",
            "Run the agent",
            dir.path(),
            &[
                ("JOB_DIR", path(dir.path())),
                ("GITHUB_OUTPUT", path(&output)),
                ("GITHUB_STEP_SUMMARY", path(&dir.path().join("summary"))),
            ],
        );
        assert!(result.status.success(), "{outcome:?}: {result:?}");
        let extra = if wanted { "stopped-early=true\n" } else { "" };
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            format!("exit=0\n{extra}"),
            "{outcome:?}"
        );
    }
    for (at, wanted) in [
        (
            "safe-outputs/aw-agent-run-1.patch, line 3 (known run secret: GH_TOKEN)\n",
            "safe-outputs/aw-agent-run-1.patch, line 3 (known run secret: GH_TOKEN)",
        ),
        (
            "safe-outputs/aw-agent-run-1.patch, line 3 (pattern: private key header)\n",
            "safe-outputs/aw-agent-run-1.patch, line 3 (pattern: private key header)",
        ),
        (
            "safe-outputs/aw-agent-run-1.patch, line 3\n",
            "safe-outputs/aw-agent-run-1.patch, line 3",
        ),
        (
            "transcript/acp.jsonl, line 12\nmore\n",
            "transcript/acp.jsonl, line 12",
        ),
        ("safe-outputs/a`@b`.patch, line 3\n", ""),
        ("../x, line 3\n", ""),
        ("safe-outputs/x.patch, line 3 $(exit 9)\n", ""),
        ("safe-outputs/x.patch, line 3 (known run secret: `x`)\n", ""),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("out")).unwrap();
        std::fs::write(dir.path().join("out/secret-at"), at).unwrap();
        executable(&dir.path().join("agentic-job"), "#!/bin/sh\nexit 1\n");
        let output = dir.path().join("output");
        let summary = dir.path().join("summary");
        let result = run_step(
            "run/action.yml",
            "Run the agent",
            dir.path(),
            &[
                ("JOB_DIR", path(dir.path())),
                ("GITHUB_OUTPUT", path(&output)),
                ("GITHUB_STEP_SUMMARY", path(&summary)),
            ],
        );
        assert!(result.status.success(), "{result:?}");
        let extra = if wanted.is_empty() {
            String::new()
        } else {
            format!("secret-at={wanted}\n")
        };
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            format!("exit=1\n{extra}")
        );
        assert_eq!(
            std::fs::read_to_string(summary).unwrap_or_default(),
            if wanted.is_empty() {
                String::new()
            } else {
                format!(
                    "Nothing of this run was uploaded: a secret or a private key is in {wanted}.\n"
                )
            }
        );
    }
}

/// Split the bounded writer's output across the reader's first-line exit.
/// An early-closing reader makes poll wake on POLLERR, then the next write
/// raises SIGPIPE; a draining reader waits for and consumes the second write.
#[test]
fn run_drains_the_bounded_secret_location_writer() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("out")).unwrap();
    std::fs::write(dir.path().join("out/secret-at"), "").unwrap();
    executable(&dir.path().join("agentic-job"), "#!/bin/sh\nexit 1\n");
    executable(
        &dir.path().join("head"),
        r#"#!/usr/bin/python3
import os, select, signal, sys
if sys.argv[1:] != ['-c', '512', os.environ['JOB_DIR'] + '/out/secret-at']:
    os.execv('/usr/bin/head', ['head'] + sys.argv[1:])
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
os.write(1, b'safe-outputs/change.patch, line 3\n')
poll = select.poll(); poll.register(1, select.POLLERR); poll.poll(1000)
os.write(1, b'x' * (512 - len(b'safe-outputs/change.patch, line 3\n')))
open('writer-finished', 'w').close()
"#,
    );
    let output = dir.path().join("output");
    let summary = dir.path().join("summary");
    let search = format!("{}:/usr/bin:/bin", dir.path().display());
    let result = run_step(
        "run/action.yml",
        "Run the agent",
        dir.path(),
        &[
            ("PATH", &search),
            ("JOB_DIR", path(dir.path())),
            ("GITHUB_OUTPUT", path(&output)),
            ("GITHUB_STEP_SUMMARY", path(&summary)),
        ],
    );
    assert!(result.status.success(), "{result:?}");
    assert!(dir.path().join("writer-finished").exists());
    assert_eq!(
        std::fs::read_to_string(output).unwrap(),
        "exit=1\nsecret-at=safe-outputs/change.patch, line 3\n"
    );
}

#[test]
fn network_refuses_debug_logging_before_minting() {
    let file = ".github/agentic-job/network/action.yml";
    let doc = definition(file);
    let steps = steps(&doc);
    assert_eq!(steps[0]["name"].as_str(), Some("Refuse step debug logging"));
    assert_eq!(steps[0]["if"].as_str(), Some("${{ inputs.secret == '' }}"));
    assert!(
        steps
            .iter()
            .position(|s| s["name"].as_str() == Some("Mint the agent job's key"))
            .unwrap()
            > 0
    );
    for value in [None, Some(""), Some("0"), Some("1")] {
        let dir = tempfile::tempdir().unwrap();
        let env: Vec<_> = value.map(|v| ("RUNNER_DEBUG", v)).into_iter().collect();
        let result = run_step(file, "Refuse step debug logging", dir.path(), &env);
        let ok = value.is_none_or(str::is_empty);
        assert_eq!(result.status.success(), ok, "{value:?}: {result:?}");
        if !ok {
            assert!(
                String::from_utf8_lossy(&result.stdout).starts_with("::error::Refusing to mint")
            );
        }
    }
    let pinned = Regex::new(r"^[\w-]+/[\w./-]+@[0-9a-f]{40}$").unwrap();
    for step in steps {
        if let Some(action) = step["uses"].as_str() {
            assert!(pinned.is_match(action), "{action}");
        }
    }
}

#[test]
fn composed_agents_keep_policy_source_and_trusted_edges() {
    let pinned = Regex::new(r"^actions/(checkout|download-artifact)@[0-9a-f]{40}$").unwrap();
    for (file, prefix) in [
        ("agent.yml", "fromJSON(inputs.policy)."),
        ("example-compose.yml", "needs.policy.outputs."),
    ] {
        let doc = definition(file);
        let agent = &doc["jobs"]["agent"];
        let steps = agent["steps"].as_vec().unwrap();
        let uses: Vec<_> = steps.iter().filter_map(|s| s["uses"].as_str()).collect();
        let local: Vec<_> = uses
            .iter()
            .copied()
            .filter(|s| !s.starts_with("actions/"))
            .collect();
        let expected = if file == "agent.yml" {
            vec![
                "./.agentic-job-source/prepare",
                "./.github/agentic-job/network",
                "./.agentic-job-source/secure-host",
                "./.agentic-job-source/run",
            ]
        } else {
            vec![
                "./.agentic-job-source/prepare",
                "./.agentic-job-source/secure-host",
                "./.agentic-job-source/run",
            ]
        };
        assert_eq!(local, expected, "{file}");
        for action in uses.iter().filter(|s| s.starts_with("actions/")) {
            assert!(pinned.is_match(action));
        }
        let checkouts: Vec<_> = steps
            .iter()
            .filter(|s| {
                s["uses"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("actions/checkout@"))
            })
            .collect();
        assert_eq!(checkouts.len(), 2);
        for step in &checkouts {
            assert_eq!(step["with"]["persist-credentials"].as_bool(), Some(false));
        }
        for (key, value) in [("repository", "source-repository"), ("ref", "source-sha")] {
            assert_eq!(
                checkouts[1]["with"][key].as_str(),
                Some(format!("${{{{ {prefix}{value} }}}}").as_str())
            );
        }
        assert_eq!(
            checkouts[1]["with"]["path"].as_str(),
            Some(".agentic-job-source")
        );
        assert_eq!(
            checkouts[0]["with"]["ref"].as_str(),
            Some(format!("${{{{ {prefix}ref }}}}").as_str())
        );
        let prepare = steps
            .iter()
            .find(|s| s["uses"].as_str() == Some("./.agentic-job-source/prepare"))
            .unwrap();
        for key in ["binary-artifact-id", "policy-artifact-id"] {
            assert_eq!(
                prepare["with"][key].as_str(),
                Some(format!("${{{{ {prefix}{key} }}}}").as_str())
            );
        }
        for key in ["safe-outputs-artifact-id", "safe-outputs-artifact-digest"] {
            assert_eq!(
                agent["outputs"][key].as_str(),
                Some(format!("${{{{ steps.run.outputs.{key} }}}}").as_str())
            );
        }
        let source_name = "The policy call's source repository and commit";
        let at = |name| {
            steps
                .iter()
                .position(|s| s["name"].as_str() == Some(name))
                .unwrap()
        };
        assert!(
            at(source_name)
                < steps
                    .iter()
                    .position(|s| s["with"]["path"].as_str() == Some(".agentic-job-source"))
                    .unwrap()
        );
        for (repo, sha, ok) in [
            ("o/r", PIN, true),
            ("", PIN, false),
            ("o/r", "", false),
            ("o/r", "main", false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let result = run_step(
                file,
                source_name,
                dir.path(),
                &[("SOURCE_REPOSITORY", repo), ("SOURCE_SHA", sha)],
            );
            assert_eq!(
                result.status.success(),
                ok,
                "{file} {repo} {sha}: {result:?}"
            );
        }
        let expanded = workflow(file)
            .replace(
                "uses: ./.agentic-job-source/prepare",
                &std::fs::read_to_string(root().join("prepare/action.yml")).unwrap(),
            )
            .replace(
                "uses: ./.agentic-job-source/secure-host",
                &std::fs::read_to_string(root().join("secure-host/action.yml")).unwrap(),
            )
            .replace(
                "uses: ./.agentic-job-source/run",
                &std::fs::read_to_string(root().join("run/action.yml")).unwrap(),
            );
        let mut start = 0;
        for name in [
            "Install the binary",
            "Write what the run is called",
            "Admit the runner-user configuration",
            "Check inference proxy reachability",
            "The host's configuration",
            "Refuse the old action's inputs",
            "The setup script",
            "The session's endpoint",
            "Prove the host is secured",
            "Run the agent",
        ] {
            let needle = format!("- name: {name}\n");
            start += expanded[start..]
                .find(&needle)
                .unwrap_or_else(|| panic!("{file}: no {name} after {start}"))
                + needle.len();
        }
        assert_eq!(
            named_step(&doc, "Check inference proxy reachability")["run"].as_str(),
            Some("agentic-job secure-host inference .agentic-job/config.toml")
        );
        assert_eq!(
            steps
                .iter()
                .filter(|s| s["run"]
                    .as_str()
                    .is_some_and(|s| s.contains("agentic-job secure-host inference")))
                .count(),
            1
        );
    }
    for file in ["agentic-job.yml", "example-compose.yml"] {
        let doc = definition(file);
        for (name, mut values) in [
            (
                "check",
                vec![
                    ("policy", "${{ toJSON(needs.policy.outputs) }}"),
                    (
                        "safe-outputs-artifact-id",
                        "${{ needs.agent.outputs.safe-outputs-artifact-id }}",
                    ),
                    (
                        "safe-outputs-artifact-digest",
                        "${{ needs.agent.outputs.safe-outputs-artifact-digest }}",
                    ),
                ],
            ),
            (
                "apply",
                vec![
                    ("policy", "${{ toJSON(needs.policy.outputs) }}"),
                    ("agent", "${{ toJSON(needs.agent) }}"),
                    ("check", "${{ toJSON(needs.check) }}"),
                ],
            ),
        ] {
            if file == "agentic-job.yml" && name == "apply" {
                values.push(("role-bindings", "${{ inputs.role-bindings }}"));
            }
            let with = doc["jobs"][name]["with"].as_hash().unwrap();
            assert_eq!(with.len(), values.len());
            for (key, value) in values {
                assert_eq!(doc["jobs"][name]["with"][key].as_str(), Some(value));
            }
        }
    }
}

#[test]
fn agent_credentials_stay_in_their_deterministic_jobs_and_steps() {
    use yaml_rust2::Yaml;
    let pinned = Regex::new(r"^actions/[\w-]+@[0-9a-f]{40}$").unwrap();
    for file in ["prepare/action.yml", "run/action.yml"] {
        let doc = definition(file);
        for step in steps(&doc) {
            if let Some(action) = step["uses"].as_str() {
                assert!(pinned.is_match(action), "{file}: {action}");
            }
        }
    }
    let reads = Yaml::Hash(
        ["contents", "issues", "pull-requests", "actions"]
            .map(|key| (Yaml::String(key.into()), Yaml::String("read".into())))
            .into_iter()
            .collect(),
    );
    for (file, name) in [
        ("agent.yml", "agent"),
        ("agentic-job.yml", "agent"),
        ("example-compose.yml", "agent"),
    ] {
        assert_eq!(
            definition(file)["jobs"][name]["permissions"],
            reads,
            "{file}"
        );
    }
    let agent = workflow("agent.yml");
    let wrapper = workflow("agentic-job.yml");
    let run = std::fs::read_to_string(root().join("run/action.yml")).unwrap();
    let doc = definition("run/action.yml");
    for (input, key) in [
        ("github-token", "GH_TOKEN"),
        ("inference-api-key", "AGENTIC_JOB_INFERENCE_KEY"),
        ("mcp-token", "AGENTIC_JOB_MCP_TOKEN"),
        ("inference-run-token", "AGENTIC_JOB_INFERENCE_RUN_TOKEN"),
    ] {
        assert_eq!(
            named_step(&doc, "Run the agent")["env"][key].as_str(),
            Some(format!("${{{{ inputs.{input} }}}}").as_str())
        );
        if input != "github-token" {
            assert_eq!(run.matches(&format!("inputs.{input}")).count(), 1);
        }
    }
    assert_eq!(doc["inputs"]["github-token"]["default"].as_str(), Some(""));
    for file in [
        "agentic-job.yml",
        "agent.yml",
        "example-compose.yml",
        "policy.yml",
        "check.yml",
        "apply.yml",
    ] {
        let text = workflow(file);
        let doc = definition(file);
        for (name, value) in doc["jobs"].as_hash().unwrap() {
            let name = name.as_str().unwrap();
            let writes = name == "apply"
                || file == "agentic-job.yml" && name == "policy"
                || file == "policy.yml" && ["notify", "apply-token"].contains(&name)
                || file == "apply.yml" && name == "conclude";
            assert_eq!(
                job(&text, name).contains("secrets.SAFE_OUTPUTS_PAT"),
                writes,
                "{file} {name}"
            );
            if file == "agent.yml" {
                assert!(value["permissions"]["id-token"].is_badvalue());
            }
        }
    }
    for (file, text) in [
        ("agentic-job.yml", wrapper.as_str()),
        ("agent.yml", agent.as_str()),
        ("review.yml", workflow("review.yml").as_str()),
    ] {
        for key in ["MCP_TOKEN", "INFERENCE_API_KEY"] {
            assert!(!text.contains(&format!("secrets.{key}")), "{file}");
        }
    }
    assert!(
        !Regex::new("check-key|mcp-token|inference-api-key")
            .unwrap()
            .is_match(&agent)
    );
    let secrets = Regex::new(r"secrets\.([\w]+)").unwrap();
    assert_eq!(
        secrets
            .captures_iter(&agent)
            .map(|c| c[1].to_owned())
            .collect::<Vec<_>>(),
        ["NETWORK_SECRET", "INFERENCE_RUN_TOKEN"]
    );
    assert_eq!(
        wrapper
            .lines()
            .filter(|l| l.contains("needs.register.outputs"))
            .collect::<Vec<_>>(),
        ["      INFERENCE_RUN_TOKEN: ${{ needs.register.outputs.run-token }}"]
    );
    assert_eq!(
        agent
            .lines()
            .filter(|l| l.contains("secrets.INFERENCE_RUN_TOKEN"))
            .collect::<Vec<_>>(),
        ["          inference-run-token: ${{ secrets.INFERENCE_RUN_TOKEN }}"]
    );
    let doc = definition("agentic-job.yml");
    let register = &doc["jobs"]["register"];
    assert_eq!(register["permissions"].as_hash().unwrap().len(), 1);
    assert_eq!(register["permissions"]["id-token"].as_str(), Some("write"));
    let register_text = job(&wrapper, "register");
    assert!(
        !Regex::new(r"secrets\.|checkout|github\.token")
            .unwrap()
            .is_match(register_text)
    );
    assert_eq!(
        register["outputs"]["run-token"].as_str(),
        Some("${{ steps.register.outputs.run-token }}")
    );
    assert_eq!(
        register["runs-on"].as_str(),
        Some("${{ fromJSON(inputs.agent-runner) }}")
    );
    let uses: Vec<_> = register["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .filter_map(|s| s["uses"].as_str())
        .collect();
    assert_eq!(
        uses,
        ["actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333"]
    );
    assert!(named_step(&doc, "Register the run at the inference proxy")["run"].as_str().unwrap().trim_end().ends_with(r#""$JOB_DIR/agentic-job" register --config "$JOB_DIR/config.toml" --output "$GITHUB_OUTPUT""#));
    assert_eq!(
        doc["on"]["workflow_call"]["inputs"]["github-reads"]["default"].as_bool(),
        Some(true)
    );
    assert!(agent.contains("github-token: ${{ inputs.github-reads && github.token || '' }}"));
    // Called workflows cannot elevate their caller's grants, even in skipped jobs.
    for entry in std::fs::read_dir(root().join(".github/workflows")).unwrap() {
        let file = entry.unwrap().path();
        if file.extension().is_none_or(|s| s != "yml") {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!text.contains("GH_READ_TOKEN"), "{file:?}");
        let doc = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
        for (name, job) in doc["jobs"].as_hash().unwrap() {
            if !job["uses"].as_str().is_some_and(|s| {
                [
                    "./.github/workflows/agentic-job.yml",
                    "./.github/workflows/dispatch.yml",
                    "./.github/workflows/example-compose.yml",
                ]
                .contains(&s)
            }) {
                continue;
            }
            for key in ["contents", "issues", "pull-requests", "actions"] {
                assert!(
                    matches!(job["permissions"][key].as_str(), Some("read" | "write")),
                    "{file:?} {name:?} {key}"
                );
            }
            assert_eq!(
                job["permissions"]["id-token"].as_str(),
                Some("write"),
                "{file:?} {name:?}"
            );
        }
    }
}

#[test]
fn wrapper_forwards_policy_settings_without_reinterpretation() {
    let wrapper = definition("agentic-job.yml");
    let policy = definition("policy.yml");
    let own = [
        "agent-runner",
        "github-reads",
        "secure-host-image-artifact-id",
        "agent-user",
    ];
    let inputs = |doc: &yaml_rust2::Yaml| {
        doc["on"]["workflow_call"]["inputs"]
            .as_hash()
            .unwrap()
            .keys()
            .map(|key| key.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        inputs(&wrapper)
            .into_iter()
            .filter(|s| !own.contains(&s.as_str()))
            .collect::<Vec<_>>(),
        inputs(&policy)
    );
    assert_eq!(
        wrapper["jobs"]["policy"]["with"].as_hash().unwrap().len(),
        inputs(&policy).len()
    );
    for name in inputs(&policy) {
        assert_eq!(
            wrapper["jobs"]["policy"]["with"][name.as_str()].as_str(),
            Some(format!("${{{{ inputs.{name} }}}}").as_str())
        );
    }
}

#[test]
fn policy_config_uses_its_own_binary_and_host_config_keeps_user_mode() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("bin")).unwrap();
    executable(
        &dir.path().join("bin/agentic-job"),
        "#!/bin/sh\nprintf '%s\\n' \"$@\"\n",
    );
    let mut env = vec![
        ("JOB_DIR", path(dir.path())),
        ("AGENT", "fake"),
        ("REPO", "example/repo"),
    ];
    for key in [
        "CONFIG",
        "MODEL",
        "CONFIG_REPO",
        "CONFIG_REF",
        "CONFIG_PATH",
        "SKILLS",
        "URL",
        "REGISTER",
        "AUDIENCE",
        "TOKEN_FILE",
        "PROVIDER",
        "TIMEOUT",
        "MAX_REQUESTS",
        "MAX_TASKS",
        "BUDGET",
        "BUDGET_USD",
        "PACKAGES",
        "NPM",
        "AGENTS",
        "SETUP",
        "SESSION",
        "IDLE_MINUTES",
        "WRITE_POLICY",
    ] {
        env.push((key, ""));
    }
    let result = run_step("policy.yml", "Write the configuration", dir.path(), &env);
    assert!(result.status.success(), "{result:?}");
    assert!(
        std::fs::read_to_string(dir.path().join("config.toml"))
            .unwrap()
            .starts_with("config\n--repo\nexample/repo\n--string\nagent.name=fake\n")
    );
    let search = format!("{}:/usr/bin:/bin", dir.path().join("bin").display());
    executable(
        &dir.path().join("bin/agentic-job"),
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RECORD\"\n",
    );
    // A host's file has no script: the runner's user runs it after setup.
    let record = dir.path().join("record");
    let result = run_step(
        "agent.yml",
        "The host's configuration",
        dir.path(),
        &[
            ("PATH", &search),
            ("RUNNER_TEMP", path(dir.path())),
            ("RECORD", path(&record)),
        ],
    );
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        std::fs::read_to_string(record).unwrap(),
        "config\n--host\n--from\n.agentic-job/config.toml\n"
    );
}

#[test]
fn caller_network_credentials_are_spent_before_the_agent() {
    let network = "./.github/agentic-job/network";
    let review = definition("review.yml");
    let register = &review["jobs"]["register"];
    let steps = register["steps"].as_vec().unwrap();
    for (name, value) in review["jobs"].as_hash().unwrap() {
        if name.as_str() != Some("register") {
            assert!(!value["steps"].as_vec().is_some_and(|steps| {
                steps
                    .iter()
                    .any(|step| step["uses"].as_str() == Some(network))
            }));
        }
    }
    assert_eq!(
        steps
            .iter()
            .filter_map(|s| s["uses"].as_str())
            .map(|s| s.split('@').next().unwrap())
            .collect::<Vec<_>>(),
        ["actions/checkout", network, "actions/download-artifact"]
    );
    let checkout = steps
        .iter()
        .find(|s| {
            s["uses"]
                .as_str()
                .is_some_and(|s| s.starts_with("actions/checkout@"))
        })
        .unwrap();
    assert_eq!(
        checkout["with"]["ref"].as_str(),
        Some("${{ needs.policy.outputs.ref }}")
    );
    assert_eq!(
        checkout["with"]["persist-credentials"].as_bool(),
        Some(false)
    );
    let join = named_step(&review, "The caller's network step");
    assert_eq!(join["id"].as_str(), Some("network"));
    assert_eq!(
        join["if"].as_str(),
        Some("${{ hashFiles('.github/agentic-job/network/action.yml') != '' }}")
    );
    assert_eq!(
        register["outputs"]["network-secret"].as_str(),
        Some("${{ steps.network.outputs.secret }}")
    );
    assert_eq!(
        review["jobs"]["agent"]["secrets"]["NETWORK_SECRET"].as_str(),
        Some("${{ needs.register.outputs.network-secret }}")
    );
    assert_eq!(
        review["jobs"]["agent"]["with"]["network"].as_bool(),
        Some(true)
    );
    let text = workflow("review.yml");
    assert_eq!(
        text.lines()
            .filter(|s| s.contains("network-secret")
                || s.contains("NETWORK_SECRET")
                || s.contains("steps.network."))
            .map(str::trim)
            .collect::<Vec<_>>(),
        [
            "network-secret: ${{ steps.network.outputs.secret }}",
            "NETWORK_SECRET: ${{ needs.register.outputs.network-secret }}"
        ]
    );
    assert!(named_step(&review, "Register the run at the inference proxy")["run"].as_str().unwrap().trim_end().ends_with(r#""$JOB_DIR/agentic-job" register --config "$JOB_DIR/config.toml" --output "$GITHUB_OUTPUT""#));
    assert!(
        !Regex::new(r"secrets\.|github\.token|agentic-job-source")
            .unwrap()
            .is_match(job(&text, "register"))
    );
    let doc = definition("agent.yml");
    let join = named_step(&doc, "The caller's network step");
    assert_eq!(join["uses"].as_str(), Some(network));
    assert_eq!(
        join["if"].as_str(),
        Some("${{ inputs.network && hashFiles('.github/agentic-job/network/action.yml') != '' }}")
    );
    assert_eq!(
        join["with"]["secret"].as_str(),
        Some("${{ secrets.NETWORK_SECRET }}")
    );
    assert_eq!(
        doc["on"]["workflow_call"]["inputs"]["network"]["default"].as_bool(),
        Some(false)
    );
    let agent = workflow("agent.yml");
    assert_eq!(
        agent
            .lines()
            .filter(|s| s.contains("secrets.NETWORK_SECRET"))
            .collect::<Vec<_>>(),
        ["          secret: ${{ secrets.NETWORK_SECRET }}"]
    );
    assert!(
        agent
            .find("- name: Admit the runner-user configuration")
            .unwrap()
            < agent.find(&format!("uses: {network}")).unwrap()
    );
    let forbidden = Regex::new(r"(?i)tailscale|join(?:s|ing)? (?:a|the) tailnet").unwrap();
    let foreign = Regex::new(r"cgwalters-forge/actions(?:/([\w/-]+))?").unwrap();
    let files = std::fs::read_dir(root().join(".github/workflows"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .chain(
            [
                "prepare/action.yml",
                "run/action.yml",
                "secure-host/action.yml",
            ]
            .map(|s| root().join(s)),
        );
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!forbidden.is_match(&text), "{file:?}");
        for found in foreign.captures_iter(&text) {
            assert_eq!(
                found.get(1).map(|m| m.as_str()),
                Some("secure-host"),
                "{file:?}"
            );
        }
    }
}

/// Apply's result step only reads what the job wrote and writes step
/// outputs and the summary: it gets no token, keeps the links the handlers
/// keep, and runs whenever they ran, without failing the job.
#[test]
fn the_result_step_passes_no_token() {
    const NAME: &str = "Say where what the run made is";
    let apply = definition("apply.yml");
    let result = named_step(&apply, NAME);
    let handlers = named_step(&apply, "Apply the outputs with gh-aw's handlers");
    assert_eq!(result["id"].as_str(), Some("result"));
    assert_eq!(
        result["if"].as_str(),
        Some("${{ !cancelled() && steps.apply.outcome != 'skipped' }}")
    );
    assert_eq!(result["continue-on-error"].as_bool(), Some(true));
    assert!(result["uses"].is_badvalue() && result["with"].is_badvalue());
    let env: Vec<_> = result["env"]
        .as_hash()
        .unwrap()
        .keys()
        .map(|key| key.as_str().unwrap())
        .collect();
    assert_eq!(
        env,
        [
            "GH_AW_SAFE_OUTPUTS_URLS",
            "GH_AW_ALLOWED_DOMAINS",
            "RUN_URL",
            "CHECKED_ARTIFACT_ID"
        ]
    );
    assert_eq!(
        result["env"]["CHECKED_ARTIFACT_ID"].as_str(),
        Some("${{ fromJSON(inputs.check).outputs.artifact-id }}")
    );
    assert_eq!(
        result["env"]["GH_AW_ALLOWED_DOMAINS"].as_str(),
        Some("${{ fromJSON(inputs.policy).allowed-domains }}")
    );
    for key in ["GH_AW_SAFE_OUTPUTS_URLS", "GH_AW_ALLOWED_DOMAINS"] {
        assert_eq!(result["env"][key], handlers["env"][key], "{key}");
    }
    assert_eq!(
        result["run"].as_str().unwrap().trim_end().lines().last(),
        Some(
            r#""$RUNNER_TEMP/apply-binary/agentic-job" result --dir "$GH_AW_TMP" --output "$GITHUB_OUTPUT" --summary "$GITHUB_STEP_SUMMARY""#
        )
    );
    let text = workflow("apply.yml");
    let step = text
        .split(&format!("- name: {NAME}\n"))
        .nth(1)
        .unwrap()
        .split("\n      - ")
        .next()
        .unwrap();
    for credential in ["secrets.", "token", "TOKEN"] {
        assert!(!step.contains(credential), "{credential}: {step}");
    }
}

#[test]
fn no_result_reports_keep_notification_opt_outs_and_fixed_targets() {
    let doc = definition("apply.yml");
    let status = named_step(&doc, "Edit the status comment");
    let gate = expression(&status["if"]).replace("fromJSON(inputs.policy)", "policy");
    for (notify, notified, missing, item, expected) in [
        ("comment", "true", "false", "42", "true"),
        ("none", "true", "false", "42", "false"),
        ("reaction", "true", "false", "42", "false"),
        ("comment", "false", "false", "42", "false"),
        // Existing blocked/missing-data reporting is independent of opt-in.
        ("none", "false", "true", "42", "true"),
        ("none", "false", "true", "*", "false"),
        ("none", "false", "true", "", "false"),
    ] {
        let context = [
            ("policy.notify", Expr::text(notify)),
            ("policy.notified", Expr::text(notified)),
            ("policy.notify-item", Expr::text(item)),
            ("needs.apply.outputs.missing-data", Expr::text(missing)),
        ];
        assert_eq!(evaluate(&gate, &context).render(), expected);
    }
    assert_eq!(
        status["env"]["REPO"].as_str(),
        Some("${{ fromJSON(inputs.policy).notify-repo }}")
    );
    assert_eq!(
        status["env"]["ITEM"].as_str(),
        Some("${{ fromJSON(inputs.policy).notify-item }}")
    );
    assert_eq!(
        status["env"]["NO_RESULT_REASON"].as_str(),
        Some("${{ steps.ended.outputs.no-result-reason }}")
    );
}

#[test]
fn optional_apply_token_admission_holds_the_pat_in_one_step() {
    let apply = definition("apply.yml");
    assert!(
        !apply["jobs"]["apply"]["if"]
            .as_str()
            .unwrap()
            .contains("always()")
    );
    for file in ["policy.yml", "agentic-job.yml"] {
        let doc = definition(file);
        assert_eq!(
            doc["on"]["workflow_call"]["inputs"]["require-safe-outputs-pat"]["default"].as_bool(),
            Some(false)
        );
    }
    let doc = definition("policy.yml");
    let steps = doc["jobs"]["apply-token"]["steps"].as_vec().unwrap();
    let text = workflow("policy.yml");
    let check = job(&text, "apply-token");
    assert_eq!(check.matches("secrets.SAFE_OUTPUTS_PAT").count(), 1);
    assert!(
        !check
            .split("- name: Check SAFE_OUTPUTS_PAT\n")
            .next()
            .unwrap()
            .contains("secrets.")
    );
    assert_eq!(
        steps
            .iter()
            .filter(|s| s["env"]["SAFE_OUTPUTS_PAT"].as_str()
                == Some("${{ secrets.SAFE_OUTPUTS_PAT }}"))
            .count(),
        1
    );
}

#[test]
fn ci_agents_take_the_build_image_by_id_only() {
    let ci = definition("ci.yml");
    for name in [
        "e2e-full",
        "e2e-limit",
        "e2e-write-policy",
        "e2e-event",
        "e2e-analysis",
        "e2e-analysis-refused",
        "e2e-review",
    ] {
        assert_eq!(ci["jobs"][name]["with"]["agent"].as_str(), Some("fake"));
        assert!(ci["jobs"][name]["with"]["inference-url"].is_badvalue());
    }
    for (name, job) in ci["jobs"].as_hash().unwrap() {
        if job["uses"].as_str() != Some("./.github/workflows/agentic-job.yml")
            || !job["with"]["proposals-artifact"].is_badvalue()
        {
            continue;
        }
        let needs = job["needs"].as_vec().unwrap();
        assert!(
            needs.iter().any(|n| n.as_str() == Some("static")),
            "{name:?}"
        );
        assert_eq!(
            job["with"]["secure-host-image-artifact-id"].as_str(),
            Some("${{ needs.static.outputs.secure-host-image-artifact-id }}")
        );
    }
    let doc = definition("build.yml");
    assert_eq!(
        doc["on"]["workflow_call"]["outputs"]["secure-host-image-artifact-id"]["value"].as_str(),
        Some("${{ jobs.build.outputs.secure-host-image-artifact-id }}")
    );
    assert_eq!(
        doc["jobs"]["build"]["outputs"]["secure-host-image-artifact-id"].as_str(),
        Some("${{ steps.image.outputs.artifact-id }}")
    );
    let image = doc["jobs"]["build"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|s| s["id"].as_str() == Some("image"))
        .unwrap();
    assert_eq!(image["with"]["name"].as_str(), Some("secure-host-image"));
    assert!(
        Regex::new(r"^actions/upload-artifact@[0-9a-f]{40}$")
            .unwrap()
            .is_match(image["uses"].as_str().unwrap())
    );
    let doc = definition("agent.yml");
    let download = steps(&doc)
        .into_iter()
        .find(|s| {
            s["with"]["artifact-ids"].as_str()
                == Some("${{ inputs.secure-host-image-artifact-id }}")
        })
        .unwrap();
    assert_eq!(
        download["if"].as_str(),
        Some("${{ inputs.secure-host-image-artifact-id != '' }}")
    );
    assert!(download["with"]["name"].is_badvalue());
}

#[test]
fn composed_example_keeps_the_callers_privilege_boundary() {
    // Shape only: the fresh-host e2e-compose job executes these sudo probes.
    let doc = definition("example-compose.yml");
    let before = named_step(&doc, "A caller's privileged step (example)")["run"]
        .as_str()
        .unwrap();
    let file = Regex::new(r"sudo install -m 0600 -o root -g root /dev/null (/var/lib/[\w-]+)")
        .unwrap()
        .captures(before)
        .unwrap()[1]
        .to_owned();
    let after = named_step(&doc, "A caller's later step (example)")["run"]
        .as_str()
        .unwrap();
    assert!(after.contains(&format!("stat -c '%U %a' {file})\" = 'root 600'")));
    assert!(
        Regex::new(r"if sudo -n true .*exit 1; fi")
            .unwrap()
            .is_match(after)
    );
}

#[test]
fn agent_configuration_provenance_and_step_gates_are_preserved() {
    let policy = definition("policy.yml");
    assert_eq!(
        named_step(&policy, "Write the configuration")["if"].as_str(),
        Some("${{ inputs.proposals-artifact == '' && steps.event.outputs.admitted != 'false' }}")
    );
    assert!(
        workflow("policy.yml")
            .split("agentic-job-policy\n")
            .nth(1)
            .unwrap()
            .split("\n  activate:")
            .next()
            .unwrap()
            .contains(".agentic-job/config.toml")
    );
    assert!(workflow("policy.yml").contains("@agentclientprotocol/claude-agent-acp@0.88.0"));
    for (file, expected) in [
        (
            "agent.yml",
            "[ -z \"$IMAGE_ARTIFACT\" ] || set -- --prepared\nagentic-job config --host \"$@\" --from .agentic-job/config.toml > \"$RUNNER_TEMP/agentic-job-host.toml\"\n",
        ),
        (
            "example-compose.yml",
            "agentic-job config --host --no-script --from .agentic-job/config.toml > \"$RUNNER_TEMP/agentic-job-host.toml\"",
        ),
    ] {
        let doc = definition(file);
        let host = named_step(&doc, "The host's configuration");
        assert_eq!(host["run"].as_str(), Some(expected), "{file}");
        let agent = &doc["jobs"]["agent"];
        let steps = agent["steps"].as_vec().unwrap();
        assert_eq!(
            steps
                .iter()
                .filter(|s| s["run"].as_str().is_some_and(|s| s.contains(" config ")))
                .count(),
            1,
            "{file}"
        );
        let secured = steps
            .iter()
            .find(|s| s["uses"].as_str() == Some("./.agentic-job-source/secure-host"))
            .unwrap();
        assert_eq!(
            secured["with"]["config"].as_str(),
            Some("${{ runner.temp }}/agentic-job-host.toml")
        );
    }
    // With an image of this source, which holds no agent code,
    // agentic-job's part of setup comes first, as root, on the file the
    // image then reads.
    let doc = definition("agent.yml");
    let steps = steps(&doc);
    let at = |name: &str| {
        steps
            .iter()
            .position(|s| s["name"].as_str() == Some(name))
            .unwrap()
    };
    let prepare = steps[at("agentic-job's part of the host's setup")];
    assert_eq!(
        prepare["if"].as_str(),
        Some("${{ inputs.secure-host-image-artifact-id != '' }}")
    );
    assert_eq!(
        prepare["run"].as_str(),
        Some(
            "sudo /usr/local/bin/agentic-job sandbox prepare --config \"$RUNNER_TEMP/agentic-job-host.toml\""
        )
    );
    let secured = steps
        .iter()
        .position(|s| s["uses"].as_str() == Some("./.agentic-job-source/secure-host"))
        .unwrap();
    assert!(at("The host's configuration") < at("agentic-job's part of the host's setup"));
    assert!(at("agentic-job's part of the host's setup") < secured);
    for (file, name) in [
        ("policy.yml", "Check that the repositories are public"),
        (
            "run/action.yml",
            "Check again that the repositories are public",
        ),
    ] {
        let doc = definition(file);
        assert!(
            named_step(&doc, name)["run"]
                .as_str()
                .unwrap()
                .contains(".private == false and .visibility == \"public\"")
        );
    }
}

#[test]
fn agent_secret_contract_accepts_only_the_intended_credentials() {
    let agent = definition("agent.yml");
    let wrapper = definition("agentic-job.yml");
    let names = |value: &yaml_rust2::Yaml| {
        value
            .as_hash()
            .unwrap()
            .keys()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(&agent["on"]["workflow_call"]["secrets"]),
        ["INFERENCE_RUN_TOKEN", "NETWORK_SECRET"]
    );
    assert_eq!(
        names(&wrapper["jobs"]["agent"]["secrets"]),
        ["INFERENCE_RUN_TOKEN"]
    );
    for (file, keys) in [
        ("agentic-job.yml", &["MCP_TOKEN", "INFERENCE_API_KEY"][..]),
        ("review.yml", &["INFERENCE_API_KEY"][..]),
    ] {
        let doc = definition(file);
        for key in keys {
            assert_eq!(
                doc["on"]["workflow_call"]["secrets"][*key]["required"].as_bool(),
                Some(false),
                "{file} {key}"
            );
        }
    }
}

fn passing() -> String {
    format!(
        "on: push
jobs:
  build:
    permissions: {{contents: read}}
    runs-on: ubuntu-26.04
    steps:
      - uses: actions/checkout@{PIN}
        with: {{persist-credentials: false}}
      - uses: cgwalters-forge/agentic-job/secure-host@{PIN}
      - run: make check
"
    )
}

const FAILING: &str = "on: push
jobs:
  build:
    runs-on: ubuntu-26.04
    steps:
      - name: Fetch
        uses: actions/checkout@v7
";

fn check(root: &Path, extra: &[&str]) -> Output {
    Command::new(BIN)
        .args(["workflows", "check", "--root"])
        .arg(root)
        .args(extra)
        .output()
        .expect("test setup")
}

/// A repository holding `files`, by path, and the result of checking it.
fn checked(files: &[(&str, &str)], extra: &[&str]) -> (i32, String, String) {
    let dir = tempfile::tempdir().expect("test setup");
    for (path, text) in files {
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().expect("test setup")).expect("test setup");
        std::fs::write(path, text).expect("test setup");
    }
    let extra: Vec<String> = extra
        .iter()
        .map(|a| a.replace("ROOT", dir.path().to_str().expect("test setup")))
        .collect();
    let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
    let output = check(dir.path(), &extra);
    (
        output.status.code().expect("test setup"),
        String::from_utf8(output.stdout).expect("test setup"),
        String::from_utf8(output.stderr).expect("test setup"),
    )
}

/// The deterministic example, as another repository copies it with the
/// local paths pinned, passes the check without an exemption.
#[test]
fn deterministic_example_passes_when_pinned() {
    const FILE: &str = ".github/workflows/example-deterministic.yml";
    let text = std::fs::read_to_string(root().join(FILE)).unwrap();
    let mut pinned = text.clone();
    for (local, remote) in [
        ("./secure-host", "cgwalters-forge/actions/secure-host"),
        (
            "./.github/workflows/agentic-job.yml",
            "cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml",
        ),
    ] {
        let from = format!("uses: {local} ");
        assert_eq!(pinned.matches(&from).count(), 1, "{local}");
        pinned = pinned.replace(&from, &format!("uses: {remote}@{PIN} "));
    }
    let (status, stdout, stderr) = checked(&[(FILE, &pinned)], &[]);
    assert_eq!(status, 0, "{stdout}{stderr}");
    // As it is here, unpinned, only the exemption admits it.
    let (status, stdout, _) = checked(&[(FILE, &text)], &[]);
    assert_eq!(status, 1, "{stdout}");
}

/// The deterministic example's producer step, with a stand-in for cargo
/// fmt, hands back what check accepts under the example's call: a pull
/// request request with its patch where the formatter changed something,
/// else a noop.
#[test]
fn deterministic_example_hands_back_what_check_accepts() {
    const REPO: &str = "cgwalters-forge/agentic-job";
    const BRANCH: &str = "agent-run-7";
    let git = |dir: &Path, args: &[&str]| {
        let status = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@localhost"])
            .args(args)
            .current_dir(dir)
            .env("HOME", dir)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    };
    for (formatter, want) in [
        ("printf 'fn  f() {}\\n' >> lib.rs", "create_pull_request"),
        ("", "noop"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (work, bin) = (dir.path().join("work"), dir.path().join("bin"));
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        executable(&bin.join("cargo"), &format!("#!/bin/sh\n{formatter}\n"));
        std::fs::write(work.join("lib.rs"), "fn main() {}\n").unwrap();
        git(&work, &["init", "-q", "-b", "main"]);
        git(&work, &["add", "lib.rs"]);
        git(&work, &["commit", "-qm", "base"]);
        let search = format!("{}:/usr/bin:/bin", path(&bin));
        let output = run_step(
            "example-deterministic.yml",
            "Format, and hand back the change",
            &work,
            &[("PATH", &search), ("REPO", REPO), ("BRANCH", BRANCH)],
        );
        assert!(output.status.success(), "{output:?}");
        let allow = root().join(".github/agentic-job/allow.toml");
        let policy = Command::new(BIN)
            .args(["policy", "--allow", path(&allow), "--repo", REPO])
            .args(["--clone-url", &format!("https://github.com/{REPO}")])
            .args(["--base", "main", "--kind", "branch"])
            .args([
                "--outputs",
                "create_pull_request,noop",
                "--max-outputs",
                "1",
            ])
            .output()
            .unwrap();
        assert!(policy.status.success(), "{policy:?}");
        std::fs::write(dir.path().join("policy.json"), &policy.stdout).unwrap();
        let proposals = work.join("proposals");
        for (command, extra) in [
            ("collect", &[][..]),
            ("check", &["--report", "report.json", "--run-id", "7"][..]),
        ] {
            let output = Command::new(BIN)
                .args([
                    command,
                    "--policy",
                    "policy.json",
                    "--outputs",
                    path(&proposals),
                ])
                .args(["--collected", "collected.json"])
                .args(extra)
                .current_dir(dir.path())
                .output()
                .unwrap();
            assert!(output.status.success(), "{want}: {command}: {output:?}");
        }
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("report.json")).unwrap())
                .unwrap();
        assert_eq!(report["ok"], true, "{want}: {report}");
        assert_eq!(report["items"][0]["type"], want, "{report}");
        assert_eq!(report["patch"].is_null(), want == "noop", "{report}");
    }
}

const LIST: &str = ".github/agentic-job/workflows.toml";

/// Files by path, extra arguments, the exit status, and what stdout or
/// stderr must say.
type Case<'a> = (&'a [(&'a str, &'a str)], &'a [&'a str], i32, &'a [&'a str]);

#[test]
fn trees() {
    let good = passing();
    let cases: &[Case] = &[
        (&[], &[], 0, &["0 problem(s)"]),
        (&[(".github/workflows/a.yml", &good)], &[], 0, &[]),
        (
            &[
                (".github/workflows/a.yml", &good),
                (".github/workflows/b.yaml", FAILING),
                (".github/workflows/notes.txt", "not a workflow"),
                (".github/workflows/sub/c.yml", FAILING),
            ],
            &[],
            1,
            &[
                ".github/workflows/b.yaml: job build has no `permissions:` map",
                ".github/workflows/b.yaml: job build neither runs secure-host",
                "2 problem(s); 2 workflow file(s) checked, 0 exempt",
            ],
        ),
        (
            &[
                (".github/workflows/b.yml", FAILING),
                (LIST, "[exempt]\n\"b.yml\" = \"tests the checker\"\n"),
            ],
            &[],
            0,
            &[
                "b.yml: exempt: tests the checker",
                "0 workflow file(s) checked, 1 exempt",
            ],
        ),
        (
            &[
                (".github/workflows/b.yml", FAILING),
                (LIST, "[exempt]\n\"b.yml\" = \"from the proposal\"\n"),
                ("base.toml", "[exempt]\n"),
            ],
            &["--exemptions", "ROOT/base.toml"],
            1,
            &["job build neither runs secure-host"],
        ),
        (
            &[(LIST, "[exempt]\n\"gone.yml\" = \"was here\"\n")],
            &[],
            1,
            &["exempts gone.yml, which is not in .github/workflows"],
        ),
        (
            &[
                (".github/workflows/b.yml", FAILING),
                (LIST, "[exempt]\n\"b.yml\" = \"  \"\n"),
            ],
            &[],
            ERROR,
            &["b.yml has no reason"],
        ),
        (
            &[(LIST, "[exempt]\n\"../b.yml\" = \"why\"\n")],
            &[],
            ERROR,
            &["not a workflow file's name"],
        ),
        (
            &[(LIST, "exempt = []\nother = 1\n")],
            &[],
            ERROR,
            &["parsing"],
        ),
        (
            &[],
            &["--exemptions", "ROOT/missing.toml"],
            ERROR,
            &["missing.toml"],
        ),
        (
            &[(".github/workflows/a.yml", "jobs: [\n")],
            &[],
            1,
            &[".github/workflows/a.yml: cannot be checked"],
        ),
    ];
    for (files, extra, code, wants) in cases {
        let (got, stdout, stderr) = checked(files, extra);
        let all = format!("{stdout}{stderr}");
        assert_eq!(got, *code, "{files:?} {extra:?}: {all}");
        for want in *wants {
            assert!(all.contains(want), "{files:?}: no {want:?} in {all}");
        }
    }
}

#[test]
fn a_linked_workflow_is_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let workflows = dir.path().join(".github/workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    std::fs::write(dir.path().join("elsewhere.yml"), passing()).unwrap();
    std::os::unix::fs::symlink("../../elsewhere.yml", workflows.join("a.yml")).unwrap();
    let output = check(dir.path(), &[]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("a.yml: cannot be checked: is not a regular file"),
        "{stdout}"
    );
}

/// The jobs under agentic-job.yml that can mint identity tokens when the
/// caller grants the call `id-token: write`, as docs/workflow.md's
/// permissions paragraph names them. A job that names no `permissions`
/// keeps the call's grant, so a new such job, or a call that stops
/// narrowing, changes this list and must change the documentation too.
#[test]
fn id_token_holders_are_the_documented_ones() {
    fn walk(dir: &Path, file: &str, holds: bool, found: &mut Vec<String>) {
        let text = std::fs::read_to_string(dir.join(file)).unwrap();
        let doc = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
        for (name, job) in doc["jobs"].as_hash().unwrap() {
            let name = name.as_str().unwrap();
            let permissions = &job["permissions"];
            // Named permissions only narrow what the call was granted.
            let holds = holds
                && (permissions.is_badvalue()
                    || permissions.as_str() == Some("write-all")
                    || permissions["id-token"].as_str() == Some("write"));
            match job["uses"].as_str() {
                Some(called) => {
                    let called = called.strip_prefix("./.github/workflows/").unwrap();
                    walk(dir, called, holds, found);
                }
                None if holds => found.push(format!("{file}:{name}")),
                None => {}
            }
        }
    }
    let dir = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/workflows"
    ));
    let mut found = Vec::new();
    walk(dir, "agentic-job.yml", true, &mut found);
    found.sort();
    assert_eq!(
        found,
        [
            "agentic-job.yml:register",
            "apply.yml:apply",
            "apply.yml:conclude",
            "check.yml:detect",
            "policy.yml:activate",
            "policy.yml:notify",
        ]
    );
}

/// This repository's own workflows pass or are listed, read at test time.
#[test]
fn this_repository_passes() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let output = check(Path::new(root), &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// A refusal by the collector, the policy check or the review verdict
/// reaches check's refusal step and the text of the conclusion comment.
#[test]
fn refusals_reach_the_conclusion_comment() {
    use serde_json::json;
    for phase in ["collector", "policy", "review"] {
        let dir = tempfile::tempdir().unwrap();
        let tmp = path(dir.path());
        let errors = if phase == "collector" {
            json!(["collector refused"])
        } else {
            json!([])
        };
        std::fs::write(
            dir.path().join("agent_output.json"),
            json!({"errors": errors, "items": []}).to_string(),
        )
        .unwrap();
        if phase == "policy" {
            let report = json!({"ok": false, "errors": ["protected files: CONTRIBUTING.md"]});
            std::fs::write(dir.path().join("report.json"), report.to_string()).unwrap();
        }
        if phase == "review" {
            // No comment is no verdict: the binary writes the report the
            // refusal step reads, and fails the step before its output.
            let output = dir.path().join("verdict-output");
            let verdict = run_step(
                "check.yml",
                "Validate the review verdict",
                dir.path(),
                &[
                    ("JOB_DIR", bin_dir()),
                    ("GH_AW_TMP", tmp),
                    ("TARGET", "12"),
                    ("GITHUB_OUTPUT", path(&output)),
                ],
            );
            assert_eq!(verdict.status.code(), Some(1), "{verdict:?}");
            assert!(!output.exists());
        }
        let reasons = dir.path().join("reasons");
        std::fs::write(&reasons, "").unwrap();
        let shown = run_step(
            "check.yml",
            "Show why check refused the outputs",
            dir.path(),
            &[
                ("JOB_DIR", bin_dir()),
                ("GH_AW_TMP", tmp),
                ("GITHUB_OUTPUT", path(&reasons)),
            ],
        );
        assert!(shown.status.success(), "{phase}: {shown:?}");
        assert!(
            String::from_utf8_lossy(&shown.stdout).starts_with("::error::Refused by check: "),
            "{phase}: {shown:?}"
        );
        let reasons = std::fs::read_to_string(&reasons).unwrap();
        let reason = reasons
            .strip_prefix("reason=")
            .and_then(|reason| reason.strip_suffix('\n'))
            .filter(|reason| !reason.is_empty() && !reason.contains('\n'))
            .unwrap_or_else(|| panic!("{phase}: {reasons:?}"));
        let output = dir.path().join("step-output");
        let ended = run_step(
            "apply.yml",
            "How the run ended",
            dir.path(),
            &[
                ("RESULTS", "success/failure/skipped"),
                ("EXIT", "0"),
                ("PR", ""),
                ("REFUSAL", reason),
                ("WORKFLOW", "test"),
                ("RUN_URL", "https://example.invalid/run"),
                ("GITHUB_OUTPUT", path(&output)),
            ],
        );
        assert!(ended.status.success(), "{phase}: {ended:?}");
        assert!(
            std::fs::read_to_string(&output)
                .unwrap()
                .contains(&format!("refused by check: {reason}")),
            "{phase}"
        );
    }
}

/// The collector is agentic-job's, and gh-aw's is not set up: a line it
/// refused fails the step after it, with the reason in agent_output.json,
/// and an error of its own fails its own.
#[test]
fn collector_refusals_fail_the_step_after_it() {
    use serde_json::json;
    let pattern = Regex::new("gh-aw/actions/setup@|collect_ndjson_output").unwrap();
    assert!(!pattern.is_match(&workflow("check.yml")));
    let dir = tempfile::tempdir().unwrap();
    executable(
        &dir.path().join("agentic-job"),
        "#!/bin/bash\nif [ \"$STATUS\" != 2 ]; then echo \"$RESULT\" > \"$GH_AW_TMP/agent_output.json\"; fi\nexit \"$STATUS\"\n",
    );
    let accepted = json!({"items": [{"type": "noop", "message": "m"}], "errors": []}).to_string();
    let refused =
        json!({"items": [], "errors": ["Line 1: add_comment requires a 'body' field (string)"]})
            .to_string();
    // (the collector's status and result, whether its step succeeds, and
    // whether the next one does)
    for (status, result, ingested, checked) in [
        ("0", accepted.as_str(), true, Some(true)),
        ("1", refused.as_str(), true, Some(false)),
        ("2", "", false, None),
    ] {
        let _ = std::fs::remove_file(dir.path().join("agent_output.json"));
        let env = [
            ("JOB_DIR", path(dir.path())),
            ("GH_AW_TMP", path(dir.path())),
            ("STATUS", status),
            ("RESULT", result),
        ];
        let ingest = run_step(
            "check.yml",
            "Ingest the outputs with agentic-job collect",
            dir.path(),
            &env,
        );
        let code = Some(i32::from(!ingested));
        assert_eq!(ingest.status.code(), code, "{status}: {ingest:?}");
        if let Some(checked) = checked {
            let check = run_step(
                "check.yml",
                "The collector refused nothing",
                dir.path(),
                &env,
            );
            let code = Some(i32::from(!checked));
            assert_eq!(check.status.code(), code, "{status}: {check:?}");
        }
    }
}

/// With `expect-check-refusal`, the policy step succeeds only on a refusal
/// whose report says why, shown in a summary that could be written; without
/// it, only on an acceptance.
#[test]
fn an_expected_refusal_needs_a_report_and_a_summary() {
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    executable(
        &dir.path().join("agentic-job"),
        "#!/bin/bash\nif [ \"$REPORT\" != missing ]; then cp \"$REPORT\" \"$GH_AW_TMP/report.json\"; fi\nexit \"$STATUS\"\n",
    );
    let fixture = dir.path().join("fixture.json");
    let refusal = json!({"ok": false, "errors": ["wrong item"]});
    // (expect-check-refusal, check's status, its report, the summary file,
    // the step's status)
    for (expect, status, report, summary, code) in [
        ("true", "1", Some(refusal.clone()), "summary", 0),
        (
            "true",
            "0",
            Some(json!({"ok": true, "errors": []})),
            "summary",
            1,
        ),
        ("true", "1", None, "summary", 2),
        ("true", "2", Some(refusal.clone()), "summary", 1),
        (
            "true",
            "1",
            Some(json!({"ok": false, "errors": []})),
            "summary",
            1,
        ),
        ("true", "1", Some(refusal.clone()), "missing/summary", 1),
        ("false", "1", Some(refusal.clone()), "summary", 1),
        (
            "false",
            "0",
            Some(json!({"ok": true, "errors": [], "patch": null})),
            "summary",
            0,
        ),
    ] {
        let _ = std::fs::remove_file(dir.path().join("report.json"));
        if let Some(report) = &report {
            std::fs::write(&fixture, report.to_string()).unwrap();
        }
        let output = run_step(
            "check.yml",
            "Check the outputs against the policy",
            dir.path(),
            &[
                ("JOB_DIR", path(dir.path())),
                ("GH_AW_TMP", path(dir.path())),
                ("COMMENT_TARGET", "64"),
                ("COMMENT_REPO", "owner/repo"),
                ("EXPECT_REFUSAL", expect),
                ("STATUS", status),
                (
                    "REPORT",
                    report.as_ref().map_or("missing", |_| path(&fixture)),
                ),
                ("GITHUB_OUTPUT", path(&dir.path().join("output"))),
                ("GITHUB_STEP_SUMMARY", path(&dir.path().join(summary))),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(code),
            "{expect} {status} {report:?} {summary}: {output:?}"
        );
    }
}

/// CI's e2e-analysis-refused holds the reason check shows to the refusal
/// it expects, and to nothing else.
#[test]
fn an_expected_refusal_shows_the_reason_ci_expects() {
    let dir = tempfile::tempdir().unwrap();
    let report = serde_json::json!({"ok": false,
        "errors": ["an add_comment with item_number outside the caller's fixed item"]});
    std::fs::write(dir.path().join("report.json"), report.to_string()).unwrap();
    let output = dir.path().join("output");
    std::fs::write(&output, "").unwrap();
    let shown = Command::new(BIN)
        .args(["diagnostics", "refusals", path(dir.path()), "--output"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(shown.status.success(), "{shown:?}");
    let output = std::fs::read_to_string(&output).unwrap();
    let reason = output
        .strip_prefix("reason=")
        .and_then(|reason| reason.strip_suffix('\n'))
        .unwrap();
    let ci = workflow("ci.yml");
    let assertion = ci
        .lines()
        .find(|line| line.contains("grep -F") && line.contains("$REFUSAL"))
        .unwrap()
        .trim();
    for (value, matches) in [(reason, true), ("unrelated refusal", false), ("", false)] {
        let status = Command::new("bash")
            .args(["-eo", "pipefail", "-c", assertion])
            .env("REFUSAL", value)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.success(), matches, "{value:?}");
    }
}

/// Workflow text that keeps check, token and refusal separation, as (file,
/// job or "" for the whole file, patterns that match, patterns that do not).
const SHAPES: &[(&str, &str, &[&str], &[&str])] = &[
    (
        "prepare/action.yml",
        "",
        &[
            r#"sudo install -m 0755 "\$JOB_DIR/agentic-job" /usr/local/bin/agentic-job"#,
            // Beside the binary secure-host is given, which loads it.
            r#"sudo install -m 0644 "\$JOB_DIR/world_write\.bpf\.o" /usr/local/bin/world_write\.bpf\.o"#,
        ],
        &[r"secrets\.|SAFE_OUTPUTS_PAT"],
    ),
    (
        "run/action.yml",
        "",
        &[
            r"PARTIAL: \$\{\{ steps.settings.outputs.apply_partial == 'true' && steps.safe-outputs.outputs.artifact-id != '' \}\}",
            r"value: \$\{\{ steps.session.outputs.endpoint \}\}",
        ],
        &[
            r"secrets\.|SAFE_OUTPUTS_PAT",
            r"(?m)^\s*(?:[^#\n]*[|;&(]\s*)?gh\s",
        ],
    ),
    (
        "secure-host/action.yml",
        "",
        &[],
        &[r"(?i)inference|session"],
    ),
    (
        "policy.yml",
        "policy",
        &[
            r"source-repository: \$\{\{ job.workflow_repository \}\}",
            r"source-sha: \$\{\{ job.workflow_sha \}\}",
            r#"--arg source_sha "\$SOURCE_SHA" '\$ARGS.named'"#,
            r#"SOURCE_SHA: \$\{\{ job.workflow_sha \}\}\n {8}run: \|\n {10}if \[ -n "\$PROFILE" \]"#,
            r"PRIVATE: \$\{\{ steps.visibility.outputs.private \}\}",
            r#"(?s)set -- "\$@" --private\n.*--output-repo "\$\{OUTPUT_REPO:-\$GITHUB_REPOSITORY\}""#,
        ],
        &["CONFIG_BINARY"],
    ),
    (
        "apply.yml",
        "apply",
        &[r"if: >-\n\s+\$\{\{ !cancelled\(\) && fromJSON\(inputs.check\).result == 'success' &&"],
        &[],
    ),
    (
        "agent.yml",
        "agent",
        &[
            r"runner-home: \$\{\{ format\('\{0\}/agent-home', runner.temp\) \}\}",
            r"- name: The setup script\n        env:",
            r"session-endpoint: \$\{\{ steps.run.outputs.session-endpoint \}\}",
            r"config: \$\{\{ runner.temp \}\}/agentic-job-host.toml",
            r"artifact-ids: \$\{\{ inputs.secure-host-image-artifact-id \}\}",
            r"image-archive: \$\{\{ inputs.secure-host-image-artifact-id != '' && format\('\{0\}/secure-host-image/secure-host.tar', runner.temp\) \|\| '' \}\}",
        ],
        &[r"agent-user: sandbox|inputs.agent-user != 'sandbox'"],
    ),
    (
        "agentic-job.yml",
        "",
        &[r"value: \$\{\{ jobs.agent.outputs.session-endpoint \}\}"],
        &[r"\n {6}network:"],
    ),
    (
        "review.yml",
        "",
        &[
            r"inference-register: \$\{\{ vars.INFERENCE_REGISTER \|\| 'github-oidc' \}\}",
            r"inference-provider: \$\{\{ vars.INFERENCE_PROVIDER \}\}",
        ],
        &[r"secrets\.INFERENCE_API_KEY|check-key|inference-api-key"],
    ),
    (
        "policy.yml",
        "apply-token",
        &[
            r"needs: policy\n    if: \$\{\{ inputs.role-bindings == '' && inputs.require-safe-outputs-pat && needs.policy.outputs.admitted == 'true' \}\}",
            r"environment: \$\{\{ inputs.apply-environment \}\}\n    permissions:\n      contents: read",
            r#"agentic-job check-apply-token --output-repo "\$OUTPUT_REPO""#,
        ],
        &[r"continue-on-error|always\(\)|cancelled\(\)"],
    ),
    (
        "policy.yml",
        "notify",
        &[
            r"needs: \[policy, activate, apply-token\]",
            r"needs.apply-token.result != 'failure'",
        ],
        &[],
    ),
    (
        "agentic-job.yml",
        "register",
        &[r"needs: policy\n"],
        &[r"always\(\)|cancelled\(\)|failure\(\)"],
    ),
    (
        "agentic-job.yml",
        "agent",
        &[r"needs: \[policy, register\]\n"],
        &[r"always\(\)|cancelled\(\)|failure\(\)"],
    ),
    (
        "example-compose.yml",
        "agent",
        &[r"needs: policy\n"],
        &[r"always\(\)|cancelled\(\)|failure\(\)"],
    ),
    // A refusal is reported only by the opted-in status helper, with the
    // optional PAT.
    (
        "apply.yml",
        "conclude",
        &[
            r"fromJSON\(inputs.policy\).notify != 'none' && fromJSON\(inputs.policy\).notified == 'true'",
            r"REPO: \$\{\{ fromJSON\(inputs.policy\).notify-repo \}\}",
            r#"conclude-binary/agentic-job" status\n"#,
            r"STATUS_TOKEN: \$\{\{ inputs.role-bindings == '' && secrets.SAFE_OUTPUTS_PAT \|\| inputs.role-bindings != '' && secrets.STATUS_TOKEN \|\| '' \}\}",
        ],
        &["Post the refusal to the comment target"],
    ),
    // Apply starts on neither an expected refusal nor a failed agent
    // unless it handed over proposals, and checks out only where its
    // outputs go.
    (
        "apply.yml",
        "apply",
        &[
            r"&& fromJSON\(inputs.policy\).expect-check-refusal != 'true' \}\}",
            r"fromJSON\(inputs.check\).result == 'success' && \(fromJSON\(inputs.policy\).proposals-artifact != ''",
            r"fromJSON\(inputs.policy\).proposals-artifact == '' && format\('\{0\}', fromJSON\(inputs.agent\).outputs.exit\) != '0'",
            r"(?s)- name: Write applied.json.*EXIT: \$\{\{ fromJSON\(inputs.policy\).proposals-artifact != '' && '0' \|\| fromJSON\(inputs.agent\).outputs.exit \}\}",
            r"if: \$\{\{ fromJSON\(inputs.check\).outputs.has-patch == 'true' && fromJSON\(inputs.policy\).apply-staged != 'true' \}\}\s+with:\s+repository: \$\{\{ env.OUTPUT_REPO \}\}",
        ],
        &[r"pull_request.head|refs/pull"],
    ),
    // Check shows a refusal, uploads inline findings folded into the
    // verdict comment, takes the proposals by upload ID or legacy name,
    // and runs its own commit's source without secrets.
    (
        "check.yml",
        "",
        &[
            r"failure\(\) \|\| steps.checked.outputs.refused == 'true'",
            r"\n {12}\$\{\{ env.GH_AW_TMP \}\}/folded.json\n",
            r#"verdict=\$\("\$JOB_DIR/agentic-job" review verdict --collected "\$GH_AW_TMP/agent_output.json" --target "\$TARGET" --report "\$GH_AW_TMP/report.json"\)"#,
            r"if: \$\{\{ fromJSON\(inputs.policy\).review == 'true' \}\}",
            r"name: \$\{\{ fromJSON\(inputs.policy\).proposals-artifact \}\}",
            r"artifact-ids: \$\{\{ inputs.safe-outputs-artifact-id \}\}",
            r#"agentic-job" check --policy"#,
            r"permissions:\n  contents: read",
            r"repository: \$\{\{ job.workflow_repository \}\}",
            r"ref: \$\{\{ job.workflow_sha \}\}",
        ],
        &[r"secrets\."],
    ),
    // An expected refusal uploads nothing applicable; the job reads the
    // proposals' upload with `actions: read`.
    (
        "check.yml",
        "check",
        &[
            r"- name: Put the patch beside the ingested outputs\n        if: \$\{\{ success\(\) && fromJSON\(inputs.policy\).expect-check-refusal != 'true' \}\}",
            r"- id: upload\n        if: \$\{\{ success\(\) && fromJSON\(inputs.policy\).expect-check-refusal != 'true' \}\}",
            r"permissions:\n      contents: read\n      actions: read\n",
        ],
        &[],
    ),
    // CI expects a refusal, and that nothing was applied; its e2e-review
    // runs when the base has the review files, and is required then.
    (
        "ci.yml",
        "",
        &[
            "expect-check-refusal: true",
            r#"test "\$REFUSED" = success"#,
            r#"test -z "\$REFUSED_APPLIED""#,
            r"e2e-review:\s+needs: \[changes, static\]\n\s+if: \$\{\{ needs\.changes\.outputs\.e2e == 'true' && needs\.changes\.outputs\.review == 'true' \}\}",
            r#"git cat-file -t "\$BASE:\$file""#,
            "Exactly one scripted verdict was posted",
            r"HEAD_SHA: \$\{\{ github.event.pull_request.head.sha \}\}",
            r#"contains\("Reviewed SHA: " \+ \$sha \+ "\\n"\)"#,
            r#"\(\.key == "e2e-review" and \$review != "true"\)"#,
        ],
        &[],
    ),
    // The review caller: the base's policy and actions, the head as data.
    (
        "review.yml",
        "",
        &[
            r"pull_request_target: *(?:#[^\n]*)?\n\s+types: \[opened, synchronize, reopened, ready_for_review\]",
            "kind: analysis",
            "notify: none",
            "review-task: workflow/review.md",
        ],
        // `pull_request.head` is held out below, but for the one test of
        // a fork.
        &[r"contents: write|secrets: inherit|refs/pull"],
    ),
    // The review agent analyses: no project toolchain or build cache.
    (
        "review.yml",
        "agent",
        &[
            r"(?s)if: \$\{\{ !cancelled\(\) && needs.register.result == 'success' .*policy: \$\{\{ toJSON\(needs.policy.outputs\) \}\}",
        ],
        &[
            r"rust-toolchain|rust-cache|setup-(?:node|python|go|java)|cargo (?:build|test|fmt|clippy)|npm (?:test|ci)",
        ],
    ),
    (
        "review.yml",
        "register",
        &[r"ref: \$\{\{ needs.policy.outputs.ref \}\}"],
        &[],
    ),
    // The status takes the verdict check set and the head policy admitted,
    // nothing the agent wrote, and runs only the pinned source's binary.
    (
        "review.yml",
        "status",
        &[
            r"VERDICT: \$\{\{ needs.check.outputs.verdict \}\}",
            r#""\$RUNNER_TEMP/bin/agentic-job" review status"#,
            r"REVIEW_URL: \$\{\{ needs.submit.outputs.review-url \}\}",
            r"if: \$\{\{ !cancelled\(\) && needs.policy.outputs.review-head != '' && needs.policy.outputs.binary-artifact-id != '' && needs.agent.result != 'cancelled' && needs.record.result == 'skipped' \}\}",
            "runs-on: ubuntu-26.04",
            r"HEAD_SHA: \$\{\{ needs.policy.outputs.review-head \}\}",
        ],
        &[
            r"needs\.agent\.outputs|needs\.check\.outputs\.artifact|pull_request\.head|needs\.policy\.outputs\.ref\b",
        ],
    ),
    (
        "review.yml",
        "carry",
        &[
            r"HEAD_SHA: \$\{\{ needs.policy.outputs.review-head \}\}",
            r#"(?s)if: >-\n\s+\$\{\{ \(vars.REVIEW_CARRY_APPROVAL == 'true' \|\|.*agentic-job" review carry --output "\$GITHUB_OUTPUT""#,
            // A push the record job would only record tries a carry first.
            r"\(github.event_name == 'pull_request_target' && startsWith\(vars.REVIEW_RECORD_ONLY, '\['\) &&\s+contains\(fromJSON\(vars.REVIEW_RECORD_ONLY \|\| '\[\]'\), github.event.pull_request.user.id\) &&\s+github.event.pull_request.head.repo.full_name != github.repository\)\) &&\s+github.event_name == 'pull_request_target' &&\s+github.event.action == 'synchronize'",
        ],
        &[],
    ),
    // Record-only: for the listed authors' fork pull requests, pending and
    // nothing else; no agent, inference, verdict or concurrency group that
    // could cancel a dispatched review of the same head.
    (
        "review.yml",
        "record",
        &[
            r"needs: \[policy, carry\]",
            r"\$\{\{ !cancelled\(\) && github.event_name == 'pull_request_target' && startsWith\(vars.REVIEW_RECORD_ONLY, '\['\) &&\s+contains\(fromJSON\(vars.REVIEW_RECORD_ONLY \|\| '\[\]'\), github.event.pull_request.user.id\) &&\s+github.event.pull_request.head.repo.full_name != github.repository &&\s+needs.policy.outputs.admitted == 'true' && needs.policy.outputs.review-head != '' &&\s+needs.policy.outputs.binary-artifact-id != '' && needs.carry.outputs.from == '' \}\}",
            r"permissions:\n      pull-requests: read\n      statuses: write\n",
            r"RECORD: 'true'",
            r"HEAD_SHA: \$\{\{ needs.policy.outputs.review-head \}\}",
            r#""\$RUNNER_TEMP/bin/agentic-job" review status\n"#,
        ],
        &[
            r"concurrency:|id-token: write|needs\.register|agent\.yml|INFERENCE_|VERDICT:|CHECK_RESULT|REVIEW_URL|CARRIED_|pull_request\.head\.sha|secrets\.",
        ],
    ),
    (
        "review.yml",
        "register",
        &[
            r"needs.carry.outputs.from == '' &&\s+!\(github.event_name == 'pull_request_target' && startsWith\(vars.REVIEW_RECORD_ONLY, '\['\) &&\s+contains\(fromJSON\(vars.REVIEW_RECORD_ONLY \|\| '\[\]'\), github.event.pull_request.user.id\) &&\s+github.event.pull_request.head.repo.full_name != github.repository\) \}\}",
        ],
        &[],
    ),
    // A dispatch: its inputs reach only the policy call's validated
    // routing and the run's name; the pool picks agent and model from the
    // repository's REVIEW_POOLS alone.
    (
        "review.yml",
        "",
        &[
            r"\nrun-name: \$\{\{ github.event_name == 'workflow_dispatch' && format\('review \{0\}#\{1\} \{2\} \(\{3\}\)', github.repository, inputs.pr, inputs.head, inputs.pool\) \|\| '' \}\}\n",
            r"\n  workflow_dispatch:\n    inputs:\n      pr:\n.*\n        type: string\n        required: true\n      head:\n.*\n        type: string\n        required: true\n      pool:\n.*\n        type: string\n        required: true\n",
            r"\n  workflow_call:\n(?:    #.*\n)*    inputs:\n      pr:\n        type: string\n        default: ''\n      head:\n        type: string\n        default: ''\n      pool:\n        type: string\n        default: ''\n",
        ],
        &[r"inputs\.(?:agent|model|config|inference)|\]\.(?:agent|model)\b"],
    ),
    (
        "review.yml",
        "pool",
        &[
            r"if: \$\{\{ github.event_name == 'workflow_dispatch' \}\}\n",
            r"permissions: \{\}\n",
            r"POOLS: \$\{\{ vars.REVIEW_POOLS \}\}\n",
        ],
        &[r"secrets|GH_TOKEN|uses:"],
    ),
    (
        "review.yml",
        "policy",
        &[
            r"event: \$\{\{ github.event_name != 'workflow_dispatch' \}\}\n",
            r"review-item: \$\{\{ github.event_name == 'workflow_dispatch' && \(inputs.pr \|\| '0'\) \|\| '' \}\}\n",
            r"review-head: \$\{\{ github.event_name == 'workflow_dispatch' && inputs.head \|\| '' \}\}\n",
            r"comment-target: \$\{\{ github.event_name == 'workflow_dispatch' && inputs.pr \|\| '' \}\}\n",
            r"needs: pool\n",
            r"agent: \$\{\{ github.event_name == 'workflow_dispatch' && needs.pool.outputs.agent \|\| github.event_name != 'workflow_dispatch' && vars.AGENT \|\| '' \}\}\n",
            r"model: \$\{\{ github.event_name == 'workflow_dispatch' && needs.pool.outputs.model \|\| github.event_name != 'workflow_dispatch' && vars.AGENT_MODEL \|\| '' \}\}\n",
            r"config: \$\{\{ github.event_name == 'workflow_dispatch' && needs.pool.outputs.config \|\| vars.AGENT_CONFIG \|\| ",
            r"inference-url: \$\{\{ vars.INFERENCE_URL \}\}\n",
        ],
        &[],
    ),
    // The dispatch step checks a requested head and writes the base's
    // review task, which the task step takes over the caller's.
    (
        "policy.yml",
        "policy",
        &[
            r"if: \$\{\{ inputs.review-item != '' \|\| inputs.review-head != '' \}\}\n",
            r"REQUESTED_HEAD: \$\{\{ inputs.review-head \}\}\n",
            r#"\[ -z "\$REQUESTED_HEAD" \] \|\|\n\s+"\$JOB_DIR/bin/agentic-job" review task "\$REVIEW_TASK" --pull-request "\$RUNNER_TEMP/dispatch-review.json" > "\$RUNNER_TEMP/review-task.md"\n"#,
            r#"elif \[ -n "\$REQUESTED_HEAD" \]; then cp "\$RUNNER_TEMP/review-task.md" "\$JOB_DIR/task.md"\n"#,
        ],
        &[],
    ),
    // The verdict is posted once: as the review, or else as apply's
    // comment. Only a checked verdict, from check's upload, is submitted;
    // the footer's job link is the agent job's own ID, from Actions.
    (
        "review.yml",
        "submit",
        &[
            r"HEAD_SHA: \$\{\{ needs.policy.outputs.review-head \}\}",
            "vars.AGENT_REAL_REVIEWS == 'true'",
            r"binary-artifact-id != '' && \(needs.carry.outputs.from != '' \|\|\s+\(needs.check.result == 'success' && needs.check.outputs.artifact-id != ''",
            r#"accepted=\(--accepted "\$RUNNER_TEMP/checked/agent_output.json"\)\n.*\n\s+"\$RUNNER_TEMP/bin/agentic-job" review submit "\$\{accepted\[@\]\}""#,
            r"VERDICT: \$\{\{ needs.check.outputs.verdict \}\}",
            r"AGENT_EXIT: \$\{\{ needs.agent.outputs.exit \}\}",
            r"AGENT_JOB: \$\{\{ needs.agent.outputs.job \}\}",
        ],
        &[r"secrets|safe-outputs-artifact-id|pull_request\.head|needs\.policy\.outputs\.ref\b"],
    ),
    (
        "review.yml",
        "apply",
        &[
            r"if: \$\{\{ !cancelled\(\) && needs.policy.result == 'success' && needs.carry.outputs.from == '' && needs.submit.outputs.review-url == '' \}\}",
        ],
        &[],
    ),
    // The refusal of an event review updates the one bounded status
    // comment, with the policy job's binary.
    (
        "review.yml",
        "refusal",
        &[
            "needs.policy.outputs.admitted == 'false' && needs.policy.outputs.binary-artifact-id != ''",
            r"artifact-ids: \$\{\{ needs.policy.outputs.binary-artifact-id \}\}\n",
            r"TEXT: \$\{\{ needs.policy.outputs.refusal \}\}",
            r#""\$RUNNER_TEMP/bin/agentic-job" status\n"#,
            "group: agentic-job-status-",
        ],
        &[],
    ),
    (
        "policy.yml",
        "",
        &[r#"review admit --decision "\$JOB_DIR/event\.json" --output "\$GITHUB_OUTPUT""#],
        &[],
    ),
    // The agent checks out the trusted base, and reports its job's ID.
    (
        "agent.yml",
        "",
        &[
            r"\n {6}job: \$\{\{ job.check_run_id \}\}\n",
            r"\n {6}job:\n {8}value: \$\{\{ jobs.agent.outputs.job \}\}\n",
            r"ref: \$\{\{ fromJSON\(inputs.policy\).ref \}\}",
        ],
        &[],
    ),
    // agentic-job.yml's agent job is agent.yml's, which takes the policy
    // call's outputs as check.yml does; dispatch.yml's configuration goes
    // through unchanged.
    (
        "agentic-job.yml",
        "",
        &[
            r"\n {4}uses: \./\.github/workflows/agent\.yml .*\n(?: {4}.*\n)*? {6}policy: \$\{\{ toJSON\(needs.policy.outputs\) \}\}\n",
            r"(?m)^      config: \$\{\{ inputs\.config \}\}$",
        ],
        &[],
    ),
    // The proposals route keeps check read-only, without secrets, and
    // starts no agent or activation.
    (
        "agentic-job.yml",
        "check",
        &[
            "needs.policy.result == 'success'",
            r"permissions:\n      contents: read",
            r"uses: \./\.github/workflows/check\.yml",
            r"safe-outputs-artifact-id: \$\{\{ needs.agent.outputs.safe-outputs-artifact-id \}\}",
            r"safe-outputs-artifact-digest: \$\{\{ needs.agent.outputs.safe-outputs-artifact-digest \}\}",
        ],
        &[r"secrets[.:]|needs.agent.outputs.(binary|policy|comment)"],
    ),
    (
        "agentic-job.yml",
        "agent",
        &[r"\n    if: .*inputs.proposals-artifact == ''"],
        &[],
    ),
    (
        "policy.yml",
        "activate",
        &[r"\n    if: .*inputs.proposals-artifact == ''"],
        &[],
    ),
    // CI runs the proposed workflow on pull requests and merge groups,
    // never with a fork's code and the base's secrets; a fork's pull
    // request without a queue fails the one required check.
    (
        "ci.yml",
        "",
        &[
            r"\non:\n  pull_request:\n  merge_group:\n  push:\n    branches: \[main\]\n\n",
            r"(?m)^      e2e:.*steps\.queue\.outputs\.enabled == 'true' \|\| github\.event\.pull_request\.head\.repo\.full_name != github\.repository.*$",
            r"(?m)^      fork-e2e:.*steps\.queue\.outputs\.enabled != 'true'.*steps\.paths\.outputs\.e2e != 'false'.*$",
            r"\n          BRANCH: \$\{\{ github\.event\.pull_request\.base\.ref \}\}\n",
            r"\n  ci:\n    if: \$\{\{ always\(\) \}\}\n    needs: required-checks\n",
            r"cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}",
            "pull_request and merge_group both run the proposed workflow",
            r"- id: queued\n        if: \$\{\{ github\.event_name == 'push' \}\}\n",
            r"- id: review\n        if: \$\{\{ github\.event_name == 'pull_request' \}\}\n        env:\n          BASE: \$\{\{ github\.event\.pull_request\.base\.sha \}\}\n",
            r"python3 -m unittest discover -s workflow -p 'test_\*\.py' -v\n {8}env:\n {10}ZIZMOR: ",
        ],
        &[
            r"pull_request_target|\bworkflow_run\b|secrets\.",
            "paths-ignore:|paths:",
            "run: node workflow/ci-paths",
        ],
    ),
    // Queue detection and the queued-push lookup read with a read-only token.
    (
        "ci.yml",
        "changes",
        &[r"\n    permissions:\n      contents: read\n      actions: read #[^\n]*\n"],
        &[r"\n    if:"],
    ),
    // A fork's pull request is no reason to pass a skipped job.
    (
        "ci.yml",
        "required-checks",
        &[r"FILTER: >-\n +\$fork_e2e == .false. and all\("],
        &[r"\$fork\b"],
    ),
    (
        "ci.yml",
        "e2e-dispatch",
        &[
            r"needs: \[changes, e2e-scratch\]",
            r#"profile: \$\{\{ fromJSON\(github\.event_name != 'push' && '\["research","review"\]' \|\| '\["research"\]'\) \}\}"#,
            r"item: \$\{\{ matrix.profile == 'review' && needs.e2e-scratch.outputs.pr \|\| '64' \}\}",
        ],
        &[],
    ),
    // The shared workflow check is off unless a repository variable names
    // its commit, runs before gh-aw's workflows are in the workspace, and
    // has no write token or secret.
    (
        "ci.yml",
        "lint",
        &[
            r#"- name: Shared workflow check\n {8}if: \$\{\{ vars\.WORKFLOW_LINT != '' \}\}\n {8}env:\n {10}WORKFLOW_LINT: \$\{\{ vars\.WORKFLOW_LINT \}\}\n {8}run: just workflow-lint "\$WORKFLOW_LINT"\n"#,
        ],
        &[r": write|secrets\."],
    ),
    // The dispatch verifier runs this revision's code with read access
    // only; the cleanup, which can write, runs none of it.
    (
        "ci.yml",
        "e2e-dispatch-verify",
        &[
            "\n    permissions:\n      contents: read\n      issues: read\n      pull-requests: read\n      actions: read # read hosted job durations; no write or cleanup authority\n    [a-z]",
            r"ref: \$\{\{ github.sha \}\}",
            "persist-credentials: false",
            r"\n {8}with:\n {10}name: agentic-job\n",
            r#""\$RUNNER_TEMP/agentic-job" config --host --from "\$CONFIG" --repo "\$GH_REPO"\)"#,
            r"\n {10}CONFIG: \.github/agentic-job/hosted\.toml\n",
            r"GH_TOKEN: \$\{\{ github.token \}\}",
            r"needs: \[changes, static, e2e-scratch, e2e-dispatch, e2e-compose, e2e-full\]",
            r"if: \$\{\{ always\(\) && needs.changes.outputs.e2e == 'true' \}\}",
            r#"test "\$REVIEW_HEAD" = "\$HEAD_SHA""#,
            r#"\[ "\$EVENT" != push \] \|\| exit 0"#,
            r"::error::missing scratch PR",
            r#"test "\$\(gh api "repos/\$GH_REPO/pulls/\$PR" --jq .head.sha\)" = "\$REVIEW_HEAD""#,
            r"name: Admit a scratch PR review and refuse the actual merge-group event\n        if: \$\{\{ github.event_name == 'merge_group' \}\}",
            r"event --allow workflow/review.toml --event-name pull_request",
            r"event --allow workflow/review.toml --event-name merge_group --event",
            r#"review admit --decision "\$dir/event.json" --base main"#,
            r#"grep -Fx 'admitted=false'"#,
        ],
        &[r": write|secrets\."],
    ),
    (
        "ci.yml",
        "e2e-verify",
        &[
            r"needs: \[.*e2e-dispatch-verify\]",
            r"if: \$\{\{ always\(\) && needs.changes.outputs.e2e == 'true' \}\}",
            r"- name: Delete the comments\n        if: \$\{\{ always\(\) ",
            r"- name: Close only the scratch pull request of this run and delete its branch\n        if: \$\{\{ always\(\) ",
        ],
        &[r"uses: actions/checkout@|agentic-job config|github.sha|\.dispatch-verifier"],
    ),
    // The probe jobs secure their host with this revision's image through
    // the forwarder, with no passing fallback.
    (
        "ci.yml",
        "confined",
        &[
            r"\n    needs: \[changes, static\]\n",
            r"name: secure-host-image\n",
            r"uses: \./secure-host # zizmor: ignore\[self-repository\] .*\n        with:\n          image-archive: \$\{\{ runner\.temp \}\}/image/secure-host\.tar\n      - ",
            r"- name: The JavaScript action main and post steps are confined\n        uses: \./\.github/actions/confine-probe # zizmor: ignore\[self-repository\] ",
            r"\n    outputs:\n      orphan: \$\{\{ steps\.orphan\.outputs\.pid \}\}\n",
            r#"echo "\$!" > "\$RUNNER_TEMP/confine-orphan\.pid""#,
            "secure-host check --record",
            r"\n        run: secure-host probe confined run-step\n",
            r"- if: \$\{\{ !cancelled\(\) \}\}\n        uses: actions/upload-artifact@",
        ],
        &[
            "uses: cgwalters-forge/agentic-job",
            "config:|--boolean|deny-runner|unlink-worker|lock-runner",
            r"binary\.sh|secure-host world-write|sandbox setup|podman run|continue-on-error|\|\| true",
            "actions/github-script@",
        ],
    ),
    // Confined's orphan was ended by the runner, read as data from its log.
    (
        "ci.yml",
        "confined-cleanup",
        &[
            r"\n    needs: \[changes, confined\]\n",
            r"\n    permissions:\n      actions: read\n    steps:\n",
            r"PID: \$\{\{ needs\.confined\.outputs\.orphan \}\}\n",
            r#"\[\[ "\$PID" =~ \^\[1-9\]\[0-9\]\*\$ \]\]"#,
            r#"grep -qF "Terminate orphan process: pid \(\$PID\) \(sleep\)""#,
            r#"gh api --allow-escape-sequences "repos/\$REPO/actions/jobs/\$job/logs" > "\$RUNNER_TEMP/confined.log""#,
        ],
        &[
            r"uses:|secrets\.|contents: write",
            "config:|--boolean|deny-runner|unlink-worker|lock-runner",
            r"binary\.sh|secure-host world-write|sandbox setup|podman run|continue-on-error|\|\| true",
        ],
    ),
    (
        "ci.yml",
        "world-write-runtime",
        &[
            r"\n    needs: \[changes, static\]\n",
            r"\n    runs-on: ubuntu-26\.04\n",
            r"\n    permissions:\n      contents: read\n    steps:\n",
            r"name: secure-host-image\n",
            r"uses: \./secure-host # zizmor: ignore\[self-repository\] .*\n        with:\n          image-archive: \$\{\{ runner\.temp \}\}/image/secure-host\.tar\n",
            r#""0 666 \$\(stat -c %d /\)""#,
            r#"grep -qF "cannot create \$probe: Permission denied" "\$RUNNER_TEMP/refused\.txt""#,
            r#""666 \$\(stat -c %d /\)""#,
        ],
        &[r"continue-on-error|\|\| true|lock-runner|filesystem-view|shell:|config:"],
    ),
    // The build's archive, never a registry's image, and probes after the
    // container has exited.
    (
        "ci.yml",
        "secure-host-image",
        &[
            r"\n    needs: \[changes, static\]\n",
            r"\n    runs-on: ubuntu-26\.04\n",
            r"\n    permissions:\n      contents: read\n    steps:\n",
            r"name: secure-host-image\n",
            r"uses: \./secure-host # zizmor: ignore\[self-repository\] .*\n        with:\n          image-archive: \$\{\{ runner\.temp \}\}/image/secure-host\.tar\n",
        ],
        &[r"--pull|ghcr\.io|continue-on-error|\|\| true|podman run"],
    ),
    (
        "ci.yml",
        "secure-host-write-policy",
        &[
            r"\n    needs: \[changes, static\]\n",
            r"\n    runs-on: ubuntu-26\.04\n",
            r"\n    permissions:\n      contents: read\n    steps:\n",
            r"printf '\\n\[egress\]\\nwrite-policy = true\\n'",
            r"uses: \./secure-host # zizmor: ignore\[self-repository\] .*\n        with:\n          config: \$\{\{ runner\.temp \}\}/write-policy\.toml\n          image-archive: \$\{\{ runner\.temp \}\}/image/secure-host\.tar\n",
        ],
        &[r"continue-on-error|\|\| true|--proxy|-x |_PROXY: "],
    ),
    (
        "secure-host/hosted.toml",
        "",
        &[r"(?m)^# The egress proxy and the network rules are on by default: no \[egress\]\.$"],
        &[r"(?m)^\s*proxy\s*=\s*false"],
    ),
    (
        ".github/actions/egress-probe/action.yml",
        "",
        &[r"\n  using: node24\n  main: main\.mjs\n$"],
        &[],
    ),
    // This repository's jobs that secure a host take the forwarder with
    // this revision's image, and none takes a shell other than the runner's.
    (
        "ci.yml",
        "secure-host-options",
        &[
            r"uses: \./secure-host # [^\n]*\n {8}with:\n(?: {10}config: [^\n]*\n)? {10}image-archive: \$\{\{ runner\.temp \}\}/image/secure-host\.tar\n",
        ],
        &["shell:"],
    ),
    (
        "ci.yml",
        "world-write-runtime",
        &[
            r"uses: \./secure-host # [^\n]*\n {8}with:\n(?: {10}config: [^\n]*\n)? {10}image-archive: \$\{\{ runner\.temp \}\}/image/secure-host\.tar\n",
        ],
        &["shell:"],
    ),
    (
        "example-secure-host.yml",
        "",
        &[r"uses: \./secure-host # [^\n]*\n {8}with:\n {10}image-archive: "],
        &[r"shell:|steps\.host\.outputs"],
    ),
    (
        "ci.yml",
        "secure-host",
        &[r"\n    needs: \[changes, static\]\n(?s:.)*\n      image-artifact: secure-host-image\n"],
        &[],
    ),
    // main's published action is the forwarder: none of the old outputs.
    (
        "ci.yml",
        "secure-host-published",
        &["uses: cgwalters-forge/agentic-job/secure-host@main "],
        &[r"\n {8}with:|steps\.host\.outputs"],
    ),
    // The required ingress check reports on every pull request (a paths
    // filter would leave it pending on others) and vets a merge group with
    // its base's code, never the queued commit's.
    (
        "workflow-ingress.yml",
        "",
        &[
            r"\n  merge_group:\n    types: \[checks_requested\]\n",
            r"\npermissions:\n  contents: read\n\njobs:\n  vet:\n",
            r"\n {10}ref: \$\{\{ github\.event\.merge_group\.base_sha \|\| github\.sha \}\}\n",
            r"BASE: \$\{\{ github\.event\.pull_request\.base\.sha \|\| github\.event\.merge_group\.base_sha \}\}",
            r"HEAD: \$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.event\.merge_group\.head_sha \}\}",
            r"cancel-in-progress: \$\{\{ github\.event_name == 'pull_request_target' \}\}",
            r"run: cargo build --locked --release -p agentic-job\n",
            r"timeout-minutes: 30\n",
            r#"python3 workflow/ingress\.py \. "\$BASE" "\$HEAD" --workflows-binary target/release/agentic-job --exemptions \.github/agentic-job/workflows\.toml\n"#,
        ],
        &[r": write|secrets\.|id-token"],
    ),
    (
        "review.yml",
        "",
        &[
            r"cancel-in-progress: \$\{\{ github\.event_name == 'pull_request_target' \|\| github\.event_name == 'workflow_dispatch' \}\}",
            r"group: review-pull-\$\{\{ github\.event\.pull_request\.number \|\| github\.event\.issue\.number \|\| inputs\.pr \}\}",
        ],
        &[],
    ),
    (
        "secure-host/binary.sh",
        "",
        &[
            r"sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 \\\n\s+install ",
        ],
        &[],
    ),
    // dispatch.yml's caller holds the run to its bounds file, its item and
    // its target; real dispatches keep one concurrency group per item, and
    // CI's scripted ones one per run, so that one queue entry's pending
    // call does not cancel another's (#544).
    (
        "dispatch.yml",
        "",
        &[
            r"uses: \./\.github/workflows/agentic-job.yml",
            "needs: target",
            r"(?m)^  group: dispatch-\$\{\{ inputs\.kind \}\}-\$\{\{ inputs\.repo \}\}-\$\{\{ inputs\.item-repo \}\}-\$\{\{ inputs\.item \}\}\$\{\{ inputs\.scripted && format\('-\{0\}', github\.run_id\) \|\| '' \}\}\n  cancel-in-progress: false$",
        ],
        &[
            r"(?m)^\s+runner:",
            "secrets: inherit",
            r"secrets\.INFERENCE_API_KEY",
        ],
    ),
    ("dispatch.yml", "target", &[], &[r"secrets(?:[.:]|\[)"]),
    (
        "example-compose.yml",
        "",
        &[
            r"(?m)^  group: compose-\$\{\{ inputs\.item \}\}\$\{\{ inputs\.scripted && format\('-\{0\}', github\.run_id\) \|\| '' \}\}\n  cancel-in-progress: false$",
        ],
        &[],
    ),
    (
        ".github/agentic-job/dispatch.toml",
        "",
        &[
            r#"(?m)^repos = \["cgwalters-forge/agentic-job"\]$"#,
            r"(?m)^max_outputs = 32$",
            r"(?m)^create_pull_request = \{ max = 1 \}$",
            r"(?m)^add_comment = \{ max = 1 \}$",
            r"(?m)^noop = \{ max = 1 \}$",
            r"(?m)^missing_tool = \{ max = 1 \}$",
            r"(?m)^missing_data = \{ max = 1 \}$",
            r"(?m)^close_issue = \{ max = 30 \}$",
        ],
        &["create_issue"],
    ),
];

/// Text each file or job holds, in this order, as (file, job or "", texts).
const TEXTS: &[(&str, &str, &[&str])] = &[
    ("example-compose.yml", "agent", &["uses: ./.agentic-job-source/prepare", "Your privileged steps go here", "name: A caller's privileged step", "End of your privileged steps", "uses: ./.agentic-job-source/secure-host", "uses: ./.agentic-job-source/run", "Your later steps go here", "name: A caller's later step"]),
    ("prepare/action.yml", "", &["artifact-ids:", "The policy call is this action's commit", "- name: Install the binary", "- name: Write what the run is called", "- name: The inference broker's address"]),
    ("run/action.yml", "", &["- name: Prove the host is secured", "The policy call is this action's commit", "- name: Read the run's settings", "- name: Refuse a GitHub token that can write", "- name: Run the agent", "- name: Check again that the repositories are public", "uses: actions/upload-artifact", "id: safe-outputs", "- name: The run's result"]),
    ("policy.yml", "policy", &["Check that the repositories are public", "- name: This workflow"]),
    // Apply posts the comment check folded, before anything that names or
    // marks what it posts.
    (
        "apply.yml",
        "",
        &[
            r#"mv "$GH_AW_TMP/folded.json" "$GH_AW_TMP/agent_output.json""#,
            "- name: Mark what a partial run opens or posts",
            "- name: Leave out what an earlier attempt applied",
        ],
    ),
    (
        "check.yml",
        "",
        &[
            "- name: Put the patch beside the ingested outputs",
            r#"review fold "$GH_AW_TMP/agent_output.json""#,
            "- id: upload",
        ],
    ),
    // The proposals are held to the agent job's digest before they are
    // downloaded, and the download to that digest.
    (
        "check.yml",
        "check",
        &[
            "- name: Require explicit artifact contracts\n",
            "- name: The proposals are the agent job's upload\n",
            "artifact-ids: ${{ inputs.safe-outputs-artifact-id }}",
            "- name: Ingest the outputs",
        ],
    ),
    (
        "check.yml",
        "check",
        &["artifact-ids: ${{ inputs.safe-outputs-artifact-id }}\n          path: .agentic-job/safe-outputs\n          digest-mismatch: error\n"],
    ),
    // Check takes the trusted IDs and the comment target from the policy
    // call, and exports what apply needs.
    (
        "check.yml",
        "",
        &[
            "value: ${{ jobs.detect.outputs.artifact-id }}",
            "value: ${{ jobs.check.outputs.refusal }}",
            "value: ${{ jobs.check.outputs.has-patch }}",
            "${{ fromJSON(inputs.policy).binary-artifact-id }}",
            "${{ fromJSON(inputs.policy).policy-artifact-id }}",
            "${{ fromJSON(inputs.policy).comment-target }}",
        ],
    ),
    (
        "agentic-job.yml",
        "check",
        &["policy: ${{ toJSON(needs.policy.outputs) }}"],
    ),
    // Who starts an automatic review: the owner, members and collaborators,
    // and a Bot whose numeric id REVIEW_BOT_IDS lists as a JSON array; a
    // `/review` comment from anyone, which its bounds hold to write access;
    // and a dispatch, which takes write access. Changing it changes who
    // spends inference.
    (
        "review.yml",
        "policy",
        &["    if: >-
      !cancelled() && needs.pool.result != 'failure' && (
      (github.event_name == 'pull_request_target' && !github.event.pull_request.draft &&
        (contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.pull_request.author_association) ||
          (github.event.pull_request.user.type == 'Bot' && startsWith(vars.REVIEW_BOT_IDS, '[') &&
            contains(fromJSON(vars.REVIEW_BOT_IDS || '[]'), github.event.pull_request.user.id)))) ||
      (github.event.issue.pull_request && startsWith(github.event.comment.body, '/review')) ||
      (github.event_name == 'workflow_dispatch' && needs.pool.result == 'success'))
"],
    ),
    // The policy job reads the bounds at the workflow's commit for
    // pull_request_target, and the agent stays on the event's base.
    (
        "policy.yml",
        "policy",
        &[
            "\n      ref: ${{ inputs.review && !inputs.review-item && (github.event.pull_request.base.sha || inputs.base) || github.sha }}\n",
            "\n          ref: ${{ github.event_name == 'pull_request_target' && github.workflow_sha || (inputs.review && !inputs.review-item && (github.event.pull_request.base.sha || inputs.base) || github.sha) }}\n",
        ],
    ),
    // Without AGENT_CONFIG, review and dispatch read this source's
    // hosted.toml, which the policy job checks out before reading it.
    (
        "policy.yml",
        "policy",
        &[
            "\n          repository: ${{ job.workflow_repository }}\n          ref: ${{ job.workflow_sha }}\n          path: .agentic-job-source\n",
            "- name: Write the configuration",
        ],
    ),
    (
        "review.yml",
        "",
        &["config: ${{ github.event_name == 'workflow_dispatch' && needs.pool.outputs.config || vars.AGENT_CONFIG || '.agentic-job-source/.github/agentic-job/hosted.toml' }}"],
    ),
    (
        "dispatch.yml",
        "",
        &["config: ${{ !inputs.scripted && vars.AGENT_CONFIG || '.agentic-job-source/.github/agentic-job/hosted.toml' }}"],
    ),
    // Policy hands on the issue it checked, not the input.
    (
        "policy.yml",
        "",
        &["\n      issue: ${{ steps.request.outputs.issue }}\n"],
    ),
    // zizmor scans the workspace: gh-aw's workflows are not there yet.
    (
        "ci.yml",
        "lint",
        &["Shared workflow check", "repository: github/gh-aw"],
    ),
    // Confined's orphan is left before every probe, the control included;
    // the run step and the action's main and post steps run under the lock.
    (
        "ci.yml",
        "confined",
        &[
            "      - name: Leave a process running\n        id: orphan\n",
            "\"$RUNNER_TEMP/secure-host-bin\" probe control before",
            "        uses: ./secure-host # zizmor: ignore[self-repository] ",
            "secure-host probe confined run-step",
            "        uses: ./.github/actions/confine-probe # zizmor: ignore[self-repository] ",
            "uses: actions/upload-artifact@",
        ],
    ),
    (
        "ci.yml",
        "world-write-runtime",
        &[
            "        uses: ./secure-host # zizmor: ignore[self-repository] ",
            "      - name: The runner's user is refused a write to a world-writable file of root\n",
            "      - name: The runner's user writes its own world-writable file (control)\n",
        ],
    ),
    (
        "ci.yml",
        "secure-host-image",
        &["        uses: ./secure-host # zizmor: ignore[self-repository] ", "if sudo -n true; then"],
    ),
    (
        "ci.yml",
        "secure-host-image",
        &["        uses: ./secure-host # zizmor: ignore[self-repository] ", "systemctl is-active --quiet docker.service"],
    ),
    (
        "ci.yml",
        "secure-host-image",
        &["        uses: ./secure-host # zizmor: ignore[self-repository] ", "egress-proxy.service"],
    ),
    // After the lock, in this order: the run step, the JavaScript action,
    // the upload.
    (
        "ci.yml",
        "secure-host-write-policy",
        &[
            "        uses: ./secure-host # zizmor: ignore[self-repository] ",
            "curl -fsS -o /dev/null https://example.com/",
            "grep -qi '^x-egress-denied:'",
            "uses: ./.github/actions/egress-probe ",
            "uses: actions/upload-artifact@",
        ],
    ),
];

#[test]
fn write_policy_only_conditions_failure_diagnostics() {
    let text = workflow("ci.yml");
    let doc = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
    let steps = doc["jobs"]["secure-host-write-policy"]["steps"]
        .as_vec()
        .unwrap();
    let diagnostic = "Refused destinations from the last 64 KiB of the proxy log";
    assert_eq!(steps.last().unwrap()["name"].as_str(), Some(diagnostic));
    for (index, step) in steps.iter().enumerate() {
        if index == steps.len() - 1 {
            assert_eq!(step["if"].as_str(), Some("${{ failure() }}"));
            assert!(step["run"].as_str().unwrap().contains("helper egress-log"));
            assert!(step["uses"].is_badvalue());
        } else {
            // Probes and uploads must run normally; a skipped probe proves nothing.
            assert!(step["if"].is_badvalue(), "conditional probe: {step:?}");
            assert_ne!(step["name"].as_str(), Some(diagnostic));
        }
    }
}

#[test]
fn workflow_shapes() {
    for (file, name, matching, other) in SHAPES {
        let text = workflow(file);
        let text = if name.is_empty() {
            text.as_str()
        } else {
            job(&text, name)
        };
        for (patterns, wanted) in [(matching, true), (other, false)] {
            for pattern in *patterns {
                let found = Regex::new(pattern).unwrap().is_match(text);
                assert_eq!(found, wanted, "{file} {name}: {pattern}");
            }
        }
    }
    for (file, name, texts) in TEXTS {
        let text = workflow(file);
        let text = if name.is_empty() {
            text.as_str()
        } else {
            job(&text, name)
        };
        let at: Vec<usize> = texts
            .iter()
            .map(|want| {
                text.find(want)
                    .unwrap_or_else(|| panic!("{file} {name}: no {want:?}"))
            })
            .collect();
        assert!(at.is_sorted(), "{file} {name}: {texts:?} at {at:?}");
    }
    assert!(root().join(".github/agentic-job/hosted.toml").is_file());
    // Of check's inputs, only the proposals' upload ID and digest are not
    // the policy call's: the producer chooses no binary, policy or target.
    let text = workflow("check.yml");
    let doc = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
    let inputs: Vec<&str> = doc["on"]["workflow_call"]["inputs"]
        .as_hash()
        .unwrap()
        .keys()
        .map(|input| input.as_str().unwrap())
        .collect();
    assert_eq!(
        inputs,
        [
            "policy",
            "safe-outputs-artifact-id",
            "safe-outputs-artifact-digest"
        ]
    );
}

/// review.yml's jobs and what each may write: comments in refusal, submit
/// and apply, the status in status, identity tokens in register and
/// check's detector, never in the agent's job, whose only secrets are the
/// register job's run token and its network step's key.
#[test]
fn the_review_caller_keeps_token_separation() {
    let text = workflow("review.yml");
    let doc = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
    let names: Vec<&str> = doc["jobs"]
        .as_hash()
        .unwrap()
        .keys()
        .map(|name| name.as_str().unwrap())
        .collect();
    let writes: [(&str, &[&str]); 11] = [
        ("pool", &[]),
        ("policy", &[]),
        ("refusal", &["pull-requests"]),
        ("carry", &[]),
        ("record", &["statuses"]),
        ("register", &["id-token"]),
        ("agent", &[]),
        ("check", &["id-token"]),
        ("submit", &["pull-requests"]),
        ("apply", &["pull-requests"]),
        ("status", &["statuses"]),
    ];
    assert_eq!(names, writes.map(|(name, _)| name));
    for (name, wanted) in writes {
        let granted: Vec<&str> = doc["jobs"][name]["permissions"]
            .as_hash()
            .unwrap()
            .iter()
            .filter(|(_, access)| access.as_str() == Some("write"))
            .map(|(permission, _)| permission.as_str().unwrap())
            .collect();
        assert_eq!(granted, wanted, "{name}");
        let secrets = job(&text, name).replace(
            "\n    secrets:\n      INFERENCE_RUN_TOKEN: ${{ needs.register.outputs.run-token }}\n      NETWORK_SECRET: ${{ needs.register.outputs.network-secret }}\n",
            "\n",
        );
        assert!(
            name == "apply" || !secrets.contains("secrets"),
            "{name}: {secrets}"
        );
    }
    let pinned = Regex::new("@[0-9a-f]{40}$").unwrap();
    for action in Regex::new(r"(?m)^ +(?:- )?uses: ([^.\s]\S*)")
        .unwrap()
        .captures_iter(&text)
    {
        assert!(pinned.is_match(&action[1]), "{}", &action[1]);
    }
    // The only uploads read: the policy job's binary of the pinned source,
    // and check's accepted outputs.
    const BINARY: &str = "${{ needs.policy.outputs.binary-artifact-id }}";
    let ids = Regex::new("artifact-ids: (.*)").unwrap();
    for (name, wanted) in [
        ("status", &[BINARY][..]),
        ("carry", &[BINARY]),
        (
            "submit",
            &[BINARY, "${{ needs.check.outputs.artifact-id }}"],
        ),
    ] {
        let found: Vec<&str> = ids
            .captures_iter(job(&text, name))
            .map(|id| id.get(1).unwrap().as_str())
            .collect();
        assert_eq!(found, wanted, "{name}");
    }
}

/// policy.yml's mode check, with `change` over a run that names nothing.
fn mode_gate(dir: &Path, change: &[(&str, &str)]) -> Output {
    let mut env = vec![
        ("RUNNER_TEMP", path(dir)),
        ("PROPOSALS", ""),
        ("EVENT", "false"),
        ("REVIEW", "false"),
        ("PARTIAL", "false"),
        ("TASK", ""),
        ("TASK_ARTIFACT", ""),
    ];
    env.extend_from_slice(change);
    run_step("policy.yml", "Check the proposals mode", dir, &env)
}

/// Proposals come without an event, a review or partial apply; an agent
/// run has a task or derives one.
#[test]
fn the_proposals_mode_gate() {
    let dir = tempfile::tempdir().unwrap();
    for (change, success) in [
        (&[("PROPOSALS", "proposals")][..], true),
        (&[("PROPOSALS", "proposals"), ("EVENT", "true")], false),
        (&[("PROPOSALS", "proposals"), ("REVIEW", "true")], false),
        (&[("PROPOSALS", "proposals"), ("PARTIAL", "true")], false),
        (&[("TASK", "run")], true),
        (&[], false),
        (&[("TASK", "run"), ("PARTIAL", "true")], true),
        (&[("PARTIAL", "true")], false),
        (&[("EVENT", "true")], true),
        (&[("REVIEW", "true")], true),
        (&[("EVENT", "true"), ("REVIEW", "true")], true),
        // The artifact's name is data.
        (&[("PROPOSALS", "$(exit 99)")], true),
    ] {
        let output = mode_gate(dir.path(), change);
        let code = Some(i32::from(!success));
        assert_eq!(output.status.code(), code, "{change:?}: {output:?}");
    }
}

/// Every call of agentic-job.yml here passes the mode check: a task
/// given as prose or an expression is one, uninterpreted.
#[test]
fn every_caller_passes_the_mode_gate() {
    use yaml_rust2::Yaml;
    let dir = tempfile::tempdir().unwrap();
    let mut callers = 0;
    for entry in std::fs::read_dir(root().join(".github/workflows")).unwrap() {
        let file = entry.unwrap().path();
        if file.extension().is_none_or(|extension| extension != "yml") {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap();
        let doc = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
        for (name, job) in doc["jobs"].as_hash().into_iter().flatten() {
            if job["uses"].as_str() != Some("./.github/workflows/agentic-job.yml") {
                continue;
            }
            let values: Vec<(&str, String)> = [
                ("proposals-artifact", "PROPOSALS"),
                ("event", "EVENT"),
                ("review", "REVIEW"),
                ("apply-partial", "PARTIAL"),
                ("task", "TASK"),
            ]
            .into_iter()
            .filter_map(|(input, variable)| {
                let value = match &job["with"][input] {
                    Yaml::String(value) => value.clone(),
                    Yaml::Boolean(value) => value.to_string(),
                    Yaml::Integer(value) => value.to_string(),
                    _ => return None,
                };
                Some((variable, value))
            })
            .collect();
            let change: Vec<(&str, &str)> = values
                .iter()
                .map(|(variable, value)| (*variable, value.as_str()))
                .collect();
            let output = mode_gate(dir.path(), &change);
            assert!(output.status.success(), "{file:?} {name:?}: {output:?}");
            callers += 1;
        }
    }
    assert!(
        callers >= 8,
        "expected the example, review and CI callers, found {callers}"
    );
}

/// Check takes explicit trusted upload IDs, and one proposal selector:
/// the agent job's upload ID with its digest, or a legacy name.
#[test]
fn the_checker_requires_explicit_artifact_contracts() {
    let dir = tempfile::tempdir().unwrap();
    let digest = "c".repeat(64);
    let prefixed = format!("sha256:{digest}");
    for (change, success) in [
        (&[][..], true),
        (
            &[
                ("PROPOSALS", ""),
                ("DIGEST", ""),
                ("NAME", "board-proposals"),
            ],
            true,
        ),
        (&[("BINARY", "")], false),
        (&[("POLICY", "")], false),
        (&[("PROPOSALS", "")], false),
        (&[("DIGEST", "")], false),
        (&[("DIGEST", prefixed.as_str())], false),
        (&[("DIGEST", &digest[1..])], false),
        (&[("DIGEST", "$(exit 0)")], false),
        (&[("DIGEST", ""), ("NAME", "board-proposals")], false),
        (&[("PROPOSALS", ""), ("NAME", "board-proposals")], false),
        (&[("POLICY", "2,4")], false),
        (&[("PROPOSALS", "$(exit 99)")], false),
        // The legacy name is data.
        (
            &[("PROPOSALS", ""), ("DIGEST", ""), ("NAME", "$(exit 99)")],
            true,
        ),
    ] {
        let mut env = vec![
            ("BINARY", "1"),
            ("POLICY", "2"),
            ("PROPOSALS", "3"),
            ("DIGEST", digest.as_str()),
            ("NAME", ""),
        ];
        env.extend_from_slice(change);
        let output = run_step(
            "check.yml",
            "Require explicit artifact contracts",
            dir.path(),
            &env,
        );
        let code = Some(i32::from(!success));
        assert_eq!(output.status.code(), code, "{change:?}: {output:?}");
    }
}

/// The agent job hands back by upload ID and digest; check holds the upload
/// to that digest, and to this run, before it downloads any of it.
#[test]
fn the_checker_refuses_another_upload_digest() {
    use serde_json::{Value, json};
    let text = workflow("check.yml");
    let doc = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
    let step = doc["jobs"]["check"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|step| step["name"].as_str() == Some("The proposals are the agent job's upload"))
        .unwrap();
    assert_eq!(
        step["if"].as_str(),
        Some("${{ fromJSON(inputs.policy).proposals-artifact == '' }}")
    );
    assert_eq!(
        step["env"]["DIGEST"].as_str(),
        Some("${{ inputs.safe-outputs-artifact-digest }}")
    );
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    // What the read API says of upload 3.
    executable(
        &bin.join("gh"),
        "#!/bin/bash\n[ \"$*\" = 'api repos/o/r/actions/artifacts/3' ] || exit 9\n[ -n \"$ANSWER\" ] && printf %s \"$ANSWER\"\n",
    );
    let search = format!("{}:{}", path(&bin), std::env::var("PATH").unwrap());
    let digest = "c".repeat(64);
    let artifact = |hash: Value, run: u64| {
        json!({"id": 3, "name": "safe-outputs", "digest": hash, "workflow_run": {"id": run}})
            .to_string()
    };
    let sha = |c: &str| json!(format!("sha256:{}", c.repeat(64)));
    // (the API's answer, the digest the agent job gave, whether check goes on)
    for (answer, given, success) in [
        (artifact(sha("c"), 7), digest.as_str(), true),
        (artifact(sha("d"), 7), &digest, false),
        (artifact(sha("c"), 7), "", false),
        (artifact(Value::Null, 7), &digest, false),
        (artifact(json!(digest), 7), &digest, false),
        (artifact(sha("c"), 8), &digest, false),
        // Not found, or not readable.
        (String::new(), &digest, false),
    ] {
        let output = run_step(
            "check.yml",
            "The proposals are the agent job's upload",
            dir.path(),
            &[
                ("PATH", &search),
                ("PROPOSALS", "3"),
                ("DIGEST", given),
                ("GITHUB_REPOSITORY", "o/r"),
                ("GITHUB_RUN_ID", "7"),
                ("ANSWER", &answer),
            ],
        );
        assert_eq!(
            output.status.success(),
            success,
            "{answer} {given}: {output:?}"
        );
    }
}

/// policy.yml's request step, with a stand-in for the policy command that
/// prints its arguments and `FAKE_SAFE_OUTPUTS` as the policy, and the
/// directory it ran in.
fn request(env: &[(&str, &str)]) -> (Output, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("bin")).unwrap();
    executable(
        &dir.path().join("bin/agentic-job"),
        "#!/bin/bash\nprintf '%s\\0' \"$@\" |\n  jq -Rs --argjson safe \"$FAKE_SAFE_OUTPUTS\" '{args: split(\"\\u0000\")[:-1], safe_outputs: $safe}'\n",
    );
    let output = dir.path().join("output");
    let mut all = vec![
        ("SOURCE_DIR", path(dir.path())),
        ("JOB_DIR", path(dir.path())),
        ("GITHUB_OUTPUT", path(&output)),
        ("GITHUB_REPOSITORY", "o/r"),
        ("ALLOW", "allow"),
        ("REPO", "o/r"),
        ("BASE", "main"),
        ("OUTPUTS", "all"),
        ("TARGET", ""),
        ("ISSUE", ""),
    ];
    all.extend_from_slice(env);
    let output = run_step(
        "policy.yml",
        "Check the request against the caller's bounds",
        dir.path(),
        &all,
    );
    (output, dir)
}

/// The policy command is told when apply holds only the job token, where
/// a push goes and which repository an item is in; an issue is a number,
/// and an item's repository is not for an event, a review or a push.
#[test]
fn the_request_step_tells_the_policy_command_its_token_and_targets() {
    let head = "a".repeat(40);
    let replacement = "b".repeat(40);
    let push = [
        ("PUSH_ITEM", "42"),
        ("PUSH_BRANCH", "agent-run-1"),
        ("PUSH_HEAD", head.as_str()),
        ("REPLACEMENT_BASE", replacement.as_str()),
        ("OUTPUT_REPO", ""),
    ];
    let pushed = |repo: &'static str| {
        let mut args = vec![
            "--pull-request",
            "42",
            "--head",
            head.as_str(),
            "--output-repo",
        ];
        args.push(repo);
        args
    };
    let with = |extra: &[(&'static str, &'static str)]| {
        let mut env = push.to_vec();
        env.extend_from_slice(extra);
        env
    };
    let item = [("ITEM_REPO", "o/tracker")];
    // (apply-environment, issue, other inputs, the policy command's
    // arguments after --max-outputs, or the refusal)
    type Case<'a> = (
        &'a str,
        &'a str,
        Vec<(&'a str, &'a str)>,
        Result<Vec<&'a str>, &'a str>,
    );
    let cases: Vec<Case> = vec![
        ("", "", vec![], Ok(vec!["--job-token"])),
        ("", "64", vec![], Ok(vec!["--job-token"])),
        ("apply", "64", vec![], Ok(vec![])),
        ("apply", "0", vec![], Err("issue is not a number")),
        ("apply", "64 ", vec![], Err("issue is not a number")),
        (
            "apply",
            "owner/repo#64",
            vec![],
            Err("issue is not a number"),
        ),
        ("apply", "$(exit 0)", vec![], Err("issue is not a number")),
        // A push names where apply applies it, for the binary to refuse
        // any repository but the run's: the calling one by default.
        ("apply", "", with(&[]), Ok(pushed("o/r"))),
        (
            "",
            "",
            with(&[]),
            Ok([pushed("o/r"), vec!["--job-token"]].concat()),
        ),
        (
            "apply",
            "",
            with(&[("OUTPUT_REPO", "x/y")]),
            Ok(pushed("x/y")),
        ),
        // The binary holds an item's repository to the bounds; an event's
        // item is the caller's, and a review's or a push's pull request
        // the target's.
        (
            "apply",
            "64",
            item.to_vec(),
            Ok(vec!["--item-repo", "o/tracker"]),
        ),
        (
            "apply",
            "",
            [&item[..], &[("EVENT", "true")]].concat(),
            Err("item-repo is not for an event-triggered run"),
        ),
        (
            "apply",
            "",
            [&item[..], &[("REVIEW_ITEM", "42")]].concat(),
            Err("item-repo is not for a review or a push"),
        ),
        (
            "apply",
            "",
            [&item[..], &[("REVIEW", "true")]].concat(),
            Err("item-repo is not for a review or a push"),
        ),
        (
            "apply",
            "",
            with(&item),
            Err("item-repo is not for a review or a push"),
        ),
    ];
    for (environment, issue, extra, wanted) in cases {
        let mut env = vec![
            ("KIND", "implement"),
            ("MAX_OUTPUTS", "3"),
            ("APPLY_ENVIRONMENT", environment),
            ("ISSUE", issue),
            (
                "FAKE_SAFE_OUTPUTS",
                r#"{"push_to_pull_request_branch": {}}"#,
            ),
        ];
        env.extend_from_slice(&extra);
        let (output, dir) = request(&env);
        let case = format!("{environment:?} {issue:?} {extra:?}: {output:?}");
        let args = match wanted {
            Err(refusal) => {
                assert_eq!(output.status.code(), Some(1), "{case}");
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(stdout.contains(&format!("::error::{refusal}")), "{case}");
                continue;
            }
            Ok(args) => args,
        };
        assert!(output.status.success(), "{case}");
        let policy: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("policy.json")).unwrap())
                .unwrap();
        let given: Vec<&str> = policy["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect();
        let at = given
            .iter()
            .position(|arg| *arg == "--max-outputs")
            .unwrap();
        assert_eq!(given[at + 2..], args, "{case}");
        if extra.iter().any(|(key, _)| *key == "PUSH_ITEM") {
            assert_eq!(
                policy["safe_outputs"]["push_to_pull_request_branch"]["replacement_base"],
                replacement.as_str(),
                "{case}"
            );
        }
        let written = std::fs::read_to_string(dir.path().join("output")).unwrap();
        assert!(
            written.lines().any(|line| line == format!("issue={issue}")),
            "{case}"
        );
    }
}

/// An event's item is in the calling repository; with outputs going to
/// another one, check and apply would hide a comment, or act on a review
/// thread, of that number there, an item the event was not about.
#[test]
fn review_thread_types_are_refused_for_an_events_item_elsewhere() {
    for kind in [
        "hide_comment",
        "create_pull_request_review_comment",
        "reply_to_pull_request_review_comment",
        "resolve_pull_request_review_thread",
    ] {
        let safe = format!(r#"{{"noop": {{"max": 1}}, "{kind}": {{"max": 1}}}}"#);
        for (extra, success) in [
            (&[][..], true),
            (&[("EVENT", "true")], true),
            (&[("EVENT", "true"), ("OUTPUT_REPO", "O/R")], true),
            (&[("OUTPUT_REPO", "x/y")], true),
            (&[("EVENT", "true"), ("OUTPUT_REPO", "x/y")], false),
        ] {
            let mut env = vec![
                ("KIND", "analysis"),
                ("MAX_OUTPUTS", "1"),
                ("APPLY_ENVIRONMENT", "apply"),
                ("FAKE_SAFE_OUTPUTS", safe.as_str()),
            ];
            env.extend_from_slice(extra);
            let (output, _dir) = request(&env);
            assert_eq!(
                output.status.success(),
                success,
                "{kind} {extra:?}: {output:?}"
            );
            if !success {
                let refusal = format!(
                    "::error::{kind} is for an event-triggered run only when output-repo is the calling repository"
                );
                assert!(
                    String::from_utf8_lossy(&output.stdout).contains(&refusal),
                    "{kind} {extra:?}: {output:?}"
                );
            }
        }
    }
}

/// A value of a GitHub Actions expression.
#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Null,
    Bool(bool),
    Text(String),
}

impl Expr {
    fn text(value: &str) -> Self {
        Self::Text(value.to_owned())
    }

    fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(value) => *value,
            Self::Text(text) => !text.is_empty(),
        }
    }

    /// The string GitHub makes of it for an output or an input.
    fn render(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Bool(value) => value.to_string(),
            Self::Text(text) => text.clone(),
        }
    }
}

/// Evaluates `expression`, of literals, context paths, `!`, `==`, `!=`,
/// `&&`, `||` and parentheses, with each path's value from `context`
/// (null if it is not there). As GitHub's do, strings compare without
/// regard to case, and `&&` and `||` yield an operand. Null equals only
/// null and the empty string, and other values of different types are
/// unequal: GitHub compares those as numbers, which comes to the same for
/// the booleans and non-numeric strings compared here.
fn evaluate(expression: &str, context: &[(&str, Expr)]) -> Expr {
    let token = Regex::new(r"^\s*('[^']*'|[!=]=|&&|\|\||[!()]|[A-Za-z_][\w.-]*)").unwrap();
    let mut tokens = Vec::new();
    let mut rest = expression;
    while !rest.trim().is_empty() {
        let found = token
            .captures(rest)
            .unwrap_or_else(|| panic!("cannot read {rest:?} of {expression:?}"));
        tokens.push(found.get(1).unwrap().as_str());
        rest = &rest[found.get(0).unwrap().end()..];
    }
    let mut parser = Parser {
        tokens,
        at: 0,
        context,
    };
    let value = parser.or();
    assert_eq!(parser.at, parser.tokens.len(), "{expression:?}");
    value
}

struct Parser<'a> {
    tokens: Vec<&'a str>,
    at: usize,
    context: &'a [(&'a str, Expr)],
}

impl Parser<'_> {
    fn eat(&mut self, token: &str) -> bool {
        let found = self.tokens.get(self.at) == Some(&token);
        self.at += usize::from(found);
        found
    }

    fn or(&mut self) -> Expr {
        let mut left = self.and();
        while self.eat("||") {
            let right = self.and();
            if !left.truthy() {
                left = right;
            }
        }
        left
    }

    fn and(&mut self) -> Expr {
        let mut left = self.equality();
        while self.eat("&&") {
            let right = self.equality();
            if left.truthy() {
                left = right;
            }
        }
        left
    }

    fn equality(&mut self) -> Expr {
        let mut left = self.not();
        loop {
            let equal = if self.eat("==") {
                true
            } else if self.eat("!=") {
                false
            } else {
                return left;
            };
            let right = self.not();
            let same = match (&left, &right) {
                (Expr::Text(a), Expr::Text(b)) => a.eq_ignore_ascii_case(b),
                (Expr::Null, Expr::Text(text)) | (Expr::Text(text), Expr::Null) => text.is_empty(),
                (a, b) => a == b,
            };
            left = Expr::Bool(same == equal);
        }
    }

    fn not(&mut self) -> Expr {
        if self.eat("!") {
            Expr::Bool(!self.not().truthy())
        } else {
            self.primary()
        }
    }

    fn primary(&mut self) -> Expr {
        let token = *self
            .tokens
            .get(self.at)
            .unwrap_or_else(|| panic!("{:?} ends early", self.tokens));
        self.at += 1;
        match token {
            "(" => {
                let value = self.or();
                assert!(self.eat(")"), "unclosed ( in {:?}", self.tokens);
                value
            }
            "true" => Expr::Bool(true),
            "false" => Expr::Bool(false),
            "null" => Expr::Null,
            _ if token.starts_with('\'') => Expr::text(&token[1..token.len() - 1]),
            _ => {
                assert!(
                    token.starts_with(|c: char| c.is_ascii_alphabetic()),
                    "{token:?} in {:?}",
                    self.tokens
                );
                self.context
                    .iter()
                    .find(|(path, _)| *path == token)
                    .map_or(Expr::Null, |(_, value)| value.clone())
            }
        }
    }
}

/// The expression of a value that is one `${{ ... }}`.
fn expression(value: &yaml_rust2::Yaml) -> &str {
    let text = value.as_str().unwrap();
    text.strip_prefix("${{ ")
        .and_then(|text| text.strip_suffix(" }}"))
        .unwrap_or_else(|| panic!("not one expression: {text:?}"))
}

/// Runs git in `dir`, without the user's or the system's configuration.
fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// ci.yml's jobs under each gate of its changes job: `full` is false only
/// on a push of a commit a merge group passed; `host` and `e2e` also
/// defer their jobs from a pull request to the queue.
const GATES: &[(&str, &[&str])] = &[
    (
        "full",
        &[
            "lint",
            "javascript",
            "rust",
            "vibe",
            "claude-acp",
            "corpus",
            "publication",
            "static",
            "confined",
            "confined-cleanup",
        ],
    ),
    (
        "host",
        &[
            "sandbox",
            "secure-host",
            "secure-host-options",
            "world-write",
            "world-write-runtime",
            "secure-host-image",
            "secure-host-write-policy",
        ],
    ),
    (
        "e2e",
        &[
            "proposals",
            "e2e-proposals",
            "e2e-deterministic",
            "e2e-scratch",
            "e2e-full",
            "e2e-limit",
            "e2e-write-policy",
            "e2e-event",
            "e2e-analysis",
            "e2e-analysis-refused",
            "e2e-secondary",
            "e2e-secondary-refused",
            "e2e-people",
            "e2e-items-scratch",
            "e2e-items",
            "e2e-threads-scratch",
            "e2e-threads",
            "e2e-check-run",
            "e2e-review",
            "e2e-dispatch",
            "e2e-compose",
            "e2e-dispatch-verify",
            "e2e-verify",
        ],
    ),
];

fn gated(gate: &str) -> &'static [&'static str] {
    GATES.iter().find(|(name, _)| *name == gate).unwrap().1
}

/// The gates skip what a queue tested and run everything otherwise: a pull
/// request with a queue defers the host and end-to-end jobs to it, a
/// fork's without one cannot run the end-to-end jobs and must fail, and a
/// push skips only what its merge group passed.
#[test]
fn ci_gates_skip_what_a_queue_tested_and_run_everything_otherwise() {
    let doc = definition("ci.yml");
    let outputs = &doc["jobs"]["changes"]["outputs"];
    for event in ["pull_request", "merge_group", "push"] {
        let pull = event == "pull_request";
        let runs: &[&str] = if event == "push" {
            &["true", "false"]
        } else {
            &[""]
        };
        for (queue, fork, paths, passed) in ["true", "false"].into_iter().flat_map(|queue| {
            [true, false].into_iter().flat_map(move |fork| {
                ["true", "false"].into_iter().flat_map(move |paths| {
                    runs.iter().map(move |passed| (queue, fork, paths, *passed))
                })
            })
        }) {
            let mut context = vec![
                ("github.event_name", Expr::text(event)),
                ("github.repository", Expr::text("owner/repo")),
                ("steps.paths.outputs.e2e", Expr::text(paths)),
            ];
            if pull {
                let head = if fork { "fork/repo" } else { "owner/repo" };
                context.push((
                    "github.event.pull_request.head.repo.full_name",
                    Expr::text(head),
                ));
                context.push(("steps.queue.outputs.enabled", Expr::text(queue)));
            }
            if !passed.is_empty() {
                context.push(("steps.queued.outputs.passed", Expr::text(passed)));
            }
            let tested = passed == "true";
            let deferred = pull && queue == "true";
            let unavailable = pull && fork;
            let e2e = if tested || deferred || unavailable {
                "false"
            } else {
                paths
            };
            let fork_e2e = unavailable && !deferred && paths != "false";
            for (key, wanted) in [
                ("full", (!tested).to_string()),
                ("host", (!tested && !deferred).to_string()),
                ("e2e", e2e.to_owned()),
                ("fork-e2e", fork_e2e.to_string()),
            ] {
                let value = evaluate(expression(&outputs[key]), &context).render();
                assert_eq!(
                    value, wanted,
                    "{key}: {event} queue={queue} fork={fork} paths={paths} passed={passed:?}"
                );
            }
        }
    }
}

/// Every ci.yml job that can write runs only under the end-to-end gate,
/// which is false for a fork's pull request and with a queue, or only
/// on a push to main: never with a pull request's code before the queue.
#[test]
fn privileged_ci_jobs_run_only_under_the_e2e_gate_or_on_push() {
    let doc = definition("ci.yml");
    let gate = Regex::new(
        r"^\$\{\{ (always\(\) && )?needs\.changes\.outputs\.e2e == 'true'( && [^|\n]*)? \}\}$",
    )
    .unwrap();
    // What a job without permissions of its own gets.
    let default = doc["permissions"].as_hash().unwrap();
    assert!(
        default
            .values()
            .all(|access| access.as_str() == Some("read")),
        "{default:?}"
    );
    let mut privileged = 0;
    for (name, job) in doc["jobs"].as_hash().unwrap() {
        let permissions = &job["permissions"];
        let writes = permissions.as_str() == Some("write-all")
            || permissions.as_hash().is_some_and(|granted| {
                granted
                    .values()
                    .any(|access| access.as_str() == Some("write"))
            });
        if !writes {
            continue;
        }
        privileged += 1;
        let condition = job["if"].as_str().unwrap_or_default();
        let e2e = gated("e2e").contains(&name.as_str().unwrap()) && gate.is_match(condition);
        assert!(
            e2e || condition == "${{ github.event_name == 'push' }}",
            "{name:?}: {condition}"
        );
    }
    assert!(privileged >= 10, "{privileged}");
}

/// A job may be skipped only under its own gate, and only when that gate
/// said "false"; anything else but success fails the aggregate. Every
/// job but the sentinels, the push-only one and forgejo is aggregated,
/// under exactly one gate.
#[test]
fn the_aggregate_accepts_a_skip_only_under_a_gate_that_said_false() {
    use serde_json::{Map, Value, json};
    fn skipped<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<(&'a str, &'a str)> {
        names.into_iter().map(|name| (name, "skipped")).collect()
    }
    let doc = definition("ci.yml");
    let mut all: Vec<&str> = doc["jobs"]
        .as_hash()
        .unwrap()
        .keys()
        .map(|name| name.as_str().unwrap())
        .filter(|name| {
            !["required-checks", "ci", "secure-host-published", "forgejo"].contains(name)
        })
        .collect();
    all.sort_unstable();
    let mut needs: Vec<&str> = doc["jobs"]["required-checks"]["needs"]
        .as_vec()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    needs.sort_unstable();
    assert_eq!(needs, all);
    let mut under: Vec<&str> = GATES
        .iter()
        .flat_map(|(_, jobs)| jobs.iter().copied())
        .chain(["changes"])
        .collect();
    under.sort_unstable();
    assert_eq!(under, all);
    for (gate, names) in GATES {
        let condition = Regex::new(&format!(
            r"^\$\{{\{{ (always\(\) && )?needs\.changes\.outputs\.{gate} == 'true'( && .*)? \}}\}}$"
        ))
        .unwrap();
        for name in *names {
            let job = &doc["jobs"][*name];
            let condition_text = job["if"].as_str().unwrap_or_default();
            assert!(
                condition.is_match(condition_text),
                "{name}: {condition_text}"
            );
            let needs = job["needs"]
                .as_vec()
                .map_or_else(|| vec![&job["needs"]], |needs| needs.iter().collect());
            assert!(
                needs.iter().any(|need| need.as_str() == Some("changes")),
                "{name}"
            );
        }
    }
    let filter = named_step(&doc, "Every job succeeded")["env"]["FILTER"]
        .as_str()
        .unwrap()
        .to_owned();
    let dir = tempfile::tempdir().unwrap();
    // Whether the aggregate passes with every job's result success but
    // those of `results`, under the gates' outputs with `change`.
    let run = |results: &[(&str, &str)], change: &[(&str, &str)]| {
        let needs: Map<String, Value> = all
            .iter()
            .map(|name| {
                let result = results
                    .iter()
                    .find(|(key, _)| key == name)
                    .map_or("success", |(_, result)| *result);
                ((*name).to_owned(), json!({ "result": result }))
            })
            .collect();
        let needs = Value::Object(needs).to_string();
        let mut env = vec![
            ("FULL", "true"),
            ("HOST", "true"),
            ("E2E", "true"),
            ("REVIEW", "true"),
            ("FORK_E2E", "false"),
            ("EVENT", "pull_request"),
            ("FILTER", filter.as_str()),
            ("NEEDS", needs.as_str()),
        ];
        env.extend_from_slice(change);
        run_step("ci.yml", "Every job succeeded", dir.path(), &env)
            .status
            .success()
    };
    let push = [
        ("FULL", "false"),
        ("HOST", "false"),
        ("E2E", "false"),
        ("REVIEW", ""),
        ("EVENT", "push"),
    ];
    let queued_pr = [("HOST", "false"), ("E2E", "false"), ("REVIEW", "false")];
    let group = ("EVENT", "merge_group");
    let (full, host, e2e) = (gated("full"), gated("host"), gated("e2e"));
    // (case, results other than success, gate outputs, whether it passes)
    type Case<'a> = (
        &'a str,
        Vec<(&'a str, &'a str)>,
        &'a [(&'a str, &'a str)],
        bool,
    );
    let cases: [Case; 14] = [
        ("everything ran", vec![], &[], true),
        (
            "push the queue passed",
            skipped([full, host, e2e].concat()),
            &push,
            true,
        ),
        (
            "PR with a queue",
            skipped([host, e2e].concat()),
            &queued_pr,
            true,
        ),
        (
            "docs-only merge group",
            skipped(e2e.iter().copied()),
            &[("E2E", "false"), ("REVIEW", ""), group],
            true,
        ),
        (
            "merge group skips review",
            skipped(["e2e-review"]),
            &[("REVIEW", ""), group],
            true,
        ),
        (
            "review not installed on base",
            skipped(["e2e-review"]),
            &[("REVIEW", "false")],
            true,
        ),
        (
            "review installed but skipped",
            skipped(["e2e-review"]),
            &[],
            false,
        ),
        (
            "a push skips the check run",
            skipped(["e2e-check-run"]),
            &[("EVENT", "push")],
            true,
        ),
        (
            "a pull request skips the check run",
            skipped(["e2e-check-run"]),
            &[],
            false,
        ),
        ("changes skipped", skipped(["changes"]), &push, false),
        (
            "host skipped on a merge group",
            skipped(["sandbox"]),
            &[("E2E", "false"), group],
            false,
        ),
        (
            "light job skipped on a PR with a queue",
            skipped(["rust"]),
            &queued_pr,
            false,
        ),
        (
            "e2e skipped with host off",
            skipped(["e2e-full"]),
            &[("HOST", "false")],
            false,
        ),
        (
            "fork without a queue",
            skipped(e2e.iter().copied()),
            &[("E2E", "false"), ("FORK_E2E", "true")],
            false,
        ),
    ];
    for (name, results, change, success) in cases {
        assert_eq!(run(&results, change), success, "{name}");
    }
    // Each job may be skipped under its own gate, and under no other.
    let off: [(&str, &[(&str, &str)]); 3] = [
        ("full", &push),
        ("host", &[("HOST", "false")]),
        ("e2e", &[("E2E", "false")]),
    ];
    for (gate, names) in GATES {
        for name in *names {
            for (other, change) in off {
                if other == *gate {
                    assert!(run(&skipped([*name]), change), "{name} under {gate}");
                } else if other != "full" {
                    assert!(!run(&skipped([*name]), change), "{name} under {other}");
                }
            }
        }
    }
    for value in ["true", "", "unknown"] {
        for (gate, variable) in [("full", "FULL"), ("host", "HOST"), ("e2e", "E2E")] {
            let results = skipped(gated(gate).iter().copied());
            assert!(!run(&results, &[(variable, value)]), "{variable}={value:?}");
        }
        assert!(!run(&[], &[("FORK_E2E", value)]), "FORK_E2E={value:?}");
    }
    for name in &all {
        for result in ["failure", "cancelled"] {
            assert!(!run(&[(name, result)], &push), "{name} {result}");
        }
    }
}

/// Runs ci.yml's step `id` with a `gh` that logs its arguments and prints
/// `answer`, or fails without one: what the step wrote to GITHUB_OUTPUT
/// and gh's arguments, or None if the step failed.
fn changes_step(id: &str, env: &[(&str, &str)], answer: Option<&str>) -> Option<(String, String)> {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    executable(
        &bin.join("gh"),
        "#!/bin/sh\necho \"$*\" >> \"$0.args\"\n[ -e \"$0.json\" ] && exec cat \"$0.json\"\nexit 1\n",
    );
    // No waiting between attempts.
    executable(&bin.join("sleep"), "#!/bin/sh\n");
    if let Some(answer) = answer {
        std::fs::write(bin.join("gh.json"), answer).unwrap();
    }
    let output = dir.path().join("output");
    std::fs::write(&output, "").unwrap();
    let search = format!("{}:/usr/local/bin:/usr/bin:/bin", path(&bin));
    let mut all = vec![
        ("PATH", search.as_str()),
        ("GITHUB_OUTPUT", path(&output)),
        ("GITHUB_REPOSITORY", "owner/repo"),
    ];
    all.extend_from_slice(env);
    let result = run_step("ci.yml", id, dir.path(), &all);
    let args = std::fs::read_to_string(bin.join("gh.args")).unwrap_or_default();
    result
        .status
        .success()
        .then(|| (std::fs::read_to_string(&output).unwrap(), args))
}

/// A push skips only a commit whose successful merge group run was built
/// on the commit main was at; any other answer runs everything, and one
/// the step cannot read, an API failure included, fails the gate.
#[test]
fn a_push_skips_only_a_commit_whose_merge_group_run_passed() {
    use serde_json::{Value, json};
    let sha = "a".repeat(40);
    let before = "c".repeat(40);
    let group = json!({"head_sha": sha, "event": "merge_group", "conclusion": "success",
        "head_branch": format!("gh-readonly-queue/main/pr-7-{before}")});
    let with = |change: Value| {
        let mut run = group.clone();
        for (key, value) in change.as_object().unwrap() {
            run[key] = value.clone();
        }
        run
    };
    let runs = |runs: Vec<Value>| Some(json!({ "workflow_runs": runs }).to_string());
    let other = "b".repeat(40);
    let zeros = "0".repeat(40);
    let upper = "C".repeat(40);
    let passed = Some("passed=true\n");
    let not = Some("passed=false\n");
    // (the API's answer, the commit before the push, the output or None)
    let cases: Vec<(Option<String>, &str, Option<&str>)> = vec![
        (runs(vec![group.clone()]), &before, passed),
        (
            runs(vec![with(json!({ "head_sha": other })), group.clone()]),
            &before,
            passed,
        ),
        // The filters are the API's; what comes back is checked all the same.
        (runs(vec![with(json!({ "head_sha": other }))]), &before, not),
        (runs(vec![with(json!({"event": "push"}))]), &before, not),
        (
            runs(vec![with(json!({"conclusion": "failure"}))]),
            &before,
            not,
        ),
        (
            runs(vec![with(json!({ "conclusion": null }))]),
            &before,
            not,
        ),
        // A group built on another commit, as when one push lands two groups.
        (
            runs(vec![with(
                json!({"head_branch": format!("gh-readonly-queue/main/pr-7-{}", "d".repeat(40))}),
            )]),
            &before,
            not,
        ),
        (
            runs(vec![with(json!({"head_branch": format!("main-{before}")}))]),
            &before,
            not,
        ),
        (runs(vec![]), &before, not),
        (
            runs(vec![with(json!({ "head_branch": null }))]),
            &before,
            None,
        ),
        // A new branch's before is all zeros, which no queue branch is built on.
        (runs(vec![group.clone()]), &zeros, not),
        (
            runs(vec![with(
                json!({"head_branch": format!("gh-readonly-queue/main/pr-7-{upper}")}),
            )]),
            &upper,
            not,
        ),
        (
            runs(vec![with(
                json!({"head_branch": "gh-readonly-queue/main/pr-7-"}),
            )]),
            "",
            not,
        ),
        // An API failure, after its retries, fails the gate.
        (None, &before, None),
        (Some("{}".to_owned()), &before, None),
    ];
    for (answer, before, wanted) in cases {
        let result = changes_step(
            "queued",
            &[("GITHUB_SHA", &sha), ("BEFORE", before)],
            answer.as_deref(),
        );
        let case = format!("{answer:?} {before:?}");
        assert_eq!(
            result.as_ref().map(|(output, _)| output.as_str()),
            wanted,
            "{case}"
        );
        if let Some((_, args)) = result {
            assert_eq!(
                args,
                format!(
                    "api repos/owner/repo/actions/workflows/ci.yml/runs?head_sha={sha}&event=merge_group&status=success&per_page=10\n"
                ),
                "{case}"
            );
        }
    }
}

/// Queue detection reads the branch's effective rules, and publishes
/// nothing it cannot read; the sentinel the ruleset requires passes only
/// on the aggregate's success.
#[test]
fn queue_detection_fails_closed_and_the_sentinel_takes_only_success() {
    use serde_json::json;
    for (rules, enabled) in [
        (json!([]), false),
        (json!([{"type": "merge_queue"}]), true),
        (json!([{"type": "required_status_checks"}]), false),
    ] {
        let pages = json!([[{"type": "deletion"}], rules]).to_string();
        let (output, args) = changes_step("queue", &[("BRANCH", "main")], Some(&pages)).unwrap();
        assert_eq!(
            args,
            "api --paginate --slurp repos/owner/repo/rules/branches/main\n"
        );
        assert_eq!(output, format!("enabled={enabled}\n"));
    }
    let (_, args) = changes_step("queue", &[("BRANCH", "release/1#x")], Some("[[]]")).unwrap();
    assert_eq!(
        args,
        "api --paginate --slurp repos/owner/repo/rules/branches/release%2F1%23x\n"
    );
    for answer in [None, Some("\"text\""), Some("[\"text\"]")] {
        assert_eq!(
            changes_step("queue", &[("BRANCH", "main")], answer),
            None,
            "{answer:?}"
        );
    }
    let doc = definition("ci.yml");
    let sentinel = doc["jobs"]["ci"]["steps"][0]["run"].as_str().unwrap();
    for result in ["success", "failure", "cancelled", "skipped", ""] {
        let status = Command::new("bash")
            .args(["-c", sentinel])
            .env("RESULT", result)
            .status()
            .unwrap();
        assert_eq!(status.success(), result == "success", "{result:?}");
    }
}

/// A merge group's analysis runs against its branch's name, which the
/// step takes only from a branch ref.
#[test]
fn merge_group_analysis_uses_a_branch_name_not_a_qualified_ref() {
    let branch = |reference: &str| {
        changes_step("merge-base", &[("REF", reference)], None).map(|(output, _)| output)
    };
    assert_eq!(
        branch("refs/heads/gh-readonly-queue/main/pr-123-abcd").as_deref(),
        Some("branch=gh-readonly-queue/main/pr-123-abcd\n")
    );
    for reference in ["refs/tags/main", "refs/heads/", "refs/heads/a\nb=c", ""] {
        assert_eq!(branch(reference), None, "{reference:?}");
    }
    let ci = workflow("ci.yml");
    assert_eq!(
        ci.matches("base: ${{ github.head_ref || needs.changes.outputs.analysis-base || 'main' }}")
            .count(),
        2
    );
}

/// The review gate reads the review files from the pull request's base,
/// whatever its head has, and fails rather than skip the review when the
/// base is not there.
#[test]
fn review_bootstrap_reads_trusted_base_files() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    let files = [
        "workflow/review.md",
        "workflow/review.toml",
        ".github/agentic-job/e2e/review.sh",
    ];
    let mut commits = 0;
    let mut commit = |names: &[&str]| {
        git(&repo, &["rm", "-rqf", "--ignore-unmatch", "."]);
        for name in names {
            let file = repo.join(name);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, "x").unwrap();
        }
        commits += 1;
        std::fs::write(repo.join("code.rs"), commits.to_string()).unwrap();
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-qm", "commit"]);
        git(&repo, &["rev-parse", "HEAD"])
    };
    let output = dir.path().join("output");
    let review = |base: &str| {
        std::fs::write(&output, "").unwrap();
        run_step(
            "ci.yml",
            "review",
            &repo,
            &[("BASE", base), ("GITHUB_OUTPUT", path(&output))],
        )
    };
    let installed = |base: &str| {
        let result = review(base);
        assert!(result.status.success(), "{result:?}");
        std::fs::read_to_string(&output).unwrap().trim().to_owned()
    };
    let base = commit(&files);
    for missing in files {
        let rest: Vec<&str> = files.into_iter().filter(|name| *name != missing).collect();
        assert_eq!(installed(&commit(&rest)), "installed=false", "{missing}");
    }
    let nested = commit(&["workflow/review.md/nested", files[1], files[2]]);
    assert_eq!(installed(&nested), "installed=false");
    // The base's files, whatever the checked-out head has.
    commit(&[]);
    assert_eq!(installed(&base), "installed=true");
    for missing in ["b".repeat(40), String::new()] {
        assert!(!review(&missing).status.success(), "{missing:?}");
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "");
    }
}

/// The changes job's path classifier, on real Git paths: only README.md
/// and Markdown under docs/ skip the end-to-end jobs, and a name it cannot
/// read, a base it cannot use or a rename runs them. It runs nothing of
/// the pull request's.
#[test]
fn the_path_classifier_reads_real_git_paths_without_running_them() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    std::fs::write(repo.join("code.rs"), "code").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "base"]);
    let base = git(&repo, &["rev-parse", "HEAD"]);
    let output = dir.path().join("output");
    let classify = |head: &str, event: &str, before: &str| {
        std::fs::write(&output, "").unwrap();
        let result = run_step(
            "ci.yml",
            "paths",
            &repo,
            &[
                ("BASE", before),
                ("HEAD", head),
                ("GITHUB_EVENT_NAME", event),
                ("RUNNER_TEMP", path(dir.path())),
                ("GITHUB_OUTPUT", path(&output)),
            ],
        );
        assert!(result.status.success(), "{result:?}");
        std::fs::read_to_string(&output).unwrap().trim().to_owned()
    };
    for (name, e2e) in [
        ("README.md", false),
        ("docs/page.md", false),
        ("docs/nested/page.md", false),
        ("workflow/ci-paths.cjs", true),
        ("docs/line\nbreak.md", true),
        ("docs/file.sh", true),
    ] {
        git(&repo, &["reset", "-q", "--hard", &base]);
        let file = repo.join(name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, "e2e=false").unwrap();
        git(&repo, &["add", name]);
        git(&repo, &["commit", "-qm", "change"]);
        let head = git(&repo, &["rev-parse", "HEAD"]);
        for event in ["pull_request", "push", "merge_group"] {
            assert_eq!(
                classify(&head, event, &base),
                format!("e2e={e2e}"),
                "{name:?} {event}"
            );
        }
    }
    assert_eq!(classify(&base, "pull_request", &base), "e2e=true");
    for before in ["0".repeat(40), "--output=bad".to_owned()] {
        assert_eq!(classify(&base, "push", &before), "e2e=true", "{before}");
    }
    git(&repo, &["reset", "-q", "--hard", &base]);
    std::fs::create_dir(repo.join("docs")).unwrap();
    git(&repo, &["mv", "code.rs", "docs/code.md"]);
    git(&repo, &["commit", "-qm", "rename"]);
    let head = git(&repo, &["rev-parse", "HEAD"]);
    assert_eq!(classify(&head, "pull_request", &base), "e2e=true");
}

/// The shared workflow check runs only on a plain OWNER/REPO@COMMIT, with
/// a just new enough for the shared Justfile's cache_directory() (1.23).
#[test]
fn the_shared_workflow_check_takes_only_a_repository_at_a_commit() {
    let ci = workflow("ci.yml");
    let minor: u32 = Regex::new(r"\n {8}if: \$\{\{ vars\.WORKFLOW_LINT != '' \}\}\n {8}uses: taiki-e/install-action@[0-9a-f]{40} # v[\d.]+\n {8}with:\n {10}tool: just@1\.(\d+)\.\d+\n")
        .unwrap()
        .captures(job(&ci, "lint"))
        .unwrap()[1]
        .parse()
        .unwrap();
    assert!(minor >= 23, "just 1.{minor}");
    // The recipe's first check, run as just runs it, with SOURCE as $1.
    let justfile = std::fs::read_to_string(root().join("Justfile")).unwrap();
    let guard = justfile
        .split("\nworkflow-lint source:\n")
        .nth(1)
        .unwrap()
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("[["))
        .unwrap();
    let commit = "a".repeat(40);
    for (source, success) in [
        (format!("owner/repo@{commit}"), true),
        (format!("my-org/my.repo_2@{commit}"), true),
        ("owner/repo@main".to_owned(), false),
        (format!("owner/repo@{}", &commit[1..]), false),
        (format!("owner/repo@{}", commit.to_uppercase()), false),
        (format!("owner@{commit}"), false),
        (format!("owner/sub/repo@{commit}"), false),
        (format!("owner/..@{commit}"), false),
        (format!("--upload-pack=x/y@{commit}"), false),
        (format!("owner/repo@{commit}\n"), false),
        (String::new(), false),
    ] {
        let status = Command::new("bash")
            .args(["-euo", "pipefail", "-c", guard, "workflow-lint", &source])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        let code = if success { 0 } else { 2 };
        assert_eq!(status.code(), Some(code), "{source:?}");
    }
}

/// PR CI tests the ingress checker with the same verified analyzers the
/// required ingress check installs; that check has no paths filter, which
/// would leave it pending on other pull requests.
#[test]
fn pr_ci_tests_the_ingress_checker_with_its_analyzers() {
    const INSTALL: &str = "Install verified static analyzers";
    let ci = definition("ci.yml");
    let ingress = definition("workflow-ingress.yml");
    let run = named_step(&ingress, INSTALL)["run"].as_str().unwrap();
    assert!(run.contains("sha256sum -c -"), "{run}");
    assert_eq!(named_step(&ci, INSTALL), named_step(&ingress, INSTALL));
    assert!(root().join("workflow/test_ingress.py").is_file());
    for (event, trigger) in ingress["on"].as_hash().unwrap() {
        assert!(
            trigger["paths"].is_badvalue() && trigger["paths-ignore"].is_badvalue(),
            "{event:?}"
        );
    }
}

/// The runner's user is the only agent user (agentic-job#2989): every
/// input that chose stays, so a caller that names `runner` still parses,
/// and no run of this repository asks for the sandbox user.
#[test]
fn the_agent_is_the_runners_user_and_no_run_asks_for_the_sandbox_user() {
    for (file, default) in [
        (
            "agentic-job.yml",
            definition("agentic-job.yml")["on"]["workflow_call"]["inputs"]["agent-user"]["default"]
                .clone(),
        ),
        (
            "agent.yml",
            definition("agent.yml")["on"]["workflow_call"]["inputs"]["agent-user"]["default"]
                .clone(),
        ),
        (
            "run/action.yml",
            definition("run/action.yml")["inputs"]["agent-user"]["default"].clone(),
        ),
    ] {
        assert_eq!(default.as_str(), Some("runner"), "{file}");
    }
    // A caller's `sandbox` reaches agent.yml's admission, which refuses it.
    let passes = Regex::new(r"(?m)^ +agent-user: (.+)$").unwrap();
    for (file, passed) in [
        ("ci.yml", &[][..]),
        ("agent.yml", &[]),
        ("agentic-job.yml", &["${{ inputs.agent-user }}"]),
    ] {
        let text = workflow(file);
        let values: Vec<&str> = passes
            .captures_iter(&text)
            .map(|value| value.get(1).unwrap().as_str())
            .collect();
        assert_eq!(values, passed, "{file}");
    }
    assert!(
        !root().join(".github/agentic-job/e2e/sandbox.sh").exists(),
        "the sandbox user's end-to-end setup is gone"
    );
}

/// What the guard leaves out is src/apply/applied.rs's to test; this is
/// that the harness runs it again with e2e-full's settings.
#[test]
fn the_full_run_harness_runs_the_apply_guard_again_as_e2e_full_applied() {
    let doc = definition("ci.yml");
    let rerun = named_step(&doc, "Run the full run's apply guard again")["run"]
        .as_str()
        .unwrap();
    let prefix = doc["jobs"]["e2e-full"]["with"]["artifact-prefix"]
        .as_str()
        .unwrap();
    for want in [
        r#""$RUNNER_TEMP/agentic-job" applied --dir "$RUNNER_TEMP/rerun" "#,
        " --comment-target 64 ",
        &format!(" --artifact-prefix {prefix} "),
    ] {
        assert!(rerun.contains(want), "{want:?} in {rerun}");
    }
    assert!(rerun.ends_with(" --token-is-pat false\n"), "{rerun}");
}

/// apt runs bounded: after `secure-host apt` has tuned it where a binary
/// exists, and with its own network waits where none does yet.
#[test]
fn ci_apt_runs_are_tuned_and_bounded() {
    let mut operations = 0;
    for (file, tuned) in [("ci.yml", true), ("build.yml", false)] {
        let doc = definition(file);
        for (name, job) in doc["jobs"].as_hash().unwrap() {
            let steps = job["steps"].as_vec().map(Vec::as_slice).unwrap_or_default();
            for (at, step) in steps.iter().enumerate() {
                let Some(run) = step["run"]
                    .as_str()
                    .filter(|run| run.starts_with("sudo apt-get"))
                else {
                    continue;
                };
                operations += 1;
                let case = format!("{file} {name:?}: {run}");
                if tuned {
                    assert!(
                        steps[..at].iter().any(|step| step["run"].as_str()
                            == Some("sudo target/debug/agentic-job secure-host apt")),
                        "{case}"
                    );
                } else {
                    assert!(
                        run.contains("-o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 "),
                        "{case}"
                    );
                }
                assert!(run.contains("-o Acquire::Retries=3"), "{case}");
                assert_eq!(step["timeout-minutes"].as_i64(), Some(5), "{case}");
            }
        }
    }
    assert_eq!(operations, 3);
}

/// CI's world-write job runs the enforcement workflow's steps, which the
/// required aggregate then takes.
#[test]
fn ci_runs_the_world_write_enforcement_steps() {
    let enforcement = definition("world-write.yml");
    assert!(!enforcement["on"]["workflow_call"].is_badvalue());
    let ci = definition("ci.yml");
    let job = &ci["jobs"]["world-write"];
    assert_eq!(job["runs-on"].as_str(), Some("ubuntu-26.04"));
    assert_eq!(job["timeout-minutes"].as_i64(), Some(10));
    assert_eq!(job["permissions"]["contents"].as_str(), Some("read"));
    let steps: Vec<&yaml_rust2::Yaml> = enforcement["jobs"]
        .as_hash()
        .unwrap()
        .values()
        .map(|job| &job["steps"])
        .collect();
    assert_eq!(steps, [&job["steps"]]);
}

/// Confined's only local actions are the forwarder and the probe, each
/// exempted only from self-repository, and confined-cleanup looks the
/// job up by confined's own name.
#[test]
fn confined_uses_only_its_local_actions_and_cleanup_finds_it() {
    let text = workflow("ci.yml");
    let confined = job(&text, "confined");
    assert_eq!(confined.matches("uses: ./").count(), 2);
    assert_eq!(confined.matches("zizmor: ignore").count(), 2);
    let doc = definition("ci.yml");
    let name = doc["jobs"]["confined-cleanup"]["steps"][0]["env"]["NAME"].as_str();
    assert!(name.is_some());
    assert_eq!(name, doc["jobs"]["confined"]["name"].as_str());
}

/// The pinned action creates $RUNNER_TEMP/secure-host/in for its config,
/// and #2642's confined job failed with ENOTDIR when a binary staged at
/// $RUNNER_TEMP/secure-host took that path first. No workflow or action
/// of this repository may use the path, as a file or a directory; names
/// that only start with it (`secure-host-bin`, `secure-host-image`) are
/// other paths.
#[test]
fn nothing_occupies_the_actions_config_directory() {
    let taken =
        Regex::new(r"(\$RUNNER_TEMP|\$\{RUNNER_TEMP\}|runner\.temp \}\})/secure-host([^-\w.]|$)")
            .unwrap();
    let mut files: Vec<PathBuf> = std::fs::read_dir(root().join(".github/workflows"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.extend(
        [
            "secure-host",
            "prepare",
            "run",
            ".github/actions/confine-probe",
        ]
        .iter()
        .map(|dir| root().join(dir).join("action.yml")),
    );
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap();
        for (number, line) in text.lines().enumerate() {
            assert!(
                !taken.is_match(line),
                "{}:{}: $RUNNER_TEMP/secure-host is the pinned action's directory: {line}",
                path.display(),
                number + 1
            );
        }
    }
    for bad in [
        "install -m 0755 \"$RUNNER_TEMP/dist/x\" \"$RUNNER_TEMP/secure-host\"",
        "path: ${{ runner.temp }}/secure-host",
        "mkdir \"${RUNNER_TEMP}/secure-host/in\"",
    ] {
        assert!(taken.is_match(bad), "{bad}");
    }
    let text = workflow("ci.yml");
    for name in ["secure-host-options", "confined"] {
        let job = job(&text, name);
        assert!(job.contains(
            "install -m 0755 \"$RUNNER_TEMP/dist/secure-host-x86_64-unknown-linux-musl\" \"$RUNNER_TEMP/secure-host-bin\""
        ));
        assert!(job.contains("\"$RUNNER_TEMP/secure-host-bin\" "));
    }
}

/// The image's binary is secure-host's, which build.yml stages, checksums
/// and pins with the others, and which the image installs on the host
/// under both its names: CI compares both with the staged file and
/// refuses agentic-job's in its place.
#[test]
fn the_image_holds_and_installs_the_secure_host_binary() {
    let containerfile = workflow("secure-host/Containerfile");
    for line in [
        "COPY --chmod=0755 secure-host-x86_64-unknown-linux-musl /secure-host\n",
        "COPY --chmod=0755 secure-host-x86_64-unknown-linux-musl /agentic-job\n",
        "ENTRYPOINT [\"/secure-host\", \"image\"]\n",
    ] {
        assert!(containerfile.contains(line), "{line}");
    }
    assert!(!containerfile.contains("COPY --chmod=0755 agentic-job-"));
    let build = workflow("build.yml");
    assert!(build.contains("for name in agentic-job fake-agent secure-host; do\n"));
    assert!(build.contains("-p agentic-job -p secure-host\n"));
    let binary = workflow("secure-host/binary.sh");
    assert!(binary.contains("NAMES=(agentic-job fake-agent secure-host)\n"));
    let release = workflow("release.yml");
    assert!(release.contains("\"secure-host-$TARGET\" \"secure-host-$TARGET.sha256\""));
    assert!(release.contains("\"secure-host-$TARGET.sha256\"\n"));
    let ci = workflow("ci.yml");
    let image = job(&ci, "secure-host-image");
    for want in [
        "for name in secure-host agentic-job; do\n            cmp \"/usr/local/bin/$name\" \"$RUNNER_TEMP/dist/secure-host-x86_64-unknown-linux-musl\"\n",
        "if cmp -s \"$RUNNER_TEMP/dist/agentic-job-x86_64-unknown-linux-musl\" /usr/local/bin/secure-host; then",
    ] {
        assert!(image.contains(want), "{want}");
    }
}

/// Every caller, agentic-job's own jobs included, gets the new action's
/// contract, under which every step after it is the runner's user's: the
/// public secure-host forwards to the one pinned new action, and refuses
/// every input of the old one, which asked for another host.
#[test]
fn the_public_secure_host_forwards_to_the_pinned_action_and_refuses_old_inputs() {
    const ACTION: &str = "secure-host/action.yml";
    const FORWARDED: [&str; 3] = ["config", "check", "image-archive"];
    let text = workflow(ACTION);
    let doc = definition(ACTION);
    let old: Vec<&str> = doc["inputs"]
        .as_hash()
        .unwrap()
        .keys()
        .map(|name| name.as_str().unwrap())
        .filter(|name| !FORWARDED.contains(name))
        .collect();
    let mut sorted = old.clone();
    sorted.sort_unstable();
    // Each is declared, so that setting one reaches the refusal.
    assert_eq!(
        sorted,
        [
            "binary",
            "build",
            "deny-runner-metadata",
            "egress",
            "egress-policy",
            "lock",
            "runner-user",
            "sandbox-user",
            "script",
            "stop-services"
        ]
    );
    assert!(doc["outputs"].is_badvalue());
    // One pin, by commit, whose comment names the image tag that commit
    // runs. site.yml (plain CI, no forwarder) takes the same one, so this
    // repository's agent job is never secured by an older image than its
    // CI. The tag is a release of this repository, at most the workspace's
    // version: Dependabot moves the commit, and a reviewer reads the comment.
    let uses: Vec<&str> = steps(&doc)
        .into_iter()
        .filter_map(|step| step["uses"].as_str())
        .collect();
    assert_eq!(uses.len(), 1, "{uses:?}");
    let pin = Regex::new(r"(?m)^ {4,6}- uses: cgwalters-forge/actions/secure-host@[0-9a-f]{40} # main, with secure-host:v(\d+)\.(\d+)\.(\d+)$").unwrap();
    let found = pin.captures(&text).unwrap_or_else(|| panic!("{}", uses[0]));
    let line = found.get(0).unwrap().as_str();
    let site = workflow("site.yml");
    let used: Vec<&str> = pin
        .find_iter(&site)
        .map(|used| used.as_str().trim())
        .collect();
    assert_eq!(used, [line.trim()]);
    let version =
        |found: &regex::Captures| -> [u64; 3] { [1, 2, 3].map(|i| found[i].parse().unwrap()) };
    // v0.6.9 supplies accounts 30–32 in its built-in runner writes, without
    // the forwarder's former policy override, and query-free diagnostics.
    assert!(
        version(&found) >= [0, 6, 9],
        "{line} predates the required built-in runner storage rules"
    );
    let cargo = std::fs::read_to_string(root().join("Cargo.toml")).unwrap();
    let workspace = Regex::new(r#"(?m)^version = "(\d+)\.(\d+)\.(\d+)"$"#)
        .unwrap()
        .captures(&cargo)
        .unwrap();
    assert!(
        version(&found) <= version(&workspace),
        "{line} is newer than the workspace's {}",
        &workspace[0]
    );
    // The new action is last, with the selected host config (proxy on),
    // not its default, which turns it off; its trust-store step runs under
    // egress: write-policy.
    let last = [
        line,
        "\n      with:\n",
        "        config: ${{ steps.config.outputs.path }}\n",
        "        check: ${{ inputs.check }}\n",
        "        egress: ${{ steps.egress.outputs.mode }}\n",
        "        image-archive: ${{ inputs.image-archive }}\n",
    ]
    .concat();
    assert!(text.ends_with(&last), "{text}");
    // The new action overrides the file's egress.write-policy with its
    // input: a configuration that asks for it, in any key form, gets it,
    // without replacing its egress.policy or creating a policy override.
    assert!(
        steps(&doc)
            .iter()
            .all(|step| step["with"]["egress-policy"].is_badvalue())
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let output = dir.path().join("output");
    let hosted = workflow("secure-host/hosted.toml");
    let escaped =
        Regex::new(r"^::error::.* has a backslash outside a comment or a multi-line string")
            .unwrap();
    for (toml, wanted) in [
        ("", Some("off")),
        (hosted.as_str(), Some("off")),
        ("[egress]\nwrite-policy = false\n", Some("off")),
        ("[egress]\n# write-policy = true\n", Some("off")),
        ("[egress]\npolicy = \"/p.toml\"\n", Some("off")),
        ("[egress]\nwrite-policy = true\n", Some("write-policy")),
        ("[egress]\n  write-policy=true # on\n", Some("write-policy")),
        ("[egress]\n\"write-policy\" = true\n", Some("write-policy")),
        ("egress.'write-policy' = true\n", Some("write-policy")),
        (
            "egress = { proxy = true, write-policy = true }\n",
            Some("write-policy"),
        ),
        (
            "[egress]\nwrite-policy = true\n# policy = \"/p.toml\"\n",
            Some("write-policy"),
        ),
        (
            "egress = { policy = \"/etc/p#1.toml\", write-policy = true }\n",
            Some("write-policy"),
        ),
        (
            "egress = { write-policy = true, \"policy\" = '/p' }\n",
            Some("write-policy"),
        ),
        (
            "[egress]\nwrite-policy = true\npolicy=\"/p\"\n",
            Some("write-policy"),
        ),
        (
            "[egress]\nwrite-policy = true\n'policy' = \"/p\"\n",
            Some("write-policy"),
        ),
        (
            "egress.write-policy = true\negress . policy = \"/p\"\n",
            Some("write-policy"),
        ),
        (
            "[egress]\nwrite-policy = true # policy = \"/p\"\n",
            Some("write-policy"),
        ),
        ("[egress]\n# \"write\\u002dpolicy\" = true\n", Some("off")),
        // Escapes could spell the key without its characters: refused.
        ("[egress]\n\"write\\u002dpolicy\" = true\n", None),
        ("egress.\"\\u0077rite-policy\" = true\n", None),
        ("[egress]\n  \"write\\x2dpolicy\"=true\n", None),
        ("[sandbox]\nstop-services = [\"a\\\\b\"]\n", None),
        // A multi-line string can close on a line that starts with '#'.
        (
            "egress = { policy = '''/p\n#''', write-policy = true }\n",
            None,
        ),
        (
            "egress = { policy = \"\"\"/p\n#\"\"\", \"write\\u002dpolicy\" = true }\n",
            None,
        ),
    ] {
        std::fs::write(&config, toml).unwrap();
        std::fs::write(&output, "").unwrap();
        let result = run_step(
            ACTION,
            "Read whether the configuration asks for the write policy",
            dir.path(),
            &[
                ("CONFIG", path(&config)),
                ("GITHUB_OUTPUT", path(&output)),
                ("ACTION_PATH", path(&root().join("secure-host"))),
                ("RUNNER_TEMP", path(dir.path())),
            ],
        );
        let written = std::fs::read_to_string(&output).unwrap();
        match wanted {
            Some(mode) => {
                assert!(result.status.success(), "{toml:?}: {result:?}");
                assert_eq!(written, format!("mode={mode}\n"), "{toml:?}");
            }
            None => {
                assert_eq!(result.status.code(), Some(1), "{toml:?}: {result:?}");
                let stdout = String::from_utf8_lossy(&result.stdout);
                assert!(escaped.is_match(&stdout), "{toml:?}: {stdout}");
                assert_eq!(written, "", "{toml:?}");
            }
        }
        assert_eq!(std::fs::read_to_string(&config).unwrap(), toml);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }
    // The refusal, run with each old input set alone, with all of them
    // and with none.
    const REFUSE: &str = "Refuse the old action's inputs";
    let variables: Vec<(&str, &str)> = named_step(&doc, REFUSE)["env"]
        .as_hash()
        .unwrap()
        .iter()
        .map(|(key, value)| {
            let input = value
                .as_str()
                .unwrap()
                .strip_prefix("${{ inputs.")
                .and_then(|value| value.strip_suffix(" }}"))
                .unwrap();
            (input, key.as_str().unwrap())
        })
        .collect();
    let mut named: Vec<&str> = variables.iter().map(|(input, _)| *input).collect();
    named.sort_unstable();
    assert_eq!(named, sorted);
    let refuse = |set: &[&str]| {
        let env: Vec<(&str, &str)> = variables
            .iter()
            .map(|(input, variable)| (*variable, if set.contains(input) { "false" } else { "" }))
            .collect();
        run_step(ACTION, REFUSE, dir.path(), &env)
    };
    assert!(refuse(&[]).status.success());
    for name in &old {
        let result = refuse(&[name]);
        assert_eq!(result.status.code(), Some(1), "{name}: {result:?}");
        let refusal = Regex::new(&format!(
            r"^::error::.*cgwalters-forge/actions/secure-host.* not {}: ",
            regex::escape(name)
        ))
        .unwrap();
        assert!(
            refusal.is_match(&String::from_utf8_lossy(&result.stdout)),
            "{name}: {result:?}"
        );
    }
    let all = refuse(&old);
    assert!(
        String::from_utf8_lossy(&all.stdout).contains(&format!(" not {}: ", old.join(" "))),
        "{all:?}"
    );
}

/// Storage uploads belong only to the transparent listener's runner
/// policy, even when the caller supplies its own policy file.
#[test]
fn the_forwarded_policy_leaves_storage_to_the_runner_writes() {
    use secure_host::proxy::policy::{ECOSYSTEMS, Policy, Request};
    let shipped = Policy::parse(&workflow("egress/policy.toml"), ECOSYSTEMS).unwrap();
    fn request<'a>(method: &'a str, host: &'a str) -> Request<'a> {
        Request {
            method,
            host,
            path: "/actions-results/x/artifact.zip",
            has_body: true,
            ..Request::default()
        }
    }
    for policy in [shipped, Policy::parse("", ECOSYSTEMS).unwrap()] {
        let runner = policy.with_runner_writes().unwrap();
        for n in 0..200 {
            let host = format!("productionresultssa{n}.blob.core.windows.net");
            let put = request("PUT", &host);
            assert_eq!(
                runner.request(&put).allowed,
                n < 20 || (30..=32).contains(&n),
                "{host}"
            );
            assert!(!runner.request(&request("POST", &host)).allowed, "{host}");
            assert!(!policy.request(&put).allowed, "{host}");
        }
        assert!(!runner.request(&request("PUT", "example.com")).allowed);
    }
}

/// `run` refuses to upload a fake agent's run whose redaction replaced
/// nothing, and the write-capable end-to-end jobs run only in a merge
/// group when a queue is enabled: a scenario without the secret-shaped
/// string would fail first there. The whole command, since a shortened
/// token is not secret-shaped (#641).
#[test]
fn every_scripted_e2e_session_prints_the_string_run_must_redact() {
    const CANARY: &str = "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef";
    let dir = root().join(".github/agentic-job/e2e");
    let setups: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".sh"))
        .collect();
    let ci = workflow("ci.yml");
    for setup in Regex::new(r"(?m)^      setup: \.github/agentic-job/e2e/([\w-]+\.sh)$")
        .unwrap()
        .captures_iter(&ci)
    {
        assert!(setups.iter().any(|name| *name == setup[1]), "{}", &setup[1]);
    }
    assert!(setups.len() >= 9, "{setups:?}");
    for file in &setups {
        let text = std::fs::read_to_string(dir.join(file)).unwrap();
        let fixture = text
            .split("<<'JSON'\n")
            .nth(1)
            .and_then(|rest| rest.split("\nJSON").next())
            .unwrap();
        let steps: Vec<serde_json::Value> = serde_json::from_str(fixture).unwrap();
        assert!(
            steps
                .iter()
                .any(|step| step["execute"]["command"] == CANARY),
            "{file}"
        );
    }
}

/// e2e-verify's cleanup of the scratch pull request, after the run of
/// agentic-job#1430's: a cut-short first response failed the step and
/// left the fixture open. Against a gh whose calls fail by number, before
/// taking effect ("fail") or after ("lost").
#[test]
fn e2e_verify_scratch_cleanup_retries_the_api_and_fails_only_on_a_leak() {
    const STEP: &str = "Close only the scratch pull request of this run and delete its branch";
    const BRANCH: &str = "e2e-scratch/39434669318-1";
    const GH: &str = r#"#!/bin/bash
cd "$GH_STATE"
n=$(( $(cat calls) + 1 )); echo "$n" > calls
echo "$*" >> log
if grep -qx "$n" fail; then echo 'unexpected end of JSON input' >&2; exit 1; fi
case "$*" in
  'api repos/o/r/pulls/1430') printf '{"state":"%s","head":{"ref":"%s","repo":{"full_name":"o/r"}}}' "$(cat pr)" "$(cat head)" ;;
  'api repos/o/r/pulls/1430 --jq .state') cat pr ;;
  'api -X PATCH repos/o/r/pulls/1430 -f state=closed') echo closed > pr; echo '{}' ;;
  'api repos/o/r/git/matching-refs/heads/{branch} --jq .[].ref') if [ -e ref ]; then echo 'refs/heads/{branch}'; fi; echo 'refs/heads/{branch}0' ;;
  'api -X DELETE repos/o/r/git/refs/heads/{branch}') [ -e ref ] || { echo 'Reference does not exist' >&2; exit 1; }; rm ref ;;
  *) echo "unexpected call: $*" >&2; exit 2 ;;
esac
if grep -qx "$n" lost; then echo 'unexpected end of JSON input' >&2; exit 1; fi
"#;
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    executable(&bin.join("gh"), &GH.replace("{branch}", BRANCH));
    // No waiting between attempts.
    executable(&bin.join("sleep"), "#!/bin/sh\n");
    let search = format!("{}:/usr/local/bin:/usr/bin:/bin", path(&bin));
    // The step's output, the pull request's state, whether the branch is
    // left and how many calls were made.
    let run = |name: &str, fail: &[u32], lost: &[u32], head: &str| {
        let state = dir.path().join(name);
        std::fs::create_dir(&state).unwrap();
        let numbers = |list: &[u32]| {
            list.iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        };
        for (file, content) in [
            ("calls", "0".to_owned()),
            ("fail", numbers(fail)),
            ("lost", numbers(lost)),
            ("pr", "open".to_owned()),
            ("head", head.to_owned()),
            ("ref", String::new()),
        ] {
            std::fs::write(state.join(file), format!("{content}\n")).unwrap();
        }
        let output = run_step(
            "ci.yml",
            STEP,
            &state,
            &[
                ("PATH", &search),
                ("GH_STATE", path(&state)),
                ("GH_REPO", "o/r"),
                ("GITHUB_RUN_ID", "39434669318"),
                ("PEOPLE_PR", "1430"),
                ("PEOPLE_BRANCH", BRANCH),
            ],
        );
        let pr = std::fs::read_to_string(state.join("pr")).unwrap();
        let calls = std::fs::read_to_string(state.join("log"))
            .unwrap()
            .lines()
            .count();
        (
            output,
            pr.trim().to_owned(),
            state.join("ref").exists(),
            calls,
        )
    };
    // (case, calls that fail, calls whose response is lost, whether the
    // step passes, the pull request's state, whether the branch is left)
    for (name, fail, lost, success, pr, left) in [
        // The incident: the first read was cut short.
        ("first read fails", &[1][..], &[][..], true, "closed", false),
        (
            "each call fails once",
            &[1, 3, 5, 7, 9],
            &[],
            true,
            "closed",
            false,
        ),
        (
            "close and delete took effect but their responses were lost",
            &[],
            &[2, 3],
            true,
            "closed",
            false,
        ),
        (
            "close never succeeds",
            &[2, 3, 4, 5],
            &[],
            false,
            "open",
            false,
        ),
        (
            "delete never succeeds",
            &[3, 4, 5, 6],
            &[],
            false,
            "closed",
            true,
        ),
        (
            "the final reads never succeed",
            &[4, 5, 6, 7],
            &[],
            false,
            "closed",
            false,
        ),
        (
            "the first read never succeeds",
            &[1, 2, 3, 4],
            &[],
            false,
            "open",
            true,
        ),
    ] {
        let (output, state, branch, _) = run(&name.replace(' ', "-"), fail, lost, BRANCH);
        assert_eq!(
            (output.status.success(), state.as_str(), branch),
            (success, pr, left),
            "{name}: {output:?}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("unexpected call"),
            "{name}: {output:?}"
        );
        if pr == "open" && !left {
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("::error::Scratch pull request #1430 is still open"),
                "{name}: {output:?}"
            );
        }
    }
    // Another branch's pull request under this number is neither closed
    // nor its branch deleted.
    let (output, pr, left, calls) = run("other-head", &[], &[], "feature");
    assert_eq!(
        (output.status.success(), pr.as_str(), left, calls),
        (false, "open", true, 1),
        "{output:?}"
    );
}

/// What a dispatch may choose. status-comment only chooses which of the
/// status credential's own comments on the item `agentic-job status`
/// edits (docs/workflow.md says what a wrong id replaces); it grants no
/// new permission.
#[test]
fn dispatch_takes_only_task_repo_item_item_repo_kind_and_status_comment() {
    let doc = definition("dispatch.yml");
    let inputs: Vec<&str> = doc["on"]["workflow_dispatch"]["inputs"]
        .as_hash()
        .unwrap()
        .keys()
        .map(|input| input.as_str().unwrap())
        .collect();
    assert_eq!(
        inputs,
        [
            "task",
            "repo",
            "item",
            "item-repo",
            "kind",
            "status-comment"
        ]
    );
}

const FORGEJO_DISPATCH: &str = "workflow/forgejo/dispatch.yml";

/// The Forgejo caller takes agent-board's job plan as strings, names runs
/// as its in-flight listing matches them, never cancels or shares a
/// concurrency group across items, and takes runners and configuration
/// only from the caller's variables, with no credential.
#[test]
fn forgejo_dispatch_takes_agent_boards_plan() {
    let text = workflow(FORGEJO_DISPATCH);
    let doc = definition(FORGEJO_DISPATCH);
    let inputs = doc["on"]["workflow_dispatch"]["inputs"].as_hash().unwrap();
    let names: Vec<&str> = inputs.keys().map(|k| k.as_str().unwrap()).collect();
    assert_eq!(names, ["task", "repo", "item", "kind", "pool", "base"]);
    for (name, input) in inputs {
        assert_eq!(input["type"].as_str(), Some("string"), "{name:?}");
    }
    assert_eq!(
        doc["run-name"].as_str(),
        Some("${{ inputs.kind }} ${{ inputs.repo }}#${{ inputs.item }} (${{ inputs.pool }})")
    );
    let concurrency = &doc["concurrency"];
    assert_eq!(concurrency["cancel-in-progress"].as_bool(), Some(false));
    let group = concurrency["group"].as_str().unwrap();
    for part in ["inputs.kind", "inputs.repo", "inputs.item"] {
        assert!(group.contains(part), "{group}");
    }
    let jobs = doc["jobs"].as_hash().unwrap();
    for (name, job) in jobs {
        assert!(job["concurrency"].is_badvalue(), "{name:?}: own group");
        assert_eq!(
            job["runs-on"].as_str(),
            Some("${{ fromJSON(vars.AGENT_RUNNER) }}"),
            "{name:?}"
        );
    }
    for credential in ["secrets.", ".token", "TOKEN"] {
        assert!(!text.contains(credential), "{credential}");
    }
}

/// The agent job refuses first: without the caller's configuration, and
/// on a runner that cannot provide the sandbox, naming #1347.
#[test]
fn forgejo_dispatch_refuses_before_anything_runs() {
    let doc = definition(FORGEJO_DISPATCH);
    let first = &doc["jobs"]["agent"]["steps"][0];
    let script = first["run"].as_str().unwrap();
    assert!(script.contains("#1347"), "{script}");
    for (url, bounds, missing) in [
        ("", "", "FORGEJO_URL"),
        ("https://forgejo.example", "", "AGENT_BOUNDS"),
    ] {
        let output = Command::new("bash")
            .args(["-c", script])
            .env("FORGEJO_URL", url)
            .env("AGENT_BOUNDS", bounds)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!output.status.success(), "{missing}: {output:?}");
        assert!(stdout.contains(missing), "{stdout}");
    }
}

/// dispatch.yml's caller fixes each profile's capabilities, routed as the
/// runner evaluates them, and forwards only the apply token, never to a
/// scripted run.
#[test]
fn the_dispatch_caller_fixes_capabilities_and_token_boundary() {
    let text = workflow("dispatch.yml");
    let doc = definition("dispatch.yml");
    let with = &doc["jobs"]["run"]["with"];
    let routed = |input: &str, kind: &str, agent: &str| {
        let context = [
            ("inputs.kind", Expr::text(kind)),
            ("inputs.item", Expr::text("42")),
            ("needs.target.outputs.agent", Expr::text(agent)),
        ];
        evaluate(expression(&with[input]), &context).render()
    };
    for (kind, run, outputs, max, review, push, fake) in [
        (
            "implement",
            "branch",
            "create_pull_request,add_comment,noop,missing_tool,missing_data",
            "3",
            "",
            "",
            "implement",
        ),
        (
            "fix",
            "branch",
            "push_to_pull_request_branch,noop,missing_tool,missing_data",
            "3",
            "",
            "42",
            "implement",
        ),
        (
            "review",
            "analysis",
            "add_comment,noop",
            "1",
            "42",
            "",
            "review",
        ),
        // Up to the bounds' max_outputs: the closes and the comment.
        (
            "triage",
            "analysis",
            "close_issue,add_comment,noop,missing_tool,missing_data",
            "max",
            "",
            "",
            "comment",
        ),
        (
            "research",
            "analysis",
            "add_comment,noop,missing_tool,missing_data",
            "3",
            "",
            "",
            "comment",
        ),
    ] {
        let got = [
            "kind",
            "outputs",
            "max-outputs",
            "review-item",
            "push-item",
            "fake-profile",
        ]
        .map(|input| routed(input, kind, "fake"));
        assert_eq!(got, [run, outputs, max, review, push, fake], "{kind}");
        assert_eq!(routed("fake-profile", kind, "claude"), "", "{kind}");
    }
    for line in [
        "allow: .github/agentic-job/dispatch.toml",
        "comment-target: ${{ inputs.item }}",
        "issue: ${{ inputs.item }}",
        "output-repo: ${{ inputs.repo }}",
        "item-repo: ${{ inputs.item-repo }}",
        "apply-environment: ${{ !inputs.scripted && vars.APPLY_ENVIRONMENT || '' }}",
        "apply-partial: false",
        "notify: ${{ (inputs.kind == 'review' || inputs.scripted) && 'none' || 'comment' }}",
        "model: ${{ needs.target.outputs.agent != 'fake' && vars.AGENT_MODEL || '' }}",
        "inference-url: ${{ needs.target.outputs.agent != 'fake' && vars.INFERENCE_URL || '' }}",
        "inference-audience: ${{ needs.target.outputs.agent != 'fake' && vars.INFERENCE_AUDIENCE || '' }}",
        "inference-register: ${{ needs.target.outputs.agent != 'fake' && vars.INFERENCE_REGISTER || 'github-oidc' }}",
        "inference-provider: ${{ needs.target.outputs.agent != 'fake' && vars.INFERENCE_PROVIDER || '' }}",
    ] {
        assert!(text.contains(line), "{line}");
    }
    let forwarded: Vec<&str> = doc["jobs"]["run"]["secrets"]
        .as_hash()
        .unwrap()
        .keys()
        .map(|name| name.as_str().unwrap())
        .collect();
    assert_eq!(forwarded, ["SAFE_OUTPUTS_PAT"]);
    // INFERENCE_API_KEY is declared so that callers that pass it still
    // parse, but not forwarded: agentic-job.yml drops it and refuses
    // `api-key`.
    for name in ["SAFE_OUTPUTS_PAT", "INFERENCE_API_KEY"] {
        let required = &doc["on"]["workflow_call"]["secrets"][name]["required"];
        assert_eq!(required.as_bool(), Some(false), "{name}");
    }
    let token = &doc["jobs"]["run"]["secrets"]["SAFE_OUTPUTS_PAT"];
    assert_eq!(
        token.as_str(),
        Some("${{ !inputs.scripted && secrets.SAFE_OUTPUTS_PAT || '' }}")
    );
    for scripted in [false, true] {
        for value in ["", "test-value"] {
            let context = [
                ("inputs.scripted", Expr::Bool(scripted)),
                ("secrets.SAFE_OUTPUTS_PAT", Expr::text(value)),
            ];
            let wanted = if scripted { "" } else { value };
            assert_eq!(
                evaluate(expression(token), &context).render(),
                wanted,
                "{scripted} {value:?}"
            );
        }
    }
}

/// The agent configuration variables reach only opencode and vibe.
#[test]
fn agent_configuration_variables_reach_only_opencode_and_vibe() {
    for (file, agent) in [
        ("dispatch.yml", "needs.target.outputs.agent"),
        ("review.yml", "vars.AGENT"),
    ] {
        let text = workflow(file);
        for (input, variable) in [
            ("agent-config-repo", "vars.AGENT_CONFIG_REPO"),
            ("agent-config-path", "vars.AGENT_CONFIG_PATH"),
        ] {
            let found = Regex::new(&format!(r"(?m)^      {input}: \$\{{\{{ (.+) \}}\}}$"))
                .unwrap()
                .captures(&text)
                .unwrap_or_else(|| panic!("{file}: no {input}"));
            let expression = found.get(1).unwrap().as_str();
            for name in ["fake", "claude", "opencode", "vibe"] {
                for config in ["", "operator-config"] {
                    let context = [(agent, Expr::text(name)), (variable, Expr::text(config))];
                    let wanted = if ["opencode", "vibe"].contains(&name) {
                        config
                    } else {
                        ""
                    };
                    assert_eq!(
                        evaluate(expression, &context).render(),
                        wanted,
                        "{file} {input} {name}"
                    );
                }
            }
            // A dispatched review takes what its pool job decided for the
            // pool's agent, whatever AGENT is.
            if file == "review.yml" {
                let pool = format!("needs.pool.outputs.{}", &input["agent-".len()..]);
                for decided in ["", "pool-config"] {
                    let context = [
                        ("github.event_name", Expr::text("workflow_dispatch")),
                        (agent, Expr::text("opencode")),
                        (variable, Expr::text("operator-config")),
                        (pool.as_str(), Expr::text(decided)),
                    ];
                    assert_eq!(evaluate(expression, &context).render(), decided, "{input}");
                }
            }
        }
    }
}

/// review.yml reads nothing of the pull request's head but whether its
/// repository is this one, which tells a fork's pull request apart for
/// the record-only mode: not its commit, branch, label or user.
#[test]
fn the_review_caller_reads_only_whether_the_head_is_a_fork() {
    const FORK: &str = "github.event.pull_request.head.repo.full_name != github.repository";
    let text = workflow("review.yml");
    assert!(text.contains(FORK));
    assert!(!text.replace(FORK, "").contains("pull_request.head"));
}

/// A dispatched review's pool: the repository's REVIEW_POOLS alone picks
/// the agent, the model and the configuration repository, and anything
/// else, an unknown pool included, stops the run with no outputs.
#[test]
fn a_dispatched_review_maps_only_a_known_pool() {
    let review = definition("review.yml");
    let script = named_step(&review, "Map the pool to its agent and model")["run"]
        .as_str()
        .unwrap();
    let pools = serde_json::json!({
        "openai": {"agent": "opencode", "model": "praxis/gpt-6.1-sol"},
        "claude": {"agent": "claude", "model": "claude-opus-5-5", "config": "c.toml"},
        "spaced": {"agent": "opencode", "model": "m\nconfig=evil"},
        "newline": {"agent": "opencode", "model": "m\n"},
        "empty": {"agent": "opencode", "model": ""},
        "modelless": {"agent": "opencode"},
        "number": {"agent": 1, "model": "m"},
    })
    .to_string();
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("output");
    let run = |pools: &str, pool: &str| {
        std::fs::write(&output, "").unwrap();
        let status = Command::new("bash")
            .args(["-e", "-c", script])
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap())
            .env("POOLS", pools)
            .env("POOL", pool)
            .env("CONFIG_REPO", "o/config")
            .env("CONFIG_PATH", "opencode.json")
            .env("GITHUB_OUTPUT", &output)
            .output()
            .unwrap();
        (
            status.status.success(),
            std::fs::read_to_string(&output).unwrap(),
        )
    };
    assert_eq!(
        run(&pools, "openai"),
        (
            true,
            "agent=opencode\nmodel=praxis/gpt-6.1-sol\nconfig=\nconfig-repo=o/config\nconfig-path=opencode.json\n".into()
        )
    );
    assert_eq!(
        run(&pools, "claude"),
        (
            true,
            "agent=claude\nmodel=claude-opus-5-5\nconfig=c.toml\nconfig-repo=\nconfig-path=\n"
                .into()
        )
    );
    for (pools, pool) in [
        (pools.as_str(), "unknown"),
        (pools.as_str(), ""),
        (pools.as_str(), "spaced"),
        (pools.as_str(), "newline"),
        (pools.as_str(), "empty"),
        (pools.as_str(), "modelless"),
        (pools.as_str(), "number"),
        ("", "openai"),
        ("[]", "openai"),
        ("not json", "openai"),
    ] {
        assert_eq!(run(pools, pool), (false, String::new()), "{pools} {pool}");
    }
}

/// The dispatch caller's wiring: `agentic-job dispatch` decides the skills
/// output (src/dispatch.rs), every input the caller passes exists in the
/// same commit's reusable workflow, and the URL of what apply made comes
/// back out through the wrapper.
#[test]
fn the_dispatch_callers_inputs_and_outputs_are_wired() {
    let dispatch = definition("dispatch.yml");
    let with = &dispatch["jobs"]["run"]["with"];
    assert_eq!(
        with["agent-skills"].as_str(),
        Some("${{ needs.target.outputs.skills == 'true' }}")
    );
    let reusable = definition("agentic-job.yml");
    let inputs = &reusable["on"]["workflow_call"]["inputs"];
    for input in with.as_hash().unwrap().keys() {
        assert!(!inputs[input.as_str().unwrap()].is_badvalue(), "{input:?}");
    }
    let apply = definition("apply.yml");
    for (file, doc, value) in [
        ("dispatch.yml", &dispatch, "jobs.run.outputs.result-url"),
        (
            "agentic-job.yml",
            &reusable,
            "jobs.apply.outputs.result-url",
        ),
        ("apply.yml", &apply, "jobs.apply.outputs.result-url"),
    ] {
        let output = &doc["on"]["workflow_call"]["outputs"]["result-url"];
        assert!(
            output["description"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "{file}"
        );
        assert_eq!(
            output["value"].as_str(),
            Some(format!("${{{{ {value} }}}}").as_str()),
            "{file}"
        );
    }
    assert_eq!(
        apply["jobs"]["apply"]["outputs"]["result-url"].as_str(),
        Some("${{ steps.result.outputs.result-url }}")
    );
}

/// CI's dispatch and compose calls are scripted, which gives each run a
/// concurrency group of its own, and the hosted agent job's bound retries
/// a 5xx in listing the run's jobs rather than failing ci.
#[test]
fn ci_calls_dispatch_and_compose_scripted() {
    let ci = definition("ci.yml");
    for (job, file) in [
        ("e2e-dispatch", "dispatch"),
        ("e2e-compose", "example-compose"),
    ] {
        let uses = format!("./.github/workflows/{file}.yml");
        assert_eq!(
            ci["jobs"][job]["uses"].as_str(),
            Some(uses.as_str()),
            "{job}"
        );
        assert_eq!(
            ci["jobs"][job]["with"]["scripted"].as_bool(),
            Some(true),
            "{job}"
        );
    }
    let bound = named_step(&ci, "Bound the hosted end-to-end agent job")["run"]
        .as_str()
        .unwrap();
    assert!(
        bound.contains(r#"read_api() { local out; for try in 1 2 3; do out=$(gh api "$@") && { printf '%s\n' "$out"; return; }; sleep 5; done; return 1; }"#),
        "{bound}"
    );
    assert_eq!(bound.matches("gh api").count(), 1, "{bound}");
}

/// The shipped dispatch-*.sh setups, played by the scripted agent in a
/// session of its own, in a temporary HOME, hand back what each profile
/// should: a patch, or one comment; the review's names the head it
/// reviewed and the toolchain it ran, and leaves the checkout clean.
#[test]
fn the_shipped_dispatch_setups_hand_back_through_a_fake_agent_session() {
    use serde_json::Value;
    let fake = Path::new(env!("CARGO_BIN_EXE_fake-agent"))
        .parent()
        .unwrap();
    // The review session runs cargo on a Rust target, so cargo must be on
    // PATH; a rustup cargo finds its toolchains from the real home.
    let search = format!("{}:{}", fake.display(), std::env::var("PATH").unwrap());
    let rustup = std::env::var_os("RUSTUP_HOME").map_or_else(
        || PathBuf::from(std::env::var_os("HOME").unwrap()).join(".rustup"),
        PathBuf::from,
    );
    // The verdict line `agentic-job review verdict` reads in check.
    let verdict = Regex::new(r"^VERDICT: (APPROVE|CHANGES)\n").unwrap();
    let toolchain = Regex::new(r"\nToolchain: cargo \d").unwrap();
    for profile in ["implement", "comment", "review"] {
        let home = tempfile::tempdir().unwrap();
        let work = home.path().join("work");
        std::fs::create_dir(&work).unwrap();
        std::fs::create_dir(home.path().join("out")).unwrap();
        let command = |program: &Path, dir: &Path| {
            let mut command = Command::new(program);
            command
                .current_dir(dir)
                .env("HOME", home.path())
                .env("RUSTUP_HOME", &rustup)
                .env("PATH", &search);
            command
        };
        let setup = command(Path::new("sh"), home.path())
            .arg(root().join(format!("workflow/dispatch-{profile}.sh")))
            .output()
            .unwrap();
        assert!(setup.status.success(), "{profile}: {setup:?}");
        git(&work, &["init", "-q"]);
        if profile == "review" {
            std::fs::create_dir(work.join("src")).unwrap();
            std::fs::write(work.join("src/lib.rs"), "").unwrap();
            std::fs::write(
                work.join("Cargo.toml"),
                "[package]\nname = \"trial\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .unwrap();
            std::fs::write(
                work.join("Cargo.lock"),
                "version = 4\n\n[[package]]\nname = \"trial\"\nversion = \"0.1.0\"\n",
            )
            .unwrap();
            git(&work, &["add", "."]);
        }
        git(&work, &["commit", "--allow-empty", "-qm", "Fixture"]);
        let drive = |args: &[&str]| {
            command(Path::new(BIN), &work)
                .arg("acp-drive")
                .args(args)
                .output()
                .unwrap()
        };
        let started = drive(&["start", "--agent", "fake"]);
        assert!(started.status.success(), "{profile}: {started:?}");
        // Stopped before anything is checked, so that no daemon is left.
        let ended = drive(&["prompt", "Run the dispatch trial."]);
        let events = drive(&["events"]);
        let stopped = drive(&["stop"]);
        for output in [&ended, &events, &stopped] {
            assert!(output.status.success(), "{profile}: {output:?}");
        }
        let ended: Value = serde_json::from_slice(&ended.stdout).unwrap();
        assert_eq!(ended["stop_reason"], "end_turn", "{profile}");
        let events: Value = serde_json::from_slice(&events.stdout).unwrap();
        for event in events["events"].as_array().unwrap() {
            match event["kind"].as_str() {
                Some("permission") => assert_eq!(event["decision"], "allow", "{profile}: {event}"),
                Some("tool_result") => {
                    assert_eq!(event["status"], "completed", "{profile}: {event}");
                }
                _ => {}
            }
        }
        let outcome: Value =
            serde_json::from_slice(&std::fs::read(home.path().join("out/outcome.json")).unwrap())
                .unwrap();
        assert!(outcome["stopped_early"].is_null(), "{profile}: {outcome}");
        assert!(
            outcome["summary"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "{profile}: {outcome}"
        );
        if profile == "implement" {
            let patch = std::fs::read_to_string(work.join("DISPATCH-TRIAL.md")).unwrap();
            assert!(patch.contains("No model"), "{patch}");
            continue;
        }
        let line = std::fs::read_to_string(home.path().join("out/safe-outputs.jsonl")).unwrap();
        let output: Value = serde_json::from_str(&line).unwrap();
        let mut keys: Vec<&String> = output.as_object().unwrap().keys().collect();
        keys.sort_unstable();
        assert_eq!(keys, ["body", "type"], "{profile}: {output}");
        assert_eq!(output["type"], "add_comment", "{profile}");
        if profile == "review" {
            let body = output["body"].as_str().unwrap();
            assert!(verdict.is_match(body), "{body}");
            assert!(body.contains(&git(&work, &["rev-parse", "HEAD"])), "{body}");
            assert!(toolchain.is_match(body), "{body}");
            assert_eq!(git(&work, &["status", "--porcelain"]), "");
        }
    }
}
