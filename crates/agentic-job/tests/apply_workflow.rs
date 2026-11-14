//! Apply's workflow shape and actual shell steps, without credentials or a forge.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use regex::Regex;
use serde_json::{Value, json};
use tempfile::TempDir;
use yaml_rust2::{Yaml, YamlLoader};

const HANDLERS: &str = "Write the handlers' configuration";
const PINNED: &str = "The policy call is this workflow's commit";
const TRIAL: &str =
    "Apply the patch on its own base, and compare what changed with what was checked";
const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

#[test]
fn staged_apply_skips_credential_steps_and_defaults_off() {
    let doc = definition("apply.yml");
    let text = workflow("apply.yml");
    let credential =
        Regex::new(r"secrets\.SAFE_OUTPUTS_PAT|github\.token|gh api|git push").unwrap();
    let read_only = [
        "The checked outputs are this run's check's",
        "Require policy's binary",
        "Release external output only after trusted detection",
    ];
    let mut skipped = 0;
    for body in Regex::new(r"\n      - (?:name:|uses:|id:)")
        .unwrap()
        .split(job(&text, "apply").split_once("\n    steps:\n").unwrap().1)
        .skip(1)
    {
        if !credential.is_match(body)
            || read_only
                .iter()
                .any(|name| body.starts_with(&format!(" {name}\n")))
        {
            continue;
        }
        let condition = body
            .lines()
            .find_map(|line| line.strip_prefix("        if: "))
            .unwrap_or("");
        assert!(
            !condition.contains("||")
                && (condition.contains("fromJSON(inputs.policy).apply-staged != 'true'")
                    || condition.contains("steps.apply.outcome != 'skipped'")),
            "{}",
            body.lines().next().unwrap()
        );
        skipped += 1;
    }
    assert!(skipped >= 6, "only {skipped} credential steps checked");
    let apply = step(&doc, "apply", "Apply the outputs with gh-aw's handlers");
    assert_eq!(apply["id"].as_str(), Some("apply"));
    assert_eq!(
        apply["if"].as_str(),
        Some("${{ fromJSON(inputs.policy).apply-staged != 'true' }}")
    );
    let policy = definition("policy.yml");
    assert_eq!(
        policy["on"]["workflow_call"]["outputs"]["apply-staged"]["value"].as_str(),
        Some("${{ jobs.policy.outputs.apply-staged }}")
    );
    for file in ["policy.yml", "agentic-job.yml"] {
        let caller = definition(file);
        let input = &caller["on"]["workflow_call"]["inputs"]["apply-staged"];
        assert!(input["description"].as_str().is_some_and(|s| !s.is_empty()));
        assert_eq!(input["type"].as_str(), Some("boolean"), "{file}");
        assert_eq!(input["default"].as_bool(), Some(false), "{file}");
        matches(
            &workflow(file),
            r"\n      apply-staged: \$\{\{ inputs\.apply-staged \}\}\n",
        );
    }
}

#[test]
fn staged_apply_escapes_preview_and_reports_no_publication() {
    let dir = TempDir::new().unwrap();
    let path = dir.path();
    let summary = path.join("summary.md");
    let report = path.join("report.json");
    json_file(
        path,
        "agent_output.json",
        &json!({"items": [{
            "type": "create_pull_request", "title": "t", "branch": "agent-run-7",
            "body": "see <img src=\"https://example.invalid/x.png\"> & [a](https://example.invalid)"
        }]}),
    );
    json_file(
        path,
        "report.json",
        &json!({"patch": {"files": [
            "src/<b>.rs", "README.md", "::error title=Approved::x"
        ]}}),
    );
    let shown = run_step(
        path,
        "Show what would be applied",
        &[
            ("GH_AW_TMP", path.to_str().unwrap()),
            ("REPORT", report.to_str().unwrap()),
            ("GITHUB_STEP_SUMMARY", summary.to_str().unwrap()),
        ],
    );
    status(&shown, 0);
    let stdout = String::from_utf8(shown.stdout).unwrap();
    assert!(stdout.contains("agent-run-7"));
    // No agent-owned line may become a runner command.
    let safe_line = Regex::new(r#"^\s*(?:["\[\]{}]|$)"#).unwrap();
    assert!(
        stdout.lines().all(|line| safe_line.is_match(line)),
        "{stdout}"
    );
    let preview = fs::read_to_string(summary).unwrap();
    assert!(preview.starts_with("### Staged: nothing was applied\n"));
    assert!(preview.contains(r"&lt;img src=\&quot;https://example.invalid/x.png\&quot;&gt; &amp;"));
    assert!(preview.contains("src/&lt;b&gt;.rs\nREADME.md"));
    assert_eq!(
        preview.matches('<').count(),
        Regex::new(r"</?pre>").unwrap().find_iter(&preview).count()
    );
    let handlers = json!({"create_pull_request": {"max": 1}});
    json_file(path, "handler-config.json", &handlers);
    let made = path.join("made.jsonl");
    for staged in ["true", "false"] {
        status(
            &run_step(
                path,
                "Write applied.json",
                &[
                    ("GH_AW_TMP", path.to_str().unwrap()),
                    ("MADE", made.to_str().unwrap()),
                    ("OUTPUT_REPO", "owner/repo"),
                    ("PR", ""),
                    ("PR_URL", ""),
                    ("FORK", ""),
                    ("EXIT", "0"),
                    ("CHECKPOINT", ""),
                    ("STAGED", staged),
                ],
            ),
            0,
        );
        let applied = read_json(path, "applied.json");
        assert_eq!(applied["staged"], staged == "true");
        assert_eq!(applied["made"], json!([]));
        assert_eq!(applied["already_applied"], json!([]));
        assert_eq!(applied.get("pull_request"), Some(&Value::Null));
        assert_eq!(applied.get("fork"), Some(&Value::Null));
        assert_eq!(applied["handlers"], handlers);
    }
}

#[test]
fn optional_pat_is_forwarded_only_to_policy_and_apply() {
    let apply = definition("apply.yml");
    assert_eq!(
        apply["on"]["workflow_call"]["secrets"]["SAFE_OUTPUTS_PAT"]["required"].as_bool(),
        Some(false)
    );
    let text = workflow("apply.yml");
    let jobs = text.split_once("\njobs:\n").unwrap().1;
    let before = jobs.split_once("\n  apply:\n").unwrap().0;
    assert!(!before.contains("secrets.SAFE_OUTPUTS_PAT"));
    matches(
        job(&text, "conclude"),
        r"STATUS_TOKEN: \$\{\{ inputs.role-bindings == '' && secrets.SAFE_OUTPUTS_PAT ",
    );
    assert_eq!(
        apply["jobs"]["apply"]["environment"].as_str(),
        Some("${{ fromJSON(inputs.policy).apply-environment }}")
    );
    assert!(
        !Regex::new("HAS_TOKEN|no passed .* secret")
            .unwrap()
            .is_match(job(&text, "apply"))
    );

    // Policy forwards the PAT to notify, not to its read-only policy job.
    let wrapper = definition("agentic-job.yml");
    let wrapper_text = workflow("agentic-job.yml");
    let consumers: Vec<_> = wrapper["jobs"]
        .as_hash()
        .unwrap()
        .keys()
        .map(|name| name.as_str().unwrap())
        .filter(|name| job(&wrapper_text, name).contains("secrets.SAFE_OUTPUTS_PAT"))
        .collect();
    assert_eq!(consumers, ["policy", "apply"]);
    assert_eq!(
        wrapper["jobs"]["apply"]["uses"].as_str(),
        Some("./.github/workflows/apply.yml")
    );

    for name in [
        "example",
        "example-command",
        "example-deterministic",
        "example-pull-request",
        "example-schedule",
        "review",
    ] {
        assert!(
            workflow(&format!("{name}.yml"))
                .contains("SAFE_OUTPUTS_PAT: ${{ secrets.SAFE_OUTPUTS_PAT }}"),
            "{name} must explicitly forward the optional PAT"
        );
    }
}

#[test]
fn ci_safe_output_callers_exercise_job_token_fallback() {
    let ci = definition("ci.yml");
    let text = workflow("ci.yml");
    let re = Regex::new(
        r"^\./\.github/workflows/(agentic-job|dispatch|example-compose|example-deterministic)\.yml$",
    ).unwrap();
    let callers: Vec<_> = ci["jobs"]
        .as_hash()
        .unwrap()
        .iter()
        .filter(|(_, caller)| {
            caller["uses"]
                .as_str()
                .is_some_and(|uses| re.is_match(uses))
        })
        .map(|(name, caller)| (name.as_str().unwrap(), caller))
        .collect();
    assert_eq!(
        callers.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        [
            "e2e-proposals",
            "e2e-deterministic",
            "e2e-full",
            "e2e-limit",
            "e2e-write-policy",
            "e2e-event",
            "e2e-analysis",
            "e2e-analysis-refused",
            "e2e-secondary",
            "e2e-secondary-refused",
            "e2e-people",
            "e2e-check-run",
            "e2e-dispatch",
            "e2e-compose",
            "e2e-review",
            "e2e-items",
            "e2e-threads",
        ]
    );
    let secret_reference = Regex::new(r"\bsecrets\.").unwrap();
    for (name, caller) in &callers {
        assert!(caller["secrets"].is_badvalue(), "{name}");
        assert!(!secret_reference.is_match(job(&text, name)), "{name}");
        if !caller["with"]["apply-environment"].is_badvalue() {
            assert_eq!(
                caller["with"]["apply-staged"].as_bool(),
                Some(true),
                "{name}"
            );
        }
    }
    for name in [
        "e2e-analysis",
        "e2e-analysis-refused",
        "e2e-people",
        "e2e-check-run",
        "e2e-compose",
        "e2e-review",
    ] {
        assert_eq!(
            ci["jobs"][name]["permissions"]["contents"].as_str(),
            Some("read"),
            "{name}"
        );
    }
    let wrapper = definition("agentic-job.yml");
    assert!(!wrapper["on"]["workflow_call"]["inputs"]["build-binary"].is_badvalue());
    for name in [
        "e2e-analysis",
        "e2e-analysis-refused",
        "e2e-people",
        "e2e-check-run",
    ] {
        let inputs = &ci["jobs"][name]["with"];
        assert_eq!(inputs["build-binary"].as_bool(), Some(true), "{name}");
        assert!(inputs["build"].is_badvalue(), "{name}");
    }
}

#[test]
fn external_detection_cannot_be_skipped_to_release_a_checked_upload() {
    let doc = definition("check.yml");
    assert_eq!(
        doc["on"]["workflow_call"]["outputs"]["detection-result"]["value"].as_str(),
        Some("${{ jobs.detect.outputs.detection-result }}")
    );
    assert_eq!(
        doc["jobs"]["detect"]["outputs"]["detection-result"].as_str(),
        Some("${{ steps.detector.outcome }}")
    );
    let release = doc["jobs"]["detect"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|step| step["id"].as_str() == Some("release"))
        .unwrap();
    let dir = TempDir::new().unwrap();
    for (external, detection, expected) in [
        ("", "skipped", 0),
        ("7", "success", 0),
        ("7", "", 1),
        ("7", "skipped", 1),
        ("7", "failure", 1),
        ("7", "cancelled", 1),
    ] {
        let output = dir.path().join("output");
        status(
            &bash(
                dir.path(),
                release["run"].as_str().unwrap(),
                &[
                    ("EXTERNAL_RUN", external),
                    ("DETECTION", detection),
                    ("ARTIFACT", "12"),
                    ("DIGEST", "digest"),
                    ("GITHUB_OUTPUT", output.to_str().unwrap()),
                ],
            ),
            expected,
        );
    }
    let apply = definition("apply.yml");
    let steps = apply["jobs"]["apply"]["steps"].as_vec().unwrap();
    let release = steps
        .iter()
        .position(|s| {
            s["name"].as_str() == Some("Release external output only after trusted detection")
        })
        .unwrap();
    let fork = steps
        .iter()
        .position(|s| s["name"].as_str() == Some("Fork the output repository for the pull request"))
        .unwrap();
    assert!(release < fork);
    assert!(steps[release]["if"].is_badvalue()); // staged mode cannot bypass it
}

#[test]
fn external_without_a_local_agent_result_is_not_partial() {
    let apply = definition("apply.yml");
    let normalized_exit = "${{ (fromJSON(inputs.policy).proposals-artifact != '' || fromJSON(inputs.policy).external-run-id != '') && '0' || fromJSON(inputs.agent).outputs.exit }}";
    for name in ["Decide whether the work is complete", "Write applied.json"] {
        assert_eq!(
            step(&apply, "apply", name)["env"]["EXIT"].as_str(),
            Some(normalized_exit)
        );
    }
    assert_eq!(
        step(&apply, "apply", "Mark what a partial run opens or posts")["if"].as_str(),
        Some(
            "${{ fromJSON(inputs.policy).proposals-artifact == '' && fromJSON(inputs.policy).external-run-id == '' && format('{0}', fromJSON(inputs.agent).outputs.exit) != '0' }}"
        )
    );
    let conclude = step(&apply, "conclude", "How the run ended");
    assert_eq!(
        conclude["env"]["RESULTS"].as_str(),
        Some(
            "${{ (fromJSON(inputs.policy).proposals-artifact != '' || fromJSON(inputs.policy).external-run-id != '') && 'success' || fromJSON(inputs.agent).result }}/${{ fromJSON(inputs.check).result }}/${{ needs.apply.result }}"
        )
    );
    assert_eq!(
        conclude["env"]["EXIT"].as_str(),
        Some(
            "${{ fromJSON(inputs.policy).external-run-id != '' && '0' || fromJSON(inputs.agent).outputs.exit }}"
        )
    );
    for pr in ["", "42"] {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("handler-config.json"), "{}").unwrap();
        fs::write(dir.path().join("skipped.json"), "[]").unwrap();
        status(
            &bash(
                dir.path(),
                step(&apply, "apply", "Write applied.json")["run"]
                    .as_str()
                    .unwrap(),
                &[
                    ("GH_AW_TMP", dir.path().to_str().unwrap()),
                    ("MADE", dir.path().join("made.jsonl").to_str().unwrap()),
                    ("OUTPUT_REPO", "owner/target"),
                    ("EXIT", "0"),
                    ("PR", pr),
                    ("PR_URL", "https://github.com/owner/target/pull/42"),
                ],
            ),
            0,
        );
        let report: Value =
            serde_json::from_slice(&fs::read(dir.path().join("applied.json")).unwrap()).unwrap();
        assert_eq!(report["partial"], false);
        assert_eq!(report["pull_request"].is_null(), pr.is_empty());
    }
}

#[test]
fn advisory_uses_the_same_check_artifact_and_cancellation_gates() {
    let policy = definition("policy.yml");
    assert_eq!(
        policy["on"]["workflow_call"]["inputs"]["advisory"]["default"].as_bool(),
        Some(false)
    );
    assert_eq!(
        policy["jobs"]["policy"]["outputs"]["review"].as_str(),
        Some("${{ inputs.review && !inputs.advisory }}")
    );
    let apply = definition("apply.yml");
    let gate = apply["jobs"]["apply"]["if"].as_str().unwrap();
    assert!(gate.contains("!cancelled() && fromJSON(inputs.check).result == 'success'"));
    assert!(!gate.contains("advisory")); // no alternate failed/cancelled-check route
    assert!(
        step(&apply, "apply", "Require the checked outputs' artifact ID")["run"]
            .as_str()
            .unwrap()
            .contains("DIGEST")
    );
    assert!(
        step(
            &apply,
            "apply",
            "The checked outputs are this run's check's"
        )["run"]
            .as_str()
            .unwrap()
            .contains(".workflow_run.id")
    );
    let check = definition("check.yml");
    assert_eq!(
        step(&check, "check", "Validate the review verdict")["if"].as_str(),
        Some("${{ fromJSON(inputs.policy).review == 'true' }}")
    );
    let admission = step(&policy, "policy", "Check the proposals mode");
    let dir = TempDir::new().unwrap();
    for (event, review, partial, proposals, expected) in [
        ("true", "true", "false", "", 0),
        ("false", "true", "false", "", 1),
        ("true", "false", "false", "", 1),
        ("true", "true", "true", "", 1),
        ("true", "true", "false", "producer", 1),
    ] {
        status(
            &bash(
                dir.path(),
                admission["run"].as_str().unwrap(),
                &[
                    ("ADVISORY", "true"),
                    ("EVENT", event),
                    ("REVIEW", review),
                    ("PARTIAL", partial),
                    ("PROPOSALS", proposals),
                    ("REVIEW_ITEM", ""),
                    ("TASK", ""),
                    ("TASK_ARTIFACT", ""),
                ],
            ),
            expected,
        );
    }
}

#[test]
fn applied_all_requires_publication_and_distinguishes_blocked_results() {
    for (outcome, asked, opened, refused, expected, missing, blocked, published) in [
        ("success", false, false, "", 0, "", "", ""),
        ("success", true, true, "", 0, "", "", "success"),
        ("success", true, false, "", 1, "", "", ""),
        ("failure", true, false, "", 1, "", "", ""),
        ("failure", false, false, "", 1, "", "", ""),
        ("success", false, false, "true", 1, "", "", ""),
        ("success", false, false, "", 1, "true", "", ""),
        ("success", false, false, "", 0, "true", "true", ""),
        ("failure", false, false, "", 1, "true", "true", ""),
        ("success", true, true, "", 1, "", "", "failure"),
        ("success", false, false, "", 1, "true", "true", "failure"),
    ] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let kind = if asked {
            "create_pull_request"
        } else {
            "add_comment"
        };
        json_file(root, "agent_output.json", &json!({"items":[{"type":kind}]}));
        json_file(
            root,
            "applied.json",
            &json!({"pull_request":if opened {json!({"number":1})} else {Value::Null}, "made":[], "already_applied":[]}),
        );
        let output = root.join("output");
        fs::write(&output, "").unwrap();
        let out = run_step(
            root,
            "Every output was applied",
            &[
                ("GH_AW_TMP", root.to_str().unwrap()),
                ("OUTCOME", outcome),
                ("FAILED", ""),
                ("OUTPUT_REPO", "owner/repo"),
                ("PROJECT_REFUSED", refused),
                ("MISSING_DATA", missing),
                ("BLOCKED", blocked),
                ("PUBLISHED", published),
                ("PUBLISH_FAILED", ""),
                ("GITHUB_OUTPUT", output.to_str().unwrap()),
            ],
        );
        status(&out, expected);
        assert_eq!(
            text(&out).contains("::notice::the run is blocked"),
            blocked == "true"
        );
        assert_eq!(
            fs::read_to_string(output).unwrap(),
            if expected == 0 && blocked == "true" {
                "blocked=true\n"
            } else {
                ""
            }
        );
    }
}

#[test]
fn staged_apply_skips_credentialed_writers_and_defaults_off() {
    let doc = definition("apply.yml");
    let credential = Regex::new(r"secrets\.|github\.token|gh api|git push").unwrap();
    let read_only = [
        "The checked outputs are this run's check's",
        "Require policy's binary",
        "Release external output only after trusted detection",
    ];
    let mut skipped = 0;
    for step in doc["jobs"]["apply"]["steps"].as_vec().unwrap() {
        if read_only.contains(&step["name"].as_str().unwrap_or_default())
            || !credential.is_match(&format!("{step:?}"))
        {
            continue;
        }
        let condition = step["if"].as_str().unwrap_or_default();
        assert!(
            !condition.contains("||")
                && (condition.contains("fromJSON(inputs.policy).apply-staged != 'true'")
                    || condition.contains("steps.apply.outcome != 'skipped'")),
            "credentialed step must skip staged apply: {step:?}"
        );
        skipped += 1;
    }
    assert!(skipped >= 6, "inventory credentialed steps: {skipped}");
    let handlers = step(&doc, "apply", "Apply the outputs with gh-aw's handlers");
    assert_eq!(handlers["id"].as_str(), Some("apply"));
    assert_eq!(
        handlers["if"].as_str(),
        Some("${{ fromJSON(inputs.policy).apply-staged != 'true' }}")
    );
    let policy = definition("policy.yml");
    assert_eq!(
        policy["on"]["workflow_call"]["outputs"]["apply-staged"]["value"].as_str(),
        Some("${{ jobs.policy.outputs.apply-staged }}")
    );
    for file in ["policy.yml", "agentic-job.yml"] {
        let caller = definition(file);
        let input = &caller["on"]["workflow_call"]["inputs"]["apply-staged"];
        assert_eq!(input["type"].as_str(), Some("boolean"), "{file}");
        assert_eq!(input["default"].as_bool(), Some(false), "{file}");
        assert!(workflow(file).contains("      apply-staged: ${{ inputs.apply-staged }}\n"));
    }
}

#[test]
fn handler_errors_use_policy_binary_and_neutralize_annotations() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fs::create_dir(root.join("apply-binary")).unwrap();
    fs::copy(BIN, root.join("apply-binary/agentic-job")).unwrap();
    json_file(
        root,
        "safe-output-errors.json",
        &json!({"failures":[
            {"type":"add_comment", "error":"bad\n::warning::@user 100%0A"},
            {"type":"create_issue"}
        ]}),
    );
    let output = root.join("output");
    fs::write(&output, "").unwrap();
    let out = run_step(
        root,
        "Show why a handler failed",
        &[
            ("GH_AW_TMP", root.to_str().unwrap()),
            ("RUNNER_TEMP", root.to_str().unwrap()),
            ("GITHUB_OUTPUT", output.to_str().unwrap()),
        ],
    );
    status(&out, 0);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "::error::Failed to apply add\\_comment: bad ::warning::@\u{200b}user 100%250A\n::error::Failed to apply create\\_issue: no error given\n"
    );
    assert_eq!(
        fs::read_to_string(output).unwrap(),
        "reason=add\\_comment: bad ::warning::@\u{200b}user 100%0A; create\\_issue: no error given\n"
    );
}

#[test]
fn staged_apply_escapes_preview_and_reports_no_writes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path();
    let summary = path.join("summary.md");
    let report = path.join("report.json");
    json_file(
        path,
        "agent_output.json",
        &json!({"items": [{
            "type": "create_pull_request", "title": "t", "branch": "agent-run-7",
            "body": "see <img src=\"https://example.invalid/x.png\"> & [a](https://example.invalid)"
        }]}),
    );
    json_file(
        path,
        "report.json",
        &json!({"patch": {"files": [
            "src/<b>.rs", "README.md", "::error title=Approved::x"
        ]}}),
    );
    let shown = run_step(
        path,
        "Show what would be applied",
        &[
            ("GH_AW_TMP", path.to_str().unwrap()),
            ("REPORT", report.to_str().unwrap()),
            ("GITHUB_STEP_SUMMARY", summary.to_str().unwrap()),
        ],
    );
    status(&shown, 0);
    let stdout = String::from_utf8(shown.stdout).unwrap();
    assert!(stdout.contains("agent-run-7"));
    // Agent text cannot become a runner command or HTML in the preview.
    let json_line = Regex::new(r#"^\s*(?:["\[\]{}]|$)"#).unwrap();
    assert!(
        stdout.lines().all(|line| json_line.is_match(line)),
        "{stdout}"
    );
    let summary = fs::read_to_string(summary).unwrap();
    assert!(summary.starts_with("### Staged: nothing was applied\n"));
    assert!(
        summary.contains(r#"&lt;img src=\&quot;https://example.invalid/x.png\&quot;&gt; &amp;"#)
    );
    assert!(summary.contains("src/&lt;b&gt;.rs\nREADME.md"));
    assert!(
        !summary
            .replace("<pre>", "")
            .replace("</pre>", "")
            .contains('<')
    );

    let handlers = json!({"create_pull_request": {"max": 1}});
    json_file(path, "handler-config.json", &handlers);
    for (staged, expected) in [("true", true), ("false", false)] {
        status(
            &run_step(
                path,
                "Write applied.json",
                &[
                    ("GH_AW_TMP", path.to_str().unwrap()),
                    ("MADE", path.join("made.jsonl").to_str().unwrap()),
                    ("OUTPUT_REPO", "owner/repo"),
                    ("PR", ""),
                    ("PR_URL", ""),
                    ("FORK", ""),
                    ("EXIT", "0"),
                    ("CHECKPOINT", ""),
                    ("STAGED", staged),
                ],
            ),
            0,
        );
        let applied = read_json(path, "applied.json");
        assert_eq!(applied["staged"], expected);
        assert_eq!(applied["made"], json!([]));
        assert_eq!(applied["already_applied"], json!([]));
        assert!(applied["pull_request"].is_null());
        assert!(applied["fork"].is_null());
        assert_eq!(applied["handlers"], handlers);
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workflow(file: &str) -> String {
    fs::read_to_string(root().join(".github/workflows").join(file)).unwrap()
}

fn definition(file: &str) -> Yaml {
    YamlLoader::load_from_str(&workflow(file))
        .unwrap()
        .remove(0)
}

// Some guards are deliberately identical in apply and conclude. Select the
// job explicitly so their equality can be checked rather than assumed.
fn step(doc: &Yaml, job: &str, name: &str) -> Yaml {
    let mut found = doc["jobs"][job]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .filter(|step| step["name"].as_str() == Some(name));
    let result = found
        .next()
        .unwrap_or_else(|| panic!("no step {job}/{name}"));
    assert!(found.next().is_none(), "duplicate step {job}/{name}");
    result.clone()
}

fn job<'a>(text: &'a str, name: &str) -> &'a str {
    let rest = text.split_once(&format!("\n  {name}:\n")).unwrap().1;
    let end = Regex::new(r"\n  [\w-]+:\n")
        .unwrap()
        .find(rest)
        .map_or(rest.len(), |m| m.start());
    &rest[..end]
}

fn matches(text: &str, pattern: &str) {
    assert!(
        Regex::new(pattern).unwrap().is_match(text),
        "pattern {pattern:?} not found in {text}"
    );
}

fn json_file(dir: &Path, name: &str, value: &Value) {
    fs::write(dir.join(name), serde_json::to_vec(value).unwrap()).unwrap();
}

fn read_json(dir: &Path, name: &str) -> Value {
    serde_json::from_slice(&fs::read(dir.join(name)).unwrap()).unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn status(out: &Output, expected: i32) {
    assert_eq!(out.status.code(), Some(expected), "{}", text(out));
}

fn bash(cwd: &Path, script: &str, env: &[(&str, &str)]) -> Output {
    Command::new("bash")
        .args(["-e", "-o", "pipefail", "-c", script])
        .current_dir(cwd)
        .envs(env.iter().copied())
        .output()
        .unwrap()
}

fn run_step(cwd: &Path, name: &str, env: &[(&str, &str)]) -> Output {
    let doc = definition("apply.yml");
    let job = if ["How the run ended", "A reaction that says how it ended"].contains(&name) {
        "conclude"
    } else {
        "apply"
    };
    bash(cwd, step(&doc, job, name)["run"].as_str().unwrap(), env)
}

fn handlers(dir: &Path, config: &Value, overrides: &[(&str, &str)]) -> (Output, Value) {
    json_file(dir, "config.json", config);
    let path = dir.to_str().unwrap();
    let env_file = dir.join("env");
    let mut env = vec![
        ("GH_AW_TMP", path),
        ("GITHUB_ENV", env_file.to_str().unwrap()),
        ("GITHUB_REPOSITORY", "owner/caller"),
        ("REPO", "owner/source"),
        ("OUTPUT_REPO", "owner/output"),
        ("ITEM_REPO", "owner/item"),
        ("BASE", "main"),
        ("BRANCH_PREFIX", ""),
        ("READY", "false"),
        ("PARTIAL", ""),
        ("TITLE_PREFIX", ""),
        ("COMMENT_TARGET", ""),
        ("PULL_REQUEST", "{}"),
        ("PUSH", "{}"),
        ("FORK", ""),
    ];
    // Command::envs keeps the last setting of a repeated key.
    env.extend_from_slice(overrides);
    let out = run_step(dir, HANDLERS, &env);
    let result = if out.status.success() {
        read_json(dir, "handler-config.json")
    } else {
        Value::Null
    };
    (out, result)
}

#[test]
fn caller_branch_acceptance_is_not_a_handler_operation() {
    let dir = TempDir::new().unwrap();
    let (out, config) = handlers(
        dir.path(),
        &json!({"own_branch_repos": [["example-org/*"]], "stack_max_steps": 3, "noop": {"max": 1}}),
        &[],
    );
    status(&out, 0);
    assert_eq!(config, json!({"noop": {"max": 1}}));
}

fn handler_settings() -> (String, String) {
    let step = step(&definition("apply.yml"), "apply", HANDLERS);
    (
        step["env"]["PULL_REQUEST"].as_str().unwrap().to_owned(),
        step["env"]["PUSH"].as_str().unwrap().to_owned(),
    )
}

#[test]
fn fork_routing_is_decided_before_fetching_the_patch_base() {
    let doc = definition("apply.yml");
    let steps = doc["jobs"]["apply"]["steps"].as_vec().unwrap();
    let position = |name| {
        steps
            .iter()
            .position(|step| step["name"].as_str() == Some(name))
            .unwrap()
    };
    let fork = "Fork the output repository for the pull request";
    assert!(position("Require policy's binary") < position(fork));
    assert!(position(fork) < position("Fetch the target's base branch"));
    let fork_step = step(&doc, "apply", fork);
    assert_eq!(fork_step["id"].as_str(), Some("fork"));
    assert_eq!(
        fork_step["if"].as_str(),
        Some(
            "${{ fromJSON(inputs.check).outputs.has-patch == 'true' && fromJSON(inputs.policy).apply-staged != 'true' }}"
        )
    );
    assert!(
        fork_step["run"]
            .as_str()
            .unwrap()
            .contains("/apply-binary/agentic-job\" push target ")
    );
    assert!(steps.iter().any(|step| step["with"]["ref"].as_str()
        == Some(
            "${{ fromJSON(inputs.policy).push-item == '' && fromJSON(inputs.policy).base || '' }}"
        )));
    let policy = definition("policy.yml");
    assert_eq!(
        policy["on"]["workflow_call"]["outputs"]["push-item"]["value"].as_str(),
        Some("${{ jobs.policy.outputs.push-item }}")
    );
    assert_eq!(
        policy["jobs"]["policy"]["outputs"]["push-item"].as_str(),
        Some("${{ inputs.push-item }}")
    );
}

#[test]
fn fork_handler_configuration_preserves_destinations_and_literal_prefixes() {
    let dir = TempDir::new().unwrap();
    let (pull_request, _) = handler_settings();
    let input = json!({"create_pull_request": {"max": 1, "draft": true}, "noop": {"max": 1}});
    for (fork, partial, title, branch) in [
        ("bot/other", "", "", "p/"),
        ("", "", "", "p/"),
        (
            "bot/other",
            "[partial: stopped at a limit] ",
            "e2e \"full\" it's:",
            "b'\"/",
        ),
        (
            "bot/other",
            "[partial: stopped at a limit] ",
            "$(id) `id` \\n %s ${X}",
            "b'\"/",
        ),
        (
            "bot/other",
            "[partial: stopped at a limit] ",
            "\" + {\"x\": 1} + \"",
            "b'\"/",
        ),
    ] {
        let (out, actual) = handlers(
            dir.path(),
            &input,
            &[
                ("OUTPUT_REPO", "owner/other"),
                ("ITEM_REPO", "owner/other"),
                ("READY", ""),
                ("PULL_REQUEST", &pull_request),
                ("FORK", fork),
                ("PARTIAL", partial),
                ("TITLE_PREFIX", title),
                ("BRANCH_PREFIX", branch),
            ],
        );
        status(&out, 0);
        let mut expected = json!({"noop": {"max": 1}});
        if !fork.is_empty() {
            expected["create_pull_request"] = json!({
                "max": 1, "draft": true, "signed_commits": false,
                "fallback_as_issue": false, "preserve_branch_name": true,
                "auto_close_issue": false, "target-repo": "owner/other",
                "base_branch": "main", "branch_prefix": branch,
                "title_prefix": format!("{partial}{title}"),
                "head-repo": fork, "allowed_repos": [fork],
            });
        }
        assert_eq!(actual, expected, "fork={fork:?}, title={title:?}");
        let env = fs::read_to_string(dir.path().join("env")).unwrap();
        let exported = env
            .lines()
            .last()
            .unwrap()
            .strip_prefix("GH_AW_SAFE_OUTPUTS_HANDLER_CONFIG=")
            .unwrap();
        assert_eq!(serde_json::from_str::<Value>(exported).unwrap(), expected);
    }
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap();
    status(&out, 0);
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn identity(dir: &Path) {
    git(dir, &["config", "user.name", "Test"]);
    git(dir, &["config", "user.email", "test@example.invalid"]);
}

fn commit(dir: &Path, content: &str) -> String {
    fs::write(dir.join("file.txt"), content).unwrap();
    git(dir, &["add", "."]);
    git(dir, &["commit", "-qm", content]);
    git(dir, &["rev-parse", "HEAD"])
}

#[test]
fn patch_guard_requires_checked_paths_and_related_base() {
    for (case, filename, files, unrelated, expected) in [
        ("ordinary", "file.txt", vec!["file.txt"], false, 0),
        ("CRLF", "file.txt", vec!["file.txt"], false, 0),
        ("Unicode", "café.txt", vec!["café.txt"], false, 0),
        ("unchecked path", "file.txt", vec!["other.txt"], false, 1),
        ("empty paths", "file.txt", vec![], false, 4),
        ("unrelated base", "file.txt", vec!["file.txt"], true, 1),
    ] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let repo = root.join("repo");
        let outputs = root.join("outputs");
        fs::create_dir(&outputs).unwrap();
        git(root, &["init", "-q", repo.to_str().unwrap()]);
        identity(&repo);
        let cr = if case == "CRLF" { "\r" } else { "" };
        fs::write(repo.join(filename), format!("before{cr}\n")).unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "base"]);
        let base = git(&repo, &["rev-parse", "HEAD"]);
        git(
            &repo,
            &["update-ref", "refs/agentic-job/target-base", &base],
        );
        fs::write(repo.join(filename), format!("after{cr}\n")).unwrap();
        git(&repo, &["commit", "-qam", "edit"]);
        let tree = git(&repo, &["rev-parse", "HEAD^{tree}"]);
        let patch = outputs.join("aw-test.patch");
        write_patch(&repo, &patch);
        git(&repo, &["reset", "--hard", &base]);
        if unrelated {
            git(&repo, &["checkout", "--orphan", "unrelated"]);
            git(&repo, &["commit", "-qm", "unrelated root"]);
            git(
                &repo,
                &["update-ref", "refs/agentic-job/target-base", "HEAD"],
            );
        }
        json_file(
            root,
            "report.json",
            &json!({"patch": {
                "file":"aw-test.patch", "base_commit":base, "files":files
            }}),
        );
        status(&run_step(&repo, "Configure git", &[]), 0);
        assert_eq!(git(&repo, &["config", "merge.renames"]), "false");
        assert_eq!(git(&repo, &["config", "am.keepcr"]), "true");
        let output = root.join("output");
        let out = run_step(
            &repo,
            TRIAL,
            &[
                ("REPORT", root.join("report.json").to_str().unwrap()),
                ("RUNNER_TEMP", root.to_str().unwrap()),
                ("GH_AW_TMP", outputs.to_str().unwrap()),
                ("REPO", "owner/repo"),
                ("BASE", "main"),
                ("GITHUB_OUTPUT", output.to_str().unwrap()),
            ],
        );
        assert_eq!(out.status.code(), Some(expected), "{case}: {}", text(&out));
        if expected == 0 {
            assert_eq!(
                fs::read_to_string(&output).unwrap(),
                format!("tree={tree}\n"),
                "{case}"
            );
        } else {
            assert!(!output.exists(), "{case}: refused trial emitted a tree");
        }
        if case == "CRLF" {
            git(&repo, &["am", "--3way", patch.to_str().unwrap()]);
            assert_eq!(fs::read(repo.join(filename)).unwrap(), b"after\r\n");
        }
    }
}

fn write_patch(repo: &Path, patch: &Path) {
    let out = Command::new("git")
        .current_dir(repo)
        .args(["format-patch", "-1", "--stdout"])
        .output()
        .unwrap();
    status(&out, 0);
    // Preserve the mail bytes, including CRLF, rather than trimming text.
    fs::write(patch, out.stdout).unwrap();
}

#[test]
fn patch_guard_does_not_follow_rename_into_protected_path() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    git(root, &["init", "-q"]);
    identity(root);
    let base = commit(root, "before\n");
    commit(root, "after\n");
    let patch = root.join("mail.patch");
    write_patch(root, &patch);
    git(root, &["reset", "--hard", &base]);
    git(root, &["mv", "file.txt", ".envrc"]);
    git(root, &["commit", "-qm", "rename"]);
    status(&run_step(root, "Configure git", &[]), 0);
    let out = Command::new("git")
        .current_dir(root)
        .args(["am", "--3way"])
        .arg(&patch)
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", text(&out));
    assert_eq!(fs::read_to_string(root.join(".envrc")).unwrap(), "before\n");
}

#[test]
fn document_handler_keeps_policy_authority_and_fixed_comment_target() {
    let dir = TempDir::new().unwrap();
    let config =
        json!({"document": {"max": 1, "document": {"public": false, "gist_ids": ["abc123"]}}});
    let (out, result) = handlers(dir.path(), &config, &[("COMMENT_TARGET", "7")]);
    status(&out, 0);
    assert_eq!(
        result["document"],
        json!({"max": 1, "document": {"public": false, "gist_ids": ["abc123"]}, "target-repo": "owner/item", "target": "7"})
    );
    assert!(safe_outputs::apply::publish::handler("document").is_some());
}

#[test]
fn issue_actions_keep_checked_repository_and_caps() {
    let dir = TempDir::new().unwrap();
    let cases = [
        (
            "close_issue",
            json!({"max":2}),
            json!({"issue_intent":false,"allow_body":true}),
        ),
        (
            "add_labels",
            json!({"max":3,"allowed":["triage"],"blocked":["release"]}),
            json!({"issue_intent":false,"create_if_missing":false}),
        ),
        (
            "add_reviewer",
            json!({"max":1,"allowed":["octocat"]}),
            json!({}),
        ),
        (
            "assign_to_user",
            json!({"max":1,"allowed":["octocat"]}),
            json!({"issue_intent":false,"unassign_first":false}),
        ),
        ("close_pull_request", json!({"max":1}), json!({})),
        ("link_sub_issue", json!({"max":2}), json!({})),
        (
            "add_comment",
            json!({"max":1}),
            json!({"target-repo":"owner/tracker","target":"99"}),
        ),
        (
            "update_issue",
            json!({"max":1,"fields":["title"]}),
            json!({"allow_body":false}),
        ),
        (
            "update_pull_request",
            json!({"max":1,"fields":["body","draft"]}),
            json!({"allow_title":false,"allow_body":true,"update_branch":false}),
        ),
        (
            "mark_pull_request_as_ready_for_review",
            json!({"max":1}),
            json!({}),
        ),
    ];
    let config = cases
        .iter()
        .map(|(name, input, _)| ((*name).to_owned(), input.clone()))
        .collect::<serde_json::Map<_, _>>();
    let (out, got) = handlers(
        dir.path(),
        &Value::Object(config),
        &[
            ("OUTPUT_REPO", "owner/other"),
            ("ITEM_REPO", "owner/tracker"),
            ("COMMENT_TARGET", "99"),
            ("READY", ""),
        ],
    );
    status(&out, 0);
    for (name, mut expected, extra) in cases {
        expected.as_object_mut().unwrap().extend(
            json!({"target-repo":"owner/source","target":"*"})
                .as_object()
                .unwrap()
                .clone(),
        );
        expected
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert_eq!(got[name], expected, "{name}");
    }
}

#[test]
fn check_run_keeps_pinned_name_and_run_repository() {
    let dir = TempDir::new().unwrap();
    for (repo, expected) in [("owner/source", 0), ("owner/caller", 1)] {
        let (out, config) = handlers(
            dir.path(),
            &json!({"create_check_run":{"max":1,"name":"agent verdict"}}),
            &[
                ("GITHUB_REPOSITORY", repo),
                ("REPO", "Owner/Source"),
                ("OUTPUT_REPO", "owner/source"),
                ("ITEM_REPO", "owner/source"),
            ],
        );
        status(&out, expected);
        if expected == 0 {
            assert_eq!(
                config["create_check_run"],
                json!({"max":1,"name":"agent verdict","target":"*"})
            );
        } else {
            assert!(
                String::from_utf8_lossy(&out.stdout).contains("posts in the calling repository")
            );
        }
    }
}

#[test]
fn discussion_goes_to_run_repository_not_an_issue() {
    let dir = TempDir::new().unwrap();
    let (out, config) = handlers(
        dir.path(),
        &json!({"create_discussion":{"max":1,"category":"Agent reports"}}),
        &[],
    );
    status(&out, 0);
    assert_eq!(
        config["create_discussion"],
        json!({"max":1,"category":"Agent reports","target-repo":"owner/source","fallback_to_issue":false,"close_older_discussions":false})
    );
}

#[test]
fn hide_comment_and_review_threads_are_held_to_triggering_item() {
    // Each original target case is run separately for hide_comment and for
    // the three review-thread handlers together.
    for types in [
        vec!["hide_comment"],
        vec![
            "create_pull_request_review_comment",
            "reply_to_pull_request_review_comment",
            "resolve_pull_request_review_thread",
        ],
    ] {
        for target in ["64", "*", "", "0"] {
            let dir = TempDir::new().unwrap();
            let input = if types[0] == "hide_comment" {
                json!({"max":1,"allowed_reasons":["SPAM"]})
            } else {
                json!({"max":2})
            };
            let config: serde_json::Map<_, _> = types
                .iter()
                .map(|name| ((*name).to_owned(), input.clone()))
                .collect();
            let (out, got) = handlers(
                dir.path(),
                &Value::Object(config),
                &[("COMMENT_TARGET", target)],
            );
            status(&out, 0);
            for name in &types {
                if target == "64" {
                    let mut expected = input.clone();
                    expected.as_object_mut().unwrap().extend(
                        json!({"target-repo":"owner/item","target":"64"})
                            .as_object()
                            .unwrap()
                            .clone(),
                    );
                    assert_eq!(got[name], expected, "{name} {target}");
                } else {
                    assert!(got.get(name).is_none(), "{name} {target}: {got}");
                }
            }
        }
    }
}

#[test]
fn carriers_exempt_at_most_github_of_policy_dot_folders() {
    let (pr, push) = handler_settings();
    for carrier in ["create_pull_request", "push_to_pull_request_branch"] {
        for folders in [
            None,
            Some(json!([])),
            Some(json!([".github"])),
            Some(json!([".agents"])),
            Some(json!([".agents", ".github"])),
        ] {
            let dir = TempDir::new().unwrap();
            let mut original = json!({"max":1,"protected_files":["CODEOWNERS"],"protected_files_policy":"blocked","protect_top_level_dot_folders":true,"protected_paths":["raw/**"]});
            if let Some(folders) = &folders {
                original["unprotected_dot_folders"] = folders.clone();
            }
            let (out, all) = handlers(
                dir.path(),
                &json!({carrier:original}),
                &[
                    ("REPO", "owner/repo"),
                    ("OUTPUT_REPO", "owner/repo"),
                    ("ITEM_REPO", "owner/repo"),
                    ("READY", ""),
                    ("PULL_REQUEST", &pr),
                    ("PUSH", &push),
                    ("FORK", "bot/repo"),
                ],
            );
            status(&out, 0);
            let got = &all[carrier];
            for key in ["unprotected_dot_folders", "protected_paths"] {
                assert!(got.get(key).is_none(), "{carrier} {folders:?}: {key}");
            }
            assert_eq!(got["protect_top_level_dot_folders"], true);
            let exempt = folders
                .as_ref()
                .is_some_and(|f| f.as_array().unwrap().contains(&json!(".github")));
            assert_eq!(
                got.get("protected_dot_folder_excludes"),
                exempt.then_some(&json!([".github"]))
            );
            assert_eq!(
                got.get("allow_workflows"),
                (exempt && carrier == "push_to_pull_request_branch").then_some(&json!(true))
            );
            assert_eq!(got["protected_files_policy"], "blocked");
            assert_eq!(got["protected_files"], json!(["CODEOWNERS"]));
            assert_eq!(got["head-repo"], "bot/repo");
            assert_eq!(got["allowed_repos"], json!(["bot/repo"]));
            let other = if carrier == "create_pull_request" {
                "push_to_pull_request_branch"
            } else {
                "create_pull_request"
            };
            assert!(all.get(other).is_none());
        }
    }
}

#[test]
fn push_uses_policy_pull_request_and_apply_fork_without_workflows() {
    let dir = TempDir::new().unwrap();
    let (pr, push_settings) = handler_settings();
    // `author` is an own-pull-request push's; the handler must keep it.
    let push = json!({"max":1,"target":"42","head":"2".repeat(40),"author":"cgwalters-bot","protected_files":[],"protect_top_level_dot_folders":true,"protected_files_policy":"blocked","max_patch_size":1024,"max_patch_files":100});
    for fork in ["bot/repo", "carol/repo", "Owner/Repo", ""] {
        let (out, config) = handlers(
            dir.path(),
            &json!({"push_to_pull_request_branch":push}),
            &[
                ("REPO", "Owner/Repo"),
                ("OUTPUT_REPO", "Owner/Repo"),
                ("ITEM_REPO", "Owner/Repo"),
                ("BASE", "dispatch/implement/agent-run-12"),
                ("BRANCH_PREFIX", "dispatch/fix/"),
                ("READY", ""),
                ("TITLE_PREFIX", "[bot] "),
                ("COMMENT_TARGET", "42"),
                ("PULL_REQUEST", &pr),
                ("PUSH", &push_settings),
                ("FORK", fork),
            ],
        );
        status(&out, 0);
        if fork.is_empty() {
            assert_eq!(config, json!({}));
            continue;
        }
        let got = &config["push_to_pull_request_branch"];
        if fork == "bot/repo" {
            let mut expected = push.clone();
            expected.as_object_mut().unwrap().extend(json!({"signed_commits":false,"fallback_as_pull_request":false,"if_no_changes":"error","target-repo":"Owner/Repo","head-repo":"bot/repo","allowed_repos":["bot/repo"],"checkout_mapping":{"owner/repo":"."}}).as_object().unwrap().clone());
            assert_eq!(got, &expected);
        } else {
            assert_eq!(got["head-repo"], fork);
            assert_eq!(got["allowed_repos"], json!([fork]));
            assert!(got.get("allow_workflows").is_none());
        }
    }
}

#[test]
fn pushed_branch_is_one_commit_on_pinned_head_with_checked_tree() {
    for (tip, replacement, expected) in [
        ("pushed", false, 0),
        ("other", false, 1),
        ("moved", false, 1),
        ("merged", false, 1),
        ("moved", true, 0),
        ("pushed", true, 1),
    ] {
        // Pushed by the handler, or recorded by the guard as an earlier
        // attempt's push or a replacement series it pushed itself.
        for recorded in [None, Some("already_applied"), Some("made")] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            let fork = root.join("fork.git");
            let origin = root.join("origin.git");
            let work = root.join("work");
            for bare in [&fork, &origin] {
                git(root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
            }
            git(root, &["init", "-q", work.to_str().unwrap()]);
            identity(&work);
            git(
                &work,
                &["remote", "add", "origin", origin.to_str().unwrap()],
            );
            let head = commit(&work, "before\n");
            let pushed = commit(&work, "after\n");
            let tree = git(&work, &["rev-parse", "HEAD^{tree}"]);
            git(&work, &["reset", "-q", "--hard", &head]);
            let other = commit(&work, "other\n");
            let moved = commit(&work, "after\n");
            git(&work, &["reset", "-q", "--hard", &head]);
            git(&work, &["merge", "-q", "--no-ff", &pushed, "-m", "merge"]);
            let merged = git(&work, &["rev-parse", "HEAD"]);
            let selected = match tip {
                "pushed" => &pushed,
                "other" => &other,
                "moved" => &moved,
                "merged" => &merged,
                _ => unreachable!(),
            };
            git(
                &work,
                &[
                    "push",
                    "-q",
                    fork.to_str().unwrap(),
                    &format!("{selected}:refs/heads/agent-run-12"),
                ],
            );
            git(
                &work,
                &[
                    "push",
                    "-q",
                    "origin",
                    &format!("{pushed}:refs/heads/agent-run-12"),
                ],
            );
            git(&work, &["reset", "-q", "--hard", &head]);
            let tmp = root.join("tmp");
            fs::create_dir(&tmp).unwrap();
            json_file(
                &tmp,
                "config.json",
                &json!({"push_to_pull_request_branch":{"target":"42","head":head}}),
            );
            let push = json!({"type":"push_to_pull_request_branch","branch":"agent-run-12"});
            json_file(
                &tmp,
                "agent_output.json",
                &json!({"items":if recorded.is_some() {json!([])} else {json!([push])}}),
            );
            let mut applied =
                json!({"pull_request":null,"refused":false,"made":[],"already_applied":[]});
            if let Some(key) = recorded {
                applied[key] = json!([push]);
            }
            json_file(&tmp, "applied.json", &applied);
            let out = run_step(
                &work,
                "Every output was applied",
                &[
                    ("GH_AW_TMP", tmp.to_str().unwrap()),
                    ("BASE", "agent-run-12"),
                    ("OUTPUT_REPO", "owner/repo"),
                    ("TREE", &tree),
                    ("FORK", "bot/repo"),
                    ("REPLACEMENT_HEAD", if replacement { &moved } else { "" }),
                    ("OUTCOME", "success"),
                    ("FAILED", "0"),
                    ("PROJECT_REFUSED", "false"),
                    ("GIT_CONFIG_COUNT", "1"),
                    (
                        "GIT_CONFIG_KEY_0",
                        &format!("url.{}.insteadOf", fork.display()),
                    ),
                    ("GIT_CONFIG_VALUE_0", "https://github.com/bot/repo"),
                ],
            );
            status(&out, expected);
            if expected != 0 {
                assert!(
                    text(&out).contains(if replacement {
                        "replacement head changed"
                    } else {
                        "agent-run-12 of bot/repo does not hold the checked change as one commit on"
                    }),
                    "{tip} recorded={recorded:?}: {}",
                    text(&out)
                );
            }
        }
    }
}

#[test]
fn complete_work_opens_ready_checkpoint_or_stopped_run_opens_draft() {
    let (pr_settings, _) = handler_settings();
    for (exit, reported, opted, checkpoint, draft) in [
        ("0", None, true, "", false),
        ("", None, true, "", false),
        ("0", Some("budget"), true, "budget", true),
        ("0", Some("incomplete"), true, "incomplete", true),
        ("124", None, true, "runtime", true),
        ("3", Some("budget"), true, "cap", true),
        ("0", None, false, "", true),
        ("0", Some("budget"), false, "budget", true),
    ] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let mut pr = json!({"max":1,"draft":true});
        if opted {
            pr["ready_when_complete"] = json!(true);
        }
        let config = json!({"create_pull_request":pr});
        json_file(root, "config.json", &config);
        let mut report = json!({"ok":true});
        if let Some(reason) = reported {
            report["checkpoint"] = json!({"reason":reason});
        }
        json_file(root, "report.json", &report);
        let out = run_step(
            root,
            "Decide whether the work is complete",
            &[
                ("GH_AW_TMP", root.to_str().unwrap()),
                ("REPORT", root.join("report.json").to_str().unwrap()),
                ("GITHUB_OUTPUT", root.join("output").to_str().unwrap()),
                ("EXIT", exit),
            ],
        );
        status(&out, 0);
        let ready = (!draft).to_string();
        let outputs = fs::read_to_string(root.join("output")).unwrap();
        let outputs: std::collections::BTreeMap<_, _> = outputs
            .trim()
            .lines()
            .map(|line| line.split_once('=').unwrap())
            .collect();
        assert_eq!(
            outputs,
            std::collections::BTreeMap::from([
                ("checkpoint", checkpoint),
                ("ready", ready.as_str())
            ]),
            "{exit} {reported:?} {opted}"
        );
        let (out, got) = handlers(
            root,
            &config,
            &[
                ("REPO", "owner/repo"),
                ("OUTPUT_REPO", "owner/repo"),
                ("ITEM_REPO", "owner/repo"),
                ("READY", outputs["ready"]),
                ("PULL_REQUEST", &pr_settings),
                ("FORK", "bot/repo"),
            ],
        );
        status(&out, 0);
        assert_eq!(got["create_pull_request"]["draft"], draft);
        assert!(
            got["create_pull_request"]
                .get("ready_when_complete")
                .is_none()
        );
    }
    let dir = TempDir::new().unwrap();
    json_file(dir.path(), "config.json", &json!({}));
    json_file(
        dir.path(),
        "report.json",
        &json!({"checkpoint":{"reason":"x\nready=true"}}),
    );
    status(
        &run_step(
            dir.path(),
            "Decide whether the work is complete",
            &[
                ("GH_AW_TMP", dir.path().to_str().unwrap()),
                ("REPORT", dir.path().join("report.json").to_str().unwrap()),
                ("GITHUB_OUTPUT", dir.path().join("output").to_str().unwrap()),
                ("EXIT", "0"),
            ],
        ),
        1,
    );
}

#[test]
fn partial_push_is_not_applied_whatever_else_it_posts() {
    for (types, expected) in [
        (vec!["add_comment"], 0),
        (vec!["close_issue"], 0),
        (vec!["push_to_pull_request_branch"], 1),
        (vec!["push_to_pull_request_branch", "add_comment"], 1),
    ] {
        let dir = TempDir::new().unwrap();
        // Make policy's binary available at the workflow's expected path.
        fs::create_dir(dir.path().join("apply-binary")).unwrap();
        std::os::unix::fs::symlink(BIN, dir.path().join("apply-binary/agentic-job")).unwrap();
        let items: Vec<_> = types
            .iter()
            .map(|kind| json!({"type":kind,"body":"b"}))
            .collect();
        json_file(dir.path(), "agent_output.json", &json!({"items":items}));
        let out = run_step(
            dir.path(),
            "Mark what a partial run opens or posts",
            &[
                ("GH_AW_TMP", dir.path().to_str().unwrap()),
                ("RUNNER_TEMP", dir.path().to_str().unwrap()),
                ("STOPPED", "its timeout"),
            ],
        );
        status(&out, expected);
        if expected != 0 {
            assert!(
                String::from_utf8_lossy(&out.stdout)
                    .contains("a partial change is not pushed to a pull request's branch")
            );
        } else {
            matches(
                read_json(dir.path(), "agent_output.json")["items"][0]["body"]
                    .as_str()
                    .unwrap(),
                r"^\*\*Partial work\.\*\* .*\n\nb$",
            );
        }
    }
}

#[test]
fn target_base_fetch_never_advances_output_repository_and_refuses_stale_base() {
    for (output_repo, push, synced, expected, base) in [
        ("owner/repo", true, false, 0, Some("fork")),
        ("Owner/Repo", true, false, 0, Some("fork")),
        ("owner/fork", true, false, 1, None),
        ("owner/fork", false, false, 1, Some("target")),
        ("owner/fork", false, true, 0, Some("target")),
    ] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let target = root.join("target");
        let fork = root.join("fork.git");
        let work = root.join("work");
        git(root, &["init", "-q", target.to_str().unwrap()]);
        identity(&target);
        let behind = commit(&target, "before\n");
        git(&target, &["branch", "-M", "main"]);
        git(
            root,
            &[
                "clone",
                "-q",
                "--bare",
                target.to_str().unwrap(),
                fork.to_str().unwrap(),
            ],
        );
        let ahead = commit(&target, "after\n");
        git(
            root,
            &[
                "clone",
                "-q",
                fork.to_str().unwrap(),
                work.to_str().unwrap(),
            ],
        );
        let kind = if push {
            "push_to_pull_request_branch"
        } else {
            "create_pull_request"
        };
        let mut config = if push {
            json!({kind:{"target":"42"}})
        } else {
            json!({kind:{"max":1}})
        };
        if synced {
            config["synced"] = json!(true);
        }
        json_file(root, "config.json", &config);
        json_file(
            root,
            "report.json",
            &json!({"patch":{"base_commit":if synced {&behind} else {&ahead}}}),
        );
        json_file(root, "agent_output.json", &json!({"items":[{"type":kind}]}));
        let out = run_step(
            &work,
            "Fetch the target's base branch",
            &[
                ("GH_AW_TMP", root.to_str().unwrap()),
                ("REPORT", root.join("report.json").to_str().unwrap()),
                ("REPO", "owner/repo"),
                ("OUTPUT_REPO", output_repo),
                ("BASE", "main"),
                ("FORK", "bot/repo"),
                ("GIT_CONFIG_COUNT", "2"),
                (
                    "GIT_CONFIG_KEY_0",
                    &format!("url.{}.insteadOf", target.display()),
                ),
                ("GIT_CONFIG_VALUE_0", "https://github.com/owner/repo"),
                (
                    "GIT_CONFIG_KEY_1",
                    &format!("url.{}.insteadOf", fork.display()),
                ),
                ("GIT_CONFIG_VALUE_1", "https://github.com/bot/repo"),
            ],
        );
        status(&out, expected);
        if expected != 0 {
            assert!(String::from_utf8_lossy(&out.stdout).contains(if push {
                "a push goes to a pull request of owner/repo"
            } else {
                "sync owner/fork"
            }));
        }
        assert_eq!(git(&fork, &["rev-parse", "main"]), behind);
        if let Some(base) = base {
            assert_eq!(
                git(&work, &["rev-parse", "refs/agentic-job/target-base"]),
                if base == "fork" { behind } else { ahead }
            );
        }
    }
}

#[test]
fn check_and_apply_refuse_policy_from_another_commit_and_empty_checked_id() {
    let apply = workflow("apply.yml");
    let checker = workflow("check.yml");
    let doc = definition("apply.yml");
    let guard = step(&doc, "apply", PINNED);
    let first_use =
        Regex::new(r"uses: actions/(checkout|download-artifact)@|- name: How the run ended")
            .unwrap();
    for (name, source) in [("check", &checker), ("apply", &apply), ("conclude", &apply)] {
        let job_text = job(source, name);
        assert!(
            job_text
                .split_once("    steps:\n")
                .unwrap()
                .1
                .starts_with("      # The pieces must be one commit"),
            "{name}"
        );
        assert!(
            job_text.find(&format!("- name: {PINNED}\n")).unwrap()
                < first_use.find(job_text).unwrap().start()
        );
        matches(
            job_text,
            r"SOURCE_REPOSITORY: \$\{\{ fromJSON\(inputs.policy\).source-repository \}\}\n {10}SOURCE_SHA: \$\{\{ fromJSON\(inputs.policy\).source-sha \}\}\n {10}REPOSITORY: \$\{\{ job.workflow_repository \}\}\n {10}SHA: \$\{\{ job.workflow_sha \}\}\n",
        );
        assert_eq!(
            step(
                &definition(if name == "check" {
                    "check.yml"
                } else {
                    "apply.yml"
                }),
                name,
                PINNED
            ),
            guard
        );
    }
    let sha = "a".repeat(40);
    let other = "b".repeat(40);
    for (repository, source, expected) in [
        ("o/r", sha.as_str(), 0),
        ("o/other", &sha, 1),
        ("o/r", &other, 1),
        ("o/r", "", 1),
        ("", "", 1),
    ] {
        let dir = TempDir::new().unwrap();
        status(
            &run_step(
                dir.path(),
                PINNED,
                &[
                    ("SOURCE_REPOSITORY", repository),
                    ("SOURCE_SHA", source),
                    ("REPOSITORY", "o/r"),
                    ("SHA", if repository.is_empty() { "" } else { &sha }),
                ],
            ),
            expected,
        );
    }
    let apply = job(&apply, "apply");
    assert!(
        apply
            .find("- name: Require the checked outputs' artifact ID\n")
            .unwrap()
            < apply.find("uses: actions/download-artifact@").unwrap()
    );
    let digest = "c".repeat(64);
    for (id, expected, hash) in [
        ("42", 0, digest.clone()),
        ("", 1, digest.clone()),
        ("0", 1, digest.clone()),
        ("01", 1, digest.clone()),
        ("1,2", 1, digest.clone()),
        ("1\n2", 1, digest.clone()),
        ("42", 1, String::new()),
        ("42", 1, format!("sha256:{digest}")),
        ("42", 1, "C".repeat(64)),
        ("42", 1, "c".repeat(63)),
    ] {
        let dir = TempDir::new().unwrap();
        status(
            &run_step(
                dir.path(),
                "Require the checked outputs' artifact ID",
                &[("CHECKED", id), ("DIGEST", &hash)],
            ),
            expected,
        );
    }
}

#[test]
fn apply_takes_only_this_runs_check_output_whatever_caller_wired() {
    let workflow = workflow("apply.yml");
    let apply = job(&workflow, "apply");
    let verify = "The checked outputs are this run's check's";
    let position = apply.find(&format!("- name: {verify}\n")).unwrap();
    assert!(
        apply
            .find("- name: Require the checked outputs' artifact ID\n")
            .unwrap()
            < position
    );
    for action in ["download-artifact", "checkout"] {
        assert!(position < apply.find(&format!("uses: actions/{action}@")).unwrap());
    }
    let checker = self::workflow("check.yml");
    matches(
        &checker,
        r"- id: upload\n {8}if: \$\{\{ success\(\) && [^\n]*\n(?:[^\n]*\n){2} {10}name: \$\{\{ fromJSON\(inputs.policy\).artifact-prefix \}\}checked-outputs\$\{\{ fromJSON\(inputs.policy\).continuation-context != '' && format\('-\{0\}-\{1\}', github.run_id, github.run_attempt\) \|\| '' \}\}\n",
    );
    matches(
        apply,
        r"NAME: \$\{\{ fromJSON\(inputs.policy\).artifact-prefix \}\}checked-outputs\n",
    );
    let digest = "c".repeat(64);
    let artifact = |name: &str, run: u64, hash: Value| {
        json!({"id":42,"name":name,"digest":hash,"workflow_run":{"id":run,"head_sha":"a".repeat(40)}}).to_string()
    };
    let hash = json!(format!("sha256:{digest}"));
    for (answer, expected) in [
        (artifact("p-checked-outputs", 7, hash.clone()), 0),
        (artifact("p-safe-outputs", 7, hash.clone()), 1),
        (artifact("checked-outputs", 7, hash.clone()), 1),
        (artifact("q-checked-outputs", 7, hash.clone()), 1),
        (artifact("p-checked-outputs", 8, hash.clone()), 1),
        (artifact("p-checked-outputs", 77, hash), 1),
        (json!({"name":"p-checked-outputs"}).to_string(), 1),
        (
            artifact(
                "p-checked-outputs",
                7,
                json!(format!("sha256:{}", "d".repeat(64))),
            ),
            1,
        ),
        (artifact("p-checked-outputs", 7, Value::Null), 1),
        (artifact("p-checked-outputs", 7, json!(digest)), 1),
        (String::new(), 1),
    ] {
        let dir = TempDir::new().unwrap();
        let script = format!(
            "gh() {{ [ \"$*\" = \"api repos/o/r/actions/artifacts/42\" ] || return 9; [ -n \"$ANSWER\" ] && printf \"%s\" \"$ANSWER\"; }}\n{}",
            step(&definition("apply.yml"), "apply", verify)["run"]
                .as_str()
                .unwrap()
        );
        status(
            &bash(
                dir.path(),
                &script,
                &[
                    ("CHECKED", "42"),
                    ("DIGEST", &digest),
                    ("NAME", "p-checked-outputs"),
                    ("GITHUB_REPOSITORY", "o/r"),
                    ("GITHUB_RUN_ID", "7"),
                    ("ANSWER", &answer),
                    ("CONTINUATION", ""),
                ],
            ),
            expected,
        );
    }
    for pattern in [
        r"artifact-digest: \$\{\{ steps.upload.outputs.artifact-digest \}\}",
        r"value: \$\{\{ jobs.detect.outputs.artifact-digest \}\}",
    ] {
        matches(&checker, pattern);
    }
    matches(
        apply,
        r"DIGEST: \$\{\{ fromJSON\(inputs.check\).outputs.artifact-digest \}\}",
    );
    matches(
        apply,
        r"artifact-ids: \$\{\{ fromJSON\(inputs.check\).outputs.artifact-id \}\}\n {10}path: [^\n]*\n {10}digest-mismatch: error\n",
    );
    matches(
        job(&self::workflow("example-compose.yml"), "apply"),
        r"(?m)^ {4}permissions:\n(?: {6}[-\w]+: \w+\n)*? {6}actions: read\n",
    );
}

#[test]
fn continuation_artifacts_refuse_prior_attempt_substitution_and_ambiguous_provenance() {
    let doc = definition("apply.yml");
    let binding = step(&doc, "apply", "The checked outputs are this run's check's");
    let verify = binding["run"].as_str().unwrap();
    let script = format!(
        "gh() {{ case \"$*\" in 'api repos/o/r/actions/artifacts/42') printf '%s' \"$ARTIFACT\";; 'api repos/o/r/actions/runs/7/artifacts?per_page=100') printf '%s' \"$LIST\";; *) return 9;; esac; }}\n{verify}"
    );
    let digest = "c".repeat(64);
    let identity = json!({"repository":"example/repo", "pull_request":12, "head":"a".repeat(40), "run_id":7, "attempt":2});
    let good = json!({"id":42, "name":"p-checked-outputs-7-2", "digest":format!("sha256:{digest}"), "expired":false, "workflow_run":{"id":7}});
    for case in [
        "valid",
        "previous-attempt",
        "old-check-job",
        "missing-check-attempt",
        "wrong-run",
        "wrong-context-run",
        "wrong-context-attempt",
        "missing-attempt",
        "missing-run",
        "legacy-name",
        "digest",
        "expired",
        "ambiguous",
        "missing",
        "wrong-id",
        "truncated",
        "unavailable",
    ] {
        let mut artifact = good.clone();
        let mut context = identity.clone();
        match case {
            "previous-attempt" => artifact["name"] = json!("p-checked-outputs-7-1"),
            "wrong-run" => artifact["workflow_run"]["id"] = json!(8),
            "wrong-context-run" => context["run_id"] = json!(8),
            "wrong-context-attempt" => context["attempt"] = json!(1),
            "missing-attempt" => {
                context.as_object_mut().unwrap().remove("attempt");
            }
            "missing-run" => {
                context.as_object_mut().unwrap().remove("run_id");
            }
            "legacy-name" => artifact["name"] = json!("p-checked-outputs"),
            "digest" => artifact["digest"] = json!(format!("sha256:{}", "d".repeat(64))),
            "expired" => artifact["expired"] = json!(true),
            _ => {}
        }
        let mut artifacts = vec![artifact.clone()];
        if case == "ambiguous" {
            artifacts.push(artifact.clone());
        }
        if case == "missing" {
            artifacts.clear();
        }
        if case == "wrong-id" {
            artifacts[0]["id"] = json!(43);
        }
        let list = if case == "unavailable" {
            String::new()
        } else {
            json!({"total_count":if case == "truncated" {101} else {artifacts.len()}, "artifacts":artifacts}).to_string()
        };
        let dir = TempDir::new().unwrap();
        status(
            &bash(
                dir.path(),
                &script,
                &[
                    ("CHECKED", "42"),
                    ("DIGEST", &digest),
                    ("NAME", "p-checked-outputs"),
                    ("GITHUB_REPOSITORY", "o/r"),
                    ("GITHUB_RUN_ID", "7"),
                    ("GITHUB_RUN_ATTEMPT", "2"),
                    (
                        "ARTIFACT_ATTEMPT",
                        match case {
                            "old-check-job" => "1",
                            "missing-check-attempt" => "",
                            _ => "2",
                        },
                    ),
                    ("CONTINUATION", &context.to_string()),
                    ("ARTIFACT", &artifact.to_string()),
                    ("LIST", &list),
                ],
            ),
            if case == "valid" { 0 } else { 1 },
        );
    }
}

#[test]
fn continuation_report_matches_every_admitted_identity_field_before_credentials() {
    let doc = definition("apply.yml");
    let name = "The checked continuation is the admitted target and attempt";
    let binding = step(&doc, "apply", name);
    let verify = binding["run"].as_str().unwrap();
    let source = workflow("apply.yml");
    let apply = job(&source, "apply");
    assert!(apply.find(name).unwrap() < apply.find("uses: actions/checkout@").unwrap());
    let identity = json!({"repository":"example/repo", "pull_request":12, "head":"a".repeat(40), "run_id":7, "attempt":2});
    for field in [
        "valid",
        "repository",
        "pull_request",
        "head",
        "run_id",
        "attempt",
        "missing",
        "refused",
        "policy",
    ] {
        let dir = TempDir::new().unwrap();
        let mut reported = identity.clone();
        if reported.get(field).is_some() {
            reported[field] = json!("wrong");
        }
        let report = dir.path().join("report.json");
        std::fs::write(&report, json!({"ok":field != "refused", "continuation":if field == "missing" {Value::Null} else {reported}}).to_string()).unwrap();
        std::fs::write(
            dir.path().join("policy.json"),
            json!({"continuation":if field == "policy" {Value::Null} else {identity.clone()}})
                .to_string(),
        )
        .unwrap();
        status(
            &bash(
                dir.path(),
                verify,
                &[
                    ("CONTINUATION", &identity.to_string()),
                    ("GH_AW_TMP", dir.path().to_str().unwrap()),
                    ("REPORT", report.to_str().unwrap()),
                ],
            ),
            if field == "valid" { 0 } else { 1 },
        );
    }
}

#[test]
fn issue_linking_executes_only_policy_binary_artifacts_from_this_run() {
    let doc = definition("apply.yml");
    let require = step(&doc, "apply", "Require policy's binary");
    for (id, name, run, success) in [
        ("42", "p-agentic-job-binary", "7", true),
        ("", "p-agentic-job-binary", "7", false),
        ("1,2", "p-agentic-job-binary", "7", false),
        ("0", "p-agentic-job-binary", "7", false),
        ("42", "p-safe-outputs", "7", false),
        ("42", "q-agentic-job-binary", "7", false),
        ("42", "p-agentic-job-binary", "8", false),
        ("42", "", "7", false),
    ] {
        let dir = TempDir::new().unwrap();
        let script = format!(
            "gh() {{ [ -n \"$NAME_FROM_API\" ] || return 9; printf '{{\"name\":\"%s\",\"workflow_run\":{{\"id\":%s}}}}' \"$NAME_FROM_API\" \"$RUN_FROM_API\"; }}\n{}",
            require["run"].as_str().unwrap()
        );
        let out = bash(
            dir.path(),
            &script,
            &[
                ("BINARY", id),
                ("NAME", "p-agentic-job-binary"),
                ("GITHUB_REPOSITORY", "o/r"),
                ("GITHUB_RUN_ID", "7"),
                ("NAME_FROM_API", name),
                ("RUN_FROM_API", run),
            ],
        );
        assert_eq!(out.status.success(), success, "{}", text(&out));
    }
    let source = workflow("apply.yml");
    for job_name in ["apply", "conclude"] {
        matches(
            job(&source, job_name),
            &format!(
                r"artifact-ids: \$\{{\{{ fromJSON\(inputs.policy\).binary-artifact-id \}}\}}\n {{10}}path: \$\{{\{{ runner.temp \}}\}}/{job_name}-binary\n {{10}}digest-mismatch: error"
            ),
        );
    }
    assert_eq!(
        step(&doc, "conclude", "Require policy's binary")["run"],
        require["run"]
    );
}

#[test]
fn notify_failure_never_stops_run_and_conclude_reports_it() {
    let policy = workflow("policy.yml");
    let notify = job(&policy, "notify");
    let agent_end = Regex::new(r"\n    (?:runs-on|permissions):").unwrap();
    matches(
        notify.split_once("    steps:\n").unwrap().0,
        r"(?m)^ {4}continue-on-error: true$",
    );
    for (file, source) in [
        ("agentic-job.yml", workflow("agentic-job.yml")),
        ("example-compose.yml", workflow("example-compose.yml")),
        (
            "workflow.md",
            fs::read_to_string(root().join("docs/workflow.md")).unwrap(),
        ),
    ] {
        let agent = source.split_once("\n  agent:\n").unwrap().1;
        let end = agent_end.find(agent).unwrap().start();
        let needs = if file == "agentic-job.yml" {
            r"\[policy, register\]"
        } else {
            "policy"
        };
        matches(
            &agent[..end],
            &format!(
                r"^ {{4}}needs: {needs}\n {{4}}(?:#.*\n {{4}})*if: \$\{{\{{ (?:inputs.proposals-artifact == '' && )?needs.policy.outputs.admitted == 'true' \}}\}}$"
            ),
        );
    }
    matches(
        &policy,
        r"notified:\n[^\n]*\n {8}value: \$\{\{ jobs.notify.result != 'skipped' \}\}",
    );
    let doc = definition("policy.yml");
    for name in [
        "An eyes reaction on what started the run",
        "A comment that says the run started",
    ] {
        assert_eq!(
            step(&doc, "notify", name)["continue-on-error"].as_bool(),
            Some(true)
        );
    }
    assert!(
        step(&doc, "notify", "What to react to, and where to comment")["continue-on-error"]
            .is_badvalue()
    );
    matches(
        notify,
        r"(?m)^ {6}item: \$\{\{ steps.target.outputs.item \}\}$",
    );
    matches(
        &policy,
        r"notify-item:\n[^\n]*\n {8}value: \$\{\{ jobs.notify.outputs.item \|\| jobs.policy.outputs.item \|\| jobs.policy.outputs.comment-target \}\}",
    );
    let source = workflow("apply.yml");
    let conclude = job(&source, "conclude");
    matches(
        conclude,
        r"- name: Edit the status comment\n {8}if: .*needs\.apply\.outputs\.missing-data == 'true'",
    );
    assert!(!conclude.contains("Post the refusal to the comment target"));
    matches(
        conclude,
        r"- name: A reaction that says how it ended\n {8}if: \$\{\{ fromJSON\(inputs.policy\).notify == 'reaction' && fromJSON\(inputs.policy\).notified == 'true' && fromJSON\(inputs.policy\).notify-id != '' \}\}",
    );
    for (kind, id, expected, call) in [
        ("issue", "42", 0, "POST repos/o/r/issues/42/reactions"),
        (
            "comment",
            "42",
            0,
            "POST repos/o/r/issues/comments/42/reactions",
        ),
        (
            "review_comment",
            "42",
            0,
            "POST repos/o/r/pulls/comments/42/reactions",
        ),
        ("issue", "$(exit 9)", 1, ""),
        ("issue", "4 2", 1, ""),
    ] {
        let dir = TempDir::new().unwrap();
        let script = format!(
            "gh() {{ echo \"$3 $4\"; }};\n{}",
            step(
                &definition("apply.yml"),
                "conclude",
                "A reaction that says how it ended"
            )["run"]
                .as_str()
                .unwrap()
        );
        let out = bash(
            dir.path(),
            &script,
            &[
                ("KIND", kind),
                ("ID", id),
                ("REACTION", "rocket"),
                ("GITHUB_REPOSITORY", "o/r"),
            ],
        );
        status(&out, expected);
        if expected == 0 {
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), call);
        }
    }
}

#[test]
fn conclude_says_how_run_ended() {
    // results, PR, no result, text, URL, over budget, PR repository, staged,
    // secret location. Locations are not secret material.
    for (results, pr, none, expected, url, over, pr_repo, staged, secret_at) in [
        (
            "success/success/success",
            "",
            "",
            "✅ [w](u) ended well.",
            "",
            "",
            "",
            "",
            "",
        ),
        (
            "success/success/success",
            "39",
            "",
            "✅ [w](u) ended well and opened pull request #39.",
            "",
            "",
            "",
            "",
            "",
        ),
        (
            "success/success/success",
            "39",
            "",
            "✅ [w](u) ended well and opened pull request o/r#39.",
            "",
            "",
            "o/r",
            "",
            "",
        ),
        (
            "success/success/success",
            "",
            "true",
            "✅ [w](u) ended well and handed back no result.",
            "",
            "",
            "",
            "",
            "",
        ),
        (
            "success/skipped/skipped",
            "",
            "",
            "✅ [w](u) ended well and handed back nothing to apply.",
            "",
            "",
            "",
            "",
            "",
        ),
        (
            "success/success/failure",
            "",
            "true",
            "❌ [w](u) failed (agent, check, apply: success/success/failure; the agent's exit state: 0).",
            "",
            "",
            "",
            "",
            "",
        ),
        (
            "success/success/success",
            "",
            "",
            "✅ [w](u) ended well. Result: https://github.com/o/r/issues/7#issuecomment-1",
            "https://github.com/o/r/issues/7#issuecomment-1",
            "",
            "",
            "",
            "",
        ),
        (
            "cancelled/skipped/skipped",
            "",
            "",
            "⏹️ [w](u) was cancelled.",
            "",
            "",
            "",
            "",
            "",
        ),
        (
            "success/success/success",
            "",
            "",
            "✅ [w](u) ended well. Its last reply took the agent over budget: it spent 565.9 of 500 AIC.",
            "",
            "565.9 of 500 AIC",
            "",
            "",
            "",
        ),
        (
            "success/success/success",
            "",
            "",
            "✅ [w](u) ended well.",
            "",
            "565.9 of 500 AIC $(exit 9)",
            "",
            "",
            "",
        ),
        (
            "success/success/failure",
            "",
            "",
            "❌ [w](u) failed (agent, check, apply: success/success/failure; the agent's exit state: 0).",
            "",
            "565.9 of 500 AIC",
            "",
            "",
            "",
        ),
        (
            "success/success/success",
            "",
            "",
            "✅ [w](u) ended well. Staged: nothing was applied; the apply job's summary shows what would have been.",
            "",
            "",
            "",
            "true",
            "",
        ),
        (
            "success/success/failure",
            "",
            "",
            "❌ [w](u) failed (agent, check, apply: success/success/failure; the agent's exit state: 0).",
            "",
            "",
            "",
            "true",
            "",
        ),
        (
            "failure/skipped/skipped",
            "",
            "",
            "❌ [w](u) failed (agent, check, apply: failure/skipped/skipped; the agent's exit state: 0). Nothing was uploaded: a secret or a private key is in `safe-outputs/aw-agent-run-1.patch, line 3 (known run secret: GH_TOKEN)`.",
            "",
            "",
            "",
            "",
            "safe-outputs/aw-agent-run-1.patch, line 3 (known run secret: GH_TOKEN)",
        ),
        (
            "failure/skipped/skipped",
            "",
            "",
            "❌ [w](u) failed (agent, check, apply: failure/skipped/skipped; the agent's exit state: 0).",
            "",
            "",
            "",
            "",
            "safe-outputs/a`@b`.patch, line 3",
        ),
        (
            "failure/skipped/skipped",
            "",
            "",
            "❌ [w](u) failed (agent, check, apply: failure/skipped/skipped; the agent's exit state: 0).",
            "",
            "",
            "",
            "",
            "../x, line 3",
        ),
    ] {
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("output");
        let out = run_step(
            dir.path(),
            "How the run ended",
            &[
                ("RESULTS", results),
                ("EXIT", "0"),
                ("PR", pr),
                ("PR_REPO", pr_repo),
                ("NO_RESULT", none),
                ("REFUSAL", ""),
                ("RESULT_URL", url),
                ("OVER_BUDGET", over),
                ("SECRET_AT", secret_at),
                ("STAGED", staged),
                ("WORKFLOW", "w"),
                ("RUN_URL", "u"),
                ("GITHUB_OUTPUT", output.to_str().unwrap()),
            ],
        );
        status(&out, 0);
        assert_eq!(
            fs::read_to_string(output).unwrap().lines().next().unwrap(),
            format!("text={expected}")
        );
    }
    // A run stopped at a limit, or whose agent said it stopped early,
    // that handed back no result did not do what it was asked (#3017).
    // (exit state, the agent's stopped-early, no result, failure class,
    // blocked, the status line)
    for (exit, stopped, none, class, blocked, expected) in [
        (
            "0",
            "true",
            "true",
            "",
            "",
            "⚠️ [w](u) stopped before the task was done and handed back no result.",
        ),
        // Only the run action's fixed word counts.
        (
            "0",
            "yes",
            "true",
            "",
            "",
            "✅ [w](u) ended well and handed back no result.",
        ),
        (
            "0",
            "",
            "true",
            "",
            "",
            "✅ [w](u) ended well and handed back no result.",
        ),
        // A run that handed back a result, or is blocked, says so as before.
        (
            "0",
            "true",
            "",
            "",
            "",
            "✅ [w](u) ended well and opened pull request #39.",
        ),
        (
            "0",
            "true",
            "true",
            "",
            "true",
            "<!-- agentic-job-outcome: blocked -->⏸️ [w](u) is blocked: it handed back missing_data and no change.",
        ),
        (
            "3",
            "",
            "true",
            "",
            "",
            "⚠️ [w](u) stopped before the task was done and handed back no result (exit state 3).",
        ),
        (
            "124",
            "true",
            "true",
            "timeout",
            "",
            "⚠️ [w](u) stopped before the task was done and handed back no result (exit state 124, timeout).",
        ),
        (
            "3",
            "",
            "",
            "",
            "",
            "✅ [w](u) ended well and opened pull request #39. The run was stopped at a limit (exit state 3); what it handed back is marked partial.",
        ),
    ] {
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("output");
        let out = run_step(
            dir.path(),
            "How the run ended",
            &[
                ("RESULTS", "success/success/success"),
                ("EXIT", exit),
                ("STOPPED_EARLY", stopped),
                ("FAILURE_CLASS", class),
                ("BLOCKED", blocked),
                ("PR", if none.is_empty() { "39" } else { "" }),
                ("NO_RESULT", none),
                ("NO_RESULT_REASON", "\"Could not hand it back.\""),
                ("WORKFLOW", "w"),
                ("RUN_URL", "u"),
                ("GITHUB_OUTPUT", output.to_str().unwrap()),
            ],
        );
        status(&out, 0);
        let written = fs::read_to_string(output).unwrap();
        assert!(written.contains(&format!("text={expected}\n")), "{written}");
        // Nor is one that handed back nothing at all, which check and
        // apply skip.
        let skipped = dir.path().join("skipped");
        let out = run_step(
            dir.path(),
            "How the run ended",
            &[
                ("RESULTS", "success/skipped/skipped"),
                ("EXIT", exit),
                ("STOPPED_EARLY", stopped),
                ("FAILURE_CLASS", class),
                ("WORKFLOW", "w"),
                ("RUN_URL", "u"),
                ("GITHUB_OUTPUT", skipped.to_str().unwrap()),
            ],
        );
        status(&out, 0);
        let stopped_line = exit != "0" || stopped == "true";
        assert_eq!(
            fs::read_to_string(skipped)
                .unwrap()
                .contains("stopped before the task was done and handed back no result"),
            stopped_line,
            "{exit} {stopped}"
        );
        // The agent's reason still reaches the status comment.
        assert_eq!(
            written.contains("no-result-reason=\"Could not hand it back.\""),
            !none.is_empty(),
            "{written}"
        );
    }
}

#[test]
fn comment_only_apply_skips_every_repository_step_including_checkout() {
    let doc = definition("apply.yml");
    let gate = "${{ fromJSON(inputs.check).outputs.has-patch == 'true' && fromJSON(inputs.policy).apply-staged != 'true' }}";
    let checkout = doc["jobs"]["apply"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/checkout@"))
        })
        .unwrap();
    assert_eq!(checkout["if"].as_str(), Some(gate));
    for name in ["Configure git", "Fetch the target's base branch", TRIAL] {
        assert_eq!(
            step(&doc, "apply", name)["if"].as_str(),
            Some(gate),
            "{name}"
        );
    }
    let checker = workflow("check.yml");
    matches(
        &checker,
        r"has-patch: \$\{\{ steps.checked.outputs.has-patch \}\}",
    );
    matches(&checker, r"value: \$\{\{ jobs.check.outputs.has-patch \}\}");
    let dir = TempDir::new().unwrap();
    json_file(dir.path(), "report.json", &json!({"patch":null}));
    // No .git and no topic base: a null patch must exit before touching git.
    status(
        &run_step(
            dir.path(),
            TRIAL,
            &[("REPORT", dir.path().join("report.json").to_str().unwrap())],
        ),
        0,
    );
}

/// Exercise checked no-write data through the CLI's real job-output encoding,
/// conclude's actual shell, and the status writer against a local forge.
#[test]
fn no_write_reports_reach_one_status_comment_without_reclassifying_outcomes() {
    use agentic_job::apply::status::{MAX_BODY_BYTES, Status};
    use safe_outputs::apply::testing::forge;
    use std::collections::BTreeMap;

    let long = format!("{}END OF INVENTORY", "inventory line\n".repeat(1500));
    for (items, results, blocked, refused, published) in [
        (
            json!([{"type":"noop", "message":"nothing to change"}]),
            "success/success/success",
            "",
            "",
            true,
        ),
        (
            json!([{"type":"noop", "message":long}]),
            "success/success/success",
            "",
            "",
            true,
        ),
        (
            json!([{"type":"noop", "message":long}, {"type":"missing_tool", "tool":"scanner", "reason":"unavailable"}]),
            "success/success/success",
            "",
            "",
            true,
        ),
        (
            json!([{"type":"missing_data", "reason":"need logs"}]),
            "success/success/success",
            "true",
            "",
            true,
        ),
        (
            json!([{"type":"missing_data", "reason":"need logs"}, {"type":"noop", "message":long}]),
            "success/success/success",
            "true",
            "",
            true,
        ),
        (
            json!([{"type":"missing_data", "reason":"need logs"}, {"type":"missing_tool", "reason":"need scanner"}, {"type":"noop", "message":long}]),
            "success/success/failure",
            "",
            "",
            true,
        ),
        (
            json!([{"type":"noop", "message":long}]),
            "failure/success/skipped",
            "",
            "",
            false,
        ),
        (
            json!([{"type":"noop", "message":long}]),
            "success/failure/skipped",
            "",
            "refused by policy",
            false,
        ),
    ] {
        let dir = TempDir::new().unwrap();
        json_file(
            dir.path(),
            "applied.json",
            &json!({"made":[], "already_applied":[], "pull_request":null}),
        );
        json_file(dir.path(), "agent_output.json", &json!({"items":items}));
        let output = dir.path().join("result");
        let summary = dir.path().join("summary");
        fs::write(&output, "").unwrap();
        fs::write(&summary, "").unwrap();
        let run_url = "https://github.com/caller/repo/actions/runs/100";
        let result = Command::new(BIN)
            .args(["result", "--dir"])
            .arg(dir.path())
            .arg("--output")
            .arg(&output)
            .arg("--summary")
            .arg(&summary)
            .env("RUN_URL", run_url)
            .env("CHECKED_ARTIFACT_ID", "99")
            .env("GH_AW_SAFE_OUTPUTS_URLS", "allowed-or-code-region")
            .output()
            .unwrap();
        status(&result, 0);
        let fields = fs::read_to_string(&output).unwrap();
        let fields: BTreeMap<_, _> = fields
            .lines()
            .map(|line| line.split_once('=').unwrap())
            .collect();
        let ended = dir.path().join("ended");
        status(
            &run_step(
                dir.path(),
                "How the run ended",
                &[
                    ("RESULTS", results),
                    ("EXIT", "0"),
                    ("PR", ""),
                    ("PR_REPO", ""),
                    ("NO_RESULT", fields["no-result"]),
                    ("NO_RESULT_REASON", fields["no-result-reason"]),
                    ("MISSING_DATA", fields["missing-data"]),
                    ("BLOCKED", blocked),
                    ("REFUSAL", refused),
                    ("WORKFLOW", "audit"),
                    ("RUN_URL", run_url),
                    ("GITHUB_OUTPUT", ended.to_str().unwrap()),
                ],
            ),
            0,
        );
        let ended = fs::read_to_string(ended).unwrap();
        let ended: BTreeMap<_, _> = ended
            .lines()
            .map(|line| line.split_once('=').unwrap())
            .collect();
        assert_eq!(ended.contains_key("no-result-reason"), published);
        let env = BTreeMap::from([
            ("REPO", "owner/item"),
            ("ITEM", "42"),
            ("GITHUB_RUN_ID", "100"),
            ("TEXT", ended["text"]),
            (
                "NO_RESULT_REASON",
                ended.get("no-result-reason").copied().unwrap_or(""),
            ),
        ]);
        let update = Status::from_env(|key| {
            env.get(key)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        })
        .unwrap();
        assert!(update.body.len() <= MAX_BODY_BYTES);
        if published && items.to_string().contains("END OF INVENTORY") {
            assert!(update.body.contains("END OF INVENTORY"));
            assert!(update.body.contains("<details>"));
            assert!(update.body.contains(&format!("{run_url}/artifacts/99")));
        }
        if blocked == "true" {
            assert!(
                update
                    .body
                    .starts_with("<!-- agentic-job-outcome: blocked -->")
            );
        } else if results.ends_with("failure") || !refused.is_empty() {
            assert!(update.body.starts_with('❌'));
        }
        if !published {
            assert!(!update.body.contains("END OF INVENTORY"));
        }
        let list = "GET /repos/owner/item/issues/42/comments?per_page=100&page=1";
        let post = "POST /repos/owner/item/issues/42/comments";
        let patch = "PATCH /repos/owner/item/issues/comments/5";
        let (github, requests) = forge(BTreeMap::from([
            (list.into(), (200, json!([]))),
            (post.into(), (201, json!({"id":5}))),
        ]));
        update.upsert(&github, "bot", &mut |_| {}).unwrap();
        let writes: Vec<_> = requests
            .try_iter()
            .filter(|r| r.line.starts_with("POST "))
            .collect();
        assert_eq!(writes.len(), 1);
        let body = writes[0].body["body"].as_str().unwrap();
        assert_eq!(body, update.body);
        // Retry edits the same item/comment; a newer run is not overwritten.
        for newer in [false, true] {
            let body = if newer {
                body.replace("run: 100", "run: 101")
            } else {
                body.to_owned()
            };
            let (github, requests) = forge(BTreeMap::from([
                (
                    list.into(),
                    (200, json!([{"id":5,"user":{"login":"bot"},"body":body}])),
                ),
                (patch.into(), (200, json!({"id":5}))),
            ]));
            update.upsert(&github, "bot", &mut |_| {}).unwrap();
            let writes: Vec<_> = requests
                .try_iter()
                .filter(|r| !r.line.starts_with("GET "))
                .collect();
            assert_eq!(writes.len(), usize::from(!newer));
            if !newer {
                assert!(writes[0].line.starts_with(patch));
                assert_eq!(writes[0].body["body"], update.body);
            }
        }
    }
}

#[test]
fn cross_repository_report_status_never_borrows_the_job_token() {
    let dir = TempDir::new().unwrap();
    let summary = dir.path().join("summary");
    fs::write(&summary, "").unwrap();
    let result = Command::new(BIN)
        .arg("status")
        .env_remove("APPLY_ROLE_BINDINGS")
        .env_remove("STATUS_TOKEN")
        .env("GITHUB_REPOSITORY", "caller/repo")
        .env("REPO", "owner/item")
        .env("ITEM", "42")
        .env("GITHUB_RUN_ID", "100")
        .env("TEXT", "ended")
        .env(
            "NO_RESULT_REASON",
            serde_json::to_string(&"long report ".repeat(2000)).unwrap(),
        )
        .env("GITHUB_STEP_SUMMARY", &summary)
        // No forge should even be contacted without a caller credential.
        .env("GH_TOKEN", "")
        .env("GITHUB_API_URL", "http://127.0.0.1:1")
        .output()
        .unwrap();
    status(&result, 0);
    assert!(
        fs::read_to_string(summary)
            .unwrap()
            .contains("cross-repository target requires")
    );
}
