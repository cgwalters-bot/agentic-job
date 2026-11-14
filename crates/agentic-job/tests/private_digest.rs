//! The private digest caller of `.github/agentic-job/private-digest/`,
//! held to docs/private-repositories.md: what its bounds admit, that check
//! keeps it to one comment on its item, that its egress policy is one a
//! private run takes, and that its workflow composes the private path of
//! policy.yml and an agent job of its own, not agentic-job.yml.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use yaml_rust2::{Yaml, YamlLoader};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

/// The example's directory, relative to the repository's root.
const DIR: &str = ".github/agentic-job/private-digest";

/// The private repository the tests put in place of the placeholder.
const REPO: &str = "owner/digest";

/// The repository placeholder of allow.toml.
const REPO_PLACEHOLDER: &str = "OWNER/PRIVATE-REPO";

/// The digest issue the tests put in place of `DIGEST_ISSUE`.
const ITEM: &str = "42";

/// The line of allow.toml that opts into private runs.
const OPT_IN: &str = "private = true\n";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn example(name: &str) -> String {
    std::fs::read_to_string(root().join(DIR).join(name)).expect("reading the example")
}

/// allow.toml for `REPO`, without its opt-in unless `private`, with
/// `extra` lines added to its `[github.outputs]`.
fn bounds(dir: &Path, name: &str, private: bool, extra: &str) -> PathBuf {
    let text = example("allow.toml").replace(REPO_PLACEHOLDER, REPO);
    assert!(text.contains(OPT_IN) && text.contains(REPO));
    let text = if private {
        text
    } else {
        text.replace(OPT_IN, "")
    };
    let path = dir.join(name);
    std::fs::write(&path, format!("{text}{extra}")).expect("writing the bounds");
    path
}

fn yaml(path: &str) -> Yaml {
    let text = std::fs::read_to_string(root().join(path)).expect("reading the workflow");
    YamlLoader::load_from_str(&text)
        .expect("parsing the workflow")
        .remove(0)
}

/// Runs the `run` script of STEP with bash in DIR, with ENV.
fn script(step: &Yaml, dir: &Path, env: &[(&str, &str)]) -> Output {
    Command::new("bash")
        .args([
            "-eo",
            "pipefail",
            "-c",
            step["run"].as_str().expect("a run step"),
        ])
        .current_dir(dir)
        .envs(env.iter().copied())
        .output()
        .expect("running bash")
}

/// A case of the bounds test: its name, the caller's bounds, the
/// organization's, the flags that differ from the request, and a part of
/// the refusal, None where it is admitted.
type Case<'a> = (
    &'a str,
    &'a Path,
    Option<&'a Path>,
    &'a [(&'a str, &'a str)],
    Option<&'a str>,
);

#[test]
fn the_bounds_admit_one_comment_in_the_private_repository_alone() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let opted = bounds(dir, "allow.toml", true, "");
    let not_opted = bounds(dir, "not-opted.toml", false, "");
    let wider = bounds(
        dir,
        "wider.toml",
        true,
        "create_pull_request = { max = 1 }\nupdate_project = { max = 1, projects = \
         [\"https://github.com/orgs/owner/projects/1\"], fields = [\"Status\"] }\n",
    );
    let clone_url = format!("https://github.com/{REPO}");
    let base: &[(&str, &str)] = &[
        ("--repo", REPO),
        ("--clone-url", &clone_url),
        ("--base", "main"),
        ("--kind", "analysis"),
        ("--outputs", "add_comment"),
        ("--max-outputs", "1"),
        ("--output-repo", REPO),
    ];
    // An empty value in a case drops its flag from `base`.
    let cases: &[Case] = &[
        ("the example", &opted, None, &[], None),
        ("the organization opts in", &opted, Some(&opted), &[], None),
        (
            "the caller does not opt in",
            &not_opted,
            None,
            &[],
            Some("do not set `private = true`"),
        ),
        (
            "the organization does not opt in",
            &opted,
            Some(&not_opted),
            &[],
            Some("do not set `private = true`"),
        ),
        (
            "another target",
            &opted,
            None,
            &[
                ("--repo", "owner/other"),
                ("--clone-url", "https://github.com/owner/other"),
                ("--output-repo", "owner/other"),
            ],
            Some("not within the bounds"),
        ),
        (
            "outputs to another repository",
            &opted,
            None,
            &[("--output-repo", "owner/public")],
            Some("applies only to its own repository"),
        ),
        (
            "no output repository",
            &opted,
            None,
            &[("--output-repo", "")],
            Some("not an unnamed one"),
        ),
        (
            "the item in another repository",
            &opted,
            None,
            &[("--item-repo", "owner/public")],
            Some("item is in its own repository"),
        ),
        (
            "two outputs",
            &opted,
            None,
            &[("--max-outputs", "2")],
            Some("max_outputs"),
        ),
        (
            "another output type",
            &opted,
            None,
            &[("--outputs", "add_comment,create_issue")],
            Some("create_issue"),
        ),
        (
            "a patch, though the bounds list it",
            &wider,
            None,
            &[("--kind", "branch"), ("--outputs", "create_pull_request")],
            Some("hands back no patch"),
        ),
        (
            "a project, though the bounds list it",
            &wider,
            None,
            &[("--outputs", "update_project")],
            Some("can't update_project"),
        ),
    ];
    for (name, allow, org, change, refusal) in cases {
        let mut command = Command::new(BIN);
        command
            .arg("policy")
            .arg("--allow")
            .arg(allow)
            .arg("--private");
        if let Some(org) = org {
            command.arg("--org-allow").arg(org);
        }
        let mut flags: Vec<(&str, &str)> = base
            .iter()
            .filter(|(flag, _)| !change.iter().any(|(changed, _)| changed == flag))
            .copied()
            .collect();
        flags.extend(change.iter().filter(|(_, value)| !value.is_empty()));
        for (flag, value) in flags {
            command.args([flag, value]);
        }
        let output = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        match refusal {
            None => {
                assert!(output.status.success(), "{name}: {stderr}");
                let policy: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(policy["private"], true, "{name}");
                assert_eq!(policy["max_outputs"], 1, "{name}");
                assert_eq!(
                    policy["safe_outputs"],
                    json!({"add_comment": {"max": 1}}),
                    "{name}"
                );
            }
            Some(refusal) => {
                assert_eq!(output.status.code(), Some(1), "{name}: {stderr}");
                assert!(output.stdout.is_empty(), "{name}");
                assert!(stderr.contains(refusal), "{name}: {stderr}");
            }
        }
    }
}

/// The name of policy.yml's step that runs `agentic-job policy`.
const POLICY_STEP: &str = "Check the request against the caller's bounds";

/// The example's placeholders filled in, as the workflow's inputs.
const FILLED: &[(&str, &str)] = &[("comment-target", ITEM), ("issue", ITEM)];

/// Runs policy.yml's POLICY_STEP in DIR with the example's policy inputs,
/// CHANGE over them, the bounds of [`bounds`], and the visibility step's
/// `private` output where `private`. Returns the step's output, with
/// what it wrote to `$GITHUB_OUTPUT`; JOB_DIR is DIR/job.
fn policy_step(dir: &Path, change: &[(&str, &str)], private: bool) -> (Output, String) {
    let policy_yml = yaml(".github/workflows/policy.yml");
    let defaults = &policy_yml["on"]["workflow_call"]["inputs"];
    let step = policy_yml["jobs"]["policy"]["steps"]
        .as_vec()
        .expect("policy.yml's steps")
        .iter()
        .find(|step| step["name"].as_str() == Some(POLICY_STEP))
        .expect("policy.yml's policy step");
    let example = yaml(&format!("{DIR}/workflow.yml"));
    let with = &example["jobs"]["policy"]["with"];
    let allow = bounds(dir, "allow.toml", true, "");
    let input = |name: &str| -> String {
        if let Some((_, value)) = change.iter().find(|(changed, _)| *changed == name) {
            return (*value).to_owned();
        }
        if name == "allow" {
            return allow.to_str().expect("a UTF-8 path").to_owned();
        }
        match (&with[name], &defaults[name]["default"]) {
            (Yaml::String(value), _) => value.replace("${{ github.repository }}", REPO),
            (Yaml::BadValue, Yaml::String(value)) => value.clone(),
            (Yaml::BadValue, Yaml::Boolean(value)) => value.to_string(),
            _ => String::new(),
        }
    };
    let job_dir = dir.join("job");
    std::fs::create_dir_all(job_dir.join("bin")).expect("making JOB_DIR");
    let _ = std::fs::remove_file(job_dir.join("bin/agentic-job"));
    std::os::unix::fs::symlink(BIN, job_dir.join("bin/agentic-job")).expect("linking the binary");
    let github_output = dir.join("github-output");
    std::fs::write(&github_output, "").expect("emptying GITHUB_OUTPUT");
    let mut env: Vec<(String, String)> = step["env"]
        .as_hash()
        .expect("the step's env")
        .iter()
        .map(|(key, value)| {
            let value = value.as_str().expect("an expression");
            let value = match value
                .strip_prefix("${{ inputs.")
                .and_then(|name| name.strip_suffix(" }}"))
            {
                Some(name) => input(name),
                None if value == "${{ steps.visibility.outputs.private }}" && private => {
                    "true".to_owned()
                }
                None => String::new(),
            };
            (key.as_str().expect("a name").to_owned(), value)
        })
        .collect();
    env.extend([
        ("JOB_DIR".to_owned(), job_dir.display().to_string()),
        (
            "GITHUB_OUTPUT".to_owned(),
            github_output.display().to_string(),
        ),
        ("GITHUB_REPOSITORY".to_owned(), REPO.to_owned()),
    ]);
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let output = script(step, dir, &env);
    let written = std::fs::read_to_string(&github_output).expect("reading GITHUB_OUTPUT");
    (output, written)
}

/// policy.yml's own policy step, given the example's inputs: a private
/// target gets `--private` and its own repository as the output
/// repository, and an issue placeholder left as it is or another output
/// repository is refused before any agent runs.
#[test]
fn policy_yml_runs_the_example_as_a_private_run() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let (output, written) = policy_step(dir, FILLED, true);
    assert!(output.status.success(), "{output:?}");
    assert!(
        written.contains(&format!("comment-target={ITEM}\n")),
        "{written}"
    );
    let policy: Value =
        serde_json::from_slice(&std::fs::read(dir.join("job/policy.json")).unwrap()).unwrap();
    assert_eq!(policy["private"], true);
    assert_eq!(policy["repo"], REPO);
    assert_eq!(policy["safe_outputs"], json!({"add_comment": {"max": 1}}));
    // A public run of the same request is not marked private.
    let (output, _) = policy_step(dir, FILLED, false);
    assert!(output.status.success(), "{output:?}");
    let policy: Value =
        serde_json::from_slice(&std::fs::read(dir.join("job/policy.json")).unwrap()).unwrap();
    assert!(policy.get("private").is_none(), "{policy}");
    for (change, refusal) in [
        (&[][..], "issue is not a number"),
        (
            &[
                ("comment-target", ITEM),
                ("issue", ITEM),
                ("output-repo", "owner/public"),
            ][..],
            "applies only to its own repository",
        ),
    ] {
        let (output, _) = policy_step(dir, change, true);
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{change:?}: {log}");
        assert!(log.contains(refusal), "{change:?}: {log}");
    }
}

/// Check, given the policy and the fixed item policy.yml makes of the
/// example, takes one comment on the digest issue and nothing else.
#[test]
fn check_takes_one_comment_on_the_digest_issue() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let (output, written) = policy_step(dir, FILLED, true);
    assert!(output.status.success(), "{output:?}");
    let target = written
        .lines()
        .find_map(|line| line.strip_prefix("comment-target="))
        .unwrap();
    assert_eq!(target, ITEM);
    let policy = dir.join("job/policy.json");
    let out = dir.join("out");
    std::fs::create_dir(&out).unwrap();
    let comment = |fields: Value| {
        let mut item = fields.as_object().unwrap().clone();
        item.insert("type".into(), json!("add_comment"));
        item.insert("body".into(), json!("This week's digest."));
        Value::Object(item)
    };
    let item: u64 = ITEM.parse().unwrap();
    // The outputs, and a part of check's refusal, None where it is
    // accepted.
    let mut cases = vec![
        (vec![comment(json!({}))], None),
        (vec![comment(json!({"item_number": item}))], None),
        (
            vec![comment(json!({"item_number": item + 1}))],
            Some("outside the caller's fixed item"),
        ),
        (
            vec![comment(
                json!({"repo": "owner/public", "item_number": item}),
            )],
            Some("which is not the policy's"),
        ),
        (
            vec![comment(json!({})), comment(json!({}))],
            Some("over max_outputs 1"),
        ),
        (
            vec![json!({"type": "create_issue", "title": "Digest", "body": "This week's digest."})],
            Some("which the policy does not allow"),
        ),
    ];
    // Check all aliases independently, and with a valid preferred selector:
    // an alternate field must not redirect a digest off the caller's issue.
    for key in [
        "item_number",
        "pr",
        "pr_number",
        "issue_number",
        "pull_request_number",
        "pull_number",
        "pr-number",
    ] {
        for value in [json!(item), json!(item.to_string())] {
            cases.push((vec![comment(json!({key: value}))], None));
        }
        for value in [json!(item + 1), json!((item + 1).to_string())] {
            for preferred in [json!({}), json!({"item_number": item})] {
                let mut fields = preferred.as_object().unwrap().clone();
                fields.insert(key.into(), value.clone());
                cases.push((
                    vec![comment(Value::Object(fields))],
                    Some("outside the caller's fixed item"),
                ));
            }
        }
    }
    for key in [
        "comment_id",
        "commentId",
        "comment-id",
        "reply_to_id",
        "target",
    ] {
        cases.push((
            vec![comment(json!({"item_number": item, key: item}))],
            Some("outside the caller's fixed destination"),
        ));
    }
    for (items, refusal) in cases {
        let lines: Vec<String> = items.iter().map(Value::to_string).collect();
        std::fs::write(out.join("outputs.jsonl"), lines.join("\n")).unwrap();
        let collected = dir.join("collected.json");
        std::fs::write(
            &collected,
            json!({"items": items, "errors": []}).to_string(),
        )
        .unwrap();
        let result = Command::new(BIN)
            .arg("check")
            .arg("--policy")
            .arg(&policy)
            .arg("--outputs")
            .arg(&out)
            .arg("--collected")
            .arg(&collected)
            .args(["--comment-repo", REPO, "--comment-target", target])
            .output()
            .unwrap();
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            result.status.code(),
            Some(i32::from(refusal.is_some())),
            "{items:?}: {log}"
        );
        if let Some(refusal) = refusal {
            assert!(log.contains(refusal), "{items:?}: {log}");
        }
    }
}

/// The configuration turns on the proxy and names the example's egress
/// policy, which `run` admits for a private run where the shipped policy
/// or one without the allowlist is refused. Run the actual host handoff
/// from a caller checkout, then read its policy from the host's root.
#[test]
fn the_configuration_keeps_the_agent_behind_the_allowlist() {
    let temp = tempfile::tempdir().unwrap();
    let checkout = temp.path().join("caller");
    std::fs::create_dir_all(checkout.join(DIR)).unwrap();
    std::fs::create_dir(checkout.join(".agentic-job")).unwrap();
    std::fs::create_dir(temp.path().join("bin")).unwrap();
    std::os::unix::fs::symlink(BIN, temp.path().join("bin/agentic-job")).unwrap();
    std::fs::write(
        checkout.join(".agentic-job/config.toml"),
        example("config.toml"),
    )
    .unwrap();
    std::fs::write(
        checkout.join(DIR).join("egress.toml"),
        example("egress.toml"),
    )
    .unwrap();
    let workflow = yaml(&format!("{DIR}/workflow.yml"));
    let step = workflow["jobs"]["agent"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|step| step["name"].as_str() == Some("The host's configuration"))
        .unwrap();
    let path = format!(
        "{}:{}",
        temp.path().join("bin").display(),
        std::env::var("PATH").unwrap()
    );
    let output = script(
        step,
        &checkout,
        &[
            ("PATH", &path),
            ("GITHUB_WORKSPACE", checkout.to_str().unwrap()),
            ("RUNNER_TEMP", temp.path().to_str().unwrap()),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let host = std::fs::read_to_string(temp.path().join("agentic-job-host.toml")).unwrap();
    let config: toml::Table = toml::from_str(&host).unwrap();
    let hosted = std::fs::read_to_string(root().join(".github/agentic-job/hosted.toml")).unwrap();
    let mut hosted: toml::Table = toml::from_str(&hosted).unwrap();
    let image = config["sandbox"]["check"]["container-image"]
        .as_str()
        .unwrap();
    let (registry, image_path) = image.split_once('/').unwrap();
    assert_eq!(registry, "registry.access.redhat.com");
    assert!(image_path.starts_with("ubi10/ubi-minimal@sha256:"));
    assert_eq!(image_path.rsplit_once(':').unwrap().1.len(), 64);
    assert!(config["sandbox"]["check"].get("containers").is_none());
    hosted["host"]["check"]
        .as_table_mut()
        .unwrap()
        .insert("container-image".into(), image.into());
    // `config --host` writes [host] as [sandbox] for the pinned image.
    assert_eq!(config["sandbox"], hosted["host"]);
    assert_eq!(config["egress"]["proxy"].as_bool(), Some(true));
    let policy = config["egress"]["policy"].as_str().unwrap();
    assert!(Path::new(policy).is_absolute(), "{policy}");
    assert_eq!(Path::new(policy), checkout.join(DIR).join("egress.toml"));
    let text = std::fs::read_to_string(Path::new("/").join(policy)).unwrap();
    assert_eq!(text, example("egress.toml"));
    let egress: toml::Table = toml::from_str(&text).unwrap();
    assert_eq!(
        egress["egress"]["allow"].as_array().unwrap(),
        &[
            "github.com".into(),
            "api.github.com".into(),
            registry.into(),
            "registry.npmjs.org".into(),
            "index.crates.io".into(),
            "static.crates.io".into(),
        ]
    );
    secure_host::egress::check_private_policy(&text).unwrap();
    let shipped = std::fs::read_to_string(root().join("egress/policy.toml")).unwrap();
    for refused in [
        text.replace("mode = \"allowlist\"\n", ""),
        {
            let mut policy = egress.clone();
            policy["egress"].as_table_mut().unwrap().remove("allow");
            policy["egress"]["mode"] = "reads-anywhere".into();
            toml::to_string(&policy).unwrap()
        },
        shipped,
    ] {
        assert!(
            secure_host::egress::check_private_policy(&refused).is_err(),
            "{refused}"
        );
    }
}

/// The workflow is inert here, calls policy.yml, check.yml and apply.yml
/// at a placeholder commit with the private path's settings, and admits
/// only a private policy for the calling repository; its agent, the
/// runner's user, is refused the private target.
#[test]
fn the_workflow_composes_the_private_path() {
    let path = format!("{DIR}/workflow.yml");
    let doc = yaml(&path);
    let jobs = &doc["jobs"];
    // Not under .github/workflows: nothing here runs it.
    assert!(!path.starts_with(".github/workflows/"));
    assert!(doc["on"]["workflow_dispatch"].is_null());
    assert!(doc["on"]["workflow_call"].is_badvalue());
    assert!(doc["on"]["workflow_dispatch"]["inputs"].is_badvalue());
    for (job, file) in [
        ("policy", "policy.yml"),
        ("check", "check.yml"),
        ("apply", "apply.yml"),
    ] {
        assert_eq!(
            jobs[job]["uses"].as_str(),
            Some(&*format!(
                "cgwalters-forge/agentic-job/.github/workflows/{file}@AGENTIC_JOB_COMMIT"
            ))
        );
        assert!(root().join(".github/workflows").join(file).is_file());
        assert!(jobs[job]["secrets"].is_badvalue(), "{job}");
    }
    let with = &jobs["policy"]["with"];
    assert_eq!(with["repo"].as_str(), Some("${{ github.repository }}"));
    for absent in [
        "output-repo",
        "item-repo",
        "fake-profile",
        "context",
        "agent-config-repo",
    ] {
        assert!(with[absent].is_badvalue(), "{absent}");
    }
    assert_eq!(with["outputs"].as_str(), Some("add_comment"));
    assert_eq!(with["max-outputs"].as_str(), Some("1"));
    assert_eq!(with["comment-target"].as_str(), Some("DIGEST_ISSUE"));
    assert_eq!(with["issue"].as_str(), Some("DIGEST_ISSUE"));
    assert_eq!(with["kind"].as_str(), Some("analysis"));
    let text = std::fs::read_to_string(root().join(&path)).unwrap();
    assert!(!text.contains("secrets."));
    assert!(!text.contains("runner-setup.py"));
    for file in ["allow", "config"] {
        let named = with[file].as_str().unwrap();
        assert_eq!(named, format!("{DIR}/{file}.toml"));
        assert!(root().join(named).is_file());
    }
    // Only apply writes, and only the comment.
    let writes = |job: &str| -> Vec<String> {
        jobs[job]["permissions"]
            .as_hash()
            .unwrap()
            .iter()
            .filter(|(_, level)| level.as_str() == Some("write"))
            .map(|(scope, _)| scope.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(writes("policy"), Vec::<String>::new());
    assert_eq!(writes("agent"), ["id-token"]);
    assert_eq!(writes("check"), ["id-token"]);
    assert_eq!(writes("apply"), ["issues"]);
    let steps = jobs["agent"]["steps"].as_vec().unwrap();
    let run = steps.last().unwrap();
    assert_eq!(run["uses"].as_str(), Some("./.agentic-job-source/run"));
    // The runner's user, which `run` refuses for a private target since
    // the sandbox user was removed (agentic-job#2989).
    assert!(run["with"]["agent-user"].is_badvalue());
    assert_eq!(
        run["with"]["runner-home"].as_str(),
        Some("${{ runner.temp }}/agent-home")
    );
    assert!(text.contains("`run` refuses a private target"));
    assert_eq!(
        run["with"]["github-token"].as_str(),
        Some("${{ github.token }}")
    );
    let index = |name: &str| {
        steps
            .iter()
            .position(|step| step["name"].as_str() == Some(name))
            .unwrap()
    };
    // The network join is a placeholder that fails, before secure-host.
    let network = index("Join the inference proxy's network (placeholder)");
    let secure_host = steps
        .iter()
        .position(|step| step["uses"].as_str() == Some("./.agentic-job-source/secure-host"))
        .unwrap();
    assert!(index("Admit the private run") < network && network < secure_host);
    let temp = tempfile::tempdir().unwrap();
    assert!(!script(&steps[network], temp.path(), &[]).status.success());
    let admit = &steps[index("Admit the private run")];
    std::fs::create_dir(temp.path().join(".agentic-job")).unwrap();
    for (policy, admitted) in [
        (json!({"repo": REPO, "private": true}), true),
        (json!({"repo": REPO}), false),
        (json!({"repo": REPO, "private": "true"}), false),
        (json!({"repo": "owner/other", "private": true}), false),
    ] {
        std::fs::write(
            temp.path().join(".agentic-job/policy.json"),
            policy.to_string(),
        )
        .unwrap();
        let output = script(admit, temp.path(), &[("GITHUB_REPOSITORY", REPO)]);
        assert_eq!(output.status.success(), admitted, "{policy}: {output:?}");
    }
}

/// policy.yml, which the example calls, admits a private target only as
/// the calling repository: a public caller naming a private one is
/// refused, and only the private caller on itself is marked private.
#[test]
fn policy_admits_a_private_target_only_from_itself() {
    let doc = yaml(".github/workflows/policy.yml");
    let step = doc["jobs"]["policy"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|step| step["name"].as_str() == Some("Check that the repositories are public"))
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    // `gh api repos/NAME --jq FILTER`, with the step's own filter.
    let gh = bin.join("gh");
    std::fs::write(
        &gh,
        format!(
            "#!/bin/sh\ncase \"$2\" in\n\
             repos/{REPO}) json='{{\"private\": true, \"visibility\": \"private\"}}' ;;\n\
             repos/owner/public) json='{{\"private\": false, \"visibility\": \"public\"}}' ;;\n\
             *) exit 1 ;;\nesac\nprintf '%s' \"$json\" | jq -r \"$4\"\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    // The caller, the target, the other repositories, and whether it is
    // admitted and marked private.
    for (caller, target, others, admitted, private) in [
        (REPO, REPO, "", true, true),
        ("owner/public", REPO, "", false, false),
        ("owner/public", "owner/public", "", true, false),
        (REPO, "owner/public", "", true, false),
        (REPO, REPO, REPO, false, false),
        (REPO, "owner/unknown", "", false, false),
    ] {
        let output_file = temp.path().join("output");
        std::fs::write(&output_file, "").unwrap();
        let output = script(
            step,
            temp.path(),
            &[
                ("PATH", &path),
                ("GITHUB_REPOSITORY", caller),
                ("GITHUB_OUTPUT", output_file.to_str().unwrap()),
                ("REPO", target),
                ("REPOS", others),
            ],
        );
        let case = format!("{caller} {target} {others:?}");
        assert_eq!(output.status.success(), admitted, "{case}: {output:?}");
        if admitted {
            assert_eq!(
                std::fs::read_to_string(&output_file).unwrap() == "private=true\n",
                private,
                "{case}"
            );
        }
    }
}
