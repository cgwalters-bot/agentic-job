//! `agentic-job policy` as a caller runs it: the exit states, and what
//! reaches standard output.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

/// The legacy policy corpus's selectors and numeric limits, exercised without
/// its old-tree checkout. Assert the serialized grant, not just admission.
#[test]
fn corpus_output_selection_and_limits() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("allow.toml");
    std::fs::write(
        &allow,
        "hosts = ['github.com']\nrepos = ['example/repo']\nbases = ['main']\n\
         max_outputs = 5\nmax_patch_bytes = 65536\nmax_patch_files = 10\n\
         [github.outputs]\ncreate_pull_request = { max = 1 }\n\
         add_comment = { max = 2 }\nnoop = { max = 1 }\n",
    )
    .unwrap();
    for (kind, outputs, maximum, expected) in [
        (
            "branch",
            "create_pull_request,noop",
            "3",
            Some((3, vec![("create_pull_request", 1), ("noop", 1)])),
        ),
        (
            "branch",
            "all",
            "max",
            Some((
                5,
                vec![("add_comment", 2), ("create_pull_request", 1), ("noop", 1)],
            )),
        ),
        (
            "branch",
            "all",
            "2",
            Some((
                2,
                vec![("add_comment", 2), ("create_pull_request", 1), ("noop", 1)],
            )),
        ),
        (
            "branch",
            "all",
            "1",
            Some((
                1,
                vec![("add_comment", 1), ("create_pull_request", 1), ("noop", 1)],
            )),
        ),
        (
            "analysis",
            "all",
            "max",
            Some((5, vec![("add_comment", 2), ("noop", 1)])),
        ),
        (
            "analysis",
            "noop,add_comment",
            "3",
            Some((3, vec![("add_comment", 2), ("noop", 1)])),
        ),
        (
            "branch",
            " noop , noop,create_pull_request",
            "3",
            Some((3, vec![("create_pull_request", 1), ("noop", 1)])),
        ),
        ("branch", "noop", "1", Some((1, vec![("noop", 1)]))),
        ("analysis", "create_pull_request,noop", "3", None),
        ("branch", "create_pull_request,delete_repo", "3", None),
        ("branch", "ALL", "3", None),
        ("branch", " , ", "3", None),
        ("branch", "", "3", None),
        ("branch", "noop", "6", None),
        ("branch", "noop", "many", None),
        ("branch", "noop", "0", None),
        ("branch", "noop", "03", None),
        ("branch", "noop", "+3", None),
        ("branch", "noop", " 3", None),
        ("branch", "noop", "1000", None),
        ("branch", "noop", "4294967296", None),
        ("branch", "noop", "", None),
    ] {
        let output = policy(
            &allow,
            &[
                ("--repo", "example/repo"),
                ("--clone-url", "https://github.com/example/repo"),
                ("--kind", kind),
                ("--outputs", outputs),
                ("--max-outputs", maximum),
            ],
        );
        let context = format!("{kind} {outputs:?} {maximum:?}: {output:?}");
        assert_eq!(
            output.status.code(),
            Some(if expected.is_some() { 0 } else { 1 }),
            "{context}"
        );
        let Some((total, limits)) = expected else {
            assert!(output.stdout.is_empty(), "{context}");
            assert!(!output.stderr.is_empty(), "{context}");
            continue;
        };
        let admitted: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(admitted["max_outputs"], total, "{context}");
        assert_eq!(admitted["kind"], kind, "{context}");
        let granted = admitted["safe_outputs"].as_object().unwrap();
        assert_eq!(granted.len(), limits.len(), "{context}");
        for (name, limit) in limits {
            assert_eq!(granted[name]["max"], limit, "{name}: {context}");
        }
    }
}

/// Native publishers cannot enforce the applying identity against a PR's
/// author yet: refuse both new bounds and an already compiled policy.
#[test]
fn own_author_is_github_only() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("allow.toml");
    let pinned = dir.path().join("policy.json");
    let head = "a".repeat(40);
    let mut github = Value::Null;
    for forge in ["github", "forgejo", "gitlab"] {
        let push_repo = if forge == "github" {
            ""
        } else {
            "push_repo = 'applying-bot/unlisted'"
        };
        std::fs::write(
            &allow,
            format!(
                "hosts = ['github.com']\nrepos = ['example/listed']\nbases = ['main']\n\
                 max_outputs = 1\nmax_patch_bytes = 65536\nmax_patch_files = 10\n\
                 [{forge}]\n{push_repo}\n\
                 [{forge}.outputs.push_to_pull_request_branch]\n\
                 max = 1\nbranches = ['dispatch/**']\nown_author = 'different-user'\n"
            ),
        )
        .unwrap();
        let output = Command::new(BIN)
            .args(["policy", "--allow"])
            .arg(&allow)
            .args([
                "--repo",
                "example/unlisted",
                "--output-repo",
                "example/unlisted",
            ])
            .args(["--clone-url", "https://github.com/example/unlisted"])
            .args(["--base", "dispatch/fix", "--kind", "branch"])
            .args([
                "--outputs",
                "push_to_pull_request_branch",
                "--max-outputs",
                "1",
            ])
            .args(["--pull-request", "12", "--head", &head])
            .args(["--pull-author", "different-user"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        if forge == "github" {
            assert!(output.status.success(), "{stderr}");
            github = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                github["safe_outputs"]["push_to_pull_request_branch"]["author"],
                "different-user"
            );
        } else {
            assert!(!output.status.success(), "{forge} accepted own_author");
            assert!(
                stderr.contains("own_author is supported only on GitHub"),
                "{stderr}"
            );
            assert!(output.stdout.is_empty());
        }
    }
    for (forge, token_env) in [("forgejo", "FORGEJO_TOKEN"), ("gitlab", "GITLAB_TOKEN")] {
        let mut policy = github.clone();
        policy["forge"] = forge.into();
        policy["push_repo"] = "applying-bot/unlisted".into();
        std::fs::write(&pinned, policy.to_string()).unwrap();
        // A previously admitted different-user PR must not reach the
        // applying-bot publisher, even with a token available. No server
        // or checked upload is needed: policy validation must fail first.
        let output = Command::new(BIN)
            .args([
                "apply",
                "--forge",
                forge,
                "--server",
                "https://forge.example",
            ])
            .args([
                "--repo",
                "example/unlisted",
                "--push-repo",
                "applying-bot/unlisted",
            ])
            .arg("--policy")
            .arg(&pinned)
            .arg("--checked")
            .arg(dir.path().join("absent"))
            .args(["--run-url", "https://ci.example/runs/1"])
            .env(token_env, "native-apply-test-token")
            .output()
            .unwrap();
        assert!(!output.status.success(), "{forge} accepted author");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("a push's author is supported only on GitHub"),
            "{stderr}"
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn context_admission() {
    let context = serde_json::json!({
        "repo": "other/reference", "clone_url": "https://github.com/other/reference",
        "commit": "a".repeat(40), "public": true,
    });
    let mut private = context.clone();
    private["public"] = false.into();
    let mut bad_host = context.clone();
    bad_host["clone_url"] = "https://other.test/other/reference".into();
    let mut bad_path = context.clone();
    bad_path["repo"] = "owner/..".into();
    let mut bad_commit = context.clone();
    bad_commit["commit"] = "main".into();
    let mut admitted_private = private.clone();
    admitted_private["repo"] = REQUEST[0].1.into();
    admitted_private["clone_url"] = REQUEST[1].1.into();
    let mut uppercase = context.clone();
    uppercase["repo"] = "OTHER/REFERENCE".into();
    for (items, accepted) in [
        (serde_json::json!([]), true),
        (serde_json::json!([context]), true),
        (serde_json::json!([context, context]), false),
        (serde_json::json!(vec![context.clone(); 9]), false),
        (serde_json::json!([private]), false),
        (serde_json::json!([admitted_private]), true),
        (serde_json::json!([context, uppercase]), false),
        (serde_json::json!([bad_host]), false),
        (serde_json::json!([bad_path]), false),
        (serde_json::json!([bad_commit]), false),
    ] {
        let output = Command::new(BIN)
            .arg("policy")
            .arg("--allow")
            .arg(data("allow.toml"))
            .args(REQUEST.iter().flat_map(|(flag, value)| [*flag, *value]))
            .arg("--context")
            .arg(items.to_string())
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            accepted,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout.is_empty(), !accepted);
    }
    // A request the workflow passes on as it came: none, or one refused
    // before any API is read, needs no token; a dispatcher cannot supply
    // a resolved entry's visibility.
    for (request, accepted) in [
        ("", true),
        ("[]", true),
        (r#"[{"repo":"owner/.."}]"#, false),
        (r#"[{"repo":"owner/repo","public":true}]"#, false),
    ] {
        let output = Command::new(BIN)
            .arg("policy")
            .arg("--allow")
            .arg(data("allow.toml"))
            .args(REQUEST.iter().flat_map(|(flag, value)| [*flag, *value]))
            .args(["--context-request", request])
            .env_remove("GH_TOKEN")
            .output()
            .unwrap();
        assert_eq!(output.status.success(), accepted, "{request:?}");
        assert_eq!(output.stdout.is_empty(), !accepted);
        if accepted {
            let policy: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(policy.get("context").is_none(), "{policy}");
        }
    }
}

/// A request within the bounds of `data/policy/allow.toml`, as pairs of a
/// flag and its value.
const REQUEST: &[(&str, &str)] = &[
    ("--repo", "bootc-dev/bootc"),
    ("--clone-url", "https://github.com/bootc-dev/bootc"),
    ("--base", "main"),
    ("--kind", "branch"),
    ("--outputs", "create_pull_request,noop"),
    ("--max-outputs", "2"),
];

fn data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/policy")
        .join(name)
}

/// Runs `policy` on `REQUEST` with the flags of `change` replaced.
fn policy(allow: &Path, change: &[(&str, &str)]) -> Output {
    let value = |flag: &str, default: &str| {
        change
            .iter()
            .find(|(changed, _)| *changed == flag)
            .map_or(default, |(_, value)| *value)
            .to_owned()
    };
    Command::new(BIN)
        .arg("policy")
        .arg("--allow")
        .arg(allow)
        .args(
            REQUEST
                .iter()
                .flat_map(|(flag, default)| [(*flag).to_owned(), value(flag, default)]),
        )
        .output()
        .expect("running agentic-job")
}

#[test]
fn organization_bounds_cli() {
    for (file, code) in [("allow.toml", 0), ("absent.toml", 2)] {
        let output = Command::new(BIN)
            .arg("policy")
            .arg("--allow")
            .arg(data("allow.toml"))
            .arg("--org-allow")
            .arg(data(file))
            .args(REQUEST.iter().flat_map(|(flag, value)| [*flag, *value]))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout.is_empty(), code != 0);
    }
}

/// `--private` reaches the bounds: refused unless the caller's and the
/// organization's files both set `private = true`, and then recorded.
#[test]
fn a_private_request_needs_every_bounds_file_to_opt_in() {
    let temp = tempfile::tempdir().unwrap();
    let opted = temp.path().join("private.toml");
    let shipped = std::fs::read_to_string(data("allow.toml")).unwrap();
    std::fs::write(&opted, format!("private = true\n{shipped}")).unwrap();
    // The bounds file, the organization's, the outputs, the exit status
    // and a part of the refusal.
    for (allow, org, outputs, code, refusal) in [
        (&opted, None, "noop", 0, ""),
        (&data("allow.toml"), None, "noop", 1, "private = true"),
        (
            &opted,
            Some(data("allow.toml")),
            "noop",
            1,
            "private = true",
        ),
        (&opted, Some(opted.clone()), "noop", 0, ""),
        (
            &opted,
            None,
            "create_pull_request,noop",
            1,
            "hands back no patch",
        ),
    ] {
        let mut command = Command::new(BIN);
        command.arg("policy").arg("--allow").arg(allow);
        if let Some(org) = &org {
            command.arg("--org-allow").arg(org);
        }
        let output = command
            .args(REQUEST.iter().flat_map(|(flag, value)| {
                [
                    *flag,
                    if *flag == "--outputs" {
                        outputs
                    } else {
                        *value
                    },
                ]
            }))
            .args(["--private", "--output-repo", "bootc-dev/bootc"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(code), "{stderr}");
        if code == 0 {
            let policy: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(policy["private"], true);
        } else {
            assert!(output.stdout.is_empty());
            assert!(stderr.contains(refusal), "{stderr}");
        }
    }
    // Opting in admits a private run; it does not mark a public one.
    let output = policy(&opted, &[]);
    let policy: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(policy.get("private").is_none(), "{policy}");
}

#[test]
fn a_request_within_the_bounds_prints_its_policy() {
    let output = policy(&data("allow.toml"), &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let policy: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(policy["repo"], "bootc-dev/bootc");
    assert_eq!(policy["clone_url"], "https://github.com/bootc-dev/bootc");
    assert_eq!(policy["base"], "main");
    assert_eq!(policy["kind"], "branch");
    assert_eq!(policy["max_outputs"], 2);
    assert_eq!(policy["max_patch_bytes"], 8_388_608);
    let outputs = policy["safe_outputs"].as_object().unwrap();
    assert_eq!(
        outputs.keys().collect::<Vec<_>>(),
        ["create_pull_request", "noop"]
    );
    assert_eq!(outputs["noop"], serde_json::json!({"max": 1}));
    let pr = &outputs["create_pull_request"];
    assert_eq!(pr["draft"], true);
    assert_eq!(pr["protected_files_policy"], "blocked");
    let protected = pr["protected_files"].as_array().unwrap();
    assert!(protected.contains(&Value::from("CONTRIBUTING.md")));
    // Not protected in any repository (#537).
    assert!(!protected.contains(&Value::from("README.md")));
}

#[test]
fn documented_proposals_request_fits_shipped_and_small_bounds() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let docs = std::fs::read_to_string(root.join("docs/workflow.md")).unwrap();
    let snippet = docs
        .split("## Proposals from a non-agent job\n")
        .nth(1)
        .unwrap()
        .split("```yaml\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    let input = |name: &str| {
        snippet
            .lines()
            .find_map(|line| line.trim().strip_prefix(&format!("{name}: ")))
            .unwrap()
            .trim_matches('\'')
    };
    let shipped = std::fs::read_to_string(root.join(input("allow"))).unwrap();
    let temp = tempfile::tempdir().unwrap();
    for ceiling in [5, 2] {
        let allow = temp.path().join("allow.toml");
        std::fs::write(
            &allow,
            shipped.replace("max_outputs = 5", &format!("max_outputs = {ceiling}")),
        )
        .unwrap();
        let output = policy(
            &allow,
            &[
                ("--repo", "cgwalters-forge/agentic-job"),
                (
                    "--clone-url",
                    "https://github.com/cgwalters-forge/agentic-job",
                ),
                ("--outputs", input("outputs")),
                ("--max-outputs", input("max-outputs")),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "ceiling {ceiling}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["max_outputs"], 2);
        assert_eq!(value["safe_outputs"]["add_comment"]["max"], 1);
    }
}

/// The getting-started caller and bounds, as the policy job would take
/// them: its request fits its bounds, and its configuration, read from
/// this source as `config` names it, composes with the scripted agent's
/// inputs, while the default request cap is refused without a broker.
/// The guide's real-agent change to that caller keeps its wiring and
/// composes with a broker and a positive request cap.
#[test]
fn try_it_caller_fits_its_bounds_and_configuration() {
    use yaml_rust2::YamlLoader;

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let guide = std::fs::read_to_string(root.join("docs/try-it.md")).unwrap();
    let section = guide.as_str();
    let block = |fence: &str| {
        section
            .split(fence)
            .nth(1)
            .unwrap()
            .split("```")
            .next()
            .unwrap()
    };
    let caller = block("```yaml\n");
    // The real-agent change to that caller: its context and removed lines
    // are the caller's, in order, and its added lines replace them.
    let (mut removed, mut added) = (String::new(), String::new());
    for line in block("```diff\n").lines() {
        let sign = line.get(..1).unwrap_or_default();
        assert!([" ", "-", "+"].contains(&sign), "not a diff line: {line:?}");
        let text = &line[1..];
        if sign != "+" {
            removed += &format!("{text}\n");
        }
        if sign != "-" {
            added += &format!("{text}\n");
        }
    }
    assert_eq!(caller.matches(&removed).count(), 1, "{removed}");
    let broker = caller.replacen(&removed, &added, 1);
    // Ordinary CI supplies the same digest-verified analyzer as ingress.
    // Lint the actual example, not a checked-in copy of the caller.
    if let Some(actionlint) = std::env::var_os("ACTIONLINT") {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("agent.yml");
        for text in [caller, &broker] {
            std::fs::write(&file, text).unwrap();
            let status = Command::new(&actionlint).arg(&file).status().unwrap();
            assert!(status.success(), "actionlint refused {text}");
        }
    }
    fn field<'a>(caller: &'a str, name: &str) -> &'a str {
        caller
            .lines()
            .find_map(|line| line.trim().strip_prefix(&format!("{name}: ")))
            .unwrap_or_else(|| panic!("no input {name}"))
            .trim_matches('"')
    }
    let input = |name: &str| field(caller, name);
    // The reusable workflow: an input's default, and the permissions its
    // agent job asks for, which GitHub refuses the whole call without.
    let workflow = std::fs::read_to_string(root.join(".github/workflows/agentic-job.yml")).unwrap();
    let workflow_yaml = YamlLoader::load_from_str(&workflow).unwrap().remove(0);
    let declared = &workflow_yaml["on"]["workflow_call"]["inputs"];
    assert!(!workflow_yaml["on"]["workflow_call"]["secrets"]["SAFE_OUTPUTS_PAT"].is_badvalue());
    let mut calls = Vec::new();
    for text in [caller, &broker] {
        let caller_yaml = YamlLoader::load_from_str(text).unwrap().remove(0);
        let secrets = caller_yaml["jobs"]["run"]["secrets"].as_hash().unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(
            caller_yaml["jobs"]["run"]["secrets"]["SAFE_OUTPUTS_PAT"].as_str(),
            Some("${{ secrets.SAFE_OUTPUTS_PAT }}")
        );
        for (key, value) in caller_yaml["jobs"]["run"]["with"].as_hash().unwrap() {
            let key = key.as_str().unwrap();
            assert!(!declared[key].is_badvalue(), "unknown caller input {key:?}");
            let valid_type = match declared[key]["type"].as_str().unwrap() {
                "string" => value.as_str().is_some(),
                "boolean" => value.as_bool().is_some(),
                "number" => value.as_i64().is_some() || value.as_f64().is_some(),
                other => panic!("unhandled input type {other}"),
            };
            assert!(valid_type, "wrong type for {key:?}: {value:?}");
        }
        for (key, value) in declared.as_hash().unwrap() {
            let key = key.as_str().unwrap();
            if value["required"].as_bool() == Some(true) && value["default"].is_badvalue() {
                assert!(
                    !caller_yaml["jobs"]["run"]["with"][key].is_badvalue(),
                    "missing required input {key:?}"
                );
            }
        }
        assert_eq!(
            caller_yaml["jobs"]["run"]["uses"].as_str().unwrap(),
            "cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@COMMIT"
        );
        calls.push(caller_yaml);
    }
    // The change keeps the dispatch, permissions, task/run/target wiring,
    // bounds and publication, and leaves partial runs unpublished.
    let (scripted, brokered) = (&calls[0], &calls[1]);
    assert_eq!(scripted["on"], brokered["on"]);
    assert_eq!(
        scripted["jobs"]["run"]["permissions"],
        brokered["jobs"]["run"]["permissions"]
    );
    for (key, value) in scripted["jobs"]["run"]["with"].as_hash().unwrap() {
        let key = key.as_str().unwrap();
        if !["agent", "max-requests"].contains(&key) {
            assert_eq!(&brokered["jobs"]["run"]["with"][key], value, "{key}");
        }
    }
    // Only the broker's address and audience are new: no `apply-partial`,
    // and registration stays the workflow's default.
    let mut new_inputs: Vec<&str> = brokered["jobs"]["run"]["with"]
        .as_hash()
        .unwrap()
        .keys()
        .map(|key| key.as_str().unwrap())
        .filter(|key| scripted["jobs"]["run"]["with"][*key].is_badvalue())
        .collect();
    new_inputs.sort();
    assert_eq!(new_inputs, ["inference-audience", "inference-url"]);
    let default = |name: &str| {
        workflow
            .split(&format!("\n      {name}:\n"))
            .nth(1)
            .unwrap()
            .lines()
            .find_map(|line| line.trim().strip_prefix("default: "))
            .unwrap()
            .trim_matches('"')
            .to_owned()
    };
    let permissions = |text: &str| -> Vec<String> {
        let mut found: Vec<String> = text
            .split("permissions:\n")
            .nth(1)
            .unwrap()
            .lines()
            .take_while(|line| {
                let line = line.trim();
                line.starts_with('#') || [": read", ": write"].iter().any(|v| line.ends_with(v))
            })
            .filter(|line| !line.trim().starts_with('#'))
            .map(|line| line.trim().to_owned())
            .collect();
        found.sort();
        found
    };
    // The agent job's reads, and the register job's identity token.
    let job = |name: &str| workflow.split(&format!("\n  {name}:\n")).nth(1).unwrap();
    let mut asked = [permissions(job("agent")), permissions(job("register"))].concat();
    asked.sort();
    assert_eq!(permissions(caller), asked);
    assert!(!input("apply-environment").is_empty());
    let temp = tempfile::tempdir().unwrap();
    let allow = temp.path().join("allow.toml");
    std::fs::write(
        &allow,
        block("```toml\n").replace("OWNER/REPO", "example-org/example"),
    )
    .unwrap();
    // `max-outputs` and `base` are left at the workflow's defaults.
    let output = policy(
        &allow,
        &[
            ("--repo", "example-org/example"),
            ("--clone-url", "https://github.com/example-org/example"),
            ("--outputs", input("outputs")),
            ("--base", &default("base")),
            ("--max-outputs", &default("max-outputs")),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = input("config")
        .strip_prefix(".agentic-job-source/")
        .expect("config is read from the pinned source");
    // Keep the generic runner's host inventory aligned with the deployed
    // one, without inheriting its repository packages or patch exceptions.
    let generic: toml::Value =
        toml::from_str(&std::fs::read_to_string(root.join(config)).unwrap()).unwrap();
    let deployed: toml::Value = toml::from_str(
        &std::fs::read_to_string(root.join(".github/agentic-job/hosted.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(generic["host"], deployed["host"]);
    assert_eq!(generic["setup"]["packages"], deployed["setup"]["packages"]);
    assert_eq!(generic.as_table().unwrap().len(), 2);
    assert_eq!(generic["setup"].as_table().unwrap().len(), 1);
    let compose = |agent: &str, max_requests: &str, inference: &[&str]| {
        Command::new(BIN)
            .arg("config")
            .arg("--from")
            .arg(root.join(config))
            .args(["--repo", "example-org/example"])
            .args(["--string", &format!("agent.name={agent}")])
            .args(["--integer", &format!("limits.max-requests={max_requests}")])
            .args(inference.iter().flat_map(|setting| ["--string", setting]))
            // The workflow's defaults for the inputs the caller leaves out;
            // without `inference-url` it passes no registration.
            .args([
                "--integer",
                &format!("limits.timeout-minutes={}", default("timeout")),
            ])
            .args([
                "--integer",
                &format!("limits.max-tasks={}", default("max-tasks")),
            ])
            .args(["--integer", &format!("limits.budget={}", default("budget"))])
            .output()
            .unwrap()
    };
    let output = compose(input("agent"), input("max-requests"), &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The workflow's default cap, as docs/workflow.md says: refused by the
    // policy job, naming the configuration keys.
    let output = compose(input("agent"), &default("max-requests"), &[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("limits.max-requests"), "{stderr}");
    // The changed caller, with synthetic stand-ins for its repository
    // variables and the workflow's registration default, keeps a positive
    // cap. Composition accepts the scripted zero for it too, uncapped, as
    // docs/workflow.md warns: the guide's change is what sets the cap.
    let register = format!("inference.register={}", default("inference-register"));
    let broker_compose = |max_requests: &str| {
        let output = compose(
            field(&broker, "agent"),
            max_requests,
            &[
                "inference.url=http://192.0.2.1:8080",
                &register,
                "inference.audience=example-audience",
            ],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let composed: toml::Value =
            toml::from_str(&String::from_utf8(output.stdout).unwrap()).unwrap();
        assert_eq!(
            composed["inference"]["register"].as_str(),
            Some("github-oidc")
        );
        composed["limits"]["max-requests"].as_integer().unwrap()
    };
    assert_eq!(broker_compose(input("max-requests")), 0);
    let cap = broker_compose(field(&broker, "max-requests"));
    assert!(cap > 0);
    assert_eq!(cap.to_string(), default("max-requests"));
}

/// Execute the documented local entrypoint, without a forge, model or host
/// setup. A second run demonstrates that its bounds stop a different request.
#[test]
fn documented_local_check_runs_and_refuses_an_out_of_bounds_request() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let guide = std::fs::read_to_string(root.join("docs/try-it.md")).unwrap();
    assert!(guide.contains("cargo build --locked -p agentic-job --bin agentic-job\nPATH=\"$PWD/target/debug:$PATH\" sh docs/examples/local.sh\n"));
    let temp = tempfile::tempdir().unwrap();
    let examples = temp.path().join("docs/examples");
    std::fs::create_dir_all(&examples).unwrap();
    for file in ["local.sh", "local.toml", "outputs.jsonl"] {
        std::fs::copy(root.join("docs/examples").join(file), examples.join(file)).unwrap();
    }
    let path = std::env::join_paths(
        [Path::new(BIN).parent().unwrap().to_path_buf()]
            .into_iter()
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    for accepted in [true, false] {
        if !accepted {
            std::fs::write(
                examples.join("outputs.jsonl"),
                r#"{"type":"add_comment","body":"Not granted by the local bounds."}"#,
            )
            .unwrap();
        }
        let output = Command::new("sh")
            .arg("docs/examples/local.sh")
            .env("PATH", &path)
            .env("TMPDIR", temp.path())
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            accepted,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        if accepted {
            let report_path = stdout
                .lines()
                .find_map(|line| line.strip_prefix("Checked local example: "))
                .unwrap();
            let report: Value =
                serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
            assert_eq!(report["ok"], true, "{report}");
            assert_eq!(report["items"][0]["type"], "noop", "{report}");
            assert!(report["patch"].is_null(), "{report}");
        } else {
            assert!(!stdout.contains("Checked local example:"), "{stdout}");
        }
    }
}

/// Check the documented deterministic hand-back with its own bounds, and
/// keep the publisher environment out of the producer and check jobs.
#[test]
fn documented_gitlab_caller_fits_its_bounds() {
    use yaml_rust2::{Yaml, YamlLoader};

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let doc = std::fs::read_to_string(root.join("docs/gitlab.md")).unwrap();
    let blocks = |fence: &str| -> Vec<&str> {
        doc.split(fence)
            .skip(1)
            .map(|rest| rest.split("```").next().unwrap())
            .collect()
    };
    let [isolation, bounds] = blocks("```toml\n")[..] else {
        panic!("docs/gitlab.md should have isolation and bounds examples");
    };
    let config = agentic_job::config::Config::parse(isolation).unwrap();
    assert_eq!(
        config.sandbox.isolation,
        agentic_job::config::Isolation::External
    );
    let pipeline = YamlLoader::load_from_str(blocks("```yaml\n")[0])
        .unwrap()
        .remove(0);
    for (_, job) in pipeline.as_hash().unwrap() {
        for key in ["before_script", "script"] {
            let script = job[key]
                .as_vec()
                .into_iter()
                .flatten()
                .map(|line| line.as_str().unwrap())
                .collect::<Vec<_>>()
                .join("\n");
            let output = Command::new("sh")
                .args(["-n", "-c", &script])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{key}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    let release = pipeline["variables"]["AGENTIC_JOB_RELEASE"]
        .as_str()
        .unwrap();
    assert!(doc.contains(&format!("\ntag={release}\n")));
    assert!(
        pipeline["apply"]["script"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|line| line.as_str().unwrap().contains("apply --forge gitlab"))
    );

    let temp = tempfile::tempdir().unwrap();
    let allow = temp.path().join("bounds.toml");
    std::fs::write(&allow, bounds).unwrap();
    let output = Command::new(BIN)
        .arg("policy")
        .arg("--allow")
        .arg(&allow)
        .args(["--repo", "group/project"])
        .args([
            "--clone-url",
            "https://gitlab.example.com/group/project.git",
        ])
        .args(["--base", "main", "--kind", "branch"])
        .args(["--outputs", "all", "--max-outputs", "max"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let policy: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(policy["forge"], "gitlab");
    // A comment-only policy grants no fork push, even when bounds name one.
    assert!(policy["push_repo"].is_null());

    let policy_file = temp.path().join("policy.json");
    std::fs::write(&policy_file, &output.stdout).unwrap();
    let script = pipeline["produce"]["script"]
        .as_vec()
        .unwrap()
        .iter()
        .map(|line| line.as_str().unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let output = Command::new("sh")
        .args(["-eu", "-c", &script])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let collected = temp.path().join("collected.json");
    let report = temp.path().join("report.json");
    for command in ["collect", "check"] {
        let mut cmd = Command::new(BIN);
        cmd.arg(command)
            .arg("--policy")
            .arg(&policy_file)
            .arg("--outputs")
            .arg(temp.path().join("handback"))
            .arg("--collected")
            .arg(&collected);
        if command == "check" {
            cmd.arg("--report").arg(&report);
        }
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Every flag the pipeline gives a command is one that command takes.
    let command = regex::Regex::new(r#"agentic-job"? ((?:[a-z][a-z-]* )+)"#).unwrap();
    let flag = regex::Regex::new(r"--[a-z][a-z-]*").unwrap();
    let mut checked = 0;
    for (_, job) in pipeline.as_hash().unwrap() {
        for key in ["before_script", "script"] {
            for line in job[key].as_vec().into_iter().flatten() {
                let line = format!("{} ", line.as_str().unwrap());
                let Some(found) = command.captures(&line) else {
                    continue;
                };
                let words: Vec<&str> = found[1].split_whitespace().collect();
                let help = Command::new(BIN)
                    .args(&words)
                    .arg("--help")
                    .output()
                    .unwrap();
                assert!(help.status.success(), "{words:?}: {help:?}");
                let help = String::from_utf8_lossy(&help.stdout);
                for flag in flag.find_iter(&line[found.get(1).unwrap().end()..]) {
                    assert!(help.contains(flag.as_str()), "{words:?} {}", flag.as_str());
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 4);

    let needs = |job: &str| -> Vec<&str> {
        pipeline[job]["needs"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|need| need.as_str().unwrap())
            .collect()
    };
    assert_eq!(needs("policy"), Vec::<&str>::new());
    assert_eq!(needs("produce"), ["policy"]);
    assert_eq!(needs("check"), ["produce"]);
    assert_eq!(needs("apply"), ["check"]);
    for job in ["policy", "produce", "check", "apply"] {
        for key in ["environment", "id_tokens", "secrets"] {
            assert_eq!(
                pipeline[job][key].is_badvalue(),
                job != "apply" || key != "environment",
                "{job}.{key}"
            );
        }
    }
    assert!(matches!(
        pipeline["apply"]["environment"]["name"],
        Yaml::String(_)
    ));
    assert!(pipeline["agent"].is_badvalue());
}

#[test]
fn a_request_outside_the_bounds_prints_no_policy() {
    // The change to the request, and a part of the reason.
    let cases: &[(&[(&str, &str)], &str)] = &[
        (
            &[
                ("--repo", "evil/bootc"),
                ("--clone-url", "https://github.com/evil/bootc"),
            ],
            "repo \"evil/bootc\"",
        ),
        (&[("--base", "release")], "base \"release\""),
        (&[("--base", "-main")], "base \"-main\""),
        (
            &[("--clone-url", "https://evil.example/bootc-dev/bootc")],
            "host",
        ),
        (&[("--outputs", "delete_repo")], "delete_repo"),
        (&[("--max-outputs", "9")], "max_outputs"),
        (&[("--kind", "analysis")], "analysis"),
        // The concern of tracker#281: text that would be structure if a
        // policy were put together as text.
        (
            &[("--repo", "bootc-dev/bootc\",\"max_outputs\":99,\"x\":\"")],
            "repo ",
        ),
        (&[("--base", "main\n\"max_outputs\": 99")], "base "),
        (&[("--base", "main\n::error::owned")], "base "),
        (&[("--base", "main ##[set-output name=x]y")], "base "),
        (
            &[("--outputs", "noop\",\"create_issue\":{\"max\":9},\"x\":\"")],
            "output type",
        ),
    ];
    for (change, want) in cases {
        let output = policy(&data("allow.toml"), change);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{change:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{change:?}");
        assert!(stderr.contains(want), "{change:?}: {stderr}");
        // Whatever the request held, every line of the log is ours, and
        // none holds a command the runner reads, even mid-line.
        assert!(
            stderr.lines().all(|line| line.starts_with("error: ")
                && !line.contains("::")
                && !line.contains("##[")),
            "{change:?}: {stderr}"
        );
    }
}

/// Bounds that configure a secondary pull request admit a run that opens
/// one, with the secondary in its policy; a run that opens no pull request
/// is admitted as before, without one.
#[test]
fn a_secondary_pull_request_is_admitted_beside_the_runs_own() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("allow.toml");
    let text = std::fs::read_to_string(data("allow.toml")).unwrap();
    std::fs::write(
        &allow,
        format!(
            "{text}\n[github.secondary_pull_request]\nrepo = \"cgwalters-forge/misctool\"\n\
             base = \"main\"\nbranch_prefix = \"agentic-job/\"\nmax = 1\n\
             max_patch_bytes = 65536\nmax_patch_files = 10\n"
        ),
    )
    .unwrap();
    let output = policy(&allow, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let printed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        printed["secondary_pull_request"]["repo"], "cgwalters-forge/misctool",
        "{printed}"
    );
    let output = policy(&allow, &[("--outputs", "add_comment,noop")]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let printed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(printed.get("secondary_pull_request").is_none(), "{printed}");
}

#[test]
fn a_bad_bounds_file_is_an_error_and_not_a_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let unknown_key = dir.path().join("unknown.toml");
    let text = std::fs::read_to_string(data("allow.toml")).unwrap();
    std::fs::write(&unknown_key, format!("allow_everything = true\n{text}")).unwrap();
    for (allow, want) in [
        (dir.path().join("missing.toml"), "reading the bounds file"),
        (unknown_key, "unknown field `allow_everything`"),
    ] {
        let output = policy(&allow, &[]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(output.stdout.is_empty());
        assert!(stderr.contains(want), "{stderr}");
    }
}

/// Repository and base cases from the legacy policy corpus, without its
/// external checkout. Malformed requests must not emit a partial policy.
#[test]
fn corpus_repository_and_base_admission() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("allow.toml");
    std::fs::write(
        &allow,
        "hosts = ['github.com']\nrepos = ['example-org/project', 'example-bot/home']\n\
         bases = ['main', 'bot/**']\nmax_outputs = 3\n\
         max_patch_bytes = 65536\nmax_patch_files = 10\n\
         [github.outputs]\ncreate_pull_request = { max = 1 }\nnoop = { max = 1 }\n",
    )
    .unwrap();
    for (repo, base, refusal) in [
        ("example-org/project", "main", None),
        ("EXAMPLE-ORG/Project", "main", None),
        ("example-bot/home", "main", None),
        ("Example-Bot/Home", "main", None),
        ("example-org/project", "bot/agent-run", None),
        ("example-org/project", "bot/a/b/c", None),
        ("other/project", "main", Some("repo")),
        ("example-bot/project", "main", Some("repo")),
        ("example-org/project/x", "main", Some("repo")),
        ("", "main", Some("repo")),
        ("example-org/project\n", "main", Some("repo")),
        (
            "example-org/project\",\"max_outputs\":99,\"x\":\"",
            "main",
            Some("repo"),
        ),
        ("example-org/project", "release", Some("base")),
        ("example-org/project", "bot/../main", Some("base")),
        ("example-org/project", "", Some("base")),
        ("example-org/project", "-main", Some("base")),
        ("example-org/project", "bot/a b", Some("base")),
        ("example-org/project", "main\n", Some("base")),
        (
            "example-org/project",
            "main\",\"max_outputs\":99,\"x\":\"",
            Some("base"),
        ),
        (
            "example-org/project",
            "main\n\"max_outputs\": 99",
            Some("base"),
        ),
    ] {
        let url = format!("https://github.com/{repo}");
        let output = policy(
            &allow,
            &[("--repo", repo), ("--clone-url", &url), ("--base", base)],
        );
        let context = format!("repo={repo:?}, base={base:?}: {output:?}");
        assert_eq!(
            output.status.code(),
            Some(i32::from(refusal.is_some())),
            "{context}"
        );
        if let Some(reason) = refusal {
            assert!(output.stdout.is_empty(), "{context}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(reason), "{context}");
            assert!(
                stderr.lines().all(|line| line.starts_with("error: ")),
                "{context}"
            );
        } else {
            let admitted: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(admitted["repo"], repo, "{context}");
            assert_eq!(admitted["clone_url"], url, "{context}");
            assert_eq!(admitted["base"], base, "{context}");
            assert_eq!(admitted["max_outputs"], 2, "{context}");
            assert_eq!(
                admitted["safe_outputs"]["create_pull_request"]["max"], 1,
                "{context}"
            );
            assert_eq!(admitted["safe_outputs"]["noop"]["max"], 1, "{context}");
        }
    }
}

#[test]
fn dispatch_profiles_use_the_example_bounds() {
    let allow =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/agentic-job/dispatch.toml");
    for (kind, outputs, repo, code) in [
        (
            "branch",
            "create_pull_request,add_comment,noop,missing_tool,missing_data",
            "cgwalters-forge/agentic-job",
            0,
        ),
        (
            "analysis",
            "add_comment,noop,missing_tool,missing_data",
            "cgwalters-forge/agentic-job",
            0,
        ),
        ("analysis", "add_comment", "other/repo", 1),
        ("analysis", "close_issue", "other/repo", 1),
        ("branch", "create_issue", "cgwalters-forge/agentic-job", 1),
        (
            "analysis",
            "create_pull_request",
            "cgwalters-forge/agentic-job",
            1,
        ),
    ] {
        let url = format!("https://github.com/{repo}");
        let output = policy(
            &allow,
            &[
                ("--repo", repo),
                ("--clone-url", &url),
                ("--kind", kind),
                ("--outputs", outputs),
                ("--max-outputs", "3"),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(code),
            "{kind}/{outputs}/{repo}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if code != 0 {
            assert!(output.stdout.is_empty());
            continue;
        }
        let policy: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(policy["max_outputs"], 3);
        for name in outputs.split(',') {
            assert_eq!(policy["safe_outputs"][name]["max"], 1, "{name}");
        }
        if kind == "branch" {
            assert_eq!(policy["safe_outputs"]["create_pull_request"]["draft"], true);
        }
    }
}

/// A triage run, as dispatch.yml requests it, may close issues of its own
/// repository with a closing comment, and check refuses one elsewhere.
#[test]
fn dispatch_triage_closes_issues_only_in_its_repository() {
    let allow =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/agentic-job/dispatch.toml");
    let repo = "cgwalters-forge/agentic-job";
    let output = policy(
        &allow,
        &[
            ("--repo", repo),
            ("--clone-url", &format!("https://github.com/{repo}")),
            ("--kind", "analysis"),
            (
                "--outputs",
                "close_issue,add_comment,noop,missing_tool,missing_data",
            ),
            ("--max-outputs", "max"),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let compiled: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(compiled["max_outputs"], 32);
    assert_eq!(compiled["safe_outputs"]["close_issue"]["max"], 30);
    assert_eq!(compiled["safe_outputs"]["add_comment"]["max"], 1);

    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.json");
    std::fs::write(&policy_path, &output.stdout).unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let close = |repo: &str, number: u64| {
        serde_json::json!({"type": "close_issue", "repo": repo, "issue_number": number,
            "state_reason": "not_planned", "body": "Overtaken by #12."})
    };
    for (items, code) in [
        (vec![close(repo, 7)], 0),
        ((1..=30).map(|n| close(repo, n)).collect(), 0),
        (vec![close("other/repo", 7)], 1),
        (vec![close(repo, 7), close("other/repo", 8)], 1),
        ((1..=31).map(|n| close(repo, n)).collect(), 1),
    ] {
        let lines: String = items.iter().map(|item| format!("{item}\n")).collect();
        std::fs::write(out.join("outputs.jsonl"), lines).unwrap();
        let collected = dir.path().join("collected.json");
        std::fs::write(
            &collected,
            serde_json::to_vec(&serde_json::json!({"items": items, "errors": []})).unwrap(),
        )
        .unwrap();
        let result = Command::new(BIN)
            .arg("check")
            .arg("--policy")
            .arg(&policy_path)
            .arg("--outputs")
            .arg(&out)
            .arg("--collected")
            .arg(&collected)
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(code),
            "{} items: {}",
            items.len(),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn dispatch_documented_unprotected_files_hint_is_valid() {
    // Read at test time, not built in: the release pin's digest does not
    // cover .github/.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/agentic-job/dispatch.toml"
    );
    let bounds = std::fs::read_to_string(path)
        .unwrap()
        .replace("# [unprotected_files]", "[unprotected_files]")
        .replace(
            "# repos = [\"OWNER/REPO\"]",
            "repos = [\"cgwalters-forge/agentic-job\"]",
        )
        .replace("# files =", "files =");
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("dispatch.toml");
    std::fs::write(&allow, bounds).unwrap();
    let output = policy(
        &allow,
        &[
            ("--repo", "cgwalters-forge/agentic-job"),
            (
                "--clone-url",
                "https://github.com/cgwalters-forge/agentic-job",
            ),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let policy: Value = serde_json::from_slice(&output.stdout).unwrap();
    let protected = policy["safe_outputs"]["create_pull_request"]["protected_files"]
        .as_array()
        .unwrap();
    assert!(!protected.contains(&serde_json::json!("CONTRIBUTING.md")));
    assert!(protected.contains(&serde_json::json!("AGENTS.md")));
}

#[test]
fn review_caller_bounds_allow_only_analysis_outputs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../workflow");
    for bounds in ["review.toml", "review-command.toml"] {
        let allow = root.join(bounds);
        let review_with = |kind: &str, outputs: &str, max: &str| {
            Command::new(BIN)
                .arg("policy")
                .arg("--allow")
                .arg(&allow)
                .args(["--repo", "cgwalters-forge/agentic-job"])
                .args([
                    "--clone-url",
                    "https://github.com/cgwalters-forge/agentic-job",
                ])
                .args(["--base", "main", "--kind", kind, "--outputs", outputs])
                .args(["--max-outputs", max])
                .output()
                .expect("running agentic-job")
        };
        let review = |kind: &str, outputs: &str| review_with(kind, outputs, "1");
        // review.yml's request: up to ten inline findings beside the verdict.
        let output = review_with(
            "analysis",
            "add_comment,noop,create_pull_request_review_comment,add_labels",
            "12",
        );
        assert!(
            output.status.success(),
            "{bounds}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let policy: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(policy["max_outputs"], 12, "{bounds}");
        assert_eq!(policy["safe_outputs"]["add_labels"]["max"], 1);
        assert_eq!(
            policy["safe_outputs"]["add_labels"]["allowed"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            policy["safe_outputs"]["create_pull_request_review_comment"],
            serde_json::json!({"max": 10}),
            "{bounds}"
        );
        let output = review_with(
            "analysis",
            "add_comment,noop,create_pull_request_review_comment",
            "13",
        );
        assert_eq!(output.status.code(), Some(1), "{bounds}: 13 outputs");
        let output = review("analysis", "add_comment,noop");
        assert!(
            output.status.success(),
            "{bounds}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let policy: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(policy["kind"], "analysis", "{bounds}");
        assert_eq!(policy["max_outputs"], 1, "{bounds}");
        assert!(
            policy["safe_outputs"].get("create_pull_request").is_none(),
            "{bounds}"
        );
        for (kind, outputs) in [
            ("branch", "create_pull_request,noop"),
            ("analysis", "add_comment,create_issue"),
            // Inline comments, never replies or resolved threads.
            (
                "analysis",
                "add_comment,reply_to_pull_request_review_comment",
            ),
            ("analysis", "add_comment,resolve_pull_request_review_thread"),
        ] {
            let output = review(kind, outputs);
            assert_eq!(output.status.code(), Some(1), "{bounds}: {kind} {outputs}");
            assert!(output.stdout.is_empty(), "{bounds}: {kind} {outputs}");
        }
    }
}
