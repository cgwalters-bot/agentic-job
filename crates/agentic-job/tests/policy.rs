//! `agentic-job policy` as a caller runs it: the exit states, and what
//! reaches standard output.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

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
#[test]
fn try_it_caller_fits_its_bounds_and_configuration() {
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
    let input = |name: &str| {
        caller
            .lines()
            .find_map(|line| line.trim().strip_prefix(&format!("{name}: ")))
            .unwrap_or_else(|| panic!("no input {name}"))
            .trim_matches('"')
    };
    // The reusable workflow: an input's default, and the permissions its
    // agent job asks for, which GitHub refuses the whole call without.
    let workflow = std::fs::read_to_string(root.join(".github/workflows/agentic-job.yml")).unwrap();
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
        block("```toml\n").replace("OWNER/REPO", "bootc-dev/bootc"),
    )
    .unwrap();
    // `max-outputs` and `base` are left at the workflow's defaults.
    let output = policy(
        &allow,
        &[
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
    let compose = |max_requests: &str| {
        Command::new(BIN)
            .arg("config")
            .arg("--from")
            .arg(root.join(config))
            .args(["--repo", "bootc-dev/bootc"])
            .args(["--string", &format!("agent.name={}", input("agent"))])
            .args(["--integer", &format!("limits.max-requests={max_requests}")])
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
    let output = compose(input("max-requests"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The workflow's default cap, as docs/workflow.md says: refused by the
    // policy job, naming the configuration keys.
    let output = compose(&default("max-requests"));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("limits.max-requests"), "{stderr}");
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
            "add_comment,noop,create_pull_request_review_comment",
            "11",
        );
        assert!(
            output.status.success(),
            "{bounds}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let policy: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(policy["max_outputs"], 11, "{bounds}");
        assert_eq!(
            policy["safe_outputs"]["create_pull_request_review_comment"],
            serde_json::json!({"max": 10}),
            "{bounds}"
        );
        let output = review_with(
            "analysis",
            "add_comment,noop,create_pull_request_review_comment",
            "12",
        );
        assert_eq!(output.status.code(), Some(1), "{bounds}: 12 outputs");
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
