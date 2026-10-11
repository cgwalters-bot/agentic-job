//! `agentic-job policy` as a caller runs it: the exit states, and what
//! reaches standard output.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

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
    assert!(
        pr["protected_files"]
            .as_array()
            .unwrap()
            .contains(&Value::from("README.md"))
    );
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
        // Whatever the request held, every line of the log is ours.
        assert!(
            stderr.lines().all(|line| line.starts_with("error: ")),
            "{change:?}: {stderr}"
        );
    }
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
            "create_pull_request,noop,missing_tool,missing_data",
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
    assert!(!protected.contains(&serde_json::json!("README.md")));
    assert!(protected.contains(&serde_json::json!("AGENTS.md")));
}

#[test]
fn review_caller_bounds_allow_only_analysis_outputs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../workflow");
    for bounds in ["review.toml", "review-command.toml"] {
        let allow = root.join(bounds);
        let review = |kind: &str, outputs: &str| {
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
                .args(["--max-outputs", "1"])
                .output()
                .expect("running agentic-job")
        };
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
        ] {
            let output = review(kind, outputs);
            assert_eq!(output.status.code(), Some(1), "{bounds}: {kind} {outputs}");
            assert!(output.stdout.is_empty(), "{bounds}: {kind} {outputs}");
        }
    }
}
