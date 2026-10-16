//! Golden files: what the old tree's `handback.mjs` hands back for a
//! checkout, and what `run`'s hand-back does for the same checkout, must
//! be the same files with the same bytes, but for one thing docs/plan.md
//! changes on purpose: the message of the patch's commit, which was the
//! pull request's title alone and is now its title and body. And a pull
//! request made up for an agent that wrote no summary now says that it
//! is partial. And commits that put the tree back at the base are
//! dropped, saying why, where the old tree made up a pull request without
//! a patch, which `check` refuses.
//!
//! The old code is run as it is, from a checkout of the old tree at the
//! commit the plan names (`OLD_TREE`), by `tests/corpus/handback-old.mjs`.
//! Without `OLD_TREE` this passes without having run; CI's `corpus` job
//! sets it.

// clippy.toml lets test functions unwrap, but not the helpers they share.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use agentic_job::config::Commit;
use agentic_job::policy::Policy;
use agentic_job::run::clone::Checkout;
use agentic_job::run::enter::{Output, Runner, Unconfined};
use agentic_job::run::handback::{self, AGENT_OUTCOME, AGENT_OUTPUTS};
use serde_json::{Value, json};

const OLD_TREE_VAR: &str = "OLD_TREE";
const RUN_ID: &str = "42";
/// What the new hand-back adds to the body of a pull request made up for
/// an agent that wrote no summary, as it is written in `outputs.jsonl`.
const NO_SUMMARY_JSON: &str =
    r"\n\nPartial change: the agent did not say what it did or that it was done.";
/// Both sides commit at this time and with no configuration but the
/// checkout's, so that the same tree gives the same commit.
const GIT_ENV: [(&str, &str); 4] = [
    ("GIT_AUTHOR_DATE", "2026-01-02T03:04:05Z"),
    ("GIT_COMMITTER_DATE", "2026-01-02T03:04:05Z"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
];
/// Makes the checkout every case starts from.
const BASE_SCRIPT: &str = "git init -q -b main . && printf 'one\\ntwo\\nthree\\n' > a.txt && \
    echo keep > keep.txt && echo gone > gone.txt && mkdir sub && echo x > sub/x.rs && \
    git add . && git -c user.name=t -c user.email=t@example.invalid commit -q -m Base";

/// Runs commands as this user, with the environment both sides share.
struct Dated;

impl Runner for Dated {
    fn run(&self, argv: &[&str], input: &[u8], max_output: usize) -> anyhow::Result<Output> {
        let vars: Vec<String> = GIT_ENV.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let mut wrapped = vec!["env"];
        wrapped.extend(vars.iter().map(String::as_str));
        wrapped.extend(argv);
        Unconfined.run(&wrapped, input, max_output)
    }
}

fn sh(dir: &Path, script: &str) -> String {
    let out = Command::new("sh")
        .args(["-ec", script])
        .current_dir(dir)
        .envs(GIT_ENV)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{script}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// One side's home: a checkout the agent changed, and its files.
struct Side {
    home: PathBuf,
    checkout: Checkout,
}

impl Side {
    fn new(root: &Path, name: &str, case: &Case) -> Self {
        let home = root.join(name);
        let dir = home.join("work/r");
        for sub in ["work/r", "out", "results", "safe-outputs"] {
            std::fs::create_dir_all(home.join(sub)).unwrap();
        }
        sh(&dir, BASE_SCRIPT);
        let base_commit = sh(&dir, "git rev-parse HEAD");
        if !case.change.is_empty() {
            sh(&dir, case.change);
        }
        Self {
            home,
            checkout: Checkout { dir, base_commit },
        }
    }

    /// The hand-back's files, by name.
    fn handed_back(&self) -> BTreeMap<String, String> {
        std::fs::read_dir(self.home.join("safe-outputs"))
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    String::from_utf8(std::fs::read(entry.path()).unwrap()).unwrap(),
                )
            })
            .collect()
    }
}

struct Case {
    name: &'static str,
    /// What the agent does in the checkout.
    change: &'static str,
    /// Its `safe-outputs.jsonl`.
    requests: &'static str,
    /// Its `outcome.json`.
    outcome: Value,
    /// The output types the policy allows.
    outputs: Value,
    max_patch_bytes: u64,
    /// Whether the two patches are the same but for the message. Not
    /// when the agent worded its own pull request: the old tree did not
    /// use that for the commit either, so there the messages differ in
    /// more than the body.
    patch: bool,
    /// Whether the new side's made-up pull request says it is partial.
    no_summary: bool,
    /// Why the new side drops the change, where the old tree made up a
    /// pull request without its patch.
    dropped: Option<&'static str>,
}

fn pull_requests() -> Value {
    json!({
        "create_pull_request": {
            "max": 1, "protected_files": [], "protect_top_level_dot_folders": true,
            "protected_files_policy": "blocked", "draft": true, "max_patch_size": 1024,
            "max_patch_files": 100,
        },
        "noop": {"max": 1},
    })
}

fn cases() -> Vec<Case> {
    let case = |name, change, requests, outcome| Case {
        name,
        change,
        requests,
        outcome,
        outputs: pull_requests(),
        max_patch_bytes: 1 << 20,
        patch: true,
        no_summary: false,
        dropped: None,
    };
    const EDIT: &str = "printf 'one\\n2\\nthree\\nfour\\n' > a.txt";
    const MANY: &str = "printf 'one\\n2\\nthree\\nfour\\n' > a.txt && git rm -q gone.txt && \
        mkdir -p new/dir && printf '#!/bin/sh\\necho hi\\n' > new/dir/run.sh && \
        chmod +x new/dir/run.sh && : > new/empty && printf 'no newline' > sub/x.rs";
    const OWN: &str = concat!(
        r#"{"type":"create_pull_request","title":"a: Edit","body":"Why.","branch":"evil/../x"}"#,
        "\n",
        r#"{"type":"noop","message":"Nothing else."}"#,
        "\n"
    );
    vec![
        case("nothing at all", "", "", json!({})),
        case(
            "only a request",
            "",
            "{\"type\":\"noop\",\"message\":\"m\"}\n",
            json!({}),
        ),
        case(
            "a change the agent did not ask to have proposed",
            MANY,
            "",
            json!({"summary": "Fix the parser.\nIt dropped the last line."}),
        ),
        Case {
            no_summary: true,
            ..case("a change and no outcome", EDIT, "", json!({}))
        },
        case(
            "a change of a run that stopped early",
            EDIT,
            "",
            json!({"summary": "Half of it.", "stopped_early": "out of\ntime"}),
        ),
        Case {
            patch: false,
            ..case(
                "the agent's own pull request",
                EDIT,
                OWN,
                json!({"summary": "s"}),
            )
        },
        Case {
            patch: false,
            ..case(
                "a type with dashes, and a line that is not JSON",
                EDIT,
                "oops\n  {\"type\":\"create-pull-request\",\"body\":\"B\",\"title\":\"T\"}  \n\n[1]\n",
                json!({"summary": "s"}),
            )
        },
        case(
            "a request for a pull request and no change",
            "",
            "{\"type\":\"create_pull_request\",\"title\":\"T\",\"body\":\"B\"}\n",
            json!({}),
        ),
        case(
            "commits of the agent's own",
            "printf 'one\\n2\\n' > a.txt && \
             git -c user.name=a -c user.email=a@example.invalid commit -q -am Mine && echo y > b.txt",
            "",
            json!({"summary": "Two things.\nBoth small."}),
        ),
        Case {
            dropped: Some("leave the tree as it was"),
            ..case(
                "a change put back",
                "echo x >> a.txt && git -c user.name=a -c user.email=a@example.invalid commit -q -am Mine && \
                 printf 'one\\ntwo\\nthree\\n' > a.txt",
                "",
                json!({"summary": "Nothing after all."}),
            )
        },
        Case {
            outputs: json!({"noop": {"max": 1}}),
            ..case(
                "a change, and pull requests are not allowed",
                EDIT,
                "{\"type\":\"noop\",\"message\":\"m\"}\n",
                json!({"summary": "s"}),
            )
        },
        Case {
            max_patch_bytes: 64,
            ..case(
                "a change over the cap",
                MANY,
                "{\"type\":\"noop\",\"message\":\"m\"}\n",
                json!({"summary": "s"}),
            )
        },
    ]
}

/// A patch without what its commit's message changes: the commit's id in
/// the first line, and the message itself, from the subject to the line
/// that ends it.
fn without_message(patch: &str) -> String {
    let mut lines = patch.lines();
    let first = lines.next().unwrap_or_default();
    let (from, rest) = first.split_at(first.find(' ').unwrap_or(0));
    assert_eq!(from, "From", "{first}");
    let rest = rest
        .trim_start()
        .split_once(' ')
        .map_or("", |(_, rest)| rest);
    let mut kept = vec![format!("From COMMIT {rest}")];
    let mut in_message = false;
    for line in lines {
        if line.starts_with("Subject: ") {
            in_message = true;
        } else if in_message && line == "---" {
            in_message = false;
        }
        if !in_message {
            kept.push(line.to_owned());
        }
    }
    kept.join("\n")
}

/// The lines of a patch that [`without_message`] leaves out, but for the
/// commit's id: from the subject to before the line that ends the
/// message.
fn message_of(patch: &str) -> Vec<&str> {
    patch
        .lines()
        .skip_while(|line| !line.starts_with("Subject: "))
        .take_while(|line| *line != "---")
        .collect()
}

#[test]
fn the_old_hand_back_and_the_new_differ_only_in_the_commit_message() {
    let Some(old_tree) = std::env::var_os(OLD_TREE_VAR) else {
        return;
    };
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/handback-old.mjs");
    for case in cases() {
        let name = case.name;
        let root = tempfile::tempdir().unwrap();
        let policy: Policy = serde_json::from_value(json!({
            "repo": "o/r", "clone_url": "https://example.invalid/o/r", "base": "main",
            "kind": "branch", "max_outputs": 3, "max_patch_bytes": case.max_patch_bytes,
            "safe_outputs": case.outputs,
        }))
        .unwrap();

        // The old tree: its supervisor found whether the tree changed
        // and read the agent's files; its hand-back did the rest.
        let old = Side::new(root.path(), "old", &case);
        let changed = !sh(&old.checkout.dir, "git status --porcelain").is_empty()
            || sh(&old.checkout.dir, "git rev-parse HEAD") != old.checkout.base_commit;
        let request = root.path().join("request.json");
        let arguments = json!({
            "workdir": old.checkout.dir, "outDir": old.home.join("safe-outputs"),
            "agentText": case.requests, "policy": policy, "repo": policy.repo,
            "ref": policy.base, "base": old.checkout.base_commit, "runId": RUN_ID,
            "outcome": case.outcome, "hasChanges": changed,
        });
        std::fs::write(&request, arguments.to_string()).unwrap();
        let ran = Command::new("node")
            .arg(&driver)
            .arg(&old_tree)
            .arg(&request)
            .envs(GIT_ENV)
            .output()
            .unwrap();
        assert!(
            ran.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&ran.stderr)
        );
        let old_patch: Value = serde_json::from_slice(&ran.stdout).unwrap();

        let new = Side::new(root.path(), "new", &case);
        assert_eq!(new.checkout.base_commit, old.checkout.base_commit, "{name}");
        if !case.requests.is_empty() {
            std::fs::write(new.home.join(AGENT_OUTPUTS), case.requests).unwrap();
        }
        std::fs::write(new.home.join(AGENT_OUTCOME), case.outcome.to_string()).unwrap();
        // The new one leaves no directory when it hands nothing back.
        std::fs::remove_dir(new.home.join("safe-outputs")).unwrap();
        let change = handback::collect(&handback::Request {
            runner: &Dated,
            home: &new.home,
            checkout: &new.checkout,
            policy: &policy,
            commit: &Commit::default(),
            run_id: RUN_ID,
            harness: None,
            run_dir: &new.home.join("results"),
            safe_outputs: &new.home.join("safe-outputs"),
        })
        .unwrap();
        std::fs::create_dir_all(new.home.join("safe-outputs")).unwrap();

        if let Some(why) = case.dropped {
            let dropped = change.dropped.unwrap();
            assert!(dropped.contains(why), "{name}: {dropped}");
            assert_eq!(change.patch["base"], new.checkout.base_commit, "{name}");
            assert!(old_patch["base"].is_null(), "{name}: {old_patch}");
            assert!(new.handed_back().is_empty(), "{name}");
            assert!(
                old.handed_back()["outputs.jsonl"].contains("create_pull_request"),
                "{name}"
            );
            continue;
        }

        // What the summary says of the patch: the same base and the same
        // refusal, and each side its own patch's size.
        for key in ["base", "error"] {
            assert_eq!(change.patch[key], old_patch[key], "{name}: {key}");
        }
        let (old_files, new_files) = (old.handed_back(), new.handed_back());
        assert_eq!(
            new_files.keys().collect::<Vec<_>>(),
            old_files.keys().collect::<Vec<_>>(),
            "{name}"
        );
        for (file, old_content) in &old_files {
            let new_content = &new_files[file];
            if !file.ends_with(".patch") {
                let new_content = if case.no_summary && file == "outputs.jsonl" {
                    assert!(new_content.contains(NO_SUMMARY_JSON), "{name}");
                    new_content.replace(NO_SUMMARY_JSON, "")
                } else {
                    new_content.clone()
                };
                assert_eq!(&new_content, old_content, "{name}: {file}");
                continue;
            }
            for (side, content, summary) in [
                ("old", old_content, &old_patch),
                ("new", new_content, &change.patch),
            ] {
                assert_eq!(summary["bytes"], content.len(), "{name}: {side}");
            }
            assert_eq!(
                without_message(new_content),
                without_message(old_content),
                "{name}: {file}"
            );
            // And the message is all of the difference. The old one is
            // the title of the pull request made up from the outcome,
            // and nothing else; the new one is the title and the body of
            // the request that was handed back, and nothing else.
            assert_ne!(new_content, old_content, "{name}: {file}");
            let request: Value = new_files["outputs.jsonl"]
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .find(|item| item["branch"].is_string())
                .unwrap();
            let (title, body) = (
                request["title"].as_str().unwrap(),
                request["body"].as_str().unwrap(),
            );
            let message = handback::commit_message(title, body, &[], RUN_ID);
            let mut expected: Vec<&str> = message.lines().collect();
            let subject = format!("Subject: [PATCH] {title}");
            expected[0] = &subject;
            assert_eq!(message_of(new_content), expected, "{name}");
            assert!(expected.len() > 2, "{name}: a message with a body");
            if case.patch {
                assert_eq!(message_of(old_content), [subject.as_str(), ""], "{name}");
            }
        }
    }
}

#[test]
fn a_patch_is_compared_without_its_message() {
    let patch = |id: &str, message: &str| {
        format!(
            "From {id} Mon Sep 17 00:00:00 2001\nX-GH-AW-Base-Commit: b\nFrom: a <a@b>\n\
             Date: d\nSubject: [PATCH] {message}\n---\n a.txt | 1 +\n\ndiff --git a/a.txt b/a.txt\n"
        )
    };
    assert_eq!(
        without_message(&patch("1111", "One")),
        without_message(&patch(
            "2222",
            "Two\n\nWith a body.\n    ---\nGenerated-by: AI"
        ))
    );
    assert_ne!(
        without_message(&patch("1111", "One")),
        without_message(&patch("1111", "One").replace("a.txt | 1 +", "a.txt | 2 +"))
    );
    assert!(without_message(&patch("1111", "One")).contains("X-GH-AW-Base-Commit: b"));
}
