//! Bind checked test evidence to the tree apply's trial made of the
//! checked patch, and say in the pull request what it holds, before the
//! handlers publish anything.
//!
//! `check` held the evidence's base and head to the commit the patch
//! applies to; only here, where the patch is applied, is its tree known.
//! A manifest naming another tree describes tests of another change, and
//! stops the job. The draft then states each outcome's count, with a link
//! to this run, whose checked upload holds the manifest and its logs. A
//! hand-back without evidence is left as it is.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use crate::check::test_evidence::Info;
use crate::exit::Exit;
use crate::files;
use crate::policy::{COMMIT_RE, CREATE_PULL_REQUEST};

/// As the other readers of check's report and the checked outputs.
const MAX_JSON_BYTES: u64 = 4 << 20;
/// How much of an object ID the draft shows.
const SHORT: usize = 12;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// check's report.json
    #[arg(long)]
    pub report: PathBuf,
    /// Checked agent_output.json, updated in place
    #[arg(long)]
    pub file: PathBuf,
    /// The tree of the checked patch applied on its base, from apply's trial
    #[arg(long, default_value = "")]
    pub tree: String,
    /// This run's page, whose checked upload holds the evidence
    #[arg(long)]
    pub run_url: String,
}

fn read(path: &std::path::Path) -> Result<Value> {
    let bytes = files::read_regular(path, MAX_JSON_BYTES)
        .with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// What the draft says of INFO, bound to TREE, with its logs at RUN_URL.
fn note(info: &Info, run_url: &str) -> String {
    let short = |id: &str| id.chars().take(SHORT).collect::<String>();
    let mut line = info.line();
    // Upper-case its first word: it opens a paragraph here.
    line.replace_range(..1, "T");
    format!(
        "{line} It names tree {}, which this patch makes on {}; the manifest and every \
         attempt's log are in [this run's checked outputs]({run_url}).",
        short(&info.tree),
        short(&info.base)
    )
}

pub fn run(args: &Args) -> Result<Exit> {
    let report = read(&args.report)?;
    let Some(evidence) = report.get("test_evidence").filter(|value| !value.is_null()) else {
        return Ok(Exit::Success);
    };
    let info: Info =
        serde_json::from_value(evidence.clone()).context("check's report's test_evidence")?;
    ensure!(
        COMMIT_RE.is_match(&args.tree),
        "the checked patch was not applied to a tree here, so the test evidence cannot be bound \
         to it"
    );
    ensure!(
        info.tree == args.tree,
        "the test evidence is of tree {}, but the checked patch applied on {} makes {}: the tests \
         ran on another change",
        info.tree,
        info.base,
        args.tree
    );
    ensure!(
        args.run_url.starts_with("https://")
            && !args
                .run_url
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || "()<>[]".contains(c)),
        "the run's URL {:?} is not one a link can hold",
        args.run_url
    );
    let mut output = read(&args.file)?;
    let items = output["items"]
        .as_array_mut()
        .context("outputs have no items array")?;
    let mut drafts = 0;
    for item in items
        .iter_mut()
        .filter(|item| item["type"] == CREATE_PULL_REQUEST)
    {
        ensure!(
            item["body"].is_null() || item["body"].is_string(),
            "pull request body is not text"
        );
        let body = item["body"].as_str().unwrap_or_default();
        item["body"] = format!("{body}\n\n{}", note(&info, &args.run_url)).into();
        drafts += 1;
    }
    ensure!(
        drafts == 1,
        "test evidence goes with one pull request; the checked outputs hold {drafts}"
    );
    std::fs::write(&args.file, serde_json::to_vec(&output)?)
        .with_context(|| format!("writing {}", args.file.display()))?;
    Ok(Exit::Success)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::*;
    use crate::check::test_evidence::tests::{BASE, TREE, manifest, rules};

    const RUN_URL: &str = "https://github.com/o/r/actions/runs/7";

    /// What check reports of the fixture manifest.
    pub(crate) fn info() -> Info {
        let logs: BTreeSet<&str> = [
            "test-evidence-1.log",
            "test-evidence-2.log",
            "test-evidence-3.log",
        ]
        .into_iter()
        .collect();
        crate::check::test_evidence::check(manifest().to_string().as_bytes(), &logs, &rules(), BASE)
            .unwrap()
    }

    #[test]
    fn binds_the_tree_and_writes_the_counts() {
        let outputs = json!({"items": [
            {"type": "create_pull_request", "title": "t", "body": "Why.", "branch": "agent-run-7"},
            {"type": "noop", "message": "x"},
        ], "errors": []});
        let with_evidence = json!({"ok": true, "test_evidence": info()});
        let other_tree = "3".repeat(40);
        // (the case, the report, the outputs, the tree, the run's URL, the
        // pull request's body or why the job stops)
        type Case<'a> = (
            &'a str,
            Value,
            Value,
            &'a str,
            &'a str,
            Result<Option<&'a str>, &'a str>,
        );
        let two = json!({"items": [
            {"type": "create_pull_request", "body": "a"},
            {"type": "create_pull_request", "body": "b"},
        ]});
        let cases: &[Case] = &[
            (
                "the patch's tree",
                with_evidence.clone(),
                outputs.clone(),
                TREE,
                RUN_URL,
                Ok(Some(
                    "Why.\n\nTest evidence: `install-to-disk` on `devspace-rhel10-64` \
                     (`quay.io/example/bootc@sha256:abc`), 3 attempt(s) planned: 1 pass, 2 fail, \
                     0 skipped, 0 not run; not every attempt passed. This is the run's own \
                     report: check held it to the patch's base, not its results to the truth. \
                     It names tree 222222222222, which this patch makes on 111111111111; the \
                     manifest and every attempt's log are in [this run's checked \
                     outputs](https://github.com/o/r/actions/runs/7).",
                )),
            ),
            (
                "no evidence",
                json!({"ok": true}),
                outputs.clone(),
                "",
                RUN_URL,
                Ok(Some("Why.")),
            ),
            (
                "another tree",
                with_evidence.clone(),
                outputs.clone(),
                &other_tree,
                RUN_URL,
                Err("the test evidence is of tree 2222222222222222222222222222222222222222, but"),
            ),
            (
                "no trial",
                with_evidence.clone(),
                outputs.clone(),
                "",
                RUN_URL,
                Err("was not applied to a tree here"),
            ),
            (
                "a link that ends early",
                with_evidence.clone(),
                outputs.clone(),
                TREE,
                "https://x/(y)",
                Err("is not one a link can hold"),
            ),
            (
                "no pull request",
                with_evidence.clone(),
                json!({"items": [{"type": "noop", "message": "x"}]}),
                TREE,
                RUN_URL,
                Err("the checked outputs hold 0"),
            ),
            (
                "two pull requests",
                with_evidence.clone(),
                two,
                TREE,
                RUN_URL,
                Err("the checked outputs hold 2"),
            ),
            (
                "a malformed report",
                json!({"test_evidence": {"tree": TREE}}),
                outputs.clone(),
                TREE,
                RUN_URL,
                Err("check's report's test_evidence"),
            ),
        ];
        for (name, report, outputs, tree, run_url, want) in cases {
            let dir = tempfile::tempdir().unwrap();
            let args = Args {
                report: dir.path().join("report.json"),
                file: dir.path().join("agent_output.json"),
                tree: (*tree).to_owned(),
                run_url: (*run_url).to_owned(),
            };
            std::fs::write(&args.report, report.to_string()).unwrap();
            std::fs::write(&args.file, outputs.to_string()).unwrap();
            let got = run(&args);
            let written: Value =
                serde_json::from_slice(&std::fs::read(&args.file).unwrap()).unwrap();
            match (got, want) {
                (Ok(Exit::Success), Ok(body)) => {
                    assert_eq!(written["items"][0]["body"].as_str(), *body, "{name}");
                    assert_eq!(written["items"][1], outputs["items"][1], "{name}");
                }
                (Err(err), Err(want)) => {
                    assert!(format!("{err:#}").contains(want), "{name}: {err:#}");
                    assert_eq!(&written, outputs, "{name}: changed on refusal");
                }
                (got, _) => panic!("{name}: {got:?}"),
            }
        }
    }
}
