//! An offline stacked hand-back, from producer through a trusted check to
//! local replay: `policy` compiles the caller's `stack-steps` bound, a
//! producer hands back one git-made mail per step, the trusted check reads
//! exactly that file, checks each step against agentic-job's credential
//! shapes and writes a receipt to a directory of its own, and local replay
//! rebuilds the accepted prefix only from that receipt. The fixture stands in
//! for trusted ingress of the admitted issue plan and receipt, which no
//! workflow, CLI command or caller provides yet: its one-file rule is the
//! fixture's, not a product guarantee. Nothing here pushes or publishes.

// clippy.toml lets test functions unwrap, but not the helpers they share.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use agentic_job::redact;
use anyhow::{Result, ensure};
use safe_outputs::apply::stack::{Stacked, build_verified};
use safe_outputs::check::stack::{self, CheckedStack, Step, artifact};
use safe_outputs::contract::Policy;
use secure_host::files;
use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

/// The producer's only file in a stacked hand-back.
const PROPOSAL: &str = "stack.json";

/// Written by the trusted check, outside the producer's directory.
const RECEIPT: &str = "stack-receipt.json";

const BOUNDS: &str = "hosts = ['github.com']\nrepos = ['example-org/example']\nbases = ['main']\nmax_outputs = 3\nmax_patch_bytes = 65536\nmax_patch_files = 10\n[github.outputs]\ncreate_pull_request = { max = 1 }\n";

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(["-c", "user.name=agent", "-c", "user.email=agent@localhost"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

/// What `policy` compiles for a run that may open pull requests, with
/// STACK_STEPS as the caller's `stack-steps` bound if given.
fn compile(dir: &Path, stack_steps: Option<u32>) -> Policy {
    let bounds = dir.join("bounds.toml");
    let extra = stack_steps.map_or(String::new(), |steps| format!("stack-steps = {steps}\n"));
    std::fs::write(&bounds, format!("{BOUNDS}{extra}")).unwrap();
    let output = Command::new(BIN)
        .args(["policy", "--allow"])
        .arg(&bounds)
        .args(["--repo", "example-org/example", "--base", "main"])
        .args(["--clone-url", "https://github.com/example-org/example"])
        .args(["--kind", "branch", "--outputs", "create_pull_request"])
        .args(["--max-outputs", "3"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

/// A producer's run: one commit per (issue, file, content) step on a base
/// holding a.txt and b.txt, handed back as one mail per step in `out/`.
struct Run {
    dir: tempfile::TempDir,
    base: String,
    policy: Policy,
}

impl Run {
    fn new(steps: &[(u64, &str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        for sub in [&repo, &dir.path().join("out"), &dir.path().join("trusted")] {
            std::fs::create_dir(sub).unwrap();
        }
        git(&repo, &["init", "-q", "--initial-branch=main"]);
        for file in ["a.txt", "b.txt"] {
            std::fs::write(repo.join(file), "old\n").unwrap();
        }
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-qm", "base"]);
        let base = git(&repo, &["rev-parse", "HEAD"]).trim().to_owned();
        let steps: Vec<_> = steps
            .iter()
            .map(|&(issue, file, content)| {
                std::fs::write(repo.join(file), content).unwrap();
                git(&repo, &["add", file]);
                git(&repo, &["commit", "-qm", &format!("Step {issue}\n\nWhy.")]);
                let patch = git(&repo, &["format-patch", "--stdout", "--no-signature", "-1"]);
                json!({"issue": issue, "title": format!("Step {issue}"), "body": "Why.", "patch": patch})
            })
            .collect();
        let proposal = json!({"base_commit": base, "steps": steps}).to_string();
        std::fs::write(dir.path().join("out").join(PROPOSAL), proposal).unwrap();
        // The trusted checkout must not hold the producer's commits.
        git(&repo, &["checkout", "-q", "--detach", &base]);
        let policy = compile(dir.path(), Some(3));
        Self { dir, base, policy }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn admission<'a>(&'a self, issues: &'a [u64]) -> artifact::Admission<'a> {
        artifact::Admission {
            policy: &self.policy,
            base_commit: &self.base,
            issues,
        }
    }

    /// The trusted check: the hand-back's one file, each step scanned.
    fn check(&self, issues: &[u64]) -> Result<CheckedStack> {
        let content = read_handback(&self.path("out"))?;
        let (checked, receipt) = artifact::check(&content, &self.admission(issues), scan)?;
        std::fs::write(self.path("trusted").join(RECEIPT), receipt)?;
        Ok(checked)
    }

    /// Local replay: the hand-back and the trusted check's receipt, read
    /// again and rechecked before any worktree, in a fresh scratch directory.
    fn replay(&self, issues: &[u64]) -> Result<Stacked> {
        let content = read_handback(&self.path("out"))?;
        let receipt = files::read_regular(
            &self.path("trusted").join(RECEIPT),
            artifact::MAX_RECEIPT_BYTES as u64,
        )
        .map_err(|err| anyhow::anyhow!("{RECEIPT} {err}"))?;
        let scratch = tempfile::tempdir_in(self.dir.path())?;
        build_verified(
            &self.path("repo"),
            &content,
            &receipt,
            &self.admission(issues),
            scan,
            scratch.path(),
        )
    }

    fn rewrite(&self, edit: impl FnOnce(&mut serde_json::Value)) {
        let path = self.path("out").join(PROPOSAL);
        let mut proposal = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        edit(&mut proposal);
        std::fs::write(path, proposal.to_string()).unwrap();
    }
}

/// Exactly the proposal, without following a link and within the stack cap:
/// a missing or extra file refuses the hand-back.
fn read_handback(out: &Path) -> Result<Vec<u8>> {
    let names: BTreeSet<_> = std::fs::read_dir(out)?
        .map(|entry| Ok(entry?.file_name()))
        .collect::<Result<_>>()?;
    ensure!(
        names.len() == 1 && names.contains(std::ffi::OsStr::new(PROPOSAL)),
        "a stacked hand-back holds exactly {PROPOSAL}"
    );
    files::read_regular(&out.join(PROPOSAL), stack::MAX_BYTES as u64)
        .map_err(|err| anyhow::anyhow!("{PROPOSAL} {err}"))
}

/// A receipt has no warning channel, so every credential shape refuses
/// the step rather than warning as the one-PR check does.
fn scan(step: &Step) -> Result<()> {
    for text in [&step.title, &step.body, &step.patch] {
        ensure!(
            !redact::is_secret_shaped(text.as_bytes()),
            "secret-shaped string"
        );
    }
    Ok(())
}

const THREE: [(u64, &str, &str); 3] = [
    (1, "a.txt", "a1\n"),
    (2, "b.txt", "b2\n"),
    (3, "b.txt", "b3\n"),
];

#[test]
fn an_admitted_stack_replays_from_its_receipt() {
    let run = Run::new(&THREE);
    let produced = git(&run.path("repo"), &["rev-parse", "main^{tree}"]);
    let checked = run.check(&[1, 2, 3]).unwrap();
    assert!(checked.refused.is_none(), "{checked:?}");
    let stacked = run.replay(&[1, 2, 3]).unwrap();
    assert!(stacked.refused.is_none());
    let mut parent = run.base.clone();
    for (index, step) in stacked.steps.iter().enumerate() {
        let shown = git(
            &run.path("repo"),
            &["show", "-s", "--format=%P %s", &step.head],
        );
        assert_eq!(shown.trim(), format!("{parent} Step {}", index + 1));
        parent = step.head.clone();
    }
    assert_eq!(format!("{}\n", stacked.steps[2].tree), produced);
}

#[test]
fn inconsistent_inputs_get_no_receipt() {
    for (case, reason) in [
        ("disabled bounds", "outside policy bounds"),
        // max_outputs still admits three.
        ("stack-steps below plan", "outside policy bounds"),
        ("other base", "trusted base commit"),
        ("extra step", "step count is outside bounds"),
        ("missing proposal", "holds exactly"),
        ("extra file", "holds exactly"),
    ] {
        let mut run = Run::new(&THREE);
        let mut issues = vec![1, 2, 3];
        match case {
            "disabled bounds" => run.policy = compile(run.dir.path(), None),
            "stack-steps below plan" => run.policy = compile(run.dir.path(), Some(2)),
            "other base" => run.base = "2".repeat(40),
            "extra step" => issues.truncate(2),
            "missing proposal" => std::fs::remove_file(run.path("out").join(PROPOSAL)).unwrap(),
            "extra file" => std::fs::write(run.path("out/notes.txt"), "more\n").unwrap(),
            _ => unreachable!(),
        }
        let error = run.check(&issues).unwrap_err().to_string();
        assert!(error.contains(reason), "{case}: {error}");
        assert!(!run.path("trusted").join(RECEIPT).exists(), "{case}");
    }
}

#[test]
fn substitution_after_check_stops_replay_before_a_worktree() {
    const CHANGED: &str = "stack proposal, admission or checked prefix changed";
    for (case, reason) in [
        ("proposal bytes", CHANGED),
        ("receipt bytes", CHANGED),
        ("missing receipt", RECEIPT),
        ("extra file", "holds exactly"),
        ("plan order", CHANGED),
        ("policy", CHANGED),
    ] {
        let mut run = Run::new(&THREE);
        run.check(&[1, 2, 3]).unwrap();
        let mut issues = vec![1, 2, 3];
        let receipt = run.path("trusted").join(RECEIPT);
        match case {
            "proposal bytes" => run.rewrite(|proposal| {
                let patch = proposal["steps"][2]["patch"].as_str().unwrap();
                proposal["steps"][2]["patch"] = json!(patch.replace("Why.", "Other."));
            }),
            "receipt bytes" => {
                let mut bytes = std::fs::read(&receipt).unwrap();
                // A digest's last hex digit, before `"}`.
                let last = bytes.len() - 3;
                bytes[last] ^= 1;
                std::fs::write(&receipt, bytes).unwrap();
            }
            "missing receipt" => std::fs::remove_file(&receipt).unwrap(),
            "extra file" => std::fs::write(run.path("out/notes.txt"), "more\n").unwrap(),
            "plan order" => issues = vec![1, 3, 2],
            "policy" => run.policy.base = "other".to_owned(),
            _ => unreachable!(),
        }
        let error = run.replay(&issues).unwrap_err().to_string();
        assert!(error.contains(reason), "{case}: {error}");
        let worktrees = git(&run.path("repo"), &["worktree", "list", "--porcelain"]);
        assert_eq!(worktrees.matches("worktree ").count(), 1, "{case}");
    }
}

#[test]
fn a_refused_step_keeps_only_the_prefix() {
    let key = ["-----BEGIN ", "PRIVATE KEY", "-----\n"].concat();
    for (case, steps, issues, accepted, reason) in [
        // The admitted order is not the proposal's.
        (
            "order",
            THREE.to_vec(),
            [1, 3, 2],
            1,
            "stack step does not match the admitted issue order",
        ),
        // The producer dropped the plan's last issue.
        (
            "missing step",
            THREE[..2].to_vec(),
            [1, 2, 3],
            2,
            "stack proposal does not cover the admitted issue plan",
        ),
        // Step 3 reverts step 2's secret, so the final diff only changes b.txt.
        (
            "reverted secret",
            vec![
                (1, "b.txt", "b1\n"),
                (2, "a.txt", key.as_str()),
                (3, "a.txt", "old\n"),
            ],
            [1, 2, 3],
            1,
            "stack step inspection refused",
        ),
    ] {
        let run = Run::new(&steps);
        if case == "reverted secret" {
            let changed = git(
                &run.path("repo"),
                &["diff", "--name-only", &run.base, "main"],
            );
            assert_eq!(changed, "b.txt\n");
        }
        let checked = run.check(&issues).unwrap();
        assert_eq!(checked.accepted.len(), accepted, "{case}");
        let refusal = checked.refused.unwrap();
        let position = accepted + 1;
        assert_eq!(
            (refusal.position, refusal.reason.as_str()),
            (position, reason)
        );
        let stacked = run.replay(&issues).unwrap();
        assert_eq!(stacked.steps.len(), accepted, "{case}");
        assert_eq!(stacked.refused.unwrap().position, position, "{case}");
    }
}

#[test]
fn an_ordinary_pull_request_hand_back_cannot_take_the_stack_path() {
    let run = Run::new(&THREE);
    let out = run.path("out");
    std::fs::remove_file(out.join(PROPOSAL)).unwrap();
    let ordinary = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/check/handback");
    for entry in std::fs::read_dir(ordinary).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), out.join(entry.file_name())).unwrap();
        // Nor is any of its files, renamed, a stack proposal.
        let content = std::fs::read(entry.path()).unwrap();
        let admission = run.admission(&[1]);
        assert!(
            artifact::check(&content, &admission, |_| panic!("inspected {entry:?}")).is_err(),
            "{entry:?}"
        );
    }
    let error = run.check(&[1]).unwrap_err().to_string();
    assert!(error.contains("holds exactly"), "{error}");
    assert!(!run.path("trusted").join(RECEIPT).exists());
}
