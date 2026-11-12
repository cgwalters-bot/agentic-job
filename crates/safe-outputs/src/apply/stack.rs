//! Experimental: building the commits of an ordered stack that
//! [`crate::check::stack`] accepted, one per step, each on its
//! predecessor and the first on the base, and rebuilding them after a fix
//! round changed one step.
//!
//! As for a [replacement series](super::replacement), the caller runs this
//! from its own binary in its own repository, every commit is held to the
//! paths check read for it, and the same mails, each with its one Date, on
//! the same parent are the same commits. A fix round therefore rebuilds
//! the whole stack from checked steps: nothing is replayed from a branch
//! check did not read. It pushes no branch and opens no pull request; no
//! CLI command or workflow calls it yet.
//!
//! A step that does not apply on its predecessor, or changes other paths,
//! stops the stack there: the steps below it are kept and none above it is
//! built, so a conflict never drops a step silently. A refusal's reason is
//! fixed text, never git's, which holds the agent's.

use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::COMMIT_RE;
use super::replacement::{Applied, Built, apply_mail, git};
use crate::check::stack::{CheckedStep, MAX_STEPS, Refusal};

const WORKTREE: &str = "stack-trial";

const MAIL: &str = "stack-mail.patch";

/// A stack's commits in step order, up to the first refusal.
#[derive(Debug)]
pub struct Stacked {
    pub steps: Vec<Built>,
    pub refused: Option<Refusal>,
}

/// Builds the accepted STEPS on BASE, the base they were checked on, in
/// REPO, in a worktree under TEMP.
pub fn build(repo: &Path, base: &str, steps: &[CheckedStep], temp: &Path) -> Result<Stacked> {
    let steps: Vec<_> = steps.iter().collect();
    replay(repo, base, &steps, temp)
}

/// Rebuilds the stack of the accepted STEPS on BASE after a fix round
/// replaced step POSITION (one-based) with FIX, checked as a step of the
/// same stack. The steps below POSITION are the same commits as before;
/// the steps above it are built again on the fix.
pub fn restack(
    repo: &Path,
    base: &str,
    steps: &[CheckedStep],
    position: usize,
    fix: &CheckedStep,
    temp: &Path,
) -> Result<Stacked> {
    ensure!(
        (1..=steps.len()).contains(&position),
        "Stack position {position} is outside a stack of {}",
        steps.len()
    );
    let mut steps: Vec<_> = steps.iter().collect();
    steps[position - 1] = fix;
    replay(repo, base, &steps, temp)
}

/// Applies STEPS on BASE in a worktree of REPO's under TEMP until one is
/// refused.
fn replay(repo: &Path, base: &str, steps: &[&CheckedStep], temp: &Path) -> Result<Stacked> {
    ensure!(COMMIT_RE.is_match(base), "Invalid stack base");
    ensure!(
        (1..=MAX_STEPS as usize).contains(&steps.len()),
        "stack step count is outside bounds"
    );
    // Git resolves a relative worktree path against REPO, not our cwd.
    let temp = std::path::absolute(temp).context("resolving the stack's temp directory")?;
    let dir = temp.join(WORKTREE);
    let dir_arg = dir.to_str().context("the stack's directory is not UTF-8")?;
    git(
        repo,
        &["worktree", "add", "--quiet", "--detach", dir_arg, base],
    )?;
    let replayed = apply_steps(&dir, &temp.join(MAIL), steps);
    let removed = git(repo, &["worktree", "remove", "--force", dir_arg]);
    let stacked = replayed?;
    removed?;
    Ok(stacked)
}

fn apply_steps(dir: &Path, file: &Path, steps: &[&CheckedStep]) -> Result<Stacked> {
    let mut stacked = Stacked {
        steps: Vec::new(),
        refused: None,
    };
    for (index, step) in steps.iter().enumerate() {
        let checked: Vec<_> = step.files.iter().map(String::as_str).collect();
        let reason = match apply_mail(dir, file, &step.step.patch, &checked)? {
            Applied::Built(built) => {
                stacked.steps.push(built);
                continue;
            }
            Applied::Failed(_) => "stack step does not apply on its predecessor",
            Applied::Nonlinear => "stack step is not one commit",
            Applied::Unchecked => "stack step changed unchecked paths",
        };
        stacked.refused = Some(Refusal {
            position: index + 1,
            reason: reason.to_owned(),
        });
        break;
    }
    Ok(stacked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::stack::Step;
    use std::process::Command;

    fn run(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    /// Commits CONTENT to FILE on REPO's HEAD and returns it as a step
    /// checked through the public stack checker, and the commit.
    fn commit(
        repo: &Path,
        base: &str,
        issue: u64,
        file: &str,
        content: &str,
    ) -> (CheckedStep, String) {
        std::fs::write(repo.join(file), content).unwrap();
        run(repo, &["add", file]);
        run(repo, &["commit", "-qm", &format!("Step {issue}\n\nWhy.")]);
        let mail = run(
            repo,
            &[
                "format-patch",
                "--stdout",
                "--no-signature",
                "--no-renames",
                "-1",
            ],
        ) + "\n";
        let step = Step {
            issue,
            title: format!("Step {issue}"),
            body: "Why.".to_owned(),
            patch: mail,
        };
        let proposal = serde_json::json!({"base_commit": base, "steps": [step]});
        let policy = crate::check::fixtures::policy();
        let mut checked = crate::check::stack::check(
            proposal.to_string().as_bytes(),
            1,
            base,
            4096,
            &policy.safe_outputs.create_pull_request.unwrap().rules(),
            |_| Ok(()),
        )
        .unwrap();
        assert!(checked.refused.is_none(), "{checked:?}");
        (
            checked.accepted.remove(0),
            run(repo, &["rev-parse", "HEAD"]),
        )
    }

    struct Fixture {
        temp: tempfile::TempDir,
        base: String,
        steps: Vec<CheckedStep>,
    }

    impl Fixture {
        fn repo(&self) -> std::path::PathBuf {
            self.temp.path().join("repo")
        }
    }

    /// Three steps: one changes a.txt, and two and three each change b.txt,
    /// three on two's change.
    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        run(&repo, &["init", "-q", "--initial-branch=main"]);
        std::fs::write(repo.join("a.txt"), "a\n").unwrap();
        std::fs::write(repo.join("b.txt"), "b\n").unwrap();
        run(&repo, &["add", "."]);
        run(&repo, &["commit", "-qm", "base"]);
        let base = run(&repo, &["rev-parse", "HEAD"]);
        let steps = [
            (1, "a.txt", "a1\n"),
            (2, "b.txt", "b2\n"),
            (3, "b.txt", "b3\n"),
        ]
        .into_iter()
        .map(|(issue, file, content)| commit(&repo, &base, issue, file, content).0)
        .collect();
        run(&repo, &["checkout", "-q", "--detach", &base]);
        Fixture { temp, base, steps }
    }

    fn show(repo: &Path, revision: &str) -> String {
        run(repo, &["show", "-s", "--format=%P %s", revision])
    }

    #[test]
    fn three_steps_stack_on_each_other() {
        let fixture = fixture();
        let repo = fixture.repo();
        let stacked = build(&repo, &fixture.base, &fixture.steps, fixture.temp.path()).unwrap();
        assert!(stacked.refused.is_none());
        let mut parent = fixture.base.clone();
        for (index, step) in stacked.steps.iter().enumerate() {
            assert_eq!(
                show(&repo, &step.head),
                format!("{parent} Step {}", index + 1)
            );
            parent = step.head.clone();
        }
        let top = &stacked.steps[2].head;
        assert_eq!(run(&repo, &["show", &format!("{top}:b.txt")]), "b3");
        let again = build(&repo, &fixture.base, &fixture.steps, fixture.temp.path()).unwrap();
        assert_eq!(again.steps, stacked.steps, "a rebuild is the same stack");
    }

    #[test]
    fn a_refused_middle_step_keeps_the_steps_below() {
        for (broken, reason) in [
            ("context", "does not apply"),
            ("paths", "unchecked paths"),
            ("mail", "does not apply"),
        ] {
            let mut fixture = fixture();
            let middle = &mut fixture.steps[1];
            match broken {
                "context" => middle.step.patch = middle.step.patch.replace("-b\n", "-x\n"),
                "paths" => middle.files = vec!["a.txt".to_owned()],
                _ => middle.step.patch = "not a mail\n".to_owned(),
            }
            let repo = fixture.repo();
            let stacked = build(&repo, &fixture.base, &fixture.steps, fixture.temp.path()).unwrap();
            assert_eq!(stacked.steps.len(), 1, "{broken}");
            let refusal = stacked.refused.unwrap();
            assert_eq!(refusal.position, 2, "{broken}");
            assert!(
                refusal.reason.contains(reason),
                "{broken}: {}",
                refusal.reason
            );
        }
    }

    #[test]
    fn a_fix_on_step_one_restacks_the_steps_above() {
        let fixture = fixture();
        let (repo, temp) = (fixture.repo(), fixture.temp.path());
        let stacked = build(&repo, &fixture.base, &fixture.steps, temp).unwrap();

        run(&repo, &["checkout", "-q", "--detach", &fixture.base]);
        let (fix, _) = commit(&repo, &fixture.base, 1, "a.txt", "a1 fixed\n");
        let restacked = restack(&repo, &fixture.base, &fixture.steps, 1, &fix, temp).unwrap();
        assert!(restacked.refused.is_none());
        let mut parent = fixture.base.clone();
        for (index, (new, old)) in restacked.steps.iter().zip(&stacked.steps).enumerate() {
            assert_ne!(new.head, old.head, "step {}", index + 1);
            assert_eq!(
                show(&repo, &new.head),
                format!("{parent} Step {}", index + 1)
            );
            parent = new.head.clone();
        }
        let top = &restacked.steps[2].head;
        assert_eq!(run(&repo, &["show", &format!("{top}:a.txt")]), "a1 fixed");
        assert_eq!(run(&repo, &["show", &format!("{top}:b.txt")]), "b3");

        // A fix on step two, which also adds c.txt, keeps step one's commit.
        let parent = &stacked.steps[0].head;
        run(&repo, &["checkout", "-q", "--detach", parent]);
        std::fs::write(repo.join("c.txt"), "c\n").unwrap();
        run(&repo, &["add", "c.txt"]);
        let (fix, _) = commit(&repo, &fixture.base, 2, "b.txt", "b2\n");
        let restacked = restack(&repo, &fixture.base, &fixture.steps, 2, &fix, temp).unwrap();
        assert!(restacked.refused.is_none());
        assert_eq!(restacked.steps[0], stacked.steps[0]);
        assert_eq!(
            show(&repo, &restacked.steps[1].head),
            format!("{parent} Step 2")
        );
        let top = &restacked.steps[2].head;
        assert_eq!(run(&repo, &["show", &format!("{top}:c.txt")]), "c");
    }

    #[test]
    fn a_conflicting_fix_stops_the_restack() {
        let fixture = fixture();
        let (repo, temp) = (fixture.repo(), fixture.temp.path());
        let stacked = build(&repo, &fixture.base, &fixture.steps, temp).unwrap();
        assert!(stacked.refused.is_none());
        assert_eq!(stacked.steps.len(), 3);
        let again = build(&repo, &fixture.base, &fixture.steps, temp).unwrap();
        assert_eq!(again.steps, stacked.steps);
        run(&repo, &["checkout", "-q", "--detach", &fixture.base]);
        // Step two's context, b.txt's one line, is gone under it.
        let (fix, _) = commit(&repo, &fixture.base, 1, "b.txt", "fixed\n");
        let restacked = restack(&repo, &fixture.base, &fixture.steps, 1, &fix, temp).unwrap();
        assert_eq!(restacked.steps.len(), 1);
        assert_ne!(restacked.steps[0], stacked.steps[0]);
        let refusal = restacked.refused.unwrap();
        assert_eq!(refusal.position, 2);
        assert_eq!(
            refusal.reason,
            "stack step does not apply on its predecessor"
        );
        assert_eq!(
            run(
                &repo,
                &["show", &format!("{}:b.txt", restacked.steps[0].head)]
            ),
            "fixed"
        );
        // Refusal leaves no worktree/session behind: the same call can retry.
        let again = restack(&repo, &fixture.base, &fixture.steps, 1, &fix, temp).unwrap();
        assert_eq!(again.steps, restacked.steps);
        assert_eq!(again.refused.unwrap().position, 2);
    }

    #[test]
    fn build_and_restack_accept_relative_temp() {
        let fixture = fixture();
        let repo = fixture.repo();
        let cwd = std::env::current_dir().unwrap();
        let temp = tempfile::tempdir_in(&cwd).unwrap();
        let relative = temp.path().strip_prefix(&cwd).unwrap();
        let stacked = build(&repo, &fixture.base, &fixture.steps, relative).unwrap();
        assert!(stacked.refused.is_none());
        assert_eq!(stacked.steps.len(), 3);
        let (fix, _) = commit(&repo, &fixture.base, 1, "a.txt", "fixed\n");
        let restacked = restack(&repo, &fixture.base, &fixture.steps, 1, &fix, relative).unwrap();
        assert!(restacked.refused.is_none());
        assert_eq!(restacked.steps.len(), 3);
        let absolute = restack(&repo, &fixture.base, &fixture.steps, 1, &fix, temp.path()).unwrap();
        assert_eq!(absolute.steps, restacked.steps);
    }

    #[test]
    fn what_is_not_a_stack_is_refused() {
        let fixture = fixture();
        let (repo, temp) = (fixture.repo(), fixture.temp.path());
        let (base, steps, fix) = (&fixture.base, &fixture.steps, &fixture.steps[0]);
        for position in [0, 4] {
            assert!(restack(&repo, base, steps, position, fix, temp).is_err());
        }
        let many: Vec<_> = (0..=MAX_STEPS)
            .map(|_| CheckedStep {
                step: Step {
                    issue: fix.step.issue,
                    title: fix.step.title.clone(),
                    body: fix.step.body.clone(),
                    patch: fix.step.patch.clone(),
                },
                files: fix.files.clone(),
            })
            .collect();
        for (base, steps) in [("main", steps.as_slice()), (base, &[]), (base, &many)] {
            assert!(build(&repo, base, steps, temp).is_err());
        }
    }
}
