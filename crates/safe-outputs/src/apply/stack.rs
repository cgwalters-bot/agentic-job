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
//! check did not read. [`push`] updates the steps' branches with exact
//! leases on the heads the caller pinned; nothing here opens a pull
//! request, and no CLI command or workflow calls it yet.
//!
//! A step that does not apply on its predecessor, or changes other paths,
//! stops the stack there: the steps below it are kept and none above it is
//! built, so a conflict never drops a step silently. A refusal's reason is
//! fixed text, never git's, which holds the agent's.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::replacement::{Applied, Built, apply_mail, git};
use super::{COMMIT_RE, plain_branch};
use crate::check::stack::{CheckedStep, MAX_STEPS, Refusal};

const WORKTREE: &str = "stack-trial";

const MAIL: &str = "stack-mail.patch";

/// One step's branch and the head the caller pinned on it when it read the
/// published stack, `None` for a branch that must not exist yet. Both come
/// from the caller's trusted configuration, never from the proposal.
#[derive(Debug, Clone, Copy)]
pub struct Lease<'a> {
    pub branch: &'a str,
    pub head: Option<&'a str>,
}

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

/// Revalidate a trusted library receipt before building anything. Check and Git
/// refusals both retain only their accepted prefix. This is local replay, not a
/// publisher: credential roles, repository/branch bounds and push leases remain
/// the responsibility of a future publication adapter.
pub fn build_verified(
    repo: &Path,
    content: &[u8],
    receipt: &[u8],
    admission: &crate::check::stack::artifact::Admission<'_>,
    inspect: impl FnMut(&crate::check::stack::Step) -> Result<()>,
    temp: &Path,
) -> Result<Stacked> {
    let checked = crate::check::stack::artifact::revalidate(content, receipt, admission, inspect)?;
    if checked.accepted.is_empty() {
        return Ok(Stacked {
            steps: Vec::new(),
            refused: checked.refused,
        });
    }
    let mut stacked = build(repo, admission.base_commit, &checked.accepted, temp)?;
    if stacked.refused.is_none() {
        stacked.refused = checked.refused;
    }
    Ok(stacked)
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

/// Pushes the built steps of STACKED from REPO to REMOTE, step N's head to
/// LEASES' branch N, in one atomic push leased on every pinned head: the
/// published stack moves as a whole or not at all. A stack whose steps are
/// all already there is an earlier attempt's push, and nothing is pushed;
/// any other head than the pinned or the built one is a concurrent write.
/// Returns whether this call pushed.
///
/// A stack shorter than LEASES, refused or a shorter prefix of the plan,
/// pushes only while no branch above it is pinned or, as of its read,
/// published: updating the steps below would leave those based on the old
/// ones. Git cannot lease a branch it does not push, so one created after
/// the read is not caught. REMOTE must carry no credential: git's errors,
/// which name it, are returned raw.
pub fn push(repo: &Path, remote: &str, stacked: &Stacked, leases: &[Lease<'_>]) -> Result<bool> {
    let built = stacked.steps.len();
    ensure!(
        (1..=MAX_STEPS as usize).contains(&leases.len()) && built <= leases.len(),
        "stack leases do not cover the stack"
    );
    let mut branches = BTreeSet::new();
    for lease in leases {
        ensure!(
            plain_branch(lease.branch) && branches.insert(lease.branch),
            "stack branches must be distinct plain branch names"
        );
        ensure!(
            lease.head.is_none_or(|head| COMMIT_RE.is_match(head)),
            "invalid pinned stack head"
        );
    }
    ensure!(!remote.starts_with('-'), "invalid stack remote");
    ensure!(
        stacked
            .refused
            .as_ref()
            .is_none_or(|refused| refused.position == built + 1),
        "stack refusal is not just above its built steps"
    );
    ensure!(
        leases[built..].iter().all(|lease| lease.head.is_none()),
        "stack of {built} steps would leave published steps above it on the old ones"
    );
    if built == 0 {
        return Ok(false);
    }
    let references: Vec<_> = leases
        .iter()
        .map(|lease| format!("refs/heads/{}", lease.branch))
        .collect();
    let current = || -> Result<Vec<Option<String>>> {
        let mut args = vec!["ls-remote", "--refs", remote];
        args.extend(references.iter().map(String::as_str));
        let listed = git(repo, &args)?;
        let heads: Vec<_> = listed
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .collect();
        Ok(references
            .iter()
            .map(|reference| {
                heads
                    .iter()
                    .find(|(_, name)| name == reference)
                    .map(|(head, _)| (*head).to_owned())
            })
            .collect())
    };
    // Every branch holds its built step, and none above them exists.
    let at = |heads: &[Option<String>]| {
        heads.iter().enumerate().all(|(index, head)| {
            head.as_deref() == stacked.steps.get(index).map(|step| step.head.as_str())
        })
    };
    let heads = current()?;
    if at(&heads) {
        return Ok(false);
    }
    ensure!(
        leases
            .iter()
            .zip(&heads)
            .all(|(lease, head)| head.as_deref() == lease.head),
        "stack branches moved since the run read them"
    );
    let mut args = vec!["push".to_owned(), "--atomic".to_owned()];
    for (lease, reference) in leases.iter().zip(&references).take(built) {
        // An empty expectation is git's lease on a branch that must not exist.
        args.push(format!(
            "--force-with-lease={reference}:{}",
            lease.head.unwrap_or("")
        ));
    }
    args.push(remote.to_owned());
    for (step, reference) in stacked.steps.iter().zip(&references) {
        args.push(format!("{}:{reference}", step.head));
    }
    let args: Vec<_> = args.iter().map(String::as_str).collect();
    git(repo, &args)?;
    ensure!(at(&current()?), "stack heads were not pushed");
    Ok(true)
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
    fn trusted_receipt_revalidates_before_local_replay_and_after_a_fix() {
        use crate::check::stack::artifact::{self, Admission};
        let fixture = fixture();
        let (repo, temp) = (fixture.repo(), fixture.temp.path());
        let mut policy = crate::check::fixtures::policy();
        policy.max_outputs = 3;
        let admission = Admission {
            policy: &policy,
            base_commit: &fixture.base,
            issues: &[1, 2, 3],
        };
        let proposal = |steps: Vec<&CheckedStep>| {
            serde_json::json!({
                "base_commit": fixture.base,
                "steps": steps.iter().map(|step| &step.step).collect::<Vec<_>>()
            })
            .to_string()
        };
        let content = proposal(fixture.steps.iter().collect());
        let (_, receipt) = artifact::check(content.as_bytes(), &admission, |_| Ok(())).unwrap();
        // A failed revalidation must not even allocate the replay worktree.
        assert!(
            build_verified(
                &repo,
                content.as_bytes(),
                &receipt,
                &admission,
                |_| anyhow::bail!("scan refused"),
                &temp.join("absent")
            )
            .is_err()
        );
        assert!(!temp.join("absent").exists());
        let built = build_verified(
            &repo,
            content.as_bytes(),
            &receipt,
            &admission,
            |_| Ok(()),
            temp,
        )
        .unwrap();
        assert_eq!(built.steps.len(), 3);
        assert!(built.refused.is_none());

        let refuse = |step: &Step| {
            ensure!(step.issue != 2, "secret gate refused");
            Ok(())
        };
        let (_, prefix_receipt) = artifact::check(content.as_bytes(), &admission, refuse).unwrap();
        let prefix = build_verified(
            &repo,
            content.as_bytes(),
            &prefix_receipt,
            &admission,
            refuse,
            temp,
        )
        .unwrap();
        assert_eq!(prefix.steps, built.steps[..1]);
        assert_eq!(prefix.refused.unwrap().position, 2);

        run(&repo, &["checkout", "-q", "--detach", &fixture.base]);
        let (fix, _) = commit(&repo, &fixture.base, 1, "a.txt", "fixed\n");
        let fixed = proposal(vec![&fix, &fixture.steps[1], &fixture.steps[2]]);
        assert!(
            build_verified(
                &repo,
                fixed.as_bytes(),
                &receipt,
                &admission,
                |_| Ok(()),
                temp
            )
            .is_err()
        );
        let (_, fixed_receipt) = artifact::check(fixed.as_bytes(), &admission, |_| Ok(())).unwrap();
        let rebuilt = build_verified(
            &repo,
            fixed.as_bytes(),
            &fixed_receipt,
            &admission,
            |_| Ok(()),
            temp,
        )
        .unwrap();
        let restacked = restack(&repo, &fixture.base, &fixture.steps, 1, &fix, temp).unwrap();
        assert_eq!(rebuilt.steps, restacked.steps);
        assert_eq!(rebuilt.steps.len(), 3);
        for (old, new) in built.steps.iter().zip(&rebuilt.steps) {
            assert_ne!(old.head, new.head);
        }
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

    const BRANCHES: [&str; 3] = ["stack/one", "stack/two", "stack/three"];

    /// A bare remote under the fixture's temp directory, and its path.
    fn remote(fixture: &Fixture) -> String {
        let remote = fixture.temp.path().join("remote.git");
        run(fixture.temp.path(), &["init", "-q", "--bare", "remote.git"]);
        remote.to_str().unwrap().to_owned()
    }

    /// REMOTE's head of each of BRANCHES, if it has one.
    fn published(repo: &Path, remote: &str) -> Vec<Option<String>> {
        BRANCHES
            .iter()
            .map(|branch| {
                let listed = run(
                    repo,
                    &[
                        "ls-remote",
                        "--refs",
                        remote,
                        &format!("refs/heads/{branch}"),
                    ],
                );
                listed
                    .split('\t')
                    .next()
                    .filter(|head| !head.is_empty())
                    .map(str::to_owned)
            })
            .collect()
    }

    fn heads(stacked: &Stacked) -> Vec<Option<String>> {
        stacked
            .steps
            .iter()
            .map(|step| Some(step.head.clone()))
            .collect()
    }

    fn leases<'a>(heads: &'a [Option<String>]) -> Vec<Lease<'a>> {
        BRANCHES
            .iter()
            .enumerate()
            .map(|(index, branch)| Lease {
                branch,
                head: heads.get(index).and_then(Option::as_deref),
            })
            .collect()
    }

    #[test]
    fn a_stack_is_pushed_and_restacked_under_leases() {
        let fixture = fixture();
        let (repo, temp) = (fixture.repo(), fixture.temp.path());
        let remote = remote(&fixture);
        let stacked = build(&repo, &fixture.base, &fixture.steps, temp).unwrap();
        assert!(push(&repo, &remote, &stacked, &leases(&[])).unwrap());
        let first = heads(&stacked);
        assert_eq!(published(&repo, &remote), first);
        // A retry after a lost response finds its own push and pushes nothing.
        assert!(!push(&repo, &remote, &stacked, &leases(&[])).unwrap());

        run(&repo, &["checkout", "-q", "--detach", &fixture.base]);
        let (fix, _) = commit(&repo, &fixture.base, 1, "a.txt", "a1 fixed\n");
        let restacked = restack(&repo, &fixture.base, &fixture.steps, 1, &fix, temp).unwrap();
        // Leases that do not name the published heads move nothing.
        let error = push(&repo, &remote, &restacked, &leases(&[])).unwrap_err();
        assert!(error.to_string().contains("moved"), "{error:#}");
        assert_eq!(published(&repo, &remote), first);
        assert!(push(&repo, &remote, &restacked, &leases(&first)).unwrap());
        let second = heads(&restacked);
        assert_eq!(published(&repo, &remote), second);

        // A concurrent write to step three since the run read the stack
        // keeps steps one and two too: the push is atomic.
        run(
            &repo,
            &[
                "push",
                "-qf",
                &remote,
                &format!("{}:refs/heads/{}", fixture.base, BRANCHES[2]),
            ],
        );
        let error = push(&repo, &remote, &stacked, &leases(&second)).unwrap_err();
        assert!(error.to_string().contains("moved"), "{error:#}");
        let mut moved = second.clone();
        moved[2] = Some(fixture.base.clone());
        assert_eq!(published(&repo, &remote), moved);
    }

    #[test]
    fn a_refused_stack_pushes_only_what_leaves_no_step_behind() {
        let fixture = fixture();
        let (repo, temp) = (fixture.repo(), fixture.temp.path());
        let remote = remote(&fixture);
        let stacked = build(&repo, &fixture.base, &fixture.steps, temp).unwrap();
        run(&repo, &["checkout", "-q", "--detach", &fixture.base]);
        let (fix, _) = commit(&repo, &fixture.base, 1, "b.txt", "fixed\n");
        let restacked = restack(&repo, &fixture.base, &fixture.steps, 1, &fix, temp).unwrap();
        assert_eq!(restacked.refused.as_ref().unwrap().position, 2);

        // Published steps two and three would stay on the old step one.
        let first = heads(&stacked);
        assert!(push(&repo, &remote, &stacked, &leases(&[])).unwrap());
        let error = push(&repo, &remote, &restacked, &leases(&first)).unwrap_err();
        assert!(error.to_string().contains("published"), "{error:#}");
        assert_eq!(published(&repo, &remote), first);
        // So would a shorter, unrefused prefix of the plan.
        let prefix = build(&repo, &fixture.base, std::slice::from_ref(&fix), temp).unwrap();
        assert!(prefix.refused.is_none());
        let error = push(&repo, &remote, &prefix, &leases(&first)).unwrap_err();
        assert!(error.to_string().contains("published"), "{error:#}");
        assert_eq!(published(&repo, &remote), first);

        // A new stack refused at step two publishes step one alone, but
        // not over a step three that appeared since the run read the stack.
        let fresh = fixture.temp.path().join("fresh.git");
        run(temp, &["init", "-q", "--bare", "fresh.git"]);
        let fresh = fresh.to_str().unwrap();
        let three = format!("{}:refs/heads/{}", fixture.base, BRANCHES[2]);
        run(&repo, &["push", "-q", fresh, &three]);
        let error = push(&repo, fresh, &restacked, &leases(&[])).unwrap_err();
        assert!(error.to_string().contains("moved"), "{error:#}");
        assert_eq!(
            published(&repo, fresh),
            [None, None, Some(fixture.base.clone())]
        );
        run(
            &repo,
            &["push", "-q", fresh, &format!(":refs/heads/{}", BRANCHES[2])],
        );
        assert!(push(&repo, fresh, &restacked, &leases(&[])).unwrap());
        let one = vec![Some(restacked.steps[0].head.clone()), None, None];
        assert_eq!(published(&repo, fresh), one);
        assert!(!push(&repo, fresh, &restacked, &leases(&[])).unwrap());
    }

    #[test]
    fn what_is_not_a_lease_is_refused() {
        let fixture = fixture();
        let (repo, temp) = (fixture.repo(), fixture.temp.path());
        let remote = remote(&fixture);
        let stacked = build(&repo, &fixture.base, &fixture.steps, temp).unwrap();
        let lease = |branch, head| Lease { branch, head };
        for leases in [
            vec![],
            leases(&[])[..2].to_vec(),
            vec![lease("one", None), lease("one", None), lease("two", None)],
            vec![
                lease("-one", None),
                lease("two", None),
                lease("three", None),
            ],
            vec![
                lease("a/../b", None),
                lease("two", None),
                lease("three", None),
            ],
            vec![
                lease("one", Some("main")),
                lease("two", None),
                lease("three", None),
            ],
        ] {
            assert!(
                push(&repo, &remote, &stacked, &leases).is_err(),
                "{leases:?}"
            );
        }
        assert!(push(&repo, "--upload-pack=x", &stacked, &leases(&[])).is_err());
        assert_eq!(published(&repo, &remote), [None, None, None]);
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
