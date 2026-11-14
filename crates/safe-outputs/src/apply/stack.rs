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
//! leases on the heads the caller pinned, and [`publish`] then opens each
//! step's pull request on its predecessor's branch through a [`Pulls`]
//! adapter; no CLI command or workflow calls either yet.
//!
//! A step that does not apply on its predecessor, or changes other paths,
//! stops the stack there: the steps below it are kept and none above it is
//! built, so a conflict never drops a step silently. A refusal's reason is
//! fixed text, never git's or the forge's, which hold the agent's.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::github::{self, Github};
use super::publish::{Run, stack_pull_text};
use super::replacement::{Applied, Built, apply_mail, git};
use super::roles::Role;
use super::{COMMIT_RE, Made, plain_branch};
use crate::check::stack::{CheckedStep, MAX_STEPS, Refusal};
use crate::contract::Policy;

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

/// Where and how a stack is published, from the caller's trusted
/// configuration, never the proposal.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    /// The admitted policy: its repository holds the stack's branches and
    /// pull requests, and the first step is opened on its base.
    pub policy: &'a Policy,
    /// The run's branch prefix, which every step's branch must have.
    pub prefix: &'a str,
    /// The create_pull_request handler's `title_prefix` and `draft`.
    pub title_prefix: &'a str,
    pub draft: bool,
}

impl Target<'_> {
    fn repo(&self) -> &str {
        &self.policy.repo
    }

    fn base(&self) -> &str {
        &self.policy.base
    }
}

/// Holds LEASES to TARGET: distinct plain branches, each the run's prefix
/// and more, none the target branch, and every pinned head a commit ID.
/// Every step's branch is the target repository's own, since a pull
/// request's base must be one of its repository's branches, so the policy
/// must accept those as for an ordinary pull request
/// (`own-branch-repos`): the repository's push workflows run on them.
fn bind(target: &Target<'_>, leases: &[Lease<'_>]) -> Result<()> {
    ensure!(
        (1..=MAX_STEPS as usize).contains(&leases.len()),
        "stack leases are outside the step bounds"
    );
    ensure!(
        target
            .policy
            .safe_outputs
            .accepts_own_branches(target.repo())?,
        "the policy does not accept branches of {} itself, which a stack needs",
        target.repo()
    );
    ensure!(plain_branch(target.base()), "invalid stack target branch");
    ensure!(
        target.prefix.ends_with('/') && plain_branch(target.prefix.trim_end_matches('/')),
        "the stack's run prefix must be a plain branch name ending with /"
    );
    let mut branches = BTreeSet::new();
    for lease in leases {
        ensure!(
            plain_branch(lease.branch) && branches.insert(lease.branch),
            "stack branches must be distinct plain branch names"
        );
        ensure!(
            lease.branch.len() > target.prefix.len()
                && lease.branch.starts_with(target.prefix)
                && lease.branch != target.base(),
            "stack branches must be under the run's prefix and not the target branch"
        );
        ensure!(
            lease.head.is_none_or(|head| COMMIT_RE.is_match(head)),
            "invalid pinned stack head"
        );
    }
    Ok(())
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
/// LEASES' branch N, held to TARGET, in one atomic push leased on every pinned head: the
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
pub fn push(
    repo: &Path,
    remote: &str,
    target: &Target<'_>,
    stacked: &Stacked,
    leases: &[Lease<'_>],
) -> Result<bool> {
    bind(target, leases)?;
    let built = stacked.steps.len();
    ensure!(built <= leases.len(), "stack leases do not cover the stack");
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

/// The pull request a step is opened as, from branch HEAD onto branch
/// BASE of the target repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pull<'a> {
    pub head: &'a str,
    pub base: &'a str,
    pub title: String,
    /// The step's body and its issue's closing line, as published.
    pub body: String,
    pub draft: bool,
}

/// The forge reads and writes [`publish`] needs, made with the caller's
/// existing credential roles.
pub trait Pulls {
    /// REPO's open pull request from PULL's head, if there is one: an
    /// earlier attempt's, whose answer may have been lost. One on another
    /// base than PULL's is an error, never retargeted.
    fn find(&self, repo: &str, pull: &Pull<'_>) -> Result<Option<Made>>;

    /// Opens PULL in REPO.
    fn open(&self, repo: &str, pull: &Pull<'_>) -> Result<Made>;
}

/// GitHub's, with the publication role's credential, which opens an
/// ordinary pull request too. A pull request's base must be a branch of
/// the repository it is opened in, so every step's branch is the target
/// repository's own: a fork cannot hold a stack.
impl Pulls for Github {
    fn find(&self, repo: &str, pull: &Pull<'_>) -> Result<Option<Made>> {
        ensure!(github::is_repo(repo), "invalid stack repository");
        let owner = repo.split('/').next().unwrap_or_default();
        let pulls = self
            .for_role(Role::Publication)?
            .pulls(repo, &format!("{owner}:{}", pull.head))?;
        let mut open = pulls.iter().filter(|found| {
            found["state"] == "open"
                && found["head"]["ref"] == pull.head
                && github::same(&found["head"]["repo"]["full_name"], repo)
        });
        let Some(found) = open.next() else {
            return Ok(None);
        };
        ensure!(
            open.next().is_none(),
            "more than one open pull request from the stack branch {}",
            pull.head
        );
        ensure!(
            found["base"]["ref"] == pull.base,
            "the open pull request from the stack branch {} is not on {}",
            pull.head,
            pull.base
        );
        Made::from_answer(found, "GET", &format!("/repos/{repo}/pulls")).map(Some)
    }

    fn open(&self, repo: &str, pull: &Pull<'_>) -> Result<Made> {
        ensure!(github::is_repo(repo), "invalid stack repository");
        let path = format!("/repos/{repo}/pulls");
        let body: Value = json!({
            "title": pull.title,
            "body": pull.body,
            "head": pull.head,
            "base": pull.base,
            "draft": pull.draft,
        });
        let answer = self.for_role(Role::Publication)?.request_retrying(
            "POST",
            &path,
            Some(&body),
            &format!("create stack pull request in {repo}"),
        )?;
        Made::from_answer(&answer, "POST", &path)
    }
}

/// One step's published pull request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// One-based.
    pub position: usize,
    pub issue: u64,
    pub branch: String,
    /// The step's commit, as pushed to `branch`.
    pub head: String,
    /// The branch the pull request is on: its predecessor's, or the
    /// target branch.
    pub base: String,
    pub pull: Made,
    /// Whether an earlier attempt had opened it already.
    pub found: bool,
}

/// What [`publish`] published, in step order.
#[derive(Debug)]
pub struct Published {
    /// Whether this call pushed, as [`push`] returns.
    pub pushed: bool,
    pub opened: Vec<Opened>,
    /// The first step without a pull request, if any: refused by check or
    /// git, or not opened. Only git's and this function's reasons are
    /// fixed text: check's may quote the step's patch.
    pub stopped: Option<Refusal>,
    /// Why the forge did not open the stopping step's pull request, where
    /// that stopped it; scrubbed of credentials, it may hold the agent's
    /// text.
    pub error: Option<anyhow::Error>,
}

/// Pushes STACKED, as [`push`] does, then opens each built step's pull
/// request in TARGET's repository with PULLS: step N's from LEASES' branch
/// N onto branch N-1, the first onto the target branch, with the title and
/// body of STEPS' step N and its issue's closing line, through RUN's gates
/// for an ordinary pull request ([`super::publish::stack_pull_text`]).
/// STEPS are the checked steps STACKED was built from, in the same order.
///
/// A pull request PULLS finds open already is an earlier attempt's and is
/// kept as it is. The first step not opened stops the stack there; the
/// pull requests below it stay published, and a later call, after the
/// caller has read the published stack again, resumes from it. A step's
/// text the gates refuse, or a failed push, writes nothing and is an error.
#[allow(clippy::too_many_arguments)]
pub fn publish(
    repo: &Path,
    remote: &str,
    target: &Target<'_>,
    run: &Run,
    steps: &[CheckedStep],
    stacked: &Stacked,
    leases: &[Lease<'_>],
    pulls: &dyn Pulls,
) -> Result<Published> {
    ensure!(
        stacked.steps.len() <= steps.len(),
        "the checked steps do not cover the built stack"
    );
    let texts = steps[..stacked.steps.len()]
        .iter()
        .map(|checked| {
            let step = &checked.step;
            stack_pull_text(
                &step.title,
                &step.body,
                step.issue,
                target.title_prefix,
                target.repo(),
                run,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let pushed = push(repo, remote, target, stacked, leases)?;
    let mut published = Published {
        pushed,
        opened: Vec::new(),
        stopped: stacked.refused.as_ref().map(|refused| Refusal {
            position: refused.position,
            reason: refused.reason.clone(),
        }),
        error: None,
    };
    for (index, ((built, checked), (title, body))) in
        stacked.steps.iter().zip(steps).zip(texts).enumerate()
    {
        let step = &checked.step;
        let base = match index {
            0 => target.base(),
            _ => leases[index - 1].branch,
        };
        let pull = Pull {
            head: leases[index].branch,
            base,
            title,
            body,
            draft: target.draft,
        };
        let made = pulls
            .find(target.repo(), &pull)
            .and_then(|found| match found {
                Some(made) => Ok((made, true)),
                None => pulls.open(target.repo(), &pull).map(|made| (made, false)),
            });
        match made {
            Ok((made, found)) => published.opened.push(Opened {
                position: index + 1,
                issue: step.issue,
                branch: pull.head.to_owned(),
                head: built.head.clone(),
                base: base.to_owned(),
                pull: made,
                found,
            }),
            Err(error) => {
                published.stopped = Some(Refusal {
                    position: index + 1,
                    reason: "stack step's pull request was not opened".to_owned(),
                });
                published.error = Some(error);
                break;
            }
        }
    }
    Ok(published)
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

    /// The fixture's policy in `owner/repo`, which accepts the repository's
    /// own branches.
    static POLICY: std::sync::LazyLock<Policy> = std::sync::LazyLock::new(|| {
        let mut policy = crate::check::fixtures::policy();
        policy.repo = "owner/repo".to_owned();
        policy.safe_outputs.own_branch_repos = vec![vec!["owner/repo".to_owned()]];
        policy
    });

    fn target() -> Target<'static> {
        Target {
            policy: &POLICY,
            prefix: "stack/",
            title_prefix: "",
            draft: true,
        }
    }

    /// A run of `owner/repo`'s, as apply.yml gives it.
    fn apply_run() -> Run {
        let domains = crate::link_domains().join(",");
        let vars: std::collections::BTreeMap<&str, &str> = [
            ("GITHUB_SERVER_URL", "https://github.com"),
            ("GITHUB_REPOSITORY", "owner/repo"),
            ("GITHUB_REPOSITORY_ID", "77"),
            ("GITHUB_RUN_ID", "4242"),
            ("GITHUB_RUN_ATTEMPT", "1"),
            ("GITHUB_JOB", "apply"),
            ("GITHUB_EVENT_NAME", "workflow_dispatch"),
            ("GITHUB_ACTOR", "owner"),
            ("GH_AW_JOB_CHECK_RUN_ID", "9001"),
            ("GH_AW_WORKFLOW_ID", "agentic-job"),
            ("GH_AW_WORKFLOW_NAME", "agentic-job"),
            ("GH_AW_SAFE_OUTPUTS_URLS", super::super::publish::URL_POLICY),
            ("GH_AW_ALLOWED_DOMAINS", domains.as_str()),
        ]
        .into_iter()
        .collect();
        Run::read(&|name| vars.get(name).map(|value| (*value).to_owned())).unwrap()
    }

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
        assert!(push(&repo, &remote, &target(), &stacked, &leases(&[])).unwrap());
        let first = heads(&stacked);
        assert_eq!(published(&repo, &remote), first);
        // A retry after a lost response finds its own push and pushes nothing.
        assert!(!push(&repo, &remote, &target(), &stacked, &leases(&[])).unwrap());

        run(&repo, &["checkout", "-q", "--detach", &fixture.base]);
        let (fix, _) = commit(&repo, &fixture.base, 1, "a.txt", "a1 fixed\n");
        let restacked = restack(&repo, &fixture.base, &fixture.steps, 1, &fix, temp).unwrap();
        // Leases that do not name the published heads move nothing.
        let error = push(&repo, &remote, &target(), &restacked, &leases(&[])).unwrap_err();
        assert!(error.to_string().contains("moved"), "{error:#}");
        assert_eq!(published(&repo, &remote), first);
        assert!(push(&repo, &remote, &target(), &restacked, &leases(&first)).unwrap());
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
        let error = push(&repo, &remote, &target(), &stacked, &leases(&second)).unwrap_err();
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
        assert!(push(&repo, &remote, &target(), &stacked, &leases(&[])).unwrap());
        let error = push(&repo, &remote, &target(), &restacked, &leases(&first)).unwrap_err();
        assert!(error.to_string().contains("published"), "{error:#}");
        assert_eq!(published(&repo, &remote), first);
        // So would a shorter, unrefused prefix of the plan.
        let prefix = build(&repo, &fixture.base, std::slice::from_ref(&fix), temp).unwrap();
        assert!(prefix.refused.is_none());
        let error = push(&repo, &remote, &target(), &prefix, &leases(&first)).unwrap_err();
        assert!(error.to_string().contains("published"), "{error:#}");
        assert_eq!(published(&repo, &remote), first);

        // A new stack refused at step two publishes step one alone, but
        // not over a step three that appeared since the run read the stack.
        let fresh = fixture.temp.path().join("fresh.git");
        run(temp, &["init", "-q", "--bare", "fresh.git"]);
        let fresh = fresh.to_str().unwrap();
        let three = format!("{}:refs/heads/{}", fixture.base, BRANCHES[2]);
        run(&repo, &["push", "-q", fresh, &three]);
        let error = push(&repo, fresh, &target(), &restacked, &leases(&[])).unwrap_err();
        assert!(error.to_string().contains("moved"), "{error:#}");
        assert_eq!(
            published(&repo, fresh),
            [None, None, Some(fixture.base.clone())]
        );
        run(
            &repo,
            &["push", "-q", fresh, &format!(":refs/heads/{}", BRANCHES[2])],
        );
        assert!(push(&repo, fresh, &target(), &restacked, &leases(&[])).unwrap());
        let one = vec![Some(restacked.steps[0].head.clone()), None, None];
        assert_eq!(published(&repo, fresh), one);
        assert!(!push(&repo, fresh, &target(), &restacked, &leases(&[])).unwrap());
    }

    #[test]
    fn what_is_not_a_lease_is_refused() {
        let fixture = fixture();
        let (repo, temp) = (fixture.repo(), fixture.temp.path());
        let remote = remote(&fixture);
        let stacked = build(&repo, &fixture.base, &fixture.steps, temp).unwrap();
        let lease = |branch, head| Lease { branch, head };
        // Each first lease, with the other two of the fixture.
        let with = |first| vec![first, lease(BRANCHES[1], None), lease(BRANCHES[2], None)];
        for leases in [
            vec![],
            leases(&[])[..2].to_vec(),
            with(lease(BRANCHES[1], None)),
            with(lease("-one", None)),
            with(lease("stack/a/../b", None)),
            with(lease(BRANCHES[0], Some("main"))),
            // Outside the run's prefix, the prefix alone, the target branch.
            with(lease("other/one", None)),
            with(lease("stack/", None)),
            with(lease("main", None)),
        ] {
            assert!(
                push(&repo, &remote, &target(), &stacked, &leases).is_err(),
                "{leases:?}"
            );
        }
        let with_policy = |change: fn(&mut Policy)| {
            let mut policy = POLICY.clone();
            change(&mut policy);
            policy
        };
        let policies = [
            with_policy(|policy| policy.base = "-main".to_owned()),
            with_policy(|policy| policy.base = BRANCHES[0].to_owned()),
            // A policy that does not accept the repository's own branches.
            with_policy(|policy| policy.safe_outputs.own_branch_repos.clear()),
            with_policy(|policy| policy.repo = "other/repo".to_owned()),
        ];
        let targets = [
            Target {
                prefix: "",
                ..target()
            },
            Target {
                prefix: "stack",
                ..target()
            },
        ]
        .into_iter()
        .chain(policies.iter().map(|policy| Target { policy, ..target() }));
        for target in targets {
            assert!(
                push(&repo, &remote, &target, &stacked, &leases(&[])).is_err(),
                "{target:?}"
            );
        }
        assert!(push(&repo, "--upload-pack=x", &target(), &stacked, &leases(&[])).is_err());
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

    /// A forge's open pull requests, which refuses to open one from the
    /// branch FAILING.
    #[derive(Default)]
    struct Forge {
        open: std::cell::RefCell<Vec<(String, String, String, bool)>>,
        failing: std::cell::Cell<Option<&'static str>>,
    }

    impl Forge {
        fn made(number: usize) -> Made {
            Made {
                url: format!("https://forge.invalid/owner/repo/pull/{number}"),
                number: Some(number as u64),
                ..Made::default()
            }
        }
    }

    impl Pulls for Forge {
        fn find(&self, repo: &str, pull: &Pull<'_>) -> Result<Option<Made>> {
            assert_eq!(repo, POLICY.repo);
            let open = self.open.borrow();
            let Some(index) = open.iter().position(|(head, ..)| head == pull.head) else {
                return Ok(None);
            };
            ensure!(open[index].1 == pull.base, "on another base");
            Ok(Some(Self::made(index + 1)))
        }

        fn open(&self, repo: &str, pull: &Pull<'_>) -> Result<Made> {
            assert_eq!(repo, POLICY.repo);
            ensure!(self.failing.get() != Some(pull.head), "forge refused");
            let mut open = self.open.borrow_mut();
            open.push((
                pull.head.to_owned(),
                pull.base.to_owned(),
                format!("{}\n{}", pull.title, pull.body),
                pull.draft,
            ));
            Ok(Self::made(open.len()))
        }
    }

    /// The bases, numbers and whether found of PUBLISHED's pull requests.
    fn opened(published: &Published) -> Vec<(&str, u64, bool)> {
        published
            .opened
            .iter()
            .map(|opened| {
                (
                    opened.base.as_str(),
                    opened.pull.number.unwrap(),
                    opened.found,
                )
            })
            .collect()
    }

    #[test]
    fn three_steps_are_published_each_on_its_predecessor() {
        let mut fixture = fixture();
        let (repo, temp) = (fixture.repo(), fixture.temp.path());
        let remote = remote(&fixture);
        let stacked = build(&repo, &fixture.base, &fixture.steps, temp).unwrap();
        // The step's text gets an ordinary pull request's gates.
        fixture.steps[0].step.body = "Why, @someone. https://unlisted.invalid/x".to_owned();
        let forge = Forge::default();
        let publish = |stacked: &Stacked, steps: &[CheckedStep], heads: &[Option<String>]| {
            publish(
                &repo,
                &remote,
                &target(),
                &apply_run(),
                steps,
                stacked,
                &leases(heads),
                &forge,
            )
            .unwrap()
        };
        let first = publish(&stacked, &fixture.steps, &[]);
        assert!(first.pushed);
        assert!(first.stopped.is_none() && first.error.is_none());
        let bases = ["main", BRANCHES[0], BRANCHES[1]];
        assert_eq!(
            opened(&first),
            [
                (bases[0], 1, false),
                (bases[1], 2, false),
                (bases[2], 3, false)
            ]
        );
        for (index, (opened, (head, base, text, draft))) in first
            .opened
            .iter()
            .zip(forge.open.borrow().iter())
            .enumerate()
        {
            let issue = index + 1;
            assert_eq!(
                (opened.position, opened.issue, opened.branch.as_str()),
                (issue, issue as u64, BRANCHES[index])
            );
            assert_eq!(opened.head, stacked.steps[index].head);
            assert_eq!(
                (head.as_str(), base.as_str()),
                (BRANCHES[index], bases[index])
            );
            let why = match issue {
                1 => "Why, `@someone`. (unlisted.invalid/redacted)",
                _ => "Why.",
            };
            let start = format!("Step {issue}\n{why}\n\nCloses #{issue}\n\n");
            assert!(text.starts_with(&start), "{text}");
            assert!(
                text.contains("<!-- gh-aw-workflow-id: agentic-job -->"),
                "{text}"
            );
            assert!(draft);
        }
        assert_eq!(published(&repo, &remote), heads(&stacked));

        // A retry after a lost answer finds what it made and opens nothing.
        let again = publish(&stacked, &fixture.steps, &[]);
        assert!(!again.pushed);
        assert_eq!(
            opened(&again),
            [
                (bases[0], 1, true),
                (bases[1], 2, true),
                (bases[2], 3, true)
            ]
        );

        // A fix round on step one restacks two and three under the same
        // pull requests.
        run(&repo, &["checkout", "-q", "--detach", &fixture.base]);
        let (fix, _) = commit(&repo, &fixture.base, 1, "a.txt", "a1 fixed\n");
        let restacked = restack(&repo, &fixture.base, &fixture.steps, 1, &fix, temp).unwrap();
        let steps: Vec<_> = std::iter::once(fix)
            .chain(fixture.steps.into_iter().skip(1))
            .collect();
        let fixed = publish(&restacked, &steps, &heads(&stacked));
        assert!(fixed.pushed);
        assert_eq!(opened(&fixed), opened(&again));
        assert_eq!(published(&repo, &remote), heads(&restacked));
        assert_eq!(forge.open.borrow().len(), 3);
    }

    #[test]
    fn a_stopped_step_keeps_the_pull_requests_below() {
        let fixture = fixture();
        let (repo, temp) = (fixture.repo(), fixture.temp.path());
        let remote = remote(&fixture);
        let stacked = build(&repo, &fixture.base, &fixture.steps, temp).unwrap();
        let forge = Forge::default();
        forge.failing.set(Some(BRANCHES[1]));
        let failed = publish(
            &repo,
            &remote,
            &target(),
            &apply_run(),
            &fixture.steps,
            &stacked,
            &leases(&[]),
            &forge,
        )
        .unwrap();
        assert_eq!(opened(&failed), [("main", 1, false)]);
        let stopped = failed.stopped.unwrap();
        assert_eq!(stopped.position, 2);
        assert_eq!(stopped.reason, "stack step's pull request was not opened");
        assert!(format!("{:#}", failed.error.unwrap()).contains("forge refused"));

        // The next attempt, which read the pushed stack, resumes at step two.
        forge.failing.set(None);
        let resumed = publish(
            &repo,
            &remote,
            &target(),
            &apply_run(),
            &fixture.steps,
            &stacked,
            &leases(&heads(&stacked)),
            &forge,
        )
        .unwrap();
        assert!(!resumed.pushed);
        assert_eq!(
            opened(&resumed),
            [
                ("main", 1, true),
                (BRANCHES[0], 2, false),
                (BRANCHES[1], 3, false)
            ]
        );

        // A refused middle step publishes step one alone, and reports the
        // refusal; a failed push opens nothing.
        let fresh = temp.join("fresh.git");
        run(temp, &["init", "-q", "--bare", "fresh.git"]);
        let fresh = fresh.to_str().unwrap();
        run(&repo, &["checkout", "-q", "--detach", &fixture.base]);
        let (fix, _) = commit(&repo, &fixture.base, 1, "b.txt", "fixed\n");
        let refused = restack(&repo, &fixture.base, &fixture.steps, 1, &fix, temp).unwrap();
        let forge = Forge::default();
        let steps = [fix];
        assert!(
            publish(
                &repo,
                fresh,
                &target(),
                &apply_run(),
                &steps,
                &refused,
                &leases(&heads(&stacked)),
                &forge
            )
            .is_err()
        );
        assert!(forge.open.borrow().is_empty());
        let published = publish(
            &repo,
            fresh,
            &target(),
            &apply_run(),
            &steps,
            &refused,
            &leases(&[]),
            &forge,
        )
        .unwrap();
        assert_eq!(opened(&published), [("main", 1, false)]);
        let stopped = published.stopped.unwrap();
        assert_eq!(stopped.position, 2);
        assert_eq!(
            stopped.reason,
            "stack step does not apply on its predecessor"
        );
        assert!(published.error.is_none());
    }

    #[test]
    fn github_finds_and_opens_step_pull_requests_with_the_publication_role() {
        use crate::apply::testing::{bound, forge};
        use std::collections::BTreeMap;
        let pulls = "GET /repos/owner/repo/pulls?head=owner%3Astack%2Ftwo&state=all&per_page=100";
        let create = "POST /repos/owner/repo/pulls";
        let pull = Pull {
            head: BRANCHES[1],
            base: BRANCHES[0],
            title: "Step 2".to_owned(),
            body: "Why.\n\nCloses #2".to_owned(),
            draft: true,
        };
        let listed = |base: &str, state: &str, repo: &str| {
            json!({
                "html_url": "https://github.invalid/owner/repo/pull/8",
                "number": 8,
                "state": state,
                "head": {"ref": BRANCHES[1], "repo": {"full_name": repo}},
                "base": {"ref": base},
            })
        };
        let made = Made {
            url: "https://github.invalid/owner/repo/pull/8".to_owned(),
            number: Some(8),
            ..Made::default()
        };
        // None open from the target repository's own branch: one is opened.
        let (github, requests) = forge(BTreeMap::from([
            (
                pulls.to_owned(),
                (
                    200,
                    json!([
                        listed(BRANCHES[0], "closed", "owner/repo"),
                        listed(BRANCHES[0], "open", "fork/repo")
                    ]),
                ),
            ),
            (
                create.to_owned(),
                (201, listed(BRANCHES[0], "open", "owner/repo")),
            ),
        ]));
        let github = bound(github);
        assert_eq!(github.find("owner/repo", &pull).unwrap(), None);
        assert_eq!(github.open("owner/repo", &pull).unwrap(), made);
        let sent: Vec<_> = requests.try_iter().collect();
        assert_eq!(sent.len(), 2);
        for request in &sent {
            assert!(
                request.authorization.contains("PUBLICATION_TOKEN"),
                "{request:?}"
            );
        }
        assert_eq!(
            sent[1].body,
            json!({"title": "Step 2", "body": "Why.\n\nCloses #2",
                   "head": BRANCHES[1], "base": BRANCHES[0], "draft": true})
        );

        // One open on its base is found; one on another base is an error.
        for (base, found) in [(BRANCHES[0], true), ("main", false)] {
            let (github, _) = forge(BTreeMap::from([(
                pulls.to_owned(),
                (200, json!([listed(base, "open", "owner/repo")])),
            )]));
            let result = bound(github).find("owner/repo", &pull);
            match found {
                true => assert_eq!(result.unwrap(), Some(made.clone())),
                false => assert!(result.is_err()),
            }
        }
        let (github, requests) = forge(BTreeMap::new());
        let github = bound(github);
        assert!(github.find("../repo", &pull).is_err());
        assert!(github.open("../repo", &pull).is_err());
        assert_eq!(requests.try_iter().count(), 0);
    }
}
