//! Rebuild and push a replacement series that `check` accepted, for
//! apply.yml: the whole branch of a pull request again, commit by commit,
//! rather than one patch on top that gh-aw's push handler applies.
//!
//! This runs from policy's binary, never from a producer checkout, and
//! builds or pushes nothing check did not bind: the series' base, its
//! commit count and each commit's paths.

use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use serde_json::Value;

use crate::exit::Exit;
use crate::files;
use crate::workflow_commands::escaped;

/// The hand-back's bound on a series, with room for JSON's escaping.
const MAX_SERIES_BYTES: u64 = 4 << 20;

/// check's own bound on the collector's result, which the report repeats.
const MAX_REPORT_BYTES: u64 = 4 << 20;

const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// A fixed committer makes the rebuilt head the same on every attempt,
/// a re-run after a successful push included.
const COMMITTER: [&str; 4] = [
    "-c",
    "user.name=github-actions[bot]",
    "-c",
    "user.email=41898282+github-actions[bot]@users.noreply.github.com",
];

static COMMIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{40}$").expect("a valid pattern"));

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Rebuild the checked series on its base and print its head and tree as step outputs
    Trial(TrialArgs),
    /// Push a rebuilt head over the branch, only while the branch is still the policy's head
    Push(PushArgs),
}

#[derive(Debug, clap::Args)]
pub struct TrialArgs {
    /// check's report.json
    #[arg(long)]
    pub report: PathBuf,
    /// The hand-back's replacement.json
    #[arg(long)]
    pub series: PathBuf,
    /// The handlers' config.json
    #[arg(long)]
    pub config: PathBuf,
    /// The base branch's head as apply resolved it, if it did
    #[arg(long, default_value = "")]
    pub current_base: String,
    /// Where the base commit is fetched from
    #[arg(long)]
    pub remote: String,
    /// A directory for the trial's worktree
    #[arg(long)]
    pub temp: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct PushArgs {
    #[arg(long)]
    pub remote: String,
    #[arg(long)]
    pub branch: String,
    /// The branch's head the policy pinned
    #[arg(long)]
    pub original_head: String,
    /// The head `trial` rebuilt
    #[arg(long)]
    pub replacement_head: String,
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        let repo = Path::new(".");
        match self {
            Self::Trial(args) => {
                let built = trial(args, repo)?;
                println!("head={}\ntree={}", built.head, built.tree);
            }
            Self::Push(args) => push(
                repo,
                &args.remote,
                &args.branch,
                &args.original_head,
                &args.replacement_head,
            )?,
        }
        Ok(Exit::Success)
    }
}

/// What a series rebuilt to.
#[derive(Debug, PartialEq, Eq)]
pub struct Built {
    pub head: String,
    pub tree: String,
}

fn read_json(path: &Path, max: u64) -> Result<Value> {
    let bytes =
        files::read_regular(path, max).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

fn trial(args: &TrialArgs, repo: &Path) -> Result<Built> {
    let report = &read_json(&args.report, MAX_REPORT_BYTES)?["patch"];
    let series = read_json(&args.series, MAX_SERIES_BYTES)?;
    let config = &read_json(&args.config, MAX_CONFIG_BYTES)?["push_to_pull_request_branch"];
    let base = report["base_commit"].as_str().unwrap_or("");
    let pinned = config["replacement_base"].as_str().unwrap_or("");
    let max = config["replacement_max_commits"].as_u64().unwrap_or(0);
    let (Some(commits), Some(commit_files)) = (
        series["commits"].as_array(),
        report["commit_files"].as_array(),
    ) else {
        bail!("Unchecked replacement series");
    };
    // Fetch only the policy's snapshot or the base trusted apply resolved,
    // and only for a series check bound commit by commit.
    ensure!(
        COMMIT_RE.is_match(base)
            && !pinned.is_empty()
            && (base == pinned || base == args.current_base)
            && series["base_commit"].as_str() == Some(base)
            && max > 0
            && commits.len() == commit_files.len()
            && commits.len() as u64 <= max,
        "Unchecked replacement series"
    );
    let mails = commits
        .iter()
        .map(|mail| mail.as_str().context("a replacement commit is not text"))
        .collect::<Result<Vec<_>>>()?;
    let paths = commit_files
        .iter()
        .map(|files| {
            files
                .as_array()
                .and_then(|files| files.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
                .context("a replacement commit's checked paths are not a list of text")
        })
        .collect::<Result<Vec<_>>>()?;
    git(repo, &["fetch", "--no-tags", &args.remote, base])?;
    materialize(base, &mails, &paths, &args.temp, repo)
}

/// Applies each mail of a series on `base` in a worktree of its own and
/// holds what each commit changed to the paths check read for it.
fn materialize(
    base: &str,
    mails: &[&str],
    checked: &[Vec<&str>],
    temp: &Path,
    repo: &Path,
) -> Result<Built> {
    let dir = temp.join("replacement-trial");
    let dir_arg = dir.to_str().context("the trial directory is not UTF-8")?;
    git(
        repo,
        &["worktree", "add", "--quiet", "--detach", dir_arg, base],
    )?;
    let built = apply_series(mails, checked, temp, &dir);
    let removed = git(repo, &["worktree", "remove", "--force", dir_arg]);
    let built = built?;
    removed?;
    Ok(built)
}

fn apply_series(mails: &[&str], checked: &[Vec<&str>], temp: &Path, dir: &Path) -> Result<Built> {
    let file = temp.join("replacement-mail.patch");
    let file_arg = file.to_str().context("the mail's path is not UTF-8")?;
    for (index, (mail, checked)) in mails.iter().zip(checked).enumerate() {
        let before = git(dir, &["rev-parse", "HEAD"])?;
        std::fs::write(&file, mail).with_context(|| format!("writing {}", file.display()))?;
        let mut am = COMMITTER.to_vec();
        am.extend([
            "am",
            "--keep-cr",
            "--committer-date-is-author-date",
            file_arg,
        ]);
        git(dir, &am)?;
        if git(dir, &["show", "-s", "--format=%P", "HEAD"])? != before {
            bail!("Nonlinear replacement");
        }
        let changed = git(
            dir,
            &[
                "-c",
                "core.quotePath=false",
                "diff",
                "--name-only",
                "--no-renames",
                &before,
                "HEAD",
            ],
        )?;
        let mut changed: Vec<&str> = changed.split('\n').collect();
        let mut checked = checked.clone();
        changed.sort_unstable();
        checked.sort_unstable();
        ensure!(
            changed == checked,
            "Replacement commit {} changed unchecked paths",
            index + 1
        );
    }
    Ok(Built {
        head: git(dir, &["rev-parse", "HEAD"])?,
        tree: git(dir, &["rev-parse", "HEAD^{tree}"])?,
    })
}

/// Pushes `replacement` over `branch` with a lease on the pinned head. A
/// branch already at `replacement` is this series pushed by an earlier
/// attempt; any other head, the same tree included, is a concurrent write.
fn push(repo: &Path, remote: &str, branch: &str, original: &str, replacement: &str) -> Result<()> {
    ensure!(
        COMMIT_RE.is_match(original) && COMMIT_RE.is_match(replacement),
        "Invalid replacement heads"
    );
    let reference = format!("refs/heads/{branch}");
    git(repo, &["check-ref-format", &reference])?;
    let current = |repo: &Path| -> Result<String> {
        let listed = git(repo, &["ls-remote", "--refs", remote, &reference])?;
        Ok(listed.split('\t').next().unwrap_or("").to_owned())
    };
    let head = current(repo)?;
    if head == replacement {
        return Ok(());
    }
    ensure!(
        head == original,
        "Replacement branch moved since the run started"
    );
    git(
        repo,
        &[
            "push",
            &format!("--force-with-lease={reference}:{original}"),
            remote,
            &format!("{replacement}:{reference}"),
        ],
    )?;
    ensure!(
        current(repo)? == replacement,
        "Replacement head was not pushed"
    );
    Ok(())
}

/// Runs git in REPO without hooks, signing or the machine's and user's
/// configuration; the repository's own (the checkout's credentials) stays.
fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Process::new("git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .context("running git")?;
    // git's messages hold the agent's text (`Applying: subject`), and they
    // end up in the step's log.
    ensure!(
        output.status.success(),
        "git {}: {}",
        escaped(&args.join(" ")),
        escaped(&String::from_utf8_lossy(&output.stderr))
    );
    Ok(String::from_utf8(output.stdout)
        .context("git's output is not UTF-8")?
        .trim()
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(dir: &Path, args: &[&str]) -> String {
        let output = Process::new("git")
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

    fn commit(repo: &Path, file: &str, message: &str) -> String {
        std::fs::write(repo.join(file), format!("{file}\n")).unwrap();
        run(repo, &["add", file]);
        run(repo, &["commit", "-qm", message]);
        run(repo, &["rev-parse", "HEAD"])
    }

    fn mail(repo: &Path) -> String {
        let args = [
            "format-patch",
            "--stdout",
            "--no-signature",
            "--no-renames",
            "-1",
            "HEAD",
        ];
        run(repo, &args) + "\n"
    }

    fn write(path: &Path, value: &Value) -> PathBuf {
        std::fs::write(path, value.to_string()).unwrap();
        path.to_owned()
    }

    #[test]
    fn replacement_rebases_checked_series_and_refuses_moved_heads() {
        let temp = tempfile::tempdir().unwrap();
        let (repo, remote) = (temp.path().join("repo"), temp.path().join("remote"));
        std::fs::create_dir(&repo).unwrap();
        run(&repo, &["init", "-q", "--initial-branch=main"]);
        run(&repo, &["config", "user.name", "Test"]);
        run(&repo, &["config", "user.email", "test@example.com"]);
        let base = commit(&repo, "base.txt", "base");
        run(&repo, &["checkout", "-qb", "agent-run-1"]);
        commit(&repo, "a.txt", "original");
        let original = commit(&repo, "b.txt", "fixup");
        run(temp.path(), &["init", "--bare", "-q", "remote"]);
        let remote = remote.to_str().unwrap();
        run(
            &repo,
            &["push", "-q", remote, "HEAD:refs/heads/agent-run-1"],
        );
        run(&repo, &["reset", "--soft", &base]);
        run(
            &repo,
            &["commit", "-qm", "parser: Keep the last line\n\nWhy."],
        );
        let squashed = mail(&repo);

        // The squashed change, rebased on a base that moved.
        run(&repo, &["checkout", "-q", "main"]);
        let moved = commit(&repo, "new-base.txt", "advance base");
        let both = vec![vec!["a.txt", "b.txt"]];
        let first = materialize(&moved, &[&squashed], &both, temp.path(), &repo).unwrap();
        let again = materialize(&moved, &[&squashed], &both, temp.path(), &repo).unwrap();
        assert_eq!(first, again, "a rebuild is the same commit");
        assert_eq!(
            run(&repo, &["show", "-s", "--format=%P", &first.head]),
            moved
        );
        let message = run(&repo, &["show", "-s", "--format=%B", &first.head]);
        assert!(message.starts_with("parser: Keep the last line"));
        let only_a = vec![vec!["a.txt"]];
        let error = materialize(&moved, &[&squashed], &only_a, temp.path(), &repo).unwrap_err();
        assert!(error.to_string().contains("unchecked paths"), "{error:#}");
        run(&repo, &["checkout", "-q", "--detach", &first.head]);
        commit(&repo, "c.txt", "second retained commit");
        let second = mail(&repo);
        let paths = vec![vec!["a.txt", "b.txt"], vec!["c.txt"]];
        let two = materialize(&moved, &[&squashed, &second], &paths, temp.path(), &repo).unwrap();
        let range = format!("{moved}..{}", two.head);
        assert_eq!(run(&repo, &["rev-list", "--count", &range]), "2");

        // The trial holds the series to the report and the configuration
        // before it fetches anything.
        run(
            &repo,
            &["push", "-q", remote, &format!("{moved}:refs/heads/main")],
        );
        let report = serde_json::json!({"patch": {"base_commit": moved, "commit_files": both}});
        let args = |pinned: &str, max: Value, current: &str| {
            let config = serde_json::json!({"push_to_pull_request_branch":
                {"replacement_base": pinned, "replacement_max_commits": max}});
            TrialArgs {
                report: write(&temp.path().join("report.json"), &report),
                series: write(
                    &temp.path().join("replacement.json"),
                    &serde_json::json!({"base_commit": moved, "commits": [squashed]}),
                ),
                config: write(&temp.path().join("config.json"), &config),
                current_base: current.to_owned(),
                remote: remote.to_owned(),
                temp: temp.path().to_owned(),
            }
        };
        assert_eq!(trial(&args(&base, 1.into(), &moved), &repo).unwrap(), first);
        // Only apply's own resolution of the base, or the policy's pin.
        assert_eq!(
            trial(&args(&moved, 1.into(), &original), &repo).unwrap(),
            first
        );
        for (pinned, max, current) in [
            (base.as_str(), 1.into(), ""),
            (base.as_str(), 1.into(), original.as_str()),
            (moved.as_str(), 0.into(), ""),
            (moved.as_str(), Value::Null, ""),
            ("", 1.into(), moved.as_str()),
        ] {
            let error = trial(&args(pinned, max, current), &repo).unwrap_err();
            assert_eq!(error.to_string(), "Unchecked replacement series");
        }
        // A report that does not bind this series: another base, another
        // commit count, or no paths at all.
        for (pinned, patch) in [
            (
                &base,
                serde_json::json!({"base_commit": base, "commit_files": both}),
            ),
            (
                &moved,
                serde_json::json!({"base_commit": moved, "commit_files": [["a.txt"], ["b.txt"]]}),
            ),
            (
                &moved,
                serde_json::json!({"base_commit": "HEAD", "commit_files": both}),
            ),
            (&moved, serde_json::json!({"base_commit": moved})),
        ] {
            let mut unbound = args(pinned, 2.into(), "");
            unbound.report = write(&unbound.report, &serde_json::json!({ "patch": patch }));
            let error = trial(&unbound, &repo).unwrap_err();
            assert_eq!(error.to_string(), "Unchecked replacement series");
        }

        let pushed = || run(Path::new(remote), &["rev-parse", "refs/heads/agent-run-1"]);
        push(&repo, remote, "agent-run-1", &original, &first.head).unwrap();
        push(&repo, remote, "agent-run-1", &original, &first.head).unwrap();
        assert_eq!(pushed(), first.head);
        // Another head, whatever its tree, is a concurrent write.
        run(
            &repo,
            &[
                "push",
                "-q",
                "--force",
                remote,
                &format!("{base}:refs/heads/agent-run-1"),
            ],
        );
        let error = push(&repo, remote, "agent-run-1", &original, &first.head).unwrap_err();
        assert!(error.to_string().contains("moved"), "{error:#}");
        assert_eq!(pushed(), base);
        assert!(push(&repo, remote, "agent-run-1", "head", &first.head).is_err());
    }
}
