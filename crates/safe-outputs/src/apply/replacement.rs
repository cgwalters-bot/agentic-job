//! Rebuild and push a replacement series that `check` accepted, for
//! apply: the whole branch of a pull request again, commit by commit,
//! rather than one patch on top that gh-aw's push handler applies.
//!
//! The caller runs this from its own binary, never from a producer
//! checkout, and it builds or pushes nothing check did not bind: the
//! series' base, its commit count and each commit's paths.
//!
//! git's messages in an error hold the agent's text (`Applying:
//! subject`): a caller that logs one escapes it first.

use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

use super::COMMIT_RE;

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

/// What [`trial`] is asked.
#[derive(Debug)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct TrialArgs {
    /// check's report.json
    #[cfg_attr(feature = "clap", arg(long))]
    pub report: PathBuf,
    /// The hand-back's replacement.json
    #[cfg_attr(feature = "clap", arg(long))]
    pub series: PathBuf,
    /// The handlers' config.json
    #[cfg_attr(feature = "clap", arg(long))]
    pub config: PathBuf,
    /// The base branch's head as apply resolved it, if it did
    #[cfg_attr(feature = "clap", arg(long, default_value = ""))]
    pub current_base: String,
    /// Where the base commit is fetched from
    #[cfg_attr(feature = "clap", arg(long))]
    pub remote: String,
    /// A directory for the trial's worktree
    #[cfg_attr(feature = "clap", arg(long))]
    pub temp: PathBuf,
}

/// What [`push`] is asked.
#[derive(Debug)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct PushArgs {
    #[cfg_attr(feature = "clap", arg(long))]
    pub remote: String,
    #[cfg_attr(feature = "clap", arg(long))]
    pub branch: String,
    /// The branch's head the policy pinned
    #[cfg_attr(feature = "clap", arg(long))]
    pub original_head: String,
    /// The head `trial` rebuilt
    #[cfg_attr(feature = "clap", arg(long))]
    pub replacement_head: String,
}

/// What a series rebuilt to.
#[derive(Debug, PartialEq, Eq)]
pub struct Built {
    pub head: String,
    pub tree: String,
}

fn read_json(read: &dyn Fn(&Path, u64) -> Result<Vec<u8>>, path: &Path, max: u64) -> Result<Value> {
    let bytes = read(path, max).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// Rebuilds the series ARGS name in REPO, reading its files with READ,
/// which gives the content of the regular file at a path, if it is at
/// most the given bytes, never through a link, as
/// [`super::Upload::read`] does.
pub fn trial(
    args: &TrialArgs,
    repo: &Path,
    read: &dyn Fn(&Path, u64) -> Result<Vec<u8>>,
) -> Result<Built> {
    let report = &read_json(read, &args.report, MAX_REPORT_BYTES)?["patch"];
    let series = read_json(read, &args.series, MAX_SERIES_BYTES)?;
    let config = &read_json(read, &args.config, MAX_CONFIG_BYTES)?["push_to_pull_request_branch"];
    let base = report["base_commit"].as_str().unwrap_or("");
    let pinned = config["replacement_base"].as_str().unwrap_or("");
    let max = config["replacement_max_commits"].as_u64().unwrap_or(0);
    let commits = series["commits"]
        .as_array()
        .context("Unchecked replacement series: series.commits is missing or not an array")?;
    let commit_files = report["commit_files"].as_array().context(
        "Unchecked replacement series: report.patch.commit_files is missing or not an array",
    )?;
    // Fetch only full commit IDs, and only for a series check bound
    // commit by commit. A non-pinned base must belong to the base branch.
    ensure!(
        COMMIT_RE.is_match(base)
            && COMMIT_RE.is_match(pinned)
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
    if base != pinned
        && base != args.current_base
        && !is_pr_merge_base(repo, &args.remote, base, pinned, config)?
    {
        // The base branch can advance while the producer works. Accept
        // its earlier snapshot only after proving it belongs to the
        // history of the head trusted apply resolved, never an arbitrary
        // producer commit or a commit of the PR's own branch.
        ensure!(
            COMMIT_RE.is_match(&args.current_base),
            "Unchecked replacement series: no trusted current base for ancestry validation"
        );
        git(
            repo,
            &["fetch", "--no-tags", &args.remote, &args.current_base],
        )?;
        git(repo, &["fetch", "--no-tags", &args.remote, pinned])?;
        git(repo, &["merge-base", "--is-ancestor", pinned, base]).context(
            "Unchecked replacement series: base does not descend from the policy snapshot",
        )?;
        git(
            repo,
            &["merge-base", "--is-ancestor", base, &args.current_base],
        )
        .context(
            "Unchecked replacement series: base is not an ancestor of the trusted current base",
        )?;
    }
    materialize(base, &mails, &paths, &args.temp, repo)
}

/// Only the PR's actual divergence point may precede the policy snapshot.
/// An arbitrary ancestor would let a producer omit target changes from the
/// checked series. Both tips come from trusted configuration, not the series.
fn is_pr_merge_base(
    repo: &Path,
    remote: &str,
    base: &str,
    pinned: &str,
    config: &Value,
) -> Result<bool> {
    let head = config["head"].as_str().unwrap_or("");
    if !COMMIT_RE.is_match(head) {
        return Ok(false);
    }
    git(repo, &["fetch", "--no-tags", remote, pinned])?;
    git(repo, &["fetch", "--no-tags", remote, head])?;
    // Multiple merge bases are ambiguous: do not admit any one of them.
    Ok(git(repo, &["merge-base", "--all", pinned, head])? == base)
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
    for (index, (mail, checked)) in mails.iter().zip(checked).enumerate() {
        match apply_mail(dir, &file, mail, checked)? {
            Applied::Built(_) => {}
            Applied::Failed(error) => return Err(error),
            Applied::Nonlinear => bail!("Nonlinear replacement"),
            Applied::Unchecked => bail!("Replacement commit {} changed unchecked paths", index + 1),
        }
    }
    built(dir)
}

/// What one mail did to a worktree.
pub(crate) enum Applied {
    Built(Built),
    /// git am refused the mail, with git's message, which holds the
    /// agent's text; the worktree is back where it was.
    Failed(anyhow::Error),
    /// git am made something other than one commit on HEAD.
    Nonlinear,
    /// The commit changed other paths than check read for it.
    Unchecked,
}

/// Applies MAIL on the HEAD of the worktree DIR as one commit, with
/// [`COMMITTER`] and the author's date, so that the same mail on the same
/// parent is the same commit; FILE holds the mail for git am. An error is
/// the worktree's, not the mail's.
pub(crate) fn apply_mail(dir: &Path, file: &Path, mail: &str, checked: &[&str]) -> Result<Applied> {
    let file_arg = file.to_str().context("the mail's path is not UTF-8")?;
    let before = git(dir, &["rev-parse", "HEAD"])?;
    std::fs::write(file, mail).with_context(|| format!("writing {}", file.display()))?;
    let mut am = COMMITTER.to_vec();
    am.extend([
        "am",
        "--keep-cr",
        "--committer-date-is-author-date",
        file_arg,
    ]);
    if let Err(error) = git(dir, &am) {
        // A mail git could not read leaves no session to abort.
        let session = git(dir, &["rev-parse", "--git-path", "rebase-apply"])?;
        if dir.join(session).exists() {
            let mut abort = COMMITTER.to_vec();
            abort.extend(["am", "--abort"]);
            git(dir, &abort)?;
        }
        return Ok(Applied::Failed(error));
    }
    if git(dir, &["show", "-s", "--format=%P", "HEAD"])? != before {
        return Ok(Applied::Nonlinear);
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
    let mut checked = checked.to_vec();
    changed.sort_unstable();
    checked.sort_unstable();
    if changed != checked {
        return Ok(Applied::Unchecked);
    }
    Ok(Applied::Built(built(dir)?))
}

fn built(dir: &Path) -> Result<Built> {
    Ok(Built {
        head: git(dir, &["rev-parse", "HEAD"])?,
        tree: git(dir, &["rev-parse", "HEAD^{tree}"])?,
    })
}

/// Pushes `replacement` over `branch` with a lease on the pinned head. A
/// branch already at `replacement` is this series pushed by an earlier
/// attempt; any other head, the same tree included, is a concurrent write.
/// Returns whether this call pushed, false for a branch already there.
pub fn push(
    repo: &Path,
    remote: &str,
    branch: &str,
    original: &str,
    replacement: &str,
) -> Result<bool> {
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
        return Ok(false);
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
    Ok(true)
}

/// Runs git in REPO without hooks, signing or the machine's and user's
/// configuration; the repository's own (the checkout's credentials) stays.
pub fn git(repo: &Path, args: &[&str]) -> Result<String> {
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
    // Raw: the caller escapes it before it logs it (see the module's
    // documentation).
    ensure!(
        output.status.success(),
        "git {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)
        .context("git's output is not UTF-8")?
        .trim()
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::super::tests::read;
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
    fn replacement_retains_upstream_merge_base() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("producer");
        std::fs::create_dir(&repo).unwrap();
        run(&repo, &["init", "-q", "--initial-branch=main"]);
        run(&repo, &["config", "user.name", "Test"]);
        run(&repo, &["config", "user.email", "test@example.com"]);
        let older = commit(&repo, "fork-main.txt", "fork main");
        run(&repo, &["checkout", "-qb", "upstream-main"]);
        let base = commit(&repo, "upstream.txt", "upstream base");
        run(&repo, &["checkout", "-qb", "bot/topic"]);
        let message = "First change\n\nReviewed-by: Reviewer <reviewer@example.com>";
        commit(&repo, "a.txt", message);
        let original = commit(&repo, "b.txt", "Second change");
        let intended_tree = run(&repo, &["rev-parse", "HEAD^{tree}"]);

        // Reword the first commit and retain the second, without rebasing.
        run(&repo, &["checkout", "-q", "--detach", "HEAD~"]);
        run(
            &repo,
            &[
                "commit",
                "--amend",
                "-qm",
                &format!("{message}\n\nExplanation."),
            ],
        );
        let first = mail(&repo);
        run(&repo, &["cherry-pick", &original]);
        let second = mail(&repo);
        run(&repo, &["checkout", "-q", "upstream-main"]);
        let pinned = commit(&repo, "advanced.txt", "upstream advanced");
        let remote_dir = temp.path().join("remote");
        run(temp.path(), &["init", "--bare", "-q", "remote"]);
        let remote = remote_dir.to_str().unwrap();
        run(
            &repo,
            &["push", "-q", remote, "main", "upstream-main", "bot/topic"],
        );

        // Apply has only trusted remote history, not the producer checkout.
        let consumer = temp.path().join("consumer");
        std::fs::create_dir(&consumer).unwrap();
        run(&consumer, &["init", "-q"]);
        let fork_pull = serde_json::json!({"number": 42, "state": "open",
            "user": {"login": "example-bot"}, "head": {
            "repo": {"full_name": "example-org/example"}, "ref": "bot/topic", "sha": original
        }, "base": {"repo": {"full_name": "example-org/example"}, "ref": "main", "sha": older}});
        let mut upstream_pull = fork_pull.clone();
        upstream_pull["base"] = serde_json::json!({
            "repo": {"full_name": "upstream/example"}, "ref": "main", "sha": base
        });
        let (github, _requests) = super::super::testing::forge([
            ("GET /repos/example-org/example/pulls/42".into(), (200, fork_pull)),
            ("GET /repos/example-org/example".into(), (200, serde_json::json!({
                "fork": true, "parent": {"full_name": "upstream/example"}
            }))),
            ("GET /repos/upstream/example/pulls?state=open&head=example-org%3Abot/topic&per_page=2".into(),
                (200, serde_json::json!([upstream_pull]))),
            ("GET /repos/upstream/example/git/ref/heads/main".into(),
                (200, serde_json::json!({"object": {"type": "commit", "sha": pinned}}))),
        ].into());
        let resolved = super::super::push::resolve(
            &github,
            &super::super::push::ResolveArgs {
                event: "false".into(),
                review: "false".into(),
                kind: "branch".into(),
                item: "42".into(),
                repo: "example-org/example".into(),
                output_repo: "example-org/example".into(),
            },
        )
        .unwrap();
        assert_eq!(
            resolved.base, pinned,
            "policy must resolve upstream, not fork main"
        );
        let config = serde_json::json!({"push_to_pull_request_branch": {
            "head": resolved.head, "replacement_base": resolved.base, "replacement_max_commits": 2
        }});
        let args = TrialArgs {
            report: temp.path().join("report.json"),
            series: temp.path().join("replacement.json"),
            config: write(&temp.path().join("config.json"), &config),
            current_base: pinned.clone(),
            remote: remote.to_owned(),
            temp: temp.path().to_owned(),
        };
        let propose = |claimed: &str| {
            write(
                &args.report,
                &serde_json::json!({"patch": {
                    "base_commit": claimed, "commit_files": [["a.txt"], ["b.txt"]]
                }}),
            );
            write(
                &args.series,
                &serde_json::json!({
                    "base_commit": claimed, "commits": [first, second]
                }),
            );
        };
        propose(&base);
        let built = trial(&args, &consumer, &read).unwrap();
        assert_eq!(built.tree, intended_tree);
        assert_eq!(
            run(&consumer, &["rev-parse", &format!("{}~2", built.head)]),
            base
        );
        assert!(
            run(
                &consumer,
                &["show", "-s", "--format=%B", &format!("{}~", built.head)]
            )
            .contains("Reviewed-by: Reviewer <reviewer@example.com>")
        );
        assert!(push(&consumer, remote, "bot/topic", &original, &built.head).unwrap());
        assert!(!push(&consumer, remote, "bot/topic", &original, &built.head).unwrap());

        // Neither an older target ancestor nor a PR-only commit is a base.
        for claimed in [&older, &original] {
            propose(claimed);
            let error = trial(&args, &consumer, &read).unwrap_err();
            assert!(
                error
                    .to_string()
                    .starts_with("Unchecked replacement series"),
                "{error:#}"
            );
        }
        propose(&base);
        let mut missing_head = config.clone();
        missing_head["push_to_pull_request_branch"]["head"] = Value::Null;
        write(&args.config, &missing_head);
        assert!(trial(&args, &consumer, &read).is_err());
        println!(
            "upstream merge-base replacement: 2 commits rebuilt; intended tree and Reviewed-by preserved; leased push and retry succeeded; older ancestor, PR-only base and missing trusted head refused"
        );
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
        assert_eq!(
            trial(&args(&base, 1.into(), &moved), &repo, &read).unwrap(),
            first
        );
        // Only apply's own resolution of the base, or the policy's pin.
        assert_eq!(
            trial(&args(&moved, 1.into(), &original), &repo, &read).unwrap(),
            first
        );
        for (pinned, max, current) in [
            (base.as_str(), 1.into(), ""),
            (base.as_str(), 1.into(), original.as_str()),
            (moved.as_str(), 0.into(), ""),
            (moved.as_str(), Value::Null, ""),
            ("", 1.into(), moved.as_str()),
        ] {
            let error = trial(&args(pinned, max, current), &repo, &read).unwrap_err();
            assert!(
                error
                    .to_string()
                    .starts_with("Unchecked replacement series"),
                "{error:#}"
            );
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
        ] {
            let mut unbound = args(pinned, 2.into(), "");
            unbound.report = write(&unbound.report, &serde_json::json!({ "patch": patch }));
            let error = trial(&unbound, &repo, &read).unwrap_err();
            assert!(
                error
                    .to_string()
                    .starts_with("Unchecked replacement series"),
                "{error:#}"
            );
        }

        for (field, expected) in [
            ("commits", "series.commits"),
            ("commit_files", "report.patch.commit_files"),
        ] {
            let unbound = args(&moved, 1.into(), "");
            if field == "commits" {
                write(&unbound.series, &serde_json::json!({"base_commit": moved}));
            } else {
                write(
                    &unbound.report,
                    &serde_json::json!({"patch": {"base_commit": moved}}),
                );
            }
            let error = trial(&unbound, &repo, &read).unwrap_err();
            assert!(error.to_string().contains(expected), "{error:#}");
        }

        let pushed = || run(Path::new(remote), &["rev-parse", "refs/heads/agent-run-1"]);
        // A re-run finds its own series there and pushes nothing.
        assert!(push(&repo, remote, "agent-run-1", &original, &first.head).unwrap());
        assert!(!push(&repo, remote, "agent-run-1", &original, &first.head).unwrap());
        assert_eq!(pushed(), first.head);
        // A later run's series over it is pushed, not found applied.
        assert!(push(&repo, remote, "agent-run-1", &first.head, &two.head).unwrap());
        assert!(!push(&repo, remote, "agent-run-1", &first.head, &two.head).unwrap());
        assert_eq!(pushed(), two.head);
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
