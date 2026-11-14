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

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

use super::COMMIT_RE;
use crate::contract::Policy;

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

/// Safe counts accompanying an application-only rebuild. Publication pushes
/// `built.head` itself; it must not apply the original, redacted mails again.
#[derive(Debug)]
pub struct RecoveredTrial {
    pub built: Built,
    pub restored_lines: usize,
    pub added_placeholders: usize,
}

struct Preparation<'a> {
    policy: &'a Policy,
    validate: &'a dyn Fn(&[u8]) -> Result<()>,
    restored: Cell<usize>,
    added: Cell<usize>,
    bytes: Cell<usize>,
    mails: Cell<usize>,
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
    trial_using(args, repo, read, None)
}

/// Rebuild with exact recovery against the authenticated base and each actual
/// predecessor. POLICY is trusted caller configuration, not producer data.
/// VALIDATE must refuse credentials in application bytes without logging them.
/// Recovered bytes live only in a private temporary mail, removed on return;
/// the only publication input is the resulting commit object.
pub fn trial_recovered(
    args: &TrialArgs,
    repo: &Path,
    read: &dyn Fn(&Path, u64) -> Result<Vec<u8>>,
    policy: &Policy,
    validate: &dyn Fn(&[u8]) -> Result<()>,
) -> Result<RecoveredTrial> {
    let preparation = Preparation {
        policy,
        validate,
        restored: Cell::new(0),
        added: Cell::new(0),
        bytes: Cell::new(0),
        mails: Cell::new(0),
    };
    let built = trial_using(args, repo, read, Some(&preparation))?;
    Ok(RecoveredTrial {
        built,
        restored_lines: preparation.restored.get(),
        added_placeholders: preparation.added.get(),
    })
}

fn trial_using(
    args: &TrialArgs,
    repo: &Path,
    read: &dyn Fn(&Path, u64) -> Result<Vec<u8>>,
    preparation: Option<&Preparation<'_>>,
) -> Result<Built> {
    let document = read_json(read, &args.report, MAX_REPORT_BYTES)?;
    let report = &document["patch"];
    let series_bytes = read(&args.series, MAX_SERIES_BYTES)?;
    let series: Value = serde_json::from_slice(&series_bytes)?;
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
    if let Some(preparation) = preparation {
        ensure!(
            document["ok"] == true && document["errors"].as_array().is_some_and(Vec::is_empty),
            "recovery requires an accepted check report"
        );
        let policy = preparation.policy;
        ensure!(
            policy.forge == crate::Forge::Github && !policy.private,
            "recovery requires a trusted public GitHub repository"
        );
        let push = policy
            .safe_outputs
            .push_to_pull_request_branch
            .as_ref()
            .context("recovery requires a trusted push policy")?;
        ensure!(
            push.replacement_base.as_deref() == Some(pinned)
                && push.replacement_max_commits as u64 == max
                && config["head"].as_str() == Some(push.head.as_str()),
            "recovery configuration differs from trusted policy"
        );
        // Recheck the original receipt and every mail, not merely the final
        // tree. Recovery may not turn a reverted forbidden edit into a push.
        let checked = crate::check::replacement::check(&series_bytes, push, policy.max_patch_bytes)
            .map_err(|_| anyhow::anyhow!("recovery requires a valid replacement series"))?;
        ensure!(
            report["bytes"].as_u64() == Some(series_bytes.len() as u64)
                && report["file"].as_str() == Some(crate::check::replacement::REPLACEMENT_FILE)
                && serde_json::to_value(&checked.files)? == report["files"]
                && serde_json::to_value(&checked.commit_files)? == report["commit_files"],
            "recovery series differs from check's receipt"
        );
        preparation.bytes.set(
            serde_json::to_vec(&crate::check::replacement::Replacement {
                base_commit: base.to_owned(),
                commits: Vec::new(),
            })?
            .len(),
        );
    }
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
    materialize_using(base, &mails, &paths, &args.temp, repo, preparation)
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
#[cfg(test)]
fn materialize(
    base: &str,
    mails: &[&str],
    checked: &[Vec<&str>],
    temp: &Path,
    repo: &Path,
) -> Result<Built> {
    materialize_using(base, mails, checked, temp, repo, None)
}

fn materialize_using(
    base: &str,
    mails: &[&str],
    checked: &[Vec<&str>],
    temp: &Path,
    repo: &Path,
    preparation: Option<&Preparation<'_>>,
) -> Result<Built> {
    let dir = temp.join("replacement-trial");
    let dir_arg = dir.to_str().context("the trial directory is not UTF-8")?;
    git(
        repo,
        &["worktree", "add", "--quiet", "--detach", dir_arg, base],
    )?;
    let built = apply_series(base, mails, checked, temp, &dir, preparation);
    let removed = git(repo, &["worktree", "remove", "--force", dir_arg]);
    let built = built?;
    removed?;
    Ok(built)
}

fn apply_series(
    base: &str,
    mails: &[&str],
    checked: &[Vec<&str>],
    temp: &Path,
    dir: &Path,
    preparation: Option<&Preparation<'_>>,
) -> Result<Built> {
    let file = temp.join("replacement-mail.patch");
    for (index, (mail, checked)) in mails.iter().zip(checked).enumerate() {
        let applied = if let Some(preparation) = preparation {
            apply_recovered(base, mail, checked, dir, temp, preparation)?
        } else {
            apply_mail(dir, &file, mail, checked)?
        };
        match applied {
            Applied::Built(_) => {}
            Applied::Failed(error) => return Err(error),
            Applied::Nonlinear => bail!("Nonlinear replacement"),
            Applied::Unchecked => bail!("Replacement commit {} changed unchecked paths", index + 1),
        }
    }
    built(dir)
}

fn apply_recovered(
    base: &str,
    mail: &str,
    checked: &[&str],
    dir: &Path,
    temp: &Path,
    preparation: &Preparation<'_>,
) -> Result<Applied> {
    let diff = mail
        .split_once("\ndiff --git ")
        .map_or("", |(_, diff)| diff);
    let needs_recovery = diff
        .lines()
        .any(|line| line.starts_with([' ', '-']) && line.contains("<inference-address>"));
    if !needs_recovery {
        // Preserve ordinary replacement compatibility (CRLF, large preimages,
        // missing final newlines and credential-shape fixture warnings). Only
        // old-side recovery needs the stricter reconstruction restrictions.
        count_application_mail(mail, preparation)?;
        preparation.added.set(
            preparation.added.get()
                + diff
                    .lines()
                    .filter(|line| line.starts_with('+'))
                    .map(|line| line.matches("<inference-address>").count())
                    .sum::<usize>(),
        );
        let file =
            tempfile::NamedTempFile::new_in(temp).context("creating private application mail")?;
        return apply_mail(dir, file.path(), mail, checked);
    }
    // Capture the immutable parent once. No working-tree file is a preimage,
    // including for later commits whose parent was rebuilt by this trial.
    let parent = git(dir, &["rev-parse", "HEAD"])?;
    let (first, rest) = mail
        .split_once('\n')
        .context("replacement mail has no header")?;
    let patch = format!(
        "{first}\n{}: {base}\n{rest}",
        crate::check::BASE_COMMIT_HEADER
    );
    let policy = preparation.policy;
    let push = policy
        .safe_outputs
        .push_to_pull_request_branch
        .as_ref()
        .context("recovery requires a trusted push policy")?;
    let rules = crate::contract::PatchRules {
        commit_author: policy.commit_author.as_deref(),
        ..push.rules()
    };
    let recovered = super::recover::reconstruct(
        &patch,
        &rules,
        base,
        usize::try_from(policy.max_patch_bytes)?,
        |path, limit| read_preimage(dir, &parent, path, limit),
    )?;
    (preparation.validate)(recovered.application_patch().as_bytes())
        .map_err(|_| anyhow::anyhow!("recovered replacement failed credential validation"))?;
    // Drop only the header we inserted. The bounded replacement protocol
    // supplies it separately, and a future recheck must see plain mails.
    let (first, rest) = recovered
        .application_patch()
        .split_once('\n')
        .context("recovered mail has no header")?;
    let rest = rest
        .strip_prefix(&format!("{}: {base}\n", crate::check::BASE_COMMIT_HEADER))
        .context("recovered mail lost its base header")?;
    let application_mail = format!("{first}\n{rest}");
    count_application_mail(&application_mail, preparation)?;
    let file =
        tempfile::NamedTempFile::new_in(temp).context("creating private application mail")?;
    // git am's error can quote a recovered context line. Never pass it (or
    // a caller's validation error) to diagnostics. The temporary mail drops
    // on both success and refusal, outside the checked artifact directory.
    let applied = apply_mail(dir, file.path(), &application_mail, checked)
        .map_err(|_| anyhow::anyhow!("recovered replacement application failed"))?;
    let applied = match applied {
        Applied::Failed(_) => bail!("recovered replacement mail did not apply"),
        other => other,
    };
    // git am searches context and is not itself an exact-position proof.
    // Hold every resulting blob to reconstruction's exact-position digest
    // before this head can become a predecessor or a publication input.
    if matches!(applied, Applied::Built(_)) {
        let head = git(dir, &["rev-parse", "HEAD"])?;
        recovered.verify_application(|path, limit| {
            if git(dir, &["ls-tree", "-z", &head, "--", path])?.is_empty() {
                return Ok(None);
            }
            read_preimage(dir, &head, path, limit).map(Some)
        })?;
    }
    preparation
        .restored
        .set(preparation.restored.get() + recovered.restored_lines);
    preparation
        .added
        .set(preparation.added.get() + recovered.added_placeholders);
    Ok(applied)
}

fn count_application_mail(mail: &str, preparation: &Preparation<'_>) -> Result<()> {
    let comma = usize::from(preparation.mails.get() != 0);
    let bytes = preparation
        .bytes
        .get()
        .checked_add(serde_json::to_vec(mail)?.len() + comma)
        .context("recovered series byte count overflow")?;
    ensure!(
        bytes as u64 <= preparation.policy.max_patch_bytes,
        "recovered series exceeds patch byte limit"
    );
    preparation.bytes.set(bytes);
    preparation.mails.set(preparation.mails.get() + 1);
    Ok(())
}

/// Read only a regular immutable blob, checking its size before obtaining its
/// bytes. `git show` on a worktree path, lossy UTF-8 and trimmed output would
/// all invalidate exact old-side comparison.
fn read_preimage(dir: &Path, parent: &str, path: &str, limit: usize) -> Result<Vec<u8>> {
    let entry = git(dir, &["ls-tree", "-z", parent, "--", path])?;
    let (metadata, named) = entry.split_once('\t').context("preimage entry is absent")?;
    let fields: Vec<_> = metadata.split(' ').collect();
    ensure!(
        fields.len() == 3
            && matches!(fields[0], "100644" | "100755")
            && fields[1] == "blob"
            && named == format!("{path}\0")
            && COMMIT_RE.is_match(fields[2]),
        "preimage is not one regular blob"
    );
    let size: usize = git(dir, &["cat-file", "-s", fields[2]])?.parse()?;
    ensure!(size <= limit, "preimage exceeds byte limit");
    let bytes = git_output(dir, &["cat-file", "blob", fields[2]])?;
    ensure!(bytes.len() == size, "preimage size changed");
    Ok(bytes)
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
    Ok(String::from_utf8(git_output(repo, args)?)
        .context("git's output is not UTF-8")?
        .trim()
        .to_owned())
}

fn git_output(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Process::new("git")
        // A full pinned SHA must name its own object, not refs/replace's.
        .arg("--no-replace-objects")
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
    Ok(output.stdout)
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

    const ADDRESS: &str = "inference.example.test:8443";

    struct RecoveryFixture {
        temp: tempfile::TempDir,
        consumer: PathBuf,
        args: TrialArgs,
        policy: Policy,
        intended_tree: String,
        original: String,
    }

    impl RecoveryFixture {
        fn new() -> Self {
            Self::with_empty_deletion(false)
        }

        fn with_empty_deletion(delete_empty: bool) -> Self {
            Self::with_options(delete_empty, false)
        }

        fn with_options(delete_empty: bool, added_placeholder: bool) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let producer = temp.path().join("producer");
            std::fs::create_dir(&producer).unwrap();
            run(&producer, &["init", "-q", "--initial-branch=main"]);
            run(&producer, &["config", "user.name", "Test"]);
            run(&producer, &["config", "user.email", "test@example.test"]);
            let source = |value: &str| {
                let suffix = if added_placeholder && value != "old" {
                    "<inference-address>\n"
                } else {
                    ""
                };
                format!("url={ADDRESS}\n{value}\n{suffix}")
            };
            std::fs::write(producer.join("config"), source("old")).unwrap();
            if delete_empty {
                std::fs::write(producer.join("empty"), "").unwrap();
                run(&producer, &["add", "empty"]);
            }
            run(&producer, &["add", "config"]);
            run(&producer, &["commit", "-qm", "Base"]);
            let base = run(&producer, &["rev-parse", "HEAD"]);
            run(&producer, &["checkout", "-qb", "topic"]);
            let mut mails = Vec::new();
            for (value, message) in [("middle", "First"), ("new", "Second")] {
                std::fs::write(producer.join("config"), source(value)).unwrap();
                if delete_empty && value == "new" {
                    std::fs::remove_file(producer.join("empty")).unwrap();
                }
                run(&producer, &["commit", "-qam", message]);
                mails.push(mail(&producer).replace(ADDRESS, "<inference-address>"));
            }
            let intended_tree = run(&producer, &["rev-parse", "HEAD^{tree}"]);
            let original = run(&producer, &["rev-parse", "HEAD"]);
            run(temp.path(), &["init", "--bare", "-q", "remote"]);
            let remote = temp.path().join("remote");
            run(
                &producer,
                &["push", "-q", remote.to_str().unwrap(), "main", "topic"],
            );
            let consumer = temp.path().join("consumer");
            std::fs::create_dir(&consumer).unwrap();
            run(&consumer, &["init", "-q"]);
            let mut policy = crate::check::fixtures::push_policy();
            let push = policy
                .safe_outputs
                .push_to_pull_request_branch
                .as_mut()
                .unwrap();
            push.replacement_base = Some(base.clone());
            push.replacement_max_commits = 2;
            push.head = original.clone();
            policy.commit_author = None;
            let series = serde_json::json!({"base_commit": base, "commits": mails});
            let args = TrialArgs {
                report: temp.path().join("report.json"),
                series: write(&temp.path().join("replacement.json"), &series),
                config: write(
                    &temp.path().join("config.json"),
                    &serde_json::to_value(&policy.safe_outputs).unwrap(),
                ),
                current_base: base,
                remote: remote.to_str().unwrap().to_owned(),
                temp: temp.path().to_owned(),
            };
            let fixture = Self {
                temp,
                consumer,
                args,
                policy,
                intended_tree,
                original,
            };
            fixture.receipt();
            fixture
        }

        fn receipt(&self) {
            let bytes = std::fs::read(&self.args.series).unwrap();
            let push = self
                .policy
                .safe_outputs
                .push_to_pull_request_branch
                .as_ref()
                .unwrap();
            let checked =
                crate::check::replacement::check(&bytes, push, self.policy.max_patch_bytes)
                    .unwrap();
            write(
                &self.args.report,
                &serde_json::json!({"ok": true, "errors": [], "patch": checked}),
            );
        }

        fn trial(&self, validate: &dyn Fn(&[u8]) -> Result<()>) -> Result<RecoveredTrial> {
            trial_recovered(&self.args, &self.consumer, &read, &self.policy, validate)
        }

        fn clean(&self) {
            assert!(!self.temp.path().join("replacement-trial").exists());
            assert!(!self.temp.path().join("replacement-mail.patch").exists());
            assert!(std::fs::read_dir(self.temp.path()).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tmp")
            }));
        }
    }

    #[test]
    fn recovered_trial_binds_predecessors_and_publishes_built_objects() {
        let original_fixture = RecoveryFixture::new();
        assert!(trial(&original_fixture.args, &original_fixture.consumer, &read).is_err());
        let fixture = RecoveryFixture::new();
        let raw = std::fs::read(&fixture.args.series).unwrap();
        assert!(
            !raw.windows(ADDRESS.len())
                .any(|bytes| bytes == ADDRESS.as_bytes())
        );
        // Poisoning a working-tree file cannot supply the preimage.
        std::fs::write(fixture.consumer.join("config"), "untrusted checkout\n").unwrap();
        let calls = Cell::new(0);
        let validate = |bytes: &[u8]| {
            assert!(std::str::from_utf8(bytes).unwrap().contains(ADDRESS));
            calls.set(calls.get() + 1);
            Ok(())
        };
        let trial = fixture.trial(&validate).unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(trial.restored_lines, 2);
        assert_eq!(trial.added_placeholders, 0);
        assert_eq!(trial.built.tree, fixture.intended_tree);
        let again = fixture.trial(&validate).unwrap();
        assert_eq!(trial.built, again.built);
        assert!(
            push(
                &fixture.consumer,
                &fixture.args.remote,
                "topic",
                &fixture.original,
                &trial.built.head
            )
            .unwrap()
        );
        assert_eq!(
            run(Path::new(&fixture.args.remote), &["rev-parse", "topic"]),
            trial.built.head
        );
        assert!(
            !push(
                &fixture.consumer,
                &fixture.args.remote,
                "topic",
                &fixture.original,
                &trial.built.head
            )
            .unwrap()
        );
        assert_eq!(std::fs::read(&fixture.args.series).unwrap(), raw);
        fixture.clean();
    }

    #[test]
    fn recovered_trial_refuses_policy_receipt_and_credential_mismatches() {
        for case in [
            "policy",
            "receipt",
            "credentials",
            "bounds",
            "wrong preimage",
            "wrong base",
            "private",
        ] {
            let mut fixture = RecoveryFixture::new();
            match case {
                "policy" => {
                    fixture
                        .policy
                        .safe_outputs
                        .push_to_pull_request_branch
                        .as_mut()
                        .unwrap()
                        .head = "3".repeat(40);
                }
                "receipt" => {
                    let mut report: Value =
                        serde_json::from_slice(&std::fs::read(&fixture.args.report).unwrap())
                            .unwrap();
                    report["patch"]["bytes"] = 0.into();
                    write(&fixture.args.report, &report);
                }
                "bounds" => fixture
                    .policy
                    .safe_outputs
                    .push_to_pull_request_branch
                    .as_mut()
                    .unwrap()
                    .protected_paths
                    .push("config".into()),
                "private" => fixture.policy.private = true,
                "wrong base" => {
                    let mut series: Value =
                        serde_json::from_slice(&std::fs::read(&fixture.args.series).unwrap())
                            .unwrap();
                    series["base_commit"] = fixture.original.clone().into();
                    write(&fixture.args.series, &series);
                    fixture.receipt();
                }
                "wrong preimage" => {
                    let bytes = std::fs::read_to_string(&fixture.args.series)
                        .unwrap()
                        .replace("url=", "other=");
                    std::fs::write(&fixture.args.series, bytes).unwrap();
                    fixture.receipt();
                }
                _ => {}
            }
            let validate = |_: &[u8]| {
                ensure!(case != "credentials", "credential at {ADDRESS}");
                Ok(())
            };
            let error = fixture.trial(&validate).unwrap_err();
            assert!(!format!("{error:#}").contains(ADDRESS), "{case}");
            fixture.clean();
        }
    }

    #[test]
    fn recovered_trial_retains_added_placeholders_and_counts_draft_warning() {
        let fixture = RecoveryFixture::new();
        let raw = std::fs::read_to_string(&fixture.args.series).unwrap();
        std::fs::write(
            &fixture.args.series,
            raw.replace("+new", "+<inference-address>"),
        )
        .unwrap();
        fixture.receipt();
        let trial = fixture.trial(&|_| Ok(())).unwrap();
        assert_eq!(trial.added_placeholders, 1);
        assert_eq!(
            run(
                &fixture.consumer,
                &["show", &format!("{}:config", trial.built.head)]
            ),
            format!("url={ADDRESS}\n<inference-address>")
        );
        fixture.clean();
    }

    #[test]
    fn recovered_trial_accepts_added_placeholder_as_later_context() {
        let fixture = RecoveryFixture::with_options(false, true);
        let trial = fixture.trial(&|_| Ok(())).unwrap();
        assert_eq!(trial.restored_lines, 2);
        assert_eq!(trial.added_placeholders, 1);
        assert_eq!(trial.built.tree, fixture.intended_tree);
        fixture.clean();
    }

    #[test]
    fn recovered_trial_allows_empty_file_deletion_without_a_hunk() {
        let fixture = RecoveryFixture::with_empty_deletion(true);
        let trial = fixture.trial(&|_| Ok(())).unwrap();
        assert_eq!(trial.built.tree, fixture.intended_tree);
        assert!(
            git(
                &fixture.consumer,
                &["ls-tree", &trial.built.head, "--", "empty"]
            )
            .unwrap()
            .is_empty()
        );
        fixture.clean();
    }

    #[test]
    fn recovered_trial_bounds_the_entire_reconstructed_series() {
        let mut fixture = RecoveryFixture::new();
        fixture.policy.max_patch_bytes = std::fs::metadata(&fixture.args.series).unwrap().len();
        let error = fixture.trial(&|_| Ok(())).unwrap_err();
        assert_eq!(
            error.to_string(),
            "recovered series exceeds patch byte limit"
        );
        fixture.clean();
    }

    #[test]
    fn ordinary_mails_do_not_require_recovery_or_credential_shape_refusal() {
        let fixture = RecoveryFixture::new();
        let raw = std::fs::read_to_string(&fixture.args.series).unwrap();
        std::fs::write(
            &fixture.args.series,
            raw.replace("<inference-address>", ADDRESS),
        )
        .unwrap();
        fixture.receipt();
        let trial = fixture
            .trial(&|_| panic!("ordinary mails are already checked"))
            .unwrap();
        assert_eq!(trial.restored_lines, 0);
        assert_eq!(trial.built.tree, fixture.intended_tree);
        fixture.clean();
    }

    #[test]
    fn preimage_reads_are_regular_bounded_and_byte_exact() {
        let fixture = RecoveryFixture::new();
        let repo = fixture.temp.path().join("producer");
        let parent = run(&repo, &["rev-parse", "HEAD"]);
        let expected = format!("url={ADDRESS}\nnew\n");
        assert_eq!(
            read_preimage(&repo, &parent, "config", expected.len()).unwrap(),
            expected.as_bytes()
        );
        assert!(read_preimage(&repo, &parent, "config", expected.len() - 1).is_err());
        assert!(read_preimage(&repo, &parent, "missing", 1024).is_err());
        std::fs::write(repo.join("alternate"), "substituted preimage\n").unwrap();
        let substitute = run(&repo, &["hash-object", "-w", "alternate"]);
        let blob = run(&repo, &["rev-parse", &format!("{parent}:config")]);
        run(&repo, &["replace", &blob, &substitute]);
        assert_eq!(
            read_preimage(&repo, &parent, "config", expected.len()).unwrap(),
            expected.as_bytes()
        );
        std::os::unix::fs::symlink("config", repo.join("link")).unwrap();
        run(&repo, &["add", "link"]);
        run(&repo, &["commit", "-qm", "Symlink"]);
        let parent = run(&repo, &["rev-parse", "HEAD"]);
        assert!(read_preimage(&repo, &parent, "link", 1024).is_err());
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
            true,
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
