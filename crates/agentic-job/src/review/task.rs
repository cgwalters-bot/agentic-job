//! Trusted code-review task composition, before publishing the policy artifact.
//!
//! With `review-shared-task`, the shared `workflow/review.md` comes first,
//! then the caller's `review-task` additions, read from the checked-out Git
//! commit rather than the worktree, then the merge guidance and the review's
//! fenced context. The agent and the detector both read the resulting
//! `task.md` from the policy artifact; neither adds to it.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};

use crate::{files, run::MAX_TASK_BYTES};

pub(super) fn compose(root: &Path, shared: &Path, local: &str) -> Result<String> {
    let bytes =
        files::read_regular(shared, MAX_TASK_BYTES).context("reading the shared review task")?;
    let mut task = text(bytes, "Shared review task")?;
    if !local.is_empty() {
        let additions = base_task(root, local)?;
        task.push_str("\n\n");
        task.push_str(&additions);
    }
    Ok(task)
}

fn text(bytes: Vec<u8>, source: &str) -> Result<String> {
    let text = String::from_utf8(bytes).with_context(|| format!("{source} must be UTF-8"))?;
    ensure!(!text.trim().is_empty(), "{source} is empty");
    Ok(text)
}

/// Read the caller's checked-out commit, not a downloaded artifact, overlay,
/// or a symlink out of that tree. Only a regular file can supply instructions.
fn base_task(root: &Path, name: &str) -> Result<String> {
    ensure!(
        name.split('/')
            .all(|p| !p.is_empty() && p != "." && p != ".."),
        "Review additions must be a relative repository file"
    );
    let git = |args: &[&str]| -> Result<Vec<u8>> {
        let output = Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .context("reading review additions from Git")?;
        ensure!(
            output.status.success(),
            "could not read review additions {name} from the caller's Git tree"
        );
        Ok(output.stdout)
    };
    let entry = String::from_utf8(git(&[
        "--literal-pathspecs",
        "ls-tree",
        "-z",
        "HEAD",
        "--",
        name,
    ])?)?;
    let object = entry
        .split_once('\t')
        .filter(|(_, path)| path.strip_suffix('\0') == Some(name))
        .and_then(|(entry, _)| {
            entry
                .strip_prefix("100644 blob ")
                .or_else(|| entry.strip_prefix("100755 blob "))
        })
        .with_context(|| {
            format!("Review additions {name} must be a regular file in the trusted caller commit")
        })?;
    let size: u64 = String::from_utf8(git(&["cat-file", "-s", object])?)?
        .trim()
        .parse()?;
    ensure!(
        size <= MAX_TASK_BYTES,
        "Review additions exceed {MAX_TASK_BYTES} bytes"
    );
    text(git(&["cat-file", "blob", object])?, "Review additions")
}

pub(crate) fn check_size(bytes: usize) -> Result<()> {
    ensure!(
        bytes as u64 <= MAX_TASK_BYTES,
        "Rendered review task is {bytes} bytes, over {MAX_TASK_BYTES} bytes"
    );
    Ok(())
}
