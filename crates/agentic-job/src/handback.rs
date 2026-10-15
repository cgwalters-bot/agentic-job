//! Producer-side convenience only: trusted capture and check still enforce policy.

use std::path::Path;
use std::process::{Command as Process, Stdio};

use anyhow::{Context, Result, ensure};
use clap::Subcommand;

use crate::check::replacement::Replacement;
use crate::exit::Exit;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Preserve format-patch mails and test the complete series on its base
    Replace {
        #[arg(long)]
        base: String,
        /// Defaults to BASE..HEAD; include every commit to retain
        range: Option<String>,
    },
}

impl Command {
    pub fn run(&self) -> Result<Exit> {
        match self {
            Self::Replace { base, range } => {
                let home = std::env::var_os("HOME").context("HOME is not set")?;
                let output = Path::new(&home).join("out/replacement.json");
                replace(Path::new("."), base, range.as_deref(), &output)?;
                eprintln!("Validated replacement written to {}", output.display());
            }
        }
        Ok(Exit::Success)
    }
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = git_command(repo).args(args).output()?;
    ensure!(
        output.status.success(),
        "git {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

fn git_command(repo: &Path) -> Process {
    let mut command = Process::new("git");
    // Repository-selection overrides can make `-C scratch` operate on the
    // producer's checkout instead. Never carry Git's ambient overrides into
    // either side of this local validation.
    for (key, _) in std::env::vars_os() {
        if key.as_encoded_bytes().starts_with(b"GIT_") {
            command.env_remove(key);
        }
    }
    command.arg("-C").arg(repo);
    command
}

fn replace(repo: &Path, base: &str, range: Option<&str>, output: &Path) -> Result<()> {
    let base = String::from_utf8(git(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{base}^{{commit}}"),
        ],
    )?)?;
    let base = base.trim();
    let default_range = format!("{base}..HEAD");
    let range = range.unwrap_or(&default_range);
    ensure!(!range.starts_with('-'), "range must not be an option");
    let ids = String::from_utf8(git(
        repo,
        &["rev-list", "--reverse", "--topo-order", range, "--"],
    )?)?;
    let ids: Vec<_> = ids.lines().collect();
    ensure!(
        !ids.is_empty() && ids.len() <= 50,
        "replacement requires 1..=50 commits"
    );
    let scratch = tempfile::tempdir()?;
    git(scratch.path(), &["init", "--quiet"])?;
    // An independent repository avoids worktree registration and leaves the
    // producer's index, HEAD and in-progress operations untouched on failure.
    let source = String::from_utf8(git(repo, &["rev-parse", "--absolute-git-dir"])?)?;
    git(
        scratch.path(),
        &["fetch", "--quiet", "--", source.trim(), base],
    )?;
    git(scratch.path(), &["checkout", "--quiet", "--detach", base])?;
    let mut commits = Vec::new();
    for id in ids {
        let defaults = crate::run::handback::FORMAT_PATCH;
        let mut args = defaults[..defaults.len() - 1].to_vec();
        args.extend([id, "--"]);
        let mail = git(repo, &args)?;
        ensure!(
            !mail.is_empty(),
            "commit {id} has no patch (empty or merge commit)"
        );
        let mut child = git_command(scratch.path())
            .args([
                "-c",
                "user.name=Handback",
                "-c",
                "user.email=handback@localhost",
                "-c",
                "core.hooksPath=/dev/null",
                "am",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        use std::io::Write;
        child
            .stdin
            .take()
            .context("git am stdin")?
            .write_all(&mail)?;
        let applied = child.wait_with_output()?;
        ensure!(
            applied.status.success(),
            "commit {id} does not apply on the replacement base: {}",
            String::from_utf8_lossy(&applied.stderr)
        );
        commits.push(String::from_utf8(mail).context("replacement mail must be UTF-8")?);
    }
    let bytes = serde_json::to_vec(&Replacement {
        base_commit: base.into(),
        commits,
    })?;
    let parent = output.parent().context("output has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write;
    file.write_all(&bytes)?;
    file.persist(output).context("writing replacement.json")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_mail_and_rejects_a_wrong_base_without_overwriting() {
        let repo = tempfile::tempdir().unwrap();
        let p = repo.path();
        git(p, &["init", "--quiet"]).unwrap();
        git(p, &["config", "user.name", "Test"]).unwrap();
        git(p, &["config", "user.email", "test@example.org"]).unwrap();
        std::fs::write(p.join("file"), "base\n").unwrap();
        git(p, &["add", "."]).unwrap();
        git(p, &["commit", "-qm", "Base"]).unwrap();
        let base = String::from_utf8(git(p, &["rev-parse", "HEAD"]).unwrap()).unwrap();
        std::fs::write(p.join("file"), "changed\n").unwrap();
        git(p, &["commit", "-qam", "Change"]).unwrap();
        let output = p.join("out/replacement.json");
        replace(p, base.trim(), None, &output).unwrap();
        let bytes = std::fs::read(&output).unwrap();
        let series: Replacement = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            series.commits[0].as_bytes(),
            git(
                p,
                &[
                    "format-patch",
                    "--stdout",
                    "--no-signature",
                    "--no-renames",
                    "-1",
                    "HEAD"
                ]
            )
            .unwrap()
        );
        assert!(series.commits[0].ends_with('\n'));
        assert!(replace(p, "HEAD", Some("HEAD~1..HEAD"), &output).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
        assert!(replace(p, "HEAD", None, &output).is_err());
    }
}
