//! Producer-side convenience only: trusted capture and check still enforce policy.

use std::path::Path;
use std::process::{Command as Process, Stdio};

use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;

use crate::check::replacement::Replacement;
use crate::exit::Exit;
use crate::files::ReadError;
use crate::redact;
use crate::run::handback::{AGENT_OUTCOME, AGENT_OUTPUTS, REPLACEMENT_PATH};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Preserve format-patch mails and test the complete series on its base
    Replace {
        #[arg(long)]
        base: String,
        /// Defaults to BASE..HEAD; include every commit to retain
        range: Option<String>,
    },
    /// Find secret-shaped strings in what the run would hand back: the
    /// change against BASE, and the files in `out/` under your home
    Scan {
        /// The commit the change is made against: the one the run started from
        #[arg(long, default_value = "HEAD")]
        base: String,
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
            Self::Scan { base } => {
                let home = std::env::var_os("HOME").context("HOME is not set")?;
                let found = scan(Path::new("."), base, Path::new(&home))?;
                if !found.is_empty() {
                    for finding in &found {
                        println!("{finding}");
                    }
                    eprintln!(
                        "{} secret-shaped string(s): `run` refuses everything this run hands \
                         back while one is there. Remove each, or build it at run time from \
                         parts that do not match, then scan again.",
                        found.len()
                    );
                    return Ok(Exit::Failure);
                }
                eprintln!("No secret-shaped string in the change or in {}", OUT_DIR);
            }
        }
        Ok(Exit::Success)
    }
}

/// Where under the agent's home `run` takes its requests and report from.
const OUT_DIR: &str = "out";

/// Bigger than any file `run` takes from `out/`; one this big is refused
/// there anyway.
const MAX_SCANNED_BYTES: u64 = 64 << 20;

/// A secret-shaped string, by where it is and the pattern it matches;
/// never by the string, which may be real.
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    location: String,
    pattern: &'static str,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: matches `{}`", self.location, self.pattern)
    }
}

/// What `run`'s final gate would refuse in the change of the checkout
/// REPO against BASE and in HOME's `out/`, while the session can still
/// fix it: found only then, it cost two runs all their work (#720). Not
/// the gate itself, which also knows the run's own secrets and scans the
/// patch as it is made; a line at a time, which finds what the gate
/// finds, since no pattern but a private key's spans lines and that one
/// also matches its first line alone.
fn scan(repo: &Path, base: &str, home: &Path) -> Result<Vec<Finding>> {
    let base = String::from_utf8(git(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{base}^{{commit}}"),
        ],
    )?)?;
    // A copy of the index, so that the checkout's own stays as it is.
    let scratch = tempfile::tempdir()?;
    let index = scratch.path().join("index");
    let own = String::from_utf8(git(repo, &["rev-parse", "--git-path", "index"])?)?;
    match std::fs::copy(repo.join(own.trim()), &index) {
        Ok(_) => {}
        // No index yet: `git add` starts an empty one.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("copying the index"),
    }
    let with_index = |args: &[&str]| -> Result<Vec<u8>> {
        let output = git_command(repo)
            .env("GIT_INDEX_FILE", &index)
            .args(args)
            .output()?;
        ensure!(
            output.status.success(),
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output.stdout)
    };
    // As `run` stages it; the patch holds the same lines, context included.
    with_index(&["add", "--all"])?;
    let diff = with_index(&[
        "diff",
        "--cached",
        "--no-renames",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        base.trim(),
        "--",
    ])?;
    let mut found = diff_findings(&diff);
    // Whatever `run` reads from there: the requests, the report (a
    // summary can become the commit message) and a replacement series.
    let names = [AGENT_OUTPUTS, AGENT_OUTCOME, REPLACEMENT_PATH];
    for name in names {
        let path = home.join(name);
        let content = match crate::files::read_regular(&path, MAX_SCANNED_BYTES) {
            Ok(content) => content,
            Err(ReadError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => bail!("{} {err}", path.display()),
        };
        for (number, line) in content.split(|&b| b == b'\n').enumerate() {
            let mut patterns = redact::secret_shapes(line);
            // `run` decodes and writes again what it takes from JSON, so
            // an escape (`\u0067hp_`) is a match by then.
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) {
                for pattern in redact::secret_shapes(value.to_string().as_bytes()) {
                    if !patterns.contains(&pattern) {
                        patterns.push(pattern);
                    }
                }
            }
            for pattern in patterns {
                found.push(Finding {
                    location: format!("{}:{}", path.display(), number + 1),
                    pattern,
                });
            }
        }
    }
    Ok(found)
}

/// PATH as a location, unless it is itself what may not be shown.
fn shown(path: &[u8]) -> String {
    if redact::secret_shapes(path).is_empty() {
        String::from_utf8_lossy(path).into_owned()
    } else {
        "a file whose name is secret-shaped".to_owned()
    }
}

/// The secret-shaped strings in DIFF, `git diff` output, each by the file
/// and line it is on: the new file's for an added line and for an
/// unchanged one the patch quotes as context, the old file's for one it
/// removes, since the patch holds all three.
fn diff_findings(diff: &[u8]) -> Vec<Finding> {
    let mut found = Vec::new();
    let (mut old_path, mut new_path) = (String::new(), String::new());
    let (mut old, mut new) = (0_usize, 0_usize);
    let mut in_hunk = false;
    for line in diff.split(|&b| b == b'\n') {
        let location = if line.starts_with(b"diff --git ") {
            in_hunk = false;
            // The names are on the lines after; this one may hold the match.
            "a file name in the diff (`git diff --name-only` lists them)".to_owned()
        } else if let Some(hunk) = line.strip_prefix(b"@@ ") {
            // `@@ -OLD[,COUNT] +NEW[,COUNT] @@ CONTEXT`
            let hunk = String::from_utf8_lossy(hunk);
            let start = |sign: char| {
                hunk.split(' ')
                    .find_map(|part| part.strip_prefix(sign))
                    .and_then(|range| range.split(',').next())
                    .and_then(|start| start.parse::<usize>().ok())
                    .unwrap_or(0)
            };
            (old, new) = (start('-'), start('+'));
            in_hunk = true;
            format!("{new_path} (a hunk header)")
        } else if in_hunk {
            match line.first() {
                Some(b'+') => {
                    new += 1;
                    format!("{new_path}:{}", new - 1)
                }
                Some(b'-') => {
                    old += 1;
                    format!("{old_path}:{} (a line the change removes)", old - 1)
                }
                Some(b' ') => {
                    (old, new) = (old + 1, new + 1);
                    format!(
                        "{new_path}:{} (an unchanged line quoted as context)",
                        new - 1
                    )
                }
                _ => format!("{new_path} (a diff line)"),
            }
        } else {
            if let Some(path) = line.strip_prefix(b"--- ") {
                old_path = shown(path.strip_prefix(b"a/").unwrap_or(path));
            } else if let Some(path) = line.strip_prefix(b"+++ ") {
                new_path = shown(path.strip_prefix(b"b/").unwrap_or(path));
            }
            format!("{new_path} (a diff header)")
        };
        for pattern in redact::secret_shapes(line) {
            found.push(Finding {
                location: location.clone(),
                pattern,
            });
        }
    }
    found
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

    #[test]
    fn a_finding_is_located_by_file_and_line_of_its_side() {
        let token = format!("gh{}_{}", "p", "a1B2".repeat(10));
        let diff = format!(
            "diff --git a/src/k.rs b/src/k.rs\n\
             index 1111111..2222222 100644\n\
             --- a/src/k.rs\n\
             +++ b/src/k.rs\n\
             @@ -10,4 +10,4 @@ fn f() {{\n\
             \x20ctx {token}\n\
             -old {token}\n\
             +new {token}\n\
             \x20clean\n\
             diff --git a/gone b/gone\n\
             deleted file mode 100644\n\
             --- a/gone\n\
             +++ /dev/null\n\
             @@ -1 +0,0 @@\n\
             -{token}\n\
             diff --git a/x b/x\n\
             new file mode 100644\n\
             --- /dev/null\n\
             +++ b/x\n\
             @@ -0,0 +1,2 @@ {token}\n\
             +clean\n\
             +sk-{token}\n"
        );
        let found: Vec<String> = diff_findings(diff.as_bytes())
            .iter()
            .map(|finding| finding.location.clone())
            .collect();
        let want = [
            "src/k.rs:10 (an unchanged line quoted as context)",
            "src/k.rs:11 (a line the change removes)",
            "src/k.rs:11",
            "gone:1 (a line the change removes)",
            "x (a hunk header)",
            "x:2",
            // Also an OpenAI key's shape.
            "x:2",
        ];
        assert_eq!(found, want);
        assert!(found.iter().all(|location| !location.contains(&token)));
    }
}
