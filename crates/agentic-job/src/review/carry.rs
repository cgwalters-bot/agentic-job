//! review.yml's carry job: an approval carried to a pull request's new head
//! without running the agent, when the push changed nothing a review would
//! read differently (#2163). Each push used to start a full review; a
//! rebase onto the base branch or a rustfmt-only commit spent as much as
//! the change itself.
//!
//! The previous head (the push's `before`) must have the status `review`
//! as the status job sets it, `success` by the job token's bot. The new
//! head is carried when its tree is exactly the approved changes replayed
//! onto the base branch (`git merge-tree` of the approved head from its
//! merge base onto the new head's), or differs from that tree only in Rust
//! files that are rustfmt's output for it. Tree equality, not
//! `git patch-id`, which ignores whitespace, and so indentation that
//! changes what Python or YAML means. Anything else, or anything that
//! fails here, leaves the full review to run.
//!
//! The heads are data: git and rustfmt read them, in a scratch repository
//! and an empty directory, so no configuration, hook, attribute driver or
//! toolchain file of theirs applies, and nothing of theirs runs.
//!
//! What this trusts: a formatter-only change is taken to mean nothing,
//! which is not so for a `.rs` file read as data (a fixture) or for
//! `line!()`, and a file of an older edition is formatted as 2024's. The
//! previous head's status is trusted too, and someone with write access can
//! set it by hand, or have a branch's workflow set it as the job token's
//! bot, as such a workflow can already submit a review as that bot.

use std::io::Write;
use std::path::Path;
use std::process::{Command as Process, Stdio};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

use super::SHA;
use super::submit::{Api, BOT, annotate};

/// The changed Rust files the formatter is run on, at most.
const MAX_FORMATTED_FILES: usize = 100;
/// One file's size, at most, for the formatter.
const MAX_FORMATTED_BYTES: usize = 1 << 20;
/// What rustfmt formats as, without the trees' configuration: a tree
/// formatted otherwise is not carried.
const RUSTFMT_EDITION: &str = "2024";
const STATUS_CONTEXT: &str = "review";
const REGULAR_FILE: &str = "100644";
/// Where the base branch is fetched to in the scratch repository.
const BASE_REF: &str = "refs/carry/base";
/// A git credential helper that answers with the job's token from the
/// environment, so the token is in no command line or configuration file.
const CREDENTIAL_HELPER: &str = "!f() { test \"$1\" = get && \
    printf 'username=x-access-token\\npassword=%s\\n' \"$GH_TOKEN\"; }; f";

/// Why an approval was carried.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Why {
    /// The approved changes, rebased onto the base branch or recommitted.
    Rebase,
    /// rustfmt's output for the approved changes, rebased or not.
    Format,
}

impl Why {
    fn word(self) -> &'static str {
        match self {
            Self::Rebase => "rebase",
            Self::Format => "format",
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::Rebase => "the same changes rebased onto the base branch",
            Self::Format => "rustfmt's output for the approved changes",
        }
    }
}

/// An approval carried to the head, from the environment the carry job's
/// outputs give the submit and status jobs.
#[derive(Debug, PartialEq)]
pub struct Carried {
    from: String,
    why: Why,
}

impl Carried {
    /// CARRIED_FROM and CARRIED_WHY, or none when CARRIED_FROM is empty.
    pub fn read(env: &dyn Fn(&str) -> String) -> Result<Option<Self>> {
        let from = env("CARRIED_FROM");
        if from.is_empty() {
            return Ok(None);
        }
        ensure!(SHA.is_match(&from), "CARRIED_FROM must be a commit SHA");
        let why = match env("CARRIED_WHY").as_str() {
            "rebase" => Why::Rebase,
            "format" => Why::Format,
            other => bail!("CARRIED_WHY must be rebase or format, not {other:?}"),
        };
        Ok(Some(Self { from, why }))
    }

    /// The approval as check's accepted output would hold it: our text,
    /// never the agent's or the pull request's.
    pub fn output(&self) -> Value {
        let body = format!(
            "VERDICT: APPROVE\n\nNo new review ran: this head is {} of {}, which the review approved.",
            self.why.describe(),
            self.from
        );
        json!({"items": [{"type": "add_comment", "body": body}], "errors": []})
    }

    /// The status description, under GitHub's 140 characters.
    pub fn status(&self) -> String {
        format!(
            "Approval of {} carried forward: {}",
            &self.from[..12],
            self.why.word()
        )
    }
}

/// COMMIT's latest `review` status, by anyone.
pub(super) fn latest_status(api: &dyn Api, repo: &str, commit: &str) -> Result<Option<Value>> {
    // Newest first, as GitHub lists them.
    let statuses = api.list(&format!("repos/{repo}/commits/{commit}/statuses"))?;
    Ok(statuses
        .into_iter()
        .find(|s| s["context"] == STATUS_CONTEXT))
}

/// Whether the review approved COMMIT: its latest `review` status, as the
/// status job sets it, is `success` by the job token's bot.
fn approved(api: &dyn Api, repo: &str, commit: &str) -> Result<bool> {
    Ok(latest_status(api, repo, commit)?
        .is_some_and(|s| s["state"] == "success" && s["creator"]["login"] == BOT))
}

/// Runs git in the scratch repository DIR without the machine's or the
/// user's configuration, with STDIN, and returns its output.
fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Process::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .context("running git")?;
    ensure!(
        output.status.success(),
        "git {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

fn git_line(dir: &Path, args: &[&str]) -> Result<String> {
    let out = String::from_utf8(git(dir, args)?).context("git's output is not UTF-8")?;
    Ok(out.lines().next().unwrap_or_default().to_owned())
}

/// FILE formatted by RUSTFMT, run in DIR, which holds no configuration.
fn format(rustfmt: &Path, dir: &Path, file: &[u8]) -> Result<Vec<u8>> {
    let mut child = Process::new(rustfmt)
        .args(["--edition", RUSTFMT_EDITION, "--emit", "stdout"])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("running {}", rustfmt.display()))?;
    child
        .stdin
        .take()
        .context("rustfmt's input")?
        .write_all(file)
        .context("writing to rustfmt")?;
    let output = child.wait_with_output().context("running rustfmt")?;
    ensure!(output.status.success(), "rustfmt failed: {}", output.status);
    Ok(output.stdout)
}

/// Why HEAD carries BEFORE's approval, in the repository DIR holding both
/// and the base branch at BASE, or none. RUSTFMT formats, run in EMPTY.
pub fn compare(
    dir: &Path,
    before: &str,
    head: &str,
    base: &str,
    rustfmt: &Path,
    empty: &Path,
) -> Result<Option<Why>> {
    let approved_base = git_line(dir, &["merge-base", before, base])?;
    let head_base = git_line(dir, &["merge-base", head, base])?;
    // The approved changes onto the new head's base: a conflict is no
    // rebase this can carry.
    let merge_base = format!("--merge-base={approved_base}");
    let Ok(expected) = git_line(
        dir,
        &[
            "merge-tree",
            "--write-tree",
            &merge_base,
            &head_base,
            before,
        ],
    ) else {
        return Ok(None);
    };
    let tree = git_line(dir, &["rev-parse", &format!("{head}^{{tree}}")])?;
    if expected == tree {
        return Ok(Some(Why::Rebase));
    }
    // `:MODE MODE OLD NEW STATUS\0PATH\0` for each changed file.
    let raw = git(
        dir,
        &["diff-tree", "-r", "-z", "--no-renames", &expected, &tree],
    )?;
    let raw = String::from_utf8(raw).context("git's output is not UTF-8")?;
    let fields: Vec<&str> = raw.split_terminator('\0').collect();
    if fields.len() > 2 * MAX_FORMATTED_FILES {
        return Ok(None);
    }
    for pair in fields.chunks(2) {
        let [meta, path] = pair else {
            bail!("unexpected git diff-tree output");
        };
        let meta: Vec<&str> = meta.trim_start_matches(':').split(' ').collect();
        let [old_mode, new_mode, old, new, status] = meta[..] else {
            bail!("unexpected git diff-tree output");
        };
        if status != "M"
            || old_mode != REGULAR_FILE
            || new_mode != REGULAR_FILE
            || !path.ends_with(".rs")
        {
            return Ok(None);
        }
        let old = git(dir, &["cat-file", "blob", old])?;
        let new = git(dir, &["cat-file", "blob", new])?;
        if old.len().max(new.len()) > MAX_FORMATTED_BYTES {
            return Ok(None);
        }
        match format(rustfmt, empty, &old) {
            Ok(formatted) if formatted == new => {}
            _ => return Ok(None),
        }
    }
    Ok(Some(Why::Format))
}

/// The carry job: appends `from` and `why` to OUTPUT when HEAD_SHA carries
/// the approval of BEFORE, the pull request's previous head, and nothing
/// when it does not, so that the review runs.
pub fn carry(env: &dyn Fn(&str) -> String, api: &dyn Api, output: &Path) -> Result<()> {
    let (before, head, base) = (env("BEFORE"), env("HEAD_SHA"), env("BASE_REF"));
    ensure!(
        SHA.is_match(&before) && SHA.is_match(&head),
        "BEFORE and HEAD_SHA must be commit SHAs"
    );
    let repo = env("GITHUB_REPOSITORY");
    ensure!(
        super::REPO.is_match(&repo),
        "GITHUB_REPOSITORY must be OWNER/NAME"
    );
    let base_ref = format!("refs/heads/{base}");
    ensure!(
        !base.is_empty()
            && Process::new("git")
                .args(["check-ref-format", &base_ref])
                .status()
                .is_ok_and(|s| s.success()),
        "BASE_REF must be a branch name"
    );
    if !approved(api, &repo, &before)? {
        annotate(
            "notice",
            &format!("The review runs: the previous head {before} is not approved"),
        );
        return Ok(());
    }
    let server = match env("GITHUB_SERVER_URL") {
        server if server.is_empty() => "https://github.com".to_owned(),
        server => server.trim_end_matches('/').to_owned(),
    };
    ensure!(
        server.starts_with("https://"),
        "GITHUB_SERVER_URL must be https"
    );
    let scratch = tempfile::tempdir().context("creating a scratch directory")?;
    let (dir, empty) = (scratch.path().join("git"), scratch.path().join("empty"));
    std::fs::create_dir(&empty).context("creating an empty directory")?;
    let url = format!("{server}/{repo}");
    let fetched = git(scratch.path(), &["init", "--quiet", "--bare", "git"]).and_then(|_| {
        git(
            &dir,
            &[
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.https.allow=always",
                "-c",
                &format!("credential.helper={CREDENTIAL_HELPER}"),
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                "--",
                &url,
                &format!("+{base_ref}:{BASE_REF}"),
                &before,
                &head,
            ],
        )
    });
    let why = fetched.and_then(|_| {
        let rustfmt = Path::new("rustfmt");
        compare(&dir, &before, &head, BASE_REF, rustfmt, &empty)
    });
    let why = match why {
        Ok(Some(why)) => why,
        Ok(None) => {
            annotate(
                "notice",
                "The review runs: the new head is neither a rebase nor rustfmt's output of the approved one",
            );
            return Ok(());
        }
        Err(err) => {
            annotate(
                "notice",
                &format!("The review runs: comparing with the approved head failed: {err:#}"),
            );
            return Ok(());
        }
    };
    annotate(
        "notice",
        &format!("Approval of {before} carried to {head}: {}", why.describe()),
    );
    std::fs::OpenOptions::new()
        .append(true)
        .open(output)
        .and_then(|mut file| writeln!(file, "from={before}\nwhy={}", why.word()))
        .with_context(|| format!("writing {}", output.display()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn run(dir: &Path, args: &[&str]) -> String {
        let out = Process::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    type Files<'a> = &'a [(&'a str, &'a str)];

    /// Writes FILES and commits them on the current branch.
    fn commit(dir: &Path, files: Files) -> String {
        for (name, text) in files {
            std::fs::write(dir.join(name), text).unwrap();
        }
        run(dir, &["add", "-A"]);
        run(dir, &["commit", "--quiet", "-m", "c"]);
        run(dir, &["rev-parse", "HEAD"])
    }

    #[test]
    fn only_a_rebase_or_formatter_output_of_the_approved_head_carries() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("r");
        let empty = scratch.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::create_dir(&dir).unwrap();
        // A stand-in for rustfmt: collapses runs of spaces, so a test of
        // the mechanism needs no toolchain.
        let fmt = scratch.path().join("fmt");
        std::fs::write(&fmt, "#!/bin/sh\nexec tr -s ' '\n").unwrap();
        std::fs::set_permissions(&fmt, std::fs::Permissions::from_mode(0o755)).unwrap();

        run(&dir, &["init", "--quiet", "-b", "main"]);
        let root = commit(&dir, &[("a.rs", "fn a() {}\n"), ("b.py", "x = 1\n")]);
        run(&dir, &["checkout", "--quiet", "-b", "pr"]);
        let approved = commit(&dir, &[("a.rs", "fn a() { b(); }\n")]);
        run(&dir, &["checkout", "--quiet", "main"]);
        let moved = commit(&dir, &[("b.py", "x = 2\n")]);

        // Each case: the new head, built from `root` or `moved` with the
        // files given, and what it carries.
        let cases: [(&str, &str, Files, Option<Why>); 7] = [
            (
                "rebased",
                &moved,
                &[("a.rs", "fn a() { b(); }\n")],
                Some(Why::Rebase),
            ),
            (
                "recommitted",
                &root,
                &[("a.rs", "fn a() { b(); }\n")],
                Some(Why::Rebase),
            ),
            (
                "spaces added, not the formatter's output",
                &root,
                &[("a.rs", "fn a() {  b();  }\n")],
                None,
            ),
            (
                "rebased, spaces added",
                &moved,
                &[("a.rs", "fn a()  { b(); }\n")],
                None,
            ),
            (
                "another change",
                &moved,
                &[("a.rs", "fn a() { c(); }\n")],
                None,
            ),
            (
                "a Python file's whitespace",
                &root,
                &[("a.rs", "fn a() { b(); }\n"), ("b.py", "x =  1\n")],
                None,
            ),
            (
                "a new Rust file",
                &root,
                &[("a.rs", "fn a() { b(); }\n"), ("c.rs", "fn c() {}\n")],
                None,
            ),
        ];
        for (name, start, files, want) in cases {
            run(&dir, &["checkout", "--quiet", "--detach", start]);
            let head = commit(&dir, files);
            let got = compare(&dir, &approved, &head, "main", &fmt, &empty).unwrap();
            assert_eq!(got, want, "{name}");
        }

        // The approved head itself badly formatted, and the new one the
        // formatter's output of it: carried, rebased or not.
        run(&dir, &["checkout", "--quiet", "--detach", &root]);
        let unformatted = commit(&dir, &[("a.rs", "fn a()  {  b(); }\n")]);
        for start in [&root, &moved] {
            run(&dir, &["checkout", "--quiet", "--detach", start]);
            let head = commit(&dir, &[("a.rs", "fn a() { b(); }\n")]);
            let got = compare(&dir, &unformatted, &head, "main", &fmt, &empty).unwrap();
            assert_eq!(got, Some(Why::Format), "{start}");
        }
        // A formatter that fails, or is missing, carries nothing.
        run(&dir, &["checkout", "--quiet", "--detach", &root]);
        let head = commit(&dir, &[("a.rs", "fn a() { b(); }\n")]);
        let missing = scratch.path().join("missing");
        let got = compare(&dir, &unformatted, &head, "main", &missing, &empty).unwrap();
        assert_eq!(got, None);
        // A conflicting rebase carries nothing either.
        run(&dir, &["checkout", "--quiet", "main"]);
        let conflicting = commit(&dir, &[("a.rs", "fn a() { d(); }\n")]);
        run(&dir, &["checkout", "--quiet", "--detach", &conflicting]);
        let head = commit(&dir, &[("a.rs", "fn a() { b(); }\n")]);
        let got = compare(&dir, &approved, &head, "main", &fmt, &empty).unwrap();
        assert_eq!(got, None);
    }

    #[derive(Default)]
    struct Statuses(Vec<Value>);

    impl Api for Statuses {
        fn get(&self, path: &str) -> Result<Value> {
            let path = path.split('?').next().unwrap();
            assert_eq!(
                path,
                format!("repos/o/r/commits/{}/statuses", "a".repeat(40))
            );
            Ok(json!(self.0))
        }

        fn post(&self, path: &str, _: &Value) -> Result<Value> {
            panic!("unexpected POST {path}")
        }
    }

    #[test]
    fn only_the_latest_review_status_by_the_bot_approves() {
        let status = |context: &str, state: &str, login: &str| json!({"context": context, "state": state, "creator": {"login": login}});
        let cases = [
            (vec![], false),
            (vec![status("review", "success", BOT)], true),
            (vec![status("ci", "success", BOT)], false),
            (vec![status("review", "success", "someone")], false),
            (vec![status("review", "failure", BOT)], false),
            (
                vec![
                    status("review", "failure", BOT),
                    status("review", "success", BOT),
                ],
                false,
            ),
            (
                vec![
                    status("ci", "failure", BOT),
                    status("review", "success", BOT),
                ],
                true,
            ),
        ];
        for (statuses, want) in cases {
            let api = Statuses(statuses.clone());
            assert_eq!(
                approved(&api, "o/r", &"a".repeat(40)).unwrap(),
                want,
                "{statuses:?}"
            );
        }
    }

    #[test]
    fn a_carried_approval_is_read_back_whole_or_refused() {
        let sha = "b".repeat(40);
        let read = |from: &str, why: &str| {
            let env: HashMap<&str, String> = [
                ("CARRIED_FROM", from.to_owned()),
                ("CARRIED_WHY", why.to_owned()),
            ]
            .into();
            Carried::read(&|key| env.get(key).cloned().unwrap_or_default())
        };
        assert_eq!(read("", "").unwrap(), None);
        let carried = read(&sha, "format").unwrap().unwrap();
        assert_eq!(carried.why, Why::Format);
        assert_eq!(
            carried.status(),
            "Approval of bbbbbbbbbbbb carried forward: format"
        );
        let body = carried.output()["items"][0]["body"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(body.starts_with("VERDICT: APPROVE\n\n"), "{body}");
        assert!(body.contains(&sha), "{body}");
        assert!(read(&sha, "").is_err());
        assert!(read(&sha, "rebase\n").is_err());
        assert!(read("main", "rebase").is_err());
    }
}
