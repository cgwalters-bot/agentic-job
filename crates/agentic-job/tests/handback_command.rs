use std::path::Path;
use std::process::Command;

#[allow(clippy::unwrap_used)]
fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn ambient_git_overrides_cannot_mutate_the_checkout_or_add_trailers() {
    let home = tempfile::tempdir().unwrap();
    let repo = home.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["config", "user.name", "Test"]);
    git(&repo, &["config", "user.email", "test@example.org"]);
    std::fs::write(repo.join("file"), "base\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "Base"]);
    let base = git(&repo, &["rev-parse", "HEAD"]);
    for (text, subject) in [("one\n", "First"), ("two\n", "Second")] {
        std::fs::write(repo.join("file"), text).unwrap();
        git(&repo, &["commit", "-qam", subject]);
    }
    let expected: Vec<_> = ["HEAD~1", "HEAD"]
        .iter()
        .map(|id| {
            git(
                &repo,
                &[
                    "format-patch",
                    "--stdout",
                    "--no-signature",
                    "--no-renames",
                    "-1",
                    id,
                ],
            )
        })
        .collect();
    git(&repo, &["config", "format.signoff", "true"]);
    git(
        &repo,
        &["config", "format.from", "Other <other@example.org>"],
    );
    git(&repo, &["config", "format.subjectPrefix", "OTHER"]);
    git(&repo, &["config", "format.thread", "deep"]);
    let head = git(&repo, &["rev-parse", "HEAD"]);
    let branch = git(&repo, &["symbolic-ref", "HEAD"]);
    let run = |base: &str, range: &str| {
        Command::new(env!("CARGO_BIN_EXE_agentic-job"))
            .current_dir(&repo)
            .env("HOME", home.path())
            .env("GIT_DIR", repo.join(".git"))
            .env("GIT_WORK_TREE", &repo)
            .env("GIT_INDEX_FILE", repo.join(".git/index"))
            .args(["handback", "replace", "--base", base, range])
            .output()
            .unwrap()
    };
    let output = run(base.trim(), "HEAD~2..HEAD");
    assert!(output.status.success(), "{:?}", output);
    let path = home.path().join("out/replacement.json");
    let bytes = std::fs::read(&path).unwrap();
    let series: agentic_job::check::replacement::Replacement =
        serde_json::from_slice(&bytes).unwrap();
    assert_eq!(series.commits, expected);
    assert!(!run("HEAD", "HEAD~2..HEAD").status.success());
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert_eq!(git(&repo, &["rev-parse", "HEAD"]), head);
    assert_eq!(git(&repo, &["symbolic-ref", "HEAD"]), branch);
    assert_eq!(git(&repo, &["status", "--porcelain"]), "");
    assert!(!repo.join(".git/rebase-apply").exists());
}

/// A token of GitHub's shape, put together here so that this file holds
/// none itself: the way the brief tells an agent to write one.
fn fake_token() -> String {
    format!("gh{}_{}", "p", "a1B2".repeat(10))
}

#[test]
fn scan_names_where_a_secret_shaped_string_is_and_passes_one_built_from_parts() {
    let home = tempfile::tempdir().unwrap();
    let repo = home.path().join("repo");
    std::fs::create_dir_all(home.path().join("out")).unwrap();
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["config", "user.name", "Test"]);
    git(&repo, &["config", "user.email", "test@example.org"]);
    std::fs::write(repo.join("README"), "base\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "Base"]);
    let base = git(&repo, &["rev-parse", "HEAD"]);
    let base = base.trim();
    // One in a commit of the agent's own, one in a file it never added,
    // one in its requests.
    std::fs::write(
        repo.join("committed.rs"),
        format!("fn a() {{}}\nconst KEY: &str = \"{}\";\n", fake_token()),
    )
    .unwrap();
    git(&repo, &["add", "committed.rs"]);
    git(&repo, &["commit", "-qm", "Fixture"]);
    std::fs::write(repo.join("new.txt"), format!("{}\n", fake_token())).unwrap();
    // A name of that shape, which may not be shown either.
    let named = format!("{}.txt", fake_token());
    std::fs::write(repo.join(&named), "clean\n").unwrap();
    let outputs = home.path().join("out/safe-outputs.jsonl");
    std::fs::write(
        &outputs,
        format!(
            "{{\"type\":\"noop\"}}\n{{\"type\":\"noop\",\"message\":\"{}\"}}\n",
            fake_token()
        ),
    )
    .unwrap();
    // Escaped in JSON, which `run` decodes before its gate sees it.
    let outcome = home.path().join("out/outcome.json");
    let escaped = fake_token().replacen('g', "\\u0067", 1);
    std::fs::write(&outcome, format!("{{\"summary\":\"{escaped}\"}}\n")).unwrap();
    let scan = || {
        Command::new(env!("CARGO_BIN_EXE_agentic-job"))
            .current_dir(&repo)
            .env("HOME", home.path())
            .args(["handback", "scan", "--base", base])
            .output()
            .unwrap()
    };

    let output = scan();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    for want in [
        "committed.rs:2: matches `gh[posur]_",
        "new.txt:1: matches `gh[posur]_",
        &format!("{}:2: matches `gh[posur]_", outputs.display()),
        &format!("{}:1: matches `gh[posur]_", outcome.display()),
        "a file whose name is secret-shaped (a diff header): matches `gh[posur]_",
    ] {
        assert!(stdout.contains(want), "{want}\n{stdout}");
    }
    // The name is on both the `diff --git` and the `+++` line.
    assert_eq!(stdout.lines().count(), 6, "{stdout}");
    // The location, never the string.
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stdout.contains(&fake_token()) && !stderr.contains(&fake_token()));
    // The checkout's own index is left as it was.
    assert_eq!(
        git(&repo, &["status", "--porcelain"]),
        format!("?? {named}\n?? new.txt\n")
    );

    // The same values built from parts at run time pass.
    std::fs::write(
        repo.join("committed.rs"),
        "fn a() {}\nfn key() -> String { format!(\"gh{}_{}\", \"p\", \"a1B2\".repeat(10)) }\n",
    )
    .unwrap();
    std::fs::write(repo.join("new.txt"), "built at run time\n").unwrap();
    std::fs::remove_file(repo.join(&named)).unwrap();
    std::fs::write(&outputs, "{\"type\":\"noop\"}\n").unwrap();
    std::fs::write(&outcome, "{\"summary\":\"done\"}\n").unwrap();
    let output = scan();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
}
