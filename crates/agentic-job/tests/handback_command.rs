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
