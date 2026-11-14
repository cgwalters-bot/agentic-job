//! Repository-scoped documentation exceptions through policy, collect and check.

use std::process::Command;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-job");

#[test]
fn documentation_exceptions_do_not_relax_other_boundaries() {
    let key = ["-----BEGIN ", "PRIVATE KEY", "-----\nfixture\n"].concat();
    for (name, files, default_error, enabled_error) in [
        (
            "documentation",
            vec![
                ("README.md", "readme\n"),
                ("AGENTS.md", "instructions\n"),
                ("docs/README.md", "nested\n"),
                ("docs/design.md", "design\n"),
            ],
            Some("AGENTS.md"),
            None,
        ),
        (
            "ordinary-docs",
            vec![("docs/design.md", "design\n")],
            None,
            None,
        ),
        (
            "other-protected-docs",
            vec![("CONTRIBUTING.md", "contribute\n")],
            Some("CONTRIBUTING.md"),
            Some("CONTRIBUTING.md"),
        ),
        (
            "manifest",
            vec![("package.json", "{}\n")],
            Some("package.json"),
            Some("package.json"),
        ),
        (
            "ci-beside-readme",
            vec![
                ("README.md", "readme\n"),
                (".github/workflows/test.yml", "on: push\n"),
            ],
            Some(".github"),
            Some(".github"),
        ),
        (
            "private-key",
            vec![("README.md", key.as_str())],
            Some("private key"),
            Some("private key"),
        ),
    ] {
        for (repo, exception) in [
            ("example/own", false),
            ("example/own", true),
            ("example/other", true),
        ] {
            // Fresh artifacts for every case: a missing report cannot reuse a prior verdict.
            let dir = tempfile::tempdir().unwrap();
            let work = dir.path().join("repo");
            let out = dir.path().join("out");
            std::fs::create_dir(&work).unwrap();
            std::fs::create_dir(&out).unwrap();
            let git = |args: &[&str]| {
                let result = Command::new("git")
                    .current_dir(&work)
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_AUTHOR_NAME", "Test")
                    .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
                    .env("GIT_COMMITTER_NAME", "Test")
                    .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
                    .args([
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-c",
                        "commit.gpgsign=false",
                    ])
                    .args(args)
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{args:?}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                String::from_utf8(result.stdout).unwrap()
            };
            git(&["init", "-q", "-b", "main"]);
            git(&["commit", "--allow-empty", "-qm", "Base"]);
            let base = git(&["rev-parse", "HEAD"]).trim().to_owned();
            for (path, content) in &files {
                let path = work.join(path);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, content).unwrap();
            }
            git(&["add", "."]);
            git(&["commit", "-qm", "Document"]);
            let patch = git(&[
                "format-patch",
                "-1",
                "--stdout",
                "--no-signature",
                "--no-renames",
            ])
            .replacen(
                "\nFrom:",
                &format!("\nX-GH-AW-Base-Commit: {base}\nFrom:"),
                1,
            );
            std::fs::write(out.join("aw-topic.patch"), patch).unwrap();
            std::fs::write(
                out.join("base.json"),
                json!({"repo":repo,"ref":"main","commit":base}).to_string(),
            )
            .unwrap();
            let item = json!({"type":"create_pull_request","title":"Document","body":"Update documentation.","branch":"topic"});
            std::fs::write(out.join("outputs.jsonl"), item.to_string()).unwrap();
            let bounds = dir.path().join("bounds.toml");
            let mut config = "hosts = ['github.com']\nrepos = ['example/*']\nbases = ['main']\nmax_outputs = 1\nmax_patch_bytes = 65536\nmax_patch_files = 10\n[github.outputs]\ncreate_pull_request = { max = 1 }\n".to_owned();
            if exception {
                config.push_str("[unprotected_files]\nrepos = ['example/own']\nfiles = ['README.md', 'AGENTS.md', 'docs/**']\n");
            }
            std::fs::write(&bounds, config).unwrap();
            let policy_path = dir.path().join("policy.json");
            let policy = Command::new(BIN)
                .args([
                    "policy",
                    "--repo",
                    repo,
                    "--clone-url",
                    &format!("https://github.com/{repo}"),
                    "--base",
                    "main",
                    "--kind",
                    "branch",
                    "--outputs",
                    "create_pull_request",
                    "--max-outputs",
                    "1",
                    "--allow",
                ])
                .arg(&bounds)
                .output()
                .unwrap();
            assert!(
                policy.status.success(),
                "{}",
                String::from_utf8_lossy(&policy.stderr)
            );
            std::fs::write(&policy_path, policy.stdout).unwrap();
            let collected = dir.path().join("collected.json");
            let collect = Command::new(BIN)
                .args(["collect", "--policy"])
                .arg(&policy_path)
                .arg("--outputs")
                .arg(&out)
                .arg("--collected")
                .arg(&collected)
                .output()
                .unwrap();
            assert!(
                collect.status.success(),
                "{}",
                String::from_utf8_lossy(&collect.stderr)
            );
            let report = dir.path().join("report.json");
            let check = Command::new(BIN)
                .args(["check", "--policy"])
                .arg(&policy_path)
                .arg("--outputs")
                .arg(&out)
                .arg("--collected")
                .arg(&collected)
                .arg("--report")
                .arg(&report)
                .output()
                .unwrap();
            let error = if exception && repo == "example/own" {
                enabled_error
            } else {
                default_error
            };
            let label = format!("{name}, {repo}, exception={exception}");
            assert_eq!(
                check.status.code(),
                Some(i32::from(error.is_some())),
                "{label}: {}",
                String::from_utf8_lossy(&check.stderr)
            );
            let verdict: Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
            assert_eq!(verdict["ok"], error.is_none(), "{label}: {verdict}");
            if let Some(error) = error {
                assert!(
                    verdict["errors"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|value| value.as_str().unwrap().contains(error)),
                    "{label}: {verdict}"
                );
            } else {
                assert_eq!(verdict["errors"], json!([]), "{label}");
                assert_eq!(verdict["items"], json!([item]), "{label}");
                let mut paths: Vec<_> = files.iter().map(|(path, _)| *path).collect();
                paths.sort_unstable();
                assert_eq!(verdict["patch"]["files"], json!(paths), "{label}");
                assert_eq!(verdict["patch"]["base_commit"], base, "{label}");
            }
        }
    }
}
