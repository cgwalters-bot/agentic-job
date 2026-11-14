//! Trusted check and apply use the same replay and Git trial. The concrete
//! threat is an agent using a placeholder as a wildcard to recover arbitrary
//! base bytes (or make a privileged publisher apply a different tree).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use safe_outputs::apply::git::Git;
use safe_outputs::replay::{Literal, Receipt};

use super::{CREATE_PULL_REQUEST, Verdict};
use crate::policy::{Forge, Policy};
use crate::{exit::Exit, files};

pub fn check(
    verdict: &mut Verdict,
    outputs: &Path,
    policy: &Policy,
    literals: Option<&[Literal]>,
) -> Result<()> {
    let Some(literals) = literals else {
        return Ok(());
    };
    // Replacement and secondary carriers deliberately get no alternative
    // replay semantics. Their endpoint-bearing hand-backs must be regenerated.
    for info in verdict
        .secondary_patch
        .iter()
        .chain(verdict.patch.iter().filter(|p| p.commit_files.is_some()))
    {
        let bytes = files::read_regular(&outputs.join(&info.file), policy.max_patch_bytes)?;
        ensure!(
            !String::from_utf8_lossy(&bytes).contains(safe_outputs::replay::PLACEHOLDER),
            "endpoint replay is unsupported for replacement/secondary patches; regenerate without endpoint substitutions"
        );
    }
    let Some(info) = verdict.patch.as_mut().filter(|p| p.commit_files.is_none()) else {
        return Ok(());
    };
    let bytes = files::read_regular(&outputs.join(&info.file), policy.max_patch_bytes)?;
    let text = std::str::from_utf8(&bytes)?;
    if !text.lines().any(|line| {
        matches!(line.as_bytes().first(), Some(b'-' | b' '))
            && line.contains(safe_outputs::replay::PLACEHOLDER)
    }) {
        return Ok(());
    }
    ensure!(
        policy.forge == Forge::Github
            && policy
                .native_handlers
                .iter()
                .any(|name| name == CREATE_PULL_REQUEST)
            && verdict
                .items
                .iter()
                .all(|item| super::item_type(item) != super::PUSH_TO_PULL_REQUEST_BRANCH),
        "endpoint replay requires the primary native GitHub create_pull_request publisher; legacy, push and other forge paths are unsupported"
    );
    let mut receipt = Receipt {
        patch_sha256: safe_outputs::replay::digest(&bytes),
        base_commit: info.base_commit.clone(),
        literals: literals.to_vec(),
        tree: String::new(),
    };
    receipt.tree = trial(policy, &bytes, &receipt, &info.files)?;
    info.replay = Some(receipt);
    Ok(())
}

pub fn trial(policy: &Policy, patch: &[u8], receipt: &Receipt, files: &[String]) -> Result<String> {
    // This fetch is independent of the agent's checkout and any base evidence
    // it supplied. Ancestry is checked before reading a single old-side byte.
    let dir = tempfile::tempdir()?;
    let git = Git {
        authorization: String::new(),
        token: "",
        extra_secrets: Vec::new(),
        committer: ("check", "check@example.invalid"),
    };
    let run = |args: &[&str], input| {
        git.run_bounded(dir.path(), args, input).map_err(|_| anyhow::anyhow!("endpoint replay Git validation failed; verify the declared base is on the target branch and regenerate the patch"))
    };
    run(&["init", "-q"], None)?;
    run(
        &[
            "fetch",
            "-q",
            "--no-tags",
            "--",
            &policy.clone_url,
            &format!("refs/heads/{}", policy.base),
        ],
        None,
    )?;
    run(
        &[
            "merge-base",
            "--is-ancestor",
            &receipt.base_commit,
            "FETCH_HEAD",
        ],
        None,
    )?;
    run(&["checkout", "-q", "--detach", &receipt.base_commit], None)?;
    let recovered = git.recover(dir.path(), patch, receipt)?;
    run(
        &["am", "-q", "--keep-cr", "--committer-date-is-author-date"],
        Some(recovered.as_bytes()),
    )?;
    let changed = run(
        &[
            "diff",
            "--no-renames",
            "--name-only",
            &receipt.base_commit,
            "HEAD",
        ],
        None,
    )?;
    let mut changed: Vec<_> = changed.lines().collect();
    let mut checked: Vec<_> = files.iter().map(String::as_str).collect();
    changed.sort_unstable();
    checked.sort_unstable();
    ensure!(
        changed == checked,
        "endpoint replay changes paths other than check accepted"
    );
    Ok(run(&["rev-parse", "HEAD^{tree}"], None)?.trim().to_owned())
}

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long)]
    pub checked: PathBuf,
}

pub fn run(args: &Args) -> Result<Exit> {
    let upload = crate::apply::upload(&args.checked);
    let report = safe_outputs::apply::read_report(&upload)?;
    ensure!(
        report.ok && report.errors.is_empty(),
        "endpoint replay requires a successful checked report"
    );
    let patch = report
        .patch
        .context("endpoint replay requires a checked primary patch")?;
    let receipt = patch.replay.context("missing trusted replay receipt")?;
    ensure!(
        receipt.base_commit == patch.base_commit && patch.commit_files.is_none(),
        "replay base/carrier differs from checked report"
    );
    let policy = <Policy as crate::policy::Load>::load(&args.checked.join("policy.json"))?;
    ensure!(
        policy.forge == Forge::Github
            && policy
                .native_handlers
                .iter()
                .any(|name| name == CREATE_PULL_REQUEST),
        "endpoint replay requires native GitHub publication"
    );
    ensure!(
        safe_outputs::check::is_patch_file_name(&patch.file),
        "invalid replay patch filename"
    );
    let bytes = files::read_regular(&args.checked.join(&patch.file), policy.max_patch_bytes)?;
    let rules = policy
        .safe_outputs
        .create_pull_request
        .as_ref()
        .context("missing pull request bounds")?;
    let reading = safe_outputs::check::read_patch(
        std::str::from_utf8(&bytes)?,
        &rules.rules(),
        &patch.base_commit,
    );
    ensure!(
        reading.problems.is_empty() && reading.files == patch.files,
        "replay patch differs from checked paths/shape"
    );
    let tree = trial(&policy, &bytes, &receipt, &patch.files)?;
    ensure!(
        tree == receipt.tree,
        "endpoint replay trial differs from check's tree"
    );
    println!("tree={tree}");
    Ok(Exit::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::{INFERENCE_ADDRESS, INFERENCE_PLACEHOLDER, Redactor};
    use crate::run::{
        log::Shared,
        upload::{Gate, Staging},
    };
    use serde_json::json;

    const ADDRESS: &str = "inference.example.test:8443";
    const NAME: &str = "aw-agent-run-7.patch";

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
            ])
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(output.status.success(), "git failed: {args:?}");
        String::from_utf8(output.stdout).unwrap()
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        repo: PathBuf,
        staging: Staging,
        policy: Policy,
        base: String,
        raw: String,
        collected: PathBuf,
    }

    impl Fixture {
        fn new(deletion: bool, endpoint: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let repo = dir.path().join("repo");
            std::fs::create_dir(&repo).unwrap();
            git(&repo, &["init", "-q", "-b", "main"]);
            let address = if endpoint {
                ADDRESS
            } else {
                "ordinary fixture value"
            };
            std::fs::write(
                repo.join("sample.txt"),
                format!("before\nurl={address}\nafter\n"),
            )
            .unwrap();
            git(&repo, &["add", "."]);
            git(&repo, &["commit", "-qm", "Base"]);
            let base = git(&repo, &["rev-parse", "HEAD"]).trim().to_owned();
            if deletion {
                std::fs::remove_file(repo.join("sample.txt")).unwrap();
            } else {
                std::fs::write(
                    repo.join("sample.txt"),
                    format!("before\nurl={address}\nnew={address}\nafter\n"),
                )
                .unwrap();
            }
            git(&repo, &["add", "-A"]);
            git(&repo, &["commit", "-qm", "Change"]);
            let raw = git(&repo, &["format-patch", "--stdout", "--no-renames", "-1"]);
            let (first, rest) = raw.split_once('\n').unwrap();
            let raw = format!("{first}\nX-GH-AW-Base-Commit: {base}\n{rest}");
            git(&repo, &["reset", "--hard", &base]);
            let staging = Staging::create(dir.path()).unwrap();
            std::fs::create_dir(staging.safe_outputs()).unwrap();
            let mut policy = crate::policy::tests::policy();
            policy.repo = "example-org/example".to_owned();
            policy.clone_url = repo.to_str().unwrap().to_owned();
            policy.base = "main".to_owned();
            policy.native_handlers = vec![CREATE_PULL_REQUEST.to_owned()];
            std::fs::write(staging.safe_outputs().join(NAME), &raw).unwrap();
            std::fs::write(
                staging.safe_outputs().join("base.json"),
                json!({"repo": policy.repo, "ref": policy.base, "commit": base}).to_string(),
            )
            .unwrap();
            std::fs::write(staging.safe_outputs().join("outputs.jsonl"), json!({"type": CREATE_PULL_REQUEST, "title": "Change", "body": "Regression coverage", "branch": "agent-run-7"}).to_string()).unwrap();
            let collected = dir.path().join("collected.json");
            Self {
                _dir: dir,
                repo,
                staging,
                policy,
                base,
                raw,
                collected,
            }
        }

        fn redact_and_collect(&self) -> String {
            let redactor =
                Shared::new(Redactor::new_named([(INFERENCE_ADDRESS, ADDRESS)]).unwrap());
            self.staging.redact_handback(&redactor).unwrap();
            self.staging
                .check(
                    Gate {
                        ended: true,
                        fake_agent: false,
                    },
                    &redactor,
                )
                .unwrap();
            let collected =
                crate::collect::collect_dir(&self.staging.safe_outputs(), &self.policy).unwrap();
            assert!(collected.errors.is_empty());
            std::fs::write(&self.collected, serde_json::to_vec(&collected).unwrap()).unwrap();
            std::fs::read_to_string(self.staging.safe_outputs().join(NAME)).unwrap()
        }

        fn verdict(&self) -> Verdict {
            let verdict = crate::check::check_run_outputs(
                &self.staging.safe_outputs(),
                &self.collected,
                &self.policy,
                "7",
            )
            .unwrap();
            assert!(verdict.ok, "{:?}", verdict.errors);
            verdict
        }
    }

    #[test]
    fn endpoint_replay_collection_check_trial_and_real_push() {
        for deletion in [true, false] {
            let f = Fixture::new(deletion, true);
            let patch = f.redact_and_collect();
            assert!(patch.contains(INFERENCE_PLACEHOLDER) && !patch.contains(ADDRESS));
            let mut verdict = f.verdict();
            let literals = [Literal::new(ADDRESS).unwrap()];
            check(
                &mut verdict,
                &f.staging.safe_outputs(),
                &f.policy,
                Some(&literals),
            )
            .unwrap();
            let info = verdict.patch.as_ref().unwrap();
            let receipt = info.replay.as_ref().unwrap();
            let serialized = serde_json::to_string(&verdict).unwrap();
            assert!(!serialized.contains(ADDRESS));
            assert_eq!(
                trial(&f.policy, patch.as_bytes(), receipt, &info.files).unwrap(),
                receipt.tree
            );
            let fork = f._dir.path().join("fork.git");
            git(
                f._dir.path(),
                &[
                    "clone",
                    "--bare",
                    "--quiet",
                    f.repo.to_str().unwrap(),
                    fork.to_str().unwrap(),
                ],
            );
            let g = Git {
                authorization: String::new(),
                token: "",
                extra_secrets: Vec::new(),
                committer: ("check", "check@example.invalid"),
            };
            let push = safe_outputs::apply::git::Push {
                from: f.repo.to_str().unwrap(),
                base: "main",
                base_commit: &f.base,
                to: fork.to_str().unwrap(),
                branch: "agent-run-7",
                patch: patch.as_bytes(),
                files: &info.files,
                head: None,
                committer: None,
                at_author_date: true,
                max_changed_kb: None,
            };
            g.push_replaying(&push, None, Some(receipt)).unwrap();
            assert_eq!(
                git(&fork, &["rev-parse", "agent-run-7^{tree}"]).trim(),
                receipt.tree
            );
            if !deletion {
                let content = git(&fork, &["show", "agent-run-7:sample.txt"]);
                assert!(content.contains(&format!("url={ADDRESS}\n")));
                assert!(content.contains(&format!("new={INFERENCE_PLACEHOLDER}\n")));
            }
            // Artifact bytes did not change, including after privileged replay.
            assert_eq!(
                std::fs::read_to_string(f.staging.safe_outputs().join(NAME)).unwrap(),
                patch
            );
            let mut wrong = receipt.clone();
            wrong.tree = "0".repeat(40);
            assert!(g.push_replaying(&push, None, Some(&wrong)).is_err());
            wrong = receipt.clone();
            wrong.patch_sha256 = "0".repeat(64);
            assert!(g.push_replaying(&push, None, Some(&wrong)).is_err());
            wrong = receipt.clone();
            wrong.base_commit = "0".repeat(40);
            assert!(g.push_replaying(&push, None, Some(&wrong)).is_err());
        }
    }

    #[test]
    fn endpoint_replay_refuses_forgery_and_preserves_unaffected_patches() {
        let f = Fixture::new(false, true);
        let patch = f.redact_and_collect();
        let literals = [Literal::new(ADDRESS).unwrap()];
        let base = format!("before\nurl={ADDRESS}\nafter\n");
        for (case, text, evidence, base_commit) in [
            (
                "surrounding bytes",
                patch.replace(" url=", " forged="),
                literals.to_vec(),
                f.base.clone(),
            ),
            (
                "coordinate",
                patch.replace("@@ -1,3 +1,4 @@", "@@ -2,3 +2,4 @@"),
                literals.to_vec(),
                f.base.clone(),
            ),
            (
                "new coordinate",
                patch.replace("@@ -1,3 +1,4 @@", "@@ -1,3 +2,4 @@"),
                literals.to_vec(),
                f.base.clone(),
            ),
            (
                "traversal",
                patch.replace("sample.txt", "../sample.txt"),
                literals.to_vec(),
                f.base.clone(),
            ),
            (
                "different path",
                patch.replace("sample.txt", "other.txt"),
                literals.to_vec(),
                f.base.clone(),
            ),
            (
                "forged provenance",
                patch.clone(),
                vec![Literal::new("another.example.test:8443").unwrap()],
                f.base.clone(),
            ),
            ("missing provenance", patch.clone(), vec![], f.base.clone()),
            (
                "wrong base",
                patch.clone(),
                literals.to_vec(),
                "0".repeat(40),
            ),
            (
                "malformed hunk",
                patch.replace("@@ -1,3 +1,4 @@", "@@ -1,4 +1,4 @@"),
                literals.to_vec(),
                f.base.clone(),
            ),
        ] {
            let result = safe_outputs::replay::recover(&text, &base_commit, &evidence, |path| {
                ensure!(path == "sample.txt", "unknown base path");
                Ok(base.clone())
            });
            assert!(result.is_err(), "{case}");
            assert!(!result.unwrap_err().to_string().contains(ADDRESS));
        }
        let mut verdict = f.verdict();
        let mut secondary = verdict.clone();
        secondary.secondary_patch = secondary.patch.take();
        assert!(
            check(
                &mut secondary,
                &f.staging.safe_outputs(),
                &f.policy,
                Some(&literals)
            )
            .is_err()
        );
        let mut replacement = verdict.clone();
        replacement.patch.as_mut().unwrap().commit_files =
            Some(vec![vec!["sample.txt".to_owned()]]);
        assert!(
            check(
                &mut replacement,
                &f.staging.safe_outputs(),
                &f.policy,
                Some(&literals)
            )
            .is_err()
        );
        let mut legacy = f.policy.clone();
        legacy.native_handlers.clear();
        assert!(
            check(
                &mut verdict,
                &f.staging.safe_outputs(),
                &legacy,
                Some(&literals)
            )
            .is_err()
        );
        check(&mut verdict, &f.staging.safe_outputs(), &f.policy, None).unwrap();
        assert!(verdict.patch.unwrap().replay.is_none());

        let ordinary = Fixture::new(false, false);
        assert_eq!(ordinary.redact_and_collect(), ordinary.raw);
        let mut verdict = ordinary.verdict();
        check(
            &mut verdict,
            &ordinary.staging.safe_outputs(),
            &ordinary.policy,
            Some(&literals),
        )
        .unwrap();
        assert!(verdict.patch.unwrap().replay.is_none());
    }

    #[test]
    fn endpoint_replay_never_hides_overlapping_credentials_or_trusts_agent_evidence() {
        let f = Fixture::new(true, true);
        let redactor = Shared::new(
            Redactor::new_named([
                (INFERENCE_ADDRESS, ADDRESS),
                ("provider API key", "example.test:8443"),
            ])
            .unwrap(),
        );
        let error = f.staging.redact_handback(&redactor).unwrap_err();
        assert!(error.to_string().contains("provider API key"));
        assert!(!error.to_string().contains(ADDRESS));
        assert_eq!(
            std::fs::read_to_string(f.staging.safe_outputs().join(NAME)).unwrap(),
            f.raw
        );

        f.redact_and_collect();
        std::fs::write(
            f.staging.safe_outputs().join("public-base.json"),
            json!({"replay": [Literal::new(ADDRESS).unwrap()]}).to_string(),
        )
        .unwrap();
        let verdict = crate::check::check_run_outputs(
            &f.staging.safe_outputs(),
            &f.collected,
            &f.policy,
            "7",
        )
        .unwrap();
        assert!(!verdict.ok && verdict.errors.iter().any(|e| e.contains("unexpected file")));
    }

    #[test]
    fn endpoint_replay_refuses_base_not_on_target_branch() {
        let f = Fixture::new(true, true);
        let patch = f.redact_and_collect();
        let receipt = Receipt {
            patch_sha256: safe_outputs::replay::digest(patch.as_bytes()),
            base_commit: f.base.clone(),
            literals: vec![Literal::new(ADDRESS).unwrap()],
            tree: String::new(),
        };
        git(&f.repo, &["checkout", "--orphan", "unrelated"]);
        git(&f.repo, &["commit", "--allow-empty", "-qm", "Unrelated"]);
        git(&f.repo, &["branch", "-f", "main", "HEAD"]);
        let error = trial(
            &f.policy,
            patch.as_bytes(),
            &receipt,
            &["sample.txt".to_owned()],
        )
        .unwrap_err();
        assert!(!error.to_string().contains(ADDRESS));
    }

    #[test]
    fn endpoint_replay_trusted_capture_check_report_and_apply_cli() {
        use crate::policy::Load;
        let f = Fixture::new(true, true);
        f.redact_and_collect();
        let config = f._dir.path().join("config.toml");
        std::fs::write(&config, format!("[commit]\nreplay-redacted-endpoints = true\n[inference]\nurl = 'http://{ADDRESS}'\nregister = 'plain'\n")).unwrap();
        let policy = f._dir.path().join("policy.json");
        std::fs::write(&policy, serde_json::to_vec(&f.policy).unwrap()).unwrap();
        let evidence = f._dir.path().join("public-base.json");
        super::super::base::run(&super::super::base::Args {
            config: Some(config),
            policy: policy.clone(),
            run_id: "7".to_owned(),
            output: evidence.clone(),
        })
        .unwrap();
        let evidence_text = std::fs::read_to_string(&evidence).unwrap();
        assert!(!evidence_text.contains(ADDRESS));
        let checked = f._dir.path().join("checked");
        std::fs::create_dir(&checked).unwrap();
        let report = checked.join("report.json");
        let args = super::super::Args {
            policy: policy.clone(),
            outputs: f.staging.safe_outputs(),
            collected: f.collected.clone(),
            report: Some(report.clone()),
            run_id: Some("7".to_owned()),
            base_secret_evidence: Some(evidence),
            continuation_context: None,
            run_attempt: None,
            comment_repo: None,
            comment_target: None,
            review_head: None,
            run_summary: None,
        };
        assert_eq!(super::super::run(&args).unwrap(), Exit::Success);
        let report_text = std::fs::read_to_string(&report).unwrap();
        assert!(!report_text.contains(ADDRESS));
        std::fs::copy(&policy, checked.join("policy.json")).unwrap();
        std::fs::copy(f.staging.safe_outputs().join(NAME), checked.join(NAME)).unwrap();
        assert_eq!(
            run(&Args {
                checked: checked.clone()
            })
            .unwrap(),
            Exit::Success
        );
        // The declared policy, not an agent's checkout, owns the fetched base.
        assert_eq!(Policy::load(&policy).unwrap().clone_url, f.policy.clone_url);
        let mut bytes = std::fs::read(checked.join(NAME)).unwrap();
        bytes.push(b'\n');
        std::fs::write(checked.join(NAME), bytes).unwrap();
        assert!(run(&Args { checked }).is_err());
    }
}
