//! Apply's routing guard, before either publisher can write. Only replacement
//! series have a shared recovery/application boundary so far. Other paths keep
//! their ordinary trial: literal placeholder text need not mean redaction.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use safe_outputs::apply::{ReportPatch, read_report, recover};

use crate::exit::Exit;
use crate::policy::{Load, Policy};
use crate::workflow_commands::escaped;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// The check job's authenticated upload directory
    #[arg(long)]
    pub checked: PathBuf,
    /// Trusted policy.json
    #[arg(long)]
    pub policy: PathBuf,
    /// Trusted caller's link to the retained checked artifact
    #[arg(long)]
    pub artifact_url: String,
}

fn patch_text(dir: &Path, patch: &ReportPatch, max: u64) -> Result<String> {
    let mut parts = Path::new(&patch.file).components();
    ensure!(
        matches!(parts.next(), Some(Component::Normal(_))) && parts.next().is_none(),
        "recovery preflight requires one plain patch filename"
    );
    let bytes = super::read_checked(&dir.join(&patch.file), max)?;
    ensure!(
        bytes.len() == patch.bytes,
        "recovery preflight patch size changed"
    );
    String::from_utf8(bytes).context("recovery preflight requires UTF-8")
}

pub fn run(args: &Args) -> Result<Exit> {
    let result = inspect(args);
    // Even a malformed producer JSON can appear in serde's error. Nothing
    // from the input, nor from a preimage, belongs in this guard's diagnostic.
    let (replacement_recovery, added) = result.map_err(|_| {
        anyhow::anyhow!(
            "unsupported or invalid inference-address recovery input; no outputs published; recover the original checked hand-back at {}",
            escaped(&args.artifact_url)
        )
    })?;
    if added > 0 {
        eprintln!(
            "warning: patch adds {added} inference-address placeholders; they remain redacted and require draft review"
        );
    }
    println!("replacement-recovery={replacement_recovery}\nadded-placeholders={added}");
    Ok(Exit::Success)
}

fn inspect(args: &Args) -> Result<(bool, usize)> {
    let policy = Policy::load(&args.policy)?;
    let report = read_report(&super::upload(&args.checked))?;
    ensure!(
        report.ok && report.errors.is_empty(),
        "check refused this hand-back"
    );
    let mut replacement_recovery = false;
    let mut added = 0;
    if let Some(patch) = &report.patch {
        let text = patch_text(&args.checked, patch, policy.max_patch_bytes)?;
        if patch.commit_files.is_some() {
            let series: safe_outputs::check::replacement::Replacement =
                serde_json::from_str(&text)?;
            for mail in &series.commits {
                let counts = recover::placeholders(mail);
                replacement_recovery |= counts.old > 0;
                added += counts.added;
            }
            ensure!(
                !replacement_recovery || policy.forge == safe_outputs::Forge::Github,
                "replacement preparation requires GitHub preimages"
            );
        } else {
            let counts = recover::placeholders(&text);
            added += counts.added;
        }
    }
    if let Some(patch) = &report.secondary_patch {
        let max = policy
            .secondary_pull_request
            .as_ref()
            .context("secondary patch without policy")?
            .max_patch_bytes;
        let text = patch_text(&args.checked.join(super::secondary::PATCH_DIR), patch, max)?;
        let counts = recover::placeholders(&text);
        added += counts.added;
    }
    // Do not let an explicit readiness request undo the automatic draft gate.
    if added > 0 {
        ensure!(
            !report.items.iter().any(|item| {
                item.get("type").and_then(serde_json::Value::as_str)
                    == Some("mark_pull_request_as_ready_for_review")
                    // A push can target an already-ready PR. The automatic
                    // readiness opt-in is not a pre-publication draft guarantee.
                    // Refuse until this path can enforce draft before pushing.
                    || item.get("type").and_then(serde_json::Value::as_str)
                        == Some("push_to_pull_request_branch")
                    || (item.get("type").and_then(serde_json::Value::as_str)
                        == Some("update_pull_request")
                        && item.get("draft") == Some(&serde_json::Value::Bool(false)))
            }),
            "added placeholders cannot be pushed or combined with a readiness request"
        );
    }
    Ok((replacement_recovery, added))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn routing_refuses_unsupported_recovery_and_keeps_only_safe_counts() {
        for (kind, old, added, private, ready, accepted) in [
            ("ordinary", false, false, false, false, true),
            ("ordinary", true, false, false, false, true),
            ("secondary", true, false, false, false, true),
            ("secondary", false, true, false, false, true),
            ("replacement", true, false, false, false, true),
            ("replacement", true, true, false, false, true),
            ("replacement", true, false, true, false, true),
            ("replacement", false, false, true, false, true),
            ("ordinary", false, true, false, true, false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut policy = if kind == "secondary" {
                crate::policy::tests::policy()
            } else {
                crate::policy::tests::push_policy()
            };
            policy.private = private;
            if kind == "secondary" {
                policy.secondary_pull_request = Some(crate::policy::Secondary {
                    repo: "example-org/secondary".into(),
                    clone_url: "https://github.com/example-org/secondary".into(),
                    base: "main".into(),
                    branch_prefix: "secondary/".into(),
                    max: 1,
                    max_patch_bytes: 1 << 20,
                    max_patch_files: 50,
                    protected_files: Vec::new(),
                    protect_top_level_dot_folders: true,
                    protected_paths: Vec::new(),
                    unprotected_dot_folders: Vec::new(),
                });
            }
            let mail = format!(
                "From test\nSubject: placeholder in message <inference-address>\n\n\
                 diff --git a/config b/config\n--- a/config\n+++ b/config\n@@ -1 +1 @@\n-{}\n+{}\n",
                if old { "<inference-address>" } else { "before" },
                if added {
                    "<inference-address>"
                } else {
                    "after"
                },
            );
            let content = if kind == "replacement" {
                json!({"base_commit": "1".repeat(40), "commits": [mail]}).to_string()
            } else {
                mail
            };
            let patch = json!({"file": "change.patch", "bytes": content.len(),
                "base_commit": "1".repeat(40), "files": ["config"],
                "commit_files": if kind == "replacement" { json!([["config"]]) } else { json!(null) }});
            let mut report = json!({"ok":true, "errors":[], "items":[]});
            if ready {
                report["items"] = json!([{"type":"mark_pull_request_as_ready_for_review"}]);
            }
            let patch_dir = if kind == "secondary" {
                report["secondary_patch"] = patch;
                let path = dir.path().join("secondary");
                std::fs::create_dir(&path).unwrap();
                path
            } else {
                report["patch"] = patch;
                dir.path().to_owned()
            };
            std::fs::write(patch_dir.join("change.patch"), &content).unwrap();
            std::fs::write(dir.path().join("report.json"), report.to_string()).unwrap();
            let args = Args {
                checked: dir.path().to_owned(),
                policy: dir.path().join("policy.json"),
                artifact_url: "https://github.com/example-org/example/actions/runs/1/artifacts/2"
                    .into(),
            };
            std::fs::write(&args.policy, serde_json::to_vec(&policy).unwrap()).unwrap();
            let result = inspect(&args);
            assert_eq!(
                result.is_ok(),
                accepted,
                "{kind} old={old} added={added} private={private}: {result:?}"
            );
            if accepted {
                assert_eq!(
                    result.unwrap(),
                    (kind == "replacement" && old, usize::from(added))
                );
                if added {
                    report["items"] = json!([{"type":"push_to_pull_request_branch"}]);
                    std::fs::write(dir.path().join("report.json"), report.to_string()).unwrap();
                    assert!(
                        inspect(&args).is_err(),
                        "a push to an already-ready PR must not bypass draft enforcement"
                    );
                }
            } else {
                let error = run(&args).unwrap_err().to_string();
                assert!(error.contains(&args.artifact_url));
                assert!(!error.contains("<inference-address>"));
                assert_eq!(
                    std::fs::read_to_string(patch_dir.join("change.patch")).unwrap(),
                    content
                );
            }
        }
    }

    #[test]
    fn preflight_refuses_unsafe_patch_paths_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "../outside.patch",
            "/outside.patch",
            "secondary/change.patch",
        ] {
            let patch = ReportPatch {
                file: name.into(),
                bytes: 1,
                base_commit: "1".repeat(40),
                files: vec!["config".into()],
                commit_files: None,
            };
            assert!(patch_text(dir.path(), &patch, 1024).is_err());
        }
        std::os::unix::fs::symlink("missing", dir.path().join("change.patch")).unwrap();
        let patch = ReportPatch {
            file: "change.patch".into(),
            bytes: 1,
            base_commit: "1".repeat(40),
            files: vec!["config".into()],
            commit_files: None,
        };
        assert!(patch_text(dir.path(), &patch, 1024).is_err());
    }
}
