//! Standalone adapter: caller-owned policy and files, shared check/plan/publish.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use safe_outputs::apply::{self, Op, Provenance, Target, Upload, gitlab::Gitlab, inline};
use safe_outputs::check::{self, Handback, Publishers, Trusted};
use safe_outputs::contract::Policy;
use safe_outputs::{
    CREATE_PULL_REQUEST, CREATE_REVIEW_COMMENT, Forge, PUSH_TO_PULL_REQUEST_BRANCH,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{MAX_LINES, MAX_OUTPUTS_BYTES, TOKEN_ENV, hash, read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextFile {
    policy: Policy,
    server: String,
    item: Option<u64>,
    item_kind: Option<apply::Kind>,
    review_head: Option<String>,
    run_url: String,
}

struct Native;

impl Publishers for Native {
    fn inline_comment(&self, item: &Map<String, Value>, forge: Forge) -> Result<()> {
        inline::fields(item, forge)
    }

    fn native_refusals(&self, _: &[Value], _: &[String]) -> Vec<String> {
        Vec::new()
    }
}

pub(super) struct Checked {
    context: ContextFile,
    files: BTreeMap<String, Vec<u8>>,
    ops: Vec<Op>,
    pub count: usize,
}

impl Checked {
    pub fn new(context: &[u8], bytes: &[u8], input: &Path) -> Result<Self> {
        let context: ContextFile =
            serde_json::from_slice(context).context("invalid GitLab context")?;
        let policy = &context.policy;
        ensure!(
            policy.forge == Forge::Gitlab,
            "context policy must select GitLab"
        );
        policy.validate().context("invalid trusted bounds")?;
        ensure!(policy.max_outputs <= 1000, "max_outputs exceeds 1000");
        ensure!(context.item.is_none_or(|n| n > 0), "item must be positive");
        ensure!(
            context.item.is_some() == context.item_kind.is_some(),
            "item and item_kind must be supplied together"
        );
        ensure!(
            bytes.split(|b| *b == b'\n').count() - usize::from(bytes.ends_with(b"\n")) <= MAX_LINES,
            "input exceeds {MAX_LINES} lines"
        );
        let config = serde_json::to_value(&policy.safe_outputs)?;
        let collected = safe_outputs::collect::collect_bytes(
            bytes,
            config.as_object().context("output bounds")?,
            Forge::Gitlab,
            &|host| {
                safe_outputs::link_domains()
                    .iter()
                    .any(|domain| host == domain || host.ends_with(&format!(".{domain}")))
            },
        )?;
        // Read only named patch inputs, never walk a producer-controlled tree.
        // Each is a bounded no-follow file; receipt digests bind the same bytes
        // used for both validation and planning.
        let dir = input.parent().unwrap_or(Path::new("."));
        let mut files = BTreeMap::new();
        for item in &collected.items {
            if matches!(
                check::item_type(item),
                CREATE_PULL_REQUEST | PUSH_TO_PULL_REQUEST_BRANCH
            ) {
                ensure!(files.is_empty(), "at most one patch operation is supported");
                let branch = item
                    .get("branch")
                    .and_then(Value::as_str)
                    .context("patch request needs branch")?;
                let name = check::patch_file_name(branch);
                ensure!(check::is_patch_file_name(&name), "invalid patch filename");
                files.insert(
                    name.clone(),
                    read(
                        &dir.join(name),
                        policy.max_patch_bytes.min(MAX_OUTPUTS_BYTES),
                    )?,
                );
                if !files.contains_key(check::BASE_FILE) {
                    files.insert(
                        check::BASE_FILE.into(),
                        read(&dir.join(check::BASE_FILE), super::MAX_CONTEXT_BYTES)?,
                    );
                }
            }
        }
        let checked = check::check(
            &Handback {
                outputs: Some(bytes),
                base: files.get(check::BASE_FILE).map(Vec::as_slice),
                patches: files
                    .iter()
                    .filter(|(name, _)| check::is_patch_file_name(name))
                    .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
                    .collect(),
                ..Default::default()
            },
            check::Collected {
                items: collected.items,
                errors: collected.errors,
            },
            policy,
            Trusted {
                comment: context.item.map(|n| (policy.repo.as_str(), n)),
                run_id: None,
            },
            &Native,
            |_| Vec::new(),
        );
        ensure!(
            checked.errors.is_empty(),
            "safe-output validation refused ({} errors)",
            checked.errors.len()
        );
        let inline_target = if checked
            .items
            .iter()
            .any(|item| check::item_type(item) == CREATE_REVIEW_COMMENT)
        {
            ensure!(
                context.item_kind == Some(apply::Kind::PullRequest),
                "inline comments require a merge request target"
            );
            Some(inline::checked_target(
                context.item.map(|n| (policy.repo.as_str(), n)),
                context.review_head.as_deref(),
                policy,
            )?)
        } else {
            None
        };
        let report = serde_json::to_vec(&json!({
            "ok": true, "errors": [], "items": checked.items,
            "patch": checked.patch, "inline_target": inline_target
        }))?;
        let target = Target {
            forge: apply::Forge::Gitlab,
            repo: &policy.repo,
            push_repo: match policy.push_repo.as_deref() {
                Some(fork) => Some(fork),
                None if policy.safe_outputs.accepts_own_branches(&policy.repo)? => {
                    Some(&policy.repo)
                }
                None => None,
            },
            comment_target: context.item,
            run_url: &context.run_url,
            status: None,
            provenance: Provenance {
                name: "safe-outputs",
                status_context: "safe-outputs",
                committer: ("safe-outputs", "noreply@example.com"),
            },
        };
        let read_upload = |path: &Path, limit: u64| -> Result<Vec<u8>> {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .context("invalid upload name")?;
            let bytes = if name == apply::REPORT_FILE {
                &report
            } else {
                files.get(name).context("missing patch input")?
            };
            ensure!(bytes.len() as u64 <= limit, "upload exceeds byte limit");
            Ok(bytes.clone())
        };
        let ops = apply::plan(
            &Upload {
                dir: &PathBuf::new(),
                read: &read_upload,
            },
            policy,
            &target,
        )
        .map_err(|errors| anyhow::anyhow!("GitLab plan refused ({} errors)", errors.len()))?;
        Ok(Self {
            context,
            files,
            ops,
            count: checked.items.len(),
        })
    }

    pub fn digests(&self) -> BTreeMap<String, String> {
        self.files
            .iter()
            .map(|(name, bytes)| (name.clone(), hash(bytes)))
            .collect()
    }

    pub fn apply(self) -> Result<()> {
        if !self.ops.is_empty() {
            let token = std::env::var(TOKEN_ENV).context("apply requires SAFE_OUTPUTS_TOKEN")?;
            ensure!(
                !token.trim().is_empty(),
                "apply requires a nonempty SAFE_OUTPUTS_TOKEN"
            );
            let policy = &self.context.policy;
            let publisher = Gitlab::new(
                &self.context.server,
                &policy.repo,
                token,
                &policy.allow_http,
            )?
            .commenting_on(self.context.item_kind)
            .accepting_own_branches(
                policy.push_repo.is_none()
                    && policy.safe_outputs.accepts_own_branches(&policy.repo)?,
            );
            for url in apply::publish(&self.ops, &publisher)? {
                println!("{url}");
            }
        }
        println!("applied {} requests", self.count);
        Ok(())
    }
}
