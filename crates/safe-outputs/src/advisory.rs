//! Head-bound advisory prose, not a review verdict or classifier result.
//!
//! The threat is stale or redirected prose borrowing the apply credential.
//! Only trusted policy selects this contract; producer fields never select it.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::contract::{COMMIT_RE, Kind, PULL_NUMBER_RE, Policy};

pub const MAX_PROSE_BYTES: usize = 46_000;
pub const MAX_FINAL_BYTES: usize = 48_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    pub repo: String,
    pub pull: u64,
    pub base: String,
    pub head: String,
}

impl Advisory {
    pub fn validate(&self, policy: &Policy) -> Result<()> {
        ensure!(
            !policy.private
                && policy.forge == crate::Forge::Github
                && policy.kind == Kind::Analysis
                && self.repo == policy.repo
                && self.base == policy.base
                && PULL_NUMBER_RE.is_match(&self.pull.to_string())
                && COMMIT_RE.is_match(&self.head),
            "advisory requires a public GitHub analysis at the policy repository, base and exact head"
        );
        ensure!(
            policy.max_outputs == 1
                && policy.safe_outputs.create_pull_request.is_none()
                && policy.safe_outputs.push_to_pull_request_branch.is_none()
                && policy.secondary_pull_request.is_none()
                && policy.safe_outputs.others.len() == 2
                && ["add_comment", "noop"]
                    .iter()
                    .all(|name| policy.safe_outputs.max_of(name) == Some(1))
                && policy.native_handlers == ["add_comment"],
            "advisory requires only one native add_comment or noop"
        );
        Ok(())
    }

    /// Strict before collection too: unknown routing/mode/SHA fields must not
    /// disappear in a sanitizer and thereby appear accepted.
    pub fn check_items(&self, items: &[Value], max_body: usize, allow_empty: bool) -> Result<()> {
        ensure!(
            (allow_empty && items.is_empty()) || items.len() == 1,
            "advisory requires exactly one comment or noop"
        );
        for item in items {
            let map = item
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("advisory output must be an object"))?;
            let (fields, text) = match item["type"].as_str() {
                Some("add_comment") => {
                    ensure!(
                        item["repo"].as_str() == Some(&self.repo)
                            && item["item_number"].as_u64() == Some(self.pull),
                        "advisory comment must name the policy repository and pull request"
                    );
                    (&["type", "repo", "item_number", "body"][..], "body")
                }
                Some("noop") => (&["type", "message"][..], "message"),
                _ => anyhow::bail!("advisory permits only add_comment or noop"),
            };
            ensure!(
                map.keys().all(|key| fields.contains(&key.as_str())),
                "unsupported advisory output field"
            );
            let body = item[text]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("advisory requires text"))?;
            ensure!(
                !body.trim().is_empty() && body.len() <= max_body,
                "advisory text exceeds its bound or is empty"
            );
            if text == "body" {
                // The guard's run/index/digest marker fits in this reserve.
                // The writer checks its actual final bytes again, never truncates.
                self.body(&format!("{body}\n{}", " ".repeat(200)))?;
            }
        }
        Ok(())
    }

    /// The last read before POST. GitHub has no conditional issue-comment POST:
    /// a PR can still move between this read and the write.
    pub fn check_pull(&self, pull: &Value) -> Result<()> {
        ensure!(
            pull["number"].as_u64() == Some(self.pull)
                && pull["state"] == "open"
                && pull["base"]["repo"]["full_name"] == self.repo
                && pull["base"]["ref"] == self.base
                && pull["head"]["sha"] == self.head,
            "advisory pull request is closed, moved or retargeted"
        );
        Ok(())
    }

    pub fn body(&self, prose: &str) -> Result<String> {
        let body = format!(
            "Advisory for reviewed head `{}` (not a review verdict).\n\n{prose}",
            self.head
        );
        ensure!(
            body.len() <= MAX_FINAL_BYTES,
            "final advisory body exceeds {MAX_FINAL_BYTES} bytes"
        );
        Ok(body)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn policy() -> Policy {
        let mut policy = crate::check::fixtures::policy();
        policy.kind = Kind::Analysis;
        policy.max_outputs = 1;
        policy.safe_outputs.create_pull_request = None;
        policy.safe_outputs.others.insert(
            "add_comment".into(),
            policy.safe_outputs.others["noop"].clone(),
        );
        policy
            .safe_outputs
            .others
            .retain(|name, _| ["add_comment", "noop"].contains(&name.as_str()));
        for limit in policy.safe_outputs.others.values_mut() {
            limit.max = 1;
        }
        policy.native_handlers = vec!["add_comment".into()];
        policy.advisory = Some(Advisory {
            repo: policy.repo.clone(),
            pull: 7,
            base: policy.base.clone(),
            head: "a".repeat(40),
        });
        policy.validate().unwrap();
        policy
    }

    #[test]
    fn advisory_is_explicit_and_cannot_widen_policy() {
        assert!(crate::check::fixtures::policy().advisory.is_none());
        let good = policy();
        let value = serde_json::to_value(&good).unwrap();
        for (pointer, value) in [
            ("/private", json!(true)),
            ("/kind", json!("branch")),
            ("/max_outputs", json!(2)),
            ("/native_handlers", json!([])),
            ("/advisory/repo", json!("other/repo")),
            ("/advisory/base", json!("other")),
            ("/advisory/head", json!("main")),
            ("/advisory/pull", json!(0)),
        ] {
            let mut changed = serde_json::to_value(&good).unwrap();
            changed["private"] = json!(false);
            *changed.pointer_mut(pointer).unwrap() = value;
            let changed: Policy = serde_json::from_value(changed).unwrap();
            assert!(changed.validate().is_err(), "{pointer}");
        }
        let mut unknown = value;
        unknown["advisory"]["classifier"] = json!(true);
        assert!(serde_json::from_value::<Policy>(unknown).is_err());
    }

    #[test]
    fn advisory_requires_the_same_open_pull_base_and_head() {
        let policy = policy();
        let advisory = policy.advisory.unwrap();
        let pull = json!({"number":7,"state":"open","base":{"ref":advisory.base,
            "repo":{"full_name":advisory.repo}},"head":{"sha":advisory.head}});
        advisory.check_pull(&pull).unwrap();
        for (pointer, value) in [
            ("/number", json!(8)),
            ("/state", json!("closed")),
            ("/head/sha", json!("b".repeat(40))),
            ("/base/ref", json!("other")),
            ("/base/repo/full_name", json!("other/repo")),
        ] {
            let mut changed = pull.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(advisory.check_pull(&changed).is_err(), "{pointer}");
        }
        assert!(advisory.check_pull(&Value::Null).is_err());
    }

    #[test]
    fn advisory_outputs_cannot_select_authority_or_exceed_bounds() {
        let advisory = policy().advisory.unwrap();
        let comment = json!({"type":"add_comment","repo":advisory.repo,"item_number":7,"body":"Prose without a verdict."});
        advisory
            .check_items(std::slice::from_ref(&comment), MAX_PROSE_BYTES, false)
            .unwrap();
        advisory
            .check_items(
                &[json!({"type":"noop","message":"Nothing useful."})],
                MAX_PROSE_BYTES,
                false,
            )
            .unwrap();
        for items in [
            vec![],
            vec![comment.clone(), comment.clone()],
            vec![json!({"type":"create_check_run","conclusion":"neutral"})],
        ] {
            assert!(
                advisory
                    .check_items(&items, MAX_PROSE_BYTES, false)
                    .is_err()
            );
        }
        for (key, value) in [
            ("repo", json!("other/repo")),
            ("item_number", json!(8)),
            ("head", json!("a".repeat(40))),
            ("mode", json!("advisory")),
            ("advisory", json!(true)),
            ("target", json!(8)),
            ("pr", json!(7)),
            ("body", json!("x".repeat(MAX_PROSE_BYTES + 1))),
        ] {
            let mut changed = comment.clone();
            changed[key] = value;
            assert!(
                advisory
                    .check_items(&[changed], MAX_PROSE_BYTES, false)
                    .is_err(),
                "{key}"
            );
        }
        assert!(advisory.body(&"x".repeat(MAX_FINAL_BYTES)).is_err());
        advisory.check_items(&[], MAX_PROSE_BYTES, true).unwrap(); // guard removed replay
    }
}
