//! Experimental library receipts, not workflow artifacts or publication authority.
//!
//! The threat is substitution of the root, ordered issue plan, policy, patch or
//! metadata between check and apply, including extending a refused prefix. The
//! trusted caller supplies [`Admission`] independently in both jobs and transfers
//! the receipt through a trusted check artifact channel. A digest is not a
//! signature: an agent allowed to replace the receipt can forge it.
//!
//! This module does no I/O. Callers must read bounded no-follow regular files,
//! run their secret gates/redaction before check, and inspect each step again at
//! revalidation. Neither CLI nor reusable workflow consumes these receipts yet.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

use super::{CheckedStack, MAX_STEPS, Step};
use crate::Forge;
use crate::contract::{COMMIT_RE, Kind, PatchRules, Policy};

const VERSION: u32 = 1;
pub const MAX_RECEIPT_BYTES: usize = 64 * 1024;

/// Caller-owned context, never derived from the producer's proposal/receipt.
/// An empty issue plan disables this path; an explicit plan admits at most ten
/// steps and never more than the policy's total output ceiling. This does not
/// change the policy's ordinary one-PR cap or authorize any publication.
#[derive(Serialize)]
pub struct Admission<'a> {
    pub policy: &'a Policy,
    pub base_commit: &'a str,
    pub issues: &'a [u64],
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    admission_sha256: String,
    proposal_sha256: String,
    accepted: Vec<StepBinding>,
    refused_position: Option<usize>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StepBinding {
    issue: u64,
    patch_sha256: String,
    metadata_sha256: String,
    files_sha256: String,
}

fn hash(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Admission<'_> {
    fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        ensure!(
            self.policy.forge == Forge::Github
                && self.policy.kind == Kind::Branch
                && self.policy.secondary_pull_request.is_none()
                && self.policy.external.is_none()
                && self.policy.advisory.is_none()
                && self.policy.continuation.is_none()
                && self.policy.safe_outputs.create_pull_request.is_some(),
            "stack receipt requires an ordinary new GitHub pull-request policy"
        );
        ensure!(
            COMMIT_RE.is_match(self.base_commit),
            "invalid admitted stack root"
        );
        ensure!(
            !self.issues.is_empty()
                && self.issues.len() <= MAX_STEPS as usize
                && self.issues.len() <= self.policy.max_outputs as usize,
            "admitted stack issue count is outside bounds"
        );
        let mut distinct = BTreeSet::new();
        ensure!(
            self.issues
                .iter()
                .all(|issue| (1..=super::MAX_ISSUE).contains(issue) && distinct.insert(issue)),
            "admitted stack requires distinct positive issues within bounds"
        );
        Ok(())
    }
}

fn checked(
    content: &[u8],
    admission: &Admission<'_>,
    mut inspect: impl FnMut(&Step) -> Result<()>,
) -> Result<CheckedStack> {
    admission.validate()?;
    let pr = admission
        .policy
        .safe_outputs
        .create_pull_request
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("stack requires create_pull_request"))?;
    let rules = PatchRules {
        commit_author: admission.policy.commit_author.as_deref(),
        ..pr.rules()
    };
    let mut position = 0;
    super::check(
        content,
        admission.issues.len() as u32,
        admission.base_commit,
        admission.policy.max_patch_bytes,
        &rules,
        |step| {
            ensure!(
                admission.issues.get(position) == Some(&step.issue),
                "stack step does not match the admitted issue order"
            );
            position += 1;
            // Do not persist or echo a scanner's potentially secret-bearing error.
            inspect(step).map_err(|_| anyhow::anyhow!("stack step inspection refused"))
        },
    )
}

fn receipt(content: &[u8], admission: &Admission<'_>, checked: &CheckedStack) -> Result<Receipt> {
    Ok(Receipt {
        version: VERSION,
        admission_sha256: hash(&serde_json::to_vec(admission)?),
        proposal_sha256: hash(content),
        accepted: checked
            .accepted
            .iter()
            .map(|checked| {
                let step = &checked.step;
                Ok(StepBinding {
                    issue: step.issue,
                    patch_sha256: hash(step.patch.as_bytes()),
                    metadata_sha256: hash(&serde_json::to_vec(&(&step.title, &step.body))?),
                    files_sha256: hash(&serde_json::to_vec(&checked.files)?),
                })
            })
            .collect::<Result<_>>()?,
        // Only a position, never an untrusted diagnostic, crosses this boundary.
        refused_position: checked.refused.as_ref().map(|refused| refused.position),
    })
}

/// Check all reached steps and produce bounded receipt bytes for trusted
/// transport. An accepted prefix is still not permission to push or open PRs.
pub fn check(
    content: &[u8],
    admission: &Admission<'_>,
    inspect: impl FnMut(&Step) -> Result<()>,
) -> Result<(CheckedStack, Vec<u8>)> {
    let checked = checked(content, admission, inspect)?;
    let bytes = serde_json::to_vec(&receipt(content, admission, &checked)?)?;
    ensure!(
        bytes.len() <= MAX_RECEIPT_BYTES,
        "stack receipt exceeds byte limit"
    );
    Ok((checked, bytes))
}

/// Independently rerun policy, ordered-issue, patch and content checks; compare
/// the entire accepted prefix before returning anything for Git replay. Even an
/// unchanged digest never bypasses `inspect`. A changed scanner result requires
/// a new trusted check receipt rather than silently extending/shrinking a prefix.
pub fn revalidate(
    content: &[u8],
    admitted_receipt: &[u8],
    admission: &Admission<'_>,
    inspect: impl FnMut(&Step) -> Result<()>,
) -> Result<CheckedStack> {
    ensure!(
        admitted_receipt.len() <= MAX_RECEIPT_BYTES,
        "stack receipt exceeds byte limit"
    );
    let expected: Receipt = serde_json::from_slice(admitted_receipt)
        .map_err(|_| anyhow::anyhow!("invalid stack receipt"))?;
    let checked = checked(content, admission, inspect)?;
    ensure!(
        expected == receipt(content, admission, &checked)?,
        "stack proposal, admission or checked prefix changed"
    );
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{fixtures::policy, stack::tests::proposal};
    use serde_json::{Value, json};

    const BASE: &str = "1111111111111111111111111111111111111111";

    #[test]
    fn receipt_binds_exact_bytes_context_metadata_and_prefix() {
        let mut policy = policy();
        policy.max_outputs = 3;
        let admission = Admission {
            policy: &policy,
            base_commit: BASE,
            issues: &[1, 2, 3],
        };
        let content = proposal().to_string();
        let (checked, receipt) = check(content.as_bytes(), &admission, |_| Ok(())).unwrap();
        assert_eq!(checked.accepted.len(), 3);
        let mut inspected = Vec::new();
        assert_eq!(
            revalidate(content.as_bytes(), &receipt, &admission, |step| {
                inspected.push(step.issue);
                Ok(())
            })
            .unwrap()
            .accepted
            .len(),
            3
        );
        assert_eq!(inspected, [1, 2, 3], "apply must scan independently");

        for key in ["issue", "title", "body", "patch"] {
            let mut changed = proposal();
            changed["steps"][1][key] = match key {
                "issue" => json!(9),
                _ => json!(format!(
                    "{} changed",
                    changed["steps"][1][key].as_str().unwrap()
                )),
            };
            assert!(
                revalidate(
                    changed.to_string().as_bytes(),
                    &receipt,
                    &admission,
                    |_| Ok(())
                )
                .is_err(),
                "{key}"
            );
        }
        // Semantic equality is insufficient: even envelope whitespace is bound.
        assert!(
            revalidate(
                format!("{content}\n").as_bytes(),
                &receipt,
                &admission,
                |_| Ok(())
            )
            .is_err()
        );
        for issues in [&[2, 1, 3][..], &[1, 2][..]] {
            assert!(
                revalidate(
                    content.as_bytes(),
                    &receipt,
                    &Admission {
                        issues,
                        ..admission
                    },
                    |_| Ok(())
                )
                .is_err()
            );
        }
        let mut changed = policy.clone();
        changed.base = "other".into();
        assert!(
            revalidate(
                content.as_bytes(),
                &receipt,
                &Admission {
                    policy: &changed,
                    ..admission
                },
                |_| Ok(())
            )
            .is_err()
        );
        assert!(
            revalidate(
                content.as_bytes(),
                &receipt,
                &Admission {
                    base_commit: "2222222222222222222222222222222222222222",
                    ..admission
                },
                |_| Ok(())
            )
            .is_err()
        );

        for (key, value) in [
            ("version", json!(2)),
            ("accepted", json!([])),
            ("refused_position", json!(2)),
            ("admission_sha256", json!("changed")),
            ("proposal_sha256", json!("changed")),
            ("unknown", json!(true)),
        ] {
            let mut changed: Value = serde_json::from_slice(&receipt).unwrap();
            changed[key] = value;
            assert!(
                revalidate(
                    content.as_bytes(),
                    changed.to_string().as_bytes(),
                    &admission,
                    |_| Ok(())
                )
                .is_err(),
                "{key}"
            );
        }
        let mut changed: Value = serde_json::from_slice(&receipt).unwrap();
        for key in ["issue", "patch_sha256", "metadata_sha256", "files_sha256"] {
            let old = changed["accepted"][0][key].clone();
            changed["accepted"][0][key] = if key == "issue" {
                json!(8)
            } else {
                json!("changed")
            };
            assert!(
                revalidate(
                    content.as_bytes(),
                    changed.to_string().as_bytes(),
                    &admission,
                    |_| Ok(())
                )
                .is_err(),
                "{key}"
            );
            changed["accepted"][0][key] = old;
        }
    }

    #[test]
    fn refused_prefix_cannot_grow_or_shrink_on_revalidation() {
        let mut policy = policy();
        policy.max_outputs = 3;
        let admission = Admission {
            policy: &policy,
            base_commit: BASE,
            issues: &[1, 2, 3],
        };
        let content = proposal().to_string();
        let refuse = |step: &Step| {
            ensure!(step.issue != 2, "scanner detail must not escape");
            Ok(())
        };
        let (checked, receipt) = check(content.as_bytes(), &admission, refuse).unwrap();
        assert_eq!(checked.accepted.len(), 1);
        assert_eq!(
            checked.refused.unwrap().reason,
            "stack step inspection refused"
        );
        assert!(!String::from_utf8_lossy(&receipt).contains("scanner detail"));
        assert_eq!(
            revalidate(content.as_bytes(), &receipt, &admission, refuse)
                .unwrap()
                .accepted
                .len(),
            1
        );
        assert!(revalidate(content.as_bytes(), &receipt, &admission, |_| Ok(())).is_err());
        assert!(
            revalidate(content.as_bytes(), &receipt, &admission, |_| anyhow::bail!(
                "refuse first"
            ))
            .is_err()
        );
        let (_, full) = check(content.as_bytes(), &admission, |_| Ok(())).unwrap();
        assert!(revalidate(content.as_bytes(), &full, &admission, refuse).is_err());
    }

    #[test]
    fn disabled_invalid_and_over_limit_admissions_never_inspect() {
        let content = proposal().to_string();
        let mut policy = policy();
        policy.max_outputs = 10;
        for issues in [
            &[][..],
            &[1, 1, 3][..],
            &[0][..],
            &[super::super::MAX_ISSUE + 1][..],
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11][..],
        ] {
            assert!(
                check(
                    content.as_bytes(),
                    &Admission {
                        policy: &policy,
                        base_commit: BASE,
                        issues
                    },
                    |_| panic!("invalid admission inspected")
                )
                .is_err()
            );
        }
        for max in [0, 1, 2] {
            policy.max_outputs = max;
            assert!(
                check(
                    content.as_bytes(),
                    &Admission {
                        policy: &policy,
                        base_commit: BASE,
                        issues: &[1, 2, 3]
                    },
                    |_| panic!("over-limit admission inspected")
                )
                .is_err()
            );
        }
        policy.max_outputs = 3;
        let admission = Admission {
            policy: &policy,
            base_commit: BASE,
            issues: &[1, 2, 3],
        };
        for receipt in [
            vec![b'x'; MAX_RECEIPT_BYTES + 1],
            b"{}".to_vec(),
            b"{\"version\":1,\"version\":1}".to_vec(),
        ] {
            assert!(
                revalidate(content.as_bytes(), &receipt, &admission, |_| panic!(
                    "invalid receipt inspected"
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn issue_order_is_admitted_not_producer_selected() {
        let mut policy = policy();
        policy.max_outputs = 3;
        let admission = Admission {
            policy: &policy,
            base_commit: BASE,
            issues: &[1, 3, 2],
        };
        let mut inspected = Vec::new();
        let (checked, _) = check(proposal().to_string().as_bytes(), &admission, |step| {
            inspected.push(step.issue);
            Ok(())
        })
        .unwrap();
        assert_eq!(inspected, [1]);
        assert_eq!(checked.accepted.len(), 1);
        assert_eq!(checked.refused.unwrap().position, 2);
    }

    #[test]
    fn policy_patch_gates_and_ordinary_one_pr_cap_remain_in_force() {
        let content = proposal().to_string();
        let mut policy = policy();
        policy.max_outputs = 3;
        for (author, bytes, reason) in [
            (Some("Other <other@example.com>"), 4096, "author"),
            (None, 1, "byte limit"),
        ] {
            policy.commit_author = author.map(str::to_owned);
            policy.max_patch_bytes = bytes;
            let admission = Admission {
                policy: &policy,
                base_commit: BASE,
                issues: &[1, 2, 3],
            };
            let (checked, receipt) = check(content.as_bytes(), &admission, |_| Ok(())).unwrap();
            assert!(checked.accepted.is_empty());
            assert!(checked.refused.unwrap().reason.contains(reason));
            assert!(
                revalidate(content.as_bytes(), &receipt, &admission, |_| Ok(()))
                    .unwrap()
                    .accepted
                    .is_empty()
            );
        }
        policy
            .safe_outputs
            .create_pull_request
            .as_mut()
            .unwrap()
            .max = 3;
        assert!(
            check(
                content.as_bytes(),
                &Admission {
                    policy: &policy,
                    base_commit: BASE,
                    issues: &[1, 2, 3]
                },
                |_| panic!("ordinary cap raised")
            )
            .is_err()
        );
        policy
            .safe_outputs
            .create_pull_request
            .as_mut()
            .unwrap()
            .max = 1;
        for forge in [Forge::Forgejo, Forge::Gitlab] {
            policy.forge = forge;
            assert!(
                check(
                    content.as_bytes(),
                    &Admission {
                        policy: &policy,
                        base_commit: BASE,
                        issues: &[1, 2, 3]
                    },
                    |_| panic!("unsupported forge inspected")
                )
                .is_err()
            );
        }
    }
}
