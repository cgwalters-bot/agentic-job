//! Bind local replay to the trusted check's exact inputs and accepted prefix.
//!
//! This prevents substituting a policy, root, issue plan or proposal after
//! check, or growing or shrinking the accepted prefix without a new check.
//! The receipt must travel through a trusted channel; it is not a signature
//! and confers no publication authority.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use serde::Serialize;

use super::{CheckedStack, MAX_ISSUE, Refusal, Step};
use crate::{contract::Policy, replay::digest};

const VERSION: u32 = 1;

/// Compact JSON: three SHA-256 hex digests, version and fixed field names.
pub const MAX_RECEIPT_BYTES: usize = 512;

/// Caller-owned inputs, obtained independently at check and replay. The plan
/// and the existing policy stack ceiling must both admit the proposal.
#[derive(Serialize)]
pub struct Admission<'a> {
    pub policy: &'a Policy,
    pub base_commit: &'a str,
    pub issues: &'a [u64],
}

#[derive(Serialize)]
struct Receipt {
    version: u32,
    admission_sha256: String,
    proposal_sha256: String,
    result_sha256: String,
}

/// Check a proposal and create a receipt for transfer by the trusted caller.
/// The caller must read bounded regular files and inspect each step's full
/// content, including for secrets, without side effects.
pub fn check(
    content: &[u8],
    admission: &Admission<'_>,
    mut inspect: impl FnMut(&Step) -> Result<()>,
) -> Result<(CheckedStack, Vec<u8>)> {
    let limit = admission
        .policy
        .safe_outputs
        .stack_max_steps
        .min(admission.policy.max_outputs)
        .min(super::MAX_STEPS) as usize;
    ensure!(
        (1..=limit).contains(&admission.issues.len()),
        "stack issue plan is outside policy bounds"
    );
    let mut distinct = BTreeSet::new();
    ensure!(
        admission
            .issues
            .iter()
            .all(|issue| (1..=MAX_ISSUE).contains(issue) && distinct.insert(issue)),
        "stack issue plan must contain distinct positive issue numbers within bounds"
    );

    let mut position = 0;
    let mut checked = super::check_policy_up_to(
        content,
        admission.policy,
        admission.base_commit,
        admission.issues.len() as u32,
        |step| {
            ensure!(
                admission.issues.get(position) == Some(&step.issue),
                "stack step does not match the admitted issue order"
            );
            position += 1;
            inspect(step).map_err(|_| anyhow::anyhow!("stack step inspection refused"))
        },
    )?;
    // Otherwise a producer could drop an admitted issue and the receipt would
    // still describe a complete, unrefused stack.
    if checked.refused.is_none() && checked.accepted.len() < admission.issues.len() {
        checked.refused = Some(Refusal {
            position: checked.accepted.len() + 1,
            reason: "stack proposal does not cover the admitted issue plan".to_owned(),
        });
    }
    // Exact proposal bytes bind the accepted steps' patches and metadata. Bind
    // their corresponding checked paths and the refusal position separately;
    // diagnostics can contain producer text and must not travel in the receipt.
    let paths: Vec<_> = checked.accepted.iter().map(|step| &step.files).collect();
    let refused = checked.refused.as_ref().map(|refusal| refusal.position);
    let bytes = serde_json::to_vec(&Receipt {
        version: VERSION,
        admission_sha256: digest(&serde_json::to_vec(admission)?),
        proposal_sha256: digest(content),
        result_sha256: digest(&serde_json::to_vec(&(paths, refused))?),
    })?;
    ensure!(
        bytes.len() <= MAX_RECEIPT_BYTES,
        "stack receipt exceeds byte limit"
    );
    Ok((checked, bytes))
}

/// Independently rerun check and compare the complete receipt before replay.
pub fn revalidate(
    content: &[u8],
    receipt: &[u8],
    admission: &Admission<'_>,
    inspect: impl FnMut(&Step) -> Result<()>,
) -> Result<CheckedStack> {
    ensure!(
        receipt.len() <= MAX_RECEIPT_BYTES,
        "stack receipt exceeds byte limit"
    );
    let (checked, expected) = check(content, admission, inspect)?;
    ensure!(
        expected == receipt,
        "stack proposal, admission or checked prefix changed"
    );
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{fixtures::policy, stack::tests::proposal};

    #[test]
    fn checked_prefix_cannot_change_between_check_and_replay() {
        let proposal = proposal();
        let content = proposal.to_string();
        let mut policy = policy();
        policy.max_outputs = 3;
        policy.safe_outputs.stack_max_steps = 3;
        let admission = Admission {
            policy: &policy,
            base_commit: proposal["base_commit"].as_str().unwrap(),
            issues: &[1, 2, 3],
        };
        let refuse = |step: &Step| {
            ensure!(step.issue != 2, "private scanner diagnostic");
            Ok(())
        };
        let (checked, receipt) = check(content.as_bytes(), &admission, refuse).unwrap();
        assert_eq!(checked.accepted.len(), 1);
        assert_eq!(
            checked.refused.unwrap().reason,
            "stack step inspection refused"
        );
        let mut inspected = Vec::new();
        let replay = revalidate(content.as_bytes(), &receipt, &admission, |step| {
            inspected.push(step.issue);
            refuse(step)
        })
        .unwrap();
        assert_eq!(inspected, [1, 2]);
        assert_eq!(replay.accepted.len(), 1);
        assert_eq!(replay.refused.unwrap().position, 2);
        assert!(revalidate(content.as_bytes(), &receipt, &admission, |_| Ok(())).is_err());
        assert!(
            revalidate(content.as_bytes(), &receipt, &admission, |_| anyhow::bail!(
                "refuse earlier"
            ))
            .is_err()
        );

        // Keep the same prefix even though the proposal bytes, policy or plan
        // are different. Prefix equality alone would accept each substitution.
        assert!(
            revalidate(
                format!("{content}\n").as_bytes(),
                &receipt,
                &admission,
                refuse
            )
            .is_err()
        );
        let mut changed = policy.clone();
        changed.base = "other".into();
        for alternate in [
            Admission {
                policy: &changed,
                ..admission
            },
            Admission {
                issues: &[1, 3, 2],
                ..admission
            },
        ] {
            assert!(revalidate(content.as_bytes(), &receipt, &alternate, refuse).is_err());
        }
        let mut tampered = receipt;
        tampered.push(b' ');
        assert!(revalidate(content.as_bytes(), &tampered, &admission, refuse).is_err());
        assert!(
            revalidate(
                content.as_bytes(),
                &[0; MAX_RECEIPT_BYTES + 1],
                &admission,
                |_| panic!("oversized receipt inspected")
            )
            .is_err()
        );
    }

    #[test]
    fn ordered_issue_plan_is_independent_and_requires_the_existing_opt_in() {
        let proposal = proposal();
        let content = proposal.to_string();
        let mut policy = policy();
        policy.max_outputs = 3;
        let base_commit = proposal["base_commit"].as_str().unwrap();
        for (limit, issues) in [
            (0, &[1, 2, 3][..]),
            (2, &[1, 2, 3]),
            (3, &[]),
            (3, &[1, 1, 3]),
        ] {
            policy.safe_outputs.stack_max_steps = limit;
            let admission = Admission {
                policy: &policy,
                base_commit,
                issues,
            };
            assert!(
                check(content.as_bytes(), &admission, |_| panic!(
                    "unadmitted proposal inspected"
                ))
                .is_err()
            );
        }
        let admission = Admission {
            policy: &policy,
            base_commit,
            issues: &[1, 3, 2],
        };
        let mut inspected = Vec::new();
        let (checked, _) = check(content.as_bytes(), &admission, |step| {
            inspected.push(step.issue);
            Ok(())
        })
        .unwrap();
        assert_eq!(inspected, [1]);
        assert_eq!(checked.accepted.len(), 1);
        assert_eq!(checked.refused.unwrap().position, 2);

        // The plan's fourth issue is missing: refused there unless an earlier
        // step already was.
        policy.max_outputs = 4;
        policy.safe_outputs.stack_max_steps = 4;
        let admission = Admission {
            policy: &policy,
            base_commit,
            issues: &[1, 2, 3, 4],
        };
        for (refused_issue, position, reason) in [
            (
                0,
                4,
                "stack proposal does not cover the admitted issue plan",
            ),
            (2, 2, "stack step inspection refused"),
        ] {
            let (checked, _) = check(content.as_bytes(), &admission, |step| {
                ensure!(step.issue != refused_issue, "refused");
                Ok(())
            })
            .unwrap();
            assert_eq!(checked.accepted.len(), position - 1);
            let refusal = checked.refused.unwrap();
            assert_eq!(
                (refusal.position, refusal.reason.as_str()),
                (position, reason)
            );
        }
    }
}
