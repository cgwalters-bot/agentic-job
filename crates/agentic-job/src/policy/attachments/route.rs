//! Experimental routing of hand-back requests to declared write attachments.
//!
//! The concrete threat is a producer request reaching an issue or pull request
//! the caller did not declare for writing, or exceeding a limit by spreading
//! writes across targets. A request goes to an attachment only when it names
//! that attachment's repository and number explicitly; it is then held to the
//! attachment's compiled write policy with the ordinary field checks. Nothing in
//! check or apply calls this yet, and the result is not a publication receipt.

use std::collections::BTreeMap;

use safe_outputs::apply::ADD_COMMENT;
use safe_outputs::check::{Publishers, item_type, redirections_to, secondary_target};
use serde_json::{Map, Value};

use super::{Admitted, Attachment, Mode, PUSH_TO_PULL_REQUEST_BRANCH, Policy};

/// Fields a request can use to name an issue or pull request by number.
const NUMBER_KEYS: &[&str] = &[
    "item_number",
    "issue_number",
    "pull_request_number",
    "pr_number",
    "pull_number",
    "pr",
    "pr-number",
];

/// Where each request goes, by index into the hand-back's items.
#[derive(Debug, PartialEq, Eq)]
pub struct Routing {
    /// Request index and attachment index, for each attachment write.
    pub routed: Vec<(usize, usize)>,
    /// Requests left to the run's own policy. Its check must count only
    /// these against that policy's per-type limits.
    pub ordinary: Vec<usize>,
}

/// Route ITEMS, the collector's sanitized requests, between the run's own
/// policy RUN and the ADMITTED attachments. OWN is the run's fixed comment
/// target, which a write attachment must not duplicate. Every item, routed or
/// not, counts against RUN's `max_outputs` and, for the types RUN allows, its
/// per-type `max`, so attachments never add to what a run may publish of a
/// type it already has.
///
/// An attachment write must be an `add_comment` with `repo` and `item_number`,
/// or a `push_to_pull_request_branch` with `repo` and `pull_request_number`,
/// naming a write attachment that allows it. Any other request that names an
/// attachment's repository and number, including any write to a read
/// attachment, refuses. Routing applies only the target and limit checks: the
/// whole hand-back must still pass check's per-item refusals, and routed pushes
/// still need their patch checked against that attachment's pinned head.
pub fn route(
    admitted: &[Admitted],
    items: &[Map<String, Value>],
    own: Option<(&str, u64)>,
    run: &Policy,
    publishers: &dyn Publishers,
) -> Result<Routing, Vec<String>> {
    let mut errors = Vec::new();
    let targets: Vec<Option<(&str, u64)>> = admitted
        .iter()
        .map(|admitted| match &admitted.attachment {
            Attachment::Issue { repo, number, .. }
            | Attachment::PullRequest { repo, number, .. } => Some((repo.as_str(), *number)),
            Attachment::Branch { .. } => None,
        })
        .collect();
    let same = |(repo, number): (&str, u64), (other, other_number): (&str, u64)| {
        repo.eq_ignore_ascii_case(other) && number == other_number
    };
    if let Some(own) = own
        && admitted.iter().zip(&targets).any(|(admitted, target)| {
            admitted.attachment.mode() == Mode::Write && target.is_some_and(|t| same(t, own))
        })
    {
        errors.push("an attachment duplicates the run's own item".to_owned());
    }
    let mut routing = Routing {
        routed: Vec::new(),
        ordinary: Vec::new(),
    };
    let mut counts: BTreeMap<(usize, &str), u32> = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        let output = item_type(item);
        let repo = item.get("repo").and_then(Value::as_str);
        // Any spelling of a number that names an attachment counts, so that an
        // alias cannot slip a write to it past routing into the ordinary check.
        // The run's own item stays the run's, even when also attached to read.
        let named: Vec<(&str, usize)> = NUMBER_KEYS
            .iter()
            .filter_map(|key| {
                let value = item.get(*key)?;
                let number = value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|value| value.parse().ok()))?;
                let named = (repo?, number);
                if own.is_some_and(|own| same(own, named)) {
                    return None;
                }
                let target = targets
                    .iter()
                    .position(|target| target.is_some_and(|target| same(target, named)))?;
                Some((*key, target))
            })
            .collect();
        let Some(&(_, target)) = named.first() else {
            routing.ordinary.push(index);
            continue;
        };
        let attachment = &admitted[target];
        let key = match output {
            ADD_COMMENT => "item_number",
            PUSH_TO_PULL_REQUEST_BRANCH => "pull_request_number",
            _ => {
                errors.push(format!("a {output} naming an attachment, which only add_comment and push_to_pull_request_branch may write"));
                continue;
            }
        };
        if named.len() != 1 || named[0].0 != key {
            errors.push(format!(
                "a {output} to an attachment must name it by {key} alone"
            ));
            continue;
        }
        let Some(policy) = attachment
            .write_policy
            .as_ref()
            .filter(|_| attachment.attachment.mode() == Mode::Write)
        else {
            errors.push(format!("a {output} to a read-only attachment"));
            continue;
        };
        if policy.safe_outputs.max_of(output).is_none() {
            errors.push(format!(
                "a {output} to an attachment whose write policy does not allow it"
            ));
            continue;
        }
        let problems = redirections_to(item, policy, targets[target], publishers);
        if !problems.is_empty() {
            errors.extend(problems);
            continue;
        }
        *counts.entry((target, output)).or_default() += 1;
        routing.routed.push((index, target));
    }
    for ((target, output), count) in &counts {
        let policy = admitted[*target]
            .write_policy
            .as_ref()
            .expect("only write policies are counted");
        let max = policy.safe_outputs.max_of(output).unwrap_or(0);
        if *count > max {
            errors.push(format!(
                "{count} {output} outputs to one attachment, over its max {max}"
            ));
        }
    }
    for (target, admitted) in admitted.iter().enumerate() {
        let total: u32 = counts
            .iter()
            .filter(|((counted, _), _)| *counted == target)
            .map(|(_, count)| count)
            .sum();
        if let Some(policy) = &admitted.write_policy
            && total > policy.max_outputs
        {
            errors.push(format!(
                "{total} outputs to one attachment, over its max_outputs {}",
                policy.max_outputs
            ));
        }
    }
    if items.len() > usize::try_from(run.max_outputs).unwrap_or(usize::MAX) {
        errors.push(format!(
            "{} outputs with attachment writes, over the run's max_outputs {}",
            items.len(),
            run.max_outputs
        ));
    }
    // A type only attachments allow is held to their limits above; one the run
    // allows too is shared with it, as both were compiled from the same bounds.
    let mut types: BTreeMap<&str, u32> = BTreeMap::new();
    // A secondary pull request has its own limit, which check counts apart.
    for item in items
        .iter()
        .filter(|item| secondary_target(item, run).is_none())
    {
        *types.entry(item_type(item)).or_default() += 1;
    }
    for (output, count) in types {
        if let Some(max) = run.safe_outputs.max_of(output)
            && count > max
        {
            errors.push(format!(
                "{count} {output} outputs with attachment writes, over the run's max {max}"
            ));
        }
    }
    if errors.is_empty() {
        Ok(routing)
    } else {
        Err(errors)
    }
}
