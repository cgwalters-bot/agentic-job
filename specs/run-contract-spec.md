# Run Contract Specification

**Version**: 0.1.0  
**Status**: Implementation snapshot

## 1. Scope

This specification describes agentic-job's existing boundary between an
untrusted proposals producer, a read-only checker, and a credentialed applier.
A producer can be a deterministic program or a coding agent. The sandbox
requirements apply to producers launched by `agentic-job run`; supplying a
`proposals-artifact` does not sandbox the caller's own job.

The form follows gh-aw's
[security architecture specification](https://github.com/github/gh-aw/blob/main/specs/security-architecture-spec.md).
For the shared safe-output model, see its section 5 and the
[safe-outputs reference](https://github.github.com/gh-aw/reference/safe-outputs/).
The NDJSON format, text sanitization and handler semantics belong to gh-aw,
not this specification. agentic-job uses its unmodified collector and handlers
at the pin documented in [safe outputs](../docs/safe-outputs.md#what-is-gh-aws-and-why).
The requirements below describe local restrictions and integration differences.

## 2. Terminology and conformance

**Producer** means the untrusted process leaving proposals. **Bounds** are the
caller's allowed repositories, bases, output types and ceilings. **Policy** is
the admitted configuration for one run. **Hand-back** is the proposals artifact,
not a trusted checkout. **Check** validates it on a separate machine; **apply**
acts on the checked result with a write-capable credential.

The words MUST, MUST NOT, SHOULD and MAY have their
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) meanings. RC identifiers are
stable requirement names. Conformance means satisfying all RC requirements in
section 3; it does not claim conformance to gh-aw's entire security architecture.
Each requirement lists existing enforcement evidence. A runtime probe is a
check, not proof against every possible attack. Section 4 is excluded from the
tested conformance claim.

## 3. Requirements

### 3.1 Admission, reads and credentials

**RC-001 — Admission.** A run MUST fit the caller's bounds for clone host,
repository, base, kind, output types and ceilings. Policy MUST NOT admit a
pull-request output for an analysis run, more than one pull request, or a
non-draft pull request. Additional organization bounds MUST only tighten access.
Enforcement: [policy.rs](../crates/agentic-job/src/policy.rs), tests
`requests_against_the_bounds`, `ceilings_and_pull_request_settings` and
`organization_policy_only_tightens_bounds`.

**RC-002 — Sandbox reads.** A sandboxed producer MAY read the repository copy
placed in its own workspace, but MUST NOT be able to list or enter the runner's
private directories, including its checkout. It MUST NOT inherit the job's
`ACTIONS_*` variables or read the OIDC request values from accessible processes.
Enforcement: [on_host.rs](../crates/agentic-job/src/sandbox/check/on_host.rs),
runtime checks `private-dir:{path}`, `env-job-variables` and `oidc-value:{name}`
(with positive controls). These run as part of `sandbox check` and run's probes;
see [probe coverage](../docs/sandbox-check.md) for prerequisites and limits.

**RC-003 — Inference credential.** When inference uses a run token, the
sandboxed producer MAY hold it in its configured private agent configuration.
The runner's token file MUST be inaccessible, and the probes MUST refuse a
token found in another writable file or accessible process environment or
command line. This is a run-scoped inference token, not a forge credential or
the model provider's key.
Enforcement: [run_token.rs](../crates/agentic-job/src/sandbox/check/run_token.rs),
runtime checks `token-runner-file`, `token-config-mode`, `token-config-dir-mode`,
`token-files` and `token-processes`.

**RC-022 — Process visibility.** After `secure-host`, the sandbox user MUST NOT
be able to enumerate or list another user's process in `/proc`, or read its
`/proc/PID/cmdline`, even with the PID known. Setup MUST enable
`hidepid=invisible` by default for every sandbox entry path.
Enforcement: [on_host.rs](../crates/agentic-job/src/sandbox/check/on_host.rs),
runtime test `proc-other-users` via a session, user-manager service and Podman
user namespace, with `proc-control-runner` and `proc-control-sandbox-*`;
[sandbox_host.rs](../crates/agentic-job/tests/sandbox_host.rs)
removes the protection with `hidepid=0` and `hidepid=1` in CI's hosted Ubuntu
26.04 `sandbox` job. Containers' own proc mounts expose only their PID namespace.

**RC-014 — Forge read credential.** A sandboxed producer MAY hold one GitHub
token, as `GH_TOKEN`, and it MUST NOT be able to write: the producer can leak
it. The reusable workflow's agent job MUST request only `contents`, `issues`,
`pull-requests` and `actions` read, plus `id-token: write` for inference
registration, and pass that job token unless the caller supplies
`GH_READ_TOKEN` or turns reads off. A supplied classic token naming any scope
but `read:*` and `user:email` MUST be refused before the agent starts; job,
App and fine-grained tokens name no scopes and are the caller's to keep
read-only. The launcher MUST pass only the run's token and drop inherited
GitHub token variables, a run without one MUST remove an earlier run's, and
its value MUST be redacted wherever the run logs or publishes. The egress
proxy MAY pass `POST api.github.com/graphql` for reads; other GitHub writes
MUST stay refused at the proxy. That allowance admits mutations too, so on that
path only GitHub's enforcement of the token's permissions stops a write.
Enforcement: [agent-actions.test.cjs](../workflow/agent-actions.test.cjs),
`the agent job token reads and only apply holds a write credential` and
`the agent gets its GitHub token, and a classic token that can write is refused first`;
[launch.rs](../crates/agentic-job/src/run/launch.rs), `agents_get_only_the_runs_github_token`;
[agent.rs](../crates/agentic-job/src/run/agent.rs), `github_tokens`;
[tests/run.rs](../crates/agentic-job/tests/run.rs),
`a_change_is_handed_back_and_the_check_accepts_it` and
`a_run_from_clone_to_the_end_of_its_run` (with a sandbox user);
[test_policy.py](../egress/test_policy.py), `test_requests`; and CI's
`e2e-full`, whose scripted agent asks for its comment only after a read with
the token succeeded and GitHub refused it a GraphQL write.

**RC-018 — What apply's credential can do.** Policy MUST refuse, before an
agent runs, an output type that the credential apply will hold cannot apply,
naming the type and the credential it needs. Without an `apply-environment`
apply holds the job token, which cannot write a Project nor fork (RC-021):
`update_project`, `create_pull_request` and `push_to_pull_request_branch`
(RC-020) are refused then, and `all` leaves them out. Every other shipped type the job token can apply in the
calling repository; where the outputs go is the caller's to bound
(`docs/dispatch.md` requires an apply environment for another repository
and for `implement`).
Enforcement: [policy.rs](../crates/agentic-job/src/policy.rs), test
`what_the_job_token_cannot_apply_is_refused`;
[proposals.test.cjs](../workflow/proposals.test.cjs), the `the policy command
is told when apply holds only the job token` cases.

### 3.2 Proposals and refusals

With `run`, the producer leaves `out/safe-outputs.jsonl` under its home and
an uncommitted working-tree change; run constructs the patch and exports the
proposals as `outputs.jsonl`. An external producer supplies that artifact file
directly. See [hand-back construction](../docs/safe-outputs.md#what-the-agent-does).

**RC-004 — Artifact routing.** A deterministic producer MAY supply a
`proposals-artifact` without running the agent or activation jobs. Check MUST
require explicit trusted binary and policy artifact IDs and exactly one
proposal selector (artifact ID or legacy name). Producer outputs MUST NOT
select the checker binary, policy or fixed comment destination.
Enforcement: [proposals.test.cjs](../workflow/proposals.test.cjs),
`proposals route retains check and token separation`,
`checker requires explicit trusted IDs and one proposal selector` and
`wrapper passes trusted checker inputs directly and exports all checker outputs`.

**RC-005 — Hand-back files.** Check MUST accept only `outputs.jsonl`, optional
`base.json` and at most one `aw-BRANCH.patch`. It MUST refuse unexpected files,
symlinks, directories, oversized files and recognized secret-shaped strings.
A pull-request request MUST have exactly its named patch and valid base
metadata matching the policy repository/base and patch header; a patch without
a pull-request request MUST be refused.
Enforcement: [check/mod.rs](../crates/agentic-job/src/check/mod.rs), tests
`what_is_refused` and `links_and_directories_are_not_read`;
[files.rs](../crates/agentic-job/src/files.rs), `reads_only_regular_files_within_the_cap`.

**RC-006 — Collected requests.** Check MUST refuse any collector errors,
unadmitted type, per-type or total count excess, repository/base redirection,
or non-draft pull request. Fixed comment destinations MUST reject explicit
redirections, including aliases and reply/existing-comment IDs, rather than
silently retargeting them.
Enforcement: [check/mod.rs](../crates/agentic-job/src/check/mod.rs), tests
`what_is_refused` and `fixed_comment_destination`.

**RC-007 — Patch interpretation.** Check MUST refuse protected paths, non-plain
relative paths, binary changes, symlinks, submodules, new executables, mode
changes, renames and file-count excess. It MUST also refuse extra mail,
unsupported mail headers, patch content hidden in the commit message and file
headers without a mode. Exact-repository policy exceptions MAY relax protected
names, but not top-level dot-folders or the fixed patch restrictions.
Enforcement: [check/patch.rs](../crates/agentic-job/src/check/patch.rs), tests
`what_is_refused` and `unprotected_names_and_folders_follow_the_policy`;
[patch_git.rs](../crates/agentic-job/tests/patch_git.rs),
`what_git_writes_is_read_as_git_means_it` and `the_reader_names_all_that_git_am_changes`.

**RC-008 — Failure gate.** A refused hand-back MUST NOT upload applicable
outputs or start apply. A missing or malformed collector result MUST be an
error, not an acceptance verdict.
Enforcement: [refusal.test.cjs](../workflow/refusal.test.cjs),
`expected refusal never uploads applicable outputs or starts apply`;
[tests/check.rs](../crates/agentic-job/tests/check.rs),
`a_check_that_cannot_be_made_is_an_error_and_writes_no_verdict`.

### 3.3 Apply

**RC-009 — Token placement.** Check MUST remain read-only and receive no
secrets. Only the agent job MAY consume `GH_READ_TOKEN` (RC-014), and only
apply MAY consume `SAFE_OUTPUTS_PAT`; its checkout and handler
API steps MUST select that explicitly passed secret when nonempty, otherwise
`github.token`, independently of the optional apply environment. Event status
jobs can also write, but are not proposal appliers.
Enforcement: [proposals.test.cjs](../workflow/proposals.test.cjs),
`proposals route retains check and token separation`;
[apply.test.cjs](../workflow/apply.test.cjs),
`apply alone consumes the optional safe outputs PAT with job-token fallback`
and the `credential expression wiring: PAT ...` cases.

**RC-010 — Repository-aware patch guard.** Before handing a patch to gh-aw's
handler, apply MUST verify that the claimed base is an ancestor of the target
base and that applying on the claimed base changes exactly the checked paths.
Git's handler configuration MUST disable rename following, so three-way
application cannot redirect an allowed edit into a protected renamed path.
Enforcement: [apply.test.cjs](../workflow/apply.test.cjs),
`apply guard: ordinary edit`, `apply guard: unchecked path`,
`apply guard: empty file list`, `apply guard: unrelated base` and
`handler cannot follow a renamed file into a protected path`.

**RC-011 — Non-patch apply.** Comment-only apply MUST skip repository steps,
including checkout. Issue closing and label addition MUST retain the checked
repository and caps, not use `output-repo` or triggering-event destinations.
Enforcement: [apply.test.cjs](../workflow/apply.test.cjs),
`comment-only apply skips every repository step, including checkout` and
`issue actions keep checked repository and caps, not output-repo or event targets`.

**RC-012 — Issue payload bounds.** Check MUST require explicit repository and
positive integer targets for `close_issue` and `add_labels`, and refuse target
aliases. Closing MUST reject `body`; issue creation MUST reject relationships
to other issues. Labels MUST fit the policy's case-insensitive allow/block
bounds. Added labels MUST also fit the per-request count and the 1–64-character
ASCII subset documented in [safe outputs](../docs/safe-outputs.md#closing-issues-and-adding-labels),
rather than be silently filtered or changed.
Enforcement: [check/mod.rs](../crates/agentic-job/src/check/mod.rs), tests
`bounded_issue_actions`, `issue_action_payloads_are_not_silently_changed`,
`issue_labels_are_checked_not_silently_filtered` and
`an_issue_that_links_other_issues_is_refused`.

**RC-013 — Re-run application.** A re-run of apply MUST NOT post an accepted
comment, issue or pull request that an earlier attempt of the same run posted,
and MUST apply the comments and issues it did not. Apply names each by run
ID, position and digest (over the call's artifact prefix, and a pull
request's over its checked patch too), puts the name last in what it posts,
hidden, and
leaves out a request whose name it finds last in a comment on the target, an
open or merged pull request from the run's branch in the fork RC-021 names,
or an issue, posted by its
own token's principal: `github-actions[bot]` for the job token, the user
`GET /user` names for a PAT, and no one for a PAT it does not name. Check MUST refuse any request holding the name. Closing, labelling and setting a project
field are left to be repeated: done twice they leave the forge as once, as
the handlers apply them here (closing with no comment, labels only that
exist, the issue's item found or added and its field set).
Conclude, which a re-run of apply runs again, MUST post its status or
refusal comment once per run and call: named `agentic-job-concluded:
RUNID/DIGEST16` (over the artifact prefix), hidden last in the body, and
edited, not posted again, when a comment of `github-actions[bot]` ends with
that name.
For `push_to_pull_request_branch`, the guard MUST leave out the push when
the fetched fork branch holds the checked tree as exactly one commit on the
policy's pinned head. The final check MUST re-fetch and verify that same
parent and tree even when the guard left it out. This reuses the guard and
its `already_applied` report, not a second marker scheme.
Enforcement: [apply.test.cjs](../workflow/apply.test.cjs), tests from
`a posted body hides the name the guard put last` to `a pull request
without a checked patch stops the guard`, `closing an issue again posts
nothing`, and the `conclude posts its comment once` cases;
[check/mod.rs](../crates/agentic-job/src/check/mod.rs), test `what_is_refused`;
the e2e-dispatch-verify step `The re-run left out what was applied, and the
comment is there once` in [ci.yml](../.github/workflows/ci.yml), which re-runs
apply's guard and not its handlers; and `AtMostOnce` and
`NoFalseSkip` in the [TLA+ model](README.md).

**RC-019 — Finding the result from the issue.** For a caller-named `issue`
(a number of the output repository, checked by policy), apply MUST end a pull
request's body with `Refs OWNER/NAME#N` in its own words, never a closing
keyword nor agent text, before the guard names it. The pull request handler
MUST have `auto_close_issue: false`, including for issue-triggered events.
Apply MUST give the URL of
what it made (the pull request, else the first comment or issue, an earlier
attempt's before this one's) as the `result-url` output of `apply.yml`,
`agentic-job.yml` and `dispatch.yml`, and in the run summary. Unless that
result is a comment on the issue, it MUST leave the issue one comment linking
the run and the result, named by run and call and looked for as RC-013 looks
for a comment, so that a re-run does not post it again. Failing to post the link
MUST NOT fail the run. A pull request title made from the agent's summary
MUST be cut at a word boundary within its limit.
Enforcement: [apply.test.cjs](../workflow/apply.test.cjs), `a pull request
refers to the issue the caller named, and closes nothing`, `a pull request's
handler pushes only to the fork, and there is none without one`, the `the result of
...` cases and `the issue is linked to what a run made once, by the token that
posts`; [dispatch.test.cjs](../workflow/dispatch.test.cjs), `caller fixes
capabilities and token boundary` and `the URL of what apply made is an output
of dispatch, by way of the wrapper`; [proposals.test.cjs](../workflow/proposals.test.cjs),
the issue cases of `the policy command is told when apply holds only the job
token`; [handback.rs](../crates/agentic-job/src/run/handback.rs), tests
`titles_are_cut_between_words` and `made_up_pull_requests`.

**RC-020 — Pushing to a pull request.** `push_to_pull_request_branch` MUST
be refused unless the caller's bounds list it with globs of the `branches` it
may go to, matched with case, and the caller names the pull request by number
(`push-item`); no part of its routing may come from agent or pull request
text. It MUST go only to the head branch of a pull request whose head
repository is the fork of the identity apply holds, a pull request apply
opened from it (RC-021), and never to a branch of the output repository nor
to anyone else's fork: the target's CI then runs the commit as a fork's.
Policy MUST refuse outputs applied anywhere but the run's repository
(`output-repo`), a pull request that is not open, whose base is not in the
run's repository or whose head is not in a fork of it, a branch outside
those globs, and a call whose apply holds only the job token; it MUST record
the number as the push's `target`, the head commit as its `head`, and `max`
as 1, MUST NOT allow `create_pull_request` beside it, and MUST refuse two
bounds files whose policies pin different pushes. The run MUST start from
that head and stop if the clone is elsewhere. Check MUST refuse a push to any
branch but that pull request's, and a patch whose base is not that head,
under the patch rules of RC-007. Apply MUST refuse a pull request that is
not open, whose head repository is not its own fork, or whose branch is not
the policy's, before it fetches or pushes anything for it, and one from a
repository its identity does not own before it forks; it MUST give gh-aw's handler that
fork as the only head repository it may push to. It MUST NOT push a partial
run's change. It MUST push without force, with no fallback to a new pull
request and without `allow_workflows`, and fail unless the branch then holds
the checked tree as one commit on that head.
Enforcement: [policy.rs](../crates/agentic-job/src/policy.rs), tests
`push_requests_against_the_bounds`, `a_push_policy_names_its_pull_request_and_always_a_max`,
`push_bounds_must_name_branches_and_one_push`, `push_bounds_intersect` and
`what_the_job_token_cannot_apply_is_refused`;
[push.test.cjs](../workflow/push.test.cjs), `a push resolves an open pull
request from a fork's branch and refuses hostile routing`;
[clone.rs](../crates/agentic-job/src/run/clone.rs), `a_push_starts_from_its_pinned_head`
and `a_push_head_is_fetched_by_its_commit_onto_the_default_branch`;
[check/mod.rs](../crates/agentic-job/src/check/mod.rs), `a_push_on_the_pinned_head_is_accepted`
and `what_is_refused_of_a_push`; [handback.rs](../crates/agentic-job/src/run/handback.rs),
`a_push_is_handed_back_as_a_patch_the_check_accepts`;
[apply.test.cjs](../workflow/apply.test.cjs), `a push is applied to the
policy pull request from apply's fork, never as a pull request, never with
workflows`, `a push goes only to a pull request apply opened from its own
fork`, `a push is verified on the branch it went to: one commit on the pinned
head, with the checked tree`, `a partial run's push is not applied, whatever
else it posts` and `target base fetching never advances the
output repository and a stale base is refused`;
[proposals.test.cjs](../workflow/proposals.test.cjs), the push cases of `the
policy command is told when apply holds only the job token`; [dispatch.test.cjs](../workflow/dispatch.test.cjs), `caller fixes
capabilities and token boundary`.

**RC-021 — Pull requests from a fork.** Apply MUST NOT push an agent's commit
to a branch of the output repository. It MUST NOT push target base commits
there either; its base must already contain the patch's base commit, or apply
MUST stop and ask the operator to sync it independently.
It MUST push a pull request's branch to
a fork of the output repository owned by the user `GET /user` names for its
credential, making the fork when there is none, and open the pull request
with that fork's owner and branch as its head, so that the output
repository's CI runs the commit as a fork's: with a read-only token, no
secrets and no OIDC token. Apply MUST fail before any push when that user
cannot be named, when it owns the output repository, when what the forge
answers is not that user's own fork and neither the caller's nor the output
repository, when the fork has no branch git can reach, or when Actions
cannot be turned off on the fork, as a push with a user's token would start
its workflows with its secrets; without a fork,
no pull request or push handler is configured. There
is no same-repository mode. This repository's CI MUST give a fork's pull
request nothing privileged: no `pull_request_target` or `workflow_run`
trigger, no secret, and no job that writes or asks for an OIDC token runs
for it; and its required `ci` check MUST NOT pass when the end-to-end jobs
it skips are needed for what it changes.
Enforcement: [apply.test.cjs](../workflow/apply.test.cjs), `a pull request is
opened from a fork the token owns, made if missing and reached by git`, `a
pull request's handler pushes only to the fork, and there is none without
one`, `the pull request is looked for from the branch gh-aw names in the fork,
prefix normalized`, `a pull request without a fork to open it from stops the
guard` and `the job fails unless every output was applied and a pull request
asked for was opened`, and `target base fetching never advances the output
repository and a stale base is refused`; [policy.rs](../crates/agentic-job/src/policy.rs), test
`what_the_job_token_cannot_apply_is_refused` (RC-018);
[dispatch.test.cjs](../workflow/dispatch.test.cjs), `real agent preflight
names all missing deployment variables together`;
[ci.yml](../.github/workflows/ci.yml), the inline `changes` path classifier
and required `ci` gate (workflow enforcement, not a live forge test).
[ci.test.cjs](../workflow/ci.test.cjs) executes the inline classifier against
local Git histories, including hostile script edits, renames and missing history.
It also tests privileged job gating and the required check's acceptance/refusal
matrix for skipped, failed and cancelled jobs.
Classification does not execute a script from the pull request's tree;
human edits to the proposed workflow still require review.

### 3.4 The caller's own agent job

**RC-022 — Untrusted logs.** Sandbox stdout and stderr, including setup
scripts and agent messages under `run`, MUST NOT set runner outputs, install
masks or create workflow annotations. Whatever of them may reach a runner
log MUST have both runner command syntaxes (`::` and `##[`) broken up
wherever they occur, not only at the start of a line, so that filtering,
reordering or interleaving whole lines downstream cannot form a command.
Protection MUST NOT depend on runner state such as `stop-commands`: a
supervisor killed with SIGKILL would leave it set for the rest of the job.
Writers sharing one pipe MUST NOT be able to join their bytes into either
syntax: each write is escaped as if it followed an unknown writer's bytes,
and is no larger than one atomic pipe write. A handled signal MUST be
passed on to the command, which is killed only after a bounded grace period.
Output directed to a regular file is data, not a runner log, and keeps its
exact bytes.
Enforcement: [workflow_commands.rs](../crates/agentic-job/src/workflow_commands.rs),
`escaping_breaks_both_syntaxes` and `writes_cannot_join_into_a_command`;
[enter.rs](../crates/agentic-job/src/sandbox/enter.rs),
`streamed_commands_are_escaped`,
`failed_spawn_fails_and_file_transfers_are_exact`,
`relays_follow_the_destination` and
`supervisor_signals_reach_the_command`;
[transcript.rs](../crates/agentic-job/src/session/transcript.rs),
`agent_logs_are_escaped_but_transcripts_keep_original_bytes`;
[check/mod.rs](../crates/agentic-job/src/sandbox/check/mod.rs),
`stderr_is_bounded_and_escaped` (probe diagnostics also contain sandbox text);
[example-secure-host.yml](../.github/workflows/example-secure-host.yml),
`Sandbox output cannot command the runner`,
`Filtered and overlapping sandbox output cannot command the runner`,
`Trusted output can command the runner` (a positive control),
`Trusted outputs are unchanged` and `Sandbox did not install a mask`. The
final job checks that the runner exports a trusted sentinel rather than
refusing it as masked, and that it does refuse one a trusted step masked.

A caller MAY write the agent job itself, between the policy, check and apply
pieces, as [the pieces](../docs/workflow.md#the-pieces-and-an-agent-job-of-your-own)
describes. The pieces keep the boundaries of 3.1 to 3.3; this section is what
the job's steps hold.

**RC-015 — Composition.** An agent job MUST run, in order: the target
checkout, the source checkout at the policy call's `source-repository` and
`source-sha`, refused before the checkout unless they name a repository and
a full commit, `prepare`, then the caller's privileged steps, `secure-host`
and `run`. `secure-host` MUST check the inference proxy before it secures the
host. The job MUST take the binary, policy and configuration only from the
policy call's upload IDs, and hand on only `run`'s outputs: check takes the
proposals' upload ID, apply the job's result and exit status. Check and
apply MUST NOT read anything else the job makes. The
convenience workflow MUST be built from these same pieces, forward every
setting to the policy call unchanged, and neither it nor any action here
joins a network itself. Check and apply MUST refuse, before they download
anything, a policy call whose `source-repository` and `source-sha` are not
their own workflow's, and apply an empty or non-numeric checked artifact ID,
or one the read API does not name as this run's upload of check's
`checked-outputs` under the policy call's artifact prefix.
`prepare` and `run` MUST refuse, before they install or run anything from
the policy upload, a `run.json` whose `source_sha` is not their own commit.
Enforcement: [agent-actions.test.cjs](../workflow/agent-actions.test.cjs),
`agentic-job.yml composes the pinned-source agent job and keeps trusted edges
off agent outputs` and its `example-compose.yml` twin,
`the source an agent job takes its actions from is the policy call's own`,
`apply applies only what check accepted, whatever the caller's gate`,
`the wrapper forwards every setting to the policy call as it is` and
`no workflow or action of this repository joins a network itself`;
[apply.test.cjs](../workflow/apply.test.cjs), `check and apply refuse a
policy call of another commit, and apply an empty checked ID` and `apply
takes only this run's check output, whatever the caller wired`;
[specs](../specs/README.md), `BrokenWiring`;
[test_inference_preflight.py](../workflow/test_inference_preflight.py),
`test_workflow_order_and_trusted_binary`;
[dispatch.test.cjs](../workflow/dispatch.test.cjs),
`caller fixes capabilities and token boundary`.

**RC-016 — Steps before `secure-host`.** A caller's steps between `prepare`
and `secure-host` run as the runner user with sudo, and MAY join a network,
install software or fetch a credential for the runner. They MUST NOT change
`.agentic-job`, `.agentic-job-source` or `/usr/local/bin/agentic-job`, and
MUST NOT leave a credential, process or socket that `secure-host`'s setup
does not close to the sandbox user: setup removes the runner's sudo and the
sandbox's routes to the host, not what a step chose to share.
Enforcement: CI's `e2e-compose` runs [example-compose.yml](../.github/workflows/example-compose.yml)
with an example privileged step that creates a root-owned file;
[agent-actions.test.cjs](../workflow/agent-actions.test.cjs),
`the composed example marks where a caller's own steps go, and its examples
prove their privileges`, holds that it sits between `prepare` and `secure-host`. What a
caller's step itself does is not tested here (section 4).

**RC-017 — Steps after `run`.** A caller's steps after `run` execute as the
runner user, outside the sandbox and without sudo, after the hand-back was
uploaded. They MAY read what the agent left on the machine and MUST treat it
as hostile: not execute it, nor hand it to a credentialed step. A caller's
own agent job MUST grant only `contents`, `issues`, `pull-requests` and
`actions` read, plus `id-token: write`, as RC-014 requires of the reusable
workflow's. That is the caller's obligation, kept by the job's own
`permissions` block and by nothing here: `run` gives the agent whichever
token it is passed, the job's included, and cannot see what a job token was
granted.
Enforcement: CI's `e2e-compose` example later step finds the earlier step's
root-owned file and fails if `sudo -n true` succeeds; the same
`agent-actions.test.cjs` test holds that it follows `run`. Only
example-compose.yml's `permissions` block is tested (section 4).

## 4. Not yet enforced

These limitations are not additional guarantees:

- Project-update payload checking restricts exact projects and fields,
  explicit repository and issue-only numeric content, and string/number field
  values in [check/mod.rs](../crates/agentic-job/src/check/mod.rs), `redirections_to`.
  That payload grammar has no dedicated enforcing test here and is not part of
  the tested conformance claim.
- RC-018 decides by `apply-environment`, not by the secret: the policy job
  cannot see whether `SAFE_OUTPUTS_PAT` is passed (RC-009 keeps it from
  policy). A PAT passed without an environment is refused `update_project`
  and `create_pull_request`, and an environment whose secret is empty, lacks
  project scope or cannot fork is admitted and fails at apply. Nor does policy check where the job token can write: it
  writes only the calling repository, and a call whose `repo` or `output-repo`
  is another, without an apply environment, is admitted and fails at apply
  (`dispatch.yml` refuses that before the run). The job token cannot push
  changes under `.github/workflows/` either, which bounds may admit.
- RC-019 posts no link when the pull request was not opened (the job then
  fails): there is no result URL. Its link comment has RC-013's
  limits for a comment, and a re-run that makes another result is not linked
  again.
- RC-020 does not hold the branch at `head` before the push: gh-aw's handler
  re-anchors on the patch's base commit and pushes without force, so a
   unrelated commit added on top of `head` makes the
  forge refuse it as not a fast-forward. A branch force-pushed or rebased so
  that `head` is no longer in it is different: the handler then applies the
  patch on the new tip, that push succeeds, and apply's last step fails only
  after it. Only the fork's owner, the identity apply holds, and maintainers
  of the output repository the pull request lets edit it can move the
  branch. Apply checks that the pull request is open, the handler does not:
  one closed in between is pushed to, on the fork's branch. A re-run of apply
   after a push succeeds without pushing again when the fork holds exactly
   one commit on `head` with the checked tree (RC-013). No CI run pushes to a live
  pull request: RC-020's evidence is unit tests and apply's steps run
  against a local repository.
- RC-021 has run against a stand-in for the forge only: no live run has made
  a fork, pushed to it or opened a pull request from it. What it guarantees
  of the output repository's CI is what GitHub gives a fork's pull request
  there; a workflow of that repository on `pull_request_target` or
  `workflow_run` still runs with its privileges, and its settings decide
  whether a fork's runs wait for approval. The fork is never deleted, its
  other branches are left as they are, and the credential that pushes to it
  can push to every other repository its user owns.
- Under RC-021 every agent's pull request is a fork's: this repository's
  CI runs no end-to-end job for it (they run on the push to main once it
  is merged), and the event and review callers refuse it unless their
  bounds say `forks = true`.
- Patch author identity is not bound to the producer or operator; see
  [issue 22](https://github.com/cgwalters-forge/agentic-job/issues/22).
- Token selection has source and expression tests, not live tests of
  environment-only secret delivery or environment protection gates. See
  [token setup](../docs/workflow.md#the-apply-job-and-its-token).
- RC-013 does not cover an issue a re-run starts within seconds of the
  attempt that opened it: the search apply looks it up with lags behind.
  Nor a comment where the destination is `*` and the request names no item,
  nor another workflow of the same repository posting a request's name with
  its job token, which is the same `github-actions[bot]`. An app's token in
  `SAFE_OUTPUTS_PAT` names no one, so a re-run with it posts again. A pull request whose branch an
  earlier attempt pushed but did not open, or that was closed unmerged with
  its branch kept, is not completed: the handler stops at the existing
  branch, as before. "Re-run all jobs" keeps the run ID, but the agent hands
  back anew, and what differs is applied as new. The hidden name is checked
  on the forge, not a ledger, so deleting what was posted lets a re-run post
  it again. Nor is a close, a label or a field value marked: a re-run after
  someone reopened the issue, removed the label or changed the field does
  it again. The model's `AtMostOnce` covers proposals, not conclude's
  status comment. An issue gh-aw's pull request handler opens in a pull
  request's place is not named, and a run whose `create_issue` max allows
  one may open it again on a re-run that gets past the run's branch.
  Conclude's reactions are not removed, so a re-run that ends otherwise
  leaves both; and "Re-run all jobs" runs `notify` again, which posts a
  second status comment.
- Whether a supplied job, App or fine-grained token can write is not
  detectable before the run: GitHub reports scopes only for classic tokens,
  and validates an empty write's body before it authorizes it (422, not
  403, to the read-only job token), so no harmless write tells them apart.
  The agent job's own token is bounded by its `permissions` block, which is
  tested in source; only `e2e-full` sees GitHub refuse it a write.
- The separate-job design runs pinned handlers, not producer scripts, in apply.
  There is no comprehensive test proving that every future workflow step with
  a credential avoids executing producer code. Source review remains necessary.
- RC-016 and RC-017 bind the steps a caller adds to its own agent job, which
  this repository cannot see. Only the order of the pieces and example-compose.yml's
  example steps are tested; a caller's step that shares a credential with the
  sandbox, or runs the agent's files after `run`, is not caught.
- RC-017's permissions are the caller's obligation, not enforced for a
  caller's own agent job. Its `permissions` block is the caller's, and `run`
  refuses only a classic token that names a write scope (RC-014): a job
  token cannot be inspected. A caller job granted `contents: write` that
  passes `github.token` to `run` hands the agent a token that can write, and
  no check fails. `agentic-job.yml` fixes its agent job's permissions
  itself, so only a composed job is exposed.

## 5. Conformance evidence

The linked Rust unit/integration tests and Node workflow tests are the current
evidence; there is no `run-contract-compliance` fixture directory yet. Sandbox
probes need a prepared host, and old-tree parity tests need external inputs;
a skipped privileged path is not a conformance result. Follow
[AGENTS.md](../AGENTS.md#build-and-checks) for commands and prerequisites.

A first compliance set should reuse the hand-back corpus as input/expected
accept-or-refuse vectors, keyed by RC-005 through RC-008, beginning with a valid
draft patch and its unexpected-file, protected-path and mismatched-base variants.

## 6. Non-goals

This contract does not guarantee that an accepted patch is correct or benign,
that all secrets are recognized by pattern matching, or that DNS cannot leak
data. It does not specify model behavior, the full sandbox or inference
protocol, every safe-output type, or GitHub's token permission model. It does
not confer isolation on an arbitrary caller job that uploads proposals, and
does not add gh-aw's compiler, workflow language or threat-detection service.
