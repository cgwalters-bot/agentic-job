# What is left

> This text is LLM generated.

The sandbox, ACP harness, output checks and reusable workflow exist.
Real-agent runs and calls from another repository have happened, as
reported in the [workflow guide](workflow.md#what-has-run-and-what-has-not). They are not
evidence that every runner image or caller configuration works.

**Caller-specific examples:** the named external repositories, rollout settings
and historical audits below record this project's deployments and planning.
They are not required setup for adopters; agentic-job takes repository identities
and policy from each caller's configuration.

The 1.0 bar is
[tracker#596](https://github.com/cgwalters-forge/tracker/issues/596):
a fresh deploy passes, the README alone suffices, v1.0 is released with
stable formats and no JavaScript, and every open issue here is either a
sub-issue of that epic or marked post-1.0 (P2), with none in
`needs-design`. All four bars remain pending; implementation is not acceptance.
Earlier README audits #2199, #2738–#2741 and readiness correction
[#2864](https://github.com/cgwalters-forge/agentic-job/issues/2864) are closed,
not live owners. [#3245](https://github.com/cgwalters-forge/agentic-job/issues/3245)
owns only the bounded documentation slice: static revalidation shipped in
[#3247](https://github.com/cgwalters-forge/agentic-job/pull/3247)
([walkthrough](workflow.md#first-run-walkthrough-8-november-2026)).
The authorized README-only live trial remains pending; stage deployment and
credential evidence remain with
[agent-board#282](https://github.com/cgwalters-forge/agent-board/issues/282).
Finishing #3245's docs does not meet tracker#596's live acceptance bar.
[#556](https://github.com/cgwalters-forge/agentic-job/issues/556) still owns
CODEOWNERS/ruleset acceptance; shipped merge-policy code does not settle which
ruleset requires code-owner review or the automation-token ownership constraint.

[#2026](https://github.com/cgwalters-forge/agentic-job/issues/2026) no longer
requires manual fixture removal: cgwalters
[chose an override](https://github.com/cgwalters-forge/agentic-job/issues/2026#issuecomment-6631996337).
The existing opt-in and trusted public-base evidence shipped in #2914/#2919
([capture](../crates/agentic-job/src/check/base.rs),
[contract](safe-outputs.md#public-base-secret-evidence));
[tracker#1455](https://github.com/cgwalters-forge/tracker/issues/1455) owns
effective caller configuration and compatible producer/checker evidence before
deletion. This ledger neither enables it nor removes the fixture.
In his [13 November response](https://github.com/cgwalters-forge/agentic-job/issues/2026#issuecomment-6860948527),
cgwalters favors reusing upstream GitHub JavaScript rather than reinventing it,
weighed against sharing with other output targets. Keep the current immutable
setup-action pin and unchanged upstream handlers, with the Rust collector/checker
as the shared local-handback and cross-forge contract. Retain validation.mjs,
handlers.test.mjs/collect.cjs, the probe github-script steps and CI's apply-guard
rerun for their [upstream parity coverage](safe-outputs.md#upstream-javascript-disposition).
This bounded disposition does not establish no-JS 1.0 acceptance or complete
fixture cleanup. The ratchet exempts only the three existing corpus harness
paths, retaining corpus.test.mjs temporarily while tracker#1455 supplies evidence.
No bundling requirement has been demonstrated. A future packaging proposal must
show a concrete offline/distribution benefit and inventory dependencies and
license notices before changing delivery; no vendor/submodule design is approved
here. Standalone adoption remains with #2398.

The apply workflow's optional-PAT forwarding and CI job-token fallback contracts
now run in `crates/agentic-job/tests/apply_workflow.rs`, including the six example
callers, the exact CI caller inventory, staged environment use and read-only
permissions. Their replaced assertions are removed from `workflow/apply.test.cjs`;
the remaining shell and upstream-handler tests still run in JavaScript. This
test-only port changes no credential routing, caller settings or permissions.
The staged-apply contracts also run in that Rust suite: credential-step gating,
default-off policy forwarding, escaped preview/log output and the empty
publication report, executing the actual workflow shell without a forge.

For [tracker#1260](https://github.com/cgwalters-forge/tracker/issues/1260),
the detector artifact-release and caller-permission assertions now run in
Rust's `tests/workflows.rs`, rather than `workflow/apply.test.cjs`. They retain
the opt-in, detection-before-release, read-only check and caller OIDC contracts;
no workflow permissions or runtime behavior change. Next slices are the
remaining local shell-step tests, then the legacy corpus cleanup once
tracker#1455 supplies trusted evidence; keep actual upstream JavaScript execution
coverage and the fixture-deletion prerequisite above intact.

Apply's final success/refusal and handler-error shell tests also run in
`tests/apply_workflow.rs`. They execute the shipped steps, preserving missing-PR,
handler-failure, refused-project and missing-data/blocked cases, plus exact
annotation and output escaping. Native publisher failure is covered both alone
and beside a blocked result, which must not hide a publication failure. This
test-only migration leaves upstream handler execution in Node and changes no
runtime control or caller setting.

Fork routing and pull-request handler configuration are also covered in
`tests/apply_workflow.rs`: trusted binary before target selection, target selection
before fetching, staged-apply gating, no PR handler without a fork, and literal
title/branch prefixes in both the JSON file and exported environment. These two
tests replace their JavaScript equivalents without changing publication behavior
or the retained upstream-handler execution tests.

The policy corpus's output selectors and numeric limits now run through the
Rust CLI in `tests/policy.rs`: exact serialized grants cover `all`,
analysis filtering, duplicate selectors and per-operation ceilings, while empty,
unknown and malformed requests must emit no policy. These tests need neither
the old-tree checkout nor Node; the legacy parity matrix remains until its
gated cleanup. No runtime control or caller setting changes.

The malformed-handback corpus cases now run through the Rust CLI in
`tests/check.rs`: invalid base JSON, a short commit, oversized base metadata,
an unexpected directory and symlinked outputs. The size test also accepts exactly
4096 bytes before refusing 4097. Only those five JavaScript cases are removed;
the key-bearing fixture, old-tree CI setup and upstream parity drivers remain
subject to the disposition above. No runtime control or caller setting changes.

The hidden-change corpus attacks also have deterministic Rust coverage in
`tests/patch_git.rs`: a bare patch inside the commit message and a base64-encoded
second mail must both be refused with the expected diagnostic, while real
`git am` must apply both the visible edit and hidden workflow file. An ordinary
patch is the accepted control. This supplements the seeded mutation suite without
depending on its payload selection. The legacy old-check comparison remains;
removing it still belongs to the gated corpus disposition above. No runtime
control, permission or caller setting changes.

The malformed-output JSONL corpus cases now run in `tests/check.rs` through
the Rust collector and checker: invalid JSON, an array and an object without
`type`. Each is refused alone and after a valid request, with line-numbered
diagnostics, so a collector error cannot silently authorize the surviving
publication. Empty and valid-request controls are accepted. Only those three
legacy cases are removed; key-bearing fixtures and upstream parity remain.
This test-only port adds no runtime control or caller setting.

The omitted-mode attack also has deterministic Rust coverage in
`tests/patch_git.rs`: real Git applies edits to a plain file, executable and
symlink without an index-header mode, inheriting their types, while the reader
refuses all three ambiguous patches. Explicit-mode ordinary edits remain positive
controls. This supplements the legacy corpus comparison without removing its
old-tree/upstream coverage or bypassing the fixture-deletion prerequisite.

The bounded-update corpus now runs in `tests/bounded_updates.rs` through Rust's
`policy`, `collect` and `check` commands. It pins issue-body and PR-title admission,
body-section operations, explicit repository/target requirements, forbidden fields
(including draft and branch changes), and marking ready only with an explicit
bound. Accepted cases assert the sanitized items as well as the exit/verdict;
refusals assert their diagnostics. Only the replaced new-check JavaScript test is
removed; old-tree comparisons, upstream drivers and gated fixtures remain.
This adds no runtime control or caller setting.

The legacy policy corpus's repository/base admission cases also run independently
in `tests/policy.rs`: listed repositories (including case variants), bot-branch
globs and nested branches, unlisted targets, malformed names and JSON-shaped
input. Accepted policies retain the requested identity and limits; refusals emit
no policy. This supplements rather than removes the old-tree comparison, whose
cleanup still awaits tracker#1455. No runtime control or caller setting changes.

## Deployment

## Runner-only hardening inventory (2026-11-05)

### 1.0 disposition ledger (2026-11-08)

Snapshot: source `6b9a75c`; 26 open issues at **2026-11-08 14:17 UTC**,
read via issues and GraphQL parent/project fields. Parent numbers below are in
`cgwalters-forge/tracker`; “none” means no parent, not no owner. No visible
project items supplied Priority values: **P2 below is proposed, not applied**.
A different parent alone does not satisfy #596's literal child-or-P2 bar.
No issue, Priority, parentage, release policy or epic is changed by this ledger.
The snapshot counts and parentage remain historical; the #3245 entries below
note the later documentation completion in #3247, not new live evidence.
The [hardening epic](https://github.com/cgwalters-forge/tracker/issues/1311)
and [#2903](https://github.com/cgwalters-forge/agentic-job/issues/2903) are
acceptance owners, not permission to build another local proxy. The operator's
[decision](https://github.com/cgwalters-forge/agentic-job/pull/2913#issuecomment-6641663846)
requires no reachable credentials. The source-address recommendation on #2903
is research, not an approved identity/deployment contract.

Runner-only removal [#2991](https://github.com/cgwalters-forge/agentic-job/pull/2991)
merged on 5 November; the parser now refuses removed user keys
([tests](../crates/agentic-job/src/config/mod.rs)). The runner inventory,
caller audit and local test records below the ledger are **5 November history**,
not current deployment proof; #3001 owns their broader reconciliation.

### Proposed issue dispositions

Every open issue is listed once. Keep current #596 children there; for
separately owned non-goals propose post-1.0 P2 without moving their parent.
“Question” means a decision is needed, not a silently applied exception.

| Open issue | Applied parent | Proposal / unresolved acceptance |
| --- | --- | --- |
| [#3245](https://github.com/cgwalters-forge/agentic-job/issues/3245) | #596 | Snapshot: keep README first-run walkthrough. Update: static documentation revalidation completed in [#3247](https://github.com/cgwalters-forge/agentic-job/pull/3247); authorized README-only live trial and agent-board#282 deployment evidence still pending. |
| [#3244](https://github.com/cgwalters-forge/agentic-job/issues/3244) | #596 | Keep: this ledger, not metadata application. |
| [#3225](https://github.com/cgwalters-forge/agentic-job/issues/3225) | none | Propose #596 child: retries/diagnostics shipped; workflow/scheduler infrastructure-outcome propagation, behavioral proof and image adoption remain. Do not restore removed network-control/container-control probes. |
| [#3188](https://github.com/cgwalters-forge/agentic-job/issues/3188) | none | Question: #596 child or P2 under stated tracker#680 owner? Notification delivery shipped in part; cross-repository targeting remains. |
| [#3179](https://github.com/cgwalters-forge/agentic-job/issues/3179) | #786 | Propose P2: disposable GitLab startup/apply proof; do not reopen closed #2110/#2111. |
| [#3143](https://github.com/cgwalters-forge/agentic-job/issues/3143) | #1311 | Question: promote its two known findings to #596 or defer P2? Audit done, filing/follow-through is not. |
| [#3080](https://github.com/cgwalters-forge/agentic-job/issues/3080) | #1215 | Propose #596 child: metadata-probe CI stability, not new isolation design. |
| [#3057](https://github.com/cgwalters-forge/agentic-job/issues/3057) | #939 | Propose P2: status-comment pacing outside the 1.0 proof. |
| [#3001](https://github.com/cgwalters-forge/agentic-job/issues/3001) | #1311 | Propose #596 child: runner-only documentation/evidence, not a second audit. |
| [#3000](https://github.com/cgwalters-forge/agentic-job/issues/3000) | #1311 | Propose #596 child: enforcement/credential refusal proof with positive controls. |
| [#2999](https://github.com/cgwalters-forge/agentic-job/issues/2999) | #1311 | Question: credentialless broker launch prerequisite for 1.0 or P2? Client code is not readiness. |
| [#2997](https://github.com/cgwalters-forge/agentic-job/issues/2997) | #1311 | Propose P2: measured small-runner compile work; retain existing split work. |
| [#2996](https://github.com/cgwalters-forge/agentic-job/issues/2996) | #1311 | Propose P2: [GitLab caller docs](gitlab.md) provide a checked deterministic example; supported credentialless deployment and live GitLab/TF evidence remain pending. |
| [#2993](https://github.com/cgwalters-forge/agentic-job/issues/2993) | #1311 | Propose P2: downstream GitLab/TF evidence; two-user/API-key runs are historical. |
| [#2903](https://github.com/cgwalters-forge/agentic-job/issues/2903) | #1311 | Question: 1.0 prerequisite or P2? Operator owns identity/listener and off-agent lifecycle approval; no local proxy mandate. |
| [#2811](https://github.com/cgwalters-forge/agentic-job/issues/2811) | #596 | Keep: exact-account egress diagnostics and caller release/image proof. |
| [#2656](https://github.com/cgwalters-forge/agentic-job/issues/2656) | #674 | Propose #596 child: released-image preparation/pin acceptance, not only source wiring. |
| [#2398](https://github.com/cgwalters-forge/agentic-job/issues/2398) | #1047 | Propose P2: operator-authorized standalone adoption and immutable revision. |
| [#2397](https://github.com/cgwalters-forge/agentic-job/issues/2397) | #1047 | Propose P2: standalone CLI live publication proof; local tests do not settle it. |
| [#2070](https://github.com/cgwalters-forge/agentic-job/issues/2070) | #674 | Propose #596 child: standalone binary/image exists; released attested image and caller proof remain. |
| [#2026](https://github.com/cgwalters-forge/agentic-job/issues/2026) | #596 | Keep: fixture cleanup awaits caller override evidence; bounded upstream reuse above preserves parity, not no-JS 1.0 acceptance. |
| [#1735](https://github.com/cgwalters-forge/agentic-job/issues/1735) | #674 | Question: propose P2 extraction, but `needs-design` still violates #596. Destination/name, governance and disclosure commitments remain operator decisions. |
| [#589](https://github.com/cgwalters-forge/agentic-job/issues/589) | #57 | Propose P2: RHEL caller, ruleset and chat acceptance outside staged 1.0 scope. |
| [#556](https://github.com/cgwalters-forge/agentic-job/issues/556) | #596 | Keep: protected CODEOWNERS and chosen ruleset need operator action, not another policy implementation. |
| [#536](https://github.com/cgwalters-forge/agentic-job/issues/536) | #976 | Propose P2: sessions/chat are explicit #596 non-goals. Runner mode takes session.listen again for chat only (specs/session.md option (a)); no bridge message authorizes a write. Do not restore a second user. Left: real tailnet/serve and hosted end-to-end proof. |
| [#137](https://github.com/cgwalters-forge/agentic-job/issues/137) | #1311 | Propose P2: non-root plain-CI image and nested Podman proof, not credential isolation. |

Reuse [#3143's findings](https://github.com/cgwalters-forge/agentic-job/issues/3143#issuecomment-6676297622):
umask-dependent positive fixtures and prepared-helper validation after host
mutation. This is disposition of existing evidence, not another general audit.
Closed #2989, #2891, #2071 and #1618 are not current open-work owners.
Scratch E2E [#3240](https://github.com/cgwalters-forge/agentic-job/issues/3240)
closed during this reconciliation, after the initial 27-issue read.

Closed [#2994](https://github.com/cgwalters-forge/agentic-job/issues/2994)
diagnostics and [#2995](https://github.com/cgwalters-forge/agentic-job/issues/2995)
GitLab summary publication are in this checkout's Unreleased changelog. Keep
their existing owners/evidence, not duplicate implementation. Neither establishes
credentialless TF/GitLab launch or live publication of this revision.

### External-runner implementation slices

The [contract](dispatch.md#external-vm-runner-to-midstream-draft) of
[#2891](https://github.com/cgwalters-forge/agentic-job/issues/2891) is
designed, not built or deployed. This is its one list of follow-ups, in
dependency order, for the next replan of
[tracker#1215](https://github.com/cgwalters-forge/tracker/issues/1215).
Slices 4 and 5 are built. None has run on an external runner. Each slice is one implement-sized pull
request. None of them enables a profile, changes credentials, broker
admission or bounds, or adds ostree or any other target. Repositories
without an owner are under `cgwalters-forge`.

1. **tracker — Closed runner profile map, all disabled.** Add
   `.github/agentic-job/runner-profiles.json` with the format and
   resolution order of [runner profiles](dispatch.md#runner-profiles), and
   a `runner` input to `dispatch.yml` defaulting to `hosted`. That input
   picks where the job runs; the existing `config` choice keeps picking a
   hosted run's configuration and must be `hosted` with an external
   profile. Make the map a protected path in the caller's bounds. The map
   may hold the disabled `devspace-rhel10-64` example. Acceptance: a hosted
   dispatch is unchanged and does not read the map; an unknown or disabled
   name, a malformed map, and an external request that is not `implement`,
   targets a non-midstream repository, or sets `pool`, `effort` or another
   `config` are each refused before any workflow starts, with a test for
   each.
2. **agent-board — Carry the profile name in job plans.** In
   `docs/job-plans.md` and plan, manual and scheduled dispatch, `runner`
   accepts `hosted` or a name of `pool`'s character set and is forwarded
   as the caller's `runner` input without resolving it. `hosted` stays the
   default planners write. Acceptance: hosted plans dispatch exactly as
   today; an ill-formed name is refused; an accepted name survives dispatch,
   dedupe and in-flight tracking, and the caller's refusal of an unknown or
   disabled name is reported, not retried as hosted. Depends on 1.
3. **agentic-job — KVM and session-libvirt preflight.** A runner
   configuration opts into the [capability preflight](dispatch.md#capability-preflight).
   Setup refuses before registration unless `/dev/kvm` is readable and
   writable by the user the agent runs as, a minimal guest starts and stops,
   and, when asked, `qemu:///session` answers and creates and destroys a
   guest. Acceptance: case-table refusals for a missing or unwritable
   device and an unanswering session; the existing `libvirt` group refusal
   kept; the positive path covered by a privileged CI test where a
   KVM-capable runner exists, and otherwise listed as unverified.
4. **agentic-job — `test-evidence.json`.** `collect` accepts the file in
   the hand-back and check.yml's checked upload carries it. Check validates
   its shape and bounds, its attempt count against `max-attempts`, one
   outcome and one regular-file log per attempt, and its base, head and
   tree against the checked patch. Apply states each outcome's count in the
   draft with a link to the run. Acceptance: refusals for a tree that is
   not the patch's, too many attempts, a dropped attempt and a symlinked or
   oversized log. Implemented for
   [#3292](https://github.com/cgwalters-forge/agentic-job/issues/3292),
   off by default ([test evidence](safe-outputs.md#repeated-test-evidence)).
   Check binds the base and head. Apply's trial binds the tree, because
   check has no repository. Tracker's bounds still need
   `[github.test_evidence]` before slice 7 can use it.
5. **agentic-job — Correlate, fetch and re-check an external run.** A
   binary subcommand does steps 3 to 5 of
   [correlation](dispatch.md#correlating-a-dispatch-with-its-external-run)
   from a dispatch record, and downloads the raw hand-back for step 6.
   Policy, check and apply take the base and the hand-back's branch run ID
   from the record. check.yml's detect job gains an output saying whether
   detection ran, and apply refuses an external hand-back without it.
   Acceptance: a mock Actions API fixture succeeds, and the fetched
   hand-back passes check.yml's real `collect` and check and a staged
   apply. It
   refuses no match, two matches, a second attempt, a wrong path, ref,
   commit, triggering actor, wrapper or agentic-job revision, a failed
   detect job, a second artifact of either name, a download that does not
   match its digest, a late run, a replayed run, a hand-back on another
   base, and a skipped trusted detection. The external `policy.json` is
   never read. It needs no deployment. Implemented for
   [#3293](https://github.com/cgwalters-forge/agentic-job/issues/3293),
   off by default and tested against offline fixtures only
   ([binary interface](dispatch.md#binary-correlation-interface)).
6. **actions — External mode of the wrapper.** In
   `.github/workflows/cgwalters-agentic-job.yml`, a mode that runs policy,
   agent and check only: no apply job, no `SAFE_OUTPUTS_PAT`, the kind,
   target, base commit and `dispatch-id` as inputs, and the id as the run
   name's bracketed suffix. It runs the profile's preflight (3), fixed
   limits and cleanup. Acceptance: workflow lint and a mocked run show no
   write credential or apply job in the mode, refusal before inference
   when a capability is missing, and cleanup on cancellation. Depends on 3.
7. **tracker — Dispatch record, waiting job and trusted apply.** Write the
   record, start the external workflow from the one step that holds the
   dispatch credential, and call 5 from a waiting job with read access only.
   Then upload the hand-back again and compose agentic-job's `policy.yml`,
   `check.yml` and `apply.yml` directly, not through the wrapper, passing
   that upload's ID and digest, with the midstream bounds and the
   `agent-apply` environment. Acceptance: a staged apply against a fixture run; a hosted
   dispatch unchanged; the dispatch credential absent from every other job.
   Depends on 1, 4, 5 and 6. The credential itself is the operator's to
   provision.
8. **bootc-dev/cgwalters-devspace-sandbox** stays
   [#589](https://github.com/cgwalters-forge/agentic-job/issues/589)'s:
   the caller's move to the external mode (6) at a new commit, calling the
   wrapper by commit rather than `@main`, broker admission for its workflow
   and the RHEL KVM smoke run. One gap is not in #589 yet: its
   `dispatch.toml` names only bootc-dev repositories, so its policy stage
   refuses a `cgwalters-forge` midstream target until those forks are added
   there. Record that on #589; do not duplicate its work or edit the
   sandbox from these slices.
9. **Operator enablement and runtime acceptance.** After the
   [prerequisites](dispatch.md#status) are settled, a reviewed tracker
   change enables the entry with approved limits and new pins. Runtime
   acceptance is the contract's
   [list](dispatch.md#repeated-test-evidence-and-acceptance): one draft
   created on an allowed midstream fork from an external run, its
   repeated-test evidence bound to the checked patch, and each negative
   proof with its positive control. Documentation checks do not stand in
   for it.
10. **Later: `fix` on an external profile.** Pin the pull request's head
    from dispatch to apply for a pushed fix, as review pins its head today,
    and add `fix` to the devspace workflow (#589). Acceptance: a moved head
    is refused as stale, not rebased onto. Until then rule 5 of
    [runner profiles](dispatch.md#runner-profiles) refuses it.

### Breaking keys and safe refusals

Since merged #2991 the parser refuses `host.create-user`, `user`, `groups`,
`allow-existing-user`, `filesystem-view`, `host.check.before-agent` and
`setup.tools`, including through the `[sandbox]` alias. It rejects them by name
with a diagnostic citing #2989, including explicit false
values; callers must delete them, not set false. It also rejects
`agent-user: sandbox` and requires `--runner-home`. The probe-only
`sandbox.check.control-url`, `fetch-repo`, `allow-sockets` and `allow-tcp-ports`
remain accepted/ignored for the old image. Refusing those keys
too waits for image migration. Since #2071 these keys are under [host], and
[sandbox] is its warned alias.

Current safe refusal examples: runner admission rejects `register = "api-key"`
and `[mcp.NAME]` before setup without needing a secret; the
[MCP example](mcp.md#configuration) is tested as a refusal, not an enablement.
`run --runner-home` refuses OIDC request credentials, `inference.front`, a
private target, `before-agent`, `setup.tools` and child-agent.
Do not remove `--runner-home` to evade the refusal. A private bounds opt-in or
successful `config` parse does not grant launch support.

### Read-only caller audit and migration owners

Read main at tracker `fb7b0170e6906ed2ad20391838b123a97ecd0a19` and actions
`f05e2372d3bd5540406d444e26c70ba8c845b07d` through the GitHub API. No external
repository was modified. Runtime broker addresses are deliberately not copied.
Links below name those inspected revisions, not a claim about future main.

| Repository/file | Observed setting/pin | Outstanding migration or operator question |
| --- | --- | --- |
| actions [cgwalters-agentic-job.yml](https://github.com/cgwalters-forge/actions/blob/f05e2372d3bd5540406d444e26c70ba8c845b07d/.github/workflows/cgwalters-agentic-job.yml) | run `agent-user: sandbox`; agent `id-token: write`; non-review `inference-api-key` from INFERENCE_API_KEY; policy/check/apply at `3f9f6425119b97bb3620a38fe0adc8e79be7dc8e` (v0.6.11) | actions wrapper owner must move all three pins together to a tested release containing #2991, set `agent-user: runner`/runner-home, move OIDC registration/network authorization out of agent job, drop key forwarding and keep api-key refused. Strip setup.script from host config and run it after lockdown as runner. A pin-only bump would fail or misstate the boundary. |
| actions [cgwalters-review.yml](https://github.com/cgwalters-forge/actions/blob/f05e2372d3bd5540406d444e26c70ba8c845b07d/.github/workflows/cgwalters-review.yml) | same v0.6.11 policy/check/apply pin, run `agent-user: sandbox`, agent OIDC permission, pinned tailnet step | Same separate-register/runner migration; retain empty agent GitHub token, exact-head checks, admission bounds and deterministic submit. |
| actions [secure-host/Containerfile.pin](https://github.com/cgwalters-forge/actions/blob/f05e2372d3bd5540406d444e26c70ba8c845b07d/secure-host/Containerfile.pin) | v0.6.9, digest `008d34bf9598ef83d7859772200f26637814d2cd105028457208ddc87d69788b`; action egress defaults off and check omits --record | Release/image owner must publish and attest tested runner-only host image, then move digest/tag together and forwarder pin here. #2070/#2656 own standalone/prepare adoption; do not assume latest actions main is this checkout's effective pin. |
| actions [secure-host/hosted.toml](https://github.com/cgwalters-forge/actions/blob/f05e2372d3bd5540406d444e26c70ba8c845b07d/secure-host/hosted.toml) | lock-runner, deny-runner-metadata, deny-runner-reads true; no explicit removed-user keys | No active key deletion found. Keep host controls; absent user keys do not prevent the old image's default user creation. Explicit egress input must still select write-policy where required. |
| tracker [.github/agentic-job/hosted.toml](https://github.com/cgwalters-forge/tracker/blob/fb7b0170e6906ed2ad20391838b123a97ecd0a19/.github/agentic-job/hosted.toml), supervisor.toml, acp-experiment.toml | allow-sockets set; setup.tools example commented, not active; no active create-user/user/groups/allow-existing-user/filesystem-view/before-agent/setup.tools in any of the eight top-level TOMLs | Tracker config owner: remove stale commented tools advice; retain probe compatibility until image migration, then reconcile ignored keys. No active removed-key deletion found; do not manufacture one. |
| tracker [.github/agentic-job/acp-experiment.toml](https://github.com/cgwalters-forge/tracker/blob/fb7b0170e6906ed2ad20391838b123a97ecd0a19/.github/agentic-job/acp-experiment.toml) | child-agent name=vibe, model=zai-glm-5-3; limits.max-requests=400 | Disable that experiment/profile during migration; runner refuses child-agent. Do not revive UID-wide reaping to retain it. |
| tracker [.github/workflows/dispatch.yml](https://github.com/cgwalters-forge/tracker/blob/fb7b0170e6906ed2ad20391838b123a97ecd0a19/.github/workflows/dispatch.yml), session.yml, supervisor.yml | actions cgwalters-agentic-job wrapper at main; session dispatch requests session=true | Tracker/actions owners must coordinate wrapper rollout and freeze a tested immutable revision. Session=true requests need a wrapper revision containing the runner-only chat slice, never a fallback to a second user; real-tailnet acceptance is still unproven. Inert session operators/origins/watch-item are not session.listen. |
| tracker [.github/workflows/review.yml](https://github.com/cgwalters-forge/tracker/blob/fb7b0170e6906ed2ad20391838b123a97ecd0a19/.github/workflows/review.yml) | actions cgwalters-review at `02d0342d682cf1c265668d7823009ae1936c4061` | Move only to a reviewed wrapper containing the runner/register migration; preserve review.toml and review-command.toml policy. A moving non-review wrapper update does not migrate this pin. |

Devspace's `rhel10-kvm-smoke.toml` remains #589's owner question, outside
the allowed tracker/actions audit. Who supplies its tested migration revision
and RHEL run? Which external lifecycle owner and identity listener will support
GitLab/TF without leaving CI/provider credentials in runner-readable state?
These are not answered by removing TOML keys or approving a bot's research.

### Acceptance evidence and missing proof

These are #596's four completion bars, not a new test checklist. No qualifying
fresh-deploy or first-run report is linked in the inspected acceptance owners.
Historical fake-agent/config checks and closed audits establish narrower facts.

| Epic bar | Shipped / missing evidence at the ledger snapshot |
| --- | --- |
| Fresh deploy passes | **Pending.** [agent-board#282](https://github.com/cgwalters-forge/agent-board/issues/282) still needs an approved real Actions-backed stage path, credential placement/authority and saved green implement/review/fix/triage report plus installed recurrence. Fake transport, templates and old runs are not this proof. Require exact runner/image/caller revisions and authenticated creation/cleanup receipts. |
| README alone suffices | **Pending.** #3245's static documentation revalidation after runner-only migration completed in [#3247](https://github.com/cgwalters-forge/agentic-job/pull/3247), not a live first run. Closed #2738–#2741/#2864 are not a fresh agent's completed first run in cgwalters-forge-stage. Need a separately authorized README-only live trial, its exact release/config/pins and resolved walkthrough failures; agent-board#282 deployment evidence is still pending. Config parsing, scripted fake launch or this documentation cleanup is insufficient. |
| v1.0 and stable formats, no JS | **Pending.** [stable interfaces](stable-interfaces.md) and [changelog](../CHANGELOG.md) exist, but their promise starts at 1.0, not at documentation merge. Need an actual published v1.0 tag/release and explicit freeze of config/safe-output contracts, #2026 fixture cleanup after tracker#1455 evidence, and cgwalters' exact JS exception decision or replacement coverage. Build releases/0.x tags do not establish this bar. |
| Closed backlog | **Pending.** Only #556/#2026/#2811/#3244/#3245 are current #596 children. The other 21 require applied child/P2 dispositions or decisions; Priority was not visible in the returned project data. #1735 remains `needs-design`; a P2 proposal or different parent alone does not clear that clause. #3143 findings need follow-through, not a duplicate audit. |

Shipped source includes runner-key refusals, the public-base override and the
standalone [secure-host binary](../crates/secure-host/src/main.rs); none proves
released-image preparation, caller pin adoption, fresh-host negative controls
with positive controls, credentialless broker lifecycle or downstream RHEL/TF/
GitLab acceptance. Those retain the owners/dispositions above. No privileged
setup, live dispatch, release or issue mutation is authorized by this ledger.

## Deployment history

The cutover epic for agentic-job and agent-board
([tracker#528](https://github.com/cgwalters-forge/tracker/issues/528)) was
closed on 23 Oct as mostly done, its remainder superseded by
[tracker#890](https://github.com/cgwalters-forge/tracker/issues/890). The old
devspace runner (`devspace.yml` in that repository) still runs, as late as
30 Oct for a session. Running agentic-job
from `bootc-dev/cgwalters-devspace-sandbox` on bootc-dev's RHEL 10 runners
is [#589](https://github.com/cgwalters-forge/agentic-job/issues/589), under
the P2 epic [tracker#57](https://github.com/cgwalters-forge/tracker/issues/57).
The operator chose that path on 30 Oct, for bootc's fix and rebase rounds
first; it waits for the operator's review-required ruleset on that
repository's `main`. Its earlier research and implement runs
([what has run](workflow.md#what-has-run-and-what-has-not)) show sandbox
setup and checks on 4 and 16 cores, inference registration and request
accounting, and a comment applied there. They do not show a pull request
applied from a fork, including into the `cgwalters-forge` midstream forks;
the chat session on RHEL; or a 64-core run.

The parity tests still use cgwalters-devspace-sandbox at
[df1e867](https://github.com/cgwalters-forge/cgwalters-devspace-sandbox/tree/df1e867bb551ed8e36bd535f6d304a0861f54913).
That is a test fixture pin, not a claim that the old deployment is unchanged.
The follow-ups for running per-job VM jobs there are the
[external-runner slices](#external-runner-implementation-slices).

## Open work

Staged-apply safety contracts now run in
`crates/agentic-job/tests/apply_workflow.rs`: default-off policy forwarding,
credentialed writer gates, escaped previews and empty publication receipts.
The tests execute the shipped preview and receipt shell steps; their duplicate
JavaScript assertions are removed from `workflow/apply.test.cjs`. Runtime
behavior, permissions and caller settings are unchanged. This is independent
of the credential and detector ports in #3712 and #3724. Remaining local
shell-step tests can move next; preserve actual upstream-handler execution
coverage and the #2026/tracker#1455 fixture-cleanup prerequisite above.

The secure-host image holds the secure-host binary and no agent code
([#2070](https://github.com/cgwalters-forge/agentic-job/issues/2070)),
but only CI runs such an image yet, from its archive; the published
image and `secure-host-published` are unproven until a release. After
the next release publishes one: move cgwalters-forge/actions/secure-host's
pin to it and the forwarder's with it; then have `agent.yml` and
`example-compose.yml` run `sandbox prepare` and write
`[host.prepared]` whatever the image (such an image refuses a job's
file without it,
[#2656](https://github.com/cgwalters-forge/agentic-job/issues/2656)),
call the binary `secure-host` in the examples and the run action, and,
a release later, drop its `agentic-job` names in the image and on the
host.

Queued execution has run ([41239144677](https://github.com/cgwalters-forge/agentic-job/actions/runs/41239144677));
the gap is hosted admission coverage for the event caller, the review verdict
and dispatch's review profile. [CI](../.github/workflows/ci.yml) now wires queued scripted dispatch review to
the run-owned scratch PR and checks its actual head and published verdict.
Its read-only verifier also exercises event/review admission using that PR's
payload and refuses the actual merge-group event; `e2e-review` remains PR-only.
These are wiring claims, not hosted proof. No PR gains write or OIDC authority. This is follow-up
to [queue rollout (#464)](https://github.com/cgwalters-forge/agentic-job/issues/464).
[#2808](https://github.com/cgwalters-forge/agentic-job/issues/2808) is now closed,
not a live acceptance owner. Its closure does not establish fresh-deploy #596
acceptance; docs-only changes skip E2E too.

Host gaps left open when the sandbox and run follow-ups closed, also
untracked:
[#729](https://github.com/cgwalters-forge/agentic-job/pull/729) left other
local DNS stubs' upstreams and bus services that ask polkit nothing, and
does not probe UDP listeners; the RHEL listeners belong in that caller's
configuration. [#741](https://github.com/cgwalters-forge/agentic-job/pull/741)
left why a file made under `umask 077` came out 0664 on ubuntu-26.04, host
probes that `run` repeats only when asked (`before-agent`), proxies for
anything but the identity-token request, and a test of `run` reaching its
probes through an agent stand-in. Streaming redaction and the upload gate
([#909](https://github.com/cgwalters-forge/agentic-job/pull/909)) still
holds one line in memory whole.

Setup in Rust ([#882](https://github.com/cgwalters-forge/agentic-job/issues/882))
and the Rust egress proxy as the default
([#919](https://github.com/cgwalters-forge/agentic-job/issues/919)) are done,
but `[egress] rust-proxy = false` still installs mitmproxy from PyPI
([egress.rs](../crates/secure-host/src/egress.rs)). Agents still install with npm
([setup.rs](../crates/agentic-job/src/sandbox/setup.rs)); a prebuilt image
where every step is non-root is
[#137](https://github.com/cgwalters-forge/agentic-job/issues/137), with the
unproven prototype in draft
[#144](https://github.com/cgwalters-forge/agentic-job/pull/144).

The gh-aw gap issues (#112 to #122) are closed, leaving untracked: storing
and restoring the checked memory file
([#119](https://github.com/cgwalters-forge/agentic-job/issues/119)), and MCP
servers started from a command, more than one secret, and Playwright
([mcp.md](mcp.md), [#120](https://github.com/cgwalters-forge/agentic-job/issues/120)).
Run guards ([#118](https://github.com/cgwalters-forge/agentic-job/issues/118))
were not planned: pacing belongs to the scheduler, and per-run caps bound
spend. The unwired cooldown and per-user history were removed with the pull
request review ([#466](https://github.com/cgwalters-forge/agentic-job/issues/466)),
so per-author limits on reviews would need a new design, with no issue yet
(#2163 paces reviews by pool, not by author); until then [review](review.md) starts automatic reviews only for the owner,
members, collaborators and bots the repository lists by id.

Pushing to a pull request's branch
([#406](https://github.com/cgwalters-forge/agentic-job/issues/406)) is off in
every shipped bounds file. Before one turns it on, a scripted `fix` case in CI's
end-to-end dispatch should push to a throwaway pull request from the applying
account's fork: today the handler's configuration with `head-repo`, its patch
lookup for a nested branch and its push to the fork, to another fork or to an
accepting repository's own branch are covered only by unit
tests and by reading gh-aw's code. That needs the same bot PAT as the fork
case below.
Dispatch refuses a scripted `fix` today: a push needs an apply environment,
and a scripted run is given none, so that case needs one first.

Pull requests from a fork ([#340](https://github.com/cgwalters-forge/agentic-job/issues/340))
have run live from one caller, with a classic PAT that has the `repo` and
`workflow` scopes. The docs require `workflow`, since apply never syncs a
fork and a stale fork's push can bring in a workflow change; a PAT without
it is untried ([#426](https://github.com/cgwalters-forge/agentic-job/issues/426)).
CI does not run them: it needs an end-to-end
job that opens one from a fork again, with a bot PAT held in an
environment that a fork's pull request cannot reach. The recommended
credential is a classic `repo` PAT of a dedicated account; a fine-grained
PAT for "All repositories" of an account that owns only its forks would
be narrower, once the permissions it needs to fork, push, turn off the
fork's Actions and open the pull request are known.

### secure-host as a standalone project

[#1735](https://github.com/cgwalters-forge/agentic-job/issues/1735) is a
`needs-design` epic parked under
[tracker#674](https://github.com/cgwalters-forge/tracker/issues/674). It
does not meet tracker#596's no-`needs-design` bar; whether it is exempt or
marked P2 is the operator's call.

Before secure-host can become its own project, it has gaps against what
the OpenSSF expects of a hosted project. They are ranked in [#1736](https://github.com/cgwalters-forge/agentic-job/issues/1736#issuecomment-6330752528)
and listed here in that order, because no run can file them as issues
(dispatch.toml allows no `create_issue` output). Each item says where it
lands: in this repository now; with the operator, because it changes
`.github/`, adds a protected file name that
[dispatch.toml](../.github/agentic-job/dispatch.toml) does not exempt,
or needs a repository setting or a decision; or in the repository step 5
of #1735 creates. Sizes are the comment's.

1. Security policy and private vulnerability reporting (S, operator).
   No `SECURITY.md` exists here, in `cgwalters-forge/actions` or in
   `cgwalters-forge/.github`, and private vulnerability reporting is off.
   Add one with a private reporting route, a 14-day first response and
   the supported versions, and turn the setting on; the response
   commitment is the operator's to give.
2. Human maintainers and review (S for the files; recruiting is ongoing,
   operator). Commits and approvals here come from bots, which Scorecard's
   Code-Review check does not count. Name the maintainers in
   `MAINTAINERS.md` and `CODEOWNERS`, require a human approval in the new
   repository's ruleset, and recruit a second maintainer.
3. DCO and an authorship rule for LLM-generated commits (S for the
   tooling, M for the policy; new repository). Commits carry no
   `Signed-off-by`. Add a DCO check with sign-off by the human who merges,
   and a written rule for how LLM-authored changes are certified; the rule
   is the operator's decision.
4. Code of conduct, contributing guide and governance (S, operator). The
   community profile is at 50%. Add `CODE_OF_CONDUCT.md` (the OpenSSF
   code of conduct), `CONTRIBUTING.md` with the build, the tests and the
   rule that new behavior comes with tests, and a short `GOVERNANCE.md`.
5. Cargo and pip dependency scanning and updates (S–M, operator).
   [dependabot.yml](../.github/dependabot.yml) covers only
   `github-actions`, [renovate.json](../.github/renovate.json) only runner
   labels, and no workflow runs cargo-audit, cargo-deny or osv-scanner, so
   nothing updates `Cargo.lock` or the hash-pinned
   `egress/requirements.txt`. Add the `cargo` and `pip` ecosystems to
   Dependabot with the same cooldown, and a `cargo deny check advisories`
   (or osv-scanner) job.
6. Release SBOM, Scorecard-visible provenance and a `v*` tag ruleset
   (S–M, operator). [release.yml](../.github/workflows/release.yml)
   attests and verifies the manifest and image, but attaches no SBOM, and
   its bundle `provenance.jsonl` probably does not match Scorecard's
   Signed-Releases names. Build with `cargo auditable`, attach an attested
   SPDX or CycloneDX SBOM for the binary and image, name the bundle
   `*.sigstore.json` or `*.intoto.jsonl`, and add the `v*` tag ruleset that
   the workflow's comment says alone limits who can tag; the repository
   has only branch rulesets.
7. Scorecard and CodeQL workflows (S, operator). No workflow uses
   `ossf/scorecard-action` or `github/codeql-action`. Add a Scorecard
   workflow that publishes results and a CodeQL workflow for Rust and
   actions, both with read-only tokens.
8. Test coverage (M, operator, since the job is CI's). Coverage is not
   measured, and the real host behavior is proven only by CI's
   fresh-runner jobs (`secure-host`, its `-options`, `-no-user`,
   `-published`, `-image` and `-write-policy` variants, `world-write` and
   `world-write-runtime`). Once the [crate split](layout.md#rust-workspace)
   is done, publish a `cargo llvm-cov` report, from the privileged jobs
   too if practical.
9. Sustained parser fuzzing (M, low priority). The opt-in
   [cargo-fuzz targets](../crates/secure-host/fuzz/README.md) cover the
   `[egress]` and `[host]` configuration and `/etc/os-release` parsers in
   their own workspace; `just check` replays their seed corpora and boundary
   tests. Coverage-guided CI scheduling or a hosted fuzzing service remains
   to be set up; the local smoke runs do not establish a Scorecard result.
10. Naming (S, decision only, operator). Nothing called `secure-host`
    exists on crates.io, npm or PyPI, but the name is generic and close to
    the DoD's "Secure Host Baseline". Choose the name for step 5 and
    reserve the crate.
11. Documentation license (S, new repository). The OpenSSF charter wants
    documentation under CC-BY-4.0; today it is all MIT OR Apache-2.0.
    Settle it at extraction, with the Linux Foundation's due diligence.

## Interactive sessions

A session run waits for one operator's prompts after its task's turn, over
the tailnet ([session runs](../specs/session.md)), with the runner's user as
the agent, which can take the bridge's one client slot itself. Writes during
a session wait for a premise the agent cannot forge, and until then for the
end-of-run check and apply. A client attaches late or comes back with the
cursor it last saw ([attaching](interactive.md#attaching-to-a-session)); no
end-to-end session has run over a real tailnet.
[#536](https://github.com/cgwalters-forge/agentic-job/issues/536) tracks the
rest. [interactive.md](interactive.md) keeps the rest of the design.

## What needs the operator

Deployment policy, environment tokens, proxy admission and Tailscale SSH
access belong to the operator, as do most of
[secure-host's gaps as a standalone project](#secure-host-as-a-standalone-project).
Per-run App tokens are deferred
([tracker#403](https://github.com/cgwalters-forge/tracker/issues/403)).
Forgejo and GitLab publishers exist
([apply](../crates/safe-outputs/src/apply/), under
[tracker#786](https://github.com/cgwalters-forge/tracker/issues/786)); a
GitLab end-to-end job now uses a disposable local CE container, following the
operator's redirect of [#2110](https://github.com/cgwalters-forge/agentic-job/issues/2110),
not a gitlab.com group or token. CI must establish live proof and stability;
[#2111](https://github.com/cgwalters-forge/agentic-job/issues/2111) is closed;
[#3179](https://github.com/cgwalters-forge/agentic-job/issues/3179) now owns
disposable GitLab startup/apply proof.
The [failed GitLab job](https://github.com/cgwalters-forge/agentic-job/actions/runs/42442455838/job/128614408124)
shows admin seeding rejecting the fixed fixture password, then exit 1 with
`OOMKilled=false`; it does not establish a port collision. CI now generates
and masks a strong disposable root password before starting the container.
Comment, fork MR and LEFT/RIGHT inline readback still need a green GitLab job;
the [next job](https://github.com/cgwalters-forge/agentic-job/actions/runs/42907789357/job/130150336450)
reached readiness about 200s after container start (108.8s waiting after
compilation) and used 2.607GiB at its post-test sample, not a peak measurement.
It stopped at the protected-patch assertion: `.gitlab-ci.yml` is refused as a
structurally protected path, not by the configurable protected-files list.
The fixture now checks that exact refusal offline and verifies no notes, MRs
or branches were published on the live refusal path.
The [13 November job](https://github.com/cgwalters-forge/agentic-job/actions/runs/43351323097/job/131642896219)
passed note and fork MR readback, then saw one fork branch instead of two.
The refusal check primes GitLab's 30-second branch-list response cache
([pinned server source](https://github.com/gitlabhq/gitlabhq/blob/2e5ae10576d/lib/api/branches.rb#L56));
the fixture now polls within its existing 120-second bound for both `main`
and `agent-run`, without lowering the expected count. That job reached
readiness about 204s after container start and sampled 2.646GiB afterward,
not peak memory. LEFT/RIGHT inline readback and a green GitLab job remain
unverified: local Docker has no daemon, and Podman cannot start even
`/bin/true` in this fix runner.
A caller's own agent job ([the pieces](workflow.md#the-pieces-and-an-agent-job-of-your-own))
can be admitted by the broker only by repository, not by its workflow
file, which widens admission ([inference admission](inference.md#which-workflows-a-broker-admits));
naming a caller's own workflow file needs broker support, with the
narrowing tracked in [tracker#452](https://github.com/cgwalters-forge/tracker/issues/452).
