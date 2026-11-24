# Graduation to bootc-dev

> This text is LLM generated.

This is the transfer runbook for [#4100](https://github.com/cgwalters-forge/agentic-job/issues/4100),
part of [tracker#1671](https://github.com/cgwalters-forge/tracker/issues/1671).
The operator, not CI, transfers the repository. The proposed destination here is
`bootc-dev/agentic-job`; confirm it before executing this checklist. Nothing in
this document authorizes moving other repositories, changing trust policy, or
publishing a release. Unchecked items are transfer gates, not completed work.

## What can land before the move

Pages already derives its project URL and source links from the running
repository in `just site-build-pages`: `SITE_URL` and
`SITE_SOURCE_URL` feed `site/mkdocs.yml`. It will build
`https://bootc-dev.github.io/agentic-job/` without a source change. A custom
domain would require different build settings; none is assumed here.

`build.yml` now sets the OCI source label from
`$GITHUB_SERVER_URL/$GITHUB_REPOSITORY`, instead of baking the old owner into
`secure-host/Containerfile`. This is metadata, not an authorization control.
It changes newly built image digests; existing image pins remain unchanged.
`release.yml` already derives the manifest repository, attestation certificate
identity and GHCR namespace from the run's repository. No new option, secret,
trust exception or publication permission is added.

The overlapping [PR #3378](https://github.com/cgwalters-forge/agentic-job/pull/3378)
owns parameterising workflow trust identities. Build on its `[identities]`
contract in `.github/agentic-job/workflows.toml`, rather than adding another
organization switch. It is still open at this inventory: **do not assume its
configuration works on main yet**. Its concrete threat is a proposal naming
its own action as host hardening and running untrusted code with root. It
trusts no deployment identities by default, reads trusted base configuration,
and retains the bounded file and closed hardening-input checks. Graduation
must wait for that work (and its outstanding full-check verification), or
explicitly schedule the remaining `src/workflows/rules.rs` identity edits.

## Reference inventory and replacement rules

Inventory taken against `6bfd22f` and open PRs on 2026-11-14. Re-run these
tracked-file searches at the final transfer revision; do not globally replace
the old organization. Each match falls under the rules below, including
historical links and recorded fixtures that deliberately keep their old value.

```sh
git grep -n -i cgwalters-forge
git grep -n -E 'ghcr.io|github.io|cert-identity|repository_owner|GITHUB_REPOSITORY'
git grep -n -E 'secrets\.|vars\.' -- .github
```

| Reference / source | After transfer | Action |
| --- | --- | --- |
| `https://github.com/cgwalters-forge/agentic-job` in root `Cargo.toml` and `crates/safe-outputs/Cargo.toml` | `https://github.com/bootc-dev/agentic-job` | Update package metadata when the destination exists; redirects suffice meanwhile. |
| README's `https://cgwalters-forge.github.io/agentic-job/` | `https://bootc-dev.github.io/agentic-job/` | Update the public entry link at cutover; Pages does not redirect. |
| Live `cgwalters-forge/agentic-job` workflow/action references in `.github/workflows/ci.yml` and the private-digest workflow template | `bootc-dev/agentic-job` with the same paths and reviewed commits | Update literal `uses` paths; GitHub does not support expressions in `uses`. Preserve the intentional public-action integration test. |
| Reusable-workflow examples in `.github/workflows/example*.yml`, `dispatch.yml`, `docs/{dispatch,quickstart,events,workflow}.md` and other current usage prose | `bootc-dev/agentic-job/...@COMMIT` | Update recommended caller paths; keep full-commit pins. Same-checkout relative workflow calls need no edit. |
| `.github/agentic-job/{allow,check-run,dispatch,items,people,secondary,threads}.toml`, `workflow/{analysis,label-review,review-command,review}.toml` | Exact self-repository entries become `bootc-dev/agentic-job` | Update caller bounds, not generic defaults; do not broaden to `bootc-dev/*`. |
| Self key in `.github/agentic-job/hosted.toml`'s toolchain mapping | `bootc-dev/agentic-job` | Preserve the tool list. Comments there and in `secure-host/hosted.toml` still refer to the external actions repository. |
| `.github/agentic-job/workflows.toml` and production workflow identities in `crates/agentic-job/src/workflows/rules.rs` | PR #3378's caller-configured self paths become `bootc-dev/agentic-job/...`; external hardening paths stay put | Land #3378 first. Do not treat a renamed action as trusted merely because its owner matches. |
| `.github/workflows/safe-outputs-cli.yml`, `.github/actions/safe-outputs-proof/{guard.cjs,guard.test.cjs}`, `.github/agentic-job/e2e/safe-outputs-context.json` | Self-repository gate, clone URL, API path, comment URL prefix and context repo all become `bootc-dev/agentic-job`; issue stays 64 | Change together before running the proof again. Keep its fixed destination, main-only gate, environment and rerun refusal. |
| `.github/agentic-job/e2e/analysis.sh` self issue target | `bootc-dev/agentic-job` | Keep the item number; run the real read-back proof after transfer. |
| Secondary e2e scripts, `.github/agentic-job/secondary.toml` and CI's `aw-cgwalters-forge-misctool-...` patch name | Unchanged `cgwalters-forge/misctool` | This is another repository, not the transferred self-repository. Confirm cross-org publication permission or disable that test explicitly. |
| `secure-host/Containerfile` source label / `.github/workflows/build.yml` | Build context's repository URL | Parameterised by this change; local builds can supply Podman's `--label` explicitly. |
| `ghcr.io/cgwalters-forge/secure-host:vVERSION` and digest pins | Old objects stay at the old namespace; new releases publish `ghcr.io/bootc-dev/secure-host:vVERSION` | No registry redirect. Do not rewrite a pinned old image's location or digest speculatively. |
| `release.json` repository and release attestation identity | New releases use `bootc-dev/agentic-job` and `https://github.com/bootc-dev/agentic-job/.github/workflows/release.yml@refs/heads/main` | Old signed manifests and identities remain old; see continuity below. |
| OIDC `sub` containing `repo:cgwalters-forge/agentic-job:...`, `repository` and reusable `job_workflow_ref` claims | New runs carry the new repository/workflow names | Update external broker trust before enabling inference; environment suffixes still depend on each job. Never accept both organizations with a wildcard. |
| Historical issue, PR, commit and evidence links throughout `docs/`, `site/`, `specs/`, `CHANGELOG.md` and source comments | Keep the original URL | GitHub redirects self-repository links. Links to other projects describe those projects, not a transfer request. |
| Recorded events/transcripts, corpus fixtures, `safe-outputs/fixtures/add-comment/source.json`, `tests/data/sandbox/ci.toml`, tests in `src/{policy,config/compose,run/session_markdown}.rs`, `tests/{event,policy,private_digest,workflows}.rs`, `safe-outputs/src/bounds.rs`, `workflow/test_workflows.py` | Keep historical data; use neutral `example-org` names for new fixtures | These are not deployment settings. #3378 already neutralises overlapping policy/workflow-rule fixtures; do not rewrite recordings to claim they ran after transfer. |

Other source references in `run/action.yml`, `src/run/enter.rs` and
`crates/secure-host/src/` describe the external hardening contract, or are test
data, not a self-repository runtime default. Registry host allowlists such as
`ghcr.io` are host-based and need no organization change.

### Other repositories are not moving implicitly

`cgwalters-forge/actions` supplies the pinned secure-host forwarder in
`secure-host/action.yml`, direct site/CLI hardening steps, and the Tailscale
wrapper plus raw `tailnets.json` URL in `.github/agentic-job/network/action.yml`.
It also supplies `.github/renovate.json`'s `renovate/runners` preset.
`release-check.rs` intentionally reads that action's pinned `Containerfile.pin`
and validates its `ghcr.io/cgwalters-forge/secure-host` image. Those are external
dependencies: leave them pinned where they are until the actions maintainers
publish a reviewed pin for the new image namespace. Moving agentic-job alone
does not move that action or its package. Align the forwarder pin, the published
path compatibility test in `tests/workflows.rs`, and the diagnostic release
checker together when adopting the new package; do not weaken the checker.

`cgwalters-forge/secure-host` in `crates/secure-host/Cargo.toml` describes the
planned standalone component; confirm its intended canonical metadata with
maintainers rather than inventing `bootc-dev/secure-host`. The compiler and
`gh-aw` fork links in `docs/{compiler,requirements,workflows-check}.md` are
design/parity provenance, not an instruction to transfer those repositories.

CI also checks out `cgwalters-forge/cgwalters-devspace-sandbox`. Keep that
dependency and the `misctool` secondary target accessible from bootc-dev, or
replace them with separately approved fixtures. `agent-board`, `agenthome`,
`forge-infra`, `.github`, `bot`, `review`, `homegit`, `agentic-job-trial` and
`bootc` references are historical evidence, caller examples or test fixtures;
none becomes a bootc-dev repository by textual substitution. Malformed paths,
case variants and REST user-route fixtures are likewise not real dependencies.

`cgwalters-forge/tracker` owns dispatch configuration and the graduation epic.
Before transfer, its operator must inventory its `.github/agentic-job/` bounds,
workflow `uses`, source repository/ref settings, workflow-ingress identities,
installation permissions and any repository property/topic routing. Set the
self target to `bootc-dev/agentic-job` and keep pinned commits unchanged until
reviewed upgrades. Do the same for every downstream caller found through
organization code search. Redirects alone do not update explicit bounds,
Actions allowed-action policies, GitHub App installation selection or OIDC
broker allowlists. No new caller option is introduced in this patch.

## Release and attestation continuity

Before transfer, archive a known released tag's commit, `release.json`,
`provenance.jsonl`, binaries and caller-reviewed SHA-256s, plus old OCI digests
and verification bundles. Keep immutable release assets and the old GHCR
package available. Do not delete/recreate tags or re-sign old bytes as if they
were built by bootc-dev. A source-label change produces a different image;
it is a new release, not a transparent retag of the old digest.

For an **old** release downloaded through the redirected repository URL,
verify the saved bundle with its original identity, not the current owner:

```sh
gh attestation verify release.json --bundle provenance.jsonl \
  --repo cgwalters-forge/agentic-job \
  --cert-identity https://github.com/cgwalters-forge/agentic-job/.github/workflows/release.yml@refs/heads/main \
  --source-ref refs/heads/main --source-digest "$OLD_COMMIT" --deny-self-hosted-runners
```

Resolve `OLD_COMMIT` from the chosen tag and compare it with the archived
commit; also require the manifest's original `.repository`, `.release`,
`.commit`, `.target` and binary checksums as in [the verification example](gitlab.md#pinned-release-binaries).
The download location can change; signed claims cannot. Use the old OCI name
and digest for old image verification. Test tokenless bundle verification on
a clean workstation after transfer: bundle availability and identity matching
are a gate, not something verified by this documentation change.

For the first **new** release require the new exact repository/certificate
identity, tag commit and manifest fields. `release.yml` already supplies these
from context and tests its own bundle before publishing. Retain
`--deny-self-hosted-runners`, exact source digest and reviewed checksums.
Never solve continuity by dropping the identity constraint or allowing any
workflow in either organization. Existing callers stay on old pins until a
reviewed change moves the release, identity, repository and checksums together;
see [release provenance](secure-host.md#where-the-binary-and-image-come-from).

## Operator checklist

### Before accepting the transfer

- [ ] Name bootc-dev maintainers with write/maintain access and at least two
  administrators able to recover releases/settings. Confirm security reporting
  and release ownership. There is no tracked CODEOWNERS at this revision;
  maintainers must add an approved bootc-dev team covering the repository and
  security boundaries. CODEOWNERS is protected from this run's patch output.
- [ ] Record effective rules, not just repository settings. Public API reads
  on 2026-11-14 found repository ruleset `24074126` and inherited organization
  ruleset `25084478`. The inherited rule will not follow the repository into
  bootc-dev. Recreate equivalent protections before resuming writes.
- [ ] Preserve main's PR requirement, one approval, stale-review dismissal,
  extra approval for unattributed changes, linear history, no force push or
  deletion, and rebase-only merges. Decide explicitly whether to require
  code-owner review (currently false); do not silently weaken existing rules.
- [ ] Preserve required check `ci`, bound to GitHub Actions integration 15368,
  and the merge queue: REBASE, ALLGREEN, 1–3 entries per merge, 3 builds,
  one-minute minimum wait, 90-minute check timeout. Confirm bootc-dev's plan
  supports the queue. `ci.yml` handles `merge_group`; test that path, not only
  a PR build. Review `workflow-ingress.yml` and the aggregate required check
  before copying settings; do not require only a spoofable similarly named job.
- [ ] Protect release `v*` tags and enable/confirm release immutability. Export
  existing settings and any bypass actors for operator review; tag protection
  and immutability were not established by this run's API reads.
- [ ] Land/verify #3378, prepare the exact caller/configuration edits from the
  inventory and review organization Actions allowlists and App installations.
  Keep commits pinned. Pause dispatch, queued merges, feed refresh and releases
  during cutover; drain publishing runs before changing destinations.

### Credentials and services

Ordinary CI, site builds and release publishing need no stored secret beyond
the scoped `GITHUB_TOKEN` (OIDC is a job permission, not a stored secret).
Do not copy the old organization's secrets wholesale. Exceptions in the
workflow sources are optional automation/caller features, not CI requirements:

| Name | Use and transfer decision |
| --- | --- |
| `THREAT_FEED_PAT` | `feed.yml` proposes feed updates only when `THREAT_FEED_REFRESH=true`. Leave off until a destination-scoped credential is approved. |
| `SAFE_OUTPUTS_PAT` | Optional apply publication credential, including self-hosted dispatch/examples; empty falls back to the job token. Reassess cross-repository scope and `agent-apply` environment approval. |
| `STATUS_TOKEN`, `REVIEW_TOKEN`, `PUSH_TOKEN`, `PUBLICATION_TOKEN` | Optional role-bound caller publication tokens; only trusted consuming jobs receive them. Rebind installation/repository permissions, not agent access. |
| `NETWORK_SECRET` | Optional agent network/Tailscale wrapper credential; review the wrapper's enrollment policy for the new repository identity. |
| `INFERENCE_RUN_TOKEN` | Short-lived registration output passed between jobs, never a secret to migrate. Update broker OIDC claims before enabling registration. |
| `INFERENCE_API_KEY` | Declared compatibility input; API-key execution is refused. Do not provision it to make CI pass. |

Repository variable listing returned HTTP 403 in this run; actual secret,
variable and environment configuration remains operator-only evidence.
Export it out of band without secret values. In particular review
`WORKFLOW_LINT` (exact `OWNER/REPO@40-hex` shared-check source),
`SOURCE_BUILD_ARTIFACTS`/`SOURCE_BUILD_COMMIT`, inference URL/audience/register/
provider settings and publication environments. Obtain inference addresses
from the deployment environment, never from this document. Preserve read-only
policy/check jobs and keep agents away from write tokens and OIDC credentials.

### Cutover and acceptance

- [ ] Transfer the repository; verify repository ID/history, tags, releases,
  issue numbers and commit pins survived. Update local remotes and current
  metadata/usage links from the inventory. Do not recreate the old repository
  name: that would defeat redirect continuity.
- [ ] Enable Pages source **GitHub Actions**, review the `github-pages`
  environment's branch/deployment policy, rebuild and verify
  `https://bootc-dev.github.io/agentic-job/`, including assets, anchors and
  source links. Arrange any old-site/custom-domain migration separately.
- [ ] Create/authorize `ghcr.io/bootc-dev/secure-host` for this repository's
  Actions token, set intended public visibility, and verify anonymous pulls
  and attestations. Repository transfer does not transfer GHCR packages.
  Retain old package access; coordinate the external actions forwarder update.
- [ ] Verify the archived old release without credentials; publish one new
  version through the existing release workflow and verify its manifest and
  image against the new exact identity. No publishing test ran in this patch.
- [ ] Run a fresh-runner full CI and merge-group queue check, the coordinated
  issue-64 proof and all e2e read-backs. Check secondary `misctool` permissions
  separately. Sandbox/secure-host tests must run on disposable hosts, not an
  existing sandbox. Re-enable dispatch and scheduled automation last.
- [ ] Re-run the reference searches. Every residual old-owner match must be
  either an intentionally preserved historical identity/fixture/link or an
  independently owned dependency. Record acceptance evidence in this document
  and link it as `Findings:` from the graduation issue; this run cannot edit
  that issue body through its allowed safe outputs.

## Burn-down: parked pull requests

Verdicts for [#4259](https://github.com/cgwalters-forge/agentic-job/issues/4259),
part of the burn-down [#4113](https://github.com/cgwalters-forge/agentic-job/issues/4113).
They are taken from each PR head diffed against main at 740ff7f on 2026-11-15.
Result: salvage three, keep three, and #3693 merged minutes later. Every
`CHANGELOG.md` and
`.github/release.yml` hunk is superseded by 5527fdd (#4203) and 376930e (#4232).
A replacement drops those hunks. None of the seven has a label now, even though
the poll's notes on five of them say `needs-human`.

- [#3333](https://github.com/cgwalters-forge/agentic-job/pull/3333) secure-host
  extraction root: **keep**. Main already has its standalone crate manifest
  (c5a308c). Nothing else splits off cleanly: even the crate docs
  (`README.md`, `EXTRACTION.md`) describe the `ci/ci.yml` rename, the retained
  `egress/` path and the `legacy-runtime` feature, which main lacks. The
  parts depend on each other. The `ci/ci.yml` template tests `egress/` in its
  new place and the `legacy-runtime` feature. The `timed.rs` move renames the
  stage log prefix that `ci.yml` greps for. `runtime.rs` and `legacy-runtime`
  rename privileged paths. Together they make one security-boundary PR under
  [#1735](https://github.com/cgwalters-forge/agentic-job/issues/1735), and a
  human has to push it because it edits `ci.yml` and `example-secure-host.yml`.
  The PR overlaps the test ports in `tests/workflows.rs` and `docs/plan.md`.
  Its bot approval of 2026-11-12 is on a head far behind main, so the rebase
  needs a new review.
- [#3674](https://github.com/cgwalters-forge/agentic-job/pull/3674) hardened
  job container: **keep**. None of it is on main. It is waiting on a maintainer
  to accept the container-job workflow shape and install
  `job-container/workflow.yml` as a workflow
  ([run](https://github.com/cgwalters-forge/tracker/actions/runs/43629982043),
  [#137](https://github.com/cgwalters-forge/agentic-job/issues/137)). It has no
  test-port overlap.
- [#3690](https://github.com/cgwalters-forge/agentic-job/pull/3690) old-side
  address recovery: **keep until d543dde is proven**, then close as superseded.
  d543dde replays redacted old sides against the trusted base and makes
  replacement series fail closed, but `[commit] replay-redacted-endpoints` is
  off by default and covers only native `create_pull_request`. The tracker sets
  neither that key in `hosted.toml` nor `native_handlers` in `dispatch.toml`,
  as d543dde asks. d543dde targets cgwalters-forge/tracker#1638, while the PR
  is part of cgwalters-forge/tracker#1309, and both are still open. Close the
  PR once the tracker enables both and a hosted run shows #1309 fixed.
  If replacement-series replay is still wanted, it belongs in a
  new issue built on `crates/safe-outputs/src/replay.rs`. That issue should
  also take on d543dde's open follow-up: apply literal placeholders the
  ordinary way first, as 5ee3b2a tried. The PR overlaps
  `tests/apply_workflow.rs` and `tests/check.rs`.
- [#3693](https://github.com/cgwalters-forge/agentic-job/pull/3693) review merge
  policy: **merged** as 6831f8d on 2026-11-15, right after the snapshot above,
  so it no longer holds the test ports in `tests/workflows.rs` and `policy.yml`
  ([#556](https://github.com/cgwalters-forge/agentic-job/issues/556)).
- [#3694](https://github.com/cgwalters-forge/agentic-job/pull/3694) attachment
  admission: **salvage**. None of it is on main, and the operator direction on
  [#3692](https://github.com/cgwalters-forge/agentic-job/issues/3692) still
  wants it. One rebased commit would carry the two `policy/attachments`
  modules, the `policy.rs` hook, `tests/attachments.rs` and the docs and spec
  text. That is about 1,800 lines with no review yet, and nothing in dispatch,
  run, check or apply uses it, so it would land as unused groundwork. It
  overlaps the test-port draft
  [#3879](https://github.com/cgwalters-forge/agentic-job/pull/3879) in
  `policy.rs`.
- [#3695](https://github.com/cgwalters-forge/agentic-job/pull/3695) threat-feed
  retry: **salvage in place**. The approved head 8821cf8 sits on top of 943038e,
  and its tree is 3fca003 plus the feed change: only
  `crates/secure-host/src/egress.rs` and `docs/workflow.md` differ, and
  main's fetch still has one 60-second window that a single stalled attempt
  can use up. Rebasing the branch onto main as one commit without the changelog
  hunk keeps the PR; `docs/workflow.md` has changed on main since and needs a
  small merge. Its test-port overlap comes only from stale rebase hunks, so the
  rebase drops it.
- [#3696](https://github.com/cgwalters-forge/agentic-job/pull/3696) stack
  receipts: **salvage**. Main has only the caller-bounded stack steps
  (b316bbc). A smaller PR on top of that would carry the receipt binding and
  revalidation: d535752, plus the per-step size check from 5ce1991. Leased pushes
  and per-step publication (9ecf31d through 5aaf444) would get their own review later.
  That review should include the unbalanced `pre`/`code` closing lines the
  last run flagged in `publish.rs`
  ([note](https://github.com/cgwalters-forge/agentic-job/pull/3696#issuecomment-6869134349),
  [#3438](https://github.com/cgwalters-forge/agentic-job/issues/3438)).
  It overlaps #3879 in `docs/stable-interfaces.md`.
