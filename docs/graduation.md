# Moving the repository to another owner

> This text is LLM generated.

This page is for maintainers who transfer agentic-job itself to a new owner,
for example from `OLD_OWNER/agentic-job` to `NEW_OWNER/agentic-job`. The
transfer is a manual operator step; nothing in CI performs or authorizes it.
Callers that only use agentic-job follow [Callers](#callers) below.

## What follows the repository

The repository's own workflows derive their identity from the running
repository, so these need no source change after the move:

| Item | Source | After the move |
| --- | --- | --- |
| Documentation site URL and source links | `just site-build-pages` | Built for the new owner's Pages URL. A custom domain needs separate build settings. |
| Image source label | `build.yml` | The new repository URL; image digests change. |
| Release manifest repository, attestation identity, registry namespace | `release.yml` | New releases use the new repository and `release.yml` identity. |
| Relative reusable-workflow calls in the same checkout | Workflow files | Unchanged. |

Forges redirect old repository URLs for git, issues and pull requests, but not
for Pages sites, container packages or explicit allowlists.

## What you change

Search tracked files at the revision you transfer, and decide each match
by the rules below. Never replace the old owner globally.

```sh
git grep -n -i OLD_OWNER
git grep -n -E 'ghcr.io|github.io|cert-identity|repository_owner|GITHUB_REPOSITORY'
git grep -n -E 'secrets\.|vars\.' -- .github
```

| Reference | Action |
| --- | --- |
| Package metadata (`repository` in `Cargo.toml` files) and the documentation link in `README.md` | Point at the new repository and site. |
| Literal `uses: OLD_OWNER/agentic-job/...` in workflows, examples and usage docs (including [Quickstart](quickstart.md)) | Point at the new path with the same reviewed full-commit pins. Keep the deliberate `@main` in CI's public-action proof and review its exact workflow-ingress exception with the path change. |
| Exact self-repository entries in `.github/agentic-job/**/*.toml` bounds and `workflow/{analysis,label-review,review-command,review}.toml` | Name the new repository exactly; do not widen to `NEW_OWNER/*`. |
| Self-repository key in `.github/agentic-job/hosted.toml`'s toolchain mapping | Rename the key; keep the tool list. |
| Trust identities in `.github/agentic-job/workflows.toml` `[identities]` | Move the self paths; leave external hardening actions where they are. A renamed action is not trusted because its owner matches. |
| Self-repository targets in end-to-end proofs and assertions about live configuration (including `crates/agentic-job/tests/workflows.rs`) | Update with the live paths and bounds they check. Keep fixed destinations and gates; rerun the proofs, including the public-action proof on a push to `main`. |
| Image and binary pins of past releases | Keep: old images stay in the old namespace and registries do not redirect. |
| Historical issue, pull request and commit links, recorded events and test fixtures | Keep. New fixtures use neutral names such as `example-org`. |
| Other repositories under the old owner | Keep. They do not move with this one; see below. |

### Dependencies that stay behind

Pinned external actions (the secure-host forwarder, hardening and network
wrappers, the Renovate preset) and the release checker that validates the
forwarder's image pin keep their old owner until those maintainers publish a
reviewed pin for the new image namespace. Then update the forwarder pin, its
compatibility test in `tests/workflows.rs` and the release checker together,
without weakening the checker. Sandboxes and secondary targets that CI checks
out must stay readable from the new owner, and writable where a test publishes
to them; otherwise replace them with approved fixtures or disable that test.

## Release and attestation continuity

Signed claims do not change when the download location does. Before the move,
archive one released tag's commit, `release.json`, its `provenance.jsonl`
bundle, binaries, reviewed SHA-256s and the image digest. While authenticated
to GitHub and the registry, save the image's separate bundle with
`gh attestation download "oci://ghcr.io/OLD_OWNER/secure-host@$OLD_IMAGE_DIGEST" --repo OLD_OWNER/agentic-job`.
Keep release assets and the old package available. Never delete and recreate
tags, or re-sign old bytes as if the new owner built them.

Verify an **old** release with its original identity, even when you
download it through the redirected URL:

```sh
gh attestation verify release.json --bundle provenance.jsonl \
  --repo OLD_OWNER/agentic-job \
  --cert-identity https://github.com/OLD_OWNER/agentic-job/.github/workflows/release.yml@refs/heads/main \
  --source-ref refs/heads/main --source-digest "$OLD_COMMIT" --deny-self-hosted-runners
```

Resolve `OLD_COMMIT` from the tag and compare it with the archive; check the
manifest fields and checksums as in [pinned release binaries](gitlab.md#pinned-release-binaries).
For an old image, use `oci://ghcr.io/OLD_OWNER/secure-host@$OLD_IMAGE_DIGEST`
as the subject and pass the downloaded image bundle to `--bundle` instead of
`provenance.jsonl`. Keep the original repository, workflow and source checks.
Verify a **new** release against the new repository and identity in the same
way. Never make both work by dropping the identity constraint or accepting
any workflow of either owner. See also [release provenance](secure-host.md#where-the-binary-and-image-come-from).

## Callers

GitHub [does not redirect actions or reusable workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#access-to-reusable-workflows).
Stage GitHub caller edits and policy changes before transfer. At cutover,
switch `uses` to the new path. Keep the same reviewed full SHA if it can
bootstrap under the new identity; do not wait for a new release. Update the
allowlists and app access at the same time. Run a caller at the new path
before resuming automation.

Follow nested `uses` too. For callers of the [shared review workflow](review.md),
coordinate a reviewed wrapper revision that moves its policy, check and apply
calls and its exact policy-source guards together. At cutover, repin callers to
that wrapper revision and test a review through it. A direct review on the
moved repository does not exercise the wrapper.

Check how the pinned workflow gets its binary. A retained source-addressed
release or a pre-transfer run selected by `SOURCE_BUILD_ARTIFACTS` can fail
verification under the new workflow identity. Where supported, set
`build-binary: true` to build from the same reviewed source. If the workflow
cannot build and its pin cannot select a prebuilt verifiable under the new
identity, stage a reviewed replacement SHA or wrapper that can build or select
one that verifies. Keep the caller paused until an end-to-end run through that
pin succeeds, including a review for review callers. Do not relax the identity
check.

Upgrading a pinned binary release is separate: keep verifying old artifacts
under the old identity until a reviewed upgrade moves the release,
repository, attestation identity and checksums together.

| Forge | What the caller updates |
| --- | --- |
| GitHub | `uses` paths, `.github/agentic-job/` bounds and workflow-ingress identities, the organization's allowed actions and app installation selection. |
| GitLab | Release download URLs, the expected attestation identity and checksums in the [pinned release](gitlab.md#pinned-release-binaries) setup. |
| Forgejo | The runner's pinned binary source; if it comes from a release, the same pins as GitLab. |

Inference brokers that trust workload identity tokens must accept the new
repository and workflow claims before inference is enabled again. Never accept
both owners with a wildcard.

## Checklist

### Before the transfer

- [ ] Name maintainers with write access and at least two administrators who
  can recover releases and settings. Add code owners for the repository and its
  security boundaries.
- [ ] Export the effective branch rules, including rules inherited from the old
  organization, which do not follow the repository. Recreate them: required
  pull requests and approval, extra approval for unattributed changes,
  stale-review dismissal, linear history, no force push or deletion,
  rebase-only merges, the required `ci` check bound to the forge's Actions app,
  and the merge queue. Review `workflow-ingress.yml` and the aggregate required
  check first, so the rule does not accept a spoofable job with a similar
  name. Do not weaken a rule silently.
- [ ] Protect `v*` release tags, enable release immutability and review any
  bypass actors.
- [ ] Stage the repository and caller edits from [What you change](#what-you-change)
  and [Callers](#callers). Check the new owner's allowed actions, app installations
  and container namespace. If the package already exists, confirm the release
  workflow's repository has write access under the package's Actions access settings.
- [ ] Pause dispatch, queued merges, scheduled automation and releases, and
  let publishing runs finish.

### Credentials

CI, site builds and releases need only the job token; workload identity is a
job permission, not a stored secret. Do not copy the old owner's secrets
wholesale. The optional ones are:

| Name | Decision |
| --- | --- |
| `THREAT_FEED_PAT` | Used by `feed.yml` only when `THREAT_FEED_REFRESH=true`. Leave off until a credential scoped to the new repository is approved. |
| `SAFE_OUTPUTS_PAT` | Optional apply credential; empty falls back to the job token. Reassess its scope and the `agent-apply` environment approval. |
| `STATUS_TOKEN`, `REVIEW_TOKEN`, `PUSH_TOKEN`, `PUBLICATION_TOKEN` | Role-bound publication tokens for trusted jobs. Rebind their permissions to the new repository. |
| `NETWORK_SECRET` | Network wrapper credential; review its enrollment policy for the new identity. |
| `INFERENCE_RUN_TOKEN` | Passed between jobs at run time; nothing to migrate. |
| `INFERENCE_API_KEY` | Refused at run time; do not provision it. |

Also review variables such as `WORKFLOW_LINT`, `SOURCE_BUILD_ARTIFACTS`,
`SOURCE_BUILD_COMMIT`, the inference settings and publication environments.
Take inference addresses from the deployment environment, not from docs.
Keep policy and check jobs read-only, and keep agents away from write tokens
and workload identity tokens.

### Cutover and acceptance

- [ ] Transfer the repository and check that its history, tags, releases, issue
  numbers and commit pins survived. Do not recreate the old name; that breaks
  the redirects.
- [ ] Switch the staged GitHub paths and policies at cutover with the reviewed
  pins from [Callers](#callers). Run a GitHub caller through binary setup to
  confirm the new path resolves and the binary builds or verifies.
  With the new exact bounds in place, confirm a real automatic pull request
  review and a comment-triggered review complete on the new repository name.
- [ ] Enable Pages from Actions, review the Pages environment policy, rebuild
  and check the site's assets, anchors and source links.
- [ ] Verify the archived old manifest and image without credentials. Publish
  the first new release, which pushes and attests the image under the new owner;
  the transfer itself does not move packages. Set or confirm the package's
  public visibility, test an anonymous pull by digest, and verify the new
  manifest and image attestations against the new identity.
- [ ] Run full CI and a merge-queue build on a fresh runner, and every
  end-to-end proof. Run sandbox and secure-host tests only on disposable hosts.
  Re-enable dispatch and scheduled automation last.
- [ ] Repeat the search: every remaining old-owner match must be a preserved
  historical link, fixture or identity, or an independently owned dependency.
