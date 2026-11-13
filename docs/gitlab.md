# Running policy, check and apply from GitLab CI

> This text is LLM generated.

A GitLab caller can use the supported policy/check/apply path today:
produce safe-output requests without a write credential, check them on a
separate runner, then publish from a trusted job that alone holds the
token. This guide uses a fixed, deterministic comment to demonstrate that
path. It is not an end-to-end agent pipeline or a reusable CI component.

**Not yet verified live.** The bounds and CI example below have local
configuration and CLI tests against current source, not the pinned release
or a live GitLab or Testing Farm run.
[#2111](https://github.com/cgwalters-forge/agentic-job/issues/2111) tracks
GitLab end-to-end proof. The downstream runs reported in
[#2993](https://github.com/cgwalters-forge/agentic-job/issues/2993) used an
older two-user/provider-key topology; they do not verify this guide or
the runner-only boundary. The internal fork and runs are reported
evidence, not independently reproduced here.

## Prerequisites and unsupported cases

Use a public project at `GROUP/PROJECT`, a protected default branch, and
isolated, fresh runners for producer, check and apply. Nested subgroup
paths (`group/sub/project`) do not match the repository pattern and are
refused; support is pending in
[#3408](https://github.com/cgwalters-forge/agentic-job/issues/3408).
Merge requests from a branch in the target project itself are also
unsupported, pending
[#3409](https://github.com/cgwalters-forge/agentic-job/issues/3409): the
publisher currently requires another owner's fork.
The trusted jobs need Linux x86-64, a POSIX shell, `curl`, `jq`,
`sha256sum` and `git`; they need neither root nor systemd. Run only trusted
CI configuration from the default branch, not merge-request code. Do not
restore caches or execute scripts or binaries from producer artifacts in
check or apply. The CI operator owns runner isolation, artifact provenance
and token issuance. Fetching a producer pipeline's hand-back across
pipelines is specified, not built, in
[the GitLab caller spec](../specs/gitlab-caller.md).

**Agent inference on GitLab is unsupported pending
[#2903](https://github.com/cgwalters-forge/agentic-job/issues/2903) and
[#2989](https://github.com/cgwalters-forge/agentic-job/issues/2989).**
GitLab has no supported registration proof for the broker.
`github-oidc` needs GitHub's identity; `plain` and `token-file` leave a
bearer token readable by the runner's user. A provider API key, MCP
credential, session, `inference.front`,
`setup.tools` or child agent is refused by `run --runner-home`.
A second sandbox user is not an option. Base64 wrapping, `hidepid` and
a `run0` shim are historical downstream accommodations, not replacements
for the runner-only credential boundary. A systemd-less container cannot
replace the hardened VM needed by an agent job. See the
[current boundary](inference.md) and
[hardening inventory](plan.md#runner-only-hardening-inventory-2026-11-05).

The pipeline below deliberately has no agent, inference configuration,
registration or sandbox setup. Do not turn its producer into an agent
job until those prerequisites have a supported path. Current broker
inference still puts an agent-readable run token on the runner; it is
not credentialless inference. External ownership of identity and lifecycle
remains part of #2903, with the endpoint-only client and readiness gate
tracked by [#2999](https://github.com/cgwalters-forge/agentic-job/issues/2999)
and [#3000](https://github.com/cgwalters-forge/agentic-job/issues/3000).
Putting the same bearer in another variable or same-UID supervisor memory
is not that path. Read deployment addresses from runtime configuration or
the environment, never copy them into code.

## Pinned release binaries

Each job downloads the static binary of one tagged release and checks it
against a SHA-256 the caller keeps in its own `.gitlab-ci.yml`. The
`.sha256` sidecar comes from the same place as the asset, so it proves
nothing on its own. On a trusted workstation with `gh`, verify the
release manifest's attestation first. Run these commands in the same shell:

```sh
set -eu
tag=v0.6.13
commit=$(gh api "repos/cgwalters-forge/agentic-job/commits/$tag" --jq .sha)
from=https://github.com/cgwalters-forge/agentic-job/releases/download/$tag
curl -fsSL -O "$from/release.json" -O "$from/provenance.jsonl"
```

Bind both the attestation and manifest to that resolved tag commit:

```sh
gh attestation verify release.json --bundle provenance.jsonl \
  --repo cgwalters-forge/agentic-job \
  --cert-identity https://github.com/cgwalters-forge/agentic-job/.github/workflows/release.yml@refs/heads/main \
  --source-ref refs/heads/main --source-digest "$commit" --deny-self-hosted-runners
jq -e --arg tag "$tag" --arg commit "$commit" \
  '.repository == "cgwalters-forge/agentic-job" and .release == $tag and .commit == $commit
  and .target == "x86_64-unknown-linux-musl"' release.json
jq -r '.sha256["agentic-job"]' release.json
```

Stop if verification fails. Put the result in `AGENTIC_JOB_SHA256` below;
the all-zero value is a fail-closed placeholder, not a release checksum.
Move the tag and digest together in a reviewed change. This follows
[`binary.sh`](../secure-host/binary.sh)'s manifest verification
([release provenance](secure-host.md#where-the-binary-and-image-come-from)).
Prefer release binaries to compiling on a small CI runner; the build
stall in #2993 is reported downstream evidence, not a measured upstream
regression.

## Bounds

Save this as `.gitlab/agentic-job/bounds.toml`, changing the host and
project to yours. Bounds are the caller's ceiling, never producer input.
`[gitlab]` selects GitLab rather than `[github]`. `push_repo` names a bot's
fork of the target project, outside the target's own group; apply verifies
that relationship before pushing a merge request. This comment-only
example never pushes, but names the fork to make the GitLab policy
explicit. See [the bounds](safe-outputs.md#the-bounds-and-the-policy) and
[GitLab operations](safe-outputs.md#publishing-to-gitlab) for other types.

```toml
hosts = ["gitlab.example.com"]
repos = ["group/project"]
bases = ["main"]
max_outputs = 1
max_patch_bytes = 1048576
max_patch_files = 50

[gitlab]
push_repo = "agentic-bot/project"

[gitlab.outputs]
add_comment = { max = 1 }
```

## Minimal deterministic pipeline

This `.gitlab-ci.yml` posts a fixed comment on one issue. Replace the
checksum, issue IID and bounds before running it from *Run pipeline* on
the protected default branch. Restrict pipeline-variable overrides to
trusted operators: they must not override pins, bounds or destinations.
Provide fresh isolated runners tagged `agentic-job-trusted` and
`agentic-job-producer`. The latter must have no publisher credential.
For an existing pipeline, merge these stages and rules deliberately.

Every trusted job fetches its own bounds and builds its own policy
outside the artifact workspace. Only check accepts the producer's
artifact; apply accepts only check's report. No artifact supplies a
command, policy or destination.

```yaml
stages: [policy, produce, check, apply]

variables:
  AGENTIC_JOB_RELEASE: v0.6.13
  AGENTIC_JOB_SHA256: "0000000000000000000000000000000000000000000000000000000000000000"
  AGENTIC_JOB_BOUNDS: .gitlab/agentic-job/bounds.toml
  AGENT_ISSUE_IID: "1"

.agentic-job:
  rules:
    - if: $CI_PIPELINE_SOURCE == "web" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  variables:
    GIT_STRATEGY: clone
  before_script:
    - AJ=$(mktemp -d)
    - curl -fsSL -o "$AJ/agentic-job" "https://github.com/cgwalters-forge/agentic-job/releases/download/$AGENTIC_JOB_RELEASE/agentic-job-x86_64-unknown-linux-musl"
    - echo "$AGENTIC_JOB_SHA256  $AJ/agentic-job" | sha256sum -c -
    - chmod 0755 "$AJ/agentic-job"
    - curl -fsS "$CI_API_V4_URL/projects/$CI_PROJECT_ID" | jq -e '.visibility == "public"'
    - curl -fsS -o "$AJ/bounds.toml" "$CI_API_V4_URL/projects/$CI_PROJECT_ID/repository/files/$(jq -rn --arg p "$AGENTIC_JOB_BOUNDS" '$p|@uri')/raw?ref=$CI_COMMIT_SHA"
    - >
      "$AJ/agentic-job" policy --allow "$AJ/bounds.toml"
      --repo "$CI_PROJECT_PATH" --clone-url "$CI_PROJECT_URL.git" --base "$CI_DEFAULT_BRANCH"
      --kind branch --outputs all --max-outputs max > "$AJ/policy.json"

policy:
  stage: policy
  extends: .agentic-job
  tags: [agentic-job-trusted]
  needs: []
  script:
    - test -s "$AJ/policy.json"

produce:
  stage: produce
  extends: .agentic-job
  tags: [agentic-job-producer]
  needs: [policy]
  script:
    - mkdir handback
    - >
      jq -nc '{type: "add_comment", body: "Deterministic GitLab caller proof."}'
      > handback/outputs.jsonl
  artifacts:
    paths: [handback/]

check:
  stage: check
  extends: .agentic-job
  tags: [agentic-job-trusted]
  needs: [produce]
  script:
    - >
      "$AJ/agentic-job" collect --policy "$AJ/policy.json" --outputs handback
      --collected "$AJ/collected.json"
    # Refuse anything the producer's artifact already placed at checked/.
    - mkdir checked
    - >
      "$AJ/agentic-job" check --policy "$AJ/policy.json" --outputs handback
      --collected "$AJ/collected.json" --report checked/report.json
  artifacts:
    paths: [checked/]

apply:
  stage: apply
  extends: .agentic-job
  tags: [agentic-job-trusted]
  needs: [check]
  environment:
    name: agentic-job-apply
    action: prepare
  script:
    - >
      "$AJ/agentic-job" apply --forge gitlab --server "$CI_SERVER_URL" --repo "$CI_PROJECT_PATH"
      --policy "$AJ/policy.json" --checked checked --run-url "$CI_PIPELINE_URL"
      --comment-target "$AGENT_ISSUE_IID" --comment-target-kind issue
```

`collect` exits nonzero for refused lines and `check` for a refused batch,
so either stops the pipeline before apply. Apply checks the report against
its own policy before writing. This example handles no patch; adding
merge requests requires appropriate bounds, the fork and the checked
patch file, not an unchecked copy of the producer's workspace.

## Publisher secrets and lifecycle

Set `GITLAB_TOKEN` to a dedicated bot token with only the access needed
to post on the target project. Scope it to the `agentic-job-apply`
environment, mark it protected and masked, and protect the default
branch. With GitLab Premium, protect the environment too. Never put it
in YAML, arguments, artifacts or logs; leave shell tracing disabled.

Audit project, group and instance variables: GitLab sends variables with
the default `*` environment scope to every job. Neither producer nor
check may receive publishing secrets. For multiple publisher roles,
scope `APPLY_ROLE_BINDINGS`, `STATUS_TOKEN`, `REVIEW_TOKEN`, `PUSH_TOKEN`
and `PUBLICATION_TOKEN` to apply only
([role binding](safe-outputs.md#forgejo-and-gitlab-roles)). A caller that
opens merge requests also needs a bot token able to push to the bounds'
fork; do not broaden the comment-only token preemptively.

An external secret manager can issue a short-lived publisher token to
apply using GitLab `id_tokens` and `secrets`. It owns expiry and
revocation; neither producer nor check should request that identity or
secret. GitLab's automatic `CI_JOB_TOKEN` still reaches each job, so keep
its cross-project allowlist minimal, leave job-token Git pushes off, and
disable unneeded registry/package features. It is not the publisher token.
See [GitLab job-token permissions](https://docs.gitlab.com/ci/jobs/ci_job_token/).

## Internal certificate authorities

Install your CA in each runner image's system trust store before jobs
start (`update-ca-certificates` on Ubuntu, `update-ca-trust` on RHEL).
This covers `curl` and `git`; do not disable TLS verification.

There is a remaining limitation: apply's GitLab API client and run's
broker API client use the Mozilla roots embedded in the binary, not the
system store or `SSL_CERT_FILE`. Publishing to an internal-CA-only GitLab
API is therefore unsupported; use an API endpoint with a publicly trusted
certificate. Installing the CA for curl alone does not fix apply.

## Diagnostics and summary publication

[#2998](https://github.com/cgwalters-forge/agentic-job/pull/2998) implemented
[#2994](https://github.com/cgwalters-forge/agentic-job/issues/2994)'s `/proc`
diagnostics, described in
[inference.md](inference.md#on-a-multi-user-guest). They observe process
visibility, not a same-user credential boundary. Stacking procfs or
setting `hidepid` hides other UIDs, not the runner's own processes or
supervisor memory; do not use it as a credential solution.

[#2995](https://github.com/cgwalters-forge/agentic-job/issues/2995) is
implemented by
[#3002](https://github.com/cgwalters-forge/agentic-job/pull/3002) and included
in the v0.6.13 pin above. Check can accept `--run-summary FILE` and apply can post that checked,
sanitized summary with `--run-summary` and the caller's comment target.
This is future integration for an agent caller, not enabled by this
deterministic example. GitLab's artifact browser otherwise shows Markdown
as plain text. See [summary publication and status targeting](safe-outputs.md#publishing-to-gitlab);
commit statuses require GitLab 18.5 or later and the caller's exact ref,
SHA and pipeline ID. A reusable component remains a later decision.
