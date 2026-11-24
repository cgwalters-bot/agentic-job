# GitLab CI reference

> This text is LLM generated.

For setup and the expected result, start with [GitLab in the Quickstart](quickstart.md#gitlab).
This reference contains the configuration files for that pipeline and the
constraints for adapting it.

## Prerequisites and unsupported cases

Current source supports nested subgroup paths and explicitly admitted
same-project merge request branches, but the pinned example uses a two-part
project path and does not open merge requests. By default, merge requests
come from another owner's fork. See [GitLab publication](safe-outputs.md#publishing-to-gitlab).
The trusted jobs need neither root nor systemd. Run only trusted CI
configuration from the default branch, not merge-request code. Do not
restore caches or execute scripts or binaries from producer artifacts in
check or apply. The CI operator owns runner isolation, artifact provenance
and token issuance. Fetching a producer pipeline's hand-back across
pipelines is specified in [the GitLab caller spec](../specs/gitlab-caller.md).
Its fetch, `external-fetch --forge gitlab` with a read-only
`GITLAB_READ_TOKEN`, and its policy and check are built and tested
offline only; its release gate refuses until GitLab detection is specified,
so it cannot publish yet.

**Agent inference on GitLab is unsupported.** GitLab has no supported
registration proof for the broker.
`github-oidc` needs GitHub's identity; `plain` and `token-file` leave a
bearer token readable by the runner's user. A provider API key, MCP
credential, `inference.front`,
`setup.tools` or child agent is refused by `run --runner-home`.
A second sandbox user is not an option. Base64 wrapping, `hidepid` and
a `run0` shim are historical downstream accommodations, not replacements
for the runner-only credential boundary. Container runners can delegate
host isolation as described below; that does not supply a new
inference identity contract. See the
[current boundary](inference.md) and
[runner-mode refusals](interface.md#removed-keys-and-runner-mode-refusals).

The pipeline below deliberately has no agent, inference configuration,
registration or sandbox setup. Do not turn its producer into an agent
job until those prerequisites have a supported path. Current broker
inference still puts an agent-readable run token on the runner; it is
not credentialless inference.
Putting the same bearer in another variable or same-UID supervisor memory
is not that path. Read deployment addresses from runtime configuration or
the environment, never copy them into code.

## Explicit external host isolation

Standalone `run` defaults to external host isolation when GitLab Runner marks
the job as disposable (`GITLAB_CI=true`, `CI_DISPOSABLE_ENVIRONMENT=true`,
no `CI_SHARED_ENVIRONMENT`) and Linux shows a regular `/.dockerenv` or
`/run/.containerenv` marker, or the standard kubelet per-pod `/etc/hosts`
bind mount. A shell executor can itself run in a long-lived container, so
a container marker and `GITLAB_CI` alone are not enough. Missing systemd
and runtime environment hints alone don't count. If detection is
inconclusive, `GITHUB_ACTIONS` is present, `DOCKER_HOST` or `CONTAINER_HOST`
is set, or a well-known Docker, Podman, containerd or CRI-O socket path
exists, the default remains `managed`: a job that can reach a host engine
is not one whose host isolation the runner owns. Detection also applies
only when the configuration sets `egress.proxy = false`: a job that asks
for the local egress proxy (the default) stays `managed`, where `run`
refuses a proxy that cannot hold the agent rather than dropping it on the
strength of hints. An explicit setting always wins: use `managed`
to retain local controls on a detected container, or declare:

```toml
[host]
isolation = "external"
```

With a complete agent/inference/limits configuration, invoke standalone
`agentic-job run --config runner.toml --runner-home HOME` with the usual
policy, metadata, task and output arguments. Do not invoke `secure-host`,
`sandbox prepare` or `sandbox setup`: external mode performs no host setup
and needs no sudo, systemd, second user or owned VM. Install the agent and
its tools in the runner image beforehand. `sandbox setup` refuses this
declaration rather than suggesting it secured the host. For a session,
set `[session] listen = true` and `bind = "ADDRESS:PORT"`, and supply a
fresh per-run `AGENTIC_JOB_ATTACH_TOKEN`; a missing/short secret
is still refused. A taskless session waits for the client's first prompt.

The runner host must provide **one job per runner**, a fresh environment
for each run, an egress allowlist (including blocking cloud metadata), and
no credentials beyond the run's own. Do not mount a Kubernetes service
account token, provider key, MCP credential, OIDC request credential,
publisher token or host/container-engine socket into the agent's reach.
Pod Security admission, NetworkPolicy and node placement are the runner
hoster's responsibility, not something detection or declaration tests.

Provider-key, MCP, OIDC, private-target, front-proxy and
child-agent refusals remain. Log redaction, run limits, hostile-data checking
on a separate runner and apply as the only publisher are unchanged.

`summary.json` and the agent's hand-back metadata record external isolation
with `host_isolation_source: "declared"` or `"detected"`. Check reads the
published `host-isolation.json` as a regular file of at most 128 bytes and
retains the bounded fields in its report. Declared records keep the older
external-only encoding; detected records add the source. Upgrade check
before using a producer that emits detected records. An absent record
means unknown, not proved managed isolation. `summary.md` distinguishes
detection from declaration, neither of which is proof. Pass it to
`check --run-summary`, which
reads a bounded regular file and sanitizes it for apply. This is
producer-reported provenance, not an attestation: it must never authorize
an output or bypass bounds. Check and apply must remain on separate,
trusted runners that never execute agent-produced code.

Any readiness check must delegate only host-control evidence (privileges,
process isolation and local network enforcement), never its reachable
credential refusals. External mode does not supply an inference identity or
establish live GitLab deployment proof.

## Pinned release binaries

Each job downloads the static binary of one tagged release and checks it
against a SHA-256 the caller keeps in its own `.gitlab-ci.yml`. The
`.sha256` sidecar comes from the same place as the asset, so it proves
nothing on its own. On a trusted workstation with `gh`, verify the
release manifest's attestation first. Replace `SOURCE_OWNER/SOURCE_REPO`
with the [agentic-job source repository](../) and run both blocks in the same shell:

```sh
set -eu
tag=v0.6.13
source_repo=SOURCE_OWNER/SOURCE_REPO
commit=$(gh api "repos/$source_repo/commits/$tag" --jq .sha)
from=https://github.com/$source_repo/releases/download/$tag
curl -fsSL -O "$from/release.json" -O "$from/provenance.jsonl"
```

Bind both the attestation and manifest to that resolved tag commit:

```sh
gh attestation verify release.json --bundle provenance.jsonl \
  --repo "$source_repo" \
  --cert-identity "https://github.com/$source_repo/.github/workflows/release.yml@refs/heads/main" \
  --source-ref refs/heads/main --source-digest "$commit" --deny-self-hosted-runners
jq -e --arg tag "$tag" --arg commit "$commit" --arg repo "$source_repo" \
  '.repository == $repo and .release == $tag and .commit == $commit
  and .target == "x86_64-unknown-linux-musl"' release.json
jq -r '.sha256["agentic-job"]' release.json
```

Stop if verification fails. Put the result in `AGENTIC_JOB_SHA256` below;
the all-zero value is a fail-closed placeholder, not a release checksum.
Move the tag and digest together in a reviewed change. This follows
[`binary.sh`](../secure-host/binary.sh)'s manifest verification
([release provenance](secure-host.md#where-the-binary-and-image-come-from)).

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

Save this as `.gitlab-ci.yml`. Replace `SOURCE_OWNER/SOURCE_REPO` in the
download URL with the same repository used for verification. For an existing
pipeline, merge these stages and rules deliberately.

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
    - curl -fsSL -o "$AJ/agentic-job" "https://github.com/SOURCE_OWNER/SOURCE_REPO/releases/download/$AGENTIC_JOB_RELEASE/agentic-job-x86_64-unknown-linux-musl"
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

With GitLab Premium, protect the publisher environment as well as the branch.
Never put the token in YAML, arguments, artifacts or logs; leave shell
tracing disabled.

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

The [`/proc` diagnostics](inference.md#on-a-multi-user-guest) observe process
visibility, not a same-user credential boundary. Stacking procfs or
setting `hidepid` hides other UIDs, not the runner's own processes or
supervisor memory; do not use it as a credential solution.

Check can accept `--run-summary FILE` and apply can post that checked,
sanitized summary with `--run-summary` and the caller's comment target.
This is future integration for an agent caller, not enabled by this
deterministic example. GitLab's artifact browser otherwise shows Markdown
as plain text. See [summary publication and status targeting](safe-outputs.md#publishing-to-gitlab);
commit statuses require GitLab 18.5 or later and the caller's exact ref,
SHA and pipeline ID. A reusable component remains a later decision.

## Publication fixture

The [`gitlab` CI job](../.github/workflows/ci.yml) configures a disposable
loopback GitLab CE for `just test-gitlab`. The [fixture](../crates/agentic-job/tests/gitlab.rs)
checks that standalone apply opens a draft merge request from a bot's fork
without changing the target branch. It does not run the example pipeline.
Never point it at a shared or production instance.
