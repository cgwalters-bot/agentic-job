# Running it on GitHub

Pin the reusable workflow to a published `vMAJOR.MINOR.PATCH` tag to use
that release's static Linux binaries. Policy resolves the tag to its own
workflow commit, verifies that the release manifest is attested by
`release.yml` on main at that commit, and checks the manifest's commit, source
digest and SHA-256 checksums before handing the binaries to the other jobs by
artifact ID. A release editor who replaces assets and checksums cannot forge
that attestation. Missing assets or mismatches stop the run; they do not fall
back to a build. Use a new release for this path: older releases lack the
attested, commit-bound manifest and policy object. Release publishing uploads
all assets to a draft before publication locks an immutable release.

Branch and full-commit pins retain the source-addressed, attested download/build
path; `build-binary: true` still forces a build. No caller ref selects a release.
Tagged downloads avoid the roughly 1.5-minute per-run compile described in
issue #606; actual savings depend on download and runner setup time, not measured
by the local tests.

Bootstrap requests use `gh` with the job's read-only token. Tag refs resolve
lightweight tags directly; annotated or unavailable refs use the commits API.
Rate-limited 403/429 responses retry within two minutes, respecting GitHub's
retry and reset headers; ordinary permission denials fail immediately.

[`.github/workflows/agentic-job.yml`](../.github/workflows/agentic-job.yml)
is one agent run as a workflow another repository calls. It is a thin
wrapper: the `agentic-job` binary decides what a run may ask for, runs
it and checks what comes back, and the workflow moves files between
separate jobs on separate machines. The apply job's additional checks are
[listed below](#what-the-apply-job-does-before-it-writes).

1. **policy**, on a small hosted machine. It checks that the target
   repository is public, fetches or builds the binary, and checks the run's request
   against the caller's bounds file (`agentic-job policy`). A request
   outside the bounds stops here, before a machine is spent on the agent.
   Discussion events are refused here until notification and output routing
   can address the discussion namespace safely.
   **activate**, on another hosted machine, removes an admitted command
   label with the caller's write token. The agent and notification jobs
   depend on its success; removal failure starts neither. Runs not started
   by a command label pass through without writing.
2. **agent**, on the caller's runner. [The step that secures a host for
   any job](secure-host.md), the action in `secure-host/`, creates the
   unprivileged user, the network rules and the egress proxy, removes
   general root access and probes access (`agentic-job sandbox setup` and
   `sandbox check`); `run` clones the target, drives the agent and
   leaves what may be uploaded.
3. **check**, on a machine the agent never touched. gh-aw's collector
   validates and sanitizes the producer's requests, then `agentic-job check`
   holds them and the patch to the policy.
4. **detect**, inside the check workflow on a separate read-only machine,
   optionally inspects accepted proposals before releasing their artifact ID.
5. **apply**, on a machine of its own, uses a write credential.
   It runs gh-aw's handlers on the checked outputs:
    a branch and a draft pull request, comments.

## Optional threat detection

Set the caller repository variable `AGENTIC_JOB_DETECT_MODEL` to a model served
by the configured inference proxy to enable detection. A run with a provider's
API key (`inference-register: api-key`) has no proxy the detector could
register with, and its key never reaches the detector's host: enabled detection
fails closed and blocks apply. To use API-key inference without detection,
the caller must explicitly unset this variable. An empty or absent
variable disables it (the default); dispatch inputs cannot change this setting.
The concrete threats are prompt-injected output instructions, secret leaks and
malicious patches that pass structural checks. Detection supplements, never
replaces, deterministic validation, and is not proof that a proposal is safe.

The separate detect job has `contents: read` and `id-token: write`, no write
credential or agent tools. It registers its own run through the same inference
proxy using the policy's configuration (`github-oidc` or `plain`, not
`token-file` or `api-key`, which fail). That proxy must be reachable from the hosted detector runner.
It sends the task, checked outputs and patches as untrusted evidence to one
OpenAI-compatible chat-completions request, capped at 2 MiB of evidence, 256
output tokens and 120 seconds. There are no retries or tool continuations.
Any threat, malformed/truncated verdict, unavailable model, registration or
cleanup error blocks release of the checked artifact and therefore apply.
Expected deterministic refusals do not run detection. The ordinary apply
conclusion/status path is unchanged. Composed callers must use check.yml's
returned artifact ID, not discover the internal pre-detection upload by name.
Composed callers must grant the check workflow `id-token: write` in addition
to `contents: read`; the deterministic check job itself retains only read access.

`activate`, `notify` and `conclude` also inherit the caller's permissions
and can remove labels, post reactions and create or edit status comments.
None of these write-capable jobs executes code produced by the agent.
Notifications are off by default (`notify: none`). With `notify: comment`,
event items and numeric `comment-target` values (including dispatch, schedule
and proposals-only runs) have one bot status comment, found by a hidden marker
and edited at start and finish across runs. It links the Actions run and the
result, or names the failed jobs/check refusal. For a run that hands back only
`missing_data`, `missing_tool` or `noop`, it includes the agent's reason, using
the same sanitizer as other agent text, limited to 1000 characters and quoted.
The same reason remains in the run summary; apply posts no separate notice.
The shipped dispatch caller opts in except for reviews, which remain silent.
Same-repository comments use the caller's job token. Cross-repository comments
use the explicitly supplied `SAFE_OUTPUTS_PAT`, in notify and conclude only;
without it the comment is skipped and the job summary explains why. No new
permission is granted. Status API failures do not fail apply. Composed callers
must pass that secret to both policy and apply for start and finish updates.
The supplied token must identify a user through `GET /user`; an unsupported
identity fails the status step rather than editing another author's comment.
Notify does not enter the apply environment: an environment-only credential
is not available there unless the caller supplies it explicitly.
Status writes with a supplied credential are not gated by apply's environment
approval; the credential remains confined to the pinned deterministic helper.

The lookup accepts only the job token's `github-actions[bot]` marker, or the
cross-repository token's authenticated user and marker, so another user's
copied marker cannot redirect an edit. It stops after 20 pages of 100 comments,
failing rather than creating a possible duplicate. Notify and conclude serialize
their lookup/write on the repository/item to avoid simultaneous creates.
A stored Actions run ID prevents a slower older run from overwriting newer status.
GitHub may replace a pending job in that concurrency group; notifications are
best-effort, not a run gate. Existing unmarked comments are not deleted or migrated.
Only the workflow's pinned source is checked out in these write-capable jobs,
with persisted credentials disabled; no agent-produced code is executed.

`policy` and `check` have `contents: read`; `agent` has `contents`,
`issues`, `pull-requests` and `actions` read, not repository write
permissions and no `id-token`, and hands its token to the agent for
[GitHub reads](#github-reads-from-the-agent). `register` has
`id-token: write` alone ([the run token](#the-run-token)).

## The run token

Under `inference-register: github-oidc` the run registers at the
inference broker with the job's identity token. With `id-token: write`
any step of a job, and anything that becomes the runner's user, can
mint identity tokens for any audience, not only the broker's: a cloud
whose trust policy admits this repository would take them
([secure-host.md](secure-host.md#one-trust-level-for-the-rest-of-the-job)).
So `agentic-job.yml` registers in a job of its own, `register`, before
the agent's. It has `id-token: write` and no other permission, checks
out nothing, and runs only the policy job's binary
(`agentic-job register`), on the agent's runner, which is on the
broker's network as the agent must be. What leaves it is the broker's
run token: narrow (inference for this run), capped by the broker,
expiring, and ended by `run` when the agent is done. The agent's job,
[`agent.yml`](../.github/workflows/agent.yml), has no `id-token`; `run`
takes the run over after `GET /v1/runs/self` says it is active. Other
modes, and no proxy at all, write no token, and `run` registers as
before.

The token passes as a job output. GitHub has no narrower channel: it
drops a job output that is masked, so the register job cannot mask it,
and an artifact or a cache entry could be read by more than this run's
jobs (an artifact by anyone who can read the repository). The output is
kept with the run and is read in one place: `agentic-job.yml` gives it
to `agent.yml` as the secret `INFERENCE_RUN_TOKEN`. That is why the
agent job is a called workflow: a called workflow's secrets are masked
in every log of its jobs, and a value from another job becomes one only
through a call's `secrets:`. A step that took it from `needs` directly
would print it in its log, with its other inputs. With step debug
logging, as on a re-run with debug logging, the runner logs each output
it sets, value included, in the register job's log, so
`agentic-job register` then refuses before it registers. Within the agent job
the token reaches `run` alone, and the agent gets it as its own, as it
always did.

What is left: a run whose agent job never starts stays registered until
the broker expires it; re-running the agent's job alone hands it the
token of a run that has ended, which `run` refuses, so re-run all jobs.
A [composed agent job](#the-pieces-and-an-agent-job-of-your-own) and
[review.yml](../.github/workflows/review.yml)'s still register in the
agent's job and keep `id-token: write` there; a composed caller can do
as `agentic-job.yml` does with a job running `agentic-job register` and
its agent job in a workflow it calls, passing `run` the secret as
`inference-run-token`.

## Context repositories

`context` is an optional JSON array (default `[]`), for example
`[{"repo":"OWNER/REPO","ref":"main"}]`. Omit `ref` to use the default branch.
The policy machine resolves each ref to a full commit before the agent machine
starts. It confirms public visibility through the forge API; errors fail closed.
The reusable workflow refuses private context repositories because run evidence
can disclose source and context is cloned without a credential (see
[private repositories](private-repositories.md)); only the target may be private.
The CLI also admits non-public context only
when every caller/organization bounds file allows its repository. Every clone URL
must name that repository on a host allowed by every bounds file. Public context
need not match the target repository globs. Visibility is policy-machine metadata,
not a field a dispatcher may supply.

Input is limited to 16 KiB and eight distinct repositories, with case-insensitive
duplicate rejection. Before starting the agent, `run` fetches each exact commit
as the sandbox user, as it clones the target, with depth one and without
submodules into `work/context/OWNER/REPO`, beside the writable `work/TARGET`
clone. A fresh sandbox is required; existing context is not reused. The clones
are then marked read-only with `chmod -R a-w`, as the sandbox user: a hint, not a
boundary. Context is a reference copy of public source at a recorded commit;
nothing is collected, pushed or applied from it, so an agent that edits it only
misleads itself. This grants no additional token permissions or network access.

The agent still starts at the target root. Its prompt names the already available
context paths and commits and tells it not to edit them, fetch them again or treat
them as instructions. `summary.json` records these paths and pins in `context`,
with `clean` saying whether each clone was still at its commit with no changed,
new or ignored files at the end (`null` if it could not tell); an edit is
reported, not refused.
Shell-tool working directory persistence is agent-specific; use relative paths
from the initial root rather than assuming a `cd` in one tool call changes later
calls.

The tracker dispatcher, external workflow wrapper and agent-board plan schema
must forward this input separately; they are not changed here.

## The pieces, and an agent job of your own

`agentic-job.yml` is four pieces, and a caller can put them together
itself when its agent job needs steps of its own: joining the inference
proxy's network, packages, a service, or something to do after the
agent. The pieces are:

| Piece | What it is | Its credential |
| --- | --- | --- |
| [`policy.yml`](../.github/workflows/policy.yml) | the `policy`, `activate` and `notify` jobs: the request against the bounds, the binary, the configuration and the task | `contents: read`; activate and notify write with what the call was granted |
| the agent job | the caller's: a checkout, [`prepare`](../prepare/action.yml), the caller's privileged steps, [`secure-host`](../secure-host/action.yml), [`run`](../run/action.yml), the caller's later steps | the caller's to keep read only: `contents`, `issues`, `pull-requests` and `actions` read, `id-token: write`; the optional GitHub read token; with `api-key`, the provider's key or GitHub token as `run`'s input `inference-api-key`, and as `AGENTIC_JOB_INFERENCE_KEY` for an optional `agentic-job check-key --config .agentic-job/config.toml` before `secure-host`; with an [`[mcp.NAME]` server](mcp.md), its credential as `run`'s input `mcp-token`; for GitHub billing with this job's own token, `copilot-requests: write` and no GitHub read token |
| [`check.yml`](../.github/workflows/check.yml) | the outputs held to the policy, then optional threat detection | `contents: read`, `id-token: write` for detect only, no secrets |
| [`apply.yml`](../.github/workflows/apply.yml) | the `apply` and `conclude` jobs | `SAFE_OUTPUTS_PAT` or the call's job token, which also needs `actions: read` |

Every setting is an input of `policy.yml` (the same inputs as
`agentic-job.yml`, without `agent-runner` and `github-reads`, which
are the agent job's), and check and apply take the policy call's
outputs as they are, with `toJSON(needs.policy.outputs)`: what is
checked and applied is what that call decided. The agent job passes
`prepare` only the policy call's two upload IDs, and check and apply
take nothing from it but its proposals' upload ID, its result and its
exit state. Its actions come from the commit of the policy call, by
the call's `source-repository` and `source-sha` outputs, so that one
pin covers the binary, the actions and the three workflows: name all
three by the same commit. Check and apply refuse, as their first step,
a policy call whose `source-repository` and `source-sha` are not their
own workflow's. `prepare` and `run` refuse, before they use the policy
upload, one whose commit is not their own: their ref when it is pinned
by a full commit, otherwise the HEAD of the checkout they run from.

A complete caller, with a network join before the agent and a step
after it. `example-org/network-join` stands in for whichever action
joins your proxy's network, pinned by commit:

```yaml
jobs:
  policy:
    uses: cgwalters-forge/agentic-job/.github/workflows/policy.yml@COMMIT
    permissions:
      contents: read
    with:
      id: ${{ inputs.item }}
      task: ${{ inputs.task }}
      repo: ${{ inputs.repo }}
      allow: .github/agentic-job/allow.toml
      config: .github/agentic-job/runner.toml
      agent: claude
      inference-url: ${{ vars.INFERENCE_URL }}
      inference-audience: ${{ vars.INFERENCE_AUDIENCE }}

  agent:
    needs: policy
    if: ${{ needs.policy.outputs.admitted == 'true' }}
    runs-on: ubuntu-26.04
    timeout-minutes: 360
    permissions:
      contents: read
      issues: read
      pull-requests: read
      actions: read
      id-token: write
    outputs:
      exit: ${{ steps.run.outputs.exit }}
      over-budget: ${{ steps.run.outputs.over-budget }}
      secret-at: ${{ steps.run.outputs.secret-at }}
      safe-outputs-artifact-id: ${{ steps.run.outputs.safe-outputs-artifact-id }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ needs.policy.outputs.ref }}
          persist-credentials: false
      - name: The policy call's source repository and commit
        env:
          SOURCE_REPOSITORY: ${{ needs.policy.outputs.source-repository }}
          SOURCE_SHA: ${{ needs.policy.outputs.source-sha }}
        run: |
          echo "$SOURCE_REPOSITORY at $SOURCE_SHA"
          [[ "$SOURCE_REPOSITORY" == */* && "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: ${{ needs.policy.outputs.source-repository }}
          ref: ${{ needs.policy.outputs.source-sha }}
          path: .agentic-job-source
          persist-credentials: false
      - uses: ./.agentic-job-source/prepare
        with:
          binary-artifact-id: ${{ needs.policy.outputs.binary-artifact-id }}
          policy-artifact-id: ${{ needs.policy.outputs.policy-artifact-id }}
      # Your privileged steps: they have root.
      - uses: example-org/network-join@0123456789abcdef0123456789abcdef01234567
        with:
          audience: ${{ vars.NETWORK_AUDIENCE }}
      # The inference proxy over that network, before setup.
      - run: agentic-job secure-host inference .agentic-job/config.toml
      - uses: ./.agentic-job-source/secure-host
        with:
          binary: /usr/local/bin/agentic-job
          config: .agentic-job/config.toml
      - id: run
        timeout-minutes: 340
        uses: ./.agentic-job-source/run
        with:
          github-token: ${{ github.token }}
      # Your later steps: the runner's user, without root.
      - env:
          EXIT: ${{ steps.run.outputs.exit }}
        run: echo "the agent's exit state was $EXIT"

  check:
    needs: [policy, agent]
    if: ${{ !cancelled() && needs.policy.result == 'success' && needs.agent.outputs.safe-outputs-artifact-id != '' }}
    permissions:
      contents: read
      id-token: write
    uses: cgwalters-forge/agentic-job/.github/workflows/check.yml@COMMIT
    with:
      policy: ${{ toJSON(needs.policy.outputs) }}
      safe-outputs-artifact-id: ${{ needs.agent.outputs.safe-outputs-artifact-id }}

  apply:
    needs: [policy, agent, check]
    if: ${{ always() && needs.policy.result == 'success' }}
    uses: cgwalters-forge/agentic-job/.github/workflows/apply.yml@COMMIT
    permissions:
      contents: read
      issues: write
      pull-requests: write
      actions: read
    secrets:
      SAFE_OUTPUTS_PAT: ${{ secrets.SAFE_OUTPUTS_PAT }}
    with:
      policy: ${{ toJSON(needs.policy.outputs) }}
      agent: ${{ toJSON(needs.agent) }}
      check: ${{ toJSON(needs.check) }}
```

Keep the `if:` lines as they are. The agent job runs only for an
admitted request, and only after the whole policy call succeeded,
activate included. Notify does not gate it: when any of its steps
fails the run goes on, and `conclude` posts the status in a new comment
on the item if there is no comment to edit. Check also runs after a failed agent run
that handed something back. Apply always runs once policy succeeded,
and decides from check's result and the agent's exit state whether
anything is applied and how the run is reported. For a
[proposals-only caller](#proposals-from-a-non-agent-job) there is no
agent job: check runs on `needs.policy.result == 'success'`, and apply
takes no `agent`.

**Your agent job's permissions** are yours to keep read only: grant
it `contents`, `issues`, `pull-requests` and `actions` read and
`id-token: write`, as above, and nothing more (or no `id-token`, with
the run registered in a job before it: [the run token](#the-run-token)). This is your
obligation: declare that `permissions` block on the job. `run` gives
the agent the token you pass, your job's included, and cannot see
what a job token was granted; a job that can write gives the agent a
token that can write, and no check catches it
([RC-017](../specs/run-contract-spec.md#34-the-callers-own-agent-job)).
Give the `apply` call `actions: read` too: apply looks up the checked
outputs' upload ID it is given, and takes it only if it is check's
`checked-outputs` of this run, whatever the `needs` it was wired from.

**Your privileged steps** go between `prepare` and `secure-host`. They
run as the runner's user with sudo. They come before anything of the
agent's is on the machine, and before `secure-host` takes root away.
Leave alone what `prepare` wrote: `.agentic-job`, `.agentic-job-source`
and `/usr/local/bin/agentic-job`. Leave no credential where the
sandbox user can read it: `secure-host` closes the places
[it lists](secure-host.md), and nothing else. A step that has to undo
itself at the end of the job can do so only without sudo
([sandbox-check.md](sandbox-check.md#after-setup-nothing-has-root)).

**Your later steps** go after `run`. They run as the runner's user
without sudo, outside the sandbox, after the agent's outputs were
uploaded. They can read what the agent left on the machine. Treat it
as hostile: don't execute it, and run untrusted commands with
`agentic-job sandbox exec`. Check and apply never read anything these
steps make. [specs/run-contract-spec.md](../specs/run-contract-spec.md#34-the-callers-own-agent-job)
is the contract and names the tests that hold it.

[example-compose.yml](../.github/workflows/example-compose.yml) is this
form, with the two places marked; CI's `e2e-compose` runs it with an
example step in each. The shipped [dispatch.yml](../.github/workflows/dispatch.yml)
still calls `agentic-job.yml`, so that its agent job stays a called
workflow's for the broker.

### Migrating from the Tailscale inputs

`tailscale-oauth-client-id`, `tailscale-audience` and `tailscale-tags`
are gone, and so is the workflow's own `tailscale/github-action` step.
A caller that joined a tailnet with them now writes its agent job as
above and joins with an action of its own choosing, pinned by commit,
as its privileged step. A copy of `agentic-job.yml` kept for such a step is no longer needed,
nor a variable set in place of `job.workflow_*`: the policy call's
`source-repository` and `source-sha` outputs name the source. A caller
that set none of them changes nothing. Join without the network's DNS;
`sandbox setup` refuses a resolver on the tailnet.

A caller-owned agent job is the caller's workflow file, so its identity
token's `job_workflow_ref` names that file, not `agentic-job.yml`. A
`called_workflows` entry for `agentic-job.yml` no longer matches it, and
the broker has to admit the calling repository's own workflows instead
([inference admission](inference.md#which-workflows-a-broker-admits)).

### Migrating an agent job of your own off secure-host's agent steps

secure-host no longer checks the inference proxy or has a
`session-endpoint` output. An agent job that composes the pieces adds
`agentic-job secure-host inference .agentic-job/config.toml` as a step
after its network join and before secure-host, as
[above](#the-pieces-and-an-agent-job-of-your-own), and reads
`session-endpoint` from the run action's step instead.

### Migrating a direct call of check.yml

`check.yml`'s separate inputs are gone: it takes `policy`, the
`toJSON(needs.policy.outputs)` of a `policy.yml` call of the same
commit, and `safe-outputs-artifact-id`. A caller that called it
directly calls `policy.yml` first, as [above](#the-pieces-and-an-agent-job-of-your-own),
and `apply.yml` after it. A caller of `agentic-job.yml` changes nothing
but dropping the `tailscale-*` inputs: a call that still passes them is
refused when the workflow starts.

### Migrating to pull requests from a fork

The `refused-pull-request` input of `agentic-job.yml` and `policy.yml` is
gone: apply no longer pushes a branch to the output repository, so there
is no pushed branch for `branch` to end with. A call that still passes
it, `fail` or `branch`, is refused when the workflow starts, as for any
unknown input; drop it when bumping the pin. A caller that asks for
`create_pull_request` also needs `apply-environment` with a
`SAFE_OUTPUTS_PAT` of an account that does not own the output
repository ([pull requests come from a fork](#pull-requests-come-from-a-fork)),
unless that repository [accepts its owner's branches](#a-repository-the-applying-account-owns),
and no longer needs `contents: write`, which only pushed the branch.

`push_to_pull_request_branch` went the same way: only to a pull request
apply opened from its fork
([#430](https://github.com/cgwalters-forge/agentic-job/issues/430)); it
now goes to any open pull request's branch apply may push to
([#553](https://github.com/cgwalters-forge/agentic-job/issues/553)). Its
bounds lose `repos`, which a bounds file that still names it is refused
for: drop it. A call that pushes needs `apply-environment`, and no call
needs `contents: write` for it any more.

## What has run, and what has not

Read this before relying on it.

- The branch pipeline runs in this repository's CI on same-repository pull requests, twice,
  with the scripted agent (`fake`): once to the end, and once stopped at
  a limit. The egress proxy, the network rules and every probe of
  `sandbox check` are real in those runs. The apply job posts the
  comments with the job's own token; neither run asks for a pull
  request, which takes a PAT ([below](#pull-requests-come-from-a-fork)).
- Claude Code and opencode have run real tasks on RHEL 10 runners.
  The reusable workflow has been called from
  `cgwalters-bot/agentic-job-trial`: runs
  [37587896350](https://github.com/cgwalters-bot/agentic-job-trial/actions/runs/37587896350)
  and [37588497422](https://github.com/cgwalters-bot/agentic-job-trial/actions/runs/37588497422)
  opened pull requests [#1](https://github.com/cgwalters-bot/agentic-job-trial/pull/1)
  and [#2](https://github.com/cgwalters-bot/agentic-job-trial/pull/2) there.
  [Issue #59](https://github.com/cgwalters-forge/agentic-job/issues/59)
  records these deployments. No caller exists in the operator's runner
  repository, `bootc-dev/cgwalters-devspace-sandbox`, yet.
  Claude Code and opencode have also run through the reusable workflow on
  GitHub-hosted runners using its old built-in `tailscale-*` inputs, including
  agent configuration and analysis runs (the [retest record](https://github.com/cgwalters-forge/agentic-job/issues/186#issuecomment-6081817294)).
  Those inputs have since been removed; see
  [Migrating from the Tailscale inputs](#migrating-from-the-tailscale-inputs).
  A caller-owned network join has run a real agent on hosted
  `ubuntu-26.04` only in this repository's [`review.yml`](review.md#configuration),
  which composes the pieces itself and joins this deployment's tailnet, then
  inline and now in its network step
  (opencode, [run 38666714558](https://github.com/cgwalters-forge/agentic-job/actions/runs/38666714558)); no other caller has.
- This repository's CI opens no pull request: apply opens one only from
  a fork, which takes a PAT that CI does not hold. `apply.test.cjs` runs
  the fork step, the handlers' configuration and the guard against a
  stand-in for the forge. Those local tests do not prove live fork
  creation or Actions disabling; a live run opened a pull request from the
  fork (apply refuses to push unless Actions read back as off there), as recorded in
  [#426](https://github.com/cgwalters-forge/agentic-job/issues/426).
  That [run, 38068331946](https://github.com/cgwalters-forge/tracker/actions/runs/38068331946),
  called from `cgwalters-forge/tracker`, used an `output-repo` other than the
  caller: it opened [board-test#45](https://github.com/cgwalters-forge-stage/board-test/pull/45).
- The example caller has been dispatched on this repository's main
  branch: once to the end, with the scripted agent's built-in session,
  and once naming a private repository, which stopped in the policy
  job. homegit's `bot-runs list`, `show`, `log` and `reconcile` read
  the first of those runs.
- The event path (`event: true`) runs in CI on same-repository pull requests and
  push of this repository (`e2e-event`, [below](#event-triggered-callers)):
  admitted on a pull request, with the comments on the pull request;
  refused on a push. With a merge queue, PRs skip these callers and merge
  groups exercise refusal only: event admission, the review verdict and
  dispatch's review profile are not covered there. Restoring that coverage is
  [follow-up work](plan.md#open-work). The slash-command, label and schedule examples are
  live here with the scripted agent.
- With a merge queue configured, pull requests (including forks) skip CI's
  write-capable end-to-end jobs; the queue runs them before landing. Without
  a queue, non-documentation fork pull requests still fail the gate because
  their read-only token cannot run those jobs. No PAT is forwarded to them.
- Not yet verified: `apply-environment` (the live caller passes a variable,
  but its resolved value is not confirmed by the cited evidence).
- Not yet verified: a `merge_group` run. No merge queue is configured
  yet, so CI has only run the pull request and push paths.
- Not tried at all: a network join in a composed caller other than
  `review.yml`, and applying a `create_issue`:
  that type is checked through gh-aw's collector and `check` in CI
  (the `corpus` job), and its handler has not run from this workflow.

## CI runner use

Workflow and action edits are also vetted by the independent base-defined
[workflow ingress check](workflow-ingress.md), including fork pull requests.
It gates a merge only once an administrator requires it in a ruleset, without
a merge queue. The queue rollout below gives up that enforcement; it is a
trust-boundary change, not just a capacity change.

The run action reports setup seconds from GitHub's job start to the first ACP
`session/prompt` dispatch, including checkout, hardening, clone and registration
(or the takeover of the run the register job registered).
If the agent never receives a task it reports that timing is unavailable.
CI asserts that the hosted `e2e-full / agent / agent` job completes within 900 seconds;
this generous regression bound is not the under-one-minute setup goal.
Job start and completion use read-only Actions metadata; the first task timestamp
comes from the harness's outgoing transcript, not an agent-provided timestamp.
Timing-report failures cannot prevent artifact upload. On a failed-jobs rerun the
bound checks the latest full agent execution, including one from a prior attempt.

CI keeps one required sentinel named `ci`, depending on the `always()`
`required-checks` aggregation job. The aggregate fails on failed, cancelled or
unexpectedly skipped dependencies; the sentinel only succeeds after it succeeds.
There are no workflow-level path exclusions. Following
[bootc's CI](https://github.com/bootc-dev/bootc/blob/main/.github/workflows/ci.yml),
the read-only `changes` job queries the base branch's effective rules. With a
`merge_queue` rule, pull requests run the non-writing checks only, and
`merge_group` runs the end-to-end callers with this repository's job tokens.
Without a queue, same-repository pull requests also run those callers. A rules
API failure fails the gate rather than guessing that testing can be deferred.
With a queue, pull requests also leave the privileged host jobs (sandbox
probes, secure-host, world-write, confined, session-sandbox) to the merge
group, so a pull request learns of their failures only when queued.
A push to main whose commit already has a successful `merge_group` run of
this workflow, built on the commit main was at before, runs only `changes`,
`secure-host-published` and the gate: the queue fast-forwards main to the
tested commit, and repeating its jobs only held runner slots under the
account's limit on concurrent jobs. Any other push runs the whole suite; a
failed look-up fails the gate. The cost: a flaky test that passed in the
queue is not run again on main, and main saves no fresh Rust caches, so after
a dependency change jobs restore an older cache by prefix while one is kept. The
[ingress workflow](workflow-ingress.md#merge-queue) also runs for merge groups;
the ruleset requires its `vet` context besides `ci`, whose aggregate does not
include it. A merge group runs the queued pull request's
own workflow files and code with this repository's job token, including the
write and OIDC permissions of the end-to-end callers, before it lands. Entering
the queue is what grants them, so whatever admits a pull request to the queue
is the gate on its workflow changes. Even a group that fails and is ejected may
already have written to the forge or spent inference budget. The queue must
require an approving human review of the current head before enqueueing,
including its workflows, actions and code executed outside the sandbox. Do not
enable the queue until that approval gate is enforced: configure at least one
required approval, require approval of the most recent push, and dismiss stale
approvals on push. Use no bypass actors, or require each bypass actor to run and
verify the full E2E suite. Future caller-bounded auto-merge must not bypass human
approval of the current head for any apply-opened PR. Workflow and action edits
(`.github/**`, `action.yml`/`action.yaml`) are examples, not the whole boundary:
the queued tree's binary and host scripts also run outside the sandbox with
write or OIDC authority. This restriction is not implemented here: part 3
remains follow-up work. The event caller reports a successful policy refusal
on merge groups, rather than trying to find a triggering pull request. The
review caller's would be another refusal, so `e2e-review` runs on pull requests
only (that `workflow/review.toml` refuses merge groups and pushes is left to
the crate's `review_caller_bounds_gate_roles` test), and dispatch omits its
PR-only review profile. Their verifiers handle these events explicitly.

The rules API's acceptance of percent-encoded slashes in base branch names has
not been verified live; an API rejection fails `changes` and the `ci` gate closed.

Queue detection is a snapshot at the PR run, not a merge-time guarantee. Before
removing the queue rule or changing it to evaluate-only, block direct merges and
rerun CI on every open PR head that passed while the queue was active. Those
green statuses did not include E2E. Actors able to bypass the queue must also
run and verify the full E2E suite before direct merging; a green PR `ci` is
insufficient. Changing the rules does not invalidate old green statuses.

Broker acceptance of pre-landing OIDC is **unknown**, not demonstrated here.
Merge-group jobs request it from
`refs/heads/gh-readonly-queue/main/pr-N-<sha>`; `secure-host/hosted.toml` configures
the host, not broker trust. The broker operator must verify the actual claims
and workflow/ref allowlist described in [inference admission](inference.md)
before enabling the queue. Acceptance authorizes spend from unmerged code;
refusal stalls the queue's E2E jobs. Do not broaden the allowlist merely to make
CI green without reviewing that pre-landing authority.

The path check uses the complete
Git diff (PR merge base to head, merge-group base to head, or push before to after), without an API's
changed-file pagination limit. Only `README.md` and Markdown under `docs/`
skip the `e2e-*` callers and their write-capable verifier.
Renames check both names; empty diffs, missing history and unknown events run
the suite. Other checks, including sandbox probes, still run where the queue does not defer them. In particular,
`workflow/review.md` is executable reviewer input, not documentation for this
filter. Workflow, sandbox, policy, fixtures and checks changes run every caller.
The aggregate accepts only those named skips when `changes` explicitly reports
`false`; detection failures, unexpected skips and cancelled jobs remain red.

CI already cancels superseded PR runs with its workflow/ref concurrency group;
main pushes are not cancelled. The dedicated review caller cancels an older
review when an automatic PR event arrives, using a per-PR group on its agent
job, which only admitted runs reach: a comment cannot cancel a review, and
only an admitted `/review` can replace a pending one. Cancellation is
best-effort: an
already-posted verdict still names its old SHA, and cancelling CI can leave
scratch branches/comments if its cleanup does not finish. No cancellation is
merge authorization or rollback.

The people E2E creates a scratch PR on `e2e-scratch/<run-id>-<attempt>`.
Both assignment and review request target that PR, and verification and cleanup
use its returned number, checking its head repository and branch before acting.
The fixture job alone creates branches/PRs; the scripted agent still has only a
read token. That job and the verifier hold write tokens, so their fixture code is
inline in `ci.yml` and they check out nothing from the proposed tree. The login comes from the repository's people bounds, not caller input.
Cleanup never sweeps other scratch PRs. Shared issue comments are filtered by
run URL; the analysis body assertion checks only the invariant text because
concurrent analyses may replace the same island. The shared eyes reaction is
not deleted: GitHub coalesces it across runs, so deleting it would race another
run's assertion. Live concurrent merge-group execution remains a forge CI check.

For a recent successful same-repository PR run,
[37870929248](https://github.com/cgwalters-forge/agentic-job/actions/runs/37870929248),
the sum of each caller's non-skipped job durations was:

| Caller | Runner-minutes | Jobs that ran | Distinct coverage |
| --- | ---: | ---: | --- |
| `e2e-full` | 7.27 | 5 | Patch/quoted handler inputs, branch and comment application |
| `e2e-limit` | 5.63 | 5 | Task limit, partial hand-back, forced source build |
| `e2e-event` | 6.20 | 7 | Event admission, base selection, notifications and conclusion |
| `e2e-review` | 4.33 | 5 | Base-owned review task, analysis verdict and reviewed SHA |
| `e2e-verify` | 0.33 | 1 | Forge assertions and cleanup |

These are elapsed runner-minutes, excluding queue waits, not billing-rounded
minutes or six minutes multiplied by every job. On main run
[37871861845](https://github.com/cgwalters-forge/agentic-job/actions/runs/37871861845),
event and review each ran only policy to prove refusal (2.22 and 2.08 minutes).
`e2e-analysis` and `e2e-analysis-refused` are not present in those samples, so
their costs remain unmeasured: the former exercises fixed-destination topic
analysis, the latter proves hostile destination refusal before apply.

All callers repeat binary acquisition and sandbox setup, but they prove
different contracts. Keep policy, agent, check and apply on separate machines:
sharing the agent's machine with a checker or writer would erase the boundary
the suite tests. Serial calls still create separate reusable-workflow jobs and
do not save runner-minutes. Combining the analysis pair or full/limit into a
new multi-scenario workflow would add machinery and reduce isolation; no callers
are combined here. The docs-only gate saves the whole caller group instead.

Landing uses required checks, GitHub auto-merge and a merge queue, not a land
job. An administrator enables the queue rule only after the approval, status
transition and broker prerequisites above are verified;
this change does not alter repository settings. It is **not** single-build batching for free:
[GitHub's queue documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue)
explicitly says merge limits do not combine `merge_group` builds. The queue can
avoid repeated manual rebases and limit build concurrency, but still tests
cumulative groups. Required review statuses and caller-bounded auto-merge for
pull requests opened by apply are separate follow-up work; neither is added here.

Queue detection uses the existing pinned GitHub script action with contents-read
access; event fields are API parameters, never interpolated shell code. Checkout
pins and non-persisted credentials are unchanged. The queue's ref belongs to this
repository, allowing the existing write-capable E2E calls without a deployment
PAT. Their permission blocks, apply-only token placement and cleanup remain
unchanged. Analysis callers use the merge-group ref to read the queued tree.
The aggregate additionally covers both analysis callers. The sentinel has no
permissions and executes no repository code. No sandbox or output guard changes.

## Proposals from a non-agent job

A caller job can upload an artifact containing `outputs.jsonl` in the
[safe-output format](safe-outputs.md), then call this workflow with
`proposals-artifact` naming it. The producer needs no write credential.
Policy still reads the caller's bounds; check still collects and validates
the requests on a separate read-only machine; apply and opted-in cross-repository
status jobs receive the write token. No agent, sandbox setup or inference runs.
Event admission, review and partial application are not available in this mode. Use a trusted caller ref
for the bounds, just as for agent runs.

```yaml
jobs:
  proposals:
    runs-on: ubuntu-24.04
    permissions: {}
    steps:
      - run: mkdir proposals && printf '%s\n' '{"type":"noop","message":"No proposals today."}' > proposals/outputs.jsonl
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: board-proposals
          path: proposals/outputs.jsonl
          if-no-files-found: error
  apply:
    needs: proposals # uploads outputs.jsonl as board-proposals
    uses: cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@COMMIT
    permissions:
      contents: read
      issues: write # apply may post the allowed comments
      pull-requests: read # the agent job's GitHub reads
      actions: read # the agent job's GitHub reads, and apply's look-up of check's upload
      id-token: write # GitHub validates the skipped register job's permission too
    with:
      id: board
      repo: OWNER/REPO
      allow: .github/agentic-job/allow.toml
      outputs: add_comment,noop
      max-outputs: '2'
      proposals-artifact: board-proposals
```

Copy the [shipped bounds file](../.github/agentic-job/allow.toml) to the path
above, set its `repos` and the call's `repo` to your public repository, and
replace `COMMIT` with a reviewed commit. Put these jobs in a workflow with
your chosen trigger. The producer above sends a noop; replace it with your
job's requests. For comments, set `comment-target` to an existing issue number.
`add_comment,noop` is within the shipped bounds; `create_issue` requires your
own explicit bounds entry. Set `max-outputs` no higher than your bounds file's
`max_outputs` (the workflow default is 3).

Keep the permissions above, or configure `apply-environment` as below and
grant `issues: read`. Even proposals-only callers need the register
job's `id-token: write` and the agent job's reads: GitHub validates the reusable workflow's
permission requests before deciding which jobs to skip. No OIDC token is requested in proposals mode.
CI's `e2e-proposals` runs this noop producer and call without a sandbox or model.
The artifact name selects untrusted data only; it does not select the policy,
binary or handler code. Upload just the hand-back files, not a checkout.
For patch proposals the existing branch, base and patch guards still apply.
`exit` is empty because no agent ran. Issue closure and label additions use the
[bounded issue actions](safe-outputs.md#closing-issues-and-changing-labels);
issue and pull request edits, the [listed fields](safe-outputs.md#updating-issues-and-pull-requests).
Pull request closure and sub-issue links use the
[same scope](safe-outputs.md#closing-pull-requests-and-linking-sub-issues).
Project updates use [named project and field bounds](safe-outputs.md#updating-project-fields)
and the apply environment token described below, not the job token.

## A caller

[`.github/workflows/example.yml`](../.github/workflows/example.yml) is a
complete one, for the scripted agent, started by hand; the
[README](../README.md#try-it) has the same caller written for another
repository. Copy it and `.github/agentic-job/allow.toml` to the same paths.
Either copy `.github/agentic-job/hosted.toml` too, or set `config` to
`.agentic-job-source/.github/agentic-job/hosted.toml`, which the workflow
reads from its own source at the pinned commit, so the pin covers the
hardening and there is no copy to keep. Replace `uses: ./.github/workflows/agentic-job.yml` with
`uses: cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@COMMIT`,
using a reviewed commit. Replace the example's `repo` default and the
bounds file's `repos` with your public repository; the allowed base is
`main`. Keep the permissions. Commit to your default branch, enable
Actions and permit the referenced actions and workflow. No branch of your
repository is written: the pull request comes from a fork.
The example applies with the `SAFE_OUTPUTS_PAT` of an `agent-apply`
environment: it asks for a pull request, which apply opens only from a
fork owned by the account whose token that is
([below](#pull-requests-come-from-a-fork)). Three more are started by events, [below](#event-triggered-callers):
a slash command in a comment, a label on a pull request, a schedule.
Every input is described where it is declared, at the top of the
workflow file; this page says what a caller has to provide for them.
The call itself:

```yaml
jobs:
  run:
    uses: cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@COMMIT
    permissions:
      contents: read
      issues: read
      pull-requests: read
      actions: read
      id-token: write
    secrets:
      SAFE_OUTPUTS_PAT: ${{ secrets.SAFE_OUTPUTS_PAT }}
    with:
      id: ${{ inputs.item }}
      task: ${{ inputs.task }}
      repo: ${{ inputs.repo }}
      allow: .github/agentic-job/allow.toml
      config: .github/agentic-job/runner.toml
      agent: claude
      agent-runner: '["self-hosted", "my-label"]'
      inference-url: ${{ vars.INFERENCE_URL }}
      inference-audience: ${{ vars.INFERENCE_AUDIENCE }}
      apply-environment: agent-apply
      apply-partial: true
```

Name the workflow by a commit you have read, not by a branch. The binary
is built from that same commit, so the pin covers both. Never pass
`secrets: inherit`: pass only the declared apply credential alias you use.

### Real agent checklist

With GitHub's billing, a real agent needs only `inference-provider:
github`, a `model` from GitHub's list and a GitHub token with Copilot
access as the secret `INFERENCE_API_KEY`
([GitHub billing](inference.md#github-billing)). With a provider's API key
(`inference-register: api-key`), it needs that key as `INFERENCE_API_KEY`,
`inference-url` and `inference-provider` ([inference](../README.md#inference)); the agent
programs and limits below still apply. Opencode also needs its `model`,
which has no default. The rest of this list is for a
broker.

Before replacing `agent: fake` with a broker, ask the inference and network
operator for the following. The proxy is a
[praxis-credential-broker](https://github.com/cgwalters-bot/praxis-credential-broker);
nothing else speaks the run API that the default `github-oidc` and
`plain` registrations use
([what it must provide](../README.md#inference)). Hosted Ubuntu alone
cannot reach a private proxy.

- **Proxy URL and audience:** set repository variables `INFERENCE_URL` and
  `INFERENCE_AUDIENCE`, and pass them as `inference-url` and
  `inference-audience`. These are addresses/identity names, not secrets.
  Keep `inference-register: github-oidc`: no repository secret or provider
  API key is needed for inference in this mode.
- **A network route:** either a disposable self-hosted `agent-runner` on
  the proxy's network, or an agent job of your own that joins the
  network in a step before `secure-host`
  ([above](#the-pieces-and-an-agent-job-of-your-own)), with whatever that
  network's operator issues for it. Prefer a credential the job mints
  from its identity token to a stored secret.
- **Broker admission:** the broker operator must enable a `called_workflows`
  policy entry for `cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml`,
  the exact commit pinned by the caller (`job_workflow_sha`), and the calling
  repository's numeric id (not just its name). Update that entry when the
  workflow pin changes. An agent job of your own is your workflow's, not
  a called one: the broker admits it by your repository instead. See [inference admission](inference.md#which-workflows-a-broker-admits).
- **Agent programs and limits:** `agent: claude` defaults to
  `@agentclientprotocol/claude-agent-acp@0.88.0` (the ACP adapter, which brings
  the Claude Agent SDK); `agent: opencode` defaults to `opencode-ai@1.18.35`.
  Both come from tarballs pinned in the binary, every dependency included,
  installed without npm or install scripts (`setup.agents`, see
  [the sandbox](sandbox.md#what-sandbox-setup-does)), and are for x86-64
  Linux with glibc: setup refuses another OS or CPU before it changes
  anything, but does not detect musl. Set `npm` to exact
  `NAME@VERSION` pins to install with npm instead; those do not pin
  their transitive dependencies. Choose `model`, `max-requests`,
  `budget` and `timeout` with the operator.

  `agent: vibe` installs `mistral-vibe==2.26.1` into a root-owned Python
  virtual environment before hardening; it does not use the `npm` input.
  Set `model` to the broker's bare Mistral model name (for example
  `devstral-small-latest`; optional with a configuration repository, below) and `inference-url` to the broker root, **not**
  its `/mistral/v1` route. Keep `inference-register: github-oidc` and set
  `inference-audience` as for the other real agents. No Mistral key is
  passed to the job. Vibe is opt-in and
  requires `max-requests`: an arbitrary broker model has no authoritative
  price in Vibe, so its local `budget` cannot be the only cap. The existing
  timeout, request-count and subagent limits still apply.

The policy job validates the effective configuration, including overrides
of the caller's `config`, before starting the agent machine. After the
caller's own steps, the agent job's `Check inference proxy reachability`
step makes a TCP connection to the effective proxy URL as the runner user,
before secure-host. This control sends no credentials
and proves only reachability, not broker admission or model availability.
A failure names the missing network route rather than blaming sandbox rules.

### Agent configuration repositories and model names

`agent-config-repo` selects a public configuration repository;
`agent-config-ref` selects its ref and `agent-config-path` its directory
(the root by default). This is agent configuration, not the runner TOML
passed as `config`. opencode reads `opencode.json`, optional `AGENTS.md`
and optional `opencode-runner.json`. Its configuration must define exactly
one provider and enable only it with `enabled_providers`, without
`disabled_providers`. The runner profile may not override providers.
The provider's address and key are replaced by the inference proxy URL
and run token, and sharing is disabled. With this configuration, `model`
is passed as supplied: use the configured provider/model name, such as
`praxis/MODEL`. Without it, opencode uses the built-in `inference` provider:
pass a bare model name (or `inference/MODEL`), not another provider's prefix.
A run fails unless the agent reports the model it was given, so a
`provider/model/variant` name, which opencode reports without its variant,
is refused.

Claude reads `CLAUDE.md` from a configuration repository; it does not use
opencode's files. Its `model` input is optional in the reusable workflow
and selects the adapter's model when supplied. The shipped dispatch
caller's preflight still requires `AGENT_MODEL` and `AGENT_RUNNER` for
all real agents. Dispatch and review forward configuration repository/path
only for opencode and Vibe; a direct or composed policy call can also
select the ref or Claude's configuration repository.

Vibe reads `config.toml` and takes only its models and `active_model`;
with it, `model` is optional in a direct call and still wins when supplied. See
[the harness](harness.md#agents) for what is taken and why.

`agent-skills: true` installs the built-in [skills](skills.md) for
`claude` or `opencode`; dispatch turns it on for `implement`.

### What a caller provides

**A bounds file** in its repository (`allow`): which repositories and
base branches a run may target, which output types and how many, how
large a patch.
[`.github/agentic-job/allow.toml`](../.github/agentic-job/allow.toml)
is this repository's. The inputs `repo`, `base`, `kind`, `outputs` and
`max-outputs` are one run's request, and the policy job refuses a
request the file does not cover. So a workflow that takes those from
whoever dispatches it is still bounded by a file that changes only by a
commit.

**A configuration file** (`config`) for what depends on the runner
image and not on the run: the services `sandbox setup` stops, the local
sockets `sandbox check` accepts, the egress rules, who the hand-back's
commit is by.
[`.github/agentic-job/hosted.toml`](../.github/agentic-job/hosted.toml)
is the one for GitHub's `ubuntu-26.04`. For another image, start from an
empty `[sandbox]` and read what `sandbox check` fails on: it names each
listener that is left. The inputs for the agent, the proxy, the limits
and the packages are written over this file by `agentic-job config`,
which takes each as the value of one key and never reads it as TOML.
It also adds the file's `[setup.repo-packages]` list for the target
repository ([a target's toolchain](dispatch.md#giving-runs-a-toolchain)).
There is no workflow input for the egress proxy's write rules: `[egress]
policy` in this file names a file that replaces
[the binary's](../egress/policy.toml). `sandbox setup` reads that path on
the agent machine, as root, from the job's workspace, which is the calling
repository checked out at the policy job's commit; give a path in that
repository, relative to its root. Without a rule there, any request but
`GET`, `HEAD` or `OPTIONS` from the sandbox user (a test suite that posts,
a publish, a login) gets `403 refused by the egress proxy`.

**Runners.** `agent-runner` is the machine the agent works on: thrown
away after the job, with passwordless sudo for the runner's user,
systemd 257 or later (for `run0`), and `apt-get` or `dnf`. `sandbox
setup` refuses a machine it has set up before, and ends by taking root
away from the runner's user: every step after it, this workflow's and
the actions' cleanup steps, runs without it
([docs/sandbox-check.md](sandbox-check.md#after-setup-nothing-has-root)),
which is one more reason the machine must not be one that runs another
job afterwards. `runner` is for the other
three jobs and defaults to `ubuntu-24.04`; where no release fits the
workflow's commit, the policy job builds the binary there with rustup,
and apt for the musl compiler. Labels resolve
in the calling repository.

**Permissions.** The call needs `contents`, `issues`, `pull-requests`
and `actions` read, and `id-token: write`: the agent job asks for the
reads [for the agent](#github-reads-from-the-agent), and the register
job for the identity token, for the proxy, whether or not the run uses
one ([the run token](#the-run-token)).
GitHub refuses the whole call when any of them is missing, even with
`github-reads: false`. The policy, register, agent and check jobs take
no more than that, and only register and check's detector the identity
token. Activate, notify, conclude and apply name no
permissions and so
keeps whatever the call was granted: with `apply-environment` grant
nothing more, and without it add `issues: write` (comments, issues and
issue updates, assignees and `link_sub_issue`) and `pull-requests: write`
(pull request updates, mark-ready, reviewers and `close_pull_request`) for
the job's own token. `create_check_run`
needs `checks: write` for the job token in either case: a user's token
cannot [create check runs](safe-outputs.md#posting-a-check-run).
`create_discussion` needs `discussions: write` for the job token when it
applies. `hide_comment`, which moderates other people's comments on the
run's item, needs `issues: write` or `pull-requests: write`, as that item is
an issue or a pull request. `create_pull_request_review_comment`,
`reply_to_pull_request_review_comment` and
`resolve_pull_request_review_thread` need `pull-requests: write`.
Nothing needs
`contents: write`: a new pull request's branch, and a push to it, go to a
fork with the environment's token ([below](#pull-requests-come-from-a-fork)).

**Limits that fit the agent.** The workflow's defaults are for a real
agent behind a proxy. A cap on model requests that nothing counts is
refused by the policy job's `agentic-job config`, before an agent machine
starts; the message names the input `max-requests`, which sets
`limits.max-requests`, and its default of 150. A run without an
inference proxy, the scripted agent's for one, passes `max-requests:
"0"` and keeps `budget`.

**Inference**, for a real agent: `inference-url`, a broker's address
(such as `http://ADDRESS:PORT`) or, with `api-key`, the provider's API
root (such as `https://api.anthropic.com`), and how the run announces
itself there (`inference-register`). The workflow passes `github-oidc` unless told
otherwise: the job proves to the proxy that it is a CI job with its
identity token, for the audience `inference-audience`, which the agent's
user cannot obtain. `plain` sends the run's name and no proof, and
`token-file` reads a token from `inference-token-file` on the runner;
both have to be chosen by name. `api-key` needs no proxy of anyone's:
`inference-url` is the provider's API root, `inference-provider` the API
it speaks, and the secret `INFERENCE_API_KEY` its key, which only the
agent job's key check before `secure-host` and its `run` step get
([inference.md](inference.md#a-provider-api-key)).
`inference-provider: github` alone sets `api-key` and GitHub's API root,
whatever `inference-register` and `inference-url` say, unless
`inference-register` is `api-key` ([GitHub billing](inference.md#github-billing)). The proxy speaks
[praxis-credential-broker](https://github.com/cgwalters-bot/praxis-credential-broker)'s run API. A proxy on a private network is
reached by joining it in a step of your own agent job. When the inference URL is an HTTP(S) IPv4 literal in
100.64.0.0/10, `agentic-job config` defaults `[egress] direct` to that URL
so that the run token never crosses the egress proxy. An explicit `direct`
list in the configuration file (even an empty one), or supplied with
`--list egress.direct=...`, takes precedence; other addresses are not
added automatically. The agent job refuses an address on the tailnet
that is not listed there before it sets the sandbox up, since the agent
could not reach it.

What the operator of a praxis-credential-broker has to turn on for a
run of this workflow to be admitted is written up, with what each
setting gives up, in
[tracker#405](https://github.com/cgwalters-forge/tracker/issues/405#issuecomment-6030469435): a
`called_workflows` entry naming this workflow file, the commit the
caller pins and the calling repository, or `any_workflow` for an owner.
Both are merged there and off.

### Event-triggered callers

The dedicated [review caller](review.md) sets `review: true` and
`review-task: workflow/review.md` to take a fixed task from the base checkout,
review an admitted head SHA, from a fork too, with an analysis-only policy,
post one validated verdict comment or noop, and report the verdict as the
commit status `review`. It requires notifications and partial application
off, and supports fake, opencode and Claude agents. Real reviewers start in
the trusted base checkout with the exact head beside it; see the
[review guide](review.md). The
[dispatch caller](dispatch.md) also supports operator-selected reviews of open
same-repository or fork PRs on the configured base, pinned to their exact head SHA.

With `event: true` the run is decided from the event that started the
calling workflow, by `agentic-job event` in the policy job
([how it decides](events.md)). The caller adds a `[trigger]` table to
its bounds file (which events, which roles, which bots, whether forks,
which commands), keys its `concurrency` on the triggering issue or pull
request, and writes `task` as the standing instruction: the event's text
follows it in the task file, fenced. Three callers in this repository,
with their copy lists below, and a dedicated review caller:

- [`example-command.yml`](../.github/workflows/example-command.yml):
  `/agent REQUEST` as a comment on an issue or pull request. Every
  comment starts the workflow; its `if` skips the ones that do not start
  with the command, and the policy job refuses the rest that may not
  start a run, in seconds, before the agent's machine is started.
- [`example-pull-request.yml`](../.github/workflows/example-pull-request.yml):
  a pull request labeled `agent-review`, on `pull_request_target` so that
  the bounds and the configuration are read from the base branch. The
  command label is removed after admission, before the agent starts, so
  applying it again can request another run. The run starts from the
  pull request's base and is told its head.
- [`example-schedule.yml`](../.github/workflows/example-schedule.yml): a
  weekly run with no item, so `comment-target` names where a comment
  goes.

Copy each selected caller and its companion files to the **same paths** in
your repository:

- **Slash command:** [`.github/workflows/example-command.yml`](../.github/workflows/example-command.yml),
  [`.github/agentic-job/allow.toml`](../.github/agentic-job/allow.toml),
  [`.github/agentic-job/hosted.toml`](../.github/agentic-job/hosted.toml) and
  [`.github/agentic-job/e2e/event.sh`](../.github/agentic-job/e2e/event.sh).
- **Label:** [`.github/workflows/example-pull-request.yml`](../.github/workflows/example-pull-request.yml),
  [`workflow/label-review.toml`](../workflow/label-review.toml),
  [`.github/agentic-job/hosted.toml`](../.github/agentic-job/hosted.toml) and
  [`.github/agentic-job/e2e/event.sh`](../.github/agentic-job/e2e/event.sh).
  Create the `agent-review` label before using it. For issues as well as
  pull requests, use the [label caller in events.md](events.md#label-caller-and-activation-step).
- **Schedule:** [`.github/workflows/example-schedule.yml`](../.github/workflows/example-schedule.yml),
  [`.github/agentic-job/allow.toml`](../.github/agentic-job/allow.toml) and
  [`.github/agentic-job/hosted.toml`](../.github/agentic-job/hosted.toml).
  Set `comment-target` to an existing issue in your repository. This caller
  uses the scripted agent's built-in file-changing session, not a setup script.
- **Dedicated review:** [`.github/workflows/review.yml`](../.github/workflows/review.yml),
  [`workflow/review.toml`](../workflow/review.toml),
  [`workflow/review-command.toml`](../workflow/review-command.toml) and
  [`workflow/review.md`](../workflow/review.md).
  This runs on pull request events or `/review`, not a label, with a real
  agent. Unlike the others, `review.yml` composes `policy.yml`, `check.yml`
  and `apply.yml` itself and is meant to be called, not copied: copy only
  the bounds and the task, and call it as in
  [another repository](review.md#another-repository).

In each other caller, replace `uses: ./.github/workflows/agentic-job.yml` with
`uses: cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@COMMIT`,
using a reviewed commit. In its bounds file, set `repos` to your public
repository and `bases` to the base branches you allow. Keep the caller's
permissions and commit all its companion files to your default branch.
The setup scripts are read from the trusted caller checkout; do not take
them from an untrusted pull request head. With `fake`, they select a fixed
session for testing the wiring, not a response to the task's text.

Comment-only callers use `kind: analysis` with `outputs: add_comment,noop`,
so no patch is handed back and policy refuses pull request outputs. They
keep `contents: read` and the item write permissions for label activation,
status and output comments. The command and schedule callers also allow pull requests, which
apply opens from a fork with its environment's token, so they too keep
`contents: read`.

What changes with `event: true`. `base` gives way to the pull request's
base branch where the event names one, and the bounds have to cover it.
`comment-target` defaults to the triggering item. The `notify` and
`conclude` jobs put an eyes reaction on what started the run and a
status comment on the item when opted in, edited when the run ends (`notify: reaction`
for reactions only, `none` for neither); they write with the call's own
token, so the call grants `issues: write` or `pull-requests: write` for
them; naming no permissions, they hold the whole of what the call was
granted, as the apply job does, and the agent's machine never holds a
token that can comment. A
refused event ends the run in the policy job: a success with the other
jobs skipped, the reason in the job summary, and the workflow's outputs
`trigger` and `trigger-reason` saying what was decided. A pull request
from a fork is refused unless the bounds say `forks = true`, for a
comment on one too: the policy job fetches the pull request to apply the
rule. `workflow_dispatch` with `event: true` admits only a dispatcher
with a listed role, which the plain `example.yml` does not check.

CI's `e2e-event` job calls the workflow with `event: true` on same-repository pull
request of this repository, where the event is admitted and the
scripted agent's comment lands on the pull request under the status
comment, and on merge groups and untested pushes to main, where those
events are not among the bounds' events and the run ends in the policy job.

### GitHub reads from the agent

The agent gets a GitHub token as `GH_TOKEN`, so `gh` and the API can read
issues, pull requests (including review comments), workflow runs and their
logs, with a higher rate limit than anonymous reads. It is the agent job's
own token, which asks
for `contents`, `issues`, `pull-requests` and `actions` read only, and
expires when the job ends. The agent can leak it, and that is accepted:
whoever gets it can read what the agent could, until the job ends, and
write nothing. The workflow passes no credential that can write to the
agent job; `SAFE_OUTPUTS_PAT`
is passed only to deterministic apply and cross-repository status jobs.

There is no secret override for agent reads: a leaked credential must not
outlive the job or carry broader permissions than the job grants.
When upgrading callers that forwarded a read-token secret, remove that
secret from the call; the reusable workflow no longer declares it. The job
token cannot read private repositories outside its own repository.
Set `github-reads: false` to give the agent no token at all.

The runner writes the token to a file in the sandbox user's home that
only it can read, and the agent launcher sets it as `GH_TOKEN` and
drops any other GitHub token variable. A run without one removes the
file. The token's value is redacted from the transcript, the logs, the
summary and the proposals, like the run's other tokens. Clone over
`https://`; public repositories need no credential, and SSH is not
allowed through the proxy.

The egress proxy still refuses writes to GitHub, with one exception:
`gh` reads issues and pull requests with GraphQL queries, which are
`POST api.github.com/graphql`, so that request passes, mutations
included. GitHub refuses a mutation only because the token cannot write;
the proxy does not look inside the query. REST writes and pushes are
refused at the proxy whatever the token. CI's `e2e-full` proves both:
its scripted agent reads its repository with `gh api` and asks for its
comment only after GitHub refused it a GraphQL comment.

### The apply job and its token

Check and apply serve any job that proposes writes, including the
[non-agent proposals route](#proposals-from-a-non-agent-job). The producer
receives no apply credential.

`SAFE_OUTPUTS_PAT` serves the same role as gh-aw's `safe-outputs.github-token`
for [cross-repository safe outputs](https://github.github.com/gh-aw/reference/cross-repository/#cross-repository-safe-outputs):
the applying job's credential when the built-in `GITHUB_TOKEN` is not enough.
That job token cannot [write to another repository](https://docs.github.com/en/actions/concepts/security/github_token#about-the-github_token)
or [write organization Projects](https://docs.github.com/en/issues/planning-and-tracking-with-projects/automating-your-project/automating-projects-using-actions).
It also cannot open pull requests whose CI runs **without approval**:
[GitHub now creates approval-required runs](https://docs.github.com/en/actions/concepts/security/github_token#when-github_token-triggers-workflow-runs).
Use an appropriately scoped PAT or GitHub App token for those operations.

gh-aw's `github-token` maps to our optional apply credential;
its `target-repo` is fixed by the caller: pull requests, comments and new issues
go to `output-repo` (or the calling repository when omitted), while issue actions
and project updates use the run's `repo`. A hidden comment is one on the run's
item, in the repository its comments go to; an event-triggered run may hide
one only when `output-repo` is the calling repository. So are review
comments, replies and resolved threads: on the run's pull request.
Unlike gh-aw's `allowed-repos`, which permits the agent to select write destinations,
`repos` in our bounds file validates only the run's target `repo`, not `output-repo`.
Output destinations are caller-fixed, are not bounded by that list, and cannot be
dynamically selected by the agent. gh-aw's wildcard `target-repo: "*"` has no
equivalent here.
For environment-based storage, our secret lives in a caller environment restricted
to the protected default branch, entered only by apply (and, with
`require-safe-outputs-pat`, by the check [below](#checking-the-token-before-the-agent)).

With no nonempty apply secret, apply uses the job's own token (even with an environment),
which can write only to the calling repository: `repo` then has to be
the calling repository, and `output-repo` is left out. The job token
cannot open a pull request either ([below](#pull-requests-come-from-a-fork)).

### Checking the token before the agent

Apply finds a wrong `SAFE_OUTPUTS_PAT` only after the agent has run.
With `require-safe-outputs-pat: true` (off by default), the policy call
refuses the run before the agent instead when the secret is missing or
empty, names no user (`GET /user`), is a classic PAT without the `repo`
or `public_repo` scope, cannot read the output repository, or belongs to
the output repository's owner. The refusal names the secret and the fix.
It saves an agent session and is not a security control: apply checks
the token again, and a fine-grained token's permissions are not asked.

The check is the `apply-token` job of policy.yml, which enters
`apply-environment`, as an environment's secret reaches only a job that
names it. An environment with required reviewers then asks before the
agent as well as before apply. The token is in one step running the
pinned `workflow/apply-token.cjs`, which only reads; it does not reach
the agent's machine. A caller whose repository
[accepts owner branches](#a-repository-the-applying-account-owns) leaves
the setting off.

### Pull requests come from a fork

Apply never pushes a new pull request's branch to the output
repository, but for [one its applying account owns](#a-repository-the-applying-account-owns);
only a fix may go to a branch of it, where the output
repository accepts that
([pushing to a pull request's branch](safe-outputs.md#pushing-to-a-pull-requests-branch)).
Before the handlers run, it forks the output repository
into the account that `GET /user` names for `SAFE_OUTPUTS_PAT` (the
forge answers with the existing fork when there is one), waits until
git reaches the fork, and gives gh-aw's `create_pull_request` handler
that fork as its `head-repo`. The handler pushes the branch there, on
top of the checked base it sits on, so the fork's own branches are
never synced, and opens the pull request in the output repository with
`head: FORK_OWNER:BRANCH`. The output repository's CI then runs the
agent's commit as a fork's pull request: with a read-only token, no
secrets and no OIDC token, and with whatever approval the repository
requires for outside contributors. A workflow there on
`pull_request_target` or `workflow_run` still runs with privileges and
must not check out or run the pull request's code.

A `push_to_pull_request_branch` goes to the branch of its pull request
wherever that is: to this fork the same way, and otherwise to another
fork of it the account may push to, or to a branch of the output
repository, only where that head repository accepts it and never with
`.github` exempted;
never to a default or protected branch
([pushing to a pull request's branch](safe-outputs.md#pushing-to-a-pull-requests-branch)).
Apply checks this before it fetches or pushes anything, and gives the push
handler that repository as its `head-repo`, which refuses any other.

A push with a PAT, unlike one with the job token, starts the fork's
workflows on `push`, with the fork's secrets and a token that writes to
the fork. So apply turns Actions off on the fork
(`PUT /repos/FORK/actions/permissions`) and reads the setting back
before it pushes anything, and stops if it cannot or they stay on. Keep
Actions off and no secrets on the bot account's forks all the same.

So `create_pull_request` needs a user's token, of an account that does
not own the output repository (but see [below](#a-repository-the-applying-account-owns)), that can fork it, push to the fork, turn
off the fork's Actions and open pull requests on it: a classic PAT of a
bot account with `repo` scope, which the Actions setting needs even
for a public repository. Give it the `workflow` scope too: the fork is
never synced, so a push to it brings in whatever workflow-file commits
the output repository gained since, which was tried live only with that
scope ([#426](https://github.com/cgwalters-forge/agentic-job/issues/426)).
That is wider than the fine-grained PAT
restricted to the exact target repositories this page used to
recommend: a classic PAT writes to every repository its account can
reach, and every handler of apply holds it. Use a dedicated bot account
with access to nothing but its own forks (no organization membership, no
collaborator invitations, no repositories of its own beyond the forks),
so that what the token can push to is what apply means it to. A fix to a
pull request from elsewhere needs write access to its head repository,
and the token can then push to any unprotected branch there: grant it
only where that is acceptable. That does
not bound everything: like any GitHub account, it can still comment, open
issues and pull requests, and fork on every public repository, and create
repositories and gists of its own, and every handler of apply holds the
token that does so. A private output repository is not supported: such
an account cannot read it, and so cannot fork it. A
fine-grained PAT of such an account, for "All repositories" with
Contents, Pull requests and Administration write, would narrow it to
the account's own repositories; which permissions GitHub asks of each
step has not been tried here ([what is left](plan.md#open-work)). Policy refuses `create_pull_request` and
`push_to_pull_request_branch` to a call without `apply-environment`, as
it refuses `update_project`: the job token names
nobody and has no account to fork into. Apply fails before it pushes
anything when `GET /user` names nobody (an App's token), or when that
user owns the output repository and so has no fork of it (but see below), or when what
the forge answers is not that user's own fork (the user's repository in
the network can be its root, or the caller's repository).

### A repository the applying account owns

An account has no fork of its own repository, so apply refuses an output
repository owned by the user `GET /user` names, unless the repository
accepts its owner's branches: its default branch has the file
`.github/agentic-job/accept-owner-branches` naming it (`owner/repo`) on a
line of its own, the file a fix push [checks too](safe-outputs.md#pushing-to-a-pull-requests-branch).
No bounds file lists such repositories; each one says so itself, in a
commit to its default branch that an agent's patch cannot make, and a
fork inherits a file naming its parent, not itself.

Then a new pull request's branch is pushed to that repository itself and
the pull request opened from it; another account's token still forks.
That gives up what the fork is for: the repository's `push` and
`pull_request` workflows run the agent's commit with its secrets, a write
token and OIDC, and its Actions are not turned off. Add the file only to a
repository whose workflows give a branch nothing an agent is not to have;
where it is also the caller, keep its apply environment to the default
branch, so that a branch's workflows cannot use its token.
Apply refuses the pull request where the bounds exempt `.github` for it
(`unprotected_files` with `dot_folders`), as a workflow file the agent
wrote would then run on its own branch. Its pull requests are not a
fork's: event and review callers there take them as the owner's
same-repository pull requests, whatever their bounds say about `forks`. A
fix pushed to one of them goes to the repository's branch under the same
file.

Every agent's pull request but one in an
[owned repository](#a-repository-the-applying-account-owns) is then a
fork's, and so is treated as one everywhere. This repository's CI skips the end-to-end jobs for it, as
they need a write token and an OIDC token, and then fails its required
`ci` check unless it changes only documentation: a maintainer runs them
from a branch of this repository with the same commits before merging. The event callers and the review caller refuse a
fork's pull request unless their bounds say `forks = true`
([events](events.md)), so an agent's pull request is reviewed by a
person or by a caller that admits forks.

A re-run looks for the pull request by the fork's owner and branch and
leaves it out when an earlier attempt opened it, so it is neither pushed
nor opened again; one whose branch was pushed and that was not opened is
not completed by a re-run ([below](#running-apply-again)). A run that
asked for a pull request and has none, or one of whose outputs a handler
failed, fails the job. No issue is opened in
the pull request's place: gh-aw's handler would leave one whatever its
`fallback_as_issue` says, so no handler may open an issue for a run
whose outputs have none.

The single optional declared secret is `SAFE_OUTPUTS_PAT`. When nonempty,
it replaces the built-in job token. Checkout and the API handlers use the same
selection. This replaces the previous credential name, with no legacy alias.
A passed secret
also works without an environment; then GitHub's environment protection rules
do not gate its use.

With `apply-environment: NAME`, only apply enters that environment of the
calling repository. An empty credential uses the job token; the environment
still gates apply. GitHub's current
[reusable-workflow documentation](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows#using-inputs-and-secrets-in-a-reusable-workflow)
says the caller **must explicitly pass the secret even if it exists only in
the environment**. The environment's same-name secret takes precedence over
a repository/organization secret. Our earlier instruction to pass nothing
was incorrect. GitHub's [secrets documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets#using-secrets-in-a-workflow)
confirms that referencing an unset secret returns an empty string: explicitly
passing it is harmless with our optional declaration and job-token fallback.
Shipped callers already pass this name, so storing the secret is enough.
To set it up:

1. Create the environment in the calling repository, limited to its
   default branch, and protect that branch.
2. Store the token as `SAFE_OUTPUTS_PAT`.
3. Explicitly pass that same name and set `apply-environment: NAME` and,
   for another repository, `output-repo`:

   ```yaml
   jobs:
     apply:
       uses: cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@COMMIT
       permissions:
         contents: read
         issues: read
         pull-requests: read
         actions: read
         id-token: write
       secrets:
         SAFE_OUTPUTS_PAT: ${{ secrets.SAFE_OUTPUTS_PAT }}
       with:
         id: proposals
         repo: OWNER/REPO
         allow: .github/agentic-job/allow.toml
         proposals-artifact: board-proposals
         outputs: add_comment,noop
         comment-target: '123'
         apply-environment: writes
   ```

For a repository/organization secret, the **stored name is caller-chosen**:
map `SAFE_OUTPUTS_PAT: ${{ secrets.YOUR_BOT_PAT }}`.
For an environment-only secret, use `SAFE_OUTPUTS_PAT` both in
storage and in the explicit mapping. Although expressions support
`secrets[inputs.name]`, that does not bypass `workflow_call`'s declared-secret
interface or the explicit-passing requirement. This workflow does not expose
an arbitrary environment-secret-name input or use `secrets: inherit`.

CI and example callers explicitly pass the optional name; CI can exercise
job-token fallback without storing a PAT or changing permissions. Local
regression tests cover empty/unset selection, shared credentials, explicit
forwarding, scripted dispatch suppression and apply-only consumption. GitHub's
documentation verifies environment delivery and precedence, not a live run here.
Still to try on GitHub: an environment-only PAT with explicit passing;
environment precedence over a same-name repository secret; unset-secret fallback;
and required-reviewer/branch protection gates. These require a trusted caller
and real environment setup, not credentials in the proposal producer.

GitHub App token minting is **not implemented yet**. An App can avoid a
long-lived PAT (its private key still needs protected storage), but the
workflow must first narrow an installation token to the checked destinations
and admitted permissions. In particular, PR creation can need both target and
fork access, issue actions use `repo` rather than `output-repo`, and organization
Projects require another permission. Do not substitute an unrestricted
installation token or claim App support from the PAT alias alone.

For `update_project`, use that same environment secret, not an additional token:
the selected apply credential must have organization **Projects: Read and write**
for a fine-grained PAT or GitHub App, and repository **Issues: Read** (plus
Metadata read) on the issue repository. A classic PAT needs **project** scope
and repository access (`repo` for private repositories). Organization approval
or SSO authorization may also be required. Other output types need their own
repository write permissions only if allowed. The handler uses the apply step's
authenticated client; no project credential is given to policy, check or the
producer. The job token cannot substitute for organization Projects access:
policy refuses `update_project` to a call without `apply-environment`, naming
the token it needs, and `outputs: all` leaves it out. It cannot see whether a
secret is passed, so a PAT passed without an environment is refused it too.

For `push_to_pull_request_branch`, the caller passes the pull request's
number as `push-item` on a `branch` run; it is off unless the bounds list it
(see [pushing to a pull request's branch](safe-outputs.md#pushing-to-a-pull-requests-branch)).
It goes only where the user `SAFE_OUTPUTS_PAT` names may push, so it needs
`apply-environment` and that token, as a new pull request does;
the job token is refused it. The policy job reads the pull request's branch
and head with its read-only token (`pull-requests: read`, which the call
already grants), and the run starts from that head. The pull request is in
the run's own repository, so `output-repo` is left out or names it; policy
refuses any other before the agent runs, and apply checks again. Apply checks
the pull request's head repository and branch
([above](#pull-requests-come-from-a-fork)) before it fetches or pushes
anything for it, and the push goes there with the environment's token. A
branch of the repository itself, or of someone else's fork, runs that
repository's workflows on the agent's commit with its secrets, which is why
that repository has to accept it. No other job's permissions change, and no token reaches the agent, check
or policy beyond the read-only ones they hold already.

The project workflow changes leave permissions, action pins and token placement
unchanged. Handler configuration fixes the issue repository to the checked run's
`repo`, not `output-repo`. The apply-only GraphQL guard prevents gh-aw's implicit
schema creation and normalized-name writes to unlisted fields. A refused project
write fails the final outcome.

Three things about that environment are easy to get wrong. Its branch
rule is evaluated against the ref the caller's run is on, not against
the commit named after `uses:`, which is one more reason to pin by
commit. Whoever may start the caller's workflow on that branch can have
the token used, through checked outputs only. And everything the token
can do is within reach of that one job, so give it no more than forking
the output repository, pushing to its own fork, and opening pull requests
and comments in the output repository. It needs no push access to the
output repository for a pull request; a fix to a pull request not from its
fork needs push access to that pull request's head repository.

For a patch, when `output-repo` is not the target, it is taken to be a fork of
it: its base branch must already contain the patch's base commit, or apply
stops with an error asking the operator to sync it independently. Apply
fetches the target's base but never pushes it to the output repository;
that would start its push workflows on unreviewed target code. The pull
request's own branch still goes to the
applying account's fork of `output-repo`, so that account must not own
`output-repo` unless that repository accepts it ([above](#a-repository-the-applying-account-owns)).

Without a patch, apply does not check out a repository, configure git or
fetch/advance a base branch. An analysis can therefore inspect a topic branch
and comment in an unrelated tracker repository via `output-repo`, even when
that repository has no such branch. `comment-target` fixes the issue/PR number;
the read-only check job refuses an explicit repository or item that differs,
including PR-number aliases, existing-comment IDs and discussion replies.
Omitting a destination in the request uses the caller's fixed destination.
Where the item is an issue of another repository than `output-repo` (for
a target with issues turned off), `item-repo` names it: `comment-target`
and `issue` are then its numbers, comments and the status comment go
there, and a pull request or new issue still to `output-repo`. Policy
refuses an `item-repo` that is not public or not within the bounds'
`repos`, since its issue text reaches the agent and the status comment
is posted with the apply credential, and refuses it with `event`, `review`,
`review-item` or `push-item`, whose items are the target's or the caller's.
Cross-repository writes still require an apply token with access to that
repository; no permissions or action pins are broadened.

CI's misdirected-analysis caller sets `expect-check-refusal: true`. Only a
policy-check exit of 1 with a nonempty refusal report counts as success;
collector, setup and other operational failures still fail, as does unexpected
acceptance. The caller exposes `check-refusal`, which CI asserts names the
fixed-item violation. Expected-refusal runs upload no checked outputs and never
start apply, even if the check unexpectedly accepts them. This changes only
result reporting and job/step conditions: permissions, token placement, action
pins and the validation rules are unchanged.

### A run stopped at a limit

A run that reaches its timeout or a request, task or spending limit is
interrupted to hand back what it has, and `run` ends with exit state 124
or 3. So does, with 3, one whose agent handed back after a turn that
ended on an error, such as a model request the provider kept refusing
([harness.md](harness.md#limits)). By default the agent job then fails and nothing is applied. With
`apply-partial: true`, a stopped run that handed back is checked like
any other and applied as a draft whose title starts with `[partial:
stopped at the timeout]` or `[partial: stopped at a limit]` and whose
first line says the same; a comment it posts starts with that line
too (gh-aw puts a note of its own before it when a pull request was
refused just before).
The agent job passes with a warning, and `summary.json` still says
`stopped_early`. Those words are the workflow's own, chosen by the exit
state, not text from the agent's machine. The exit state does not say
which of the request, task and spending limits or the error it was, so
the marking does not either. `summary.json` does, and so does the commit's message
where the agent gave no reason of its own for stopping. A stopped run that handed
back neither a pull request nor a comment has nothing to carry them,
and the apply job fails rather than apply it unmarked.

A stopped run cannot clean up after its own commands, so the hand-back
of any run leaves untracked binary files (a `__pycache__`, say) out of
the patch. `outcome.json` and `summary.json` name them in
`omitted_untracked_binary_files`, and a summary the agent wrote gains a
line saying how many. A changed binary file that git tracks, or one the
agent staged, stays in the patch, and `check` refuses it.

### Trying a caller without writes

With `apply-staged: true` (off by default) a run goes through policy,
agent and check as any other, and the apply job writes nothing: it does
not fork, push, post or look for what an earlier attempt posted, and no
step of it holds `SAFE_OUTPUTS_PAT`. Its summary shows the outputs check
accepted, escaped so that nothing in them renders, and the files of the
patch; `applied.json` has `staged: true` and an empty `made`, and its
`handlers` leave out a pull request's or push's, which need the fork. Like
gh-aw's `staged:`, it is for trying a new caller or bounds before they
may write. The patch is not tried on the target's base, which needs
apply's checkout; check's own checks still ran. `notify` is left as it
is: with `comment` the status comment is still posted and edited, and
says the run was staged. Use `notify: none` for a run that writes
nothing at all.

## What a run leaves

Jobs of a called workflow are named `CALLER JOB / JOB`: for the example,
`run / policy`, `run / agent`, `run / check` and `run / apply`. The
condensed transcript is the group `agent (condensed)` of the step `Run
the agent` in `run / agent`, and `summary.md` is that job's summary.

Artifacts, each name after `artifact-prefix`: `agent-run` (`summary.json`,
`summary.md`, `condensed.log`, `outcome.json`; 90 days),
`agent-transcript` (30 days) and `safe-outputs` (30 days) in the old
tree's names and schemas; `agentic-job-policy` (`policy.json`),
`checked-outputs` (what the apply job applied, with `check`'s report)
and `applied` (`applied.json`, 90 days); and `agentic-job-binary` for a
day. `applied.json` names what the apply job made:

```json
{"schema": "agentic-job-applied/v1", "repo": "OWNER/NAME", "staged": false, "partial": false,
 "made": [{"type": "create_pull_request", "number": 12, "url": "..."}],
 "refused": false, "already_applied": [],
 "pull_request": {"number": 12, "url": "..."}, "handlers": {}}
```

`made` is gh-aw's own list. `pull_request` is null when none was opened,
and `refused` then says whether the forge refused it to Actions after
the branch was pushed; nothing in `made` stands for it then.
`already_applied` lists what an earlier attempt of the job had posted
(`type`, `name`, `url`), which this one left out; see
[running apply again](#running-apply-again).
For a push it holds `type` and the pull request's `url`, without a body marker:
the fork branch's one-parent commit and checked tree are the evidence.
`handlers` is the configuration the handlers ran with.

The workflow's outputs are `exit` (the exit state of `run`),
`pull-request`, `applied-artifact-id` and `result-url`: the URL of the pull
request, or else of the first comment or issue apply made or found made, also
in the run summary. With `issue` set to a number of the output repository, a
new pull request gets `Closes #N` unless that line is already present,
or a line of the body starts with `Part of #N` or `Refs #N`: the agent's
word that its change does only part of the issue, which merging must not close;
an item in another repository gets `Refs OWNER/NAME#N` instead. Existing batch
references are preserved, and fix runs leave the PR body alone. Without
`issue` a pull request links nothing, and apply warns that it does: a
caller that composes `policy.yml` itself, as a wrapper of `dispatch.yml`
might, has to pass its item as `issue`, not only as `comment-target`. When notifications are
enabled, conclude puts the result link in the item's single status comment.
A link that cannot be posted fails no run.
A run whose checked outputs are only `noop`, `missing_tool` or
`missing_data` makes nothing anyone would see: its run summary says "No
result" with the agent's reason, passed through gh-aw's sanitizer as the
handlers run it (mentions, HTML comments and URLs off its allowlist
neutralized, cut at 1000 characters) and quoted line by line. With
`notify: comment`, the status comment includes the quoted reason.
When these outputs include `missing_data`, apply fails: the task is incomplete,
and a job has no neutral conclusion. Conclude posts or updates the item's
bounded status comment with the reason and run link even with `notify: none`
or `notify: reaction`. Without a fixed numeric item, only the summary is available;
cross-repository status still requires the caller's `SAFE_OUTPUTS_PAT`.
Ordinary noops and missing-tool declines stay green and respect notification settings.
An agent's `stopped_early` is
not seen here: a run that hands back nothing at all has no checked outputs,
and check and apply are skipped.

### Running apply again

Re-running the apply job applies the accepted outputs again, and gh-aw's
handlers would post each comment, issue and pull request again: once a
merged pull request's branch is deleted, even the pull request. So
before the handlers run, apply names each comment, issue and pull
request `agentic-job-applied: RUNID/POSITION/DIGEST`, by the run, its
place among the outputs and the first 16 hex digits of the SHA-256 of
the `artifact-prefix` and the request (for a pull request, and the patch
`check` accepted). The calls of one run share its ID, and two of them can
hand back the same request, so the prefix, which tells them apart, is
part of the name. Apply puts the name last in the body, so its first line
is still the verdict or the partial run's note; the handlers' client
turns that line into an HTML comment as it is sent. An attempt then
leaves out each request whose name it finds last in a body already
posted:

- a comment, among the comments on its target;
- a pull request, on an open or merged pull request from the run's
  branch (the job's `pull-request` output is then that one's);
- an issue, through the forge's search, as gh-aw finds its own issues.
  The search lags seconds behind, so an issue opened just before is not
  found.

A push to a pull request's branch uses the same guard, summary and
`already_applied` list, but needs no new marker. If the fetched fork branch
already holds exactly one commit on the policy's pinned head with the tree
the patch trial checked, the guard leaves out that push and succeeds without
pushing. Other outputs keep their original positions for their hidden markers.
The final step fetches and verifies that branch again, including a skipped
push; unrelated branch advances and merge commits do not count as applied.

CI's credentialless `workflow/fix-handler.test.cjs` runs the pinned gh-aw
push handler on a scripted patch with a different caller repository and the
target checkout at the workspace root. Forge reads are mocked, transport is
redirected to home-directory scratch, and both remotes are local bare git
repositories. It verifies the fork's parent and tree, an unchanged target,
the mapping's negative control and the re-run guard with real git. This is
not a live dispatch or sandbox test: those still need a prepared runner and
a user's write token to create/manage the applying identity's fork.

The rest are applied, so a re-run completes an attempt that stopped
part-way, and the job summary lists what was left out. A pull request
whose branch was pushed and that was not opened is the exception: the
handler stops at the branch that is already there. Only what the
job's token posted counts: `github-actions[bot]`'s for the job token,
the user's `GET /user` names for a PAT; a name in anyone else's comment,
another app's bot included, is ignored. A token in `SAFE_OUTPUTS_PAT`
that `GET /user` does not name, such as an app's, has no one whose
posts count: nothing is left out, and a re-run posts again. `check`
refuses any request holding the name, so the agent cannot make one
request look applied by posting another. Closing an issue, adding
labels and setting a project field are left to be done again: done
twice they leave the forge as once, unless someone undid them in
between. A re-run of apply runs `conclude` again too; it edits the same
item-scoped `agentic-job-status` comment as notify, rather than posting another.
"Re-run all jobs" keeps the run's ID, but runs
the agent again: what it hands back the same is left out, and what
differs is applied as new. A pull request with a different
patch is new even with the same title, body and branch; its handler
then stops at the run's branch, which is already there, and apply
fails rather than report the earlier pull request.

### Auditing downloaded artifacts

Download `agent-run`, `safe-outputs`, `checked-outputs` and, when available,
`check-diagnostics` into directories
of those names under one directory, then run `agentic-job audit DIR`.
For a local `run --out DIR`, the summary is read from `DIR/run` instead.
An artifact downloaded flat is also accepted. With a custom artifact
prefix, name the local directories as above.

The audit also accepts a separate, diagnostics-only `check-diagnostics`
artifact, produced by `node safe-outputs/diagnostics.mjs SOURCE DESTINATION`.
It contains
bounded collector errors (`agent_output.json`) and, if the policy check ran,
its verdict and errors (`report.json`). Requests and patches are omitted.
The successful `checked-outputs` artifact takes precedence when both exist;
diagnostics are never input to apply. Publication requires workflow steps
that run after either refusal gate fails; without that wiring, refusal
evidence may be missing even after all available artifacts have been
downloaded.

The audit reports tool call counts and errors, proxy and permission
denials, raw handed-back requests, collector refusals, the policy check's
verdict and estimated cost. `--json` emits `agentic-job-audit/v1`, with
stable finding codes: `proxy_denied`, `permission_denied`, `run_failure`,
`patch_dropped`, `collector_refused`, `check_refused`, `cost_unknown`,
`collector_missing`, `check_missing` and `handback_missing`. Missing
artifacts are not evidence that checks passed. A readable audit exits
successfully even when it reports refusals; malformed input is an error.

This is an offline inspection, not another check or an attestation: it
executes nothing from the artifacts and does not apply a patch. Tool
counts and denials come from `summary.json`; it does not replay the
transcript. Cost is agent-reported and unverified, even when token counts
come from the inference proxy. Unknown cost is not zero. `summary.md`,
which the workflow appends to the step summary, includes the cost line.
OTLP export is deferred: no collector endpoint or telemetry credentials
are configured, and audit does not send artifact data anywhere.

## What the apply job does before it writes

`check` reads a patch's text on a machine without the repository. Three
things only the job that applies it can settle
([#17](https://github.com/cgwalters-forge/agentic-job/issues/17)):

- **The base.** The commit a patch says it starts from is the
  hand-back's own claim. The job fetches the target's base branch
  itself and requires that commit to be one of its ancestors. The
  checkout is whole, since at depth one gh-aw's handler would apply the
  patch on the branch's tip instead.
- **The files.** The job first applies the patch on that commit with a
  plain `git am`, which takes a patch only where it applies exactly, and
  compares the files that changed with the ones `check` saw the patch
  name. Only then do the handlers apply and push it.
- **Renames.** `merge.renames` is off in the checkout, so that the
  handler's `git am --3way` stops with a conflict where it would
  otherwise look for a file by content and change another path than the
  patch names.

The branch is the fourth thing. Its name is in the hand-back, and the
handlers push the name they are given, so the job requires it to be
`agent-run-RUNID` of this very run before the handlers push anything;
a branch that exists is never overwritten. So a job that is run again
in the same run, after its first attempt pushed, stops at the branch
that is already there, unless its pull request was opened, which it then
leaves out ([running apply again](#running-apply-again)).

Both the trial and the handler keep a carriage return at the end of a
line (`am.keepcr`), for patches to files with CRLF line ends.
`node --test workflow/apply.test.cjs` exercises the workflow's actual
shell steps locally, including CRLF preservation, Unicode paths, file-list
mismatches, unrelated bases and a rename into a protected path. File-list
extraction failures stop the trial; Git's path quoting is disabled for
the comparison, since `check` rejects control characters in paths.

The separately dispatched `safe-outputs-probe.yml` predates these guards
and does not yet exercise them. Its fixture-only handler path still needs
the same checker report, fetched-base ancestry check and trial comparison
before it can serve as evidence for these protections.

The patch's `From:` line is not proof of anything: `check` holds it to
nothing ([#22](https://github.com/cgwalters-forge/agentic-job/issues/22)),
and a machine that can upload a hand-back can write any author there.
Who opened the pull request is the token's owner.

The exit state that decides between a whole and a partial run comes from
the agent's machine. A machine that lied about it could have a partial
run applied without its marking, or a whole one with it; it could not
get anything past `check`.

## Organization bounds in a custom policy job

The reusable workflow has no organization-bounds input. For a custom
trusted policy job, `agentic-job policy --org-allow FILE` checks the
request independently against the caller's bounds and a second trusted
bounds file. It takes the lower output and patch caps, the common output
types, and the union of protected file names. Neither file can widen the
other. Explicit requests outside either file are refused; `all`/`max`
takes the intersection. This intersects output policies, not `[trigger]`
tables: organization trigger admission must be checked separately with
`event`. Fetch organization bounds from a trusted pinned ref before
policy evaluation. Merely wrapping `policy.yml` and fetching a file does
not make it consume that file; reusable-workflow wiring remains part of
[#118](https://github.com/cgwalters-forge/agentic-job/issues/118).

## Things a caller should know

**Callers started by a pull request.** A workflow that runs on
`pull_request` reads its bounds file, its configuration and its setup
script from the pull request's merge commit, so whoever opens the pull
request writes them. Take the task and those files from a trusted ref
instead (`workflow_dispatch`, or `pull_request_target`, which this
workflow reads like `pull_request` and which checks nothing out from the
head), as for any workflow that holds a token; `example-pull-request.yml`
does. With `event: true` the bounds also refuse a pull request from a
fork unless they say otherwise, and a pull request whose actor (whoever
opened, pushed to or labeled it) lacks a listed role.

**What the pinned actions bring.** The workflow names every action by
commit: `actions/checkout`, `actions/upload-artifact`,
`actions/download-artifact`, `actions/github-script`, gh-aw's
`actions/setup`. They run only what is in the pinned commit. An action
of the caller's own agent job is the caller's to pin and to read. The
build fetches crates as `Cargo.lock` pins them,
and `sandbox setup` installs the caller's packages with the image's
package manager.

**The egress proxy's pins.** `sandbox setup` runs as root and takes two
things from the network before the rules load, each pinned in this
repository (the first only with `[egress] rust-proxy = false`). mitmproxy and
all it depends on are installed with `pip --require-hashes
--only-binary :all:` from `egress/requirements.txt`, which names each
at one version with the hashes of its files: pip installs no file that is not one of those, and builds nothing. That
file is generated from `egress/requirements.in`, whose first lines give
the command. The threat feed is fetched at one commit of its repository
and must have the SHA-256 written beside it (`DENYLIST_COMMIT` and
`DENYLIST_SHA256` in `crates/agentic-job/src/sandbox/egress.rs`): a
file that is not that one stops the setup, and a fetch that fails
leaves the proxy without a feed, with a warning, as before. To move the
feed, take the newest commit of the file and the checksum of the file
there, and put the two in a pull request:

```sh
commit=$(gh api 'repos/hagezi/dns-blocklists/commits?path=wildcard/tif.medium-onlydomains.txt&per_page=1' --jq '.[0].sha')
curl -fsSL "https://raw.githubusercontent.com/hagezi/dns-blocklists/$commit/wildcard/tif.medium-onlydomains.txt" | sha256sum
```

The feed changes more than once a day upstream, so a run blocks what
was known when the pin was last moved. Should the pinned commit stop being served, every run would go
without a feed and only warn: CI's `sandbox` jobs require the feed to
load, so the next pull request here would show it.

The fetch retries transient curl failures up to three times, with a
60-second retry window and a 60-second timeout per attempt. The retry
window is not a total wall-clock cap: the last attempt can finish after
it. A successful fetch still has to pass the pinned checksum check.

Stale pins miss newly listed malware and phishing hosts. To propose updates
every eight hours, enable the repository variable `THREAT_FEED_REFRESH=true`
and provide `THREAT_FEED_PAT`, a dedicated token restricted to this repository
with contents and pull-request write permissions. This is off by default:
the organization's job token may not be allowed to open pull requests.
The `threat-feed pin` workflow runs only trusted default-branch code, with a
read-only job token; only its publishing step receives the dedicated token.
Do not grant it workflow or administration access. No untrusted feed text is
executed or included in a commit message. The job proposes a draft, never
merges it, and leaves an existing feed proposal untouched. Normal PR checks
and human review remain required. It refuses to publish when the first 100
open PRs do not establish that no proposal exists.
If pushing succeeds but creating the PR fails, an operator must open the
draft from the existing maintenance branch or delete that orphan before
retrying the same pin. The job never force-pushes to recover from a failure.

`just refresh-feed` performs the same update locally without credentials or
forge writes; `just test-feed-refresh` checks its validation. The updater
reads the upstream repository and file from the runtime constants, resolves
one commit and hashes the exact bytes fetched at it. Fetches have 60-second
timeouts, no redirects and size caps (256 KiB metadata, 16 MiB feed); malformed
commits, empty feeds and unexpected domain-list formats fail without changing
the source. A fresh proposal is not a freshness guarantee: pins remain stale
until reviewed and merged, and the feed is supplementary hardening, not an
exfiltration boundary.

The retry and requirements-file regression tests already address part of
[#108](https://github.com/cgwalters-forge/agentic-job/issues/108). That issue
still tracks a CI embedded-source scan that handles `concat!` and multiline macros. The
world-write walk it also tracked is gone, replaced by the access-time
policy ([secure-host.md](secure-host.md#access-time-world-write-policy)).
Source-attested prebuilt releases now replace manual release pins;
their trust model is described below.

**Steps that run after the agent.** In the agent job, as the runner's
user: the second check that the repositories are public, the uploads,
the step that turns the run's exit state into the job's result, and the
post-steps of `actions/checkout` (it removes the credential
settings of a checkout that kept none), then the caller's own later
steps and their post-steps, [above](#the-pieces-and-an-agent-job-of-your-own).
None of them reads the sandbox user's files; the
uploads take only what `run` put under its own directory after the gate.

**Where the binary comes from.**
[`secure-host/binary.sh`](../secure-host/binary.sh) hashes the content,
modes and names of `Cargo.lock`, `Cargo.toml`, `crates`, `egress`, the
skills it installs (`skills`, `workflow/review.md`) and itself (it decides what a release holds) at the caller's pinned commit.
It looks for `build-FULL_DIGEST`, not the latest release. The release
contains a manifest with that source digest and the SHA-256 checksums of
the binaries and the world-write policy object, plus a GitHub
build-provenance bundle.
Before trusting the manifest, `gh attestation verify` checks that it was
signed by this repository's `pin.yml` workflow on `refs/heads/main`, on a
GitHub-hosted runner. Then the script checks the manifest's source,
repository, target and release name, and checks each file's checksum.
Replacing release assets, signing from a PR or using another workflow
cannot substitute a binary. The trust anchor is GitHub's attestation
service and this repository's main-branch publishing workflow, not a
mutable release tag or the caller repository's cache.

Only a missing manifest (HTTP 404) falls back to building, with a notice
that it takes about two minutes. A download or verification failure stops
the job rather than silently building. A caller can always request a
source build with `build-binary: true`. Fetching requires Node and `gh`
with attestation support; GitHub-hosted runners provide them. The bundle
is downloaded with the release, so verification needs no forge token.

A build cache was not used, though the plan had one. The reason this
page gave before was wrong: the agent is the sandbox user and has no
token to write a cache with. The reason that holds is that a cache is
the calling repository's, where any workflow on the default branch or
on the run's own ref can leave an entry under the key of a commit
nobody has built yet, and the
first run at that commit would take it for its binary, the `check` of
that run included. A cache is also one per calling repository, where a
release is fetched by every caller.

When main's source changes, the `prebuilt` workflow (`pin.yml`) makes an
uncached build and publishes its source-addressed release. No branch,
pull request or human merge is needed. Commits that only change docs or
workflow usage share their source's release. A run started before the
build finishes still builds locally; subsequent runs fetch the prebuilt.
The build job has only contents-read access. The publishing job executes
no built binaries; it has contents-write to publish, OIDC and
attestations-write to sign the manifest, and no pull-requests permission.
Uploads are staged in a draft release and published only when complete;
rerunning repairs an interrupted draft. Repeated builds of the same source
leave the first published release intact.

**Versions to pin.** A version is released by hand: raise the
workspace's version in `Cargo.toml`, merge, and run the `release`
workflow on main with that version (`0.1.0`, no `v`). It refuses a run
off main, a version that is not `MAJOR.MINOR.PATCH`, not the workspace's
or not newer than every `v` tag (`just release-check`), and a run whose
`v` tags changed while it built. It then tags main's commit `vVERSION`
and publishes the binaries with notes listing the pull requests merged
since the previous version.
Selecting the binary is unchanged: the tag's commit fetches its
source-addressed release like any other commit.

A caller pins the version's tag in place of a commit, for the reusable
workflows and the actions alike:

```yaml
    uses: cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@v0.1.0
```

and has Dependabot propose newer versions, daily:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: daily
    cooldown: # a hijacked release is usually pulled within its first week
      default-days: 7
    groups: # every piece on one version, in one pull request
      agentic-job:
        patterns: ["cgwalters-forge/agentic-job*"]
```

A tag can be moved or deleted by anyone who can push tags unless the
repository turns on immutable releases
(a repository setting, which the workflow cannot set). With them on, a
published release's tag and files cannot change, and a caller pinning
the tag gets what was released. Without them, a commit is the only pin
that cannot move. The run's own check that it is on main is against
mistakes: anyone who can push a branch can dispatch a copy without it,
and its job token can create a `v` tag. A tag ruleset would not stop
that while this workflow tags with the job token, since the ruleset
would have to let GitHub Actions through.

Should publishing fail after the tag is made, delete the tag (and any
draft release on it) before running the workflow again. Callers keep
every piece of the workflow on one version, as on one commit, which is
what the `groups` entry above is for.

**Inputs a caller forwards.** The bounds file holds `repo`, `base`,
`kind`, `outputs` and `max-outputs`, and nothing holds any other input.
A caller that passes one on from whoever dispatches it gives that
person the choice: of the bounds file itself (`allow`), of the limits,
of the machine that holds the apply token (`runner`), of the repository
that token is aimed at (`output-repo`). Forward the task, the target
and the request, and write the rest in the caller's file.

**Issues a run opens.** Issue-label bounds tighten the existing
`create_issue` output; they do not add new output types or complete
[#113](https://github.com/cgwalters-forge/agentic-job/issues/113).
Additional output types, target-specific bounds, computed apply
permissions and fake-agent CI coverage remain separate work for that
issue. Where the bounds list `create_issue`, the issue's
labels can be bounded with `allowed` and `blocked` lists:

```toml
[outputs.create_issue]
max = 1
allowed = ["agent-triage", "documentation"]
blocked = ["release"]
```

`check` refuses the entire hand-back if any label is outside `allowed`
or appears in `blocked`; blocked wins if a label appears in both lists.
Label matching ignores ASCII case. An empty `allowed` permits no labels;
omitting it preserves the existing unrestricted behavior except for
`blocked`. `add_labels` also uses these limits, but requires `allowed` explicitly.
Assignees remain the agent's, sanitized by gh-aw's collector, as gh-aw
allows by default; a bounds rule for them is not written yet
([#113](https://github.com/cgwalters-forge/agentic-job/issues/113)). A
request that names other issues (`parent`, `blocked_by`) is refused by
`check`, since nothing bounds which; gh-aw's handler still makes the new
issue a sub-issue of the issue an event-triggered run was started from,
when it was. The apply job lets no handler open more issues than that
count, none for a run without the type.

**Comments gh-aw adds.** When the caller's run was started by an issue
or a pull request, gh-aw's handlers also comment there, in the calling
repository, to say what they made.

**One run at a time.** The workflow sets no `concurrency`: the caller
does, as `example.yml` does for each `id` and the event-triggered
examples do for each issue or pull request, on the job that calls the
workflow rather than on the workflow: a workflow-level group is joined
before a job's `if` is evaluated, so a comment that is no command would
cancel a command waiting its turn. GitHub keeps one waiting run per
group either way. `event.json` carries the
same key (`issue-N`, `pull-N`, `schedule`, `dispatch`) for whoever
reads a run, but a group is decided before any job runs, so it is the
caller's expression that sets it.
