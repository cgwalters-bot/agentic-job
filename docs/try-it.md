# Getting started

> This text is LLM generated.

Start with a local safe-output check, then run the scripted agent on GitHub.
Neither needs a model, broker, self-hosted pool or access to this project's
deployment. The GitHub run tries the things it must not be able to do,
changes one file, and proposes a draft pull request from a bot's fork.
The scripted agent does not interpret your task or exercise model inference.

## 1. Check a local hand-back without credentials

On Linux, install Git, a C compiler/linker and stable Rust 1.88 or newer.
Choose a full agentic-job commit you have reviewed and replace `COMMIT`
before running these commands (the commit must contain this guide's examples):

```sh
git clone https://github.com/cgwalters-forge/agentic-job.git
cd agentic-job
git checkout COMMIT
cargo build --locked -p agentic-job --bin agentic-job
PATH="$PWD/target/debug:$PATH" sh docs/examples/local.sh
```

The [eight-line script](examples/local.sh) loads [bounds](examples/local.toml),
collects a fixed [noop request](examples/outputs.jsonl), and checks it with
the built CLI. It prints a temporary report path. Expect exit 0 and an
accepted noop in that JSON report; keep it for inspection or delete the
printed temporary directory afterward. It makes no forge calls, runs no
agent and changes no host settings. It is a smoke test of the hand-back contract,
not evidence of sandbox isolation or publication. Do not run `secure-host`
or `sandbox setup` on your workstation or inside an existing sandbox.

## 2. Prepare your GitHub repository

You need a public repository you own, a default branch named `main` (or
the substitution below), GitHub Actions enabled, and an authenticated `gh`
CLI on your workstation. The agent uses fresh GitHub-hosted `ubuntu-26.04`
runners; this recipe is not for an existing self-hosted machine.

Choose a full agentic-job commit you have reviewed. These examples follow
current source, not necessarily a released tag: the commit must contain
[`docs/examples/hosted.toml`](examples/hosted.toml). Replace `COMMIT` below
with that SHA. No release pin or live deployment is certified by this guide;
[versions and deployment evidence](workflow.md#first-run-walkthrough-8-november-2026)
explain that distinction. The workflow obtains its binary from the same
source, using an attested prebuilt binary when available or building it.

Create these two files in **your** repository, not the agentic-job checkout.

`.github/workflows/agent.yml`, in a public repository of your own:

```yaml
name: agent
on:
  workflow_dispatch:
    inputs:
      task: { type: string, required: true }
permissions: {}
concurrency:
  group: agent-${{ github.workflow }}
jobs:
  run:
    # Replace COMMIT with a full reviewed source commit.
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
      id: ${{ github.run_id }}
      task: ${{ inputs.task }}
      repo: ${{ github.repository }}
      outputs: create_pull_request,noop
      allow: .github/agentic-job/allow.toml
      # Generic hosted-runner settings, covered by the same source pin.
      config: .agentic-job-source/docs/examples/hosted.toml
      apply-environment: agent-apply
      agent: fake
      # Nothing counts model requests without a broker, and a cap that
      # nothing counts is refused.
      max-requests: "0"
```

`.github/agentic-job/allow.toml`, with your repository in `repos` and
your default branch in `bases`. If that branch is not `main`, also set
`base: YOUR_DEFAULT_BRANCH` in the caller's `with:` block: the workflow
defaults to `main`, not the repository's default branch.

```toml
hosts = ["github.com"]
repos = ["OWNER/REPO"]
bases = ["main"]
max_outputs = 3
max_patch_bytes = 1048576
max_patch_files = 50

[github.outputs]
create_pull_request = { max = 1 }
noop = { max = 1 }
missing_tool = { max = 1 }
```

Before dispatch, configure these settings in your repository:

- **Accounts.** Yours, owning the repository, and a dedicated bot account
  that does not own it, does not belong to any organization and has write
  access only to its own forks.
- **Secret.** `SAFE_OUTPUTS_PAT`: a classic PAT of the bot account with
  the `repo` and `workflow` scopes, stored in an environment named
  `agent-apply` that is limited to your default branch
  ([pull requests come from a fork](workflow.md#pull-requests-come-from-a-fork)).
  An empty secret, or your own PAT (unless the repository
  [accepts that](workflow.md#a-repository-the-applying-account-owns)),
  fails in apply after the agent has run. To avoid spending a run with a
  missing or wrong publishing credential, the existing optional
  `require-safe-outputs-pat: true` input checks it before the agent runs;
  it is off by default and not needed to follow this example.
- **Settings.** Actions enabled, and `cgwalters-forge/agentic-job` and the
  actions it pins allowed if the repository restricts actions. The pull
  request's CI runs as an outside contributor's would.

## 3. Dispatch and inspect the first agent run

With `gh` authenticated as your operator account, run from your repository's
checkout. Commit both files to your default branch and start it:

```sh
gh workflow run agent.yml -f task='say hello'
gh run list --workflow agent.yml --limit 1
gh run view RUN_ID
gh run watch RUN_ID --exit-status
```

Replace `RUN_ID` with the dispatched run's id. If `agent-apply` requires
approval, approve the waiting environment job in Actions before expecting
apply to finish. Check should admit the one-file patch; apply should report
the resulting draft pull request in the `applied` artifact. Open that pull
request and inspect the diff. Agent success alone proves neither result.

If policy refuses the run, check `OWNER/REPO`, the base branch, output bounds
and source pin first. If apply fails, check the environment secret, bot's
fork permissions and any waiting approval. If host probes fail, inspect
their named failure; do not disable a probe to obtain a green first run.

## 4. Choose the next step

**A real agent:** follow the [real agent checklist](workflow.md#real-agent-checklist)
with your broker and runner operators. Then change the caller above in place;
keep its dispatch input, `id`, `task`, `repo`, outputs, bounds, secret and
apply environment, and leave `apply-partial` off:

```diff
       apply-environment: agent-apply
-      agent: fake
-      # Nothing counts model requests without a broker, and a cap that
-      # nothing counts is refused.
-      max-requests: "0"
+      agent: claude
+      inference-url: ${{ vars.INFERENCE_URL }}
+      inference-audience: ${{ vars.INFERENCE_AUDIENCE }}
+      # The workflow's default; a zero would leave requests uncapped.
+      max-requests: "150"
```

Use `150` or another positive cap agreed with the broker operator; do not
keep `"0"`. Before dispatch you need the repository variables
`INFERENCE_URL` and `INFERENCE_AUDIENCE`, broker admission of this
workflow pin and repository, and a [route to the broker](workflow.md#real-agent-checklist)
from the `agent-runner`, where both register and agent run. That runner is
GitHub-hosted `ubuntu-26.04` unless you set it and a matching `config`,
and a hosted runner cannot reach a private broker. Three jobs differ in
credentials: register holds the OIDC request credential and registers the
run; the agent job gets none, only the broker's run token beside its read-only
GitHub token; and the optional [threat detector](workflow.md#optional-threat-detection),
when `AGENTIC_JOB_DETECT_MODEL` is set, has its own OIDC permission and
registers its own run from a hosted `ubuntu-26.04` runner, which then also
needs a route to the broker. For detection, the broker must also admit
`check.yml` at the same pinned commit for the same caller repository ID;
admitting `agentic-job.yml` alone covers only the main registration.
Do not switch to `plain` to bypass an admission
failure or put a provider key on the runner. The checks below compose this
change offline; no live broker run of it is shown here.

**Other forges:** [Get started on GitLab](try-gitlab.md) with a fixed issue
note, or [get started on Forgejo](try-forgejo.md) with a check-only scripted
trial. Both guides point to standalone publication fixtures; neither runs a
model-backed agent pipeline.

## What CI checks

`cargo test --locked -p agentic-job --test policy` parses the GitHub YAML,
checks its inputs against the reusable workflow, composes its generic host
configuration and admits its bounds. It applies the real-agent change to
that caller, checks its inputs again, and composes it with synthetic broker
settings, requiring a positive request cap. In CI the same test runs pinned
actionlint on the guide's YAML, before and after that change, to check
workflow syntax and expressions.
It also parses the GitLab pipeline,
checks its command flags and job separation, and runs its deterministic
producer through collect/check. The same suite executes the local script
above. `just site-test` builds the site and tests its pages and link
rewriting. Run `just site-check` after it to check rendered link destinations
and fragments. These checks need no model or forge writes; they do not establish
live GitHub/GitLab deployment or privileged host proof.
