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
agent and changes no host settings. It is a local contract demonstration,
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
apply to finish. Inspect the check/apply summaries and `applied` artifact;
a successful agent job alone does not mean a pull request was published.

If policy refuses the run, check `OWNER/REPO`, the base branch, output bounds
and source pin first. If apply fails, check the environment secret, bot's
fork permissions and any waiting approval. If host probes fail, inspect
their named failure; do not disable a probe to obtain a green first run.

## 4. Choose the next step

**A real agent** needs a credential broker
([what a broker provides](inference.md#what-a-broker-provides)), but
it doesn't need any secret beyond `SAFE_OUTPUTS_PAT`. Replace
`agent: fake` with `claude`, drop `max-requests: "0"` (the default caps at 150 requests, which the
broker counts), and pass `inference-url` and `inference-audience` from the
broker's operator and an `agent-runner` that reaches the broker in **both**
the separate register job and the agent job. Keep the default
`inference-register: github-oidc`; the operator must admit the caller's
numeric repository id and exact workflow commit. Do not switch to `plain`
to bypass an admission failure ([its limits](inference.md#registering-without-proof));
agentic-job doesn't provision runners. The
[real agent checklist](workflow.md#real-agent-checklist) has the rest.

**GitLab:** follow the [deterministic GitLab CI caller](gitlab.md#minimal-deterministic-pipeline)
for a policy/produce/check/apply pipeline and its bounds, binary-verification
and publisher-token setup. It posts a fixed comment, not an agent-generated
change. GitLab agent inference is not yet supported; do not copy a GitHub
broker identity or work around that boundary with a provider key.

## What CI checks

`cargo test --locked -p agentic-job --test policy` parses the GitHub YAML,
checks its inputs against the reusable workflow, composes its generic host
configuration and admits its bounds. It also parses the GitLab pipeline,
checks its command flags and job separation, and runs its deterministic
producer through collect/check. The same suite executes the local script
above. `just site-test` builds the site and tests its pages and link
rewriting. These checks need no model or forge writes; they do not establish
live GitHub/GitLab deployment or privileged host proof.
