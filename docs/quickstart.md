# Quickstart

> This text is LLM generated.

Check a hand-back locally, then choose your forge. The first runs below
are scripted: they do not interpret your task or need model credentials.

| Forge | What the first run does |
| --- | --- |
| [GitHub](#github) | Runs a scripted agent and proposes a one-file draft pull request from a bot's fork. |
| [GitLab](#gitlab) | Checks and posts one fixed issue note. No agent or inference. |
| [Forgejo](#forgejo) | Checks a one-file patch and draft pull request request without publishing. No agent or inference. |

## Check a local hand-back

On Linux, install Git, a C compiler/linker and stable Rust 1.88 or newer.
Replace `SOURCE_OWNER/SOURCE_REPO` with the [agentic-job source repository](../)
and `COMMIT` with a full reviewed commit containing this guide's examples.

```sh
git clone https://github.com/SOURCE_OWNER/SOURCE_REPO.git agentic-job
cd agentic-job
git checkout COMMIT
cargo build --locked -p agentic-job --bin agentic-job
PATH="$PWD/target/debug:$PATH" sh docs/examples/local.sh
```

Expect exit 0 and an accepted `noop` in the JSON report printed by the
[script](examples/local.sh). You can delete its temporary directory afterward.
This checks output admission, not host isolation or publication. Do not run
`secure-host` or `sandbox setup` on your workstation or in an existing sandbox.

## GitHub

### Prepare the repository

You need a public repository you own, a default branch named `main` (or
the substitution below), GitHub Actions enabled, and an authenticated `gh`
CLI on your workstation. The agent uses fresh GitHub-hosted `ubuntu-26.04`
runners; this recipe is not for an existing self-hosted machine.

Use a reviewed source pin containing [`docs/examples/hosted.toml`](examples/hosted.toml).
The workflow uses a binary from that same source. Do not assume an older release
has the same workflow inputs or runner setup; see [versions to pin](workflow.md#versions-to-pin).

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
    uses: SOURCE_OWNER/SOURCE_REPO/.github/workflows/agentic-job.yml@COMMIT
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
  Pass only the named secret, not `secrets: inherit`.
- **Settings.** If the repository restricts Actions, allow the source
  workflow and the actions it pins. The pull request's CI runs as an
  outside contributor's would.

### Dispatch and inspect the run

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

### Connect a real agent

Before replacing the scripted agent, arrange these with your broker and runner operators:

| Requirement | What to configure |
| --- | --- |
| Broker identity | Set repository variables `INFERENCE_URL` and `INFERENCE_AUDIENCE`. Keep the default `github-oidc` registration. Do not put a provider key on the runner or use `plain` to bypass admission. |
| Admission | Admit the source workflow path, exact workflow SHA and caller's numeric repository ID in the broker. Update admission when the pin changes. See [broker admission](inference.md#which-workflows-a-broker-admits). |
| Network | Both register and agent jobs need a route to the broker. For a private broker, use [disposable self-hosted runners or a composed workflow](workflow.md#the-pieces-and-an-agent-job-of-your-own); match the runner configuration to the host. |
| Limits | Agree on a model, positive request cap, cost budget and timeout. Keep `apply-partial` off for this example. |

Change the same caller in place, leaving its dispatch, bounds and publisher wiring as is:

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

Only register needs the OIDC request credential. The agent gets the broker's
run token, not the OIDC credential or provider key. If you separately enable
[threat detection](workflow.md#optional-threat-detection), its hosted check job
also needs broker reachability and admission for `check.yml` at the same pin
and caller ID. The examples are checked offline; see
[deployment evidence and gaps](workflow.md#what-has-run-and-what-has-not).

## GitLab

1. Use a public `GROUP/PROJECT` (no subgroups for this example), a protected
   default branch and an open issue. Use fresh, isolated Linux x86-64 runners
   tagged `agentic-job-producer` and `agentic-job-trusted` with a POSIX shell,
   Git, curl, jq and sha256sum. The GitLab API needs publicly trusted HTTPS.
2. [Verify the release](gitlab.md#pinned-release-binaries), then install the
   [bounds](gitlab.md#bounds) and [pipeline](gitlab.md#minimal-deterministic-pipeline)
   on the protected default branch. Substitute the host, project, base,
   verified binary checksum and issue IID. Keep the bounds at one `add_comment`
   and restrict pipeline-variable overrides to trusted operators so other
   dispatchers cannot replace the binary pin or redirect apply.
3. Give a dedicated bot an `api` token with just the project access needed
   to comment. Set `GITLAB_TOKEN` as a masked, protected variable scoped to
   `agentic-job-apply` only; see [publisher secrets](gitlab.md#publisher-secrets-and-lifecycle).
4. Select **Run pipeline** on the protected default branch. Check should leave
   `checked/report.json`; apply should post `Deterministic GitLab caller proof.`
   once on the selected issue.

The example is checked locally, not verified on a live runner. The separate
[publication fixture](gitlab.md#publication-fixture) exercises a draft merge
request on disposable GitLab CE, not this pipeline. Do not add an agent or
substitute a provider key; GitLab has no supported inference registration path.

## Forgejo

1. Use a dedicated Forgejo Actions dispatch repository, a separate public
   target with an initialized base branch, and a bot fork distinct from the
   dispatch repository. Use a trusted, isolated runner with Bash, Git, jq
   and a pinned `agentic-job` binary. It must reach Forgejo directly over HTTPS.
2. Review and copy the [trial workflow](../workflow/forgejo/dispatch.yml) to
   `.forgejo/workflows/dispatch.yml` on the dispatch repository's protected
   default branch. Set `TRIAL_RUNNER` to its runner labels as JSON (for example
   `["agentic-job"]`), `TRIAL_FORGEJO_URL` to the instance URL, `AGENT_BOUNDS`
   to the absolute path of the runner-owned [bounds file](dispatch.md#scripted-forgejo-trial),
   and `TRIAL_SCRIPTED` to `true`. Admit one `create_pull_request` and one patch
   file; omit `allow_http` for HTTPS. Do not give the dispatch repository or
   its runners a publishing PAT: a runner label does not authorize a workflow
   or ref, and Forgejo's automatic token can write to the dispatch repository.
3. In Actions, dispatch `dispatch` on the default branch with `kind=implement`,
   `repo` set to the public target and `base` to its admitted branch. Fill in
   `task`, `item` and `pool` (for example `say hello`, `1` and `trial`). Check
   should admit one draft request and patch. Read the check step's log; the
   report and patch stay in the runner's temporary directory, not an uploaded artifact.

The HTTPS Actions setup is not verified live. The trial does not publish or
run a model. [Standalone Forgejo apply](safe-outputs.md#publishing-to-forgejo)
is tested separately by a [fixture](../crates/agentic-job/tests/forgejo.rs) on a
disposable instance, not through Actions.
