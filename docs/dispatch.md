# Dispatch an operator task

> This text is LLM generated.

Dispatch a task against an existing issue or code change. The caller's
[bounds](safe-outputs.md#the-bounds-and-the-policy), not task text, authorize outputs.

| Forge | How to start | What to expect |
| --- | --- | --- |
| GitHub | [Run the dispatch workflow](#run-the-dispatch-workflow) from Actions or `gh`. | Scripted by default; supports real agents and publication. |
| GitLab | [Run the deterministic pipeline](quickstart.md#gitlab) on the protected default branch. | Posts a fixed issue note without an agent. |
| Forgejo | [Run the Actions trial](#forgejo-actions-caller) on the default branch. | Checks a scripted patch; no agent or publication. |

## Run the dispatch workflow

On GitHub, use **Actions → dispatch → Run workflow** on the default
branch (other refs are refused), or run this from the caller checkout:

```sh
gh workflow run dispatch.yml -f repo=OWNER/REPO -f item=1 \
  -f kind=triage -f task='Summarize the next step on this issue'
```

If not installed, copy [dispatch.yml](../.github/workflows/dispatch.yml) and
[dispatch.toml](../.github/agentic-job/dispatch.toml) to the same paths in
your caller repository. In the workflow, set `jobs.run.uses` to
`SOURCE_OWNER/agentic-job/.github/workflows/agentic-job.yml@COMMIT` and set
the `target` checkout's `repository` and `ref` to `SOURCE_OWNER/agentic-job`
and that same full, reviewed commit SHA. In the bounds, set `repos` to your
exact public target repository, with `main` as the base. Commit the files
to the protected default branch and allow the pinned workflows and actions.

For the trial, leave variables unset and choose an issue in the caller
repository. The script ignores `task` and posts a canned comment, with no
inference or additional secret.

### Inputs

| Input | Value |
| --- | --- |
| `repo`, `item`, `task` | Public `OWNER/REPO`, positive item number, public task text. |
| `kind` | Profile below. |
| `item-repo` | Allowlisted `OWNER/TRACKER` for implement, triage or research. Comments follow the item; changes target `repo`. |
| `base` | Implement only: [stack on `pr:N`](#stack-an-implement-run); otherwise `main`. |
| `status-comment` | Reuse the status account's comment on this item by ID. |
| `status-comment-mode` | `edit` (default) reuses one status; `add` posts one per run. |
| `session`, `idle-minutes`, `runner` | [Session and runner selection](#start-a-session-on-a-chosen-runner). |

### Choose a profile

| `kind` | Item | Checked result, subject to bounds |
| --- | --- | --- |
| `triage` | Issue | One comment; real runs may also close up to 30 target issues with reasons. |
| `research` | Issue or pull request | One comment; no patch, verdict or pull request head checkout. |
| `implement` | Issue | One draft pull request, or one comment for a comment-only task. The scripted change adds `DISPATCH-TRIAL.md`. |
| `review` | Open pull request against the configured base | [Verdict](review.md#the-verdict) on the pinned head (including forks) or no publication; may add one bounded label. Not merge approval. |
| `fix` | Open pull request | Pushes to the authorized head branch; redispatch if it moves. Off by default; enable `push_to_pull_request_branch` with branch globs in the [bounds](safe-outputs.md#pushing-to-a-pull-requests-branch). |

For implement, fix or a cross-repository dispatch, set `APPLY_ENVIRONMENT`
to an environment restricted to the protected default branch and store
[`SAFE_OUTPUTS_PAT`](workflow.md#the-apply-job-and-its-token) there for a
dedicated publishing account. This includes manual runs using `fake`, not
CI's `scripted: true`, which supplies neither the environment nor the token.
Reusable callers forward the secret by name, never with `secrets: inherit`.
Implement normally uses the account's fork; branches in a target it owns
need [explicit acceptance](workflow.md#a-repository-the-applying-account-owns).

### Find the result

The run summary shows the result link (`result-url`) or no-write reason.
`missing_data` with no change and at most a `noop` sets `blocked: true`
without failing; other combinations fail. Ordinary status comments are for
same-repository non-review runs; blocked reasons can also be posted elsewhere
with the publication token.

A draft adds `Closes #N` for an issue in the receiving repository or
`Refs OWNER/REPO#N` for an issue elsewhere. For partial work in the same
repository, start a PR body line with `Part of #N` or `Refs #N` instead.
To batch issues, put the primary issue in `item` and name the rest in `task`.

For matching `kind`, `repo`, `item-repo` and `item`, a new dispatch replaces
the waiting run, not the active one.

### Stack an implement run

Set `base=pr:N` for an open pull request into the target's default branch.
Set `AGENTIC_JOB_STACK_AUTHOR` to the bot login to exclude other authors.
Allow the head branch in `bases`; for the bot's public fork, also include
`create_pull_request` in `native_handlers`. The draft targets the head in
its repository (the bot's fork or the target), leaving the lower PR alone.

## Switch to a real agent

Set these GitHub repository variables on the caller, not in the dispatch:

| Variable | Value |
| --- | --- |
| `AGENT`, `AGENT_MODEL` | `opencode`, `claude` or `vibe`, and a model supported by the agent and broker. |
| `AGENT_RUNNER`, `AGENT_CONFIG` | Disposable runner labels as JSON and an optional runner TOML path (defaults to pinned hosted config). |
| `AGENT_CONFIG_REPO`, `AGENT_CONFIG_PATH` | Optional public repository and directory for opencode or Vibe configuration, not runner TOML. |
| `INFERENCE_URL`, `INFERENCE_AUDIENCE` | Reachable broker URL and its configured GitHub OIDC audience. No provider API key on the runner. |
| `RUNNER_GATE` | `true` (in any case) to start the agent only through the [launch gate](secure-host.md#the-runner-only-launch-gate), without the job's read token. No hosted runner passes it yet. |

Confirm [broker admission](inference.md#which-workflows-a-broker-admits),
budgets and reachability from registration and agent jobs. For private
network access, you may need to [compose your own job](workflow.md#the-pieces-and-an-agent-job-of-your-own).

## Start a session on a chosen runner

Set `session=true` to [keep the agent available](interactive.md) after its
first turn. `idle-minutes` defaults to 10, maximum 60. No scripted runs or
reviews. Check and apply wait for the session to end.

Set `runner` to a name in the caller's `AGENT_RUNNERS` JSON map, for example
`{"isolated":{"runs-on":["self-hosted","isolated"],"config":".github/agentic-job/session.toml"}}`.
Names prevent tasks from choosing labels or paths outside that map. Omit
`runner` for the defaults. For sessions, use a runner already on the tailnet
and a `[session]` configuration that admits the operator.

## Giving runs a toolchain

In the runner TOML (`AGENT_CONFIG` or the named runner's `config`), set
`[setup]` `packages` for all targets. `[setup.repo-packages]` adds packages
by `OWNER/REPO`, with an optional `default` fallback. Only trusted caller
configuration can choose what is installed as root. To replace removed
`[setup.tools]`, use distribution packages or adapt the caller to pass the
reusable workflow's unprivileged `setup` input.

### Capability preflight

On a disposable runner, opt in with `[preflight]` to require `vcpus`,
`memory-gib`, `disk-gib`, `kvm` or `libvirt = "session"`. Missing capabilities
fail the agent job before the task starts. KVM requires a working hardware
guest; there is no software fallback. See the [CLI reference](interface.md).

## External runs

The shipped dispatcher does not orchestrate separate runs. These opt-in
interfaces are for custom callers.

### Match the external run

Keep the dispatch record on the trusted caller. Match exactly one producer
attempt before fetching its raw hand-back. A digest verifies the downloaded
bytes, not who produced them or whether tests ran. Re-check the raw files
under caller bounds; never execute them as code.

### Binary correlation interface

| Forge | Available interfaces |
| --- | --- |
| GitHub | `external-fetch` verifies a caller-owned record and writes a receipt for one draft implement result. |
| GitLab | `external-fetch --forge gitlab` and receipt checking are available; apply refuses GitLab receipts. See the [caller spec](../specs/gitlab-caller.md). |

On GitHub, compose the same-pinned policy, check and apply workflows:

1. Pass the receipt JSON to policy as `external-receipt`, with `output-repo`
   equal to `repo` and `issue` equal to the recorded item number.
2. Upload only the extracted raw files in the trusted caller run. Pass
   policy's outputs and the new upload's `safe-outputs-artifact-id` and
   `safe-outputs-artifact-digest` to check.
3. Set `AGENTIC_JOB_DETECT_MODEL`: apply requires successful detection in
   the caller. Give apply `policy: ${{ toJSON(needs.policy.outputs) }}` and
   `check: ${{ toJSON(needs.check) }}` (including the job result). Keep
   publishing credentials off producer runners.

See the [external run module](../crates/agentic-job/src/external.rs)
for the record and receipt formats.

### Resources, lifetime and cleanup

Set a deadline and destroy each disposable host and its guests on success,
failure and cancellation. Fetch and check do not manage their lifecycle.

### Repeated-test evidence and acceptance

Opt in to [repeated-test evidence](safe-outputs.md#repeated-test-evidence)
to bind accepted attempts and logs to the patch. Include failures and skips.
Validation is not proof a test ran, and missing evidence does not block a draft.

## Forgejo Actions caller

Use the [scripted Forgejo trial](quickstart.md#forgejo) with a dispatch repository
distinct from both the public target and publisher's fork. Do not put a
publishing token on any runner available to the dispatch repository: the
automatic job token already has write access to that repository.

### Scripted Forgejo trial

| Repository variable | Value |
| --- | --- |
| `TRIAL_SCRIPTED` | `true`; accepts only `implement` on the default branch. |
| `TRIAL_RUNNER` | JSON runner labels for a trusted isolated runner with pinned `agentic-job`, Bash, Git and jq. |
| `TRIAL_FORGEJO_URL` | Forgejo instance URL. |
| `AGENT_BOUNDS` | Absolute path to runner-provisioned bounds, not writable by jobs. Admit the public target and base, set `[forgejo].push_repo` to the separate fork, and bound `[forgejo.outputs]` to one `create_pull_request`. |

Success means the one-file patch and draft request passed check, not that
a pull request was opened.
