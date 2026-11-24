# Stable interfaces

> This text is LLM generated.

This page lists what a caller can rely on across releases. Each entry
links to the page that documents it in full.

## The promise

Before 1.0, nothing is promised: a 0.x release may change anything here.
[GitHub Releases](https://github.com/cgwalters-forge/agentic-job/releases)
say what each release changed.

From 1.0, a stable interface is removed, renamed or given a new meaning
only in a new major version. A release that deprecates one says so in its
release notes first. New optional inputs, keys, request types and fields
may come in any release.

Unlike [gh-aw](https://github.github.com/gh-aw/reference/releases/), there is
no compiled lock file or runtime version check: your pin is the compatibility
boundary. Pin the workflows and the binary to a release or commit
([versions to pin](workflow.md#versions-to-pin)), and upgrade them together.
Configuration files refuse keys they do not know, except a few that their
pages name as accepted and ignored. So an older pin refuses a file that uses a
key added in a later release. From 1.0, a file that works with one release
keeps working with the next release in the same major version.

Where a page documents the values a stable input or key takes, such as
`base: pr:N` ([dispatch](dispatch.md)) or `status-comment-mode`'s `edit` and
`add`, those values are stable too.

Everything not listed here is internal and may change in any release. That
includes the inputs of the other workflows and actions (`policy.yml`,
`check.yml`, `apply.yml` and the rest), job and step names, artifact names and
contents (`policy.json`, `summary.json`, `applied.json` and so on), the agent's
brief, the built-in skills, and `agentic-job` commands except as described
below. Interfaces marked experimental on their own pages, such as the
standalone `safe-outputs` CLI's context and receipt and the
[external correlation interface](dispatch.md#binary-correlation-interface),
are not stable either.

## What is stable

| Interface | Forges | Reference |
| --- | --- | --- |
| [The reusable workflow](#the-reusable-workflow): inputs, secrets, `exit` and `failure-class` | GitHub | [workflow](workflow.md#a-caller) |
| [The review workflow's dispatch](#the-review-workflows-dispatch) | GitHub | [review](review.md#dispatched-reviews) |
| [Configuration files](#configuration-files): bounds, runner and secure-host | GitHub, GitLab, Forgejo | [files read](interface.md#files-read) |
| [Safe-output requests](#safe-output-requests) and which forge publishes which | GitHub, GitLab, Forgejo | [safe outputs](safe-outputs.md) |
| [Hand-back files](#hand-back-files) an agent or job leaves | GitHub, GitLab, Forgejo | [what the agent does](safe-outputs.md#what-the-agent-does) |
| [Publishing from your own CI](#publishing-from-your-own-ci): `apply --forge`, its target and status flags, and its token variables | GitLab, Forgejo | [publishing to GitLab](safe-outputs.md#publishing-to-gitlab), [publishing to Forgejo](safe-outputs.md#publishing-to-forgejo) |

## Publishing from your own CI

On GitLab and Forgejo you run `agentic-job policy`, `check` and `apply` from
your own CI; see [GitLab CI](gitlab.md) and [Forgejo](quickstart.md#forgejo).
Besides the files and request types below, these parts of
`agentic-job apply --forge gitlab|forgejo` are stable, with the `check`
flags they depend on:

| Part | Names |
| --- | --- |
| Where to publish | `--server`, `--repo`, `--policy`, `--checked`, `--run-url`, `--push-repo` |
| The caller's comment target | `--comment-target`; on GitLab also `--comment-target-kind` (`issue` or `pull-request`) and `--run-summary`, which posts what `check --run-summary FILE` accepted |
| Inline review comments | `check --comment-repo`, `--comment-target` and `--review-head` |
| The caller's commit status | `--status` and `--status-sha`, which set the status named `agentic-job`; on GitLab also `--status-ref` and `--status-pipeline-id` |
| The write token | `FORGEJO_TOKEN` or `GITLAB_TOKEN`; or, when `APPLY_ROLE_BINDINGS` is nonempty, `STATUS_TOKEN`, `REVIEW_TOKEN`, `PUSH_TOKEN` and `PUBLICATION_TOKEN` with no fallback ([Forgejo and GitLab roles](safe-outputs.md#forgejo-and-gitlab-roles)) |

## The reusable workflow

Call [`.github/workflows/agentic-job.yml`](../.github/workflows/agentic-job.yml)
with `workflow_call`. Each input's `description:` field and
[a caller](workflow.md#a-caller) say what it does.

| Group | Inputs |
| --- | --- |
| The run | `id`, `task`, `task-artifact`, `repo`, `base`, `kind`, `outputs`, `max-outputs`, `allow`, `config`, `context`, `push-item`, `proposals-artifact`, `bind-continuation` |
| Reviews and events | `review`, `advisory`, `review-task`, `review-item`, `review-shared-task`, `review-head`, `event` |
| The agent | `agent`, `model`, `agent-config-repo`, `agent-config-ref`, `agent-config-path`, `agent-skills`, `agent-user`, `github-reads`, `runner-gate`, `packages`, `npm`, `setup`, `egress-write-policy`, `session`, `idle-minutes` |
| Runners and the binary | `runner`, `agent-runner`, `build-binary` |
| Inference | `inference-url`, `inference-register` (`github-oidc`, `plain` or `token-file`), `inference-audience`, `inference-token-file` |
| Limits | `timeout`, `max-requests`, `max-tasks`, `budget-usd` |
| Applying | `output-repo`, `item-repo`, `apply-environment`, `apply-partial`, `apply-staged`, `require-safe-outputs-pat`, `comment-target`, `issue`, `notify`, `status-comment`, `status-comment-mode`, `title-prefix`, `branch-prefix`, `artifact-prefix`, `role-bindings` |

`agent-user` accepts only `runner`; removed values are refused
([removed keys](interface.md#removed-keys-and-runner-mode-refusals)).
`runner` and `agent-runner` default to `"ubuntu-26.04"`.
`runner-gate` is off by default ([launch gate](secure-host.md#the-runner-only-launch-gate)).

These inputs are not stable: `budget` (use `budget-usd`); `fake-profile`,
`expect-check-refusal` and `secure-host-image-artifact-id`, which exist for
this repository's tests; and `inference-provider` and
`inference-register: api-key`, which are parsed but refused
([a provider API key](inference.md#a-provider-api-key)).

| Secret | Use |
| --- | --- |
| `SAFE_OUTPUTS_PAT` | The token the apply job writes with. Pass it explicitly, not with `inherit` ([the apply job and its token](workflow.md#the-apply-job-and-its-token)). |
| `STATUS_TOKEN`, `REVIEW_TOKEN`, `PUSH_TOKEN`, `PUBLICATION_TOKEN` | One token per role when `role-bindings` is set; there is then no fallback to `SAFE_OUTPUTS_PAT` ([role credentials](workflow.md#caller-configured-role-credentials)). |

The secrets `INFERENCE_API_KEY` and `MCP_TOKEN` are declared for
compatibility but reach no job, and are not stable.

The repository variable `SOURCE_BUILD_ARTIFACTS=true`, off by default, runs
the binary from main's latest attested build instead of a release, and
`SOURCE_BUILD_COMMIT=FULL_SHA` holds it to one commit
([where the binary comes from](workflow.md#where-the-binary-comes-from)).
Review calls ignore both and always run the binary for the called workflow's
source, so changing them does not roll back a review.

### Why a run failed

Two outputs say how a run that did not end well ended
([why a run failed](workflow.md#why-a-run-failed)). `exit` is the run's exit
state: 0, 1, 3, 4 or 124 ([exit states](interface.md#exit-states)). An error
of `run` itself, such as a launch gate refusal before the agent starts,
has `exit` 2 and no `failure-class`. The job log says why; retrying a gate
refusal on the same host will fail again.
`failure-class` is empty or one of these words:

| Word | Meaning | Requeue? |
| --- | --- | --- |
| `timeout` | The run reached its time limit. | read the summary |
| `budget` | The run went over its budget. | read the summary |
| `stall` | A turn sent nothing for the stall timeout, twice. | read the summary |
| `agent_exit` | The agent's process exited. | read the summary |
| `inference_rate_limited` | The inference service rate-limited the run. | yes, after a wait |
| `inference_overloaded` | The inference service was overloaded. | yes, after a wait |
| `inference_unreachable` | The inference service could not be reached. | yes, after a wait |
| `inference_quota` | The inference account ran out of quota. | no |
| `inference_unauthorized` | The inference service refused the credential. | no |
| `control_unreachable` | The host check before the run could not reach a host outside the runner, so the agent never started; `exit` is 4. | a bounded number of times |

The word is fixed, but it is read from what the agent says and prints, so an
agent can make a run end `inference_rate_limited`. Bound how often you
requeue one item, as with any retry. A new word may come
in any release. Treat a word you do not know as a failure to look at, not
one to retry.

For `control_unreachable`, the run step also fails with an error annotation
that begins `agentic-job run ended with exit state 4 (control_unreachable):`.
A scheduler can match that prefix to tell a run that never started.

## The review workflow's dispatch

[`.github/workflows/review.yml`](../.github/workflows/review.yml) takes the
`workflow_dispatch` and `workflow_call` string inputs `pr`, `head` and `pool`.
A dispatched run is named `review OWNER/REPO#PR HEAD (POOL)`, which a
scheduler can read back. The repository variables `REVIEW_POOLS` and
`REVIEW_RECORD_ONLY` configure it ([dispatched reviews](review.md#dispatched-reviews)).

## Configuration files

All three files are TOML.

| File | Given as | Contents |
| --- | --- | --- |
| Bounds | the workflow's `allow` input; `agentic-job policy --allow`, `event --allow` | What a run may write and where ([the bounds and the policy](safe-outputs.md#the-bounds-and-the-policy)) |
| Runner configuration | the workflow's `config` input; `agentic-job config --from`, `run --config` | `[host]`, `[egress]`, `[setup]`, `[inference]`, `[agent]`, `[limits]`, `[session]`, `[commit]`, `[preflight]` ([files read](interface.md#files-read)) |
| Secure-host configuration | the secure-host action's `config` input; `agentic-job config --host` | `[host]`, `[egress]` and `[setup]` of the runner configuration, nothing else ([secure-host](secure-host.md)) |

The bounds file has these top-level keys: `hosts`, `allow_http`, `repos`,
`bases`, `private`, `max_outputs`, `max_patch_bytes`, `max_patch_files`,
`protected`, `commit_author`, `native_handlers` and `dedupe`, the table
`[unprotected_files]`, and exactly one forge section: `[github]`, `[gitlab]`
or `[forgejo]`, each with its `outputs.TYPE` tables.

Repository names are `owner/name` on GitHub and Forgejo. On GitLab they may
have more components, as in `group/subgroup/project`. A GitLab fork must
be outside the target's top-level group
([publishing to GitLab](safe-outputs.md#publishing-to-gitlab)).

`agentic-job config --no-session` refuses a runner configuration whose
effective `session.listen` is true, including one inherited from the file.

`[host]` was called `[sandbox]` before #2071. `[sandbox]`, and a `sandbox.KEY`
setting of `config`, are still read with a warning, and a file with both
tables is refused. The alias stays at least until the release after the first
one whose image the secure-host forwarder pins and which reads `[host]`
(#2656). Until then `config --host` without `[host.prepared]` writes
`[sandbox]`. Removing the alias will be listed as a breaking change in the
release notes first.

The keys of the removed sandbox user are refused by name
([removed keys](interface.md#removed-keys-and-runner-mode-refusals)).

## Safe-output requests

A run hands back requests in gh-aw's
[safe-output format](https://github.github.com/gh-aw/reference/safe-outputs/):
one JSON object per line, with a `type` and that type's fields. The types
gh-aw defines, and their fields, follow gh-aw at the pinned commit, as
recorded in [`validation.json`](../safe-outputs/validation.json); `document`
is agentic-job's own. The bounds decide which
types a run may use, and each type's page in [safe outputs](safe-outputs.md)
gives its own target and field checks.

| Type | GitHub | GitLab | Forgejo |
| --- | --- | --- | --- |
| `add_comment`, `create_pull_request`, `push_to_pull_request_branch`, `create_pull_request_review_comment`, `create_issue`, `close_issue`, `close_pull_request`, `add_labels`, `remove_labels` | yes | yes | yes |
| `noop`, `missing_tool`, `missing_data` | no write | no write | no write |
| `create_discussion`, `update_issue`, `update_pull_request`, `mark_pull_request_as_ready_for_review`, `add_reviewer`, `assign_to_user`, `link_sub_issue`, `hide_comment`, `update_project`, `create_check_run`, `reply_to_pull_request_review_comment`, `resolve_pull_request_review_thread` | yes | refused | refused |
| `document`, where `native_handlers` lists it ([durable findings documents](safe-outputs.md#durable-findings-documents)) | yes, native only | refused | refused |

On GitLab, `add_labels` and `remove_labels` name their item with exactly one
of `issue_number` or `pull_request_number`, not `item_number`. See
[publishing to GitLab](safe-outputs.md#publishing-to-gitlab) and
[publishing to Forgejo](safe-outputs.md#publishing-to-forgejo).

On GitHub, the bounds' `native_handlers` may list types that agentic-job
publishes with its own handlers instead of gh-aw's
([agentic-job's own handlers](safe-outputs.md#agentic-jobs-own-handlers)).

## Hand-back files

An agent leaves these under its home directory for `run` to collect
([what the agent does](safe-outputs.md#what-the-agent-does)):

| File | Contents |
| --- | --- |
| `out/safe-outputs.jsonl` | The requests above: at most 1 MiB and 1000 nonblank lines. A file over a limit is refused whole. |
| `out/outcome.json` | At most 64 KiB: `summary`, `tests` (each with `command`, `exit_code` and `duration_s`), `stopped_early` (null or why), and, where the bounds' `ready_when_complete` asks for one, `checkpoint` (`complete`, `done`, `left`, `next`). An open checkpoint keeps the work a draft ([ready or draft](safe-outputs.md#ready-or-draft)). |
| `out/replacement.json` | Optional: a series of commits that replaces a pull request's branch ([replacing the complete series](safe-outputs.md#replacing-the-complete-series)). |
| `out/test-evidence.json` and `out/test-evidence-N.log` | Only where the bounds have `[github.test_evidence]`: schema `agentic-job/test-evidence/v1` ([repeated test evidence](safe-outputs.md#repeated-test-evidence)). |

A job other than the agent hands back through the workflow's
`proposals-artifact` input: an artifact holding `outputs.jsonl`, and
optionally `base.json` and one `aw-BRANCH.patch`
([proposals from a non-agent job](workflow.md#proposals-from-a-non-agent-job)).
