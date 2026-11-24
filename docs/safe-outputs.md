# Safe outputs

> This text is LLM generated.

<!-- Preserve deep links to sections now in tables. -->
<!-- markdownlint-disable MD033 -->

A safe output requests a forge action, such as a comment or draft pull request.
A separate job checks it against caller-owned bounds before publishing. The format comes from
[GitHub Agentic Workflows (gh-aw)](https://github.github.com/gh-aw/reference/safe-outputs/);
the configuration and supported operations differ.

## The bounds and the policy

Start with one destination and one operation. For example, a GitHub caller
can allow one comment:

```toml
hosts = ["github.com"]
repos = ["OWNER/REPO"]
bases = ["main"]
max_outputs = 1

[github.outputs]
add_comment = { max = 1 }
```

For a manual GitHub run, copy the [example caller](../.github/workflows/example.yml)
and keep its `id`, `task`, agent and permission settings. As in the
[Quickstart](quickstart.md), call the workflow at a pinned commit and set
`config: .agentic-job-source/docs/examples/hosted.toml`. A comment needs no
`apply-environment` or `SAFE_OUTPUTS_PAT`; drop both. Point `allow`
at this file and set `repo: OWNER/REPO`, `kind: analysis`, `outputs: add_comment`,
`max-outputs: '1'` and `comment-target: '7'` (your issue number). With the
example's `agent: fake`, also set `fake-profile: comment`, which posts one fixed
comment; a real agent needs a task asking for that comment. Use the calling repository for this example;
`repos` checks the checkout, not GitHub's `output-repo`. Apply needs
[`issues: write`](workflow.md#the-apply-job-and-its-token), which the example grants.

On GitLab or Forgejo, use its host and `[gitlab.outputs]` or `[forgejo.outputs]`.
Unlisted types are disabled. Set patch byte and file limits for code changes.
Organization bounds can only narrow caller bounds.

## What the agent does

1. Leave ordinary changes uncommitted and unpushed; the runner makes one patch.
2. Write one JSON object per line to `~/out/safe-outputs.jsonl`.
   `agentic-job handback guide` lists enabled types and fields.
3. Record checks and unfinished work in `~/out/outcome.json`. Run
   `agentic-job handback check` and fix refusals before ending the session.

For a fixed comment target:

```json
{"type":"add_comment","body":"The documentation builds locally."}
```

Over 1 MiB or 1,000 nonblank request lines refuses the whole hand-back, patch
included. `[commit] format = true` opts into Rust formatting without adding paths.

## Without an agent

Pass `proposals-artifact` to skip the agent but keep check and apply. Supply
`outputs.jsonl`; for a change add `base.json` and `aw-agent-run-RUNID.patch`,
a single-commit mail patch with `X-GH-AW-Base-Commit: SHA`. Use this run's
`agent-run-RUNID` branch. See the [producer and caller example](../.github/workflows/example-deterministic.yml#L66-L121).

## Who applies

Keep write credentials out of the producer and check jobs. Apply treats artifacts
as data, not code. Mentions and URLs may be filtered. Never include credentials:
known run secrets and private keys normally refuse; other credential shapes may
only warn. Apply is not atomic: inspect the destination before retrying.

<a id="the-check-in-two-halves"></a><a id="off-github"></a>

The check job runs `agentic-job collect --policy FILE --outputs DIR --collected FILE`,
which sanitizes each request as gh-aw's collector would and exits 1 if it refused
a line, then `check` with the same `--collected` file against the policy and patch.
Neither needs a forge: a GitLab or Forgejo caller runs both on its checking
machine, as in the [GitLab pipeline](gitlab.md).

## Neutral profile

Workflow publishers on every forge share the request types below; the
[collector schema](../safe-outputs/validation.json) lists what the collector
parses, which is more than each publisher accepts. **PR** includes GitLab merge requests. See [safe-output requests](stable-interfaces.md#safe-output-requests).

| Request `type` | Effect |
| --- | --- |
| `add_comment` | Post a comment on an admitted issue or PR. |
| `create_pull_request` | Propose the checked patch. Draft by default (Forgejo uses `WIP:`). |
| `push_to_pull_request_branch` | Update an admitted open PR's branch only if its checked head still matches. |
| `create_pull_request_review_comment` | Post a finding on a diff line. |
| `create_issue` | Open an issue. |
| `add_labels`, `remove_labels` | Change allowed labels on an issue or PR. |
| `close_issue`, `close_pull_request` | Close the named item without merging. |
| `noop`, `missing_tool`, `missing_data` | Report without requesting a forge write. |

### Publishing to GitHub

Apply uses pinned gh-aw handlers or opt-in native handlers.

<a id="closing-issues-and-changing-labels"></a>

Pre-create labels and set `allowed` (optionally `blocked`). Names are 1–64 ASCII
letters, digits, spaces or `- _ . / :`, without surrounding whitespace or a
leading `-`. Label and close requests name the exact `repo` and a positive item
number; include the closing reason in `body`.

| Additional GitHub operations | Required bounds or conditions |
| --- | --- |
| <a id="updating-issues-and-pull-requests"></a>`update_issue`, `update_pull_request` | Set `fields`: issue `title`, `body`, `status`; PR `title`, `body`, `draft`, `update_branch`. |
| <a id="closing-pull-requests-and-linking-sub-issues"></a>`link_sub_issue` | Like `close_pull_request`, restricted to the admitted repository. |
| <a id="updating-project-fields"></a>`update_project` | Bound `projects` and `fields`; use an apply-environment credential with project access. |
| <a id="posting-a-check-run"></a>`create_check_run` | Pin a name that no branch protection or ruleset requires. Use a GitHub App credential with checks write access. |
| `create_discussion` | Set `category`. |
| `add_reviewer`, `assign_to_user` | Set `allowed` logins. |
| `hide_comment` | Set `allowed_reasons`. |
| `mark_pull_request_as_ready_for_review`, `reply_to_pull_request_review_comment`, `resolve_pull_request_review_thread` | Enable explicitly for the admitted PR. |
| <a id="durable-findings-documents"></a>`document` | Native only. Write a gist and link it on the fixed issue; no other writes in the batch. Use a gist-write user credential. Updates require an allowed, owned gist ID. Secret gists are readable by anyone with the URL. [Fields and limits](../crates/safe-outputs/src/document.rs). |

<a id="agentic-jobs-own-handlers"></a>
<a id="proposing-follow-up-issues"></a>

Select [native handlers](../crates/safe-outputs/src/apply/github.rs) with
`native_handlers`. With native issue creation, `comment_on_duplicate = true`
can post on any same-title open issue in the output repository, even outside the
fixed comment target. Retrying can post again.

### Publishing to GitLab

Set a fixed item **and kind** for notes. Target labels by `issue_number` or
`pull_request_number`, never `item_number`. See
[GitLab credentials and status](gitlab.md#publisher-secrets-and-lifecycle)
and [run summaries](gitlab.md#diagnostics-and-summary-publication).

For merge requests from a fork, set `push_repo` outside the target's top-level
group: subgroups inherit that group's CI variables. For `group/team/project`,
policy refuses `group/bot/project`; `bot/project` can be eligible.

### Publishing to Forgejo

Issues and PRs share numbers. Give [apply](interface.md#commands) `FORGEJO_TOKEN`.
For PRs, set `push_repo` in bounds and pass the same fork as `--push-repo`.

### Caller-bound publisher roles

To prevent an operation borrowing a stronger credential, opt in with
`role-bindings` on GitHub or `APPLY_ROLE_BINDINGS` on GitLab and Forgejo. Bind
all four roles to numeric actor IDs. Missing or mismatched tokens refuse without
fallback. GitHub requires supported native handlers; only GitHub supports App bindings.

<a id="forgejo-and-gitlab-roles"></a>

| Role | Credential | Used for |
| --- | --- | --- |
| `status` | `STATUS_TOKEN` | Caller status |
| `review` | `REVIEW_TOKEN` | Comments and inline findings |
| `fork_push` | `PUSH_TOKEN` | Fork and git writes |
| `publication` | `PUBLICATION_TOKEN` | PR, issue and metadata publication |

### Review comments on the pull request

<a id="neutral-inline-comments"></a>

GitLab and Forgejo require an admitted PR and a trusted review head for inline
findings. Use `path`, `line`, `body` and optional `side` (`RIGHT` by default).
A stale head or an unresolved diff position refuses publication. Retrying may
post again.

#### Head-bound advisory publication

To prevent stale or redirected comments, GitHub `advisory: true` binds prose
to an admitted PR head. Use `event: true`, `review: true`, `kind: analysis`,
`outputs: add_comment,noop`, `max-outputs: '1'` and `notify: none`, and point
`review-task` at a task file in the trusted base; plain `task` does not replace
it. Leave `comment-target`, `review-item`, `proposals-artifact`, `output-repo`
and `apply-environment` empty and `apply-partial` false. Ask for prose, not verdicts or inline findings. See
[caller validation](../.github/workflows/policy.yml#L553-L567) and the
[review request check](../crates/agentic-job/src/review/mod.rs#L452-L465).

## Publishing changes

### Pushing to a pull request's branch

Allow `push_to_pull_request_branch` with branch globs. Own branches may run CI
with privileges; review them before enabling `own-branch-repos` (GitHub, GitLab)
or GitHub's `in-repo-pull-requests`. Write access alone is not acceptance.
Agent-written `.github` files need bounds whose `[unprotected_files]` names the
repository in `repos` with `dot_folders = [".github"]`. Even then, a fix push of them is always refused in
the calling repository. Outside apply's own fork, the head repository must
accept the push as above (`own-branch-repos` or its default branch's
`.github/agentic-job/accept-owner-branches`) and its default branch must also
have `.github/agentic-job/accept-workflow-pushes` naming that repository
(`owner/repo`) on a line of its own; caller bounds cannot replace that file.
Such a workflow runs with the head repository's secrets before review, so check
first that no organization secret it can read also reaches the calling
repository. See [apply safeguards](workflow.md#what-the-apply-job-does-before-it-writes).

#### Replacing the complete series

To rewrite GitHub PR history, opt in with `replacement_max_commits` under the
push bound. Run `agentic-job handback replace --base BASE_SHA [RANGE]`. Every
commit is checked, not just the final tree, and the push is leased to the old
head to avoid overwriting another writer's changes.

### Ready or draft

<a id="unchanged-completion-remains-unavailable"></a>

GitHub's `ready_when_complete` keeps checkpoints draft and marks completed work
ready. A continuation still needs a verified push; `noop` cannot make it ready.

### A secondary pull request

`[github.secondary_pull_request]` admits one additional draft to a fixed `repo`,
`base` and `branch_prefix` (ending in `/`, such as `agentic-job/`), with `max = 1`, `max_patch_bytes` and `max_patch_files`.
It counts toward `max_outputs`. See [caller setup](workflow.md#a-secondary-pull-request).

### Repeated test evidence

Opt in with `[github.test_evidence]`. Include `test-evidence.json` and
`test-evidence-N.log` for the exact tested tree. See the
[acceptance contract](dispatch.md#repeated-test-evidence-and-acceptance).

## Standalone CLI

For a separate CI pipeline, build with `cargo build --locked -p safe-outputs --bin safe-outputs`.
Use trusted context in both jobs:

```sh
target/debug/safe-outputs check --context context.json --input outputs.jsonl --checked checked.json
target/debug/safe-outputs apply --context context.json --input outputs.jsonl --checked checked.json
```

Transfer the exact input and fresh receipt through the trusted check job's artifact
channel. A receipt binds bytes, not provenance. Give only apply `SAFE_OUTPUTS_TOKEN`
through CI secrets. Context and receipts are experimental.

| Forge | Apply support and context |
| --- | --- |
| GitHub (default) | New comments and reports only. Set `repo`, `item`, `max_outputs`, `outputs` and optionally `api_url`, as in this [caller context](../.github/agentic-job/e2e/safe-outputs-context.json). |
| GitLab | Pass `--forge gitlab` to both commands. All neutral types; for patches transfer `base.json` and `aw-BRANCH.patch` too. |
| Forgejo | Pass `--forge forgejo` to both commands. New comments and reports only. |

<a id="standalone-gitlab-ci"></a><a id="standalone-forgejo-comments"></a>

GitLab and Forgejo contexts hold the effective `policy`, not the TOML bounds.
Compile it in a trusted job from bounds whose host and `[gitlab.outputs]` or
`[forgejo.outputs]` select the forge:

```sh
agentic-job policy --allow bounds.toml --repo OWNER/REPO --clone-url https://forge.example/OWNER/REPO \
  --base main --kind analysis --outputs add_comment --max-outputs 1 > policy.json
jq -n --slurpfile policy policy.json '{policy: $policy[0], server: "https://forge.example",
  item: 7, item_kind: "issue", run_url: "https://ci.example/runs/123"}' > context.json
```

`item_kind` is `issue` or `pull-request`. Inline GitLab findings also need
`review_head`. Never take a credential destination from producer output.

## Further reference

| Topic | Reference |
| --- | --- |
| <a id="public-base-secret-evidence"></a>Public-base secret evidence | `[commit] allow-base-secret-lines` is off by default. It permits exact already-public base content, never known run secrets or new keys. [Configuration](stable-interfaces.md). |
| <a id="endpoint-redacted-patch-replay"></a>Endpoint-redacted replay | `[commit] replay-redacted-endpoints` is off by default. Only native primary GitHub PR creation can recover authenticated old-side endpoint text. [Replay](../crates/safe-outputs/src/replay.rs). |
| <a id="stacked-proposals-library-groundwork-only"></a>Stacked proposals | [Library only](../crates/safe-outputs/src/check/stack.rs); no workflow publication support. |
| <a id="library-boundary"></a>Library boundary | [`safe-outputs`](../crates/safe-outputs/src/lib.rs) handles validation and publication; callers own run admission, artifacts and credentials. [Export inventory](../crates/safe-outputs/export.paths). |
| <a id="what-is-gh-aws-and-why"></a>gh-aw compatibility | The collector runs on every forge. See [the pinned adapter](../.github/workflows/apply.yml) and [parity background](background-ghaw.md). |
| <a id="the-publication-corpus"></a><a id="upstream-javascript-disposition"></a>Upstream parity | [Corpus and pinned drivers](../crates/agentic-job/tests/corpus), [validation generator](../safe-outputs/validation.mjs), and [contributor checks](contributing.md#build-and-checks). |
