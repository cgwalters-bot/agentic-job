# Pull request review

> This text is LLM generated.

The [`review.yml`](../.github/workflows/review.yml) reusable workflow has an
agent review each pull request and post one verdict, APPROVE or CHANGES. The
agent reads the head as data inside the [sandbox](sandbox.md), and nothing
outside it checks out or runs the head, so pull requests from forks are safe
to review.

| Forge | Pull request review |
| --- | --- |
| GitHub | `review.yml`, described here |
| GitLab | Not available yet |
| Forgejo | Not available yet |

## When a review runs

| Trigger | Who | Notes |
| --- | --- | --- |
| Pull request opened, synchronized, reopened or marked ready | Authors whose `author_association` is `OWNER`, `MEMBER` or `COLLABORATOR` | Drafts wait. The forge sets the association, not the author. |
| A bot's pull request | Bots whose numeric user id is in `REVIEW_BOT_IDS` and whose login is in the bounds' `bots` | Off by default. For Dependabot on github.com, `[49699333]`. |
| `/review` comment | Anyone with admin, maintain or write permission | Reviews anyone's pull request. |
| `workflow_dispatch` | Holders of `actions: write` | See [dispatched reviews](#dispatched-reviews). |

Nothing caps reviews per author, so automatic reviews are limited to trusted
authors: otherwise anyone could drain the broker's cap shared with every
other run. One review asks for at most 150 requests, 5 US dollars and 75
minutes, but under a `plain` broker registration only the shared cap holds
([inference](inference.md)). A push cancels the review it supersedes. A
bot's pull request text, such as release notes, can steer the verdict, so
weigh that before listing a bot. When policy refuses an event, the bot's
status comment says `Review refused by policy: REASON`.

## What you can rely on

- The workflow, its bounds ([`review.toml`](../workflow/review.toml),
  [`review-command.toml`](../workflow/review-command.toml)) and the
  [standing task](../workflow/review.md) come from the trusted caller, never
  the head.
- The head is fetched without credentials. The agent still holds a broker run
  token and a read-only forge token
  ([tokens](workflow.md#which-tokens-reach-what)).
- Check refuses any output but one verdict comment or a noop, and the
  optional inline findings and escalation label below, all for the reviewed
  pull request.

Model review is not a trust boundary: the author controls what the agent
reads and can sway its verdict. Required human or code-owner approvals belong
in the forge's branch rules, and neither `/review` nor an agent approval
replaces them.

## The verdict

The reviewer first tries the change as a user would, building the head and
running new or changed commands from the docs and `--help`, and reports that
under "Tried". It then reads the diff and surrounding code. It does not rerun
test suites, linters or CI; those are separate required checks.

The first line is `VERDICT: APPROVE` or `VERDICT: CHANGES`. Findings are
tagged blocker, important or nit, and only a blocker earns CHANGES: a
concrete failure of the change's main purpose, or a material defect it
introduces. An approval lists the rest under "Follow-ups". The reviewer also
asks whether the change should exist as written, or extend an existing
mechanism instead. Beside the verdict, it may anchor up to ten findings to
lines ([review comments](safe-outputs.md#review-comments-on-the-pull-request)).

The commit status `review` on the head is `success` for a checked APPROVE
that posted, carried ones included, `failure` for CHANGES, a noop or a
review that failed to post, and `pending` for a
[record-only event](#record-only-pushes). No status is set
when the run was cancelled, or when another open pull request shares the
head, until a maintainer closes the duplicate and comments `/review`. `review` is
a compatibility status, not the merge gate. Remove it from required checks
before enabling a merge queue: merge groups aren't reviewed, so queued pull
requests would wait until they time out.

### Bounded security escalation

The reviewer can ask for a human, by adding one label, only for a concrete
security risk it cannot bound. To stop an agent from labelling other pull
requests or driving label-triggered automation, the bounds allow exactly
one label:

```toml
[github.outputs.add_labels]
max = 1
allowed = ["security-triage"]
```

The stock `review.yml` always asks for `add_labels`, so its bounds must keep
this entry: removing it refuses every review. The shipped
[`review.toml`](../workflow/review.toml) and
[`review-command.toml`](../workflow/review-command.toml) allow `needs-human`;
name your own label in both and create it before the first review. A custom
caller of `policy.yml` leaves escalation off unless it adds `add_labels` to
its bounds and asks for exactly `add_comment,noop,add_labels` with
`max-outputs: '2'`, or
`add_comment,noop,create_pull_request_review_comment,add_labels` with
`'12'`. Any other label request refuses the whole review. The label
signals; it doesn't block merging.

## Merge policy

The owner states whether the review job's approval is enough to merge in
`.github/agentic-job/merge.toml` on the default branch:

```toml
# an approving review by the review job merges by default
merge = "agent"
```

or `merge = "person"`, the default. The file holds only that line and
comments, at most 4 KiB, or policy fails. The reviewer is told the policy; branch
rules still decide what an approval merges. To keep paths for a person, list
them in CODEOWNERS, naming a person rather than the automation account, and
turn on **Require review from Code Owners**:

```text
# Paths that need the repository owner's review whatever the merge policy
# (docs/review.md#merge-policy). Nothing parses this comment.
/.github/agentic-job/merge.toml @OWNER
/.github/CODEOWNERS @OWNER
```

Check refuses an agent's patch to either file.

## Optional features

Each is a repository variable, off by default.

| Variable | Effect |
| --- | --- |
| `AGENT_REAL_REVIEWS=true` | [Post the verdict as a review](#real-reviews-and-the-poll-contract), not a comment. |
| `REVIEW_CARRY_APPROVAL=true` | [Carry an approval](#carried-approvals) across a rebase or rustfmt-only push. |
| `REVIEW_HISTORY=true` | [Give the reviewer earlier reviews](#review-history). |
| `REVIEW_RECORD_ONLY` | [Record, don't review](#record-only-pushes), pushes by the listed user ids. |

### Real reviews and the poll contract

The `submit` job posts an `APPROVED` or `CHANGES_REQUESTED` review bound to
the head, with inline findings as its comments; when nothing can be
submitted, the verdict is a comment as before
([`submit.rs`](../crates/agentic-job/src/review/submit.rs)). An APPROVE is
submitted whatever files the pull request changes, workflows and review
instructions included; only branch rules, code owners and required checks
stand between it and a merge. Enable
**Settings → Actions → General → Allow GitHub Actions to create and approve
pull requests**. The reviewer is `github-actions[bot]`, so its own pull
requests can't use this path.

Pollers should read reviews, not comments or the status: the latest
non-pending, non-comment review by `github-actions[bot]` approves only if it
is `APPROVED` with `commit_id` equal to the current head. Move pollers before
turning this on.

With `merge = "agent"`, one required approval lets the bot's approval count
on paths that don't require a human code owner. With `merge = "person"`, the
setting informs the reviewer but does not enforce a human approval: the bot
can still satisfy a one-approval rule. To require a human for every change,
cover every path with human CODEOWNERS and require their review. In either
mode, dismiss stale approvals, keep `ci` and the
[workflow-ingress check](workflow-ingress.md) required, and give the
automation no bypass.

### Carried approvals

A push whose head is exactly the approved changes replayed onto the base, or
differs only by `rustfmt` output, keeps the approval without running the
agent ([`carry.rs`](../crates/agentic-job/src/review/carry.rs)). This trusts
that the change still holds on the moved base, and the previous head's
`review` status, which someone with write access could set; `ci` still runs. `/review`
always runs a full review.

### Review history

The reviewer gets earlier verdicts and comments from people with write
access, as untrusted data, and first says whether each earlier finding is
resolved ([`history.rs`](../crates/agentic-job/src/review/history.rs)).
Scoping a re-review to the latest changes also needs `AGENT_REAL_REVIEWS`.
To dispute a finding, cite its ID in a "Disputed" section near the top of
the description before the next review; the reviewer changes a finding only
if the code confirms the evidence.

## Shared code review task

A trusted caller of `policy.yml` or `agentic-job.yml` can set
`review-shared-task: OWNER/REPO@COMMIT` to use a public repository's
`workflow/review.md` at a full commit SHA. Set it in the calling workflow,
never from event data, on `pull_request_target`, `issue_comment` or a
dispatch from the default branch. `review-task` may name a committed file of
local additions. A missing or blank file fails policy, and a task over
262,144 bytes is refused rather than cut.

## Dispatched reviews

A scheduler can start reviews itself, to pace them with its other runs, by
dispatching `review.yml` on the default branch with `pr`, `head` (the full
SHA) and `pool`. `REVIEW_POOLS` maps each pool to an `agent`, a `model` and
an optional `config`, for example
`{"pool-a": {"agent": "opencode", "model": "MODEL"}}`; an unmapped pool
fails the run. The pull request must be open, not a draft, and still at
`head`. The run is named `review OWNER/REPO#PR HEAD (POOL)`.

### Record-only pushes

With `REVIEW_RECORD_ONLY`, a JSON array of user ids, an admitted event on a
fork pull request by one of those authors (opened, synchronized, reopened or
marked ready) sets `review` to `pending` for the scheduler to dispatch. On
`synchronize`, the wrapper tries to carry an approval first. Recording skips
heads with an existing status, so an already reviewed head normally leaves no
fresh `pending` marker. GitHub cannot make the read and write atomic: a
status posted between those steps can still be overwritten. `/review` and pull
requests from the repository's own branches still review as usual. Enable it
together with the scheduler, or heads get two reviews or none.

## Draft classifier reviews

A scheduler can sort drafts by a checked classification: an approval holding
one `agent-board-draft-review` fence of schema `agent-board/draft-review/v1`.
To stop agent prose or an ordinary review being passed off as one, this is
off unless the trusted caller sets the `policy.yml` input
`review-draft-classifier: true` on an exact-head dispatch with
`outputs: add_comment,noop`, `max-outputs: '1'`, `notify: none`,
`apply-partial: false`, and `review-item` and `comment-target` both the pull
request number, as well as the settings of any exact-head review
(`review: true`, `event: false`, `kind: analysis`, a real agent and model).
Set `review-task` to a nonempty task file path relative to the trusted base
checkout. A shared review task does not replace this input.
Policy refuses a dispatch without the required settings
([`mod.rs`](../crates/agentic-job/src/review/mod.rs),
[`classifier.rs`](../crates/agentic-job/src/review/classifier.rs)), so
`review.yml` itself can't run one; it needs its own caller of `policy.yml`.

### Checked handoff to a wrapper

Pin `policy.yml`, `check.yml` and the binary together, and pass
`policy: ${{ toJSON(needs.policy.outputs) }}` to check. Submit only after the
agent exits 0, check succeeds with a nonempty artifact ID, and the verdict is
a checked APPROVE or CHANGES; take `agent_output.json` from that artifact in
the same run, never a carried approval, and run
`agentic-job review submit --accepted agent_output.json --output "$GITHUB_OUTPUT"`
with the environment of `review.yml`'s
[`submit` job](../.github/workflows/review.yml): `REAL_REVIEWS: 'true'`,
`CHECK_RESULT`, `AGENT_EXIT` and `VERDICT` from those jobs, or it posts
nothing. Take `PULL`, `HEAD_SHA` and `BASE` from policy's `comment-target`,
`review-head` and `base`, and `REVIEW_DRAFT_CLASSIFIER` from policy's
`review-draft-classifier` output, never from dispatch input. Name that job
`agent-board-review-result-v1`, only in this mode. The consumer should check
the live pull request again before using the result.

## Configuration

| Variable | |
| --- | --- |
| `AGENT` | `claude`, `opencode` or `vibe`; required |
| `AGENT_MODEL` | the model, as the inference proxy serves it |
| `INFERENCE_URL`, `INFERENCE_AUDIENCE` | the proxy, and its identity token audience |
| `INFERENCE_REGISTER`, `INFERENCE_PROVIDER` | optional; `api-key` is refused |
| `AGENT_RUNNER` | optional runner label as JSON; default `ubuntu-26.04` |
| `AGENT_CONFIG` | optional; default [`hosted.toml`](../.github/agentic-job/hosted.toml) at the called commit |
| `AGENT_CONFIG_REPO`, `AGENT_CONFIG_PATH` | optional, opencode's or Vibe's configuration |
| `REVIEW_BOT_IDS` | optional, [bots reviewed automatically](#when-a-review-runs) |
| `REVIEW_POOLS` | for [dispatched reviews](#dispatched-reviews) |

[Optional features](#optional-features) add their own variables. The secret
`SAFE_OUTPUTS_PAT` optionally lets apply post as a user. The broker must
[admit `review.yml`](inference.md#which-workflows-a-broker-admits).

If the runner can't reach the proxy, add a
[composite action](https://docs.github.com/en/actions/sharing-automations/creating-actions/creating-a-composite-action)
at `.github/agentic-job/network/action.yml`, such as a VPN join. It runs from
the trusted base, with no repository secret, before registration and before
the sandbox is set up. A `secret` it outputs goes to the agent job's join;
make it single-use, as anything still valid afterwards is the agent's.

## Another repository

Call the workflow at a full commit SHA you have reviewed:

```yaml
name: review
on:
  pull_request_target:
    types: [opened, synchronize, reopened, ready_for_review]
  issue_comment:
    types: [created]
permissions: {}
jobs:
  review:
    if: >-
      github.event_name == 'pull_request_target' ||
      (github.event.issue.pull_request && startsWith(github.event.comment.body, '/review'))
    uses: cgwalters-forge/agentic-job/.github/workflows/review.yml@COMMIT
    permissions:
      contents: read
      issues: read
      pull-requests: write
      actions: read
      id-token: write
      statuses: write
    secrets:
      SAFE_OUTPUTS_PAT: ${{ secrets.SAFE_OUTPUTS_PAT }}
```

Copy [`workflow/review.toml`](../workflow/review.toml),
[`workflow/review-command.toml`](../workflow/review-command.toml) and
[`workflow/review.md`](../workflow/review.md) to the same paths. In **both**
bounds files, name your repository and your
[escalation label](#bounded-security-escalation), and create that label:

```toml
repos = ["OWNER/REPO"]
bases = ["main"]
# ...

[github.outputs]
# ...
add_labels = { max = 1, allowed = ["LABEL"] }
```

With a file that doesn't name your repository, every review it governs,
automatic or `/review`, fails in the policy job, with nothing posted on the
pull request. If the reviewer asks for a missing label, apply fails. In
comment mode that means `review` is `failure`. With
`AGENT_REAL_REVIEWS=true`, a real approval can post before apply runs; it
still counts as `success` even if apply fails. Don't rely on label failure
to hold a merge.
The stock wrapper reviews pull requests on `main` only: changing
`bases` does not let it review another branch. Set the
[variables](#configuration), and register `review.yml` at that commit with
the broker in its `called_workflows` form.

For [dispatched reviews](#dispatched-reviews), also add `workflow_dispatch`
with string inputs `pr`, `head` and `pool`, let it through the `if:`, pass
the inputs in `with:`, and name the runs:

```yaml
run-name: ${{ github.event_name == 'workflow_dispatch' && format('review {0}#{1} {2} ({3})', github.repository, inputs.pr, inputs.head, inputs.pool) || '' }}
```

Don't call `review.yml` from a dispatch meant for anything else: without a
known `pool`, it fails.
