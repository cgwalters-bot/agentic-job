# Pull request review

[`review.yml`](../.github/workflows/review.yml) has a real agent review pull
requests on `main`: when one is opened, synchronized, reopened or marked
ready for review (drafts wait), and again on a `/review` comment from someone
with admin, maintain or write permission. The bounds admit any role's pull
request, forks included ([`review.toml`](../workflow/review.toml),
`roles = ["all"]`), but the policy job's `if:` starts automatic reviews only
for authors whose `author_association` is `OWNER`, `MEMBER` or
`COLLABORATOR`. GitHub sets that field; the author cannot. Anyone else's pull
request, including one from someone with commits already merged here
(`CONTRIBUTOR`), is reviewed when someone with write access comments
`/review`, which keeps the role check
([`review-command.toml`](../workflow/review-command.toml)). Bots
are refused unless listed, so a bot's pull request gets no `review` status:
none is listed today, and this repository has no Dependabot or Renovate
configuration. A repository that adds one must list the bot in `bots` or not
require `review`, or its pull requests wait on an expected status forever. The
workflow, the bounds and the
[standing task](../workflow/review.md) come from the trusted caller, never the
head. On `pull_request_target`, policy and task files are read at
`github.workflow_sha`, the running caller workflow's revision, not the pull
request's possibly stale base SHA. The agent's separate trusted base checkout
is unchanged.

When policy refuses an event review, the existing single bot status comment
says `Review refused by policy: REASON` on one line. The reason is bounded to
1000 characters and Markdown-escaped. Only the pinned workflow source runs
with the comment-writing token; no head code or agent output is executed.
This does not enable notifications for admitted reviews, change admission,
or set a review commit status for a refused head.

The agent starts in the base checkout with the exact admitted head SHA fetched
beside it, inside the sandbox and with no credential: the head is data, and
nothing outside the sandbox checks it out or runs it. That is what makes forks
safe to admit. One review's inference is bounded in `review.yml` by
`max-requests: '150'`, `budget: '500'` (AIC, hundredths of a dollar) and
`timeout: '75'` minutes. Under the broker's `plain` registration the per-run
cap is only a convention ([inference.md](inference.md)); what then bounds
spending is the broker's aggregate cap, which every caller shares. Nothing
caps reviews per author or across pull requests: a push cancels the review it
supersedes, which has spent what it spent by then, but each pull request runs
its own. That is why automatic reviews are limited to those authors: if anyone
could start them, opening pull requests, or closing and reopening one, would
drain the shared cap and stall every implement, fix and review run until its
window resets. One of those authors can still do that; per-author limits are
[remaining work](plan.md).
A malicious head can still sway its own verdict, including an opt-in GitHub
approval. Model review is not a trust boundary.

The `review` status is not a security control. The author of a pull request
writes both the code reviewed and the title and body the agent reads, so they
can talk their own review into APPROVE. On a pull request from someone without
write access, `review` success must not, alone or together with `ci`, gate
auto-merge or a merge queue: a person with write access has to approve the
merge. The same restriction applies to an automated GitHub approval: admitting
a `/review` is not human merge approval. Requiring `review` stops a change from merging without a review; it
does not make an approved change trusted.

## The verdict

The reviewer reads the diff and surrounding code and reports findings. It does
not run existing test suites, formatters or linters to confirm they pass, and
does not look up or report CI results. It may build and run code to test whether
a specific concern holds, such as a function failing under a condition no test
covers, and reports what it ran and what it showed only for that concern.
The verdict has no `Verification:` paragraph. This applies
to both `review.yml`'s standing task and dispatch's `review` profile. CI is a
separate required check; the merge gate combines the checks, not the reviewer.
These are review instructions, not an execution restriction enforced by the
sandbox. Job permissions, token separation and output validation are unchanged.

The one output is a comment whose first line starts with `VERDICT: APPROVE` or
`VERDICT: CHANGES`, or a noop. `VERDICT: REJECT`, which briefs written for the
earlier format still ask for, counts as CHANGES; the earlier `REASON:` line is
no longer required. The check job refuses anything else, and any
field that would retarget the comment. The `status` job then sets the commit
status `review` on the reviewed head: `success` only for a checked APPROVE
whose comment was posted, `failure` for CHANGES, a noop or a run that did not
get that far. The status job
holds `statuses: write`, `pull-requests: write` and `contents: read` (to
check out `workflow/review.cjs` from the policy call's pinned source, never
the head), and reads no agent text: the verdict is one of two words check.yml
set, mapped by `reviewStatus`. With real reviews enabled it also reads the
applied comment as inert review-body data.

A status belongs to the commit, and the pull request's title and body reach
the agent, so anyone could open a second pull request at someone else's head
and talk its review into APPROVE. The status is set only when the triggering
pull request is the one open pull request at that head; otherwise the run
leaves a notice and the status as it was.

The flip side: anyone can hold back the status on someone else's pull
request, without write access, by opening a second pull request from a fork
at the same head. Neither run then sets a status, and a required `review`
stays expected until a maintainer closes the duplicate and asks for
`/review`.

Automatic events cancel a superseded review; only admitted runs enter the
per-PR group, so a comment cannot cancel one. A cancelled run sets no status,
and a head no run finished leaves a required `review` expected.

## Real reviews and the poll contract

Set repository variable `AGENT_REAL_REVIEWS=true` to opt in; unset is off.
The status job uses its own `GITHUB_TOKEN`, never `SAFE_OUTPUTS_PAT`, to submit
an `APPROVED` or `CHANGES_REQUESTED` review after check and apply succeed.
Enable **Settings → Actions → General → Workflow permissions → Allow GitHub
Actions to create and approve pull requests**. The reviewer is
`github-actions[bot]`, distinct from the bot account opening the PR. PRs opened
by that Actions identity cannot use this approval path. An approval's or change
request's body is the applied comment, unchanged, with `VERDICT:` still its first line. Inline findings remain
file/line citations in the body; no inline review comments are generated.

The review is bound to `commit_id`, and a head that already changed is skipped.
At most 300 files (three API pages) are inspected; incomplete or oversized lists
fail closed. Workflow changes in general are approved or not on the review's
judgement; their deterministic guard is the base branch's
[workflow-ingress check](workflow-ingress.md), so keep it a required check in
the ruleset. Approval is
withheld only when either side of a rename is part of the review's own gate:
`review.yml`, the `policy.yml`, `check.yml` and `apply.yml` it calls,
`workflow-ingress.yml`, `workflow/review.cjs`, `workflow/review.md`,
the admission files `workflow/activation.cjs`, `workflow/policy-command.cjs`,
`workflow/review.toml` and `workflow/review-command.toml`, the default agent
configuration `.github/agentic-job/hosted.toml`, the reporting helper
`workflow/status.cjs`, `workflow/ingress.py`, its analyzer configuration
`workflow/actionlint.yaml` or this document, which records the
ruleset. Otherwise a change weakening the gate would merge on that gate's own
approval. The status job then submits a `COMMENTED` review whose first line is
exactly `Approval withheld: this pull request changes the review's own gate and
needs a human approval.`, followed by the applied comment; agent text cannot
start a review body, so a poll can match that line to label the PR for a human.
CHANGES is submitted as usual.

Pollers read `GET /repos/{owner}/{repo}/pulls/{number}/reviews`, not issue
comment text or the `review` status. For `github-actions[bot]`, select the latest
non-pending, non-comment review by submission time (ID breaks ties). Only
`APPROVED` with `commit_id` equal to the current head is approval;
`CHANGES_REQUESTED` triggers the existing fix dispatch and its body supplies
findings. `DISMISSED`, absent or stale approval means wait, not approval.
Other reviewers' outstanding change requests remain GitHub's merge gate; the
poller must not override them. Noop, cancellation, refusal, a withheld gate
approval or submission failure produces no new approval. This repository does
not implement the external tracker's poll loop.

For `main`, enable the pull-request rule with **1 required approving review**,
and **Dismiss stale pull request approvals when new commits are pushed**.
Keep the merge queue and
required `ci` check, remove `review` from required status checks, and give the
automation identity no ruleset bypass. GitHub blocks an outstanding change
request; the review requirement gates queue entry. Repository settings cannot
be changed by this PR. Enabling repository auto-merge and requesting queue
entry at PR creation belong to the opening controller; this workflow never
merges or enables auto-merge itself.

### Compatibility status

`review` is a compatibility status, not the merge gate. It must not be added
to the ruleset while `main` has a merge
queue. The status is reported on the pull request's head commit only:
`review.yml` has no `merge_group` trigger, and merge-group runs are not
reviewed. A queue
[waits for every required check](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue)
on the merge group's own commit, and a ruleset's required status checks cannot
be limited to pull requests, so a required `review` would hold each queued pull
request until the queue's timeout removes it. How to report on a group is
not designed.

## Configuration

The workflow is set up like tracker's production caller: the agent job runs on
`vars.AGENT_RUNNER` (default `ubuntu-26.04`) and joins the inference proxy's
tailnet with `cgwalters-forge/actions/tailscale` before `secure-host`. It
needs these repository or organization variables, and no secret:

| Variable | |
| --- | --- |
| `AGENT` | `claude` or `opencode`; unset fails the run rather than fall back to the scripted agent |
| `AGENT_MODEL` | the model, as the proxy serves it |
| `INFERENCE_URL`, `INFERENCE_AUDIENCE` | the proxy, and the audience of the run's identity token |
| `AGENT_RUNNER` | optional, a runner label as JSON |
| `AGENT_CONFIG` | optional, the runner's configuration file; default `.github/agentic-job/hosted.toml`, written for `ubuntu-26.04` |
| `AGENT_CONFIG_REPO`, `AGENT_CONFIG_PATH` | optional, where opencode's configuration is; passed only when `AGENT` is `opencode`, as in `dispatch.yml` |

`SAFE_OUTPUTS_PAT` is optional and goes only to apply, to post as a user
rather than `github-actions[bot]`; real reviews always use the status job's
token. Here the agent job's identity token names
this repository's own `review.yml` as its `job_workflow_ref`, so the broker
needs the `any_workflow` entry narrowed to this repository, and the tailnet's
federated identity has to admit it too
([inference.md](inference.md#which-workflows-a-broker-admits)).

## Another repository

Another repository (agent-board next) calls this workflow at a pinned commit:

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

`COMMIT` is the full SHA of a reviewed commit of this repository. The caller
copies [`workflow/review.toml`](../workflow/review.toml),
[`workflow/review-command.toml`](../workflow/review-command.toml) (both with
its own `repos` and `bases`), [`workflow/review.md`](../workflow/review.md) and
[`.github/agentic-job/hosted.toml`](../.github/agentic-job/hosted.toml) to the
same paths, and sets the variables above. The broker entry for it is the
`called_workflows` form, naming `review.yml` at that commit.

## Tests

`node --test workflow/real-review.test.cjs` covers opt-in submission, both
review states, unchanged bodies and exact commits, stale heads, failed runs,
protected paths and renames, bounded pagination and invalid comment targets.
The tests use fake APIs; actual forge writes are left to real workflow runs.

`node --test workflow/review.test.cjs` covers admission, request bounds,
the verdict grammar, hostile outputs, the status for each combination of
check, verdict, apply and open pull requests at the head (`reviewStatus` and
`reportStatus` against a fake API) and, by reading `review.yml`, which job
holds which token, which authors start automatic reviews and what the status
job runs. It also checks that both review prompts require code analysis without
running checks or consulting CI, and that the review agent job has no project
toolchain installation or build-cache restore. `node --test
workflow/agent-actions.test.cjs` checks that the tailnet join is one pinned
step of the agent job, between `prepare` and `secure-host`. In the crate,
`tests/event.rs` runs the binary against both shipped bounds files as
`review.yml`'s `allow:` line picks them (`review_caller_bounds_gate_roles`):
anyone's pull request event, forks included, is admitted, `/review` needs
write, and neither file admits the other's events; `tests/policy.rs` checks
that both allow only the analysis outputs. CI's `e2e-review` runs the
policy, agent, check and apply path with the scripted agent and no inference,
through `agentic-job.yml`; `review.yml` itself, its tailnet join and its
status job's API calls run only on real pull requests. Real-model review quality is not
asserted.

The opt-in captured-request regression uses a real opencode runtime and a
loopback deterministic model endpoint, not credentials or real inference:

```sh
cargo build --locked
AGENTIC_JOB_TEST_REAL_OPENCODE=1 node --test workflow/review-runtime.test.cjs
```

Install the workflow's npm version on PATH first. The test checks a trusted
instruction positive control and data-file reads, and that hostile head
AGENTS.md, CLAUDE.md and project configuration are not loaded as instructions
at startup. Without the opt-in it is skipped. It makes no immutability claim.

The npm registry available during this change reports `opencode-ai` latest as
1.18.35, not a stable 2.x release. The workflow default uses that available
release; the launcher no longer refuses versions. The 2.x migration and its
configuration/ACP breaking-change review remain pending publication of an
installable stable 2.x package.
