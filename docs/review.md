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
start no automatic review unless the repository variable `REVIEW_BOT_IDS`,
a JSON array, lists the bot author's numeric user id, which GitHub never
reassigns, and the bounds' `bots` list its login. `review.toml` lists only
`dependabot[bot]`; setting `REVIEW_BOT_IDS` to `[49699333]`, Dependabot's
id on github.com, has its pull requests reviewed without a `/review`.
Unset, the default, every bot's pull request waits for that comment. Set,
the agent reads such a pull request's text, upstream release notes
included, without anyone having asked: it is data to a sandboxed agent
without a credential, but it can steer the verdict. Dependabot has no
write access, so, as below, a person with write access still has to
approve the merge: the review saves the `/review`, not that approval. The
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
field that would retarget the comment. A redundant `item_number` equal to the
fixed pull request number is accepted; other routing fields remain refused.
The prompts ask for only `type` and `body`.

### Inline findings

Next to a verdict comment, never a noop, `review.yml`'s agent may return up
to ten `create_pull_request_review_comment` outputs, one per finding with a
line: the bounds list the type with `max = 10` and `max_outputs = 11`.
Check holds each to the triggering pull request with the rules every
review comment has ([safe outputs](safe-outputs.md#review-comments-on-the-pull-request));
`checkOutputs` also refuses a `repo`, any field a review comment cannot
carry, a path with control characters or over 1024 characters, a range
that ends before it starts, and a verdict comment whose body would exceed
60000 characters with every inline finding folded in. That bound keeps
whichever body is posted under GitHub's 65536-character limit.
With real reviews they are the review's comments, as above. Otherwise,
or when nothing is submitted, apply folds them into the comment's body,
under "Inline findings" after the verdict, each under its path and line,
and posts no review comment: gh-aw's handler would put them in a second
review, of event `COMMENT`, apart from the verdict. A path is shown with Markdown
characters escaped, as it is the agent's and gh-aw does not sanitize it.
Dispatch's `review` profile does not offer them.

Each finding is tagged blocker, important or nit, and only a blocker earns
CHANGES: a finding that makes the change wrong for its main purpose, loses
data, or opens a security hole with a concrete path the reviewer can state,
such as what a weakened permission, gate, bound, pin, token placement or
trigger now lets someone do. Both prompts ask for every finding in one pass
and, in an approving review, for important findings and nits under
"Follow-ups" with file and line, for later pull requests; a fix for a blocker
may take them along. Blocking on each new narrow finding cost a fix, CI and
review run per finding, ten rounds on one pull request. Check does not read
severities: refusing a mislabelled verdict would only lose its comment, and
the status would fail as it does for CHANGES.

When check refuses the output or apply fails to post it, the existing failure
status says
`The review did not post; see the workflow run` and links to that run.
The `status` job then sets the commit
status `review` on the reviewed head: `success` only for a checked APPROVE
that was posted, as the review or the comment, `failure` for CHANGES, a noop
or a run that did not get that far. The status job
holds `statuses: write`, `pull-requests: read` and `contents: read` (to
check out `workflow/review.cjs` from the policy call's pinned source, never
the head), and reads no agent text: the verdict is one of two words check.yml
set, mapped by `reviewStatus`.

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
The verdict is then posted once, as the review, instead of as a comment as
well (#583). The `submit` job, after check and before apply, uses its own
`GITHUB_TOKEN` (`pull-requests: write`), never `SAFE_OUTPUTS_PAT`, to submit
an `APPROVED` or `CHANGES_REQUESTED` review, and apply then posts no comment.
When nothing is submitted (a noop, a run stopped at a limit, a head that moved
or a failed submission, which also leaves the run red), apply posts the comment
as it does with the variable off, and that comment is what sets the status.
A refusal is not silent: `submit` logs the status and the response's
`message` and `errors` (never its headers or URL, which hold the credential)
as an error annotation. A 422, GitHub refusing the submission (a locked
conversation, for example), posts the verdict as that plain comment itself,
saying the review could not be submitted and why; the comment's URL counts
as posted for the status, and apply posts nothing beside it. Any other
failure still leaves the comment to apply. A re-run of all jobs posts its
own.
A re-run of failed jobs posts nothing twice: `submit` submits nothing where
this run already has an applied comment, and reuses an identical review at
the same head. A re-run of all jobs that reaches other findings submits a new
review, the latest; one after a run whose comment was posted posts comments.
Enable **Settings → Actions → General → Workflow permissions → Allow GitHub
Actions to create and approve pull requests**. The reviewer is
`github-actions[bot]`, distinct from the bot account opening the PR. PRs opened
by that Actions identity cannot use this approval path. An approval's or change
request's body is the request check accepted, read from check's upload in the
same run rather than back from the forge, sanitized once by gh-aw's collector
in check (apply's handler sanitizes a comment again), with `VERDICT:` still its first line.
After it come a visible footer in the form of gh-aw's comment footer,
`> Generated by [workflow](URL) for #N at HEAD`, linking the agent job (else
the run, where a runner gives no job ID) from Actions' context, never the
review text, and gh-aw's run marker (`<!-- gh-aw-agentic-workflow: ... run: URL -->`), as its
handler ends a comment. As with gh-aw's footer, a body that leaves `<details>`
or a code fence open can fold the footer away or show it as code. A comment
apply posts instead keeps gh-aw's own footer, which links the run.

Inline findings ([below](#inline-findings)) are the submitted review's
own comments, in the same `pulls.createReview` call, so they belong to the
approval or change request rather than standing beside it. Each needs its
path and line, and a range's first line in the same hunk, in the diff of
the head `submit` just read; one that is not, or whose file the API shows
no patch for, goes in the review's body after the verdict line instead. A
bad anchor so neither loses the finding nor fails the submission. The
split depends only on the head, so a re-run at the same head builds the
same body and reuses the review as above. The files are read only to place
comments, never to decide whether to approve.

The review is bound to `commit_id`, and a head that already changed is skipped.
An APPROVE is submitted whatever files the pull request changes, including
workflows, bounds and the review's own workflow, script and instructions.
Whether that approval is enough to merge is the repository's
[merge policy](#merge-policy) and GitHub's code-owner rule, not a gate-file
list here. The deterministic guards stay: keep `ci` and the base branch's
[workflow-ingress check](workflow-ingress.md) required in the ruleset.
CHANGES is submitted as usual.

Pollers read `GET /repos/{owner}/{repo}/pulls/{number}/reviews`, not issue
comment text or the `review` status. A submitted verdict has no comment
beside it, so a poller that still matches `VERDICT:` in comments finds none:
move such a poller (tracker's `reviewText`, for its fix task) to reviews
before setting the variable, or before a caller that has it set follows a
commit with this behaviour. For `github-actions[bot]`, select the latest
non-pending, non-comment review by submission time (ID breaks ties). Only
`APPROVED` with `commit_id` equal to the current head is approval;
`CHANGES_REQUESTED` triggers the existing fix dispatch and its body supplies
findings. `DISMISSED`, absent or stale approval means wait, not approval.
Other reviewers' outstanding change requests remain GitHub's merge gate; the
poller must not override them. Noop, cancellation, refusal or submission
failure produces no new approval. This repository does
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

### Merge policy

Whether the review job's approval merges a pull request by default is the
repository owner's decision, kept in the repository rather than in prose the
reviewer weighs: reviewers at older pins kept arguing whether a person should
be required, and refused changes the owner had accepted (#556). The policy
job reads `.github/agentic-job/merge.toml` from the same trusted checkout of
the default branch as the standing task, never the head, and `workflow/review.cjs` appends it to the task under
"Merge policy" as the owner's statement:

```toml
# an approving review by the review job merges by default
merge = "agent"
```

or `merge = "person"`, where a person approves every merge after the review.
The file holds that one line among comments and blank lines; anything else,
a symbolic link or more than 4 KiB fails the policy job. Without the file the
policy is `person`, and the reviewer is told it is the default, not the
owner's choice. The statement changes what the reviewer is told, not what
GitHub enforces: an APPROVE is submitted under either policy, and the
ruleset's required approvals decide what it merges. So the reviewer is told
to review as hard under `person` too.

Paths that still need the owner are listed in CODEOWNERS (`.github/`, the root
or `docs/`), and the owner turns on **Require review from Code Owners** in the
ruleset. The review job's approval is not a code owner's, so with that rule
those paths wait for the owner whatever the model says; without it, CODEOWNERS
only requests reviewers and holds nothing. The reviewer is asked to name the
changed paths that have a code owner after its verdict line ("Needs the
owner's review: …"), so the pull request says why it waits, and to list
there any change to the policy file or to a CODEOWNERS file, which changes
who decides even before CODEOWNERS covers it; that line is the
model's reading and informs, while GitHub's rule is what holds the merge. The
reviewer cannot see the ruleset, so it is told to review those paths as hard
as any other. Only the owner can add CODEOWNERS, since check refuses an
agent's patch to it. Start it with the policy file and CODEOWNERS itself, so
changing who decides takes the owner:

```text
# Paths that need the repository owner's review whatever the merge policy
# (docs/review.md#merge-policy). Nothing parses this comment.
/.github/agentic-job/merge.toml @OWNER
/.github/CODEOWNERS @OWNER
```

Check refuses an agent's patch to either file, `.github/` exemption or not
([safe outputs](safe-outputs.md)), so no implement or fix run can change the
policy or drop the owner's review. The code that states the policy
(`workflow/review.cjs`, `workflow/review.md`, `review.yml`) is reviewed like
any other change to the harness; an owner who wants it held for a person
lists it in CODEOWNERS too. Dispatched reviews
(`dispatch.yml`'s `review` profile) are not given a merge policy.

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

`review.yml` has no network or inference setup of its own; the deployment
supplies both, from what the repository owns, never from inputs a
dispatcher could set:

- **Network.** The agent job runs on `vars.AGENT_RUNNER` (default
  `ubuntu-26.04`). Where that runner cannot reach the inference proxy, the
  caller adds a [local composite action](https://docs.github.com/en/actions/sharing-automations/creating-actions/creating-a-composite-action)
  at `.github/agentic-job/network/action.yml` in its own repository: a VPN
  or tailnet join, for example. The register job runs it before it
  registers the run, and the agent job (`agent.yml`, called with
  `network: true`) runs it as root after `prepare` and before
  `secure-host`, so before anything of the agent's is on the machine;
  both skip it when the file is absent, the default. It comes from a
  checkout of the trusted base (the commit the policy job decided), never
  the pull request's head, so a pull request cannot change what runs
  there: changing it takes a merge to the base branch, like changing
  `review.yml`. It gets no repository secret. The register job's identity
  token is there for a federated join; the agent job has none, since the
  agent is the runner's user. So the step may leave the agent job a
  credential of its own minting as its `secret` output: `review.yml`
  passes it to `agent.yml` as the secret `NETWORK_SECRET`, which gives it
  to the step there alone, as its `secret` input. It has to be spent by
  that join, as a single-use key is: whatever is still valid after
  `secure-host` is the agent's. This repository's step mints such a key.
- **Inference.** The variables below name the proxy and the agent; nothing
  in `review.yml` defaults to a deployment's.

This repository's own review gate, the `pull_request_target` caller of the
same file, keeps working through that route: its network step is
[`.github/agentic-job/network`](../.github/agentic-job/network/action.yml),
which joins this deployment's tailnet, and its variables name this
deployment's proxy. Other repositories of this deployment call
`cgwalters-forge/actions`' `cgwalters-review.yml`, which composes the same
jobs at a release with that join. The inline join this replaces ran
here; the network step itself has not yet run on a real pull request.
It needs these repository or organization variables, and with a broker no secret:

| Variable | |
| --- | --- |
| `AGENT` | `claude` or `opencode`; unset fails the run rather than fall back to the scripted agent |
| `AGENT_MODEL` | the model, as the proxy serves it |
| `INFERENCE_URL`, `INFERENCE_AUDIENCE` | the proxy, and the audience of the run's identity token |
| `INFERENCE_REGISTER`, `INFERENCE_PROVIDER` | optional; `api-key`, a provider's API key in place of a broker ([inference](inference.md#a-provider-api-key)), is refused for now, as in `agentic-job.yml`: the agent is the runner's user, which would hold the key |
| `AGENT_RUNNER` | optional, a runner label as JSON |
| `AGENT_CONFIG` | optional, the caller's runner configuration file; default this repository's [`hosted.toml`](../.github/agentic-job/hosted.toml) at the called commit, written for `ubuntu-26.04` |
| `AGENT_CONFIG_REPO`, `AGENT_CONFIG_PATH` | optional, where opencode's or Vibe's configuration is; passed only when `AGENT` is `opencode` or `vibe`, as in `dispatch.yml`, so it must hold that agent's file |
| `REVIEW_BOT_IDS` | optional, a JSON array of the user ids of bots whose pull requests are reviewed automatically ([above](#pull-request-review)); its bounds must list their logins too |

`SAFE_OUTPUTS_PAT` is optional and goes only to apply, to post as a user
rather than `github-actions[bot]`; real reviews always use the submit job's
token. `INFERENCE_API_KEY` is still declared, so that a caller that
passes it is not refused, and goes to no job. The workflow, its steps
and the network step are the base branch's, and the head is data the
agent reads. The register job's identity token names `review.yml` as its
`job_workflow_ref`, so the broker, and a network step's federated identity,
have to admit it: here the `any_workflow` entry narrowed to this repository
([inference.md](inference.md#which-workflows-a-broker-admits)).

## Another repository

Another repository calls this workflow at a pinned commit:

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
its own `repos` and `bases`) and [`workflow/review.md`](../workflow/review.md)
to the same paths, sets the variables above and, if its runner needs one,
adds its own [network step](#configuration). Its own
`.github/agentic-job/merge.toml` and CODEOWNERS, if any, are its
[merge policy](#merge-policy); without them it is `person`. It needs no copy of
`hosted.toml`: without `AGENT_CONFIG` the policy job reads the one in
this repository at `COMMIT`, so a reviewed pin also pins the runner
hardening, and a caller on another image names its own file instead. A
caller that kept an edited copy sets `AGENT_CONFIG` to its path, or the
copy is no longer read. The broker entry for it is the
`called_workflows` form, naming `review.yml` at that commit.

## Tests

`node --test workflow/real-review.test.cjs` covers opt-in submission, both
review states, the checked body with its run marker at the exact commit, stale
heads, stopped or failed runs and noops, outputs that do not match the
verdict, re-runs and lost responses that must not post twice, and
inline comments placed in the review or moved to its body.
The tests use fake APIs; actual forge writes are left to real workflow runs.

`node --test workflow/review.test.cjs` covers the merge policy file and
the statement the task gets from it, admission, request bounds,
the verdict grammar, inline findings and their folding into the comment,
hostile outputs, the status for each combination of
check, verdict, apply and open pull requests at the head (`reviewStatus` and
`reportStatus` against a fake API) and, by reading `review.yml`, which job
holds which token, which authors start automatic reviews and what the status
job runs. It also checks that both review prompts require code analysis without
running checks or consulting CI, findings tagged blocker, important or nit and
CHANGES only for a blocker, and that the review agent job has no project
toolchain installation or build-cache restore. `node --test
workflow/agent-actions.test.cjs` checks that the caller's network step is
one optional step of the register job, from its base checkout, and of
`agent.yml`'s job when review.yml asks for it, between `prepare` and
`secure-host`, that no workflow joins a network itself, and
that this repository's network action pins what it uses. In the crate,
`tests/event.rs` runs the binary against both shipped bounds files as
`review.yml`'s `allow:` line picks them (`review_caller_bounds_gate_roles`):
anyone's pull request event, forks included, is admitted, `/review` needs
write, and neither file admits the other's events; `tests/policy.rs` checks
that both allow only the analysis outputs. CI's `e2e-review` runs the
policy, agent, check and apply path with the scripted agent and no inference,
through `agentic-job.yml`; `review.yml` itself, its network step and its
submit and status jobs' API calls run only on real pull requests. Real-model review quality is not
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
