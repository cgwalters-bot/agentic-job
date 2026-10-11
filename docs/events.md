# Event-triggered runs

A caller's workflow can be started by anything GitHub delivers: an
issue, a comment, a pull request, a schedule, a dispatch. What makes
that safe and useful is one command, `agentic-job event`, which is the
only thing that reads the event's payload. It is gh-aw's
`pre_activation` and `activation` jobs in one place
([the validation against gh-aw](https://github.com/cgwalters-forge/agentic-job/blob/bot/initial-docs/docs/background-ghaw.md)): who may start a run, from
which events, and how the event's text reaches the agent.

**State.** The command, its wiring into the reusable workflow
(`event: true`, [described here](workflow.md#event-triggered-callers))
and three example callers are on main; CI runs the event path on every
pull request and every push (`e2e-event`), and the command's decision on
recorded and hand-written payloads. The workflow does not yet fetch a
pull request's head for general event runs (the task names it, and the agent
fetches it); the dedicated review mode checks out the admitted SHA.
Label-command decisions are implemented in the binary;
the reusable workflow removes admitted command labels before activation.
Discussion decisions still need workflow support for
discussion targets before they can be used with `event: true`.

The dedicated [pull request review caller](review.md) adds a base-branch task,
an analysis-only head checkout and a checked verdict comment. Real inference
is disabled by default.

## The decision

### Decision inputs

```text
agentic-job event --allow allow.toml --event-name "$GITHUB_EVENT_NAME" \
    --event "$GITHUB_EVENT_PATH" --actor "$GITHUB_ACTOR" \
    --repository "$GITHUB_REPOSITORY" --actor-permission permission.json \
    [--pull-request pull.json] --task task.md --out DIR
```

It reads the `[trigger]` table of the caller's bounds file and decides,
fail closed: a bounds file without the table starts nothing. Exit 0 and
`DIR/task.md` when the run may start; exit 1 and no task when it may
not; exit 2 when the bounds or the payload cannot be read. Either way
`DIR/event.json` (`agentic-job-event/v1`) says what was decided and why,
so the workflow can end quietly.

```toml
[trigger]
# Which events may start a run: issues, issue_comment, pull_request,
# pull_request_target, pull_request_review_comment, schedule,
# workflow_dispatch, discussion (label commands only).
events = ["issue_comment", "pull_request", "schedule"]
# The roles an actor may hold, exactly: "maintain" is not "write", and
# "admin" is not either. gh-aw's default.
roles = ["admin", "maintain", "write"]
# Bot logins admitted without a role. Never github-actions[bot].
bots = []
# Whether a pull request whose head is in another repository may start a run.
forks = false
# A comment must start with one of these.
commands = ["/agent"]
# Optional label commands for item events. Match the added label exactly.
labels = ["agent-review"]
```

The checks, in order:

1. The event is one the bounds list.
2. The actor (`github.actor`) is the payload's `sender`, and the
   payload's repository is the one the workflow runs in.
3. A schedule has no actor and passes. Otherwise the actor is a bot
   (`[bot]`, or `sender.type` is `Bot`) and must be in `bots`, or a
   person whose role on the repository is in `roles`. The role comes
   from the response of
   `GET /repos/OWNER/NAME/collaborators/LOGIN/permission` (`role_name`,
   or `permission` where there is none), which the workflow fetches with
   its own token: the binary holds none. `github-actions[bot]` is
   refused whatever the bounds say, since a run it starts is a loop.
4. The action is one that starts a run: `opened`, `reopened` and
   `labeled` for issues; `opened`, `reopened`, `synchronize`,
   `ready_for_review` and `labeled` for pull requests; `created` for
   comments. An edit is not one: the editor may not be the author, and
    the text that was read is gone. With nonempty `labels`, issues and
    pull requests must instead be `labeled` with a listed label in
    `event.label.name`: an existing label on the item does not count.
    With empty or absent `labels`, the previous item-event behavior is
    unchanged. `discussion` supports only listed label commands.
5. A comment's actor is its author.
6. A comment's body starts with one of `commands`, at the very first
   character, as gh-aw matches it. Everything after the command is the
   request.
7. A pull request's head is in the repository, or `forks = true`. A
   fork's head is never reported as something to start from. The payload
   of a comment on a pull request does not say where the head is, so the
   workflow fetches the pull request (`GET /repos/OWNER/NAME/pulls/N`)
   and passes it in; it has to be the one the comment is on, and then
   the same rule applies to its head. Without it, such a comment is
   admitted only with `forks = true`.

What `event.json` carries for the workflow: the item (`issue`,
`pull_request` or `discussion`, its number, and its URL when it is under the
repository's; no text of the event is in this file), the default target
of an `add_comment`; the command; for a pull request its base branch
and, when the head is the repository's own, the head's ref and sha; a
`concurrency` key (`issue-N`, `pull-N`, `schedule`, `dispatch`); and
`react_to`, the comment or item the workflow puts an eyes reaction on so
the human sees the run started. The `reason` is one line.
For label commands, `command` is the exact label name, without slash
normalization. Discussions use `discussion-N` for concurrency and have
no issue-reaction target.

### Label caller and activation step

A label caller should subscribe to `issues: types: [labeled]` and/or
`pull_request_target: types: [labeled]`, use trusted base-branch bounds
with `events = ["issues", "pull_request_target"]` and
`labels = ["agent-review"]`, and call the reusable workflow with
`event: true`. A job-level `if: github.event.label.name == 'agent-review'`
is an optimization, not the authorization check. Keep the existing
item-level concurrency rule and role/fork checks.

For example, a caller pinned to a workflow with label activation can use:

```yaml
name: Label review
on:
  issues:
    types: [labeled]
  pull_request_target:
    types: [labeled]
permissions: {}
jobs:
  run:
    if: github.event.label.name == 'agent-review'
    concurrency:
      group: label-review-${{ github.event.issue.number || github.event.pull_request.number }}
      cancel-in-progress: false
    uses: cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@COMMIT
    permissions:
      contents: read
      id-token: write
      issues: write
      pull-requests: write
      actions: read
    with:
      id: label-${{ github.event.issue.number || github.event.pull_request.number }}
      repo: ${{ github.repository }}
      event: true
      kind: analysis
      outputs: add_comment,noop
      allow: workflow/label-review.toml
      config: .github/agentic-job/hosted.toml
      task: Review the triggering item and report findings.
      agent: fake
      setup: .github/agentic-job/e2e/event.sh
      max-requests: '0'
```

Save the caller as `.github/workflows/label-review.yml`. Copy
[`workflow/label-review.toml`](../workflow/label-review.toml),
[`.github/agentic-job/hosted.toml`](../.github/agentic-job/hosted.toml) and
[`.github/agentic-job/e2e/event.sh`](../.github/agentic-job/e2e/event.sh)
to the same paths in your repository. Replace `COMMIT` with the reviewed
workflow commit, set `repos` and `bases` in the bounds to your repository
and base branches, and create the `agent-review` label. Commit these files
to your default branch before applying the label as an admitted actor.
The dedicated
[`workflow/label-review.toml`](../workflow/label-review.toml) bounds admit
only label commands; do not add `labels` to shared bounds used by CI for
opened or synchronize events. The scripted agent is for validating
the caller; a real agent also needs its inference settings.

Comment-only callers should use `kind: analysis` and explicitly request
`outputs: add_comment,noop`: analysis runs hand back no patch, and policy
refuses a request to create a pull request for that kind. The setup script
selects the scripted comment session; without it, `fake` uses its built-in
file-changing session, not the caller's task. Keep `contents: read`:
activation, notification and apply need the item write permissions, not
permission to push a branch. The other event callers' complete copy lists
are in [the workflow guide](workflow.md#event-triggered-callers).

The reusable workflow's trusted `activate` job removes the command label
**after admission and before starting the agent or notifying the item**.
It reads the policy job's decision, not interpolated event text, and runs
code from the reusable workflow's own pinned commit. Removal failure
fails activation and skips the agent. Reapplying the label starts another
admission and removal cycle. The
[`example-pull-request.yml`](../.github/workflows/example-pull-request.yml)
selects `workflow/label-review.toml` instead of the shared
`.github/agentic-job/allow.toml` to use this lifecycle; the caller above
covers issues too.

Activation uses the caller's write permission on its own machine, like
notification and apply. Policy, agent and check explicitly restrict their
tokens to read permissions (and the agent's identity permission).
Discussions are refused at the workflow boundary before routing outputs
or starting any write job: discussion notification, GraphQL label removal
and kind-aware output routing remain unimplemented. The parser can still
describe a discussion decision for another consumer; this is not support
for running discussions through the reusable workflow.

## The task file

The caller's own task text comes first, unchanged. Then a line saying
which event on which item by whom started the run; for a pull request,
that its head can be fetched as `refs/pull/N/head`, with the commit id
when the head is the repository's own (never a branch name: that is the
author's text); and a notice that what follows is text from GitHub, data
for the task and not instructions. Then each piece of the event's text,
named (the request, the item's title, its body, a review comment's place
in the diff), inside a fence of backticks longer than any run of
backticks in it, so that nothing in the text can close the fence early.
gh-aw substitutes its sanitized text unfenced where the prompt names
it; the fence is the difference.

Before it is fenced, each piece is stripped of ANSI escape sequences,
control characters other than tab and newline (so a carriage return
cannot overwrite a line in the job log), every Unicode format character
(category Cf: zero-width spaces and joiners, bidi controls, soft
hyphens, the byte-order mark, and the tag block that hides text inside
an emoji) and the line and paragraph separators; and capped at 64 KiB
and 2000 lines, with 160 KiB for all of it. With the caller's task,
64 KiB at most, the file stays under the 256 KiB `run` accepts; a test
holds the sum. Mentions, issue references and URLs are left as written:
the task file notifies nobody, and they matter only when the agent
copies text into an output, where gh-aw's collector handles them.
Unicode normalization and homoglyph mapping, which gh-aw also does, are
not done.

## What the workflow does with it

With `event: true`, the policy job, after the binary is in place and
before anything else: fetches the actor's permission and, for a comment
on a pull request, the pull request, with the job's token; runs `event`
on the payload GitHub wrote, with the `task` input as the caller's own
task; and on a refusal ends the run there, with the reason in the job
summary and in the `trigger-reason` output, the other jobs skipped and
the workflow green, since most refusals are comments that are not
commands. Admitted, the task file goes to the agent job with the policy,
the pull request's base is the run's base (the bounds have to cover it),
and `comment-target` defaults to the item. A `notify` job puts an eyes
reaction on what started the run and a status comment on the item, and
a `conclude` job edits that comment when the run ends, or adds a rocket
or confused reaction instead (`notify: reaction`), or nothing (`notify:
none`); like the apply job these write with what the caller granted the
call, and the agent's machine never holds a token that can comment.
The event's text never reaches a script: the binary reads the payload
from `GITHUB_EVENT_PATH`, and the task file is passed by path. The
caller keys its `concurrency.group` on the triggering issue or pull
request itself, on the job that calls the workflow, as the examples do:
a group is decided before any job runs, and a workflow-level one is
joined before the job's `if` is evaluated.

A refused trigger leaves no comment: the policy job holds no token that
could write one, by design, and a run that was never admitted has
nothing to say. The job summary and the `trigger` outputs say why.

## Optional run guards for custom policy jobs

The `[trigger]` table also accepts `stop-after` (an RFC 3339 timestamp),
`cooldown` (positive integer seconds), and `max-runs-per-user` (a positive
integer, in a rolling 24-hour window). At or after the deadline the event
is refused. Cooldown and user counts include only trusted records of
admitted agent starts; refused events and denied actors do not renew the
window. The current run ID is excluded. No roles or dispatches are exempt.

History-dependent guards require `event --run-history FILE`. The trusted
policy job must establish complete coverage of the calling workflow's trusted
admitted starts since an inclusive lower bound covering the larger of cooldown
and 24 hours, and supply the following history (timestamps are RFC 3339):

```json
{
  "coverage": "admitted_starts",
  "workflow_id": 123,
  "current_run_id": 456,
  "since": "2026-10-06T00:00:00Z",
  "total_count": 0,
  "workflow_runs": []
}
```

`coverage` is a required trusted attestation: `since` bounds admitted-start
timestamps, not workflow creation timestamps. Include runs created before
`since` that started within the window, including queue or approval delays.
For example, a run created 25 hours ago but admitted one minute ago counts
against both a 24-hour user quota and a cooldown longer than one minute.
Fetching every page of a last-24-hours **created-time** query cannot establish
this coverage, even if GitHub reports `total_count = 0`. The future fetcher must
obtain complete admitted-start coverage from trusted evidence or fail closed;
it must not label creation-only coverage as `admitted_starts`.

`workflow_runs` holds objects with `id`, `workflow_id`, `actor.login`, and
a required `admission` record: `{"status":"started","started_at":"2026-10-07T12:00:00Z"}`
or `{"status":"not_started"}`. An unannotated GitHub run list is rejected.
The fetcher must obtain these records from trusted policy/start evidence,
not from workflow conclusions or agent-written artifacts. Unknown or
unavailable evidence must fail closed, never become `not_started`.
The fetcher supplies the trusted workflow
and current-run IDs; the binary checks the coverage declaration, scope, unique
IDs, count and window bound, but cannot independently verify the fetcher's
completeness attestation. `total_count` counts the supplied history records,
not a creation-filtered API result. Missing history refuses admission; malformed or truncated
history is an input error. Fetch slightly beyond the window to allow for
time spent between fetching and evaluation. History is capped at 4 MiB.
The reusable workflow does **not yet fetch or pass this file**; enabling
these guards without that integration refuses runs rather than ignoring
the guard. This does not complete
[#118](https://github.com/cgwalters-forge/agentic-job/issues/118).
Workflow history fetching, pagination, current workflow/run ID binding,
trusted admission evidence and hosted admission/refusal E2E remain required.

These are snapshot guards, not atomic quotas: concurrent policy jobs can
observe the same history. Use caller concurrency as well. Rerun attempts
share a GitHub run ID and are not separately counted. Issue-search and
check-status guards (`skip-if-match`/`skip-if-no-match` and
`skip-if-check-failing`) and a daily AI-credit guard are not implemented;
the latter needs a trusted proxy usage API and a decision about dispatch
exemptions.
