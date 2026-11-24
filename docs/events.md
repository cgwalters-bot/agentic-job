# Event-triggered runs

> This text is LLM generated.

Your CI configuration decides when to start a workflow. Event admission is a
separate check: it decides whether that event may start an agent run and what
context the agent receives. A workflow starting does not mean the agent will run.

| Forge | How to start a run |
| --- | --- |
| GitHub | Subscribe to events in a caller workflow and opt into admission with `event: true`. |
| GitLab | Use the [manual web pipeline](try-gitlab.md). The event admission settings below do not apply. |
| Forgejo | Use the [manual Actions dispatch](try-forgejo.md). The event admission settings below do not apply. |

## Set up a GitHub caller

1. Start with a [caller example and its companion files](workflow.md#event-triggered-callers).
   Set `on:` to the events and activity types you want GitHub to deliver. Pin the
   reusable workflow to a reviewed commit and set `event: true` on the call.
2. Point `allow` at a trusted bounds file. Set `repos` and `bases` for your
   repository and configure `[github.trigger]` as shown below. `bases` allows branches;
   it does not select one. For events that don't supply a pull request base, set
   `with.base` to the branch to run from. For example, on `trunk`, set `base: trunk`
   under the call's `with:` and `bases = ["trunk"]` in the bounds file. Otherwise
   the `base` input defaults to `main`.

   Pinning the reusable workflow does not pin these caller files. To keep a pull
   request from supplying its own bounds or setup, use the base-branch
   `pull_request_target` pattern in the [label example](#label-caller-and-activation-step)
   and do not execute its head code in the caller.
3. Write `task` as the standing instruction. For item events, use a job-level
   concurrency group keyed to the issue or pull request to avoid overlapping
   runs on the same item.

For example, subscribe to `issue_comment` with `types: [created]` to accept
comments such as `/agent Summarize this issue`. The copied command bounds already
allow this event and command. To restrict admission to `/agent` on `issue_comment`,
edit these keys in the existing `[github.trigger]` table:

```toml
[github.trigger]
events = ["issue_comment"]
commands = ["/agent"]
```

For a comment-only smoke test, set `kind: analysis` and `outputs: add_comment,noop`.
The agent cannot hand back a patch or request a pull request in this mode.
Keep the example's permissions, including `issues: write` for issue comments
and `pull-requests: write` for pull request comments. Remove the `SAFE_OUTPUTS_PAT`
secret mapping and `apply-environment`; the job token can post in the same repository.

Commit the caller and its companion files to the default branch, then post the
command as a user with an allowed role. Expect a fixed test comment on the
triggering item: the example's `agent: fake` and setup script do not answer the
request, and changing `task` does not change the scripted reply.

## Decision inputs

Admission is opt-in: without `event: true` the workflow does not use this check;
with it, a missing `[github.trigger]` admits nothing. The bounds file limits
what the caller subscribed to; it does not subscribe to events on its own.

| `[github.trigger]` key | What it controls |
| --- | --- |
| `events` | Required list of event names. Only the supported activities below can start a run. |
| `roles` | Exact repository roles, default `["admin", "maintain", "write"]`. Listing only `write` does not admit an `admin`. Use `["all"]` by itself to admit people regardless of role. |
| `bots` | Bot logins allowed to trigger runs. Empty by default. `github-actions[bot]` is always refused to prevent workflow loops. |
| `forks` | Defaults to `false` to keep pull requests from other repositories from triggering runs. Set `true` to allow them, including via pull request comments. This does not make their code or text trusted. |
| `commands` | Required nonempty list for comment events, such as `["/agent"]`. Start the comment with the command, with no leading space. Separate the request from the command with a space, tab or newline. |
| `labels` | Optional exact names of newly added command labels. A nonempty list restricts issue and pull request events to matching `labeled` events; a label already on the item does not count. |
| `stop-after` | Optional deadline; see [Deadline](#deadline). |

| Event | Supported activities |
| --- | --- |
| `issues` | `opened`, `reopened`, `labeled` |
| `pull_request`, `pull_request_target` | `opened`, `reopened`, `synchronize`, `ready_for_review`, `labeled` |
| `issue_comment` | `created` on an issue or pull request, with a matching command |
| `pull_request_review_comment` | `created` on a pull request diff, with a matching command |
| `schedule` | Scheduled run; no sender role is required. |
| `workflow_dispatch` | Manual run; the sender is subject to the role or bot check. |

Discussion events are not supported. The workflow actor must be the event sender
(except on a schedule) and, for a comment, also its author. Edits do not start
runs: the editor may not be the author, and the original text is gone.

## Label caller and activation step

To run on a label instead of opening or updating an item, copy the
[pull request label example](../.github/workflows/example-pull-request.yml)
and its [companion files](workflow.md#event-triggered-callers), following the
pinning and bounds instructions there. Create `agent-review` in your repository.
Keep its [label bounds](../workflow/label-review.toml) separate from callers that
need ordinary issue or pull request events. The example uses `agent: fake` to
post a fixed test comment, not a real review.

The example subscribes to `pull_request_target` with `types: [labeled]`, so it
uses the base branch's workflow and settings rather than the pull request's.
To accept issue labels too, add `issues` with `types: [labeled]` under `on:`
and keep `"issues"` in `events`. Issue events supply no pull request base, so set
`with.base` to the intended branch and allow it in `bases`. Use the issue or pull
request number in the caller's `id` and concurrency group
(`github.event.issue.number || github.event.pull_request.number`).
Grant `issues: write` for issues and `pull-requests: write` for pull requests.
If you keep the job's label `if`, it skips unrelated labels early; the bounds
file still controls admission.

Apply the label as an allowed actor. Once admitted, the workflow removes the
label before starting the agent. If removal fails, the agent does not start.
Apply the label again to request another run.

## What happens after the event

- **Refused:** A normal refusal (for example, a comment with no command) skips
  the agent without failing the workflow or posting a comment. See the job
  summary or the `trigger-reason` workflow output. Invalid configuration is an
  error, not a skipped command.
- **Admitted:** The agent gets the caller's task first, then sanitized event
  text in fenced blocks marked as untrusted data, not instructions. Long event
  text may be truncated. A pull request event uses the pull request's base
  branch, which must be allowed by `bases`, and identifies its head. A general
  event run does not check out that head automatically. For analysis of an exact
  head commit, use the [dedicated review caller](review.md).
- **Comment target:** `add_comment` defaults to the triggering item's number.
  Leave `output-repo` unset to reply in the triggering repository; changing it
  can send the comment to a different item with the same number. For a run
  without an item (for example, a schedule), set `comment-target` if you want
  to post a comment.

| `notify` | Routine status notifications on the triggering item |
| --- | --- |
| `none` (default) | No status comment or reaction. |
| `reaction` | An eyes reaction at the start and a reaction indicating the result. |
| `comment` | An eyes reaction and a status comment, updated when the run ends. |

Notifications need write permission on the target item. A notification failure
does not block the agent. A run that ends with `missing_data` can post a status
comment even with `notify: none` or `reaction`.

See the [CLI reference](interface.md) for `agentic-job event` and the
[event module](../crates/agentic-job/src/event/mod.rs) for decision and task
format details.

## Deadline

Set `stop-after = "2027-01-01T00:00:00Z"` in `[github.trigger]` to stop
admitting events at or after that RFC 3339 timestamp. Event admission does not
enforce a cooldown or a per-user run quota.
