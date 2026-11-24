# Private repositories

> This text is LLM generated.

agentic-job supports public repositories only. On GitHub, the reusable
workflows refuse a private caller and any target, agent configuration,
context or item repository they cannot confirm to be public; the
`private = true` bounds key does not lift that refusal today. On GitLab
and Forgejo, the caller's own pipeline or workflow is the only
visibility check, so keep one.

gh-aw runs in private repositories, with explicit authentication for
cross-repository access
([using gh-aw at scale](https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/guides/using-at-scale.mdx#L42-L48)).
agentic-job does not, because a run publishes what the agent saw and the
agent shares its user with the job that runs it
([limitations](limitations.md)).

## What is checked

| Forge | Check | What happens |
| --- | --- | --- |
| GitHub | `policy.yml`, before the agent starts | The target, agent configuration, context and item repositories must be reported public. Internal, unknown visibility and API errors refuse the run. |
| GitHub | The agent job's admission step | Refuses a private or unknown caller, and a policy marked private. |
| GitHub | `run`'s action, before upload | Checks the target and agent configuration again. A rate-limited check waits and retries a bounded number of times, then refuses; any other failure refuses. |
| GitLab | The project's own pipeline | The [GitLab example](gitlab.md) checks the project's `visibility == "public"` before `policy`, which covers caller and target because they are the same project there. Keep that check if you adapt it. |
| Forgejo | The caller's workflow | Nothing checks visibility for you. Name only public repositories, as in the [Forgejo quickstart](quickstart.md#forgejo). |

`agentic-job run` also refuses a policy that `policy --private` marked
private, on any forge. The standalone CLI does not query a target's
visibility itself.

The check before upload cannot recall what was already sent to inference
or printed to a job log if a repository becomes private while the agent
works.

## Why runs are public only

Everything a run leaves is readable by whoever can read the caller's CI:
the job log with the condensed transcript, the summary, artifacts with the
fuller transcript, tool output and egress evidence, and the published
outputs ([what a run leaves](workflow.md#what-a-run-leaves)). On a public
caller that is anyone. Shorter retention does not retract a log, a
download or a published comment.

A private caller's access controls would not be enough on their own:

| Channel | Why it can disclose source |
| --- | --- |
| Run evidence | A hostile agent can copy source into reasoning, tool output, summaries or requested comments. [Redaction](workflow.md#github-reads-from-the-agent) removes known credential values; it does not recognize source. |
| Network reads | A GET's path or query can carry bytes to any host the egress policy allows, so write rules alone do not stop exfiltration. |
| CI service writes | The agent runs as the runner's user, which can write to the CI service, for example another repository's artifacts, with a token of its own ([secure host](secure-host.md)). |
| Runner logs | Some runner providers publish provisioning and diagnostic logs outside the forge. |
| Inference | The model service receives the context, under its own access and retention policy. |

## Opting in

The bounds key `private = true` is off by default. Setting it, in the
caller's bounds file and the organization's if there is one, changes what
`agentic-job policy --private` admits, but `run` still refuses the result:

| `policy --private` requires or refuses | Why |
| --- | --- |
| Every bounds file sets `private = true` | Neither the caller nor the organization alone can opt the other in. |
| The target is the calling repository | Its evidence stays with that repository's audience. |
| Outputs and the item are in the target | Comments do not land in another, possibly public, repository. |
| No `create_pull_request` or `push_to_pull_request_branch` on GitHub | Apply pushes through a fork it checks without a credential. GitLab and Forgejo admit `create_pull_request`, asked for by name, when every bounds file names the same `push_repo`; apply then pushes only to that fork, and only if it is private ([GitLab](safe-outputs.md#publishing-to-gitlab), [Forgejo](safe-outputs.md#publishing-to-forgejo)). |
| No `update_project` | A project's audience is not the repository's. |

Before its refusal, `run` also checks that a private policy has the
egress proxy, a domain allowlist that keeps no write rule but git
fetch's, and the job's read token, which is the only credential the
target's clone gets. These checks stay for a future private-run design
that puts a second user between the agent and the job; do not compose
your own job to work around the refusal.

## A reference caller

[`.github/agentic-job/private-digest/`](../.github/agentic-job/private-digest/workflow.yml)
composes the conditions above for one digest comment on one issue of a
private repository. It is kept as a test fixture, not as supported setup:
its agent step now fails on `run`'s refusal. Its files say what each
setting is for, including the placeholders to replace and the gates an
adopter confirms by hand, and `crates/agentic-job/tests/private_digest.rs`
holds it to the rules on this page.
