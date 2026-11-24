# Requirements and threat model

> This text is LLM generated.

agentic-job treats an agent's work as a proposal, not a trusted CI result.
In the reusable workflow, the agent job has no forge write credential. A clean
job checks what the agent hands back, and a separate job can publish checked
output. The agent shares the runner's user account: the job boundary, not the
agent process, separates it from publishing credentials.

Like [gh-aw](background-ghaw.md#feature-comparison), agentic-job separates
proposal from publication. It uses a hardened runner account and a reusable
workflow, not a workflow compiler or a separate agent runtime sandbox.

## Actors and trust

Assume prompt injection succeeds. Treat the agent, the text it reads, and the
patches, reports and logs it produces as untrusted. Trust the people who control
the caller workflow, its configuration and setup dependencies, and the systems
that enforce the boundaries: the CI service, runner and operating system,
toolchain, and inference service.

| What you control | What to do |
| --- | --- |
| Workflow, task and policy | Pin the reusable workflow to a reviewed commit. Load tasks, setup and [bounds](workflow.md) from a protected ref, not an untrusted change's merge commit. Treat event text and inputs as data, not as source for privileged scripts. On GitHub, use [event rules](events.md) to restrict actors and forks, and set a [deadline](events.md#deadline) for temporary automation. |
| Runner | Use a fresh supported runner for one agent job and discard it afterward. Run [host lockdown](secure-host.md) before any untrusted step. Treat packages installed during privileged setup as trusted code. |
| Credentials | Keep the agent job read-only and free of forge write tokens, provider keys, MCP credentials and permission to mint identity tokens. Grant trusted apply and status jobs only the permissions their enabled operations need. Restrict the apply environment to trusted refs. Status jobs use run metadata but do not apply agent proposals or execute agent-produced code. |
| Job order and review | The reusable workflow fixes the agent job's steps; it does not validate the rest of your CI. If you compose your own jobs, keep proposal, check and apply separate. Review proposed changes before merge. |

## What the agent job does not isolate

| Boundary | What you can rely on |
| --- | --- |
| Host privileges | With host lockdown, later steps lose root. This does not isolate processes running under the same user account. The agent can read that user's files and credentials and interfere with the process supervising it, including its logs and local limits. |
| Read and inference access | The GitHub workflow forwards a read token by default. Set `github-reads: false` to stop forwarding it, not to isolate same-user CI state. The [inference run token](inference.md), when used, is reachable by the agent. |
| Repository visibility | Runner execution requires a public target; the reusable agent workflow also requires a public caller. [Private-target policy](private-repositories.md) does not override these restrictions. |
| Network access | Host setup makes the [egress write policy](secure-host.md#the-egress-write-policy-for-an-agent-job) opt-in, but agent runs with the proxy enabled require it. It restricts writes, not all traffic, and on GitHub it permits runner writes to the Actions service. An allowed read request can still carry data out. |
| Cleanup | Stopping the agent does not guarantee that every process it started has stopped. Discard the runner after the job. Do not rely on it for availability or for protecting other workloads on the same machine. |

## R7. What leaves the sandbox is checked data

| Output | What the check establishes |
| --- | --- |
| Requests and patches | The clean check job treats them as data and validates format and [safe-output policy](safe-outputs.md). An accepted patch is not proof that its code is safe. |
| Logs, evidence and exit status | These describe the run but are not trusted verdicts. The check validates proposals, not all of the material the agent can produce. |

## R16. The agent's writes are capped, checked outputs applied elsewhere

Set bounds on output types, counts, destinations and patch size before the
agent starts. The separate apply job publishes only checked outputs and does
not execute code from the proposal. Analysis runs cannot request pull requests.
Pull requests default to drafts; use the [readiness setting](safe-outputs.md#ready-or-draft)
to open completed work ready for review.

Top-level dot-folders are protected by default. Of these, only `.github` can
be exempted. Whether bounds grant the exemption by exact repository name or
organization rule, GitHub may run changed workflows from a fork pull request
before review.
Require workflow-run approval for all external contributors, keep the
publishing account outside the target's members and collaborators, and keep
self-hosted runners unavailable to fork pull requests. Enforce a trusted
[workflow ingress check](workflow-ingress.md) through a ruleset, not just a
required status name a changed workflow could also report. An output check
does not replace those controls or review before merge.

## Choose a forge

| Forge | Where to start |
| --- | --- |
| GitHub | Use the [reusable workflow](workflow.md) for agent runs and separate check and apply jobs. |
| GitLab | The [deterministic pipeline](try-gitlab.md) shows policy, check and apply. Model-backed runs are not supported. |
| Forgejo | The [scripted trial](try-forgejo.md) checks proposals but does not publish or run a model. Standalone publication is separate; do not give the dispatch job a publishing credential. |
