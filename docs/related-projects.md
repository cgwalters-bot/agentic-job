# Related projects

> This text is LLM generated.

agentic-job runs one coding agent in one sandboxed job on a forge and turns
what the agent asks for into checked [safe outputs](safe-outputs.md). It
does not schedule work, keep a task board or coordinate several agents; a
caller does that. This page helps you decide whether another project fits
your need better, or works alongside agentic-job.

The gh-aw comparison was checked against gh-aw v1.2.2 in November 2026;
the other descriptions are observations from September and October 2026,
not an audit of each current release.

| Project | What it is | Relation to agentic-job |
| --- | --- | --- |
| [GitHub Agentic Workflows (gh-aw)](#github-agentic-workflows-gh-aw) | Agent workflows compiled to GitHub Actions | Closest alternative; source of the safe-output format |
| [Paperclip](#paperclip) | Server and web UI for a "company" of agents | A scheduler and board; local adapters run unsandboxed |
| [fullsend](#fullsend) | Agent framework for GitHub, GitLab and Forgejo | Overlaps; separate dispatch, sandbox and apply scripts |
| [agentic-ci](#agentic-ci) | Python CLI running agents in CI | Overlaps closely; drives agent CLIs directly |
| [Agent Client Protocol](#agent-client-protocol) | Protocol between clients and agents | Used as-is by the harness |
| [OpenShell](#openshell) | Kernel-enforced agent sandbox | Candidate sandbox and egress layer; untried |
| [Hive](#hive) | Issue classifier and agent dispatcher | A scheduler; overlaps with agentic-job's callers |
| [devaipod](#devaipod) | Earlier podman and devcontainer agent tool | Archived predecessor |
| [Scion, Ambient Code](#others) | Multi-agent platforms | Larger scope; orchestration |

## GitHub Agentic Workflows (gh-aw)

[gh-aw](https://github.com/github/gh-aw) compiles Markdown workflows into
[GitHub Actions workflows](https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/compilation-process.md)
and runs the agent in its
[AWF runtime](https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/agent-runtimes.md),
on Docker or preview VMs. It fits if you only use GitHub and want
workflows compiled to Actions.

agentic-job instead runs on a hardened host as an unprivileged user, with
rootless Podman and `/dev/kvm` where provisioned, drives the agent over
ACP, and publishes to GitHub, GitLab and Forgejo, though not with full
GitHub parity on the others ([forge support](safe-outputs.md#neutral-profile)).
The agent still gets a run token and normally a GitHub read token; credentialed MCP is
refused ([inference boundary](inference.md#current-boundary-5-november-2026),
[MCP status](mcp.md#current-status)).

agentic-job borrows gh-aw's safe-output format, collector semantics,
validation data and GitHub handlers, pinned at an older version than the
one compared.
[The comparison](background-ghaw.md) has the
[feature table](background-ghaw.md#feature-comparison),
[what remains borrowed](background-ghaw.md#what-remains-borrowed),
[what could go upstream](background-ghaw.md#what-could-go-upstream) and
[how cross-repository coordinators fit](background-ghaw.md#across-repositories-gh-cao-and-agent-board).

## Paperclip

[Paperclip](https://paperclip.ing/) is a Node.js server and web UI for
running a "company" of agents with an org chart, goals, budgets and an
issue board. Agents [wake](https://docs.paperclip.ing/start/core-concepts)
on a timer, an assignment or a mention, and run through adapters such as
Claude Code, Codex or a webhook.

Paperclip keeps its board in its own PostgreSQL database. A scheduler
built on agentic-job can use the forge's own issues and pull requests
instead, so state is backed up and permissioned with the code. For
execution, Paperclip's
[runtime guide](https://github.com/paperclipai/paperclip/blob/master/docs/agents-runtime.md#9-security-and-risk-notes)
notes that local CLI adapters run unsandboxed on the host, with remote
sandboxes as optional plugins; with
agentic-job the sandbox is not optional and a run's only effects are safe
outputs.

## fullsend

[fullsend](https://github.com/fullsend-ai/fullsend) is a framework for
autonomous agents on GitHub, GitLab and Forgejo, with its own dispatch,
sandbox, harness and privileged scripts that apply an agent's output.
A [proposal](https://github.com/fullsend-ai/fullsend/pull/6614) there
suggests adopting the safe-outputs model in place of privileged
post-scripts. agentic-job aims to be usable as an ordinary CI step, such
as a Forgejo Actions job or a Tekton step, not only a GitHub Actions
workflow.

## agentic-ci

[agentic-ci](https://github.com/opendatahub-io/agentic-ci) is a Python CLI
that runs Claude Code, OpenCode or Codex non-interactively in CI, with
`local`, `podman` and `openshell` backends, OpenTelemetry token and cost
summaries, and gates before and after a run for sensitive files, commit
authorship and leaked secrets. It drives each agent's CLI directly where
agentic-job uses ACP; its gates overlap with the safe-output check.

## Agent Client Protocol

The [Agent Client Protocol](https://agentclientprotocol.com) and its
adapters are what the [harness](harness.md) is built on. They are used
unmodified, and problems are reported upstream.

## OpenShell

[OpenShell](https://github.com/NVIDIA/OpenShell) enforces filesystem,
system call and network policy for agents in the kernel and injects
credentials only for approved endpoints. It could provide the sandbox and
egress policy if it allows nested rootless Podman and `/dev/kvm`; that has
not been tried.

## Hive

[Hive](https://github.com/hivecommons/hive) is a Go program that
enumerates GitHub issues and pull requests, filters and classifies them
deterministically before any model sees them, and dispatches agents in
tmux sessions behind a token-scoping proxy. It is a scheduler, so it
overlaps with what calls agentic-job, not with agentic-job itself.
[Hive's pipeline](hive.md) compares its stages, pacing and token tiers
with a coordinator design.

## devaipod

[devaipod](https://github.com/cgwalters/devaipod), an earlier tool by the
same author, combined OpenCode, Podman, devcontainer specifications and a
fine-grained forge MCP server. It was archived in July 2026 in favor of
separate unprivileged users and OpenShell. Its
[related projects page](https://github.com/cgwalters/devaipod/blob/main/docs/src/related-projects.md)
covers OpenHands, SWE-agent, Goose and others.

## Others

[Scion](https://github.com/GoogleCloudPlatform/scion) is a multi-agent
orchestration platform with agent-agnostic containers, per-agent
credentials and messaging between agents.
[Ambient Code](https://github.com/ambient-code/platform) hosts teams of
agents on Kubernetes. Both work at a larger scope than agentic-job, which
runs one agent per job and leaves orchestration to its caller.
