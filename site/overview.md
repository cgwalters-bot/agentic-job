# agentic-job

> This text is LLM generated.

This project takes as a core premise that [AI (LLMs) and CI should go together](https://blog.verbum.org/2026/08/21/agentic-ai-and-software-forges/);
operational concerns (security, scalability, observability) for your agents should align with your regular deterministic CI.

This project is heavily inspired by [GitHub Agentic Workflows](https://github.github.com/gh-aw/) but makes some different design choices.

## Core model

An agent invocation starts as a forge-native runner (e.g. GitHub action workflow), can perform arbitrary read-only
operations, and at the end can post output through a [safe outputs](https://github.github.com/gh-aw/reference/safe-outputs/) style
model.

The supported harnesses are Claude Code, opencode and Vibe, using
[ACP (Agent Client Protocol)](https://agentclientprotocol.com/get-started/introduction).
See [agent harnesses](../docs/harness.md) for configuration.

## Host Security vs Agent Security

Projects like [OpenShell](https://github.com/NVIDIA/OpenShell) and many others aim to constrain
agents specifically. This project again takes the stance that we should secure CI in general,
and agents are just one type of workload.

The [`secure-host` action](../docs/secure-host.md) locks down a fresh
supported GitHub Actions runner so that later steps cannot regain `sudo`.
It is built from this workspace and also published through
`cgwalters-forge/actions/secure-host`. Losing root does not protect
credentials from another process running as the same user; see the
[credential boundary](../docs/inference.md).

## Try it

Follow the [getting-started walkthrough](../docs/try-it.md) for a local
safe-output check and a first scripted agent run on GitHub, then connect a
real agent. GitLab currently supports the deterministic policy/check/apply
example, **not agent inference**; its [guide](../docs/gitlab.md) names the
remaining prerequisites and live-verification gaps.

## Documentation

- [Workflow and deployment evidence](../docs/workflow.md), [events](../docs/events.md), [dispatch](../docs/dispatch.md) and [GitLab CI](../docs/gitlab.md).
- [Safe outputs](../docs/safe-outputs.md), [host security](../docs/secure-host.md) and [known limitations](../docs/limitations.md).
- [Agent harnesses](../docs/harness.md), [inference](../docs/inference.md), [MCP](../docs/mcp.md) and [skills](../docs/skills.md).
- [Design and trust](../docs/requirements.md), [related projects](../docs/related-projects.md) and [interactive sessions](../docs/interactive.md).
- [Project layout and license](../docs/layout.md), [stable interfaces](../docs/stable-interfaces.md) and [remaining work](../docs/plan.md).
- [Contributing](../docs/contributing.md): design constraints, checks, code conventions and security boundaries.
