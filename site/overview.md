# How it works

> This text is LLM generated.

agentic-job runs untrusted steps in CI without giving them the credentials
that publish changes. It applies the same separation to deterministic scripts
and coding agents. Start with the [Quickstart](../docs/quickstart.md) to see
what you can run on your forge.

## Core model

1. **Policy** decides where the run may act and which outputs it may request.
2. **Produce** runs the script or agent without publishing credentials. It leaves
   a hand-back: requests for changes and, when needed, a patch.
3. **Check** validates the hand-back against policy on a separate trusted runner.
4. **Apply** publishes only admitted requests. It holds the publishing credential
   and does not execute agent-produced code.

This [safe-output model](../docs/safe-outputs.md) is inspired by
[GitHub Agentic Workflows](https://github.github.com/gh-aw/). See the
[comparison](../docs/background-ghaw.md) for the differences.

The supported harnesses are Claude Code, opencode and Vibe, using
[ACP (Agent Client Protocol)](https://agentclientprotocol.com/get-started/introduction).
See [agent harnesses](../docs/harness.md) for configuration.

## Host Security vs Agent Security

On supported GitHub Actions runners, [`secure-host`](../docs/secure-host.md)
prevents later steps from regaining `sudo`. Removing root access does not
hide credentials from code running as the same user. For broker-backed
agents, the provider key stays with the [inference broker](../docs/inference.md);
the agent receives only a token for its own run.

## Try it

Use the [Quickstart](../docs/quickstart.md) to check a local hand-back, then
try a scripted agent on GitHub, a fixed issue note on GitLab, or a check-only
trial on Forgejo. Only GitHub has a supported model-backed workflow here.

## Documentation

- **Guides:** [GitHub workflows](../docs/workflow.md), [dispatch](../docs/dispatch.md) and [inference](../docs/inference.md).
- **Reference:** [CLI](../docs/interface.md), [safe outputs](../docs/safe-outputs.md), [GitLab CI](../docs/gitlab.md) and [limitations](../docs/limitations.md).
- **Design notes:** [trust model](../docs/requirements.md) and [host security](../docs/secure-host.md).
- **Contributing:** [project guidelines](../docs/contributing.md) and [layout](../docs/layout.md).
