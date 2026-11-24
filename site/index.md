---
description: Run untrusted CI steps, a coding agent included, without the credentials they could misuse.
---

# agentic-job

> This text is LLM generated.

agentic-job runs a coding agent in CI with no write token and no
model key in its reach, and has another machine check what it
produced before anything with a write token acts on it.

[Get started](../docs/quickstart.md), or read [how it works](overview.md).

## Agent security is just CI security

A coding agent working on an issue is the same kind of risk as a build
script from a pull request or a dependency's install hook: code you did
not write, steered by text you did not write, on a machine that holds
your tokens. agentic-job gives all three the same defence.

- **A sandboxed agent**

    The agent runs as an ordinary unprivileged user on a runner that has
    lost sudo and the container daemon, in a job that holds no secret but a
    run token, and no token that can write to the forge. [The sandbox](../docs/sandbox.md)

- **Checked safe outputs, applied elsewhere**

    The agent can only leave a file of requests. A second job checks them
    on a clean machine and a third applies them; no job with a write token
    runs anything the agent wrote. [Safe outputs](../docs/safe-outputs.md)

- **secure-host for any job**

    One step takes sudo and the container daemon away from every later
    step of a job, then probes that it did and fails the job if not. It
    needs no agent. [Securing the CI host](../docs/secure-host.md)

- **Bounded tokens**

    The agent's forge token is read only and expires with the job. The
    model key stays with a credential broker on another machine, which
    hands each run a token good for that run alone.
    [Which tokens reach what](../docs/workflow.md#which-tokens-reach-what)

## Try it in a workflow

Start with a fresh, trusted runner as described in the
[host guide](../docs/secure-host.md#example-harden-a-deterministic-job).
Replace `COMMIT` with a reviewed commit and `make check` with your test
command. Install any system packages before hardening the runner.

```yaml
on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-26.04
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - uses: cgwalters-forge/actions/secure-host@COMMIT
        with:
          egress: write-policy
      - run: make check
```

## Compared with GitHub Agentic Workflows

agentic-job is for work that needs a [hardened host-user sandbox](../docs/sandbox.md)
with rootless containers, `/dev/kvm` and user namespaces, and
[ACP sessions](../docs/harness.md) rather than an engine-specific integration.
[secure-host](../docs/secure-host.md) removes general root access before the
agent runs. [Check runs on a separate runner](../docs/safe-outputs.md), then
one apply job publishes the admitted outputs without executing agent code.

The agent holds no forge write token or provider key; it does hold a read-only
forge token and a run token. [Inference goes through a broker](../docs/inference.md)
on another machine. [Credentialed MCP is refused](../docs/mcp.md) until an
external proxy route is supported. Beyond GitHub, there is a
[GitLab policy/check/apply path](../docs/gitlab.md), not yet a supported live
agent pipeline, and [limited Forgejo publishing](../docs/safe-outputs.md#publishing-to-forgejo).

[gh-aw](https://github.github.com/gh-aw/) is the better fit when you want its
[workflow catalogue](https://github.github.com/gh-aw/gallery/),
[GitHub-native Markdown authoring and compiler](https://github.github.com/gh-aw/setup/creating-workflows/),
or its [community](https://github.com/orgs/community/discussions/186451).
agentic-job callers instead write [ordinary workflow YAML](../docs/workflow.md).
[The comparison](../docs/background-ghaw.md) lists the differences item by item.

## Read more

- [Running it on GitHub](../docs/workflow.md): the reusable workflow, its jobs and tokens.
- [Inference through a proxy](../docs/inference.md): reaching a model without holding its key.
