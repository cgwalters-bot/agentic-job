# Comparison with GitHub Agentic Workflows

> This text is LLM generated.

This page compares agentic-job with
[gh-aw v1.2.2](https://github.com/github/gh-aw/releases/tag/v1.2.2), as of
2026-11-14 (commit `399a445fe2d8926c616b54b1b82a16b5b2be4445`). It compares
sources and documentation. It is not a live security test or a cost
benchmark. Links in the table point at that release's sources, not at gh-aw's
documentation site, which changes. agentic-job's gh-aw compatibility pin
is older, v0.91.12-7 ([what is borrowed](#what-remains-borrowed)).

## Where each fits

Choose agentic-job when:

- the agent needs rootless containers, `/dev/kvm` or user namespaces on a
  [hardened disposable host](sandbox.md). Container builds that need the
  network need host networking and the egress proxy's CA bundle;
- you want one [ACP session protocol](harness.md) for several agents;
- you want outputs [checked on a separate machine](safe-outputs.md) before
  one apply job publishes them; apply never runs the agent's code.

Choose gh-aw when its
[workflow catalogue](https://github.github.com/gh-aw/gallery/), its
[Markdown authoring and compilation](https://github.github.com/gh-aw/setup/creating-workflows/)
or its wider set of outputs and triggers fit your project. Read agentic-job's
[known limitations](limitations.md) before you deploy it.

The agent in agentic-job has no provider key and no forge write token. It
does hold a run token for the [inference broker](inference.md) and,
normally, the job's read-only forge token
([token placement](workflow.md#which-tokens-reach-what)). Processes running
as the same user can read both. Do not call it credentialless.
[Credentialed MCP is refused](mcp.md#current-status).

Neither sandbox model is stronger in general. agentic-job runs the agent as
the runner's own user on a hardened host, so it shares the host kernel and
relies on [host hardening](secure-host.md). gh-aw's default Docker runtime
also shares the kernel. Its preview KVM microVM runtimes have their own
provisioning and compatibility limits
([runtime matrix][gh-runtime]). [Choose how to isolate the job](sandbox.md#choose-how-to-isolate-the-job)
lists the options here.

## Feature comparison

| Feature | gh-aw v1.2.2 | agentic-job |
| --- | --- | --- |
| Sandbox | Docker by default, with rootless AWF and network isolation, and the Docker socket hidden. Privileged Docker and preview microVMs are alternatives. [Sandbox][gh-sandbox], [runtimes][gh-runtime] | The agent runs as the runner's user on a hardened disposable host, with rootless Podman and KVM where the host provides them. [Sandbox](sandbox.md) |
| Inference credentials | Provider keys can stay in an API-proxy sidecar outside the agent container. Other authentication options exist. [Copilot][gh-copilot], [routing][gh-routing], [authentication][gh-auth] | An external broker holds the provider key, and the agent holds a run token. Putting a provider key on the runner is refused. [Inference](inference.md) |
| Network egress | Domain and ecosystem allowlists, with a small default set. Provider-hosted web tools have a separate policy. [Network][gh-network] | An egress proxy allows reads by default, except to threat-feed destinations, and has rules for writes. An agent run with the proxy on must use the write policy. A domain allowlist is opt-in. [Network access](sandbox.md#network-access) |
| Safe outputs | The agent writes structured requests, and a collector validates and sanitizes them. If no other output is configured, `create-issue` is enabled. [Safe outputs][gh-outputs] | The agent writes JSONL. `check` runs on another machine and enforces the caller's bounds by type, target, size, path and secrets. Every output is off unless enabled. [Safe outputs](safe-outputs.md) |
| Threat detection | On by default once any safe output is configured. In the default warn mode, a threat or detector failure annotates reviewable outputs, turns branch pushes into reviewable ones and blocks only the rest. Blocking everything needs `continue-on-error: false`. [Threat detection][gh-detection], [modes][gh-detection-modes] | Off unless the caller sets a detection model. When enabled, any threat or detector error blocks apply. [Threat detection](workflow.md#optional-threat-detection) |
| Apply | Permission-scoped output jobs, which recheck patch digests before publishing. [Output jobs][gh-outputs] | Apply uses only the artifact that `check` released. Base, path and head-lease guards still apply. [Who applies](safe-outputs.md#who-applies) |
| Agents and sessions | Native drivers for each engine. Durable sessions are experimental. [Engines][gh-engines] | One ACP client drives every supported agent. You can join a session interactively, but nothing you send authorizes a write. [Harness](harness.md), [interactive sessions](interactive.md) |
| Forges | GitHub. GitHub Enterprise Server compatibility is not an end-to-end support commitment. GitLab and Forgejo execution was not verified. [Enterprise][gh-enterprise] | The full workflow runs on GitHub. GitLab and Forgejo publish a subset of the outputs with native publishers. GitLab cannot run agent inference yet, and its guide is not verified live. [Forge matrix](safe-outputs.md#neutral-profile), [GitLab](gitlab.md) |
| Private repositories | Documented as supported with explicit authentication; runtime repository lists allow only public targets by default. Not verified live. [Private repositories][gh-private] | Refused: only public targets are supported. [Private repositories](private-repositories.md) |
| Authoring | Markdown with YAML frontmatter, compiled to a `.lock.yml` workflow. [Compilation][gh-compile], [imports][gh-imports] | Ordinary CI YAML that calls a pinned reusable workflow, with a task and TOML bounds. [Why no compiler](compiler.md), [workflow checker](workflows-check.md) |
| Catalogue | A gallery of example workflows. [Gallery][gh-gallery] | No catalogue, only example callers. [Dispatch](dispatch.md) |
| Cost | CI minutes plus inference, cost estimates and caps on turns. [Cost management][gh-cost] | CI minutes plus inference, the inference broker to operate, and extra jobs for check and apply. A budget watcher and offline audit report usage. [Audit](workflow.md#auditing-downloaded-artifacts) |

No one has compared cost, latency or maintenance on matched tasks.

## What remains borrowed

agentic-job uses gh-aw's safe-output format, JSONL vocabulary and
sanitization rules. Fixtures from the pinned upstream collector test its own
collector. Its validation data is generated from gh-aw. On GitHub, apply
still runs the pinned gh-aw handlers for outputs that the Rust handlers do
not cover. [What is gh-aw's, and why](safe-outputs.md#what-is-gh-aws-and-why)
and the [upstream JavaScript disposition](safe-outputs.md#upstream-javascript-disposition)
give the details.

## What could go upstream

These are proposals, not plans that gh-aw has announced:

- **A host-user runtime** for workloads that need rootless Podman or KVM,
  with the same egress and credential boundaries. Compare it with gh-aw's
  [runtime contracts][gh-runtime] first; the earlier fork is
  [not production work](compiler.md#the-options-that-were-not-chosen).
- **An ACP engine adapter**, as an alternative to a driver for each
  [engine][gh-engines].
- **Deterministic output checks and publishers that work on any forge**,
  starting from the [standalone checker](safe-outputs.md#standalone-cli).
  Reconcile them with gh-aw's [safe-output contract][gh-outputs] first.

## Coordinators across repositories

[gh-cao](https://github.com/githubnext/gh-cao) describes itself as central
agentic operations across repositories. It is a coordinator, not a sandbox
that runs the agent, and this comparison did not review it. agentic-job runs one task per job; callers
handle scheduling and admission across runs ([dispatch](dispatch.md)).

[gh-runtime]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/agent-runtimes.md
[gh-sandbox]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/sandbox.md
[gh-copilot]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/engines/copilot.md
[gh-routing]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/model-routing.md
[gh-auth]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/auth.mdx
[gh-network]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/network.md
[gh-outputs]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/safe-outputs.md
[gh-detection]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/threat-detection.md
[gh-detection-modes]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/threat-detection.md#L124
[gh-private]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/guides/using-at-scale.mdx
[gh-engines]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/engines.md
[gh-enterprise]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/enterprise-configuration.md
[gh-compile]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/compilation-process.md
[gh-imports]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/imports.md
[gh-gallery]: https://github.com/github/gh-aw/tree/v1.2.2/docs/src/content/docs/gallery
[gh-cost]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/cost-management.md
