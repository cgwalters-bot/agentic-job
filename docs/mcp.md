# MCP and the runner-only boundary

> This text is LLM generated.

## Current status

`run --runner-home` refuses `[mcp.NAME]`. A remote server's credential in
`run`'s environment or memory is readable by the same-UID agent. The reusable
workflow declares `MCP_TOKEN` for compatibility but passes it to no job.
Do not send it to an agent job of your own or revive the second-user path.
The second user was removed in [#2991](https://github.com/cgwalters-forge/agentic-job/pull/2991);
the local-proxy code that remains is not support for runner-only credential
isolation.

An agent can start a credential-free local MCP process with its own tools.
That process has the agent's authority, not a new trusted boundary. MCP results
are untrusted text and may contain prompt injection.

## Configuration

This schema-valid example is a **launch refusal example**, not a way to enable
credentialed MCP. `runner-setup.py admit` refuses it before setup; standalone
`run --runner-home` refuses it too:

```toml
[agent]
name = "fake"
[limits]
timeout-minutes = 5
max-requests = 0
uncapped = true
[mcp.tracker]
url = "https://mcp.example.com/mcp"
secret = "MCP_TOKEN"
allowed = ["search_issues", "get_issue"]
```

Configuration parsing still accepts one server and 1–64 exact tool names.
It requires HTTPS (even on loopback), no URL user/password/fragment, and only
the secret name `MCP_TOKEN`. Parsing does not establish a usable launch path.
No real credential is needed to test the refusal.

## What `run` does

In runner mode it refuses local credentialed MCP, before starting the agent.
The retained legacy proxy implements a tools-only JSON-RPC allowlist:
`initialize`, initialized/cancelled notifications, `ping`, `tools/list`,
allowed `tools/call`, and answers to server pings. It refuses resources,
prompts, completions, sampling and batches, and bounds upstream responses to
8 MiB. Those tests describe a legacy implementation, not a same-UID secret
holder that can safely be enabled.

## Future external route

[Broker#61](https://github.com/cgwalters-bot/praxis-credential-broker/issues/61)
owns a bounded external MCP route, after
[broker#60](https://github.com/cgwalters-bot/praxis-credential-broker/issues/60)'s
approved credentialless identity/lifecycle contract. Neither source-address
research nor a Praxis example proves deployed peer preservation, method parity,
expiry or revocation. The agentic-job consumer is follow-up work; do not assume
that #2999 restores MCP. No new local proxy is planned here.

## What it does not give

An allowed tool can send everything in its arguments to the remote server.
A write-capable tool bypasses safe outputs, and detection does not inspect MCP
traffic. Future admission must retain trusted upstream selection, tool/method
and response bounds, negative controls and credential nondisclosure. See
[the acceptance inventory](plan.md#runner-only-hardening-inventory-2026-11-05).
