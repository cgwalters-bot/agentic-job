# MCP

> This text is LLM generated.

## Current status

Model Context Protocol (MCP) lets an agent call tools provided by a server.
**agentic-job does not support managed MCP servers in runner mode.** Leave
`[mcp.NAME]` out of your configuration. Workflow admission rejects it before
setup, and standalone `run --runner-home` rejects it before starting the agent,
even without a credential.

The reusable workflow declares `MCP_TOKEN` for compatibility but does not
pass it to any job. Do not supply an MCP credential to an agent job: the agent
runs as the same OS user as `run` and can read credentials held by that user.

## Configuration

`agentic-job config` still accepts one legacy `[mcp.NAME]` table. Parsing
success does not mean the run can start.

| Field | Accepted by the parser |
| --- | --- |
| `url` | HTTPS URL, including on loopback, with no user information or fragment. |
| `secret` | The literal name `MCP_TOKEN`, not a credential value. |
| `allowed` | 1–64 distinct, exact tool names; no wildcard. |

This example parses but is **refused at launch**. No credential is needed to
reproduce the refusal.

```toml
[agent]
name = "fake"
[limits]
timeout-minutes = 5
max-requests = 0
uncapped = true
[mcp.example]
url = "https://mcp.example.com/mcp"
secret = "MCP_TOKEN"
allowed = ["search_issues", "get_issue"]
```

## Use a local tool

If your agent supports it, use the agent's own tools to start a local MCP
process that needs no credentials. The process runs with the agent's authority;
it is not a separate trust boundary or a managed integration.

Treat tool results as untrusted data: they may contain prompt injection. A
tool can pass its inputs to a remote service; don't send data that service
shouldn't receive. Use [safe outputs](safe-outputs.md) for forge writes so
they go through the check job. Direct tool calls do not go through that check.
