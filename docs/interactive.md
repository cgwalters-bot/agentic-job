# Interactive sessions

> This text is LLM generated.

Use an interactive session to ask an agent follow-up questions in the same run.
Start with a task, or let the first prompt start the conversation. Sessions are
off by default. Chat does not change the run's permissions or approve writes:
proposed changes still go through [safe outputs](safe-outputs.md) after the run ends.

## Start a session

For standalone `agentic-job run`, enable the listener in the runner configuration:

```toml
[session]
listen = true
```

Choose how clients will reach the runner: use a [tailnet](#attaching-to-a-session)
or configure an [attach gateway](#an-attach-gateway). With the listener enabled,
you can omit `--task` or supply a blank task file. An explicitly named file
must still exist and fit the task size limit. Without the listener, a task is required.

| Forge | How to start a session from CI |
| --- | --- |
| GitHub | Use `session: true` in the reusable workflow or [start a session on a chosen runner](dispatch.md#start-a-session-on-a-chosen-runner) by manual dispatch. Both need an initial task and a runner configured for sessions and already joined to the tailnet. The shipped dispatch does not support sessions for review or scripted runs. |
| GitLab | Use standalone `run` with an [attach gateway](#an-attach-gateway) on a runner with [external host isolation](gitlab.md#explicit-external-host-isolation). |
| Forgejo | The shipped dispatch workflow does not support sessions. |

## Attaching to a session

For tailnet access, enable HTTPS certificates on the tailnet and join the
runner before host setup. With the egress proxy enabled, join without accepting
tailnet DNS (`tailscale up --accept-dns=false`). Configure access in the runner's
`[session]` table:

| Setting | What to set |
| --- | --- |
| `origins` | List at least one allowed browser origin, even if you only use the terminal client. Use HTTPS except for local clients on `localhost` or `127.0.0.1`. This prevents other sites from using the browser's tailnet access to attach. |
| `operators` | List allowed Tailscale logins. A client connecting by login also needs an allowed origin. This list can be empty if `capability` is set. |
| `capability` | Name the app capability for tagged clients. Grant it in the tailnet policy to client devices, not CI runners. If the client sends an origin, it must be allowed. |

While the run is live, use the `wss://NAME/` endpoint from the setup log or
from your caller if it publishes the endpoint. The job summary and
`session-endpoint` workflow output are available after the agent job ends,
too late to attach. To connect from a tagged device with the capability:

```sh
agentic-job session connect wss://NAME/
```

The terminal client does not send an `Origin` header. If it gets HTTP 403
when using an operator login alone, use an allowed browser client or connect
from a device with the capability grant.

| To… | Do this |
| --- | --- |
| Send a prompt | Enter one line. The terminal client sends one turn at a time; if the task is still running, it waits and retries the prompt. |
| End the session | Close standard input (Ctrl-D in a terminal). Work already in progress can finish before the run ends. |
| Leave without ending it | Press Ctrl-C. The client prints its last replay cursor. |
| Resume a detached session | Run `agentic-job session connect --since CURSOR wss://NAME/` before the session ends. This rejoins the same conversation; the terminal client also tries to reconnect automatically after a dropped connection. |
| Read the stream from a program | Add `--json` for one JSON message per line. See the [ACP wire reference](../specs/session.md#wire) for custom clients and cursors. |

By default, the terminal client replays everything still retained. If a cursor
is too old, the client resumes from the oldest available point; see the run's
`acp.jsonl` transcript for older events. A prompt accepted before a connection
dropped is not resent automatically.

## An attach gateway

For a standalone runner without a tailnet identity, use a gateway that can
reach the runner over a private or encrypted network. The gateway authenticates
the operator; the bridge checks a per-run secret to keep out other jobs or
services that can reach it.

| Where | What to set |
| --- | --- |
| Runner configuration | Set `[session] listen = true` and `bind` to the `ADDRESS:PORT` the gateway can reach. Leave `operators`, `origins` and `capability` unset. |
| Run environment | Set `AGENTIC_JOB_ATTACH_TOKEN` to a fresh secret for each run (32–1024 bytes of visible ASCII; `openssl rand -hex 32` is one way to generate it). The reusable workflow does not pass this variable. |
| Gateway | Open the WebSocket with `Authorization: Bearer SECRET`, using the same secret. The bridge does not encrypt this connection, so do not expose it on a public or shared network without transport encryption. |

The terminal client cannot connect directly to this bridge: it does not send
the bearer header. For a gateway client, see the [ACP wire reference](../specs/session.md#wire).

## Session limits

| Limit | What to expect |
| --- | --- |
| Idle time | `session.idle-minutes` defaults to 10 and can be set to at most 60. It starts when a taskless session is ready or when the initial task turn ends, and resets after each client turn. Attaching or polling does not reset it. |
| Overall time and budget | The run's limits still apply from startup. For a taskless counted run, the first-inference watchdog starts with the first prompt, not while waiting for it. |
| Client access | One client can be connected at a time. The agent shares the runner user and can take that slot, preventing the operator from attaching. Do not treat a session prompt as proof of operator consent. |

The run's permission policy still decides which actions the agent may take.
For implementation details, see the [session bridge](../crates/agentic-job/src/session/bridge.rs)
and [terminal client](../crates/agentic-job/src/session/connect.rs).
