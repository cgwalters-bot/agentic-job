# Agent harnesses

> This text is LLM generated.

The harness starts the agent, sends it the task, watches its limits and records
the session. Choose an agent that works with your [inference endpoint](inference.md),
set limits, then use the run summary to see what happened.

## Agents

### Agent adapters

For standalone `agentic-job run`, this TOML fragment selects Claude Code
with a provider that resolves `opus`. Add the required
[`[inference]` URL and registration mode](inference.md#what-run-does) and
[`[limits]` settings](#limits) to make a run configuration:

```toml
[agent]
name = "claude"
model = "opus"
```

For the GitHub reusable workflow, set `with.agent`, `with.model`,
`with.timeout` and `with.max-requests` to override the corresponding settings
in `with.config`. Even if omitted, `with.agent`, `with.timeout` and
`with.max-requests` override the file with their defaults: `fake`, 60 minutes
and 150 requests. Follow the [real agent checklist](workflow.md#real-agent-checklist)
for broker setup and limits.

| `[agent] name` | Program and tested version | Inference | Live nudges and item updates |
| --- | --- | --- | --- |
| `claude` | Claude Code via `@agentclientprotocol/claude-agent-acp` 0.88.0 | Anthropic-compatible | Yes |
| `opencode` | `opencode-ai` 1.18.35 | A configured opencode provider | Yes |
| `vibe` | `mistral-vibe` 2.26.1, installed by sandbox setup | Mistral-compatible broker route | No |
| `fake` | The released `fake-agent` binary | None; use it to test a run without a model | Yes |

Use the [installation and PATH requirements](sandbox.md#who-installs-the-agents)
when provisioning an agent. Other versions aren't covered by the adapter tests.
There is no caller-defined adapter registry. For contributor information, see
[Adding an agent](layout.md#adding-an-agent).

| Optional `[agent]` setting | Effect |
| --- | --- |
| `config-repo`, `config-ref`, `config-path` | Claude Code, OpenCode and Vibe only. Load supported settings from a trusted public repository URL. The ref defaults to its default branch, and the path to its root. See [Claude and opencode configuration](workflow.md#agent-configuration-repositories-and-model-names) or the Vibe rules below. |
| `[agent.context-windows]` | For Vibe models defined by the run, map model names to context windows in tokens. The default is 32,768; the maximum is 1,048,576. Match the window your provider actually serves. Models imported from a config repository declare their own. |
| `fallback-model` | Claude Code and `fake` only. After retries for sustained provider overload, try one alternative model in the same session. The model must be available through the same provider. |
| `skills`, `subagents` | Configure [skills or named worker subagents](skills.md). |

For Vibe, the configuration repository's `config.toml` can supply up to 32
`[[models]]` using `provider = "mistral"` or `"llamacpp"`. Each entry needs
a broker model `name`. The optional selection `alias` defaults to `name`;
aliases must be unique and cannot be `mistral-medium-3.5` or `devstral-2`.

```toml
active_model = "coding"

[[models]]
name = "example-broker-model"
alias = "coding"
provider = "mistral"
```

`active_model` must select an imported model by alias and is required when
the run does not supply a model. Other settings, including provider
definitions, are not imported.

## What it does

`agentic-job run` talks to the agent over standard input and output using the
[Agent Client Protocol](https://agentclientprotocol.com) (ACP). The agent uses
its own file and shell tools. ACP permission answers apply only to actions the
agent asks about; the [sandbox](sandbox.md), not ACP, is the security boundary.

The agent and `run` share the runner's user. Environment filtering doesn't hide
credentials in files or processes accessible to that user. The agent can tamper
with its transcript and harness limits, so treat the record as a diagnostic, not
an attestation. See [inference credential requirements](inference.md) before
provisioning a runner, or [interactive sessions](interactive.md) to join a run.

## Limits

| `[limits]` setting | What it controls |
| --- | --- |
| `timeout-minutes` | Required wall-clock limit, including retries and hand-back. |
| `max-requests` | Model requests as counted by the inference broker. Refused if accounting is unavailable at startup (including `token-file` registration). If [accounting becomes unavailable](inference.md#what-run-does) during the run, the run stops. |
| `budget` | Spending in hundredths of a US dollar, based on cost reported by the agent after replies. It can't prevent the reply that takes the run over budget. |
| `max-tasks` | Delegated tasks. With [named workers](skills.md#worker-subagents), their calls count separately under `max-worker-tasks`. |
| `max-worker-tasks` | Tasks addressed to configured workers. Workers also require `max-requests`; the lead agent's reported cost can omit worker usage. |
| `max-repeats` | Warning threshold for consecutive completed calls with identical tool, input and result (2–100; off by default). If two more identical calls follow, the harness asks for hand-back, even on adapters that don't receive the warning. Unchanged polling results count too. |
| `uncapped` | Set to `true` only when deliberately running without either `max-requests` or `budget`. A timeout is still required. |

Set at least one of `max-requests` and `budget` unless you opt out with
`uncapped = true`. Vibe requires `max-requests` and broker registration with
request accounting; a spending budget alone isn't enough. Use a broker-side
cap when you need a hard request ceiling; the harness checks the count periodically.

Near a time or request limit, or after too many delegated tasks, the harness
cancels the turn and asks the agent to hand back partial work. Over-budget stops
do not get an extra turn. When a run requires an output and the agent finishes
without one, the harness normally sends one reminder; if nothing is handed back,
the run fails. An incomplete [checkpoint](safe-outputs.md#ready-or-draft) stays
incomplete even if the turn ends normally.

## Updates of the run's item

To send new issue or pull request activity into a running turn, opt in with
`watch-item = true` in `[session]`. `watch-seconds` defaults to 60 and accepts
10–3600. Runs using `--runner-gate` do not allow the watch.

| Forge | What to provide | Updates delivered |
| --- | --- | --- |
| GitHub | `--watch-item 'OWNER/REPO#NUMBER'` and the agent's read-only `GH_TOKEN`. The reusable workflow supplies the item when available. | New issue or pull request comments and body edits; not line-level review comments. |
| GitLab | `--watch-item` with a public issue URL such as `https://gitlab.example.org/GROUP/PROJECT/-/issues/123`, and `CI_SERVER_URL` set to the installation's base URL. No token is used. | New public issue comments; no internal or system notes or body edits. |
| Forgejo | Not supported. | None. |

Only updates from the watch's start are eligible; include earlier context in the
task. Updates are untrusted input, not authorization. Delivery is best effort
and limited to ten updates per run, each at most 8,000 characters. See `updates`
in `summary.json` for links to the updates actually sent.

### Nudges on the clock

Set `nudges = true` in `[session]` to ask a running agent to checkpoint halfway
through `timeout-minutes` and to wrap up at five-sixths. This is off by default,
doesn't require an item watch, and only works with adapters that accept live
updates. Check `notices` in `summary.json` to see which nudges were sent.

## A second agent

Current runs reject `[child-agent]` and don't provision a child for `acp-drive`.
Use [worker subagents](skills.md#worker-subagents) for supported delegation within
the main agent; workers don't provide a separate isolation boundary.

## How a run ends

| What happened | Where to look |
| --- | --- |
| A limit stopped the run | `handed_back` in `summary.json` says whether partial work was returned. A timeout without hand-back exits 124. See [exit states](interface.md#exit-states). |
| The provider failed | The harness retries transient failures within the run's limits, but doesn't wait out exhausted quota or rejected credentials. Check `provider_error` in `summary.json`. A recognized provider failure can preserve a change as a partial result. |
| The agent went quiet | The harness can retry a stalled task turn once. If the broker reports zero requests after five minutes, the run stops as `no_requests` (retryable exit 4). That check is skipped when the count is unavailable. |

Hand-back isn't publication. See [how to recover partial work](workflow.md#a-run-stopped-at-a-limit)
if a limit or provider failure stopped the run.

### Reading a session in the summary

The run summary includes a redacted session preview by default. Set
`render-session = false` in `[agent]` to disable both the preview and the
rendered `session.md` in the `agent-run` artifact. Otherwise, open `session.md`
for the full rendering (tool output is bounded). Also check the agent's own
`agent-logs.txt` in the transcript, when collected. Costs shown in the session
are agent-reported, not broker accounting. See
[run artifacts](workflow.md#what-a-run-leaves) for the full inventory.
