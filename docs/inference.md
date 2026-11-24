# Inference through a broker

> This text is LLM generated.

A real agent reaches its model through a broker on another machine that holds
the provider key. The run normally gets a short-lived, capped run token from it
and ends that token when the agent finishes.

## Credential boundary

The agent and `run` share the runner's user, so the agent can read anything
`run` holds; separate processes, environment filtering, Yama or `hidepid=2` do
not change that. Keep provider keys, MCP credentials and OIDC request
credentials off the agent machine. `run --runner-home` refuses API-key mode,
configured MCP and known OIDC request environment variables; those checks do
not inventory credentials on the machine. Check and apply run elsewhere and
never execute agent-produced code.

What the agent can still read:

| Credential | Why it is there | How to limit it |
| --- | --- | --- |
| The broker's run token | The agent's model requests carry it | Broker caps, expiry and `run` ending the run at finish |
| A forge read token (GitHub workflow) | Lets the agent read issues, pull requests and logs | `github-reads: false` stops forwarding it |

So broker inference is not credentialless inference
([#2903](https://github.com/cgwalters-forge/agentic-job/issues/2903)). Do not
add a second user or a local proxy to work around a
[runner-mode refusal](interface.md#removed-keys-and-runner-mode-refusals).
A disposable container job can take over host controls, not credentials; see
[external host isolation](gitlab.md#explicit-external-host-isolation).

## What a broker provides

The client speaks
[praxis-credential-broker](https://github.com/cgwalters-bot/praxis-credential-broker)'s
run API.

| Request | Purpose |
| --- | --- |
| `POST /v1/runs` | Register a run; 201 returns the run token and a usage record |
| `GET /v1/runs/self` | Read the run's usage; `run` polls it to count requests |
| `DELETE /v1/runs/self` | End the run, so the token admits nothing more |

Agents reach the model under the broker's root URL:

| Agent | Default route | Override |
| --- | --- | --- |
| Claude Code | `/anthropic` | `inference.anthropic-url` |
| opencode | `/v1` | `inference.openai-url` |
| Vibe | `/mistral/v1/chat/completions` | none |

Broker policy owns admission, caps, expiry and injecting the provider key;
reachability is not authentication.

## What `run` does

`run` registers a run (or takes over one an earlier job registered), writes
the token into the agent's configuration, counts requests while the agent
works, and ends the run at finish.

### Configuration

| `[inference]` key | Workflow input | Meaning |
| --- | --- | --- |
| `url` | `inference-url` | The broker's root URL, not one of its routes. Required for any other key. |
| `register` | `inference-register` | How to get a run token; see the modes below. No default in the binary; the reusable workflow passes `github-oidc`. |
| `audience` | `inference-audience` | The OIDC audience the broker expects, for `github-oidc` |
| `token-file` | `inference-token-file` | Absolute path of a token, for `token-file` |
| `identity-proxy` | none | An HTTPS CONNECT proxy for the identity-token request only, for a host that reaches the CI system only through one |
| `anthropic-url`, `openai-url` | none | Override the routes above |

`limits.max-requests` caps the run's model requests. Read the broker's
address from configuration or the environment; never copy it into code.

### Registration modes

| Mode | What it does | Limits |
| --- | --- | --- |
| `github-oidc` | A separate job with `id-token: write` registers with its identity token; the agent job takes the run over through `AGENTIC_JOB_INFERENCE_RUN_TOKEN` | GitHub only. The agent job must not hold OIDC request credentials. |
| `plain` | Registers with a name (`x-run-id`, up to 128 letters, digits, `.`, `_`, `-`) and no proof, if the broker admits unproven runs (off by default; otherwise 401) | The agent can register another run to reset its per-run cap; only broker-wide quotas and the job timeout bound it. A name stays taken for a day after expiry; a 409 is not retried. |
| `token-file` | Reads a bearer token from a file | No counting and no ending the run. `limits.max-requests` is refused, so a workflow caller must pass `max-requests: "0"` (its default is 150). Not an isolation mechanism. |

### What you can rely on

- The token is kept in memory and written only into the agent's
  configuration, which the agent can read.
- The request cap is enforced by polling the broker, not by the broker. If
  polling keeps failing, a run with `max-requests` stops within about three
  and a half minutes. Treat it as a guard, not a hard spending cap.
- Registering and ending the run are retried on timeouts, 429 and 5xx. A 404
  is a failure: a broker without the run API never runs an agent uncapped.
  Ambiguous retries can leave a registration whose token never arrived; the
  broker's expiry cleans it up.
- Requests to the broker ignore the job's `HTTP_PROXY` and follow no
  redirects: `url` must reach the broker directly.
- If the broker no longer knows the run when it is ended (401), the run fails
  even after a successful turn: exit 1, or exit 3 when it retains a change,
  classified `inference_unreachable`. Nothing is uploaded until the run is
  ended. Same-user interference can stop cleanup, so the broker's expiry must
  not rely on `run` alone.
- Configured `host:port` literals of the broker are replaced by
  `<inference-address>` in hand-backs, logs and transcripts. A URL rendered
  without its explicit port does not match, so give ports explicitly. The
  replacement can break a patch, so review it. This is not comprehensive
  address nondisclosure. Known run tokens, upstream credentials and private
  keys refuse the upload.

## Forges

| Forge | Registration |
| --- | --- |
| GitHub | `github-oidc` through the reusable workflow's separate `register` job; see [the run token](workflow.md#the-run-token) |
| GitLab | Agent runs unsupported: no supported registration proof yet; see [GitLab](gitlab.md) |
| Forgejo | Agent runs unsupported: no supported registration proof yet; see the [Forgejo trial](try-forgejo.md) |

Do not substitute a provider key for a missing identity contract. On GitHub,
`agentic-job register` writes the token as a job output, which the workflow
passes to the agent job as the secret `INFERENCE_RUN_TOKEN`. Step debug
logging would print job outputs, so registration refuses to run with it. To
retry, rerun all jobs: the agent job's token has ended.

## Which workflows a broker admits

On GitHub the broker's token policy admits runs by the identity token's
claims:

| Policy | Admits |
| --- | --- |
| `called_workflows` | A reusable workflow at a ref or commit, called from listed repository IDs |
| `any_workflow` | Any workflow of a repository or owner |

Move pins and the broker's admitted workflow commits together. If you compose
the agent job in your own workflow file, it does not carry the reusable
workflow's `job_workflow_ref`: admit your separate registration job instead.
Repository-wide admission is broader than admitting one workflow; choose it
deliberately. Never grant OIDC to the agent job to make admission succeed.

## Reaching the broker

On a managed runner, `egress.write-policy` enforces the configured proxy
policy. The default still allows reads to unlisted public hosts. To restrict
read destinations as well, set `[egress] mode = "allowlist"` and list the
needed domains in `allow` in the proxy policy file (`egress.policy`). Forge
write exceptions still prevent private-source confinement. With external
isolation, enforce egress on the host instead.

See the [egress write policy](secure-host.md#the-egress-write-policy-for-an-agent-job)
for routing a public broker or using `egress.direct` for a tailnet IPv4
address. If you join a tailnet, do it in trusted steps before host lockdown,
with no join credential left readable by the agent.

## Prompt caching

`summary.json` reports `cache_ratio` from the broker's `cache_read` and
`input` token counts, or marks agent-reported figures as such when the broker
has no record. Caching is set by agent and provider configuration. For
opencode models that need encrypted reasoning replay, set
`"options": {"include": ["reasoning.encrypted_content"]}` in the configuration
repository.

## A provider API key

These options would put a provider credential where the agent can read it,
and are refused in runner mode and by the reusable workflows:

| Option | Why it is refused |
| --- | --- |
| `register = "api-key"` | `run` would hold the provider key. `INFERENCE_API_KEY` is declared for compatibility but forwarded to no job. |
| `inference-provider: github` | Implies `api-key`; a Copilot-capable token pays for inference. Do not grant `copilot-requests: write` or pass that token to the agent job. |
| `inference.front = true` | `run` would hold the broker's upstream token in its own memory |
| `stop-long-retry-after` | Needs `front` or `api-key` to see upstream 429s, so it has no runner-mode effect |

Do not compose a second-user caller to enable them. Externally owned billing
or key injection needs its own verified broker contract.

### On a multi-user guest

Some test systems put a secret on a wrapper's command line. Mounting `/proc`
with `hidepid` hides other users' processes, not same-user processes or
`run`'s memory, so it is not a credential solution. Keep credential injection
off the agent's machine.
