# Known limitations

> This text is LLM generated.

This page lists what agentic-job does not do, or does not yet prove, so you
can decide what to add around it. For what has actually run, see
[what has run, and what has not](workflow.md#what-has-run-and-what-has-not):
a passing local test is not proof that a deployment works. Remaining work is
tracked in the [plan](plan.md).

## Forge support

| Forge | What works | Limits |
| --- | --- | --- |
| GitHub | The reusable workflow: policy, agent, check and apply jobs. | Pull requests from forks do not get the jobs that write. Most of [gh-aw's catalogue](https://github.github.com/gh-aw/gallery/) is not supported ([comparison](background-ghaw.md#where-each-fits)). |
| GitLab | Policy, check and apply ([GitLab](gitlab.md)). | Not a supported live agent pipeline. |
| Forgejo | Publishing a subset of safe outputs ([Forgejo publishing](safe-outputs.md#publishing-to-forgejo)). | Only the output types listed there. |

## The host and the agent

The [hardened host](secure-host.md) removes root from later steps, but those
steps, and the agent, still run as the runner's user with the job's tokens
and an open network. Host setup takes about two minutes on a hosted GitHub
runner.

- The agent can read whatever the job holds: its files, its environment and
  its tokens ([what it does not do](sandbox.md#what-it-does-not-do)).
- The egress proxy allows reads from any host unless the policy file sets
  `[egress] mode = "allowlist"`, which is off by default
  ([the agent's network](sandbox.md#what-setup-does-for-an-agent)).
- `host.close-resolved`, off by default and set in the
  [hosted example](examples/hosted.toml), closes the system resolver to
  every user but root. The runner's user still resolves names, so data can
  leave through DNS ([the agent's network](sandbox.md#what-setup-does-for-an-agent)).
- The world-write policy is proven at run time on hosted Ubuntu 26.04, not
  on RHEL 10 or CentOS Stream 10 ([secure-host](secure-host.md)).
- Private target repositories need a bounds opt-in, and the runner-only
  launch still refuses them ([private repositories](private-repositories.md)).

### External host isolation

A standalone container run can set `[host] isolation = "external"` to say the
runner host already gives one job per runner, a fresh environment, an egress
allowlist and no credentials beyond the run's own. On GitLab, a disposable
job with a recognized container signal, no container engine in reach and
`egress.proxy = false` defaults to external; other jobs default to managed.
Neither the declaration nor the detection proves isolation: agentic-job then
does no host setup, and you own those guarantees. Credential refusals,
session secrets, redaction and the separate check and apply jobs still apply
([external host isolation](gitlab.md#explicit-external-host-isolation)).
Local tests do not prove Kubernetes Pod Security or a live GitLab inference
deployment.

## Credentials

- The agent holds a read-only forge token and a broker run token
  ([which tokens reach what](workflow.md#which-tokens-reach-what)), so this
  is not credentialless operation. The agent job has no `id-token`; a
  separate job registers the run ([the run token](workflow.md#the-run-token)).
- The reusable workflow accepts no model key or MCP credential, so a real
  agent needs an inference broker ([a provider API key](inference.md#a-provider-api-key)).
  In an agent job of your own that uses a key, nothing outside the provider
  caps spending.
- Managed MCP servers are refused in runner mode, even without a credential
  ([MCP's current status](mcp.md#current-status)).
- A broker admits a caller's own agent job by repository, so any workflow in
  that repository is admitted
  ([which workflows a broker admits](inference.md#which-workflows-a-broker-admits)).
- A missing, empty or owner's `SAFE_OUTPUTS_PAT` fails only in the apply
  job, after the agent has run, unless the caller sets
  `require-safe-outputs-pat`
  ([checking the token first](workflow.md#checking-the-token-before-the-agent)).
- Pushing to a stale fork with a PAT that lacks the `workflow` scope has not
  been tried ([pull requests come from a fork](workflow.md#pull-requests-come-from-a-fork)).
