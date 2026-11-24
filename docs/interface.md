# Command-line reference

> This text is LLM generated.

`agentic-job` runs an agent in CI and checks its hand-back before publication.
Start with [GitHub](quickstart.md#github), [GitLab](quickstart.md#gitlab), or [Forgejo](quickstart.md#forgejo).

## Commands

Run `agentic-job --help` to list commands or `agentic-job COMMAND --help` for
flags. See [stable interfaces](stable-interfaces.md) for compatibility promises.

| To… | Use | What to expect |
| --- | --- | --- |
| Inspect a finished run | `audit DIR [--json]` | Reads downloaded [artifacts](workflow.md#auditing-downloaded-artifacts) offline without executing or applying them. Findings alone do not cause a nonzero exit. |
| Talk to a running agent | `session connect ENDPOINT [--json] [--since CURSOR]` | [Attach or reconnect](interactive.md#attaching-to-a-session), replaying retained messages after the cursor. Ctrl-C detaches; end of input ends the session. |
| Validate a hand-back from inside a run | `handback check` | Check changes, requests and the outcome report. From a workstation, try the [credential-free example](quickstart.md#check-a-local-hand-back) instead. |

### Compose a pipeline

Keep policy and validation in trusted jobs outside the agent's control, and
give publication credentials only to the apply job. See the
[trust model](requirements.md#actors-and-trust).

| Stage | Commands | What they do |
| --- | --- | --- |
| Admit a run | `event`, `policy` | `event` admits supported [event payloads](events.md). `policy` checks the request against caller bounds and prints `policy.json` for later stages. |
| Configure the run | `config` | Composes TOML from `--from FILE` and typed settings such as `--string TABLE.KEY=VALUE`. Values are data, not TOML snippets; empty settings leave the file unchanged. |
| Prepare and verify the host | `sandbox setup`, `sandbox check`, `sandbox preflight` | Run setup as root, and [probes](sandbox-check.md) and [preflight](dispatch.md#capability-preflight) as the runner user. For image preparation, use `config --prepared` and `sandbox prepare` (as root); for host-only configuration use `config --host`. |
| Run the agent | `run --runner-home DIR --policy FILE --task FILE --meta FILE --out DIR` | Runs as the runner user and collects the hand-back. The agent shares the supervisor's user ID; do not give the job credentials or files the agent must not access. |
| Validate a hand-back | `collect`, then `check` | `collect` sanitizes requests; `check` verifies the trusted `--collected` file and patch against policy. Apply from the accepted report, trusted requests and `check --stage` files, never directly from agent artifacts. See [the two-part check](safe-outputs.md#the-check-in-two-halves). |
| Check workflow definitions | `workflows check` | Reports workflow files, jobs and steps that violate the [workflow checks](workflows-check.md). |

| Forge | Publish checked results |
| --- | --- |
| GitHub | Use the [apply workflow](workflow.md#running-apply-again). On retries, `applied` skips outputs it can identify as already published. |
| GitLab | Use [`apply --forge gitlab`](safe-outputs.md#publishing-to-gitlab) in the trusted job with the caller's merge request or issue context. |
| Forgejo | Use [`apply --forge forgejo`](safe-outputs.md#publishing-to-forgejo) in the trusted job with the caller's pull request or issue context. |

For host setup without an agent, use the separate
[`secure-host` binary](secure-host.md#the-secure-host-binary).
For [external GitHub Actions runs](dispatch.md#binary-correlation-interface),
use `external-fetch`, `policy --external-receipt` with `--output-repo`, and
`external-release` to require trusted check and detection before apply.

## Files read

| Input | Contents |
| --- | --- |
| `policy --allow FILE` | Caller-owned [bounds](safe-outputs.md#the-bounds-and-the-policy): allowed clone hosts, repositories and base branches, output types and counts, and patch size and file limits. With `--allow-sha256 HEX`, refused unless it has that [pinned digest](dispatch.md#bounds-the-runner-pins). |
| `run --policy FILE` | The approved request written by `policy`. |
| `run --task FILE` | The instructions for the agent. |
| `run --meta FILE` | CI metadata (JSON), copied into `summary.json`. Include `run_id`, which names the patch. |
| `run --config FILE` | Secret-free runner settings (TOML). The default is `/etc/agentic-job/config.toml`, installed by `sandbox setup`. Selecting another file does not perform setup. |

`run` refuses symlinks and files writable by its effective user. Mount a trusted
configuration read-only and keep the path and mount source under trusted control:
an agent that can replace the file can change later runs' limits, inference
routing or session access. `--allow-writable-config` is off by default and skips
only the write-access check. This is a startup guard, not isolation from the
agent. The configuration is read once, not watched for changes.

| TOML table | Use it to configure… |
| --- | --- |
| `[host]` | Host setup and [checks](sandbox-check.md). `[sandbox]` is a deprecated alias; do not use both. |
| `[egress]` | Network policy and proxy settings. |
| `[setup]` | Packages and agent installation. For repository toolchains, use [unprivileged setup](dispatch.md#giving-runs-a-toolchain). |
| `[inference]` | [Inference](inference.md) endpoint and authentication. |
| `[agent]` | Agent, model, public configuration repository and [skills](skills.md). |
| `[limits]` | [Run limits](harness.md#limits). Set `timeout-minutes` and an enforceable request or spending cap, or explicitly set `uncapped = true`. |
| `[session]` | Optional [interactive sessions](interactive.md) and who can attach. |
| `[preflight]` | Optional [host capability requirements](dispatch.md#capability-preflight). |
| `[commit]` | Hand-back commit authorship, trailers and formatting. |

Unknown keys are refused. This minimal scripted-agent configuration needs no
inference credential. Parsing it with `config --from FILE` does not test the host.

```toml
[agent]
name = "fake"
[limits]
timeout-minutes = 5
max-requests = 0
uncapped = true
[egress]
write-policy = true
```

### Removed keys and runner-mode refusals

| If your configuration has… | What to do |
| --- | --- |
| `host.create-user`, `host.user`, `host.groups`, `host.allow-existing-user`, `host.filesystem-view`, `host.check.before-agent`, or `setup.tools` | Delete the keys, even if set to `false`. The same applies under the `[sandbox]` alias for host keys. |
| `agent-user: sandbox` | Remove it from the workflow inputs; `run` requires `--runner-home`. |
| `register = "api-key"`, `[mcp.NAME]`, `[child-agent]`, or `inference.front` | Remove these settings; runner mode does not support them. |
| OIDC request credentials in the run job or a private target | Do not launch in that context. Register separately when using OIDC, and use a public target. A policy opt-in does not grant launch support. |

## Files written

| Command | Output |
| --- | --- |
| `policy` | Prints `policy.json`: the admitted request, clone URL and safe-output policy. |
| `run` | On passing the upload gate, writes `run/` summaries and logs, `transcript.tar.zst`, and any `safe-outputs/` under `--out`. See [artifact contents](workflow.md#what-a-run-leaves). |
| `check --report FILE` | Writes the JSON verdict, including refusal reasons and paths named by the patch. |

## Exit states

| Code | `run` | Other commands |
| --- | --- | --- |
| `0` | The agent ended its turn. | Success, acceptance or passing probes. |
| `1` | The agent failed or was cancelled, the run was stopped by a signal, or the inference proxy no longer knew the run token at teardown. | Refusal or a failed probe. |
| `2` | Bad arguments, internal error, failed upload gate or failed cleanup. | Bad arguments or internal error. |
| `3` | A request, task or spending limit stopped the agent, or it handed back after a turn error or with a token the proxy forgot. | — |
| `4` | Startup failed before work began; it is safe to retry. | For `sandbox check`, only a control reaching outside the host failed. |
| `124` | The run timed out. | — |

For `3` and `124`, read `summary.json` to see whether the agent handed back.

## Testing Farm launcher

This optional [GitLab integration](../specs/gitlab-caller.md#testing-farm-as-a-later-layer)
is unverified against a live Testing Farm. Supply a trusted JSON request file
and binary from outside the checkout. The [request fields](../crates/agentic-job/src/testing_farm.rs)
pin a plan commit, environment, timeout (1–330 minutes), API and artifact paths.
Guests can read request variables; do not pass secrets or use a plan that
reserves guests or adds SSH keys.

Use GitLab and protected GitLab Runners 17.3 or later. Scope the masked,
protected `TESTING_FARM_API_TOKEN` to this job's protected environment. Only
trusted actors may start the pipeline or supply its variables; do not forward
upstream variables. Use a fresh per-job container shared by `script` and
`after_script`, with private `/tmp` outside checkout, cache and artifacts.
Leave the job disabled if you cannot enforce these conditions.

This example allows a 120-minute request an extra 12 minutes for download
and separate time for cleanup. Replace the example image and runner tag.

```yaml
agent_job:
  timeout: 2h 20m
  image: registry.example.com/owner/agentic-job@sha256:DIGEST
  tags: [protected-runner]
  environment:
    name: testing-farm
  inherit:
    default: false
  dependencies: []
  variables:
    GIT_STRATEGY: empty
    RUNNER_SCRIPT_TIMEOUT: 2h12m
    RUNNER_AFTER_SCRIPT_TIMEOUT: 5m
  script:
    - mkdir -m 700 /tmp/agentic-job-testing-farm
    - agentic-job testing-farm-launch --request /etc/agentic-job/testing-farm.json --id /tmp/agentic-job-testing-farm/request-id --output .
  after_script:
    - agentic-job testing-farm-cancel --request /etc/agentic-job/testing-farm.json --id /tmp/agentic-job-testing-farm/request-id
  artifacts:
    when: on_success
    paths: ['*']
```

The launcher attempts cancellation at its deadline, including queue time.
If the ID was never recorded or cleanup cannot run, a queued request may
start after the job ends. Accepted cancellation does not prove guest destruction.

Only a passing request yields flat hand-back files from a bounded ZIP. The job
uploads those files, not the ZIP; both archives must fit the 128 MiB limit.
Verify the plan's artifact path, access and retention before enabling the job:
guest artifacts exist before validation and a refused download leaves them there.
