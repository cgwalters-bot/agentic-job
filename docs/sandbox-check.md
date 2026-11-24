# Check a hardened runner

> This text is LLM generated.

`agentic-job sandbox check` verifies selected protections on a CI runner before
you start an agent. It tests the runner's account, which is also the account
the agent uses. A pass is not proof that processes running as that account
are isolated from one another.

## Run the check

After [host setup](sandbox.md), run this on the CI host as the runner's
user, **not** as root:

```sh
agentic-job sandbox check
```

The check assumes that setup locked the runner, which is the default. With
`host.lock-runner = false` the runner's user keeps `sudo`, and the check
skips its privilege probes without failing, so exit `0` does not show that
the runner is locked. Do not start an agent on such a host. The
[run action](../run/action.yml) refuses an unlocked host. A custom job does
not inherit that guard: before the agent starts, it must confirm that the
installed `/etc/agentic-job/config.toml` does not turn the lock off.

In your own CI job, put the check after any intervening repository steps and
before starting the agent. Do not start the agent if the check fails.
The run action already checks before starting the agent.
The shipped [secure-host action](secure-host.md#inputs-and-outputs) also
checks by default but does not save a passing record, so the run action
normally probes again. Keep that setup-time check before the first step that
runs untrusted repository code: a later check cannot protect a step that ran
on a misconfigured host. Set `check: false` on secure-host only when every
step between the two actions is trusted, and leave no record across steps
that run repository code.

| Command | Behavior |
| --- | --- |
| `agentic-job sandbox check` | Run the probes. This is the default. |
| `agentic-job sandbox check --record` | Run the probes and, if they pass and the CI job provides the required environment, save a result for one later check. |
| `agentic-job sandbox check --unless-passed` | Reuse a matching passing result once; otherwise run the probes. Does not save a new record. |

The flags are mutually exclusive. For a record to be reusable, the job,
binary build, and installed configuration must match. Recording needs an absolute
`RUNNER_TEMP` and the job identifiers `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`,
and `GITHUB_JOB`. An ordinary check works without these, and a passing
`--record` check can still leave no record if the write fails. The next check
consumes the record even if it does not match; starting an agent also clears
it. Reuse a result only between trusted steps:
the runner's user can write the record or change host state after the check.
See the [record implementation](../crates/secure-host/src/check/record.rs).

## Read the result

Look for `FAIL` and the probe ID in the job log. Some probes have a positive
control: an operation that must succeed so the corresponding denial counts
as evidence that the protection works. An unexpected result from either
the probe or the control fails the check.

| `agentic-job sandbox check` exit code | Meaning and next step |
| --- | --- |
| `0` | The applicable probes passed, or the check reused a matching record. Read any skip notes before relying on a particular probe; a pass does not establish that the runner is locked. |
| `1` | A probe or control other than external reachability failed. Fix the problem in the log before starting the agent. |
| `2` | The check could not run or finish: invalid arguments such as two of the mutually exclusive flags, running as root, an unreadable configuration, or a probe that could not be made. Fix the error before starting the agent. |
| `4` | Only external reachability failed after the check's own retries. The agent did not start. Check the network diagnostics: broken runner networking can look like an external outage. |

For exit `4`, the run action fails the job and reports `exit: 4` and
`failure-class: control_unreachable` in its outputs. If you automate retries,
requeue the whole workflow a bounded number of times, not just the agent job.
The standalone `secure-host` binary returns `1` for this case. See
[why a run failed](workflow.md#why-a-run-failed).

## The egress policy and containers

With `egress.write-policy` enabled, `write-policy-read` checks that the
runner can read an allowed destination, and `write-policy-post` checks
that the proxy itself refuses a write. The check does not change the
allowlist. If there is no suitable destination for the read, the log says
it was skipped. A fallback POST to a disallowed destination checks only
that the proxy blocks that request; if there is no suitable fallback,
the POST is skipped too. See the [egress probe reference in code](../crates/secure-host/src/check/net.rs).

Older host images, including the one used by the shipped secure-host action,
check a fixed read destination. If their setup-time check fails under a narrow
allowlist, check the logged destination against your policy.

| `[host.check]` key | Current behavior |
| --- | --- |
| `before-agent` | Rejected. Remove it from the configuration. |
| `control-url`, `fetch-repo`, `allow-sockets`, `allow-tcp-ports` | Accepted for compatibility with older host images and logged as ignored by the current check. |
| `container-image`, `containers` | Do not enable container probes in `sandbox check`. |

## `run`'s token probes

Neither `sandbox check` nor `run --runner-home` probes whether the agent
can read the run token, from the host or from a container. `run --runner-home`
rejects `inference.front`; the container settings do not restore those probes.
The agent can read the token from `run`'s environment. Do not rely on a passing
check to protect credentials accessible to the runner's user. See
[what the sandbox tests](sandbox.md#what-is-tested).

## A session's bridge

The check does not probe the [session bridge](../specs/session.md). An agent
can reach its own bridge and take the client slot before the operator. That
can block the operator's chat, but attaching to the bridge does not grant
credentials or write permissions.

## The helper

After setup locks the runner, later steps cannot use general-purpose `sudo`.
The installed [privileged helper](../crates/secure-host/src/helper.rs)
allows only predefined operations, such as reading the proxy log. No manual
helper call is needed to run the check.

Finish trusted provisioning that needs root before the lock. Keep untrusted
steps after the lock and remove any dependency they have on root. Check
cleanup hooks too: if a network logout hook needs `sudo`, use a registration
that expires automatically instead. Discard a self-hosted runner after the
job rather than reusing the locked host.
