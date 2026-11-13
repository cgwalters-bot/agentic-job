# Requirements and threat model

> This text is LLM generated.

These requirements retain R1–R16 from
[workflow-compiler](https://github.com/cgwalters-forge/workflow-compiler/blob/448c60c769577b345db2ad0028997f743daa5973/docs/requirements.md)
so older issues remain readable. agentic-job has no compiler. Its binary
and reusable workflow enforce the boundaries below; they do not inspect
other jobs a caller writes.

## Actors and trust

The caller's maintainers choose the runner, pinned workflow, bounds,
setup packages, inference proxy and apply credential. They are trusted.
The CI platform, kernel, systemd, sudo, nftables, toolchain, mitmproxy,
gh-aw scripts and inference proxy are also trusted.

The agent and all text it reads are untrusted. Assume prompt injection
succeeds. The agent must have no forge write credential. Current broker runs
still expose a run token and, by default, a GitHub read token; this does **not**
meet [#2903](https://github.com/cgwalters-forge/agentic-job/issues/2903)'s no-credentials goal.
It proposes outputs; a clean job checks
them before a separate job applies them. Event notification jobs also
have write access, but never consume agent-written outputs.

The operator chose runner-only execution on 4 November 2026
([#2989](https://github.com/cgwalters-forge/agentic-job/issues/2989)).
[#2991](https://github.com/cgwalters-forge/agentic-job/pull/2991) removed
the old second-user implementation; do not reintroduce it as an escape from
runner-mode refusals. The migration and
acceptance gaps are recorded in [the dated inventory](plan.md#runner-only-hardening-inventory-2026-11-05).

- `runner`, the default: `run --runner-home`, and the agent is the
  runner's own user, as any deterministic step after secure-host is.
  What separates it is secure-host's deprivileging (R4), a job with
  read-only tokens, no `id-token` and no secret but the run token, and
  the check on another machine. Nothing protects the transcript, the
  limits or `run`'s environment from the agent, which can also stop or
  kill `run`; cleanup kills only the agent's process group, the token
  probes do not run, and the egress proxy does not filter it unless the
  caller opts into `egress.write-policy`, which holds it to the write
  rules, with the runner's own Actions-service writes
  ([secure-host.md](secure-host.md#the-egress-write-policy-for-an-agent-job)).
  `run` refuses what would need the second user, a private target included
  ([`refuse_without_second_user`](../crates/agentic-job/src/run/mod.rs)).
- The legacy `sandbox` mode was removed in #2991, and `agent-user: sandbox`
  is refused. Neither `hidepid=2` nor environment filtering isolates
  same-UID processes.

R1 to R3 and R7 below say what holds in each, the runner's user first.

## Requirements

### R1. Nothing after setup runs outside the sandbox on the agent's behalf

The reusable workflow fixes the agent job's steps. The caller cannot
insert a shell or action there. With the runner's user as the agent,
the setup script runs as that user after secure-host. Packages and npm install hooks run as root before the lock and
must be trusted by the caller. A standalone action cannot enforce the
ordering of steps around it.

### R2. The agent is the runner's user, not an isolated supervisor client

The old separate-user requirement is superseded by #2989. Runner entry clears
the inherited environment at the runner's UID. `ACTIONS_*` configuration
variables are refused, but clearing them does not protect earlier same-UID
processes, memory or files. Host probes are not proof of supervisor isolation;
they do not cover every service behind the system bus or all UDP listeners.
See the action's [probes](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/probes.md#local-sockets).

### R3. No reachable credentials is a goal, not the current guarantee

With the runner's user, the default, the agent can read every file of
that user and `run`'s environment, so the job holds only read-only
tokens and the run token, and the token probe does not run. The network
rules that restrict private-network access match the sandbox user only;
the runner's user is refused metadata too with
`host.deny-runner-metadata`, on with the lock unless set false (not
yet in the image the forwarder pins:
[what main has](secure-host.md#what-main-has-that-the-pinned-image-does-not-yet)),
and `run` refuses `[host.check] before-agent`, so host probes do not
repeat. The reusable workflow passes no inference key or MCP credential.
Caller-owned steps can still expose credentials; these are not made safe by
secure-host. The credentialless client and readiness gate remain
[#2999](https://github.com/cgwalters-forge/agentic-job/issues/2999) and
[#3000](https://github.com/cgwalters-forge/agentic-job/issues/3000). In runner mode
the target is cloned without credentials
([sandbox-check.md](sandbox-check.md)).
[Inference modes](inference.md) differ: `plain` permits new registrations
without proof; `token-file` has no request accounting or revocation by `run`.

### R4. The runner's user loses root before the agent runs

secure-host's lock meets this for every later step, the agent included
([R4 there](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/threat-model.md#r4-the-runners-user-loses-root-before-untrusted-steps-run)).
The agent doesn't need root. Runner mode uses no helper user switch or UID-wide
reaping; the remaining host helper has fixed operations, not generic root execution
([the helper](sandbox-check.md#the-helper)).

### R5. Nothing of the agent's outlives the run

The supervisor stops only the agent's process group in runner mode, so what
the agent detached from it can run until the job ends. UID-wide cleanup in
the legacy implementation is not a runner-mode guarantee. Setup does not
put the runner's user on the cron or at deny lists.
Session and signal-cleanup tests cover this; the machine must still be destroyed after one job.

### R6. The agent's instructions come from files it cannot change

Partly met. The host configuration and Claude managed settings are
root-owned; the task arrives from supervisor memory over ACP. Agent
instruction files and opencode configuration in the sandbox home remain
writable by the agent. A caller must take its task and configuration from
a trusted ref, not an untrusted pull request's merge commit.

### R7. What leaves the sandbox is checked data

The supervisor reads agent files with size bounds, as its own user with
`--runner-home` (where the agent is the same user and could change
anything `run` holds), turns the working tree into a patch with hooks disabled, redacts evidence
and gates uploads. `collect`, gh-aw's collector ported, sanitizes requests; `check` enforces
policy and parses the patch. The exit state is untrusted, and patch
authorship is not validated
([#22](https://github.com/cgwalters-forge/agentic-job/issues/22)).
See [safe-outputs.md](safe-outputs.md) for the rules and corpus tests.

### R8. Steps that hold credentials read only what was handed over

Uploads read the supervisor's gated output directory. Apply reads checked
outputs on another VM and executes no agent-produced code. The runner
still owns job credentials and can read its own files after the lock:
this requirement describes the workflow's data flow, not everything that
user could do.

### R9. Actions are pinned, and none runs in the sandbox

External actions in the workflow are pinned by commit. The binary is
fetched by a checksum at that commit when the release source digest
matches, or built from that source. Pinning is maintained by review;
there is no compiler enforcing it on caller workflows.
[`workflows check`](workflows-check.md) refuses unpinned actions in
a repository that runs it. Downloads performed by an
action require separate review.

### R10. What the guarantees depend on

The host's dependencies are secure-host's
([R10 there](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/threat-model.md#r10-what-the-guarantees-depend-on)).
Trust and protect the caller ref containing bounds and setup configuration.
Give each job minimal permissions; notification and apply jobs inherit
the caller's grant. Limit an apply environment to trusted refs. Targets
must be public for runner execution; a policy-level private opt-in does not
override the launch refusal ([private repositories](private-repositories.md)).
[workflow.md](workflow.md) explains these settings.

### R11. Lints are not boundaries

As for any job ([R11 there](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/threat-model.md#r11-lints-are-not-boundaries)). For the
agent, sandbox entry drops the job environment regardless of a caller's
secrets, shell or environment. This is not isolation from same-UID state.

### R12. Untrusted text never becomes privileged code

Workflow inputs pass through environment values and file arguments, not
script interpolation. Policy validates repository and base names;
configuration composition treats inputs as values, not TOML. Event text
is sanitized and fenced. Tests cover validation and composition; review
must preserve the workflow's handling of new inputs.

### R13. Nothing the sandbox produced is run with privileges later

Check and apply use fresh VMs and treat artifacts as data. The reusable
workflow uses no build cache. Apply trials the patch on a fetched base
ancestor and compares changed paths, with rename detection disabled.
Top-level dot-folders are protected by default. Caller bounds may exempt
`.github`, and only it, for pull requests to repositories they name exactly,
including fix pushes to an open PR's branch in apply's own fork; git configuration
and the other fixed patch refusals remain protected. Apply never executes the
workflows it pushes, but the target's own `pull_request` CI runs a fork pull
request's edited workflows before anyone reviews them. So the output check
is not the gate against bad workflow edits, and this project provides none:
an operator who exempts `.github` must first require approval of workflow
runs for all external contributors, keep the apply account neither a member
nor a collaborator of the target, keep self-hosted runners unreachable
from fork pull requests, and supply any workflow check at PR ingress, with
review before merge.

### R14. Generated files are checked by code a pull request cannot change

Compiler-only requirement; there are no generated workflow files here.
The replacement is a reviewed commit pin and protected caller refs.

### R15. Untrusted text is reviewed before an agent is given it

Outside this project. Whatever starts runs may review incoming text.
The sandbox must hold when that review is absent or wrong.

### R16. The agent's writes are capped, checked outputs applied elsewhere

Policy caps output types, counts and patch size before the agent starts.
Pull requests are drafts unless bounds open complete work ready; analysis runs cannot request one. Collector and
policy checks run on a clean VM before apply. Apply credentials are the
job token or an environment secret, not tokens minted per run.
Event bounds restrict actors and forks, and can end at a deadline. See
[events.md](events.md#deadline).

## Evidence and non-goals

CI uses the scripted agent for E2E runs, mutation tests for host probes,
mock inference servers and a corpus of requests and patches. Real-agent
deployment evidence is reported in the [workflow guide](workflow.md#what-has-run-and-what-has-not),
not implied by unit tests. This documentation review did not run hosted
workflows or verify remote deployment state.

This is not a kernel boundary, protection from trusted maintainers,
confidentiality for public data, or an availability guarantee. Reads can
carry data out through GET requests, and local DNS services may also
provide an exfiltration path. The agent can consume the machine until
its limits stop it. Remaining work is in [plan.md](plan.md).
