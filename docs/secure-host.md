# Securing the CI host

> This text is LLM generated.

An agent is one more untrusted step of a job, like a build script from a
pull request. secure-host hardens the host before such steps run, agent or
not. Start with a fresh, disposable runner from a trusted image without
arbitrary privileged helpers. Setup checks known privileged binaries; it
does not inventory the filesystem for setuid-root programs. The default
check fails the step if a probe fails; a pass is evidence for the case
probed, not proof that the runner image meets that prerequisite.

On GitHub, the step is the action
[`cgwalters-forge/actions/secure-host`](https://github.com/cgwalters-forge/actions/blob/main/secure-host/README.md),
which runs the attested, digest-pinned image this repository builds. Its
documents are the reference for what setup does to the host
([further reading](#further-reading)). This page covers using it, and
what agentic-job adds on top.

## Example: harden a deterministic job

Use a fresh runner from a trusted image as described above. Install any
system packages before the hardening step. Replace `COMMIT` with a reviewed
commit and `make check` with your repository's test command:

```yaml
on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-26.04
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - uses: cgwalters-forge/actions/secure-host@COMMIT
        with:
          egress: write-policy
      - run: make check
```

The direct action's `egress` input overrides `egress.write-policy` in a
custom TOML file. Use `egress: write-policy` as shown to enable write
filtering; the default `off` disables it even if the file sets it to `true`.
The [forwarder](#inputs-and-outputs) takes that setting from TOML instead.

Later steps run as the runner's user, which is also the agent's user.
Losing root does not hide the job's tokens from them, so keep write
credentials in other jobs, as the reusable workflow does
([token boundaries](workflow.md#which-tokens-reach-what)).

## What a later step can rely on

These controls assume a fresh, trusted runner image without arbitrary
privileged helpers. A passing check does not establish that prerequisite.

| After the step | Unless |
| --- | --- |
| No general-purpose sudo, root group membership or access to the container daemon socket. A limited sudo grant to the root-owned probe helper remains | `host.lock-runner = false`, which also turns off the rows below but the world-write one |
| No connection to the cloud metadata service | `host.deny-runner-metadata = false` |
| A world-writable file or non-sticky directory on the root filesystem changes only by its owner. Other filesystems, such as a tmpfs, are outside the policy | |
| A process of the runner's user cannot read the environment of another (`/proc/PID/environ`), the Worker among them, unless it is that process's ancestor or the Worker itself. Command lines and `status` stay readable | `host.deny-runner-reads = false`, or off the image, the loader ran without `--deny-runner-reads` ([below](#on-a-host-without-a-github-actions-runner)). On the pinned image a forced core dump still exposes them ([below](#what-main-has-that-the-pinned-image-does-not-yet)) |
| The Worker's diagnostic socket is unlinked | `host.unlink-worker-diagnostics = false`; independent of the row above |
| HTTP(S) requests of the runner's user go through the egress proxy and its write rules | Write filtering is off by default; enable it through the interface you call ([direct action](#example-harden-a-deterministic-job), [forwarder](#inputs-and-outputs)) |

The write policy is not exfiltration prevention. Reads (GET, HEAD,
OPTIONS) pass to most hosts and can carry data in their URLs, the
runner's own writes to the Actions service and artifact storage are
allowed, and DNS to the configured resolvers, connections open before
setup and configured direct endpoints, such as an inference broker on the
tailnet, pass outside the proxy
([`policy.rs`](../crates/secure-host/src/proxy/policy.rs),
[`network.rs`](../crates/secure-host/src/network.rs)).

Unless `check: false`, `sandbox check` probes these and fails the step if
a probe fails; it checks the diagnostic socket only when its row is on. It
does not probe the runner-read rule: the image's loader enables and proves
that one.

Every later step shares one uid and one trust level, so each can read
what another left in the workspace, the environment or the job's tokens
([threat model](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/threat-model.md#what-a-later-step-can-count-on-and-what-it-cannot)).

## Inputs and outputs

This repository's own action, [`secure-host/action.yml`](../secure-host/action.yml),
forwards to a pinned commit of that action with these inputs, all optional.
Set `egress.write-policy = true` in its TOML configuration to enable write
filtering. The forwarder translates that setting to the direct action's
`egress: write-policy` input; it does not expose a separate `egress` input.

| Input | Default | What it sets |
| --- | --- | --- |
| `config` | [hosted.toml](../secure-host/hosted.toml) on Ubuntu 26.04, [rhel-cloud.toml](../secure-host/rhel-cloud.toml) on RHEL 10 | A TOML file with the `[host]`, `[egress]` and `[setup]` tables. Your file replaces the default whole. The pinned image reads `[host]` only under its deprecated name `[sandbox]` |
| `check` | `true` | `false` skips `sandbox check` after setup. The pinned action does not pass `--record`, so either choice leaves no [check record](sandbox-check.md) for a later check to reuse |
| `image-archive` | none | An image archive, as `podman load` takes it, run unverified in place of the pinned image: for a job that built it |

It has no outputs. The inputs it had before forwarding, such as `lock` or
`sandbox-user`, now fail the step rather than set up another host than
the one asked for. The forwarder also refuses a `config` with a backslash
outside a comment or a multi-line string, which could set
`egress.write-policy` in a way it does not read.

## Supported hosts

| Host | Pinned image | Current source |
| --- | --- | --- |
| Ubuntu 26.04 | yes | yes |
| RHEL 10, including minor releases | yes | yes |
| CentOS Stream 10 | no | yes |

Admission reads `ID` and `VERSION_ID` in `/etc/os-release`; `ID_LIKE`
never admits a host. Ubuntu 26.04 is the only host with runtime
evidence; RHEL admission is not proof that every control works there.

### What main has that the pinned image does not yet

The forwarder gets these changes only with the next pinned image:

| Change | Effect |
| --- | --- |
| CentOS Stream 10 admitted | Uses `rhel-cloud.toml`, which also stops cockpit, sssd-kcm, gssproxy and sshd |
| Core dumps discarded under `host.deny-runner-reads` | Stops a step forcing a dump of another runner process to read its memory ([#1618](https://github.com/cgwalters-forge/agentic-job/issues/1618)). Every job on the host loses its core dumps; set `host.deny-runner-reads = false` if you need them |
| Ubuntu package downloads share a 45-second deadline | The failure names the stage that timed out |

## On a host without a GitHub Actions runner

On a GitLab or Forgejo runner, a self-hosted machine or a VM of your own,
run the binary directly. Use a fresh, disposable host from a trusted image
without arbitrary privileged helpers. These commands change users, sudo,
services and firewall rules, so never run them inside an existing sandbox.
Follow the [release manifest verification recipe](gitlab.md#pinned-release-binaries),
then check `secure-host-x86_64-unknown-linux-musl` against `.sha256["secure-host"]`
and `world_write.bpf.o` against `.sha256["world_write.bpf.o"]` from the same
verified manifest before installing either asset. Check the
[loader prerequisites](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/world-write.md#loading).

Save this as `host.toml`, replacing `runner` with the existing non-root job user:

```toml
[host]
runner-user = "runner"
deny-runner-reads = false
```

Run the setup commands from the job user's shell with sudo, and run the
check as that same user without sudo. The check reads the installed
configuration, not `host.toml`:

```sh
sudo secure-host world-write /path/to/world_write.bpf.o
sudo secure-host setup --config host.toml
secure-host check
```

The loader needs kernel BTF and installs bpftool if missing. It leaves the
runner-read rule off unless given `--deny-runner-reads` (and
`--sole-worker` when the Worker did not start it); setup never loads that
rule itself. `agentic-job secure-host world-write`, `agentic-job sandbox
setup` and `agentic-job sandbox check` do the same and also prepare the
agent's part.
A runner whose jobs run in a container the job does not own cannot be
hardened this way. `host.isolation = "external"` disables managed setup and
declares isolation that the runner host must supply itself
([external host isolation](gitlab.md#explicit-external-host-isolation)).

| Without | What changes |
| --- | --- |
| A `Runner.Worker` process | The runner-read rule exempts exactly one Worker, so where the image's loader runs, set `host.deny-runner-reads = false`. Setup skips unlinking the Worker's diagnostic socket and says so |
| sudo from the runner's user | Set `host.runner-user` to the non-root user whose job to harden |
| `RUNNER_TEMP` and `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_JOB` | No [check record](sandbox-check.md), so every check runs its probes |

## The agent job

The reusable workflow's agent job runs the same step, then the
configuration's `setup.script`, then the agent, both as the runner's user
(`run --runner-home`). Nothing stands between the agent and the job's own
credentials, so the job holds only the broker's run token and, by default,
a read-only forge token. A separate job registers with the inference
broker ([the run token](workflow.md#the-run-token)), and another machine
checks what the agent hands back ([safe outputs](safe-outputs.md)).

With an image built from this source (`image-archive`), the job first runs
`sudo agentic-job sandbox prepare` to install the agents; the pinned image
rejects the prepared configuration until
[#2656](https://github.com/cgwalters-forge/agentic-job/issues/2656).

### The egress write policy for an agent job

Without the
[egress write policy](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/egress.md#egress-write-policy-opt-in),
the runner's user can write anywhere but the metadata service. An agent
run with the egress proxy on requires it: `agentic-job config` turns it on
when unset and refuses an explicit `false`. The workflow's
`egress-write-policy` input requests it too.

The policy holds the agent, the setup script and every later step. Because
the agent is the runner's uid, it also gets the runner's own write rules:
the Actions service, and PUTs to the artifact storage accounts listed in
[the proxy's policy](../crates/secure-host/src/proxy/policy.rs). The agent
job refuses a private caller or target with the policy on
([private repositories](private-repositories.md#opting-in)).

`run`'s own requests go through the proxy too. The one built-in exception
is an inference broker on the tailnet. A provider's API or a broker at a
public address needs a `[[write]]` rule of yours.

### The runner-only launch gate

Because the agent shares the runner's uid, it can read whatever another
process of that uid holds. The run action's `runner-gate: true`
(`run --runner-gate`, off by default) checks the host as that uid before
starting the agent: credentials in environments, command lines and known
files, sudo and root-equivalent groups, memory reads, the Worker's
diagnostic socket and egress around the proxy. It refuses to start the
agent if any check fails, naming each missing control in the job log
without printing a value. A refusal is not worth retrying on the same
host: `run` exits 2 before writing any output, so the run action's `exit`
is 2 with no `failure-class` or summary ([outputs](stable-interfaces.md)).

To pass, a job needs `egress.write-policy`, no `github-token`,
`persist-credentials: false` on checkout, the lock's defaults, Yama scope 3
(irreversible until reboot), IPv6 disabled at boot, no subordinate uid
allocations and the runner's registration out of the uid's reach. No
hosted configuration passes yet; do not turn off the runner-read rule to
make one pass. The reusable workflow's `runner-gate` input turns the gate
on; a gated caller also sets `github-reads: false`, since the agent's job
token fails the gate. `dispatch.yml` does both for a non-scripted run of a
caller whose `RUNNER_GATE` variable is `true`. [`run/gate.rs`](../crates/agentic-job/src/run/gate.rs)
documents each check.

## The secure-host binary

`crates/secure-host` builds `secure-host`, the host's side with nothing
that runs an agent: `supported`, `apt`, `world-write`, `setup`, `check`,
`config`, and `image`, the image's entrypoint. Its
[command line](../crates/secure-host/src/cli.rs) and
[configuration](../crates/secure-host/src/config.rs) document the rest.

## Where the binary and image come from

A release pushes `ghcr.io/cgwalters-forge/secure-host:vVERSION`, a
`FROM scratch` image with the static binary and `world_write.bpf.o`
([`Containerfile`](../secure-host/Containerfile)), and attests it by digest
from `release.yml` on main. The action verifies that attestation before it
pulls the image. Releases and main's attested build artifacts also carry
`secure-host-x86_64-unknown-linux-musl`, with its checksum in the attested
manifest beside agentic-job's.

The reusable workflow fetches the binaries with
[`binary.sh`](../secure-host/binary.sh), which verifies the manifest's
attestation and every checksum and stops the job on any mismatch
([binary trust model](workflow.md#things-a-caller-should-know)).

## Further reading

The action's documents describe the host in full:

| Topic | Document |
| --- | --- |
| The contract and its caveats | [README](https://github.com/cgwalters-forge/actions/blob/main/secure-host/README.md) |
| What a later step can count on | [threat model](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/threat-model.md) |
| What setup changes, the lock, containers | [setup](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/setup.md) |
| The egress proxy and write policy | [egress](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/egress.md) |
| The world-write policy and its loader | [world-write](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/world-write.md) |
| Reads between the runner's processes | [runner reads](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/runner-reads.md) |
| What `sandbox check` proves | [probes](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/probes.md) |
| Where each probe has been seen to fail, timings | [evidence](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/evidence.md) |
