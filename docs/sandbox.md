# The agent on a hardened host

> This text is LLM generated.

What `agentic-job sandbox setup` adds to a host for an agent, and why.
The host itself (what setup changes, the lock, the network rules and the
egress proxy) is documented with the action that runs it:
[setup](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/setup.md#what-the-step-does-to-the-host),
[egress](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/egress.md)
and the
[threat model](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/threat-model.md#what-it-assumes).
The code is `crates/secure-host/`, `crates/agentic-job/src/sandbox/` and `egress/`
([layout](layout.md)); `run`'s probes are in
[sandbox-check.md](sandbox-check.md), the requirements it serves in
[requirements.md](requirements.md), and how a workflow calls it in
[workflow.md](workflow.md).

The agent is treated as a hostile process. It reads text that anyone can
write (issues, pull requests, CI logs, a repository's own files), so the
design assumes prompt injection succeeds. What then matters is what the
process can reach. The agent is the runner's own user, in the home
`run --runner-home` gives: since
[#2989](https://github.com/cgwalters-forge/agentic-job/issues/2989) setup
creates no second user, and the job is the unit of trust. The agent can
read whatever the runner's user can, so the job holds nothing the agent
may not have; `run` refuses what only a second user could keep from it
(an inference provider's key, an MCP credential, `inference.front`, a
private target, `[child-agent]`). `session.listen` is taken: the agent
can attach to its own session's bridge ahead of the operator, which
denies the operator the chat but gives it no credential or write: no
message over the bridge authorizes one ([session runs](../specs/session.md)).
It can also interfere with `run`, its transcript and limits, so check and
apply must run on separate machines. `hidepid` hides **other users'**
processes; it is not a same-UID credential boundary, and neither a clean
environment nor keeping a key in `run`'s memory changes that.

This protects against the agent, not an untrusted workflow running
outside it. A merge queue executes proposed workflow files and code
with write and OIDC permissions before landing. The
[ingress checker](workflow-ingress.md#merge-queue) vets each merge group, but
the group's own workflow definition runs it; human approval before enqueueing is the trust gate, including for
workflow steps that build or execute the proposed binary outside the agent's run.

## Why not a container

gh-aw runs the agent in a container behind a firewall, with the
container runtime's socket hidden. The work this was built for is on
bootable containers: it builds images with rootless podman and boots
VMs through `/dev/kvm`. Those need the host, or a container weakened
until it is no longer the boundary
([background](https://github.com/cgwalters-forge/gh-aw/issues/1)). So
the host is hardened and the agent runs on it as the runner's user,
with whatever podman and devices that user has.

## What setup does for an agent

Besides the host's setup, `sandbox setup` does the following. Before a
secure-host image that holds no agent code, `sandbox prepare` does it
alone, as root, and installs agentic-job as the helper that the image's
setup keeps ([the agent job](secure-host.md#the-agent-job)):

- installs `setup.npm`, as root and on the open network; npm versions
  must be exact;
- installs `setup.agents` from npm tarballs pinned in the binary
  ([pins](../crates/agentic-job/src/sandbox/setup/agents.toml)): every package of each agent by its
  SHA-512 integrity, unpacked by `agentic-job` into
  `/opt/agentic-job/agents` with no npm and no install script, its
  programs linked in `/usr/local/bin`; a tarball that does not match its
  pin is refused, and the pins are for Linux on x86-64 with glibc
  ([proposed deprecation](#who-installs-the-agents));
- writes the agent's managed settings, which `run` checks.

It runs no `setup.script`: the reusable workflow's agent job runs it
after setup, as the runner's user, in the agent's home and with
`host.env`. A host's file (`agentic-job config --host`) leaves the
script out, and setup refuses one that has it. The keys of the removed
second user (`host.create-user`, `host.user`, `host.groups`,
`host.allow-existing-user`, `host.filesystem-view`,
`host.check.before-agent`, `setup.tools`) are refused by name.
`[host]` was `[sandbox]` before #2071; that name is still read, with a
warning, but not beside `[host]`
([stable interfaces](stable-interfaces.md#configuration-files)).

On a fresh disposable supported host, first load the matching world-write
object as described in [standalone host setup](secure-host.md#on-a-host-that-is-not-a-github-actions-runner);
`sandbox setup` does not load it and refuses to proceed without its pins.
Start setup with sudo as the runner's user, or from a root shell or a
systemd unit after boot. For the latter two, set `host.runner-user` in
the configuration to the existing non-root user whose job this is. A unit:

```ini
[Unit]
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/agentic-job secure-host world-write /path/to/world_write.bpf.o
ExecStart=/usr/local/bin/agentic-job sandbox setup --config /etc/agentic-job-setup.toml

[Install]
WantedBy=multi-user.target
```

`egress.direct` lists endpoints reached without the proxy, each an IPv4
address and port on the tailnet; it is for the
[inference proxy](inference.md), so that the run token never crosses the
egress proxy. Under `egress.write-policy` the runner's user, and so the
agent, reaches each of them and no other tailnet address.

`host.close-resolved`, off by default, closes systemd-resolved's
Varlink socket and system-bus interface to every user but root and, on
the bus, the runner's. resolved answers any local user there and asks
upstream as itself, so a name lookup (`DATA.attacker.example`) can carry
data out around the egress proxy. It needs systemd 258 or newer. Both
`hosted.toml` files set it: the action's default
(`secure-host/hosted.toml`) and the workflow's
(`.github/agentic-job/hosted.toml`). The egress policy file, the shipped
one or `egress.policy`'s in its place, may set `[egress] mode = "allowlist"`
with `allow`, at most 256 domains or gh-aw ecosystem identifiers
(`egress/policy.py`): every destination, reads included, must then be one
of them or under one, and an address literal is refused. The default,
`mode = "reads-anywhere"`, lets a read go to any host not on the threat
feed.

Past DNS, the egress proxy never connects to the ranges in
`PROXY_DENIED_V4` and `PROXY_DENIED_V6`
(`crates/secure-host/src/network.rs`): loopback, the private ranges,
link-local, the tailnet, multicast, some reserved ranges and Azure's
WireServer. The rules for its uid refuse them whatever a name resolves
to. The Rust proxy also checks the resolved addresses and answers 403
with `X-Egress-Denied: destination is on a private or local network the egress proxy never reaches`
if any is in those ranges, rather than the unexplained 502 an
in-cluster inference name previously received
([#1810](https://github.com/cgwalters-forge/agentic-job/issues/1810)).
Under an `[egress]` allowlist the policy refuses an address literal
anyway, unless `--refuse` refuses it first; both keep precedence over
the private-network reason, and a name the policy refuses is not resolved.
A forge on a private network has no way in: `run` clones the target from
the `https://` (or `allow_http`) URL `policy` admitted for a host of the
caller's bounds, and nothing prepares a clone for it before network
lockdown. Whether to allow a named private destination is open
([#1812](https://github.com/cgwalters-forge/agentic-job/issues/1812)).

`run` starts every command of the agent's through `env -i` in the
agent's home, with defaults for `PATH` and `LANG`, the user's names and
overrides from `host.env`; a variable named `ACTIONS_*` (the job's identity-token
request is two of them) is refused by name in the configuration. That
keeps `run`'s own variables out of what the agent's commands get, not
what the agent could read from `run`'s process: there is no uid between
them.

### Who installs the agents

The deliverable is the `agentic-job` binary; the agents are the
caller's to install, at versions the caller chooses. `setup.agents` and
its pins exist because `npm install -g` resolves dependencies afresh and
runs their install scripts as root, not so that the binary holds an
opinion on agent versions, which it should not
([#3617](https://github.com/cgwalters-forge/agentic-job/issues/3617)).
The direction is to move installation into the caller's job and retire
the installer. What is implemented: `setup.agents` is the reusable
workflow's default, `pinned-agents` (a development binary, not released)
installs the same pins for `just claude-acp-test`, and the pins name the
only versions this repository tests
([agent adapters](harness.md#agent-adapters)). The stages further down
are a proposal, and the issue, not this page, says how far it has got.

What `run` asks of an installed agent, whoever installed it, from the
launcher and setup code:

- For agents found by name, `launch-agent` searches the effective `PATH`:
  `/usr/local/bin:/usr/bin:/bin` by default, unless the trusted `host.env.PATH`
  overrides it. The runner's user must be able to execute the program.
  `run` checks its own binary's path before it clones, not the agent's;
  an agent that is missing fails the run when the session starts it.
- Install it in a trusted caller-owned step before hardening and before
  credentials arrive, never from the target checkout or from inputs the
  task controls. Secure-host hardens the default `PATH` directories and
  their ancestors, not the programs or their dependencies. The caller
  must keep the executable, any resolved symlink target, and its runtime
  dependency tree in locations the runner's user cannot modify or replace.
  If overriding `PATH`, also protect the search directories and their
  ancestors so the agent cannot put another program ahead of the intended one.
- The agent's managed settings and run configuration come from
  `sandbox setup` or `prepare` and from `run`, both from the same
  configuration, whatever installed the agent
  ([what a move must keep](harness.md#what-moving-a-shim-out-must-keep)).
  Where neither setup command runs, Claude's managed settings must
  still be there; see the runner-image case below.

How a caller installs one today, from most to least pinned:

- `setup.agents`, the default: the reusable workflow sets it to the
  pinned `opencode-ai` or `claude-agent-acp` unless the caller's `npm`
  input replaces it.
- `setup.npm` with exact `NAME@VERSION` pins (the `npm` input): npm
  installs them as root on the open network, with their install scripts,
  and resolves transitive dependencies afresh.
- On a standalone host with caller-owned configuration, install opencode
  or `claude-agent-acp` before setup, or use `setup.packages` if the
  distribution packages it. Leave both `setup.agents` and `setup.npm`
  unset or empty in the configuration passed to setup. The existing
  [composed-job example](workflow.md#the-pieces-and-an-agent-job-of-your-own)
  does not do this: policy adds the pin for opencode
  or Claude when `npm` is empty, even when `packages` is set. Its installer
  can replace a caller's entry in `/usr/local/bin` or shadow a program in
  `/usr/bin` on the default `PATH`. A composed caller-install example is
  proposed below, and no test yet drives a caller-installed version
  outside the tested pins.
- The runner image alone, under `[host] isolation = "external"`
  ([external host isolation](gitlab.md#explicit-external-host-isolation)):
  no setup runs there, so the image holds the agent, and Vibe's
  virtualenv at the path below if Vibe is the agent. The agent alone
  is enough only for opencode and Vibe. For Claude, `run` also reads
  `/etc/claude-code/managed-settings.json` and refuses the run before it
  starts the adapter unless the file is byte for byte what `sandbox setup`
  would write for the run's `[agent]` and `[inference]` configuration.
  The trusted image builder must supply that file, and it must not be
  writable by the runner's user: `run` compares the content but does not
  check who owns the file, and external isolation does not protect it.
  No command prints the file on its own; `sandbox setup` and
  `sandbox prepare` write it from the same configuration.
- Vibe, under setup, by none of the others: setup installs the pinned
  `mistral-vibe` into a root-owned virtualenv at a fixed path,
  `/opt/agentic-job/vibe`, which the launcher names. A caller cannot put
  Vibe elsewhere until the launcher is moved out or taught where to look.

Runtime dependencies, as the source has them, not as a contract: the
`agentic-job` release is a static musl build with rustls, so the binary
itself needs no OpenSSL or glibc on the host; `run` needs `git`,
`getent` (its own libc reads only `/etc/passwd`) and a POSIX `sh` with
coreutils (`env`, `test`, `timeout`, `mkdir`, `chmod`, `rm`, `cat` and
the like) on the effective `PATH`, and setup needs root once. Its `env`
must accept `-C`, which `run` uses to start the agent in its home; GNU
coreutils does, BusyBox does not. `claude-agent-acp` runs on the host's
`node`; `setup.agents` refuses that agent when there is no `node`, a
check that does not run for an adapter the caller installed. The native
Claude Code executable that ships with the adapter's pinned Claude Agent
SDK, and `opencode`, are binaries for Linux x86-64 with glibc; Vibe needs `python3` with
`venv` (setup installs `python3-venv`) and PyPI at setup time; `setup.npm`
needs `npm`. Any other OS, CPU or libc is untested, and nothing detects
musl on the host.

The staged deprecation, as proposed:

1. **Document.** Describe caller-owned installation as the preferred
   direction. A deprecation notice is proposed, not emitted today;
   `setup.agents` and its lock keep working with the workflow's pinned defaults.
2. **A caller-owned installation example.** A caller installs its agents
   in a step of its own before `secure-host`, with an integrity check of
   what it fetches, the trusted-setup boundary above, and configuration
   that does not install another copy. The first-party
   test pins (`just claude-acp-test`, the Vibe adapter test) move to CI
   fixtures. That way the tests no longer depend on the runtime lock,
   which stage 4 removes.
3. **Decouple discovery from layout.** Launchers find an agent on the
   `PATH` rather than at a fixed path, Vibe's included, and a test drives
   an externally installed agent, without weakening inference routing or
   isolation. Bespoke shims, Vibe's launcher first, move to a project of
   their own; its destination is not chosen here.
4. **Remove.** Once callers have moved, the installer, the embedded lock
   and `just agents-lock` go, and `setup.agents` is refused by name like
   the removed second-user keys. No image with pinned agents becomes the
   primary deliverable; whether an optional binary-only image is wanted
   is open.

### What hardens the agent's user

The lock, the world-write policy, the metadata, Worker-diagnostics and
runner-read rules and, under `egress.write-policy`, the egress proxy's
write rules harden the runner's own user, and every later step runs as
it, the agent included. The second, sandbox user that setup made before
issue 2989 added a uid on top of that; it went because it did not fit
the GitHub Actions ecosystem, where every step and action is the
runner's user.

## What is tested

`sandbox check` probes the host as the runner's user, with positive
controls where the host provides them
([probes](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/probes.md)):
the lock, the metadata rule, the world-write policy, ptrace, the stopped
services, the Worker's diagnostic sockets, the crypto policies and, under
`egress.write-policy`, the proxy's refusal of a write. `sandbox probe
no-user` checks that setup made no second user and left the runner's
sudo the helper's rule alone. `run` makes none of the run token's probes
of [sandbox-check.md](sandbox-check.md#runs-token-probes): the token is in
`run`'s own environment, which the agent can read. CI's `sandbox` job
runs setup and the check for real on hosted `ubuntu-26.04`, then removes
each protection in turn and requires that the matching probes fail
(`tests/sandbox_host.rs`), after showing that setup refuses the removed
keys, a setup script and a host without the world-write policy
(`tests/sandbox_fresh.rs`). What that runner cannot show, and what was
tried by hand elsewhere, is in the action's
[evidence](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/evidence.md#where-each-probe-has-been-seen-to-fail).

## What it does not do

What the host does not stop is in the action's
[threat model](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/threat-model.md#not-claimed)
and [egress](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/egress.md#what-egress-does-not-stop).
For an agent in particular:

- The agent can read whatever the runner's user can: the job's files,
  its environment and `run`'s.
- The egress proxy holds the agent, the runner's user, only under
  `egress.write-policy`. `config` turns it on for a run's file that keeps
  the proxy and leaves it unset, and `run` refuses an agent with the
  proxy on and the write policy off. With `egress.proxy = false` the
  agent's network is the runner's, open but for the metadata service
  under `host.deny-runner-metadata`.
- What the agent leaves running outside its process group runs until
  the job ends: nothing kills every process of the runner's user.
- A container the agent starts has no network of its own. It reaches the
  proxy only on the host's network, and trusts it only if the
  certificate is mounted into it; nothing configures podman to do
  either. Use the
  [container recipe](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/setup.md#containers)
  for networked builds and runs.
- `setup.npm` runs the packages' install scripts as root, which is why
  the list is the caller's and never the task's. `setup.agents` runs
  none, and installs only what a release of this repository reviewed.
