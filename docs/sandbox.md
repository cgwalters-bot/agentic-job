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
  pin is refused, and the pins are for Linux on x86-64 with glibc;
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
agent's home, with a fixed `PATH` and `LANG`, the user's names and
`host.env`; a variable named `ACTIONS_*` (the job's identity-token
request is two of them) is refused by name in the configuration. That
keeps `run`'s own variables out of what the agent's commands get, not
what the agent could read from `run`'s process: there is no uid between
them.

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
