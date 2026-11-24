# Run an agent on a hardened host

> This text is LLM generated.

Use a fresh, disposable runner for each agent job. The agent runs as the
runner's user, not in a container launched by managed setup. The agent can
use tools and devices available to the runner user, such as rootless Podman
and `/dev/kvm`.
The host hardening restricts what the job can do; it does not hide the job's
files or credentials from the agent.

## Choose how to isolate the job

| Setup | What to do |
| --- | --- |
| Managed GitHub job, default image | Use the [reusable workflow](workflow.md). Its host step uses the [pinned v0.6.9 image](secure-host.md#deployed-write-policy-diagnostics) by default. Setup creates a separate account by default, but the agent does not use it. See the `egress.policy` prerequisite below. |
| Managed GitHub job, current-source test image | The reusable workflow's test-only `secure-host-image-artifact-id` takes a [compatible host-only image archive](secure-host.md#the-agent-job) from the calling run. Use only an archive from a trusted build: setup runs it as root without the default image's attestation check. Current-source setup does not create a separate account. |
| Managed standalone host | Follow [standalone host setup](secure-host.md#on-a-host-that-is-not-a-github-actions-runner) on a supported disposable host. Load the matching `world_write.bpf.o` before running `sudo /usr/local/bin/agentic-job sandbox setup --config FILE` (use the installed binary's absolute path). Current-source setup does not create a separate account. If starting from a root shell or systemd rather than using sudo as the runner, set `host.runner-user` to the existing non-root runner user. |
| Externally isolated runner | With `[host] isolation = "external"`, do not run `sandbox setup` or `sandbox prepare`. Disable the local proxy (`egress.proxy = false`). [Mount the trusted run config read-only](interface.md#files-read) and pass it to `run --config`. Use one job per fresh runner, enforce an outbound allowlist that blocks cloud metadata, and do not expose a host engine socket or extra credentials. Declaring or detecting external mode does not verify those controls. See [external isolation and GitLab detection](gitlab.md#explicit-external-host-isolation). |

The [GitLab trial](try-gitlab.md) demonstrates publication, not agent execution.
The [Forgejo trial](try-forgejo.md) checks a scripted handback without an agent.

## What setup does for an agent

The pinned image and standalone `sandbox setup` install configured tools,
write agent settings that `run` checks, and apply the
[host protections](secure-host.md). With a compatible host-only image, the
workflow does the agent setup separately before hardening. The steps below
show what the workflow does, with `RUN.toml` standing for its run configuration:

```sh
agentic-job config --host --prepared --from RUN.toml > "$RUNNER_TEMP/HOST.toml"
sudo /usr/local/bin/agentic-job sandbox prepare --config "$RUNNER_TEMP/HOST.toml"
```

The workflow then passes the same file's absolute path to the host step as `config`.
The default v0.6.9 image does its own preparation and rejects `[host.prepared]`.
See [the agent job](secure-host.md#the-agent-job) for image compatibility.

Keep setup inputs under caller control. The reusable workflow runs `setup.script`
after hardening, as the runner user in the agent's home with `host.env`.
`agentic-job config --host` omits the script; `sandbox setup` rejects a host
configuration that includes it. Agent commands start in the directory passed
to `run --runner-home` with a clean environment and caller overrides from
`host.env`. This is not a credential boundary.

### Who installs the agents

| Installation | What to configure |
| --- | --- |
| Pinned workflow default | The reusable workflow selects pinned OpenCode or Claude packages with `setup.agents` unless you supply `npm`. This installer verifies the pinned packages and does not run npm install scripts. The bundled native packages target Linux x86-64 with glibc; Claude also needs Node.js. |
| Managed Vibe | Set `agent.name = "vibe"` to select the managed Vibe installer. You do not need a `setup.agents` entry for Vibe. |
| Caller-selected npm packages | Install npm on the host and use exact `NAME@VERSION` entries in `setup.npm` (the workflow's `npm` input). npm resolves transitive dependencies at setup time and can run install scripts as root, before network lockdown. Never take this list from a task or target checkout. |
| Caller-installed OpenCode or Claude on a standalone host | Install in a trusted step before hardening and before credentials arrive, never from the target checkout. Leave `setup.agents` and `setup.npm` unset or empty in the standalone configuration. Put the executable on the effective `PATH` (`/usr/local/bin:/usr/bin:/bin` by default, overridden by `host.env.PATH`). Protect the search directories, executable, symlink targets and dependencies from changes by the runner user. |
| External runner image | Install the agent and its dependencies in the image, including an `env` that supports `-C` (such as GNU `env`). For Claude, a trusted build step must produce `/etc/claude-code/managed-settings.json` from the same run configuration. See the [`managed_settings` Rust function](../crates/agentic-job/src/run/agent.rs#L1555-L1565); it takes the agent kind and inference endpoint, not a TOML file. `run` checks the exact bytes; keep the file unwritable by the runner. For Vibe, provide the virtual environment at `/opt/agentic-job/vibe`, the same path managed setup uses. |

Leaving `npm` empty in the composed workflow is not the same as leaving
`setup.npm` empty on a standalone host. The workflow can still select a
pinned package that replaces or shadows the caller's executable. See
[agent adapters](harness.md#agent-adapters) for the supported agents.

### Network access

| Setting | Effect |
| --- | --- |
| `egress.write-policy` | Applies the proxy's write restrictions to the runner user, including [built-in GitHub Actions write allowances](secure-host.md#the-egress-write-policy-for-an-agent-job). When composing a run configuration with the proxy enabled, `agentic-job config` turns this on if unset. `run` refuses to start an agent with the proxy enabled but this policy disabled. |
| `egress.proxy = false` | Turns off proxy filtering. On a managed host, metadata blocking is separate (`host.deny-runner-metadata`); on an externally isolated runner, network restrictions are your responsibility. |
| `egress.policy` | Points to a proxy policy file. The default destination mode, `reads-anywhere`, permits reads to public destinations not on the threat feed. In that file, set `[egress]` with `mode = "allowlist"` and `allow` to restrict reads as well as writes. It accepts domains (including their subdomains) and gh-aw ecosystem names, up to 256 domains after expansion. It rejects IP literals. Allowlisting a domain does not grant permission to write to it. With the default v0.6.9 GitHub image and `egress.write-policy` enabled, the image's check requires a successful read of `https://example.com/`. Include `example.com` in the allowlist or use a compatible trusted current-source image. |
| `egress.direct` | Lists exact tailnet IPv4 addresses and ports reachable without the proxy under write policy. Use only for trusted endpoints such as the [inference proxy](inference.md), so the run token does not cross the egress proxy. |
| `host.close-resolved` | Off by default. On systemd 258 or later, restricts local access to systemd-resolved's interfaces to close a DNS path around the proxy for other local users. The runner user retains resolver access, so this does not close every DNS path for the agent. |

The proxy cannot reach private or local networks, even when an allowed name
resolves there. An allowlist entry does not make a private-network forge
reachable. Managed setup does not configure Podman networking or trust. See
the [full Podman recipe](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/setup.md#containers)
for network flags, CA bundle paths and proxy variables. Keep TLS verification enabled.

## What is tested

The GitHub host step runs the selected image's check before the agent starts.
For managed standalone setup, run `agentic-job sandbox check` as the runner
user with the binary that set up the host. These checks probe configured host
protections, including the lock, metadata blocking, world-write policy and
proxy write refusal. Current-source checks choose a read probe according to
the configured policy, which need not admit `example.com`. Check the output
for skipped probes as well as failures. These probes do not show that the
agent cannot read the run token. See [sandbox checks](sandbox-check.md) for
probe coverage and failure diagnosis.

## Keep credentials and publishing separate

Assume an agent can be induced to follow instructions in an issue, log, or
checkout. Do not place anything in its job that it must not read. `run` refuses
identity-token request credentials, inference provider keys, MCP credentials,
`inference.front`, private targets, and `[child-agent]` with the runner-user
model. The [run token](workflow.md#the-run-token) is for the agent to use.
In an [interactive session](../specs/session.md), the agent can take the
connection slot before the operator. The session bridge does not authorize
publishing.

The same-user agent can interfere with the harness and its local limits. A
local timeout is not whole-job containment: cleanup stops only the agent's
process group, and processes outside it can continue until the runner is
torn down.

Run [check and apply](safe-outputs.md) on machines separate from the agent
job. Treat its files, transcript, and output requests as untrusted. Host
hardening does not protect privileged workflow steps that execute proposed code
outside the agent job. On GitHub, require human approval of the current pull
request head before admitting it to the [merge queue](workflow-ingress.md#merge-queue),
which can run proposed code with write and identity-token permissions.
