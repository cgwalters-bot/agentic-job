# Comparison with GitHub Agentic Workflows and gh-cao

> This text is LLM generated.

This comparison was refreshed on **2026-11-14** against
[gh-aw v1.2.2](https://github.com/github/gh-aw/releases/tag/v1.2.2), published
**2026-11-10**. The release tag was checked out at commit
`399a445fe2d8926c616b54b1b82a16b5b2be4445`. All gh-aw sources below refer to
that release, not its moving documentation site. This is a source/documentation
comparison, not a live security test or a cost benchmark. It supersedes the
v0.92.6 comparison from [#1625](https://github.com/cgwalters-forge/agentic-job/pull/1625).

The agentic-job column describes this checkout, not every deployed caller.
Its gh-aw compatibility pin is still **v0.91.12-7**, not v1.2.2; refreshing
this comparison does not upgrade the collector fixtures, validation data or
apply handlers ([what is borrowed](safe-outputs.md#what-is-gh-aws-and-why)).

## Where each fits

Choose agentic-job when the work needs a [host-user sandbox](sandbox.md) with
rootless containers, `/dev/kvm` and user namespaces, or when you want one
[ACP session protocol](harness.md) across agents. Its
[secure-host hardening](secure-host.md) removes general root access before
untrusted steps run and can also be used without an agent. Outputs are
[checked on a separate runner](safe-outputs.md) before one apply job publishes
the admitted requests; that job never executes agent-produced code.

The credential boundary is specific: the agent has no provider key or forge
write token, but it can read the job's read-only forge token and broker run
token ([token placement](workflow.md#which-tokens-reach-what)).
[Inference is proxied through a broker on another machine](inference.md).
[Credentialed MCP is refused](mcp.md); the external proxy route is future work,
not a deployed credentialless MCP service.

The CLI also supports a [GitLab policy/check/apply path](gitlab.md) and
[Forgejo comments and pull requests](safe-outputs.md#publishing-to-forgejo).
These are not equivalent to the GitHub reusable workflow: GitLab agent
inference is unsupported, and its current guide is not verified live.

Choose gh-aw when its [workflow catalogue](https://github.github.com/gh-aw/gallery/),
[GitHub-native Markdown authoring and compilation](https://github.github.com/gh-aw/setup/creating-workflows/),
or [community](https://github.com/orgs/community/discussions/186451) fits your
project. agentic-job instead uses [ordinary workflow YAML](workflow.md) and
supports fewer outputs and triggers, as detailed below. Read its
[known limitations](limitations.md) before deploying it.

## Why a host user and not a container

Choose agentic-job when the workload needs a hardened disposable host for
rootless Podman or `/dev/kvm`, an ACP session, and bounded outputs checked on
another machine before publication. Its [sandbox](sandbox.md) treats the
agent as the runner's own, potentially hostile user: the job, not a second
user or a process environment, is the trust boundary. This preserves host
tooling without giving the agent a privileged container daemon socket.
Container builds needing the network require host networking and the proxy's
CA bundle; see the [container recipe](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/setup.md#containers).

Choose gh-aw when its GitHub Actions authoring, built-in integrations and
workflow examples fit the task; its [compiler][gh-compile] constructs the
job graph from Markdown and YAML frontmatter. Its default is a Docker
sandbox, but it also has preview KVM microVM runtimes, so "gh-aw is only a
container" is no longer an adequate distinction ([runtime matrix][gh-runtime]).
Neither model is universally stronger: agentic-job shares the host kernel
and trusts host hardening; gh-aw's default Docker shares the kernel too,
while its preview VMs have different provisioning and compatibility limits.

**Do not call agentic-job credentialless.** In the supported broker path the
provider key stays off the agent machine, but the agent receives a run bearer
token and normally a GitHub read token. Same-UID processes cannot hide keys
from it. Credentialed MCP is currently refused, not safely proxied locally
([inference boundary](inference.md#current-boundary-5-november-2026),
[MCP status](mcp.md#current-status)). No forge write token is given to the
agent; check and apply run on separate machines and do not execute its code.

## Feature comparison

| Feature | gh-aw v1.2.2 (release-pinned evidence) | agentic-job in this checkout |
| --- | --- | --- |
| Sandbox | The default runtime profile is, in gh-aw's words, "Docker runtime, rootless AWF, network isolation"; privileged Docker (`docker-sudo-iptables`), preview Cloud Hypervisor and preview NVX are alternatives. The default hides the Docker socket. [Sandbox][gh-sandbox], [runtime requirements][gh-runtime]. | Hardened disposable host, agent as runner UID; rootless Podman and KVM where provisioned. Same-UID transcript and harness limits are not trusted attestations. [Sandbox](sandbox.md), [harness](harness.md). |
| Inference credentials | Provider credentials can stay in the AWF API-proxy sidecar on the runner, outside the agent container; Copilot Actions-token and provider WIF options also exist. This is not a claim that all configurations are credentialless. [Copilot isolation][gh-copilot], [native-provider routing][gh-routing], [authentication][gh-auth]. | External broker holds the provider key; a separate registration job holds OIDC credentials. Agent still holds a run token and, by default, a read-only GitHub token. Provider-key runner mode is refused. [Inference](inference.md), [job separation](workflow.md). |
| Network egress | Domain/ecosystem allowlists, with a small `defaults` set when omitted and no network for `{}`; blocked entries win. Provider-hosted web tools need separate `hosted-web` policy, not just `network.allowed`. [Network][gh-network]. | Rust egress proxy: by default reads except pinned threat-feed destinations, with rules for writes; domain allowlist is opt-in. Runner-user write-policy enforcement is also opt-in, not an assumed default. [Egress policy](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/egress.md). |
| Safe outputs and deterministic checking | Structured requests via safe-output tools/CLI; collector validates and sanitizes JSONL. Permission-controlled jobs execute enabled operations. Unlike this project, omission of non-system outputs auto-enables `create-issue` unless explicitly disabled. [Safe outputs][gh-outputs], [collector][gh-collector]. | Agent writes JSONL. Rust collector plus `check` on another machine enforce trusted per-type/target bounds, byte/file/path/type caps and secret checks. Every operation is off unless enabled. Agent can run the same handback checks locally. [Contract](safe-outputs.md). |
| Threat detection | Documented default at this tag: automatically enabled once any safe output is configured, running after the agent job and before output jobs. Its default enforcement is warn mode (`continue-on-error: true`): a detected threat or detector failure annotates reviewable outputs, converts branch pushes and aborts only non-reviewable outputs; blocking all outputs requires `continue-on-error: false`. This is the documentation's statement, not a verified live run. [Threat detection][gh-detection], [enforcement modes][gh-detection-modes]. | Opt-in: off unless the caller sets a detection model variable; dispatch inputs cannot enable it. When enabled it fails closed: any threat, malformed verdict, unavailable model or registration error blocks release of the checked artifact and therefore apply. It supplements deterministic checks and is not proof a proposal is safe. [Optional threat detection](workflow.md#optional-threat-detection). |
| Apply | Separate permission-controlled output jobs. PR patch/bundle handling captures bytes and uses private snapshots, with digest/identity rechecks at publication boundaries. That handler-time guarantee alone is not detection provenance or a transaction. [Output jobs][gh-outputs], [transport requirements][gh-transport], [implementation][gh-integrity]. | Apply downloads the artifact ID/digest released by check; base, changed-path and head-lease guards remain. GitHub uses pinned gh-aw handlers plus opt-in native handlers; other forges use native publishers. [Apply](safe-outputs.md#who-applies), [workflow](workflow.md). |
| ACP and sessions | Native engine interfaces and unified session capture; experimental artifact-backed durable sessions for all six built-ins, with engine-specific resume behavior. Restored history can carry prompt injection and does not restore workspace changes or exactly-once effects. ACP support was **not verified** in the reviewed engine contracts. [Engines and durable runs][gh-engines]. | One ACP client drives Claude Code, opencode, Vibe and a scripted test agent. Interactive joining and item-comment steering exist; they do not authorize writes. This is not a claim of equivalent cross-run durable resume. [Harness](harness.md), [agent registry](../crates/agentic-job/src/session/agents.toml), [interactive sessions](interactive.md). |
| Forges and integrations | GitHub Actions/GitHub operations; GHES and data-residency compatibility are explicitly not an end-to-end support commitment. Jira, Linear and Azure DevOps integrations do not establish GitLab/Forgejo execution support, which was **not verified**. [Enterprise scope][gh-enterprise], [output integrations][gh-outputs], [tools][gh-tools]. | GitHub reusable workflow; Forgejo and GitLab have native publication subsets, not full GitHub parity. GitLab policy/check/apply is available, but agent inference there remains unsupported pending broker identity/lifecycle work. [Forge matrix](safe-outputs.md#neutral-profile), [GitLab status](gitlab.md). |
| Repository visibility | Its documentation describes running in and reading from private repositories, given explicit authentication: cross-repository private reads need a PAT or GitHub App. Runtime repository lists (`multi: true`) allow only public targets by default, and in a public workflow repository they cannot select private or internal targets even with such a token; ordinary static checkouts are not restricted that way. Live private-repository behavior was **not verified**. [Private repositories][gh-private], [checkout visibility policy][gh-checkout]. | Public targets only. `run --runner-home` refuses private targets, and the reusable agent job refuses private, internal or unknown callers and targets even when bounds say `private = true`; API errors during the visibility check also refuse the run. [Private repositories](private-repositories.md). |
| Authoring | Markdown instructions and YAML frontmatter compile into Actions `.lock.yml`; body instructions load at runtime, while configuration changes require compilation. Imports compose configuration/prompts. [Compilation][gh-compile], [imports][gh-imports]. | Ordinary YAML calling a pinned reusable workflow, a task, and caller-owned TOML bounds/configuration. No workflow compiler; optional base-trusted workflow shape checking. [Compiler decision](compiler.md), [workflow checker](workflows-check.md). |
| Catalogue size | At this tag: **18 gallery Markdown/MDX pages** and **365 top-level workflow Markdown sources** in the upstream tree, including smoke/conformance/maintenance examples. These are not 365 supported catalogue products. Total installable community catalogue size was **not verified**. [Gallery tree][gh-gallery], [workflow tree][gh-workflows]; counting method below. | No equivalent curated installable catalogue. Repository-owned example callers exist; they are examples, not a promise of tested deployments for every combination. [Caller guide](dispatch.md), [deployment evidence](workflow.md#what-has-run-and-what-has-not). |
| Operational cost | Actions minutes plus provider inference; AIC estimates, logs/audit and runtime credit/turn caps. Estimates are not provider invoices. Operating the default runtime requires Docker and supporting gateway/proxy services. [Cost management][gh-cost], [limits][gh-engines], [runtime prerequisites][gh-runtime]. | Runner minutes plus inference, and an external broker to operate. Budget watcher and offline audit report usage/estimated cost; scheduler-wide admission belongs to callers. Host preparation and separate check/apply jobs also cost time. [Inference](inference.md), [limits](harness.md), [audit](workflow.md#auditing-downloaded-artifacts). **No matched-task dollar, latency or maintenance-cost comparison was measured.** |

The catalogue counts are reproducible from `git ls-tree -r --name-only HEAD`
in the v1.2.2 checkout: count `.md` files directly under `.github/workflows/`
(exclude subdirectories and generated `.lock.yml`), and recursively count
`.md`/`.mdx` under `docs/src/content/docs/gallery/`. Gallery pages can describe
several workflows; the two counts must not be added together or compared as
deployment counts. No live community registry was inventoried.

## What remains borrowed

agentic-job still uses gh-aw's safe-output idea, JSONL vocabulary and
sanitization semantics. Its Rust collector is held to fixtures produced by
the older pinned upstream collector, not assumed compatible with every
v1.2.2 addition. Generated `safe-outputs/validation.json` derives from gh-aw's
compiled workflows. GitHub apply still loads the pinned handler manager for
operations not routed to native Rust handlers; staged apply follows the same
separation of requests from writes. See the maintained
[dependency and parity account](safe-outputs.md#what-is-gh-aws-and-why) and
[upstream JavaScript disposition](safe-outputs.md#upstream-javascript-disposition).
This refresh changes none of those pins or contracts.

## What could go upstream

These are proposals, not upstream support or announced plans:

- **A host-user runtime with a concrete threat model.** Share the rootless
  Podman/KVM use case, secure-host probes and separation of credential-bearing
  jobs. A useful proposal must retain egress and credential boundaries, not
  expose a privileged daemon. The earlier host-user fork is not production
  integration ([compiler investigation](compiler.md#the-options-that-were-not-chosen));
  compare against gh-aw's current [runtime contracts][gh-runtime] first.
- **An ACP engine adapter.** Offer the common session client, cancellation,
  transcript and loopback adapter tests as an alternative to per-engine
  drivers. Mapping ACP onto gh-aw's [engine contracts][gh-engines] remains
  untried; do not equate unified logs with ACP transport.
- **Reusable deterministic output checks and forge-neutral publishers.**
  Share the [standalone Rust checker](safe-outputs.md#standalone-cli), bounded
  patch-admission cases, exact-head leases and Forgejo/GitLab notification
  filtering tests. First reconcile their policy semantics with the newer
  upstream [safe-output contract][gh-outputs] and [transport checks][gh-transport];
  these are test/code candidates, not a claim that gh-aw lacks such checks.

Conversely, gh-aw's [durable-session evidence][gh-engines],
[cost accounting][gh-cost] and [workflow examples][gh-gallery] are useful
reference points for work here. Reusing them requires a deliberate pin/parity
update or implementation, not just changing this comparison.

## Across repositories: gh-cao and agent-board

[gh-cao](https://github.com/githubnext/gh-cao) (GitHub Central Agentic Ops)
and [agent-board](https://github.com/cgwalters-forge/agent-board) are related
coordinator projects. They are not the execution boundary compared above.
This refresh did not check out or re-evaluate a gh-cao release, its catalogue,
dashboard or operating costs; the older description is not evidence of its
current capabilities. Consult each project's current README before choosing
a coordinator. agentic-job itself runs one task; callers own scheduling and
cross-run admission ([dispatch](dispatch.md)).

## Positioning follow-up

[#4096](https://github.com/cgwalters-forge/agentic-job/issues/4096) asks for
concrete positioning rather than "most people should use gh-aw". The choice
above follows that direction, with two corrections to that issue's wording:
say **no provider key or forge write credential on the agent machine**, not
"no credentials"; and say **credentialed MCP is refused in runner-only mode**,
not that a local MCP proxy currently isolates its secret. Keep GitLab
publication separate from unsupported GitLab agent inference. The detailed
limits are in [inference.md](inference.md), [mcp.md](mcp.md) and
[gitlab.md](gitlab.md). This run cannot edit issue bodies through its allowed
safe outputs; the issue wording still needs that correction.

[gh-runtime]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/agent-runtimes.md
[gh-sandbox]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/sandbox.md#L34-L142
[gh-copilot]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/engines/copilot.md#L111
[gh-routing]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/model-routing.md#L288
[gh-auth]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/auth.mdx#L19-L69
[gh-network]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/network.md#L8-L64
[gh-outputs]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/safe-outputs.md
[gh-collector]: https://github.com/github/gh-aw/blob/v1.2.2/actions/setup/js/collect_ndjson_output.cjs
[gh-detection]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/threat-detection.md#L13-L61
[gh-detection-modes]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/threat-detection.md#L124
[gh-private]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/guides/using-at-scale.mdx#L42-L48
[gh-checkout]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/checkout.md#L160
[gh-transport]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/specs/safe-outputs-specification.md#L2917-L2944
[gh-integrity]: https://github.com/github/gh-aw/blob/v1.2.2/actions/setup/js/transport_integrity.cjs#L21-L118
[gh-engines]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/engines.md#L12-L126
[gh-enterprise]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/enterprise-configuration.md#L12-L37
[gh-tools]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/tools.md
[gh-compile]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/compilation-process.md#L8-L18
[gh-imports]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/imports.md
[gh-gallery]: https://github.com/github/gh-aw/tree/v1.2.2/docs/src/content/docs/gallery
[gh-workflows]: https://github.com/github/gh-aw/tree/v1.2.2/.github/workflows
[gh-cost]: https://github.com/github/gh-aw/blob/v1.2.2/docs/src/content/docs/reference/cost-management.md#L8-L31
