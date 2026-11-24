# Contributing

> This text is LLM generated.

agentic-job hardens a CI host so it can run untrusted steps, a coding agent among them,
and checks what those steps produce on another machine before applying it.
This page says what a change must respect and how to check it.
Start with the [overview](../site/overview.md) for usage and the
[project layout](layout.md) for where the code lives.

## Design principles

agentic-job is a generic agentic-workflow tool that any repository on any
supported forge can adopt, in the spirit of [gh-aw](https://github.github.com/gh-aw/).
It knows nothing of a particular organization, repository, custom property,
topic, label or account. Repository rules, such as which repositories are
forks and how they are treated, come from the caller's configuration, never
from code or defaults.

Generic mechanisms are fine: a bounds rule may take an organization as a
parameter. Test fixtures use neutral names such as `example-org/example`.

Keep it simple: a change should pass the "secure" gut check without extra
machinery, and before adding a control, name the threat it stops. Hardening
is not specific to agents, so code and documentation must also read correctly
for deterministic jobs. Watch what gh-aw does, and share ideas and code with
it and other projects, citing sources.

## Build and checks

You need Linux with Git, [just](https://github.com/casey/just), a C linker,
stable Rust 1.88 or newer (edition 2024), Node 22 and Python 3.11 or newer.
Cargo needs network access on a cold cache. Ordinary tests use local fixtures
and loopback mock services, not a real inference service or forge credential.

The [Justfile](../Justfile) holds the commands [CI](../.github/workflows/ci.yml)
runs, with prerequisites and observed timings in its comments.

| Step | Command |
| --- | --- |
| Run the narrow test covering your change | `cargo test --locked -p <crate> <name>` |
| Format | `just fmt` |
| Required before every commit you hand back | `just check` |

A change that fails `just check` isn't done.

Passing the workspace suite does **not** prove the privileged paths: `run`
and `probe` tests can pass without executing them, and `session` takes a
different path without `AGENTIC_JOB_TEST_SANDBOX_USER`. These checks need
inputs or permissions a workstation or sandbox usually lacks; leave them to
CI, whose [ci.yml](../.github/workflows/ci.yml) and
[build.yml](../.github/workflows/build.yml) hold their setup and pins.

| Check | Needs |
| --- | --- |
| Sandbox and secure-host tests (ignored `sandbox_fresh`, `sandbox_host`) | a fresh disposable machine with root and systemd; they change users, sudo, services and firewall rules |
| Corpus and parity tests | the pinned old-tree and gh-aw checkouts |
| Validation regeneration | gh-aw's compiled workflows |
| Release-pin and proxy hash checks | downloads of published binaries and wheels |
| End-to-end jobs | write access to a forge |

Never run destructive host setup, the ignored sandbox tests or secure-host
examples inside an existing sandbox, and do not broaden network access from
one to make a check run.

Reading forge data with the token a run was given is allowed: the item, its
comments and review threads, check results, job logs and artifacts. Every
forge write (comments, pushes, API mutations) goes through
[safe outputs](safe-outputs.md). A fix run reads the latest review on the
pull request and the log of the failing required check before changing
anything; a task that says "measure from a real CI log" means fetch one.

## Code conventions

- New logic goes in Rust. CI's `javascript` job lets JavaScript outside
  `.github/actions/` and the corpus harness files it names only shrink. Keep
  that allowance and the
  [pinned upstream parity drivers](safe-outputs.md#upstream-javascript-disposition)
  with their coverage until trusted caller evidence supports removing them;
  they do not meet the 1.0 no-JavaScript bar.
- Use `anyhow::Result`, `Context` for useful failure messages and
  `bail!`/`ensure!` for invalid input. Unsafe code is forbidden and
  `unwrap` is denied outside tests.
- Keep modules small and use named constants for limits, protocol values and
  environment keys. Extend existing case-table tests for acceptance and refusal
  boundaries rather than duplicating test bodies.
- Rustfmt and warning-free Clippy are required.
- Build-time includes come only from what the release source digest covers
  (`crates/`, `egress/`, `skills/`, `workflow/review.md`), which the
  `embedded_sources` test enforces; tests read other files at run time.
- A change to an interface [stable-interfaces.md](stable-interfaces.md) names
  also updates that page.

Commit subjects use `area: Imperative subject`, and the message explains why.
Release notes come from merged pull request titles, so give each pull request
a descriptive title with an area prefix; do not edit `CHANGELOG.md` or add changelog fragments.

## Security and scope

When a change touches workflows, action pins, permissions, token placement,
caller bounds or check code, explain its security consequences. Preserve the
[job and token separation](workflow.md) and the
[safe-output contract](safe-outputs.md):

| Job | What it may hold |
| --- | --- |
| `policy`, `check` | read-only repository access |
| `agent` | read access and OIDC permission; the agent, the runner's user, gets at most a read-only forge token and never the OIDC request credential: `run` refuses to start if that credential is present |
| `apply` | the only consumer of `SAFE_OUTPUTS_PAT`, passed explicitly; when empty it falls back to the job token, whether or not an apply environment is configured |
| `activate`, `notify`, `conclude` | caller permissions for labels and status; none runs agent-produced code |

Release, pin publishing and end-to-end cleanup jobs can also write; review
their permissions on any change.

These paths are security boundaries. Keep their size, count, path and type
limits, no-follow regular-file reads and fail-closed refusals intact.

| Crate | Boundary code |
| --- | --- |
| `crates/agentic-job` | `src/policy.rs`, `src/check/`, `src/redact.rs`, `src/run/handback.rs`, `src/event/`, upload and probe code, sandbox setup, helper, network and check code |
| `crates/secure-host` | all of it, including `files.rs` and the egress proxy |
| `crates/safe-outputs` | `contract.rs`, `bounds.rs`, `check/` (patch parsing above all) and `apply/` (publishing and its push) |
| repository root | `egress/` policy |

The agent's [host](sandbox.md) and [check](sandbox-check.md) pages link the
host's threat model and probe coverage.

Do not weaken bounds, pins or tests to make a change pass. Do not edit the
generated `safe-outputs/validation.json` by hand or vendor gh-aw; run its
generator against the pinned source. Keep changes task-scoped: no unrelated
formatting, build artifacts, binaries, symlinks, submodules, new executables,
mode changes, credentials or generated litter such as `__pycache__`. A run's
brief sets protected paths and output limits, and this guide grants no
exceptions to them.

Agent hand-back expectations are in [AGENTS.md](../AGENTS.md#hand-back).
