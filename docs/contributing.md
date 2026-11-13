# Contributing

> This text is LLM generated.

agentic-job hardens a CI host so it can run untrusted steps, including a coding agent.
Its Rust CLI and reusable workflow separate the agent from credentials and check its outputs on another machine before applying them.
Start with the [overview](../site/overview.md) for usage, limitations and topic documentation,
and the [project layout](layout.md) for the contributor's map.

## Design principles

agentic-job is a generic GitHub agentic-workflow tool that any repository can
adopt, in the spirit of [gh-aw](https://github.github.com/gh-aw/).
It knows nothing of agent-board, this organization, or any particular repository,
custom property, topic, label or account. Repository rules, including which
repositories are midstream forks and how they are treated, come from the caller's
configuration, never from code.

Generic mechanisms are fine: for example, the `{org, forks}` bounds rule takes
the organization as a parameter. Names of our repositories, properties or topics
must not appear in non-test code or defaults. Test fixtures use neutral example
names such as `example-org/example`, not our real repositories.

## Build and checks

Run from the repository root on Linux with Git, just and a C compiler/linker.
The workspace uses Rust edition 2024 and requires Rust 1.88 or newer;
use stable Rust, Node 22 and Python 3.11+ (`tomllib`). Cargo needs network
access on a cold cache; ordinary tests use local fixtures and loopback mock
services, not a real inference service or forge credential.

The [Justfile](../Justfile) provides the commands from [CI](../.github/workflows/ci.yml),
with short comments recording prerequisites and observed timings (guidance, not
CI guarantees). The Markdown recipe spells out the CLI equivalent of CI's action.
Run the narrow test covering a change first, then applicable checks.
Run `just fmt` and then `just check` before every commit you hand back;
a change that fails `just check` isn't done.

CI's `javascript` job lets the JavaScript outside `site/`, `.github/actions/`
and exactly `corpus.test.mjs`, `handlers.test.mjs` and `collect.cjs` in
`crates/agentic-job/tests/corpus/` only shrink: put new logic in the Rust binary,
and do not add `.js`, `.mjs`, `.cjs` or `.ts` files elsewhere. The directory itself
is not exempt. The legacy `corpus.test.mjs` allowance is temporary pending
tracker#1455's trusted caller evidence for deletion; its CI dependencies remain.
Keep the [pinned upstream parity drivers](safe-outputs.md#upstream-javascript-disposition)
and their coverage; this is not acceptance of the 1.0 no-JavaScript bar.

Passing the workspace suite does **not** prove the privileged integration paths:
`run` and `probe` tests can return successfully without executing those paths,
and `session` uses a different path without `AGENTIC_JOB_TEST_SANDBOX_USER`.

Other CI checks need a prepared runner; their exact setup, commands and pins
are in [ci.yml](../.github/workflows/ci.yml) and [build.yml](../.github/workflows/build.yml).
Do not run destructive host setup, ignored `sandbox_fresh`/`sandbox_host` tests,
or secure-host examples inside an existing sandbox: they change users, sudo,
services and firewall rules. CI uses fresh Ubuntu 26.04 machines with root and
systemd; its `sandbox` job has a 30-minute limit. There is no second user to
test as: the runner's user is the only agent user (#2989).

Corpus/parity tests need the pinned external old-tree and gh-aw checkouts;
validation regeneration needs gh-aw's compiled workflows. Release-pin checks
download published binaries, proxy hash checks download wheels, and end-to-end
jobs write to the forge. Leave these to CI when those inputs or permissions
are absent; do not broaden network access from a sandbox.
Their CI job limits are 5–20 minutes, not measured runtimes.

The forge rule is about writes. Reading public forge data with the token the
run was given is allowed and expected: the item, its comments and review
threads, check results, Actions job logs and artifacts. Writing to a forge
(comments, pushes, API mutations, end-to-end tests that write) goes only
through [safe outputs](safe-outputs.md). A fix run finds what it must fix
in the latest review on the pull request and the log of the failing required
check; read both before changing anything. A task that says "measure from a
real CI log" means fetch one.

## Code conventions

Rust uses `anyhow::Result`, `Context` for useful failure messages, and
`bail!`/`ensure!` for invalid input. Workspace lints forbid unsafe code and deny
`unwrap_used`; unwraps are allowed in tests, not production code. Follow the
existing small modules and named constants for limits, protocol values and
environment keys. Extend case-table tests for acceptance/refusal boundaries
(for example `policy.rs`, `config/compose.rs` and `session/budget.rs`) rather
than duplicating test bodies. Rustfmt and warning-free Clippy are required.
Tests must not use `include_str!` for files outside `crates/` or `egress/`;
read those files at test time instead. The binary may also embed `skills/`
and `workflow/review.md`, which the source digest covers; the
`embedded_sources` test refuses anything else, and any include path that
is not one plain string literal.
Recent commits usually use `area: Imperative subject` (for example `run: Leave…`);
explain the reason for a change, not just the diff, in its commit message.
A user-visible change adds a line under Unreleased in [CHANGELOG.md](../CHANGELOG.md),
and a change to an interface [stable-interfaces.md](stable-interfaces.md) names also updates that page.

## Security and scope

Keep it simple: pass the "secure" gut check without extra machinery.
Watch what [gh-aw](https://github.github.com/gh-aw/) does, and share ideas and
code with it and other projects where we can, citing sources.
Hardening is not specific to agents; code and documentation must also read
correctly for deterministic jobs.

Explain security consequences whenever touching workflows, action pins,
permissions, token placement, caller bounds or check code. Preserve the
[job/token separation](workflow.md) and [safe-output contract](safe-outputs.md):
`policy` and `check` have read-only repository access; `agent` has read access
and OIDC permission, but the agent, the runner's user, has at most a read-only
forge token and never the OIDC request credential, beside which `run` refuses
to start. Only `apply` consumes `SAFE_OUTPUTS_PAT`,
explicitly passed even for an environment secret. If empty it falls back to
the job token, whether or not an apply environment is configured.
`activate`, `notify` and `conclude` inherit caller permissions and can write
labels/status; none may execute agent-produced code. Release/pin publishing
and CI end-to-end cleanup also have write-capable jobs: review their permissions.

The boundaries include `src/policy.rs`, `src/check/`,
`src/redact.rs`, `src/run/handback.rs`, upload/probe code,
`src/event/`, sandbox setup/helper/network/check code and `egress/` policy,
all under the agentic-job crate unless a root path is given, all of
`crates/secure-host/` (`files.rs` and the egress proxy among it), and
`crates/safe-outputs/`'s `contract.rs`, `bounds.rs`, `check/`
(especially patch parsing) and `apply/` (publishing and its git push). Keep size/count/path/type
limits, no-follow regular-file reads and fail-closed refusals intact.
See the host's [threat model](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/threat-model.md)
and [probe coverage](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/probes.md),
and the agent's [host](sandbox.md) and [check](sandbox-check.md).

Do not edit generated `safe-outputs/validation.json` by hand or vendor gh-aw;
use its generator against the pinned source when updating it. Do not weaken
bounds, pins or tests to make a change pass. Keep changes task-scoped: no
unrelated formatting, build artifacts, binary files, symlinks, submodules,
new executables, mode changes or credentials. A run's brief defines protected
paths and output limits; this guide does not grant exceptions to them.
Do not leave generated litter such as `__pycache__` in a patch.

Agent hand-back expectations are in [AGENTS.md](../AGENTS.md#hand-back).
