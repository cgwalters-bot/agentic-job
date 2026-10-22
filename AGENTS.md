# Working on agentic-job

agentic-job hardens a CI host so it can run untrusted steps, including a coding agent.
Its Rust CLI and reusable workflow separate the agent from credentials and check its outputs on another machine before applying them.
Start with the [README](README.md) for usage, limitations and topic documentation.

## Layout

- `crates/agentic-job/`: the only Rust crate; CLI, policy, event admission, sessions, sandbox, run, check and audit code.
- `crates/agentic-job/src/bin/fake-agent.rs`: scripted agent for protocol and end-to-end tests.
- `crates/agentic-job/tests/`: CLI integration tests; `data/` fixtures and `corpus/` old/new implementation parity tests.
- `egress/`: Python filtering proxy policy, tests and hash-pinned dependencies embedded in the binary.
- `secure-host/`: composite hardening action, binary fetching/checksums and release pin.
- `safe-outputs/`: validation derived from pinned gh-aw workflows, generator and refusal diagnostics.
- `workflow/`: event activation/label consumption and its Node tests.
- `skills/`: agent skills and subagents embedded in the binary ([skills](docs/skills.md)).
- `.github/workflows/`: reusable workflow, CI, examples, release and pin automation.
- `.github/agentic-job/`: caller bounds/configuration and scripted end-to-end scenarios.
- `docs/`: topic guides, [requirements](docs/requirements.md) and [remaining work](docs/plan.md).

## Build and checks

Run from the repository root on Linux with Git and a C compiler/linker.
The workspace uses Rust edition 2024 and requires Rust 1.88 or newer;
use stable Rust, Node 22 and Python 3.11+ (`tomllib`). Cargo needs network
access on a cold cache; ordinary tests use local fixtures and loopback mock
services, not a real inference service or forge credential.

The following commands are from [CI](.github/workflows/ci.yml), except the
explicit CLI spelling of the Markdown action and the extra diagnostics test.
Observed wall times on one unprivileged runner are guidance, not CI guarantees:

- `cargo build --locked`: 19 seconds with dependencies already checked.
- `cargo fmt --all --check`: under 1 second.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: 42 seconds on a cold dependency cache.
- `cargo test --workspace --locked`: 92 seconds including compilation; session tests alone took 22 seconds.
- `node --test workflow/activation.test.cjs`: under 1 second.
- `python3 -m unittest discover -s egress -v`: under 1 second.
- `node --test secure-host/binary.test.mjs`: under 1 second.
- `node --test safe-outputs/diagnostics.test.mjs`: under 1 second; useful for diagnostics changes, not a separate CI step.
- `npx --yes markdownlint-cli2 '**/*.md'`: 4 seconds including tool download; CI uses markdownlint-cli2-action with the same glob and repository configuration.
- `lychee --offline --include-fragments --no-progress "**/*.md"`: CI's relative-link/anchor check; requires lychee (local timing not measured).
- `just workflow-lint OWNER/REPO@COMMIT`: the forge's shared actionlint, zizmor and runner-label check, as CI runs it when the `WORKFLOW_LINT` repository variable is set; needs just, cargo, network and docker (`CONTAINER=podman` otherwise). 5 seconds with images and crates cached.

Run the narrow test covering a change first, then the applicable checks above.
Passing the workspace suite does **not** prove the privileged integration paths:
`run` and `probe` tests can return successfully without executing those paths,
and `session` uses a different path without `AGENTIC_JOB_TEST_SANDBOX_USER`.
Old-tree hand-back parity also skips without `OLD_TREE`.

Other CI checks need a prepared runner; their exact setup, commands and pins
are in [ci.yml](.github/workflows/ci.yml) and [build.yml](.github/workflows/build.yml).
Do not run destructive host setup, ignored `sandbox_fresh`/`sandbox_host` tests,
or secure-host examples inside an existing sandbox: they change users, sudo,
services and firewall rules. CI uses fresh Ubuntu 26.04 machines with root and
systemd/run0; sandbox probes took 27 minutes unsharded and are now four shards
with 30-minute job limits. `AGENTIC_JOB_TEST_SANDBOX_USER` needs a second user,
sudo/run0 and an installed fake agent; do not enable it here. CI covers the
sandbox user through the `e2e-sandbox` reusable-workflow job instead.

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
through [safe outputs](docs/safe-outputs.md). A fix run finds what it must fix
in the latest review on the pull request and the log of the failing required
check; read both before changing anything. A task that says "measure from a
real CI log" means fetch one.

The static build is `cargo build --release --locked --target x86_64-unknown-linux-musl -p agentic-job`
after installing musl-tools and adding that Rust target; CI allows 30 minutes.
The target and musl-gcc are prerequisites, not provided by a normal Rust installation.

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

## Security and scope

Keep it simple: pass the "secure" gut check without extra machinery.
Watch what [gh-aw](https://github.github.com/gh-aw/) does, and share ideas and
code with it and other projects where we can, citing sources.
Hardening is not specific to agents; code and documentation must also read
correctly for deterministic jobs.

Explain security consequences whenever touching workflows, action pins,
permissions, token placement, caller bounds or check code. Preserve the
[job/token separation](docs/workflow.md) and [safe-output contract](docs/safe-outputs.md):
`policy` and `check` have read-only repository access; `agent` has read access
and OIDC permission, but the sandbox user has at most a read-only forge token
and never the OIDC request credential. Only `apply` consumes `SAFE_OUTPUTS_PAT`,
explicitly passed even for an environment secret. If empty it falls back to
the job token, whether or not an apply environment is configured.
`activate`, `notify` and `conclude` inherit caller permissions and can write
labels/status; none may execute agent-produced code. Release/pin publishing
and CI end-to-end cleanup also have write-capable jobs: review their permissions.

The boundaries include `src/policy.rs`, `src/check/` (especially patch parsing),
`src/files.rs`, `src/redact.rs`, `src/run/handback.rs`, upload/probe code,
`src/event/`, sandbox setup/helper/network/check code and `egress/` policy,
all under the crate unless a root path is given. Keep size/count/path/type
limits, no-follow regular-file reads and fail-closed refusals intact.
See the host's [threat model](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/threat-model.md)
and [probe coverage](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/probes.md),
and the agent's [sandbox user](docs/sandbox.md) and [token probes](docs/sandbox-check.md).

Do not edit generated `safe-outputs/validation.json` by hand or vendor gh-aw;
use its generator against the pinned source when updating it. Do not weaken
bounds, pins or tests to make a change pass. Keep changes task-scoped: no
unrelated formatting, build artifacts, binary files, symlinks, submodules,
new executables, mode changes or credentials. A run's brief defines protected
paths and output limits; this guide does not grant exceptions to them.
Do not leave generated litter such as `__pycache__` in a patch.

## Hand-back

Leave the working tree uncommitted: the runner produces one commit and one
draft pull request, as described in [safe outputs](docs/safe-outputs.md#what-the-agent-does).
Use a concise description stating what changed and why, exact verification
commands and exit statuses, and what was left unverified. Record real results,
including failures and skipped prerequisites, in the brief's outcome file;
never describe a skipped privileged test as verified.
