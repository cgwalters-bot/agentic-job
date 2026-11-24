# Where the code lives

> This text is LLM generated.

This is the contributor's map: which crate and directory owns what, so you
know where a change goes. Each module's own docs say how it works.
Commands, configuration and exit states are in [interface.md](interface.md);
deployment is in [workflow.md](workflow.md); design constraints and checks
are in [contributing.md](contributing.md).

## Crates

The workspace has three crates. Dependencies run one way: agentic-job
depends on the other two, and neither depends on agentic-job or on each
other.

| Crate | Owns | Binaries |
| --- | --- | --- |
| `crates/agentic-job` | Running an agent: configuration, event admission, the ACP session, `run`, check and apply around the library, `acp-drive` | `agentic-job`, and `fake-agent`, the scripted ACP agent tests and scripted runs use |
| `crates/secure-host` | Securing a CI host for any untrusted job: host setup, the network rules and egress proxy, the privileged helper, and the probes that prove it. It knows nothing of agents, inference or safe outputs | `secure-host`, which the [secure-host image](secure-host.md#the-secure-host-binary) holds |
| `crates/safe-outputs` | gh-aw's safe-output contract: request vocabulary, collector, policy and bounds, check of a hand-back, and publishing to GitHub, GitLab and Forgejo | none |

Releases publish all three binaries. `cargo tree -p secure-host` shows
that secure-host stays free of agent code; a test resolves its manifest
on its own. agentic-job re-exports both libraries' items at their old
module paths, such as `sandbox::setup` or `policy::Policy`.
[safe-outputs.md](safe-outputs.md#library-boundary) lists what moved into
the library and what stays.

## agentic-job modules

One module per command holds that command's arguments and entry point;
`cli.rs` only assembles them. Paths are relative to
`crates/agentic-job/src/`.

| Path | Responsibility |
| --- | --- |
| `main.rs`, `cli.rs`, `exit.rs` | Command dispatch and exit states |
| `config/` | TOML types, validation and composition from workflow inputs |
| `policy.rs`, `policy/` | Reading bounds and policy files, and compiling a run's request into its policy |
| `event/` | Event admission, run guards and fenced task context |
| `activate.rs`, `dispatch.rs`, `external.rs` | Command labels, the dispatch workflow's `target` job, and caller-owned dispatch correlation |
| `run/` | Clone, inference registration, agent configuration, session orchestration and hand-back |
| `session/` | ACP transport, permissions, limits, transcript and digest |
| `acp_drive/` | `acp-drive`: the daemon and commands that drive a run's child agent |
| `handback.rs` | `handback check`, the agent's own preview of the checks |
| `check/`, `collect.rs`, `detect.rs` | The `check` and `collect` commands around the library, plus secret scanning, memory, checkpoints and the detector |
| `apply/`, `apply_token.rs` | Publishing checked outputs through the library's publishers, and the early token probe |
| `diagnostics.rs`, `audit.rs` | Why check or apply refused a run, and offline artifact inspection |
| `review/` | Workflow-side review routing |
| `sandbox/` | agentic-job's part of host setup (agents, tools, managed settings, `sandbox prepare`) and of the helper and probes |
| `secure_host/` | The `secure-host` action's steps and the inference check |
| `workflows/` | `workflows check`: job-shape rules for a repository's workflow files |
| `testing_farm.rs` | Launching a run on Testing Farm |
| `redact.rs` | Secret redaction |
| `bin/` | `fake-agent` and the release and pin tools |

## The session

`session::run` drives one agent process for one task: it starts the agent
behind the caller's launch wrapper, answers its permission requests,
holds it to its limits, and records `acp.jsonl`, `agent-stderr.log` and
`harness.json`. `session/agents.toml` is the built-in registry of ACP
agents. The [harness guide](harness.md) describes what a session does from
the outside.

## `run`

`run` clones the target, registers the run with the inference proxy,
writes the agent's settings, starts it and drives the session, then
reads the hand-back: the outcome, the requests and one patch made from
the uncommitted tree. It builds redacted logs and a summary, and uploads
nothing if cleanup failed or a secret remains. The supervisor runs as the
runner's user and the agent shares its UID, so same-UID files,
environment and memory are not a credential boundary
([requirements.md](requirements.md#actors-and-trust)).
[interface.md](interface.md#files-written) and
[workflow.md](workflow.md#what-a-run-leaves) describe the outputs.

### Adding an agent

An ACP command in the registry is not enough for `run`. A new agent needs
launcher and configuration code that pins its provider, keeps project
settings from redirecting the run token, filters its environment, and
knows its token file, API route, instruction files and cost reporting.
Limits depend on recognizing its subagent tool names and on its reported
usage, so test against the real adapter, not only generated
configuration. See the
[ACP agent registry](../crates/agentic-job/src/session/agents.toml) for
adapter-specific requirements.

## Other directories

| Directory | Holds |
| --- | --- |
| `secure-host/` | The standalone action, its image's Containerfile, hosted configuration and binary-fetch script |
| `prepare/`, `run/` | The composite actions that install the binary and inputs before setup, and run the agent on a locked host |
| `workflow/` | Scripts and files the reusable workflows read |
| `egress/` | The mitmproxy addon, its policy, hashed dependencies and Python tests; the default proxy is the Rust one in secure-host |
| `safe-outputs/` | Validation rules derived from gh-aw, their generator and fixtures |
| `skills/` | The agents' [skills](skills.md) and subagents, embedded in the binary |
| `specs/` | TLA+ models and their checker, and the run, session and GitLab-caller specs |
| `site/` | The documentation site |

gh-aw's handlers come from its pinned setup action, not a vendored copy.
When you change that pin, regenerate what is derived from it with the
commands below.

| What | Command |
| --- | --- |
| Ecosystem identifiers | `python3 egress/ecosystems.py GH_AW_CHECKOUT` |
| Validation rules | `node safe-outputs/validation.mjs GH_AW_CHECKOUT` |
| `collect`'s parity fixtures | `just collect-fixtures GH_AW_JS` |
| [Publication corpus](safe-outputs.md#the-publication-corpus) | `just publication-corpus` |

## Tests and CI

Unit tests sit beside the code; binary integration tests are in
`crates/agentic-job/tests/`. Its `corpus/` tests compare behavior with the
old tree and gh-aw's pinned handlers and need those checkouts; their
source files name the variables. [ci.yml](../.github/workflows/ci.yml)
runs the lints, tests, static builds, sandbox mutation tests and
scripted-agent runs, and its `ci` job gathers them. Host tests need a
disposable runner with root and systemd 257; never run them on a
workstation. The [Justfile](../Justfile) has the local commands.

## License

Licensed under either of [Apache License, Version 2.0](../LICENSE-APACHE)
or [MIT license](../LICENSE-MIT) at your option. User-visible changes are
recorded in [GitHub Releases](https://github.com/cgwalters-forge/agentic-job/releases).
