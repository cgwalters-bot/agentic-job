# Dispatching an operator task

The [shipped dispatch caller](../.github/workflows/dispatch.yml) runs the
scripted agent by default: no model, inference service or secret is needed
when the target is your own public repository. Its sessions ignore task text;
they test policy, sandbox, hand-back, check and apply, not agent quality.

## Ten-minute scripted trial

Copy these files to the **same paths** in your repository:

- [dispatch.yml](../.github/workflows/dispatch.yml)
- [dispatch.toml](../.github/agentic-job/dispatch.toml)
- [hosted.toml](../.github/agentic-job/hosted.toml)

In `dispatch.yml`, replace `uses: ./.github/workflows/agentic-job.yml` with
`uses: cgwalters-forge/agentic-job/.github/workflows/agentic-job.yml@COMMIT`,
where `COMMIT` is the full reviewed SHA of the source you copied, **including
the `review-item` and `fake-profile` inputs**. A local reusable call here pins the workflow, binary
and actions to this checkout's commit: it cannot silently run an older release.
In `dispatch.toml`, replace `repos` with your exact public repository name.
Commit the files to your protected default branch and allow the pinned actions
and reusable workflow in Actions settings. `implement` also needs
`APPLY_ENVIRONMENT` ([below](#switch-to-a-real-agent)): apply opens its
pull request only from a fork owned by the account whose PAT that is.

Leave the other repository variables unset for this trial. Start with an existing issue:

```sh
gh workflow run dispatch.yml -f repo=OWNER/REPO -f item=1 \
  -f kind=triage -f task='Test the dispatch wiring without a model'
```

`triage` and `research` post a canned comment on that issue and leave the tree
clean. `implement` writes `DISPATCH-TRIAL.md` and proposes one draft PR from
the applying account's fork. `review` takes an **open,
same-repository pull request number targeting main**, not an issue number. It
posts a clearly scripted verdict naming the pinned head. This is not an
approval or permission to merge. Delete trial comments, and branches in the
applying account's fork, when finished.

`fix` takes the number of an open pull request that implement opened, from
the applying account's fork. Its run starts from that pull request's branch
at the head it had when dispatched, and its change is pushed there, to the
fork, as one commit on top, never force-pushed; a pull request that moved
meanwhile is refused, and the run has to be dispatched again. A
same-repository pull request, or one from anyone else's fork, is refused: a
push to it would run the target's `pull_request` workflows on agent-written
code with their write token and OIDC
([#340](https://github.com/cgwalters-forge/agentic-job/issues/340),
[#430](https://github.com/cgwalters-forge/agentic-job/issues/430)). Like
implement it needs `APPLY_ENVIRONMENT`. It is **off** in the shipped bounds;
to enable it for a target, add to `dispatch.toml`

```toml
push_to_pull_request_branch = { max = 1, branches = ["dispatch/**"] }
```

with globs of the branches a fix may push to; see
[pushing to a pull request's branch](safe-outputs.md#pushing-to-a-pull-requests-branch).
The scripted session is implement's.

Every run's result can be found from the issue it was dispatched for. A draft
PR ends its body with `Refs OWNER/REPO#N`, which apply writes from the `repo`
and `item` inputs, not from agent text; `Refs` closes nothing on merge. Its
title is the first line of the agent's summary, cut between words to 100
characters. Unless the result is a comment on the issue itself (triage,
research and review), apply leaves one short comment there linking the run and
its result, once even when the job is re-run. The result's URL is the
`result-url` output of `dispatch.yml` (and of `agentic-job.yml` and
`apply.yml`) and is in the run summary.

All targets must use `main` and fit the committed bounds. Do not use globs.
Protected documentation is refused by default; to deliberately permit a file,
use `[unprotected_files]` in the bounds file as shown in its commented example.
See [output validation](safe-outputs.md).

## Switch to a real agent

Set operator-controlled repository variables (not dispatch inputs):

- `AGENT`: `opencode` or `claude` (`fake` is the default).
- `AGENT_MODEL`: the model name the selected agent and broker support.
- `AGENT_RUNNER`: JSON runner labels, for example
  `["self-hosted","agentic-job"]`, for a disposable proxy-reachable image.
- `INFERENCE_URL`: the reachable broker URL, for example `http://BROKER:PORT`.
- `INFERENCE_AUDIENCE`: the broker's configured GitHub OIDC audience.
- `AGENT_CONFIG`: the caller's runner configuration path if not using hosted
  Ubuntu 26.04. The default is `.github/agentic-job/hosted.toml`; verify sandbox
  probes on your own image rather than copying hosted-image socket exceptions.
- `AGENT_CONFIG_REPO`: optional public `OWNER/NAME` repository holding opencode's
  configuration; `AGENT_CONFIG_PATH` selects its directory (empty for the root).
  These are used only with `AGENT=opencode`, not in the scripted trial. They
  select agent configuration, not the runner TOML named by `AGENT_CONFIG`.

Preflight names **all** missing model, runner, URL and audience variables at
once, before policy/build or agent startup. It rejects unknown agents.
Real agents have a 150-request cap; scripted sessions have no inference and
`max-requests: 0`. Real agents do not install scripted sessions.
Hosted Ubuntu alone cannot reach a private broker. The shipped dispatch
caller calls the complete reusable workflow, which has no network-join
inputs. To join a private network on a hosted runner, adapt the caller to
the [composed form](workflow.md#the-pieces-and-an-agent-job-of-your-own):
call `policy.yml`, write your own agent job, then call `check.yml` and
`apply.yml`, all from the same reviewed commit. In the agent job, run
`prepare`, your chosen network-join step, `secure-host`, then `run`, as
[example-compose.yml](../.github/workflows/example-compose.yml) marks.
The join action and its credentials are yours, not a built-in vendor
integration. Pin that action by commit, leave no credential readable by
the sandbox user, and keep the agent job's repository permissions read
only. For a tailnet join, disable its DNS: sandbox setup rejects tailnet
resolvers when the egress proxy is enabled. This composed form
changes what the broker has to admit
([inference admission](inference.md#which-workflows-a-broker-admits)). Or provide disposable runners
with passwordless sudo initially and systemd 257+, Node and apt-get or dnf;
see [runner requirements](workflow.md#what-a-caller-provides).

Configure the broker to verify GitHub identity tokens with the chosen audience
and admit the caller repository. Confirm registration and per-run budgets
before real tasks. No model API key goes on the runner. Narrowing broker
admission to a specific caller remains optional hardening tracked in
[tracker#452](https://github.com/cgwalters-forge/tracker/issues/452).

For `implement`, and for cross-repository targets, set `APPLY_ENVIRONMENT` to a caller environment
restricted to the protected default branch, and store its sole secret
`SAFE_OUTPUTS_PAT` there, as described in
[credential setup](workflow.md#the-apply-job-and-its-token).
This is gh-aw's `safe-outputs.github-token` for
[cross-repository safe outputs](https://github.github.com/gh-aw/reference/cross-repository/#cross-repository-safe-outputs);
see [the mapping and job-token limits](workflow.md#the-apply-job-and-its-token).
Use a classic PAT with `repo` and `workflow` scopes of a dedicated bot account that does not
own the target and has write access to nothing but its own forks: such a PAT
writes to every repository its account can, and still comments, opens issues
and forks on any public repository, so the account is what bounds it. Apply
pushes an `implement` branch only to that account's fork of the target, which
it makes if missing, and turns off Actions there before it pushes
([pull requests come from a fork](workflow.md#pull-requests-come-from-a-fork)).
Preflight names a missing `APPLY_ENVIRONMENT` too.
Only apply enters the environment; an empty secret falls back to the job token,
which cannot write cross-repository, fork or open pull requests. The shipped caller explicitly forwards
`SAFE_OUTPUTS_PAT` whether or not an environment is configured; scripted CI
forwards no credential value. If you call `dispatch.yml` as a reusable workflow,
explicitly pass `SAFE_OUTPUTS_PAT: ${{ secrets.SAFE_OUTPUTS_PAT }}` to that wrapper
too. A repository/organization secret also works; environment protection rules
still gate apply, and the environment's same-name secret takes precedence.
Never use `secrets: inherit`. For same-repository triage, research and review
the apply job uses its job token instead; no environment is needed.

## Giving runs a toolchain

A sandbox has only what the runner image and the runner configuration
(`AGENT_CONFIG`, by default [hosted.toml](../.github/agentic-job/hosted.toml))
put there. `[setup] packages` is installed for every run;
`[setup.repo-packages]` adds a list for the target repository, or the
`default` list for a target with none:

```toml
[setup.repo-packages]
default = []
"OWNER/REPO" = ["cargo"]
"OWNER/OTHER" = ["cargo", "golang-go"]
```

The policy job picks the entry (`agentic-job config --repo`) and prints
the resulting `setup.packages`, held to the same checks as every package
name; `sandbox setup` installs them with apt or dnf, as root and from the
distribution's signed archive, before it locks the host. Names ignore
case, as in the bounds. The list applies to every profile of a run on
that target, so triage and research pay its install time too, and so do
this repository's own end-to-end jobs, which share `hosted.toml`. The
[secure-host action](secure-host.md) has no target and gets only the
`default` list.

The list comes only from the caller's file, never from the target
repository: its contents, a pull request's head included, are untrusted,
and a package list read from them would let anyone who can open a pull
request choose what is installed as root. For the same reason
`rust-toolchain.toml`, `.tool-versions` and the like are not read. A
toolchain the distribution lacks needs a `setup` script of the caller's
(the reusable workflow's input; the shipped dispatch caller passes none),
which runs as the sandbox user, never as root.

**Rust.** The shipped configuration gives this repository Ubuntu 26.04's
`cargo` (1.93.1, pulling in `rustc` and `gcc` as its linker), which is
newer than its `rust-version` of 1.88. That is preferred to rustup:
nothing is fetched by a script, the packages are signed, and the run
starts with the toolchain installed. A target that pins a newer Rust in
its own `rust-toolchain` file can be given rustup from a caller `setup`
script instead. rustup then follows the target's file, but as the
sandbox user: the target picks a toolchain version, not what root
installs.

A `cargo build --locked` needs no egress rule: the proxy lets every
`GET` through, and Cargo only reads, from `index.crates.io` (the sparse
index), `static.crates.io` (the crates) and, for git dependencies, a
forge whose `git fetch` is already allowed. The shipped configuration
lists those hosts in a comment; no write is opened for them. Allowing
crates.io means the run executes code from it: every crate is checked
against the checksum in `Cargo.lock`, but build scripts and procedural
macros of the target's dependencies run as the sandbox user, as the
target's own tests do. That is the same reach as the agent's own: the
sandbox user's read-only GitHub token and inference access, not the
host's root, the runner's user or a write credential.

In a container on Ubuntu 26.04 through the same egress proxy, installing
`cargo` took 24 seconds (70 packages, most of them `gcc` and LLVM, which
the hosted image partly has already), and a cold `cargo test --workspace
--locked --no-run` of this repository 68 seconds. The hosted runner's
`Sandbox setup stage packages` line in the agent job's log is the
authoritative figure.

The scripted review session checks it: when the checkout has a
`Cargo.lock`, it runs `cargo --version` and `cargo metadata --locked`
(which downloads every dependency) and names the version on a
`Toolchain:` line of its verdict, or `none`. CI's dispatch verifier
requires a cargo version there for this repository.

## Sessions and boundaries

The built-in [patch](../workflow/dispatch-implement.sh),
[comment](../workflow/dispatch-comment.sh) and
[review](../workflow/dispatch-review.sh) session installers come from the pinned
reusable source: you need no setup script. They run as the sandbox user and write
`$HOME/.config/fake-agent/demo.json`. That JSON is an array of scripted steps:
`write` takes `title`, `path` and `content`; `execute` takes `title` and
`command`; `say`, `read` and `cost` are also supported. `{home}` and `{cwd}`
expand to the sandbox home and checkout. An executed command's failure is
reported to the session, not automatically a failing run: make your session
check the result if needed. The current fake-agent upload gate requires at
least one redaction: retain the shipped session's first `execute` step when
customizing. Its dynamically constructed canary is deliberately not a real
credential; the transcript must redact it before publication. This control is
specific to scripted runs, not a requirement of real agents.
To customize, omit `fake-profile` and use your own `setup` script
writing the same JSON path. The shipped sessions show the two hand-back files:
`{home}/out/safe-outputs.jsonl` (one safe-output JSON object per line) and
`{home}/out/outcome.json` (summary, tests, questions and stopped_early).
The implement session needs only the patch and outcome: apply constructs its
draft request from that summary. [Safe outputs](safe-outputs.md) defines the
fields and limits. Editing a session changes the trial, not the real agent.

Preflight has contents read only and fetches issue/PR title and body without
checking out target code. Text reaches the task as fenced JSON data, with
angle brackets escaped so it cannot close the fence. Dispatch inputs are never
pasted into executable code. Default-branch checks apply to manual dispatch;
the workflow-call interface lets same-repository CI exercise the exact caller.
Its caller must be trusted like any other workflow with write permissions.

The reusable policy and check jobs downscope to contents read; the agent job
has read access and runner-only OIDC registration. The sandbox has neither
forge nor OIDC credentials. Only apply receives the configured environment
token; apply and refusal reporting can use the caller's write-capable job
token, and neither executes agent-produced code. Review resolves
the open PR's exact head through the read-only policy API, refuses forks and
wrong bases, and enforces one verdict comment or noop in the clean check job.
Real reviewers start in the base checkout with the pinned head beside it.
Other profiles allow one each of noop, missing_tool and missing_data, three
outputs total; implement permits one draft PR, fix one push to the dispatched
pull request's branch, triage/research one comment.
Comment routing is fixed to the dispatched item, not agent-supplied fields.

## Verification

`node --test workflow/dispatch.test.cjs workflow/review.test.cjs` executes the
actual preflight, all shipped sessions and hostile review routing/output cases.
CI calls the **same dispatch.yml**, running triage and research on pushes and
same-repository PRs, plus review on PRs. Not implement: CI holds no PAT to
fork with. Its separate verifier checks both issue comments and the review
verdict, then existing CI cleanup removes the comments. Fork PRs skip these
jobs.
These tests do not prove real-model quality or connectivity to a private broker.
