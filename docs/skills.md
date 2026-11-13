# Skills

> This text is LLM generated.

A run can give its agent procedures as [Agent Skills](https://agentskills.io/)
(a `SKILL.md` with a `name` and a `description`) and the subagents they
use, so that a task names the procedure ("Use the implement skill")
instead of spelling it out in every caller's prompt. The text is kept in one place,
in this repository or the configured agent configuration repository.

| Skill or subagent | Source | What it does |
| --- | --- | --- |
| `implement` | [`skills/implement/SKILL.md`](../skills/implement/SKILL.md) | Make the change, run the checks, then review the whole diff with `diff-reviewer`; only blockers trigger a second pass, on the fix delta |
| `review` | [`workflow/review.md`](../workflow/review.md), the review caller's standing task, with a header | Review a pull request read-only and return one verdict comment |
| `diff-reviewer` (subagent) | [`skills/agents/diff-reviewer.md`](../skills/agents/diff-reviewer.md) | Argue against an uncommitted change and tag each finding blocker, important or nit |

## Turning it on

It is off by default. `[agent] skills = true` in the run's configuration,
or the workflow input `agent-skills: true`, installs them. All three real
harnesses get the embedded procedures above, and also the root `skills/`
tree from `[agent] config-repo`. `fake` refuses the option because it
cannot use skills.

The runner owns the current harness's user skills directory. Each run
replaces that tree, even when the option is off or no configuration
repository is specified. Other harnesses' directories are left alone. Embedded
procedures win over source files at the same paths.

## Worker subagents

A job can opt into named workers independently of `skills`. They use the
lead's tools and inference route, but select their own model. For example,
in the caller-owned TOML passed as the workflow's `config` input:

```toml
[agent]
name = "opencode"
model = "example/strong"
skills = true
subagents = [
  { name = "worker", model = "example/fast", description = "Run delegated tests, read logs and bisect failures." },
]

[limits]
timeout-minutes = 75
max-requests = 150
max-tasks = 4
max-worker-tasks = 12
```

The default `subagents = []` installs no workers and leaves task counting
unchanged. `max-tasks` counts reviews and other delegation; only tasks
explicitly addressed to a configured worker count against
`max-worker-tasks` instead. Unknown or missing targets stay under
`max-tasks`. Both limits are per run, not concurrency limits. As with the
existing task cap, ACP observation triggers a hand-back after the count
exceeds its allowance; it is not a pre-execution tool gate. A caller can
set either allowance in its job configuration (`agentic-job config
--integer limits.max-worker-tasks=12` also works); the workflow's existing
`max-tasks` input still selects the review/other allowance.

Workers require positive `max-worker-tasks` and `max-requests`: the lead's
reported budget may omit worker usage, while the inference proxy counts
all requests using the run's token. Every worker uses that same token, so
the proxy's run record and the existing cost summary include their tokens
per upstream model, not just the lead's ACP usage. Missing usage or prices
are still reported as partial/unpriced, never invented. Task caps are
cooperation limits, not a boundary against agent code; the proxy-wide
request cap remains the spending bound.
Workers also require a broker route with per-model token accounting;
`register = "api-key"` is refused because its local record counts requests
only, not per-model tokens.

Before launch, setup reads the run's actual inference API route's model
catalog and refuses any worker model ID it does not advertise, with a clear
`agent.subagents` error. A route without a usable `data[].id` model catalog
cannot enable workers. Use exact advertised model IDs, not aliases that a
provider might resolve only during inference. For opencode, the runner
adds the model to its sole configured provider and prefixes the profile's
`model` with that provider's name; an existing prefix for that same provider
is accepted and stripped for the upstream request. A source model definition
that maps that ID to a different upstream `id`, or a provider `whitelist` or
`blacklist` that excludes it, is refused. Claude uses the model ID directly.
Vibe adds a model with a private `worker-NAME` alias and selects
that alias with the subagent profile's `active_model`; a source alias
collision is refused. Context windows use `agent.context-windows` as for
the lead's models.

The runner writes opencode/Claude Markdown profiles with `model:` and
`mode: subagent`, or Vibe TOML profiles with `agent_type = "subagent"`, in
the user-only directories listed below. Before each run, including runs
without workers, it removes only profiles bearing its generated-worker
marker. Unrelated native profiles are preserved; a worker name that collides
with one is refused rather than overwriting it.
Claude's project subagents can still shadow user profiles, as with the
reviewer below; workers do not add a permission or isolation boundary.

Names become file paths: to prevent traversal or replacing the embedded
reviewer/built-ins, names must be unique, start with a lowercase letter,
and contain only lowercase ASCII letters, digits and hyphens (at most 64
bytes). `diff-reviewer` and the harnesses' common built-in names are
reserved. At most 16 workers are accepted, each with a nonempty model of
at most 256 printable non-space ASCII characters and a description of
1–4096 bytes without NUL. Text fields are quoted, not pasted as native
configuration. `fake` refuses workers.

## Source skills

To use skills from a configuration repository, set `agent.config-repo` (or the caller's
`AGENT_CONFIG_REPO` repository variable) to the configuration repository
that owns them, enable skills, and name the skill in the task, for example
"Use the ast-explore skill to investigate this issue." No repository names
are built into the installer. Sources and refs belong in repository-owned
configuration, not dispatcher-controlled task inputs. With skills enabled,
per-agent configuration files may be absent, allowing a skills-only source;
the normal generated configuration and explicit model then apply.

Skills are always read from the source repository's root `skills/`, not
`config-path` (which still selects per-agent configuration). The installer
accepts at most 64 non-executable regular files, at most 1 MiB combined,
with UTF-8 contents and bounded, simple relative paths under skill directories.
It reads committed Git blobs rather than following checkout links. These
checks prevent a source tree from redirecting file reads or destination
paths; they do not make skill instructions trustworthy. Do not put secrets
or arbitrary configuration in that tree. Tool installation is separate:
this does not execute a caller's tool installer or skill scripts.

For example, the shipped [dispatch caller](dispatch.md) turns it on for `implement` with
`claude`, `opencode` or `vibe`, and its task then names the skill ("Use the
implement skill") in place of the procedure. Other profiles and agents keep the
prompt they had. The review caller does not use it yet: its standing task
is still passed as the task.

## Where each agent reads them

The binary embeds the files and `run` writes them into the agent's home,
as the runner's user:

| Agent | Skills | Subagents | Source read |
| --- | --- | --- | --- |
| `claude` | `~/.claude/skills/NAME/SKILL.md` | `~/.claude/agents/NAME.md` | The [skills](https://code.claude.com/docs/en/skills) and [subagents](https://code.claude.com/docs/en/sub-agents) documentation; `@agentclientprotocol/claude-agent-acp@0.88.0` starts the SDK with the `user` setting source |
| `opencode` | `~/.config/opencode/skills/NAME/SKILL.md` | `~/.config/opencode/agents/NAME.md` | opencode v1.18.35's `src/skill/index.ts`, `src/config/paths.ts` and `src/config/agent.ts` |
| `vibe` | `$VIBE_HOME/skills/NAME/SKILL.md` (`~/.config/agentic-job/vibe/skills/`) | `$VIBE_HOME/agents/NAME.toml` and `$VIBE_HOME/prompts/NAME.md` | Vibe 2.26.1's `vibe/core/config/harness_files/_paths.py`, `vibe/core/skills/manager.py`, `vibe/core/agents/` and `vibe/core/prompts/__init__.py` |

Vibe has no Markdown subagents. Its subagent is an agent profile with
`agent_type = "subagent"`, which its `task` tool runs. The profile's
`system_prompt_id` names the reviewer's text, without frontmatter, as
its system prompt. The profile sets nothing else, so the reviewer runs
with the main agent's tools and permissions. The launcher gives Vibe only
its user source, so a target repository's `.vibe/` cannot replace them.

The launcher turns off opencode's project configuration and external
skills (`~/.claude/skills`, `~/.agents/skills`), so its global
configuration directory is the only place it finds them. The subagent's
`mode: subagent` is what makes it one for opencode; Claude Code ignores
the key.

For Vibe, the `vibe` CI job's `cargo test --test vibe`
(`AGENTIC_JOB_TEST_VIBE_PYTHON`) loads the pinned Vibe's skill and agent
managers, with the launcher's user-only source, against a home that `run`'s
files were written to. It checks that they find `implement`, `review` and
the `diff-reviewer` subagent with its prompt there. It also checks that they
ignore a target repository's `.vibe/` in a folder Vibe trusts, which the
project source would read. It makes no model request.

The opt-in test `cargo test --test skills` runs the pinned opencode
(`opencode debug skill` and `debug agent`) and the Claude Agent SDK the
pinned adapter resolves, with the setting sources the adapter passes (its
`init` message), against a home that `run`'s files were written to, and
checks that each finds `implement`, `review`, `diff-reviewer` and a worker
with its explicit model there and
that opencode ignores a target repository's own. Neither makes a model
request. The ACP adapter itself and a real session with a model are not
part of it. It needs both packages installed outside the repository:

```sh
npm install --no-save --prefix "$TMP/agents" opencode-ai@1.18.35 @agentclientprotocol/claude-agent-acp@0.88.0
AGENTIC_JOB_TEST_OPENCODE="$TMP/agents/node_modules/.bin/opencode" \
AGENTIC_JOB_TEST_CLAUDE_ACP="$TMP/agents/node_modules/@agentclientprotocol/claude-agent-acp" \
  cargo test --locked --test skills -- --nocapture
```

CI does not run it yet: an `npm install` outside a lockfile is a zizmor
finding the [ingress check](workflow-ingress.md) refuses, so CI needs
a locked install, or a maintainer's exemption, first.

## What it does not protect

A skill is instructions, not a control. The run's bounds, `check` and
the [review](review.md) are what stand between the agent and a merge;
the self-review is the agent's diligence, capped at two passes and stopped
on no blockers. Important findings and nits go in the description as
follow-ups; the review job remains the merge gate. A target repository's
`.claude/agents/diff-reviewer.md` would replace Claude Code's user
subagent of that name (project subagents win there, user skills win over
project ones), which can make a self-review weaker but cannot change
what the run may hand back. Review and unclassified subagent tasks count
against `limits.max-tasks` (the workflows' default is 4), which bounds the
review loop; explicitly configured workers have their own allowance.

The skills are built into the binary: `skills/` and `workflow/review.md`
are part of the [source digest](workflow.md#things-a-caller-should-know)
that decides whether a published release is this source's: changing
them, the review caller's task included, needs a new release before a
caller that does not build the binary can use that commit.

Not yet: skills for fix, triage and research, and a caller's configuration overriding embedded procedures
([#542](https://github.com/cgwalters-forge/agentic-job/issues/542)).
