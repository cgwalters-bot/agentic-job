# Skills

> This text is LLM generated.

A skill is a written procedure the agent loads by name. With skills on, a
task can say "Use the implement skill" instead of spelling the procedure out
in every caller's prompt. Skills use the [Agent Skills](https://agentskills.io/)
format: a directory holding a `SKILL.md` with a `name` and a `description`.
A run can also install subagents: the built-in reviewer, and worker
subagents you name in configuration.

Unlike gh-aw, which takes skills from a workflow's `skills:` frontmatter, a
run here takes them from the binary and from one configuration repository,
and the task picks one by name.

## Built-in skills

| Skill or subagent | Source | What it does |
| --- | --- | --- |
| `implement` | [`skills/implement/SKILL.md`](../skills/implement/SKILL.md) | Make the change, run the checks, then have `diff-reviewer` review the whole diff; a second pass runs only for blockers, on the fix |
| `review` | [`workflow/review.md`](../workflow/review.md), the review caller's standing task | Review a pull request read-only and return one verdict comment |
| `diff-reviewer` (subagent) | [`skills/agents/diff-reviewer.md`](../skills/agents/diff-reviewer.md) | Argue against an uncommitted change and tag each finding blocker, important or nit |

The skills are built into the binary, and their sources count toward the
[source digest](workflow.md#things-a-caller-should-know). If you change
them, a caller that uses a published release needs a new release before it
gets the change.

## Turning it on

Skills are off by default. Set `[agent] skills = true` in the run's
configuration. On GitHub the workflow input `agent-skills: true` does the
same. The [dispatch caller](dispatch.md) turns skills on for `implement`
with `claude`, `opencode` or `vibe`, and its task names the skill. The
review caller still passes its standing task as the prompt.

`claude`, `opencode` and `vibe` support skills; `fake` refuses the option.
The runner owns the current agent's user skills directory: each run
deletes everything in it, even when skills are off, so a skill an earlier
run left behind is never read. Don't keep your own skills there. Other
agents' directories are left alone.

| Agent | Skills | Subagents |
| --- | --- | --- |
| `claude` | `~/.claude/skills/NAME/SKILL.md` | `~/.claude/agents/NAME.md` |
| `opencode` | `~/.config/opencode/skills/NAME/SKILL.md` | `~/.config/opencode/agents/NAME.md` |
| `vibe` | `~/.config/agentic-job/vibe/skills/NAME/SKILL.md` | `~/.config/agentic-job/vibe/agents/NAME.toml`, with its prompt in `prompts/NAME.md` |

opencode and Vibe read only these user directories, so a target
repository cannot replace the installed skills. Claude Code is different:
a target repository's `.claude/agents/diff-reviewer.md` wins over the
installed reviewer (see [below](#what-it-does-not-protect)).

## Skills from a configuration repository

To add your own skills, put them under `skills/` at the root of a
public configuration repository. Name that repository in `[agent]
config-repo` (on GitHub, the caller's `AGENT_CONFIG_REPO` repository variable
also works), turn skills on, and name the skill in the task: "Use the
ast-explore skill to investigate this issue." Choose the repository and
ref in configuration the caller's repository owns, not in task inputs a
dispatcher controls. The skills tree is read from the root even when
`config-path` points elsewhere for the agent's own configuration. With
skills on, that configuration may be absent, so a repository can hold
skills only; the run then uses its generated configuration and `model`.

A built-in skill wins over a repository file at the same path. The
installer reads committed Git blobs and refuses the whole tree if any of
these fail:

| Limit | Value |
| --- | --- |
| Files | At most 64, regular and not executable; no links or submodules |
| Size | At most 1 MiB combined |
| Contents | UTF-8 |
| Paths | Inside a skill directory (`skills/NAME/...`, not `skills/README.md`), at most 256 bytes, only ASCII letters, digits and `_.-`, no part starting with `.` or `-` |

These limits stop a repository from redirecting reads or writes outside
the skills directory. They do not make a skill's instructions trustworthy.
Keep secrets and other configuration out of that tree. The run does not
execute skill scripts or install tools a skill mentions.

## Worker subagents

A worker is a named subagent with its own model that the lead agent can
delegate work to. Workers use the lead's tools and inference route.
Workers do not depend on `skills`. Configure them in the run's
[configuration](interface.md):

```toml
[agent]
name = "opencode"
model = "example/strong"
skills = true
subagents = [
  { name = "worker", model = "example/fast", description = "Run delegated tests, read logs and bisect failures." },
]

[limits]
max-requests = 150
max-tasks = 4
max-worker-tasks = 12
```

| Field | Rule |
| --- | --- |
| `subagents` | Default `[]`, no workers; at most 16; `fake` refuses them |
| `name` | Unique, starts with a lowercase letter, then lowercase ASCII letters, digits and `-`, at most 64 bytes; not `diff-reviewer` or an agent's built-in name |
| `model` | An exact model ID the run's inference route lists in its model catalog (`data[].id`), at most 256 printable ASCII characters without spaces; no aliases |
| `description` | 1 to 4096 bytes, no NUL |
| `limits.max-worker-tasks` | Positive, required with workers and only with them; how many tasks the lead may give configured workers in the run |
| `limits.max-tasks` | Reviews and every other task, including tasks for unknown subagents; the workflows default to 4 |
| `limits.max-requests` | Positive, required with workers: the lead's reported usage may leave out worker usage, but the inference proxy counts every request |

Setup reads the route's model catalog before launch and refuses a worker
model the catalog does not list. A route without a usable catalog cannot
have workers. Workers also need a broker route that records tokens per
model. `register = "api-key"` is refused, because it records request counts
but not tokens. Context windows come from `agent.context-windows`, as for
the lead. `agentic-job config --integer limits.max-worker-tasks=12` sets
the worker allowance too; the workflow's `max-tasks` input still sets
the review allowance.

Worker usage is in the run's cost summary per model. Missing usage or
prices are reported as partial or unpriced, never estimated. Task limits
are counted as tasks start. A run that goes over one is told to hand
back; tool calls are not blocked in advance. The request cap at the
proxy is the actual spending limit.

Each run removes the worker profiles it wrote before, and only those.
Your other profiles stay. A worker whose name matches one of them is
refused rather than overwriting it.

## What it does not protect

A skill is instructions, not a control. The run's bounds, `check` and the
[review](review.md) are what stand between the agent and a merge. The
`implement` self-review is the agent's own diligence: at most two passes,
stopping when no blockers remain, with important findings and nits listed
in the description. The review job remains the merge gate.

In Claude Code a target repository's own `.claude/agents/diff-reviewer.md`
replaces the installed subagent of that name, as can a profile named like a
worker. That can weaken a self-review but cannot change what the run may
hand back. Workers add no permission or isolation boundary.

Not yet: skills for fix, triage and research, and letting a caller's
configuration override built-in procedures
([#542](https://github.com/cgwalters-forge/agentic-job/issues/542)).
