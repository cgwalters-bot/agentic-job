# Skills

A run can give its agent procedures as [Agent Skills](https://agentskills.io/)
(a `SKILL.md` with a `name` and a `description`) and the subagents they
use, so that a task names the procedure ("Use the implement skill")
instead of spelling it out in every caller's prompt. The text lives once,
in this repository, and every supported agent gets the same text.

| Skill or subagent | Source | What it does |
| --- | --- | --- |
| `implement` | [`skills/implement/SKILL.md`](../skills/implement/SKILL.md) | Make the change, run the checks, then review the whole diff with `diff-reviewer`; only blockers trigger a second pass, on the fix delta |
| `review` | [`workflow/review.md`](../workflow/review.md), the review caller's standing task, with a header | Review a pull request read-only and return one verdict comment |
| `diff-reviewer` (subagent) | [`skills/agents/diff-reviewer.md`](../skills/agents/diff-reviewer.md) | Argue against an uncommitted change and tag each finding blocker, important or nit |

## Turning it on

It is off by default. `[agent] skills = true` in the run's configuration,
or the workflow input `agent-skills: true`, installs them; a run of the same agent without
it removes those files if an earlier run left them in the sandbox user's
home. A run of the other agent leaves them, and does not read them. It is
refused for `vibe` and `fake`: a task that names a skill the agent does
not have would run with no procedure at all.

The [dispatch caller](dispatch.md) turns it on for `implement` with
`claude` or `opencode`, and its task then names the skill ("Use the
implement skill") in place of the procedure. Other profiles and agents keep the
prompt they had. The review caller does not use it yet: its standing task
is still passed as the task.

## Where each agent reads them

The binary embeds the files and `run` writes them, as the sandbox user,
into that user's home:

| Agent | Skills | Subagents | Source read |
| --- | --- | --- | --- |
| `claude` | `~/.claude/skills/NAME/SKILL.md` | `~/.claude/agents/NAME.md` | The [skills](https://code.claude.com/docs/en/skills) and [subagents](https://code.claude.com/docs/en/sub-agents) documentation; `@agentclientprotocol/claude-agent-acp@0.88.0` starts the SDK with the `user` setting source |
| `opencode` | `~/.config/opencode/skills/NAME/SKILL.md` | `~/.config/opencode/agents/NAME.md` | opencode v1.18.35's `src/skill/index.ts`, `src/config/paths.ts` and `src/config/agent.ts` |

The launcher turns off opencode's project configuration and external
skills (`~/.claude/skills`, `~/.agents/skills`), so its global
configuration directory is the only place it finds them. The subagent's
`mode: subagent` is what makes it one for opencode; Claude Code ignores
the key.

The opt-in test `cargo test --test skills` runs the pinned opencode
(`opencode debug skill` and `debug agent`) and the Claude Agent SDK the
pinned adapter resolves, with the setting sources the adapter passes (its
`init` message), against a home that `run`'s files were written to, and
checks that each finds `implement`, `review` and `diff-reviewer` there and
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
what the run may hand back. Subagent tasks count against
`limits.max-tasks` (the workflows' default is 4), which also bounds the
review loop.

The skills are built into the binary: `skills/` and `workflow/review.md`
are part of the [source digest](workflow.md#things-a-caller-should-know)
that decides whether a published release is this source's: changing
them, the review caller's task included, needs a new release before a
caller that does not build the binary can use that commit.

Not yet: skills for fix, triage and research, Vibe, and a caller's
configuration repository adding or overriding skills
([#542](https://github.com/cgwalters-forge/agentic-job/issues/542)).
