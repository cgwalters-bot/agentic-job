# Hive and agentic-job

> This text is LLM generated.

[Hive][hive] is an external scheduler for GitHub issues and pull requests.
It decides what work is ready and when to dispatch agents. agentic-job runs
one task in CI and checks what the agent hands back; it does not maintain a
queue or decide what to work on next. You do not need Hive to use agentic-job.

## What Hive does

| Stage | What to expect |
| --- | --- |
| Filter | Hive skips held issues. With reporter trust enabled, an issue from an untrusted reporter needs a maintainer's label to enter the queue. |
| Classify | Rules route issues to agents and decide whether to fix, write a spec, or ask for clarification. Routing by title or label is not authorization. |
| Pace | Hive adjusts how often it dispatches agents based on queue depth. Its rolling token budget is checked between dispatches, not reserved before each run. |
| Gate | When Hive evaluates merge eligibility, it excludes drafts, held pull requests, and those with failing required checks. The merge relay requires the requested revision to match the head in the latest eligibility snapshot. |
| Scope credentials | Hive grants different GitHub App token permissions by agent tier. A tier can grant write access; do not assume a Hive session has the same read-only boundary as an agentic-job run. |

For details, see the [Hive architecture][architecture] and [merge eligibility code][merge]
at the revision used for this comparison. This is a source comparison, not an
integration test.

## When you need a coordinator

Start with a single CI workflow if you already know what should trigger each
run. Add a coordinator when you need to pick work from a backlog, order tasks
across repositories, or cap concurrent runs across several workflows.

| Decision | Where to put it |
| --- | --- |
| Which work to admit | In the caller. Use trusted authorization, not text that an issue author can write. For GitHub triggers, see [event admission](events.md). |
| When to dispatch or retry | In the coordinator. Keep concurrency and retry limits there, and distinguish missing forge data from an empty queue. |
| Which changes the agent can propose | In the caller's [safe-output configuration](safe-outputs.md). The agent gets at most read-only forge access; a separate trusted step applies permitted outputs after checks. |
| Whether to merge | In the repository's merge policy or trusted coordinator. A checked proposal does not replace review or required merge checks. |

On GitHub, gh-aw documents both [dispatching separate worker workflows][orchestrator]
and using a [native queue][queue] that authorizes each task attempt. With
agentic-job, the queue and dispatch stay with the caller, and each run checks
its own outputs.

[hive]: https://github.com/hivecommons/hive/tree/0680bb52ffcda6824522415cb652806b66b8338f
[architecture]: https://github.com/hivecommons/hive/blob/0680bb52ffcda6824522415cb652806b66b8338f/src/docs/architecture.md
[merge]: https://github.com/hivecommons/hive/blob/0680bb52ffcda6824522415cb652806b66b8338f/src/cmd/hive/merge_eligibility.go#L231-L300
[orchestrator]: https://github.github.com/gh-aw/patterns/orchestrator-ops/
[queue]: https://github.github.com/gh-aw/patterns/workqueue-ops/
