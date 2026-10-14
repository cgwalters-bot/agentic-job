---
name: implement
description: Make one change a task asks for, check it, and review it adversarially before handing it back. Use when the task says to use the implement skill.
---

# Implement

1. Read the repository's instructions for agents and the documentation for
   the area you change before changing anything.
2. Make the change the task asks for, and only that. Add or extend tests
   that fail without it.
3. Run the narrowest test covering the change, then the checks the
   repository and the task permit. Fix what fails.
4. Review the change: start the `diff-reviewer` subagent. Give it the
   repository and the whole diff against the commit you started from,
   new files included, not your reasoning. Save the reviewed state. Stop
   on no blockers; list important findings and nits as follow-ups in the
   description. Only if the first pass found a blocker, fix blockers and
   run the checks again, then give the reviewer only the delta since the
   first pass. Stop after at most two passes; report any remaining blockers.
   The review job remains the merge gate.
5. Hand back as the task's brief says. The description says briefly what
   changed and why, how it was verified, what was left undone, and, in one
   line, how many review passes ran and what the last left open.

Report failures and skipped checks as they are: never describe a check
you did not run as passing.
