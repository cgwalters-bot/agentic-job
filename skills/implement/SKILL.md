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
   commit you started from and the repository, not your reasoning. Fix
   every blocker, run the checks again and start a new review. Important
   findings and nits may be fixed or listed in the description. Stop when
   a pass finds no blocker or after three passes.
5. Hand back as the task's brief says. The description says briefly what
   changed and why, how it was verified, what was left undone, and, in one
   line, how many review passes ran and what the last left open.

Report failures and skipped checks as they are: never describe a check
you did not run as passing.
