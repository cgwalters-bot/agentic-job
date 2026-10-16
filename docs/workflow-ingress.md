# Workflow changes at pull request ingress

[`workflow-ingress.yml`](../.github/workflows/workflow-ingress.yml) runs on
`pull_request_target` and `merge_group`. It has only `contents: read`, no secrets or OIDC
permission, and never executes PR code. The checker and the SHA-256-verified
actionlint 1.7.12 and zizmor 1.30.1 pins come from `github.sha`, which for this
event is the tip of the PR's base branch, not its head. The workflow definition
comes from the base branch too, or from the ref the ruleset names when a
ruleset runs it.

The job reports as `vet` on every PR, so a ruleset can require that status
context; it passes at once when no `.github/` or `action.yml`/`action.yaml`
file changed. It runs when a PR is opened, synchronized, reopened or edited;
required by a ruleset, GitHub ignores those `types`. Retargeting a PR to another base
does not run it again, so close and reopen a retargeted PR, or push to it.

The checker reads changed workflow/action files at the PR head as Git blobs
into an isolated temporary directory. It rejects files over 1 MiB, and any
changed path under `.github` that is a symlink or submodule. Zizmor runs
offline, without repository configuration, including its default audits;
actionlint checks workflows with shellcheck/pyflakes disabled.
Any finding in a changed file fails, even if it existed before this PR.
Deleted and unchanged files are not audited. No job digest or finding-identity
grandfathering is involved.

An inline `# zizmor: ignore[...]` comment can silence unrelated findings, so
added or changed ignores in the diff against the merge-base fail, with one
exception: exactly `# zizmor: ignore[self-repository]` on a step's `uses:` line
whose literal path begins with `./`, or a job's `uses:` line naming
`./.github/workflows/<name>.yml`. The workflow filename must start with an ASCII
letter, digit, underscore or hyphen, contain only those characters and dots,
and contain no `..`. Neither form permits remote references; both run code
from this repository that still needs human review.
The checker accepts block-style steps with `- uses:` or `- name:`/`- id:` followed
by `uses:`, with a plain single-line name/id, an unquoted or single-/double-quoted
local path and an optional reason after the directive. The exception requires
LF line endings and YAML quoted scalars closed on their line. Quotes within
plain scalar values and indented `|`/`>` block bodies do not open YAML quoting.
Structural refusals report the source line and reason when an ignore is refused.
Other spellings and placements fail closed.
Ignores already on the base branch keep working. Every other new or changed
exemption is refused, including additional audit names on a local step.
It goes on the line zizmor reports; a comment elsewhere does nothing.
Actionlint has no inline-ignore syntax: fix real findings instead.
PR configuration files cannot
disable either analyzer here. The base branch's `.github/actionlint.yaml`
(CI's shared workflow check reads a pull request's own copy) adds the
GitHub-hosted `ubuntu-26.04` label missing from actionlint's built-in list; it
does not disable label checks. It also filters the pinned analyzer's unknown
`job.workflow_repository`/`job.workflow_sha` fields in policy, check and apply,
and `jobs.notify.result` in policy. Only the secret-free secure-host test
workflow may use deprecated log commands: its hostile probes and positive
control verify that sandbox log escaping stops runner-command injection.
These message- and file-specific filters also cover the isolated Git blobs;
other expression and deprecated-command errors still fail.

This check catches patterns the analyzers know to be bad, and new exemptions
from them. It does **not** stop a hostile PR. In particular it does not judge
new `permissions`, secrets or `id-token: write` on triggers the analyzers
consider safe, such as `push`, and an ignore already on the base keeps covering
its line whatever changes below it: a workflow whose `pull_request_target`
trigger is exempted can be turned into one that runs PR code. Nor does it
prove scripts safe or analyze transitive action/reusable-workflow behavior.
Human or reviewer approval before merge does all of that. Analyzer parser
vulnerabilities remain a risk: the runner has a runtime token and the base
branch's cache scope, even though its repository token is read-only.

An administrator must enforce the trusted workflow with a ruleset; a required
status name alone can be imitated by PR-owned workflows. Installation needs
maintainer review because the old default branch cannot run a new definition.
Events produced with `GITHUB_TOKEN` do not trigger workflows; token-created PRs
need an app/PAT-triggered event. Private-repository unauthenticated fetches are
not supported. Hosted event delivery and ruleset enforcement need verification
on GitHub, not just local tests.

## Merge queue

A queue merges a group commit, not the head the PR run vetted, so `vet` also
runs on `merge_group` and checks `base_sha..head_sha` with the checker and
analyzer pins checked out at `base_sha`, never the queued tree. That workflow
definition is the queued one, though: a PR that edits this workflow, or adds
another job reporting `vet`, can pass the group's check. The PR-time run from
the base branch still audits such an edit; the human approval required below
is the gate for it.

Enqueueing runs the proposed workflows and code with repository write and OIDC
permissions before landing, even if the group later fails. Therefore the queue
must require an approving human review of the current head before admission.
The sandbox does not protect credentials held by workflow steps outside it.
Future auto-merge must not bypass human approval of the current head for any
apply-opened PR. Edits to `.github/**` or `action.yml`/`action.yaml` are examples,
not the entire boundary: binaries and host scripts built from the queued tree
also execute outside the sandbox. Require at least one approval, approval of
the most recent push, and dismissal of stale approvals on push. Allow no bypass
actors unless they run and verify the full E2E suite before merging.
Do not enable the queue until this approval requirement and broker OIDC trust
have been verified. Queue setting changes also require rerunning open PRs whose
green CI skipped E2E, as described in the rollout guide.
