# Workflow changes at pull request ingress

[`workflow-ingress.yml`](../.github/workflows/workflow-ingress.yml) runs on
`pull_request_target`. It has only `contents: read`, no secrets or OIDC
permission, and never executes PR code. The checker and the SHA-256-verified
actionlint 1.7.12 and zizmor 1.30.1 pins come from `github.sha`, which for this
event is the tip of the PR's base branch, not its head. The workflow definition
comes from the base branch too, or from the ref the ruleset names when a
ruleset runs it.

On its own the workflow runs when a PR that touches `.github/` or an
`action.yml`/`action.yaml` is opened, synchronized, reopened or edited. Required
by a ruleset, GitHub ignores those `types` and `paths` filters: the job then
runs for every PR (it passes at once when nothing relevant changed) and only
when one is opened, synchronized or reopened. Retargeting a PR to another base
does not run it again, so close and reopen a retargeted PR, or push to it.

The checker reads changed workflow/action files at the PR head as Git blobs
into an isolated temporary directory. It rejects files over 1 MiB, and any
changed path under `.github` that is a symlink or submodule. Zizmor runs
offline, without repository configuration, including its default audits;
actionlint checks workflows with shellcheck/pyflakes disabled.
Any finding in a changed file fails, even if it existed before this PR.
Deleted and unchanged files are not audited. No custom YAML policy, job digest
or finding-identity grandfathering is involved.

An inline `# zizmor: ignore[...]` comment switches a finding off, so a PR cannot
add one: a changed file whose diff against the merge-base adds or changes a
line with such a comment fails. Ignores already on the base branch keep
working. A new exemption is for a maintainer to land, bypassing the ruleset,
after reading its reason. It goes on the line zizmor reports; a comment
elsewhere, such as at the top of the file, does nothing. The same holds for the
first change to a workflow that has findings today. Actionlint has no
inline-ignore syntax: fix its findings instead. PR configuration files cannot
disable either analyzer. The trusted `workflow/actionlint.yaml` adds the
GitHub-hosted `ubuntu-26.04` label missing from actionlint's built-in list; it
does not disable label checks.

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
need an app/PAT-triggered event. Merge queues and private-repository unauthenticated
fetches are not supported. Hosted event delivery and ruleset enforcement need
verification on GitHub, not just local tests.
