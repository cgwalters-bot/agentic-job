# Check workflow changes before merging

> This text is LLM generated.

A pull request can change the CI that reviews it. Keep the required check on a
trusted revision so a proposal cannot change the rules used to vet itself.
Static checks catch known unsafe patterns; they do not replace human review.

| Forge | Where to start |
| --- | --- |
| GitHub | Start with [Installing a caller check](workflows-check.md#installing-a-caller-check) for a workflow policy check in your repository. |
| GitLab | This check is specific to GitHub Actions. See the [GitLab guide](try-gitlab.md) for running agentic-job on GitLab. |
| Forgejo | This check is not provided for Forgejo. See the [Forgejo guide](try-forgejo.md) for running agentic-job there. |

## Require the check on GitHub

The caller example checks workflow policy only. The [agentic-job repository's
ingress workflow](../.github/workflows/workflow-ingress.yml) also runs static
analyzers and reports as `vet`. It builds from this repository's sources and
uses its configuration; it is a reference, not a drop-in workflow. Unlike the
caller recipe, `vet` uses `cancel-in-progress` for pull requests. GitHub
[advises against cancellation in ruleset workflows][ruleset-concurrency].

Follow the [caller recipe](workflows-check.md#installing-a-caller-check) to
require the trusted workflow, not just a status name.

[ruleset-concurrency]: https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/troubleshooting-rules#concurrency

On pull requests, `vet` uses base-owned code and policy, reads proposed files
as data, and never runs proposed code. It has read-only repository access and
no secrets or OIDC permission.

## Read the check result

| Check | Coverage | What to do if it fails |
| --- | --- | --- |
| zizmor and actionlint | Both check changed workflows with lowercase `.yml` or `.yaml` extensions; zizmor also audits changed `action.yml` and `action.yaml` files. Deleted and unchanged files are not scanned. Changed definitions over 1 MiB and changed symlinks or submodules under `.github` or at action definitions are refused. | Fix the reported findings, even if they predate the pull request. Pull request configuration cannot disable these checks. |
| [`workflows check`](workflows-check.md) | Inspects the proposed workflow set, including case variants of `.yml` and `.yaml`, even if no workflow changed. Files must be regular, at most 1 MiB each, and number at most 500. Only the base revision supplies exemptions, which skip policy validation for the named files. | Fix the reported policy violation. Before renaming or deleting an exempt workflow, land the removal of its exemption in a separate pull request. |

A green `vet` does not approve new permissions, secret access or OIDC grants,
including in `push` workflows that can run as soon as a PR merges. Review those
grants and what scripts, called actions and reusable workflows actually do.

New or edited zizmor ignores are refused except for
`# zizmor: ignore[self-repository]` on the reported `uses:` line of a local
action step or local reusable workflow call. Use block-style YAML and a literal
local path, such as `./.github/actions/example` for an action or
`./.github/workflows/example.yml` for a reusable workflow (only `.yml`
qualifies). The exception does not cover remote references or additional audit
names. See the [checker source](../workflow/ingress.py) for exact recognition
rules. Review the local code even when the ignore is allowed. Existing ignores
remain active and can hide findings after later edits.

| Situation | What to do |
| --- | --- |
| You changed the target branch | Even if `vet` is green, push an update or close and reopen the pull request to get a fresh run against the new base. |
| Automation opened the pull request with `GITHUB_TOKEN` | Use an event triggered by a GitHub App token or personal access token. |
| The repository is private | The supplied workflow fetches proposed revisions without authentication; it does not support private repositories. |

## Merge queue

Require human approval of the current head **before** admitting a pull request
to the queue. Require at least one approval, require approval of the most recent
push, and dismiss stale approvals on push. Do not let automation bypass review.

The ordinary `merge_group` run checks the combined changes with the group's
base checker and policy, but takes its workflow definition from the queued
tree. A green `vet` status from that run does not prove that the trusted
workflow ran. The queue can run proposed workflows and code outside the sandbox
with write access and OIDC before the group passes. Verify the approval rules
and, if you use an OIDC broker, its trust policy before enabling the queue.
See [CI runner use](workflow.md#ci-runner-use) for what to recheck when changing
queue settings.
