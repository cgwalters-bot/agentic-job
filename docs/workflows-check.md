# Check repository workflows

> This text is LLM generated.

Use `agentic-job workflows check` to catch unsafe job layouts before merging.
Like [gh-aw lint](https://github.github.com/gh-aw/reference/workflow-linters/),
it checks action pins and expressions in executable fields. Unlike that linter,
it reads only Actions YAML and requires one of four job layouts. It neither
generates nor runs workflows.

| Forge | What the command checks |
| --- | --- |
| GitHub | `.yml` and `.yaml` files directly in `.github/workflows/` (case-insensitive extensions). |
| GitLab | Not supported. |
| Forgejo | Not supported; files under `.github/workflows/` are checked as GitHub Actions YAML. |

## Run the check locally

From a trusted checkout of the repository, run:

```sh
agentic-job workflows check
```

| Option | Default |
| --- | --- |
| `--root DIR` | Current directory. |
| `--exemptions FILE` | `.github/agentic-job/workflows.toml` under the root. If absent by default, no identities or exemptions are configured. |

| Exit code | Meaning |
| --- | --- |
| `0` | No refusals. A missing workflow directory counts as an empty set. |
| `1` | Workflow refusal (including unreadable or unparseable files) or stale exemption. Findings locate the problem and suggest a fix. |
| `2` | Configuration or workflow directory error, including exceeding the file count limit. |

## Configure trusted actions and workflows

Set trusted identities in `.github/agentic-job/workflows.toml`; none are built
in. Use exact lowercase `owner/repo[/path]` names without refs or wildcards.
In YAML, pin each remote `uses:` to a lowercase 40-hex commit SHA. Pins fix the
revision, not its trustworthiness: review their provenance and code.

```toml
[identities]
reusable_workflows = ["owner/repo/.github/workflows/agent.yml"]
agent_actions = ["owner/repo/run-agent"]

[identities.secure_host]
"owner/repo/secure-host" = "check"
```

| Key | Purpose |
| --- | --- |
| `reusable_workflows` | Workflows you trust to isolate agents and check outputs before applying them. |
| `secure_host` | Map trusted hardening actions to a profile. `check` allows only literal `check: true`; `write-policy` also allows literal `egress: write-policy`. Inputs are optional; all others are refused. |
| `agent_actions` | Action paths and subpaths forbidden outside the reusable workflow, in addition to known agent actions and `agentic-job run` in scripts. |

## Choose a job layout

Give every non-exempt job an explicit `permissions:` map. Set
`persist-credentials: false` on `actions/checkout` to keep tokens off disk.

| Job | What to write |
| --- | --- |
| Run an agent | Call a configured, pinned [reusable workflow](workflow.md) rather than adding agent steps. |
| Run repository code | Use a configured, pinned secure-host action immediately after checkout and before running repository code. |
| Publish a Pages site | Use a separate [deploy-only job](#deploy-only-pages-jobs). |
| Use a secret to publish build output | Use a separate [trusted artifact consumer](#trusted-artifact-consumers). |

### Hardened jobs

Setup before secure-host can run as root. The checkout rule does not detect
code from scripts, caches, or downloads; keep untrusted inputs after hardening.

| To prevent | Do this |
| --- | --- |
| Untrusted code running before hardening | Run only trusted setup before secure-host. The allowed pre-hardening actions are `actions/checkout`, `actions/cache`, `actions/cache/restore`, `actions/download-artifact`, and `actions/setup-{dotnet,go,java,node,python}`. Once checkout runs, only another checkout can come before secure-host. A local action cannot stand in for secure-host. |
| Steps running after hardening was skipped or failed | Leave `if:` and `continue-on-error:` off the secure-host step. Do not suppress failures on the job or steps before hardening. After hardening, omit status functions or use standalone `success()`. |
| Credentials reaching untrusted steps | Do not use `secrets` expressions anywhere in the job (including inputs and conditions) or in workflow `env:`. Do not grant `id-token` access. |

Use local `./` actions only after hardening. Keep containers, services, and
`docker://` actions out of these jobs; hardening stops the container daemon.

### Deploy-only Pages jobs

Build and upload the site with `actions/upload-pages-artifact` in a hardened
job. Set `needs:` on the deploy job to wait for that upload. To keep repository
code away from the deploy credentials, run only `actions/deploy-pages`, which
fetches the artifact itself.

| Field | Accepted |
| --- | --- |
| `uses` | `actions/deploy-pages` pinned to `368f82528645a54fb793d4d04e342629a3f51346` (v5.0.1) or `d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e` (v4.0.5). |
| `permissions` | Deployment needs `pages: write` and `id-token: write`. The checker allows those grants and `contents: read`, but does not require them. |
| `with` | Literal `artifact_name`, `error_count`, `preview`, `reporting_interval`, or `timeout`. |

Do not add checkout, scripts, extra actions, containers, services, secret
expressions, or workflow, job, or step `env:`.

### Trusted artifact consumers

A credential-bearing consumer must not run producer code. List only hardened
jobs in `needs:`. Have one producer upload a single file named `artifact` and
export its artifact ID and `sha256sum artifact` digest, not the archive digest
from upload-artifact's `artifact-digest` output.

Copy these first two steps, changing only the producer and output names. Both
outputs must come from the same producer.

```yaml
- uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
  with: {artifact-ids: '${{ needs.build.outputs.id }}'}
- shell: bash
  env: {ARTIFACT_SHA256: '${{ needs.build.outputs.digest }}'}
  run: |
    shopt -s dotglob nullglob
    entries=(*)
    [[ ${#entries[@]} -eq 1 && ${entries[0]} == artifact && -f artifact && ! -L artifact ]]
    [[ "$ARTIFACT_SHA256" =~ ^[0-9a-f]{64}$ ]]
    printf '%s  artifact\n' "$ARTIFACT_SHA256" | sha256sum --check --strict -
```

After that, use only trusted `run:` steps that require successful verification.
They may receive secrets via step `env:`. Do not add workflow or job `env:` or
`defaults:`, job `continue-on-error:`, containers, services, checkout, or other
actions. Review both scripts and step environments: shell or runtime loader
variables must not point to producer-controlled files. Treat the payload as
data, never code. The digest detects a mismatch, not whether the producer is
trustworthy.

### Execution surfaces

Use literals in fields that select or run code. To keep external text out of
scripts, pass it through step `env:` and read it as data with quoted shell
variables or `process.env`. `uses:` never accepts expressions. Shell commands,
shell and working-directory settings, `actions/github-script`'s `script`,
action `entrypoint` and `args` inputs, and container image and option fields use a
[closed expression allowlist](../crates/agentic-job/src/workflows/rules.rs).
Only direct references to selected job, step, runner and GitHub metadata, or
literal-matrix values where supported, are allowed. For example, `github.sha`
is allowed; `env.*`, event payloads, and step outputs are not. The checker does
not infer whether other action inputs run code.

## Exemptions

List an exception by filename, with a non-empty reason:

```toml
[exempt]
"workflow-policy.yml" = "Runs a trusted checker with a read-only token; proposed workflows are data only."
```

The checker prints each exemption and skips the entire file, even parsing.
Review exempt workflows separately. To delete or rename an exempt workflow,
land the exemption removal first; a stale exemption fails the check.

## Installing a caller check

Enforcement is opt-in. To prevent a proposal from replacing the checker or
exempting itself:

1. Review and land the CI job and configuration on the base branch, including
   a trusted checker pin and any exemption for the job's workflow.
2. Use the base branch's copy of the [ingress helper](../workflow/ingress.py)
   to check the complete workflow set at the exact proposed head, including
   unchanged files. Pass the base TOML with the identities and exemptions.
   The helper reads Git blobs without checking out proposal code, rejects
   symlinks and submodules in workflow paths, and quotes diagnostics so
   proposed text cannot issue runner commands. Fail the job if extraction or
   checking fails. Give it read-only repository access and no secrets.
3. Require the trusted workflow in a ruleset; a status name alone can be
   imitated. See [workflow ingress](workflow-ingress.md) for a CI example
   covering pull requests and merge groups. Require human approval of the
   current head before merge queue admission.

## Bounds and limits

| Input | Limit |
| --- | --- |
| Workflow set | 500 files, up to 1 MiB each; checked files must be regular files, not symlinks. |
| Configuration | One regular TOML file, up to 64 KiB; unknown keys are refused. |
| Workflow YAML | One document with string keys and no duplicates, anchors, aliases, merge keys, or explicit tags. Nesting and parsed size are bounded. |

A pass checks job layout, not script safety, trigger policy, runner freshness,
or what invoked actions and reusable workflows do. Use fresh runners for
credential-bearing jobs and review changes even when the check passes.
