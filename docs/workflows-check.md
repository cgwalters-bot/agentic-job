# Checking a repository's workflow files

> This text is LLM generated.

`agentic-job workflows check [--root DIR] [--exemptions FILE]` gives
ordinary, hand-written workflow files the job shape guarantee that the
[compiler](compiler.md) used to give. The rules come from workflow-compiler's
[`src/shape.rs` and `lib/gha.ncl`](https://github.com/cgwalters-forge/workflow-compiler/tree/448c60c769577b345db2ad0028997f743daa5973).
Those files checked compiled output independently of its source. This
command checks workflow files directly; it does not generate them. It reads
every `.yml` and `.yaml` file directly in `ROOT/.github/workflows`, the
only place GitHub reads, with the extension in any case. It exits 0
when nothing is refused and 1 when something is, including a workflow
file it cannot read or parse. It exits 2 when the exemptions file or the
directory cannot be read (see [interface.md](interface.md)).

This repository runs it in the required `vet` job on every pull request and
merge group, from base-branch code with base exemptions. Callers opt in by
installing a trusted check; nothing is enabled in their repositories by default.

## What each job must be

Every job must do one of four things. It can call a caller-configured reusable
workflow at a 40-hex commit, which holds the agent, check and apply jobs. It can
have steps that include a caller-configured secure-host action.
Or it can be a [deploy-only Pages job](#deploy-only-pages-jobs) or a
[trusted artifact consumer](#trusted-artifact-consumers). Each
refusal below names the file, the job and the step (by number, with its
name, action or first script line), and says what to write instead.

| Refused | The threat it stops |
| --- | --- |
| A job that neither runs secure-host nor calls the reusable workflow, and is neither deploy-only Pages nor a trusted artifact consumer | Untrusted steps on a host whose runner's user still has root, and whose other users' files are open |
| A secure-host step with `if:` or `continue-on-error:`, or inputs outside the closed allowlist below | A job that goes on without hardening, or redirects hardening so the runner's user keeps root |
| A post-hardening condition with a status function other than standalone `success()`, or `continue-on-error` other than literal false on the job or a pre-hardening step | Later steps running after an earlier failure skipped hardening, or a hardening failure being silently ignored |
| A `uses:` before secure-host other than GitHub's `checkout`, `cache`, `cache/restore`, `download-artifact` and `setup-{dotnet,go,java,node,python}`, including a local `./` action | An action running with root before hardening, which can leave a root process or sudo rule behind that secure-host does not undo |
| Any step after `actions/checkout` and before secure-host, other than another checkout | The checked-out tree, which may be anyone's, run with root before hardening by a script or by an action that reads it |
| `id-token` other than `none` in the permissions of a job that runs secure-host | Its untrusted steps minting OIDC tokens for any audience; ask for them in a separate job |
| A `secrets` expression anywhere in a job that runs secure-host, an `if:` or the workflow's `env:` included | A secret readable by every step after secure-host, which all run as one user; use it in a separate job that takes artifacts as data |
| A `uses:` not pinned to a 40-hex commit (local `./` actions after secure-host are the job's own checkout) | A moved tag or branch that swaps the code a step runs |
| `container:`, `services:` or a `docker://` action in a job that runs secure-host | Nothing a check needs to stop: secure-host stops the container daemon, so these would fail at run time anyway |
| A job without its own `permissions:` map | A job token with the workflow's or the repository's default grant, which may be write |
| Any expression outside the closed execution-context allowlist in the fields below, including every `env.*` expression; any expression in `uses` | Text supplied by others becoming code or selecting code run with the job's token; env shadowing cannot bypass this rule |
| `actions/checkout` without `persist-credentials: false` | The job's token left in `.git/config`, where every later step and anything it hands the sandbox can read it |
| An agent step outside the reusable workflow: caller-configured agent actions, Claude Code, Codex and Gemini CLI actions, or `agentic-job run` in a script | An agent running as the runner's user with the job's token and files, with no sandbox and no check of its outputs on another machine |
| A key these rules read (`uses`, `run`, `permissions`, `container` and the like) spelled in another case | A file that GitHub might read differently from this check |
| Case-folded duplicate action inputs or env keys | GitHub choosing a different value from the checker; action inputs are read case-insensitively, including `lock`, `config`, `script` and `persist-credentials` |

### Caller identities

A proposal must not be able to name its own action as hardening and then run
untrusted steps with root. Deployment identities therefore come from the same
trusted base-branch file as exemptions, never the proposed tree's configuration.
The optional `[identities]` table defaults to empty: no reusable workflow or
hardening action is trusted implicitly. The file retains its 64 KiB limit,
regular-file checks and rejection of unknown keys. Names are lowercase exact
`owner/repo[/path]` paths without refs or wildcards; workflow uses still need
40-hex pins. For example:

```toml
[identities]
reusable_workflows = ["example-org/runner/.github/workflows/agent.yml"]
agent_actions = ["example-org/runner/prepare", "example-org/runner/run"]

[identities.secure_host]
"example-org/runner/secure-host" = "check"
"example-org/actions/secure-host" = "write-policy"
```

Both secure-host profiles admit only the existing closed hardening inputs:
`check` allows `check: true`; `write-policy` additionally allows literal
`egress: write-policy`. Neither permits arbitrary configuration inputs or
skipping hardening. `agent_actions` adds paths (and their subpaths) refused
outside the reusable workflow, beside the built-in third-party agent actions.
Only configure implementations whose hardening and sandbox contracts you trust.
This repository's deployment settings live in
[its caller configuration](../.github/agentic-job/workflows.toml).

### Deploy-only Pages jobs

Publishing to GitHub Pages needs `actions/deploy-pages` in a job with
`pages: write` and `id-token: write`, and a job that runs secure-host may
not hold `id-token`. So a job without secure-host that has an
`actions/deploy-pages` step is held to a narrower shape instead: a build
job runs secure-host and uploads the site with
`actions/upload-pages-artifact`, and the deploy job only takes that
artifact as data; deploy-pages fetches it itself. The OIDC request token
and the Pages write grant are safe there because nothing the repository
or a proposal wrote runs beside them. Expression, key-case,
`permissions:` map and step-key rules are those of other jobs.

| Refused in a deploy-only job | The threat it stops |
| --- | --- |
| A step other than `uses:` of `actions/deploy-pages`, including `actions/checkout`, a `run:` step, a local `./` or `docker://` action, and `actions/download-artifact` | Repository or proposal code, or an action that runs it, executing with the OIDC request token and the Pages grant and no hardening; download-artifact's `path:` can extract over the action's own code, and its `repository:` fetch another repository's files |
| An `env:` in the workflow, the job or a step | `NODE_OPTIONS` or `LD_PRELOAD` loading code into the action's own process |
| A deploy-pages input other than `artifact_name`, `error_count`, `preview`, `reporting_interval` and `timeout`, or any value that is not a literal | Another `token` or a value others supplied steering the deployment |
| A `uses:` not pinned to an allowlisted upstream commit | A moved ref or a fork-network commit that swaps the code holding those credentials |
| A grant other than `pages: write`, `id-token: write` and `contents: read` | A job that runs no secure-host holding more than deploying needs |
| `container:` or `services:` | An image the repository names, running beside the deploy steps |
| A `secrets` expression anywhere in the job, an `if:` or the workflow's `env:` included | A secret handed to the action, which needs none |

This trusts GitHub's action at the pinned commit to serve the artifact
as data, as it is documented to. Only upstream v5.0.1,
`368f82528645a54fb793d4d04e342629a3f51346`, and v4.0.5,
`d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e`, are admitted. Additions to
the allowlist need review as credential-bearing code: GitHub also
resolves fork-network commits under the upstream repository name. The
check does not judge `runs-on:`: a reused self-hosted runner could hold
a process an earlier job left behind.

### Trusted artifact consumers

The concrete threat is build-produced code running beside a deployment secret.
A trusted consumer may hold secrets and an environment, but does no checkout
and uses only the reviewed `actions/download-artifact` v8.0.2 commit below,
followed by a fixed first script checking one payload file named `artifact`.
That script requires the workspace to contain exactly that one regular,
non-symlink file, including when counting hidden entries, so tools cannot load
unchecked producer files beside the payload.
Subsequent steps are trusted `run:` scripts that validate and consume that file
as data, never execute it. The checker certifies this shape, not those scripts'
semantics: review must establish that they treat the payload as data. A digest
from the producer binds the file to its output, not to an independent approval.
No consumer exception is enabled by default; a job must fit the whole shape.

| Refused in a trusted consumer | The threat it stops |
| --- | --- |
| Missing or empty `needs:`, or any dependency without secure-host | Data selected from a job outside the hardening boundary; reusable workflow calls are not secure-host producer jobs |
| Anything but one initial download with exactly `artifact-ids: '${{ needs.<job>.outputs.<id> }}'` | Artifact substitution by name, expression operators, other repositories or runs; `path:` can extract over trusted files and `merge-multiple` can overlay artifacts |
| A downloader commit other than `9000827ccba6bdab643e8b6fd33ac0654aef8333` | Unreviewed code holding the consumer's credentials |
| A checkout, any other action, or downloads after the check | Producer code running with credentials, or unchecked files replacing verified data |
| A first `run:` other than the exact check below with `shell: bash` and only `ARTIFACT_SHA256` from the same producer's output | Output text becoming shell code or checksum filenames; checking the wrong producer's digest |
| Conditions, failure suppression or extra fields on the download/check; a later condition that can bypass success | Consumption after a skipped or failed verification |
| Workflow or job `env:`/`defaults:`, extra check env keys, `container:`, `services:` or job `continue-on-error:` | Loading code into the downloader or shell, changing how verification runs, or hiding failure |

For the [secure-host README contract](https://github.com/cgwalters-forge/actions/blob/main/secure-host/README.md),
replace the placeholder `verify-digest` with the following consumer. The build
job uploads exactly one file, `artifact`, exports its SHA-256 as `digest`, and
exports upload-artifact's `artifact-id` as `id`. Compute the file's digest with
`sha256sum artifact`; **do not** use upload-artifact's `artifact-digest`, which
hashes the ZIP, not the extracted file. Substitute your trusted data validator
for `validate`; it must be available without a checkout or another action.

```yaml
publish:
  needs: build
  runs-on: ubuntu-26.04
  permissions: {contents: read, actions: read}
  environment: release
  steps:
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
    - run: validate artifact
      env: {TOKEN: '${{ secrets.DEPLOY }}'}
```

The first two steps admit only the shown keys plus `name:`. Later scripts use
the ordinary execution-expression and step-key rules (without matrix execution
expressions), may receive secrets through step env, and must retain success
guards. Producers are checked independently: merely naming secure-host does
not hide a weakening input, missing pin or secret in the producer. As with
Pages, use fresh runners; the checker does not certify `runs-on:` or processes
left by a previous job.

Later steps' env values are not checked for code loading. Review them together
with the scripts: for example, `BASH_ENV: artifact` would execute the payload
with the step's credentials despite a successful digest check. Never set shell
or runtime loader variables to producer-controlled files.

### Execution surfaces

The table-driven rule covers these fields from
[GitHub's workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).
Every row uses the same expression allowlist, except `uses`, where GitHub
does not permit expressions and the checker refuses every expression.
Container shorthand strings are images. Container and Docker fields are
checked even though secure-host jobs also refuse containers outright.

The hardening boundary must use a configured secure-host path at a
40-hex commit; a local action is not certified. The closed input table is:

| Configured profile | Admitted input | Value |
| --- | --- | --- |
| Either profile | `check` | Literal `true` (YAML boolean or string) |
| `write-policy` only | `egress` | Literal `write-policy` |

`check: true` means the same to the forwarder and the old action before the
forward. The standalone action's write policy opts into restricting HTTP writes
to allowed destinations; egress is otherwise off by default. It is not complete
exfiltration prevention. Omitting inputs keeps the action's defaults. All other
inputs are refused: the forwarder fails on the old action's `lock`, `egress`,
`deny-runner-metadata` and `build`, and at an old commit their admitted values
only restated its defaults or chose how to get the binary; `image-archive`
runs an unverified image; `runner-user`
and the old action's other user redirect identities; `stop-services` replaces the daemon
list; `binary` replaces trusted code; `egress-policy` and `script` select
unchecked files. `config` is also refused, even with `lock: true`: this checker
does not validate configuration files, which can redirect the runner lock.
Literal repository paths do not make either `config` or `egress-policy` safe:
the checker does not read them, so it cannot detect a redirected lock or a
policy that opens arbitrary writes.
Unknown inputs, expressions and other values fail closed.

The checker is not told which repository it checks, so even the repository
that defines secure-host cannot name it as `./secure-host`: it exempts the
workflow files that do.

| Scope | Field |
| --- | --- |
| Step | `run` |
| Step | `shell` |
| Step | `working-directory` |
| Step | `uses` |
| github-script step | `with.script` (input names are case-insensitive) |
| Docker step | `with.entrypoint` |
| Docker step | `with.args` |
| Job | `uses` |
| Job | `defaults.run.shell` |
| Job | `defaults.run.working-directory` |
| Workflow | `defaults.run.shell` |
| Workflow | `defaults.run.working-directory` |
| Job | `container` (shorthand image) |
| Job | `container.image` |
| Job | `container.options` |
| Job | `services.<id>.image` |
| Job | `services.<id>.options` |

Unknown step keys and unknown keys in job/workflow `defaults` or
`defaults.run` are refused, so a future execution field cannot silently
bypass the rule. Defaults accept only `run`, and its map accepts only
`shell` and `working-directory`. Docker `entrypoint` and `args` inputs are
checked conservatively on all actions, since an action can hide its Docker
implementation. Arbitrary other action inputs are not interpreted as code;
the checker cannot determine what arbitrary action implementations execute.

Execution expressions must be a single direct property reference. The closed
allowlist is `runner.{os,arch,name,temp,tool_cache,debug,environment}`,
`github.{sha,run_id,run_number,run_attempt,repository,repository_id,repository_owner_id}`,
`steps.<id>.{outcome,conclusion}`, `job.status`, and `matrix.<key>` only
when the matrix is an object with no expressions anywhere in its values.
Functions, operators, indexing, unknown properties and all other contexts
are refused, including `env`, `inputs`, `needs`, `secrets`, `vars`, event
numbers and step outputs. Pass values through step `env:` and read quoted
shell variables (or `process.env` in github-script); no env taint tracking
is needed. `run:` steps before secure-host and before any checkout are
allowed: they are the job's own commands, such as installing packages,
and run with root. Only `actions/checkout` starts the ordering rule: code
fetched by a `run:` step, a downloaded artifact or a restored cache before
secure-host is not recognized, so keep those after it. The `secrets` rule matches the word in any expression,
from the first `${{` of a value to its end, so one in a string literal or
after the expression is refused too. The agent rule is a list of known actions and one
command, not a way to recognize any agent. A `docker` action named through
`action.yml` and not `docker://` is not detected; it fails at run time
once the daemon is stopped. After secure-host, conditions without status
functions retain GitHub's implicit `success()` guard. Conditions with status
functions are conservatively refused unless they are just `success()`;
even `success() || always()` can run without hardening. The check does not
otherwise judge conditions, triggers or what an allowed action does. The
[ingress check](workflow-ingress.md) and review do.

## Exemptions

A workflow file may be exempted only by its name, with a non-empty reason,
in `.github/agentic-job/workflows.toml`:

```toml
[exempt]
"ci.yml" = "This repository's CI: tests this revision's source, naming it by local path."
```

An exempt file is not parsed or checked. Its name and reason are printed,
and an entry for a file that does not exist is refused. When the files
come from a proposal, pass the base branch's list with `--exemptions`
so that the proposal cannot exempt itself or change trusted identities. Without
the option, the file under `--root` is read, and a missing one exempts nothing
and trusts no deployment identities.
Deleting or renaming an exempt workflow is therefore refused, including with
an explicit `--exemptions` file. A maintainer must land the exemption removal
first, then delete or rename the workflow in a subsequent proposal.

This repository's own workflow files are all listed, each with its
reason. They call the reusable workflow and secure-host by local path to
test this revision, or are the reusable workflow's own jobs, or its build,
release and CI. A caller names the same files by commit and passes.

## Bounds

Workflow files are read without following a link (a link is refused),
up to 1 MiB each and 500 in all. The exemptions file is read the same
way, up to 64 KiB. YAML is read from the parser's events into a tree
built here, not through the parser's loader. Nesting stops at 64 levels,
and a file stops at 100,000 nodes or 8 MiB of scalar text (keys included).
YAML anchors, aliases, merge keys and explicit tags are refused.
Use ordinary mappings and sequences instead of
sharing YAML nodes. Mapping keys must be strings; duplicate keys and multiple
documents are also refused. Refusals name the line. This deliberately smaller
YAML subset prevents alias expansion from bypassing the depth bound.
The command checks workflow files, not action manifests.

## Installing a caller check

The threat is a proposal exempting itself or replacing the checker with code
that always passes. Keep the checker, script and exemptions outside the proposed
tree. For example, copy `workflow/ingress.py` from the same source revision as
this document into the caller's base branch (review and land it there first),
then use this job. The separate binary pin below supplies the existing CLI;
it does not supply the ingress script. This example runs only the
shape checker; this repository's [ingress workflow](../.github/workflows/workflow-ingress.yml)
also installs and runs pinned actionlint and zizmor.

```yaml
name: workflow-policy
on:
  pull_request_target:
    types: [opened, synchronize, reopened, edited]
  merge_group:
    types: [checks_requested]
permissions:
  contents: read
jobs:
  workflow-policy:
    permissions:
      contents: read
    runs-on: ubuntu-26.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ github.event.merge_group.base_sha || github.sha }}
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          repository: cgwalters-forge/agentic-job
          ref: 23e74c719b7a50c9f576a5de4e630eeeb13ea357
          path: checker
          persist-credentials: false
      - run: cargo build --locked --release -p agentic-job
        working-directory: checker
      - env:
          BASE: ${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha }}
          HEAD: ${{ github.event.pull_request.head.sha || github.event.merge_group.head_sha }}
          PR: ${{ github.event.pull_request.number }}
        run: |
          [[ "$BASE" =~ ^[0-9a-f]{40}$ && "$HEAD" =~ ^[0-9a-f]{40}$ ]]
          git fetch --no-tags origin "$BASE" "$HEAD"
          PYTHONPATH=workflow python3 -c 'import os; from ingress import check_workflows; raise SystemExit(0 if check_workflows(".", os.environ["HEAD"], "checker/target/release/agentic-job", ".github/agentic-job/workflows.toml") else 1)'
```

The binary pin above contains the checker command. Fetching commits
by SHA works for public repositories; for PR heads use `refs/pull/$PR/head` if
the forge does not allow fetching the head SHA directly. No proposed checkout,
action, build script or exemption runs. Permissions remain `contents: read`;
pass no secrets. The temporary workflow tree is limited to 500 regular files
of 1 MiB each, and analyzer output is quoted against workflow-command injection.

This job neither runs secure-host nor calls the reusable workflow, so the
checker refuses it. Exempt it in the base branch's
`.github/agentic-job/workflows.toml`, as this repository exempts its own
ingress workflow: it runs base-branch code only and reads the proposal as data.

```toml
[exempt]
"workflow-policy.yml" = "Runs the base branch's checker on proposed workflow files as data, with a read-only token."
```

Land this job and the exemptions through maintainer review, run it once, then
require `workflow-policy` in the branch ruleset for pull requests and merge
groups. Prefer a ruleset-required trusted workflow: a required status name
alone can be imitated by a proposal's job. Keep human approval of the current
head before merge-queue admission; see [ingress limitations](workflow-ingress.md).
