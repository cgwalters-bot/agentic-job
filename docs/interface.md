# The binary

> This text is LLM generated.

`agentic-job` is the interface. The [reusable workflow](workflow.md) is
a wrapper that moves files between jobs. Another CI system would run
the same commands. The workflow fetches a checksummed static release
binary when its source digest matches the pinned commit; otherwise it
builds that source. Opting into `SOURCE_BUILD_ARTIFACTS=true` instead selects
the latest successful main build's attested workflow artifact, with
`SOURCE_BUILD_COMMIT` for hand rollback. `build-binary: true` forces a build.

## Commands

Runner-only execution uses `run --runner-home DIR`. It does not isolate the
supervisor from the same-UID agent. The operator superseded the second-user
direction in [#2989](https://github.com/cgwalters-forge/agentic-job/issues/2989);
[#2991](https://github.com/cgwalters-forge/agentic-job/pull/2991) removed it.
The keys it removed and what runner mode refuses are
[listed below](#removed-keys-and-runner-mode-refusals).

| Command | Runs as | Does |
| --- | --- | --- |
| `policy --allow FILE --repo OWNER/NAME --clone-url URL --base BRANCH --kind branch\|analysis --outputs LIST --max-outputs N` | anyone | Checks one run's request against the caller's bounds and prints `policy.json`. `--outputs` takes `all` and `--max-outputs` takes `max`, for whatever the bounds allow. |
| `config [--host] [--prepared] [--from FILE] [--string TABLE.KEY=VALUE]... [--integer ...]... [--boolean ...]... [--list ...]...` | anyone | Writes TOML from a file and individual settings. `--host` checks only the host configuration; `--prepared` writes `[host.prepared]` from the run's tables, for `sandbox prepare`. Writes `[host]`, but `[sandbox]` with `--host` and no `[host.prepared]`, for the image the forwarder pins ([stable interfaces](stable-interfaces.md#configuration-files)). |
| `sandbox setup --config FILE` | root | Prepares the host the agent runs on, and copies the configuration to `/etc/agentic-job/`. |
| `sandbox prepare --config FILE` | root | Before the secure-host image, which holds no agent code: installs the packages, `[setup] npm` and `agents` and Vibe, writes the agent's managed settings and installs this binary as the helper that the image's setup keeps. Refuses a file without `[host.prepared]`, and `sandbox setup` one with it. |
| `sandbox check [--record\|--unless-passed]` | the runner's user | Probes the sandbox as the sandbox user, with positive controls where the host provides them. `--record` leaves a record when all probes pass, and `--unless-passed` (run's) probes nothing when it finds that record, against the same configuration, with nothing having entered the sandbox user since ([sandbox-check.md](sandbox-check.md)). |
| `sandbox preflight --config FILE` | the runner's user | Proves what `[preflight]` asks of the host by using it: `/dev/kvm`, a KVM guest, a `qemu:///session` guest, CPUs, memory and disk ([capability preflight](dispatch.md#capability-preflight)). Refuses to run as root; checks nothing without the table. |
| `run --runner-home DIR --policy FILE --task FILE --meta FILE --out DIR [--config FILE] [--allow-writable-config]` | the runner's user | Runs the agent as this user and takes what it hands back. |
| `collect --policy FILE --outputs DIR --collected FILE` | anyone | Validates and sanitizes the handed-back requests as gh-aw's collector does, in check.yml and for a caller off GitHub ([safe-outputs.md](safe-outputs.md#off-github)). Exit 1 if it refused a line. |
| `check --policy FILE --outputs DIR --collected FILE [--report FILE] [--comment-repo OWNER/NAME --comment-target N --review-head SHA] [--run-summary FILE]` | anyone | Checks handed-back outputs and patch against the policy. Neutral inline comments require the trusted caller's fixed item and admitted head, recorded in the report. A run summary that passes its checks is sanitized into the report for GitLab's apply to post ([safe outputs](safe-outputs.md#publishing-to-gitlab)). |
| `apply --forge forgejo --server URL --repo OWNER/NAME --policy FILE --checked DIR --run-url URL [--comment-target N] [--push-repo OWNER/NAME] [--status STATE --status-sha SHA]` | the apply job | Publishes checked comments, issues, labels and closing, and a pull request from the bounds' fork or a push to its open one, to Forgejo with `FORGEJO_TOKEN`, or per-role tokens under `APPLY_ROLE_BINDINGS` ([roles](safe-outputs.md#forgejo-and-gitlab-roles)), then the caller's commit status ([safe outputs](safe-outputs.md#publishing-to-forgejo)). |
| `apply --forge gitlab --server URL --repo GROUP/PROJECT --policy FILE --checked DIR --run-url URL [--comment-target IID --comment-target-kind issue\|pull-request [--run-summary]] [--push-repo GROUP/PROJECT] [--status STATE --status-sha SHA --status-ref REF --status-pipeline-id ID]` | the apply job | Publishes a checked note on the caller's issue or merge request, a merge request from the bounds' fork (or from the project itself where `own-branch-repos` accepts it) or a push to its open one, issues, label changes and closings to GitLab with `GITLAB_TOKEN`, or per-role tokens under `APPLY_ROLE_BINDINGS` ([roles](safe-outputs.md#forgejo-and-gitlab-roles)), then, with `--run-summary`, the run summary check accepted as a note there, then the caller's context-bound commit status ([safe outputs](safe-outputs.md#publishing-to-gitlab)). |
| `applied --dir DIR --report FILE --output-repo OWNER/NAME --repo OWNER/NAME --item-repo OWNER/NAME [--comment-target N] [--branch-prefix P] [--artifact-prefix P] [--fork OWNER/NAME --base BRANCH --tree SHA --replacement-head SHA --made FILE] --token-is-pat BOOL` | the apply job | With `GH_TOKEN`, leaves out of `DIR/agent_output.json` what an earlier attempt of the job applied, names the rest and lists what it left out in `DIR/skipped.json`, before gh-aw's handlers run; pushes a replacement series itself and appends it to the `--made` file, which it then requires; refuses a close_issue naming a pull request or a transferred issue, a reply off the run's pull request and a pull request without a fork before writing anything ([running apply again](workflow.md#running-apply-again)). Exit 1 on a refusal. |
| `event --allow FILE --event-name NAME --event FILE --actor LOGIN --repository OWNER/NAME --out DIR` | trusted policy job | Decides event admission. Optional files: `--actor-permission`, `--pull-request`, `--task`. See [events.md](events.md). |
| `external-fetch --record FILE --archive FILE --outputs DIR --receipt FILE` | trusted read-only waiting job | Correlates an external dispatch, verifies API identities and the raw ZIP's digest, and extracts bounded raw files. All output paths must be new; see [external correlation](dispatch.md#binary-correlation-interface). |
| `external-release --policy FILE --report FILE --detection-result success` | trusted apply job | Refuses external output without this caller's successful trusted check and detection. Hosted policy is unchanged. |
| `external-staged --policy FILE --dir DIR` | trusted check job | Refuses an external upload whose staged patches, replacement or test evidence (`secondary/` included) are not named in the policy's receipt or differ from its digests; names are compared before any file is read. Refuses a hosted policy. |
| `testing-farm-launch --request FILE --output DIR --id FILE` | a producer's agent job | Submits one Testing Farm request, keeps its ID in job-private state while live, cancels it at its timeout, and writes flat hand-back files into an empty directory only after the request and archive checks pass ([Testing Farm launcher](#testing-farm-launcher)). Not verified against a live Testing Farm. |
| `testing-farm-cancel --request FILE --id FILE` | the same job's `after_script` | Cancels the request a stopped launcher left live, from its ID file, and sends nothing without one ([Testing Farm launcher](#testing-farm-launcher)). A successful cancel is not observed guest destruction. |
| `workflows check [--root DIR] [--exemptions FILE]` | anyone | Refuses workflow files whose jobs neither run secure-host nor call the reusable workflow, and the other shapes in [workflows-check.md](workflows-check.md). Exit 1 names each file, job and step. |
| `acp-drive start\|prompt\|events\|cancel\|status\|stop` | a run's agent | Starts the run's child agent and drives it over ACP ([harness.md](harness.md#a-second-agent)). |
| `session connect ENDPOINT [--json] [--since CURSOR]` | an operator or their agent | Joins a session run's conversation, late or again, with a replay of what the agent said after the cursor (all that is kept by default): each line of standard input is a prompt, and it prints what the agent says and a line per finished tool call, or with `--json` each message from the bridge as one line. It connects again with its cursor when the connection drops; the end of its input ends the session, and Ctrl-C only detaches ([attaching](interactive.md#attaching-to-a-session), [wire](../specs/session.md#wire)). |
| `audit DIR [--json]` | anyone | Inspects downloaded artifacts offline. Findings do not cause a refusal exit code. See [workflow.md](workflow.md#auditing-downloaded-artifacts). |

Internal commands are hidden: `launch-agent`
(what `run` has the session start, as the sandbox user), `sandbox
probe-local` (what `sandbox check` runs as the sandbox user), `sandbox
probe` (what CI's `confined` job tries as the runner's user), and
`helper`, the root-owned entry point for privileged operations after setup.

`sandbox check` and `run` are the supervisor. It runs as the runner's
user, whose general sudo access setup removes by default. A narrow sudo
rule permits the root-owned helper to enter the sandbox with `run0`, reap
its processes and read the proxy's fixed log. Without `--runner-home`,
it performs all operations in the agent's files (the clone, git, reading the
outcome and the requests) as the sandbox user. This prevents a link planted
by the agent from making it read the runner's files. The reusable
workflow, by default (`agent-user: runner`), and `review.yml` pass
`--runner-home`: `run` uses no sandbox
user, the agent is the runner's user and can read and change the
transcript and the limits, read `run`'s environment and stop `run`,
cleanup is the agent's process group only, and the token probes do not
run. What separates the agent there is the job's read-only tokens, no
`id-token` and no secret but the run token, secure-host's deprivileging
and the check on another machine
([requirements.md](requirements.md#actors-and-trust)).
[sandbox-check.md](sandbox-check.md#the-helper) describes the helper, and the action's
[lock](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/setup.md#the-lock) its limits.

`check` intentionally handles only half the validation. gh-aw's rules define
request types, counts and text sanitization. `collect` ports these rules,
and fixtures verify that it follows them. `--collected` is what
`collect` made of the outputs, and is given by path so that it is never
taken from what the agent's machine uploaded. [safe-outputs.md](safe-outputs.md) has both halves.

`policy --external-receipt FILE` accepts only the trusted waiting job's
receipt, after ordinary caller/organization bounds compilation. It pins
check to the recorded base commit and external run's branch without
trusting external policy/configuration. It requires `--output-repo` to
name the target: apply takes an omitted one to be the calling repository,
which `policy.yml` passes explicitly. This is compose-only and off by
default; the complete reusable workflow has no such input.

`config` exists because a workflow gets a run's settings as strings from
whoever called it. Each setting is the value of its one key and is never
read as TOML, so an input that holds a quote or a table header cannot
add a key. Empty settings leave the file unchanged. Use `--host` when
composing a configuration for `secure-host` without an agent.

The `secure-host` binary, from the same workspace and release, is the
host's side alone: `supported`, `apt`, `world-write`, `setup`, `check`,
`config` and the image's entrypoint `image`, with no command that runs
an agent ([secure-host.md](secure-host.md#the-secure-host-binary)).

## Testing Farm launcher

`testing-farm-launch` is the launcher of the GitLab caller's
[Testing Farm layer](../specs/gitlab-caller.md#testing-farm-as-a-later-layer).
Nothing runs it unless a caller's job does. It has not run against a live
Testing Farm; the API fields below are from Testing Farm's
[request page](https://docs.testing-farm.io/Testing%20Farm/0.1/test-request.html)
and the fixtures in `testing_farm/tests.rs`.

`--request` is the caller's JSON. The request body sent to Testing Farm
holds only these of its fields: `url`, the plan repository over HTTPS;
`ref`, its full commit; `plan`, as `/plans/NAME`; `compose`; `arch`;
`timeout`, 1 to 330 minutes; and, optionally, `variables`, at most 64 plain
variables. The launcher alone reads `api`, the HTTPS root of Testing Farm's
API; `artifacts`, the HTTPS root of its artifact storage; and `handback`,
the ZIP's relative path under the request's artifacts. URLs have no
trailing slash. The body has no `secrets`, tmt arguments or webhook, and
the guest can read every variable. tmt matches `test.fmf.name` as a
regular expression, so the launcher sends `plan` escaped and anchored
(`^/plans/NAME$`): it selects that plan alone, not one whose name it
prefixes.

The `api` and `artifacts` roots below are the Public Ranch's; a passed
request's `run.artifacts` must be exactly the `artifacts` root followed by
`/ID`, so another ranch
needs its own
[artifact root](https://docs.testing-farm.io/Testing%20Farm/0.1/services.html#artifacts).

```json
{
  "api": "https://api.testing-farm.io",
  "url": "https://gitlab.example.com/example-org/plans",
  "ref": "0123456789abcdef0123456789abcdef01234567",
  "plan": "/plans/agent",
  "compose": "Fedora-Rawhide",
  "arch": "x86_64",
  "timeout": 120,
  "variables": {"AGENT_ITEM": "7"},
  "artifacts": "https://artifacts.dev.testing-farm.io",
  "handback": "handback/handback.zip"
}
```

The file must come from the caller's trusted revision, not from the
pipeline's checkout of the code under test or from generated input: its
`api` decides where the write-capable token goes. The launcher sends
`TESTING_FARM_API_TOKEN` only in the `Authorization` header of its calls to
`api`, never from an environment variable a pipeline could override. It
refuses a request body that contains the token, so a variable cannot carry
it to the guest, where a wrapper command line has exposed secrets before
([inference.md](inference.md#on-a-multi-user-guest)). It refuses variables
named `TF_RESERVATION*`, which Testing Farm's reserve test reads: a reserved
guest keeps the agent's workspace reachable over SSH after the job.
The pinned plan itself must not reserve the guest or add SSH keys; the
launcher cannot see what the plan runs.

Here `/etc/agentic-job/testing-farm.json` stands for a file the trusted
caller provides, such as one in the job's image, never one in the checkout;
the `agentic-job` binary comes from that image too. Keep the token in a
masked, protected CI/CD variable whose environment scope is only
`testing-farm`, protect that environment, and define the job in the
caller's trusted pipeline configuration, so only this job on a protected
ref gets the token.

Before enabling this job, restrict the producer project's
[minimum role for pipeline variables](https://docs.gitlab.com/ci/variables/#restrict-pipeline-variables)
to a role held only by trusted dispatch actors or administrators (for example,
`maintainer` with a trusted Maintainer dispatch identity). Restrict who can
start this token-bearing pipeline on the protected ref to those same trusted
actors. The dispatch identity must be allowed to send the caller's exact
recorded variables, including `AGENTIC_JOB_RELEASE` and `AGENTIC_JOB_SHA256`;
the fetcher checks that set after the run. Do not forward upstream YAML or
pipeline variables to the producer, or allow untrusted triggers, schedules,
or manual job variables to add to that set. Only trusted administrators may
configure higher-precedence project, group, instance or policy variables;
do not override the job's checkout, artifact or timeout settings. A protected
environment alone does not enforce these restrictions. On a deployment
that cannot enforce them, do not give the job the token.

Enable this job only on GitLab 17.3 or later and assign its
`testing-farm-private` tag only to protected GitLab Runners 17.3 or later.
The server minimum is for generally available
[`after_script` on cancellation](https://docs.gitlab.com/ci/yaml/script/#skip-after_script-commands-if-a-job-is-canceled);
the runner minimum also covers the `empty` Git strategy used below.
If the deployment cannot enforce these prerequisites, leave the job disabled.
Those runners must run `script` and `after_script` in the same fresh,
per-job container, with a private `/tmp` (no shared or restored mount there).
The ID file stays there, outside the checkout, cache and artifacts;
`after_script` cancels whatever request it names. Do not use this example
on a shell executor or a reused container.
`GIT_STRATEGY: empty` starts an empty build directory for the artifact files
([Git strategy](https://docs.gitlab.com/ci/runners/configure_runners/#git-strategy)).
`dependencies: []` restores no artifacts, and `inherit: default: false`
keeps a pipeline default from adding a cache or `before_script`.

```yaml
agent_job:
  timeout: 2h 20m
  image: registry.example.com/caller/agentic-job@sha256:DIGEST
  tags: [testing-farm-private]
  environment:
    name: testing-farm
  inherit:
    default: false
  dependencies: []
  variables:
    GIT_STRATEGY: empty
    RUNNER_SCRIPT_TIMEOUT: 2h12m
    RUNNER_AFTER_SCRIPT_TIMEOUT: 5m
  script:
    - mkdir -m 700 /tmp/agentic-job-testing-farm
    - agentic-job testing-farm-launch --request /etc/agentic-job/testing-farm.json --id /tmp/agentic-job-testing-farm/request-id --output .
  after_script:
    - agentic-job testing-farm-cancel --request /etc/agentic-job/testing-farm.json --id /tmp/agentic-job-testing-farm/request-id
  artifacts:
    when: on_success
    paths: ['*']
```

`timeout` is the request's `settings.pipeline.timeout` and the launcher's
own deadline, measured on a monotonic clock from its start. Testing Farm
starts the pipeline timeout only when the request is `running`, so queue
time counts against the launcher's deadline but not the request's. The
launcher decides the deadline on a status read that starts at or after it.
If a live read spans the deadline, the launcher immediately reads again. If
that read still shows it live, after an unknown state, or after any other
failure while the request may be live, the launcher sends
`DELETE /v0.1/requests/ID`. Each status read and the DELETE have 30 seconds
each, so a live request can take up to 90 seconds after the deadline to
cancel. A passed request's download has ten minutes after its status read:
give the job's script, through
`RUNNER_SCRIPT_TIMEOUT`, at least eleven minutes more than the request's
`timeout`, and the job's own `timeout` room for `after_script` after it.

While the request may be live, its ID is in `--id`, a new file written
once the POST returns a valid ID. The launcher removes it when Testing Farm
reports the request ended or accepts the launcher's DELETE, and keeps it
when that DELETE fails. `testing-farm-cancel` sends
`DELETE /v0.1/requests/ID` for the ID in that file and removes it; without
the file it sends nothing. Run it in the job's `after_script`, as above,
with the same trusted request file and token. On the deployment described
above, `after_script` runs when a job is cancelled. On a timeout it runs
only when the script stops at `RUNNER_SCRIPT_TIMEOUT` with
`RUNNER_AFTER_SCRIPT_TIMEOUT` still inside the job's `timeout`
([`after_script`](https://docs.gitlab.com/ci/yaml/#after_script)).
It is the only cleanup for a request that is still
`queued` when the job stops, since the pipeline timeout has not started.

A successful DELETE means Testing Farm accepted the cancellation, not that
a guest was destroyed. Testing Farm does not document destroying the guest
on cancellation, so that remains an unverified prerequisite. If the job
stops after the POST and before the ID file is written, if the POST's
response is lost, or if the runner dies before `after_script` runs, no
step can cancel the request: it can still start after the job is gone and
runs until its pipeline timeout.

The launcher prints the request ID, which is evidence for the draft, not
authority. Only a request that is `complete` with the overall result
`passed` is downloaded. The status response's `run.artifacts` must be
`ARTIFACTS/ID`, the request's own directory in the caller's storage, and
the launcher fetches `HANDBACK` under it, with no token and no redirects,
within ten minutes even past the deadline. Whether a plan can put its ZIP
at a fixed path there is unverified: tmt's work directories may have
generated names, so check the artifacts of a passed request of the same
plan before relying on `handback`. The ZIP must fit `external-fetch`'s
128 MiB archive bound and hold only flat hand-back files under its ZIP
checks. Only then are the validated files written directly into `--output`,
which must already exist and be empty when the launcher starts. `--id` must
not exist. GitLab Runner packages those files at the root of its own job
archive, which the caller fetches. Do not upload the downloaded ZIP as a
member of the job archive. Upload only on success: a failed write or
interrupted script can leave an incomplete set of files.
The runner's archive must independently fit the GitLab upload limit and
the fetcher's 128 MiB compressed limit; repackaging can change its size.

Testing Farm's storage holds what the guest writes there before the
launcher or any trusted check sees it, and a download the launcher refuses
removes nothing. The Public Ranch serves artifacts to anyone with the
request's URL, without a token, and
[keeps them for 90 days](https://docs.testing-farm.io/Testing%20Farm/0.1/services.html#artifacts).
Use public storage only when the plan, variables, source, patches and logs
are all safe to publish. Before using private source, or producing
private patches or logs, verify the deployment's access control and
retention.

## Removed keys and runner-mode refusals

The parser refuses `host.create-user`, `user`, `groups`,
`allow-existing-user`, `filesystem-view`, `host.check.before-agent` and
`setup.tools`, including through the `[sandbox]` alias, by name and with a
diagnostic citing #2989, even when set to false: callers delete them. It
also refuses `agent-user: sandbox` and requires `--runner-home`. The
probe-only `sandbox.check.control-url`, `fetch-repo`, `allow-sockets` and
`allow-tcp-ports` are still accepted and ignored for the old image; refusing
them waits for its migration. These keys are under `[host]`, and `[sandbox]`
is its warned alias.

Runner admission refuses `register = "api-key"` and `[mcp.NAME]` before
setup, without needing a secret; the [MCP example](mcp.md#configuration) is
tested as a refusal, not an enablement. `run --runner-home` refuses OIDC
request credentials, `inference.front`, a private target, `before-agent`,
`setup.tools` and a child agent. Do not remove `--runner-home` to evade a
refusal. A private bounds opt-in or a successful `config` parse does not
grant launch support.

## Files read

This minimal deterministic configuration parses today and is admitted for a
public runner-mode job. It requires no inference or credential; `config`
acceptance is not host setup or live sandbox proof:

```toml
[agent]
name = "fake"
[limits]
timeout-minutes = 5
max-requests = 0
uncapped = true
[egress]
write-policy = true
```

**`--allow`**, the caller's bounds: the hosts a clone URL may name, globs
for repositories and base branches, a ceiling per output type and in
all, the patch's size and file limits.
[This repository's](../.github/agentic-job/allow.toml) is an example.

**`--config`**, TOML with these tables. Unknown keys are refused.
`run` defaults to `config::ROOT_COPY`, `/etc/agentic-job/config.toml`,
the root-owned copy `sandbox setup` leaves. `run --config FILE` is a
supported alternative for long-lived servers started outside the workflow:
mount a trusted configuration read-only and pass its path. Both paths use
the same TOML parsing, unknown-key refusals and run admission checks; selecting
a file does not perform host setup or change the helper's root-owned config.
The configuration contains no secret.

Before reading either path, `run` requires a regular file (not a symlink) and
checks write access for its effective uid, including groups, ACLs and read-only
mounts. A writable file is refused unless `--allow-writable-config` explicitly
acknowledges it; this option is off by default and skips only the write-access
check, not configuration validation. The threat is an agent editing settings
that a later run trusts: it could relax limits, redirect inference, change the
agent command/environment, or admit different session operators. A read-only
mount whose source and mount controls remain trusted prevents those edits.
If the caller opts into a writable file, it trusts whoever can change that
file and should not reuse agent-modified settings as operator policy.

This is a startup guard, not isolation from a hostile same-uid process.
Clearing write bits alone is not a trust boundary: an owner can restore them,
and a writable parent can permit replacement. Keep the file and its path under
trusted control (including the mount source), especially between server runs.
The loaded configuration is a snapshot; it is not watched for changes.

| Table | Holds |
| --- | --- |
| `[host]` | `[sandbox]` before #2071, still read with a warning, but not beside `[host]` ([stable interfaces](stable-interfaces.md#configuration-files)): the runner's user and its lock, directories to close, services to stop; `[host.check]` has what the probes need and what they accept, `before-agent`, `fetch-repo` and `containers` ([sandbox-check.md](sandbox-check.md#the-egress-policy-and-containers)); `[host.prepared]`, which `config --prepared` writes, says that `sandbox prepare` ran and what the run's tables ask of the host's rules: `refuse` (the broker under `inference.front`) and `serve-port` (the session bridge's) |
| `[egress]` | `proxy` (whether the egress proxy runs), `direct` (addresses reached without it), `policy`, `rust-proxy` (the binary's own proxy in place of mitmproxy; on by default, `false` needs `python3-venv` in `[setup] packages`) |
| `[setup]` | `packages`, `npm`, `agents` (pinned in the binary); caller-owned toolchain scripts run unprivileged after lockdown through the reusable workflow's `setup` input, not host `setup.script`; `tools` was removed and is refused ([toolchain migration](dispatch.md#giving-runs-a-toolchain)); `repo-packages` only in a file given to `agentic-job config`, which adds the `--repo` entry to `packages` |
| `[inference]` | `url`; `register`, one of `github-oidc`, `plain` and `token-file`, with no default; `audience`; `token-file`; `identity-proxy`; `anthropic-url` and `openai-url` |
| `[agent]` | `name`, `model`, and `config-repo`, `config-ref`, `config-path` for a public repository holding its configuration; `skills` to install the built-in [skills](skills.md) |
| `[child-agent]` | Legacy configuration for `name` (only `vibe`) and `model` of a [second agent](harness.md#a-second-agent); current `run` refuses it because there is no second user |
| `[limits]` | `timeout-minutes`, `max-requests`, `max-tasks`, `budget`, `uncapped`; `max-repeats` ([repeated tool calls](harness.md#limits), off by default) |
| `[mcp.NAME]` | Legacy configuration for `url`, `secret` (only `MCP_TOKEN`) and `allowed` of a remote [MCP server](mcp.md); current `run` refuses it because the same-UID agent could read its credential |
| `[session]` | `listen`, `operators`, `origins`, `capability` (a Tailscale app capability that lets tagged nodes in), `bind` (for an [attach gateway](interactive.md#an-attach-gateway) instead of the tailnet) and `idle-minutes` for a [conversation](interactive.md); `watch-item` and `watch-seconds` to send the agent [updates of the run's item](harness.md#updates-of-the-runs-item) (off by default); `nudges` for [nudges on the clock](harness.md#nudges-on-the-clock) (off by default) |
| `[preflight]` | `kvm`, `libvirt` (only `"session"`), `vcpus`, `memory-gib` and `disk-gib`: what `sandbox preflight` proves before the run ([capability preflight](dispatch.md#capability-preflight)); off by default, and left out of a host's file |
| `[commit]` | `author` and `trailers` of the hand-back's commit; a bounds file's `commit_author` ([safe outputs](safe-outputs.md#the-bounds-and-the-policy)) takes the place of `author`; `format` to format the agent's Rust first ([off by default](safe-outputs.md#what-the-agent-does)) |

`[limits]` without a timeout is refused, and so is one that caps neither
model requests nor spending unless it says `uncapped = true`. A cap on
model requests that nothing counts is refused too
([harness.md](harness.md)). [`hosted.toml`](../.github/agentic-job/hosted.toml)
is a configuration for GitHub's `ubuntu-26.04`.

**`--meta`**, JSON about the run from the CI system, copied into
`summary.json`. Its `run_id` names the patch, so a run has to be given
one.

## Files written

`policy` prints `policy.json`: the request as allowed, the clone URL for
`run`, and the configuration `collect` and gh-aw's handlers run with.

`run` writes under `--out`, in the names and schemas of the tree this
replaces so that its readers keep working: `run/` (`summary.json`,
`summary.md`, `condensed.log`, `outcome.json`), `transcript.tar.zst`,
and `safe-outputs/` if something was handed back. They exist only for a
run that passed the gate on uploads.
[workflow.md](workflow.md#what-a-run-leaves) describes the artifacts.

`check --report` writes the verdict as JSON, with the reasons for a
refusal and the files the patch names.

## Exit states

Callers branch on these, so they are part of the interface.

| State | `run` | The other commands |
| --- | --- | --- |
| 0 | the agent ended its turn | accepted; every probe passed |
| 1 | the agent failed or cancelled, the inference proxy no longer knew the run's token when it was ended ([inference.md](inference.md#what-run-does)), or a signal stopped `run` | refused; a probe failed |
| 2 | bad arguments, an internal error, results that did not pass the gate, or a run that could not be cleaned up after | bad arguments or an internal error |
| 3 | a request, task or spending limit stopped the agent, or it handed back after a turn that ended on an error, or a change on a token the proxy forgot | |
| 4 | the run never started: something before the agent failed (the check of where the binary is, the agent's configuration, the clone, the registration at the proxy, the probe of the run token); trying again is safe | |
| 124 | the timeout stopped the agent | |

For 3 and 124, `summary.json` says whether the agent handed back.
A session that ends in an internal error still exits 2, but its results
are taken as a failure that hands nothing back, so a run that passes the
gate leaves a summary saying why.

## What the binary knows of GitHub

Little, and on purpose: the clone URL comes in through the policy, and
the check that the target is public needs the forge's API, so the
workflow does it. The binary reads the `ACTIONS_ID_TOKEN_REQUEST_*`
variables to register with `github-oidc`, and `RUNNER_TEMP`,
`RUNNER_WORKSPACE` and `GITHUB_WORKSPACE` in `sandbox check`, to probe
the job's work directories. It starts nothing with the job's `ACTIONS_*`
variables in its environment, and keeps whatever the agent chose from
being read as a command by GitHub's runner on its way to the job log.

No wrapper for another CI system exists. Event admission reads GitHub
payloads but leaves API calls to the trusted workflow.
