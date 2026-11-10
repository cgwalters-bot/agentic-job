# Changelog

User-visible changes to the reusable workflows, the actions and the
`agentic-job` binary, newest first. Each version's
[release notes](https://github.com/cgwalters-forge/agentic-job/releases)
list every pull request merged into it; `build-DIGEST` releases are CI
artifacts, not versions. [Stable interfaces](docs/stable-interfaces.md)
says what a caller may rely on across versions.

## Unreleased

- GitHub dispatch and fix bounds may set `[github.outputs] own-branch-repos`
  to accept own-branch pushes by repository pattern, alongside the existing
  per-repository opt-in file (#3402). The default remains off.

- The README is now a short introduction linking to the topic guides;
  the getting-started walkthrough lives in `docs/try-it.md` (#3375).

- GitHub bounds `repos` may opt into `{org = "ORG", forks = false}` to
  admit live, non-fork, non-archived repositories owned by that organization.
  Exact repository entries remain explicit exceptions (#3332).

- Apply lists a replacement series it pushed to a pull request's branch
  under `made` in `applied.json`, not under `already_applied`, which now
  holds it only when an earlier attempt had pushed that same head (#3322).

- The shipped `dispatch.yml` caller can start a session (`session`, off by
  default, and `idle-minutes`) and run the agent job on a `runner` named in
  the caller's new `AGENT_RUNNERS` variable, a closed map of names to
  `runs-on` labels and runner configuration. `agentic-job dispatch`
  refuses an unknown or malformed entry and scripted sessions. Review policy
  refuses listening sessions even when enabled by the runner TOML rather
  than the dispatch input (#536).

- Opt-in `external-fetch` correlates a caller-owned dispatch record with
  exactly one attempt-1 Actions run, checks its pins/jobs/artifacts again
  at release, and verifies the raw hand-back's API digest before bounded
  extraction. Composed policy/check/apply can bind that receipt's exact
  base and branch; external apply requires explicit successful trusted
  detection. No external caller or deployment is enabled (#3293).

- A run may hand back repeated-test evidence beside a pull request's
  patch, where the bounds' new `[github.test_evidence]` allows it (off by
  default). The evidence is `out/test-evidence.json` and one log per
  attempt. Check binds its base and head to the checked patch and refuses
  a malformed manifest, too many attempts, a dropped or extra attempt, and
  an unsafe, linked or oversized log. Apply refuses a tree other than the
  one the patch makes. Otherwise the draft gets each outcome's count and a
  link to the run (#3292).

- The run action carries a host check that failed only to reach a host
  outside the runner, after its retries, as `exit` 4 with the new failure
  class `control_unreachable`, which the reusable workflows pass on and the
  status comment names; its job still fails before the agent starts. A
  dispatcher may requeue such a run a bounded number of times. Any other
  failure of the check fails the job with no exit state or class, as
  before (#3225).

- Setup with `[host.prepared]` refuses a helper that is missing or not a
  regular file in its preflight, before it changes the host (#3262).

- A session's client attaches from anywhere, late or again. The bridge
  numbers the agent's notifications (`params._meta.botHarness.cursor`) and
  keeps the latest 4096, up to 4 MiB; a `session/new` with
  `_meta.botHarness.since` is sent what came after that cursor first, and
  is refused with the cursor it can have where its own is past the latest
  or no longer kept. Behavior change: a connection that ends without a
  normal close (code 1000) no longer ends the session; it goes on to its
  idle timeout, a turn that runs finishes, and the bridge listens for the
  client again. A normal close ends it as before. `session connect`
  replays since `--since` (everything kept by default), prints a line per
  finished tool call, connects again with its cursor when the connection
  drops, waits for an unanswered turn to finish before honoring input EOF
  after reconnecting, and detaches on Ctrl-C, printing
  the cursor to resume from (part of #536).

- Behavior change: `run` and the reusable workflow's runner admission take
  `[session] listen` (`session: true`) again, with the runner's user as the
  agent, for chat only. The agent can attach to its own session's bridge
  ahead of the operator and so deny them the chat; no message over the
  bridge authorizes a write, which still waits for the end-of-run check and
  apply. The helper's `session-serve` now runs once per job, so a process
  the agent leaves behind cannot have the runner's name served to it after
  the run. The network rules for the bridge's port, which held only the
  removed sandbox user, are gone (part of #536).

- `sandbox check` retries its read of an outside host under
  `egress.write-policy` (`write-policy-read`) up to three times with a
  short backoff, logs why each try failed (DNS, connect, timeout, TLS or
  HTTP status), and exits 4, the retryable not-started state, when that
  read is all that failed (#3225).

- `[session] nudges = true` (off by default) sends the agent two messages
  on the clock: halfway through its timeout, to checkpoint and plan, and
  at five sixths of it, to finish and hand back. They go the way updates
  of the run's item go, so Claude Code, which gets no budget notices,
  gets them too (#3190).

- Behavior change: the reusable workflow's `timeout` input now defaults
  to 60 minutes, not 75. A caller that leaves it out gets runs 15
  minutes shorter; set `timeout: "75"` to keep the old limit (#3190).

- `create_issue`'s bound may set `comment_on_duplicate = true`, with
  `create_issue` in `native_handlers`: apply then posts the body on the
  oldest open issue titled exactly as asked instead of opening another, so
  a run can propose follow-ups without refiling earlier runs' and can refine
  an existing issue by naming its title. Off by default (part of #3191).

- Dispatch `research` now accepts a pull request as well as an issue and
  posts its one bounded comment on that item. Repository bounds, fixed comment
  routing and cross-repository token requirements are unchanged; research
  remains analysis-only, not review or fix (#3159).

- Add a secret-free `gitlab` CI job exercising apply comments, fork merge
  requests and inline discussions against a pinned disposable GitLab CE
  container, including quick-action and `@all` neutralization (#2110).
  Like Forgejo, it is ignored in ordinary tests and non-required until stable.

- A push's bound may set `own_author = "LOGIN"`, the account apply pushes
  as. A fix run on that account's own pull request is then admitted in a
  repository `repos` does not list, with only the push and `noop`/`missing_*`
  outputs (and the run's status comment on that pull request). Policy and
  apply each read the author from the forge, and apply refuses unless the
  pull request is still by that login and it is the identity apply holds. `push resolve` prints `author=` too. Off by
  default (#3162).

- Under `host.deny-runner-reads`, setup discards every core dump on the
  host (`kernel.core_pattern = |/bin/false`), and `sandbox check` fails
  closed without it (`core-pattern`). This closes a forced dump
  (`prlimit`, `SIGSEGV`, `coredumpctl dump`) of a step's parent, `run` or
  the Worker. Jobs on such a host, deterministic ones too, get no core
  dumps. CI's `confined` job now probes the parent's environment, `mem`,
  ptrace and forced dump, and the Worker's environment and dump. `run`'s
  `--runner-home` refusals are unchanged (#1618).

- Remove the secure-host forwarder's redundant runner-storage policy
  override: the pinned v0.6.9 image already admits those exact PUT
  destinations on the transparent listener. Caller policies are left
  untouched, and the explicit proxy no longer gains those extra writes
  from the forwarder (#2811).

- **Deprecated:** the host's configuration table `[sandbox]`, with
  `[sandbox.check]` and `[sandbox.prepared]`, is now `[host]`, and
  messages name its keys `host.KEY` (#2071). `[sandbox]` and `config`'s
  `sandbox.KEY` settings still work as an alias: same keys, defaults and
  checks, plus a warning on standard error. A file with both tables is
  refused. The alias stays at least until the release after the one whose
  image the secure-host forwarder pins (#2656), and its removal will be
  listed here as breaking first. `config` writes `[host]`. The exception
  is `config --host` without `[host.prepared]`, which still writes
  `[sandbox]` because the pinned v0.6.9 image reads only that name.
  `runner-sandbox` and every default are unchanged.

- Document the agreed external VM-runner to midstream draft contract, with
  a devspace profile example and separate runtime implementation slices.
  External dispatch and cross-run apply are not deployed by this change;
  hosted behavior and bounds are unchanged (#2891).

- Add off-by-default `advisory` event-review publication: one checked comment
  or noop bound to the admitted repository, PR, base branch and exact head.
  The writer re-reads the open PR before posting; ordinary review verdicts
  are unchanged. Callers need a new compatible policy/check/apply pin; no
  caller migration or classifier is included (#3085).

- The secure-host image is built from a new `secure-host` binary, the
  host's side with no agent code (`supported`, `apt`, `world-write`,
  `setup`, `check`, `config`, `image`), which releases also publish with
  its checksum (#2070). For one release the image and the host also give
  it agentic-job's name (`/agentic-job`, `/usr/local/bin/agentic-job`),
  for what the pinned cgwalters-forge/actions/secure-host calls by it
  (`config --host`, `sandbox check`). An agent job with such an image
  first runs `agentic-job sandbox prepare` as root, which installs the
  agents, their managed settings and agentic-job as the helper, on a file
  `config --host --prepared` wrote: its `[sandbox.prepared]` table tells
  the image's setup to keep that helper and what the run's tables ask of
  the host's rules, and the image refuses a job's tables without it.
  `agentic-job secure-host image` is gone: the image's entrypoint is
  `secure-host image`. The published image and the action's pin move only
  after a release (#2656).

- **Breaking:** the sandbox user is gone; the runner's user is the only agent
  user (#2989). `sandbox setup` creates no `runner-sandbox` user, sudoers or
  scheduler entries for it, runs no `setup.script` (the agent job runs it as
  the runner's user) and no longer needs `run0`. `helper enter`, `reap`,
  `disable-linger`, `crontab-remove` and `pkexec-control`, `sandbox
  probe-local` and `sandbox probe sandbox-user` are removed; `sandbox check`
  probes the runner's user (lock, metadata rule, world-write policy,
  write policy) and `sandbox probe no-user` checks that no second user exists.
  `run` requires `--runner-home`, and refuses what needed a second user
  (`api-key`, `inference.front`, `[mcp]`, private targets, `session.listen`,
  `[child-agent]`). With no second user for the egress proxy to hold,
  `config` turns `egress.write-policy` on for a run's file that keeps the
  proxy and leaves it unset, and `run` and `config` refuse an agent with
  the proxy on and the write policy off. The pinned image's built-in
  runner writes admit the artifact storage accounts for later uploads.
  `agent-user: sandbox` is refused. The keys
  `sandbox.create-user`, `sandbox.user`, `sandbox.groups`,
  `sandbox.allow-existing-user`, `sandbox.filesystem-view`,
  `sandbox.check.before-agent` and `setup.tools` are refused by name;
  `sandbox.check.control-url`, `fetch-repo`, `allow-sockets` and
  `allow-tcp-ports` are accepted and reported as ignored while the pinned
  image still reads them. A host's file (`config --host`) has no
  `setup.script`, and `sandbox setup` refuses one. Hosts set up by the
  pinned secure-host image (v0.6.9) still get the unused `runner-sandbox`
  user until the pin moves to an image with this change.
- The secure-host forwarder and site CI now select the reviewed actions#180
  pin and attested v0.6.9 image, bringing method/host-only write-refusal
  diagnostics to callers without printing signed URLs. No storage accounts
  are added; identifying the failed artifact-upload destination still needs
  a fresh run using this deployment (#2811).

- `review resolve-dispatch`, `task`, `verdict` and `submit` take an
  opt-in, `REVIEW_DRAFT_CLASSIFIER=true`, for a dispatched review of a
  draft whose verdict carries one checked `agent-board/draft-review/v1`
  result, bound to the pull request's repository, number, head, base,
  title and description and read again before it is submitted. Off by
  default; without it a draft is refused as before, and a verdict that
  opens such a result's fence is now refused. No workflow sets it yet
  ([draft classifier reviews](docs/review.md#draft-classifier-reviews),
  #3040).

- A rebase fix round can hand back a replacement series for a pull request
  that grew past `max_patch_files`: bounds may set `replacement_max_files`
  on `push_to_pull_request_branch` (off by default, at most 500) for the
  series' total. `handback scan` reads a `replacement.json` mail by mail, so
  a run-token fixture that the base commit holds, on a line the series
  deletes, is no longer refused. A run that handed back no result after
  its agent set `stopped_early`, or after a limit stopped it, now gets a
  status line saying it stopped before the task was done instead of ✅.
  The run action and `agent.yml` gain a `stopped-early` output for this
  (#3017).

- Clarify the runner-only credential boundary and current launch refusals.
  Record the still-open #2991 migration, caller key/pin gaps and a dated
  hardening acceptance inventory; credentialless inference/MCP remain future
  work, not a property established by documentation or static checks (#3001).

- GitLab callers can post the run's `summary.md` as a note on their issue
  or merge request, where GitLab renders it. Without the note it is only a
  zip download, because GitLab has no job summary. Off by default:
  `agentic-job check --run-summary FILE` limits it to the job summary's
  size, leaves out a credential-shaped one, and sanitizes it into the
  report as a comment body is sanitized, links included. `agentic-job apply
  --forge gitlab --run-summary` then posts it with mentions and quick
  actions broken (#2995).

- `run`'s refusal of a provider key or broker token in a readable process
  now says whether `/proc`'s `hidepid` hides other users' processes and, if
  not, how to mount a procfs that does; `run` logs a note when a caller's
  procfs is mounted over `/proc`. The docs cover api-key mode on multi-user
  guests such as Testing Farm's (#2994).

- The secure-host forwarder picks up the config-volume SELinux relabel fix
  (actions#190), allowing setup to read its configuration on enforcing hosts
  such as RHEL 10 (#2925). The pinned secure-host image remains v0.6.4.

- Hand-backs also replace the agent-facing inference and MCP proxy tokens with
  placeholders. Run tokens, upstream credentials and private keys still refuse
  publication; refused work is retained in mode-0700 `OUT/refused-handback` on
  the operator's host, never in a public artifact (#2902).

- Opt-in `[commit] allow-base-secret-lines` accepts exact public-base fixture
  lines removed, retained or moved in the same file. New keys and cross-file
  copies still refuse; known run secrets are never exempt (#2914).

- Checked no-write-only outcomes retain long sanitized reports collapsed in the
  opted-in item status comment instead of cutting them at 1000 characters.
  Rendered report/body budgets disclose overflow and link the retained artifact;
  short blocked outcomes and notification opt-outs are unchanged. The shipped
  implement dispatch profile also permits one caller-bounded item comment (#2892).

- Hand-backs replace inference addresses with `<inference-address>` rather than
  discarding the run, and report the replacement count. Credentials and private
  keys still refuse upload; logs keep their current redaction.
  `[inference] allow-base-address-lines` is now a legacy no-op (#2899).

- Replacement-series apply accepts a checked base snapshot between the policy
  snapshot and the trusted current base-branch head, so main advancing during a rebase
  round no longer blocks it. Missing commit arrays are diagnosed separately.

- Opt-in `inference.stop-long-retry-after` stops a silent agent after a
  model 429 requests more than 120 seconds of waiting, reporting
  `inference_rate_limited` without resending the task. A later successful
  model request clears it. Requires `inference.front` or `api-key`.

- Upload-gate refusals name the known run secret's source or the private-key
  rule in the error and run summary, never the matched text (#2828).

- An opt-in post-release check (`check-forwarder-image: true`) fails with both
  tags when the secure-host forwarder's image differs from the newest `v` tag.

- Apply accepts the applying account's existing fork in the output repository's
  fork network even when its parent differs, retaining the ownership and
  Actions-off checks (#2801).

- Egress write refusals name the method and destination host without signed
  URL queries. The runner's results-storage PUT rule also admits the exact
  `productionresultssa32` account, verified by a GitHub artifact redirect (#2811).

- The hosted configurations (`secure-host/hosted.toml` and the agent's
  `.github/agentic-job/hosted.toml`) stop `acpid.socket` and `acpid.service`,
  whose local socket on some hosted runners failed `local-sockets` (#2790).

## v0.6.5 - 2026-11-02

- A silent subagent task no longer disables `stall-timeout`: the stalled
  turn is cancelled and retried once on the same session, keeping its work.
- Runs with a known proxy request count of zero stop after five minutes with
  `no_requests` and retryable exit 4, logging bounded process state and last
  output before killing the agent. Direct providers without counts are unchanged.
- The `secure-host` forwarder runs the secure-host v0.6.4 image, so the
  agent's `agentic-job` on PATH is no longer 0.6.3, which refused the
  v0.6.4 policy's hand-back configuration (#2771).
- Capture refuses request files over 1000 nonblank lines whole, including
  their changes or replacement series, instead of publishing a truncated prefix.
  `handback check` reports the refusal even without a working-tree change (#2750).
- Apply leaves a continued pull request draft under `ready_when_complete` if
  it has a `hold` label (case-insensitive) or its labels cannot be read,
  recording why without failing the applied push (#2690).
- With `[commit] format = true`, Rust hand-back formatting now restores
  changes to files outside the agent's original patch, so workspace-wide
  `just fmt` or `cargo fmt --all` cannot widen it. A missing or failing
  formatter warns and leaves the original change unformatted (#2160).
- A Forgejo Actions dispatch caller, `workflow/forgejo/dispatch.yml`, for
  callers to copy to `.forgejo/workflows/dispatch.yml`, takes agent-board's inputs and refuses a runner that cannot provide the
  sandbox; its session, check and apply are not wired yet.
- `review.yml` takes `workflow_dispatch` (and `workflow_call`) inputs
  `pr`, `head` and `pool`, named `review OWNER/REPO#PR HEAD (POOL)`, so a
  scheduler can start reviews paced by pool: the repository variable
  `REVIEW_POOLS` alone maps the pool to an agent and a model, an unknown
  pool fails the run, and the pull request must be open, not a draft, on
  the base and still at `head`. `policy.yml` and `agentic-job.yml` take
  `review-head` for it. With `REVIEW_RECORD_ONLY`, a JSON array of user
  ids (unset is off), those authors' fork pull request pushes try a
  carried approval and otherwise only set `review` pending, running no
  agent (docs/review.md#dispatched-reviews; part of #2163). A caller
  whose own run is a `workflow_dispatch` must now pass a known `pool`, or
  not call `review.yml` from it.
- Breaking (0.x): a bounds file names its forge with exactly one
  `[github]`, `[forgejo]` or `[gitlab]` section, which holds its
  `outputs`; `[github]` also holds `trigger`, `memory` and
  `secondary_pull_request`, and `[forgejo]` and `[gitlab]` hold
  `push_repo`, which they need to allow `create_pull_request`. The old
  top-level `outputs`, `trigger`, `memory`, `secondary_pull_request`,
  `push_repo` and scalar `forge` keys are refused: move GitHub keys under
  `[github]`, and a Forgejo or GitLab fork into its section, when bumping
  the pinned workflow ref; a top-level `push_repo`, which GitHub's apply
  never read, goes. `policy.json` is unchanged (#1393).
- The extracted `safe-outputs` component provides standalone `check` and `apply`
  commands for bounded JSONL, with explicit trusted context and a separate apply
  credential. Native publishing is limited to new GitHub comments; other writing
  operations refuse before any write. An opt-in deterministic workflow targets
  the existing e2e issue 64 (docs/safe-outputs.md#standalone-cli).
- A Claude Code turn with nothing from it for ten minutes, and no tool call
  running, is cancelled and sent again once, then fails the run as `stall`,
  as opencode's does, rather than holding the job to its limit
  (docs/harness.md).
- The shipped `hosted.toml` installs the distribution's clippy alongside
  cargo and rustfmt for this repository, so sandbox runs can pass Rust
  lint checks without fetching another toolchain.
- The Rust egress proxy explains destinations in its firewall's denied
  ranges with 403 and a private/local-network reason in `X-Egress-Denied`,
  instead of an unexplained 502; `--refuse` and policy denials keep precedence.
- The run action's "Run the agent" step no longer fails now and then with
  exit 141 when it reads where a secret was found, on runners whose `head`
  is uutils (Ubuntu 26.04).
- `workflows check` admits literal `egress: write-policy` on standalone
  secure-host and a narrow trusted artifact consumer with a fixed first
  digest check that requires the payload to be the workspace's only entry.
  `config` and `egress-policy` remain refused because their
  contents are not validated (docs/workflows-check.md).
- `example-deterministic.yml` proposes a pull request with no agent: a
  job runs secure-host and `cargo fmt --all`, and hands the patch to check
  and apply through `proposals-artifact`. CI's `e2e-deterministic` runs it
  staged (docs/safe-outputs.md#without-an-agent).
- GitHub apply optionally binds status, review/result comments, fork-push and
  upstream publication to caller-configured role tokens (`role-bindings`).
  Explicit mappings fail closed on missing or wrong credentials, separate push
  from publication, and use numeric actor/App provenance for ownership.
  Legacy PAT fallback is unchanged without a mapping. Role mode requires native
  handlers and excludes replacement pushes; live App proof remains unfinished
  (docs/safe-outputs.md#caller-bound-publisher-roles).
- `agentic-job apply --forge forgejo|gitlab` routes status, review comments,
  fork pushes and publication through the same roles when the caller sets
  `APPLY_ROLE_BINDINGS` and the four role tokens: each token's numeric
  `/user` id must match its `actor_id` before any write, `app_id` refuses,
  a new pull request is pushed with `PUSH_TOKEN` and opened with
  `PUBLICATION_TOKEN`, and a missing role token never falls back to
  `FORGEJO_TOKEN`/`GITLAB_TOKEN` (docs/safe-outputs.md#forgejo-and-gitlab-roles).
- apply's result step, which sets `result-url` and the no-result outputs
  and summary, is policy's binary, `agentic-job result`, in place of a
  github-script step, with the same outputs, summary and sanitized reason.
  The step no longer receives apply's write token: it makes no forge
  writes (docs/workflow.md#what-a-run-leaves).
- Secure-host admits CentOS Stream 10 by exact `ID=centos`, `VERSION_ID=10`
  with its own privileged-binary allowlist. The forwarder selects a RHEL 10 /
  CentOS Stream 10 cloud default that stops local listeners without socket
  exceptions; AlmaLinux, Rocky and untested releases remain refused.
- Move ordinary Ubuntu VM jobs, examples and the reusable workflow's
  `runner` default to Ubuntu 26.04, matching `agent-runner`. Explicit caller
  runner selections remain unchanged.
- `native_handlers` also takes `push_to_pull_request_branch`,
  `create_issue` and `create_pull_request_review_comment`, which
  agentic-job's own handlers publish as gh-aw's pinned handlers do. A
  push is check's patch on the run's head, with a lease on it, to the
  pull request's branch in `head-repo`, with gh-aw's commit comment; its
  commit is dated the patch's author date. An issue for an issue event is
  linked as that issue's sub-issue. Review comments go in one review of
  event `COMMENT` after every other routed request, and are refused in a
  run that leaves gh-aw any type. The publication corpus gains cases for
  sub-issues, a comment outside the diff and re-runs mixing both
  handlers (docs/safe-outputs.md#agentic-jobs-own-handlers).
- Repair live Forgejo inline-review assertions: deleted-line comments identify
  the fixture's base commit, while the review and checked target bind current
  head. Keep the subsequent stale-head, out-of-diff and pending-review
  zero-write checks and metadata cases in the same scenario.
- Tailnet container refusals share one container start per endpoint, with
  the existing target IDs, order and ten-second deadlines. The batch uses
  the serial container lane within the bounded probe pool; missing or
  malformed target results fail closed and name the affected targets.
- Secure-host checks refill a bounded probe pool as each attempt finishes,
  rather than waiting for the slowest attempt in each batch. Report order,
  probe IDs and refusal deadlines are unchanged; note-only runner controls
  retain their separate three-second bound.
- Forgejo `apply` preflight now projects labels per item in batch order,
  allowing an explicitly authorized remove-then-add exclusive-label
  transition without weakening live pre-write checks. Label paging accepts
  all repositories up to the advertised 1000-label ceiling and still
  refuses overflow. Real-Forgejo coverage now includes labelled issue
  creation, issue/PR closing, wrong-kind refusals and close reruns with
  the scoped apply token.
- GitLab commit statuses now require GitLab 18.5+ and trusted `--status-ref` and
  `--status-pipeline-id`, validated against the project and pinned SHA
  before any writes; archived pipelines or CI configuration errors refuse.
  Reruns compare only the current job's full state,
  description and run URL across bounded pages; an older match no longer
  suppresses an update, and `error` updates a previous `failure` description.
  Another run's pending/running job refuses instead of taking over its
  identity. Status remains opt-in, with no agent-visible request or new
  token permissions; ambiguous legacy status calls fail explicitly.
- apply's guard against applying twice what an earlier attempt applied
  is policy's binary, `agentic-job applied`, in place of a github-script
  step, with the same names, refusals, re-closing and outputs; apply's
  token now goes to the binary there, as it does for the fork step. Its
  step annotation on a refusal no longer starts `Unhandled error: Error:`
  (docs/workflow.md#running-apply-again).
- Forgejo and GitLab `apply` now publish the neutral
  `create_pull_request_review_comment` output, off unless bounded in policy.
  `check --review-head SHA` binds it to the caller's fixed PR/MR and admitted
  head; apply refuses foreign targets, stale heads, unavailable or
  out-of-diff anchors, a push to the same PR/MR and, on Forgejo, a pending
  review it would submit, before writing. Forgejo uses line positions in a
  comment-only review; GitLab uses discussion positions with base/start/head
  SHAs. Multiline fields are refused, not silently shortened. No approvals,
  reviewer assignments or thread-resolution operations are added.
- `agentic-job apply --forge gitlab` also publishes
  `push_to_pull_request_branch`, one commit on the policy's open merge
  request's branch in the bounds' fork, under the same patch, head and
  lease rules as Forgejo's; a merge request from another project or
  branch, or whose head moved, is refused before any write. `--status`
  and `--status-sha` now set the caller's commit status on GitLab too,
  name `agentic-job`, with `failure` and `error` both GitLab's `failed`;
  a re-run finding its own status set writes none
  (docs/safe-outputs.md#publishing-to-gitlab).
- The pinned model price table accepts opt-in `estimate = true` rates with
  a required one-line `basis`. Run costs include these rates and label the
  figure estimated in `summary.json` and `summary.md`, naming the estimated
  models; models without rates remain unpriced.
- Run costs price `gpt-6.1-sol`, `gpt-6-astra` and `gpt-6-luna` at
  OpenAI's standard-tier list prices instead of reporting them unpriced.
- `native_handlers` also takes `add_labels`, `remove_labels`,
  `close_issue` and `close_pull_request`: agentic-job's own handlers
  publish them as gh-aw's pinned handlers do, which the publication corpus
  checks for each, now with cases for filtered and missing labels,
  already closed and reopened issues, failed closing comments and a run
  mixing both handlers across a re-run. A routed request must name its
  item by number, and its labels must be plain ones, which `check`
  enforces. Every other type, `push_to_pull_request_branch`,
  `create_issue` and `create_pull_request_review_comment` among them,
  stays gh-aw's (docs/safe-outputs.md#agentic-jobs-own-handlers).
- `agentic-job apply --forge gitlab` also publishes `create_issue`,
  `close_issue`, `close_pull_request`, `add_labels` and `remove_labels`.
  GitLab numbers issues and merge requests apart, so on GitLab a label
  request names its item by exactly one of `issue_number` and
  `pull_request_number` (`item_number` stays refused there), which
  `agentic-job collect` now takes for those types; it refuses an
  `issue_number` or `pull_request_number` a type does not take there
  instead of dropping it. Every label must already exist in the project
  by its exact name, as GitLab would create it; a re-run changes nothing
  more (docs/safe-outputs.md#publishing-to-gitlab).
- `summary.json` gives `cache_ratio`, the share of the run's input read
  from the prompt cache, and `cache_warning`, true for an opencode run
  that read under half from it after more than three requests;
  `summary.md` says both (docs/inference.md#prompt-caching).
- Runs with agent `claude` whose `run` is newer than the pinned
  secure-host image, such as `review.yml` at a commit of main, start
  again. Since the attribution change below they stopped on
  "managed-settings.json is not what this run's configuration calls
  for": the image's release writes the managed settings without the
  attribution switches, which are now in the user settings `run` writes
  in the agent's home.
- `agentic-job apply --forge gitlab` publishes a checked hand-back's
  `add_comment`, as a note on the caller's issue or merge request
  (`--comment-target-kind` says which), and `create_pull_request`, as a
  merge request from the bounds' fork, to GitLab with `GITLAB_TOKEN`.
  Every body has GitLab's mentions (`@all`, `@here`, groups) and quick
  actions (a line starting with `/`) broken, including inside code so
  escaped delimiters cannot bypass the filter; other types and `--status`
  are refused (docs/safe-outputs.md#publishing-to-gitlab). On Forgejo
  too, a pull request's title now has its mentions broken.
- `sandbox setup` and `sandbox check` take less time in the slow tail
  of hosted runs: apt installs suspend needrestart's process scan, the
  network stage cuts a runner's control short after 3 seconds (one that
  has not connected is a note, as before), and the tailnet's refusals
  from a container are made at once in one container. Every probe and
  refusal timeout stays.
- `[commit] format`, off by default and set by `hosted.toml`, has `run`
  format a branch run's Rust before taking its patch: `just fmt` where
  the Justfile has it, else `cargo fmt --all`, as the sandbox user. A
  missing rustfmt is a warning (docs/safe-outputs.md#what-the-agent-does).
  `hosted.toml` adds `rustfmt` to this repository's packages.
- `review.yml`, with the repository variable `REVIEW_HISTORY=true`, gives
  the review agent the pull request's earlier verdicts by the review job,
  their findings and the replies to them, the commits since each and the
  conversation's comments, sanitized, as an untrusted
  `~/review-history.json`; the review task has it settle earlier findings
  first and record resolved ones on `Resolved:` lines. New:
  `agentic-job review history`, `run --review-history` and `agent.yml`'s
  `review-history` input (docs/review.md#review-history).
- `sandbox.close-resolved`, off by default, closes systemd-resolved to
  every user but root and the runner's, so the sandbox user cannot send
  data out in a name lookup around the egress proxy; both `hosted.toml`
  files set it. No release note had named it (docs/sandbox.md).
- `agentic-job dispatch`'s `review` profile, like `review.yml`, asks whether a
  change should exist as written before whether it works, blocking with
  "should not exist as written: X instead", and flags tests that only restate
  the implementation as important findings.
- `review.yml`, with the repository variable `REVIEW_CARRY_APPROVAL=true`,
  carries the previous head's approval to a push that is only that head
  rebased onto the base branch or rustfmt's output of it, instead of
  running the agent; the status `review`, and the submitted review where
  real reviews are on, say whose approval and why. New:
  `agentic-job review carry`; `review submit --accepted` is optional for
  a carried approval (docs/review.md#carried-approvals).
- A run the timeout stops no longer ends well when the agent answers the
  cancel with `end_turn`, as opencode does, without the output the run
  requires: the agent gets its hand-back turn, and a run that still hands
  back nothing exits 124 with `the agent timed out without handing back a
  result`, which the run action makes its error annotation. A review that
  timed out with no verdict had concluded success, so nothing re-ran it
  (#2149). opencode now has a `stall-timeout` of 600 seconds: one of its
  model requests hung for 70 minutes, until the timeout, and a stall's
  cancel it answers with `end_turn` is still a stall (docs/harness.md).
- `agentic-job apply --forge forgejo` publishes `push_to_pull_request_branch`:
  one commit on the policy's open pull request's branch, only in the bounds'
  `push_repo` fork, only at the head the run was asked for, without force and
  under a lease on that head, so a branch that moved is refused. Its new
  `--status STATE --status-sha SHA` sets the caller's commit status, context
  `agentic-job`, after every other write; no request can ask for one
  (docs/safe-outputs.md#pushing-to-a-pull-requests-branch-on-forgejo,
  docs/safe-outputs.md#commit-statuses-on-forgejo).
- A bounds file's `native_handlers` (off by default) has apply publish
  `add_comment` and `create_pull_request` on GitHub with agentic-job's own
  handlers (`agentic-job publish`) instead of gh-aw's. They send what gh-aw's
  pinned handlers send, which the publication corpus checks, and they
  refuse a run that gh-aw would publish differently before writing anything.
  The routed requests must come before every other type but `noop`,
  `missing_tool` and `missing_data`, which `check` enforces
  (docs/safe-outputs.md#agentic-jobs-own-handlers).
- `agentic-job diagnostics handler-errors` takes more than one report.
- `agentic-job apply --forge forgejo` also publishes `add_labels`,
  `remove_labels`, `close_issue`, `close_pull_request` and `create_issue`,
  and writes nothing for `noop`, `missing_tool` and `missing_data` instead
  of refusing them. Before any write it reads each target and refuses
  another kind of item or one not of the repository, and a label the
  repository lacks, which it never creates, or a label change Forgejo
  would carry out on other labels; it refuses fields Forgejo has
  no meaning for, such as `temporary_id` or `state_reason: not_planned`
  (docs/safe-outputs.md#labels-issues-and-closing-on-forgejo).
- Status edits drop a run-supplied `agent-board-maintain-plan` marker rather
  than give it bot-last-edited provenance. Fake-forge and workflow tests pin
  this contract, including completion and retries; ordinary caller markers
  are still preserved (docs/workflow.md).
- CI's new `forgejo` job runs `agentic-job apply` against a real Forgejo
  15 LTS container: a comment and a pull request from the bot's fork, a
  neutralized mention and a refused protected path, with a token scoped to
  `write:repository` and `write:issue` (docs/safe-outputs.md#publishing-to-forgejo).
  It is not yet a required check.
- `run` no longer succeeds when the inference proxy no longer knows the
  run's token at its end (HTTP 401, as after a broker restart): it says
  `inference token revoked mid-run (broker restart?)` and exits 1, or 3
  with the change as a partial one if the agent handed one back
  (docs/inference.md#what-run-does). Under `ready_when_complete`, the
  agent's own request from a run that stopped early now carries a
  checkpoint too, so that it opens as a draft. Broker token loss is reported
  as `inference_unreachable`, including for a partial change.
- Under `egress.write-policy`, the runner may also upload to the verified
  results storage accounts `productionresultssa31` and
  `productionresultssa30`, alongside gh-aw's first twenty. Hosted runners
  now get these accounts, so `upload-artifact` failed (tracker#974).
- With `[session] listen`, `sandbox check` probes that the sandbox user cannot
  reach the session bridge on loopback or at the node's own tailnet addresses,
  against a listener of the runner's user as the control
  (docs/sandbox-check.md#a-sessions-bridge).
- `.github/agentic-job/private-digest/` is a reference caller for a private
  repository: one digest comment on one issue, with the sandbox user, the
  egress allowlist and the job's read token. It is an example to copy and is
  not installed (docs/private-repositories.md#a-reference-caller).
- dispatch.yml's `target` job runs `agentic-job dispatch` in place of its
  github-script step, with the same refusals, outputs and task text. It
  checks out the agentic-job source to get the binary: a copy names
  `cgwalters-forge/agentic-job` and the commit its `run` job pins there
  (docs/dispatch.md).
- `policy.yml` and `agentic-job.yml` can take the task as an artifact,
  `task-artifact`, as an alternative to `task`, which still works: the
  runner drops a job output its secret masker changes, so a task quoting
  credential-shaped text passed this way no longer reaches policy empty.
- `budget-usd` caps a run's spend in US dollars. `budget` (AIC) is
  deprecated and used only while `budget-usd` is empty; it will be
  removed after one release. Run summaries and opted-in status comments
  report the run's cost in dollars.
- A run a model provider's failure stopped hands back its uncommitted
  change as a partial pull request instead of losing it. Sessions retry
  a transient provider failure for every agent, and Claude Code can fall
  back to `agent.fallback-model` after a long overload. The new
  `failure-class` output names what a failed run died of.
- A run that hands back only `missing_data` is reported as blocked (the
  `blocked` output) and apply succeeds.
- Policy admits a run that asks for the bounds'
  `[secondary_pull_request]`, and apply opens it from
  `SAFE_OUTPUTS_PAT`'s fork, never with the job token.
- `dedupe = true` in the bounds refuses a dispatch that overlaps an
  active run. The policy job now needs `actions: read`: a caller that
  calls `policy.yml` itself must grant it.
- The detector retries registering and ending the run through a proxy
  restart.
- A session admits tagged tailnet nodes by `[session] capability`, and
  `agentic-job session connect` joins one from a terminal.
- `agentic-job collect` validates every safe-output type a run may be
  allowed, and is now the only collector, in `handback check` and in the
  check job; gh-aw's collector no longer runs. Event admission,
  dispatched reviews, label activation, push, status comments and issue
  linking moved from workflow JavaScript into the binary.
- Claude Code's own commit and pull request attribution is turned off in
  agent runs, so the run's configured trailers are its only credit
  unless the target repository's settings turn it back on.
- The run action's setup duration report is gone.
- The egress proxy refuses an address a refused name resolves to before
  its domain allowlist, so the error names the right cause.

## v0.6.4 - 2026-10-23

- Off GitHub: `agentic-job collect` validates safe outputs in Rust, and
  `agentic-job apply --forge forgejo` publishes a checked hand-back to
  Forgejo. Runs off GitHub are held to a neutral safe-output profile, and
  bounds may admit plain-HTTP clone URLs for hosts they name.
- `run` fronts the inference broker with its own proxy, so the agent
  never holds the run token, and the handback scan refuses a run token.
- The runner's user is the default agent user; `agent-user: sandbox`
  selects the second user. `sandbox.create-user = false` opts out of
  creating it.
- New inputs: `agent-user`, `egress-write-policy`, holding the agent job
  to the egress proxy's write rules, and `status-comment`, naming the
  comment a run's status goes in.
- A hand-back whose requests file is not taken is dropped, and the
  summary says why.
- Bounds may add protected paths as globs, and the per-output pins apply
  to `add_reviewer` and `assign_to_user`.
- Bounds may reserve a `[secondary_pull_request]`; policy still refuses a
  run that would open one.
- Under the runner lock, the metadata, runner-read and Worker-diagnostics
  rules are on by default.
- Apply escapes what its handlers log, so a patch cannot form a workflow
  command, and keeps carriage returns in patches applied to Forgejo.
- The documentation is published as a site on GitHub Pages.

## v0.6.3 - 2026-10-19

- The second user, `secure-host/internal` and `sandbox exec` are
  retired.
- A named inference broker can be given its tailnet address by the agent
  job.
- A session hands back when the agent is stuck on one tool call, and
  retries a rate-limited task turn before asking for a hand-back.
- Review logs why GitHub refused a review submission.

## v0.6.2 - 2026-10-18

- The public `secure-host` action forwards to
  `cgwalters-forge/actions/secure-host`, and the agent runs as the
  runner's user after it.
- Safe outputs are handed back by artifact id and digest, and check
  verifies the digest.
- The inference run is registered in a job before the agent's, which
  loses `id-token`.
- Opt-in: every runner process held to the egress write policy, and the
  runner-read rule turned on from the host configuration.
- Review carries inline findings in the submitted review.
- Status updates on the same repository honor the caller's identity.
- `workflows check` holds proposals to the base's shape policy and pins
  secure-host's new path.

## v0.6.1 - 2026-10-17

- The release's secure-host image is attested, and its digest is read
  without a trailing newline.

## v0.6.0 - 2026-10-17

- The first release with the secure-host image: a FROM-scratch image,
  built and attested, that sets the host up through `nsenter`, and runs
  the egress proxy as a root podman unit.
- Opt-in: refuse reads between the runner's processes.
- Forgotten shell overrides are kept away from runner credentials.
- `workflows check` holds secure-host jobs to the two-job pattern.
- `handback check` refuses a `missing_data` with no reason.
