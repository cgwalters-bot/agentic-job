# Pull request review caller

[`review.yml`](../.github/workflows/review.yml) admits same-repository pull
requests targeting `main` and `/review` comments from actors with admin,
maintain or write permission. Forks and issue comments are refused. The
workflow, bounds and [standing task](../workflow/review.md) come from the base,
not the pull request head.

The separate [dispatched review](dispatch.md) also accepts open fork pull
requests on the configured base. It resolves the exact head SHA through the
target repository's PR API and fetches that SHA without forge credentials in
the sandbox. It does not use the fork's URL or branch as a fetch argument,
broaden job permissions, or change automatic event admission. Fork end-to-end
CI remains a separate concern.

To try the scripted caller in another repository, follow the
[complete copy and edit list](workflow.md#event-triggered-callers), including
the setup script, bounds and standing task. No label is needed for this caller.

Review is an analysis run. Real agents start in the base checkout, with the
exact admitted head SHA checked out beside it and named in the task as data.
The scripted agent starts in the head so its verdict can report that SHA.
The only output is one verdict comment or noop. A separate clean check job
requires `VERDICT: APPROVE`, `VERDICT: CHANGES` or `VERDICT: REJECT`, followed
by a `REASON:` line of at most 200 Unicode characters. It rejects alternate
targets and editing fields. The apply job checks out no caller code and posts
only the checked text; a verdict is not a GitHub approval or merge authority.

## Enabling a real reviewer

The checked-in caller still uses `fake` and its scripted setup. To deploy a
real reviewer, remove that setup and choose `agent: opencode` or `agent: claude`.
Use a disposable runner with systemd 257 and connectivity to the inference
proxy, configure `inference-url`, retain `inference-register: github-oidc`,
and set a nonzero `max-requests`. Opencode also needs a `model` naming a model
served by the proxy. The reusable workflow supplies its default opencode npm
pin; a caller can override `npm` like other dependencies. Claude's pinned ACP
adapter is also supplied by default; neither agent needs an explicit `npm` input.

The caller grants contents, issues and actions read for the agent's GitHub
reads, id-token write for broker registration, and pull-requests write for
posting. Policy and check restrict themselves to
contents read. The agent job has no comment token accessible to the sandbox;
only the separate apply job posts. No inherited secrets or apply environment
are needed with GitHub OIDC. Keep the existing full action pins and use a
reviewed reusable-workflow commit when copying the caller to another repository.

For this repository, deployment requires changing `review.yml` from the fake
setup, selecting `agent-runner` labels for a proxy-reachable disposable runner,
and supplying `inference-url` (for example from `vars.INFERENCE_URL`) and the
opencode `model`. A request cap such as `max-requests: '100'` is required;
`kind: analysis`, `outputs: add_comment,noop`, `max-outputs: '1'`, `notify: none`,
`allow: workflow/review.toml` and the standing task stay unchanged. No new secret
is required in OIDC mode. The private runner labels, proxy URL and supported
model are deployment values, not known from this checkout; hosted Ubuntu alone
cannot reach a private proxy.

Optional hardening is narrowing which workflows the proxy admits, tracked by
cgwalters-forge/tracker#452. That does not replace event admission or sandboxing.

## Coverage and limits

The run is ephemeral and creates no persistent state. The agent already runs
arbitrary code inside the sandbox, including tests and writes to its own
instructions or configuration. Protecting those files from the agent is not a
security boundary. The boundary is the sandbox, no credentials in reach, and
one verdict checked and posted by separate jobs. A malicious head can influence
the verdict; a queued verdict names the admitted SHA, not necessarily the newest
head, and is never merge authorization.

Automatic PR events cancel superseded reviews in the caller's per-PR job
concurrency group. `/review` comments share the group but cannot cancel an
active run before authorization; ordinary comments do not enter it. GitHub can
still replace a pending job in that group with an unauthorized `/review`
request; this is not a guarantee of queued-review availability. A verdict
already posted is not removed by cancellation. See [CI runner use](workflow.md#ci-runner-use)
for the docs-only CI filter and the batching trade-offs.

`node --test workflow/review.test.cjs` covers admission, request bounds and
hostile outputs. The scripted privileged run and hosted comment posting need
the prepared CI runner and GitHub Actions respectively. They do not assert
real-model review quality.

The opt-in captured-request regression uses a real opencode runtime and a
loopback deterministic model endpoint, not credentials or real inference:

```sh
cargo build --locked
AGENTIC_JOB_TEST_REAL_OPENCODE=1 node --test workflow/review-runtime.test.cjs
```

Install the workflow's npm version on PATH first. The test checks a trusted
instruction positive control and data-file reads, and that hostile head
AGENTS.md, CLAUDE.md and project configuration are not loaded as instructions
at startup. Without the opt-in it is skipped. It makes no immutability claim.

The npm registry available during this change reports `opencode-ai` latest as
1.18.35, not a stable 2.x release. The workflow default uses that available
release; the launcher no longer refuses versions. The 2.x migration and its
configuration/ACP breaking-change review remain pending publication of an
installable stable 2.x package.
