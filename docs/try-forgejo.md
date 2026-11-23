# Getting started on Forgejo

> This text is LLM generated.

Start with a scripted trial that checks a one-file patch and a request to
open a draft pull request. The trial in [PR #4506](https://github.com/cgwalters-forge/agentic-job/pull/4506)
is not in the baseline Forgejo caller: it runs no agent, uses no inference
endpoint, and opens no pull request. A separate CI fixture demonstrates
standalone publication to disposable Forgejo.

## Run the check-only trial

1. Use a dedicated Forgejo Actions dispatch repository, a separate public
   target with an initialized base branch, and a bot fork named in the bounds.
   Use a trusted, isolated runner with Bash, Git, jq and a pinned `agentic-job`
   binary. The runner must reach the forge directly over HTTPS: the trial
   reads the base anonymously without a proxy or redirects.
2. Review the [trial workflow](https://github.com/cgwalters-forge/agentic-job/blob/57a9402a33334bdbe09be5c6fe7196192f83139c/workflow/forgejo/dispatch.yml)
   and its [setup and bounds example](https://github.com/cgwalters-forge/agentic-job/blob/57a9402a33334bdbe09be5c6fe7196192f83139c/docs/dispatch.md#scripted-forgejo-trial).
   Copy that revision's workflow to `.forgejo/workflows/dispatch.yml` on the
   dispatch repository's protected default branch. Set `TRIAL_RUNNER`
   to the runner's labels as JSON (for example `["agentic-job"]`),
   `TRIAL_FORGEJO_URL` to the instance URL and
   `AGENT_BOUNDS` to the absolute path of a runner-owned bounds file. Use
   the linked bounds example for one `create_pull_request` and one patch file;
   omit `allow_http` for HTTPS. Set `TRIAL_SCRIPTED=true` to opt in.
   Do not put a publishing PAT in dispatch-repository secrets or on any
   runner available to the dispatch repository:
   Forgejo's automatic job token can write to the dispatch repository even
   with `permissions: {}`, and a runner label does not authorize a workflow or ref.
3. In Actions, manually dispatch `dispatch` on the repository's default
   branch with `kind=implement`, `repo` set to your public target, `base` to
   its admitted base branch, and `task`, `item` and `pool` filled in
   (for example `say hello`, `1` and `trial`). The script ignores the task.
   The check step must succeed; it leaves `checked/report.json` with
   `ok: true`, one draft `create_pull_request` item and the matching
   `aw-agent-run-<run-id>.patch` alongside it under the job's `RUNNER_TEMP`.
   There is no uploaded artifact or PR URL; use the job log to check the step
   unless you have trusted access to the still-existing temporary directory.

The [review of the trial revision](https://github.com/cgwalters-forge/agentic-job/pull/4506#pullrequestreview-6014559063)
reports a successful disposable loopback Actions dispatch and zero PRs;
the HTTPS setup above remains unverified. Separately, the
[trial's CI job](https://github.com/cgwalters-forge/agentic-job/actions/runs/45068962963/job/137351452957)
tests the producer and check scripts against a real Forgejo service, not the
Actions runner. The fixture checks both the accepted request and refusal of
an oversized patch.

## See a pull request in the publication fixture

On a disposable Linux Docker host with Git and stable Rust, use the
[`forgejo` CI job](../.github/workflows/ci.yml) on the main checkout to start
its loopback service and set the fixture environment, then run:

```sh
cargo test --locked --test forgejo -- --ignored --nocapture
```

The [fixture](../crates/agentic-job/tests/forgejo.rs) mints its own bot PAT
with `write:repository` and `write:issue`, then verifies the apply URL,
fork branch and one-file PR diff. Forgejo marks the draft with `WIP:`.
These scopes are for [standalone apply](safe-outputs.md#publishing-to-forgejo),
not for the trial. Never point the fixture at a shared instance or wire the
trial's checked files to a PAT-bearing Actions runner. Follow
[#4505](https://github.com/cgwalters-forge/agentic-job/issues/4505) for a
trusted Actions publication handoff and
[#2999](https://github.com/cgwalters-forge/agentic-job/issues/2999) for
credentialless runner inference; the trial wires up neither.
