# Getting started on GitLab

> This text is LLM generated.

Start with a pipeline that posts one fixed issue note. It exercises policy,
production, check and apply without a model or an agent. A separate CI fixture
opens a draft merge request on disposable GitLab CE; that is not an agent run
or a proof that the pipeline below publishes merge requests.

## Run the deterministic caller

1. Start with a public `GROUP/PROJECT` (no subgroups for this example), a
   protected default branch and an open issue. Use fresh isolated Linux x86-64 runners tagged
   `agentic-job-producer` and `agentic-job-trusted`, with a POSIX shell, Git,
   curl, jq and sha256sum. Use a publicly trusted HTTPS endpoint for the
   GitLab API. No inference endpoint is used.
2. Follow [release verification](gitlab.md#pinned-release-binaries), then
   install the [bounds](gitlab.md#bounds) and
   [`.gitlab-ci.yml`](gitlab.md#minimal-deterministic-pipeline) on the
   protected default branch. Substitute your host, project, base, verified
   SHA-256 and issue IID. Keep the bounds at one `add_comment`. The example
   names a `push_repo`, but the note-only policy never uses it; only the
   merge-request fixture needs an actual fork.
   Restrict pipeline-variable overrides to trusted operators so another
   dispatcher cannot replace the binary pin and checksum or redirect apply.
   Set [the bot's `GITLAB_TOKEN`](gitlab.md#publisher-secrets-and-lifecycle)
   as a masked, protected variable scoped only to `agentic-job-apply`.
   Use the `api` scope for the note API; give the bot only the project
   access it needs to comment. Do not expose the token to produce or check.
3. In GitLab, select **Run pipeline** on the protected default branch. This
   caller accepts the web trigger, not a push or API trigger. Look for a
   successful check and the `checked/report.json` artifact, then confirm
   apply posted `Deterministic GitLab caller proof.` once on the selected issue.

**Unverified on a live runner:** the pinned example and its web trigger.
`cargo test --locked -p agentic-job --test policy documented_gitlab_caller_fits_its_bounds`
checks the caller's configuration and runs its producer through collect/check
locally; it does not apply the note.

## See a draft merge request in the publication fixture

On a disposable Linux Docker host with Git and stable Rust, follow the
[`gitlab` CI job](../.github/workflows/ci.yml) to start its loopback GitLab CE
and set the fixture environment, then run:

```sh
just test-gitlab
```

The [fixture](../crates/agentic-job/tests/gitlab.rs) creates its own bot, `api`
PAT, target and fork. It checks that apply prints a URL for `Draft: Fix it`,
that the merge request comes from the fork into `main` with the one-file diff,
and that apply leaves the target branch unchanged. This tests
[GitLab publication](safe-outputs.md#publishing-to-gitlab), not GitLab Runner.
See the [passing fixture run](https://github.com/cgwalters-forge/agentic-job/actions/runs/45068962963/job/137351453002).
Never point the fixture at a shared or production instance.

**A model-backed run is not supported.** GitLab has no supported inference
registration path for the runner-only setup. Follow
[#2903](https://github.com/cgwalters-forge/agentic-job/issues/2903) and
[#2999](https://github.com/cgwalters-forge/agentic-job/issues/2999); don't
substitute a provider key or a bearer token on the producer.
