# Private repositories

Runs are public-only by default. The public-only admission check stops private
source and configuration from becoming public run evidence. API errors, unknown
visibility and internal repositories are refused, not treated as public. A
caller can opt one kind of private run in: its own private repository as the
target, with `private = true` in every bounds file, the egress domain allowlist
on the agent machine and its runner's logs kept private. Such a run hands back
comments, reviews and other non-patch outputs, not a patch or a project
update. Each checked
condition below is refused when it does not hold.

## What is published today

The reusable workflow checks target, agent-configuration and item repository
visibility on the policy machine; context resolution independently requires
public metadata. The run action checks target and agent-configuration visibility
again before artifact upload. This second check cannot recall material already
sent to inference, printed in a job log or written to a summary if visibility
changes during execution. The standalone CLI's bounds checks are not a private
workflow admission guarantee.

The [run evidence guide](workflow.md#what-a-run-leaves) lists the artifacts and
retention periods. The agent job prints a condensed transcript to its Actions
log and writes a rendered session/job summary. `agent-run` retains summaries,
the condensed log and outcome for 90 days; `agent-transcript` retains the fuller
transcript, tool output, agent logs and egress evidence for 30 days. Proposed
patches and safe-output requests are retained in `safe-outputs` for 30 days.
Policy, checked-output and applied-result artifacts record decisions and
destinations. Applying outputs creates durable forge objects such as PRs,
comments and reviews, potentially in a different repository.

On a public caller these are public run evidence (artifact downloads may require
authentication). A private caller's Actions access controls do not make a run
safe on their own: the target, caller, output repository, runner operator and
inference service can be different trust domains. Runner provisioning/diagnostic
logs are another publication surface; some runner providers publish them
separately from Actions. Shorter artifact retention does not retract logs,
downloads or already-applied outputs.

## What a private run would leak

A hostile job can copy source, configuration, filenames and issue text into
tool output, reasoning, summaries, patches or requested comments. Current
[redaction](workflow.md#github-reads-from-the-agent) removes known credential
values; it is not a private-source classifier. Source transformed, encoded or
split by a hostile process cannot be made safe by ordinary secret masking.
The agent also sends context to inference, whose access and retention policy
must be part of the confidentiality decision.

Network write restrictions alone do not stop exfiltration: a GET path can carry
private bytes to an attacker. The shipped reads-anywhere policy permits that
unless the destination is otherwise denied. Even an allowed shared service or
attacker-controlled subdomain can receive those bytes. Runner-user processes,
direct endpoints and local services must not provide a bypass around the
sandbox user's proxy policy.

## Opting in

The reusable workflow refuses a private target, or a private caller, for
now, whatever the bounds say: its agent job runs the agent as the
runner's user, with no second user between it and `run`, until the host
keeps the runner's processes from reading each other
([workflow.md](workflow.md)). What follows is what the binary admits for
a caller that composes its own agent job with a sandbox user.

Add `private = true` at the top level of the caller's bounds file, and of the
organization's if there is one; both must set it. Then a run is admitted with a
private target only if all of these hold, each checked where it is enforced:

- **Evidence stays with the repository's audience.** The policy job admits a
  target that is not public only if the API reports it `private` and it is
  the calling repository. Its Actions logs, summaries and artifacts are then
  visible only to its collaborators. `agentic-job policy --private` refuses
  the run unless every bounds file opts in. It also requires the output
  repository to be the target, so that comments and status do not land in
  another, possibly public, repository; the workflow accepts no `item-repo`
  for a private run. It refuses `create_pull_request` and
  `push_to_pull_request_branch`: apply pushes a patch through a fork, which
  it checks without a credential, so a private fork is out of its reach.
  Off GitHub, every bounds file naming the same `push_repo` admits
  `create_pull_request` when it is asked for by name (`all` leaves it
  out). Forgejo's apply pushes only to that fork, and only if the fork is
  private ([publishing to Forgejo](safe-outputs.md#publishing-to-forgejo)).
  It refuses `update_project` too: a project's fields are read by the
  project's audience, which nothing confines to the repository's.
  The run action repeats the visibility check before upload.
- **The proxy limits where the source can go.** `run` refuses a private
  policy unless the sandbox uses the egress proxy (`egress.proxy`) and the
  policy file the proxy enforces sets `[egress] mode = "allowlist"`
  ([domain allowlist](sandbox.md#opt-in-domain-allowlist)), selected by
  `egress.policy` in the caller's configuration. That file may keep no
  `[[write]]` rule but git fetch's `POST` to paths ending in
  `/git-upload-pack`: any other rule is a channel to what its endpoint stores.
  The shipped GraphQL rule, for example, would pass a mutation that another
  token posts to a public issue, so `gh`'s GraphQL reads are unavailable;
  REST reads (`gh api`) still work. Review every allowed domain, the inference
  endpoint and any `egress.direct` endpoint as a place the source can go:
  direct endpoints do not pass the proxy, and the check cannot judge them.
- **One read credential, for the target only.** The agent configuration
  and context repositories are cloned without a credential and stay
  public-only. `run` refuses
  a private policy without the job's read token (`github-reads`, the default).
  It clones the target with a git credential helper scoped to the target's
  clone URL, which reads that token from the sandbox user's file of it. The
  token is never in a command line, URL or configuration value. The job token
  can read only the calling repository and expires with the job; no PAT is
  added. Policy and check keep read-only access; only apply holds a write
  credential.

One condition cannot be checked: **the runner's own logs must not be public.**
Use a runner whose provisioning and diagnostic logs only the repository's
audience can read, such as the caller's own. Some providers, including
bootc-dev's devspace runners, publish theirs. The runner is a workflow input,
so a caller that opts in should not let a dispatcher choose it. Inference
access and retention are likewise the caller's decision.

Organization and repository identities come from the caller's repository: the
bounds files it owns and the repository the workflow runs in, never a workflow
input a dispatcher can set. BPF host evidence and release binaries improve other
boundaries; they do not make a private run safe on their own.
