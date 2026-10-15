# Private repositories: why runs are refused

Private runs are not supported. There is no `private = true` setting or
dispatcher override. The public-only admission check stops private source and
configuration from becoming public run evidence; repository bounds alone do
not establish confidentiality. API errors, unknown visibility and internal
repositories are refused, not treated as public.

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
safe: the target, caller, output repository, runner operator and inference
service can be different trust domains. Runner provisioning/diagnostic logs
are another publication surface; some runner providers publish them separately
from Actions. Shorter artifact retention does not retract logs, downloads or
already-applied outputs.

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

## Requirements before any future opt-in

Keep the existing public-only gate until all of these have an implementation
and acceptance evidence. This document does not grant an exception.

- **Evidence disclosure:** keep private logs, summaries, artifacts, caches and
  runner diagnostics within the intended audience, including failure, rerun
  and post-job paths. Define retention/deletion and access policy for each
  surface. Redact sensitive evidence before publication or withhold it;
  token masking alone is insufficient. Check output destinations against that
  audience before apply, and cover inference retention/access separately.
- **Network disclosure:** require the shipped bounded
  [domain allowlist](sandbox.md#opt-in-domain-allowlist) from #616, selected by
  trusted caller configuration. Its maximum 256 domains and 253-character
  entries are limits, not evidence that a domain is safe. Review every allowed
  domain and subdomain, inference endpoint, write rule and direct endpoint for
  exfiltration. Demonstrate denied redirects and runner/local-service bypasses;
  allowlist support alone does not enable private runs.
- **Credential disclosure:** define separate read-token routing for target,
  context and agent-configuration fetches and optional forge reads. The
  agent-configuration clone currently has no credential; adding a broad PAT
  to make it work would expand exposure. Preserve policy/check read-only
  access and apply-only write credentials, keeping OIDC and runner service
  tokens out of the sandbox. Test cross-repository routing and token absence
  from logs, artifacts, URLs and process environments outside the intended
  consumer.

Any future opt-in and repository/organization identities must come from
repository-owned trusted configuration, not workflow inputs a dispatcher can
set. Refusal must remain the default and fail closed when requirements cannot
be verified. BPF host evidence and release binaries improve other boundaries;
neither supplies private-log isolation or safe read-token routing.
