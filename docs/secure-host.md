# Securing the CI host: one setup step for any job

> This text is LLM generated.

Agent security is just CI security. An agent is one more untrusted step
of a job, like a build script from a pull request or a dependency's
install hook, and what protects a job from one protects it from the
others. So the hardening is a step of its own that any job can run
before untrusted steps, whether or not an agent runs afterwards:
[`cgwalters-forge/actions/secure-host`](https://github.com/cgwalters-forge/actions/blob/main/secure-host/README.md),
which runs the image this repository builds. Later workflow steps run as
the runner's user, which is also the agent's user. The former second-user
direction is superseded by [#2989](https://github.com/cgwalters-forge/agentic-job/issues/2989);
[#2991](https://github.com/cgwalters-forge/agentic-job/pull/2991) removed it.

That action's README and documents are the documentation of record for
the host: what setup changes, the lock, the world-write policy, the rule
against reading another runner process, egress and the probes
([where each section went](#where-the-host-documentation-went)). This
page keeps what concerns agentic-job alone: the forwarder, how the agent
job uses the action, and where the binary and image come from. Those
documents describe the pinned image, which can lag this repository's
main branch. They cover later host changes when the pin moves.

## Example: harden a deterministic job

Everything that needs root runs before the hardening step. Replace `COMMIT`
with a reviewed pin:

```yaml
jobs:
  build:
    runs-on: ubuntu-26.04
    steps:
      - run: sudo apt-get install -y libfoo-dev   # root: before the step
      - uses: actions/checkout@v7
      - uses: cgwalters-forge/actions/secure-host@COMMIT
      - run: make check                           # runner's user, no sudo
```

Losing root does not hide the job's tokens from later steps. The reusable
workflow keeps write credentials in separate jobs
([token boundaries](workflow.md#which-tokens-reach-what)).

## The public action forwards to cgwalters-forge/actions/secure-host

[`secure-host/action.yml`](../secure-host/action.yml) forwards to
`cgwalters-forge/actions/secure-host` at a pinned commit, which runs the
attested, digest-pinned [image](#where-the-binary-and-image-come-from)
([tracker#674](https://github.com/cgwalters-forge/tracker/issues/674)).
It passes on `config`, `check` and `image-archive`. A caller that names
`cgwalters-forge/agentic-job/secure-host` at a commit from before the
forward keeps the old action. At `@main` or a later commit:

- The new action's contract has no second user to run steps as: every
  step after it is the runner's user's. The old action's outputs are
  gone, so a step that reads them gets an empty string.
- Without a `config`, the forwarder passes this repository's
  [`hosted.toml`](../secure-host/hosted.toml) for Ubuntu 26.04 or
  [`rhel-cloud.toml`](../secure-host/rhel-cloud.toml) for RHEL 10 and
  CentOS Stream 10, selected from `/etc/os-release`, and not the new
  action's default, which turns egress filtering off: the
  v0.6 image's binary still creates its second user, and a step that
  runs code as it keeps writing only through the proxy's rules. A
  `config` of the caller's own replaces it whole. The new action sets
  `egress.write-policy` from its own `egress` input, over the file, so
  the forwarder passes `egress: write-policy` when the file asks for it,
  and refuses a file with a backslash outside a comment or with a
  multi-line string, either of which could ask for it in a way the
  forwarder does not read.
- The forwarder and `site.yml` pin the same commit of the new action;
  its comment names the image tag that commit runs, and
  [tests/workflows.rs](../crates/agentic-job/tests/workflows.rs)'
  `the_public_secure_host_forwards_to_the_pinned_action_and_refuses_old_inputs`
  refuses a pin whose two copies differ, whose tag is older than v0.6.9
  (the required runner storage rules), or newer than the workspace's version.
- The floor is ubuntu-26.04, the runner the new action is written for;
  the pinned image admits exactly Ubuntu 26.04 and RHEL 10
  ([supported hosts](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/setup.md#supported-hosts)).
- Setting another input of the old action that chose the host fails the
  step and names the new action: `lock`, `egress`,
  `deny-runner-metadata`, `egress-policy`, `stop-services`,
  `sandbox-user`, `runner-user`, `script`, `binary` or `build`. Each
  asked for a host the new action would not set up, so the step does
  not ignore it. A configuration file says the same things.

### What main has that the pinned image does not yet

The action's documents describe the image it pins (v0.6.9). Main has
changed the host since, and a forwarder caller gets these only with the
next image release:

- The Ubuntu `packages` stage shares a 45-second deadline across package
  downloads and, if needed, one index refresh and download retry. A stuck
  acquisition gets at most five more seconds for forced cleanup. A failure
  names mirror name resolution/DNS and connectivity as things to check;
  apt's own output remains in the job log. Installation then uses
  `--no-download`, so no later acquisition can reintroduce the DNS wait,
  and the deadline never kills dpkg. This also refuses downloads that take
  longer than the budget on a slow but working network. Dnf is unchanged.
- Host admission also accepts CentOS Stream 10, by exact `ID=centos` and
  `VERSION_ID=10`, with separate privileged-binary allowlist rows. Ubuntu
  26.04 and RHEL 10 (including minor releases) remain admitted. `ID_LIKE`
  never grants admission: CentOS 9, AlmaLinux, Rocky, Fedora and other
  untested distributions stay refused. The forwarder's default selection
  uses the same match; an unknown host with no explicit config fails
  before forwarding. Its RHEL-family cloud config stops cockpit,
  sssd-kcm, gssproxy and sshd (including `sshd-unix-local.socket`) so
  untrusted code cannot reach those listeners; it adds no socket
  exceptions. An explicit `config` still replaces the default whole.
  The pinned image does not yet admit CentOS Stream 10, even with this
  default; use an image built from this source until the pin moves.
- Under `host.deny-runner-reads`, setup discards every core dump on the
  host: it sets `kernel.core_pattern` to `|/bin/false`, and `secure-host
  check` fails its `core-pattern` probe on a host without it. The
  runner-read rule and Yama scope 1 refuse a step the environment, `mem`
  and ptrace of its parent, `run` or the Worker. Without this, the step
  could still raise that process's core limit with `prlimit`, kill it with
  `SIGSEGV` and read its environment and memory from `coredumpctl dump`
  ([#1618](https://github.com/cgwalters-forge/agentic-job/issues/1618)).
  `prlimit` and `kill` need only the same uid, and the default pattern
  hands the dump to systemd-coredump, which keeps it readable by that uid.
  The pattern is the kernel's and applies in every namespace. Only root
  in the host's user namespace can change it, and the lock that the rule
  requires keeps the runner's user from becoming root. So every job on
  such a host loses its core dumps, deterministic CI included; a job that
  needs them sets `host.deny-runner-reads = false`. CI's `confined` job
  probes each route in its control before secure-host and requires it to
  fail after. It forces a dump only of a child of its own that carries a
  marker, never of the Worker. Until the pin moves, a host the pinned
  image sets up keeps its dumps, and the check the run action runs is
  that image's binary, which does not look. `run` still refuses an inference
  provider's key, an MCP credential, the OIDC request and the rest under
  `--runner-home` ([sandbox](sandbox.md)). These probes are the evidence
  a later decision to lift any of them would rest on, and they do not
  lift them.

### Deployed write-policy diagnostics

The forwarder selects actions commit
`466a490e983ff07e6fb076fa4bd8b4d5f918fcd6`, the reviewed
[#180](https://github.com/cgwalters-forge/actions/pull/180) deployment,
whose `Containerfile.pin` names the attested v0.6.9 image, digest
`sha256:008d34bf9598ef83d7859772200f26637814d2cd105028457208ddc87d69788b`.
Before pulling it, the action verifies the digest's SLSA provenance against
its signer, this repository's `release.yml` on `refs/heads/main`, built on a
GitHub-hosted runner; the provenance it accepts names source revision
`57119eeffa17ea41b383cfdaf8370b8abeba8868`, which the `v0.6.9` tag points at.
It includes [#2816](https://github.com/cgwalters-forge/agentic-job/pull/2816):
write-policy refusal responses name the method and connection host, never
the path or signed query. The upload step itself prints that response even
when it cannot upload artifacts; no proxy-log artifact is needed for it.
Image attestation verification, write-policy selection and token boundaries
are unchanged by this pin update.

For [#2811](https://github.com/cgwalters-forge/agentic-job/issues/2811), the
example workflow has now uploaded an artifact under this deployment on a
hosted runner. Actions' [#228](https://github.com/cgwalters-forge/actions/pull/228)
moves `example-plain-ci.yml` to that action commit and asserts the pin in
its workflow test; the pull request run for its head
`8c3486ee6006f4baf112b954ffafd3df6088640f`,
[42487605263](https://github.com/cgwalters-forge/actions/actions/runs/42487605263),
passed:

- The build job's secure-host step verified the attestation of that digest,
  set up the host with `egress: write-policy`, and passed the write-policy
  sandbox checks: the runner reads with no proxy variable set, its POST to
  `example.com` is refused, and the sandbox cannot reach the runner's listener.
- `actions/upload-artifact` uploaded the one-file artifact 13620365713
  (171 bytes, ZIP digest
  `sha256:9955628b4bbcbd9ccb2c1b2a6ac1b8a3d47a107aae05529480221e12fac60d5e`)
  with no refusal response.
- The publish job downloaded it by ID, checked that digest and validated the
  extracted file as one commit ID. Its download redirect named
  `productionresultssa18`, one of the admitted accounts below, as the account
  holding the artifact; the upload step's log names no host. So the run
  shows one admitted destination, not where a refused upload would have gone.

That is pull request evidence, not default-branch adoption. On 2026-11-09
actions' `main` (`eef41d3b216c731fda0960d6c9876a6ab3cd159a`) still pins the
example to `c9a9501729bc306f3efdc188056b51149c1c9398`, whose image is v0.6.4,
digest `sha256:df9133ce3d7ca05c9de0c5eb7d1f6c662065288191ac857d6c877ab5833e5b49`;
its latest example run
[42488914598](https://github.com/cgwalters-forge/actions/actions/runs/42488914598)
passed with that image and says nothing about the corrected one. #228 is
approved and conflict-free but behind `main`, and its required `ci` check
([42487605277](https://github.com/cgwalters-forge/actions/actions/runs/42487605277))
fails in zizmor: four `ref-version-mismatch` warnings on the `# main`
comments of wrapper pins in `cgwalters-agent.yml` and
`cgwalters-agentic-job.yml`, files #228 does not change; `ci` fails the same
way on `main`
([42488914465](https://github.com/cgwalters-forge/actions/actions/runs/42488914465)).
Once that check passes and #228 merges, record here the default branch's
effective action and image and a post-merge example run's upload and
consumer result; until then #2811 stays open. The pin is actions' to land;
this repository does not duplicate it. Tracker and other callers of actions'
wrappers must select the corrected deployment themselves: neither this
forwarder update nor #228 moves their pins.

The historical refusals, agentic-job run
[41476599777](https://github.com/cgwalters-forge/agentic-job/actions/runs/41476599777)
and actions runs
[42349245829](https://github.com/cgwalters-forge/actions/actions/runs/42349245829)
and [42349923436](https://github.com/cgwalters-forge/actions/actions/runs/42349923436),
still name no upload host: each ends with a PUT the egress proxy refused,
and a download redirect in the same run names the account holding an
artifact already uploaded, not the refused PUT's destination. One success
does not show that every dynamic upload destination is admitted. A future
refusal is recorded as its query-free method and host with run and step
links, never a signed URL or header. A further exact-host, PUT-only admission needs verified GitHub
ownership of that storage account, from a results-service signed-upload
response or artifact redirect, and positive and negative boundary tests,
not ranges, suffixes or DNS existence.

Under `egress.write-policy`, the runner's storage writes go only to the
results service's twenty `productionresultssaN` accounts from gh-aw,
`productionresultssa30`, `productionresultssa31` and `productionresultssa32`, verified through
GitHub's artifact service redirects in CI runs
[40611370113](https://github.com/cgwalters-forge/agentic-job/actions/runs/40611370113),
[40812985049](https://github.com/cgwalters-forge/agentic-job/actions/runs/40812985049)
and [41476599777](https://github.com/cgwalters-forge/agentic-job/actions/runs/41476599777)
(DNS existence alone does not establish ownership;
[#1422](https://github.com/cgwalters-forge/agentic-job/pull/1422),
[tracker#974](https://github.com/cgwalters-forge/tracker/issues/974)),
not to every Azure storage account.

These are the pinned image's built-in runner writes, not rules injected
by the forwarder into the explicit proxy's policy. The forwarder leaves
`egress.policy` alone and no longer constructs a combined policy file.
Artifact uploads run as the runner's uid: public HTTP/HTTPS connections
are redirected to the transparent listener, whose `runner_policy` adds
these PUT-only rules. The action exports CA trust variables, not explicit
proxy variables, for later steps. Removing the override therefore keeps
runner uploads working while removing those extra PUT permissions from
the explicit proxy (unless a caller's own policy grants them).

## On a host that is not a GitHub Actions runner

A self-hosted CI job, or a VM of its own, needs the binary **and its matching
`world_write.bpf.o`**, from a verified release or a trusted source build
([provenance](#where-the-binary-and-image-come-from)). On a fresh disposable
[supported host](#what-main-has-that-the-pinned-image-does-not-yet), load the
object as root before setup, then check as the user the later steps run as:

```sh
sudo secure-host world-write /path/to/world_write.bpf.o
sudo secure-host setup --config FILE
secure-host check
```

`agentic-job secure-host world-write`, `agentic-job sandbox setup` and
`agentic-job sandbox check` do the same, and that setup does the agent's
part too.

These are host-changing commands, not commands to run inside an existing
sandbox. The loader needs kernel BTF, BPF privileges, `runuser` and bpftool
(which it installs if missing); setup does not activate BPF itself and
refuses missing policy pins. The loader checks modify-return tracing links,
enables the root-device map and proves a denied write with writable controls
([loader](../crates/secure-host/src/world_write.rs)). Host admission alone is
not runtime evidence: the policy has hosted Ubuntu 26.04 evidence, not a
RHEL 10 or CentOS Stream 10 runtime proof.

None of these commands needs `RUNNER_TEMP`, the `GITHUB_*` environment or a
`Runner.Worker` process. What changes without them:

- With no `Runner.Worker`, `host.unlink-worker-diagnostics` has no
  socket to unlink: setup prints that it skipped the step and why, and
  `sandbox check` notes the same rather than passing a probe. With one or
  more Workers, both behave as on a GitHub runner.
- The runner-read rule exempts exactly one `Runner.Worker`, so where the
  secure-host image's loader runs, a host without one sets
  `host.deny-runner-reads = false`; the loader refuses it otherwise
  and names this key. The standalone loader above leaves the runner-read
  rule off; `sandbox setup` alone never loads it, even when the key is true.
  With a Worker and that rule required, pass `--deny-runner-reads` to the
  loader (`--sole-worker` too if the loader is not its descendant).
- Started from a root shell or a systemd unit rather than sudo as the
  runner's user, setup needs `host.runner-user` naming an existing
  non-root user; otherwise it cannot identify whose job to harden.
- The check record that lets a later check in the same job skip its
  probes ([sandbox-check.md](sandbox-check.md)) needs `RUNNER_TEMP` and
  `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT` and `GITHUB_JOB`. Without them
  there is no record, and every check runs its probes.
- `sandbox timed` is the GitHub action's wrapper, which times setup and
  the probes for the job summary; a plain host does not need it.

## The agent job

The agent job (`agent.yml`, which `agentic-job.yml` and `review.yml`
call) runs the forwarder with the policy job's configuration except for
`setup.script`, and then the agent as the runner's user
(`run --runner-home`, the run action's default `agent-user: runner`).
The image would run `setup.script` as its second user, from the host's
root, so the job runs it itself, after secure-host, in the agent's home.
`sandbox setup` refuses a host's `setup.script` since #2991. The image also
installs its own binary in `/usr/local/bin` over the one `prepare` put
there, so `run` starts the policy job's binary from the job directory.
The composed example (`example-compose.yml`) has the same steps, and
CI's jobs that secure a host run the forwarder with this revision's
image (`image-archive`).

An image of this source holds the secure-host binary and no agent code
([below](#the-secure-host-binary)), so with one the agent job does
agentic-job's part of setup first, as root: `sudo agentic-job sandbox
prepare` installs the packages, the agents and Vibe, writes the agent's
managed settings, and installs the policy job's binary as the helper,
with the operations `run` needs of root later. The host's file says so,
`[host.prepared]`, which `agentic-job config --host --prepared`
writes from the run's tables: the image's setup then keeps that helper
rather than installing itself (it must be a regular file there, and is
made root's alone with its directories, or setup refuses), and holds
the egress proxy and the network rules to what the run's tables ask
(the broker under `inference.front`), and serves the session bridge's
port when the tables name one, which
it does not read itself. agentic-job's readers refuse a table that no
longer says what the run's tables ask. The pinned image, a release
whose binary is agentic-job's and does all of setup, refuses that
table, so until a release is pinned the agent job runs this step only
with `image-archive`, as CI's end-to-end jobs do; running it before
every image is
[#2656](https://github.com/cgwalters-forge/agentic-job/issues/2656).

The agent is then a later step like any other: no root, the metadata
service only where the configuration leaves it open
([above](#what-main-has-that-the-pinned-image-does-not-yet)), and, as
the action's
[threat model](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/threat-model.md#what-a-later-step-can-count-on-and-what-it-cannot)
says, nothing between it and the job's own tokens. So the agent job
must not hold credentials it expects to hide from the agent. It still holds
the run token and, by default, a read-only forge token; credentialless
admission is future work, not a claim of this setup. It has no `id-token`: a `register` job before
it registers with the inference broker and passes on only the broker's
run token, as a secret of the agent's job
([the run token](workflow.md#the-run-token)); `review.yml` calls the same
agent job, after a `register` job of its own. The composed example runs
only the scripted agent, which registers nothing, and holds no
`id-token` either. What the agent hands back is checked on another
machine before a job with a write token acts on it
([workflow](workflow.md)).

### The egress write policy for an agent job

Without the
[egress write policy](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/egress.md#egress-write-policy-opt-in),
the runner's writes go anywhere but the metadata service. Host setup keeps
it opt-in, through `egress.write-policy` in its configuration. An agent
run with the proxy enabled now requires the write policy: `config` turns
it on when unset and refuses an explicit false value. The workflow's
`egress-write-policy` input can also request it. It holds the agent, the
setup script and every later step of the job.

It restricts the agent less than it restricts the sandbox user. The agent is the
runner's uid, so it gets the runner's own write rules: it can write to
the Actions service with a token of its own, such as another
repository's runtime token, and upload what it read there, and the
pinned image's storage rules admit only the exact results accounts
[listed above](#deployed-write-policy-diagnostics). There is no
supported second-user escape from that channel. The agent job refuses
a private caller or target with the write policy on
([private-repositories.md](private-repositories.md#opting-in)).

`run`'s own requests are held too. The one built-in exception is
`egress.direct`, which `agentic-job config` fills with an `inference.url`
on the tailnet when the file names none, so that the broker is reached
at its own address; a provider's API under `register = "api-key"`, or a
broker at a public address, needs a `[[write]]` rule of the caller's.
The agent trusts the proxy through two sources: the system's store,
which curl, git and OpenSSL read, and `NODE_EXTRA_CA_CERTS` and
`REQUESTS_CA_BUNDLE`, which `run --runner-home` adds to the agent's
otherwise cleared environment. CI's `e2e-write-policy` job runs the
scripted agent this way: it reads through the proxy with curl and Node,
is refused a POST, and its hand-back is uploaded and applied.

## Inputs and outputs

The forwarder exposes these three inputs of the new action; every one is optional.

| Input | What it sets |
| --- | --- |
| `config` | A TOML file with the `[sandbox]`, `[egress]` and `[setup]` tables: the lock, egress, the metadata refusal, the daemons to stop. The pinned image reads the host's table only by this name, which an image of this source takes as `[host]`'s deprecated alias (#2071); a file for an image of this source, `image-archive`, may use `[host]`. Default: [hosted.toml](../secure-host/hosted.toml) for Ubuntu 26.04, [rhel-cloud.toml](../secure-host/rhel-cloud.toml) for RHEL 10 or exact CentOS Stream 10, with the egress proxy on. Another image listens on other sockets: `sandbox check` names each one left |
| `check` | `false` skips `sandbox check`. Default `true`. The pinned action does not pass `--record`, so it leaves no passing record for the run action's `--unless-passed` check; that check probes again ([record mechanism](sandbox-check.md)) |
| `image-archive` | An image archive, as `podman load` takes it, run in place of the pinned image, unverified: for a job that built it, as CI's do |

It has no outputs. The action knows nothing of inference or sessions: an
agent job checks its inference proxy before this step, and the run action
reads a session's endpoint after it ([workflow](workflow.md)).

## The secure-host binary

`crates/secure-host` builds `secure-host`, the host's side with nothing
that runs an agent: `supported`, `apt`, `world-write`, `setup`, `check`,
`config` and `image`, the image's entrypoint, which installs the binary
on the host and runs the first three steps and setup there through
`nsenter`. Its hidden commands are what the host runs it for after
setup: `helper`, the egress proxy's unit and the probes.

`secure-host setup` and `check` read a host's file, or a job's whole
file as an agent job passes it: `[host]` and `[egress]` are held to
their keys, `[setup]` to `packages`, and `setup.script` is refused as
`sandbox setup` refuses it. `[sandbox]` is read as `[host]` with a
warning, and refused beside it
([stable interfaces](stable-interfaces.md#configuration-files)); `config`
writes `[host]`, from either name in the file or in a setting such as
the pinned action's `--string sandbox.runner-user=`. Any other table or
`[setup]` key is a program's, and is refused unless `[host.prepared]`
says the
program's step ran: it sets nothing here, so setup would leave out what
it asks of the host. With the table setup names those keys, keeps the
copy the program's step installed as the helper, and holds the egress
proxy and the network rules to the table; without it, its own copy is
the helper.

The pinned cgwalters-forge/actions/secure-host calls the image's binary
by agentic-job's name: `--entrypoint /agentic-job ... config --host`,
and `agentic-job sandbox check` on the host. For one release the image
answers to both: it has the binary at `/secure-host` and
`/agentic-job`, installs it as `/usr/local/bin/secure-host` and
`/usr/local/bin/agentic-job`, and takes `config --host` and `sandbox
check`, `probe` and `egress-proxy`. `agentic-job secure-host image` is
gone; agentic-job's other `secure-host` subcommands and `sandbox setup`
stay.

CI proves the image of each revision from its archive: the
`secure-host-image` job checks that both names on the host are the
staged secure-host binary and not agentic-job's, and `confined` probes
a step under it. The split landed in
[#3124](https://github.com/cgwalters-forge/agentic-job/pull/3124), source
`b16c6d63e37ff78050c4dd3bf92739dabadf3fa4`; its
[archive acceptance](https://github.com/cgwalters-forge/agentic-job/actions/runs/42126577776/job/127593880482)
is not published-path acceptance.

### Published standalone acceptance (#2070)

Rechecked on 2026-11-09: the effective action, image digest and source
remain [the v0.6.9 deployment above](#deployed-write-policy-diagnostics).
The actual Ubuntu
[`secure-host-published` setup/check](https://github.com/cgwalters-forge/agentic-job/actions/runs/42143295583/job/127648635121)
verified that image's attestation, completed setup and passed 96 checks.
It is a **legacy baseline**, not proof of the split or runner-only setup.
The same run's
[`e2e-dispatch`](https://github.com/cgwalters-forge/agentic-job/actions/runs/42143295583/job/127648702033)
was skipped, not agent E2E evidence.

The split shipped in
[v0.6.12](https://github.com/cgwalters-forge/agentic-job/releases/tag/v0.6.12),
source `eecc8c434e67a7607264ab3f7d90c88b6d02042a`.
[Actions#211](https://github.com/cgwalters-forge/actions/pull/211) proposes
image digest `sha256:d5fd0f3e102c589807df68656d5623f6d6cbc9ecb257bdd3c9af431242d7b73a`
at reviewed head `502522ad437a469da99120f89e848219434f16a7`, but is still
open. [Actions#230](https://github.com/cgwalters-forge/actions/issues/230)
owns adoption using that bump; compatibility/evidence
[#231](https://github.com/cgwalters-forge/actions/pull/231) and attestation
regression [#235](https://github.com/cgwalters-forge/actions/pull/235) are
also open. The exact prerequisite to moving this repository's forwarder
and site pins is a reviewed immutable action revision selecting a
compatible, attested published standalone image through that adoption.
Neither pin moves here; no competing bump or release is needed from this PR.
[Tracker#1369](https://github.com/cgwalters-forge/tracker/issues/1369)
still records the release train's single-versioned-actions-pin blocker.

The push-only `secure-host-published` job now binds its expected version
and action SHA to the forwarder in regression tests. Only the exact reviewed
legacy deployment gets the legacy baseline branch. Every replacement must
report `secure-host VERSION` under **both** installed executable names,
have identical installed bytes, and pass the action's `config --host
--string sandbox.runner-user=…` and `sandbox check` compatibility calls.
The action itself exercises `/agentic-job` configuration in the image
before setup; neither an archive override nor `check: false` is used.
Failures stop the job, not a silently skipped acceptance step. This adds
acceptance only, not a new host control, permission or credential exception.

Fresh Ubuntu published standalone setup/check and executable acceptance
are **pending**, as is applicable published-path agent E2E such as
`e2e-dispatch`. That E2E also depends on
[#2656](https://github.com/cgwalters-forge/agentic-job/issues/2656)'s
unconditional `sandbox prepare` and canonical host config adoption after
image compatibility is established; this slice does not force either
against the legacy image. v0.6.12 proves the split only: it does not contain
[#3144](https://github.com/cgwalters-forge/agentic-job/pull/3144) or
[#3154](https://github.com/cgwalters-forge/agentic-job/pull/3154).
The later containing numbered release,
[v0.6.13](https://github.com/cgwalters-forge/agentic-job/releases/tag/v0.6.13),
was published on 2026-11-10 at source
`4439980da2aef4db79b40890599ea661daab12b0`; its release notes include both
changes. Publication is no longer the blocker, but does not prove deployment.
Their deployment remains pending verification of the exact attested image,
effective pin adoption and actual `core-pattern`,
confined run/JavaScript main/post and confined-cleanup evidence. `build-*`
archives, skipped jobs and green old-image jobs do not satisfy those gates.
RHEL runtime acceptance is separately **pending**, not inferred from Ubuntu.
[#2070](https://github.com/cgwalters-forge/agentic-job/issues/2070) stays open
while these deployment and runtime obligations remain.

## Where the binary and image come from

The host's binary is the image's. A release pushes
`ghcr.io/cgwalters-forge/secure-host:vVERSION`, an image `FROM scratch`
with the static secure-host binary and the compiled world-write object
`world_write.bpf.o` ([`Containerfile`](../secure-host/Containerfile)),
and attests it by its digest from `release.yml` on main; what the image
does on the host is in the action's
[setup](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/setup.md#the-image).
A new package on ghcr.io is private until an owner makes it public.
Version releases and main's attested workflow artifacts also contain
`secure-host-x86_64-unknown-linux-musl`, its checksum in the attested
manifest beside agentic-job's.

The policy job gets the binary an agent job runs with
[`binary.sh`](../secure-host/binary.sh), a shell script since no
`agentic-job` exists yet, which computes the source digest at the pinned
commit and, by default, looks for legacy `build-FULL_DIGEST`. It verifies the release
manifest's GitHub attestation before checking the source digest and the
checksums of the binaries and the world-write object, whose SHA-256 is
in the attested `release.json` next to the binaries'; a manifest without
it is refused whole. A missing release falls back to a source build with
a notice (installing clang with musl-tools when missing); failed
verification stops the job. Main now uploads attested run artifacts instead
of creating build releases. The off-default `SOURCE_BUILD_ARTIFACTS=true`
reader selects the latest successful main push (or `SOURCE_BUILD_COMMIT` for
rollback) and verifies against that run's head SHA, not the workflow checkout.
Missing artifacts and verification failures stop that reader; there is no
automatic rollback. Existing releases remain intact. See
[the workflow's binary trust model](workflow.md#things-a-caller-should-know)
for the verification and publishing boundaries. Fetching needs bash,
`sha256sum`, jq and `gh` with attestation support, which it installs
where it is missing. It uses the job's read-only token and retries
signaled GitHub throttling within two minutes.
Building needs rustup.
The policy job's `build-binary: true` builds even when a prebuilt exists.
The reusable workflow's agent job gets the object with the binary from
the policy job's upload, and [`prepare`](../prepare/action.yml) installs
it beside `/usr/local/bin/agentic-job`.

## Where the host documentation went

Each topic is a document of `cgwalters-forge/actions/secure-host`:

| Topic | There |
| --- | --- |
| The contract, the caveats of running every step as the runner's user, the sandbox user | [README](https://github.com/cgwalters-forge/actions/blob/main/secure-host/README.md) |
| What a later step can count on, one trust level for the rest of the job, R4, R10 and R11 | [threat model](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/threat-model.md) |
| The image, supported hosts, what setup does to the host, the lock, what a job has to know, containers, running it without the action | [setup](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/setup.md) |
| The egress write policy, the proxy's policy file and domain allowlist, the network rules | [egress](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/egress.md) |
| The access-time world-write policy, its loader, and what went with the walk | [world-write](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/world-write.md) |
| Reads between the runner's own processes, the Worker's diagnostic sockets | [runner reads](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/runner-reads.md) |
| What `sandbox check` proves | [probes](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/probes.md) |
| CI's run-time controls, where each probe has been seen to fail, timings, RHEL 10 | [evidence](https://github.com/cgwalters-forge/actions/blob/main/secure-host/docs/evidence.md) |
