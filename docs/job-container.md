# Non-root job container (experimental)

> This text is LLM generated.

The opt-in image in [`job-container/`](../job-container/Containerfile) addresses
a concrete threat: a job becoming container root through a privileged executable
and then using GitHub's mounted host Docker socket. It runs as UID/GID 1001,
matching hosted runners' workspace ownership, removes sudo, strips every
setuid/setgid bit and all file capabilities except the exact capabilities needed
by `newuidmap` and `newgidmap`. Its final build step audits that invariant.
Subordinate IDs allow nested rootless Podman to build and run multi-user images;
they do not create a separate host-side agent or supervisor user.

Nothing enables this image for agentic-job callers by default. It is a generic
CI building block, not a replacement for runner-only host hardening or the
separate policy/check/apply jobs and credential refusals in [the workflow](workflow.md).

## Delivery and acceptance

The inactive [workflow template](../job-container/workflow.yml) builds and audits pull
requests with read-only repository access. It never publishes PR images.
CI also injects real setuid/setgid files and an extra file capability into a
disposable root instance and requires the final image's audit to reject each.
Reviewed pushes to main build an archive without publication credentials. A separate job
validates same-run repository/workflow/attempt/head identity, artifact ID/name,
size (at most 2 GiB), artifact digest and archive checksum, then copies OCI data
to `ghcr.io/OWNER/REPO/job-container:sha-COMMIT-run-RUN-ATTEMPT`, without
checking out source, loading or running the image. A fresh Ubuntu 26.04 job pulls that
candidate **by digest**, with read-only package credentials (private GHCR
packages are supported). Only after the probe, including JavaScript post steps,
succeeds does a separate publisher update `:latest`. Failed candidates remain
commit-addressed, never promoted. Runtime validation is deliberately post-merge;
merging a green PR build is not proof that the runtime probe succeeds.

**Activation is outstanding.** The existing [workflow checker](workflows-check.md)
requires secure-host (which stops the container daemon) or its narrowly defined
trusted-consumer shape. It intentionally refuses this new job-container shape.
Do not weaken the checker or let this proposal exempt itself. A maintainer must
review ingress admission in the trusted base configuration, then install the
template as `.github/workflows/job-container.yml`. The exact installation is a
copy of `job-container/workflow.yml` to that path, unchanged. If choosing the
existing whole-workflow exemption mechanism, the base configuration entry is:

```toml
[exempt]
"job-container.yml" = "Opt-in job-image CI: isolated main-only OCI publication, read-only digest probes, no host-hardening claim."
```

That admission requires explicit maintainer review; it is not included here.
There is no live CI job or package publication until activation. The existing
exemption checker also refuses entries without their workflow file, so installation
and trusted admission need a coordinated maintainer change, not an agent bypass.

The job container uses exactly:

```text
--security-opt seccomp=unconfined --security-opt apparmor=unconfined --security-opt systempaths=unconfined --device /dev/fuse
```

The bounded hosted probe emits PASS/FAIL lines and exits nonzero on failure. It
checks UID/GID, sudo absence, checkout/workspace writes, full subordinate maps,
effective Podman settings, a real Fedora run, a multi-user build/run, Docker
socket EACCES both directly and in `podman unshare`, and container-local process
visibility. A missing socket or broken helper fails instead of counting as a
successful denial. Local JavaScript main/post and composite actions also
assert the non-root identity. GitHub does not support pre hooks on local actions;
this fixture does not prove remote JavaScript pre-hook execution. The job summary
records the tested digest.

**Evidence status:** this combined hardened UID-1001 image has not been built or
run in the implementation sandbox. No successful digest or hosted run is claimed.
CI must supply those results before adoption. The historical
[probe report](https://github.com/cgwalters-forge/tracker/issues/445#issuecomment-6045692740),
[probe5 workflow](https://github.com/cgwalters-bot/agentic-job-trial/blob/main/.github/workflows/container-probe5.yml)
and [actual run](https://github.com/cgwalters-bot/agentic-job-trial/actions/runs/37677907684)
showed UID 1000 running Fedora and building a second user but failing workspace
writes; UID 1001 with no-new-privileges wrote the workspace but failed the
multi-user build. Neither proves this image's combined behavior. This image does
not use no-new-privileges because the mapping helpers require their capabilities.
The earlier [prototype PR](https://github.com/cgwalters-forge/agentic-job/pull/144)
was closed without merging.

## Limits

Shell steps, JavaScript actions and composite steps run inside the job container.
Docker actions and services are separate sibling containers and **do not** inherit
this image's non-root guarantee; the runner's
[Docker action handler](https://github.com/actions/runner/blob/v2.337.0/src/Runner.Worker/Handlers/ContainerActionHandler.cs)
can give them the host socket. Do not treat arbitrary action types as covered.

There is **no network policy** here: no workflow step can provision the host
before GitHub starts the job container. Seccomp and AppArmor are disabled for the
workload, system paths are unmasked, `/dev/fuse` is exposed, and the host kernel
is shared. Kernel/runtime vulnerabilities are outside this boundary. The runner
temp directory and world-writable tool cache are shared. Step-delivered tokens
and other credentials remain readable to workload code. This does not implement
credential isolation, credentialless inference, egress enforcement or RHEL/KVM
support. Keep least-privilege tokens and trusted publication on separate jobs.
