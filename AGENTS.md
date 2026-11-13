# Start with [README.md](README.md)

It links to the documentation site and its sources in this checkout.

Read the [contributor guide](docs/contributing.md) for design constraints,
code conventions, check prerequisites and security boundaries before changing code.
The [Justfile](Justfile) holds check commands and timing guidance;
run the narrow test covering a change first, then applicable checks.
**Run `just fmt` and then `just check` before every commit you hand back;
a change that fails `just check` isn't done.**

## Constraints

- Keep repository-specific rules in caller configuration, never in code or
  defaults. Use neutral names in test fixtures; see [design principles](docs/contributing.md#design-principles).
- Do not run destructive host setup, ignored `sandbox_fresh`/`sandbox_host`
  tests or secure-host examples inside an existing sandbox. Passing ordinary
  tests does not prove privileged paths; see [checks](docs/contributing.md#build-and-checks).
- Forge reads are allowed; all forge writes go through [safe outputs](docs/safe-outputs.md).
  Fix runs read the latest PR review and failing required-check log first.
  A request to measure from a real CI log requires fetching one.
- Preserve [security boundaries](docs/contributing.md#security-and-scope),
  bounds, pins and tests. Do not hand-edit generated validation or vendor gh-aw.
  Keep changes task-scoped and free of artifacts, binaries, symlinks, submodules,
  new executables, mode changes, credentials and generated litter.
  The run brief's protected paths and output limits admit no exceptions here.

## Hand-back

Leave the working tree uncommitted: the runner produces one commit and one
draft pull request, as described in [safe outputs](docs/safe-outputs.md#what-the-agent-does).
Use a concise description stating what changed and why, exact verification
commands and exit statuses, and what was left unverified. Record real results,
including failures and skipped prerequisites, in the brief's outcome file;
never describe a skipped privileged test as verified.
