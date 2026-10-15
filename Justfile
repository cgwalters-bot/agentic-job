# Recipes the workflows run, so a check reads the same here and in CI.

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments := true

# Pinned collector and mocked forge handlers; no forge writes.
test-safe-output-handlers:
    node --test crates/agentic-job/tests/corpus/handlers.test.mjs

# Privileged integration proof: only on a fresh disposable supported host.
world-write-evidence out:
    node secure-host/world-write-evidence.mjs "$1"

world-write-test:
    node --test secure-host/world-write.test.mjs secure-host/world-write-cases.test.mjs secure-host/world-write-evidence.test.mjs

test-binary:
    node --test secure-host/binary.test.mjs

# Refuses VERSION unless it may be released from this checkout (its tags
# included); prints the previous version tag. See src/bin/release-check.rs.
release-check version:
    git tag --list 'v*' | cargo run --quiet --locked -p agentic-job --bin release-check -- "$1"

# SOURCE, OWNER/REPO@COMMIT, is the forge's shared workflow check, whose
# lint/ directory runs as its README says; CI takes it from the
# WORKFLOW_LINT repository variable. A full commit, so a later push there
# cannot change this check's code unreviewed; its analyzers' images are
# still pulled by tag. The shape check keeps the value from reaching git
# as an option. The analyzers read this checkout's configuration, a pull
# request's included, so workflow-ingress.yml, not this, is the gate.
# actionlint, zizmor and a denial of ubuntu-latest over this checkout.
workflow-lint source:
    #!/usr/bin/env bash
    set -euo pipefail
    [[ "$1" =~ ^([A-Za-z0-9-]+/[A-Za-z0-9_][A-Za-z0-9._-]*)@([0-9a-f]{40})$ ]] || { echo "workflow-lint: want OWNER/REPO@COMMIT, not '$1'" >&2; exit 2; }
    repository="${BASH_REMATCH[1]}" commit="${BASH_REMATCH[2]}"
    checkout=$(mktemp -d)
    trap 'rm -rf "$checkout"' EXIT
    git -C "$checkout" init --quiet
    git -C "$checkout" fetch --quiet --depth 1 "${GITHUB_SERVER_URL:-https://github.com}/$repository" "$commit"
    git -C "$checkout" checkout --quiet --detach FETCH_HEAD
    {{ just_executable() }} --justfile "$checkout/lint/Justfile" --working-directory . check
