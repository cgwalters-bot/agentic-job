# Recipes the workflows run, so a check reads the same here and in CI.

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments := true

test-feed-refresh:
    node --test secure-host/refresh-feed.test.mjs

refresh-feed:
    node secure-host/refresh-feed.mjs update

publish-feed-refresh:
    node secure-host/refresh-feed.mjs publish

# Pinned collector and mocked forge handlers; no forge writes.
test-safe-output-handlers:
    node --test crates/agentic-job/tests/corpus/handlers.test.mjs

runner-egress-test:
    node --test workflow/runner-egress/parse.test.mjs

runner-egress-fixture:
    node -e 'require("node:fs").writeFileSync(process.env.RUNNER_TEMP + "/runner-egress-fixture.txt", "Outbound observation fixture\n")'

# Privileged integration proof: only on a fresh disposable supported host.
world-write-evidence out:
    node secure-host/world-write-evidence.mjs "$1"

world-write-test:
    node --test secure-host/world-write.test.mjs secure-host/world-write-cases.test.mjs secure-host/world-write-evidence.test.mjs

test-binary:
    node --test secure-host/binary.test.mjs

# Unprivileged regression tests for setup, its probe batching and summaries.
setup-tests:
    cargo test --locked --lib sandbox::setup::tests
    cargo test --locked --lib sandbox::check::
    node --test workflow/setup-timing.test.mjs secure-host/apt.test.mjs

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

# The real Claude Code ACP adapter, at the version the reusable workflow
# installs, against a loopback stub: it must offer its own Read, Edit and
# Write (tests/claude.rs). Needs node and the registry; no npm, no model key.
# A host with Claude Code's managed settings fails it: they would send
# the requests elsewhere.
claude-acp-test:
    #!/usr/bin/env bash
    set -euo pipefail
    spec=$(grep -o -m1 '@agentclientprotocol/claude-agent-acp@[0-9][0-9.]*' .github/workflows/policy.yml)
    prefix=$(mktemp -d)
    trap 'rm -rf "$prefix"' EXIT
    # As setup installs it: from the pins, without npm.
    installed=$(cargo run --quiet --locked --bin pinned-agents -- install "$prefix" "$spec")
    AGENTIC_JOB_TEST_CLAUDE_ACP="$installed/node_modules/@agentclientprotocol/claude-agent-acp" \
        cargo test --locked --test claude -- --nocapture

# Prints SPEC's entry for crates/agentic-job/src/sandbox/setup/agents.toml,
# from npm's resolution of PACKAGE for the runners' platform, without its
# scripts; each LINK is NAME=PATH, a program and what it runs. PACKAGE is
# SPEC unless SPEC's install script picks a platform package: then that.
# Needs npm and the registry; review the entry before replacing the old.
agents-lock spec package +links:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    echo '{}' > "$dir/package.json"
    npm install --prefix "$dir" --package-lock-only --ignore-scripts --no-audit --no-fund \
        --os=linux --cpu=x64 --libc=glibc -- "$2" >&2
    cargo run --quiet --locked --bin pinned-agents -- lock "$1" "${@:3}" < "$dir/package-lock.json"
