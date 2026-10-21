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

# The parity fixtures of `collect` (crates/agentic-job/tests/data/collect):
# what gh-aw's collector makes of each case's lines and configuration,
# with links kept as `policy` keeps them. GH_AW_JS is actions/setup/js of
# gh-aw at the commit check.yml pins its setup action at.
collect-fixtures gh-aw-js:
    #!/usr/bin/env bash
    set -euo pipefail
    domains=$(grep -v '^#' crates/agentic-job/src/top-level-domains.txt | tr '[:upper:]' '[:lower:]' | paste -sd, -)
    scratch=$(mktemp -d)
    trap 'rm -rf "$scratch"' EXIT
    for case in crates/agentic-job/tests/data/collect/*/; do
        env -u GITHUB_SERVER_URL -u GITHUB_API_URL GH_AW_ALLOWED_DOMAINS="$domains" \
            node crates/agentic-job/tests/corpus/collect.cjs "$1" "$case/outputs.jsonl" "$case/config.json" \
            safe-outputs/validation.json owner/name "$scratch/collected.json"
        node -e 'const fs = require("node:fs"); const [from, to] = process.argv.slice(1); fs.writeFileSync(to, JSON.stringify(JSON.parse(fs.readFileSync(from, "utf8")), null, 2) + "\n");' \
            "$scratch/collected.json" "$case/collected.json"
    done

runner-egress-test:
    node --test workflow/runner-egress/parse.test.mjs

runner-egress-fixture:
    node -e 'require("node:fs").writeFileSync(process.env.RUNNER_TEMP + "/runner-egress-fixture.txt", "Outbound observation fixture\n")'

# Privileged integration proof: only on a fresh disposable supported host.
# The checkout's binary loads the policy, as secure-host has it do.
world-write-evidence out:
    cargo build --locked -p agentic-job --bin agentic-job
    node secure-host/world-write-evidence.mjs "$1" target/debug/agentic-job

world-write-test:
    node --test secure-host/world-write-cases.test.mjs secure-host/world-write-evidence.test.mjs

test-binary:
    node --test secure-host/binary.test.mjs

# Unprivileged regression tests for setup, its probe batching and summaries.
setup-tests:
    cargo test --locked --lib sandbox::setup::tests
    cargo test --locked --lib sandbox::check::
    node --test workflow/setup-timing.test.mjs

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

# IANA's top-level domains, the hosts whose https links gh-aw keeps in
# what a run posts (policy::link_domains). A domain added since the last
# refresh has its links redacted until this runs; review the diff.
refresh-top-level-domains:
    curl --fail --silent --show-error --proto '=https' --output crates/agentic-job/src/top-level-domains.txt https://data.iana.org/TLD/tlds-alpha-by-domain.txt

# The documentation site in site/, a rendering of docs/ and the README.
# Dependencies come from the lock alone, without their install scripts.
# SITE_BASE, SITE_URL and SITE_SOURCE_URL (site/astro.config.mjs) place it.
site-build:
    cd site && npm ci --ignore-scripts --no-audit --no-fund
    cd site && ASTRO_TELEMETRY_DISABLED=1 npm run build

# site-build for GitHub Pages, from a GitHub Actions run's own variables:
# served at the repository's default project-site address,
# https://OWNER.github.io/REPO/ (a custom domain or a REPO named
# OWNER.github.io would need other values), and linking repository files
# at the built commit.
site-build-pages:
    SITE_URL="https://$GITHUB_REPOSITORY_OWNER.github.io" SITE_BASE="/${GITHUB_REPOSITORY#*/}/" SITE_SOURCE_URL="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/blob/$GITHUB_SHA/" {{ just_executable() }} site-build

site-test:
    node --test site/links.test.mjs

# Links and fragments of a build served at /, as site-build makes it by
# default; links to repository files then name the checkout's files.
site-check:
    lychee --offline --include-fragments --index-files index.html,. --no-progress --root-dir "$PWD/site/dist" 'site/dist/**/*.html'
