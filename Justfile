# Recipes the workflows run, so a check reads the same here and in CI.
# Timings below are observations on one unprivileged runner, not CI guarantees.

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments := true

test-feed-refresh:
    cargo test --locked -p agentic-job --bin refresh-feed

# Format Rust before check.
fmt:
    cargo fmt --all
    cargo fmt --manifest-path crates/secure-host/fuzz/Cargo.toml

# What CI's rust job runs; nothing slower or networked beyond Cargo's fetch.
check:
    just fmt-check
    just clippy
    just test
    just fuzz-check

# Dependencies already checked: 19 seconds.
build:
    cargo build --locked

# Under 1 second.
fmt-check:
    cargo fmt --all --check

# Cold dependency cache: 42 seconds.
clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# Including compilation: 92 seconds; session tests alone took 22 seconds.
test:
    cargo test --workspace --locked

# Under 1 second; local fixtures, no forge or inference credentials.
proxy-test:
    python3 -m unittest discover -s egress -v

# 4 seconds including download; CI's markdownlint-cli2-action uses the same glob/config.
markdown-lint:
    npx --yes markdownlint-cli2 '**/*.md'

# CI's relative-link/anchor check; requires lychee, timing not measured.
markdown-links:
    lychee --offline --include-fragments --no-progress "**/*.md"

# Requires musl-tools and rustup target add x86_64-unknown-linux-musl; CI limit 30 minutes.
build-static:
    cargo build --release --locked --target x86_64-unknown-linux-musl -p agentic-job

# Bounded corpus replay; coverage-guided fuzzing is opt-in (fuzz/README.md).
fuzz-check:
    cargo fmt --manifest-path crates/secure-host/fuzz/Cargo.toml --check
    CARGO_TARGET_DIR=target cargo clippy --manifest-path crates/secure-host/fuzz/Cargo.toml --all-targets --locked -- -D warnings
    CARGO_TARGET_DIR=target cargo test --manifest-path crates/secure-host/fuzz/Cargo.toml --lib --locked

refresh-feed:
    cargo run --quiet --locked -p agentic-job --bin refresh-feed -- update

# What refresh-feed built: no build runs in the step feed.yml gives the
# token, though the job's earlier steps built the locked dependencies.
publish-feed-refresh:
    target/debug/refresh-feed publish

# Pinned collector and mocked forge handlers; no forge writes.
test-safe-output-handlers:
    node --test crates/agentic-job/tests/corpus/handlers.test.mjs

# Copied-tree export proof, unprivileged/offline after dependencies are cached.
# Builds only the component and a test-support consumer, never runner/host source.
test-safe-outputs-export:
    cargo test --locked -p safe-outputs --test export -- --ignored --nocapture

# The parity fixtures of `collect` (crates/agentic-job/tests/data/collect):
# what gh-aw's collector makes of each case's lines and configuration,
# with links kept as `policy` keeps them. GH_AW_JS is actions/setup/js of
# gh-aw at the commit apply.yml pins its setup action at.
collect-fixtures gh-aw-js:
    #!/usr/bin/env bash
    set -euo pipefail
    domains=$(grep -v '^#' crates/safe-outputs/src/top-level-domains.txt | tr '[:upper:]' '[:lower:]' | paste -sd, -)
    scratch=$(mktemp -d)
    trap 'rm -rf "$scratch"' EXIT
    for case in crates/agentic-job/tests/data/collect/*/; do
        env -u GITHUB_SERVER_URL -u GITHUB_API_URL GH_AW_ALLOWED_DOMAINS="$domains" \
            node crates/agentic-job/tests/corpus/collect.cjs "$1" "$case/outputs.jsonl" "$case/config.json" \
            safe-outputs/validation.json owner/name "$scratch/collected.json"
        node -e 'const fs = require("node:fs"); const [from, to] = process.argv.slice(1); fs.writeFileSync(to, JSON.stringify(JSON.parse(fs.readFileSync(from, "utf8")), null, 2) + "\n");' \
            "$scratch/collected.json" "$case/collected.json"
    done

# The publication corpus (crates/agentic-job/tests/publication.rs), recorded
# again from gh-aw and actions/github-script at the commits apply.yml pins.
# Needs node, git, jq and the network; replaces /tmp/gh-aw. Review the diff:
# it is what the pinned handlers now send to GitHub.
publication-corpus:
    #!/usr/bin/env bash
    set -euo pipefail
    scratch=$(mktemp -d)
    trap 'rm -rf "$scratch"' EXIT
    for action in github/gh-aw/actions/setup actions/github-script; do
        commit=$(grep -o -m1 "$action@[0-9a-f]\{40\}" .github/workflows/apply.yml | cut -d@ -f2)
        repo=$(cut -d/ -f1-2 <<< "$action")
        dir="$scratch/${repo#*/}"
        git init --quiet "$dir"
        # What the test reads of each: gh-aw's scripts, github-script's bundle.
        git -C "$dir" sparse-checkout set --no-cone /actions/setup/js/ /action.yml /dist/
        git -C "$dir" fetch --quiet --depth 1 "https://github.com/$repo" "$commit"
        git -C "$dir" checkout --quiet --detach FETCH_HEAD
    done
    AGENTIC_JOB_TEST_GH_AW="$scratch/gh-aw" AGENTIC_JOB_TEST_GITHUB_SCRIPT="$scratch/github-script" AGENTIC_JOB_BLESS_PUBLICATION=1 \
        cargo test --locked -p agentic-job --test publication -- --ignored

# Privileged integration proof: only on a fresh disposable supported host.
# The checkout's binary loads the policy, as secure-host has it do.
world-write-evidence out:
    cargo build --locked -p agentic-job --bin agentic-job --bin world-write-evidence
    target/debug/world-write-evidence "$1" target/debug/agentic-job

world-write-test:
    cargo test --locked -p agentic-job --bin world-write-evidence --test world_write_worker

test-binary:
    cargo test --locked -p agentic-job --test binary_sh

# Disposable GitLab CE supplied by CI; no external forge access. Up to 25 minutes.
test-gitlab:
    cargo build --locked -p safe-outputs --bin safe-outputs
    cargo test --locked -p agentic-job --test gitlab -- --ignored --nocapture

# Unprivileged regression tests for setup, its probe batching and summaries.
setup-tests:
    cargo test --locked -p agentic-job --lib sandbox::setup::tests
    cargo test --locked -p secure-host --lib -- setup::tests check:: timed::

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
# Needs just, cargo, network and docker (or CONTAINER=podman); 5 seconds cached.
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
# what a run posts (safe_outputs::link_domains). A domain added since the
# last refresh has its links redacted until this runs; review the diff.
refresh-top-level-domains:
    curl --fail --silent --show-error --proto '=https' --output crates/safe-outputs/src/top-level-domains.txt https://data.iana.org/TLD/tlds-alpha-by-domain.txt

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

# dist.test.mjs checks the pages site-build renders, so it builds first.
site-test: site-build
    node --test site/links.test.mjs site/index.test.mjs site/dist.test.mjs

# Links and fragments of a build served at /, as site-build makes it by
# default; links to repository files then name the checkout's files.
site-check:
    lychee --offline --include-fragments --index-files index.html,. --no-progress --root-dir "$PWD/site/dist" 'site/dist/**/*.html'
