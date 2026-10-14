# Recipes the workflows run, so a check reads the same here and in CI.

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments := true

# Refuses VERSION unless it may be released from this checkout (its tags
# included); prints the previous version tag. See src/bin/release-check.rs.
release-check version:
    git tag --list 'v*' | cargo run --quiet --locked -p agentic-job --bin release-check -- "$1"
