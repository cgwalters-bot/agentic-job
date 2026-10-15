#!/bin/sh
# The scripted agent of CI's run that closes and links scratch items.
# e2e-items-scratch made the run's base a commit naming the scratch sub-issue
# and opened the scratch pull request from it; the agent finds both with
# its read-only token and asks to close the one and link the other under
# the scratch issue CI comments on. Like every scripted run it also
# prints the secret-shaped string `run` insists was redacted.
set -eu
mkdir -p "$HOME/.config/fake-agent"
cat > "$HOME/.config/fake-agent/items.sh" <<'SH'
set -eu
repo=$(git remote get-url origin | sed -e 's#^https://github.com/##' -e 's#\.git$##')
sub=$(git log -1 --format=%s | sed -n 's/^e2e scratch: link #\([0-9][0-9]*\) under #64$/\1/p')
pr=$(gh api "repos/$repo/commits/$(git rev-parse HEAD)/pulls" --jq '[.[] | select(.state == "open")][0].number // empty')
test -n "$sub" && test -n "$pr"
printf '{"type": "close_pull_request", "repo": "%s", "pull_request_number": %s, "body": "Closed by the scripted agent of an end-to-end run."}\n' "$repo" "$pr" >> "$HOME/out/safe-outputs.jsonl"
printf '{"type": "link_sub_issue", "repo": "%s", "parent_issue_number": 64, "sub_issue_number": %s}\n' "$repo" "$sub" >> "$HOME/out/safe-outputs.jsonl"
SH
cat > "$HOME/.config/fake-agent/demo.json" <<'JSON'
[
  {"say": "End-to-end run: close the scratch pull request and link the scratch sub-issue."},
  {"execute": {"title": "Bash", "command": "sh \"$HOME/.config/fake-agent/items.sh\""}},
  {"execute": {"title": "Bash", "command": "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef"}},
  {"write": {"title": "Write", "path": "{home}/out/outcome.json", "content": "{\"summary\": \"Closed and linked the scratch items.\", \"tests\": [], \"stopped_early\": null}\n"}},
  {"cost": {"usd": 0.01}},
  {"say": "Done."}
]
JSON
