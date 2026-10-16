#!/bin/sh
# The scripted agent of CI's run that closes, links and hides scratch items.
# e2e-items-scratch made the run's base a commit naming the scratch sub-issue
# and the scratch comment, and opened the scratch pull request from it; the
# agent finds them with its read-only token and asks to close the pull
# request, link the sub-issue under the scratch issue CI comments on, and
# hide the comment there as outdated. Like every scripted run it also
# prints the secret-shaped string `run` insists was redacted.
set -eu
mkdir -p "$HOME/.config/fake-agent"
cat > "$HOME/.config/fake-agent/items.sh" <<'SH'
set -eu
repo=$(git remote get-url origin | sed -e 's#^https://github.com/##' -e 's#\.git$##')
sub=$(git log -1 --format=%s | sed -n 's/^e2e scratch: link #\([0-9][0-9]*\) under #64$/\1/p')
pr=$(gh api "repos/$repo/commits/$(git rev-parse HEAD)/pulls" --jq '[.[] | select(.state == "open")][0].number // empty')
comment=$(git log -1 --format=%b | sed -n 's/^hide \([A-Za-z0-9_-][A-Za-z0-9_-]*\)$/\1/p')
test -n "$sub" && test -n "$pr" && test -n "$comment"
printf '{"type": "close_pull_request", "repo": "%s", "pull_request_number": %s, "body": "Closed by the scripted agent of an end-to-end run."}\n' "$repo" "$pr" >> "$HOME/out/safe-outputs.jsonl"
printf '{"type": "link_sub_issue", "repo": "%s", "parent_issue_number": 64, "sub_issue_number": %s}\n' "$repo" "$sub" >> "$HOME/out/safe-outputs.jsonl"
printf '{"type": "hide_comment", "comment_id": "%s", "reason": "OUTDATED"}\n' "$comment" >> "$HOME/out/safe-outputs.jsonl"
SH
cat > "$HOME/.config/fake-agent/demo.json" <<'JSON'
[
  {"say": "End-to-end run: close the scratch pull request, link the scratch sub-issue and hide the scratch comment."},
  {"execute": {"title": "Bash", "command": "sh \"$HOME/.config/fake-agent/items.sh\""}},
  {"execute": {"title": "Bash", "command": "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef"}},
  {"write": {"title": "Write", "path": "{home}/out/outcome.json", "content": "{\"summary\": \"Closed, linked and hid the scratch items.\", \"tests\": [], \"stopped_early\": null}\n"}},
  {"cost": {"usd": 0.01}},
  {"say": "Done."}
]
JSON
