#!/bin/sh
# The scripted agent of CI's run on review threads. e2e-threads-scratch
# opened the scratch pull request from the run's base, which adds the one
# line of e2e-threads.txt, and left a review comment on it; the agent finds
# both with its read-only token and asks to comment on that line, reply to
# the comment and resolve its thread. Like every scripted run it also
# prints the secret-shaped string `run` insists was redacted.
set -eu
mkdir -p "$HOME/.config/fake-agent"
cat > "$HOME/.config/fake-agent/threads.sh" <<'SH'
set -eu
repo=$(git remote get-url origin | sed -e 's#^https://github.com/##' -e 's#\.git$##')
pr=$(gh api "repos/$repo/commits/$(git rev-parse HEAD)/pulls" --jq '[.[] | select(.state == "open")][0].number // empty')
test -n "$pr"
scratch='[.[] | select(.user.login == "github-actions[bot]" and .in_reply_to_id == null)][0]'
id=$(gh api "repos/$repo/pulls/$pr/comments" --jq "$scratch.id // empty")
node=$(gh api "repos/$repo/pulls/$pr/comments" --jq "$scratch.node_id // empty")
test -n "$id" && test -n "$node"
printf '{"type": "create_pull_request_review_comment", "path": "e2e-threads.txt", "line": 1, "body": "Review comment of the scripted agent of an end-to-end run."}\n' >> "$HOME/out/safe-outputs.jsonl"
printf '{"type": "reply_to_pull_request_review_comment", "comment_id": %s, "body": "Reply of the scripted agent of an end-to-end run."}\n' "$id" >> "$HOME/out/safe-outputs.jsonl"
printf '{"type": "resolve_pull_request_review_thread", "thread_id": "%s"}\n' "$node" >> "$HOME/out/safe-outputs.jsonl"
SH
cat > "$HOME/.config/fake-agent/demo.json" <<'JSON'
[
  {"say": "End-to-end run: comment on the scratch pull request's line, reply to its review comment and resolve the thread."},
  {"execute": {"title": "Bash", "command": "sh \"$HOME/.config/fake-agent/threads.sh\""}},
  {"execute": {"title": "Bash", "command": "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef"}},
  {"write": {"title": "Write", "path": "{home}/out/outcome.json", "content": "{\"summary\": \"Commented on, replied to and resolved the scratch review thread.\", \"tests\": [], \"stopped_early\": null}\n"}},
  {"cost": {"usd": 0.01}},
  {"say": "Done."}
]
JSON
