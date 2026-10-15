#!/bin/sh
# The scripted agent asks for a neutral check run on the head of the pull
# request this CI run is for. The clone is of that pull request's branch,
# or of the merge group's, whose name says the pull request's number.
# The check run's name is the bounds', not the agent's.
# Like every scripted run it also prints the secret-shaped string `run`
# insists was redacted.
set -eu
mkdir -p "$HOME/.config/fake-agent"
cat > "$HOME/.config/fake-agent/check-run.sh" <<'SH'
set -eu
repo=$(git remote get-url origin | sed -e 's#^https://github.com/##' -e 's#\.git$##')
branch=$(git rev-parse --abbrev-ref HEAD)
case "$branch" in
  gh-readonly-queue/*) pr=$(printf '%s\n' "$branch" | sed -n 's#^gh-readonly-queue/.*/pr-\([0-9][0-9]*\)-[0-9a-f]*$#\1#p') ;;
  *) pr=$(gh api "repos/$repo/commits/$(git rev-parse HEAD)/pulls" --jq '[.[] | select(.state == "open")][0].number // empty') ;;
esac
test -n "$pr"
printf '{"type": "create_check_run", "pull_request_number": %s, "conclusion": "neutral", "title": "Scripted agent", "summary": "A neutral check run from the scripted agent of an end-to-end run."}\n' "$pr" >> "$HOME/out/safe-outputs.jsonl"
SH
cat > "$HOME/.config/fake-agent/demo.json" <<'JSON'
[
  {"say": "End-to-end run: one neutral check run."},
  {"execute": {"title": "Bash", "command": "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef"}},
  {"execute": {"title": "Bash", "command": "sh \"$HOME/.config/fake-agent/check-run.sh\""}},
  {"write": {"title": "Write", "path": "{home}/out/outcome.json", "content": "{\"summary\": \"Asked for a neutral check run.\", \"tests\": [], \"stopped_early\": null}\n"}},
  {"cost": {"usd": 0.01}},
  {"say": "Done."}
]
JSON
