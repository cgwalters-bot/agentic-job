#!/bin/sh
# The scripted agent's session for CI's run that names people: it assigns
# the listed user on the scratch issue and, when one is open, requests the
# listed reviewer on the scratch pull request. That pull request is found
# by its title with the run's read-only token; it must be opened by someone
# other than the listed reviewer, who cannot review their own.
set -eu
mkdir -p "$HOME/.config/fake-agent"
cat > "$HOME/.config/fake-agent/people.sh" <<'SH'
set -eu
repo=$(git remote get-url origin | sed -e 's#^https://github.com/##' -e 's#\.git$##')
out="$HOME/out/safe-outputs.jsonl"
printf '{"type": "assign_to_user", "repo": "%s", "issue_number": 64, "assignees": ["cgwalters-bot"]}\n' "$repo" >> "$out"
pr=$(gh api "repos/$repo/pulls?state=open&per_page=100" \
  --jq '[.[] | select(.title == "Scratch pull request for CI'"'"'s end-to-end runs")][0].number // empty')
if [ -n "$pr" ]; then
  printf '{"type": "add_reviewer", "repo": "%s", "pull_request_number": %s, "reviewers": ["cgwalters-bot"]}\n' "$repo" "$pr" >> "$out"
fi
cat "$out"
SH
cat > "$HOME/.config/fake-agent/demo.json" <<'JSON'
[
  {"say": "End-to-end run: a listed assignee and reviewer."},
  {"execute": {"title": "Bash", "command": "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef"}},
  {"execute": {"title": "Bash", "command": "sh \"$HOME/.config/fake-agent/people.sh\""}},
  {"write": {"title": "Write", "path": "{home}/out/outcome.json", "content": "{\"summary\": \"Assigned and requested the listed user.\", \"tests\": [], \"stopped_early\": null}\n"}},
  {"cost": {"usd": 0.01}},
  {"say": "Done."}
]
JSON
