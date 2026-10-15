#!/bin/sh
# The scripted agent's session for CI's run that names people: it assigns
# the listed user and requests review on this run's scratch pull request.
# Its base branch carries the fixture metadata created before this caller.
set -eu
mkdir -p "$HOME/.config/fake-agent"
cat > "$HOME/.config/fake-agent/people.sh" <<'SH'
set -eu
repo=$(git remote get-url origin | sed -e 's#^https://github.com/##' -e 's#\.git$##')
out="$HOME/out/safe-outputs.jsonl"
branch=$(jq -er .branch e2e-people.json)
login=$(jq -er .login e2e-people.json)
owner=${repo%/*}
pr=$(gh api --method GET "repos/$repo/pulls" -f state=open -f "head=$owner:$branch" \
  --jq 'if length == 1 then .[0].number else error("expected exactly one run-owned PR") end')
jq -nc --arg repo "$repo" --argjson pr "$pr" --arg login "$login" \
  '{type:"assign_to_user",repo:$repo,issue_number:$pr,assignees:[$login]}, {type:"add_reviewer",repo:$repo,pull_request_number:$pr,reviewers:[$login]}' >> "$out"
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
