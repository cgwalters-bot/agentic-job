#!/bin/sh
# The scripted agent of an end-to-end run that hands back a change of the
# run's own and one to the policy's secondary repository
# (docs/safe-outputs.md#a-secondary-pull-request), each with its
# create_pull_request; apply then opens a draft pull request in each, from
# the token's forks. Its caller needs bounds with a [secondary_pull_request]
# table and a SAFE_OUTPUTS_PAT that reaches that repository
# (docs/workflow.md#a-secondary-pull-request), which CI's callers do not
# hold yet, so ci.yml does not run it: a caller that does names this file
# as its `setup`. Like every scripted run it also prints the secret-shaped
# string `run` insists was redacted.
set -eu
mkdir -p "$HOME/.config/fake-agent"
cat > "$HOME/.config/fake-agent/secondary.sh" <<'SH'
set -eu
# `run` clones the secondary repository, and only it, to ~/work/secondary/OWNER/NAME.
tree=$(find "$HOME/work/secondary" -mindepth 2 -maxdepth 2 -type d)
test -n "$tree" && test "$(printf '%s\n' "$tree" | wc -l)" = 1
repo=${tree#"$HOME/work/secondary/"}
echo 'A line of the scripted agent of an end-to-end run.' > e2e-secondary.txt
echo 'A line of the scripted agent of an end-to-end run, in the secondary repository.' > "$tree/e2e-secondary.txt"
printf '{"type": "create_pull_request", "title": "e2e: Add a line", "body": "The run'"'"'s own pull request of an end-to-end run."}\n' >> "$HOME/out/safe-outputs.jsonl"
printf '{"type": "create_pull_request", "repo": "%s", "title": "e2e: Add a line", "body": "The secondary pull request of an end-to-end run."}\n' "$repo" >> "$HOME/out/safe-outputs.jsonl"
SH
cat > "$HOME/.config/fake-agent/demo.json" <<'JSON'
[
  {"say": "End-to-end run: a pull request of the run's own and one in the secondary repository."},
  {"execute": {"title": "Bash", "command": "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef"}},
  {"execute": {"title": "Bash", "command": "sh \"$HOME/.config/fake-agent/secondary.sh\""}},
  {"write": {"title": "Write", "path": "{home}/out/outcome.json", "content": "{\"summary\": \"Added a line to each repository.\", \"tests\": [], \"stopped_early\": null}\n"}},
  {"cost": {"usd": 0.01}},
  {"say": "Done."}
]
JSON
