#!/bin/sh
# What the scripted agent does in CI's run with `agent-user: sandbox`:
# secure-host runs this as the sandbox user, and the agent, that user
# too, prints who and where it is and asks for its comment only when it
# is not the runner's user, its home is the sandbox user's, and the
# runner's home is closed to it. CI's check of the comment fails if any
# does not hold.
set -eu
mkdir -p "$HOME/.config/fake-agent"
cat > "$HOME/.config/fake-agent/user-probe.sh" <<'SH'
set -eu
echo "USER=$(id -un) HOME=$HOME"
test "$(id -un)" = runner-sandbox
test "$HOME" = /home/runner-sandbox
# The runner's own user, and with it the job's checkout and its files.
test "$(stat -c %U /home/runner)" = runner
if ls /home/runner > /dev/null 2>&1; then
  echo "the sandbox user can list the runner's home" >&2
  exit 1
fi
printf '%s\n' '{"type": "add_comment", "body": "A comment from the scripted agent of a sandbox-user run."}' >> "$HOME/out/safe-outputs.jsonl"
SH
cat > "$HOME/.config/fake-agent/demo.json" <<'JSON'
[
  {"say": "End-to-end run as the sandbox user: one comment."},
  {"execute": {"title": "Bash", "command": "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef"}},
  {"execute": {"title": "Bash", "command": "sh \"$HOME/.config/fake-agent/user-probe.sh\""}},
  {"write": {"title": "Write", "path": "{home}/out/outcome.json", "content": "{\"summary\": \"Ran as the sandbox user, in its home.\", \"tests\": [], \"stopped_early\": null}\n"}},
  {"cost": {"usd": 0.01}},
  {"say": "Done."}
]
JSON
