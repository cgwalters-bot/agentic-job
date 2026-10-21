#!/bin/sh
# What the scripted agent does in CI's run with the egress-write-policy
# input: as the runner's user, with no proxy in its environment, curl and
# Node read an arbitrary host through the egress proxy (so both trust its
# per-job authority: the system's store, and NODE_EXTRA_CA_CERTS that
# `run` passes on), and the proxy refuses a POST there. It asks for its
# comment only when all three hold, so CI's check of the comment fails if
# any does not.
set -eu
mkdir -p "$HOME/.config/fake-agent"
cat > "$HOME/.config/fake-agent/write-probe.sh" <<'SH'
set -eu
curl -fsS -o /dev/null https://example.com/
node -e 'fetch("https://example.com/").then(r => process.exit(r.ok ? 0 : 1), e => { console.error(e); process.exit(1); })'
headers=$(curl -sS -o /dev/null -D - -X POST --data probe https://example.com/)
printf '%s\n' "$headers"
printf '%s\n' "$headers" | grep -qi '^x-egress-denied:'
printf '%s\n' '{"type": "add_comment", "body": "A comment from the scripted agent of a write-policy run."}' >> "$HOME/out/safe-outputs.jsonl"
SH
cat > "$HOME/.config/fake-agent/demo.json" <<'JSON'
[
  {"say": "End-to-end run under the egress write policy: one comment."},
  {"execute": {"title": "Bash", "command": "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef"}},
  {"execute": {"title": "Bash", "command": "sh \"$HOME/.config/fake-agent/write-probe.sh\""}},
  {"write": {"title": "Write", "path": "{home}/out/outcome.json", "content": "{\"summary\": \"Read through the egress proxy and was refused a POST.\", \"tests\": [], \"stopped_early\": null}\n"}},
  {"cost": {"usd": 0.01}},
  {"say": "Done."}
]
JSON
