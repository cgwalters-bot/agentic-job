#!/bin/sh
# The scripted agent's session for the topic-branch analysis: one comment
# on the scratch issue, and an update of its body. `replace-island` keeps
# one section of the body, which each run replaces rather than appends to.
set -eu
mkdir -p "$HOME/.config/fake-agent"
cat > "$HOME/.config/fake-agent/demo.json" <<'JSON'
[
  {"say": "Topic-branch analysis: one comment and one body update on the scratch issue."},
  {"execute": {"title": "Bash", "command": "git log --oneline -1 && id -un"}},
  {"execute": {"title": "Bash", "command": "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef"}},
  {"write": {"title": "Write", "path": "{home}/out/safe-outputs.jsonl", "content": "{\"type\": \"add_comment\", \"body\": \"A comment from the scripted agent of an event-triggered run.\"}\n{\"type\": \"update_issue\", \"repo\": \"cgwalters-forge/agentic-job\", \"issue_number\": 64, \"operation\": \"replace-island\", \"body\": \"A body section from the scripted agent of a topic-branch analysis.\"}\n"}},
  {"write": {"title": "Write", "path": "{home}/out/outcome.json", "content": "{\"summary\": \"Commented on and updated the scratch issue.\", \"tests\": [], \"stopped_early\": null}\n"}},
  {"cost": {"usd": 0.01}},
  {"say": "Done."}
]
JSON
