#!/bin/sh
# What the scripted agent does in CI's end-to-end run: `sandbox setup`
# runs this as the sandbox user, and `fake-agent demo` then plays the
# session it leaves. It prints a string shaped like a credential (which
# the run insists was redacted) and asks for a comment, but only when
# its GitHub token reads this repository and GitHub refuses it a write,
# so CI's check of the comment fails if either probe does (#112).
set -eu
mkdir -p "$HOME/.config/fake-agent"
cat > "$HOME/.config/fake-agent/github-probe.sh" <<'SH'
set -eu
repo=$(git remote get-url origin | sed -e 's#^https://github.com/##' -e 's#\.git$##')
# A read, with the run's token: gh does nothing without one.
test "$(gh api "repos/$repo" --jq .full_name)" = "$repo"
# A write, on the issue CI comments on (ci.yml's comment-target), that
# GitHub and not the egress proxy must refuse.
issue=$(gh api "repos/$repo/issues/64" --jq .node_id)
if out=$(gh api graphql -f id="$issue" -f query='mutation($id: ID!) {
  addComment(input: {subjectId: $id, body: "The scripted agent'"'"'s GitHub token could write."}) { clientMutationId } }' 2>&1); then
  echo "the agent's GitHub token wrote to $repo" >&2
  exit 1
fi
printf '%s\n' "$out"
case "$out" in *"egress proxy"*) exit 1 ;; *"not accessible"*) ;; *) exit 1 ;; esac
# Without the egress-write-policy input the agent's writes are open: no
# proxy refuses its POST (e2e-write-policy is the run where one does).
headers=$(curl -sS -o /dev/null -D - -X POST --data probe https://example.com/)
case "$headers" in *[Xx]-[Ee]gress-[Dd]enied:*) exit 1 ;; esac
printf '%s\n' '{"type": "add_comment", "body": "A comment from the scripted agent of an end-to-end run."}' >> "$HOME/out/safe-outputs.jsonl"
SH
cat > "$HOME/.config/fake-agent/demo.json" <<'JSON'
[
  {"say": "End-to-end run: one comment."},
  {"execute": {"title": "Bash", "command": "printf 'fake secret: gh%s_%s\\n' p FAKEREDACTIONCANARY0123456789abcdef"}},
  {"execute": {"title": "Bash", "command": "git log --oneline -1 && id -un"}},
  {"execute": {"title": "Bash", "command": "sh \"$HOME/.config/fake-agent/github-probe.sh\""}},
  {"write": {"title": "Write", "path": "{home}/out/outcome.json", "content": "{\"summary\": \"Commented on the scratch issue.\", \"tests\": [{\"command\": \"git log --oneline -1\", \"exit_code\": 0, \"duration_s\": 0}], \"stopped_early\": null}\n"}},
  {"cost": {"usd": 0.01}},
  {"say": "Done."}
]
JSON
