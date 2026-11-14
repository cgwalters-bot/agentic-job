set -eu
out=$(mktemp -d)
agentic-job policy --allow docs/examples/local.toml --repo example-org/example --clone-url https://github.com/example-org/example --base main --kind analysis --outputs noop --max-outputs 1 > "$out/policy.json"
mkdir "$out/handback"
cp docs/examples/outputs.jsonl "$out/handback/outputs.jsonl"
agentic-job collect --policy "$out/policy.json" --outputs "$out/handback" --collected "$out/collected.json"
agentic-job check --policy "$out/policy.json" --outputs "$out/handback" --collected "$out/collected.json" --report "$out/report.json"
printf 'Checked local example: %s/report.json\n' "$out"
