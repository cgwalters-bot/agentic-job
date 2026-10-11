// Runs gh-aw's collector as its ingestion step does, outside a workflow:
//   node collect.cjs GH_AW_JS OUTPUTS CONFIG VALIDATION OWNER/NAME RESULT
// The collector is written for actions/github-script, so its globals are
// stood in for; nothing of it is changed. RESULT gets what it stores as
// agent_output.json, which `agentic-job check --collected` reads.
const fs = require("node:fs");
const path = require("node:path");

const [js, outputs, config, validation, repository, result] = process.argv.slice(2);
const [owner, repo] = repository.split("/");
let output;
Object.assign(globalThis, {
  core: {
    info() {}, warning() {}, error() {}, exportVariable() {},
    setOutput(name, value) { if (name === "output") output = value; },
    setFailed(message) { throw new Error(message); },
  },
  context: { repo: { owner, repo }, payload: {}, eventName: "workflow_dispatch" },
  // It looks up the authors of add_comment targets; there is no network here.
  github: { rest: { issues: { get: async () => { throw new Error("no forge API in this test"); } } } },
});
Object.assign(process.env, {
  GH_AW_SAFE_OUTPUTS: outputs, GH_AW_SAFE_OUTPUTS_CONFIG_PATH: config, GH_AW_VALIDATION_CONFIG_PATH: validation,
  // check.yml's URL policy.
  GH_AW_SAFE_OUTPUTS_URLS: "allowed-or-code-region",
});
// Its own copy of the result goes to /tmp/gh-aw unless told otherwise.
require(path.join(js, "constants.cjs")).TMP_GH_AW_PATH = path.join(path.dirname(result), "gh-aw");

require(path.join(js, "collect_ndjson_output.cjs")).main().then(() => {
  if (typeof output !== "string" || output === "") throw new Error("gh-aw's collector produced no output");
  fs.writeFileSync(result, output);
}).catch((e) => {
  console.error(`collect: ${e.message}`);
  process.exit(1);
});
