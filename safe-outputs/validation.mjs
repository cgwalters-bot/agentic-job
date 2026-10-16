#!/usr/bin/env node
// Writes validation.json, the per-type rules gh-aw's collector
// (collect_ndjson_output.cjs) validates an agent's outputs against. gh-aw's
// compiler generates them into each workflow it compiles
// (GH_AW_VALIDATION_JSON) and publishes them nowhere else, so they are read
// out of gh-aw's own compiled workflows at the commit its setup action is
// pinned to in .github/workflows/.
//   validation.mjs GH_AW_CHECKOUT [--check]
// --check writes nothing and fails if validation.json is not what would be
// written.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "validation.json");
const LOCK_DIR = ".github/workflows";
const LOCK_SUFFIX = ".lock.yml";
const KEY = "GH_AW_VALIDATION_JSON: |";
// The output types a run may be allowed.
const TYPES = ["create_pull_request", "add_comment", "create_issue", "create_discussion", "close_issue", "add_labels", "remove_labels", "update_issue", "update_pull_request", "mark_pull_request_as_ready_for_review", "add_reviewer", "assign_to_user", "close_pull_request", "link_sub_issue", "create_check_run", "update_project", "push_to_pull_request_branch", "noop", "missing_tool", "missing_data"];
// What a workflow of gh-aw's switches on for a type of its own: a free-form
// `data` object and its schema. No run here is allowed one, and the
// collector refuses `data` for a type without them.
const WORKFLOW_OPTIONS = ["dataEnabled", "dataSchema"];

// The JSON of the block scalar after KEY in the lock file NAME's TEXT, or
// null.
function validationOf(name, text) {
  const lines = text.split("\n");
  const at = lines.findIndex((l) => l.trim() === KEY);
  if (at < 0) return null;
  const indent = lines[at].search(/\S/);
  const end = lines.findIndex((l, i) => i > at && l.trim() !== "" && l.search(/\S/) <= indent);
  try {
    return JSON.parse(lines.slice(at + 1, end < 0 ? undefined : end).join("\n"));
  } catch (e) {
    throw new Error(`${name}: its ${KEY} block is not JSON: ${e.message}`);
  }
}

// A type's rule without the options one workflow switched on, as text to
// compare.
const common = (rule) => JSON.stringify(Object.fromEntries(Object.entries(rule).filter(([k]) => !WORKFLOW_OPTIONS.includes(k))));

function generate(checkout) {
  const dir = join(checkout, LOCK_DIR);
  const rules = {};
  const from = {};
  for (const name of readdirSync(dir).filter((n) => n.endsWith(LOCK_SUFFIX)).sort()) {
    const found = validationOf(name, readFileSync(join(dir, name), "utf8")) ?? {};
    for (const type of TYPES.filter((t) => t in found)) {
      // Apart from those options every lock file must give a type the same
      // rule, or the first one read would decide silently.
      const rule = common(found[type]);
      if (type in rules && rules[type] !== rule) throw new Error(`${type}: ${name} and ${from[type]} disagree on its rule`);
      rules[type] = rule;
      from[type] ??= name;
    }
  }
  const missing = TYPES.filter((t) => !(t in rules));
  if (missing.length > 0) throw new Error(`no lock file in ${dir} has rules for ${missing.join(", ")}`);
  return `${JSON.stringify(Object.fromEntries(TYPES.map((t) => [t, JSON.parse(rules[t])])), null, 2)}\n`;
}

const [checkout, flag] = process.argv.slice(2);
if (!checkout || (flag !== undefined && flag !== "--check")) {
  console.error("usage: validation.mjs GH_AW_CHECKOUT [--check]");
  process.exit(2);
}
try {
  const text = generate(checkout);
  if (flag !== "--check") {
    writeFileSync(OUT, text);
  } else if (readFileSync(OUT, "utf8") !== text) {
    throw new Error(`${OUT} is not what gh-aw at ${checkout} generates; run validation.mjs without --check`);
  }
} catch (e) {
  console.error(`validation.mjs: ${e.message}`);
  process.exit(1);
}
