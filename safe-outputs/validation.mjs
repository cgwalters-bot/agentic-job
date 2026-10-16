#!/usr/bin/env node
// Writes validation.json, the per-type rules gh-aw's collector
// (collect_ndjson_output.cjs) validates an agent's outputs against. gh-aw's
// compiler generates them into each workflow it compiles
// (GH_AW_VALIDATION_JSON) and publishes them nowhere else, so they are read
// out of gh-aw's own compiled workflows at the commit its setup action is
// pinned to in .github/workflows/.
//   validation.mjs GH_AW_CHECKOUT [--check]
// It also writes the limits gh-aw's handlers hold a request to only when
// apply runs them, after the session (HANDLER_LIMITS below), read out of
// the handlers' code at the same commit, for `handback check`.
// --check writes nothing and fails if either file is not what would be
// written.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "validation.json");
const LIMITS_OUT = join(HERE, "../crates/agentic-job/src/check/handler-limits.json");
const HANDLERS_DIR = "actions/setup/js";
const LOCK_DIR = ".github/workflows";
const LOCK_SUFFIX = ".lock.yml";
const KEY = "GH_AW_VALIDATION_JSON: |";
// The output types a run may be allowed.
const TYPES = ["create_pull_request", "add_comment", "create_issue", "create_discussion", "hide_comment", "create_pull_request_review_comment", "reply_to_pull_request_review_comment", "resolve_pull_request_review_thread", "close_issue", "add_labels", "remove_labels", "update_issue", "update_pull_request", "mark_pull_request_as_ready_for_review", "add_reviewer", "assign_to_user", "close_pull_request", "link_sub_issue", "create_check_run", "update_project", "push_to_pull_request_branch", "noop", "missing_tool", "missing_data"];
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

// The handlers' limits on the fields of a request: the value of a
// constant, the error a handler raises over it, and the code that applies
// it, which must be in the handler as written here, or this fails: a
// change to what is counted, or where, is then read before it is copied.
// `measure` is how `handback check` counts (check/handler_limits.rs); in
// the message, `max` and `got` are the expressions that become `{max}`
// and `{got}`, and `name` the one that becomes the field's name. A
// comment is held to its limits twice, as written and with the footer
// gh-aw adds (`footer` below), whose own links and length count too.
const HANDLER_LIMITS = [
  {
    type: "add_comment", field: "body", measure: "length", footer: "length",
    constant: ["comment_limit_helpers.cjs", "MAX_COMMENT_LENGTH"],
    message: ["comment_limit_helpers.cjs", "E006"], max: "MAX_COMMENT_LENGTH", got: "body.length",
    applied: [["comment_limit_helpers.cjs", "if (body.length > MAX_COMMENT_LENGTH) {"]],
  },
  {
    type: "add_comment", field: "body", measure: "links", footer: "links",
    constant: ["comment_limit_helpers.cjs", "MAX_LINKS"],
    message: ["comment_limit_helpers.cjs", "E008"], max: "MAX_LINKS", got: "links",
    applied: [
      ["comment_limit_helpers.cjs", "const links = (body.match(/https?:\\/\\/[^\\s]+/g) || []).length;"],
      ["comment_limit_helpers.cjs", "if (links > MAX_LINKS) {"],
    ],
  },
  {
    type: "create_issue", field: "labels", measure: "distinct",
    constant: ["constants.cjs", "MAX_LABELS"],
    message: ["limit_enforcement_helpers.cjs", "E003"], max: "maxLimit", got: "array.length", name: "parameterName",
    applied: [
      ["limit_enforcement_helpers.cjs", "if (array && Array.isArray(array) && array.length > maxLimit) {"],
      ["create_issue.cjs", ".filter((label, index, arr) => arr.indexOf(label) === index);"],
    ],
  },
  {
    type: "add_labels", field: "labels", measure: "count",
    constant: ["constants.cjs", "MAX_LABELS"],
    message: ["limit_enforcement_helpers.cjs", "E003"], max: "maxLimit", got: "array.length", name: "parameterName",
    applied: [
      ["limit_enforcement_helpers.cjs", "if (array && Array.isArray(array) && array.length > maxLimit) {"],
      ["add_labels.cjs", "const configuredMaxLabels = config.max_labels ?? MAX_LABELS;"],
    ],
  },
];

// Every call of a limit's check in the handlers, and why it is held in
// the session or need not be: a call this does not list fails it, so a
// limit gh-aw adds is not missed.
const LIMIT_CALLS = {
  "add_comment.cjs: enforceCommentLimits(processedBody)": "add_comment, as written and with its footer",
  "add_labels.cjs: tryEnforceArrayLimit(requestedLabelNames, maxLabels, \"labels\")": "add_labels; apply sets no max_labels",
  "create_issue.cjs: tryEnforceArrayLimit(labels, MAX_LABELS, \"labels\")": "create_issue",
  "create_issue.cjs: tryEnforceArrayLimit(assignees, MAX_ASSIGNEES, \"assignees\")": "validation.json gives create_issue no assignees",
  "comment_memory.cjs: enforceCommentLimits(managedBody)": "no run is allowed comment_memory",
  "create_discussion.cjs: tryEnforceArrayLimit(discussionLabels, MAX_LABELS, \"labels\")": "validation.json gives create_discussion no labels",
  "create_pull_request.cjs: enforcePullRequestLimits(patchContent, maxFiles)": "check holds a patch to the policy's max_patch_files",
  "create_pull_request_helpers.cjs: tryEnforceArrayLimit(sanitized, MAX_ASSIGNEES, \"assignees\")": "a fallback issue, which apply turns off",
  "safe_outputs_handlers.cjs: enforceCommentLimits(body)": "gh-aw's MCP server, which no run has",
  "update_issue.cjs: tryEnforceArrayLimit(updateData.labels, MAX_LABELS, \"labels\")": "policy allows an update_issue its title, body and status only",
  "update_issue.cjs: tryEnforceArrayLimit(updateData.assignees, MAX_ASSIGNEES, \"assignees\")": "policy allows an update_issue its title, body and status only",
  "update_discussion.cjs: tryEnforceArrayLimit(item.labels, MAX_LABELS, \"labels\")": "no run is allowed update_discussion",
};
const LIMIT_CALL = /(?<!function )\b(enforceCommentLimits|tryEnforceArrayLimit|enforcePullRequestLimits)\(([^()]*)\)/g;

// What is added to a comment before gh-aw checks it again: its footer as
// add_comment.cjs assembles it where apply.yml configures nothing of it,
// by gh-aw's own code, and what apply.yml itself adds (APPLY_ADDS). Its
// links are as many whatever the names in it; its length is of the longest
// owner and repository names GitHub allows, 20-digit ids, a discussion's
// history link and a workflow name as long as apply.yml lets the caller's
// be.
const APPLY = join(HERE, "../.github/workflows/apply.yml");
const MAX_WORKFLOW_NAME = 100;
// apply.yml's additions at their longest, each with the text there it comes
// from: a partial run's note before the body (of the longer reason), and the
// marker after it, which becomes an HTML comment as it is sent (its index
// given an id's digits).
const STOPPED = "a request, task or spending limit, or an error that ended the agent's turn";
const APPLY_ADDS = [
  [`'${STOPPED.replace("'", "''")}'`, ""],
  ['"**Partial work.** The run was stopped at $STOPPED before the task was done; this is what it handed back."',
    `**Partial work.** The run was stopped at ${STOPPED} before the task was done; this is what it handed back.\n\n`],
  ['|= "\\($note)\\n\\n\\(.)"', ""],
  ["`agentic-job-applied: ${process.env.GITHUB_RUN_ID}/${index}/${hash.digest('hex').slice(0, 16)}`", ""],
  ["body: `${item.body ?? ''}\\n\\n${name}`", `\n\n<!-- agentic-job-applied: ${"9".repeat(20)}/${"9".repeat(20)}/${"f".repeat(16)} -->`],
  ['"<!-- $1 -->"', ""],
  [`const MAX_WORKFLOW_NAME = ${MAX_WORKFLOW_NAME};`, ""],
];
function footer(checkout) {
  const require = createRequire(join(checkout, HANDLERS_DIR, "footer.cjs"));
  globalThis.core ??= { info() {}, debug() {}, warning() {}, notice() {} };
  const [owner, repo, id, name] = ["o".repeat(39), "r".repeat(100), "9".repeat(20), "w".repeat(MAX_WORKFLOW_NAME)];
  // None of gh-aw's other settings, which apply.yml does not make either.
  for (const key of Object.keys(process.env).filter((k) => k.startsWith("GH_AW_"))) delete process.env[key];
  Object.assign(process.env, {
    GITHUB_REPOSITORY: `${owner}/${repo}`, GITHUB_REPOSITORY_ID: id, GITHUB_RUN_ID: id, GITHUB_RUN_ATTEMPT: id,
    GITHUB_JOB: "apply", GH_AW_JOB_CHECK_RUN_ID: id, GH_AW_WORKFLOW_ID: "agentic-job", GITHUB_SERVER_URL: "https://github.com",
  });
  const { assembleMarkdownBodyParts } = require("./markdown_body_helpers.cjs");
  const { appendExecutionProvenance } = require("./execution_provenance.cjs");
  const { generateHistoryUrl } = require("./generate_history_link.cjs");
  const runUrl = `https://github.com/${owner}/${repo}/actions/runs/${id}`;
  const historyUrl = generateHistoryUrl({ owner, repo, itemType: "discussion_comment", workflowId: "agentic-job", serverUrl: "https://github.com" });
  const parts = assembleMarkdownBodyParts({ includeFooter: true, workflowName: name, runUrl, historyUrl, triggeringIssueNumber: Number(id) });
  let added = appendExecutionProvenance(`\n\n${parts.footer}`, name, runUrl);
  const apply = readFileSync(APPLY, "utf8");
  for (const [text, adds] of APPLY_ADDS) {
    if (!apply.includes(text)) throw new Error(`apply.yml no longer has \`${text}\``);
    added += adds;
  }
  return { links: (added.match(/https?:\/\/[^\s]+/g) || []).length, length: added.length };
}

function generateLimits(checkout) {
  const dir = join(checkout, HANDLERS_DIR);
  const read = (file) => readFileSync(join(dir, file), "utf8");
  const one = (found, what) => {
    if (found.length !== 1) throw new Error(`${what}: found ${found.length} times, not once`);
    return found[0];
  };
  const calls = new Set();
  for (const file of readdirSync(dir).filter((n) => n.endsWith(".cjs") && !n.endsWith(".test.cjs") && n !== "limit_enforcement_helpers.cjs")) {
    for (const [call] of read(file).matchAll(LIMIT_CALL)) calls.add(`${file}: ${call}`);
  }
  const unlisted = [...calls].filter((call) => !(call in LIMIT_CALLS));
  const gone = Object.keys(LIMIT_CALLS).filter((call) => !calls.has(call));
  if (unlisted.length > 0 || gone.length > 0) {
    throw new Error(`the handlers' limit checks are not those listed: new ${JSON.stringify(unlisted)}, gone ${JSON.stringify(gone)}`);
  }
  const added = footer(checkout);
  const limits = HANDLER_LIMITS.map((limit) => {
    const [constantFile, constant] = limit.constant;
    const max = Number(one([...read(constantFile).matchAll(new RegExp(`^const ${constant} = (\\d+);$`, "gm"))], `${constantFile}: ${constant}`)[1]);
    const [messageFile, code] = limit.message;
    let message = one([...read(messageFile).matchAll(new RegExp(`\`(${code}: [^\`]*)\``, "g"))], `${messageFile}: the ${code} message`)[1];
    message = message.replaceAll(`\${${limit.max}}`, "{max}").replaceAll(`\${${limit.got}}`, "{got}");
    if (limit.name) message = message.replaceAll(`\${${limit.name}}`, limit.field);
    if (message.includes("${") || !message.includes("{max}") || !message.includes("{got}")) {
      throw new Error(`${messageFile}: the ${code} message is not one of a limit and a count: ${message}`);
    }
    for (const [file, text] of limit.applied) {
      if (!read(file).includes(text)) throw new Error(`${file} no longer has \`${text}\``);
    }
    const footer = limit.footer ? added[limit.footer] : 0;
    return { type: limit.type, field: limit.field, measure: limit.measure, max, footer, message };
  });
  return `${JSON.stringify(limits, null, 2)}\n`;
}

const [arg, flag] = process.argv.slice(2);
// createRequire takes only an absolute path; CI passes a relative one.
const checkout = arg && resolve(arg);
if (!checkout || (flag !== undefined && flag !== "--check")) {
  console.error("usage: validation.mjs GH_AW_CHECKOUT [--check]");
  process.exit(2);
}
try {
  for (const [out, text] of [[OUT, generate(checkout)], [LIMITS_OUT, generateLimits(checkout)]]) {
    if (flag !== "--check") {
      writeFileSync(out, text);
    } else if (readFileSync(out, "utf8") !== text) {
      throw new Error(`${out} is not what gh-aw at ${checkout} generates; run validation.mjs without --check`);
    }
  }
} catch (e) {
  console.error(`validation.mjs: ${e.message}`);
  process.exit(1);
}
