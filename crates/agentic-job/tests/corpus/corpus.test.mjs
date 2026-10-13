// The corpus: the old tree's safe-outputs check and the new one get the
// same requests and the same hand-backs, and must give the same verdict.
//
// The old check is cgwalters-devspace-sandbox's safe-outputs/safe-outputs.mjs
// at the commit docs/plan.md names, run as it is (it vendors gh-aw's
// collector). The new one is `agentic-job policy`, then gh-aw's collector
// from gh-aw's own repository with the validation rules of safe-outputs/
// here, then `agentic-job check`. The hand-backs are made by the old
// tree's own handback.mjs from real git repositories, so the patches are
// what `git format-patch` writes. The cases are those of the old tree's
// safe-outputs.test.mjs, and more; two are the hand-backs of real runs
// (safe-outputs/fixtures).
//
//   OLD_TREE=... GH_AW_JS=.../actions/setup/js AGENTIC_JOB=.../agentic-job \
//     node --test corpus.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readlinkSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const env = (name) => {
  assert.ok(process.env[name], `${name} must be set; see the top of this file`);
  return resolve(process.env[name]);
};
const OLD_TREE = env("OLD_TREE");
const GH_AW_JS = env("GH_AW_JS");
const AGENTIC_JOB = env("AGENTIC_JOB");
const HERE = dirname(fileURLToPath(import.meta.url));
const fromOld = (path) => import(pathToFileURL(join(OLD_TREE, path)));

const old = await fromOld("safe-outputs/safe-outputs.mjs");
const { BASE, REPO, patchOf, repoWith, scratch, write } = await fromOld("safe-outputs/test-helpers.mjs");
const { buildPatch } = await fromOld("agent/handback.mjs");
const VENDORED = join(OLD_TREE, "vendor/gh-aw");
// What the check job here gives gh-aw's collector, and two real hand-backs.
const SAFE_OUTPUTS = join(HERE, "../../../../safe-outputs");

// The old tree's allowlist as a bounds file: the same bounds, so that a
// difference in a verdict is a difference in the code.
const BOUNDS = join(scratch(), "allow.toml");
{
  const a = old.ALLOWLIST;
  const list = (v) => JSON.stringify(v);
  writeFileSync(BOUNDS, [
    'hosts = ["github.com"]',
    `repos = ${list(a.repos)}`, `bases = ${list(a.bases)}`,
    `max_outputs = ${a.max_outputs}`, `max_patch_bytes = ${a.max_patch_bytes}`, `max_patch_files = ${a.max_patch_files}`,
    "[outputs]", ...Object.entries(a.outputs).map(([type, { max }]) => `${type} = { max = ${max} }`),
    "[unprotected_files]", `repos = ${list(a.unprotected_files.repos)}`, `files = ${list(a.unprotected_files.files)}`,
  ].join("\n") + "\n");
}

// The old tree's policy, less the one deliberate difference: README.md is
// protected nowhere (#537). So a difference in a verdict is still one in
// the code.
function oldPolicy(inputs) {
  const was = old.compilePolicy(inputs);
  const pr = was.policy?.safe_outputs?.create_pull_request;
  if (pr) pr.protected_files = pr.protected_files.filter((name) => name !== "README.md");
  return was;
}

const agenticJob = (...args) => spawnSync(AGENTIC_JOB, args, { encoding: "utf8" });

// `agentic-job policy` for the old tree's dispatch inputs: {status, policy, stderr}.
function newPolicy({ repo, base, workflow, outputs, maxOutputs }) {
  const r = agenticJob("policy", "--allow", BOUNDS, "--repo", repo, "--clone-url", `https://github.com/${repo}`,
    "--base", base, "--kind", workflow, "--outputs", outputs, "--max-outputs", maxOutputs);
  assert.ok([0, 1].includes(r.status), `policy exited ${r.status}: ${r.stderr}`);
  return { status: r.status, policy: r.status === 0 ? JSON.parse(r.stdout) : undefined, stderr: r.stderr };
}

// The new check of the hand-back in DIR: gh-aw's collector, configured by
// the policy, and then `agentic-job check`. Returns the verdict.
function newCheck(dir, policy) {
  const work = scratch();
  const file = (name) => join(work, name);
  writeFileSync(file("policy.json"), JSON.stringify(policy));
  writeFileSync(file("config.json"), JSON.stringify(policy.safe_outputs));
  const collected = spawnSync(process.execPath, [join(HERE, "collect.cjs"), GH_AW_JS, join(dir, old.OUTPUTS_FILE),
    file("config.json"), join(SAFE_OUTPUTS, "validation.json"), policy.repo, file("agent_output.json")], { encoding: "utf8" });
  // A collector that fails stops the job before the check: a refusal.
  if (collected.status !== 0) return { ok: false, errors: [collected.stderr], items: [], patch: null };
  const r = agenticJob("check", "--policy", file("policy.json"), "--outputs", dir,
    "--collected", file("agent_output.json"), "--report", file("verdict.json"));
  assert.ok([0, 1].includes(r.status), `check exited ${r.status}: ${r.stderr}`);
  const verdict = JSON.parse(readFileSync(file("verdict.json"), "utf8"));
  assert.equal(verdict.ok, r.status === 0, "the exit state is the verdict");
  return verdict;
}

test("gh-aw's collector is the code the old tree vendored", () => {
  const upstream = JSON.parse(readFileSync(join(VENDORED, "UPSTREAM.json"), "utf8"));
  const generated = Object.keys(upstream.generated);
  for (const [name, sha] of Object.entries(upstream.files).filter(([name]) => !generated.includes(name))) {
    assert.equal(createHash("sha256").update(readFileSync(join(GH_AW_JS, name))).digest("hex"), sha, name);
  }
});

const INPUTS = { repo: REPO, base: BASE, workflow: "branch", outputs: "create_pull_request,noop", maxOutputs: "3" };
// The bot's own repository, where AGENTS.md may change too.
const OWN_REPO = "cgwalters-bot/homegit";

test("policy: a request against the bounds", () => {
  for (const [name, change] of [
    // The cases of the old tree's test.
    ["ok", {}],
    ["another owner", { repo: "evil/bootc" }],
    ["a repo of another case", { repo: "BOOTC-DEV/bootc" }],
    ["a malformed repo", { repo: "bootc-dev/bootc/x" }],
    ["a base not listed", { base: "release" }],
    ["a bot branch", { base: "bot/agent-run-praxis" }],
    ["a base with ..", { base: "bot/../main" }],
    ["a type not listed", { outputs: "create_pull_request,delete_repo" }],
    ["no types", { outputs: " , " }],
    ["too many outputs", { maxOutputs: "6" }],
    ["no number", { maxOutputs: "many" }],
    ["a pull request from an analysis run", { workflow: "analysis" }],
    ["an analysis run's comments", { workflow: "analysis", outputs: "noop,add_comment" }],
    ["all types", { outputs: "all", maxOutputs: "max" }],
    ["all types of an analysis run", { workflow: "analysis", outputs: "all" }],
    // And more.
    ["the bot's own repository", { repo: OWN_REPO }],
    ["the bot's own repository in another case", { repo: "CGWalters-Bot/Homegit" }],
    ["a repository of the same owner", { repo: "cgwalters-bot/bootc" }],
    ["every type, two of each at most", { outputs: "all", maxOutputs: "2" }],
    ["a type twice, with spaces", { outputs: " noop , noop,create_pull_request" }],
    ["one type", { outputs: "noop", maxOutputs: "1" }],
    ["all, in capitals", { outputs: "ALL" }],
    ["zero outputs", { maxOutputs: "0" }],
    ["a number with a leading zero", { maxOutputs: "03" }],
    ["a number with a sign", { maxOutputs: "+3" }],
    ["a number with a space", { maxOutputs: " 3" }],
    ["a long number", { maxOutputs: "1000" }],
    ["no number at all", { maxOutputs: "" }],
    ["no types at all", { outputs: "" }],
    ["no repo", { repo: "" }],
    ["no base", { base: "" }],
    ["a base that starts with a dash", { base: "-main" }],
    ["a base with a space", { base: "bot/a b" }],
    ["a nested bot branch", { base: "bot/a/b/c" }],
    ["a repo with a newline", { repo: "bootc-dev/bootc\n" }],
    ["a base with a newline", { base: "main\n" }],
    // The concern of tracker#281: text that would be structure in JSON.
    ["a repo with a quote", { repo: 'bootc-dev/bootc","max_outputs":99,"x":"' }],
    ["a base with a quote", { base: 'main","max_outputs":99,"x":"' }],
    ["a base with a newline and a key", { base: 'main\n"max_outputs": 99' }],
    ["a type with a quote", { outputs: 'noop","create_issue":{"max":9},"x":"' }],
  ]) {
    const inputs = { ...INPUTS, ...change };
    const was = oldPolicy(inputs);
    const now = newPolicy(inputs);
    assert.equal(now.status === 0, was.errors.length === 0, `${name}: old ${JSON.stringify(was.errors)}, new ${now.stderr}`);
    if (!now.policy) continue;
    // What gh-aw's collector is configured with, key for key, and the caps.
    assert.deepEqual(now.policy.safe_outputs, was.policy.safe_outputs, name);
    for (const key of ["repo", "base", "max_outputs", "max_patch_bytes"]) assert.deepEqual(now.policy[key], was.policy[key], `${name}: ${key}`);
    assert.deepEqual(Object.keys(now.policy).sort(), ["base", "clone_url", "kind", "max_outputs", "max_patch_bytes", "repo", "safe_outputs"], name);
  }
});

const BRANCH = "agent-run-7";
const PR = { type: "create_pull_request", title: "Fix the thing", body: "Why.", branch: BRANCH };
const NOOP = { type: "noop", message: "Nothing to do." };
const TOKEN = `ghp_${"a1B2".repeat(10)}`;

// A hand-back directory: outputs.jsonl LINES, a base.json and the patch.
function handback({ lines, patch, base, baseJson, repo = REPO, extra = {}, also = () => {} }) {
  const dir = scratch();
  const items = lines.map((l) => (typeof l === "string" ? l : JSON.stringify(l)));
  if (items.length > 0) writeFileSync(join(dir, old.OUTPUTS_FILE), `${items.join("\n")}\n`);
  if (patch) writeFileSync(join(dir, old.patchFileName(BRANCH)), patch);
  if (base !== null) writeFileSync(join(dir, old.BASE_FILE), JSON.stringify(baseJson ?? { repo, ref: BASE, commit: base }));
  write(dir, extra);
  also(dir);
  return dir;
}

const policies = new Map();
// The old and the new policy of INPUTS with CHANGE; both must exist.
function bothPolicies(change = {}) {
  const key = JSON.stringify(change);
  if (!policies.has(key)) {
    const inputs = { ...INPUTS, ...change };
    policies.set(key, { was: oldPolicy(inputs).policy, now: newPolicy(inputs).policy });
    assert.ok(policies.get(key).was && policies.get(key).now, `a policy for ${key}`);
  }
  return policies.get(key);
}

// Checks one hand-back with both: ARGS are handback's, or a directory that
// holds one. WANT is null for one both accept, or a pattern both refusals
// must match.
async function same(name, args, want, change) {
  const { was, now } = bothPolicies(change);
  const dir = typeof args === "string" ? args : handback(args);
  const oldVerdict = await old.checkOutputs(dir, was);
  const newVerdict = newCheck(dir, now);
  const told = `${name}: old ${JSON.stringify(oldVerdict.errors)}, new ${JSON.stringify(newVerdict.errors)}`;
  assert.equal(newVerdict.ok, oldVerdict.ok, told);
  assert.equal(oldVerdict.ok, want === null, told);
  if (want) for (const errors of [oldVerdict.errors, newVerdict.errors]) assert.match(errors.join("\n"), want, told);
  // The requests as gh-aw sanitized them, and which patch, are the same too.
  assert.deepEqual(newVerdict.items, oldVerdict.items, name);
  const { files, ...patch } = newVerdict.patch ?? {};
  assert.deepEqual(newVerdict.patch && patch, oldVerdict.patch, name);
  return newVerdict;
}

const edit = (files) => (dir) => write(dir, files);
const bad = (files) => patchOf(edit(files));
const git = (dir, ...args) => assert.equal(spawnSync("git", ["-C", dir, ...args], { env: { PATH: process.env.PATH, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" } }).status, 0, args.join(" "));
const GOOD = patchOf(edit({ "src/lib.rs": "fn main() { println!(\"hi\"); }\n", "src/new.rs": "pub fn f() {}\n" }));
const withPatch = ({ patch, base }, lines = [PR]) => ({ lines, patch, base });
const EXECUTABLES = [{ "run.sh": "#!/bin/sh\n", "gone.sh": "x\n" }, ["run.sh", "gone.sh"]];
const MANY_LINES = Array.from({ length: 60 }, (_, i) => `line ${i}\n`).join("");

test("check: what both accept", async () => {
  for (const [name, args, items] of [
    // The cases of the old tree's test.
    ["a pull request", withPatch(GOOD), 1],
    ["a pull request and a noop", withPatch(GOOD, [PR, NOOP]), 2],
    ["a nested README", withPatch(patchOf(edit({ "tests/coccinelle/README.md": "x\n" }))), 1],
    ["a change to an executable file", withPatch(patchOf(edit({ "run.sh": "#!/bin/sh\necho hi\n" }), ...EXECUTABLES)), 1],
    ["the deletion of an executable file", withPatch(patchOf((d) => rmSync(join(d, "gone.sh")), ...EXECUTABLES)), 1],
    ["a noop alone", { lines: [NOOP], base: null }, 1],
    ["nothing", { lines: [], base: null }, 0],
    // And more.
    ["a deletion", withPatch(patchOf((d) => rmSync(join(d, "src/lib.rs")))), 1],
    ["a file moved, which is a deletion and an addition", withPatch(patchOf((d) => renameSync(join(d, "src/lib.rs"), join(d, "src/main.rs")))), 1],
    ["an empty new file", withPatch(bad({ "src/empty.rs": "" })), 1],
    ["a file without a last newline", withPatch(bad({ "src/lib.rs": "fn main() { 1 }" })), 1],
    ["a file with carriage returns", withPatch(bad({ "src/dos.txt": "one\r\ntwo\r\n" })), 1],
    ["text that is not ASCII", withPatch(bad({ "src/lib.rs": "// é ✓\n" })), 1],
    ["several hunks", withPatch(patchOf(edit({ "big.txt": MANY_LINES.replace("line 3\n", "three\n").replace("line 50\n", "") }), { "big.txt": MANY_LINES })), 1],
    ["content that looks like a patch", withPatch(bad({ "notes.txt": "--- a/.github/x\n+++ b/.github/x\n@@ -1 +1 @@\ndiff --git a/.github/y b/.github/y\nnew file mode 120000\nGIT binary patch\n" })), 1],
    ["removed content that looks like a patch", withPatch(patchOf((d) => rmSync(join(d, "notes.txt")), { "notes.txt": "-- a/.github/x\n++ b/.github/x\n" })), 1],
    ["names with every plain character", withPatch(bad({ "a_b/c+d@e=f,g-h.rs": "x\n" })), 1],
    ["docs below the top", withPatch(bad({ "docs/design.md": "x\n" })), 1],
    ["a top-level dot-file", withPatch(bad({ ".editorconfig": "root = true\n" })), 1],
    ["a title that gh-aw sanitizes", withPatch(GOOD, [{ ...PR, title: "Fix @octocat's thing", body: "cc @octocat see https://evil.example/x" }]), 1],
    ["a branch in capitals", withPatch(GOOD, [{ ...PR, branch: "Agent-Run-7" }]), 1],
  ]) {
    const verdict = await same(name, args, null);
    assert.equal(verdict.items.length, items, name);
  }
});

test("check: what both refuse", async () => {
  const executable = patchOf((d) => {
    write(d, { "run.sh": "#!/bin/sh\n" });
    chmodSync(join(d, "run.sh"), 0o755);
  });
  // A repository within the repository, which git adds as a submodule.
  const submodule = (d) => {
    const sub = join(d, "sub");
    write(sub, { "x.txt": "x\n" });
    git(sub, "init", "-q");
    git(sub, "add", "--all");
    git(sub, "-c", "user.name=t", "-c", "user.email=t@localhost", "commit", "-q", "-m", "sub");
  };
  const big = Array.from({ length: 30000 }, (_, i) => JSON.stringify({ type: "noop", message: `padding ${i} ${"x".repeat(20)}` }));
  for (const [name, args, want] of [
    // The cases of the old tree's test.
    ["an output type not allowed", { lines: [{ type: "add_comment", body: "x", item_number: 1 }], base: null }, /Unexpected output type 'add_comment'/],
    ["a type nobody knows", { lines: [{ type: "delete_repo" }], base: null }, /Unexpected output type 'delete_repo'/],
    ["a line that is not JSON", { lines: ["rm -rf /"], base: null }, /Invalid JSON/],
    ["more of a type than its maximum", withPatch(GOOD, [PR, PR]), /Too many items of type 'create_pull_request'/],
    ["more outputs than max_outputs", withPatch(GOOD, [{ type: "noop", message: "a" }, PR, PR]), /Too many|over max_outputs/],
    ["a field gh-aw's rules require", withPatch(GOOD, [{ type: "create_pull_request", branch: BRANCH }]), /title|body/],
    ["a secret in a request", { lines: [{ type: "noop", message: `key ${TOKEN}` }], base: null }, /secret-shaped string in outputs\.jsonl/],
    ["a pull request without its patch", { lines: [PR], base: GOOD.base }, /needs exactly one patch/],
    ["a patch without a pull request", { lines: [], patch: GOOD.patch, base: GOOD.base }, /patch without a create_pull_request/],
    ["a pull request without base.json", { lines: [PR], patch: GOOD.patch, base: null }, /base\.json is not/],
    ["a base.json for another repo", { ...withPatch(GOOD), baseJson: { repo: "bootc-dev/other", ref: BASE, commit: GOOD.base } }, /base\.json is not/],
    ["a base.json for another base", { ...withPatch(GOOD), baseJson: { repo: REPO, ref: "bot/x", commit: GOOD.base } }, /base\.json is not/],
    ["a patch of another base commit", { lines: [PR], patch: GOOD.patch, base: "0".repeat(40) }, /X-GH-AW-Base-Commit/],
    ["a stray file", { lines: [], base: null, extra: { "notes.txt": "hi" } }, /unexpected file "notes\.txt"/],
    ["a protected file (CONTRIBUTING.md, gh-aw's list)", withPatch(bad({ "CONTRIBUTING.md": "x\n" })), /protected files.*CONTRIBUTING\.md/],
    ["a manifest (package.json)", withPatch(bad({ "package.json": "{}\n" })), /protected files.*package\.json/],
    ["CI (.github/)", withPatch(bad({ ".github/workflows/x.yml": "on: push\n" })), /\.github/],
    ["a nested git file", withPatch(bad({ "sub/.gitattributes": "* -diff\n" })), /protected path/],
    ["a path with a space", withPatch(bad({ "a b.rs": "x\n" })), /not a plain relative path/],
    ["a new executable", withPatch(executable), /new symlink, submodule, executable/],
    ["a symlink", withPatch(patchOf((d) => symlinkSync("/etc/passwd", join(d, "link")))), /symlink|special/],
    ["a binary file", withPatch(patchOf((d) => writeFileSync(join(d, "blob.bin"), Buffer.from([0, 1, 2, 255, 0])))), /binary/],
    ["a secret in the patch", withPatch(bad({ "src/k.rs": `const K: &str = "${TOKEN}";\n` })), /secret-shaped string in aw-/],
    ["a ghr_ token", { lines: [{ type: "noop", message: `ghr_${"a1B2".repeat(10)}` }], base: null }, /secret-shaped string in outputs\.jsonl/],
    ["a GitLab token", { lines: [{ type: "noop", message: `glpat-${"a1B2".repeat(6)}` }], base: null }, /secret-shaped string/],
    ["an AWS key id", { lines: [{ type: "noop", message: `AKIA${"A1B2".repeat(4)}` }], base: null }, /secret-shaped string/],
    ["more files than allowed", withPatch(patchOf((d) => write(d, Object.fromEntries(Array.from({ length: 101 }, (_, i) => [`f/${i}.rs`, "x\n"]))))), /101 files/],
    // And more.
    ["a file made executable", withPatch(patchOf((d) => chmodSync(join(d, "src/lib.rs"), 0o755))), /mode change/],
    ["a submodule", withPatch(patchOf(submodule)), /symlink, submodule/],
    ["a name that is not ASCII", withPatch(bad({ "é.rs": "x\n" })), /not a plain relative path|unparseable header/],
    ["a name with a quote", withPatch(bad({ 'a"b.rs': "x\n" })), /not a plain relative path|unparseable header/],
    ["a name that starts with a dash", withPatch(bad({ "-x.rs": "x\n" })), /not a plain relative path/],
    ["git's own ignore file", withPatch(bad({ ".gitignore": "target\n" })), /protected path/],
    ["a nested CODEOWNERS", withPatch(bad({ "docs/CODEOWNERS": "* @x\n" })), /protected/],
    ["an .envrc", withPatch(bad({ ".envrc": "export X=1\n" })), /protected path/],
    ["an editor's settings", withPatch(bad({ ".vscode/settings.json": "{}\n" })), /protected/],
    ["hooks", withPatch(bad({ "sub/.husky/pre-commit": "x\n" })), /protected path/],
    ["a lock file below the top", withPatch(bad({ "web/package-lock.json": "{}\n" })), /protected files.*package-lock\.json/],
    ["agent instructions", withPatch(bad({ "docs/CLAUDE.md": "x\n" })), /protected files.*CLAUDE\.md/],
    ["a private key in the patch", withPatch(bad({ "k.pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n" })), /secret-shaped string in aw-/],
    ["a run token in a request", { lines: [{ type: "noop", message: `praxis-run-${"0f".repeat(32)}` }], base: null }, /secret-shaped string/],
    ["a secret in base.json", { ...withPatch(GOOD), baseJson: { repo: REPO, ref: BASE, commit: GOOD.base, note: TOKEN } }, /secret-shaped string in base\.json/],
    ["two patches", { ...withPatch(GOOD), extra: { "aw-other.patch": GOOD.patch } }, /needs exactly one patch/],
    ["a patch under another name", { lines: [PR], base: GOOD.base, extra: { "aw-other.patch": GOOD.patch } }, /needs exactly one patch/],
    ["a patch for another branch than the request's", withPatch(GOOD, [{ ...PR, branch: "other" }]), /needs exactly one patch/],
    ["a base.json that is not JSON", { ...withPatch(GOOD), also: (d) => writeFileSync(join(d, old.BASE_FILE), "{") }, /base\.json is not/],
    ["a base.json with a short commit", { ...withPatch(GOOD), baseJson: { repo: REPO, ref: BASE, commit: GOOD.base.slice(0, 12) } }, /base\.json is not/],
    ["a base.json too big", { ...withPatch(GOOD), baseJson: { repo: REPO, ref: BASE, commit: GOOD.base, pad: "x".repeat(5000) } }, /base\.json is \d+ bytes, over 4096/],
    ["outputs too big", { lines: big, base: null }, /outputs\.jsonl is \d+ bytes, over 1048576/],
    ["a directory", { lines: [NOOP], base: null, also: (d) => mkdirSync(join(d, "sub")) }, /unexpected file "sub"/],
    ["a link for the outputs", { lines: [], base: null, also: (d) => symlinkSync("/etc/hostname", join(d, old.OUTPUTS_FILE)) }, /outputs\.jsonl is not a regular file/],
    ["a patch that is no patch", { lines: [PR], patch: "rm -rf /\n", base: GOOD.base }, /holds no change/],
    ["a patch with no change", { lines: [PR], patch: GOOD.patch.toString().split("diff --git")[0], base: GOOD.base }, /holds no change/],
    ["two noops", { lines: [NOOP, NOOP], base: null }, /Too many items of type 'noop'/],
    ["a request with no type", { lines: [{ message: "x" }], base: null }, /./],
    ["a request that is an array", { lines: ["[1, 2]"], base: null }, /./],
  ]) {
    await same(name, args, want);
  }
});

test("check: docs are unprotected only in the repositories the bounds name", async () => {
  const docs = { "README.md": "x\n", "AGENTS.md": "x\n", "docs/README.md": "x\n", "docs/design.md": "x\n" };
  for (const [name, files, own, upstream] of [
    ["README.md, AGENTS.md and docs/", docs, null, /protected files.*: AGENTS\.md/],
    ["docs/ alone", { "docs/design.md": "x\n" }, null, null],
    ["other protected docs", { "CONTRIBUTING.md": "x\n" }, /protected files.*CONTRIBUTING\.md/, /protected files.*CONTRIBUTING\.md/],
    ["a manifest", { "package.json": "{}\n" }, /protected files.*package\.json/, /protected files.*package\.json/],
    ["CI, beside a README", { "README.md": "x\n", ".github/workflows/x.yml": "on: push\n" }, /\.github/, /\.github/],
    ["a secret in a README", { "README.md": `${TOKEN}\n` }, /secret-shaped/, /secret-shaped/],
  ]) {
    const { patch, base } = patchOf(edit(files));
    for (const [repo, want] of [[OWN_REPO, own], [REPO, upstream]]) {
      await same(`${name} in ${repo}`, { lines: [PR], patch, base, repo }, want, { repo });
    }
  }
});

test("check: every type, at its ceiling and over it", async () => {
  const all = { outputs: "all", maxOutputs: "max" };
  const comment = (n) => ({ type: "add_comment", body: `comment ${n}`, item_number: n });
  const tool = { type: "missing_tool", tool: "cargo-nextest", reason: "not installed" };
  const data = { type: "missing_data", data_type: "logs", reason: "none kept" };
  for (const [name, lines, want] of [
    ["comments, a missing tool and missing data", [comment(1), comment(2), tool, data], null],
    ["three comments", [comment(1), comment(2), comment(3)], null],
    ["four comments", [comment(1), comment(2), comment(3), comment(4)], /Too many items of type 'add_comment'/],
    ["six outputs within each type's ceiling", [comment(1), comment(2), comment(3), tool, tool, tool], /over max_outputs/],
    ["a pull request among them, with its patch", null, null],
  ]) {
    const args = lines ? { lines, base: null } : withPatch(GOOD, [PR, comment(1), NOOP]);
    await same(name, args, want, all);
  }
  // An analysis run has no create_pull_request to hand back.
  await same("a pull request from an analysis run", withPatch(GOOD), /Unexpected output type 'create_pull_request'/, { workflow: "analysis", outputs: "all" });
});

// A type the old tree never had, so there is nothing of it to compare
// with: the new policy, gh-aw's collector and the new check alone.
test("check: create_issue, through the collector and the check", () => {
  const bounds = join(scratch(), "allow.toml");
  writeFileSync(bounds, readFileSync(BOUNDS, "utf8").replace("[outputs]\n", "[outputs]\ncreate_issue = { max = 1 }\n"));
  const r = agenticJob("policy", "--allow", bounds, "--repo", REPO, "--clone-url", `https://github.com/${REPO}`,
    "--base", BASE, "--kind", "analysis", "--outputs", "create_issue,noop", "--max-outputs", "2");
  assert.equal(r.status, 0, r.stderr);
  const policy = JSON.parse(r.stdout);
  assert.deepEqual(policy.safe_outputs.create_issue, { max: 1 });
  const issue = { type: "create_issue", title: "A flaky test in nightly", body: "The nightly run fails once a week on the same test." };
  for (const [name, lines, want] of [
    ["one issue and a noop", [issue, NOOP], null],
    ["two issues", [issue, issue], /Too many items of type 'create_issue'/],
    ["an issue without a title", [{ type: "create_issue", body: issue.body }], /title/],
    ["an issue whose body is too short", [{ ...issue, body: "x" }], /body/],
    ["an issue that names a parent", [{ ...issue, parent: 7 }], /links another issue/],
  ]) {
    const verdict = newCheck(handback({ lines, base: null }), policy);
    assert.equal(verdict.ok, want === null, `${name}: ${JSON.stringify(verdict.errors)}`);
    if (want) assert.match(verdict.errors.join("\n"), want, name);
    else assert.equal(verdict.items.length, lines.length, name);
  }
  const limits = { allowed: ["triage", "blocked"], blocked: ["blocked"] };
  for (const [name, bounds, fields, ok] of [
    ["missing labels", limits, {}, true],
    ["empty labels", limits, { labels: [] }, true],
    ["allowed label ignoring case", limits, { labels: ["TRIAGE"] }, true],
    ["disallowed label", limits, { labels: ["other"] }, false],
    ["blocked takes precedence", limits, { labels: ["BLOCKED"] }, false],
    ["mixed labels", limits, { labels: ["triage", "other"] }, false],
    ["empty allowlist without labels", { allowed: [] }, {}, true],
    ["empty allowlist with empty labels", { allowed: [] }, { labels: [] }, true],
    ["empty allowlist with a label", { allowed: [] }, { labels: ["triage"] }, false],
    ["blocklist only without labels", { blocked: ["blocked"] }, {}, true],
    ["blocklist only with another label", { blocked: ["blocked"] }, { labels: ["other"] }, true],
    ["blocklist only with blocked label", { blocked: ["blocked"] }, { labels: ["BLOCKED"] }, false],
  ]) {
    const bounded = structuredClone(policy);
    bounded.safe_outputs.create_issue = { max: 1, ...bounds };
    const verdict = newCheck(handback({ lines: [{ ...issue, ...fields }], base: null }), bounded);
    assert.equal(verdict.ok, ok, `${name}: ${JSON.stringify(verdict.errors)}`);
    if (!ok) assert.match(verdict.errors.join("\n"), /label limits/, name);
  }
});

test("check: bounded issue actions, through the collector and the check", () => {
  const bounds = join(scratch(), 'allow.toml');
  writeFileSync(bounds, readFileSync(BOUNDS, 'utf8').replace('[outputs]\n',
    '[outputs]\nclose_issue = { max = 1 }\nadd_labels = { max = 1, allowed = ["triage", "blocked"], blocked = ["blocked"] }\n'));
  const result = agenticJob('policy', '--allow', bounds, '--repo', REPO, '--clone-url', `https://github.com/${REPO}`,
    '--base', BASE, '--kind', 'analysis', '--outputs', 'close_issue,add_labels', '--max-outputs', '2');
  assert.equal(result.status, 0, result.stderr);
  const policy = JSON.parse(result.stdout);
  for (const [type, key] of [['close_issue', 'issue_number'], ['add_labels', 'item_number']]) {
    const item = { type, repo: REPO, [key]: 7, ...(type === 'add_labels' ? { labels: ['triage'] } : {}) };
    for (const [name, lines, ok] of [
      ['accepted', [item], true],
      ['another repository', [{ ...item, repo: 'other/repo' }], false],
      ['no repository', [{ ...item, repo: undefined }], false],
      ['no number', [{ ...item, [key]: undefined }], false],
      ['zero number', [{ ...item, [key]: 0 }], false],
      ['over count', [item, item], false],
      ...(type === 'add_labels' ? [
        ['disallowed label', [{ ...item, labels: ['release'] }], false],
        ['blocked label', [{ ...item, labels: ['blocked'] }], false],
        ['label object', [{ ...item, labels: [{ name: 'triage' }] }], false],
      ] : [
        ['duplicate relationship', [{ ...item, duplicate_of: 'other/repo#8' }], false],
      ]),
    ]) {
      const verdict = newCheck(handback({ lines, base: null }), policy);
      assert.equal(verdict.ok, ok, `${type}: ${name}: ${JSON.stringify(verdict.errors)}`);
    }
  }
});

test("check: the hand-backs of two real runs of the old tree", async () => {
  for (const [name, change] of [
    ["create-pull-request", { repo: OWN_REPO, outputs: "create_pull_request,noop,missing_tool" }],
    ["add-comment", { repo: "cgwalters-forge/tracker", workflow: "analysis", outputs: "add_comment,noop,missing_data" }],
  ]) {
    const from = join(SAFE_OUTPUTS, "fixtures", name);
    const read = (file) => JSON.parse(readFileSync(join(from, file), "utf8"));
    const dir = scratch();
    for (const file of read("source.json").files) copyFileSync(join(from, file), join(dir, file));
    // The configuration the old tree compiled for that run, as it was kept.
    assert.deepEqual(bothPolicies(change).now.safe_outputs, read("config.json"), name);
    const verdict = await same(name, dir, null, change);
    assert.equal(verdict.items.length, 1, name);
  }
});

// Where the two differ, on purpose. `git am` applies changes that have no
// `diff --git` line a reader of the text would find: one that the commit
// message carries, and one in a second mail whose body is encoded. The old
// check read only those lines and so passed both (it looked again once the
// patch was applied, on the operator's workstation). The new check is the
// only look before a job with a write token applies the patch, and
// refuses them.
test("check: a change hidden from a reader of the patch is refused, and git would have applied it", async () => {
  const hidden = ".github/workflows/x.yml";
  const bare = `--- /dev/null\n+++ b/${hidden}\n@@ -0,0 +1 @@\n+on: push\n`;
  const encoded = Buffer.from(`diff --git a/${hidden} b/${hidden}\nnew file mode 100755\n${bare}`).toString("base64");
  const mail = `From evil Thu Jan  1 00:00:00 2026\nFrom: x <x@localhost>\nDate: Thu, 1 Jan 2026 00:00:00 +0000\nSubject: injected\nContent-Transfer-Encoding: base64\n\n${encoded}\n`;
  const { was, now } = bothPolicies();
  for (const [name, message, after, want] of [
    ["in the commit message", `Change things\n\n${bare}`, "", /a line of the commit message that git would read as a patch/],
    ["in a second mail", "Change things", mail, /a line after a file's change that is no part of one/],
  ]) {
    const repo = repoWith();
    write(repo.dir, { "src/lib.rs": "fn main() { 1 }\n" });
    const patch = Buffer.concat([buildPatch(repo.git, repo.base, message, 1 << 20).patch, Buffer.from(after)]);
    const dir = handback({ lines: [PR], patch, base: repo.base });

    assert.equal((await old.checkOutputs(dir, was)).ok, true, `${name}: the old check passes it`);
    const verdict = newCheck(dir, now);
    assert.equal(verdict.ok, false, name);
    assert.match(verdict.errors.join("\n"), want, name);

    // A clone at the base, as a job that applies the patch would have.
    const clone = join(scratch(), "clone");
    git(repo.dir, "clone", "-q", repo.dir, clone);
    git(clone, "reset", "-q", "--hard", repo.base);
    git(clone, "-c", "user.name=t", "-c", "user.email=t@localhost", "am", "--quiet", join(dir, old.patchFileName(BRANCH)));
    assert.equal(existsSync(join(clone, hidden)), true, `${name}: git am made the hidden file`);
  }
});

// The same kind of difference, for a file's type. git takes the mode a
// file has when a header states none, so an edit to a link passes a
// reader that judges the type by the mode the header gives.
test("check: an edit to a link whose header leaves its mode out is refused, and git would have applied it", async () => {
  const commit = ["-c", "user.name=t", "-c", "user.email=t@localhost", "commit", "-q", "-m", "A link"];
  const repo = repoWith();
  symlinkSync("src/lib.rs", join(repo.dir, "link"));
  git(repo.dir, "add", "--all");
  git(repo.dir, ...commit);
  const base = spawnSync("git", ["-C", repo.dir, "rev-parse", "HEAD"], { encoding: "utf8" }).stdout.trim();
  rmSync(join(repo.dir, "link"));
  symlinkSync("/etc/passwd", join(repo.dir, "link"));
  const asGitWritesIt = buildPatch(repo.git, base, "Change things", 1 << 20).patch.toString();
  const mode = /^(index [0-9a-f]+\.\.[0-9a-f]+) 120000$/m;
  assert.match(asGitWritesIt, mode);
  const { was, now } = bothPolicies();
  const dir = handback({ lines: [PR], patch: asGitWritesIt.replace(mode, "$1"), base });

  assert.equal((await old.checkOutputs(dir, was)).ok, true, "the old check passes it");
  const verdict = newCheck(dir, now);
  assert.equal(verdict.ok, false);
  assert.match(verdict.errors.join("\n"), /a change to "link" that does not state its mode/);

  const clone = join(scratch(), "clone");
  git(repo.dir, "clone", "-q", repo.dir, clone);
  git(clone, "reset", "-q", "--hard", base);
  git(clone, "-c", "user.name=t", "-c", "user.email=t@localhost", "am", "--quiet", join(dir, old.patchFileName(BRANCH)));
  assert.equal(readlinkSync(join(clone, "link")), "/etc/passwd", "git am pointed the link elsewhere");
});

// What no reader of the text can see. Where a patch does not apply as it
// is, `git am --3way` looks for the file its index line names by content,
// and with rename detection applies the change to another path. Both
// checks pass such a patch. The new one reports the paths it read, so the
// job that applies it can compare them with what changed, and without
// rename detection git does not apply it at all.
test("check: git am --3way can apply a patch to another file than it names, which the reported paths show", async () => {
  const run = (dir, ...args) => spawnSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@localhost", ...args],
    { encoding: "utf8", env: { PATH: process.env.PATH, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" } });
  const repo = repoWith({ "src/lib.rs": "fn main() {}\n", ".envrc": "export WHO=good\n" });
  const blob = run(repo.dir, "rev-parse", "HEAD:.envrc").stdout.trim();
  const named = "docs/notes.txt";
  const patch = [
    `From ${"2".repeat(40)} Mon Sep 17 00:00:00 2001`, `X-GH-AW-Base-Commit: ${repo.base}`,
    "From: agent <agent@localhost>", "Date: Tue, 6 Oct 2026 21:02:35 -0400", "Subject: [PATCH] Change things", "", "---", "",
    `diff --git a/${named} b/${named}`, `index ${blob}..${"2".repeat(40)} 100644`, `--- a/${named}`, `+++ b/${named}`,
    "@@ -1 +1 @@", "-export WHO=good", "+export WHO=evil", "",
  ].join("\n");
  const { was, now } = bothPolicies();
  const dir = handback({ lines: [PR], patch, base: repo.base });
  const file = join(dir, old.patchFileName(BRANCH));

  assert.equal((await old.checkOutputs(dir, was)).ok, true, "the old check passes it");
  const verdict = newCheck(dir, now);
  assert.equal(verdict.ok, true, "and so does the new one");
  assert.deepEqual(verdict.patch.files, [named]);

  const clone = (name) => {
    const to = join(scratch(), name);
    git(repo.dir, "clone", "-q", repo.dir, to);
    git(to, "reset", "-q", "--hard", repo.base);
    return to;
  };
  const followed = clone("followed");
  assert.equal(run(followed, "am", "--quiet", "--3way", file).status, 0, "git am --3way applies it");
  const changed = run(followed, "diff", "--name-only", "--no-renames", repo.base, "HEAD").stdout.trim().split("\n");
  assert.deepEqual(changed, [".envrc"], "to a file the patch does not name");
  assert.notDeepEqual(changed, verdict.patch.files, "which the reported paths show");
  assert.notEqual(run(clone("strict"), "-c", "merge.renames=false", "am", "--quiet", "--3way", file).status, 0, "and without rename detection it does not apply");
});
