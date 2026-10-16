// `node --test secure-host/binary.test.mjs`: the digest names content, modes and names
// and nothing else, and a file that is not the pinned one is refused. binary.sh
// runs in a copy of a small source tree, with the fetch helper, gh and build tools
// replaced by stubs that serve fixture files and log what they were asked.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import "./github.test.mjs";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "binary.sh");
const BUILT_FROM = readFileSync(SCRIPT, "utf8").match(/^BUILT_FROM=\(([^)]*)\)$/m)[1].split(" ");
const REPOSITORY = "cgwalters-forge/agentic-job";
const TARGET = "x86_64-unknown-linux-musl";
const NAMES = ["agentic-job", "fake-agent"];
const OBJECT = "world_write.bpf.o";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const STUBS = {
  gh: `echo "gh $*" >> "$STUB_LOG"; [ ! -e "$STUB_FILES/gh-fail" ] || { echo "signature refused" >&2; exit 1; }`,
  clang: `echo "clang $*" >> "$STUB_LOG"; while [ "$1" != -o ]; do shift; done; echo object > "$2"`,
  "musl-gcc": "exit 0",
  rustup: `echo "rustup $*" >> "$STUB_LOG"`,
  cargo: `echo "cargo $*" >> "$STUB_LOG"; mkdir -p target/${TARGET}/release
for name in ${NAMES.join(" ")}; do echo built > target/${TARGET}/release/$name; done`,
  sudo: `echo "sudo $*" >> "$STUB_LOG"`,
};

function stubs() {
  const bin = mkdtempSync(join(tmpdir(), "stubs-"));
  for (const [name, body] of Object.entries(STUBS)) {
    writeFileSync(join(bin, name), `#!/bin/bash\n${body}\n`);
    chmodSync(join(bin, name), 0o755);
  }
  return bin;
}
const BIN = stubs();

// A source with every part of BUILT_FROM, and this binary.sh in it.
function tree() {
  const root = mkdtempSync(join(tmpdir(), "source-"));
  for (const name of BUILT_FROM) {
    if (name.includes(".")) {
      mkdirSync(dirname(join(root, name)), { recursive: true });
      writeFileSync(join(root, name), name);
    } else {
      mkdirSync(join(root, name, "src"), { recursive: true });
      writeFileSync(join(root, name, "src", "lib.rs"), "// lib\n");
    }
  }
  copyFileSync(SCRIPT, join(root, "secure-host/binary.sh"));
  // The helper's gh transport/retry cases run above; this boundary supplies
  // bytes and the helper's distinct missing-resource exit status.
  writeFileSync(join(root, "secure-host/github.mjs"), `
import { appendFileSync, existsSync, readFileSync } from "node:fs";
const [, , command, url, missing] = process.argv;
if (command !== "download") process.exit(1);
appendFileSync(process.env.STUB_LOG, "fetch " + url + "\\n");
const root = process.env.STUB_FILES;
const path = root + "/" + url.replace(/^https:\\/\\//, "");
const fail = existsSync(root + "/fail") && url.endsWith("/" + readFileSync(root + "/fail", "utf8"));
if (fail) process.exit(1);
if (!existsSync(path)) process.exit(missing === "missing" ? 2 : 1);
process.stdout.write(readFileSync(path));
`);
  return root;
}

function run(root, args, { env = {}, files = {}, fail, ghFail = false, script = join(root, "secure-host/binary.sh") } = {}) {
  const served = mkdtempSync(join(tmpdir(), "served-"));
  for (const [url, bytes] of Object.entries(files)) {
    const path = join(served, url.replace(/^https:\/\//, ""));
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, bytes);
  }
  if (fail) writeFileSync(join(served, "fail"), fail);
  if (ghFail) writeFileSync(join(served, "gh-fail"), "");
  const log = join(served, "log");
  writeFileSync(log, "");
  const output = join(served, "output");
  const clean = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("WORKFLOW_")));
  const result = spawnSync("bash", [script, ...args], {
    encoding: "utf8",
    env: { ...clean, PATH: `${BIN}:${process.env.PATH}`, STUB_FILES: served, STUB_LOG: log, GITHUB_OUTPUT: output, ...env },
  });
  return { ...result, log: readFileSync(log, "utf8").trim().split("\n").filter(Boolean),
    output: existsSync(output) ? readFileSync(output, "utf8") : "" };
}

// By this checkout's binary.sh, which a change to the tree's copy leaves as it is.
const digest = (root) => {
  const { status, stdout, stderr } = run(root, ["digest", "--root", root], { script: SCRIPT });
  assert.equal(status, 0, stderr);
  return stdout.trim();
};

test("the digest is of content, modes and names, and of nothing else", () => {
  const changes = [
    ["a file's content", (root) => writeFileSync(join(root, "crates/src/lib.rs"), "// other\n"), true],
    ["a file's name", (root) => renameSync(join(root, "crates/src/lib.rs"), join(root, "crates/src/main.rs")), true],
    ["a new file", (root) => writeFileSync(join(root, "egress/new.py"), ""), true],
    ["a dotfile", (root) => writeFileSync(join(root, "egress/.new"), ""), true],
    ["the executable bit", (root) => chmodSync(join(root, "crates/src/lib.rs"), 0o755), true],
    ["a link", (root) => symlinkSync("lib.rs", join(root, "crates/src/link.rs")), true],
    ["Cargo.lock", (root) => writeFileSync(join(root, "Cargo.lock"), "changed"), true],
    ["what a release holds", (root) => writeFileSync(join(root, "secure-host/binary.sh"), "changed"), true],
    ["a file's time", (root) => utimesSync(join(root, "crates/src/lib.rs"), 1, 1), false],
    ["group and other bits", (root) => chmodSync(join(root, "crates/src/lib.rs"), 0o600), false],
    ["an empty directory", (root) => mkdirSync(join(root, "crates/empty")), false],
    ["a file outside the source", (root) => writeFileSync(join(root, "README.md"), "x"), false],
  ];
  for (const [what, change, changes_it] of changes) {
    const root = tree();
    const before = digest(root);
    assert.match(before, /^[0-9a-f]{64}$/);
    assert.equal(digest(tree()), before, "two copies of one source differ");
    change(root);
    assert.equal(digest(root) !== before, changes_it, what);
  }
});

// Each line `KIND SHA256 PATH`, a directory's names in byte order, depth
// first: `a/b` before `a.c`, though `.` sorts before `/`.
test("the digest is of the listing binary.sh documents", () => {
  const root = tree();
  mkdirSync(join(root, "crates/a"));
  writeFileSync(join(root, "crates/a/b"), "b");
  writeFileSync(join(root, "crates/a.c"), "c");
  chmodSync(join(root, "crates/a.c"), 0o755);
  symlinkSync("../x", join(root, "egress/l"));
  const file = (path) => sha256(readFileSync(join(root, path)));
  const listing = [
    `f ${file("Cargo.lock")} Cargo.lock`, `f ${file("Cargo.toml")} Cargo.toml`,
    `f ${file("crates/a/b")} crates/a/b`, `x ${file("crates/a.c")} crates/a.c`, `f ${file("crates/src/lib.rs")} crates/src/lib.rs`,
    `l ${sha256("../x")} egress/l`, `f ${file("egress/src/lib.rs")} egress/src/lib.rs`,
    `f ${file("skills/src/lib.rs")} skills/src/lib.rs`, `f ${file("workflow/review.md")} workflow/review.md`,
    `f ${file("secure-host/binary.sh")} secure-host/binary.sh`,
    `f ${file("secure-host/github.mjs")} secure-host/github.mjs`,
  ];
  assert.deepEqual(BUILT_FROM, ["Cargo.lock", "Cargo.toml", "crates", "egress", "skills", "workflow/review.md", "secure-host/binary.sh", "secure-host/github.mjs"]);
  assert.equal(digest(root), sha256(listing.map((line) => `${line}\n`).join("")));
});

test("a link is its target, not what the target holds", () => {
  const [one, other] = [tree(), tree()];
  symlinkSync("lib.rs", join(one, "crates/src/link.rs"));
  symlinkSync("../src/lib.rs", join(other, "crates/src/link.rs"));
  assert.notEqual(digest(one), digest(other));
});

test("a link's target is all of it, and a name with a newline has no digest", () => {
  const [one, other] = [tree(), tree()];
  symlinkSync("lib.rs", join(one, "crates/src/link.rs"));
  symlinkSync("lib.rs\n", join(other, "crates/src/link.rs"));
  assert.notEqual(digest(one), digest(other));
  const root = tree();
  writeFileSync(join(root, "crates/src/lib.rs\n"), "// lib\n");
  const { status, stderr } = run(root, ["digest", "--root", root], { script: SCRIPT });
  assert.equal(status, 1);
  assert.match(stderr, /has a newline in its name/);
});

test("a source with a part missing has no digest", () => {
  const root = tree();
  renameSync(join(root, "egress"), join(root, "elsewhere"));
  const { status, stdout, stderr } = run(root, ["digest", "--root", root]);
  assert.equal(status, 1);
  assert.equal(stdout, "");
  assert.match(stderr, /egress is neither a file, a link nor a directory/);
});

const BYTES = "binary";
const checksums = () => Object.fromEntries([...NAMES, OBJECT].map((name) => [name, sha256(BYTES)]));
const assets = (from, change = () => BYTES) => Object.fromEntries([...NAMES.map((name) => `${name}-${TARGET}`), OBJECT]
  .map((asset) => [`${from}/${asset}`, change(asset)]));

// What `get` left in OUT, and that every file there is the release's.
function fetched(out) {
  for (const name of NAMES) assert.equal(statSync(join(out, name)).mode & 0o777, 0o755);
  assert.equal(statSync(join(out, OBJECT)).mode & 0o777, 0o644);
  for (const name of [...NAMES, OBJECT]) assert.equal(readFileSync(join(out, name), "utf8"), BYTES);
}

test("source-addressed releases verify before trusting bytes and fail closed", () => {
  const root = tree();
  const source = digest(root);
  const from = `https://github.com/${REPOSITORY}/releases/download/build-${source}`;
  const manifest = { repository: REPOSITORY, release: `build-${source}`, target: TARGET, source, sha256: checksums() };
  const verify = `gh attestation verify OUT/release.json --bundle OUT/provenance.jsonl --repo ${REPOSITORY} --cert-identity https://github.com/${REPOSITORY}/.github/workflows/pin.yml@refs/heads/main --source-ref refs/heads/main --deny-self-hosted-runners`;
  const cases = [
    ["valid", {}, {}, 0],
    ["absent", null, {}, 0],
    ["wrong source", { source: "b".repeat(64) }, {}, /refusing it/],
    ["wrong repository", { repository: "other/repo" }, {}, /refusing it/],
    ["wrong target", { target: "other" }, {}, /refusing it/],
    ["wrong tag", { release: "latest" }, {}, /refusing it/],
    ["no checksum for the object", { sha256: Object.fromEntries(NAMES.map((name) => [name, sha256(BYTES)])) }, {}, /no checksum for world_write\.bpf\.o/],
    ["a short checksum", { sha256: { ...checksums(), "fake-agent": "0" } }, {}, /no checksum for fake-agent/],
    ["not JSON", "{", {}, /refusing it/],
    ["bad attestation", {}, { ghFail: true }, /signature refused/],
    ["bad binary", {}, { bad: `agentic-job-${TARGET}` }, /agentic-job of build-[0-9a-f]+ has SHA-256 [0-9a-f]{64}, and the pin says [0-9a-f]{64}: refusing it/],
    ["bad object", {}, { bad: OBJECT }, /world_write\.bpf\.o of .* refusing it/],
    ...["release.json", "provenance.jsonl", `agentic-job-${TARGET}`, OBJECT].map((asset) => [`${asset} cannot be fetched`, {}, { fail: asset }, /error: fetching https:\/\/.*: GitHub request failed/]),
  ];
  for (const [name, change, { ghFail, bad, fail }, expected] of cases) {
    const out = join(mkdtempSync(join(tmpdir(), "release-")), "bin");
    const files = change === null ? {} : {
      [`${from}/release.json`]: typeof change === "string" ? change : JSON.stringify({ ...manifest, ...change }),
      [`${from}/provenance.jsonl`]: "bundle",
      ...assets(from, (asset) => asset === bad ? "tampered" : BYTES),
    };
    const result = run(root, ["get", "--out", out], { files, fail, ghFail });
    if (expected instanceof RegExp) {
      assert.equal(result.status, 1, name);
      assert.match(result.stderr, expected, name);
      assert.equal(result.output, "", name);
      assert.ok(!result.log.some((line) => line.startsWith("cargo")), `${name}: built in place of a refused release`);
    } else assert.equal(result.status, 0, `${name}: ${result.stderr}`);
    // Nothing but the manifest and its bundle before the attestation.
    const at = result.log.findIndex((line) => line.startsWith("gh "));
    if (at >= 0) {
      assert.equal(result.log[at].replaceAll(out, "OUT"), verify, name);
      assert.deepEqual(result.log.slice(0, at), [`fetch ${from}/release.json`, `fetch ${from}/provenance.jsonl`], name);
    }
    if (name === "valid") {
      fetched(out);
      assert.equal(result.output, `fetched=true\nsource=${source}\n`);
      assert.match(result.stdout, new RegExp(`fetched build-${source} by its attested checksums`));
    }
    if (name === "absent") {
      assert.equal(at, -1);
      assert.match(result.stdout, /::notice::No release exists for source/);
      assert.equal(result.output, `fetched=false\nsource=${source}\n`);
      assert.ok(result.log.includes(`cargo build --release --locked --target ${TARGET} -p agentic-job`));
      for (const name of NAMES) assert.equal(statSync(join(out, name)).mode & 0o777, 0o755);
    }
  }
});

test("a requested build fetches nothing, and installs only the compilers missing", () => {
  const root = tree();
  const out = join(mkdtempSync(join(tmpdir(), "build-")), "bin");
  const result = run(root, ["get", "--out", out, "--build"]);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(!result.log.some((line) => line.startsWith("fetch") || line.startsWith("gh") || line.startsWith("sudo")), result.log.join("\n"));
  assert.deepEqual(result.log, [
    `clang -O2 -g -target bpfel -Wall -Wextra -Werror -c ${root}/crates/agentic-job/bpf/world_write.bpf.c -o ${out}/${OBJECT}`,
    `rustup target add ${TARGET}`,
    `cargo build --release --locked --target ${TARGET} -p agentic-job`,
  ]);
  assert.match(result.stdout, /::notice::A build was requested/);
  assert.match(result.output, /^fetched=false\n/);
  for (const name of NAMES) assert.equal(readFileSync(join(out, name), "utf8"), "built\n");
  assert.equal(readFileSync(join(out, OBJECT), "utf8"), "object\n");
});

test("tagged releases check identity and bytes and fail closed", () => {
  const root = tree();
  const source = digest(root);
  const repository = "example/tool", commit = "a".repeat(40);
  const from = `https://github.com/${repository}/releases/download/v1.2.3`;
  const env = { WORKFLOW_REPOSITORY: repository, WORKFLOW_SHA: commit,
    WORKFLOW_IDENTITY: JSON.stringify({ workflow_ref: `${repository}/.github/workflows/policy.yml@refs/tags/v1.2.3`, other: 1 }) };
  const manifest = { repository, commit, source, release: "v1.2.3", target: TARGET, sha256: checksums() };
  for (const bad of [null, "annotated", "absent-ref", "tag", "attestation", "repository", "commit", "source", "release", "target", "sha256", "bytes", "missing", "identity"]) {
    const out = join(mkdtempSync(join(tmpdir(), "tagged-")), "bin");
    const files = {
      ...(bad === "absent-ref" ? {} : { [`https://api.github.com/repos/${repository}/git/ref/tags/v1.2.3`]: JSON.stringify({ object: { type: bad === "annotated" ? "tag" : "commit", sha: bad === "tag" ? "b".repeat(40) : commit } }) }),
      [`https://api.github.com/repos/${repository}/commits/v1.2.3`]: JSON.stringify({ sha: bad === "tag" ? "b".repeat(40) : commit }),
      [`${from}/release.json`]: JSON.stringify({ ...manifest, ...(bad ? { [bad]: "wrong" } : {}) }),
      [`${from}/provenance.jsonl`]: "bundle",
      ...assets(from, () => bad === "bytes" ? "altered" : BYTES),
    };
    const result = run(root, ["get", "--out", out], {
      files, ghFail: bad === "attestation", fail: bad === "missing" ? "release.json" : undefined,
      env: bad === "identity" ? { ...env, WORKFLOW_SHA: "main" } : env,
    });
    if (bad && !["annotated", "absent-ref"].includes(bad)) {
      assert.equal(result.status, 1, bad);
      assert.ok(!result.log.some((line) => line.startsWith("cargo") || line.includes(`/${REPOSITORY}/`)), `${bad}: ${result.log.join("\n")}`);
      continue;
    }
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.log.some((line) => line.includes("/commits/v1.2.3")), ["annotated", "absent-ref"].includes(bad));
    assert.deepEqual(result.log.filter((line) => line.startsWith("gh ")), [`gh attestation verify ${out}/release.json --bundle ${out}/provenance.jsonl --repo ${repository} --cert-identity https://github.com/${repository}/.github/workflows/release.yml@refs/heads/main --source-ref refs/heads/main --source-digest ${commit} --deny-self-hosted-runners`]);
    fetched(out);
    assert.match(result.stdout, /fetched tagged release by its attested checksums/);
    assert.equal(result.output, `fetched=true\nsource=${source}\n`);
  }
});

test("branches, commit pins and caller refs do not select tagged assets", () => {
  const root = tree();
  for (const ref of [undefined, "example/tool/.github/workflows/policy.yml@refs/heads/main",
    `example/tool/.github/workflows/policy.yml@${"a".repeat(40)}`,
    "other/caller/.github/workflows/policy.yml@refs/tags/v1.2.3"]) {
    const out = join(mkdtempSync(join(tmpdir(), "untagged-")), "bin");
    const result = run(root, ["get", "--out", out], { env: { WORKFLOW_REPOSITORY: "example/tool", WORKFLOW_SHA: "a".repeat(40),
      WORKFLOW_IDENTITY: JSON.stringify(ref === undefined ? {} : { workflow_ref: ref }) } });
    assert.equal(result.status, 0, result.stderr);
    assert.ok(!result.log.some((line) => line.includes("example/tool")), String(ref));
    assert.match(result.stdout, /built from this source/);
  }
});

test("the manifest binds the source digest to the checksums of the build", () => {
  const root = tree();
  const dist = mkdtempSync(join(tmpdir(), "dist-"));
  for (const name of NAMES) writeFileSync(join(dist, `${name}-${TARGET}`), name);
  writeFileSync(join(dist, OBJECT), OBJECT);
  const pinned = run(root, ["pin", "--dist", dist, "--release", "build-x", "--repository", "example/tool"], { env: { GITHUB_SHA: "c".repeat(40) } });
  assert.equal(pinned.status, 0, pinned.stderr);
  assert.deepEqual(JSON.parse(pinned.stdout), { repository: "example/tool", release: "build-x", target: TARGET, source: digest(root),
    commit: "c".repeat(40), sha256: Object.fromEntries([...NAMES, OBJECT].map((name) => [name, sha256(name)])) });
  const local = run(root, ["pin", "--dist", dist, "--release", "build-x"], { env: { GITHUB_SHA: "" } });
  assert.equal(JSON.parse(local.stdout).repository, REPOSITORY);
  assert.equal(JSON.parse(local.stdout).commit, undefined);
  const missing = mkdtempSync(join(tmpdir(), "dist-"));
  const refused = run(root, ["pin", "--dist", missing, "--release", "build-x"]);
  assert.equal(refused.status, 1);
  assert.equal(refused.stdout, "");
});

test("an unknown command or argument is refused", () => {
  const root = tree();
  for (const args of [[], ["verify"], ["get", "--out"], ["get", "--outdir", "x"], ["object"]]) {
    const result = run(root, args);
    assert.equal(result.status, 1, args.join(" "));
    assert.match(result.stderr, /^error: /, args.join(" "));
  }
});
