#!/usr/bin/env node
// Gets a source-addressed release using its attested manifest, or builds
// this source when no manifest has been published yet.
//
// What decides that a file is the release's is its checksum in the
// verified, source-matching manifest, and not where it came from:
// one that does not match stops the job, and nothing is built in
// its place. A build is not kept in a cache: a cache is the calling
// repository's, where any workflow on its default branch or on the run's
// own ref can leave an entry for a commit nobody has built yet. A push
// to main that changes the source publishes its release a few minutes
// after the push (pin.yml, which skips a push a newer one overtook): a
// job of a commit off main, of a skipped one, or one that starts in
// those minutes builds, and the build's minutes are the price of taking
// nothing on trust but this repository's attestation.
//
//   binary.mjs get --out DIR [--build]   the binaries, into DIR
//   binary.mjs object --out DIR          the world-write policy object, into DIR
//   binary.mjs digest [--root DIR]       the digest of the source at DIR
//   binary.mjs pin --dist DIR --release TAG [--repository OWNER/NAME]
//                                        release.json for a build of this source
//   binary.mjs verify --dist DIR         DIR holds the pinned release's files
//
// The action and the reusable workflow's policy job both run `get`, the
// workflows that publish a release run `pin`, and tests cover verification: the
// rule is written once. Node's standard library only.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, chmodSync, copyFileSync, lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const HERE = dirname(fileURLToPath(import.meta.url));

// This repository at this file's commit.
export const ROOT = resolve(HERE, "..");

export const REPOSITORY = "cgwalters-forge/agentic-job";

// What the binaries are built from. Whatever the build comes to read from
// elsewhere (an `include_str!` of a file outside these, a toolchain file)
// has to be added, or a job would take a release for its own source when
// it is not; CI's `release-pin` looks for the first of those. This file
// decides what a release holds: a release published before that changed
// lacks a file this one requires, and must not be taken for this source.
// `skills` and `workflow/review.md` are the agents' skills, built in.
export const BUILT_FROM = ["Cargo.lock", "Cargo.toml", "crates", "egress", "skills", "workflow/review.md", "secure-host/binary.mjs"];

// The scripted agent too: a run with `agent: fake` needs it.
export const NAMES = ["agentic-job", "fake-agent"];

// One static binary, so that it runs on whatever the job's runner is.
export const TARGET = "x86_64-unknown-linux-musl";

// The access-time world-write policy, compiled once with the binaries and
// taken by its checksum, so that a host loading it needs no compiler. CO-RE
// relocates it to the running kernel; it is little-endian, as TARGET is.
export const OBJECT = "world_write.bpf.o";
const OBJECT_SOURCE = "crates/agentic-job/bpf/world_write.bpf.c";

const FETCH_TRIES = 3;
const FETCH_TIMEOUT_MS = 120_000;
const OWNER_EXECUTE = 0o100;
const MODE_PROGRAM = 0o755;
const MODE_FILE = 0o644;

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Every file under `path` of `root`, in the order of their names, as
// `KIND SHA256 PATH`: `x` for a program, `f` for another file, `l` for a
// link, whose content is where it points.
function* entries(root, path) {
  const full = join(root, path);
  const stat = lstatSync(full);
  if (stat.isSymbolicLink()) yield `l ${sha256(readlinkSync(full))} ${path}`;
  else if (stat.isFile()) yield `${stat.mode & OWNER_EXECUTE ? "x" : "f"} ${sha256(readFileSync(full))} ${path}`;
  else if (stat.isDirectory()) {
    for (const name of readdirSync(full).sort()) yield* entries(root, `${path}/${name}`);
  } else throw new Error(`${full} is neither a file, a link nor a directory`);
}

// The digest of the source at `root`: of the content, modes and names of
// everything the binaries are built from, and of nothing else. It needs
// no git, so that it is the same in a checkout and in the copy of this
// repository a runner fetches for an action. A file that is not the
// source's (a build's leavings) changes it, and the job then builds.
export function digest(root = ROOT) {
  const hash = createHash("sha256");
  for (const path of BUILT_FROM) for (const line of entries(root, path)) hash.update(`${line}\n`);
  return hash.digest("hex");
}

export function readPin(path) {
  const pin = JSON.parse(readFileSync(path, "utf8"));
  for (const name of [...NAMES, OBJECT]) {
    if (pin.release && !/^[0-9a-f]{64}$/.test(pin.sha256?.[name] ?? "")) throw new Error(`${path} pins ${pin.release} with no checksum for ${name}`);
  }
  return pin;
}

// Throws unless `bytes` are the file the pin names.
export function checked(pin, name, bytes) {
  const found = sha256(bytes);
  if (found !== pin.sha256[name]) throw new Error(`${name} of ${pin.release} has SHA-256 ${found}, and the pin says ${pin.sha256[name]}: refusing it`);
  return bytes;
}

async function download(url, missing = false) {
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
      if (missing && response.status === 404) return null;
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return Buffer.from(await response.arrayBuffer());
    } catch (err) {
      if (attempt === FETCH_TRIES) throw new Error(`fetching ${url}: ${err.message}`);
    }
  }
}

export function validateManifest(pin, source) {
  if (pin.repository !== REPOSITORY || pin.target !== TARGET || pin.source !== source || pin.release !== `build-${source}`) {
    throw new Error("release manifest does not describe this source: refusing it");
  }
}

export async function fetchRelease(source, out, { fetchFile = download, verify = run } = {}) {
  const release = `build-${source}`;
  const from = `https://github.com/${REPOSITORY}/releases/download/${release}`;
  const manifest = await fetchFile(`${from}/release.json`, true);
  if (manifest === null) return false;
  const path = join(out, "release.json");
  const bundle = join(out, "provenance.jsonl");
  writeFileSync(path, manifest);
  writeFileSync(bundle, await fetchFile(`${from}/provenance.jsonl`));
  // Verify before trusting any manifest field. A release editor cannot
  // substitute bytes or attest a manifest from a PR or another workflow.
  verify("gh", ["attestation", "verify", path, "--bundle", bundle,
    "--repo", REPOSITORY, "--cert-identity", `https://github.com/${REPOSITORY}/.github/workflows/pin.yml@refs/heads/main`,
    "--source-ref", "refs/heads/main", "--deny-self-hosted-runners"]);
  const pin = readPin(path);
  validateManifest(pin, source);
  for (const name of NAMES) {
    writeFileSync(join(out, name), checked(pin, name, await fetchFile(`${from}/${name}-${TARGET}`)), { mode: MODE_PROGRAM });
  }
  writeFileSync(join(out, OBJECT), checked(pin, OBJECT, await fetchFile(`${from}/${OBJECT}`)), { mode: MODE_FILE });
  return true;
}

function run(program, args, options = {}) {
  const { status, error } = spawnSync(program, args, { stdio: "inherit", ...options });
  if (error) throw new Error(`running ${program}: ${error.message}`);
  if (status !== 0) throw new Error(`${program} ${args.join(" ")} ended with status ${status}`);
}

const has = (program) => spawnSync("sh", ["-c", `command -v ${program}`], { stdio: "ignore" }).status === 0;

export function compileObject(out, runner = run) {
  mkdirSync(out, { recursive: true });
  runner("clang", ["-O2", "-g", "-target", "bpfel", "-Wall", "-Wextra", "-Werror",
    "-c", join(ROOT, OBJECT_SOURCE), "-o", join(out, OBJECT)]);
}

// musl-gcc is for the C that dependencies bring with them, clang for the
// policy object.
function build(out) {
  const missing = [["musl-gcc", "musl-tools"], ["clang", "clang"]].filter(([program]) => !has(program)).map(([, pkg]) => pkg);
  if (missing.length) {
    if (!has("apt-get")) throw new Error(`a build needs ${missing.join(" and ")}, and this machine has no apt-get to install them with`);
    run("sudo", ["node", join(HERE, "apt.mjs")]);
    run("sudo", ["apt-get", "install", "-y", "--no-install-recommends", ...missing]);
  }
  compileObject(out);
  run("rustup", ["target", "add", TARGET]);
  run("cargo", ["build", "--release", "--locked", "--target", TARGET, "-p", "agentic-job"], { cwd: ROOT });
  for (const name of NAMES) {
    copyFileSync(join(ROOT, "target", TARGET, "release", name), join(out, name));
    chmodSync(join(out, name), MODE_PROGRAM);
  }
}

async function get({ out, build: asked }) {
  if (!out) throw new Error("get: --out DIR is required");
  const source = digest();
  mkdirSync(out, { recursive: true });
  const fetched = !asked && await fetchRelease(source, out);
  if (!fetched) {
    const why = asked
      ? "A build was requested"
      : `No release exists for source ${source} (pin.yml publishes one for each push to main, a few minutes after it; a commit off main has none)`;
    console.log(`::notice::${why}; building from this source, about two minutes`);
    build(out);
  }
  console.log(fetched ? `fetched build-${source} by its attested checksums` : "built from this source");
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `fetched=${fetched}\nsource=${source}\n`);
}

// release.json for the files of `dist`, as a build of this source left them.
function pin({ dist, release, repository }) {
  if (!dist || !release) throw new Error("pin: --dist DIR and --release TAG are required");
  const sums = NAMES.map((name) => [name, sha256(readFileSync(join(dist, `${name}-${TARGET}`)))]);
  sums.push([OBJECT, sha256(readFileSync(join(dist, OBJECT)))]);
  const pinned = { repository: repository || REPOSITORY, release, target: TARGET, source: digest(), sha256: Object.fromEntries(sums) };
  console.log(JSON.stringify(pinned, null, 2));
}

function verify({ dist }) {
  if (!dist) throw new Error("verify: --dist DIR is required");
  const pin = readPin(join(dist, "release.json"));
  for (const name of NAMES) checked(pin, name, readFileSync(join(dist, `${name}-${pin.target}`)));
  checked(pin, OBJECT, readFileSync(join(dist, OBJECT)));
  console.log(`${dist} holds ${pin.release}, by the pinned checksums`);
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      out: { type: "string" },
      build: { type: "boolean" },
      root: { type: "string" },
      dist: { type: "string" },
      release: { type: "string" },
      repository: { type: "string" },
    },
  });
  const object = ({ out }) => {
    if (!out) throw new Error("object: --out DIR is required");
    compileObject(out);
  };
  const commands = { get, pin, verify, object, digest: ({ root }) => console.log(digest(root)) };
  const command = commands[positionals[0]];
  if (!command || positionals.length !== 1) throw new Error(`usage: binary.mjs ${Object.keys(commands).join("|")} [options]`);
  await command(values);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(`error: ${err.message}`);
    process.exit(1);
  });
}
