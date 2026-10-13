// `node --test secure-host/binary.test.mjs`: the digest names content, modes and names
// and nothing else, and a file that is not the pinned one is refused.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, renameSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { BUILT_FROM, NAMES, OBJECT, REPOSITORY, TARGET, checked, digest, fetchRelease, readPin } from "./binary.mjs";

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
  return root;
}

test("the digest is of content, modes and names, and of nothing else", () => {
  const changes = [
    ["a file's content", (root) => writeFileSync(join(root, "crates/src/lib.rs"), "// other\n"), true],
    ["a file's name", (root) => renameSync(join(root, "crates/src/lib.rs"), join(root, "crates/src/main.rs")), true],
    ["a new file", (root) => writeFileSync(join(root, "egress/new.py"), ""), true],
    ["the executable bit", (root) => chmodSync(join(root, "crates/src/lib.rs"), 0o755), true],
    ["a link", (root) => symlinkSync("lib.rs", join(root, "crates/src/link.rs")), true],
    ["Cargo.lock", (root) => writeFileSync(join(root, "Cargo.lock"), "changed"), true],
    ["what a release holds", (root) => writeFileSync(join(root, "secure-host/binary.mjs"), "changed"), true],
    ["a file's time", (root) => utimesSync(join(root, "crates/src/lib.rs"), 1, 1), false],
    ["group and other bits", (root) => chmodSync(join(root, "crates/src/lib.rs"), 0o600), false],
    ["an empty directory", (root) => mkdirSync(join(root, "crates/empty")), false],
    ["a file outside the source", (root) => writeFileSync(join(root, "README.md"), "x"), false],
  ];
  for (const [what, change, changes_it] of changes) {
    const root = tree();
    const before = digest(root);
    assert.equal(digest(tree()), before, "two copies of one source differ");
    change(root);
    assert.equal(digest(root) !== before, changes_it, what);
  }
});

test("a link is its target, not what the target holds", () => {
  const [one, other] = [tree(), tree()];
  symlinkSync("lib.rs", join(one, "crates/src/link.rs"));
  symlinkSync("../src/lib.rs", join(other, "crates/src/link.rs"));
  assert.notEqual(digest(one), digest(other));
});

test("a source with a part missing has no digest", () => {
  const root = tree();
  renameSync(join(root, "egress"), join(root, "elsewhere"));
  assert.throws(() => digest(root), /ENOENT/);
});

test("only the pinned bytes are taken", () => {
  const bytes = Buffer.from("the binary");
  const sum = createHash("sha256").update(bytes).digest("hex");
  const pin = { release: "v1", sha256: Object.fromEntries(NAMES.map((name) => [name, sum])) };
  assert.equal(checked(pin, NAMES[0], bytes), bytes);
  assert.throws(() => checked(pin, NAMES[0], Buffer.from("another binary")), /refusing it/);
});

test("a release without checksums does not read", () => {
  const path = join(mkdtempSync(join(tmpdir(), "pin-")), "release.json");
  writeFileSync(path, JSON.stringify({ release: "v1", sha256: { [NAMES[0]]: "0".repeat(64) } }));
  assert.throws(() => readPin(path), /no checksum for/);
  // A release from before the policy object was one of its files.
  writeFileSync(path, JSON.stringify({ release: "v1", sha256: Object.fromEntries(NAMES.map((name) => [name, "0".repeat(64)])) }));
  assert.throws(() => readPin(path), new RegExp(`no checksum for ${OBJECT}`));
});

test("source-addressed releases verify before trusting bytes and fail closed", async () => {
  const source = "a".repeat(64);
  const bytes = Buffer.from("binary");
  const manifest = { repository: REPOSITORY, release: `build-${source}`, target: TARGET, source,
    sha256: Object.fromEntries([...NAMES, OBJECT].map((name) => [name, createHash("sha256").update(bytes).digest("hex")])) };
  const cases = [
    ["valid", {}, false, false, true],
    ["absent", null, false, false, false],
    ["wrong source", { source: "b".repeat(64) }, false, false, /refusing/],
    ["wrong repository", { repository: "other/repo" }, false, false, /refusing/],
    ["wrong target", { target: "other" }, false, false, /refusing/],
    ["wrong tag", { release: "latest" }, false, false, /refusing/],
    ["bad attestation", {}, true, false, /signature/],
    ["bad binary", {}, false, true, /refusing/],
    ["bad object", {}, false, OBJECT, /refusing/],
  ];
  for (const [name, change, badSignature, badBytes, expected] of cases) {
    let verified = false;
    const options = {
      fetchFile: async (url, missing) => {
        assert.ok(url.startsWith(`https://github.com/${REPOSITORY}/releases/download/build-${source}/`));
        if (url.endsWith("release.json")) {
          assert.equal(missing, true);
          return change === null ? null : Buffer.from(JSON.stringify({ ...manifest, ...change }));
        }
        if (url.endsWith("provenance.jsonl")) return Buffer.from("bundle");
        assert.equal(verified, true, "binary downloaded before verification");
        const bad = badBytes === true || (badBytes && url.endsWith(`/${badBytes}`));
        return bad ? Buffer.from("tampered") : bytes;
      },
      verify: (program, args) => {
        assert.equal(program, "gh");
        assert.ok(args.includes("--cert-identity"));
        assert.ok(args.includes(`https://github.com/${REPOSITORY}/.github/workflows/pin.yml@refs/heads/main`));
        assert.ok(args.includes("refs/heads/main"));
        assert.ok(args.includes("--deny-self-hosted-runners"));
        if (badSignature) throw new Error("signature refused");
        verified = true;
      },
    };
    const out = mkdtempSync(join(tmpdir(), "release-"));
    if (expected instanceof RegExp) await assert.rejects(fetchRelease(source, out, options), expected, name);
    else assert.equal(await fetchRelease(source, out, options), expected, name);
    if (expected === true) {
      assert.equal(statSync(join(out, NAMES[0])).mode & 0o777, 0o755);
      assert.equal(statSync(join(out, OBJECT)).mode & 0o777, 0o644);
    }
  }
  for (const failedAsset of ["release.json", "provenance.jsonl", `agentic-job-${TARGET}`, OBJECT]) {
    await assert.rejects(fetchRelease(source, mkdtempSync(join(tmpdir(), "failure-")), {
      fetchFile: async (url) => {
        if (url.endsWith(`/${failedAsset}`)) throw new Error("download failed");
        return url.endsWith("release.json") ? Buffer.from(JSON.stringify(manifest)) : bytes;
      },
      verify: () => {},
    }), /download failed/, failedAsset);
  }
});
