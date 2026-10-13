import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { exercise, fixtures } from "./world-write-cases.mjs";

test("fixtures populate parents before exposing them to the no-root-exemption policy", () => {
  for (const [sticky, owner, workerTarget] of [[false, false, true], [true, false, true], [false, true, true], [false, false, false]]) {
    const entries = new Map();
    const io = {
      mkdirSync(path, { mode }) { entries.set(path, { uid: 0, gid: 0, mode }); },
      statSync(path) { return entries.get(path); },
      chownSync(path, uid) { entries.get(path).uid = uid; },
      chmodSync(path, mode) { entries.get(path).mode = mode; },
      writeFileSync(path) {
        const parent = entries.get(path.slice(0, path.lastIndexOf("/")));
        assert.ok(parent.uid === 0 || !(parent.mode & 0o002) || (parent.mode & 0o1000),
          `root fixture creation denied in ${path}`);
        entries.set(path, { uid: 0, gid: 0, mode: 0o644 });
      },
    };
    fixtures("/fixture", sticky, owner, 123, { io, workerTarget });
    for (const dir of ["/fixture", "/fixture-target"]) {
      assert.equal(entries.get(dir).mode, sticky ? 0o1777 : 0o777);
      assert.equal(entries.get(dir).uid, owner || (workerTarget && dir.endsWith("-target")) ? 123 : 0);
    }
    for (const name of ["file", "unlink", "rename"]) {
      assert.equal(entries.get(`/fixture/${name}`).mode, 0o666);
      assert.equal(entries.get(`/fixture/${name}`).uid, owner || sticky ? 123 : 0);
    }
    assert.equal(entries.get("/fixture-target/source").uid, 123);
  }
});

test("allowed matrix exercises both rename parents and entry operations", () => {
  const root = mkdtempSync(join(tmpdir(), "world-write-cases-"));
  const path = `${root}/fixture`;
  try {
    mkdirSync(path);
    mkdirSync(`${path}-target`);
    for (const name of ["file", "unlink", "rename"]) writeFileSync(`${path}/${name}`, "fixture");
    writeFileSync(`${path}-target/source`, "fixture");
    exercise(path, false);
    for (const name of ["file", "created", "destination"]) assert.ok(existsSync(`${path}/${name}`));
    for (const name of ["unlink", "rename"]) assert.equal(existsSync(`${path}/${name}`), false);
    assert.ok(existsSync(`${path}-target/moved`));
    assert.equal(existsSync(`${path}-target/source`), false);
  } finally {
    rmSync(root, { recursive: true });
  }
});

test("a missing fixture is not accepted as a policy denial", () => {
  const root = mkdtempSync(join(tmpdir(), "world-write-cases-"));
  try {
    assert.throws(() => exercise(`${root}/absent`, true), { code: "ERR_ASSERTION" });
    assert.throws(() => exercise(`${root}/absent`, false), { code: "ENOENT" });
  } finally {
    rmSync(root, { recursive: true });
  }
});

test("named denials must each be refused, and only names of operations are accepted", () => {
  const root = mkdtempSync(join(tmpdir(), "world-write-cases-"));
  const path = `${root}/fixture`;
  try {
    fixtures(path, false, true, process.getuid());
    assert.throws(() => exercise(path, ["truncate"]), { code: "ERR_ASSERTION" });
    assert.equal(existsSync(`${path}/created`), false);
    // write is allowed and runs; the unexpectedly allowed create is not a denial.
    assert.throws(() => exercise(path, ["create"]), { code: "ERR_ASSERTION", message: /create/ });
    assert.ok(existsSync(`${path}/created`));
  } finally {
    rmSync(root, { recursive: true });
  }
});

test("staged worker runs without importing anything from the checkout", () => {
  const root = mkdtempSync(join(tmpdir(), "world-write-worker-"));
  try {
    for (const name of ["world-write-host.mjs", "world-write-cases.mjs"]) {
      copyFileSync(new URL(name, import.meta.url), `${root}/${name}`);
    }
    fixtures(`${root}/fixture`, false, true, process.getuid());
    const output = execFileSync(process.execPath,
      [`${root}/world-write-host.mjs`, "worker", `${root}/fixture`, "false"],
      { encoding: "utf8", timeout: 10_000 });
    assert.match(output, /rename-destination allowed/);
  } finally {
    rmSync(root, { recursive: true });
  }
});
