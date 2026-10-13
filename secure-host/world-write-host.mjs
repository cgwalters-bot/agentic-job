// Fresh hosted runner only. Separate invocations prove the links outlive loading.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, chownSync, copyFileSync, mkdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { exercise, fixtures } from "./world-write-cases.mjs";

if (process.argv[2] === "worker") {
  assert.notEqual(process.getuid(), 0);
  const denied = process.argv[4];
  exercise(process.argv[3], denied === "true" || (denied !== "false" && denied.split(",")));
  process.exit(0);
}

const run = (command, args) => execFileSync(command, args, { stdio: "inherit", timeout: 120_000 });

const directory = "/world-write-ci";
const foreign = `${directory}/foreign`;
const owned = `${directory}/owned`;
const uid = Number(execFileSync("id", ["-u", "nobody"], { encoding: "utf8" }).trim());
assert.ok(uid > 0);
const mount = `${directory}/tmpfs`;
// A container's root: an overlay whose layers are on the root filesystem,
// mounted by root, as rootful Podman's storage is. Overlayfs creates the
// upper entry with the caller's fsuid (its creator credentials), so the policy
// refuses a create in a foreign world-writable upper parent; unlink and rename
// run with the mounter's (root's) credentials and are allowed.
const overlay = `${directory}/overlay`;
const layers = `${directory}/layers`;
const cases = [
  [`${directory}/nonsticky`, true, false, false],
  [`${directory}/sticky`, false, true, false],
  [`${directory}/owner`, false, false, true],
  [`${mount}/foreign`, false, false, false],
  [`${overlay}/foreign`, ["create"], false, false],
];
if (process.argv[2] === "before") {
  mkdirSync(directory, { mode: 0o755 });
  // Hosted checkout ancestors need not be searchable by nobody. Keep the worker
  // and its shared operations in a root-owned, searchable location instead.
  for (const name of ["world-write-host.mjs", "world-write-cases.mjs"]) {
    copyFileSync(new URL(name, import.meta.url), `${directory}/${name}`);
    chmodSync(`${directory}/${name}`, 0o644);
  }
  assert.equal(statSync(directory).dev, statSync("/").dev);
  for (const path of [foreign, owned]) {
    writeFileSync(path, "fixture");
    chmodSync(path, 0o666);
  }
  chownSync(owned, uid, statSync(owned).gid);
  mkdirSync(mount);
  run("mount", ["-t", "tmpfs", "-o", "size=1m", "tmpfs", mount]);
  assert.notEqual(statSync(mount).dev, statSync("/").dev);
  for (const layer of ["lower", "upper", "work"]) mkdirSync(`${layers}/${layer}`, { recursive: true, mode: 0o755 });
  mkdirSync(overlay);
  run("mount", ["-t", "overlay", "-o",
    `lowerdir=${layers}/lower,upperdir=${layers}/upper,workdir=${layers}/work`, "overlay", overlay]);
  assert.notEqual(statSync(overlay).dev, statSync("/").dev);
  assert.equal(statSync(`${layers}/upper`).dev, statSync("/").dev);
} else {
  assert.equal(process.argv[2], "after");
}
const denied = process.argv[2] === "after";
for (const [path, expected] of [[foreign, denied], [owned, false]]) {
  execFileSync("runuser", ["-u", "nobody", "--", process.execPath, "-e",
    `const assert = require('node:assert/strict'); const fs = require('node:fs');
     if (process.argv[2] === 'true') assert.throws(() => fs.appendFileSync(process.argv[1], 'write'), {code: 'EACCES'});
     else fs.appendFileSync(process.argv[1], 'write');`, path, String(expected)], { stdio: "inherit", timeout: 120_000 });
}
for (const [path, policyDenies, sticky, owner] of cases) {
  if (!path.startsWith(mount)) assert.equal(statSync(directory).dev, statSync("/").dev);
  fixtures(path, sticky, owner, uid, { workerTarget: !path.startsWith(overlay) });
  run("runuser", ["-u", "nobody", "--", process.execPath, `${directory}/world-write-host.mjs`,
    "worker", path, String(denied && policyDenies)]);
  // Root has no policy exemption either. Close worker-owned parents before
  // privileged fixture cleanup, rather than accidentally testing a root bypass.
  chmodSync(path, 0o755);
  chmodSync(`${path}-target`, 0o755);
  rmSync(path, { recursive: true });
  rmSync(`${path}-target`, { recursive: true });
}
if (denied) {
  run("umount", [mount]);
  run("umount", [overlay]);
  rmSync(directory, { recursive: true });
}
console.log(`world-write ${process.argv[2]}: foreign write ${denied ? "denied" : "allowed"}; owner write allowed`);
