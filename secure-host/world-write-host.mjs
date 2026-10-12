// Fresh hosted runner only. Separate invocations prove the links outlive loading.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, chownSync, mkdirSync, rmdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";

const directory = "/world-write-ci";
const foreign = `${directory}/foreign`;
const owned = `${directory}/owned`;
const uid = Number(execFileSync("id", ["-u", "nobody"], { encoding: "utf8" }).trim());
assert.ok(uid > 0);
if (process.argv[2] === "before") {
  mkdirSync(directory, { mode: 0o755 });
  assert.equal(statSync(directory).dev, statSync("/").dev);
  for (const path of [foreign, owned]) {
    writeFileSync(path, "fixture");
    chmodSync(path, 0o666);
  }
  chownSync(owned, uid, statSync(owned).gid);
} else {
  assert.equal(process.argv[2], "after");
}
const denied = process.argv[2] === "after";
for (const [path, expected] of [[foreign, denied], [owned, false]]) {
  execFileSync("runuser", ["-u", "nobody", "--", process.execPath, "-e",
    `const assert = require('node:assert/strict'); const fs = require('node:fs');
     if (process.argv[2] === 'true') assert.throws(() => fs.appendFileSync(process.argv[1], 'write'), {code: 'EACCES'});
     else fs.appendFileSync(process.argv[1], 'write');`, path, String(expected)], { stdio: "inherit" });
}
if (denied) {
  for (const path of [foreign, owned]) unlinkSync(path);
  rmdirSync(directory);
}
console.log(`world-write ${process.argv[2]}: foreign write ${denied ? "denied" : "allowed"}; owner write allowed`);
