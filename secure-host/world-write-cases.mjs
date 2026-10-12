// Shared by the unprivileged hosted worker and ordinary regression tests.
import assert from "node:assert/strict";
import * as fs from "node:fs";

export function fixtures(path, sticky, owner, uid, io = fs) {
  const directories = [path, `${path}-target`];
  for (const dir of directories) io.mkdirSync(dir, { mode: 0o755 });
  for (const name of ["file", "unlink", "rename"]) {
    const file = `${path}/${name}`;
    io.writeFileSync(file, "fixture");
    if (owner || sticky) io.chownSync(file, uid, io.statSync(file).gid);
    io.chmodSync(file, 0o666);
  }
  const source = `${path}-target/source`;
  io.writeFileSync(source, "fixture");
  io.chownSync(source, uid, io.statSync(source).gid);
  // Populate first: the policy has no root exemption for foreign writable parents.
  for (const dir of directories) {
    // The target is owned by the worker: isolate each rename's tested parent.
    if (owner || dir.endsWith("-target")) io.chownSync(dir, uid, io.statSync(dir).gid);
    io.chmodSync(dir, sticky ? 0o1777 : 0o777);
  }
}

export function exercise(directory, denied) {
  const operations = [
    ["write", () => fs.appendFileSync(`${directory}/file`, "write")],
    ["create", () => fs.writeFileSync(`${directory}/created`, "created")],
    ["unlink", () => fs.unlinkSync(`${directory}/unlink`)],
    ["rename-source", () => fs.renameSync(`${directory}/rename`, `${directory}-target/moved`)],
    ["rename-destination", () => fs.renameSync(`${directory}-target/source`, `${directory}/destination`)],
  ];
  for (const [name, operation] of operations) {
    if (denied) assert.throws(operation, { code: "EACCES" }, `${directory}: ${name}`);
    else operation();
    console.log(`${directory}: ${name} ${denied ? "denied" : "allowed"}`);
  }
}
