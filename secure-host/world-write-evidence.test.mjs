import assert from "node:assert/strict";
import { test } from "node:test";
import { evidence } from "./world-write-evidence.mjs";

for (const failure of [null, "before", "world-write.mjs", "after", "build", "install", "-W", "HEAD", "version", "hash"]) {
  test(`evidence fails closed: ${failure ?? "success"}`, () => {
    let summary;
    const calls = [];
    const options = {
      osRelease: "ID=ubuntu\nVERSION_ID=26.04\n",
      run(program, args) {
        calls.push([program, ...args]);
        if (failure && args.some(arg => arg === failure || arg.endsWith(`/${failure}`))) throw new Error("probe failed");
        return "fixture output";
      },
      hash: () => {
        if (failure === "hash") throw new Error("hash failed");
        return "a".repeat(64);
      },
      build(out, run) {
        if (failure === "build") throw new Error("compiler failed");
        run("clang", ["-target", "bpfel", "-o", `${out}/world_write.bpf.o`]);
      },
      publish: text => { summary = text; },
      clock: () => 0,
    };
    if (failure) assert.throws(() => evidence("/tmp/object", options));
    else evidence("/tmp/object", options);
    assert.match(summary, failure ? /FAIL: acceptance incomplete/ : /PASS: all controls passed/);
    if (failure) assert.doesNotMatch(summary, /PASS: all controls passed/);
    if (failure) assert.match(summary, /(?:probe|compiler|hash) failed/);
    if (!failure) {
      assert.match(summary, /world_write.bpf.o/);
      assert.match(summary, /foreign write EACCES, owner write succeeds/);
      assert.ok(calls.some(call => call.includes("after")));
    }
    if (["before", "world-write.mjs", "build"].includes(failure)) {
      assert.ok(!calls.some(call => call.includes("after")));
    }
  });
}

test("RHEL package evidence uses the same controls, without an Ubuntu fallback", () => {
  const calls = [];
  evidence("/tmp/object", {
    osRelease: 'ID="rhel"\nVERSION_ID="10.1"\n',
    run: (program, args) => { calls.push([program, ...args]); return ""; },
    hash: () => "digest", build: () => {}, publish: () => {},
  });
  assert.ok(calls.some(call => call.includes("dnf")));
  assert.ok(calls.some(call => call.includes("rpm")));
  assert.ok(calls.some(call => call.includes("after")));
  assert.ok(!calls.some(call => call.includes("apt-get")));
});

test("unsupported hosts fail before any command or build", () => {
  let summary;
  assert.throws(() => evidence("/tmp/object", {
    osRelease: "ID=ubuntu\nVERSION_ID=24.04\n",
    run: () => assert.fail("must not execute"),
    build: () => assert.fail("must not build"),
    publish: text => { summary = text; },
  }), /requires Ubuntu 26.04 or RHEL 10/);
  assert.match(summary, /Host admission: FAIL/);
});
