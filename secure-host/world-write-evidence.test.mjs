import assert from "node:assert/strict";
import { test } from "node:test";
import { evidence } from "./world-write-evidence.mjs";

for (const failure of [null, "supported", "before", "world-write", "after", "build", "install", "-W", "HEAD", "version", "hash"]) {
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
    if (failure) assert.throws(() => evidence("/tmp/object", "/tmp/agentic-job", options));
    else evidence("/tmp/object", "/tmp/agentic-job", options);
    assert.match(summary, failure ? /FAIL: acceptance incomplete/ : /PASS: all controls passed/);
    if (failure) assert.doesNotMatch(summary, /PASS: all controls passed/);
    if (failure) assert.match(summary, /(?:probe|compiler|hash) failed/);
    if (!failure) {
      assert.match(summary, /world_write.bpf.o/);
      assert.match(summary, /foreign write EACCES, owner write succeeds/);
      assert.ok(calls.some(call => call.includes("after")));
    }
    if (["supported", "before", "world-write", "build"].includes(failure)) {
      assert.ok(!calls.some(call => call.includes("after")));
    }
  });
}

test("RHEL package evidence uses the same controls, without an Ubuntu fallback", () => {
  const calls = [];
  evidence("/tmp/object", "/tmp/agentic-job", {
    osRelease: 'ID="rhel"\nVERSION_ID="10.1"\n',
    run: (program, args) => { calls.push([program, ...args]); return ""; },
    hash: () => "digest", build: () => {}, publish: () => {},
  });
  assert.ok(calls.some(call => call.includes("dnf")));
  assert.ok(calls.some(call => call.includes("rpm")));
  assert.ok(calls.some(call => call.includes("after")));
  assert.ok(!calls.some(call => call.includes("apt-get")));
});

test("an unsupported host fails at admission, before any other command or build", () => {
  let summary;
  const calls = [];
  assert.throws(() => evidence("/tmp/object", "/tmp/agentic-job", {
    osRelease: "ID=ubuntu\nVERSION_ID=24.04\n",
    run: (program, args) => {
      calls.push([program, ...args]);
      throw new Error("secure-host: requires Ubuntu 26.04 or RHEL 10");
    },
    build: () => assert.fail("must not build"),
    publish: text => { summary = text; },
  }), /requires Ubuntu 26.04 or RHEL 10/);
  assert.deepEqual(calls, [["/tmp/agentic-job", "secure-host", "supported"]]);
  assert.match(summary, /Host admission: FAIL/);
});
