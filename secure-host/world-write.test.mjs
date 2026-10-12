import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { attach, PIN, PROGRAMS, rootConfig } from "./world-write.mjs";

test("convert Linux stat device encoding to kernel dev_t and enable atomically", () => {
  for (const [major, minor] of [[0n, 0n], [8n, 1n], [259n, 65537n], [4095n, 1048575n]]) {
    const dev = (minor & 255n) | ((major & 4095n) << 8n) |
      ((minor & ~255n) << 12n) | ((major & ~4095n) << 32n);
    for (const order of ["LE", "BE"]) {
      const bytes = Buffer.from(rootConfig(dev, order).map(byte => parseInt(byte, 16)));
      const read = order === "LE" ? bytes.readUInt32LE.bind(bytes) : bytes.readUInt32BE.bind(bytes);
      assert.equal(read(0), Number((major << 20n) | minor));
      assert.equal(read(4), 1);
    }
  }
  assert.throws(() => rootConfig(1n << 44n), /exceeds/);
  assert.throws(() => rootConfig(1n << 32n), /exceeds/);
});

test("all four autoattached link pins are verified before map activation", () => {
  const calls = [];
  attach("policy.o", 2049n, (command, args) => {
    calls.push([command, args]);
    return '{"type":"tracing","attach_type":"modify_return"}';
  });
  assert.deepEqual(calls[0], ["bpftool", ["prog", "loadall", "policy.o", `${PIN}/links`,
    "autoattach", "pinmaps", `${PIN}/maps`]]);
  assert.deepEqual(calls.slice(1, 5).map(call => call[1].at(-1)), PROGRAMS.map(name => `${PIN}/links/${name}`));
  assert.equal(calls[5][1][0], "map");
  assert.equal(calls.length, 6);
});

test("load, each attach/pin inspection, and map initialization failures propagate", () => {
  for (let failed = 0; failed < 6; failed++) {
    let count = 0;
    assert.throws(() => attach("policy.o", 2049n, () => {
      if (count++ === failed) throw new Error("bpftool failure");
      return '{"type":"tracing","attach_type":"modify_return"}';
    }), /bpftool failure/);
    assert.equal(count, failed + 1);
  }
  for (const result of ['{"type":"program"}', '{}', 'invalid json',
    '{"type":"tracing"}', '{"type":"tracing","attach_type":"trace_fentry"}']) {
    let count = 0;
    assert.throws(() => attach("policy.o", 2049n, () => count++ ? result : ""));
    assert.equal(count, 2, "must not enable an unattached program");
  }
});

test("action loading is explicitly opt-in and precedes removal of root", () => {
  const action = readFileSync(new URL("./action.yml", import.meta.url), "utf8");
  assert.match(action, /world-write-bpf:[\s\S]*?default: "false"/);
  assert.match(action, /if: \$\{\{ inputs.world-write-bpf == 'true' \}\}/);
  assert.ok(action.indexOf('sudo node "$ACTION/world-write.mjs"') <
    action.indexOf("sudo agentic-job sandbox setup"));
});
