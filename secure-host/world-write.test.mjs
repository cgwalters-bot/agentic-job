import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { attach, PIN, PROGRAMS, reportRefusal, rootConfig, runCommand } from "./world-write.mjs";

// Shape emitted by bpftool -j -f link show (not single-link show pinned).
const links = PROGRAMS.map((name, index) => ({
  id: index + 1, type: "tracing", prog_id: index + 10,
  prog_type: "tracing", attach_type: "modify_return",
  target_obj_id: 0, target_btf_id: index + 100,
  pinned: [`${PIN}/links/${name}`],
}));

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
    return JSON.stringify(links);
  });
  assert.deepEqual(calls[0], ["bpftool", ["prog", "loadall", "policy.o", `${PIN}/links`,
    "autoattach", "pinmaps", `${PIN}/maps`]]);
  assert.deepEqual(calls[1], ["bpftool", ["-j", "-f", "link", "show"]]);
  assert.equal(calls[2][1][0], "map");
  assert.equal(calls.length, 3);
});

test("load, each attach/pin inspection, and map initialization failures propagate", () => {
  for (let failed = 0; failed < 3; failed++) {
    let count = 0;
    assert.throws(() => attach("policy.o", 2049n, () => {
      if (count++ === failed) throw new Error("bpftool failure");
      return JSON.stringify(links);
    }), /bpftool failure/);
    assert.equal(count, failed + 1);
  }
  const invalid = [null, {}, [], [...links, links[0]]];
  for (let index = 0; index < links.length; index++) {
    for (const override of [{ type: "program" }, { attach_type: "trace_fentry" },
      { attach_type: undefined }, { pinned: undefined }, { pinned: ["/other/pin"] }]) {
      invalid.push(links.map((link, i) => i === index ? { ...link, ...override } : link));
    }
    invalid.push(links.filter((_, i) => i !== index));
  }
  for (const result of [...invalid.map(value => JSON.stringify(value)), 'invalid json']) {
    let count = 0;
    assert.throws(() => attach("policy.o", 2049n, () => count++ ? result : ""));
    assert.equal(count, 2, "must not enable an unattached program");
  }
});

test("unrelated links do not interfere with exact pin verification", () => {
  attach("policy.o", 2049n, () => JSON.stringify([
    ...links, { type: "cgroup", pinned: ["/unrelated"] },
  ]));
});

test("command failures retain stderr and exit status", () => {
  assert.throws(() => runCommand(process.execPath, ["-e",
    "process.stderr.write('pin lookup failed'); process.exit(23)"]), error => {
    assert.match(error.message, /exit status 23, signal none/);
    assert.match(error.message, /stderr: pin lookup failed/);
    assert.ok(error.message.includes(process.execPath));
    return true;
  });
  assert.equal(runCommand(process.execPath, ["-e", "process.stdout.write('ok')"]), "ok");
});

test("every refusal includes host diagnostics even if bpftool is unavailable", () => {
  for (const unavailable of [false, true]) {
    const messages = [], calls = [];
    reportRefusal(new Error("original failure"), (command, args) => {
      calls.push([command, args]);
      if (command === "bpftool" && unavailable) throw new Error("bpftool missing");
      return command === "bpftool" ? "bpftool v7.6.0\n" : "7.0.0\n";
    }, message => messages.push(message));
    assert.deepEqual(calls, [["bpftool", ["version"]], ["uname", ["-r"]]]);
    assert.equal(messages[0], "world-write setup refused: original failure");
    assert.match(messages[1], unavailable ? /diagnostic failed: bpftool missing/ : /bpftool v7.6.0/);
    assert.equal(messages[2], "uname -r: 7.0.0");
  }
});

test("world-write enforcement feeds the ruleset-required CI aggregate", () => {
  const ci = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  const enforcement = readFileSync(new URL("../.github/workflows/world-write.yml", import.meta.url), "utf8");
  assert.match(enforcement, /on:\n  workflow_call:/);
  assert.match(ci, /merge_group:/);
  const job = ci.split("  world-write:\n")[1].split(/\n  [^ \n]/)[0];
  assert.match(job, /runs-on: ubuntu-26.04\n    timeout-minutes: 10/);
  assert.match(job, /permissions:\n      contents: read/);
  assert.equal(job.split("    steps:\n")[1].trimEnd(),
    enforcement.split("    steps:\n")[1].trimEnd());
  assert.match(ci, /required-checks:[\s\S]*?needs: \[[^\]]*world-write[,\]]/);
  assert.match(ci, /ci:\n    if: \$\{\{ always\(\) \}\}\n    needs: required-checks/);
});

test("action loading is explicitly opt-in and precedes removal of root", () => {
  const action = readFileSync(new URL("./action.yml", import.meta.url), "utf8");
  assert.match(action, /world-write-bpf:[\s\S]*?default: "false"/);
  assert.match(action, /if: \$\{\{ inputs.world-write-bpf == 'true' \}\}/);
  assert.ok(action.indexOf('sudo node "$ACTION/world-write.mjs"') <
    action.indexOf("sudo agentic-job sandbox setup"));
});
