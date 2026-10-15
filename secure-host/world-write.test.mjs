import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { attach, bpftoolInstall, ensureBpftool, PIN, PROGRAMS, reportRefusal, rootConfig, runCommand } from "./world-write.mjs";

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

test("the action always loads the policy, before setup takes root away", () => {
  const action = readFileSync(new URL("./action.yml", import.meta.url), "utf8");
  assert.doesNotMatch(action, /world-write-bpf/);
  const step = action.split("    - name: Load the world-write policy\n")[1].split("\n    - ")[0];
  assert.doesNotMatch(step, /\bif:/);
  assert.match(step, /sudo node "\$ACTION\/world-write.mjs"/);
  const setup = action.indexOf('node "$ACTION/../workflow/setup-timing.mjs" --run setup');
  assert.ok(setup >= 0, "the action must invoke setup through the timing wrapper");
  assert.ok(action.indexOf('sudo node "$ACTION/world-write.mjs"') < setup);
  const timing = readFileSync(new URL("../workflow/setup-timing.mjs", import.meta.url), "utf8");
  assert.match(timing, /\['sudo', \['agentic-job', 'sandbox', 'setup', '--config'/);
});

test("the agent job's prepare installs the object beside the binary secure-host is given", () => {
  const prepare = readFileSync(new URL("../prepare/action.yml", import.meta.url), "utf8");
  assert.match(prepare, /sudo install -m 0644 "\$JOB_DIR\/world_write.bpf.o" \/usr\/local\/bin\/world_write.bpf.o/);
});

// Setup refuses a host without these pins (sandbox/setup.rs), and the
// sandbox probes switch the policy off through its map.
test("setup looks for the pins this loader makes", () => {
  const setup = readFileSync(new URL("../crates/agentic-job/src/sandbox/setup.rs", import.meta.url), "utf8");
  assert.ok(setup.includes(`WORLD_WRITE_PIN: &str = "${PIN}";`));
  const links = /WORLD_WRITE_LINKS: &\[&str\] = &\[([^\]]*)\]/.exec(setup)[1];
  assert.deepEqual([...links.matchAll(/"([a-z_]+)"/g)].map(match => match[1]), PROGRAMS);
});

test("bpftool is installed only where it does not run, from the host's packages", () => {
  const ubuntu = 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="26.04"\n';
  const rhel = 'NAME="Red Hat Enterprise Linux"\nID="rhel"\nVERSION_ID="10.1"\n';
  assert.deepEqual(bpftoolInstall(ubuntu, "7.0.0-1012-azure"), ["apt-get", ["-o", "Acquire::Retries=3",
    "install", "-y", "--no-install-recommends", "linux-tools-common", "linux-tools-7.0.0-1012-azure"]]);
  assert.deepEqual(bpftoolInstall(rhel, "6.12.0-55.el10.x86_64"), ["dnf", ["install", "-y", "bpftool"]]);
  assert.throws(() => bpftoolInstall(ubuntu, "7.0 -x"), /unexpected kernel release/);
  assert.throws(() => bpftoolInstall("ID=fedora\n", "6.12"), /no bpftool package known for fedora/);
  for (const [present, release, expected] of [
    [true, ubuntu, [["bpftool", ["version"]]]],
    [false, ubuntu, [["bpftool", ["version"]], ["uname", ["-r"]], bpftoolInstall(ubuntu, "7.0.0-1012-azure"),
      ["bpftool", ["version"]]]],
    [false, rhel, [["bpftool", ["version"]], ["uname", ["-r"]], ["dnf", ["install", "-y", "bpftool"]],
      ["bpftool", ["version"]]]],
  ]) {
    const calls = [];
    let installed = present;
    ensureBpftool((command, args) => {
      calls.push([command, args]);
      if (command === "bpftool" && !installed) throw new Error("bpftool missing");
      if (command === "apt-get" || command === "dnf") installed = true;
      return command === "uname" ? "7.0.0-1012-azure\n" : "";
    }, release);
    assert.deepEqual(calls, expected);
  }
  // An install that leaves no working bpftool refuses.
  assert.throws(() => ensureBpftool((command) => {
    if (command === "bpftool") throw new Error("bpftool missing");
    return "7.0.0-1012-azure\n";
  }, ubuntu), /bpftool missing/);
});
