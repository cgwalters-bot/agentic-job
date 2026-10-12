import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { REFUSAL, requireSupportedHost, supportedHost } from "./platform.mjs";

test("support is determined by ID and release, not a derivative's ID_LIKE", () => {
  const cases = [
    ["ubuntu", "26.04", true],
    ["ubuntu", "24.04", false],
    ["ubuntu", "22.04", false],
    ["ubuntu", "26.10", false],
    ["ubuntu", "26.04.1", false],
    ["rhel", "10", true],
    ["rhel", "10.0", true],
    ["rhel", "10.2", true],
    ["rhel", "9.6", false],
    ["rhel", "11", false],
    ["rhel", "100", false],
    ["rhel", "10.", false],
    ["centos", "10", false],
    ["rocky", "10", false],
    ["almalinux", "10", false],
    ["fedora", "44", false],
    ["debian", "13", false],
  ];
  for (const [id, version, expected] of cases) {
    for (const quote of ["", '"', "'"]) {
      const text = `# release\nNAME="Example Linux"\nID=${quote}${id}${quote}\nVERSION_ID=${quote}${version}${quote}\nID_LIKE="ubuntu rhel"\n`;
      assert.equal(supportedHost(text), expected, `${id} ${version} ${quote}`);
    }
  }
});

test("missing, ambiguous and shell-expression identity fields fail closed", () => {
  for (const text of [
    "", 'ID=ubuntu\n', 'VERSION_ID="26.04"\n',
    'ID_LIKE=ubuntu\nVERSION_ID="26.04"\n',
    'ID=ubuntu\nID=rhel\nVERSION_ID="26.04"\n',
    'ID=ubuntu\nVERSION_ID="26.04"\nVERSION_ID="24.04"\n',
    'ID="ubuntu\nVERSION_ID="26.04"\n',
    'ID=$(printf ubuntu)\nVERSION_ID="26.04"\n',
    'ID=ubuntu\nVERSION_ID="$VERSION"\n',
  ]) assert.equal(supportedHost(text), false, text);
});

test("file admission has one clear refusal, including an unreadable release", () => {
  const dir = mkdtempSync(join(tmpdir(), "agentic-platform-"));
  const path = join(dir, "os-release");
  try {
    for (const text of ['ID=ubuntu\nVERSION_ID="26.04"\n', 'ID=rhel\nVERSION_ID="10.2"\n']) {
      writeFileSync(path, text);
      assert.doesNotThrow(() => requireSupportedHost(path));
    }
    writeFileSync(path, 'ID=fedora\nVERSION_ID="44"\n');
    for (const refused of [path, dir, join(dir, "missing")]) {
      assert.throws(() => requireSupportedHost(refused), { message: REFUSAL });
    }
    assert.equal(REFUSAL.split("\n").length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the action admits the host before apt, fetching, installing or setup", () => {
  const action = readFileSync(new URL("./action.yml", import.meta.url), "utf8");
  const steps = action.slice(action.indexOf("  steps:\n"));
  assert.match(steps, /^  steps:\n    - name: Check supported host\n/);
  assert.ok(steps.indexOf('node "$ACTION/platform.mjs"') < steps.indexOf('sudo node "$ACTION/apt.mjs"'));
});
