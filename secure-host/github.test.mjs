import assert from "node:assert/strict";
import { test } from "node:test";
import { download, github, prepare } from "./github.mjs";

test("prep installs gh only when missing, including dnf hosts", () => {
  for (const manager of [null, "dnf", "apt-get"]) {
    const installs = [];
    prepare((program, args) => {
      if (program === "sudo") { installs.push(args); return { status: 0 }; }
      return { status: program === (manager ?? "gh") ? 0 : 1 };
    });
    assert.deepEqual(installs, manager ? [[manager, "install", "-y", "gh"]] : []);
  }
  assert.throws(() => prepare(() => ({ status: 1 })), /no supported package manager/);
});

test("gh retries rate-limited 403, not a permission denial", async () => {
  for (const limited of [true, false]) {
    let calls = 0;
    const request = github(["api", "test"], { wait: async () => {},
      run: async () => {
        if (calls++ === 0) throw { stderr: `< HTTP/2.0 403 Forbidden\n${limited ? "< Retry-After: 0\n" : ""}` };
        return { stdout: Buffer.from("ok") };
      } });
    if (limited) assert.equal(String(await request), "ok");
    else await assert.rejects(request, /HTTP 403.*permissions/);
    assert.equal(calls, limited ? 2 : 1);
  }
});

test("release assets come from one REST lookup, then the asset by id", async () => {
  const url = "https://github.com/o/r/releases/download/build-1/release.json";
  const release = JSON.stringify({ assets: [{ name: "other", id: 1 }, { name: "release.json", id: 7 }] });
  for (const [lookup, missing, expected] of [
    [{ stdout: release }, false, "asset"],
    [{ stdout: release }, true, "asset"],
    // An absent release is the lookup's 404, whatever else gh might ask.
    [{ stderr: "< HTTP/2.0 404 Not Found\n" }, true, null],
    [{ stderr: "< HTTP/2.0 404 Not Found\n" }, false, /HTTP 404/],
    [{ stdout: JSON.stringify({ assets: [] }) }, true, null],
    [{ stdout: JSON.stringify({ assets: [] }) }, false, /no asset release\.json/],
  ]) {
    const calls = [];
    const request = download(url, missing, { run: async (program, args) => {
      calls.push(args);
      if (calls.length > 1) return { stdout: Buffer.from("asset") };
      if (lookup.stderr) throw lookup;
      return { stdout: Buffer.from(lookup.stdout) };
    } });
    if (expected instanceof RegExp) await assert.rejects(request, expected);
    else assert.equal(expected === null ? await request : String(await request), expected);
    assert.deepEqual(calls[0], ["api", "repos/o/r/releases/tags/build-1"]);
    if (expected === "asset") assert.deepEqual(calls[1], ["api", "-H", "Accept: application/octet-stream", "repos/o/r/releases/assets/7"]);
    assert.equal(calls.length, expected === "asset" ? 2 : 1);
  }
});

test("retry respects server delays and the two minute budget", async () => {
  for (const [headers, expected] of [
    ["Retry-After: 3", 3000],
    ["X-Ratelimit-Remaining: 0\n< X-Ratelimit-Reset: 5", 5000],
    ["Retry-After: 121", null],
  ]) {
    let clock = 0, calls = 0;
    const waits = [];
    const request = github(["api", "test"], { now: () => clock,
      wait: async ms => { waits.push(ms); clock += ms; },
      run: async () => {
        calls++;
        if (calls === 1 || expected === null) throw { stderr: `< HTTP/2.0 429 Too Many Requests\n< ${headers}\n` };
        return { stdout: Buffer.from("ok") };
      } });
    if (expected === null) await assert.rejects(request, /rate limit.*budget/);
    else assert.equal(String(await request), "ok");
    assert.deepEqual(waits, expected === null ? [] : [expected]);
  }
});

test("retry uses the failed response headers, not a redirect's", async () => {
  let calls = 0;
  const waits = [];
  await github(["api", "test"], { now: () => 0, wait: async ms => waits.push(ms),
    run: async () => {
      if (calls++ === 0) throw { stderr: "< HTTP/2.0 302 Found\n< X-Ratelimit-Remaining: 4999\n< X-Ratelimit-Reset: 1\n< HTTP/2.0 403 Forbidden\n< X-Ratelimit-Remaining: 0\n< X-Ratelimit-Reset: 60\n" };
      return { stdout: Buffer.from("binary") };
    } });
  assert.deepEqual(waits, [60000]);
});
