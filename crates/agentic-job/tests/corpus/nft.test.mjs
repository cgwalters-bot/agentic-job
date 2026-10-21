// The network rules and the egress proxy's files against the old tree's.
//
// Except for resolver-scoped proxy DNS and the metadata service's IPv6
// address, the ruleset must be what the old tree's setup-runner-sandbox.mjs
// generates for the same uids, direct endpoints and proxy uid. That script
// cannot be imported (it runs as it loads), so its constants and its two
// functions are cut out of its source and loaded as a module of their
// own. And egress/ here must be
// agent/egress/ there, byte for byte: the proxy was moved, not changed.
// The changes made since are the exceptions, recorded in egress-delta.json
// as text replaced in the old tree's file (#112 lets gh's GraphQL reads
// through, and tests that); any other difference fails. Its pin is
// another: the old tree's requirements.txt, which names mitmproxy alone,
// is requirements.in here, and requirements.txt is generated from it
// with every dependency and the hashes of its files. And the files ADDED
// since, which the old tree has no counterpart of: #116's ecosystem
// identifiers, their generator, and the test through a live proxy.
//
//   OLD_TREE=... AGENTIC_JOB=.../agentic-job node --test nft.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const env = (name) => {
  assert.ok(process.env[name], `${name} must be set; see the top of this file`);
  return resolve(process.env[name]);
};
const OLD_TREE = env("OLD_TREE");
const AGENTIC_JOB = env("AGENTIC_JOB");
const EGRESS = join(dirname(fileURLToPath(import.meta.url)), "../../../../egress");
const PINS = "requirements.txt";
const PINS_SOURCE = "requirements.in";
const ADDED = [PINS_SOURCE, "ecosystem_domains.json", "ecosystems.py", "test_live.py"];
const DELTA = JSON.parse(readFileSync(new URL("egress-delta.json", import.meta.url), "utf8"));

// Intentional security difference: the old tree refuses the sandbox's uids
// the metadata service at its IPv4 address only, so without the proxy an
// IPv6 metadata endpoint (EC2's) stays reachable. The ruleset here refuses
// both, so the old tree's text gets the IPv6 rule next to the IPv4 one.
const METADATA_V4 = "meta skuid @sandbox_uids ip daddr 169.254.169.254 counter reject";
const METADATA_V6 = "meta skuid @sandbox_uids ip6 daddr fd00:ec2::254 counter reject";
const withMetadataV6 = (ruleset) => {
  assert.equal(ruleset.split(METADATA_V4).length, 2, "the old rule must occur once");
  return ruleset.replace(METADATA_V4, `${METADATA_V4}\n    ${METADATA_V6}`);
};

// From the first constant to the end of sandboxRules.
const source = readFileSync(join(OLD_TREE, "scripts/setup-runner-sandbox.mjs"), "utf8");
const start = source.indexOf("const SANDBOX_GROUPS");
const end = source.indexOf("// The environment runner-sandbox's commands get");
assert.ok(start > 0 && end > start, "the old script is not laid out as this test expects");
const module = join(mkdtempSync(join(tmpdir(), "old-rules-")), "rules.mjs");
writeFileSync(module, `import { isIPv4 } from "node:net";\n${source.slice(start, end)}\nexport { sandboxRules, tailnetEndpoint };\n`);
const old = await import(pathToFileURL(module));

const UIDS = ["1002", "165536-231071"];
const BROKER = "http://100.101.102.103:18080/v1";
// uids, direct URLs, the proxy's uid
const CASES = [
  [["1002"], [], undefined],
  [UIDS, [], undefined],
  [UIDS, [BROKER], undefined],
  [UIDS, [], 993],
  [UIDS, [BROKER], 993],
  [UIDS, [BROKER, "https://100.64.0.1", "http://100.127.255.254:8080"], 993],
  [["1002", "165536-231071", "300000-300999"], [BROKER], 61234],
];

for (const [uids, direct, proxy] of CASES) {
  test(`rules for ${uids.length} uid ranges, ${direct.length} direct, proxy ${proxy ?? "none"}`, () => {
    const args = ["sandbox", "nft-rules", ...uids.flatMap((u) => ["--uid", u]), ...direct.flatMap((d) => ["--direct", d]),
      ...(proxy === undefined ? [] : ["--proxy-uid", String(proxy)])];
    const r = spawnSync(AGENTIC_JOB, args, { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    // Intentional security difference: no blanket DNS exception. With no
    // --resolver, even public DNS destinations must be rejected.
    const expected = withMetadataV6(old.sandboxRules(uids, direct.map(old.tailnetEndpoint), proxy))
      .replace(`meta skuid ${proxy} meta l4proto { tcp, udp } th dport 53 accept`,
        `meta skuid ${proxy} meta l4proto { tcp, udp } th dport 53 counter reject`);
    assert.equal(r.stdout, expected);
  });
}

test("proxy DNS exceptions name only supplied resolver literals", () => {
  const args = ["sandbox", "nft-rules", "--uid", "1002", "--proxy-uid", "993",
    "--resolver", "10.0.0.2", "--resolver", "2001:db8::53"];
  const r = spawnSync(AGENTIC_JOB, args, { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const blanket = "meta skuid 993 meta l4proto { tcp, udp } th dport 53 accept";
  const scoped = [
    "meta skuid 993 ip daddr 10.0.0.2 meta l4proto { tcp, udp } th dport 53 accept",
    "meta skuid 993 ip6 daddr 2001:db8::53 meta l4proto { tcp, udp } th dport 53 accept",
    "meta skuid 993 meta l4proto { tcp, udp } th dport 53 counter reject",
  ].join("\n    ");
  const baseline = withMetadataV6(old.sandboxRules(["1002"], [], 993));
  assert.ok(baseline.includes(blanket));
  assert.equal(r.stdout, baseline.replace(blanket, scoped));
  const bad = spawnSync(AGENTIC_JOB, [...args, "--resolver", "10.0.0.2;accept"], { encoding: "utf8" });
  assert.equal(bad.status, 2);
});

test("both refuse what is not a tailnet endpoint", () => {
  for (const url of ["http://10.0.0.1:80", "http://proxy.example:18080", "ftp://100.101.102.103", "http://100.128.0.1"]) {
    assert.throws(() => old.tailnetEndpoint(url), undefined, url);
    const r = spawnSync(AGENTIC_JOB, ["sandbox", "nft-rules", "--uid", "1002", "--direct", url], { encoding: "utf8" });
    assert.equal(r.status, 2, `${url}: ${r.stdout}`);
  }
});

// The old tree's file with each recorded replacement made, each of
// whose old text must occur in it exactly once.
const withDelta = (text, name) => (DELTA[name] ?? []).reduce((text, { old, new: replacement }) => {
  const [from, to] = [old.join("\n"), replacement.join("\n")];
  assert.equal(text.split(from).length, 2, `${name}: the delta's old text must occur once:\n${from}`);
  return text.replace(from, () => to);
}, text);

test("egress/ is the old tree's agent/egress/ plus only the recorded delta", () => {
  const theirs = join(OLD_TREE, "agent/egress");
  const names = readdirSync(theirs).sort();
  assert.deepEqual(readdirSync(EGRESS).filter((name) => !ADDED.includes(name)).sort(), names);
  for (const name of Object.keys(DELTA)) assert.ok(names.includes(name), `${name}: delta for no file`);
  for (const name of names.filter((name) => name !== PINS)) {
    const ours = readFileSync(join(EGRESS, name));
    const expected = withDelta(readFileSync(join(theirs, name), "utf8"), name);
    assert.ok(ours.equals(Buffer.from(expected)), `${name} differs from the old tree's plus the recorded delta`);
  }
  const pinned = (file) => readFileSync(file, "utf8").split("\n").filter((line) => line && !line.startsWith("#"));
  assert.deepEqual(pinned(join(EGRESS, PINS_SOURCE)), pinned(join(theirs, PINS)));
});
