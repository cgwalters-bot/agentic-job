import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { NAMES, OBJECT, TARGET } from "./binary.mjs";
import { fetchTagged } from "./tagged.mjs";

test("tagged releases check identity and bytes and fail closed", async () => {
  const repository = "example/tool", commit = "a".repeat(40), source = "b".repeat(64);
  const bytes = Buffer.from("binary");
  const manifest = { repository, commit, source, release: "v1.2.3", target: TARGET,
    sha256: Object.fromEntries([...NAMES, OBJECT].map(name => [name, createHash("sha256").update(bytes).digest("hex")])) };
  for (const bad of [null, "annotated", "absent-ref", "tag", "attestation", "repository", "commit", "source", "release", "target", "sha256", "bytes", "missing"]) {
    const fallback = ["annotated", "absent-ref"].includes(bad);
    const out = mkdtempSync(join(tmpdir(), "tagged-"));
    const verified = [];
    const options = { repository, commit, source, out,
      ref: `${repository}/.github/workflows/policy.yml@refs/tags/v1.2.3`,
      verify: (program, args) => {
        verified.push([program, ...args].join(" "));
        if (bad === "attestation") throw new Error("gh attestation verify ended with status 1");
      },
      fetchFile: async url => {
        if (bad === "missing") throw new Error("download failed");
        if (url.includes("/git/ref/tags/")) return bad === "absent-ref" ? null : JSON.stringify({ object: { type: fallback ? "tag" : "commit", sha: bad === "tag" ? "wrong" : commit } });
        if (url.startsWith("https://api.github.com/")) {
          assert.ok(fallback, "lightweight tags must not need commits API");
          assert.ok(url.endsWith("/commits/v1.2.3"));
          return JSON.stringify({ sha: commit });
        }
        assert.ok(url.startsWith(`https://github.com/${repository}/releases/download/v1.2.3/`));
        if (url.endsWith("release.json")) return JSON.stringify({ ...manifest, ...(bad ? { [bad]: "wrong" } : {}) });
        return bad === "bytes" ? Buffer.from("altered") : bytes;
      } };
    if (bad && !fallback) await assert.rejects(fetchTagged(options), undefined, bad);
    else {
      assert.equal(await fetchTagged(options), true);
      assert.deepEqual(verified, [`gh attestation verify ${join(out, "release.json")} --bundle ${join(out, "provenance.jsonl")} --repo ${repository} --cert-identity https://github.com/${repository}/.github/workflows/release.yml@refs/heads/main --source-ref refs/heads/main --source-digest ${commit} --deny-self-hosted-runners`]);
      for (const name of [...NAMES, OBJECT]) assert.deepEqual(readFileSync(join(out, name)), bytes);
    }
  }
});

test("branches, commit pins and caller refs do not select tagged assets", async () => {
  for (const ref of [undefined, "example/tool/.github/workflows/policy.yml@refs/heads/main",
    `example/tool/.github/workflows/policy.yml@${"a".repeat(40)}`,
    "other/caller/.github/workflows/policy.yml@refs/tags/v1.2.3"]) {
    assert.equal(await fetchTagged({ repository: "example/tool", ref,
      fetchFile: () => assert.fail("must not download") }), false);
  }
});
