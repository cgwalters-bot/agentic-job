import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const read = (file) => readFile(new URL(file, import.meta.url), "utf8");

// The landing page's snippets are copies, not examples of their own: each
// must stay a fenced block of the README, which says what the call needs.
test("landing page snippets are README blocks", async () => {
  const [page, readme] = await Promise.all([read("index.mdx"), read("../README.md")]);
  const blocks = [...page.matchAll(/^```yaml\n[\s\S]*?^```$/gm)].map((m) => m[0]);
  assert.ok(blocks.length > 0, "no yaml block on the landing page");
  for (const block of blocks) {
    assert.ok(readme.includes(`\n${block}\n`), `not a README block:\n${block}`);
  }
});
