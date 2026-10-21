import assert from "node:assert/strict";
import { test } from "node:test";
import { firstHeading, headingAnchor, pageId, remarkRepositoryLinks, rewrite } from "./links.mjs";

const opts = { base: "/agentic-job/", source: "https://forge.example/o/r/blob/abc/" };

test("rewrite", () => {
  for (const [url, from, want] of [
    // Between docs pages, with and without a fragment.
    ["sandbox.md", "docs/workflow.md", "/agentic-job/docs/sandbox/"],
    ["sandbox-check.md#network", "docs/sandbox.md", "/agentic-job/docs/sandbox-check/#network"],
    // The README and the landing page are pages too.
    ["../README.md#try-it", "docs/inference.md", "/agentic-job/overview/#try-it"],
    ["docs/inference.md", "README.md", "/agentic-job/docs/inference/"],
    ["../docs/workflow.md", "site/index.mdx", "/agentic-job/docs/workflow/"],
    ["index.mdx", "site/index.mdx", "/agentic-job/"],
    // Other repository files, Markdown or not, go to the forge.
    ["../specs/session.md", "docs/sandbox.md", "https://forge.example/o/r/blob/abc/specs/session.md"],
    [".github/workflows/example.yml", "README.md", "https://forge.example/o/r/blob/abc/.github/workflows/example.yml"],
    ["../crates/agentic-job/src/policy.rs#L10", "docs/layout.md", "https://forge.example/o/r/blob/abc/crates/agentic-job/src/policy.rs#L10"],
    ["../skills/", "docs/skills.md", "https://forge.example/o/r/blob/abc/skills/"],
    ["..", "docs/layout.md", "https://forge.example/o/r/blob/abc/"],
    // Kept: external, absolute, fragment-only, and out of the repository.
    ["https://example.com/a.md", "docs/sandbox.md", "https://example.com/a.md"],
    ["mailto:a@example.com", "README.md", "mailto:a@example.com"],
    ["/docs/x.md", "README.md", "/docs/x.md"],
    ["#network", "docs/sandbox.md", "#network"],
    ["../../elsewhere.md", "docs/sandbox.md", "../../elsewhere.md"],
  ]) {
    assert.equal(rewrite(url, from, opts), want, `${from}: ${url}`);
  }
});

test("pageId", () => {
  assert.equal(pageId("README.md"), "overview");
  assert.equal(pageId("site/index.mdx"), "");
  assert.equal(pageId("docs/sandbox.md"), "docs/sandbox");
  // Only the pages the collection loads.
  assert.equal(pageId("docs/sub/x.md"), null);
  assert.equal(pageId("docs/plan.txt"), null);
  assert.equal(pageId("specs/session.md"), null);
});

test("headingAnchor", () => {
  assert.equal(headingAnchor("Running it on GitHub"), "running-it-on-github");
  assert.equal(headingAnchor("The sandbox: a hardened host, not a container"), "the-sandbox-a-hardened-host-not-a-container");
  assert.equal(headingAnchor("Inference through a proxy"), "inference-through-a-proxy");
  assert.equal(headingAnchor("gh-aw's run_id"), "gh-aws-run_id");
});

test("remarkRepositoryLinks", () => {
  const plugin = remarkRepositoryLinks({ root: "/repo", ...opts });
  const page = () => ({
    children: [
      { type: "heading", depth: 1, children: [{ type: "text", value: "The " }, { type: "inlineCode", value: "run" }, { type: "text", value: " step" }] },
      { type: "paragraph", children: [{ type: "link", url: "sandbox.md#network", children: [] }] },
      { type: "definition", url: "../README.md" },
    ],
  });
  const tree = page();
  plugin(tree, { path: "/repo/docs/harness.md" });
  assert.deepEqual(tree.children[0], { type: "html", value: '<span id="the-run-step"></span>' });
  assert.equal(tree.children[1].children[0].url, "/agentic-job/docs/sandbox/#network");
  assert.equal(tree.children[2].url, "/agentic-job/overview/");
  // A file the site does not render as a page is left alone.
  const other = page();
  plugin(other, { path: "/repo/specs/session.md" });
  assert.deepEqual(other, page());
});

test("firstHeading", () => {
  assert.equal(firstHeading("# The `run` step\n\ntext"), "The run step");
  assert.equal(firstHeading("\n# Title\n"), "Title");
  assert.equal(firstHeading("text\n# Later\n"), null);
  assert.equal(firstHeading("## Second level\n"), null);
});
