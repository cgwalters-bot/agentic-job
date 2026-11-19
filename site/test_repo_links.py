import re
import unittest
from urllib.parse import urljoin

from markdown import Markdown
from zensical.extensions.context import ContextExtension, Page

from repo_links import DOCS, PAGES, ROOT, RepositoryLinksExtension, page_path, rewrite

SOURCE = "https://forge.example/o/r/blob/abc/"

# The repository files the site renders.
SOURCES = [*PAGES, *(f"{DOCS}{p.name}" for p in sorted((ROOT / DOCS).glob("*.md")))]


class RepositoryLinksTest(unittest.TestCase):
    def test_rewrite(self):
        for url, page, want in [
            # Between docs pages, with and without a fragment.
            ("sandbox.md", "docs/workflow.md", "sandbox.md"),
            ("sandbox-check.md#network", "docs/sandbox.md", "sandbox-check.md#network"),
            # The overview and the landing page are pages too, copied out
            # of site/ to the root of the docs directory.
            ("../site/overview.md#try-it", "docs/inference.md", "../overview.md#try-it"),
            ("../docs/inference.md", "overview.md", "docs/inference.md"),
            ("../docs/workflow.md", "index.md", "docs/workflow.md"),
            ("index.md", "index.md", "index.md"),
            # Other repository files, Markdown or not, go to the forge.
            ("../README.md", "docs/inference.md", f"{SOURCE}README.md"),
            ("../specs/session.md", "docs/sandbox.md", f"{SOURCE}specs/session.md"),
            ("../crates/agentic-job/src/policy.rs#L10", "docs/layout.md", f"{SOURCE}crates/agentic-job/src/policy.rs#L10"),
            ("../skills/", "docs/skills.md", f"{SOURCE}skills/"),
            ("..", "docs/layout.md", SOURCE),
            ("../docs/examples/a%20b.yml", "overview.md", f"{SOURCE}docs/examples/a%20b.yml"),
            # Kept: external, absolute, fragment-only, and out of the repository.
            ("https://example.com/a.md", "docs/sandbox.md", "https://example.com/a.md"),
            ("mailto:a@example.com", "overview.md", "mailto:a@example.com"),
            ("/docs/x.md", "overview.md", "/docs/x.md"),
            ("#network", "docs/sandbox.md", "#network"),
            ("../../elsewhere.md", "docs/sandbox.md", "../../elsewhere.md"),
        ]:
            with self.subTest(page=page, url=url):
                self.assertEqual(rewrite(url, page, SOURCE), want)

    def test_page_path(self):
        for file, want in [
            ("README.md", None),
            ("site/overview.md", "overview.md"),
            ("site/index.md", "index.md"),
            ("docs/sandbox.md", "docs/sandbox.md"),
            # Only the pages `just site-build` copies.
            ("docs/sub/x.md", None),
            ("docs/plan.txt", None),
            ("specs/session.md", None),
        ]:
            with self.subTest(file=file):
                self.assertEqual(page_path(file), want)

    def test_extension(self):
        md = Markdown(
            extensions=[
                ContextExtension(page=Page(url="docs/harness/", path="docs/harness.md"), config={}),
                RepositoryLinksExtension(source=SOURCE),
            ]
        )
        html = md.convert("[a](sandbox.md#network) [b][o] `[c](x.md)`\n\n[o]: ../site/overview.md\n")
        self.assertEqual(
            html,
            '<p><a href="sandbox.md#network">a</a> <a href="../overview.md">b</a> <code>[c](x.md)</code></p>',
        )

    # The URLs the Astro site served (`just site-test` builds first): each
    # page's route, and the 404 page.
    def test_built_routes(self):
        dist = ROOT / "site/dist"
        for file in SOURCES:
            path = page_path(file)
            route = "" if path == "index.md" else path.removesuffix(".md")
            with self.subTest(file=file):
                self.assertTrue((dist / route / "index.html").is_file(), f"no page at /{route}")
        self.assertTrue((dist / "404.html").is_file())

    def test_built_navigation(self):
        home = (ROOT / "site/dist/index.html").read_text()
        _, primary, sidebar = home.partition('<nav class="md-nav md-nav--primary"')
        self.assertTrue(primary, "no primary navigation on the home page")
        sidebar = sidebar.split('<div class="md-content"', 1)[0]
        routes = [
            urljoin("/", href)
            for href in re.findall(r'<a href="([^"]*)" class="md-nav__link\b', sidebar)
            if not href.startswith("#")  # In-page table of contents.
        ]
        self.assertEqual(routes[:3], ["/", "/docs/try-it/", "/docs/workflow/"])
        docs_routes = [
            f"/{file.removesuffix('.md')}/" for file in SOURCES if file.startswith(DOCS)
        ]
        self.assertCountEqual(routes, ["/", *docs_routes])

    # Python-Markdown ends a list item at a nested list, or a paragraph or
    # code block after a blank line, indented less than 4 spaces; the forge
    # does not, so the site would show such a document's structure
    # differently.
    def test_list_item_blocks_indented_4_spaces(self):
        for file in SOURCES:
            fence = False
            blank = False
            for number, line in enumerate((ROOT / file).read_text().splitlines(), 1):
                shallow = re.match(r" {1,3}\S", line)
                nested_list = re.match(r" {1,3}([-*+]|\d+\.) ", line)
                with self.subTest(file=file, line=number):
                    self.assertFalse(not fence and (blank and shallow or nested_list), line)
                if line.lstrip().startswith(("```", "~~~")):
                    fence = not fence
                blank = not line.strip()

    # And a list item after such a block needs a blank line, or it is
    # rendered as text of the block's paragraph.
    def test_no_list_item_in_built_paragraph(self):
        for page in sorted((ROOT / "site/dist").rglob("*.html")):
            for paragraph in re.findall(r"<p>(.*?)</p>", page.read_text(), re.DOTALL):
                with self.subTest(page=str(page)):
                    self.assertIsNone(re.search(r"\n\s*(\d+\.|[-*+]) ", paragraph), paragraph[:80])

    # The landing page's snippets are copies, not examples of their own:
    # each must stay a fenced block of the host guide, which says what the
    # call needs.
    def test_landing_page_snippets_are_host_guide_blocks(self):
        page = (ROOT / "site/index.md").read_text()
        guide = (ROOT / "docs/secure-host.md").read_text()
        blocks = re.findall(r"^```yaml\n.*?^```$", page, re.MULTILINE | re.DOTALL)
        self.assertTrue(blocks, "no yaml block on the landing page")
        for block in blocks:
            self.assertIn(f"\n{block}\n", guide, "not a host guide block")


if __name__ == "__main__":
    unittest.main()
