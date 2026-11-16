"""Python-Markdown extension: links between repository files, for the site.

The site renders the repository's Markdown, so a link between files keeps
the form that works on the forge (`sandbox.md#anchor`,
`../site/overview.md`). `just site-build` copies the pages into the
docs directory by route; this rewrites each link written relative to a
page's repository path to the copied page it names, which Zensical then
resolves and checks, or to `source` (the prefix of a URL of a repository
file, ending in `/`) for any other repository file.
"""

import posixpath
import re
from pathlib import Path
from urllib.parse import quote, unquote

from markdown import Extension
from markdown.treeprocessors import Treeprocessor
from zensical.extensions.context import ContextPreprocessor

ROOT = Path(__file__).resolve().parent.parent

# Repository files the site renders outside `docs/`, by their path in the
# docs directory; `docs/*.md` keep their own. `just site-build` copies
# these and the two must agree.
PAGES = {
    "site/index.md": "index.md",
    "site/overview.md": "overview.md",
}
DOCS = "docs/"

SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)


def page_path(file):
    """The docs-directory path of repository file `file`, or None."""
    if file in PAGES:
        return PAGES[file]
    name = file.removeprefix(DOCS)
    if name != file and name.endswith(".md") and "/" not in name:
        return file
    return None


def source_file(page):
    """The repository path of the page at docs-directory path `page`."""
    return next((file for file, path in PAGES.items() if path == page), page)


def rewrite(url, page, source):
    """Rewrites `url`, as written in the page at docs-directory path `page`.

    External, absolute and fragment-only links are kept, as is a link out
    of the repository, which this cannot place.
    """
    if SCHEME.match(url) or url.startswith(("/", "#")) or url == "":
        return url
    target, hash_, fragment = url.partition("#")
    fragment = hash_ + fragment
    origin = source_file(page)
    file = posixpath.normpath(posixpath.join(posixpath.dirname(origin), unquote(target)))
    if file == ".." or file.startswith("../"):
        return url
    if file != "." and target.endswith("/"):
        file += "/"
    path = page_path(file)
    if path is not None:
        return posixpath.relpath(path, posixpath.dirname(page) or ".") + fragment
    return source + quote("" if file == "." else file) + fragment


class RepositoryLinks(Treeprocessor):
    def __init__(self, md, source):
        super().__init__(md)
        self.source = source

    def run(self, root):
        context = ContextPreprocessor.from_markdown(self.md)
        if context is None:
            raise RuntimeError("repo_links: no Zensical page context; it runs only under Zensical")
        page = Path(context.page.path).as_posix()
        for link in root.iter("a"):
            href = link.get("href")
            if href is not None:
                link.set("href", rewrite(href, page, self.source))


class RepositoryLinksExtension(Extension):
    def __init__(self, **kwargs):
        self.config = {"source": ["", "Prefix of repository file URLs, ending in /"]}
        super().__init__(**kwargs)

    def extendMarkdown(self, md):
        # Links to files that are not pages go to the forge's view of the
        # built commit when deployed (`just site-build-pages`), and to the
        # checkout itself otherwise, so a local link check also proves
        # those files exist.
        source = self.getConfig("source") or ROOT.as_uri() + "/"
        # After inline links are parsed, before Zensical resolves them.
        md.treeprocessors.register(RepositoryLinks(md, source), "repo_links", 0)


def makeExtension(**kwargs):
    return RepositoryLinksExtension(**kwargs)
