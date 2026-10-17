"""Exercise the base-owned checker against proposed Git blobs, not a checkout."""

import os
from pathlib import Path
import tempfile
import unittest

from ingress import check_workflows, git


class WorkflowBlobTests(unittest.TestCase):
    def test_proposals(self):
        binary = Path(os.environ.get("WORKFLOWS_BINARY", "target/debug/agentic-job")).resolve()
        self.assertTrue(binary.is_file(), "build agentic-job before running this suite")
        pin = "0123456789abcdef0123456789abcdef01234567"
        good = ("on: push\njobs:\n  test:\n    permissions: {contents: read}\n"
                "    runs-on: ubuntu-24.04\n    steps:\n"
                f"      - uses: cgwalters-forge/agentic-job/secure-host@{pin}\n"
                "      - run: echo good\n")
        cases = [
            ("good.yaml", good, True),
            ("bad.yml", "jobs: {bad: {runs-on: ubuntu-24.04, steps: []}}", False),
            (".yml", "jobs: {bad: {runs-on: ubuntu-24.04, steps: []}}", False),
            (".yaml", "jobs: {bad: {runs-on: ubuntu-24.04, steps: []}}", False),
            ("upper.YML", good, True),
            ("deleted", None, False),
            ("renamed.yml", good, False),
            ("link.yml", "symlink", ValueError),
            ("module.yml", "gitlink", ValueError),
            ("directory-link", "directory-link", ValueError),
            ("unchanged", None, True),
            ("limit", "limit", True),
            ("over-limit", "limit", ValueError),
            ("huge.yml", "#" * (1024 * 1024 + 1), ValueError),
        ]
        for name, content, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                repo = Path(temp)
                git(repo, "init", "-q")
                git(repo, "config", "user.name", "Test")
                git(repo, "config", "user.email", "test@example.org")
                workflows = repo / ".github/workflows"
                workflows.mkdir(parents=True)
                original = workflows / "exempt.yml"
                original.write_text("base exemption")
                exemptions = repo / "base.toml"
                exemptions.write_text('[exempt]\n"exempt.yml" = "base policy"\n')
                git(repo, "add", ".")
                git(repo, "commit", "-qm", "base")
                base = git(repo, "rev-parse", "HEAD").decode().strip()
                if name in ("deleted", "renamed.yml"):
                    original.unlink()
                if content == "directory-link":
                    original.unlink()
                    workflows.rmdir()
                    workflows.symlink_to("elsewhere")
                elif content == "limit":
                    for index in range(499 if name == "limit" else 500):
                        (workflows / f"good-{index}.yml").write_text(good)
                elif content == "gitlink":
                    pass  # Add the index-only gitlink after staging disk files.
                elif content is not None:
                    path = workflows / name
                    if content == "symlink":
                        path.symlink_to("exempt.yml")
                    else:
                        path.write_text(content)
                # A proposed exemption must not silence the bad workflow.
                proposed_policy = repo / ".github/agentic-job/workflows.toml"
                proposed_policy.parent.mkdir()
                proposed_policy.write_text(f'[exempt]\n"{name}" = "proposed bypass"\n')
                git(repo, "add", ".")
                if content == "gitlink":
                    git(repo, "update-index", "--add", "--cacheinfo",
                        f"160000,{base},.github/workflows/{name}")
                git(repo, "commit", "-qm", "head")
                head = git(repo, "rev-parse", "HEAD").decode().strip()
                # Leave the trusted checkout at base, as the real job does.
                git(repo, "checkout", "-q", base)
                if expected is ValueError:
                    with self.assertRaises(ValueError):
                        check_workflows(repo, head, binary, exemptions)
                else:
                    self.assertEqual(check_workflows(repo, head, binary, exemptions), expected)
