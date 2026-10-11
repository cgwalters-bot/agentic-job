"""Real analyzer tests: findings are never grandfathered, newly ignored or executed."""

from pathlib import Path
import tempfile
import unittest

from ingress import check, git


class IngressTests(unittest.TestCase):
    def test_changed_files(self):
        good = ("name: test\non: push\npermissions: {}\njobs:\n  test:\n"
                "    runs-on: ubuntu-24.04\n    steps:\n      - run: echo ok\n")
        bad_action = ("name: local\ndescription: test\nruns:\n  using: composite\n"
                      "  steps:\n    - shell: bash\n      run: echo ${{ github.event.issue.title }}\n")
        ignored = good.replace("- run: echo ok", "- uses: actions/checkout@v4 # zizmor: ignore[unpinned-uses] intentional test\n        with:\n          persist-credentials: false")
        # (path, head content, expected[, base content if it differs])
        cases = [
            (".github/workflows/test.yml", good, True),
            (".github/workflows/test.yml", good.replace("echo ok", "echo ${{ github.event.issue.title }}"), False),
            (".github/workflows/test.yml", "jobs: [", False),
            (".github/workflows/test.yml", ignored, True),
            (".github/workflows/test.yml", ignored, False, good),
            (".github/workflows/test.yml", ignored.replace("intentional test", "reworded"), False, ignored),
            ("local/action.yml", bad_action, False),
            (":(literal)local/action.yml", bad_action, False),
            (".github/unrelated.yml", "not a workflow", True),
            ("unrelated.yml", "not a workflow", True),
        ]
        for name, content, expected, *base in cases:
            with self.subTest(name=name, content=content), tempfile.TemporaryDirectory(dir=Path.home()) as temp:
                repo = Path(temp)
                content = content.replace("echo ok", f"touch {repo}/executed")
                git(repo, "init", "-q")
                git(repo, "config", "user.name", "Test")
                git(repo, "config", "user.email", "test@example.org")
                source = repo / name
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(base[0] if base else content)
                git(repo, "add", ".")
                git(repo, "commit", "-qm", "base")
                base = git(repo, "rev-parse", "HEAD").decode().strip()
                # An existing finding still fails after an unrelated comment edit.
                source.write_text(content + "# changed\n")
                git(repo, "add", ".")
                git(repo, "commit", "-qm", "head")
                head = git(repo, "rev-parse", "HEAD").decode().strip()
                self.assertEqual(check(repo, base, head), expected)
                self.assertFalse((repo / "executed").exists())


if __name__ == "__main__":
    unittest.main()
