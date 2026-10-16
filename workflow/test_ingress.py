"""Real analyzer tests: findings are never grandfathered, newly ignored or executed."""

from pathlib import Path
from contextlib import redirect_stdout
import io
import tempfile
import unittest

from ingress import check, git, local_step_ignores


class IngressTests(unittest.TestCase):
    def test_scalar_quotes(self):
        step = "jobs:\n  test:\n    steps:\n      - uses: ./local # zizmor: ignore[self-repository]\n"
        cases = [
            ("name: Open this run's scratch pull request\n", True),
            ('name: A plain "quote\n', True),
            ("run: |\n  printf '%s\\n' 'first\n  second'\n", True),
            ("run: >-\n  a 'quoted\n  body\n", True),
            ("steps:\n  - run: |\n      printf 'first\n      second'\n", True),
            ('name: "real multiline\ncontinued"\n', False),
            ("name: 'real multiline\ncontinued'\n", False),
            ('"multiline:\ncontinued": value\n', False),
            ('run: |\nname: "real multiline\ncontinued"\n', False),
            ('steps:\n  - run: |\n    name: "real multiline\ncontinued"\n', False),
        ]
        for prefix, expected in cases:
            with self.subTest(prefix=prefix):
                diagnostics = []
                allowed = local_step_ignores(prefix + step, diagnostics)
                self.assertEqual(bool(allowed), expected)
                self.assertEqual(bool(diagnostics), not expected)
                if diagnostics:
                    self.assertIn("does not close", diagnostics[0][1])

    def test_local_ignore_syntax(self):
        prefix = "jobs:\n  test:\n    steps:\n"
        cases = [
            ("      - uses: ./local # zizmor: ignore[self-repository]", True),
            ("      - name: Local\n        uses: './local' # zizmor: ignore[self-repository] reason", True),
            ('      - id: local\n        uses: "./local" # zizmor: ignore[self-repository]', True),
            ("      - uses: remote/action@v1 # zizmor: ignore[self-repository]", False),
            ("      - uses: ./local # zizmor: ignore[self-repository, unpinned-uses]", False),
            ("      - uses: ./local # ZIZMOR: ignore[self-repository]", False),
            ("      - uses: ./local # zizmor: ignore[self-repository] # zizmor: ignore[other]", False),
            ("      - run: |\n          uses: ./local # zizmor: ignore[self-repository]", False),
            ("      - name: |\n          uses: ./local # zizmor: ignore[self-repository]\n        run: echo ok", False),
            ("      - name: >\n          uses: ./local # zizmor: ignore[self-repository]\n        run: echo ok", False),
            ("      - name: plain\n          uses: ./local # zizmor: ignore[self-repository]\n        run: echo ok", False),
            ('      - name: "multiline\n        uses: ./local # zizmor: ignore[self-repository]\n        end"\n        run: echo ok', False),
            ("      - uses: ./local\n        # zizmor: ignore[self-repository]", False),
        ]
        for step, expected in cases:
            with self.subTest(step=step):
                self.assertEqual(bool(local_step_ignores(prefix + step)), expected)
        self.assertFalse(local_step_ignores(
            "jobs:\n  test:\n    uses: ./local # zizmor: ignore[self-repository]"))
        self.assertTrue(local_step_ignores(
            "runs:\n  using: composite\n  steps:\n    - uses: ./local # zizmor: ignore[self-repository]"))
        for separator in ("\r", "\r\n", "\x85", "\u2028", "\u2029"):
            with self.subTest(separator=repr(separator)):
                self.assertFalse(local_step_ignores(
                    prefix.replace("\n", separator) + cases[0][0]))
        self.assertFalse(local_step_ignores(
            'name: "multiline\n' + prefix + cases[0][0] + '\nend"\n'))

    def test_local_workflow_ignore_syntax(self):
        cases = [
            ("./.github/workflows/local.yml", True),
            ("'./.github/workflows/local.yml'", True),
            ('"./.github/workflows/local.yml"', True),
            ("remote/repo/.github/workflows/local.yml@main", False),
            ("./.github/workflows/../local.yml", False),
            ("./.github/workflows/sub/local.yml", False),
            ("./.github/workflows/local..yml", False),
            ("./local.yml", False),
            ("./.github/workflows/local.yaml", False),
        ]
        for path, expected in cases:
            with self.subTest(path=path):
                text = f"jobs:\n  test:\n    uses: {path} # zizmor: ignore[self-repository]"
                self.assertEqual(local_step_ignores(text), {3} if expected else set())
        for directive in ("ignore[unpinned-uses]", "ignore[self-repository, unpinned-uses]",
                          "ignore [self-repository]", "ignore[self-repository] # zizmor: ignore[other]"):
            with self.subTest(directive=directive):
                self.assertFalse(local_step_ignores(
                    f"jobs:\n  test:\n    uses: ./.github/workflows/local.yml # zizmor: {directive}"))

    def test_repository_baseline(self):
        """Once a maintainer lands exemptions, ordinary edits pass ingress."""
        root = Path(__file__).resolve().parent.parent
        sources = sorted((root / ".github/workflows").glob("*.yml"))
        sources += sorted(root.glob("*/action.yml"))
        self.assertTrue(sources)
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            repo = Path(temp)
            git(repo, "init", "-q")
            git(repo, "config", "user.name", "Test")
            git(repo, "config", "user.email", "test@example.org")
            for source in sources:
                target = repo / source.relative_to(root)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "maintainer baseline")
            base = git(repo, "rev-parse", "HEAD").decode().strip()
            for source in sources:
                target = repo / source.relative_to(root)
                target.write_bytes(target.read_bytes() + b"\n# ordinary PR edit\n")
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "ordinary edits")
            head = git(repo, "rev-parse", "HEAD").decode().strip()
            self.assertTrue(check(repo, base, head))

    def test_changed_files(self):
        good = ("name: test\non: push\npermissions: {}\njobs:\n  test:\n"
                "    runs-on: ubuntu-24.04\n    steps:\n      - run: echo ok\n")
        bad_action = ("name: local\ndescription: test\nruns:\n  using: composite\n"
                      "  steps:\n    - shell: bash\n      run: echo ${{ github.event.issue.title }}\n")
        ignored = good.replace("- run: echo ok", "- uses: actions/checkout@v4 # zizmor: ignore[unpinned-uses] intentional test\n        with:\n          persist-credentials: false")
        source_context = good.replace(
            "- run: echo ok", "- run: echo $SOURCE\n        env:\n          SOURCE: ${{ job.workflow_repository }}")
        local = good.replace("- run: echo ok", "- name: Local\n        uses: ./local # zizmor: ignore[self-repository] reviewed")
        scalar_ignore = good.replace("- run: echo ok", "- name: |\n          uses: ./local # zizmor: ignore[self-repository]\n        run: echo ok")
        local_workflow = ("name: test\non: push\npermissions: {}\njobs:\n  test:\n"
                          "    uses: ./.github/workflows/local.yml # zizmor: ignore[self-repository]\n")
        # (path, head content, expected[, base content if it differs])
        cases = [
            (".github/workflows/test.yml", good, True),
            (".github/workflows/test.yml", good.replace("echo ok", "echo ${{ github.event.issue.title }}"), False),
            (".github/workflows/test.yml", "jobs: [", False),
            (".github/workflows/test.yml", ignored, True),
            (".github/workflows/test.yml", ignored, False, good),
            (".github/workflows/test.yml", ignored.replace("intentional test", "reworded"), False, ignored),
            (".github/workflows/test.yml", local, True, good),
            (".github/workflows/test.yml", local.replace("name: test", "name: Open this run's scratch pull request"), True, good),
            (".github/workflows/test.yml", local + "      - run: |\n          printf '%s\\n' 'first\n          second'\n", True, good),
            (".github/workflows/test.yml", local.replace("reviewed", "new reason"), True, local),
            (".github/workflows/test.yml", local.replace("- name: Local\n        uses:", "- uses:"), True, good),
            (".github/workflows/test.yml", local.replace("./local", "'./local'"), True, good),
            (".github/workflows/test.yml", local.replace("./local", '"./local"'), True, good),
            (".github/workflows/test.yml", local.replace("./local", "remote/action@" + "a" * 40), False, good),
            (".github/workflows/test.yml", local_workflow, True, good),
            (".github/workflows/test.yml", local_workflow.replace("./.github/workflows/local.yml", "remote/repo/.github/workflows/local.yml@" + "a" * 40), False, good),
            (".github/workflows/test.yml", local_workflow.replace("/local.yml", "/../local.yml"), False, good),
            (".github/workflows/test.yml", local_workflow.replace("self-repository", "unpinned-uses"), False, good),
            (".github/workflows/test.yml", local_workflow.replace("ignore[", "ignore ["), False, good),
            (".github/workflows/test.yml", local.replace("./local", "actions/checkout@v4"), False, good),
            (".github/workflows/test.yml", local.replace("self-repository", "self-repository, unpinned-uses"), False, good),
            (".github/workflows/test.yml", local + "# zizmor: ignore[unpinned-uses]\n", False, good),
            (".github/workflows/test.yml", local.replace("uses: ./local", "uses: ./other"), True, local),
            (".github/workflows/test.yml", local.replace("self-repository", "unpinned-uses"), False, local),
            (".github/workflows/test.yml", scalar_ignore, False, good),
            (".github/workflows/test.yml", 'name: "multiline\njobs:\n  test:\n    steps:\n      - uses: ./local # zizmor: ignore[self-repository]\nend"\n' + good.replace("name: test\n", ""), False, good),
            (".github/workflows/test.yml", "# first\r# second\n" + local + "      - uses: actions/checkout@v4 # zizmor: ignore[unpinned-uses]\n        with:\n          persist-credentials: false\n", False, "# first\r# second\n" + local),
            (".github/workflows/policy.yml", source_context, True),
            (".github/workflows/check.yml", source_context, True),
            (".github/workflows/apply.yml", source_context, True),
            (".github/workflows/test.yml", source_context, False),
            (".github/workflows/policy.yml", source_context.replace("workflow_repository", "workflow_repositroy"), False),
            (".github/workflows/policy.yml", source_context.replace("job.workflow_repository", "job.result"), False),
            (".github/workflows/policy.yml", good.replace("ubuntu-24.04", "ubuntu-nonexistent"), False),
            (".github/workflows/policy.yml", good.replace("echo ok", "echo '::set-output name=bad::value'"), False),
            ("local/action.yml", bad_action, False),
            ("local/action.yml", "name: local\ndescription: test\nruns:\n  using: composite\n  steps:\n    - uses: ./other # zizmor: ignore[self-repository]\n", True, "name: local\ndescription: test\nruns:\n  using: composite\n  steps:\n    - run: echo ok\n      shell: bash\n"),
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
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(check(repo, base, head), expected)
                if 'name: "multiline\n' in content:
                    self.assertIn("at line 1: quoted YAML scalar does not close", output.getvalue())
                if "# first\r" in content:
                    self.assertIn("at line 1: non-LF YAML line break", output.getvalue())
                self.assertFalse((repo / "executed").exists())


if __name__ == "__main__":
    unittest.main()
