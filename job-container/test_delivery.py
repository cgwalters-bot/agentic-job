"""Exercise the publisher's actual jq predicates with stale/hostile metadata."""

import copy
import json
from pathlib import Path
import re
import subprocess
import unittest


WORKFLOW = Path(__file__).with_name("workflow.yml")


class DeliveryTests(unittest.TestCase):
    def test_metadata_binding(self):
        filters = re.findall(r"^\s+jq -e .* '([^']+)' ", WORKFLOW.read_text(), re.MULTILINE)
        self.assertEqual(len(filters), 2)
        variables = {"sha": "reviewed-head", "repo": "example-org/example", "attempt": 2}
        run = {
            "event": "push", "head_branch": "main", "head_sha": variables["sha"],
            "repository": {"full_name": variables["repo"]}, "run_attempt": 2,
            "path": ".github/workflows/job-container.yml",
        }
        self.check_filter(filters[0], run, variables, [
            ("event", "pull_request"), ("head_branch", "other"),
            ("head_sha", "stale"), ("run_attempt", 1),
            ("path", ".github/workflows/other.yml"),
            ("repository", {"full_name": "other-org/example"}),
        ])
        variables = {
            "name": "job-container-123-2", "sha": "reviewed-head",
            "digest": "sha256:archive-digest", "id": 456, "run": 123, "repo": 789,
        }
        artifact = {
            "id": 456, "name": variables["name"], "expired": False,
            "size_in_bytes": 100, "digest": variables["digest"],
            "workflow_run": {"id": 123, "head_sha": variables["sha"],
                             "repository_id": 789, "head_repository_id": 789},
        }
        self.check_filter(filters[1], artifact, variables, [
            ("id", 457), ("name", "job-container-123-1"), ("expired", True),
            ("size_in_bytes", 0), ("size_in_bytes", 2147483649),
            ("digest", "sha256:substituted"), ("workflow_run", None),
            *(("workflow_run", {**artifact["workflow_run"], key: value})
              for key, value in (("id", 124), ("head_sha", "stale"),
                                 ("repository_id", 790), ("head_repository_id", 790))),
        ])
        self.assertTrue(self.accepts(filters[1], {**artifact, "size_in_bytes": 2147483648}, variables))

    def accepts(self, program, data, variables):
        args = ["jq", "-e"]
        for name, value in variables.items():
            args.extend(["--argjson", name, json.dumps(value)])
        return subprocess.run(
            [*args, program], input=json.dumps(data), text=True,
            capture_output=True, timeout=5,
        ).returncode == 0

    def check_filter(self, program, valid, variables, invalid):
        self.assertTrue(self.accepts(program, valid, variables))
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(valid)
                changed[key] = value
                self.assertFalse(self.accepts(program, changed, variables))
        for key in valid:
            with self.subTest(missing=key):
                changed = copy.deepcopy(valid)
                del changed[key]
                self.assertFalse(self.accepts(program, changed, variables))


if __name__ == "__main__":
    unittest.main()
