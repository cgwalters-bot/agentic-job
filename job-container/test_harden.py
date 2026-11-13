"""Unprivileged negative tests; never alter this machine's filesystem."""

import stat
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import harden


class AuditTests(unittest.TestCase):
    def test_discovers_real_privileged_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "usr/bin").mkdir(parents=True)
            for name, mode in (("ordinary", 0o755), ("setuid", 0o4755), ("setgid", 0o2755)):
                path = root / "usr/bin" / name
                path.touch()
                path.chmod(mode)
            found = {Path(path).name for path, info in harden.files(directory) if info.st_mode & 0o6000}
            self.assertEqual(found, {"setuid", "setgid"})

    def test_accepts_only_exact_helper_capabilities(self):
        cases = [
            ("clean", 0o755, harden.HELPERS, False, True),
            ("setuid", 0o4755, harden.HELPERS, False, False),
            ("setgid", 0o2755, harden.HELPERS, False, False),
            ("missing helpers", 0o755, {}, False, False),
            ("extra capability", 0o755, {**harden.HELPERS, "/usr/bin/extra": "cap_setuid=ep"}, False, False),
            ("wrong helper", 0o755, {**harden.HELPERS, "/usr/bin/newuidmap": "cap_setuid=eip"}, False, False),
            ("sudo", 0o755, harden.HELPERS, True, False),
        ]
        for name, mode, caps, sudo, accepted in cases:
            with self.subTest(name=name), patch.object(
                harden, "files", return_value=[("/usr/bin/example", SimpleNamespace(st_mode=stat.S_IFREG | mode))]
            ), patch.object(harden, "capabilities", return_value=caps), patch.object(
                harden.os.path, "exists", return_value=sudo
            ):
                if accepted:
                    harden.audit()
                else:
                    with self.assertRaises(SystemExit):
                        harden.audit()


if __name__ == "__main__":
    unittest.main()
