"""Strip routes to container root, then audit the final image filesystem."""

import os
import stat
import subprocess
import sys


HELPERS = {
    "/usr/bin/newuidmap": "cap_setuid=ep",
    "/usr/bin/newgidmap": "cap_setgid=ep",
}


def walk_error(error):
    raise error


def files(root_path="/"):
    for root, directories, names in os.walk(root_path, followlinks=False, onerror=walk_error):
        if root == root_path:
            directories[:] = [d for d in directories if d not in {"proc", "sys", "dev"}]
        for name in names:
            path = os.path.join(root, name)
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode):
                yield path, info


def capabilities():
    found = {}
    for path, _ in files():
        if "security.capability" in os.listxattr(path):
            result = subprocess.run(
                ["getcap", path], text=True, capture_output=True, check=True
            )
            name, capability = result.stdout.strip().split(" ", 1)
            found[name] = capability
    return found


def audit():
    privileged = [path for path, info in files() if info.st_mode & 0o6000]
    if privileged:
        raise SystemExit(f"FAIL: setuid/setgid files remain: {privileged}")
    found = capabilities()
    if found != HELPERS:
        raise SystemExit(f"FAIL: unexpected file capabilities: {found}")
    if any(os.path.exists(path) for path in ("/usr/bin/sudo", "/bin/sudo")):
        raise SystemExit("FAIL: sudo remains")
    print("PASS: no setuid/setgid files; only mapping helpers have capabilities")


def main():
    for path, info in files():
        if info.st_mode & 0o6000:
            os.chmod(path, stat.S_IMODE(info.st_mode) & ~0o6000)
    for path in capabilities():
        subprocess.run(["setcap", "-r", path], check=True)
    for path, capability in HELPERS.items():
        subprocess.run(["setcap", capability, path], check=True)
    audit()


if __name__ == "__main__":
    audit() if sys.argv[1:] == ["--audit"] else main()
