"""Run only as container root in disposable CI, after the image is built."""

from pathlib import Path
import subprocess
import tempfile


AUDIT = ["python3", "/usr/local/lib/job-container-harden.py", "--audit"]


def main():
    subprocess.run(AUDIT, check=True, timeout=60)
    with tempfile.TemporaryDirectory() as directory:
        dirty = Path(directory, "dirty")
        dirty.write_text("not executable code\n")
        for name, mode, capability in (
            ("setuid", 0o4755, None),
            ("setgid", 0o2755, None),
            ("extra capability", 0o755, "cap_net_bind_service=ep"),
        ):
            dirty.chmod(mode)
            if capability:
                subprocess.run(["setcap", capability, str(dirty)], check=True, timeout=5)
            result = subprocess.run(AUDIT, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 or "FAIL:" not in result.stderr:
                raise RuntimeError(f"FAIL: audit did not reject actual {name}: {result}")
            print(f"PASS: actual {name} rejected", flush=True)
        dirty.unlink()
    subprocess.run(AUDIT, check=True, timeout=60)


if __name__ == "__main__":
    main()
