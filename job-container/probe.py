"""Hosted runtime assertions: missing prerequisites are failures, not denials."""

import errno
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile


FEDORA = "registry.fedoraproject.org/fedora:44"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)
    print(f"PASS: {message}", flush=True)


def run(*args, **kwargs):
    return subprocess.run(
        args, check=True, text=True, stdout=subprocess.PIPE, timeout=180, **kwargs
    ).stdout


def socket_denied():
    path = "/var/run/docker.sock"
    require(stat.S_ISSOCK(os.stat(path).st_mode), "host Docker socket exists")
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(5)
        try:
            client.connect(path)
        except OSError as error:
            require(error.errno == errno.EACCES, "Docker socket connect fails with EACCES")
        else:
            raise RuntimeError("host Docker socket is accessible")


def identity():
    require(os.getuid() == os.getgid() == 1001, "step UID/GID are 1001")
    require(shutil.which("sudo") is None, "sudo is absent")


def main():
    identity()
    socket_denied()
    run("podman", "unshare", "python3", str(Path(__file__).resolve()), "socket")
    for kind in ("uid", "gid"):
        mapping = run("podman", "unshare", "cat", f"/proc/self/{kind}_map")
        rows = [list(map(int, line.split())) for line in mapping.splitlines()]
        require(rows == [[0, 1001, 1], [1, 100000, 65536]], f"full subordinate {kind} map: {rows}")
    info = json.loads(run("podman", "info", "--format=json"))
    store, host = info["store"], info["host"]
    require(store["graphDriverName"] == "overlay", "Podman uses overlay")
    require(store["graphOptions"].get("overlay.mount_program", {}).get("Executable") == "/usr/bin/fuse-overlayfs", "Podman uses fuse-overlayfs")
    require(store["graphRoot"] == "/home/runner/.local/share/containers/storage", "HOME-independent graph root")
    require(store["runRoot"] == "/tmp/run-user-1001/containers", "HOME-independent run root")
    require(host["cgroupManager"] == "cgroupfs" and host["eventLogger"] == "file" and host["ociRuntime"]["name"] == "crun", "effective Podman engine settings")
    require(run("podman", "run", "--rm", "--cgroups=disabled", FEDORA, "id", "-u").strip() == "0", "Fedora runs in nested rootless Podman")
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, "Containerfile").write_text(
            f"FROM {FEDORA}\nRUN useradd --uid 2000 second && touch /home-proof && chown second:second /home-proof\n"
            "USER second\nRUN test $(id -u) = 2000 && echo second > /home-proof\nCMD [\"cat\", \"/home-proof\"]\n"
        )
        run("podman", "build", "--isolation=chroot", "-t", "localhost/multi-user-probe", directory)
    require(run("podman", "run", "--rm", "--cgroups=disabled", "localhost/multi-user-probe").strip() == "second", "build and run use a second user")
    workspace = Path(os.environ["GITHUB_WORKSPACE"])
    require((workspace / ".git").is_dir(), "actions/checkout populated the workspace")
    with tempfile.TemporaryFile(dir=workspace) as output:
        output.write(b"workspace is writable")
    require(True, "checkout workspace is writable")
    # A nested PID namespace has a PID 1 with no parent visible here. Host
    # runners instead have systemd as PID 1; GitHub starts this image with tail.
    status = Path("/proc/1/status").read_text()
    require("PPid:\t0\n" in status and Path("/proc/1/comm").read_text().strip() == "tail", "PID 1 is the job container's tail, not the host init")
    processes = run("ps", "-eo", "pid,ppid,comm,args")
    print(processes, flush=True)
    require(not any(name in processes for name in ("Runner.Listener", "Runner.Worker", "/usr/bin/dockerd")), "host runner and Docker daemon processes are not visible")


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["socket"]:
            socket_denied()
        elif sys.argv[1:] == ["identity"]:
            identity()
        else:
            main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
