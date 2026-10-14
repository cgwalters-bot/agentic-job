"""Run trusted analyzers on changed PR Git blobs, never PR programs."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


# Looser than zizmor's own syntax, so a near miss fails too.
IGNORE = re.compile(r"zizmor\s*:\s*ignore", re.IGNORECASE)
LOCAL_IGNORE = re.compile(
    r"(?:- )?uses: (?:\./[^\s#'\"]+|'\./[^'\r\n]+'|\"\./[^\"\r\n]+\")"
    r" +# zizmor: ignore\[self-repository\](?: +[^\r\n]*)?")


def local_step_ignores(text):
    """Recognize a conservative block-style subset, not arbitrary YAML syntax."""
    allowed = set()
    parents = []
    # Git's hunk coordinates count LF, not Python/YAML's other line breaks.
    # Refuse other YAML line breaks rather than normalize them.
    if any(char in text for char in "\r\x85\u2028\u2029"):
        return allowed
    # A multiline quoted scalar can contain unindented, YAML-looking text.
    # Do not mistake it for structure. Conservatively require quotes to close
    # on their line, even in script bodies; the analyzers handle full YAML.
    for line in text.split("\n"):
        unquoted = re.sub(r"'(?:[^']|'')*'|\"(?:[^\"\\]|\\.)*\"", "", line)
        if any(quote in unquoted.split("#", 1)[0] for quote in "'\""):
            return allowed
    for number, line in enumerate(text.split("\n"), 1):
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        while parents and parents[-1][0] >= indent:
            parents.pop()
        path = [value for _, value in parents]
        # Only steps, never a job's reusable-workflow uses. Keeping every other
        # line as an opaque parent also excludes comments inside block scalars.
        if (not stripped.startswith("- ") and path and
                indent == parents[-1][0] + 2 and re.fullmatch(
                    r"- (?:name|id): [^\s|>'\"!&][^\r\n]*", path[-1])):
            path = path[:-1]
        step = (len(path) == 3 and path[0] == "jobs:" and
                re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*:", path[1]) and
                path[2] == "steps:") or path == ["runs:", "steps:"]
        if step and LOCAL_IGNORE.fullmatch(stripped) and len(IGNORE.findall(line)) == 1:
            allowed.add(number)
        parents.append((indent, stripped))
    return allowed


def git(repo, *args):
    return subprocess.run(["git", "--literal-pathspecs", "-C", str(repo), *args], check=True,
                          capture_output=True).stdout


def check(repo, base, head):
    if not all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in (base, head)):
        raise ValueError("base and head must be full commit SHAs")
    ancestor = git(repo, "merge-base", base, head).decode().strip()
    names = git(repo, "diff", "--no-ext-diff", "--no-renames", "--name-only",
                "-z", ancestor, head, "--").decode().split("\0")
    changed = [name for name in names if name == ".github" or name.startswith(".github/")
               or Path(name).name in ("action.yml", "action.yaml")]
    if not changed:
        return True
    failed = False
    with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP", Path.home())) as temp:
        for name in changed:
            entry = git(repo, "ls-tree", "-z", head, "--", name)
            if not entry:  # Deleted definitions have nothing to lint.
                continue
            mode, kind, oid = entry.split(b"\t", 1)[0].split()
            if mode not in (b"100644", b"100755") or kind != b"blob":
                raise ValueError(f"not a regular file: {name!r}")
            if not (re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", name)
                    or Path(name).name in ("action.yml", "action.yaml")):
                continue
            if int(git(repo, "cat-file", "-s", oid.decode())) > 1024 * 1024:
                raise ValueError(f"workflow/action exceeds 1 MiB: {name!r}")
            source = Path(temp) / Path(name).name
            source.write_bytes(git(repo, "cat-file", "blob", oid.decode()))
            print(f"Checking {name!r}", flush=True)
            # A PR must not silence unrelated findings. Local action steps are
            # the sole exception; their code still needs human review.
            allowed = local_step_ignores(source.read_bytes().decode(errors="replace"))
            patch = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--text", "--no-renames",
                         "-U0", ancestor, head, "--", name).decode(errors="replace")
            new_line = 0
            refused = False
            for line in patch.split("\n"):
                hunk = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
                if hunk:
                    new_line = int(hunk[1])
                elif line.startswith("+") and new_line:
                    refused |= bool(IGNORE.search(line) and new_line not in allowed)
                    new_line += 1
                elif line.startswith(" "):
                    new_line += 1
            if refused:
                print(f"New or changed zizmor ignore in {name!r}: only self-repository on a local action step is allowed.")
                failed = True
            commands = [[os.environ.get("ZIZMOR", "zizmor"), "--offline", "--no-config",
                         "--strict-collection", "--no-progress", str(source)]]
            if name.startswith(".github/workflows/"):
                commands.append([os.environ.get("ACTIONLINT", "actionlint"),
                                 "-config-file", str(Path(__file__).resolve().parents[1] / ".github" / "actionlint.yaml"),
                                 "-shellcheck=", "-pyflakes=", str(source)])
            for command in commands:
                result = subprocess.run(command, cwd=temp, capture_output=True)
                # Quote hostile source text so it cannot become workflow commands.
                print(json.dumps({"file": name, "stdout": result.stdout.decode(errors="replace"),
                                  "stderr": result.stderr.decode(errors="replace")}))
                failed |= result.returncode != 0
            source.unlink()
    return not failed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    parser.add_argument("base")
    parser.add_argument("head")
    args = parser.parse_args()
    try:
        raise SystemExit(0 if check(args.repo, args.base, args.head) else 1)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Ingress failed: {error}\n")
