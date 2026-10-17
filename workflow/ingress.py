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
LOCAL_WORKFLOW_IGNORE = re.compile(
    r"uses: (?:\./\.github/workflows/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.yml"
    r"|'\./\.github/workflows/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.yml'"
    r'|"\./\.github/workflows/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.yml")'
    r" +# zizmor: ignore\[self-repository\](?: +[^\r\n]*)?")


def local_step_ignores(text, diagnostics=None):
    """Recognize a conservative block-style subset, not arbitrary YAML syntax."""
    allowed = set()
    parents = []
    # Git's hunk coordinates count LF, not Python/YAML's other line breaks.
    # Refuse other YAML line breaks rather than normalize them.
    def refuse(number, reason):
        if diagnostics is not None:
            diagnostics.append((number, reason))
        return set()

    for number, line in enumerate(text.split("\n"), 1):
        if any(char in line for char in "\r\x85\u2028\u2029"):
            return refuse(number, "non-LF YAML line break")
    # A multiline quoted scalar can contain unindented, YAML-looking text.
    # Do not mistake it for structure. Conservatively require quotes to close
    # on their line; script bodies and plain scalar values are not YAML quotes.
    block_indent = None
    for number, line in enumerate(text.split("\n"), 1):
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if block_indent is not None:
            if not stripped or indent > block_indent:
                continue
            block_indent = None
        if not stripped or stripped.startswith("#"):
            continue
        item = stripped.removeprefix("- ")
        if item.startswith(("'", '"')):
            # Quoted keys can span lines too; do not split at their colons.
            value = item
        else:
            value = re.split(r":(?: +|$)", item, maxsplit=1)[-1].lstrip(" ")
        # Only a value's leading quote opens YAML quoting. Keep properties
        # and flow syntax conservative rather than interpreting arbitrary YAML.
        if re.fullmatch(r"[|>](?:[1-9][+-]?|[+-][1-9]?)? *(?:#.*)?", value):
            block_indent = indent + (2 if stripped.startswith("- ") else 0)
            continue
        if not value.startswith(("'", '"', "!", "&", "[", "{")):
            continue
        unquoted = re.sub(r"'(?:[^']|'')*'|\"(?:[^\"\\]|\\.)*\"", "", value)
        if any(quote in unquoted.split("#", 1)[0] for quote in "'\""):
            return refuse(number, "quoted YAML scalar does not close on its line")
    for number, line in enumerate(text.split("\n"), 1):
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        while parents and parents[-1][0] >= indent:
            parents.pop()
        path = [value for _, value in parents]
        # Keeping every other line as an opaque parent also excludes comments
        # inside block scalars.
        if (not stripped.startswith("- ") and path and
                indent == parents[-1][0] + 2 and re.fullmatch(
                    r"- (?:name|id): [^\s|>'\"!&][^\r\n]*", path[-1])):
            path = path[:-1]
        step = (len(path) == 3 and path[0] == "jobs:" and
                re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*:", path[1]) and
                path[2] == "steps:") or path == ["runs:", "steps:"]
        job = (len(path) == 2 and path[0] == "jobs:" and
               re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*:", path[1]))
        # Workflow calls stay in this repository, just like local action steps.
        # A single filename (and no '..') cannot escape the workflow directory.
        local_job = (job and LOCAL_WORKFLOW_IGNORE.fullmatch(stripped) and
                     ".." not in stripped.split(" #", 1)[0])
        if (step and LOCAL_IGNORE.fullmatch(stripped) or local_job) and len(IGNORE.findall(line)) == 1:
            allowed.add(number)
        parents.append((indent, stripped))
    return allowed


def git(repo, *args):
    return subprocess.run(["git", "--literal-pathspecs", "-C", str(repo), *args], check=True,
                          capture_output=True).stdout


def check_workflows(repo, head, binary, exemptions):
    """Check the complete proposed workflow set, with base-owned policy and code."""
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("head must be a full commit SHA")
    with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP", Path.home())) as temp:
        workflows = Path(temp) / ".github" / "workflows"
        workflows.mkdir(parents=True)
        count = 0
        # Recursive ls-tree does not traverse symlinks or gitlinks. Inspect the
        # ancestors too, so replacing the directory cannot hide workflows.
        entries = git(repo, "ls-tree", "-r", "-t", "-z", head, "--", ".github")
        for entry in entries.split(b"\0"):
            if not entry:
                continue
            metadata, raw_name = entry.split(b"\t", 1)
            mode, kind, oid = metadata.split()
            name = raw_name.decode()
            if name in (".github", ".github/workflows"):
                if kind != b"tree":
                    raise ValueError(f"not a directory: {name!r}")
                continue
            if not re.fullmatch(r"\.github/workflows/[^/]*\.(?i:ya?ml)", name):
                continue
            if mode not in (b"100644", b"100755") or kind != b"blob":
                raise ValueError(f"not a regular workflow file: {name!r}")
            count += 1
            if count > 500:
                raise ValueError("more than 500 workflow files")
            if int(git(repo, "cat-file", "-s", oid.decode())) > 1024 * 1024:
                raise ValueError(f"workflow exceeds 1 MiB: {name!r}")
            (workflows / Path(name).name).write_bytes(git(repo, "cat-file", "blob", oid.decode()))
        result = subprocess.run([str(Path(binary).resolve()), "workflows", "check",
                                 "--root", temp, "--exemptions", str(Path(exemptions).resolve())],
                                capture_output=True)
        # Checker diagnostics contain proposed text; do not emit workflow commands.
        print(json.dumps({"workflows_stdout": result.stdout.decode(errors="replace"),
                          "workflows_stderr": result.stderr.decode(errors="replace")}))
        return result.returncode == 0


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
            # A PR must not silence unrelated findings. Local action steps and
            # local workflow calls still need human review of their code.
            diagnostics = []
            allowed = local_step_ignores(source.read_bytes().decode(errors="replace"), diagnostics)
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
                for number, reason in diagnostics:
                    print(f"Ignore recognition refused in {name!r} at line {number}: {reason}.")
                print(f"New or changed zizmor ignore in {name!r}: only self-repository on a local action step or local workflow call is allowed.")
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
    parser.add_argument("--workflows-binary", type=Path)
    parser.add_argument("--exemptions", type=Path)
    args = parser.parse_args()
    try:
        if bool(args.workflows_binary) != bool(args.exemptions):
            raise ValueError("--workflows-binary and --exemptions must be given together")
        shapes = (check_workflows(args.repo, args.head, args.workflows_binary, args.exemptions)
                  if args.workflows_binary else True)
        raise SystemExit(0 if check(args.repo, args.base, args.head) and shapes else 1)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Ingress failed: {error}\n")
