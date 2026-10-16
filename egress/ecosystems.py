"""Writes ecosystem_domains.json: gh-aw's ecosystem identifiers (github,
containers, node, python, ...) and the hosts each one names, which an
allowlist policy's `allow` may use in place of the hosts (policy.py). They
are read from gh-aw's pkg/workflow/data/ecosystem_domains.json at the
commit CI checks gh-aw out at, and are taken as gh-aw has them: what
policy.py refuses is refused when a policy names the identifier. Only the
"ecosystems" table is taken; gh-aw's compound identifiers live in its Go
code and are not here.

  python3 egress/ecosystems.py GH_AW_CHECKOUT [--check]

--check writes nothing and fails if ecosystem_domains.json is not what
would be written.
"""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

OUT = Path(__file__).with_name("ecosystem_domains.json")
SOURCE = "pkg/workflow/data/ecosystem_domains.json"
# Without a dot, so that an identifier can never be read as a domain.
IDENTIFIER = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def digest(ecosystems: dict) -> str:
    """The SHA-256 of the identifiers and their hosts, as canonical JSON."""
    text = json.dumps(ecosystems, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode()).hexdigest()


def generate(checkout: Path) -> str:
    raw = (checkout / SOURCE).read_bytes()
    commit = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], check=True,
                            capture_output=True, text=True).stdout.strip()
    ecosystems = json.loads(raw)["ecosystems"]
    if not isinstance(ecosystems, dict) or not ecosystems:
        raise ValueError(f"{SOURCE}: ecosystems is not a table")
    for name, hosts in ecosystems.items():
        if not IDENTIFIER.fullmatch(name):
            raise ValueError(f"{SOURCE}: {name!r} is not an identifier policy.py can tell from a domain")
        if not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) for h in hosts):
            raise ValueError(f"{SOURCE}: {name} is not a list of hosts")
    out = {
        "source": f"https://github.com/github/gh-aw/blob/{commit}/{SOURCE}",
        "commit": commit,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "sha256": digest(ecosystems),
        "ecosystems": dict(sorted(ecosystems.items())),
    }
    return json.dumps(out, indent=2) + "\n"


def main(argv: list) -> int:
    if len(argv) not in (1, 2) or argv[1:] not in ([], ["--check"]):
        print("usage: ecosystems.py GH_AW_CHECKOUT [--check]", file=sys.stderr)
        return 2
    text = generate(Path(argv[0]))
    if argv[1:] != ["--check"]:
        OUT.write_text(text, encoding="utf-8")
    elif OUT.read_text(encoding="utf-8") != text:
        print(f"{OUT} is not what gh-aw at {argv[0]} generates; run ecosystems.py without --check",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
