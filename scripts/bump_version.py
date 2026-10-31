"""Prepare a release: bump the single version source and date the changelog section.

    uv run python scripts/bump_version.py 0.1.0        # or: patch | minor | major

It edits src/provena/_version.py and moves `## [Unreleased]` in CHANGELOG.md to
`## [X.Y.Z] - YYYY-MM-DD` (keeping an empty Unreleased section). It never commits, tags or
pushes: review the diff, open the release PR, and tag on main after it is merged
(`git tag vX.Y.Z && git push origin vX.Y.Z`) — releasing is a deliberate human step.
"""

import datetime as dt
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "src" / "provena" / "_version.py"
CHANGELOG = ROOT / "CHANGELOG.md"


def current() -> tuple[int, int, int]:
    m = re.search(r'__version__ = "(\d+)\.(\d+)\.(\d+)"', VERSION_FILE.read_text())
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


def target(arg: str) -> str:
    major, minor, patch = current()
    bumps = {"major": (major + 1, 0, 0), "minor": (major, minor + 1, 0),
             "patch": (major, minor, patch + 1)}
    if arg in bumps:
        return ".".join(map(str, bumps[arg]))
    if not re.fullmatch(r"\d+\.\d+\.\d+", arg):
        raise SystemExit("usage: bump_version.py X.Y.Z | major | minor | patch")
    if tuple(map(int, arg.split("."))) <= current():
        raise SystemExit(f"{arg} is not newer than {'.'.join(map(str, current()))}")
    return arg


def main() -> None:
    new = target(sys.argv[1] if len(sys.argv) > 1 else "")
    text = CHANGELOG.read_text()
    if "## [Unreleased]" not in text:
        raise SystemExit("CHANGELOG.md has no [Unreleased] section")
    today = dt.date.today().isoformat()
    CHANGELOG.write_text(text.replace("## [Unreleased]",
                                      f"## [Unreleased]\n\n## [{new}] - {today}", 1))
    VERSION_FILE.write_text(f'__version__ = "{new}"\n')
    print(f"version {new}; CHANGELOG section dated {today}. Next: review, PR, merge, then tag "
          f"v{new} on main (needs the maintainer's go-ahead).")


if __name__ == "__main__":
    main()
