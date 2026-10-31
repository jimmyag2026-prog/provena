"""Enforce the package layering from docs/ARCHITECTURE.md §6.1."""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "provena"

ALLOWED = {
    "core": set(),
    "store": {"core"},
    "client": {"core"},
    "sdk": {"core", "store", "client"},
    "adapters": {"core", "store", "client", "sdk"},
    "cli": {"core", "store", "client", "sdk", "server", "adapters"},
    "server": {"core"},
}


def _provena_imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        elif isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        else:
            continue
        for name in names:
            parts = name.split(".")
            if parts[0] == "provena" and len(parts) > 1 and parts[1] in ALLOWED:
                found.add(parts[1])
    return found


def test_layering():
    violations = []
    for sub, allowed in ALLOWED.items():
        for f in (SRC / sub).rglob("*.py"):
            bad = _provena_imports(f) - allowed - {sub}
            if bad:
                violations.append(f"{f.relative_to(SRC)} imports {sorted(bad)}")
    assert not violations, violations


def test_version_single_source():
    import provena
    from provena._version import __version__

    assert provena.__version__ == __version__
