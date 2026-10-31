"""Machine output for `provena --json` (docs/spec/cli-contract-v1.md).

In JSON mode every human line goes to stderr and stdout carries one envelope; commands add
their structured result with `data(...)` and warnings with `warn(...)`.
"""

from __future__ import annotations

import json
import sys

SCHEMA = "provena-cli/1"

_state = {"json": False, "lines": False, "out": None, "data": {}, "warnings": [],
          "error": None}

# exit code -> default error code
DEFAULT_ERRORS = {1: "E_VERIFY", 2: "E_USAGE", 3: "E_NETWORK", 4: "E_PASSPHRASE",
                  5: "E_INCOMPLETE", 6: "E_CORRUPT", 7: "E_VOID", 130: "E_INTERRUPTED"}


def start(json_mode: bool, lines: bool = False, out=None) -> None:
    _state.update(json=json_mode or lines, lines=lines, out=out, data={}, warnings=[],
                  error=None)


def item(record: dict) -> None:
    """With --json-lines: one line per completed item, as soon as it is recorded (a killed
    batch leaves exactly the lines of what is on the ledger)."""
    if _state["lines"] and _state["out"] is not None:
        _state["out"].write(json.dumps(record, sort_keys=True, default=str) + "\n")
        _state["out"].flush()


def json_mode() -> bool:
    return _state["json"]


def data(**fields) -> None:
    """Add fields to this command's result (complete identifiers only)."""
    _state["data"].update(fields)


def error(code: str, message: str, hint: str | None = None) -> None:
    """The error of a command that returns a non-zero exit code without raising."""
    _state["error"] = {"code": code, "message": message, "hint": hint}


def pending_error() -> dict | None:
    return _state["error"]


def warn(code: str, message: str) -> None:
    _state["warnings"].append({"code": code, "message": message})
    print(f"warning: {message}", file=sys.stderr)


def entry_ref(repo, h: str, path: str | None = None) -> dict:
    e = repo.entry(h)
    ref = {"hash": h, "index": repo.entry_index(h), "kind": e["kind"]}
    if path:
        ref["path"] = path
    return ref


def emit(command: str, code: int, error: dict | None, stream) -> None:
    envelope = {"schema": SCHEMA, "command": command, "ok": code == 0, "exit": code,
                "data": _state["data"], "warnings": _state["warnings"], "error": error}
    stream.write(json.dumps(envelope, sort_keys=True, default=str) + "\n")
    stream.flush()
