"""Paths that come from the ledger are untrusted input (any co-member can write them)."""

from __future__ import annotations

from pathlib import Path

from provena.core.errors import ProvenaError


class UnsafePath(ProvenaError):
    pass


def safe_relpath(name: str) -> Path:
    """A relative path with no absolute root, no parent traversal and nothing inside tool
    metadata directories (.provena, .git). Raises UnsafePath otherwise."""
    if not isinstance(name, str):
        raise UnsafePath(f"refusing non-string path from ledger: {name!r}")
    parts = [p for p in Path(name).parts if p not in ("", ".", "/")]
    if not parts or ".." in parts or Path(name).is_absolute() or "\\" in name:
        raise UnsafePath(f"refusing unsafe path from ledger: {name!r}")
    for part in parts:
        # Case-insensitive filesystems (macOS, Windows) map `.GIT` to `.git`; Windows also
        # drops trailing dots/spaces and treats `:` as an alternate data stream.
        folded = part.rstrip(" .").casefold()
        if (folded in RESERVED or folded.split(".")[0].rstrip(" ") in WINDOWS_DEVICES
                or ":" in part or not part.isprintable()):
            raise UnsafePath(f"refusing unsafe path from ledger: {name!r}")
    return Path(*parts)


RESERVED = {".provena", ".git", ""}
# Win32 device names are special in any directory and with any extension (`nul.txt`).
WINDOWS_DEVICES = {"con", "prn", "aux", "nul", "conin$", "conout$",
                   *(f"{d}{i}" for d in ("com", "lpt") for i in (*"123456789", "¹", "²", "³"))}
