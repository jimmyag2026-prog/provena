"""Ledger entries: the only unit ever written to a Provena log (ARCHITECTURE.md §3.3).

Entries are plain JSON objects so that they round-trip through storage, the wire and other
languages unchanged. This module owns the envelope (shape, signature, hash); per-kind body rules
and authorization live in provena.core.state.
"""

from __future__ import annotations

import re
import time

from provena.core.canonical import canonicalize
from provena.core.errors import VerificationError
from provena.core.hashing import TAG_ENTRY_HASH, TAG_ENTRY_SIG, tagged
from provena.core.keys import AgentKey, AgentPublic
from provena.core.merkle import leaf_hash

VERSION = 1
KINDS = ("genesis", "entity", "activity", "plan", "reveal", "attest", "member", "key", "redact",
         "grant", "meta")
FIELDS = ("v", "project", "kind", "author", "prev", "refs", "body", "sealed", "ts", "sig")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")  # \Z: "$" would accept a trailing newline


def _unsigned(entry: dict) -> dict:
    return {k: entry[k] for k in FIELDS if k != "sig"}


def build(author: AgentKey, kind: str, *, project: str | None, prev: str | None = None,
          refs: list[str] | None = None, body: dict | None = None, sealed: str | None = None,
          ts: int | None = None) -> dict:
    entry = {
        "v": VERSION,
        "project": project,
        "kind": kind,
        "author": author.id,
        "prev": prev,
        "refs": refs or [],
        "body": body or {},
        "sealed": sealed,
        "ts": int(time.time() * 1000) if ts is None else ts,
    }
    check_shape({**entry, "sig": "0" * 128})
    entry["sig"] = author.sign(TAG_ENTRY_SIG, canonicalize(entry)).hex()
    return entry


def check_shape(entry: dict) -> None:
    """Structural validation at the trust boundary (anything read from disk or the network)."""
    if not isinstance(entry, dict) or set(entry) != set(FIELDS):
        raise VerificationError("entry: wrong field set")
    if entry["v"] != VERSION:
        raise VerificationError(f"entry: unsupported version {entry['v']!r}")
    if entry["kind"] not in KINDS:
        raise VerificationError(f"entry: unknown kind {entry['kind']!r}")
    if (entry["kind"] == "genesis") != (entry["project"] is None):
        raise VerificationError("entry: project must be null exactly for genesis")
    for field in ("project", "prev"):
        if entry[field] is not None and not _HEX64.match(str(entry[field])):
            raise VerificationError(f"entry: {field} must be a hex sha256 or null")
    if not isinstance(entry["refs"], list) or not all(
        isinstance(r, str) and _HEX64.match(r) for r in entry["refs"]
    ):
        raise VerificationError("entry: refs must be hex sha256 strings")
    if not isinstance(entry["body"], dict):
        raise VerificationError("entry: body must be an object")
    if entry["sealed"] is not None and not isinstance(entry["sealed"], str):
        raise VerificationError("entry: sealed must be a string or null")
    if not isinstance(entry["ts"], int) or isinstance(entry["ts"], bool) or entry["ts"] < 0:
        raise VerificationError("entry: ts must be a non-negative integer")
    if not isinstance(entry["sig"], str) or not re.fullmatch(r"[0-9a-f]{128}", entry["sig"]):
        raise VerificationError("entry: malformed signature")
    canonicalize(entry)


def verify_signature(entry: dict, author: AgentPublic, *, shape_checked: bool = False) -> None:
    if not shape_checked:
        check_shape(entry)
    if author.id != entry["author"]:
        raise VerificationError("entry: author key does not match author id")
    author.verify(TAG_ENTRY_SIG, canonicalize(_unsigned(entry)), bytes.fromhex(entry["sig"]))


def entry_hash(entry: dict) -> str:
    """Hex id of an entry; commits to every field including the signature."""
    return tagged(TAG_ENTRY_HASH, canonicalize(entry)).hex()


def entry_leaf(entry: dict) -> bytes:
    return leaf_hash(bytes.fromhex(entry_hash(entry)))
