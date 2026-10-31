"""Signed tree heads: a log signer's statement "project P's log has SIZE entries with ROOT".

The same structure serves the hub's STH and a researcher's self-signed local checkpoint; the
verifier reports which one it got, because they carry very different time guarantees.
"""

from __future__ import annotations

import time

from provena.core import merkle
from provena.core.canonical import canonicalize
from provena.core.errors import VerificationError
from provena.core.hashing import TAG_STH
from provena.core.keys import AgentKey, AgentPublic

FIELDS = ("v", "project", "size", "root", "time", "signer")


def make_head(signer: AgentKey, project: str, leaves, at_ms: int | None = None) -> dict:
    """*leaves* is a list of leaf hashes or a merkle.MerkleLog (cached, for the hub)."""
    log = leaves if isinstance(leaves, merkle.MerkleLog) else merkle.MerkleLog(leaves)
    head = {"v": 1, "project": project, "size": len(log), "root": log.root().hex(),
            "time": int(time.time() * 1000) if at_ms is None else at_ms, "signer": signer.id}
    head["sig"] = signer.sign(TAG_STH, canonicalize(head)).hex()
    return head


def unsigned(head: dict) -> dict:
    return {k: head[k] for k in FIELDS}


def verify_head(head: dict, signer: AgentPublic) -> None:
    if set(head) - {"sig"} != set(FIELDS) or head["v"] != 1:
        raise VerificationError("tree head: malformed")
    if signer.id != head["signer"]:
        raise VerificationError("tree head: signer key mismatch")
    signer.verify(TAG_STH, canonicalize(unsigned(head)), bytes.fromhex(head["sig"]))
