"""Witness cosignatures on tree heads.

A witness keeps the last head it saw for each (log, project). It cosigns a new head only after
verifying the log's signature and a consistency proof from that last head, so two witnesses with
honest storage can never cosign two forks of the same log.
"""

from __future__ import annotations

from collections.abc import Sequence

from provena.core import merkle
from provena.core.canonical import canonicalize
from provena.core.errors import VerificationError
from provena.core.hashing import TAG_COSIG, TAG_HEAD_ID, tagged
from provena.core.keys import AgentKey, AgentPublic
from provena.core.treehead import verify_head

COSIG_FIELDS = ("v", "head", "witness", "time")


def head_id(head: dict) -> str:
    """Hex identifier of a signed tree head (commits to the signature too)."""
    return tagged(TAG_HEAD_ID, canonicalize(head)).hex()


def check_extension(previous: dict | None, head: dict, log: AgentPublic,
                    proof: Sequence[bytes], predecessors: frozenset[str] = frozenset()) -> None:
    """Verify *head* is signed by *log* and extends *previous* (if any) append-only.
    *predecessors*: earlier keys of the same log, from a hand-over the caller verified."""
    verify_head(head, log)
    if previous is None:
        return
    if previous["project"] != head["project"] or \
            previous["signer"] not in {head["signer"], *predecessors}:
        raise VerificationError("witness: head is for another log")
    if head["size"] < previous["size"]:
        raise VerificationError("witness: log shrank")
    if head["size"] == previous["size"]:
        if head["root"] != previous["root"]:
            raise VerificationError("witness: same size, different root (fork)")
        return
    merkle.verify_consistency(previous["size"], head["size"], bytes.fromhex(previous["root"]),
                              bytes.fromhex(head["root"]), proof)


def cosign(witness: AgentKey, head: dict, at_ms: int) -> dict:
    c = {"v": 1, "head": head_id(head), "witness": witness.id, "time": at_ms}
    c["sig"] = witness.sign(TAG_COSIG, canonicalize(c)).hex()
    return c


def verify_cosig(cosig: dict, head: dict, witness: AgentPublic) -> None:
    if set(cosig) - {"sig"} != set(COSIG_FIELDS) or cosig["witness"] != witness.id:
        raise VerificationError("cosignature: malformed or wrong witness")
    if cosig["head"] != head_id(head):
        raise VerificationError("cosignature is for a different head")
    witness.verify(TAG_COSIG, canonicalize({k: cosig[k] for k in COSIG_FIELDS}),
                   bytes.fromhex(cosig["sig"]))
