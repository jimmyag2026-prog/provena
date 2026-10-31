"""External time anchoring (ARCHITECTURE.md §5.3).

The hub periodically builds a "root of roots": a Merkle tree whose leaves are the latest signed
head of every project, and has an external time source attest to that root. One anchor covers
every project, so cost is independent of scale. A project head's membership in an anchor is an
ordinary inclusion proof; providers only ever see a 32-byte digest.

Providers:
  self      the hub signs (digest, time) itself — for development; adds no independent trust
  rfc3161   an RFC 3161 Time-Stamp Authority token (see provena.core.rfc3161)
"""

from __future__ import annotations

from provena.core import merkle, rfc3161
from provena.core.canonical import canonicalize
from provena.core.encoding import unb64u
from provena.core.errors import VerificationError
from provena.core.hashing import TAG_ANCHOR_LEAF, TAG_SELF_ANCHOR, tagged
from provena.core.keys import AgentKey, AgentPublic


def anchor_leaf(head: dict) -> bytes:
    return merkle.leaf_hash(tagged(TAG_ANCHOR_LEAF, canonicalize(head)))


def root_of_roots(heads: list[dict]) -> tuple[bytes, list[dict]]:
    """Order heads canonically (by project) and return (root, ordered heads)."""
    ordered = sorted(heads, key=lambda h: h["project"])
    return merkle.root([anchor_leaf(h) for h in ordered]), ordered


def self_stamp(hub: AgentKey, digest: bytes, at_ms: int) -> dict:
    stamp = {"digest": digest.hex(), "time": at_ms, "signer": hub.id}
    return {**stamp, "sig": hub.sign(TAG_SELF_ANCHOR, canonicalize(stamp)).hex()}


def verify_self_stamp(receipt: dict, digest: bytes, hub: AgentPublic) -> int:
    stamp = {k: receipt[k] for k in ("digest", "time", "signer")}
    if stamp["digest"] != digest.hex() or stamp["signer"] != hub.id:
        raise VerificationError("self anchor: digest or signer mismatch")
    hub.verify(TAG_SELF_ANCHOR, canonicalize(stamp), bytes.fromhex(receipt["sig"]))
    return receipt["time"]


def verify_anchor_record(record: dict, head: dict, *,
                         log: AgentPublic) -> tuple[str, int, str, str | None]:
    """Check that *head* is included in the anchored root and the stamp covers that root.

    Returns (provider, attested time in ms, issuer description, TSA certificate fingerprint or
    None). *log* is the hub key (needed for `self` stamps). Whether to trust the issuer is the
    caller's decision.
    """
    anchor = record["anchor"]
    root = bytes.fromhex(anchor["digest"])
    merkle.verify_inclusion(anchor_leaf(head), record["index"], anchor["size"],
                            [bytes.fromhex(p) for p in record["proof"]], root)
    provider = anchor["provider"]
    if provider == "self":
        return provider, verify_self_stamp(anchor["receipt"], root, log), f"hub {log.id}", None
    if provider == "rfc3161":
        info = rfc3161.inspect_token(unb64u(anchor["receipt"]["token"]), root)
        return (provider, info.time_ms, f"TSA {info.tsa_subject}; cert sha256 "
                f"{info.tsa_fingerprint[:16]}…", info.tsa_fingerprint)
    raise VerificationError(f"unknown anchor provider {provider!r}")
