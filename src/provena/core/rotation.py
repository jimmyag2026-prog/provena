"""Hub log key rotation (ADR 0010).

A rotation statement says "log key *old* is succeeded by log key *new* from *time* on". Both keys
sign it: the old key authorizes the hand-over, the new key proves it is held. Trust moves forward
only: a verifier that trusts *old* also trusts its successor, never the other way round, so a
leaked old key that the verifier has dropped cannot vouch for anything.
"""

from __future__ import annotations

from provena.core.canonical import canonicalize
from provena.core.errors import VerificationError
from provena.core.hashing import TAG_LOG_ROTATION
from provena.core.keys import AgentKey, verify_card

FIELDS = ("v", "old", "new", "time")
MAX_CHAIN = 64
MAX_SAFE = 2**53 - 1  # JSON integers both verifiers read exactly


def make(old: AgentKey, old_card: dict, new: AgentKey, new_card: dict, at_ms: int) -> dict:
    body = {"v": 1, "old": old_card, "new": new_card, "time": at_ms}
    msg = canonicalize(body)
    return {**body, "sig_old": old.sign(TAG_LOG_ROTATION, msg).hex(),
            "sig_new": new.sign(TAG_LOG_ROTATION, msg).hex()}


def verify(stmt: dict) -> tuple[str, str]:
    """(old id, new id) of a well-formed rotation signed by both keys."""
    if not isinstance(stmt, dict) or set(stmt) != {*FIELDS, "sig_old", "sig_new"} \
            or type(stmt["v"]) is not int or stmt["v"] != 1 \
            or type(stmt["time"]) is not int or not 0 <= stmt["time"] <= MAX_SAFE:
        raise VerificationError("log rotation: malformed statement")
    old, new = verify_card(stmt["old"]), verify_card(stmt["new"])
    if stmt["old"].get("kind") != "hub" or stmt["new"].get("kind") != "hub" or old.id == new.id:
        raise VerificationError("log rotation: both keys must be distinct hub keys")
    msg = canonicalize({k: stmt[k] for k in FIELDS})
    old.verify(TAG_LOG_ROTATION, msg, bytes.fromhex(stmt["sig_old"]))
    new.verify(TAG_LOG_ROTATION, msg, bytes.fromhex(stmt["sig_new"]))
    return old.id, new.id


def successors(statements: list[dict]) -> dict[str, dict]:
    """old id -> the statement handing it over. A key with two successors is a fork."""
    if len(statements) > MAX_CHAIN:
        raise VerificationError("log rotation: too many statements")
    out: dict[str, dict] = {}
    for stmt in statements:
        old, new = verify(stmt)
        if old in out and out[old]["new"]["id"] != new:
            raise VerificationError(f"log rotation: key {old} was handed to two successors")
        out[old] = stmt
    return out


def chain(statements: list[dict], start: str, end: str) -> list[dict] | None:
    """The statements leading from log key *start* forward to *end*, or None."""
    nxt, path, at = successors(statements), [], start
    while at != end:
        if at not in nxt or len(path) >= MAX_CHAIN:
            return None
        path.append(nxt[at])
        at = nxt[at]["new"]["id"]
    return path


def extend_trust(trusted: set[str], statements: list[dict]) -> dict[str, str]:
    """Successor id -> the trusted id it descends from, for every key *trusted* hands over to."""
    nxt, added = successors(statements), {}
    for root in list(trusted):
        at, steps = root, 0
        while at in nxt and steps < MAX_CHAIN:
            at, steps = nxt[at]["new"]["id"], steps + 1
            if at not in trusted and at not in added:
                added[at] = root
    return added
