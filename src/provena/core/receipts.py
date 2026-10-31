"""Hub receipts: Signed Entry Timestamps (SET) and signed HTTP requests."""

from __future__ import annotations

import hashlib

from provena.core.canonical import canonicalize
from provena.core.errors import VerificationError
from provena.core.hashing import TAG_REQUEST, TAG_SET
from provena.core.keys import AgentKey, AgentPublic

SET_FIELDS = ("v", "project", "index", "entry_hash", "integrated_time", "signer")
REQUEST_WINDOW_MS = 300_000


def make_set(hub: AgentKey, project: str, index: int, entry_hash: str, at_ms: int) -> dict:
    s = {"v": 1, "project": project, "index": index, "entry_hash": entry_hash,
         "integrated_time": at_ms, "signer": hub.id}
    s["sig"] = hub.sign(TAG_SET, canonicalize(s)).hex()
    return s


def verify_set(s: dict, hub: AgentPublic) -> None:
    if set(s) - {"sig"} != set(SET_FIELDS) or s["signer"] != hub.id:
        raise VerificationError("SET: malformed or wrong signer")
    hub.verify(TAG_SET, canonicalize({k: s[k] for k in SET_FIELDS}), bytes.fromhex(s["sig"]))


def request_payload(method: str, path: str, query: str, body: bytes, agent: str,
                    at_ms: int) -> bytes:
    return canonicalize({"method": method.upper(), "path": path, "query": query,
                         "body": hashlib.sha256(body).hexdigest(), "agent": agent,
                         "time": at_ms})


def sign_request(agent: AgentKey, method: str, path: str, query: str, body: bytes,
                 at_ms: int) -> dict[str, str]:
    sig = agent.sign(TAG_REQUEST, request_payload(method, path, query, body, agent.id, at_ms))
    return {"X-Provena-Agent": agent.id, "X-Provena-Time": str(at_ms),
            "X-Provena-Signature": sig.hex()}


def verify_request(pub: AgentPublic, method: str, path: str, query: str, body: bytes,
                   at_ms: int, signature_hex: str, now_ms: int) -> None:
    if abs(now_ms - at_ms) > REQUEST_WINDOW_MS:
        raise VerificationError("request timestamp outside the allowed window")
    pub.verify(TAG_REQUEST, request_payload(method, path, query, body, pub.id, at_ms),
               bytes.fromhex(signature_hex))
