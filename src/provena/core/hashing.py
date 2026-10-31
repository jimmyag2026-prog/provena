"""SHA-256 with explicit domain separation.

Every hash Provena signs or commits to is prefixed with a tag so that a digest computed for one
purpose can never be replayed as a digest for another.
"""

import hashlib

TAG_ENTRY_SIG = b"provena/entry/v1"
TAG_ENTRY_HASH = b"provena/entry-hash/v1"
TAG_COMMIT = b"provena/commit/v1"
TAG_AGENT_ID = b"provena/agent-id/v1"
TAG_AGENT_CARD = b"provena/agent-card/v1"
TAG_STH = b"provena/sth/v1"
TAG_SET = b"provena/set/v1"
TAG_REQUEST = b"provena/request/v1"
TAG_COSIG = b"provena/cosig/v1"
TAG_HEAD_ID = b"provena/head-id/v1"
TAG_ANCHOR_LEAF = b"provena/anchor-leaf/v1"
TAG_SELF_ANCHOR = b"provena/self-anchor/v1"
TAG_CREDENTIAL = b"provena/credential/v1"
TAG_LOG_ROTATION = b"provena/log-rotation/v1"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged(tag: bytes, *parts: bytes) -> bytes:
    """sha256(len(tag) || tag || part_1 || ... ) — the tag length prevents prefix ambiguity."""
    h = hashlib.sha256()
    h.update(len(tag).to_bytes(1, "big"))
    h.update(tag)
    for part in parts:
        h.update(part)
    return h.digest()


def signing_message(tag: bytes, payload: bytes) -> bytes:
    """Bytes actually fed to Ed25519: length-prefixed tag followed by the payload."""
    return len(tag).to_bytes(1, "big") + tag + payload
