"""Salted, hiding commitments to plaintext content (ADR 0002)."""

import hmac
import os

from provena.core.errors import VerificationError
from provena.core.hashing import TAG_COMMIT, tagged


def new_salt() -> bytes:
    return os.urandom(32)


def commit(salt: bytes, plain_sha256: bytes) -> bytes:
    if len(salt) != 32 or len(plain_sha256) != 32:
        raise ValueError("salt and digest must be 32 bytes")
    return tagged(TAG_COMMIT, salt, plain_sha256)


def verify_opening(commitment: bytes, salt: bytes, plain_sha256: bytes) -> None:
    if not hmac.compare_digest(commit(salt, plain_sha256), commitment):
        raise VerificationError("commitment opening does not match")
