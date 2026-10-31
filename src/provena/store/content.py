"""Decrypt ledger content to a file, publishing it only if it is exactly what was committed."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from provena.core import aead, commitment
from provena.core.errors import VerificationError


def decrypt_verified(cipher_path: Path, dek: bytes, dest: Path, salt_hex: str, plain_hex: str,
                     commitment_hex: str) -> int:
    """Stream-decrypt into *dest*. The file appears only if the plaintext matches the recorded
    hash and opens the commitment. Returns the plaintext size."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, suffix=".part")
    try:
        with open(cipher_path, "rb") as src, os.fdopen(fd, "wb") as dst:
            info = aead.decrypt_stream(dek, src, dst)
        if info.plain_sha256.hex() != plain_hex:
            raise VerificationError("decrypted content does not match the recorded hash")
        commitment.verify_opening(bytes.fromhex(commitment_hex), bytes.fromhex(salt_hex),
                                  info.plain_sha256)
        os.replace(tmp, dest)
        return info.plain_size
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
