"""Chunked authenticated encryption (STREAM construction over AES-256-GCM).

Layout: header = MAGIC(4) | chunk_size(u32 BE) | nonce_prefix(7), then ciphertext chunks of
chunk_size + 16 bytes (the last one may be shorter). Chunk i uses nonce
prefix | i (u32 BE) | last_flag(1); the header is the AAD of every chunk. This detects
truncation, reordering, and splicing between files.
"""

from __future__ import annotations

import hashlib
import io
import os
from dataclasses import dataclass
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from provena.core.errors import DecryptionError

MAGIC = b"PVE1"
DEFAULT_CHUNK = 1 << 20
MAX_CHUNK = 16 << 20
TAG_LEN = 16
HEADER_LEN = 4 + 4 + 7


@dataclass(frozen=True)
class StreamInfo:
    plain_sha256: bytes
    cipher_sha256: bytes
    plain_size: int
    cipher_size: int


def new_key() -> bytes:
    return os.urandom(32)


def _nonce(prefix: bytes, index: int, last: bool) -> bytes:
    return prefix + index.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


def _chunks(src: BinaryIO, size: int):
    """Yield (chunk, is_last); an empty input yields one empty last chunk."""
    current = src.read(size)
    while True:
        nxt = src.read(size)
        yield current, not nxt
        if not nxt:
            return
        current = nxt


def encrypt_stream(
    key: bytes, src: BinaryIO, dst: BinaryIO, *,
    chunk_size: int = DEFAULT_CHUNK, nonce_prefix: bytes | None = None,
) -> StreamInfo:
    prefix = nonce_prefix if nonce_prefix is not None else os.urandom(7)
    if not 0 < chunk_size <= MAX_CHUNK:
        raise ValueError(f"chunk size must be 1..{MAX_CHUNK}")
    header = MAGIC + chunk_size.to_bytes(4, "big") + prefix
    aead = AESGCM(key)
    plain_h, cipher_h = hashlib.sha256(), hashlib.sha256()
    plain_n = 0
    dst.write(header)
    cipher_h.update(header)
    cipher_n = len(header)
    for i, (chunk, last) in enumerate(_chunks(src, chunk_size)):
        plain_h.update(chunk)
        plain_n += len(chunk)
        ct = aead.encrypt(_nonce(prefix, i, last), chunk, header)
        dst.write(ct)
        cipher_h.update(ct)
        cipher_n += len(ct)
    return StreamInfo(plain_h.digest(), cipher_h.digest(), plain_n, cipher_n)


def decrypt_stream(key: bytes, src: BinaryIO, dst: BinaryIO) -> StreamInfo:
    header = src.read(HEADER_LEN)
    if len(header) != HEADER_LEN or header[:4] != MAGIC:
        raise DecryptionError("not a Provena ciphertext")
    chunk_size = int.from_bytes(header[4:8], "big")
    if not 0 < chunk_size <= MAX_CHUNK:
        # the header is authenticated, but a key holder chose it: one chunk is read into
        # memory at a time, so a huge value would let any member exhaust a decrypting hub
        raise DecryptionError(f"chunk size {chunk_size} outside 1..{MAX_CHUNK}")
    prefix = header[8:]
    aead = AESGCM(key)
    plain_h, cipher_h = hashlib.sha256(), hashlib.sha256(header)
    plain_n, cipher_n = 0, HEADER_LEN
    for i, (ct, last) in enumerate(_chunks(src, chunk_size + TAG_LEN)):
        try:
            chunk = aead.decrypt(_nonce(prefix, i, last), ct, header)
        except InvalidTag as exc:
            raise DecryptionError(f"chunk {i} failed authentication") from exc
        cipher_h.update(ct)
        cipher_n += len(ct)
        plain_h.update(chunk)
        plain_n += len(chunk)
        dst.write(chunk)
    return StreamInfo(plain_h.digest(), cipher_h.digest(), plain_n, cipher_n)


def encrypt_bytes(key: bytes, data: bytes, **kw) -> bytes:
    out = io.BytesIO()
    encrypt_stream(key, io.BytesIO(data), out, **kw)
    return out.getvalue()


def decrypt_bytes(key: bytes, data: bytes) -> bytes:
    out = io.BytesIO()
    decrypt_stream(key, io.BytesIO(data), out)
    return out.getvalue()
