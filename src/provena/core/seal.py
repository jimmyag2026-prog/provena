"""Small-message encryption: symmetric key wrapping and sealing to an X25519 public key.

seal_to is HPKE base mode in spirit (ephemeral X25519 + HKDF-SHA256 + AES-256-GCM) with the
ephemeral and recipient public keys bound into both the KDF salt and the AEAD associated data.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from provena.core.errors import DecryptionError

SEAL_INFO = b"provena/seal/v1"


def wrap(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unwrap(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as exc:
        raise DecryptionError("unwrap failed") from exc


def _derive(shared: bytes, eph_pub: bytes, recipient_pub: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub,
                info=SEAL_INFO + info).derive(shared)


def seal_to(recipient_pub: bytes, plaintext: bytes, info: bytes = b"") -> bytes:
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = _derive(eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub)), eph_pub,
                  recipient_pub, info)
    nonce = os.urandom(12)
    return eph_pub + nonce + AESGCM(key).encrypt(nonce, plaintext, eph_pub + recipient_pub)


def open_sealed(recipient: X25519PrivateKey, blob: bytes, info: bytes = b"") -> bytes:
    eph_pub, nonce, ct = blob[:32], blob[32:44], blob[44:]
    recipient_pub = recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = _derive(recipient.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub,
                  recipient_pub, info)
    try:
        return AESGCM(key).decrypt(nonce, ct, eph_pub + recipient_pub)
    except InvalidTag as exc:
        raise DecryptionError("sealed box failed authentication") from exc
