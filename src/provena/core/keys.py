"""Agent identities: an Ed25519 signing key plus an X25519 key-encapsulation key.

The agent id is derived from the signing key only. The KEM key is bound to it by a self-signed
*agent card*, so anyone holding the card can check both keys belong to the same agent.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from provena.core.canonical import canonicalize
from provena.core.encoding import b32_lower
from provena.core.errors import DecryptionError, VerificationError
from provena.core.hashing import TAG_AGENT_CARD, TAG_AGENT_ID, signing_message, tagged

AGENT_KINDS = ("person", "instrument", "software", "org", "hub")
ID_PREFIX = "pv1a"


def _raw_pub(key) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def agent_id(sign_pub: bytes) -> str:
    return ID_PREFIX + b32_lower(tagged(TAG_AGENT_ID, sign_pub))[:32]


@dataclass(frozen=True)
class AgentPublic:
    sign_pub: bytes
    kem_pub: bytes

    @property
    def id(self) -> str:
        return agent_id(self.sign_pub)

    def verify(self, tag: bytes, payload: bytes, signature: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(self.sign_pub).verify(
                signature, signing_message(tag, payload)
            )
        except InvalidSignature as exc:
            raise VerificationError(f"bad signature from {self.id}") from exc

    def to_dict(self) -> dict:
        return {"id": self.id, "sign": self.sign_pub.hex(), "kem": self.kem_pub.hex()}

    @classmethod
    def from_dict(cls, d: dict) -> AgentPublic:
        pub = cls(bytes.fromhex(d["sign"]), bytes.fromhex(d["kem"]))
        if d.get("id") != pub.id:  # required: callers key state by this id
            raise VerificationError("agent id missing or does not match signing key")
        return pub


class AgentKey:
    """Private half of an agent identity. Seeds never leave this object except via export."""

    def __init__(self, sign_seed: bytes, kem_seed: bytes):
        self._sign = Ed25519PrivateKey.from_private_bytes(sign_seed)
        self._kem = X25519PrivateKey.from_private_bytes(kem_seed)
        self._seeds = sign_seed + kem_seed
        self.public = AgentPublic(_raw_pub(self._sign.public_key()),
                                  _raw_pub(self._kem.public_key()))

    @classmethod
    def generate(cls) -> AgentKey:
        return cls(os.urandom(32), os.urandom(32))

    @property
    def id(self) -> str:
        return self.public.id

    @property
    def kem_private(self) -> X25519PrivateKey:
        return self._kem

    def sign(self, tag: bytes, payload: bytes) -> bytes:
        return self._sign.sign(signing_message(tag, payload))

    def sign_note(self, body: bytes) -> bytes:
        """A C2SP signed-note signature (checkpoints for transparency-log witnesses): Ed25519
        over the note text. A note starts with a printable origin line; no ledger message can
        (they start with a length byte below 0x20), so the two never stand in for each other."""
        if not body or not 0x20 <= body[0] < 0x7f or not body.endswith(b"\n"):
            raise ValueError("a note body starts with a printable line and ends with a newline")
        return self._sign.sign(body)

    def sign_dsse(self, payload_type: str, payload: bytes) -> bytes:
        """A DSSE signature (in-toto envelopes): Ed25519 over PAE(type, payload), as other
        DSSE verifiers expect. PAE starts with "DSSEv1 ", which no ledger message (a length
        byte, then a provena/… tag) can equal, so the two never stand in for each other."""
        return self._sign.sign(dsse_pae(payload_type, payload))

    def make_card(self, kind: str, name: str = "") -> dict:
        """Self-signed statement binding the KEM key (and optional display name) to this id."""
        if kind not in AGENT_KINDS:
            raise ValueError(f"unknown agent kind {kind!r}")
        card = {"v": 1, "kind": kind, "name": name, **self.public.to_dict()}
        card["sig"] = self.sign(TAG_AGENT_CARD, canonicalize(card)).hex()
        return card

    # -- keyfile -------------------------------------------------------------------------------

    def export_encrypted(self, passphrase: str, *, n: int = 2**15) -> dict:
        salt, nonce = os.urandom(16), os.urandom(12)
        header = {"v": 1, "id": self.id, "kdf": {"name": "scrypt", "n": n, "r": 8, "p": 1,
                                                 "salt": salt.hex()}}
        key = Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(passphrase.encode())
        ct = AESGCM(key).encrypt(nonce, self._seeds, canonicalize(header))
        return {**header, "nonce": nonce.hex(), "ct": ct.hex()}

    @classmethod
    def load_encrypted(cls, keyfile: dict, passphrase: str) -> AgentKey:
        header = {k: keyfile[k] for k in ("v", "id", "kdf")}
        kdf = keyfile["kdf"]
        key = Scrypt(salt=bytes.fromhex(kdf["salt"]), length=32, n=kdf["n"], r=kdf["r"],
                     p=kdf["p"]).derive(passphrase.encode())
        try:
            seeds = AESGCM(key).decrypt(bytes.fromhex(keyfile["nonce"]),
                                        bytes.fromhex(keyfile["ct"]), canonicalize(header))
        except Exception as exc:
            raise DecryptionError("wrong passphrase or corrupted keyfile") from exc
        agent = cls(seeds[:32], seeds[32:])
        if agent.id != keyfile["id"]:
            raise DecryptionError("keyfile id mismatch")
        return agent


def verify_card(card: dict) -> AgentPublic:
    body = {k: v for k, v in card.items() if k != "sig"}
    pub = AgentPublic.from_dict(body)
    pub.verify(TAG_AGENT_CARD, canonicalize(body), bytes.fromhex(card["sig"]))
    return pub


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def verify_dsse(pub: AgentPublic, payload_type: str, payload: bytes, signature: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(pub.sign_pub).verify(
            signature, dsse_pae(payload_type, payload))
    except InvalidSignature as exc:
        raise VerificationError(f"bad DSSE signature from {pub.id}") from exc
