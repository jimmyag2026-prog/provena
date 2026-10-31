"""Tree heads as C2SP checkpoints (signed notes), the format transparency-log witnesses read.

    <origin>\n<tree size>\n<base64 root hash>\n\n— <key name> <base64(key hash || signature)>\n

The key name is the origin; the key hash is the first 4 bytes of
SHA-256(name || "\n" || 0x01 || Ed25519 public key) (c2sp.org/signed-note).
"""

from __future__ import annotations

import base64
import hashlib

from provena.core.errors import VerificationError
from provena.core.keys import AgentKey, AgentPublic


def origin(hub_id: str, project: str) -> str:
    return f"provena/{hub_id}/{project}"


def key_hash(name: str, public: bytes) -> bytes:
    return hashlib.sha256(name.encode() + b"\n\x01" + public).digest()[:4]


def vkey(name: str, public: bytes) -> str:
    """The verifier key string witnesses are configured with."""
    encoded = base64.b64encode(b"\x01" + public).decode()
    return f"{name}+{key_hash(name, public).hex()}+{encoded}"


def body(name: str, size: int, root_hex: str) -> bytes:
    root = base64.b64encode(bytes.fromhex(root_hex)).decode()
    return f"{name}\n{size}\n{root}\n".encode()


def sign(hub: AgentKey, project: str, head: dict) -> str:
    name = origin(hub.id, project)
    text = body(name, head["size"], head["root"])
    sig = base64.b64encode(key_hash(name, hub.public.sign_pub) + hub.sign_note(text)).decode()
    return text.decode() + f"\n— {name} {sig}\n"


def verify(note: str, hub: AgentPublic) -> tuple[str, int, str]:
    """(origin, size, root hex) of a checkpoint signed by *hub*."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    text, sep, sigs = note.partition("\n\n")
    if not sep:
        raise VerificationError("checkpoint: no signature block")
    lines = text.split("\n")
    if len(lines) < 3:
        raise VerificationError("checkpoint: needs origin, size and root lines")
    name = lines[0]
    raw = (text + "\n").encode()
    for line in sigs.strip("\n").split("\n"):
        dash, _, rest = line.partition(" ")
        key_name, _, blob = rest.partition(" ")
        if dash != "—" or key_name != name:
            continue
        data = base64.b64decode(blob)
        if data[:4] != key_hash(name, hub.sign_pub):
            continue
        try:
            Ed25519PublicKey.from_public_bytes(hub.sign_pub).verify(data[4:], raw)
        except InvalidSignature as exc:
            raise VerificationError("checkpoint: bad signature") from exc
        return name, int(lines[1]), base64.b64decode(lines[2]).hex()
    raise VerificationError("checkpoint: no signature by this hub")
