"""Regenerate golden test vectors in tests/vectors/.

Vectors are cross-language contracts (the JS verifier must reproduce them). Only regenerate when a
format change is intended, and record that change in CHANGELOG as breaking.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from provena.core import aead, commitment, hashing  # noqa: E402
from provena.core.canonical import canonicalize  # noqa: E402
from provena.core.keys import AgentKey  # noqa: E402

SEED_A = bytes(range(32))
SEED_B = bytes(range(32, 64))


def core_vectors() -> dict:
    agent = AgentKey(SEED_A, SEED_B)
    card = agent.make_card("person", "Ada")
    salt = bytes([7]) * 32
    plain = b"provena test vector\n"
    ct = aead.encrypt_bytes(bytes([9]) * 32, plain, chunk_size=8, nonce_prefix=bytes(7))
    obj = {"b": [1, True, None], "a": "é\n", "c": {"z": -5, "y": ""}}
    return {
        "canonical": {"input": obj, "output": canonicalize(obj).decode()},
        "tagged_hash": {"tag": "provena/commit/v1", "parts_hex": ["00ff", "abcd"],
                        "output": hashing.tagged(b"provena/commit/v1", b"\x00\xff",
                                                 b"\xab\xcd").hex()},
        "agent": {"sign_seed": SEED_A.hex(), "kem_seed": SEED_B.hex(), "id": agent.id,
                  "sign_pub": agent.public.sign_pub.hex(), "kem_pub": agent.public.kem_pub.hex(),
                  "card": card},
        "commitment": {"salt": salt.hex(), "plaintext": plain.decode(),
                       "plain_sha256": hashing.sha256(plain).hex(),
                       "commitment": commitment.commit(salt, hashing.sha256(plain)).hex()},
        "aead": {"key": (bytes([9]) * 32).hex(), "chunk_size": 8, "nonce_prefix": "00" * 7,
                 "plaintext": plain.decode(), "ciphertext": ct.hex()},
    }


def main() -> None:
    out = ROOT / "tests" / "vectors" / "core.json"
    out.write_text(json.dumps(core_vectors(), indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
