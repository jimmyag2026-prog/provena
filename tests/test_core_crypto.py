import io
import json
from pathlib import Path

import pytest

from provena.core import aead, commitment, hashing, seal
from provena.core.canonical import canonicalize
from provena.core.errors import CanonicalizationError, DecryptionError, VerificationError
from provena.core.keys import AgentKey, AgentPublic, verify_card

VEC = json.loads((Path(__file__).parent / "vectors" / "core.json").read_text())


# -- golden vectors (cross-language contract) ------------------------------------------------

def test_vector_canonical():
    assert canonicalize(VEC["canonical"]["input"]).decode() == VEC["canonical"]["output"]


def test_vector_tagged_hash():
    v = VEC["tagged_hash"]
    parts = [bytes.fromhex(p) for p in v["parts_hex"]]
    assert hashing.tagged(v["tag"].encode(), *parts).hex() == v["output"]


def test_vector_agent_and_card():
    v = VEC["agent"]
    agent = AgentKey(bytes.fromhex(v["sign_seed"]), bytes.fromhex(v["kem_seed"]))
    assert agent.id == v["id"]
    assert agent.public.kem_pub.hex() == v["kem_pub"]
    assert agent.make_card("person", "Ada") == v["card"]  # Ed25519 is deterministic
    assert verify_card(v["card"]).id == v["id"]


def test_vector_commitment():
    v = VEC["commitment"]
    digest = hashing.sha256(v["plaintext"].encode())
    assert digest.hex() == v["plain_sha256"]
    assert commitment.commit(bytes.fromhex(v["salt"]), digest).hex() == v["commitment"]


def test_vector_aead():
    v = VEC["aead"]
    key = bytes.fromhex(v["key"])
    ct = aead.encrypt_bytes(key, v["plaintext"].encode(), chunk_size=v["chunk_size"],
                            nonce_prefix=bytes.fromhex(v["nonce_prefix"]))
    assert ct.hex() == v["ciphertext"]
    assert aead.decrypt_bytes(key, ct).decode() == v["plaintext"]


# -- external standards ----------------------------------------------------------------------

def test_jcs_sorts_by_utf16_code_units():
    # RFC 8785 §3.2.3 example: astral U+1F600 sorts before U+FB33 in UTF-16.
    obj = {"€": 1, "\r": 2, "דּ": 3, "1": 4, "\U0001f600": 5, "\u0080": 6, "ö": 7}
    keys = list(json.loads(canonicalize(obj)).keys())
    assert keys == ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]


def test_rfc8032_ed25519_test1():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
    assert sk.sign(b"").hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970"
        "1cf9b46bd25bf5f0595bbe24655141438e7a100b")


# -- behaviour -------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [1.5, {"a": float("nan")}, {1: "x"}, 2**60, b"bytes"])
def test_canonical_rejects(bad):
    with pytest.raises(CanonicalizationError):
        canonicalize(bad)


def test_signature_roundtrip_and_tamper():
    agent = AgentKey.generate()
    sig = agent.sign(hashing.TAG_ENTRY_SIG, b"payload")
    agent.public.verify(hashing.TAG_ENTRY_SIG, b"payload", sig)
    with pytest.raises(VerificationError):
        agent.public.verify(hashing.TAG_ENTRY_SIG, b"payload!", sig)
    with pytest.raises(VerificationError):  # domain separation: same bytes, other purpose
        agent.public.verify(hashing.TAG_STH, b"payload", sig)


def test_card_tamper_detected():
    card = AgentKey.generate().make_card("instrument", "plate-reader-01")
    card["name"] = "plate-reader-02"
    with pytest.raises(VerificationError):
        verify_card(card)


def test_public_from_dict_checks_id():
    d = AgentKey.generate().public.to_dict()
    d["id"] = AgentKey.generate().id
    with pytest.raises(VerificationError):
        AgentPublic.from_dict(d)


def test_keyfile_roundtrip():
    agent = AgentKey.generate()
    kf = agent.export_encrypted("correct horse", n=2**10)
    assert AgentKey.load_encrypted(kf, "correct horse").id == agent.id
    with pytest.raises(DecryptionError):
        AgentKey.load_encrypted(kf, "wrong")


@pytest.mark.parametrize("size", [0, 1, 7, 8, 9, 64, 1000])
def test_aead_sizes(size):
    key, data = aead.new_key(), bytes(range(256)) * 4
    data = data[:size]
    src, ct = io.BytesIO(data), io.BytesIO()
    info = aead.encrypt_stream(key, src, ct, chunk_size=8)
    assert info.plain_sha256 == hashing.sha256(data)
    assert info.cipher_sha256 == hashing.sha256(ct.getvalue())
    assert aead.decrypt_bytes(key, ct.getvalue()) == data


def test_aead_detects_truncation_and_flip():
    key = aead.new_key()
    ct = aead.encrypt_bytes(key, b"x" * 40, chunk_size=8)
    with pytest.raises(DecryptionError):
        aead.decrypt_bytes(key, ct[: aead.HEADER_LEN + 24])  # drop trailing chunks
    flipped = bytearray(ct)
    flipped[-1] ^= 1
    with pytest.raises(DecryptionError):
        aead.decrypt_bytes(key, bytes(flipped))
    with pytest.raises(DecryptionError):
        aead.decrypt_bytes(aead.new_key(), ct)


def test_seal_roundtrip_and_binding():
    alice, mallory = AgentKey.generate(), AgentKey.generate()
    blob = seal.seal_to(alice.public.kem_pub, b"project key", b"epoch-0")
    assert seal.open_sealed(alice.kem_private, blob, b"epoch-0") == b"project key"
    with pytest.raises(DecryptionError):
        seal.open_sealed(mallory.kem_private, blob, b"epoch-0")
    with pytest.raises(DecryptionError):
        seal.open_sealed(alice.kem_private, blob, b"epoch-1")


def test_wrap_roundtrip():
    k = aead.new_key()
    assert seal.unwrap(k, seal.wrap(k, b"dek", b"aad"), b"aad") == b"dek"
    with pytest.raises(DecryptionError):
        seal.unwrap(k, seal.wrap(k, b"dek", b"aad"), b"other")


def test_commitment_opening():
    salt, digest = commitment.new_salt(), hashing.sha256(b"data")
    c = commitment.commit(salt, digest)
    commitment.verify_opening(c, salt, digest)
    with pytest.raises(VerificationError):
        commitment.verify_opening(c, commitment.new_salt(), digest)
