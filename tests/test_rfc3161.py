import datetime as dt
from pathlib import Path

import pytest

from provena.core import der, hashing, rfc3161
from provena.core.errors import VerificationError
from tests.tsa_fixture import LocalTSA

VECTORS = Path(__file__).parent / "vectors"
REAL_DIGEST = hashing.sha256(b"provena rfc3161 test vector")


def test_real_freetsa_token():
    """A token issued by freetsa.org on 2026-10-30: cross-checks our DER/CMS handling."""
    info = rfc3161.inspect_token((VECTORS / "freetsa_token.der").read_bytes(), REAL_DIGEST)
    assert info.time_ms == 1793381476000
    assert "freetsa.org" in info.tsa_subject
    with pytest.raises(VerificationError, match="different digest"):
        rfc3161.inspect_token((VECTORS / "freetsa_token.der").read_bytes(),
                              hashing.sha256(b"x"))


def test_local_tsa_roundtrip_and_request_encoding():
    tsa = LocalTSA()
    digest = hashing.sha256(b"root of roots")
    token = rfc3161.token_from_response(tsa.respond(rfc3161.make_request(digest, 7)))
    info = rfc3161.inspect_token(token, digest)
    assert abs(info.time_ms / 1000 - dt.datetime.now(dt.UTC).timestamp()) < 5
    assert info.tsa_subject == "CN=Provena Test TSA"


def test_bad_tokens_rejected():
    digest = hashing.sha256(b"d")
    with pytest.raises(VerificationError, match="messageDigest"):
        rfc3161.inspect_token(LocalTSA().token(digest, tamper_attr=True), digest)
    with pytest.raises(VerificationError, match="extendedKeyUsage"):
        rfc3161.inspect_token(LocalTSA(eku=False).token(digest), digest)
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=30)
    with pytest.raises(VerificationError, match="validity"):
        rfc3161.inspect_token(LocalTSA().token(digest, when=old), digest)
    token = bytearray(LocalTSA().token(digest))
    token[-5] ^= 1  # inside the signature
    with pytest.raises(VerificationError):
        rfc3161.inspect_token(bytes(token), digest)


def test_signing_certificate_attribute_enforced():
    digest = hashing.sha256(b"d")
    with pytest.raises(VerificationError, match="signingCertificate attribute missing"):
        rfc3161.inspect_token(LocalTSA().token(digest, ess="absent"), digest)
    with pytest.raises(VerificationError, match="does not match the signer"):
        rfc3161.inspect_token(LocalTSA().token(digest, ess="wrong"), digest)


def test_refused_response():
    refused = der.seq(der.seq(der.integer(2)))
    with pytest.raises(VerificationError, match="refused"):
        rfc3161.token_from_response(refused)


@pytest.mark.parametrize("data", [b"", b"\x30", b"\x30\x05\x02\x01", b"\x30\x00\x00"])
def test_der_rejects_garbage(data):
    with pytest.raises(VerificationError):
        der.parse(data)


def test_oid_roundtrip():
    for dotted in ("1.2.840.113549.1.9.16.1.4", "2.16.840.1.101.3.4.2.1", "1.3.6.1.5.5.7.3.8"):
        assert der.as_oid(der.parse(der.oid(dotted))) == dotted
