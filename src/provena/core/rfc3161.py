"""RFC 3161 time-stamp tokens: request encoding and offline token verification.

verify checks: the token is CMS SignedData over a TSTInfo; the TSTInfo's message imprint is
SHA-256 of our digest; the signed attributes carry the TSTInfo's hash; the signature verifies
under the embedded TSA certificate, which must be marked for time stamping and valid at genTime.
Chain-of-trust to a TSA root is reported (subject + fingerprint), not decided, here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from provena.core import der
from provena.core.errors import VerificationError

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"     # ESSCertID (SHA-1), RFC 2634
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"  # ESSCertIDv2, RFC 5035 / RFC 5816
HASHES = {
    "1.3.14.3.2.26": hashes.SHA1, OID_SHA256: hashes.SHA256,
    "2.16.840.1.101.3.4.2.2": hashes.SHA384, "2.16.840.1.101.3.4.2.3": hashes.SHA512,
}


@dataclass(frozen=True)
class TokenInfo:
    time_ms: int
    serial: int
    tsa_subject: str
    tsa_fingerprint: str


def make_request(digest: bytes, nonce: int) -> bytes:
    imprint = der.seq(der.seq(der.oid(OID_SHA256), der.null()), der.octets(digest))
    return der.seq(der.integer(1), imprint, der.integer(nonce), der.boolean(True))


def token_from_response(response: bytes) -> bytes:
    root = der.parse(response)
    status = der.as_int(root.child(0).child(0))
    if status not in (0, 1):  # granted, grantedWithMods
        raise VerificationError(f"TSA refused the request (status {status})")
    return root.child(1).raw


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise VerificationError(f"rfc3161: {msg}")


def _gen_time(node: der.Node) -> int:
    _need(node.tag == der.GENERALIZED_TIME, "genTime missing")
    text = node.content.decode("ascii")
    _need(text.endswith("Z"), "genTime must be UTC")
    main, _, frac = text[:-1].partition(".")
    dt = datetime.strptime(main, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    return int(dt.timestamp() * 1000) + (int((frac + "000")[:3]) if frac else 0)


def _hash(oid: str):
    _need(oid in HASHES, f"unsupported digest algorithm {oid}")
    return HASHES[oid]()


def inspect_token(token: bytes, digest: bytes) -> TokenInfo:
    ci = der.parse(token)
    _need(der.as_oid(ci.child(0)) == OID_SIGNED_DATA, "not CMS SignedData")
    sd = ci.child(1).child(0)
    parts = sd.children()
    encap = parts[2]
    _need(der.as_oid(encap.child(0)) == OID_TSTINFO, "content is not a TSTInfo")
    tst_der = encap.child(1).child(0).content
    certs = [x509.load_der_x509_certificate(n.raw) for p in parts[3:-1] if p.tag == 0xA0
             for n in p.children()]
    signer_info = parts[-1].child(0)
    si = signer_info.children()
    _need(si[3].tag == 0xA0, "signed attributes required")
    digest_alg = der.as_oid(si[2].child(0))
    signed_attrs = si[3]
    signature = si[5].content

    # TSTInfo binds our digest and the time
    tst = der.parse(tst_der).children()
    imprint = tst[2]
    _need(der.as_oid(imprint.child(0).child(0)) == OID_SHA256, "imprint must be SHA-256")
    _need(imprint.child(1).content == digest, "token is for a different digest")
    serial = der.as_int(tst[3])
    time_ms = _gen_time(tst[4])

    # signed attributes bind the TSTInfo
    attrs = {der.as_oid(a.child(0)): a.child(1).child(0) for a in signed_attrs.children()}
    _need(OID_MESSAGE_DIGEST in attrs, "messageDigest attribute missing")
    h = hashes.Hash(_hash(digest_alg))
    h.update(tst_der)
    _need(attrs[OID_MESSAGE_DIGEST].content == h.finalize(), "messageDigest mismatch")
    if OID_CONTENT_TYPE in attrs:
        _need(der.as_oid(attrs[OID_CONTENT_TYPE]) == OID_TSTINFO, "contentType mismatch")

    cert = _signer_cert(si[1], certs)
    _check_ess_cert_id(attrs, cert)
    signed = bytes([der.SET]) + signed_attrs.raw[1:]  # [0] IMPLICIT -> SET OF for signing
    pub = cert.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, signed, padding.PKCS1v15(), _hash(digest_alg))
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, signed, ec.ECDSA(_hash(digest_alg)))
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(signature, signed)
        else:
            raise VerificationError("rfc3161: unsupported TSA key type")
    except InvalidSignature as exc:
        raise VerificationError("rfc3161: TSA signature invalid") from exc

    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise VerificationError("rfc3161: TSA certificate lacks extendedKeyUsage") from exc
    _need(ExtendedKeyUsageOID.TIME_STAMPING in eku, "certificate not issued for time stamping")
    at = datetime.fromtimestamp(time_ms / 1000, tz=UTC)
    _need(cert.not_valid_before_utc <= at <= cert.not_valid_after_utc,
          "genTime outside the TSA certificate's validity")
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    subject = f"CN={cn[0].value!s}" if cn else cert.subject.rfc4514_string()
    return TokenInfo(time_ms, serial, subject,
                     hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest())


def _check_ess_cert_id(attrs: dict, cert: x509.Certificate) -> None:
    """The signed attributes must name the signing certificate by hash (RFC 3161 §2.4.1),
    so a token cannot be re-attributed to a different certificate with the same key."""
    if OID_SIGNING_CERT_V2 in attrs:
        first = attrs[OID_SIGNING_CERT_V2].child(0).child(0)  # certs[0]: ESSCertIDv2
        fields = first.children()
        alg = OID_SHA256
        if fields[0].tag == der.SEQUENCE:  # optional hashAlgorithm
            alg = der.as_oid(fields[0].child(0))
            fields = fields[1:]
        expected = fields[0].content
    elif OID_SIGNING_CERT in attrs:
        alg = "1.3.14.3.2.26"
        expected = attrs[OID_SIGNING_CERT].child(0).child(0).child(0).content
    else:
        raise VerificationError("rfc3161: signingCertificate attribute missing")
    h = hashes.Hash(_hash(alg))
    h.update(cert.public_bytes(Encoding.DER))
    _need(h.finalize() == expected, "signingCertificate does not match the signer certificate")


def _signer_cert(sid: der.Node, certs: list[x509.Certificate]) -> x509.Certificate:
    _need(bool(certs), "token carries no certificate (request certReq=true)")
    if sid.tag == der.SEQUENCE:  # IssuerAndSerialNumber
        issuer, serial = sid.child(0).raw, der.as_int(sid.child(1))
        for c in certs:
            if c.serial_number == serial and c.issuer.public_bytes() == issuer:
                return c
    elif sid.tag == 0x80:  # [0] SubjectKeyIdentifier
        for c in certs:
            try:
                ski = c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            except x509.ExtensionNotFound:
                continue
            if ski.digest == sid.content:
                return c
    raise VerificationError("rfc3161: signer certificate not found in token")


