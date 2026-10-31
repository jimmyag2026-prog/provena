"""A local RFC 3161 TSA for tests: builds real CMS SignedData time-stamp tokens."""

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from provena.core import der
from provena.core.rfc3161 import (
    OID_CONTENT_TYPE,
    OID_MESSAGE_DIGEST,
    OID_SHA256,
    OID_SIGNED_DATA,
    OID_SIGNING_CERT_V2,
    OID_TSTINFO,
)


class LocalTSA:
    def __init__(self, *, eku=True):
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Provena Test TSA")])
        now = dt.datetime.now(dt.UTC)
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(self.key.public_key()).serial_number(4242)
                   .not_valid_before(now - dt.timedelta(days=1))
                   .not_valid_after(now + dt.timedelta(days=365)))
        if eku:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        self.cert = builder.sign(self.key, hashes.SHA256())
        self.serial = 1

    def token(self, digest: bytes, *, when=None, tamper_attr=False, ess="good") -> bytes:
        when = when or dt.datetime.now(dt.UTC)
        self.serial += 1
        tst = der.seq(
            der.integer(1), der.oid("1.2.3.4"),
            der.seq(der.seq(der.oid(OID_SHA256), der.null()), der.octets(digest)),
            der.integer(self.serial),
            der.tlv(der.GENERALIZED_TIME, when.strftime("%Y%m%d%H%M%SZ").encode()))
        h = hashes.Hash(hashes.SHA256())
        h.update(tst)
        md = h.finalize()
        if tamper_attr:
            md = bytes(32)
        attrs = [der.seq(der.oid(OID_CONTENT_TYPE), der.set_of(der.oid(OID_TSTINFO))),
                 der.seq(der.oid(OID_MESSAGE_DIGEST), der.set_of(der.octets(md)))]
        if ess != "absent":
            h = hashes.Hash(hashes.SHA256())
            h.update(self.cert.public_bytes(Encoding.DER) if ess == "good" else b"other cert")
            ess_v2 = der.seq(der.seq(der.seq(der.octets(h.finalize()))))  # certs[0].certHash
            attrs.append(der.seq(der.oid(OID_SIGNING_CERT_V2), der.set_of(ess_v2)))
        signed_set = der.set_of(*attrs)
        sig = self.key.sign(signed_set, ec.ECDSA(hashes.SHA256()))
        issuer_serial = der.seq(self.cert.issuer.public_bytes(), der.integer(4242))
        signer_info = der.seq(
            der.integer(1), issuer_serial, der.seq(der.oid(OID_SHA256), der.null()),
            bytes([0xA0]) + signed_set[1:],
            der.seq(der.oid("1.2.840.10045.4.3.2")), der.octets(sig))
        signed_data = der.seq(
            der.integer(3), der.set_of(der.seq(der.oid(OID_SHA256), der.null())),
            der.seq(der.oid(OID_TSTINFO), der.explicit(0, der.octets(tst))),
            bytes([0xA0]) + der.seq(self.cert.public_bytes(Encoding.DER))[1:],
            der.set_of(signer_info))
        return der.seq(der.oid(OID_SIGNED_DATA), der.explicit(0, signed_data))

    def respond(self, request: bytes) -> bytes:
        req = der.parse(request)
        digest = req.child(1).child(1).content
        return der.seq(der.seq(der.integer(0)), self.token(digest))
