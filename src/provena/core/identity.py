"""Identity credentials: an organisation's agent key vouches for who holds another agent key.

    {"v": 1, "issuer": <org agent id>, "subject": <agent id>, "claims": {"name": …,
     "affiliation": …, "orcid": …}, "issued": ms, "expires": ms, "sig": …}

A credential is only as good as the verifier's trust in its issuer (`provena trust add org …`);
like every other trust decision (ADR 0007) the bundle cannot make it count on its own.
"""

from __future__ import annotations

import re

from provena.core.canonical import canonicalize
from provena.core.errors import VerificationError
from provena.core.hashing import TAG_CREDENTIAL
from provena.core.keys import AgentKey, AgentPublic, verify_card

FIELDS = ("v", "issuer", "subject", "claims", "issued", "expires")
CLAIMS = {"name": 200, "affiliation": 200, "orcid": 19, "email": 254, "role": 100}
ORCID = re.compile(r"\A\d{4}-\d{4}-\d{4}-\d{3}[\dX]\Z")


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise VerificationError(f"credential: {msg}")


# Bidi overrides/isolates and zero-width characters can make a displayed name lie.
_INVISIBLE = {*range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2066, 0x206A), 0xFEFF,
              0x2028, 0x2029}


def _plain(text: str) -> bool:
    """No control, bidi or zero-width characters. Deliberately not str.isprintable(), whose
    answer depends on the Unicode version and would split Python and JS verifiers."""
    return all(ord(c) >= 0x20 and not 0x7F <= ord(c) <= 0x9F and ord(c) not in _INVISIBLE
               for c in text)


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 2**53 - 1


def check_claims(claims) -> None:
    _need(isinstance(claims, dict) and claims and set(claims) <= set(CLAIMS), "unknown claims")
    for k, v in claims.items():
        _need(isinstance(v, str) and 0 < len(v) <= CLAIMS[k] and _plain(v), f"bad {k}")
    if "orcid" in claims:
        _need(bool(ORCID.match(claims["orcid"])), "malformed ORCID iD")


def issue(org: AgentKey, subject_id: str, claims: dict, *, issued: int, expires: int) -> dict:
    check_claims(claims)
    _need(_is_int(issued) and _is_int(expires) and expires > issued, "bad validity period")
    cred = {"v": 1, "issuer": org.id, "subject": subject_id, "claims": dict(claims),
            "issued": issued, "expires": expires}
    cred["sig"] = org.sign(TAG_CREDENTIAL, canonicalize(cred)).hex()
    return cred


def verify(cred: dict, issuer_card: dict, *, at_ms: int) -> AgentPublic:
    """Check signature, shape and validity at *at_ms* (the time the credential is used for,
    e.g. a trusted log head time). Returns the issuer key; trust is the caller's decision."""
    _need(isinstance(cred, dict) and set(cred) == {*FIELDS, "sig"} and cred["v"] == 1,
          "malformed")
    issuer = verify_card(issuer_card)
    _need(issuer.id == cred["issuer"], "issuer card does not match")
    _need(issuer_card.get("kind") == "org", "issuer must be an org agent")
    check_claims(cred["claims"])
    issuer.verify(TAG_CREDENTIAL, canonicalize({k: cred[k] for k in FIELDS}),
                  bytes.fromhex(cred["sig"]))
    _need(_is_int(cred["issued"]) and _is_int(cred["expires"]), "bad validity period")
    _need(cred["issued"] <= at_ms <= cred["expires"], "not valid at the time in question")
    return issuer
