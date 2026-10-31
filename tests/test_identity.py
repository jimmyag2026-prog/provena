import copy
import json

import pytest

from provena.core import entries, identity
from provena.core.bundle import make_bundle
from provena.core.errors import VerificationError
from provena.core.keys import AgentKey
from provena.core.treehead import make_head
from provena.core.verify import verify_bundle

T0 = 1_800_000_000_000


@pytest.fixture
def org():
    key = AgentKey.generate()
    return key, key.make_card("org", "Example University")


def test_issue_and_verify(org):
    key, card = org
    subject = AgentKey.generate()
    cred = identity.issue(key, subject.id, {"name": "Ada Lovelace", "orcid": "0000-0002-1825-0097"},
                          issued=T0, expires=T0 + 1000)
    assert identity.verify(cred, card, at_ms=T0 + 1).id == key.id
    with pytest.raises(VerificationError, match="not valid"):
        identity.verify(cred, card, at_ms=T0 + 5000)
    tampered = copy.deepcopy(cred)
    tampered["claims"]["name"] = "Mallory"
    with pytest.raises(VerificationError):
        identity.verify(tampered, card, at_ms=T0 + 1)
    person = AgentKey.generate()
    with pytest.raises(VerificationError, match="org"):
        identity.verify(identity.issue(person, subject.id, {"name": "x"}, issued=T0,
                                       expires=T0 + 9), person.make_card("person"), at_ms=T0)
    with pytest.raises(VerificationError):
        identity.issue(key, subject.id, {"orcid": "1234"}, issued=T0, expires=T0 + 1)
    with pytest.raises(VerificationError):
        identity.issue(key, subject.id, {"name": "a\nb"}, issued=T0, expires=T0 + 1)


def _bundle(lab, org, at):
    key, card = org
    cred = identity.issue(key, lab.owner.id, {"name": "Ada Lovelace", "affiliation": "Chem"},
                          issued=at - 1000, expires=at + 1000)
    hub = AgentKey.generate()
    target = lab.put_entity(lab.owner)
    head = make_head(hub, lab.state.project, [entries.entry_leaf(e) for e in lab.log], at_ms=at)
    return make_bundle(lab.log, head, hub.make_card("hub"), [target],
                       credentials=[{"credential": cred, "issuer_card": card}]), hub


def test_bundle_identity_facts_follow_org_trust(lab, org):
    b, hub = _bundle(lab, org, T0)
    untrusted = verify_bundle(b, trusted_logs={hub.id})
    assert untrusted.ok and any("Ada Lovelace" in n for n in untrusted.notes)
    assert not any("Ada Lovelace" in f for f in untrusted.facts)
    trusted = verify_bundle(b, trusted_logs={hub.id}, trusted_orgs={org[0].id})
    assert any("Ada Lovelace" in f for f in trusted.facts)
    assert trusted.trust == untrusted.trust  # identity never changes the time trust level
    expired, _ = _bundle(lab, org, T0)
    expired["credentials"][0]["credential"]["expires"] = T0 - 1  # breaks the signature too
    broken = verify_bundle(expired, trusted_logs={hub.id}, trusted_orgs={org[0].id})
    assert broken.ok and any("not accepted" in n for n in broken.notes)  # reported, not fatal
    assert not any("Ada Lovelace" in f for f in broken.facts)


def test_credentials_need_a_trusted_head_time(lab, org):
    """Regression (review 4 #1): a throwaway-key head backdated into the validity window."""
    b, hub = _bundle(lab, org, T0)
    report = verify_bundle(b, trusted_orgs={org[0].id})        # head signer not trusted
    assert report.ok and report.trust == "unverified"
    assert not any("Ada Lovelace" in f for f in report.facts)
    assert any("not from a trusted log" in n for n in report.notes)


def test_bundles_only_carry_credentials_of_their_authors(lab, org):
    """Regression (review 4 #2): every member's credential leaked into every bundle."""
    key, card = org
    stranger = AgentKey.generate()
    cred = identity.issue(key, stranger.id, {"name": "Not In This Bundle"}, issued=T0,
                          expires=T0 + 10**9)
    b, _ = _bundle(lab, org, T0)
    rebuilt = make_bundle(lab.log, b["head"], b["head_signer"], b["targets"],
                          credentials=[*b["credentials"],
                                       {"credential": cred, "issuer_card": card}])
    assert [c["credential"]["subject"] for c in rebuilt["credentials"]] == [lab.owner.id]


def test_claims_reject_invisible_and_bool_times(org):
    key, _ = org
    for bad in ("Ada\u202eecalovoL", "A\u200bda", "x\ufeff"):
        with pytest.raises(VerificationError):
            identity.issue(key, "x", {"name": bad}, issued=T0, expires=T0 + 1)
    with pytest.raises(VerificationError):
        identity.issue(key, "x", {"name": "ok"}, issued=True, expires=T0)


def test_js_identity_parity(lab, org, tmp_path):
    import shutil

    if shutil.which("node") is None:
        pytest.skip("node not installed")
    from tests.test_js_verifier import ROOT, _run_node

    b, hub = _bundle(lab, org, T0)
    out = _run_node(tmp_path, {
        "vectors": json.loads((ROOT / "tests" / "vectors" / "core.json").read_text()),
        "bundles": {"cred": b},
        "options": {"cred": {"trustedLogs": [hub.id], "trustedOrgs": [org[0].id]}}})
    js = out["results"]["cred"]
    py = verify_bundle(b, trusted_logs={hub.id}, trusted_orgs={org[0].id})
    assert js["ok"] and py.ok
    assert [f for f in js["facts"] if "per org" in f] == [f for f in py.facts if "per org" in f]
