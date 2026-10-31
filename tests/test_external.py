"""Inputs from other projects: activity.external + attached bundles."""

import copy
import json
import shutil

import pytest

from provena.core import builders, entries
from provena.core.bundle import make_bundle
from provena.core.errors import VerificationError
from provena.core.keys import AgentKey
from provena.core.treehead import make_head
from provena.core.verify import verify_bundle
from tests.conftest import Lab

HUB = AgentKey.generate()
HUB_CARD = HUB.make_card("hub", "hub")


def _hub_bundle(lab, targets, **kw):
    head = make_head(HUB, lab.state.project, [entries.entry_leaf(e) for e in lab.log])
    return make_bundle(lab.log, head, HUB_CARD, targets, **kw)


@pytest.fixture
def two_labs():
    a, b = Lab(), Lab()                                  # lab A publishes a dataset
    dataset = a.put_entity(a.owner, b"public reference set\n", name="ref.csv")
    out = b.put_entity(b.owner, b"analysis\n", name="out.csv")
    act = b.add(builders.activity(b.state, b.owner, generated=[out],
                                  external=[(a.state.project, dataset)]))
    return a, b, dataset, act


def test_external_input_proven_by_attached_bundle(two_labs):
    a, b, dataset, act = two_labs
    sub = _hub_bundle(a, [dataset])
    bundle = _hub_bundle(b, [act], external=[sub])
    report = verify_bundle(bundle, trusted_logs={HUB.id})
    assert report.ok, report.errors
    assert any("used entry" in f and dataset[:12] in f for f in report.facts)
    unproven = verify_bundle(_hub_bundle(b, [act]), trusted_logs={HUB.id})
    assert unproven.ok and any("no attached bundle proves it" in n for n in unproven.notes)
    untrusted = verify_bundle(bundle)
    assert not any("used entry" in f for f in untrusted.facts)


def test_tampered_or_nested_external_rejected(two_labs):
    a, b, dataset, act = two_labs
    sub = _hub_bundle(a, [dataset])
    bad = copy.deepcopy(sub)
    bad["entries"][-1]["entry"]["ts"] += 1
    assert not verify_bundle(_hub_bundle(b, [act], external=[bad]), trusted_logs={HUB.id}).ok
    nested = copy.deepcopy(sub)
    nested["external"] = [copy.deepcopy(sub)]
    assert not verify_bundle(_hub_bundle(b, [act], external=[nested])).ok


def test_external_must_point_to_another_project(two_labs):
    _, b, _, _ = two_labs
    own = b.put_entity(b.owner, b"x", name="x")
    with pytest.raises(VerificationError, match="other projects"):
        b.add(builders.activity(b.state, b.owner, generated=[],
                                used=[own], external=[(b.state.project, own)]))


def test_js_external_parity(two_labs, tmp_path):
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    from tests.test_js_verifier import ROOT, _run_node

    a, b, dataset, act = two_labs
    sub = _hub_bundle(a, [dataset])
    good = _hub_bundle(b, [act], external=[sub])
    bad = copy.deepcopy(good)
    bad["external"][0]["entries"][-1]["entry"]["ts"] += 1
    opts = {"trustedLogs": [HUB.id]}
    out = _run_node(tmp_path, {
        "vectors": json.loads((ROOT / "tests" / "vectors" / "core.json").read_text()),
        "bundles": {"good": good, "bad": bad}, "options": {"good": opts, "bad": opts}})
    py = verify_bundle(good, trusted_logs={HUB.id})
    assert out["results"]["good"]["ok"] and not out["results"]["bad"]["ok"]
    assert [f for f in out["results"]["good"]["facts"] if "used entry" in f] == [
        f for f in py.facts if "used entry" in f]


def test_review5_parity_cases(two_labs, tmp_path):
    """Regression (review 5 F3-F6): malformed relayed credentials, null receipts, prototype
    names in citations, citations of non-target lineage entries."""
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    from tests.test_js_verifier import ROOT, _run_node

    a, b, dataset, act = two_labs
    sub = _hub_bundle(a, [dataset])
    good = _hub_bundle(b, [act], external=[sub])
    cases = {
        "cred_bad_issuer": {**good, "credentials": [{"credential": {
            "v": 1, "issuer": "x", "subject": b.owner.id, "claims": {"name": "n"},
            "issued": 0, "expires": 1, "sig": "00"}, "issuer_card": "x"}]},
        "cred_list_subject": {**good, "credentials": [{"credential": {"subject": []},
                                                       "issuer_card": {}}]},
        "receipt_null": {**good, "entries": [{**good["entries"][0], "receipt": None},
                                             *good["entries"][1:]]},
    }
    expected = {"cred_bad_issuer": True, "cred_list_subject": True, "receipt_null": False}
    opts = {"trustedLogs": [HUB.id]}
    out = _run_node(tmp_path, {
        "vectors": json.loads((ROOT / "tests" / "vectors" / "core.json").read_text()),
        "bundles": cases, "options": {k: opts for k in cases}})
    for name, bundle in cases.items():
        py = verify_bundle(bundle, trusted_logs={HUB.id})
        assert py.ok == expected[name], (name, py.errors)
        assert out["results"][name]["ok"] == py.ok, (name, out["results"][name]["errors"])

    # an attached bundle whose targets do not include the cited entry proves nothing about it
    lineage_only = _hub_bundle(a, [a.put_entity(a.owner, b"later", name="later")])
    report = verify_bundle(_hub_bundle(b, [act], external=[lineage_only]),
                           trusted_logs={HUB.id})
    assert report.ok and not any("used entry" in f for f in report.facts)


def test_float_literals_rejected_by_both_verifiers(two_labs, tmp_path):
    """Red team: `1.0` in a signed integer field was VALID in the browser, INVALID in the CLI."""
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    from tests.test_js_verifier import ROOT, _run_node

    a, _, dataset, _ = two_labs
    good = _hub_bundle(a, [dataset])
    text = json.dumps(good)
    t = str(good["head"]["time"])
    floaty = text.replace(f'"time": {t}', f'"time": {t}.0', 1)
    assert floaty != text
    assert not verify_bundle(json.loads(floaty)).ok
    out = _run_node(tmp_path, {
        "vectors": json.loads((ROOT / "tests" / "vectors" / "core.json").read_text()),
        "bundles": {}, "texts": {"good": text, "floaty": floaty,
                                 "string_dots": json.dumps({**good, "note": "1.0 in a string"})},
        "options": {k: {"trustedLogs": [HUB.id]} for k in ("good", "floaty", "string_dots")}})
    assert out["results"]["good"]["ok"] and out["results"]["string_dots"]["ok"]
    assert not out["results"]["floaty"]["ok"]
