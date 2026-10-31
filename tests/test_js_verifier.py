"""The browser verifier must agree with the Python verifier on every case."""

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from provena.core import builders, entries, merkle
from provena.core.anchor import root_of_roots, self_stamp
from provena.core.bundle import make_bundle
from provena.core.keys import AgentKey
from provena.core.treehead import make_head
from provena.core.verify import verify_bundle
from provena.core.witness import cosign
from tests.test_bundle import experiment  # noqa: F401 (fixture)

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _cases(lab):
    hub, witness = AgentKey.generate(), AgentKey.generate()
    hub_card, w_card = hub.make_card("hub", "hub"), witness.make_card("org", "w")
    plan = lab.put_plan(lab.owner)
    raw = lab.put_entity(lab.owner, b"raw\n")
    out = lab.put_entity(lab.owner, b"out\n", name="out.txt")
    act = lab.add(builders.activity(lab.state, lab.owner, used=[raw], generated=[out],
                                    plan_ref=plan))
    reviewer = lab.join("reviewer")
    lab.add(builders.attest(lab.state, reviewer, out, type="review", verdict="pass"))
    leaves = [entries.entry_leaf(e) for e in lab.log]
    anchored_head = make_head(hub, lab.state.project, leaves[:4])
    root, ordered = root_of_roots([anchored_head])
    anchor = {"anchor": {"v": 1, "provider": "self", "digest": root.hex(), "size": 1,
                         "time": 1, "receipt": self_stamp(hub, root, 1700000000000)},
              "head": anchored_head, "index": 0, "proof": [], "log_card": hub_card}
    head = make_head(hub, lab.state.project, leaves)
    s = lab.secrets[out]
    opening = {out: {"salt": s.salt.hex(), "plain_sha256": s.plain_sha256.hex()}}
    cases = {
        "selective": make_bundle(lab.log, head, hub_card, [act], openings=opening,
                                 contents={out: b"out\n"},
                                 cosignatures=[{"cosig": cosign(witness, head, 5),
                                                "card": w_card}],
                                 anchors=[anchor]),
        "full": make_bundle(lab.log, head, hub_card, [out], mode="full"),
        "older_cosig": make_bundle(lab.log, head, hub_card, [raw],
                                   cosignatures=[{"cosig": cosign(witness, anchored_head, 5),
                                                  "card": w_card, "head": anchored_head,
                                                  "log_card": hub_card}]),
        "self_signed": make_bundle(lab.log, make_head(lab.owner, lab.state.project, leaves),
                                   lab.owner.make_card("person"), [raw]),
    }
    base = cases["selective"]
    for name, mutate in {
        "bad_entry": lambda b: b["entries"][2]["entry"].update(ts=7),
        "bad_head": lambda b: b["head"].update(time=b["head"]["time"] + 1),
        "bad_proof": lambda b: b["entries"][-1]["proof"].__setitem__(0, "00" * 32),
        "bad_content": lambda b: next(iter(b["openings"].values())).update(content="AAAA"),
        "bad_cosig": lambda b: b["cosignatures"][0]["cosig"].update(time=6),
        "bad_anchor": lambda b: b["anchors"][0]["anchor"]["receipt"].update(time=2),
    }.items():
        mutated = copy.deepcopy(base)
        mutate(mutated)
        cases[name] = mutated
    assert merkle.root(leaves).hex() == head["root"] and ordered
    cases["untrusted"] = copy.deepcopy(base)  # same bundle, verified with no trust sets
    trust = {"logs": [hub.id], "witnesses": [witness.id]}
    return cases, trust


def _run_node(tmp_path, payload):
    task = tmp_path / "task.json"
    task.write_text(json.dumps(payload))
    proc = subprocess.run(["node", str(ROOT / "tests" / "js" / "run.mjs"), str(task)],
                          capture_output=True, text=True, check=True)
    return json.loads(proc.stdout)


def _rfc3161_case(lab, tsa):
    """A bundle whose head is anchored by an RFC 3161 token from *tsa*."""
    from provena.core.encoding import b64u
    from provena.core.rfc3161 import make_request, token_from_response

    hub = AgentKey.generate()
    hub_card = hub.make_card("hub", "hub")
    raw = lab.put_entity(lab.owner, b"raw\n")
    leaves = [entries.entry_leaf(e) for e in lab.log]
    head = make_head(hub, lab.state.project, leaves)
    root, _ = root_of_roots([head])
    token = token_from_response(tsa.respond(make_request(root, 1)))
    anchor = {"anchor": {"v": 1, "provider": "rfc3161", "digest": root.hex(), "size": 1,
                         "time": 1, "receipt": {"token": b64u(token), "tsa": "local"}},
              "head": head, "index": 0, "proof": [], "log_card": hub_card}
    return make_bundle(lab.log, head, hub_card, [raw], anchors=[anchor])


def test_js_rfc3161(lab, tmp_path):
    import hashlib

    from cryptography.hazmat.primitives.serialization import Encoding

    from provena.core import hashing
    from tests.tsa_fixture import LocalTSA

    anchor_tsa = LocalTSA()
    bundle = _rfc3161_case(lab, anchor_tsa)
    hub_id = bundle["head"]["signer"]
    fp = hashlib.sha256(anchor_tsa.cert.public_bytes(Encoding.DER)).hexdigest()
    trust_js = {"trustedLogs": [hub_id], "trustedTsas": [fp]}
    tsa = LocalTSA()
    digest_b = hashing.sha256(b"ess")
    wrong_ess = tsa.token(digest_b, ess="wrong").hex()
    tampered = copy.deepcopy(bundle)
    tampered["anchors"][0]["anchor"]["digest"] = "00" * 32
    real = (ROOT / "tests" / "vectors" / "freetsa_token.der").read_bytes().hex()
    digest = hashing.sha256(b"provena rfc3161 test vector").hex()
    out = _run_node(tmp_path, {
        "vectors": json.loads((ROOT / "tests" / "vectors" / "core.json").read_text()),
        "bundles": {"anchored": bundle, "tampered": tampered, "no_tsa_trust": bundle},
        "options": {"anchored": trust_js, "tampered": trust_js,
                    "no_tsa_trust": {"trustedLogs": [hub_id]}},
        "tokens": {"freetsa": {"token": real, "digest": digest},
                   "freetsa_wrong_digest": {"token": real, "digest": "00" * 32},
                   "wrong_ess": {"token": wrong_ess, "digest": digest_b.hex()}}})
    assert "signingCertificate" in out["tokens"]["wrong_ess"]["error"]
    assert out["tokens"]["freetsa"] == {"ok": True, "time": 1793381476000,
                                        "subject": "CN=www.freetsa.org"}
    assert not out["tokens"]["freetsa_wrong_digest"]["ok"]
    py = verify_bundle(bundle, trusted_logs={hub_id}, trusted_tsas={fp})
    assert py.ok and py.trust == "anchored"
    assert out["results"]["no_tsa_trust"]["trust"] == "log-sequenced"
    assert out["results"]["anchored"]["ok"] and out["results"]["anchored"]["trust"] == "anchored"
    assert not out["results"]["tampered"]["ok"] and not verify_bundle(tampered).ok


def test_js_rejects_harking_claim(lab, tmp_path):
    from tests.conftest import Lab
    from tests.test_bundle import harking_bundle

    vectors = json.loads((ROOT / "tests" / "vectors" / "core.json").read_text())
    out = _run_node(tmp_path, {"vectors": vectors, "bundles": {"h": harking_bundle(Lab())}})
    r = out["results"]["h"]
    assert r["ok"] and not any("preregistration holds" in f for f in r["facts"])


def test_js_agrees_with_python(lab, tmp_path):
    cases, trust = _cases(lab)
    vectors = json.loads((ROOT / "tests" / "vectors" / "core.json").read_text())
    js_opts = {n: {"trustedLogs": trust["logs"], "trustedWitnesses": trust["witnesses"]}
               for n in cases if n != "untrusted"}
    out = _run_node(tmp_path, {"vectors": vectors, "bundles": cases, "options": js_opts})
    assert all(out["checks"].values()), out["checks"]
    for name, bundle in cases.items():
        py_opts = {} if name == "untrusted" else {"trusted_logs": set(trust["logs"]),
                                                  "trusted_witnesses": set(trust["witnesses"])}
        py = verify_bundle(bundle, **py_opts)
        js = out["results"][name]
        assert js["ok"] == py.ok, (name, js["errors"], py.errors)
        if py.ok:
            assert js["trust"] == py.trust, name
            assert js["preregistration"] == py.preregistration, name
    assert out["results"]["selective"]["trust"] == "witnessed"
    assert out["results"]["older_cosig"]["trust"] == "witnessed"
    assert out["results"]["untrusted"]["trust"] == "unverified"
    facts = "\n".join(out["results"]["selective"]["facts"])
    assert "preregistration holds" in facts and "matches its commitment" in facts


def test_js_review2_cases(tmp_path):
    """Regressions from the second review, checked in both verifiers."""
    from tests.conftest import Lab

    # (C) an outsider smuggles a foreign genesis in at index 1 to introduce their own key
    lab = Lab()
    target = lab.put_entity(lab.owner, b"x\n")
    outsider = AgentKey.generate()
    foreign_genesis, _ = builders.new_project(outsider, outsider.make_card("person"))
    attest = entries.build(outsider, "attest", project=lab.state.project, refs=[target],
                           body={"target": target, "type": "endorse", "verdict": "pass"})
    log = [lab.log[0], foreign_genesis, lab.state.entries[target], attest]
    head = make_head(outsider, lab.state.project, [entries.entry_leaf(e) for e in log])
    smuggled = make_bundle(log, head, outsider.make_card("person"),
                           [entries.entry_hash(attest)], lineage=False)

    # (2) reordered self-signed log claiming preregistration
    lab2 = Lab()
    data = lab2.put_entity(lab2.owner, b"result\n", name="r.csv")
    plan = lab2.put_plan(lab2.owner)
    act = entries.build(lab2.owner, "activity", project=lab2.state.project, prev=plan,
                        refs=[data, plan], body={"used": [], "generated": [data], "plan": plan})
    order = [lab2.log[0], lab2.state.entries[plan], lab2.state.entries[data], act]
    head2 = make_head(lab2.owner, lab2.state.project, [entries.entry_leaf(e) for e in order])
    reordered = make_bundle(order, head2, lab2.owner.make_card("person"),
                            [entries.entry_hash(act)])

    vectors = json.loads((ROOT / "tests" / "vectors" / "core.json").read_text())
    out = _run_node(tmp_path, {"vectors": vectors,
                               "bundles": {"smuggled": smuggled, "reordered": reordered}})
    for name, bundle in (("smuggled", smuggled), ("reordered", reordered)):
        py, js = verify_bundle(bundle), out["results"][name]
        assert js["ok"] == py.ok, (name, js, py.errors)
        assert not any("preregistration holds" in f for f in js["facts"])
    assert not out["results"]["smuggled"]["ok"]


def _rule_corpus():
    """Full bundles over logs that each break one state-machine rule (built bypassing the
    state machine), plus one valid log exercising every kind."""
    from tests.conftest import Lab

    def finish(lab, extra):
        log = lab.log + extra
        head = make_head(lab.owner, lab.state.project, [entries.entry_leaf(e) for e in log])
        tgt = entries.entry_hash(log[-1])
        return make_bundle(log, head, lab.owner.make_card("person"), [tgt], mode="full")

    def raw(lab, author, kind, body, refs=(), prev="auto", sealed=None):
        return entries.build(author, kind, project=lab.state.project,
                             prev=lab.state.heads.get(author.id) if prev == "auto" else prev,
                             refs=list(refs), body=body, sealed=sealed)

    cases = {}
    # valid: every kind, membership changes, rotation, succession
    lab = Lab()
    rev, con = lab.join("reviewer"), lab.join("contributor")
    plan = lab.put_plan(lab.owner)
    data = lab.put_entity(con, b"d\n")
    out = lab.put_entity(con, b"o\n", name="o")
    lab.add(builders.activity(lab.state, con, used=[data], generated=[out], plan_ref=plan))
    lab.add(builders.attest(lab.state, rev, out, type="replicate", verdict="pass"))
    s = lab.secrets[plan]
    lab.add(builders.reveal(lab.state, lab.owner, plan, salt=s.salt, plain_sha256=s.plain_sha256))
    lab.add(builders.meta(lab.state, lab.owner, title="t", tags=["x"]))
    other = AgentKey.generate()
    so = lab.secrets[out]
    lab.add(builders.grant(lab.state, con, out, other.make_card("person"), dek=so.dek,
                           salt=so.salt, plain_sha256=so.plain_sha256, name="o"))
    e, _ = builders.member_remove(lab.state, lab.owner, rev.id)
    lab.add(e)
    e, _ = builders.rotate(lab.state, lab.owner)
    lab.add(e)
    lab.add(builders.redact(lab.state, con, data, reason="consent"))
    succ = AgentKey.generate()
    lab.add(builders.succeed(lab.state, con, succ.make_card("person")))
    last = lab.put_entity(succ, b"after succession\n", name="z")
    assert last
    cases["valid"] = finish(lab, [])

    def fresh():
        lab = Lab()
        return lab, lab.join("contributor"), lab.join("viewer"), lab.join("maintainer")

    lab, con, viewer, maint = fresh()
    stranger = AgentKey.generate()
    cases["non_member"] = finish(lab, [entries.build(stranger, "plan", project=lab.state.project,
                                                     body={"commitment": "00" * 32})])
    lab, con, viewer, maint = fresh()
    body, sec, size = lab.content(viewer, b"v")
    cases["viewer_entity"] = finish(lab, [builders.entity(lab.state, viewer, body, sec, name="v",
                                                          plain_size=size)])
    lab, con, viewer, maint = fresh()
    cases["prev_gap"] = finish(lab, [raw(lab, lab.owner, "plan", {"commitment": "00" * 32},
                                         prev="ab" * 32)])
    lab, con, viewer, maint = fresh()
    cases["maint_adds_owner"] = finish(lab, [builders.member_add(
        lab.state, maint, AgentKey.generate().make_card("person"), "owner")])
    lab, con, viewer, maint = fresh()
    rot, _ = builders.rotate(lab.state, lab.owner)
    wraps = dict(rot["body"]["wraps"])
    wraps.popitem()
    cases["rotate_missing_wrap"] = finish(lab, [raw(lab, lab.owner, "key", {
        "action": "rotate", "epoch": 1, "wraps": wraps})])
    lab, con, viewer, maint = fresh()
    p = lab.put_plan(lab.owner)
    cases["bad_reveal"] = finish(lab, [builders.reveal(lab.state, lab.owner, p, salt=bytes(32),
                                                       plain_sha256=bytes(32))])
    lab, con, viewer, maint = fresh()
    d = lab.put_entity(lab.owner)
    dup = dict(lab.state.entries[d]["body"])
    cases["duplicate_cid"] = finish(lab, [builders.entity(lab.state, con, dup, lab.secrets[d],
                                                          name="dup", plain_size=1)])
    lab, con, viewer, maint = fresh()
    p = lab.put_plan(con)
    d = lab.put_entity(lab.owner)
    cases["squat"] = finish(lab, [builders.activity(lab.state, con, generated=[d], plan_ref=p)])
    lab, con, viewer, maint = fresh()
    d = lab.put_entity(lab.owner)
    p = lab.put_plan(lab.owner)
    cases["output_before_plan"] = finish(lab, [builders.activity(lab.state, lab.owner,
                                                                 generated=[d], plan_ref=p)])
    lab, con, viewer, maint = fresh()
    cases["meta_by_contributor"] = finish(lab, [builders.meta(lab.state, con, title="x")])
    lab, con, viewer, maint = fresh()
    rm, _ = builders.member_remove(lab.state, lab.owner, con.id)
    lab.add(rm)
    cases["removed_writes"] = finish(lab, [raw(lab, con, "plan", {"commitment": "00" * 32})])
    lab, con, viewer, maint = fresh()
    cases["last_owner_demoted"] = finish(lab, [builders.member_role(lab.state, lab.owner,
                                                                    lab.owner.id, "viewer")])
    lab, con, viewer, maint = fresh()
    own = lab.put_entity(lab.owner, b"own", name="own")
    cases["external_own_project"] = finish(lab, [raw(lab, lab.owner, "activity", {
        "used": [own], "generated": [], "plan": None,
        "external": [{"project": lab.state.project, "entry": own}]}, refs=[own])])
    lab, con, viewer, maint = fresh()
    cases["external_bad_shape"] = finish(lab, [raw(lab, lab.owner, "activity", {
        "used": [], "generated": [], "plan": None, "external": [{"project": "x"}]})])
    for name, field in (("bool_epoch", "epoch"), ("bool_size", "size")):
        lab, con, viewer, maint = fresh()
        body, sec, size = lab.content(lab.owner, b"b")
        body[field] = True if field == "epoch" else True
        cases[name] = finish(lab, [builders.entity(lab.state, lab.owner, body, sec, name="b",
                                                   plain_size=size)])
    return cases


def test_js_full_replay_agrees_on_rule_corpus(tmp_path):
    cases = _rule_corpus()
    vectors = json.loads((ROOT / "tests" / "vectors" / "core.json").read_text())
    out = _run_node(tmp_path, {"vectors": vectors, "bundles": cases})
    for name, bundle in cases.items():
        py = verify_bundle(bundle)
        js = out["results"][name]
        assert py.ok == (name == "valid"), (name, py.errors)
        assert js["ok"] == py.ok, (name, js["errors"], py.errors)


def _resign(author, entry):
    """Sign an entry exactly as given, bypassing entries.build's shape check."""
    from provena.core.canonical import canonicalize
    from provena.core.hashing import TAG_ENTRY_SIG

    unsigned = {k: v for k, v in entry.items() if k != "sig"}
    return {**unsigned, "sig": author.sign(TAG_ENTRY_SIG, canonicalize(unsigned)).hex()}


def test_js_shape_and_meta_parity(tmp_path):
    """Regression (review 3 #5, #6): JS accepted malformed shapes Python rejects, and counted
    string lengths in UTF-16 units."""
    from tests.conftest import Lab

    cases = {}

    def full(lab, extra):
        log = lab.log + extra
        head = make_head(lab.owner, lab.state.project, [entries.entry_leaf(e) for e in log])
        return make_bundle(log, head, lab.owner.make_card("person"),
                           [entries.entry_hash(log[-1])], mode="full")

    mutations = {
        "ts_string": {"ts": "1"}, "ts_negative": {"ts": -1}, "ts_bool": {"ts": True},
        "sealed_object": {"sealed": {"x": 1}}, "refs_string": {"refs": ""},
        "body_array": {"body": []},
    }
    for name, change in mutations.items():
        lab = Lab()
        base = entries.build(lab.owner, "plan", project=lab.state.project,
                             prev=lab.state.heads[lab.owner.id], body={"commitment": "00" * 32})
        cases[name] = full(lab, [_resign(lab.owner, {**base, **change})])
    lab = Lab()
    cases["meta_proto_keys"] = full(lab, [_resign(lab.owner, entries.build(
        lab.owner, "meta", project=lab.state.project, prev=lab.state.heads[lab.owner.id],
        body={"title": "x"}) | {"body": {"constructor": 1, "toString": "x"}})])
    lab = Lab()
    lab.add(builders.meta(lab.state, lab.owner, title="\U0001f9ea" * 150))  # 150 code points
    cases["valid_emoji_title"] = full(lab, [])

    vectors = json.loads((ROOT / "tests" / "vectors" / "core.json").read_text())
    out = _run_node(tmp_path, {"vectors": vectors, "bundles": cases})
    for name, bundle in cases.items():
        py, js = verify_bundle(bundle), out["results"][name]
        assert py.ok == (name == "valid_emoji_title"), (name, py.errors)
        assert js["ok"] == py.ok, (name, js["errors"], py.errors)


def test_js_checks_supplied_content_like_python(experiment_lab, tmp_path):
    from provena.core.encoding import b64u

    b, result, raw = experiment_lab
    cases = {"good": b, "fake": b, "unopened": b}
    supplied = {"good": {result: b"Kd=7nM\n"}, "fake": {result: b"fake"},
                "unopened": {raw: b"OD600\n0.41\n"}}
    vectors = json.loads((ROOT / "tests" / "vectors" / "core.json").read_text())
    out = _run_node(tmp_path, {"vectors": vectors, "bundles": cases, "options": {
        n: {"contentsB64": {h: b64u(c) for h, c in supplied[n].items()}} for n in cases}})
    for name in cases:
        py = verify_bundle(b, external_contents=supplied[name])
        assert out["results"][name]["ok"] == py.ok, (name, out["results"][name]["errors"])
    assert [out["results"][n]["ok"] for n in cases] == [True, False, False]



@pytest.fixture
def experiment_lab(experiment):  # noqa: F811 (fixture argument)
    from tests.test_bundle import HUB_CARD, _head, _opening

    lab, h = experiment
    b = make_bundle(lab.log, _head(lab), HUB_CARD, [h["activity"]],
                    openings={h["result"]: _opening(lab, h["result"])},
                    contents={h["result"]: b"Kd=7nM\n"})
    return b, h["result"], h["raw"]
