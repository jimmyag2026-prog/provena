import copy

import pytest

from provena.core import builders, entries
from provena.core.bundle import make_bundle
from provena.core.keys import AgentKey
from provena.core.treehead import make_head
from provena.core.verify import TRUST_LOG, TRUST_SELF, verify_bundle

HUB = AgentKey.generate()
HUB_CARD = HUB.make_card("hub", "test-hub")


@pytest.fixture
def experiment(lab):
    tech = lab.join("contributor", kind="instrument")
    plan = lab.put_plan(lab.owner)
    raw = lab.put_entity(tech, b"OD600\n0.41\n")
    result = lab.put_entity(lab.owner, b"Kd=7nM\n", name="fit.json")
    act = lab.add(builders.activity(lab.state, lab.owner, used=[raw], generated=[result],
                                    plan_ref=plan))
    reviewer = lab.join("reviewer")
    lab.add(builders.attest(lab.state, reviewer, result, type="replicate", verdict="pass"))
    lab.put_entity(lab.owner, b"unrelated\n", name="other.csv")
    return lab, {"plan": plan, "raw": raw, "result": result, "activity": act}


def _head(lab, signer=HUB):
    return make_head(signer, lab.state.project, [entries.entry_leaf(e) for e in lab.log])


def _opening(lab, h):
    s = lab.secrets[h]
    return {"salt": s.salt.hex(), "plain_sha256": s.plain_sha256.hex()}


def test_selective_bundle_proves_lineage_and_prereg(experiment):
    lab, h = experiment
    b = make_bundle(lab.log, _head(lab), HUB_CARD, [h["activity"]],
                    openings={h["result"]: _opening(lab, h["result"])},
                    contents={h["result"]: b"Kd=7nM\n"})
    report = verify_bundle(b, trusted_logs={HUB.id})
    assert report.ok, report.errors
    assert report.trust == TRUST_LOG
    text = "\n".join(report.facts)
    assert "preregistration holds" in text
    assert "replicate attestation" in text
    assert "matches its commitment" in text
    proven = set(report.verified_entries)
    assert {h["plan"], h["raw"], h["result"], h["activity"]} <= proven
    assert len(proven) < len(lab.log)  # the unrelated entity stays out


def test_full_bundle_replays_everything(experiment):
    lab, h = experiment
    b = make_bundle(lab.log, _head(lab, lab.owner), lab.owner.make_card("person"),
                    [h["result"]], mode="full")
    report = verify_bundle(b)
    assert report.ok, report.errors
    assert report.trust == TRUST_SELF
    assert len(report.verified_entries) == len(lab.log)


def test_ledger_reveal_counts_as_opening(experiment):
    lab, h = experiment
    s = lab.secrets[h["plan"]]
    lab.add(builders.reveal(lab.state, lab.owner, h["plan"], salt=s.salt,
                            plain_sha256=s.plain_sha256))
    report = verify_bundle(make_bundle(lab.log, _head(lab), HUB_CARD, [h["plan"]]))
    assert report.ok, report.errors
    assert any("commitment of" in f for f in report.facts)


def _mutations(bundle):
    def entry_body(b):
        b["entries"][1]["entry"]["ts"] += 1

    def head_root(b):
        b["head"]["root"] = "00" * 32

    def head_time(b):
        b["head"]["time"] -= 86_400_000  # backdating the head breaks its signature

    def proof(b):
        b["entries"][-1]["proof"][0] = "11" * 32

    def index(b):
        b["entries"][-1]["index"] -= 1

    def drop_genesis(b):
        b["entries"].pop(0)

    def drop_author_intro(b):
        b["entries"] = [it for it in b["entries"]
                        if not (it["entry"]["kind"] == "member"
                                and it["entry"]["body"]["role"] == "contributor")]

    def wrong_salt(b):
        next(iter(b["openings"].values()))["salt"] = "22" * 32

    def wrong_content(b):
        next(iter(b["openings"].values()))["content"] = "AAAA"

    def foreign_target(b):
        b["targets"].append("ab" * 32)

    return [entry_body, head_root, head_time, proof, index, drop_genesis, drop_author_intro,
            wrong_salt, wrong_content, foreign_target]


@pytest.mark.parametrize("mutation", _mutations(None), ids=lambda f: f.__name__)
def test_any_tampering_fails(experiment, mutation):
    lab, h = experiment
    b = make_bundle(lab.log, _head(lab), HUB_CARD, [h["activity"]],
                    openings={h["result"]: _opening(lab, h["result"])},
                    contents={h["result"]: b"Kd=7nM\n"})
    assert verify_bundle(copy.deepcopy(b)).ok
    mutation(b)
    report = verify_bundle(b)
    assert not report.ok


def test_untrusted_log_is_unverified(experiment):
    lab, h = experiment
    b = make_bundle(lab.log, _head(lab), HUB_CARD, [h["raw"]])
    report = verify_bundle(b, trusted_logs={AgentKey.generate().id})
    assert report.ok and report.trust == "unverified"
    assert not any("existing no later than" in f for f in report.facts)


def test_head_must_cover_targets(experiment):
    lab, h = experiment
    old_head = make_head(HUB, lab.state.project, [entries.entry_leaf(e) for e in lab.log[:3]])
    with pytest.raises(ValueError):
        make_bundle(lab.log, old_head, HUB_CARD, [h["result"]])


def test_external_content_check(experiment):
    lab, h = experiment
    b = make_bundle(lab.log, _head(lab), HUB_CARD, [h["raw"]],
                    openings={h["raw"]: _opening(lab, h["raw"])})
    assert verify_bundle(b, external_contents={h["raw"]: b"OD600\n0.41\n"}).ok
    assert not verify_bundle(b, external_contents={h["raw"]: b"OD600\n0.99\n"}).ok


def harking_bundle(lab):
    """A log the state machine would reject (result before plan), sequenced by a log that
    does not validate: the verifier itself must refuse to call it preregistered."""
    result = lab.put_entity(lab.owner, b"Kd=7nM\n", name="result.csv")
    plan = lab.put_plan(lab.owner)
    act = entries.build(lab.owner, "activity", project=lab.state.project,
                        prev=lab.state.heads[lab.owner.id], refs=[result, plan],
                        body={"used": [], "generated": [result], "plan": plan})
    log = lab.log + [act]
    head = make_head(HUB, lab.state.project, [entries.entry_leaf(e) for e in log])
    return make_bundle(log, head, HUB_CARD, [entries.entry_hash(act)])


def test_verifier_rejects_harking_claim(lab):
    report = verify_bundle(harking_bundle(lab), trusted_logs={HUB.id})
    assert report.ok
    assert not any("preregistration holds" in f for f in report.facts)
    assert any("preregistration NOT shown" in n for n in report.notes)


def test_reordered_self_signed_bundle_cannot_claim_preregistration(lab):
    """Regression (re-review #2): data registered before the plan, re-sequenced by the author
    under a self-signed head as [genesis, plan, data, activity]."""
    data = lab.put_entity(lab.owner, b"result\n", name="r.csv")
    plan = lab.put_plan(lab.owner)
    gen, data_e, plan_e = lab.log[0], lab.state.entries[data], lab.state.entries[plan]
    act = entries.build(lab.owner, "activity", project=lab.state.project, prev=plan,
                        refs=[data, plan], body={"used": [], "generated": [data], "plan": plan})
    forged_order = [gen, plan_e, data_e, act]
    head = make_head(lab.owner, lab.state.project, [entries.entry_leaf(e) for e in forged_order])
    b = make_bundle(forged_order, head, lab.owner.make_card("person"), [entries.entry_hash(act)])
    report = verify_bundle(b)
    assert not report.ok or not any("preregistration holds" in f for f in report.facts)


def test_proving_a_result_includes_how_it_was_made(experiment):
    """The generating activity (which points at its outputs) and its inputs and plan travel
    with a bundle proving only the output."""
    lab, h = experiment
    b = make_bundle(lab.log, _head(lab), HUB_CARD, [h["result"]])
    proven = {entries.entry_hash(it["entry"]) for it in b["entries"]}
    assert {h["activity"], h["raw"], h["plan"]} <= proven
    report = verify_bundle(b, trusted_logs={HUB.id})
    assert any("preregistration holds" in f for f in report.facts)


def test_proving_one_output_does_not_disclose_siblings(lab):
    """Review 5 F7: walking back to the generating activity must not pull in its other
    outputs."""
    raw = lab.put_entity(lab.owner, b"in\n", name="in")
    out1 = lab.put_entity(lab.owner, b"o1\n", name="o1")
    out2 = lab.put_entity(lab.owner, b"o2\n", name="o2")
    act = lab.add(builders.activity(lab.state, lab.owner, used=[raw], generated=[out1, out2]))
    b = make_bundle(lab.log, _head(lab), HUB_CARD, [out1])
    proven = {entries.entry_hash(it["entry"]) for it in b["entries"]}
    assert {out1, act, raw} <= proven and out2 not in proven
    assert verify_bundle(b, trusted_logs={HUB.id}).ok


def test_supplied_content_is_checked_even_when_plaintext_is_embedded(experiment):
    """Lane F: `verify --content ID=fake` reported a match when the bundle embedded the
    plaintext (the embedded copy was checked instead of the verifier's file)."""
    lab, h = experiment
    b = make_bundle(lab.log, _head(lab), HUB_CARD, [h["activity"]],
                    openings={h["result"]: _opening(lab, h["result"])},
                    contents={h["result"]: b"Kd=7nM\n"})
    assert verify_bundle(b, external_contents={h["result"]: b"Kd=7nM\n"}).ok
    bad = verify_bundle(b, external_contents={h["result"]: b"fake"})
    assert not bad.ok and "supplied content" in " ".join(bad.errors)
    unopened = verify_bundle(b, external_contents={h["raw"]: b"OD600\n0.41\n"})
    assert not unopened.ok and "does not open" in " ".join(unopened.errors)
