"""Randomised project histories: the browser replay must agree with Python on every one.

Valid histories mix every kind (members joining/leaving, rotations, successions, data, steps,
reveals, grants, attestations, redactions, cards); each is also re-checked with two entries
swapped, which both verifiers must reject.
"""

import json
import random
import shutil

import pytest

from provena.core import builders, entries
from provena.core.bundle import make_bundle
from provena.core.keys import AgentKey
from provena.core.state import ProjectState
from provena.core.treehead import make_head
from provena.core.verify import verify_bundle
from tests.conftest import Lab

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _history(rng: random.Random, rules: int = 2) -> Lab:
    lab = Lab(rules=rules)
    agents = {lab.owner.id: lab.owner}
    plans, data, steps = [], [], []

    def writer():
        ids = [i for i in lab.state.active_ids()
               if lab.state.role_of(i) in ("owner", "maintainer", "contributor")]
        return agents[rng.choice(sorted(ids))]

    for _ in range(rng.randint(6, 18)):
        ops = ["join", "join", "entity", "entity", "plan", "activity", "attest", "reveal",
               "grant", "redact", "remove", "rotate", "meta", "succeed"]
        if rules >= 2:
            ops += ["rewrap", "reveal_step", "publish_key"]
        op = rng.choice(ops)
        st = lab.state
        try:
            if op == "join":
                a = AgentKey.generate()
                role = rng.choice(["maintainer", "contributor", "reviewer", "viewer"])
                lab.add(builders.member_add(st, lab.owner, a.make_card("person"), role))
                agents[a.id] = a
            elif op == "entity":
                w = writer()
                data.append(lab.put_entity(w, rng.randbytes(16), name=f"d{len(data)}"))
            elif op == "plan":
                plans.append(lab.put_plan(writer(), rng.randbytes(8)))
            elif op == "activity" and data:
                w = writer()
                fresh = [d for d in data if d not in st.generated_by
                         and st.entries[d]["author"] == w.id]
                plan = rng.choice(plans) if plans and rng.random() < 0.5 else None
                gen = [d for d in fresh if plan is None
                       or st.position[d] > st.position[plan]][:1]
                used = [d for d in rng.sample(data, k=min(2, len(data))) if d not in gen]
                if used or gen:
                    details = {"command": ["x"], "exit_code": rng.choice([0, 0, 2])}
                    steps.append((lab.add(builders.activity(st, w, used=used, generated=gen,
                                                            plan_ref=plan, details=details)),
                                  w))
            elif op == "attest" and data:
                ids = [i for i in st.active_ids() if st.role_of(i) != "viewer"]
                lab.add(builders.attest(st, agents[rng.choice(sorted(ids))], rng.choice(data),
                                        type="review", verdict="pass"))
            elif op == "reveal" and data:
                d = rng.choice(data)
                if d not in st.reveals and d not in st.redacted:
                    s = lab.secrets[d]
                    lab.add(builders.reveal(st, lab.owner, d, salt=s.salt,
                                            plain_sha256=s.plain_sha256))
            elif op == "grant" and data:
                d = rng.choice(data)
                if d not in st.redacted:
                    s = lab.secrets[d]
                    lab.add(builders.grant(st, lab.owner, d, AgentKey.generate().make_card(
                        "person"), dek=s.dek, salt=s.salt, plain_sha256=s.plain_sha256,
                        name="g"))
            elif op == "redact" and data:
                d = rng.choice(data)
                if d not in st.redacted:
                    lab.add(builders.redact(st, lab.owner, d, reason="test"))
            elif op == "remove":
                ids = [i for i in st.active_ids() if st.role_of(i) != "owner"]
                if ids:
                    e, _ = builders.member_remove(st, lab.owner, rng.choice(sorted(ids)))
                    lab.add(e)
            elif op == "rotate":
                e, _ = builders.rotate(st, lab.owner)
                lab.add(e)
            elif op == "meta":
                lab.add(builders.meta(st, lab.owner, title=f"t{rng.randint(0, 99)}"))
            elif op == "rewrap":
                ids = [i for i in st.active_ids() if i != lab.owner.id and any(
                    lab.owner.id in w and i not in w for w in st.wraps.values())]
                if ids:
                    lab.add(builders.member_rewrap(st, lab.owner, rng.choice(sorted(ids))))
            elif op == "reveal_step" and steps:
                h, w = rng.choice(steps)
                if h not in st.reveals and w.id in st.active_ids():
                    private = builders.open_entry_fields(st, w, st.entries[h])
                    lab.add(builders.reveal_activity(st, w, h, private,
                                                     publish_details=rng.random() < 0.5))
            elif op == "publish_key" and data:
                d = rng.choice(data)
                r = st.reveals.get(d)
                if r is not None and not r.get("dek") and d not in st.redacted:
                    s = lab.secrets[d]
                    lab.add(builders.reveal(st, lab.owner, d, salt=s.salt,
                                            plain_sha256=s.plain_sha256, dek=s.dek))
            elif op == "succeed":
                ids = [i for i in st.active_ids() if i != lab.owner.id]
                if ids:
                    old = agents[rng.choice(sorted(ids))]
                    new = AgentKey.generate()
                    lab.add(builders.succeed(st, old, new.make_card("person")))
                    agents[new.id] = new
        except Exception as exc:  # the generator only builds valid steps; surface surprises
            raise AssertionError(f"generator produced an invalid {op}: {exc}") from exc
    return lab


def _full(log, owner, project):
    head = make_head(owner, project, [entries.entry_leaf(e) for e in log])
    return make_bundle(log, head, owner.make_card("person"), [entries.entry_hash(log[-1])],
                       mode="full")


@pytest.mark.parametrize("rules", [1, 2])
def test_random_histories_agree(tmp_path, rules):
    from tests.test_js_verifier import ROOT, _run_node

    rng = random.Random(31 + rules)
    cases, expected = {}, {}
    for i in range(40):
        lab = _history(rng, rules)
        ProjectState.replay(lab.log)  # sanity: the history really is valid
        cases[f"h{i}"] = _full(lab.log, lab.owner, lab.state.project)
        expected[f"h{i}"] = True
        if len(lab.log) > 3:
            j = rng.randint(1, len(lab.log) - 2)
            swapped = lab.log[:j] + [lab.log[j + 1], lab.log[j]] + lab.log[j + 2:]
            cases[f"h{i}-swap"] = _full(swapped, lab.owner, lab.state.project)
            expected[f"h{i}-swap"] = None  # decided by Python, must match in JS
    out = _run_node(tmp_path, {
        "vectors": json.loads((ROOT / "tests" / "vectors" / "core.json").read_text()),
        "bundles": cases})
    for name, bundle in cases.items():
        py = verify_bundle(bundle)
        if expected[name] is not None:
            assert py.ok, (name, py.errors)
        assert out["results"][name]["ok"] == py.ok, (name, out["results"][name]["errors"],
                                                     py.errors)
