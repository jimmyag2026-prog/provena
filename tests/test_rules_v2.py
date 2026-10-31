"""ADR 0009 rules 2, case by case, in both verifiers (full bundles replay every rule)."""

import copy
import json
import shutil

import pytest

from provena.core import builders
from provena.core.errors import ProvenaError, VerificationError
from provena.core.keys import AgentKey
from provena.core.state import ProjectState
from provena.core.verify import verify_bundle
from tests.conftest import Lab
from tests.test_state_fuzz import _full


def _both(tmp_path, cases: dict) -> dict:
    """name -> (python ok, browser ok)"""
    from tests.test_js_verifier import ROOT, _run_node

    bundles = {n: _full(lab.log, lab.owner, lab.state.project) for n, lab in cases.items()}
    py = {n: verify_bundle(b).ok for n, b in bundles.items()}
    if shutil.which("node") is None:
        return {n: (ok, ok) for n, ok in py.items()}
    out = _run_node(tmp_path, {"vectors": json.loads(
        (ROOT / "tests" / "vectors" / "core.json").read_text()), "bundles": bundles})
    return {n: (py[n], out["results"][n]["ok"]) for n in bundles}


def _forged(lab: Lab, entry: dict) -> Lab:
    """*lab* with *entry* appended without applying it (to test that verifiers refuse it)."""
    bad = copy.copy(lab)
    bad.log = [*lab.log, entry]
    return bad


def test_rewrap_gives_a_late_member_the_history(tmp_path):
    lab = Lab()
    old = lab.put_entity(lab.owner, b"before\n", name="old.csv")
    e, _ = builders.rotate(lab.state, lab.owner)
    lab.add(e)
    late = lab.join("contributor")
    with pytest.raises(ProvenaError):
        builders.epoch_key(lab.state, late, 0)
    lab.add(builders.member_rewrap(lab.state, lab.owner, late.id))
    assert builders.epoch_key(lab.state, late, 0)                  # history readable now
    assert builders.open_entry_fields(lab.state, late, lab.state.entries[old])["name"] \
        == "old.csv"
    with pytest.raises(ProvenaError):
        builders.member_rewrap(lab.state, lab.owner, late.id)       # nothing left to share
    v1 = Lab(rules=1)
    v1.join("contributor")
    body = {"action": "rewrap", "agent": v1.owner.id, "epoch_wraps": {"0": "x"}}
    assert _both(tmp_path, {"ok": lab, "v1": _forged(v1, builders._entry(
        v1.state, v1.owner, "member", body=body))}) == {"ok": (True, True),
                                                       "v1": (False, False)}


def test_a_step_can_be_opened_and_its_details_checked(tmp_path):
    lab = Lab()
    d = lab.put_entity(lab.owner, b"x\n", name="d.csv")
    act = lab.add(builders.activity(lab.state, lab.owner, used=[d],
                                    details={"command": ["fit"], "exit_code": 3,
                                             "model": "m-1"}))
    assert lab.state.entries[act]["body"]["status"] == "failed"     # public without opening
    private = builders.open_entry_fields(lab.state, lab.owner, lab.state.entries[act])
    good = builders.reveal_activity(lab.state, lab.owner, act, private)
    tampered = copy.deepcopy(good)
    tampered["body"]["details"]["exit_code"] = 0
    tampered = builders._entry(lab.state, lab.owner, "reveal", refs=[act],
                               body=tampered["body"])
    with pytest.raises(VerificationError):
        copy.deepcopy(lab.state).apply(tampered)
    bad = _forged(lab, tampered)
    lab.add(good)
    assert lab.state.reveals[act]["details"]["exit_code"] == 3
    assert _both(tmp_path, {"ok": lab, "tampered": bad}) == {"ok": (True, True),
                                                             "tampered": (False, False)}


def test_a_content_key_can_be_published_after_a_reveal_once(tmp_path):
    lab = Lab()
    d = lab.put_entity(lab.owner, b"secret\n", name="d.csv")
    s = lab.secrets[d]
    lab.add(builders.reveal(lab.state, lab.owner, d, salt=s.salt, plain_sha256=s.plain_sha256))
    lab.add(builders.reveal(lab.state, lab.owner, d, salt=s.salt, plain_sha256=s.plain_sha256,
                            dek=s.dek))
    again = builders.reveal(lab.state, lab.owner, d, salt=s.salt, plain_sha256=s.plain_sha256,
                            dek=s.dek)
    v1 = Lab(rules=1)
    d1 = v1.put_entity(v1.owner, b"secret\n", name="d.csv")
    s1 = v1.secrets[d1]
    v1.add(builders.reveal(v1.state, v1.owner, d1, salt=s1.salt, plain_sha256=s1.plain_sha256))
    upgrade_v1 = builders.reveal(v1.state, v1.owner, d1, salt=s1.salt,
                                 plain_sha256=s1.plain_sha256, dek=s1.dek)
    assert _both(tmp_path, {"ok": lab, "twice": _forged(lab, again),
                            "v1": _forged(v1, upgrade_v1)}) == {
        "ok": (True, True), "twice": (False, False), "v1": (False, False)}


def test_rules_versions_are_gated(tmp_path):
    v1 = Lab(rules=1)
    d = v1.put_entity(v1.owner, b"x\n", name="d.csv")
    a = builders.activity(v1.state, v1.owner, used=[d], details={"exit_code": 0})
    assert "status" not in a["body"]                                # rules 1 entries as before
    smuggled = copy.deepcopy(a["body"])
    smuggled["status"] = "ok"
    bad = builders._entry(v1.state, v1.owner, "activity", refs=[d], body=smuggled,
                          sealed=a["sealed"])
    owner = AgentKey.generate()
    g3, _ = builders.new_project(owner, owner.make_card("person"), rules=3)
    with pytest.raises(VerificationError, match="unknown ledger rules"):
        ProjectState.from_genesis(g3)
    assert _both(tmp_path, {"smuggled": _forged(v1, bad)}) == {"smuggled": (False, False)}


def test_selective_bundles_check_opened_details_too(tmp_path):
    from provena.core import entries
    from provena.core.bundle import make_bundle
    from provena.core.treehead import make_head
    from tests.test_js_verifier import ROOT, _run_node

    lab = Lab()
    d = lab.put_entity(lab.owner, b"x\n", name="d.csv")
    act = lab.add(builders.activity(lab.state, lab.owner, used=[d], details={"exit_code": 3}))
    private = builders.open_entry_fields(lab.state, lab.owner, lab.state.entries[act])
    good = builders.reveal_activity(lab.state, lab.owner, act, private)
    forged = copy.deepcopy(good)
    forged["body"]["details"]["exit_code"] = 0
    forged = builders._entry(lab.state, lab.owner, "reveal", refs=[act], body=forged["body"])
    bundles = {}
    for name, rev in (("good", good), ("forged", forged)):
        log = [*lab.log, rev]
        head = make_head(lab.owner, lab.state.project, [entries.entry_leaf(e) for e in log])
        bundles[name] = make_bundle(log, head, lab.owner.make_card("person"),
                                    [entries.entry_hash(rev)])
    py = {n: verify_bundle(b) for n, b in bundles.items()}
    assert py["good"].ok and any("opened: exit code 3" in f for f in py["good"].facts)
    assert not py["forged"].ok
    if shutil.which("node"):
        out = _run_node(tmp_path, {"vectors": json.loads(
            (ROOT / "tests" / "vectors" / "core.json").read_text()), "bundles": bundles})
        assert [out["results"][n]["ok"] for n in ("good", "forged")] == [True, False]


def test_cli_recovery_reads_history_and_publish_after_reveal(tmp_path, monkeypatch, capsys):
    from provena.cli.main import main

    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PROVENA_PASSPHRASE", "pw")
    monkeypatch.setenv("PROVENA_SCRYPT_N", "1024")
    (tmp_path / "w").mkdir()
    monkeypatch.chdir(tmp_path / "w")
    assert main(["keygen"]) == 0 and main(["init", "--name", "x"]) == 0
    (tmp_path / "w" / "old.csv").write_text("before")
    assert main(["add", "old.csv"]) == 0 and main(["rotate"]) == 0
    assert main(["--agent", "recovery", "keygen"]) == 0
    card = str(tmp_path / "home" / "agents" / "recovery.card.json")
    assert main(["member", "add", card, "--role", "owner", "--history"]) == 0
    capsys.readouterr()
    assert main(["--agent", "recovery", "cat", "old.csv"]) == 0       # epoch 0 data
    assert capsys.readouterr().out == "before"
    rid = json.loads((tmp_path / "home" / "agents" / "recovery.card.json").read_text())["id"]
    assert main(["member", "history", rid]) == 5                      # nothing left to share
    assert main(["reveal", "old.csv"]) == 0
    assert main(["publish", "old.csv"]) == 0                          # key added afterwards
    assert main(["verify"]) == 0


def test_public_status_must_match_the_revealed_exit_code(tmp_path):
    """Review of phases 2–6: status "ok" with a revealed exit code 1 passed both verifiers."""
    lab = Lab()
    d = lab.put_entity(lab.owner, b"x\n", name="d.csv")
    a = builders.activity(lab.state, lab.owner, used=[d], details={"exit_code": 1})
    body = copy.deepcopy(a["body"])
    body["status"] = "ok"                                          # a lie about the outcome
    lying = builders._entry(lab.state, lab.owner, "activity", refs=[d], body=body,
                            sealed=a["sealed"])
    h = lab.add(lying)                                             # accepted: details sealed
    private = builders.open_entry_fields(lab.state, lab.owner, lab.state.entries[h])
    rev = builders.reveal_activity(lab.state, lab.owner, h, private)
    with pytest.raises(VerificationError, match="contradicts"):
        copy.deepcopy(lab.state).apply(rev)
    assert _both(tmp_path, {"lie": _forged(lab, rev)}) == {"lie": (False, False)}


def test_rules_null_is_not_absent(tmp_path):
    from provena.core import entries
    from tests.test_js_verifier import ROOT, _run_node

    owner = AgentKey.generate()
    g, _ = builders.new_project(owner, owner.make_card("person"), rules=None)
    bundle = _full([g], owner, entries.entry_hash(g))
    assert not verify_bundle(bundle).ok
    if shutil.which("node"):
        out = _run_node(tmp_path, {"vectors": json.loads(
            (ROOT / "tests" / "vectors" / "core.json").read_text()), "bundles": {"n": bundle}})
        assert out["results"]["n"]["ok"] is False
