"""Hub log key rotation (ADR 0010): a hand-over signed by both keys; trust moves forward only."""

import copy
import json
import os
import shutil

import pytest
from fastapi.testclient import TestClient

from provena.cli.main import main
from provena.client.hub import HubClient
from provena.core import entries, rotation
from provena.core.bundle import make_bundle
from provena.core.errors import VerificationError
from provena.core.keys import AgentKey
from provena.core.treehead import make_head
from provena.core.verify import TRUST_LOG, verify_bundle
from provena.server.app import create_app, load_or_create_hub_key, rotate_hub_key
from provena.store.repo import Repo
from tests.test_js_verifier import _run_node
from tests.test_mirror import PRIMARY, hubs  # noqa: F401 (fixture)


def _keys(n=3):
    keys = [AgentKey.generate() for _ in range(n)]
    return keys, [k.make_card("hub", "hub") for k in keys]


def test_statement_is_signed_by_both_keys_and_chains_forward():
    (a, b, c), (ca, cb, cc) = _keys()
    ab, bc = rotation.make(a, ca, b, cb, 1), rotation.make(b, cb, c, cc, 2)
    assert rotation.verify(ab) == (a.id, b.id)
    assert rotation.chain([ab, bc], a.id, c.id) == [ab, bc]
    assert rotation.chain([ab, bc], c.id, a.id) is None           # never backwards
    assert rotation.extend_trust({a.id}, [ab, bc]) == {b.id: a.id, c.id: a.id}
    assert rotation.extend_trust({c.id}, [ab, bc]) == {}
    forged = {**ab, "sig_new": ab["sig_old"]}                     # the new key never agreed
    with pytest.raises(VerificationError):
        rotation.verify(forged)
    (x,), (cx,) = _keys(1)
    with pytest.raises(VerificationError, match="two successors"):
        rotation.successors([ab, rotation.make(a, ca, x, cx, 3)])


def _bundles(lab):
    """A bundle whose head is signed by the hub's second key, after a hand-over from the first."""
    (old, new), (c_old, c_new) = _keys(2)
    raw = lab.put_entity(lab.owner, b"raw\n")
    head = make_head(new, lab.state.project, [entries.entry_leaf(e) for e in lab.log])
    stmt = rotation.make(old, c_old, new, c_new, 1)
    rotated = make_bundle(lab.log, head, c_new, [raw], log_rotations=[stmt])
    tampered = copy.deepcopy(rotated)
    tampered["log_rotations"][0]["time"] = 2
    cases = {"rotated": rotated, "bare": make_bundle(lab.log, head, c_new, [raw]),
             "tampered": tampered}
    return cases, old.id, new.id


def test_both_verifiers_follow_a_hand_over_from_a_trusted_key(lab, tmp_path):
    cases, old, new = _bundles(lab)
    py = {n: verify_bundle(b, trusted_logs={old}) for n, b in cases.items()}
    assert py["rotated"].ok and py["rotated"].trust == TRUST_LOG
    assert any("successor of" in n for n in py["rotated"].notes)
    assert py["bare"].ok and py["bare"].trust != TRUST_LOG       # no hand-over, no trust
    assert not py["tampered"].ok
    # trusting only the new key says nothing about heads the old key signed
    assert not rotation.extend_trust({new}, cases["rotated"]["log_rotations"])
    out = _run_node(tmp_path, {"vectors": _vectors(), "bundles": cases,
                               "options": {n: {"trustedLogs": [old]} for n in cases}})
    for name, report in py.items():
        js = out["results"][name]
        assert js["ok"] == report.ok, (name, js["errors"], report.errors)
        if report.ok:
            assert js["trust"] == report.trust, name


def _vectors():
    from tests.test_js_verifier import ROOT

    return json.loads((ROOT / "tests" / "vectors" / "core.json").read_text())


def _restart(tmp_path, http):
    key, card = load_or_create_hub_key(tmp_path / "a", "pw")
    http[PRIMARY] = TestClient(create_app(tmp_path / "a", key, card))
    return card


def test_clients_witnesses_and_proofs_follow_a_rotated_hub(hubs, capsys):  # noqa: F811
    from provena.client.witness import Witness

    tmp_path, http = hubs
    repo = Repo.find()
    pid, old = repo.state.project, repo.config["hub_card"]["id"]
    w = AgentKey.generate()
    witness = Witness(w, w.make_card("org"), tmp_path / "witness.json")
    witness.observe(HubClient(PRIMARY, http=http[PRIMARY]), pid)

    stmt = rotate_hub_key(tmp_path / "a", "pw")
    card = _restart(tmp_path, http)
    assert stmt["new"]["id"] == card["id"] != old
    hub = HubClient(PRIMARY, http=http[PRIMARY])
    assert hub.sth(pid)["signer"] == card["id"]                  # latest head re-signed
    assert hub.sth(pid, 1)["signer"] == old                      # history stays as signed

    (tmp_path / "lab" / "more.csv").write_text("x\n")
    assert main(["add", "more.csv"]) == 0
    capsys.readouterr()
    assert main(["--json", "push"]) == 0
    env = json.loads(capsys.readouterr().out)
    assert env["warnings"][0]["code"] == "W_HUB_KEY_ROTATED"
    assert Repo.find().config["hub_card"]["id"] == card["id"]
    assert main(["doctor"]) == 0

    witness.observe(hub, pid)                                    # follows, still append-only
    assert main(["prove", "more.csv", "-o", str(tmp_path / "p.pvb")]) == 0
    capsys.readouterr()
    assert main(["--json", "verify", str(tmp_path / "p.pvb"), "--trust-log", old]) == 0
    data = json.loads(capsys.readouterr().out)["data"]
    assert data["verify"]["trust"] == "log-sequenced"


def test_a_key_change_without_hand_over_is_still_refused(hubs, capsys):  # noqa: F811
    from provena.client.witness import Witness

    tmp_path, http = hubs
    pid = Repo.find().state.project
    w = AgentKey.generate()
    witness = Witness(w, w.make_card("org"), tmp_path / "witness.json")
    witness.observe(HubClient(PRIMARY, http=http[PRIMARY]), pid)
    (tmp_path / "a" / "hub.key.json").unlink()                   # a reset hub, same data
    (tmp_path / "a" / "hub.card.json").unlink()
    _restart(tmp_path, http)
    with pytest.raises(VerificationError, match="without a hand-over"):
        witness.observe(HubClient(PRIMARY, http=http[PRIMARY]), pid)
    capsys.readouterr()
    assert main(["pull"]) == 6
    assert "no hand-over" in capsys.readouterr().err


def test_rotate_key_needs_yes_and_a_stopped_hub(hubs, monkeypatch, capsys):  # noqa: F811
    tmp_path, http = hubs
    monkeypatch.setenv("PROVENA_HUB_PASSPHRASE", "pw")
    data = str(tmp_path / "a")
    assert main(["hub", "rotate-key", "--data", data]) == 2
    from provena.cli.hubcmds import _lock_data_dir

    held = _lock_data_dir((tmp_path / "a").resolve())
    assert main(["hub", "rotate-key", "--data", data, "--yes"]) != 0
    held.close()
    capsys.readouterr()
    assert main(["--json", "hub", "rotate-key", "--data", data, "--yes"]) == 0
    out = json.loads(capsys.readouterr().out)["data"]
    assert (tmp_path / "a" / f"hub.key.retired-{out['old']}.json").exists()
    assert len(json.loads((tmp_path / "a" / "hub.rotations.json").read_text())) == 1


def test_clones_and_lagging_checkouts_read_history_signed_by_the_old_key(hubs, capsys,  # noqa: F811
                                                                        tmp_path_factory):
    tmp_path, http = hubs
    lab = tmp_path / "lab"
    pid = Repo.find().state.project
    shutil.copytree(lab, tmp_path / "behind")                    # synced before the rotation
    (lab / "more.csv").write_text("x\n")
    assert main(["add", "more.csv"]) == 0
    assert main(["push"]) == 0
    rotate_hub_key(tmp_path / "a", "pw")
    _restart(tmp_path, http)
    os.chdir(tmp_path / "behind")
    assert main(["pull"]) == 0                                   # old receipts, new key
    os.chdir(tmp_path)
    assert main(["clone", PRIMARY, pid, str(tmp_path / "fresh")]) == 0
    fresh = Repo(tmp_path / "fresh")
    assert fresh.config["hub_rotations"] and fresh.config["hub_past_cards"]
    assert len(fresh.log()) == len(Repo(lab).log())


def test_witness_keeps_every_projects_history_across_the_hand_over(hubs, lab):  # noqa: F811
    from provena.client.witness import Witness

    tmp_path, http = hubs
    pid = Repo.find().state.project
    other_dir = tmp_path / "lab2"
    other_dir.mkdir()
    os.chdir(other_dir)
    assert main(["init", "--name", "q"]) == 0
    (other_dir / "q.csv").write_text("q\n")
    assert main(["add", "q.csv"]) == 0
    assert main(["remote", PRIMARY]) == 0
    assert main(["push"]) == 0
    other = Repo.find().state.project
    w = AgentKey.generate()
    witness = Witness(w, w.make_card("org"), tmp_path / "witness.json")
    hub = HubClient(PRIMARY, http=http[PRIMARY])
    for p in (pid, other):
        witness.observe(hub, p)
    small = hub.sth(other, 1)
    rotate_hub_key(tmp_path / "a", "pw")
    _restart(tmp_path, http)
    hub = HubClient(PRIMARY, http=http[PRIMARY])
    witness.observe(hub, pid)                                    # re-pins on this project
    key, _ = load_or_create_hub_key(tmp_path / "a", "pw")
    shrunk = make_head(key, other, [entries.entry_leaf(e) for e in Repo.find().log()[:1]])
    assert shrunk["size"] == small["size"]
    from unittest import mock

    with mock.patch.object(HubClient, "sth", lambda self, p, size=None: shrunk), \
            pytest.raises(VerificationError, match="shrank"):
        witness.observe(hub, other)                              # still append-only


def test_verifiers_agree_on_odd_rotation_fields(lab, tmp_path):
    cases, old, _ = _bundles(lab)
    base = cases["rotated"]
    odd = {"empty_object": {**base, "log_rotations": {}},
           "null": {**base, "log_rotations": None},
           "bool_version": {**base, "log_rotations": [{**base["log_rotations"][0], "v": True}]}}
    out = _run_node(tmp_path, {"vectors": _vectors(), "bundles": odd,
                               "options": {n: {"trustedLogs": [old]} for n in odd}})
    for name, bundle in odd.items():
        py = verify_bundle(bundle, trusted_logs={old})
        assert out["results"][name]["ok"] == py.ok, (name, py.errors)
    assert verify_bundle(odd["null"], trusted_logs={old}).ok
    assert not verify_bundle(odd["empty_object"], trusted_logs={old}).ok


def test_a_rotation_cut_short_is_finished_or_dropped_on_start(tmp_path):
    from provena.server import app as app_mod

    data = tmp_path / "h"
    old_key, old_card = load_or_create_hub_key(data, "pw")
    new_key = AgentKey.generate()
    app_mod._write_durably(data / "hub.key.next.json",
                           json.dumps(new_key.export_encrypted("pw", n=1024)), 0o600)
    key, _ = load_or_create_hub_key(data, "pw")                  # crashed before the statement
    assert key.id == old_key.id and not (data / "hub.key.next.json").exists()
    stmt = rotation.make(old_key, old_card, new_key, new_key.make_card("hub", "h"), 1)
    app_mod._write_durably(data / "hub.key.next.json",
                           json.dumps(new_key.export_encrypted("pw", n=1024)), 0o600)
    app_mod._write_durably(data / "hub.rotations.json", json.dumps([stmt]))
    key, card = load_or_create_hub_key(data, "pw")               # crashed after it
    assert key.id == card["id"] == new_key.id
    assert (data / f"hub.key.retired-{old_key.id}.json").exists()
    (data / "hub.key.json").unlink()
    with pytest.raises(VerificationError, match="rotated"):
        load_or_create_hub_key(data, "pw")                       # never mint a third key
