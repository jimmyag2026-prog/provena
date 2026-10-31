"""Replay snapshots (a cache, never evidence): resuming must equal replaying from scratch."""

import json
import random

import pytest

from provena.core.errors import VerificationError
from provena.core.state import ProjectState
from tests.test_state_fuzz import _history


def _same(a: ProjectState, b: ProjectState) -> None:
    assert a.snapshot() == b.snapshot()
    assert a.entries == b.entries and a.position == b.position


@pytest.mark.parametrize("rules", [1, 2])
def test_resume_from_any_prefix_equals_full_replay(rules):
    rng = random.Random(7 + rules)
    for _ in range(25):
        log = _history(rng, rules).log
        full = ProjectState.replay(log)
        for k in sorted({1, len(log) // 2, len(log)}):
            snap = json.loads(json.dumps(ProjectState.replay(log[:k]).snapshot()))
            _same(ProjectState.resume(snap, log), full)


def test_the_tail_is_still_checked_and_mismatches_are_refused(lab):
    lab.put_entity(lab.owner, b"a\n")
    lab.put_entity(lab.owner, b"b\n")
    log = lab.log
    snap = ProjectState.replay(log[:2]).snapshot()
    hashes = ProjectState.replay(log).order
    assert ProjectState.resume(snap, log, hashes).order == hashes
    with pytest.raises(VerificationError, match="does not match"):
        ProjectState.resume(snap, log, list(reversed(hashes)))
    with pytest.raises(VerificationError, match="ahead"):
        ProjectState.resume(ProjectState.replay(log).snapshot(), log[:2])
    tampered = [*log[:2], {**log[2], "ts": log[2]["ts"] + 1}]   # the tail is verified as usual
    with pytest.raises(VerificationError):
        ProjectState.resume(snap, tampered)


def test_a_checkout_resumes_from_its_snapshot_and_ignores_a_stale_one(lab, tmp_path,
                                                                       monkeypatch):
    from provena.store import repo as repo_mod
    from provena.store.repo import Repo

    monkeypatch.setattr(repo_mod, "SNAPSHOT_EVERY", 2)
    for i in range(4):
        lab.put_entity(lab.owner, f"{i}\n".encode())
    root = tmp_path / "co"
    repo = Repo.init(root, "default", lab.log[0])
    for e in lab.log[1:]:
        repo.append(e)
    expected = ProjectState.replay(lab.log)
    _same(Repo(root).state, expected)                      # writes the snapshot
    snap = root / ".provena" / "state.snapshot.json"
    assert snap.exists()
    replays = []
    real = ProjectState.replay
    monkeypatch.setattr(ProjectState, "replay", classmethod(
        lambda cls, log: replays.append(len(log)) or real.__func__(cls, log)))
    _same(Repo(root).state, expected)
    assert replays == []                                   # resumed, not replayed
    log = (root / ".provena" / "log.jsonl").read_bytes()
    (root / ".provena" / "log.jsonl").write_bytes(log.replace(b'"ts": ', b'"ts":  ', 1))
    _same(Repo(root).state, expected)                      # prefix bytes changed: full replay
    assert replays == [len(lab.log)]


def test_hub_cold_load_resumes_and_falls_back_on_a_bad_snapshot(lab, tmp_path, monkeypatch,
                                                                caplog):
    from provena.core.keys import AgentKey
    from provena.server import hub as hub_mod
    from provena.server.hub import Hub
    from provena.server.storage import Storage

    monkeypatch.setattr(hub_mod, "SNAPSHOT_EVERY", 2)
    for i in range(5):
        lab.put_entity(lab.owner, f"{i}\n".encode())
    key = AgentKey.generate()
    card = key.make_card("hub", "h")
    hub = Hub(Storage(tmp_path / "hub"), key, card)
    pid = hub.create_project(lab.log[0])["entry_hash"]
    for e in lab.log[1:]:
        hub.submit(pid, e)
    stored = hub.storage.snapshot(pid)
    assert stored and len(stored["order"]) >= 4               # written as the log grew
    expected = ProjectState.replay(lab.log)

    replays = []
    real = ProjectState.replay
    monkeypatch.setattr(ProjectState, "replay", classmethod(
        lambda cls, log: replays.append(len(log)) or real.__func__(cls, log)))
    _same(Hub(Storage(tmp_path / "hub"), key, card)._state(pid), expected)
    assert replays == []
    bad = {**stored, "order": list(reversed(stored["order"]))}
    hub.storage.put_snapshot(pid, bad)
    _same(Hub(Storage(tmp_path / "hub"), key, card)._state(pid), expected)
    assert replays == [len(lab.log)] and "snapshot not used" in caplog.text


def test_a_snapshot_written_by_someone_else_is_ignored(lab, tmp_path, monkeypatch):
    """The checkout may be shared or synced: a forged snapshot must not change roles."""
    from provena.store import repo as repo_mod
    from provena.store.repo import Repo

    monkeypatch.setattr(repo_mod, "SNAPSHOT_EVERY", 1)
    lab.put_entity(lab.owner, b"a\n")
    root = tmp_path / "co"
    repo = Repo.init(root, "default", lab.log[0])
    repo.append(lab.log[1])
    assert Repo(root).state                                # writes an authenticated snapshot
    path = root / ".provena" / "state.snapshot.json"
    snap = json.loads(path.read_text())
    inner = json.loads(snap["state"])
    inner["meta"] = {"title": "forged"}
    path.write_text(json.dumps({**snap, "state": json.dumps(inner)}))
    assert Repo(root).state.meta != {"title": "forged"}
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "other-user"))  # another key
    path.write_text(json.dumps(snap))
    assert Repo(root).state.snapshot() == ProjectState.replay(lab.log).snapshot()


def test_hub_still_quarantines_a_damaged_stored_entry(lab, tmp_path, monkeypatch):
    import sqlite3

    from provena.core.keys import AgentKey
    from provena.server import hub as hub_mod
    from provena.server.hub import Hub, Unavailable
    from provena.server.storage import Storage

    monkeypatch.setattr(hub_mod, "SNAPSHOT_EVERY", 2)
    for i in range(4):
        lab.put_entity(lab.owner, f"{i}\n".encode())
    key = AgentKey.generate()
    card = key.make_card("hub", "h")
    hub = Hub(Storage(tmp_path / "hub"), key, card)
    pid = hub.create_project(lab.log[0])["entry_hash"]
    for e in lab.log[1:]:
        hub.submit(pid, e)
    assert hub.storage.snapshot(pid)
    db = tmp_path / "hub" / "hub.sqlite3"
    with sqlite3.connect(db) as conn:                       # inside the snapshot's prefix
        (entry,) = conn.execute("SELECT entry FROM entries WHERE idx = 1").fetchone()
        damaged = json.loads(entry)
        damaged["ts"] += 1
        conn.execute("UPDATE entries SET entry = ? WHERE idx = 1", (json.dumps(damaged),))
    fresh = Hub(Storage(tmp_path / "hub"), key, card)
    with pytest.raises(Unavailable):
        fresh._state(pid)
    assert pid in fresh.broken


def test_a_refused_snapshot_is_replaced_on_the_next_load(lab, tmp_path, monkeypatch):
    from provena.core.keys import AgentKey
    from provena.server import hub as hub_mod
    from provena.server.hub import Hub
    from provena.server.storage import Storage

    monkeypatch.setattr(hub_mod, "SNAPSHOT_EVERY", 2)
    for i in range(3):
        lab.put_entity(lab.owner, f"{i}\n".encode())
    key = AgentKey.generate()
    card = key.make_card("hub", "h")
    hub = Hub(Storage(tmp_path / "hub"), key, card)
    pid = hub.create_project(lab.log[0])["entry_hash"]
    for e in lab.log[1:]:
        hub.submit(pid, e)
    hub.storage._sql.write(("UPDATE snapshots SET state = ? WHERE project = ?",
                            ('{"v": 1}', pid)))                        # malformed row
    fresh = Hub(Storage(tmp_path / "hub"), key, card)
    _same(fresh._state(pid), ProjectState.replay(lab.log))              # no 500
    assert len(fresh.storage.snapshot(pid)["order"]) == len(lab.log)   # rewritten
