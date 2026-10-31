"""Eighth review: lazy loading off the hub lock, transactional catalog and shred bookkeeping,
and the published-download plaintext cache."""

import hashlib
import sqlite3
import threading
import time

import pytest
from fastapi.testclient import TestClient

from provena.client.hub import HubClient
from provena.core import builders, commitment
from provena.core import state as st
from provena.core.entries import entry_hash
from provena.core.keys import AgentKey
from provena.sdk import sync
from provena.server import web
from provena.server.app import create_app, load_or_create_hub_key
from provena.server.hub import Hub
from provena.server.storage import Storage
from provena.store.repo import Repo


def _hub(tmp_path, cache_size=2000):
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    return Hub(Storage(tmp_path / "hub"), key, card, cache_size=cache_size), key, card


def _project(hub, alice):
    g, _ = builders.new_project(alice, alice.make_card("person"), visibility="public")
    hub.create_project(g)
    return entry_hash(g)


def test_cold_load_runs_outside_the_hub_lock_once(tmp_path, monkeypatch):
    hub, *_ = _hub(tmp_path, cache_size=1)
    alice = AgentKey.generate()
    cold, hot = _project(hub, alice), None
    hot = _project(hub, alice)                       # evicts `cold`
    real, calls = st.ProjectState.replay.__func__, []

    def slow(cls, log):
        calls.append(1)
        time.sleep(1.0)                              # stands in for a very long log
        return real(cls, log)

    monkeypatch.setattr(st.ProjectState, "replay", classmethod(slow))
    loaders = [threading.Thread(target=hub.size, args=(cold,)) for _ in range(3)]
    for t in loaders:
        t.start()
    time.sleep(0.2)
    t0 = time.monotonic()
    with hub._lock:                                  # the hub lock is free during the replay
        pass
    assert time.monotonic() - t0 < 0.5
    for t in loaders:
        t.join()
    assert len(calls) == 1                           # single flight
    assert hub.size(cold) == 1 and hot


def test_catalog_commits_with_the_genesis(tmp_path, monkeypatch):
    hub, key, card = _hub(tmp_path, cache_size=1)
    alice = AgentKey.generate()
    g, _ = builders.new_project(alice, alice.make_card("person"), visibility="public")
    real = hub.storage.catalog_stmt
    monkeypatch.setattr(hub.storage, "catalog_stmt",
                        lambda *a: ("INSERT INTO no_such_table VALUES (1)", ()))
    with pytest.raises(sqlite3.OperationalError):
        hub.create_project(g)
    pid = entry_hash(g)
    assert hub.storage.head(pid) is None            # nothing committed without its catalog row
    monkeypatch.setattr(hub.storage, "catalog_stmt", real)
    hub.create_project(g)                            # the client's retry succeeds
    _project(hub, alice)                             # evicts it
    assert hub.size(pid) == 1 and hub.project_count() == 2


def test_redaction_deletion_is_recorded_with_the_redaction(tmp_path, monkeypatch):
    app, http, repo, alice, client = _web(tmp_path)
    h, cid = _publish(tmp_path, repo, alice, client, "d.csv", b"SECRET,1\n")
    hub = app.state.hub
    monkeypatch.setattr(hub.storage, "delete_blob",
                        lambda *a: (_ for _ in ()).throw(OSError("storage down")))
    repo.append(builders.redact(repo.state, alice, h, reason="withdrawn"))
    sync.push(repo, client, agent=alice)
    pid = repo.state.project
    assert (pid, cid) in hub.storage.pending_shreds()
    monkeypatch.undo()
    hub.reshred()
    assert not hub.storage.has_blob(pid, cid) and not hub.storage.pending_shreds()


def _web(tmp_path):
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    app = create_app(tmp_path / "hub", key, card)
    http = TestClient(app)
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"), visibility="public")
    repo = Repo.init(tmp_path / "a", "alice", genesis)
    client = HubClient("http://testserver", agent=alice, http=http)
    sync.pin_hub(repo, "http://testserver", client)
    sync.push(repo, client, agent=alice)
    return app, http, repo, alice, client


def _publish(tmp_path, repo, alice, client, name, data, poison=False):
    p = tmp_path / "a" / name
    p.write_bytes(data)
    body, sec, size = repo.encrypt_file(alice, p)
    plain = sec.plain_sha256
    if poison:  # commit to a different plaintext hash than the ciphertext decrypts to
        plain = hashlib.sha256(b"something else").digest()
        body = dict(body, commitment=commitment.commit(sec.salt, plain).hex())
    h = repo.append(builders.entity(repo.state, alice, body, sec, name=name, plain_size=size))
    repo.append(builders.reveal(repo.state, alice, h, salt=sec.salt, plain_sha256=plain,
                                dek=sec.dek, name=name))
    sync.push(repo, client, agent=alice)
    return h, body["cid"]


def test_redaction_during_cold_decrypt_leaves_no_plaintext(tmp_path, monkeypatch):
    app, http, repo, alice, client = _web(tmp_path)
    h, cid = _publish(tmp_path, repo, alice, client, "d.csv", b"SECRET,1\n")
    pid = repo.state.project
    gate, inside = threading.Event(), threading.Event()
    real = web.aead.decrypt_stream

    def slow(dek, src, dst):
        info = real(dek, src, dst)
        inside.set()
        gate.wait(10)  # the redaction lands while this cold decrypt is in flight
        return info

    monkeypatch.setattr(web.aead, "decrypt_stream", slow)
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", http.get(f"/p/{pid}/files/{h}")))
    t.start()
    assert inside.wait(10)
    repo.append(builders.redact(repo.state, alice, h, reason="withdrawn"))
    sync.push(repo, client, agent=alice)
    gate.set()
    t.join(10)
    assert out["r"].status_code == 404 and b"SECRET" not in out["r"].content
    assert not app.state.hub.storage.published_path(pid, cid).exists()


def test_unverifiable_published_content_is_decrypted_once(tmp_path, monkeypatch):
    app, http, repo, alice, client = _web(tmp_path)
    bad, _ = _publish(tmp_path, repo, alice, client, "bad.bin", b"x" * 1000, poison=True)
    pid = repo.state.project
    calls, real = [], web.aead.decrypt_stream
    monkeypatch.setattr(web.aead, "decrypt_stream",
                        lambda *a: (calls.append(1), real(*a))[1])
    for _ in range(3):
        assert http.get(f"/p/{pid}/files/{bad}").status_code == 422
    assert len(calls) == 1


def test_plaintext_cache_is_bounded(tmp_path):
    storage = Storage(tmp_path / "hub")
    for i in range(3):
        f = storage.published_path("ab" * 32, f"{i:02x}" * 32)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"x" * 100)
    (f.parent / "leftover.part").write_bytes(b"x")
    storage.trim_published(250)
    assert len(list((tmp_path / "hub" / "published").glob("*/*/*[!t]"))) == 2
    assert storage.sweep_partials() >= 1


def test_overtaken_cold_load_is_not_cached_stale(tmp_path, monkeypatch):
    """Review 9: loaded, written, evicted while a gated loader replayed old state."""
    hub, *_ = _hub(tmp_path, cache_size=1)
    alice, bob = AgentKey.generate(), AgentKey.generate()
    g, _ = builders.new_project(alice, alice.make_card("person"), visibility="private")
    hub.create_project(g)
    P = entry_hash(g)
    local = st.ProjectState.from_genesis(g)
    add = builders.member_add(local, alice, bob.make_card("person"), "contributor")
    local.apply(add)
    hub.submit(P, add)
    q, _ = builders.new_project(alice, alice.make_card("person"), visibility="public")
    hub.create_project(q)                                   # evicts P
    Q = entry_hash(q)

    real = st.ProjectState.replay.__func__
    in_replay, release = threading.Event(), threading.Event()

    def replay(cls, log):
        if threading.current_thread().name == "T1":
            in_replay.set()
            release.wait(5)
        return real(cls, log)

    monkeypatch.setattr(st.ProjectState, "replay", classmethod(replay))
    remove, _ = builders.member_remove(local, alice, bob.id)

    # Thread schedule between submit's warm-up (_entry outside the lock) and `with self._lock`:
    # another request evicts P and a reader T1 starts a cold load of P.
    orig, armed = hub._entry, [True]

    def entry(p):
        r = orig(p)
        if armed[0] and p == P and not hub._lock._is_owned():
            armed[0] = False
            orig(Q)                                          # evicts P
            threading.Thread(target=hub.size, args=(P,), name="T1").start()
            assert in_replay.wait(5)                         # T1 holds a snapshot of size 2
        return r

    monkeypatch.setattr(hub, "_entry", entry)
    hub.submit(P, remove)                                    # inline load + append (#2)
    monkeypatch.setattr(hub, "_entry", orig)
    assert hub.storage.head(P)["size"] == 3
    orig(Q)                                                  # evicts P again
    release.set()
    for th in threading.enumerate():
        if th.name == "T1":
            th.join()
    state, log = hub._cache[P]
    assert len(log) == 3 == hub.storage.head(P)["size"]     # the overtaken snapshot is redone
    assert not state.members[bob.id].active                  # the removal is not lost


def test_cold_loads_are_capped(tmp_path, monkeypatch):
    from provena.server import hub as hub_mod
    from provena.server.hub import Unavailable

    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    hub = Hub(Storage(tmp_path / "hub"), key, card, cache_size=1, cold_loads=1)
    alice = AgentKey.generate()
    first, second = _project(hub, alice), _project(hub, alice)
    _project(hub, alice)                                  # both evicted
    monkeypatch.setattr(hub_mod, "COLD_LOAD_WAIT", 0.2)
    real, started = st.ProjectState.replay.__func__, threading.Event()

    def slow(cls, log):
        started.set()
        time.sleep(1.0)
        return real(cls, log)

    monkeypatch.setattr(st.ProjectState, "replay", classmethod(slow))
    t = threading.Thread(target=hub.size, args=(first,))
    t.start()
    assert started.wait(5)
    with pytest.raises(Unavailable, match="busy"):
        hub.size(second)                                  # the one slot is taken
    t.join()
