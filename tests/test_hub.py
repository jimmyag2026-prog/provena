import json
import shutil

import pytest
from fastapi.testclient import TestClient

from provena.client.hub import HubClient, HubError
from provena.core import builders, entries
from provena.core.bundle import make_bundle
from provena.core.errors import VerificationError
from provena.core.keys import AgentKey
from provena.core.verify import TRUST_LOG, verify_bundle
from provena.sdk import sync
from provena.server.app import create_app, load_or_create_hub_key
from provena.store.repo import Repo

URL = "http://testserver"


@pytest.fixture
def hub_app(tmp_path):
    key, card = load_or_create_hub_key(tmp_path / "hub", "hubpw")
    return create_app(tmp_path / "hub", key, card)


@pytest.fixture
def world(tmp_path, hub_app):
    """Alice's local repo with some data, plus a client factory bound to the in-process hub."""
    http = TestClient(hub_app)

    def client(agent=None):
        return HubClient(URL, agent=agent, http=http)

    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person", "alice"), name="p")
    repo = Repo.init(tmp_path / "alice", "alice", genesis)
    (tmp_path / "alice" / "raw.csv").write_bytes(b"1,2,3\n")
    body, secrets, size = repo.encrypt_file(alice, tmp_path / "alice" / "raw.csv")
    raw = repo.append(builders.entity(repo.state, alice, body, secrets, name="raw.csv",
                                      plain_size=size))
    sync.pin_hub(repo, URL, client())
    return {"repo": repo, "alice": alice, "client": client, "raw": raw, "app": hub_app,
            "tmp": tmp_path}


def test_push_then_clone_by_member(world):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    res = sync.push(repo, client(alice), agent=alice)
    assert res.pushed == 1 and res.blobs_up == 1 and res.head["size"] == 2

    bob = AgentKey.generate()
    repo.append(builders.member_add(repo.state, alice, bob.make_card("person", "bob"),
                                    "contributor"))
    sync.push(repo, client(alice), agent=alice)

    bob_repo, r = sync.clone(URL, repo.state.project, world["tmp"] / "bob", "bob", bob,
                             client(bob))
    assert r.pulled == 3 and r.blobs_down == 1
    assert bob_repo.state.order == repo.state.order
    cid = repo.entry(world["raw"])["body"]["cid"]
    assert bob_repo.blob_path(cid).read_bytes() == repo.blob_path(cid).read_bytes()


def test_concurrent_writers_merge(world):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    bob = AgentKey.generate()
    repo.append(builders.member_add(repo.state, alice, bob.make_card("person"), "contributor"))
    sync.push(repo, client(alice), agent=alice)
    bob_repo, _ = sync.clone(URL, repo.state.project, world["tmp"] / "bob", "bob", bob,
                             client(bob))
    # both write offline, then sync: hub order wins, nobody's entry is lost
    plan_body = {"commitment": "aa" * 32}
    salt = builders.ContentSecrets(b"\0" * 32, b"\0" * 32, b"\0" * 32)
    repo.append(builders.plan(repo.state, alice, plan_body, salt, title="a"))
    bob_repo.append(builders.plan(bob_repo.state, bob, {"commitment": "bb" * 32}, salt,
                                  title="b"))
    sync.push(bob_repo, client(bob), agent=bob)
    res = sync.push(repo, client(alice), agent=alice)
    assert res.pulled == 1 and res.pushed == 1
    sync.pull(bob_repo, client(bob), agent=bob)
    assert bob_repo.state.order == repo.state.order


def test_private_project_requires_membership(world):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    sync.push(repo, client(alice), agent=alice)
    pid = repo.state.project
    with pytest.raises(HubError) as anon:
        client().entries(pid)
    assert anon.value.status == 401
    with pytest.raises(HubError) as stranger:
        client(AgentKey.generate()).entries(pid)
    assert stranger.value.status == 403
    cid = repo.entry(world["raw"])["body"]["cid"]
    with pytest.raises(HubError):
        client().get_blob(pid, cid)
    # STH and proofs are public: they reveal nothing but the log size
    assert client().sth(pid)["size"] == 2


def test_revealed_with_key_blob_is_public(world):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    raw = world["raw"]
    private = builders.open_entry_fields(repo.state, alice, repo.entry(raw))
    repo.append(builders.reveal(repo.state, alice, raw, salt=bytes.fromhex(private["salt"]),
                                plain_sha256=bytes.fromhex(private["plain_sha256"]),
                                dek=repo.blob_dek(alice, raw)))
    sync.push(repo, client(alice), agent=alice)
    cid = repo.entry(raw)["body"]["cid"]
    assert client().get_blob(repo.state.project, cid) == repo.blob_path(cid).read_bytes()


def test_hub_rejects_invalid_and_bad_blobs(world):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    sync.push(repo, client(alice), agent=alice)
    pid = repo.state.project
    mallory = AgentKey.generate()
    forged = entries.build(mallory, "plan", project=pid, body={"commitment": "00" * 32})
    with pytest.raises(HubError) as exc:
        client().submit(pid, forged)
    assert exc.value.status == 422
    cid = repo.entry(world["raw"])["body"]["cid"]
    with pytest.raises(HubError):
        client().put_blob(pid, "cd" * 32, b"junk")
    client().put_blob(pid, cid, b"junk")  # already stored: ignored, never overwritten
    assert client(alice).get_blob(pid, cid) == repo.blob_path(cid).read_bytes()


def test_redact_shreds_hub_blob(world):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    sync.push(repo, client(alice), agent=alice)
    repo.append(builders.redact(repo.state, alice, world["raw"], reason="consent withdrawn"))
    sync.push(repo, client(alice), agent=alice)
    cid = repo.entry(world["raw"])["body"]["cid"]
    assert not client(alice).has_blob(repo.state.project, cid)


def test_forked_hub_detected(world, tmp_path):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    sync.push(repo, client(alice), agent=alice)
    # The hub operator rewrites history: same key, new database with a different entry 1.
    hub_dir = tmp_path / "hub"
    (hub_dir / "hub.sqlite3").unlink()
    key, card = load_or_create_hub_key(hub_dir, "hubpw")
    forked = TestClient(create_app(hub_dir, key, card))
    fork_client = HubClient(URL, agent=alice, http=forked)
    fork_client.create_project(repo.log()[0])
    other = builders.plan(repo.state, alice, {"commitment": "ee" * 32},
                          builders.ContentSecrets(b"\0" * 32, b"\0" * 32, b"\0" * 32), title="x")
    # pretend alice never wrote raw.csv: her chain continues straight from genesis
    other = entries.build(alice, "plan", project=repo.state.project, prev=repo.state.order[0],
                          body=other["body"],
                          sealed=other["sealed"])
    fork_client.submit(repo.state.project, other)
    with pytest.raises(VerificationError):
        sync.pull(repo, fork_client, agent=alice)


def test_hub_head_makes_log_sequenced_bundle(world):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    res = sync.push(repo, client(alice), agent=alice)
    b = make_bundle(repo.log(), res.head, repo.config["hub_card"], [world["raw"]])
    report = verify_bundle(b, trusted_logs={repo.config["hub_card"]["id"]})
    assert report.ok, report.errors
    assert report.trust == TRUST_LOG


def test_hub_restart_reloads_state(world, tmp_path):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    sync.push(repo, client(alice), agent=alice)
    key, card = load_or_create_hub_key(tmp_path / "hub", "hubpw")
    restarted = HubClient(URL, agent=alice, http=TestClient(create_app(tmp_path / "hub", key,
                                                                       card)))
    assert restarted.sth(repo.state.project)["size"] == 2
    assert json.dumps(restarted.entries(repo.state.project)[1]["entry"]) == json.dumps(
        repo.log()[1])


def test_entries_pagination(world, monkeypatch):
    from provena.server import app as app_module

    repo, alice, client = world["repo"], world["alice"], world["client"]
    sync.push(repo, client(alice), agent=alice)
    for i in range(5):
        repo.append(builders.plan(repo.state, alice, {"commitment": f"{i:02x}" * 32},
                                  builders.ContentSecrets(b"\0" * 32, b"\0" * 32, b"\0" * 32),
                                  title=str(i)))
    sync.push(repo, client(alice), agent=alice)
    monkeypatch.setattr(app_module, "PAGE_SIZE", 2)  # read at request time via closure
    got = client(alice).entries(repo.state.project)
    assert [g["index"] for g in got] == list(range(7))


def test_corrupt_project_does_not_take_down_hub(world, tmp_path):
    """Regression (security review #4): one unreplayable log made Hub.__init__ fail for all."""
    import sqlite3

    repo, alice, client = world["repo"], world["alice"], world["client"]
    sync.push(repo, client(alice), agent=alice)
    db = sqlite3.connect(tmp_path / "hub" / "hub.sqlite3")
    row = db.execute("SELECT entry FROM entries WHERE idx = 1").fetchone()
    tampered = json.loads(row[0])
    tampered["ts"] += 1
    db.execute("UPDATE entries SET entry = ? WHERE idx = 1", (json.dumps(tampered),))
    db.commit()
    key, card = load_or_create_hub_key(tmp_path / "hub", "hubpw")
    restarted = HubClient(URL, agent=alice,
                          http=TestClient(create_app(tmp_path / "hub", key, card)))
    assert restarted.info()["card"]["id"] == card["id"]
    with pytest.raises(HubError) as exc:
        restarted.entries(repo.state.project)
    assert exc.value.status == 503
    with pytest.raises(HubError) as exc:  # re-creating a quarantined project is refused
        restarted.create_project(repo.log()[0])
    assert exc.value.status == 409


def test_cross_project_cid_alias_gives_nothing(world, tmp_path):
    """Regression (security review #3): another project referencing a victim's cid could read
    the private ciphertext anonymously and shred it via its own redaction."""
    repo, alice, client = world["repo"], world["alice"], world["client"]
    sync.push(repo, client(alice), agent=alice)
    victim_body = repo.entry(world["raw"])["body"]
    cid = victim_body["cid"]

    mallory = AgentKey.generate()
    genesis, _ = builders.new_project(mallory, mallory.make_card("person"), visibility="public")
    evil = Repo.init(tmp_path / "evil", "m", genesis)
    sync.pin_hub(evil, URL, client())
    secrets = builders.ContentSecrets(b"\0" * 32, b"\0" * 32, b"\0" * 32)
    pek = builders.epoch_key(evil.state, mallory)
    body = {**victim_body, "dek": builders.b64u(builders.wrap(pek, b"\0" * 32,
                                                              bytes.fromhex(victim_body["commitment"])))}
    alias = evil.append(builders.entity(evil.state, mallory, body, secrets, name="x",
                                        plain_size=1))
    sync.push(evil, client(mallory), agent=mallory)
    with pytest.raises(HubError) as exc:
        client().get_blob(evil.state.project, cid)
    assert exc.value.status == 404
    evil.append(builders.redact(evil.state, mallory, alias, reason="x"))
    sync.push(evil, client(mallory), agent=mallory)
    assert client(alice).get_blob(repo.state.project, cid) == repo.blob_path(cid).read_bytes()


def test_streamed_upload_rejects_wrong_bytes_without_publishing(world, tmp_path):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    (tmp_path / "alice" / "big.bin").write_bytes(b"\x07" * (3 << 20))
    body, secrets, size = repo.encrypt_file(alice, tmp_path / "alice" / "big.bin")
    h = repo.append(builders.entity(repo.state, alice, body, secrets, name="big.bin",
                                    plain_size=size))
    pid, cid = repo.state.project, body["cid"]
    sync.push(repo, client(alice), agent=alice)          # pushes entries and the 3 MiB blob
    assert client(alice).get_blob(pid, cid) == repo.blob_path(cid).read_bytes()
    assert h
    # a second project entity whose blob is uploaded with tampered bytes is refused
    (tmp_path / "alice" / "b2.bin").write_bytes(b"\x08" * 1000)
    body2, s2, size2 = repo.encrypt_file(alice, tmp_path / "alice" / "b2.bin")
    repo.append(builders.entity(repo.state, alice, body2, s2, name="b2", plain_size=size2))
    data = bytearray(repo.blob_path(body2["cid"]).read_bytes())
    repo.blob_path(body2["cid"]).unlink()  # keep local copy out of push
    sync.push(repo, client(alice), agent=alice)
    data[-1] ^= 1
    with pytest.raises(HubError) as exc:
        client().put_blob(pid, body2["cid"], bytes(data))
    assert exc.value.status == 422
    assert not client(alice).has_blob(pid, body2["cid"])


def test_upload_is_capped_at_ledger_size_and_leaves_nothing(world, tmp_path):
    """Regression (review 3 #2): spooling up to 1 GiB regardless of the ledger, temp files
    left behind on errors."""
    repo, alice, client = world["repo"], world["alice"], world["client"]
    raw = world["raw"]
    cid = repo.entry(raw)["body"]["cid"]
    blob = repo.blob_path(cid).read_bytes()
    repo.blob_path(cid).unlink()
    sync.push(repo, client(alice), agent=alice)      # entries only: the hub expects the blob
    with pytest.raises(HubError) as exc:
        client().put_blob(repo.state.project, cid, blob + b"x" * 4096)
    assert exc.value.status == 413
    hub_dir = tmp_path / "hub"
    assert not list(hub_dir.rglob("*.part")) and not list(hub_dir.glob("*.upload"))
    client().put_blob(repo.state.project, cid, blob)
    assert client(alice).has_blob(repo.state.project, cid)


def test_partial_uploads_swept_on_start(tmp_path):
    from provena.server.storage import Storage

    (tmp_path / "blobs" / "ab" ).mkdir(parents=True)
    (tmp_path / "blobs" / "ab" / "tmpx.part").write_bytes(b"junk")
    (tmp_path / "old.upload").write_bytes(b"junk")
    Storage(tmp_path)
    assert not list(tmp_path.rglob("*.part")) and not list(tmp_path.glob("*.upload"))


def test_upload_finishing_after_redaction_is_not_published(world):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    raw = world["raw"]
    cid = repo.entry(raw)["body"]["cid"]
    blob = repo.blob_path(cid).read_bytes()
    repo.blob_path(cid).unlink()
    sync.push(repo, client(alice), agent=alice)
    hub = world["app"].state.hub
    tmp = hub.storage.upload_path(repo.state.project, cid)   # upload in flight…
    tmp.write_bytes(blob)
    repo.append(builders.redact(repo.state, alice, raw, reason="withdrawn"))
    sync.push(repo, client(alice), agent=alice)              # …redaction sequenced meanwhile
    with pytest.raises(VerificationError, match="redacted"):
        hub.commit_upload(repo.state.project, cid, tmp, len(blob), cid)
    assert not hub.storage.has_blob(repo.state.project, cid)


def test_bundles_carry_signed_receipts(world, tmp_path):
    import copy as _copy

    repo, alice, client = world["repo"], world["alice"], world["client"]
    res = sync.push(repo, client(alice), agent=alice)
    hub_id = repo.config["hub_card"]["id"]
    b = make_bundle(repo.log(), res.head, repo.config["hub_card"], [world["raw"]],
                    **sync.bundle_evidence(repo, res.head))
    assert any("receipt" in it for it in b["entries"])
    report = verify_bundle(b, trusted_logs={hub_id})
    assert report.ok and any("was sequenced at" in f for f in report.facts)
    untrusted = verify_bundle(b)
    assert untrusted.ok and not any("was sequenced at" in f for f in untrusted.facts)
    bad = _copy.deepcopy(b)
    item = next(it for it in bad["entries"] if "receipt" in it)
    item["receipt"]["integrated_time"] -= 1
    assert not verify_bundle(bad).ok

    if shutil.which("node"):
        from tests.test_js_verifier import ROOT, _run_node

        out = _run_node(tmp_path, {
            "vectors": json.loads((ROOT / "tests" / "vectors" / "core.json").read_text()),
            "bundles": {"ok": b, "bad": bad},
            "options": {"ok": {"trustedLogs": [hub_id]}, "bad": {"trustedLogs": [hub_id]}}})
        assert out["results"]["ok"]["ok"] and not out["results"]["bad"]["ok"]
        assert [f for f in out["results"]["ok"]["facts"] if "sequenced at" in f] == [
            f for f in report.facts if "sequenced at" in f]


def test_health_and_metrics(world):
    repo, alice, client = world["repo"], world["alice"], world["client"]
    sync.push(repo, client(alice), agent=alice)
    http = client().http
    assert http.get("/healthz").json() == {"ok": True, "projects": 1, "quarantined": 0}
    text = http.get("/metrics").text
    assert "provena_projects 1" in text and "provena_entries 2" in text
    assert "provena_anchor_attempts_total 0" in text and "provena_anchor_independent 0" in text
    http.post("/v1/anchors/run")
    text = http.get("/metrics").text
    assert "provena_anchor_attempts_total 1" in text and "provena_anchor_failures_total 0" in text


def test_head_on_private_blob_requires_membership(world):
    """Red team: HEAD revealed whether a cid exists in a private project."""
    repo, alice, client = world["repo"], world["alice"], world["client"]
    sync.push(repo, client(alice), agent=alice)
    cid = repo.entry(world["raw"])["body"]["cid"]
    path = f"/v1/projects/{repo.state.project}/blobs/{cid}"
    assert client().http.head(path).status_code == 401
    assert client(alice).has_blob(repo.state.project, cid)


def test_lazy_loading_cache_and_catalog(tmp_path):
    """Start-up loads nothing; projects load on demand into a bounded LRU; listings come from
    the catalog; a pre-catalog database is migrated once."""
    from provena.server.hub import Hub
    from provena.server.storage import Storage

    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    hub = Hub(Storage(tmp_path / "hub"), key, card, cache_size=2)
    alice = AgentKey.generate()
    pids = []
    for _ in range(4):
        g, _ = builders.new_project(alice, alice.make_card("person"), visibility="public")
        res = hub.create_project(g)
        pids.append(res["receipt"]["project"])
    assert len(hub._cache) == 2                                  # bounded
    st = hub._state(pids[0])                                     # evicted earlier: reloads
    hub.submit(pids[0], builders.meta(st, alice, title="first"))
    assert {r["project"]: r["meta"] for r in hub.storage.catalog()}[pids[0]] == {"title": "first"}

    restarted = Hub(Storage(tmp_path / "hub"), key, card)
    assert len(restarted._cache) == 0 and restarted.project_count() == 4
    assert restarted.size(pids[0]) == 2

    import sqlite3
    db = sqlite3.connect(tmp_path / "hub" / "hub.sqlite3")
    db.execute("DELETE FROM catalog")
    db.commit()
    migrated = Hub(Storage(tmp_path / "hub"), key, card)
    assert migrated.project_count() == 4
    assert {r["project"] for r in migrated.storage.catalog()} == set(pids)


def test_project_creation_allowlist_and_per_creator_cap(tmp_path):
    key, card = load_or_create_hub_key(tmp_path / "hub", "hubpw")
    allow = tmp_path / "creators.txt"
    alice, mallory = AgentKey.generate(), AgentKey.generate()
    allow.write_text(f"# registered labs\n{alice.id}  # alice\n")
    http = TestClient(create_app(tmp_path / "hub", key, card, creators_file=allow,
                                 projects_per_creator=2))

    def create(agent, name):
        genesis, _ = builders.new_project(agent, agent.make_card("person"), name=name)
        return http.post("/v1/projects", json={"entry": genesis})

    assert create(alice, "a1").status_code == 201
    r = create(mallory, "m1")
    assert r.status_code == 403 and mallory.id in r.json()["error"]
    allow.write_text(allow.read_text() + mallory.id + "\n")   # edited without a restart
    assert create(mallory, "m1").status_code == 201
    assert create(alice, "a2").status_code == 201
    r = create(alice, "a3")
    assert r.status_code == 403 and "limit of 2" in r.json()["error"]
    allow.unlink()                                             # unreadable allowlist: closed
    assert create(mallory, "m2").status_code == 403


def test_push_checks_blobs_in_one_request(world, monkeypatch):
    """Push asked the hub about every local blob with its own HEAD request."""
    repo, alice, client = world["repo"], world["alice"], world["client"]
    for i in range(5):
        f = world["tmp"] / "alice" / f"d{i}.csv"
        f.write_bytes(f"{i}\n".encode())
        body, secrets, size = repo.encrypt_file(alice, f)
        repo.append(builders.entity(repo.state, alice, body, secrets, name=f.name,
                                    plain_size=size))
    c = client(alice)
    calls = []
    monkeypatch.setattr(c, "has_blob", lambda *a: calls.append(a) or True)
    assert sync.push(repo, c, agent=alice).blobs_up == 6
    assert sync.push(repo, c, agent=alice).blobs_up == 0          # nothing missing any more
    assert calls == []

    pid = repo.state.project
    stranger = HubClient(URL, agent=AgentKey.generate(), http=c.http)
    with pytest.raises(HubError) as exc:                            # private: members only
        stranger.missing_blobs(pid, ["x"])
    assert exc.value.status in (401, 403)
    with pytest.raises(HubError) as exc:
        c._send("POST", f"/v1/projects/{pid}/blobs/missing", json={"cids": ["x"] * 1001})
    assert exc.value.status == 400


def test_signed_requests_behind_a_prefix_stripping_proxy(tmp_path):
    """DO trial hub: Caddy strips /provena, but clients sign the path they sent."""
    key, card = load_or_create_hub_key(tmp_path / "hub", "hubpw")
    app = create_app(tmp_path / "hub", key, card, base_path="/provena")

    async def caddy(scope, receive, send):  # `uri strip_prefix /provena`
        if scope["type"] == "http" and scope["path"].startswith("/provena"):
            scope = {**scope, "path": scope["path"][len("/provena"):] or "/",
                     "raw_path": scope["path"][len("/provena"):].encode() or b"/"}
        await app(scope, receive, send)

    http = TestClient(caddy, base_url="http://testserver/provena")
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person", "a"), name="p")
    repo = Repo.init(tmp_path / "alice", "alice", genesis)
    client = HubClient("http://testserver/provena", agent=alice, http=http)
    sync.pin_hub(repo, "http://testserver/provena", client)
    assert sync.push(repo, client, agent=alice).head["size"] == 1   # create + signed reads
    assert sync.pull(repo, client, agent=alice).pulled == 0
