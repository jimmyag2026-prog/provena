"""The hub on S3-compatible storage (moto in-process mock)."""

import threading

import pytest

pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")
from fastapi.testclient import TestClient  # noqa: E402
from moto import mock_aws  # noqa: E402

from provena.client.hub import HubClient, HubError  # noqa: E402
from provena.core import builders  # noqa: E402
from provena.core.keys import AgentKey  # noqa: E402
from provena.sdk import sync  # noqa: E402
from provena.server.app import create_app, load_or_create_hub_key  # noqa: E402
from provena.server.blobstore import S3BlobStore  # noqa: E402
from provena.store.repo import Repo  # noqa: E402

URL = "http://testserver"


@pytest.fixture
def s3(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test",
                 "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        client = boto3.client("s3")
        client.create_bucket(Bucket="lab-hub")
        yield client


def test_hub_round_trip_on_s3(s3, tmp_path):
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    store = S3BlobStore("lab-hub", spool_dir=tmp_path / "hub" / "spool", client=s3)
    http = TestClient(create_app(tmp_path / "hub", key, card, blob_store=store))
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"))
    repo = Repo.init(tmp_path / "a", "alice", genesis)
    (tmp_path / "a" / "big.bin").write_bytes(b"\x05" * (3 << 20))
    body, secrets, size = repo.encrypt_file(alice, tmp_path / "a" / "big.bin")
    h = repo.append(builders.entity(repo.state, alice, body, secrets, name="big.bin",
                                    plain_size=size))
    client = HubClient(URL, agent=alice, http=http)
    sync.pin_hub(repo, URL, client)
    assert sync.push(repo, client, agent=alice).blobs_up == 1
    pid, cid = repo.state.project, body["cid"]
    obj = s3.head_object(Bucket="lab-hub", Key=f"provena/{pid}/{cid}")
    assert obj["ContentLength"] == body["size"]

    bob = AgentKey.generate()
    repo.append(builders.member_add(repo.state, alice, bob.make_card("person"), "viewer"))
    sync.push(repo, client, agent=alice)
    bob_repo, res = sync.clone(URL, pid, tmp_path / "b", "bob", bob,
                               HubClient(URL, agent=bob, http=http))
    assert res.blobs_down == 1
    assert bob_repo.blob_path(cid).read_bytes() == repo.blob_path(cid).read_bytes()

    with pytest.raises(HubError):  # anonymous read of a private project on S3 too
        HubClient(URL, http=http).get_blob(pid, cid)
    repo.append(builders.redact(repo.state, alice, h, reason="withdrawn"))
    sync.push(repo, client, agent=alice)
    assert s3.list_objects_v2(Bucket="lab-hub").get("KeyCount", 0) == 0
    assert not list((tmp_path / "hub" / "spool").glob("*.part"))


def test_s3_rejects_oversize_upload(s3, tmp_path):
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    store = S3BlobStore("lab-hub", spool_dir=tmp_path / "hub" / "spool", client=s3)
    http = TestClient(create_app(tmp_path / "hub", key, card, blob_store=store))
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"))
    repo = Repo.init(tmp_path / "a", "alice", genesis)
    (tmp_path / "a" / "x").write_bytes(b"x")
    body, secrets, size = repo.encrypt_file(alice, tmp_path / "a" / "x")
    repo.append(builders.entity(repo.state, alice, body, secrets, name="x", plain_size=size))
    blob = repo.blob_path(body["cid"]).read_bytes()
    repo.blob_path(body["cid"]).unlink()
    client = HubClient(URL, agent=alice, http=http)
    sync.pin_hub(repo, URL, client)
    sync.push(repo, client, agent=alice)
    with pytest.raises(HubError) as exc:
        client.put_blob(repo.state.project, body["cid"], blob + b"pad")
    assert exc.value.status == 413
    assert s3.list_objects_v2(Bucket="lab-hub").get("KeyCount", 0) == 0


def test_failed_s3_delete_never_serves_redacted_content(s3, tmp_path):
    """Regression (review 4 #3): a transient delete failure left redacted ciphertext served."""
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    store = S3BlobStore("lab-hub", spool_dir=tmp_path / "hub" / "spool", client=s3)
    real_delete = store.delete
    store.delete = lambda *a: (_ for _ in ()).throw(ConnectionError("endpoint down"))
    http = TestClient(create_app(tmp_path / "hub", key, card, blob_store=store))
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"), visibility="public")
    repo = Repo.init(tmp_path / "a", "alice", genesis)
    (tmp_path / "a" / "x").write_bytes(b"secret")
    body, secrets, size = repo.encrypt_file(alice, tmp_path / "a" / "x")
    h = repo.append(builders.entity(repo.state, alice, body, secrets, name="x", plain_size=size))
    client = HubClient(URL, agent=alice, http=http)
    sync.pin_hub(repo, URL, client)
    sync.push(repo, client, agent=alice)
    repo.append(builders.redact(repo.state, alice, h, reason="withdrawn"))
    sync.push(repo, client, agent=alice)                       # delete fails, push succeeds
    pid, cid = repo.state.project, body["cid"]
    assert s3.list_objects_v2(Bucket="lab-hub")["KeyCount"] == 1  # object still there…
    with pytest.raises(HubError) as exc:                          # …but never served
        HubClient(URL, http=http).get_blob(pid, cid)
    assert exc.value.status == 404
    store.delete = real_delete
    create_app(tmp_path / "hub", key, card, blob_store=store)    # restart retries the delete
    assert s3.list_objects_v2(Bucket="lab-hub").get("KeyCount", 0) == 0


def test_s3_publish_happens_outside_the_hub_lock(s3, tmp_path):
    """Regression (review 4 #4): a 1 GiB S3 upload held the sequencing lock."""
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    store = S3BlobStore("lab-hub", spool_dir=tmp_path / "hub" / "spool", client=s3)
    app = create_app(tmp_path / "hub", key, card, blob_store=store)
    hub = app.state.hub
    seen = []
    real_publish = store.publish

    def lock_held_elsewhere() -> bool:
        """True if another thread cannot take the hub lock right now."""
        result = []

        def probe():
            got = hub._lock.acquire(blocking=False)
            result.append(not got)
            if got:
                hub._lock.release()

        t = threading.Thread(target=probe)
        t.start()
        t.join()
        return result[0]

    store.publish = lambda *a: (seen.append(lock_held_elsewhere()), real_publish(*a))[1]
    http = TestClient(app)
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"))
    repo = Repo.init(tmp_path / "a", "alice", genesis)
    (tmp_path / "a" / "x").write_bytes(b"x")
    body, secrets, size = repo.encrypt_file(alice, tmp_path / "a" / "x")
    repo.append(builders.entity(repo.state, alice, body, secrets, name="x", plain_size=size))
    client = HubClient(URL, agent=alice, http=http)
    sync.pin_hub(repo, URL, client)
    sync.push(repo, client, agent=alice)
    assert seen == [False]
