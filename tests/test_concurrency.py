"""Hub writes run in worker threads: hammer one hub from many threads and check that every
log stays consistent (heads match replays, nothing lost or duplicated, pages never 500)."""

import threading

from fastapi.testclient import TestClient

from provena.client.hub import HubClient
from provena.core import builders, entries, merkle
from provena.core.keys import AgentKey
from provena.core.state import ProjectState
from provena.sdk import sync
from provena.server.app import create_app, load_or_create_hub_key
from provena.store.repo import Repo

URL = "http://testserver"


def test_concurrent_writers_and_readers(tmp_path):
    from provena.server.limits import Limits

    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    app = create_app(tmp_path / "hub", key, card,
                     limits=Limits(writes_per_minute=1e6, burst=10**6, project_burst=1000))
    http = TestClient(app)
    errors: list[str] = []
    repos = []

    def writer(i: int):
        try:
            alice = AgentKey.generate()
            genesis, _ = builders.new_project(alice, alice.make_card("person"),
                                              visibility="public")
            repo = Repo.init(tmp_path / f"w{i}", "a", genesis)
            client = HubClient(URL, agent=alice, http=http)
            sync.pin_hub(repo, URL, client)
            for j in range(8):
                (tmp_path / f"w{i}" / f"f{j}").write_bytes(f"{i}-{j}".encode())
                body, sec, size = repo.encrypt_file(alice, tmp_path / f"w{i}" / f"f{j}")
                repo.append(builders.entity(repo.state, alice, body, sec, name=f"f{j}",
                                            plain_size=size))
                if j % 3 == 2:
                    sync.push(repo, client, agent=alice)
            sync.push(repo, client, agent=alice)
            repos.append(repo)
        except Exception as exc:  # collect, assert in the main thread
            errors.append(f"writer {i}: {exc!r}")

    def reader(stop: threading.Event):
        while not stop.is_set():
            for path in ("/", "/healthz", "/metrics"):
                r = http.get(path)
                if r.status_code != 200:
                    errors.append(f"GET {path} -> {r.status_code}")
            try:
                app.state.hub.run_anchor()
            except Exception as exc:
                errors.append(f"anchor: {exc!r}")

    stop = threading.Event()
    readers = [threading.Thread(target=reader, args=(stop,)) for _ in range(3)]
    writers = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
    for t in readers + writers:
        t.start()
    for t in writers:
        t.join()
    stop.set()
    for t in readers:
        t.join()
    assert not errors, errors[:5]
    hub = app.state.hub
    assert len(repos) == 8
    for repo in repos:
        pid = repo.state.project
        stored = hub.storage.load_log(pid)
        assert [entries.entry_hash(e) for e in stored] == repo.state.order  # same order
        state = ProjectState.replay(stored)
        head = hub.storage.head(pid)
        assert head["size"] == len(state.order) == 9
        assert head["root"] == merkle.root([entries.entry_leaf(e) for e in stored]).hex()
    restarted = create_app(tmp_path / "hub", key, card)   # everything reloads cleanly
    assert not restarted.state.hub.broken
