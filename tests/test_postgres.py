"""The hub's metadata on PostgreSQL (a throwaway local cluster; skipped without binaries)."""

import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("psycopg")
from fastapi.testclient import TestClient  # noqa: E402

from provena.client.hub import HubClient  # noqa: E402
from provena.core import builders  # noqa: E402
from provena.core.keys import AgentKey  # noqa: E402
from provena.sdk import sync  # noqa: E402
from provena.server.app import create_app, load_or_create_hub_key  # noqa: E402
from provena.store.repo import Repo  # noqa: E402

PG_BIN = next((Path(p) for p in ("/opt/homebrew/opt/postgresql@15/bin",
                                 "/usr/lib/postgresql/16/bin", "/usr/lib/postgresql/15/bin")
               if (Path(p) / "initdb").exists()), None)
if PG_BIN is None and shutil.which("initdb"):
    PG_BIN = Path(shutil.which("initdb")).parent
pytestmark = pytest.mark.skipif(PG_BIN is None, reason="PostgreSQL binaries not installed")


@pytest.fixture(scope="module")
def pg(tmp_path_factory):
    data = tmp_path_factory.mktemp("pgdata")
    env = {**os.environ, "LC_ALL": "C", "LANG": "C"}  # postgres refuses unusable locales
    subprocess.run([str(PG_BIN / "initdb"), "-D", str(data), "-A", "trust", "-U", "postgres",
                    "--locale=C", "-E", "UTF8"],
                   check=True, capture_output=True, env=env)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    subprocess.run([str(PG_BIN / "pg_ctl"), "-D", str(data), "-w", "-l", str(data / "log"),
                    "-o", f"-p {port} -c listen_addresses=127.0.0.1 -c unix_socket_directories=''",
                    "start"],
                   check=True, capture_output=True, env=env)
    yield f"postgresql://postgres@127.0.0.1:{port}/postgres"
    subprocess.run([str(PG_BIN / "pg_ctl"), "-D", str(data), "-w", "stop", "-m", "fast"],
                   capture_output=True, env=env)


def test_hub_on_postgres_survives_restart(pg, tmp_path):
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    http = TestClient(create_app(tmp_path / "hub", key, card, database=pg))
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"))
    repo = Repo.init(tmp_path / "a", "alice", genesis)
    for i in range(3):
        (tmp_path / "a" / f"f{i}.csv").write_text(str(i))
        body, secrets, size = repo.encrypt_file(alice, tmp_path / "a" / f"f{i}.csv")
        repo.append(builders.entity(repo.state, alice, body, secrets, name=f"f{i}",
                                    plain_size=size))
    client = HubClient("http://testserver", agent=alice, http=http)
    sync.pin_hub(repo, "http://testserver", client)
    res = sync.push(repo, client, agent=alice)
    assert res.pushed == 3 and res.head["size"] == 4  # genesis is created, not "pushed"
    assert not (tmp_path / "hub" / "hub.sqlite3").exists()   # metadata lives in Postgres
    restarted = TestClient(create_app(tmp_path / "hub", key, card, database=pg))
    again = HubClient("http://testserver", agent=alice, http=restarted)
    assert again.sth(repo.state.project)["size"] == 4
    assert len(again.entries(repo.state.project)) == 4
    w = AgentKey.generate()
    from provena.client.witness import Witness

    Witness(w, w.make_card("org"), tmp_path / "w.json").observe(
        HubClient("http://testserver", http=restarted), repo.state.project)
    assert again.latest_cosignatures(repo.state.project)["head"]["size"] == 4
