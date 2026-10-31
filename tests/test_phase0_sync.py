"""Phase 0 (agent testing): syncs that stopped half way or hid trouble behind exit 0."""

import json
import shutil

import pytest
from fastapi.testclient import TestClient

from provena.cli.main import main
from provena.client.hub import HubClient, HubError
from provena.server.app import create_app, load_or_create_hub_key
from provena.store.repo import Repo
from tests.test_mirror import MIRROR, PRIMARY, hubs  # noqa: F401 (fixture)


def test_rate_limited_requests_are_retried(monkeypatch):
    calls = []

    def once(self, *a, **k):
        calls.append(1)
        if len(calls) < 3:
            raise HubError(429, "rate limit exceeded", retry_after="0.01")
        return "ok"

    monkeypatch.setattr(HubClient, "_send_once", once)
    assert HubClient("http://x")._send("GET", "/") == "ok" and len(calls) == 3
    calls.clear()
    monkeypatch.setattr(HubClient, "retry_wait", 0.0)
    with pytest.raises(HubError):
        HubClient("http://x")._send("GET", "/")


def test_an_interrupted_push_is_reported(hubs, monkeypatch, capsys):  # noqa: F811
    tmp_path, http = hubs
    lab = tmp_path / "lab"
    (lab / "b.csv").write_text("b")
    assert main(["add", "b.csv"]) == 0

    def cut(*a, **k):
        raise KeyboardInterrupt

    real = HubClient.put_blob
    monkeypatch.setattr(HubClient, "put_blob", cut)
    assert main(["push"]) == 130                          # entries went, the file did not
    monkeypatch.setattr(HubClient, "put_blob", real)
    capsys.readouterr()
    assert main(["status"]) == 0
    assert "did not finish" in capsys.readouterr().out
    assert main(["doctor"]) == 1
    assert main(["push"]) == 0
    capsys.readouterr()
    assert main(["status"]) == 0
    assert "did not finish" not in capsys.readouterr().out


def test_hub_key_is_checked_before_anything_is_written(hubs, monkeypatch, capsys):  # noqa: F811
    tmp_path, http = hubs
    key, card = load_or_create_hub_key(tmp_path / "reset", "pw")      # same URL, new hub
    http[PRIMARY] = TestClient(create_app(tmp_path / "reset", key, card))
    capsys.readouterr()
    assert main(["push"]) == 6
    assert "nothing was pushed" in capsys.readouterr().err
    assert HubClient(PRIMARY, http=http[PRIMARY]).project(Repo.find().state.project) is None


def test_a_rolled_back_hub_is_named(hubs, monkeypatch, capsys):  # noqa: F811
    tmp_path, http = hubs
    lab = tmp_path / "lab"
    shutil.copytree(tmp_path / "a", tmp_path / "backup")             # operator's backup
    (lab / "c.csv").write_text("c")
    assert main(["add", "c.csv"]) == 0 and main(["push"]) == 0
    key, card = load_or_create_hub_key(tmp_path / "backup", "pw")
    http[PRIMARY] = TestClient(create_app(tmp_path / "backup", key, card))  # restored old copy
    capsys.readouterr()
    assert main(["pull"]) == 6
    assert "rolled back" in capsys.readouterr().err
    assert main(["doctor"]) == 1
    assert "rolled" in capsys.readouterr().out


def test_entries_stranded_by_a_rotation_exit_5_and_can_be_redone(hubs, monkeypatch,  # noqa: F811
                                                               capsys):
    tmp_path, http = hubs
    lab = tmp_path / "lab"
    assert main(["--agent", "bench", "keygen"]) == 0
    assert main(["member", "add", str(tmp_path / "home" / "agents" / "bench.card.json"),
                 "--role", "contributor"]) == 0
    pid = Repo.find().state.project
    monkeypatch.chdir(tmp_path)
    assert main(["--agent", "bench", "clone", PRIMARY, pid, "bench"]) == 0
    monkeypatch.chdir(tmp_path / "bench")
    (tmp_path / "bench" / "r.txt").write_text("result")
    assert main(["--agent", "bench", "add", "r.txt"]) == 0            # on the old epoch
    monkeypatch.chdir(lab)
    assert main(["rotate"]) == 0 and main(["push"]) == 0               # meanwhile: a rotation
    monkeypatch.chdir(tmp_path / "bench")
    capsys.readouterr()
    assert main(["--agent", "bench", "push"]) == 5
    assert "NOT pushed" in capsys.readouterr().err
    assert "r.txt" not in Repo.find().tracked
    assert main(["--agent", "bench", "doctor"]) == 1
    assert main(["--agent", "bench", "stranded", "redo"]) == 0
    assert main(["--agent", "bench", "push"]) == 0
    assert "r.txt" in Repo.find().tracked


def test_a_clone_from_a_mirror_does_not_fork_the_project(hubs, monkeypatch, capsys):  # noqa: F811
    tmp_path, http = hubs
    assert main(["mirror", MIRROR]) == 0
    pid = Repo.find().state.project
    monkeypatch.chdir(tmp_path)
    assert main(["clone", MIRROR, pid, "copy"]) == 0                  # the primary is "down"
    monkeypatch.chdir(tmp_path / "copy")
    (tmp_path / "copy" / "n.txt").write_text("n")
    assert main(["add", "n.txt"]) == 0
    capsys.readouterr()
    assert main(["push"]) == 5
    assert "--rehome" in capsys.readouterr().err
    assert main(["remote", "--rehome"]) == 0
    assert Repo.find().config["hub"] == PRIMARY
    assert main(["push"]) == 0
    assert main(["verify"]) == 0


def test_one_hub_process_per_data_directory(tmp_path, monkeypatch):
    from provena.cli import hubcmds
    from provena.cli.common import CliError

    held = hubcmds._lock_data_dir(tmp_path)
    with pytest.raises(CliError):
        hubcmds._lock_data_dir(tmp_path)
    held.close()
    hubcmds._lock_data_dir(tmp_path).close()


def test_concurrent_versions_of_one_path_are_a_conflict(hubs, monkeypatch, capsys):  # noqa: F811
    tmp_path, http = hubs
    lab = tmp_path / "lab"
    assert main(["--agent", "bench", "keygen"]) == 0
    assert main(["member", "add", str(tmp_path / "home" / "agents" / "bench.card.json"),
                 "--role", "contributor"]) == 0
    pid = Repo.find().state.project
    monkeypatch.chdir(tmp_path)
    assert main(["--agent", "bench", "clone", PRIMARY, pid, "bench"]) == 0
    monkeypatch.chdir(tmp_path / "bench")
    (tmp_path / "bench" / "plate.csv").write_text("well,od\nA1,0.9\n")      # bench's version
    assert main(["--agent", "bench", "add", "plate.csv"]) == 0
    monkeypatch.chdir(lab)
    (lab / "plate.csv").write_text("well,od\nA1,0.1\n")                      # the owner's version
    assert main(["add", "plate.csv"]) == 0 and main(["push"]) == 0
    monkeypatch.chdir(tmp_path / "bench")
    capsys.readouterr()
    assert main(["--agent", "bench", "push"]) == 5                          # E_CONFLICT
    assert "CONFLICT plate.csv" in capsys.readouterr().err
    assert main(["--json", "--agent", "bench", "status"]) == 0
    c = json.loads(capsys.readouterr().out)["data"]["conflicts"][0]
    assert main(["--agent", "bench", "resolve", "plate.csv", "--keep", c["theirs"]]) == 0
    assert (tmp_path / "bench" / "plate.csv").read_text() == "well,od\nA1,0.1\n"
    assert Repo.find().config["conflicts"] == []
    assert main(["--agent", "bench", "push"]) == 0


def test_resolve_keeps_unrecorded_local_edits(hubs, monkeypatch, capsys):  # noqa: F811
    tmp_path, http = hubs
    lab = tmp_path / "lab"
    assert main(["--agent", "bench", "keygen"]) == 0
    assert main(["member", "add", str(tmp_path / "home" / "agents" / "bench.card.json"),
                 "--role", "contributor"]) == 0
    pid = Repo.find().state.project
    monkeypatch.chdir(tmp_path)
    assert main(["--agent", "bench", "clone", PRIMARY, pid, "bench"]) == 0
    monkeypatch.chdir(tmp_path / "bench")
    (tmp_path / "bench" / "p.csv").write_text("bench")
    assert main(["--agent", "bench", "add", "p.csv"]) == 0
    monkeypatch.chdir(lab)
    (lab / "p.csv").write_text("owner")
    assert main(["add", "p.csv"]) == 0 and main(["push"]) == 0
    monkeypatch.chdir(tmp_path / "bench")
    assert main(["--agent", "bench", "push"]) == 5
    theirs = Repo.find().config["conflicts"][0]["theirs"]
    (tmp_path / "bench" / "p.csv").write_text("an edit nobody recorded")
    assert main(["--agent", "bench", "resolve", "p.csv", "--keep", theirs]) == 5
    assert (tmp_path / "bench" / "p.csv").read_text() == "an edit nobody recorded"
    assert main(["--agent", "bench", "resolve", "p.csv", "--keep", theirs, "--force"]) == 0
    assert (tmp_path / "bench" / "p.csv").read_text() == "owner"
