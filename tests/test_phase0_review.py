"""Independent review of Phase 0: each finding, reproduced."""

import io
import os
import shutil
import sys

import pytest
from fastapi.testclient import TestClient

from provena.cli import ledger
from provena.cli.main import main
from provena.client.hub import HubClient
from provena.server.app import create_app, load_or_create_hub_key
from provena.store.repo import Repo
from tests.test_mirror import MIRROR, PRIMARY, hubs  # noqa: F401 (fixture)


def test_mirroring_from_a_mirror_clone_is_refused(hubs, monkeypatch):  # noqa: F811
    tmp_path, _ = hubs
    assert main(["mirror", MIRROR]) == 0
    pid = Repo.find().state.project
    monkeypatch.chdir(tmp_path)
    assert main(["clone", MIRROR, pid, "c1"]) == 0
    monkeypatch.chdir(tmp_path / "c1")
    assert main(["mirror", PRIMARY]) == 5           # would record the mirror as a primary


def test_only_admins_record_the_primary(hubs, monkeypatch):  # noqa: F811
    tmp_path, http = hubs
    assert main(["--agent", "bob", "keygen"]) == 0
    assert main(["member", "add", str(tmp_path / "home" / "agents" / "bob.card.json"),
                 "--role", "contributor"]) == 0
    assert main(["push"]) == 0 and main(["mirror", MIRROR]) == 0
    from provena.store.home import Home

    bob = Home().load_agent("bob", "pw")
    pid = Repo.find().state.project
    r = HubClient(MIRROR, agent=bob, http=http[MIRROR])
    with pytest.raises(Exception, match="403"):
        r.set_primary(pid, "http://evil", Repo.find().config["hub_card"])


def test_a_rollback_followed_by_new_writes_is_named(hubs, monkeypatch, capsys):  # noqa: F811
    tmp_path, http = hubs
    lab = tmp_path / "lab"
    shutil.copytree(tmp_path / "a", tmp_path / "backup")
    (lab / "c.csv").write_text("c")
    assert main(["add", "c.csv"]) == 0 and main(["push"]) == 0
    key, card = load_or_create_hub_key(tmp_path / "backup", "pw")
    http[PRIMARY] = TestClient(create_app(tmp_path / "backup", key, card))
    monkeypatch.chdir(tmp_path)                            # a teammate writes to the old copy
    pid = Repo.find(lab).state.project
    assert main(["clone", PRIMARY, pid, "mate"]) == 0
    monkeypatch.chdir(tmp_path / "mate")
    for name in ("x.csv", "y.csv"):
        (tmp_path / "mate" / name).write_text(name)
        assert main(["add", name]) == 0
    assert main(["push"]) == 0
    monkeypatch.chdir(lab)
    capsys.readouterr()
    assert main(["pull"]) == 6
    assert "rolled back and then written to" in capsys.readouterr().err


def test_run_survives_a_closed_output_pipe(tmp_path, monkeypatch):
    class Gone(io.RawIOBase):
        def writable(self):
            return True

        def write(self, b):
            raise BrokenPipeError

    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BufferedWriter(Gone())))
    proc = ledger._execute([sys.executable, "-c", "print('x' * 1_000_000)"],
                           tmp_path / "t" / "run.log")
    assert proc.returncode == 0
    assert (tmp_path / "t" / "run.log").stat().st_size > 1_000_000


def test_hub_secrets_mounted_by_containers(tmp_path, monkeypatch):
    from provena.store.secrets import read_secret

    f = tmp_path / "hub_pass"
    f.write_text("pw \n")
    f.chmod(0o444)
    monkeypatch.setenv("PROVENA_HUB_PASSPHRASE_FILE", str(f))
    assert read_secret("x", env="PROVENA_HUB_PASSPHRASE", service=True) == "pw"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PROVENA_PASSPHRASE", "pw")
    monkeypatch.setenv("PROVENA_SCRYPT_N", "1024")
    (tmp_path / "w").mkdir()
    monkeypatch.chdir(tmp_path / "w")
    assert main(["keygen"]) == 0 and main(["init", "--name", "x"]) == 0
    return tmp_path / "w"


def test_add_refuses_names_checkouts_would_refuse(env):
    (env / ".git").mkdir()
    (env / ".git" / "config").write_text("x")
    for name in ("a:b.txt", "back\\slash.txt"):
        (env / name).write_text("x")
    for bad in (".git/config", "a:b.txt", "back\\slash.txt"):
        assert main(["add", bad]) == 2, bad
    if os.path.exists(env / ".PROVENA" / "config.json"):        # case-insensitive filesystem
        assert main(["add", ".PROVENA/config.json"]) == 2


def test_agent_names_from_before_still_load(env):
    assert main(["--agent", "lab laptop", "keygen"]) == 0
    assert main(["--agent", "lab laptop", "card"]) == 0
    assert main(["--agent", ".hidden", "keygen"]) == 2


def test_run_with_out_keeps_the_terminal(env, monkeypatch):
    seen = []
    real = ledger._execute
    monkeypatch.setattr(ledger, "_execute", lambda cmd, t: seen.append(t) or real(cmd, t))
    assert main(["run", "--out", "res", "--", sys.executable, "-c", "pass"]) == 0
    assert seen == [None]                                   # not captured
    assert main(["verify"]) == 0                            # still recorded
