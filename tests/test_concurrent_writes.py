"""Lane-D/E finding: two writers on one project forked the author's chain (permanently)."""

import os
import subprocess
import sys
import threading

from provena.cli.main import main
from provena.core.state import ProjectState
from provena.sdk import open as sdk_open
from provena.store.repo import Repo


def _setup(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PROVENA_PASSPHRASE", "pw")
    monkeypatch.setenv("PROVENA_SCRYPT_N", "1024")
    work = tmp_path / "p"
    work.mkdir()
    monkeypatch.chdir(work)
    assert main(["keygen"]) == 0 and main(["init", "--name", "c"]) == 0
    return work


def test_threads_with_their_own_project_objects(tmp_path, monkeypatch):
    work = _setup(tmp_path, monkeypatch)
    errors = []

    def writer(tag):
        proj = sdk_open(work, passphrase="pw")       # each holds its own cached state
        for i in range(15):
            f = work / f"{tag}{i}.txt"
            f.write_text(f"{tag}{i}")
            try:
                proj.add(f)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=writer, args=(t,)) for t in "ab"]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    state = ProjectState.replay(Repo(work).log())
    assert len(state.order) == 31
    assert len(Repo(work).tracked) == 30


def test_processes_adding_at_once(tmp_path, monkeypatch):
    work = _setup(tmp_path, monkeypatch)
    for i in range(10):
        (work / f"a{i}.txt").write_text(f"a{i}")
        (work / f"b{i}.txt").write_text(f"b{i}")
    code = ("import sys\nfrom provena.cli.main import main\n"
            "for f in sys.argv[1:]:\n    assert main(['add', f]) == 0\n")
    procs = [subprocess.Popen([sys.executable, "-c", code, *[f"{t}{i}.txt" for i in range(10)]],
                              env=dict(os.environ)) for t in "ab"]
    assert [p.wait(timeout=120) for p in procs] == [0, 0]
    assert main(["verify"]) == 0
    assert len(Repo(work).state.order) == 21


def test_stale_project_object_after_a_cli_write(tmp_path, monkeypatch):
    work = _setup(tmp_path, monkeypatch)
    proj = sdk_open(work, passphrase="pw")
    (work / "x.txt").write_text("x")
    proj.add(work / "x.txt")
    (work / "y.txt").write_text("y")
    assert main(["add", "y.txt"]) == 0                   # behind the SDK object's back
    (work / "z.txt").write_text("z")
    proj.add(work / "z.txt")
    assert main(["verify"]) == 0


def test_entry_built_on_a_stale_state_is_refused_not_written(tmp_path, monkeypatch):
    from provena.core import builders
    from provena.store.home import Home
    from provena.store.repo import RepoError

    work = _setup(tmp_path, monkeypatch)
    agent = Home().load_agent("default", "pw")
    stale = Repo(work)
    entry = builders.meta(stale.state, agent, title="stale")      # built, not yet appended
    assert main(["meta", "--title", "other"]) == 0                 # another writer
    try:
        stale.append(entry)
        raise AssertionError("stale entry was accepted")
    except RepoError as exc:
        assert "run it again" in str(exc)
    assert main(["verify"]) == 0
