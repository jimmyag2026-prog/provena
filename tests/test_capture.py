import pytest

from provena import sdk
from provena.cli.main import main
from provena.sdk.capture import Capture


@pytest.fixture
def instrument(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PROVENA_PASSPHRASE", "pw")
    monkeypatch.setenv("PROVENA_SCRYPT_N", "1024")
    work = tmp_path / "lab"
    (work / "out").mkdir(parents=True)
    monkeypatch.chdir(work)
    main(["keygen", "--kind", "instrument", "--display", "plate-reader-01"])
    main(["init", "--name", "capture"])
    return work, Capture(sdk.open(work), work / "out")


def test_registers_only_stable_files_and_versions_changes(instrument):
    work, cap = instrument
    f = work / "out" / "run1.csv"
    f.write_text("a\n")
    assert cap.poll().registered == []          # first sighting: wait for stability
    first = cap.poll().registered
    assert [r for r, _ in first] == ["out/run1.csv"]
    assert cap.poll().registered == []          # unchanged: never re-registered

    f.write_text("a\nb\n")                      # instrument overwrote the file
    cap.poll()
    second = cap.poll().registered
    assert len(second) == 1
    entry = cap.repo.entry(second[0][1])
    assert first[0][1] in entry["refs"]         # new version points at the old one
    assert entry["body"]["capture"]["by"] == cap.project.agent.id


def test_restart_does_not_reregister(instrument):
    work, cap = instrument
    (work / "out" / "x.csv").write_text("x")
    cap.poll()
    cap.poll()
    again = Capture(cap.project, work / "out")
    again.poll()
    assert again.poll().registered == []


def test_cli_once(instrument, capsys):
    work, _ = instrument
    (work / "out" / "y.csv").write_text("y")
    assert main(["capture", "out", "--once", "--interval", "0.05"]) == 0
    assert "captured out/y.csv" in capsys.readouterr().out
