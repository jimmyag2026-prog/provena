"""Phase 0 (agent testing): inputs an agent gets wrong, and runs without a terminal."""

import json
import sys

import pytest

from provena import sdk
from provena.cli.main import main
from provena.store.repo import Repo


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PROVENA_PASSPHRASE", "pw")
    monkeypatch.setenv("PROVENA_SCRYPT_N", "1024")
    work = tmp_path / "exp"
    work.mkdir()
    monkeypatch.chdir(work)
    assert main(["keygen"]) == 0 and main(["init", "--name", "x"]) == 0
    return work


def _kinds(capsys):
    capsys.readouterr()
    assert main(["log", "--json"]) == 0
    return [e["kind"] for e in json.loads(capsys.readouterr().out)]


def test_no_terminal_and_no_passphrase_is_a_clean_auth_error(env, monkeypatch, capsys):
    monkeypatch.delenv("PROVENA_PASSPHRASE")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    capsys.readouterr()
    assert main(["log"]) == 4
    assert "PROVENA_PASSPHRASE_FILE" in capsys.readouterr().err
    assert main(["hub", "serve", "--data", str(env / "hub")]) == 4


def test_passphrase_file(env, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("PROVENA_PASSPHRASE")
    f = tmp_path / "pw.txt"
    f.write_text("pw\n")
    f.chmod(0o644)
    monkeypatch.setenv("PROVENA_PASSPHRASE_FILE", str(f))
    assert main(["log"]) == 4                                     # readable by others
    f.chmod(0o600)
    assert main(["log"]) == 0
    monkeypatch.setenv("PROVENA_PASSPHRASE_FILE_DEFAULT", str(tmp_path / "missing"))
    assert main(["log"]) == 4                                     # per-agent file wins


def test_agent_names_cannot_leave_the_agents_folder(env, tmp_path):
    assert main(["keygen", "--name", "../evil"]) == 2
    assert not (tmp_path / "home" / "evil.key.json").exists()
    assert main(["--agent", "../evil", "log"]) == 2


def test_add_refuses_paths_that_would_poison_the_ledger(env, tmp_path, capsys):
    (tmp_path / "outside.txt").write_text("o")
    (env / "d").mkdir()
    (env / "ok.txt").write_text("ok")
    for bad in [str(tmp_path / "outside.txt"), "../outside.txt", ".provena/config.json", "d"]:
        assert main(["add", bad]) == 2, bad
    assert main(["add", "ok.txt", "missing.txt"]) == 2            # nothing of the batch
    assert _kinds(capsys) == ["genesis"]
    (env / "link.txt").symlink_to(env / "ok.txt")
    assert main(["add", "link.txt"]) == 0
    assert "link.txt" in Repo(env).tracked                        # its own name


def test_runs_without_declared_files_are_recorded(env, capsys):
    assert main(["run", "--", sys.executable, "-c", "print('hello')"]) == 0
    assert main(["run", "--out", "res", "--", sys.executable, "-c",
                 "raise SystemExit(3)"]) == 3                     # failed, wrote nothing
    assert _kinds(capsys)[1:] == ["entity", "activity", "entity", "activity"]
    transcripts = [p for p in Repo(env).tracked if p.startswith("transcripts/")]
    assert len(transcripts) == 2
    assert b"hello" in (env / transcripts[0]).read_bytes() or \
        b"hello" in (env / transcripts[1]).read_bytes()
    (env / "s.py").write_text("print(open('data.csv').read())")
    (env / "data.csv").write_text("1,2")
    assert main(["run", "--", sys.executable, "s.py", "data.csv"]) == 0  # inputs from argv


def test_steps_are_opened_on_the_ledger(env, capsys):
    main(["run", "--", sys.executable, "-c", "raise SystemExit(4)"])
    act = [Repo.hash_of(e) for e in Repo(env).log() if e["kind"] == "activity"][-1]
    assert Repo(env).entry(act)["body"]["status"] == "failed"     # public at once (rules 2)
    capsys.readouterr()
    assert main(["--json", "reveal", act[:12]]) == 0              # its details become public
    assert json.loads(capsys.readouterr().out)["data"]["details"]["exit_code"] == 4
    assert main(["reveal", act[:12]]) == 0                        # idempotent
    assert main(["prove", act[:12], "--open", act[:12], "-o", "x.pvb"]) == 2   # use reveal
    assert main(["prove", act[:12], "-o", "y.pvb"]) == 0
    assert main(["verify", "y.pvb"]) == 0


def test_sdk_params_and_tool_errors(env):
    proj = sdk.open(env, passphrase="pw")
    with proj.run("train", params={"lr": 0.05, "layers": (2, 3), "big": 2**70}) as r:
        (env / "m.json").write_text("{}")
        r.output(env / "m.json")
    assert r.activity is not None
    with pytest.raises(ZeroDivisionError):                          # the tool's own error
        with proj.run("search the web", params={"q": "x"}) as r2:
            raise ZeroDivisionError("tool failed")
    assert r2.activity is not None                                 # recorded without files
    with pytest.raises(TypeError):
        with proj.run("bad", params={"f": object()}):
            raise AssertionError("must fail before the tool runs")
    assert main(["verify"]) == 0


def test_ciphertext_chunk_size_is_bounded():
    """v2 review: decrypt_stream read one chunk of whatever size the header claimed."""
    import io

    from provena.core import aead
    from provena.core.errors import DecryptionError

    key = bytes(32)
    ct = bytearray(aead.encrypt_bytes(key, b"hello"))
    assert aead.decrypt_bytes(key, bytes(ct)) == b"hello"
    ct[4:8] = (aead.MAX_CHUNK + 1).to_bytes(4, "big")
    with pytest.raises(DecryptionError, match="chunk size"):
        aead.decrypt_stream(key, io.BytesIO(bytes(ct)), io.BytesIO())
