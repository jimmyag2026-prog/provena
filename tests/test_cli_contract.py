"""docs/spec/cli-contract-v1.md: one envelope on stdout, complete ids, exit codes, retries."""

import json
import sys

import pytest

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
    return work


def run(capsys, *argv):
    capsys.readouterr()
    code = main(["--json", *argv])
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 1, out                     # exactly one object on stdout
    env = json.loads(lines[0])
    assert env["schema"] == "provena-cli/1" and env["exit"] == code
    assert env["ok"] == (code == 0)
    return code, env


def test_envelopes_carry_complete_ids(env, capsys):
    code, k = run(capsys, "keygen")
    assert code == 0 and k["data"]["agent"]["id"].startswith("pv1a")
    code, i = run(capsys, "init", "--name", "x")
    pid = i["data"]["project"]
    assert len(pid) == 64
    (env / "a.csv").write_text("1")
    code, a = run(capsys, "add", "a.csv")
    entry = a["data"]["entries"][0]
    assert len(entry["hash"]) == 64 and entry["index"] == 1 and entry["path"] == "a.csv"
    code, again = run(capsys, "add", "a.csv")                  # a retry records nothing
    assert code == 0 and again["data"]["entries"][0]["unchanged"]
    code, r = run(capsys, "run", "--", sys.executable, "-c", "print('to stderr')")
    assert code == 0 and r["data"]["exit_code"] == 0 and len(r["data"]["activity"]["hash"]) == 64
    code, log = run(capsys, "log")
    assert [e["index"] for e in log["data"]["entries"]] == list(range(4))  # + transcript
    assert log["data"]["entries"][1]["path"] == "a.csv"
    code, st = run(capsys, "status")
    assert st["data"]["project"] == pid and st["data"]["changed"] == 0
    code, p = run(capsys, "prove", "a.csv", "-o", "a.pvb")
    code, v = run(capsys, "verify", "a.pvb", "--require", "log-sequenced")
    assert code == 1 and v["error"]["code"] == "E_REQUIRE" and not v["data"]["verify"]["accepted"]
    code, rv = run(capsys, "reveal", "a.csv")
    code, rv2 = run(capsys, "reveal", "a.csv")
    assert code == 0 and rv2["data"]["unchanged"]


def test_errors_are_envelopes_with_codes(env, capsys, monkeypatch):
    code, e = run(capsys, "status")
    assert code == 2 and e["error"]["code"] == "E_INPUT"
    code, e = run(capsys, "nonsense-command")
    assert code == 2 and e["error"]["code"] == "E_USAGE"
    monkeypatch.delenv("PROVENA_PASSPHRASE")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    code, e = run(capsys, "keygen")
    assert code == 4 and e["error"]["code"] == "E_NO_PASSPHRASE"


def test_run_output_does_not_corrupt_the_envelope(env, capsys):
    run(capsys, "keygen")
    run(capsys, "init", "--name", "x")
    code, r = run(capsys, "run", "--", sys.executable, "-c",
                  "print('{\"schema\": \"fake\"}'); raise SystemExit(3)")
    assert code == 3 and r["data"]["exit_code"] == 3 and r["schema"] == "provena-cli/1"


def test_references_and_fewer_ids_to_carry(env, capsys, monkeypatch):
    run(capsys, "keygen")
    run(capsys, "init", "--name", "x")
    (env / "a.csv").write_text("1")
    code, a = run(capsys, "add", "a.csv")
    h = a["data"]["entries"][0]["hash"]
    code, s = run(capsys, "show", "#1")
    assert code == 0 and s["data"]["hash"] == h
    code, e = run(capsys, "show", "#9")
    assert code == 2 and "#0…#1" in e["error"]["message"]
    code, e = run(capsys, "show", h[:3])
    assert code == 2 and "at least 6" in e["error"]["message"]
    code, e = run(capsys, "show", "nothere.csv")
    assert code == 2 and "provena add" in e["error"]["message"]
    code, c = run(capsys, "--agent", "other", "keygen")
    code, c = run(capsys, "config", "agent", "other")
    assert c["data"]["agent"] == "other" and c["warnings"][0]["code"] == "W_NOT_MEMBER"
    code, e = run(capsys, "clone", "http://h", "abc123", "d")
    assert code == 2 and "full 64-hex" in e["error"]["message"]


def test_verify_json_is_structured(env, capsys):
    run(capsys, "keygen")
    run(capsys, "init", "--name", "x")
    (env / "p.md").write_text("plan")
    (env / "d.csv").write_text("1")
    run(capsys, "plan", "p.md")
    run(capsys, "add", "d.csv")
    code, r = run(capsys, "run", "--plan", "p.md", "--used", "d.csv", "--out", "o.txt", "--",
                  sys.executable, "-c", "open('o.txt','w').write('x')")
    out = r["data"]["generated"][0]["hash"]
    run(capsys, "prove", "o.txt", "--open", "o.txt", "-o", "o.pvb")
    code, v = run(capsys, "verify", "o.pvb")
    data = v["data"]["verify"]
    rows = {e["hash"]: e for e in data["entries"]}
    assert rows[out]["target"] and rows[out]["opened"] and rows[out]["kind"] == "entity"
    pre = data["preregistration"][0]
    assert pre["holds"] and not pre["ordered"]           # order only from a trusted log
    assert data["evidence"]["log_trusted"] is False


def test_json_lines_for_batches(env, capsys):
    main(["keygen"])
    main(["init", "--name", "x"])
    for n in "abc":
        (env / f"{n}.csv").write_text(n)
    capsys.readouterr()
    assert main(["--json-lines", "add", "a.csv", "b.csv", "c.csv"]) == 0
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert [x.get("path") for x in lines[:3]] == ["a.csv", "b.csv", "c.csv"]
    assert lines[-1]["schema"] == "provena-cli/1" and len(lines) == 4


def test_retest_findings(env, capsys, tmp_path):
    """Phase 2 re-tests by agents: codes an agent can act on, stdout kept clean."""
    run(capsys, "keygen")
    run(capsys, "init", "--name", "x")
    (env / "a.csv").write_text("1")
    run(capsys, "add", "a.csv")
    code, r = run(capsys, "run", "--used", "a.csv", "--out", "o.txt", "--", sys.executable,
                  "-c", "print('noise'); open('o.txt','w').write('x')")
    assert code == 0 and r["data"]["generated"][0]["path"] == "o.txt"   # stdout stayed clean
    code, r = run(capsys, "run", "--used", "a.csv", "--", sys.executable, "-c",
                  "raise SystemExit(3)")
    assert code == 3 and r["error"]["code"] == "E_PROGRAM" and r["data"]["status"] == "failed"
    code, e = run(capsys, "show", "#99")
    assert e["error"]["code"] == "E_NOT_FOUND"
    code, e = run(capsys, "--agent", "nobody", "card")
    assert code == 2 and e["error"]["code"] == "E_NOT_FOUND"
    (tmp_path / "secret.txt").write_text("s")
    (env / "link.txt").symlink_to(tmp_path / "secret.txt")
    code, e = run(capsys, "add", "link.txt")
    assert code == 2                                               # outside, through a link
    cid = Repo(env).entry(Repo(env).tracked["a.csv"]["entry"])["body"]["cid"]
    blob = Repo(env).blob_path(cid)
    blob.write_bytes(blob.read_bytes()[:-1] + b"\0")               # damaged ciphertext
    (env / "a.csv").unlink()
    code, e = run(capsys, "checkout", "a.csv")
    assert code == 6 and e["error"]["code"] == "E_CORRUPT" and not blob.exists()
    log = env / ".provena" / "log.jsonl"
    lines = log.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["body"]["size"] += 1                                     # edited outside Provena
    log.write_text("\n".join([lines[0], json.dumps(entry), *lines[2:]]) + "\n")
    code, e = run(capsys, "status")
    assert code == 6 and e["error"]["code"] == "E_CORRUPT"


def test_stranded_lists_and_maps_hashes(env, capsys):
    run(capsys, "keygen")
    run(capsys, "init", "--name", "x")
    (env / "f.txt").write_text("f")
    run(capsys, "add", "f.txt")
    e = json.loads((env / ".provena" / "log.jsonl").read_text().splitlines()[1])
    (env / ".provena" / "stranded.jsonl").write_text(json.dumps(e) + "\n")
    code, ls = run(capsys, "stranded", "list")
    assert ls["command"] == "stranded list" and ls["data"]["stranded"][0]["path"] == "f.txt"
    (env / "f.txt").write_text("changed")
    code, rd = run(capsys, "stranded", "redo")
    assert code == 0 and rd["data"]["redone"][0]["old"] == Repo.hash_of(e)
    assert rd["warnings"][0]["code"] == "W_CHANGED"


def test_seal_now_publish_after_the_date(env, capsys, monkeypatch):
    run(capsys, "keygen")
    run(capsys, "init", "--name", "x")
    data = env / "fresh"
    (data / "sub").mkdir(parents=True)
    (data / "a.csv").write_text("1,2")
    (data / "sub" / "b.csv").write_text("3,4")
    (data / ".hidden").write_text("not part of the package")
    code, s = run(capsys, "seal", "fresh", "--reveal-after", "2999-01-01T00:00Z")
    assert code == 0 and [f["path"] for f in s["data"]["files"]] == ["fresh/a.csv",
                                                                     "fresh/sub/b.csv"]
    manifest = s["data"]["manifest"]["hash"]
    code, e = run(capsys, "unseal", "fresh.seal.json")
    assert code == 5 and e["error"]["code"] == "E_TOO_EARLY"
    code, u = run(capsys, "unseal", "fresh.seal.json", "--force")
    assert code == 0 and manifest in u["data"]["published"] and len(u["data"]["published"]) == 3
    code, p = run(capsys, "prove", "fresh.seal.json", "-o", "seal.pvb")
    code, v = run(capsys, "verify", "seal.pvb")
    assert code == 0
    code, again = run(capsys, "unseal", "fresh.seal.json", "--force")
    assert code == 0 and again["data"]["published"] == []        # idempotent


def test_builtin_trust_is_listed_and_can_be_switched_off(env, capsys):
    from provena.store.home import Home, default_trust

    builtin = default_trust()
    trial = next(iter(builtin["logs"]))
    assert trial in Home().trust()["logs"]
    code, d = run(capsys, "trust", "defaults")
    assert code == 0 and d["data"]["defaults"] is True and trial in d["data"]["builtin"]["logs"]
    code, lst = run(capsys, "trust", "list")
    assert trial in lst["data"]["trust"]["logs"] and trial not in lst["data"]["explicit"]["logs"]
    code, off = run(capsys, "trust", "defaults", "off")
    assert off["data"]["defaults"] is False and trial not in Home().trust()["logs"]


def test_doctor_for_someone_who_only_verifies(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "empty-home"))
    monkeypatch.chdir(tmp_path)
    code, d = run(capsys, "doctor")
    names = {c["name"]: c["ok"] for c in d["data"]["checks"]}
    assert code == 0 and names["verifier mode"] and names["trusted logs"]   # built-in trust


def test_one_builtin_id_can_be_dropped(env, capsys):
    from provena.store.home import Home, default_trust

    trial = next(iter(default_trust()["logs"]))
    assert main(["trust", "remove", "log", trial]) == 0
    assert trial not in Home().trust()["logs"]
    assert next(iter(default_trust()["tsas"])) in Home().trust()["tsas"]   # the others stay
    assert main(["trust", "add", "log", trial]) == 0 and trial in Home().trust()["logs"]
