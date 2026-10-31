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
    assert main(["keygen", "--display", "Ada"]) == 0
    assert main(["init", "--name", "binding-assay"]) == 0
    return work


def _log(capsys):
    capsys.readouterr()
    assert main(["log", "--json"]) == 0
    return json.loads(capsys.readouterr().out)


def test_end_to_end_experiment(env, capsys):
    (env / "protocol.md").write_text("Measure Kd of X:Y; success if < 10 nM\n")
    (env / "raw.csv").write_text("conc,signal\n1,0.1\n10,0.5\n")
    (env / "fit.py").write_text(
        "import pathlib; pathlib.Path('out').mkdir(exist_ok=True);"
        "pathlib.Path('out/kd.txt').write_text('Kd=7nM')\n")
    assert main(["plan", "protocol.md", "--title", "prereg"]) == 0
    assert main(["add", "raw.csv"]) == 0
    assert main(["run", "--plan", "protocol.md", "--used", "raw.csv", "--used", "fit.py",
                 "--out", "out", "--", sys.executable, "fit.py"]) == 0
    log = _log(capsys)
    assert [e["kind"] for e in log] == ["genesis", "plan", "entity", "entity", "entity",
                                        "activity"]
    activity = log[-1]["body"]
    assert activity["plan"] and len(activity["used"]) == 2 and len(activity["generated"]) == 1

    assert main(["cat", "out/kd.txt"]) == 0
    assert capsys.readouterr().out == "Kd=7nM"
    assert main(["verify"]) == 0
    assert "OK" in capsys.readouterr().out
    assert main(["status"]) == 0
    assert "clean" in capsys.readouterr().out

    assert main(["reveal", "protocol.md", "--with-key"]) == 0
    assert main(["log"]) == 0
    assert "prereg" in capsys.readouterr().out


def test_failed_run_is_recorded(env, capsys):
    (env / "in.txt").write_text("x")
    rc = main(["run", "--used", "in.txt", "--", sys.executable, "-c", "raise SystemExit(3)"])
    assert rc == 3
    assert "negative results" in capsys.readouterr().out
    assert _log(capsys)[-1]["kind"] == "activity"


def test_tampering_is_detected(env, capsys):
    (env / "raw.csv").write_text("a,b\n")
    main(["add", "raw.csv"])
    repo = Repo.find(env)
    cid = repo.state.entries[repo.state.order[-1]]["body"]["cid"]
    blob = repo.blob_path(cid)
    data = bytearray(blob.read_bytes())
    data[-1] ^= 1
    blob.write_bytes(bytes(data))
    assert main(["verify"]) == 1
    assert "blob does not match cid" in capsys.readouterr().out

    (env / "raw.csv").write_text("a,b\nedited\n")
    main(["status"])
    assert "modified  raw.csv" in capsys.readouterr().out


def test_log_tamper_breaks_replay(env, capsys):
    (env / "raw.csv").write_text("a\n")
    main(["add", "raw.csv"])
    log_path = env / ".provena" / "log.jsonl"
    lines = log_path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["ts"] += 1
    lines[1] = json.dumps(entry)
    log_path.write_text("\n".join(lines) + "\n")
    assert main(["verify", "--no-decrypt"]) == 1


def test_member_flow(env, tmp_path, capsys, monkeypatch):
    assert main(["--agent", "bob", "keygen"]) == 0
    card = tmp_path / "home" / "agents" / "bob.card.json"
    assert main(["member", "add", str(card), "--role", "reviewer"]) == 0
    (env / "d.txt").write_text("d")
    main(["add", "d.txt"])
    assert main(["--agent", "bob", "attest", "d.txt", "--type", "review", "--verdict",
                 "pass"]) == 0
    assert main(["--agent", "bob", "add", "d.txt"]) == 2  # reviewers cannot register data
    bob_id = json.loads(card.read_text())["id"]
    assert main(["member", "rm", bob_id]) == 0
    assert main(["redact", "d.txt", "--reason", "withdrawn"]) == 0
    assert main(["verify"]) == 0


def test_wrong_passphrase(env, monkeypatch, capsys):
    monkeypatch.setenv("PROVENA_PASSPHRASE", "nope")
    assert main(["log"]) == 4                                   # EXIT_AUTH
    assert "wrong passphrase" in capsys.readouterr().err


def test_prove_and_verify_bundle(env, tmp_path, capsys):
    (env / "protocol.md").write_text("H1\n")
    (env / "raw.csv").write_text("1,2\n")
    main(["plan", "protocol.md"])
    main(["add", "raw.csv"])
    main(["run", "--plan", "protocol.md", "--used", "raw.csv", "--out", "res.txt", "--",
          sys.executable, "-c", "open('res.txt','w').write('ok')"])
    out = tmp_path / "res.pvb"
    assert main(["prove", "res.txt", "--open", "res.txt", "-o", str(out)]) == 0
    capsys.readouterr()
    assert main(["verify", str(out), "--content", f"{_hash_of(env, 'res.txt')}=res.txt"]) == 0
    text = capsys.readouterr().out
    assert "VALID" in text and "matches its commitment" in text

    full = tmp_path / "full.pvb"
    assert main(["prove", "res.txt", "--full", "--open", "protocol.md", "--embed",
                 "-o", str(full)]) == 0
    assert main(["verify", str(full)]) == 0

    (env / "res.txt").write_text("tampered")
    capsys.readouterr()
    assert main(["verify", str(out), "--content", f"{_hash_of(env, 'res.txt')}=res.txt"]) == 1
    assert "INVALID" in capsys.readouterr().out


def _hash_of(env, path):
    return Repo.find(env).tracked[path]["entry"][:12]


def test_cli_push_clone_via_hub(env, tmp_path, monkeypatch, capsys):
    from fastapi.testclient import TestClient

    from provena.client.hub import HubClient
    from provena.sdk import sync
    from provena.server.app import create_app, load_or_create_hub_key

    key, card = load_or_create_hub_key(tmp_path / "hubdata", "hubpw")
    http = TestClient(create_app(tmp_path / "hubdata", key, card))
    monkeypatch.setattr(sync, "make_client",
                        lambda url, agent: HubClient(url, agent=agent, http=http))
    (env / "raw.csv").write_text("1\n")
    main(["add", "raw.csv"])
    assert main(["remote", "http://testserver"]) == 0
    assert main(["push"]) == 0
    assert "pushed 1 entries, 1 blobs" in capsys.readouterr().out
    pid = Repo.find(env).config["project"]
    clone_dir = tmp_path / "copy"
    assert main(["clone", "http://testserver", pid, str(clone_dir)]) == 0
    monkeypatch.chdir(clone_dir)
    capsys.readouterr()
    assert main(["cat", "raw.csv"]) == 0  # not checked out here: resolved from the ledger
    assert capsys.readouterr().out == "1\n"
    h = Repo.find(env).tracked["raw.csv"]["entry"]
    assert main(["cat", h[:12]]) == 0 and main(["cat", "#1"]) == 0
    assert main(["cat", h[:4]]) == 2                  # too short to be unambiguous for long
    assert capsys.readouterr().out == "1\n1\n"
    assert main(["verify"]) == 0


@pytest.fixture
def hubbed(env, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from provena.client.hub import HubClient
    from provena.sdk import sync
    from provena.server.app import create_app, load_or_create_hub_key

    key, card = load_or_create_hub_key(tmp_path / "hubdata", "hubpw")
    http = TestClient(create_app(tmp_path / "hubdata", key, card))
    monkeypatch.setattr(sync, "make_client",
                        lambda url, agent: HubClient(url, agent=agent, http=http))
    assert main(["remote", "http://testserver"]) == 0
    return env


def test_share_with_reviewer(hubbed, tmp_path, monkeypatch, capsys):
    (hubbed / "raw.csv").write_text("secret,data\n")
    (hubbed / "other.csv").write_text("not shared\n")
    main(["add", "raw.csv", "other.csv"])
    main(["push"])
    assert main(["--agent", "rev", "keygen"]) == 0
    card = tmp_path / "home" / "agents" / "rev.card.json"
    bundle = tmp_path / "share.pvb"
    assert main(["share", "raw.csv", "--to", str(card), "-o", str(bundle)]) == 0

    out = tmp_path / "inbox"
    monkeypatch.chdir(tmp_path)
    capsys.readouterr()
    assert main(["--agent", "rev", "open", str(bundle), "--hub", "http://testserver",
                 "-o", str(out)]) == 0
    assert (out / "raw.csv").read_text() == "secret,data\n"
    # the grant does not open anything else, and a stranger can open nothing
    assert main(["--agent", "x", "keygen"]) == 0
    assert main(["--agent", "x", "open", str(bundle), "--hub", "http://testserver"]) == 2


def test_publish_then_anyone_opens(hubbed, tmp_path, monkeypatch, capsys):
    (hubbed / "result.txt").write_text("Kd = 7 nM\n")
    main(["add", "result.txt"])
    assert main(["publish", "result.txt"]) == 0
    bundle = tmp_path / "pub.pvb"
    assert main(["prove", "result.txt", "-o", str(bundle)]) == 0
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "nobody"))
    monkeypatch.chdir(tmp_path)
    assert main(["open", str(bundle), "--hub", "http://testserver", "-o", "pub"]) == 0
    files = list((tmp_path / "pub").iterdir())
    assert len(files) == 1 and files[0].read_text() == "Kd = 7 nM\n"
    assert files[0].name == "result.txt"  # publish also publishes the name


def test_checkout_after_clone(hubbed, tmp_path, monkeypatch, capsys):
    (hubbed / "data").mkdir()
    (hubbed / "data" / "a.csv").write_text("1\n")
    main(["add", "data/a.csv"])
    main(["push"])
    pid = Repo.find(hubbed).config["project"]
    dest = tmp_path / "clone"
    assert main(["clone", "http://testserver", pid, str(dest)]) == 0
    monkeypatch.chdir(dest)
    assert main(["checkout"]) == 0
    assert (dest / "data" / "a.csv").read_text() == "1\n"
    capsys.readouterr()
    assert main(["status"]) == 0
    assert "clean" in capsys.readouterr().out


def test_unsafe_ledger_path_rejected():
    from provena.cli.main import CliError, _safe_relpath

    for bad in ("../x", "/etc/passwd", "a/../../b", "", ".provena/heads.jsonl",
                "data/.git/config"):
        with pytest.raises(CliError):
            _safe_relpath(bad)
    assert str(_safe_relpath("./a/b.csv")) == "a/b.csv"


def test_lineage(env, capsys):
    (env / "protocol.md").write_text("H\n")
    (env / "raw.csv").write_text("1\n")
    main(["plan", "protocol.md"])
    main(["add", "raw.csv"])
    main(["run", "--plan", "protocol.md", "--used", "raw.csv", "--out", "mid.txt", "--",
          sys.executable, "-c", "open('mid.txt','w').write('m')"])
    main(["run", "--used", "mid.txt", "--out", "final.txt", "--",
          sys.executable, "-c", "open('final.txt','w').write('f')"])
    capsys.readouterr()
    assert main(["lineage", "final.txt"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("entity")
    assert "used entity" in out and "mid.txt" in out and "raw.csv" in out
    assert "under plan" in out and "protocol.md" in out


def test_trust_store_drives_trust_level(hubbed, tmp_path, capsys):
    (hubbed / "r.txt").write_text("r\n")
    main(["add", "r.txt"])
    main(["push"])
    b = tmp_path / "r.pvb"
    main(["prove", "r.txt", "-o", str(b)])
    capsys.readouterr()
    assert main(["verify", str(b), "--require", "log-sequenced"]) == 0  # remote trusted it
    assert "VALID (log-sequenced)" in capsys.readouterr().out
    hub_id = Repo.find(hubbed).config["hub_card"]["id"]
    assert main(["trust", "remove", "log", hub_id]) == 0
    capsys.readouterr()
    assert main(["verify", str(b), "--require", "log-sequenced"]) == 1
    assert "VALID (unverified)" in capsys.readouterr().out
    assert main(["verify", str(b), "--trust-log", hub_id, "--require", "log-sequenced"]) == 0


def test_cite_and_entry_page(hubbed, capsys, monkeypatch):
    from provena.sdk import sync

    (hubbed / "kd.json").write_text("{}")
    main(["add", "kd.json"])
    assert main(["push"]) == 0
    capsys.readouterr()
    assert main(["cite", "kd.json", "--format", "json"]) == 0
    rec = json.loads(capsys.readouterr().out)
    assert rec["index"] == 1 and rec["head"]["size"] >= 2
    assert rec["url"].endswith(f"/p/{rec['project']}/e/{rec['entry']}")
    assert main(["cite", "kd.json", "--format", "bibtex"]) == 0
    assert "@misc{provena:" in capsys.readouterr().out
    http = sync.make_client("http://testserver", None).http
    path = rec["url"].replace("http://testserver", "")
    assert "spa.js" in http.get(path).text                    # the citation URL: the SPA
    page = http.get("/classic" + path).text                   # and its no-JS twin
    assert rec["entry"] in page and "#1 of" in page and "Author" not in page  # private
    view = http.get(f"/v1/projects/{rec['project']}/entries/{rec['entry']}").json()
    assert view["index"] == 1 and "entry" not in view


def test_rerun_replicates_and_detects_nondeterminism(env, tmp_path, capsys):
    (env / "data.csv").write_text("3\n4\n")
    (env / "sum.py").write_text(
        "print(sum(int(x) for x in open('data.csv')), file=open('total.txt', 'w'))\n")
    main(["run", "--used", "data.csv", "--used", "sum.py", "--out", "total.txt", "--",
          sys.executable, "sum.py"])
    (env / "noisy.py").write_text("import os; open('n.txt','w').write(os.urandom(8).hex())\n")
    main(["run", "--used", "noisy.py", "--out", "n.txt", "--", sys.executable, "noisy.py"])
    log = _log(capsys)
    acts = [Repo.hash_of(e) for e in log if e["kind"] == "activity"]

    capsys.readouterr()
    assert main(["rerun", acts[0][:12]]) == 2          # never runs without --yes
    assert "pass --yes" in capsys.readouterr().out
    assert main(["rerun", acts[0][:12], "--yes", "--attest",
                 "--workdir", str(tmp_path / "w1")]) == 0
    out = capsys.readouterr().out
    assert "match    total.txt" in out and "replication PASS" in out
    assert main(["rerun", acts[1][:12], "--yes", "--workdir", str(tmp_path / "w2")]) == 1
    assert "DIFFERS" in capsys.readouterr().out
    assert _log(capsys)[-1]["body"]["type"] == "replicate"


def test_bibtex_title_cannot_inject_latex():
    from provena.cli.main import _bibtex_safe

    assert _bibtex_safe("A}, note={\\input{/etc/passwd}") == "A, note=input/etc/passwd"
    assert _bibtex_safe("50% & more_x") == "50\\% \\& more\\_x"


def test_paths_case_and_platform_tricks_rejected():
    """Regression (review 3 #7): case-insensitive filesystems map .GIT to .git."""
    from provena.store.paths import UnsafePath, safe_relpath

    for bad in ("NUL", "data/con.txt", "LPT1.csv", "COM¹", "lpt³.txt", "CONIN$", "nul .txt",
                ".GIT/config", ".Provena/config.json",
                "data/.git./hooks/x", ".git /x",
                "a:b.txt", "dir\\\\..\\\\x", "x/\\x1b[2Jy"):
        with pytest.raises(UnsafePath):
            safe_relpath(bad)
    assert str(safe_relpath("data/.gitignore-like.csv")) == "data/.gitignore-like.csv"


def test_rerun_child_does_not_inherit_passphrase(env, tmp_path, capsys):
    """Regression (review 3 #8): PROVENA_PASSPHRASE leaked into re-executed commands."""
    (env / "probe.py").write_text(
        "import os; open('seen.txt','w').write(os.environ.get('PROVENA_PASSPHRASE','<none>'))\n")
    main(["run", "--used", "probe.py", "--out", "seen.txt", "--", sys.executable, "probe.py"])
    act = [Repo.hash_of(e) for e in _log(capsys) if e["kind"] == "activity"][-1]
    work = tmp_path / "w"
    main(["rerun", act[:12], "--yes", "--workdir", str(work)])
    assert (work / "seen.txt").read_text() == "<none>"
    out = capsys.readouterr().out
    assert "inputs restored into the workspace" in out and "probe.py" in out


def test_doctor_and_status_sync_state(hubbed, capsys):
    (hubbed / "a.txt").write_text("a")
    main(["add", "a.txt"])
    capsys.readouterr()
    main(["status"])
    assert "2 entries not pushed yet" in capsys.readouterr().out  # genesis + a.txt
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "✗ everything pushed" in out and "✓ hub log key is trusted" in out
    main(["push"])
    capsys.readouterr()
    main(["doctor"])
    out = capsys.readouterr().out
    assert "✓ everything pushed" in out and "✓ hub reachable, log key matches pin" in out


def test_identity_cli_flow(env, tmp_path, capsys):
    assert main(["--agent", "uni", "keygen", "--kind", "org", "--display", "Example U"]) == 0
    me = tmp_path / "home" / "agents" / "default.card.json"
    cred = tmp_path / "cred.json"
    assert main(["--agent", "uni", "identity", "issue", str(me), "--name", "Ada Lovelace",
                 "--affiliation", "Chemistry", "-o", str(cred)]) == 0
    assert main(["identity", "attach", str(cred)]) == 0
    (env / "r.txt").write_text("r")
    main(["add", "r.txt"])
    b = tmp_path / "r.pvb"
    main(["prove", "r.txt", "-o", str(b)])
    uni = json.loads((tmp_path / "home" / "agents" / "uni.card.json").read_text())["id"]
    capsys.readouterr()
    main(["verify", str(b)])
    assert "not counted: org not in your trusted set" in capsys.readouterr().out
    main(["trust", "add", "org", uni])
    capsys.readouterr()
    main(["verify", str(b)])
    out = capsys.readouterr().out
    assert "is affiliation: Chemistry, name: Ada Lovelace per org" in out


def test_verify_before_deadline(hubbed, tmp_path, capsys):
    (hubbed / "sub.csv").write_text("x")
    main(["add", "sub.csv"])
    main(["push"])
    b = tmp_path / "sub.pvb"
    main(["prove", "sub.csv", "-o", str(b)])
    capsys.readouterr()
    assert main(["verify", str(b), "--before", "2999-01-01T00:00Z"]) == 0
    assert "existed no later than" in capsys.readouterr().out
    assert main(["verify", str(b), "--before", "2000-01-01T00:00Z"]) == 1
    hub_id = Repo.find(hubbed).config["hub_card"]["id"]
    main(["trust", "remove", "log", hub_id])
    capsys.readouterr()
    assert main(["verify", str(b), "--before", "2999-01-01T00:00Z"]) == 1  # no trusted time
    assert "no trusted time evidence" in capsys.readouterr().out
    assert main(["verify", str(b), "--before", "2999-01-01T00:00"]) == 2  # needs a time zone


def test_open_refuses_hostile_names_and_overwrites(hubbed, tmp_path, monkeypatch, capsys):
    """Regression (review 5 F1): reveal names chosen by a bundle's author became write paths."""
    from provena.cli.main import CliError
    from provena.cli.proofs import _open_destination

    out = tmp_path / "out"
    out.mkdir()
    (out / "existing.txt").write_text("mine")
    for bad in (".bashrc", ".github/workflows/ci.yml", "src/.envrc", "../x"):
        with pytest.raises(CliError):
            _open_destination(out.resolve(), bad, force=False)
    with pytest.raises(CliError, match="exists"):
        _open_destination(out.resolve(), "existing.txt", force=False)
    assert _open_destination(out.resolve(), "existing.txt", force=True)
    (tmp_path / "elsewhere").mkdir()
    (out / "link").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(CliError, match="leaves the output directory"):
        _open_destination(out.resolve(), "link/x.txt", force=False)


def test_before_rejects_empty_targets_and_stray_content(hubbed, tmp_path, capsys):
    """Regression (review 5 F2)."""
    (hubbed / "a.txt").write_text("a")
    (hubbed / "b.txt").write_text("b")
    main(["add", "a.txt", "b.txt"])
    main(["push"])
    b = tmp_path / "a.pvb"
    main(["prove", "a.txt", "-o", str(b)])
    bundle = json.loads(b.read_text())
    stripped = tmp_path / "stripped.pvb"
    stripped.write_text(json.dumps({**bundle, "targets": []}))
    assert main(["verify", str(stripped), "--before", "2999-01-01T00:00Z"]) == 1
    b2 = tmp_path / "ab.pvb"
    main(["prove", "a.txt", "--full", "-o", str(b2)])
    other = Repo.find(hubbed).tracked["b.txt"]["entry"]
    capsys.readouterr()
    assert main(["verify", str(b2), "--before", "2999-01-01T00:00Z",
                 "--content", f"{other[:12]}=b.txt"]) == 2      # a usage error (contract)
    assert "does not open" in capsys.readouterr().err


def test_cli_rejects_float_bundles_like_the_browser(env, tmp_path, capsys):
    """Review 6 #5: a float anywhere in the file (even an unsigned hint) is invalid in both."""
    (env / "a.txt").write_text("a")
    main(["add", "a.txt"])
    b = tmp_path / "a.pvb"
    main(["prove", "a.txt", "-o", str(b)])
    bundle = json.loads(b.read_text())
    text = json.dumps({**bundle, "hint": 1.5})
    (tmp_path / "f.pvb").write_text(text)
    capsys.readouterr()
    assert main(["verify", str(tmp_path / "f.pvb")]) == 1
    assert "INVALID" in capsys.readouterr().out
    (tmp_path / "bom.pvb").write_text("﻿" + json.dumps(bundle))
    assert main(["verify", str(tmp_path / "bom.pvb")]) == 0


def test_verify_json(env, tmp_path, capsys):
    (env / "raw.csv").write_text("1,2\n")
    main(["add", "raw.csv"])
    out = tmp_path / "raw.pvb"
    assert main(["prove", "raw.csv", "-o", str(out)]) == 0
    capsys.readouterr()
    assert main(["verify", str(out), "--json", "--require", "self-sequenced"]) == 0
    v = json.loads(capsys.readouterr().out)
    assert v["format"] == "provena-verify/1" and v["valid"] and v["exit"] == 0
    assert v["trust"] == "self-sequenced" and v["checks"]["require"]["ok"]
    assert main(["verify", str(out), "--json", "--before", "2000-01-01T00:00Z"]) == 1
    v = json.loads(capsys.readouterr().out)
    assert v["valid"] and not v["checks"]["before"]["ok"] and v["exit"] == 1
    assert v["accepted"] is False                       # valid, but a required check failed
    out.write_text(out.read_text().replace('"index": 0', '"index": 1.5', 1))
    assert main(["verify", str(out), "--json"]) == 1
    v = json.loads(capsys.readouterr().out)
    assert not v["valid"] and v["errors"]


def test_run_as_the_guide_writes_it(env, tmp_path, capsys):
    """Docs walkthrough: `--used raw/` crashed, `--out results/` claimed untouched files, and
    the script was not an input, so `rerun` of a step recorded exactly as documented failed."""
    (env / "raw").mkdir()
    (env / "raw" / "plate1.csv").write_text("1\n2\n")
    (env / "raw" / "plate2.csv").write_text("3\n")
    (env / "results").mkdir()
    (env / "results" / "old.txt").write_text("from an earlier step\n")
    (env / "fit.py").write_text(
        "import glob\nn = sum(len(open(f).readlines()) for f in sorted(glob.glob('raw/*.csv')))\n"
        "open('results/kd.txt', 'w').write(str(n))\n")
    capsys.readouterr()
    assert main(["run", "--used", "raw/", "--out", "results/", "--", sys.executable,
                 "fit.py"]) == 0
    assert "used=3 generated=1" in capsys.readouterr().out    # 2 plates + fit.py; kd.txt only
    act = [Repo.hash_of(e) for e in _log(capsys) if e["kind"] == "activity"][-1]
    assert main(["rerun", act[:12], "--yes", "--workdir", str(tmp_path / "w")]) == 0
    assert "replication PASS" in capsys.readouterr().out


def test_member_list_and_short_ids_and_trust_validation(env, tmp_path, capsys):
    """Docs walkthrough: no way to list members, `log` ids were refused, trust took anything."""
    assert main(["--agent", "bob", "keygen", "--display", "Bob"]) == 0
    bob = json.loads((tmp_path / "home" / "agents" / "bob.card.json").read_text())
    assert main(["member", "add", str(tmp_path / "home" / "agents" / "bob.card.json"),
                 "--role", "viewer"]) == 0
    capsys.readouterr()
    assert main(["member", "list"]) == 0
    assert bob["id"] in capsys.readouterr().out
    assert main(["member", "rm", bob["id"][:16]]) == 0              # as `provena log` shows it
    assert not Repo.find().state.members[bob["id"]].active
    assert main(["trust", "add", "tsa", "32e841a95cc1"]) == 2        # truncated fingerprint
    assert main(["trust", "add", "witness", "garbage"]) == 2
    assert main(["trust", "add", "witness", bob["id"]]) == 0


def test_run_refuses_symlinks_out_of_the_repository(env, tmp_path, capsys):
    """Review 11: `--used data/` encrypted a symlinked key file from outside into the ledger."""
    (tmp_path / "secret.key").write_text("not for the ledger")
    (env / "data").mkdir()
    (env / "data" / "innocent.csv").symlink_to(tmp_path / "secret.key")
    assert main(["run", "--used", "data", "--", sys.executable, "-c", "pass"]) == 2
    assert "outside this repository" in capsys.readouterr().err


@pytest.mark.skipif(__import__("provena.cli.sandbox", fromlist=["x"]).available() is None,
                    reason="no sandbox tool on this platform")
def test_rerun_in_the_sandbox(env, tmp_path, capsys, monkeypatch):
    """A collaborator's recorded command replicates inside the sandbox and cannot read keys."""
    (env / "probe.py").write_text(
        "import os\ntry:\n    out = 'leaked' if os.listdir(os.environ['KEYS']) else 'hidden'\n"
        "except (PermissionError, FileNotFoundError):\n    out = 'hidden'\n"
        "open('seen.txt', 'w').write(out)\n")
    monkeypatch.setenv("KEYS", str(tmp_path / "home"))
    main(["run", "--out", "seen.txt", "--", sys.executable, "probe.py"])
    act = [Repo.hash_of(e) for e in _log(capsys) if e["kind"] == "activity"][-1]
    assert (env / "seen.txt").read_text() == "leaked"            # unsandboxed original run
    monkeypatch.delenv("PROVENA_PASSPHRASE")
    monkeypatch.setattr("provena.cli.common._passphrase", lambda *a, **k: "pw")
    work = tmp_path / "w"
    assert main(["rerun", act[:12], "--yes", "--sandbox", "require", "--workdir",
                 str(work)]) == 1                               # output differs: hidden
    assert (work / "seen.txt").read_text() == "hidden"


def test_named_output_is_recorded_even_when_unchanged(env, capsys):
    """Review 13: `--out ./r.json` was treated as a directory member and dropped when the step
    reproduced it byte for byte."""
    cmd = [sys.executable, "-c", "open('r.json', 'w').write('1')"]
    for _ in range(2):
        capsys.readouterr()
        assert main(["run", "--out", "./r.json", "--", *cmd]) == 0
        assert "generated=1" in capsys.readouterr().out


def test_succeed_hands_role_and_keys_to_a_new_local_key(env, tmp_path, capsys):
    (env / "d.txt").write_text("secret data")
    assert main(["add", "d.txt"]) == 0
    assert main(["--agent", "laptop2", "keygen", "--display", "Ada (laptop 2)"]) == 0
    assert main(["succeed", "laptop2"]) == 0
    assert Repo.find().config["agent"] == "laptop2"
    capsys.readouterr()
    assert main(["cat", "d.txt"]) == 0                       # the new key reads old epochs
    assert capsys.readouterr().out == "secret data"
    (env / "e.txt").write_text("e")
    assert main(["add", "e.txt"]) == 0                       # and signs as the owner
    assert main(["--agent", "default", "add", "e.txt"]) == 2  # the old key is inactive
    assert main(["succeed", "laptop2"]) == 2                 # cannot succeed to itself
    assert main(["succeed", "nope"]) == 2
    assert main(["verify"]) == 0
