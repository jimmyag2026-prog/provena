"""in-toto/DSSE export of a step, checked with a plain Ed25519 verifier (not our helper)."""

import base64
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from provena.cli.main import main
from tests.test_phase0_inputs import env  # noqa: F401 (fixture)


def test_step_exports_as_a_standard_dsse_envelope(env, tmp_path, capsys):  # noqa: F811
    (env / "d.csv").write_text("1,2")
    assert main(["add", "d.csv"]) == 0
    assert main(["run", "--used", "d.csv", "--out", "o.txt", "--", sys.executable, "-c",
                 "open('o.txt','w').write('x')"]) == 0
    capsys.readouterr()
    assert main(["--json", "log"]) == 0
    step = [e for e in json.loads(capsys.readouterr().out)["data"]["entries"]
            if e["kind"] == "activity"][-1]["hash"]
    assert main(["reveal", step]) == 0
    assert main(["export", "intoto", "--step", step, "-o", "s.json"]) == 0
    env_ = json.loads((env / "s.json").read_text())
    payload = base64.b64decode(env_["payload"])
    t = env_["payloadType"].encode()
    pae = b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)
    card = json.loads((tmp_path / "home" / "agents" / "default.card.json").read_text())
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(card["sign"])).verify(
        base64.b64decode(env_["signatures"][0]["sig"]), pae)     # raises if invalid
    st = json.loads(payload)
    assert st["_type"] == "https://in-toto.io/Statement/v1"
    assert st["subject"][0]["name"] == "o.txt"
    import hashlib

    assert st["subject"][0]["digest"]["sha256"] == hashlib.sha256(b"x").hexdigest()
    assert st["predicate"]["ledger"]["entry"] == step and st["predicate"]["status"] == "ok"
    assert st["predicate"]["details"]["exit_code"] == 0      # revealed before export


def test_verify_badge(env, capsys):  # noqa: F811
    (env / "d.csv").write_text("1")
    assert main(["add", "d.csv"]) == 0
    assert main(["prove", "d.csv", "-o", "d.pvb"]) == 0
    assert main(["verify", "d.pvb", "--badge", "b.svg"]) == 0
    assert "self-sequenced" in (env / "b.svg").read_text()
    (env / "bad.pvb").write_text("{}")
    assert main(["verify", "bad.pvb", "--badge", "x.svg"]) == 1
    assert "invalid" in (env / "x.svg").read_text()
