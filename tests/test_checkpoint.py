"""C2SP checkpoints of tree heads, checked with a plain Ed25519 verifier (c2sp.org/signed-note)."""

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from provena.core import checkpoint as cp
from provena.sdk import sync
from tests.test_hub import hub_app, world  # noqa: F401 (fixtures)


def test_hub_serves_a_signed_note_a_witness_can_check(world):  # noqa: F811
    repo, alice, client = world["repo"], world["alice"], world["client"]
    sync.push(repo, client(alice), agent=alice)
    pid = repo.state.project
    http = client().http
    note = http.get(f"/v1/projects/{pid}/checkpoint").text
    head = client().sth(pid)
    text, _, sig_line = note.partition("\n\n")
    name, size, root = text.split("\n")
    assert size == str(head["size"]) and base64.b64decode(root).hex() == head["root"]
    dash, key_name, blob = sig_line.strip().split(" ")
    assert dash == "—" and key_name == name == f"provena/{head['signer']}/{pid}"
    data = base64.b64decode(blob)
    card = client().info()["card"]
    pub = bytes.fromhex(card["sign"])
    assert data[:4] == hashlib.sha256(name.encode() + b"\n\x01" + pub).digest()[:4]
    Ed25519PublicKey.from_public_bytes(pub).verify(data[4:], (text + "\n").encode())
    vkey = http.get("/v1/hub/vkey", params={"project": pid}).text.strip()
    assert vkey.startswith(name + "+") and vkey.endswith(base64.b64encode(b"\x01" + pub).decode())
    from provena.core.keys import verify_card

    assert cp.verify(note, verify_card(card)) == (name, head["size"], head["root"])
