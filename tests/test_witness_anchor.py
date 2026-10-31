import pytest
from fastapi.testclient import TestClient

from provena.client.hub import HubClient, HubError
from provena.client.witness import Witness
from provena.core import builders, entries, merkle
from provena.core.bundle import make_bundle
from provena.core.errors import VerificationError
from provena.core.keys import AgentKey
from provena.core.treehead import make_head
from provena.core.verify import TRUST_LOG, TRUST_WITNESSED, verify_bundle
from provena.core.witness import check_extension, cosign, verify_cosig
from provena.sdk import sync
from provena.server.app import create_app, load_or_create_hub_key
from provena.store.repo import Repo

URL = "http://testserver"


@pytest.fixture
def setup(tmp_path):
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    http = TestClient(create_app(tmp_path / "hub", key, card))
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"), name="p")
    repo = Repo.init(tmp_path / "a", "alice", genesis)
    (tmp_path / "a" / "x.csv").write_bytes(b"x\n")
    body, secrets, size = repo.encrypt_file(alice, tmp_path / "a" / "x.csv")
    x = repo.append(builders.entity(repo.state, alice, body, secrets, name="x.csv",
                                    plain_size=size))
    client = HubClient(URL, agent=alice, http=http)
    sync.pin_hub(repo, URL, client)
    sync.push(repo, client, agent=alice)
    w = AgentKey.generate()
    witness = Witness(w, w.make_card("org", "witness-1"), tmp_path / "w.json")
    return {"repo": repo, "alice": alice, "client": client, "x": x, "witness": witness,
            "http": http, "tmp": tmp_path}


def _bundle(repo, targets):
    hub_head = max((h for h in repo.heads()), key=lambda h: h["head"]["size"])
    return make_bundle(repo.log(), hub_head["head"], hub_head["signer_card"], targets,
                       **sync.bundle_evidence(repo, hub_head["head"]))


def _trust(setup, **extra):
    return {"trusted_logs": {setup["repo"].config["hub_card"]["id"]},
            "trusted_witnesses": {setup["witness"].card["id"]}, **extra}


def test_trust_levels_progress(setup):
    repo, client, alice = setup["repo"], setup["client"], setup["alice"]
    assert verify_bundle(_bundle(repo, [setup["x"]])).trust == "unverified"
    assert verify_bundle(_bundle(repo, [setup["x"]]), **_trust(setup)).trust == TRUST_LOG

    setup["witness"].observe(HubClient(URL, http=setup["http"]), repo.state.project)
    sync.pull(repo, client, agent=alice)
    report = verify_bundle(_bundle(repo, [setup["x"]]), **_trust(setup))
    assert report.ok and report.trust == TRUST_WITNESSED
    other = _trust(setup, trusted_witnesses={AgentKey.generate().id})
    untrusted_witness = verify_bundle(_bundle(repo, [setup["x"]]), **other)
    assert untrusted_witness.ok and untrusted_witness.trust == TRUST_LOG
    assert any("not counted" in n for n in untrusted_witness.notes)

    assert client.run_anchor()["anchored"]
    sync.pull(repo, client, agent=alice)
    report = verify_bundle(_bundle(repo, [setup["x"]]), **_trust(setup))
    assert report.ok, report.errors
    assert any("anchored via self" in f for f in report.facts)
    assert report.trust == TRUST_WITNESSED  # a self anchor adds no independent trust
    assert any("adds no independent time evidence" in n for n in report.notes)


def test_anchor_survives_later_growth(setup):
    """An anchor over an older head still dates entries after the log grows."""
    repo, client, alice = setup["repo"], setup["client"], setup["alice"]
    client.run_anchor()
    plan_body = {"commitment": "ab" * 32}
    s = builders.ContentSecrets(b"\1" * 32, b"\2" * 32, b"\3" * 32)
    later = repo.append(builders.plan(repo.state, alice, plan_body, s, title="later"))
    sync.push(repo, client, agent=alice)
    b = _bundle(repo, [setup["x"], later])
    report = verify_bundle(b, **_trust(setup))
    assert report.ok, report.errors
    dated = [f for f in report.facts if "existed no later than" in f and "anchored" in f]
    assert len(dated) == 1 and setup["x"][:12] in dated[0]  # only the pre-anchor entry
    b["anchors"][0]["consistency"][0] = "00" * 32
    assert not verify_bundle(b).ok


def test_tampered_anchor_and_cosig_fail(setup):
    repo, client, alice = setup["repo"], setup["client"], setup["alice"]
    setup["witness"].observe(HubClient(URL, http=setup["http"]), repo.state.project)
    client.run_anchor()
    sync.pull(repo, client, agent=alice)
    b = _bundle(repo, [setup["x"]])
    assert verify_bundle(b).ok
    bad = _bundle(repo, [setup["x"]])
    bad["anchors"][0]["anchor"]["receipt"]["time"] -= 1000
    assert not verify_bundle(bad).ok
    bad = _bundle(repo, [setup["x"]])
    bad["cosignatures"][0]["cosig"]["time"] += 1
    assert not verify_bundle(bad).ok


def test_witness_refuses_fork():
    hub = AgentKey.generate()
    w = AgentKey.generate()
    leaves = [merkle.leaf_hash(bytes([i])) for i in range(6)]
    pid = "aa" * 32
    old = make_head(hub, pid, leaves[:4])
    forked_leaves = leaves[:2] + [merkle.leaf_hash(b"evil")] + leaves[3:]
    new = make_head(hub, pid, forked_leaves)
    proof = merkle.consistency_proof(forked_leaves, 4)
    with pytest.raises(VerificationError):
        check_extension(old, new, hub.public, proof)
    same_size_fork = make_head(hub, pid, forked_leaves[:4])
    with pytest.raises(VerificationError, match="fork"):
        check_extension(old, same_size_fork, hub.public, [])
    good = make_head(hub, pid, leaves)
    check_extension(old, good, hub.public, merkle.consistency_proof(leaves, 4))
    c = cosign(w, good, 1)
    verify_cosig(c, good, w.public)
    with pytest.raises(VerificationError):
        verify_cosig(c, old, w.public)


def test_hub_rejects_bad_cosignature(setup):
    repo, client = setup["repo"], setup["client"]
    head = client.sth(repo.state.project)
    w = AgentKey.generate()
    c = cosign(w, head, 1)
    c["time"] = 2
    with pytest.raises(HubError):
        client.add_cosignature(repo.state.project, head["size"], c, w.make_card("org"))


def test_anchor_endpoint_throttled(setup):
    client = setup["client"]
    client.run_anchor()
    with pytest.raises(HubError) as exc:
        client.run_anchor()
    assert exc.value.status == 429


def test_entries_proven_against_hub_head(setup):
    repo = setup["repo"]
    leaves = [entries.entry_leaf(e) for e in repo.log()]
    head = setup["client"].sth(repo.state.project)
    assert merkle.root(leaves).hex() == head["root"]


def test_rfc3161_anchor_gives_anchored_trust(tmp_path):
    from provena.server.hub import RFC3161AnchorProvider
    from tests.tsa_fixture import LocalTSA

    tsa = LocalTSA()
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    provider = RFC3161AnchorProvider("https://tsa.test", post=tsa.respond)
    http = TestClient(create_app(tmp_path / "hub", key, card, anchor_provider=provider))
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"), name="p")
    repo = Repo.init(tmp_path / "a", "alice", genesis)
    client = HubClient(URL, agent=alice, http=http)
    sync.pin_hub(repo, URL, client)
    sync.push(repo, client, agent=alice)
    assert client.run_anchor()["anchor"]["provider"] == "rfc3161"
    sync.pull(repo, client, agent=alice)
    import hashlib

    from cryptography.hazmat.primitives.serialization import Encoding

    fp = hashlib.sha256(tsa.cert.public_bytes(Encoding.DER)).hexdigest()
    hub_id = repo.config["hub_card"]["id"]
    b = _bundle(repo, [repo.state.order[0]])
    untrusted_tsa = verify_bundle(b, trusted_logs={hub_id})
    assert untrusted_tsa.ok and untrusted_tsa.trust == "log-sequenced"
    assert any(fp in n for n in untrusted_tsa.notes)  # tells you what to trust
    report = verify_bundle(b, trusted_logs={hub_id}, trusted_tsas={fp})
    assert report.ok, report.errors
    assert report.trust == "anchored"
    assert any("Provena Test TSA" in f for f in report.facts)


def test_cosignature_on_older_head_still_counts(setup):
    """A witness that cosigned an earlier head vouches for everything up to that size."""
    repo, client, alice = setup["repo"], setup["client"], setup["alice"]
    setup["witness"].observe(HubClient(URL, http=setup["http"]), repo.state.project)
    s = builders.ContentSecrets(b"\1" * 32, b"\2" * 32, b"\3" * 32)
    later = repo.append(builders.plan(repo.state, alice, {"commitment": "cd" * 32}, s,
                                      title="later"))
    sync.push(repo, client, agent=alice)
    early = verify_bundle(_bundle(repo, [setup["x"]]), **_trust(setup))
    assert early.ok and early.trust == TRUST_WITNESSED, early.errors
    late = verify_bundle(_bundle(repo, [setup["x"], later]), **_trust(setup))
    assert late.ok and late.trust == TRUST_LOG  # the later entry is not covered
    b = _bundle(repo, [setup["x"]])
    b["cosignatures"][0]["consistency"][0] = "00" * 32
    assert not verify_bundle(b).ok


def test_forged_trust_evidence_is_not_counted(setup, tmp_path):
    """Regression (security review #1): re-wrap genuine entries under a throwaway log key, a
    self-made witness and a self-made "DigiCert" TSA backdating to 2020. Must not be anchored,
    witnessed or even log-sequenced, and must not state the forged times as facts."""
    import datetime as dt

    from provena.core.anchor import root_of_roots
    from provena.core.encoding import b64u
    from provena.core.rfc3161 import make_request, token_from_response
    from provena.core.treehead import make_head
    from tests.tsa_fixture import LocalTSA

    repo = setup["repo"]
    fake_log, fake_w = AgentKey.generate(), AgentKey.generate()
    fake_log_card = fake_log.make_card("hub", "Totally Real Hub")
    leaves = [entries.entry_leaf(e) for e in repo.log()]
    when = int(dt.datetime(2019, 12, 31, tzinfo=dt.UTC).timestamp() * 1000)
    head = make_head(fake_log, repo.state.project, leaves, at_ms=when)
    root, _ = root_of_roots([head])
    tsa = LocalTSA()
    token = token_from_response(tsa.respond(make_request(root, 1)))
    anchor = {"anchor": {"v": 1, "provider": "rfc3161", "digest": root.hex(), "size": 1,
                         "time": 1, "receipt": {"token": b64u(token), "tsa": "x"}},
              "head": head, "index": 0, "proof": [], "log_card": fake_log_card}
    b = make_bundle(repo.log(), head, fake_log_card, [setup["x"]],
                    cosignatures=[{"cosig": cosign(fake_w, head, when),
                                   "card": fake_w.make_card("org", "witness")}],
                    anchors=[anchor])
    report = verify_bundle(b, **_trust(setup))
    assert report.ok and report.trust == "unverified"
    assert not any("existed no later than" in f or "cosigned" in f for f in report.facts)
    # even against a trusted hub head, a bogus TSA anchor cannot backdate anything
    genuine = _bundle(repo, [setup["x"]])
    real_head = genuine["head"]
    root2, _ = root_of_roots([real_head])
    token2 = token_from_response(tsa.respond(make_request(root2, 2)))
    genuine["anchors"] = [{"anchor": {"v": 1, "provider": "rfc3161", "digest": root2.hex(),
                                      "size": 1, "time": 1,
                                      "receipt": {"token": b64u(token2), "tsa": "x"}},
                           "head": real_head, "index": 0, "proof": [], "consistency": [],
                           "log_card": repo.config["hub_card"]}]
    report = verify_bundle(genuine, **_trust(setup))
    assert report.ok and report.trust == TRUST_LOG


def test_anchor_older_than_head_rejected(setup):
    """A time-stamp earlier than the head it covers is inconsistent evidence."""
    import datetime as dt

    from provena.core.anchor import root_of_roots
    from provena.core.encoding import b64u
    from provena.core.rfc3161 import make_request  # noqa: F401
    from tests.tsa_fixture import LocalTSA

    repo = setup["repo"]
    genuine = _bundle(repo, [setup["x"]])
    head = genuine["head"]
    root, _ = root_of_roots([head])
    tsa = LocalTSA()
    old = dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)
    token = tsa.token(root, when=old)
    genuine["anchors"] = [{"anchor": {"v": 1, "provider": "rfc3161", "digest": root.hex(),
                                      "size": 1, "time": 1,
                                      "receipt": {"token": b64u(token), "tsa": "x"}},
                           "head": head, "index": 0, "proof": [], "consistency": [],
                           "log_card": repo.config["hub_card"]}]
    report = verify_bundle(genuine, **_trust(setup))
    assert not report.ok and "precedes" in report.errors[0]


def test_reanchoring_restamps_an_unchanged_root(setup):
    hub = setup["http"].app.state.hub
    assert hub.run_anchor() is not None
    assert hub.run_anchor() is None                 # unchanged root, no re-anchoring configured
    hub.reanchor_after_ms = 0
    again = hub.run_anchor()
    assert again is not None and len(hub.storage.anchors()) == 2
    assert again["digest"] == hub.storage.anchors()[0][0]["digest"]


def test_policy_witness_count_in_both_verifiers(tmp_path):
    """A project whose policy asks for 2 witnesses is `witnessed` only with 2 trusted ones (the
    policy field used to be recorded but never enforced)."""
    import json
    import shutil
    import subprocess
    from pathlib import Path

    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    http = TestClient(create_app(tmp_path / "hub", key, card))
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"), witnesses=2, name="p")
    repo = Repo.init(tmp_path / "a", "alice", genesis)
    (tmp_path / "a" / "x.csv").write_bytes(b"x\n")
    body, secrets, size = repo.encrypt_file(alice, tmp_path / "a" / "x.csv")
    x = repo.append(builders.entity(repo.state, alice, body, secrets, name="x.csv",
                                    plain_size=size))
    client = HubClient(URL, agent=alice, http=http)
    sync.pin_hub(repo, URL, client)
    sync.push(repo, client, agent=alice)
    witnesses = []
    for i in range(2):
        w = AgentKey.generate()
        witnesses.append(Witness(w, w.make_card("org", f"w{i}"), tmp_path / f"w{i}.json"))
    trust = {"trusted_logs": {repo.config["hub_card"]["id"]},
             "trusted_witnesses": {w.card["id"] for w in witnesses}}
    bundles = {}
    for i, w in enumerate(witnesses):
        w.observe(HubClient(URL, http=http), repo.state.project)
        sync.pull(repo, client, agent=alice)
        bundles[f"after{i + 1}"] = _bundle(repo, [x])
    one, two = (verify_bundle(bundles[k], **trust) for k in ("after1", "after2"))
    assert one.trust == TRUST_LOG and any("asks for 2 witnesses" in n for n in one.notes)
    assert two.trust == TRUST_WITNESSED
    if shutil.which("node"):
        root = Path(__file__).resolve().parents[1]
        task = tmp_path / "task.json"
        opts = {"trustedLogs": sorted(trust["trusted_logs"]),
                "trustedWitnesses": sorted(trust["trusted_witnesses"])}
        vectors = json.loads((root / "tests" / "vectors" / "core.json").read_text())
        task.write_text(json.dumps({"vectors": vectors, "bundles": bundles,
                                    "options": {k: opts for k in bundles}}))
        out = json.loads(subprocess.run(["node", str(root / "tests" / "js" / "run.mjs"),
                                         str(task)], capture_output=True, text=True,
                                        check=True).stdout)
        assert out["results"]["after1"]["trust"] == TRUST_LOG
        assert out["results"]["after2"]["trust"] == TRUST_WITNESSED



def test_first_anchor_request_allowed_right_after_boot(tmp_path, monkeypatch):
    """CI: monotonic() is the uptime on Linux, so on a VM booted <30 s ago the very first
    anchor request was refused as 'too recent'."""
    import provena.server.app as app_module

    monkeypatch.setattr(app_module.time, "monotonic", lambda: 5.0)
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    r = TestClient(create_app(tmp_path / "hub", key, card)).post("/v1/anchors/run")
    assert r.status_code == 200
