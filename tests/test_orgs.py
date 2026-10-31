"""Hub orgs, quotas, API keys (ADR 0012) and storage schema versions."""

import io
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from provena.cli.main import main
from provena.core import builders
from provena.core.keys import AgentKey
from provena.server import storage as storage_mod
from provena.server.app import create_app, load_or_create_hub_key
from provena.server.hub import Forbidden, Hub
from provena.server.policy import Policy, PolicyError, hash_key, parse
from provena.server.storage import SchemaTooNew, Storage
from tests.conftest import Lab


def _hub(tmp_path, policy: dict) -> Hub:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    key = AgentKey.generate()
    hub = Hub(Storage(tmp_path / "hub"), key, key.make_card("hub", "h"))
    hub.policy = Policy(path)
    return hub


def _file(lab: Lab, data: bytes) -> tuple[dict, str, bytes]:
    """An entity entry with its ciphertext (the Lab helper drops the ciphertext)."""
    out = io.BytesIO()
    body, secrets, size = builders.encrypt_content(builders.epoch_key(lab.state, lab.owner),
                                                   lab.state.epoch, io.BytesIO(data), out)
    entry = builders.entity(lab.state, lab.owner, body, secrets, name="f", plain_size=size)
    lab.add(entry)
    return entry, body["cid"], out.getvalue()


def test_schema_migrates_forward_and_refuses_a_newer_one(tmp_path):
    store = Storage(tmp_path)
    assert store.schema_version() == storage_mod.SCHEMA_VERSION
    db = tmp_path / "hub.sqlite3"
    with sqlite3.connect(db) as conn:          # a hub from before versioning: no meta row
        conn.execute("DELETE FROM meta")
        conn.execute("DROP TABLE project_orgs")
    assert Storage(tmp_path).schema_version() == storage_mod.SCHEMA_VERSION
    assert Storage(tmp_path).org_projects("x") == []
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    with pytest.raises(SchemaTooNew):
        Storage(tmp_path)


def test_policy_is_validated():
    a = "pv1a" + "x" * 32
    with pytest.raises(PolicyError, match="in orgs"):
        parse({"orgs": {"a": {"agents": [a]}, "b": {"agents": [a]}}})
    with pytest.raises(PolicyError):
        parse({"orgs": {"a": {"api_keys": ["plaintext-key"]}}})
    with pytest.raises(PolicyError):
        parse({"orgs": {"a": {"max_projects": -1}}})
    with pytest.raises(PolicyError):
        parse({"admins": []})


def test_org_project_quota_and_default_and_fail_closed(tmp_path):
    org_lab = Lab()
    hub = _hub(tmp_path, {"orgs": {"lab-a": {"agents": [org_lab.owner.id], "max_projects": 1}}})
    hub.create_project(org_lab.log[0], org_lab.owner.id)
    second = AgentKey.generate()
    other, _ = builders.new_project(org_lab.owner, org_lab.owner.make_card("person"), name="2")
    with pytest.raises(Forbidden, match="limit of 1"):
        hub.create_project(other, org_lab.owner.id)
    stranger = Lab()
    with pytest.raises(Forbidden, match="admitted"):           # no default: org agents only
        hub.create_project(stranger.log[0], stranger.owner.id)
    (tmp_path / "policy.json").write_text(json.dumps(
        {"orgs": {"lab-a": {"agents": [org_lab.owner.id]}}, "default": {"max_projects": 1}}))
    hub.create_project(stranger.log[0], stranger.owner.id)      # re-read: default applies
    assert hub.storage.project_org(stranger.state.project) == f"agent:{stranger.owner.id}"
    (tmp_path / "policy.json").write_text("{not json")
    g, _ = builders.new_project(second, second.make_card("person"))
    with pytest.raises(Forbidden):                              # broken file admits nobody
        hub.create_project(g, second.id)


def test_storage_quota_counts_uploads_and_redactions(tmp_path):
    lab = Lab()
    hub = _hub(tmp_path, {"orgs": {"lab-a": {"agents": [lab.owner.id], "max_bytes": 200}}})
    pid = hub.create_project(lab.log[0], lab.owner.id)["entry_hash"]
    entry, cid, blob = _file(lab, b"x" * 100)
    hub.submit(pid, entry)
    assert hub.put_blob(pid, cid, [blob])
    used = hub.storage.org_bytes("lab-a")
    assert used == len(blob) > 100
    big, big_cid, big_blob = _file(lab, b"y" * 100)
    hub.submit(pid, big)
    with pytest.raises(Forbidden, match="quota"):
        hub.put_blob(pid, big_cid, [big_blob])
    target = lab.state.cids[cid]
    lab.add(builders.redact(lab.state, lab.owner, target, reason="test"))
    hub.submit(pid, lab.log[-1])
    assert hub.storage.org_bytes("lab-a") == 0                  # shredded bytes are freed
    assert hub.put_blob(pid, big_cid, [big_blob])


def test_usage_endpoint_needs_the_orgs_api_key(tmp_path, monkeypatch, capsys):
    lab = Lab()
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    capsys.readouterr()
    assert main(["--json", "hub", "api-key", "lab-a"]) == 0
    made = json.loads(capsys.readouterr().out)["data"]
    assert made["policy_entry"] == f"sha256:{hash_key(made['api_key'])}"
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"orgs": {
        "lab-a": {"agents": [lab.owner.id], "api_keys": [made["policy_entry"]]},
        "lab-b": {"agents": []}}}))
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    http = TestClient(create_app(tmp_path / "hub", key, card, policy_file=policy))
    http.app.state.hub.create_project(lab.log[0], lab.owner.id)
    auth = {"Authorization": f"Bearer {made['api_key']}"}
    assert http.get("/v1/orgs/lab-a/usage").status_code == 401
    assert http.get("/v1/orgs/lab-b/usage", headers=auth).status_code == 401
    usage = http.get("/v1/orgs/lab-a/usage", headers=auth).json()
    assert usage["projects"] == [lab.state.project] and usage["bytes"] == 0
    assert set(usage["limits"]) == {"max_projects", "max_bytes"}   # no agents or key hashes
    other = Lab()
    assert http.post("/v1/projects", json={"entry": other.log[0]}).status_code == 401


def test_review_usage_cannot_drift_and_others_cannot_be_charged(tmp_path):
    lab, outsider = Lab(), Lab()
    hub = _hub(tmp_path, {"orgs": {"lab-a": {"agents": [lab.owner.id], "max_bytes": 10_000},
                                   "lab-b": {"agents": [outsider.owner.id]}}})
    with pytest.raises(Forbidden, match="own agents"):          # e.g. a mirror by an outsider
        hub.create_project(lab.log[0], outsider.owner.id)
    pid = hub.create_project(lab.log[0], lab.owner.id)["entry_hash"]
    entry, cid, blob = _file(lab, b"x" * 100)
    hub.submit(pid, entry)
    hub.put_blob(pid, cid, [blob])
    hub.storage.count_blob(pid, cid, len(blob))                 # a concurrent duplicate upload
    assert hub.storage.org_bytes("lab-a") == len(blob)
    target = lab.state.cids[cid]
    lab.add(builders.redact(lab.state, lab.owner, target, reason="test"))
    hub.submit(pid, lab.log[-1])
    hub._shred(pid, cid)                                        # a retried shred
    assert hub.storage.org_bytes("lab-a") == 0
    late, late_cid, late_blob = _file(lab, b"z" * 10)
    hub.submit(pid, late)
    (tmp_path / "policy.json").write_text(json.dumps({"orgs": {}}))   # org removed
    with pytest.raises(Forbidden, match="no longer admitted"):
        hub.put_blob(pid, late_cid, [late_blob])


def test_cli_push_creates_a_project_on_a_policy_hub(tmp_path, monkeypatch, capsys):
    from provena.client.hub import HubClient
    from provena.sdk import sync

    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PROVENA_PASSPHRASE", "pw")
    monkeypatch.setenv("PROVENA_SCRYPT_N", "1024")
    capsys.readouterr()
    assert main(["--json", "keygen"]) == 0
    me = json.loads(capsys.readouterr().out)["data"]["agent"]
    me = me["id"] if isinstance(me, dict) else me
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"orgs": {"lab-a": {"agents": [me], "max_projects": 1}}}))
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    http = TestClient(create_app(tmp_path / "hub", key, card, policy_file=policy))
    monkeypatch.setattr(sync, "make_client",
                        lambda url, agent: HubClient(url, agent=agent, http=http))
    (tmp_path / "lab").mkdir()
    monkeypatch.chdir(tmp_path / "lab")
    assert main(["init", "--name", "x"]) == 0
    assert main(["remote", "http://testserver"]) == 0
    assert main(["push"]) == 0
    assert http.app.state.hub.storage.org_projects("lab-a")
