"""`provena mirror`: the same log on a second hub, with identical roots (availability)."""

import pytest
from fastapi.testclient import TestClient

from provena.cli.main import main
from provena.client.hub import HubClient
from provena.core import builders, entries, merkle
from provena.core.errors import VerificationError
from provena.core.treehead import make_head
from provena.sdk import sync
from provena.server.app import create_app, load_or_create_hub_key
from provena.store.repo import Repo

PRIMARY, MIRROR = "http://primary", "http://mirror"


@pytest.fixture
def hubs(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PROVENA_PASSPHRASE", "pw")
    monkeypatch.setenv("PROVENA_SCRYPT_N", "1024")
    http = {}
    for url, name in ((PRIMARY, "a"), (MIRROR, "b")):
        key, card = load_or_create_hub_key(tmp_path / name, "pw")
        http[url] = TestClient(create_app(tmp_path / name, key, card))
    monkeypatch.setattr(sync, "make_client",
                        lambda url, agent: HubClient(url, agent=agent, http=http[url]))
    assert main(["keygen", "--display", "Ada"]) == 0
    lab = tmp_path / "lab"
    lab.mkdir()
    monkeypatch.chdir(lab)
    assert main(["init", "--name", "assay"]) == 0
    (lab / "plate.csv").write_text("well,od\nA1,0.4\n")
    assert main(["add", "plate.csv"]) == 0
    assert main(["remote", PRIMARY]) == 0
    assert main(["push"]) == 0
    return tmp_path, http


def test_mirror_has_the_same_root_and_can_be_cloned(hubs, monkeypatch, capsys):
    tmp_path, http = hubs
    capsys.readouterr()
    assert main(["mirror", MIRROR]) == 0
    assert "same root" in capsys.readouterr().out
    pid = Repo.find().state.project
    a = HubClient(PRIMARY, http=http[PRIMARY]).sth(pid)
    b = HubClient(MIRROR, http=http[MIRROR]).sth(pid)
    assert (a["size"], a["root"]) == (b["size"], b["root"]) and a["signer"] != b["signer"]

    (tmp_path / "lab" / "plate2.csv").write_text("well,od\nA2,0.5\n")
    assert main(["add", "plate2.csv"]) == 0
    capsys.readouterr()
    assert main(["mirror", MIRROR]) == 0       # only the hub-sequenced prefix mirrors
    assert "mirrored 0 entries" in capsys.readouterr().out
    assert main(["push"]) == 0
    assert main(["mirror", "--check", MIRROR]) == 0
    assert "1 behind" in capsys.readouterr().out
    assert main(["mirror", MIRROR]) == 0                 # incremental

    monkeypatch.chdir(tmp_path)                          # the primary is down: clone the mirror
    assert main(["clone", MIRROR, pid, "copy"]) == 0
    assert (tmp_path / "copy" / ".provena").exists()


def test_a_forked_mirror_is_detected(hubs, monkeypatch):
    tmp_path, http = hubs
    assert main(["mirror", MIRROR]) == 0
    repo = Repo.find()
    real = HubClient.project

    key, _ = load_or_create_hub_key(tmp_path / "b", "pw")   # the mirror signs another history
    fork = make_head(key, repo.state.project, merkle.MerkleLog([b"x", b"y"]))

    def forked(self, pid):
        info = real(self, pid)
        if self.url == MIRROR:
            info["head"] = fork
        return info

    monkeypatch.setattr(HubClient, "project", forked)
    with pytest.raises(VerificationError, match="forked"):
        sync.mirror(repo, MIRROR, sync.make_client(MIRROR, None), check_only=True)


def test_primary_cannot_be_its_own_mirror(hubs):
    with pytest.raises(VerificationError, match="primary"):
        sync.mirror(Repo.find(), PRIMARY, sync.make_client(PRIMARY, None))


def test_one_witness_cross_checks_primary_and_mirror(hubs, monkeypatch):
    from provena.client.witness import Witness
    from provena.core.keys import AgentKey

    tmp_path, http = hubs
    assert main(["mirror", MIRROR]) == 0
    repo = Repo.find()
    pid = repo.state.project
    w = AgentKey.generate()
    witness = Witness(w, w.make_card("org"), tmp_path / "witness.json")
    primary, mirror = (HubClient(u, http=http[u]) for u in (PRIMARY, MIRROR))
    witness.observe(primary, pid)
    witness.observe(mirror, pid)                     # same root at the same size: fine

    (tmp_path / "lab" / "more.csv").write_text("x\n")
    assert main(["add", "more.csv"]) == 0
    assert main(["push"]) == 0
    witness.observe(primary, pid)                    # primary grew; mirror is behind
    key, _ = load_or_create_hub_key(tmp_path / "b", "pw")
    leaves = repo.leaves()
    fork = make_head(key, pid, merkle.MerkleLog([*leaves[:-1], b"\x01" * 32]))
    monkeypatch.setattr(HubClient, "sth", lambda self, p: fork)
    with pytest.raises(VerificationError, match="fork"):
        witness.observe(mirror, pid)                 # same size, different root


def test_witness_refuses_a_smaller_forked_head_and_remembers_the_fork(hubs, monkeypatch):
    """Review 10: a head below every remembered size was never compared."""
    from provena.client.witness import Witness
    from provena.core.keys import AgentKey

    tmp_path, http = hubs
    assert main(["mirror", MIRROR]) == 0                       # mirror at size N
    for i in range(3):
        (tmp_path / "lab" / f"f{i}.csv").write_text(f"{i}\n")
        assert main(["add", f"f{i}.csv"]) == 0
    assert main(["push"]) == 0                                 # primary at N+3
    repo = Repo.find()
    pid, leaves = repo.state.project, repo.leaves()
    primary, mirror = (HubClient(u, http=http[u]) for u in (PRIMARY, MIRROR))
    small = mirror.sth(pid)["size"]
    w = AgentKey.generate()
    witness = Witness(w, w.make_card("org"), tmp_path / "w.json")
    witness.observe(primary, pid)
    key, _ = load_or_create_hub_key(tmp_path / "b", "pw")
    fork = make_head(key, pid, merkle.MerkleLog([*leaves[:small - 1], b"\x02" * 32]))
    real = HubClient.sth
    monkeypatch.setattr(HubClient, "sth",
                        lambda self, p: fork if self.url == MIRROR else real(self, p))
    with pytest.raises(VerificationError, match=f"{PRIMARY}|{MIRROR}"):
        witness.observe(mirror, pid)
    with pytest.raises(VerificationError, match="seen earlier"):
        witness.observe(primary, pid)                          # stops cosigning the project


def test_stale_checkout_does_not_republish_redacted_ciphertext(hubs, monkeypatch):
    """Review 10: mirroring from a checkout that never saw a redaction made elsewhere."""
    import pathlib

    tmp_path, http = hubs
    repo = Repo.find()
    pid = repo.state.project
    target = next(h for h in repo.state.order if repo.state.entries[h]["kind"] == "entity")
    cid = repo.state.entries[target]["body"]["cid"]
    monkeypatch.chdir(tmp_path)
    assert main(["clone", PRIMARY, pid, "copy"]) == 0
    monkeypatch.chdir(tmp_path / "copy")
    assert main(["redact", target[:12], "--reason", "consent withdrawn"]) == 0
    assert main(["push"]) == 0
    monkeypatch.chdir(tmp_path / "lab")                         # stale: never pulled
    assert main(["mirror", MIRROR]) == 0
    assert not [q for q in pathlib.Path(tmp_path / "b").rglob("*") if cid in q.name]
    a, b = (HubClient(u, http=http[u]).sth(pid) for u in (PRIMARY, MIRROR))
    assert (a["size"], a["root"]) == (b["size"], b["root"])     # the redaction mirrored too


@pytest.mark.parametrize("trigger", ["mirror", "push"])
def test_blobless_pull_does_not_lose_teammates_content(hubs, monkeypatch, capsys, trigger):
    """Review 13: mirror / push pull entries without ciphertext; a later pull never fetched
    it, so a teammate's new file stayed unreadable."""
    tmp_path, http = hubs
    pid = Repo.find().state.project
    monkeypatch.chdir(tmp_path)
    assert main(["clone", PRIMARY, pid, "copy"]) == 0
    monkeypatch.chdir(tmp_path / "copy")
    (tmp_path / "copy" / "new.csv").write_text("b\n")
    assert main(["add", "new.csv"]) == 0
    assert main(["push"]) == 0
    monkeypatch.chdir(tmp_path / "lab")
    assert main(["mirror", MIRROR] if trigger == "mirror" else ["push"]) == 0
    assert main(["pull"]) == 0
    st = Repo.find().state
    h = [x for x in st.order if st.entries[x]["kind"] == "entity"][-1]
    capsys.readouterr()
    assert main(["cat", h[:16]]) == 0
    assert "b" in capsys.readouterr().out


def test_pull_from_mirror_while_primary_is_down(hubs, monkeypatch, capsys):
    """An existing checkout catches up from a mirror; the primary later adds its receipts."""
    tmp_path, http = hubs
    pid = Repo.find().state.project
    monkeypatch.chdir(tmp_path)
    assert main(["clone", PRIMARY, pid, "copy"]) == 0
    monkeypatch.chdir(tmp_path / "copy")
    (tmp_path / "copy" / "new.csv").write_text("from B\n")
    assert main(["add", "new.csv"]) == 0
    assert main(["push"]) == 0
    assert main(["mirror", MIRROR]) == 0
    monkeypatch.chdir(tmp_path / "lab")
    assert main(["mirror", "--check", MIRROR]) == 0              # pin it while the primary is up
    synced = Repo.find().config["synced"]
    down = sync.make_client

    def primary_down(url, agent):
        if url == PRIMARY:
            raise ConnectionError("primary unreachable")
        return down(url, agent)

    monkeypatch.setattr(sync, "make_client", primary_down)
    capsys.readouterr()
    assert main(["pull", "--from", MIRROR]) == 0
    repo = Repo.find()
    assert repo.config["synced"] == synced                      # sync point unchanged
    h = [x for x in repo.state.order if repo.state.entries[x]["kind"] == "entity"][-1]
    assert main(["cat", h[:16]]) == 0 and "from B" in capsys.readouterr().out
    monkeypatch.setattr(sync, "make_client", down)              # the primary is back
    assert main(["pull"]) == 0
    assert Repo.find().config["synced"] == len(Repo.find().state.order)


def test_pull_from_a_mirror_that_rewrote_history_fails(hubs, monkeypatch):
    tmp_path, http = hubs
    assert main(["mirror", MIRROR]) == 0
    repo = Repo.find()
    key, _ = load_or_create_hub_key(tmp_path / "b", "pw")
    fork = make_head(key, repo.state.project, merkle.MerkleLog([*repo.leaves(), b"\x03" * 32]))
    monkeypatch.setattr(HubClient, "sth", lambda self, p: fork)
    from provena.store.home import Home

    agent = Home().load_agent(repo.config["agent"], "pw")
    with pytest.raises(VerificationError, match="contradicts|do not extend"):
        sync.pull_mirror(repo, MIRROR, sync.make_client(MIRROR, agent), agent=agent)


def test_mirror_only_entries_are_dropped_not_pushed(hubs, monkeypatch, capsys):
    """Review 14: entries read from a mirror sat with the user's own pending ones, so `push`
    relayed mirror-only entries to the primary (and an equivocating member could wedge pulls)."""
    from provena.store.home import Home

    tmp_path, http = hubs
    pid = Repo.find().state.project
    assert main(["--agent", "bob", "keygen", "--display", "Bob"]) == 0
    assert main(["member", "add", str(tmp_path / "home" / "agents" / "bob.card.json"),
                 "--role", "contributor"]) == 0
    assert main(["mirror", MIRROR]) == 0
    monkeypatch.chdir(tmp_path)
    assert main(["--agent", "bob", "clone", PRIMARY, pid, "copy"]) == 0
    monkeypatch.chdir(tmp_path / "lab")
    # Bob's entry that only the mirror sequences
    copy = Repo.find(tmp_path / "copy")
    (tmp_path / "copy" / "side.csv").write_text("mirror only\n")
    agent = Home().load_agent("bob", "pw")
    body, sec, size = copy.encrypt_file(agent, tmp_path / "copy" / "side.csv")
    side = builders.entity(copy.state, agent, body, sec, name="side.csv", plain_size=size)
    HubClient(MIRROR, agent=agent, http=http[MIRROR]).submit(pid, side)
    assert main(["pull", "--from", MIRROR]) == 0
    repo = Repo.find()
    side_hash = entries.entry_hash(side)
    assert side_hash in repo.state.entries and side_hash in repo.config["mirror_pending"]
    (tmp_path / "lab" / "mine.csv").write_text("my own\n")
    assert main(["add", "mine.csv"]) == 0
    capsys.readouterr()
    assert main(["push"]) == 0
    assert "pushed 1 entries" in capsys.readouterr().out          # only the user's own
    repo = Repo.find()
    assert side_hash not in repo.state.entries and not repo.config["mirror_pending"]
    assert HubClient(PRIMARY, http=http[PRIMARY]).sth(pid)["size"] == len(repo.state.order)


def _bob(tmp_path, monkeypatch, pid):
    from provena.store.home import Home

    assert main(["--agent", "bob", "keygen", "--display", "Bob"]) == 0
    assert main(["member", "add", str(tmp_path / "home" / "agents" / "bob.card.json"),
                 "--role", "contributor"]) == 0
    monkeypatch.chdir(tmp_path)
    assert main(["--agent", "bob", "clone", PRIMARY, pid, "copy"]) == 0
    monkeypatch.chdir(tmp_path / "lab")
    return Repo.find(tmp_path / "copy"), Home().load_agent("bob", "pw")


def _bob_entity(copy, agent, path, text):
    path.write_text(text)
    body, sec, size = copy.encrypt_file(agent, path)
    return builders.entity(copy.state, agent, body, sec, name=path.name, plain_size=size)


def test_entries_built_on_unconfirmed_mirror_entries_are_set_aside(hubs, monkeypatch, capsys):
    """Review 15: an attestation on a mirror-only entry wedged every later pull and push."""
    tmp_path, http = hubs
    pid = Repo.find().state.project
    copy, agent = _bob(tmp_path, monkeypatch, pid)
    assert main(["mirror", MIRROR]) == 0
    side = _bob_entity(copy, agent, tmp_path / "copy" / "side.csv", "x\n")
    HubClient(MIRROR, agent=agent, http=http[MIRROR]).submit(pid, side)
    assert main(["pull", "--from", MIRROR]) == 0
    assert main(["attest", entries.entry_hash(side)[:16], "--type", "review"]) == 0
    capsys.readouterr()
    assert main(["pull"]) == 5                                   # EXIT_STATE: not pushed
    assert "NOT pushed" in capsys.readouterr().err
    assert (tmp_path / "lab" / ".provena" / "stranded.jsonl").exists()
    assert main(["push"]) == 0
    assert main(["stranded", "list"]) == 0
    assert "attest" in capsys.readouterr().out
    assert main(["stranded", "redo"]) == 5                       # an attestation: by hand


def test_pull_while_a_teammate_pushes(hubs, monkeypatch):
    """Review 15: entries and head were fetched separately, so a concurrent push made pull fail."""
    tmp_path, http = hubs
    pid = Repo.find().state.project
    copy, agent = _bob(tmp_path, monkeypatch, pid)
    e = _bob_entity(copy, agent, tmp_path / "copy" / "c.csv", "y\n")
    bob = HubClient(PRIMARY, agent=agent, http=http[PRIMARY])
    real, fired = HubClient.entries, []

    def entries_then_teammate_submits(self, p, start=0):
        out = real(self, p, start)
        if not fired:
            fired.append(1)
            bob.submit(pid, e)
        return out

    monkeypatch.setattr(HubClient, "entries", entries_then_teammate_submits)
    assert main(["pull"]) == 0
    monkeypatch.setattr(HubClient, "entries", real)
    assert main(["pull"]) == 0
    assert entries.entry_hash(e) in Repo.find().state.entries
