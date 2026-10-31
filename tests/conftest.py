import io

import pytest

from provena.core import builders
from provena.core.keys import AgentKey
from provena.core.state import ProjectState


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path_factory, monkeypatch):
    """Nothing a test does may touch the real ~/.provena (tests set their own home on top)."""
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path_factory.mktemp("home")))


class Lab:
    """A small project fixture: owner plus helpers that append and apply entries."""

    def __init__(self, visibility="private", rules=builders.RULES):
        self.owner = AgentKey.generate()
        genesis, _ = builders.new_project(self.owner, self.owner.make_card("person", "owner"),
                                          visibility=visibility, name="assay-42", rules=rules)
        self.log = [genesis]
        self.state = ProjectState.from_genesis(genesis)
        self.secrets = {}

    def add(self, entry):
        h = self.state.apply(entry)
        self.log.append(entry)
        return h

    def join(self, role, kind="person"):
        agent = AgentKey.generate()
        self.add(builders.member_add(self.state, self.owner, agent.make_card(kind), role))
        return agent

    def content(self, author, data: bytes):
        pek = builders.epoch_key(self.state, author)
        body, secrets, size = builders.encrypt_content(pek, self.state.epoch, io.BytesIO(data),
                                                       io.BytesIO())
        return body, secrets, size

    def put_entity(self, author, data=b"raw,data\n1,2\n", name="plate1.csv", refs=()):
        body, secrets, size = self.content(author, data)
        h = self.add(builders.entity(self.state, author, body, secrets, name=name,
                                     plain_size=size, refs=refs))
        self.secrets[h] = secrets
        return h

    def put_plan(self, author, text=b"Hypothesis: X binds Y with Kd < 10 nM"):
        body, secrets, _ = self.content(author, text)
        body = {"commitment": body["commitment"]}  # commitment only, no blob
        h = self.add(builders.plan(self.state, author, body, secrets, title="prereg"))
        self.secrets[h] = secrets
        return h


@pytest.fixture
def lab():
    return Lab()
