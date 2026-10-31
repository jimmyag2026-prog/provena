from fastapi.testclient import TestClient

from provena.core import builders
from provena.core.keys import AgentKey
from provena.server.app import create_app, load_or_create_hub_key
from provena.server.limits import Limits, TokenBuckets, client_key


def test_token_bucket_refills():
    b = TokenBuckets(rate_per_sec=1.0, burst=2)
    assert b.take("a", now=0) and b.take("a", now=0)
    assert not b.take("a", now=0.5)
    assert b.take("a", now=1.6)
    assert b.take("b", now=0)  # buckets are per client


def test_hub_rate_limits_writes_and_project_creation(tmp_path):
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    app = create_app(tmp_path / "hub", key, card,
                     limits=Limits(writes_per_minute=1, burst=2, projects_per_hour=1,
                                   project_burst=3, max_projects=2))
    http = TestClient(app)
    statuses = []
    for _ in range(5):
        a = AgentKey.generate()
        genesis, _ = builders.new_project(a, a.make_card("person"))
        statuses.append(http.post("/v1/projects", json={"entry": genesis}).status_code)
    # project bucket allows a burst of 3; the hub-wide cap of 2 projects bites on the third
    assert statuses == [201, 201, 503, 429, 429]
    assert http.get("/v1/hub").status_code == 200  # reads are not limited


def test_bucket_memory_is_bounded():
    """Regression (review 3 #3): the old prune never removed anything."""
    b = TokenBuckets(rate_per_sec=1.0, burst=5, max_keys=1000)
    for i in range(50_000):
        b.take(f"10.0.{i // 256}.{i % 256}", now=0)
    assert len(b._state) == 1000


def test_client_keys():
    assert client_key("2001:db8::1") == client_key("2001:db8::ffff") == "2001:db8::/64"
    assert client_key("2001:db8:0:1::1") != client_key("2001:db8::1")
    assert client_key("203.0.113.7") == "203.0.113.7"
    assert client_key("::ffff:203.0.113.7") == "203.0.113.7"


def test_spoofed_forwarded_for_is_ignored(tmp_path):
    """Regression (review 3 #4): the leftmost X-Forwarded-For entry is client-controlled."""
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    app = create_app(tmp_path / "hub", key, card, trust_forwarded_for=True,
                     limits=Limits(projects_per_hour=1, project_burst=3))
    http = TestClient(app)
    codes = []
    for i in range(6):
        a = AgentKey.generate()
        genesis, _ = builders.new_project(a, a.make_card("person"))
        codes.append(http.post("/v1/projects", json={"entry": genesis},
                               headers={"X-Forwarded-For": f"198.51.100.{i}, 192.0.2.1"})
                     .status_code)
    assert codes[:3] == [201, 201, 201] and set(codes[3:]) == {429}
