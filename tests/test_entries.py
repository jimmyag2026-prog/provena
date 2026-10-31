import pytest

from provena.core import entries
from provena.core.errors import VerificationError
from provena.core.keys import AgentKey

H = "ab" * 32


def test_build_verify_and_hash_stability():
    a = AgentKey.generate()
    e = entries.build(a, "entity", project=H, refs=[H], body={"cid": H}, ts=1)
    entries.verify_signature(e, a.public)
    assert entries.entry_hash(e) == entries.entry_hash(dict(reversed(list(e.items()))))
    assert len(entries.entry_leaf(e)) == 32


@pytest.mark.parametrize("field,value", [
    ("body", {"cid": "cd" * 32}), ("ts", 2), ("refs", []), ("kind", "plan"), ("prev", H),
])
def test_any_field_change_breaks_signature(field, value):
    a = AgentKey.generate()
    e = entries.build(a, "entity", project=H, refs=[H], body={"cid": H}, ts=1)
    e[field] = value
    with pytest.raises(VerificationError):
        entries.verify_signature(e, a.public)


def test_wrong_author_key():
    a, b = AgentKey.generate(), AgentKey.generate()
    e = entries.build(a, "entity", project=H, ts=1)
    with pytest.raises(VerificationError):
        entries.verify_signature(e, b.public)


@pytest.mark.parametrize("mutate", [
    lambda e: e.pop("sealed"),
    lambda e: e.update(extra=1),
    lambda e: e.update(v=2),
    lambda e: e.update(kind="nope"),
    lambda e: e.update(project=None),
    lambda e: e.update(refs=["xyz"]),
    lambda e: e.update(ts=1.5),
    lambda e: e.update(ts=True),
    lambda e: e.update(sig="00"),
])
def test_shape_rejections(mutate):
    e = entries.build(AgentKey.generate(), "entity", project=H, ts=1)
    mutate(e)
    with pytest.raises(VerificationError):
        entries.check_shape(e)


def test_genesis_must_have_null_project():
    a = AgentKey.generate()
    entries.build(a, "genesis", project=None)
    with pytest.raises(VerificationError):
        entries.build(a, "genesis", project=H)
