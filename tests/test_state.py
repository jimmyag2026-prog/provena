import pytest

from provena.core import builders, entries
from provena.core.errors import VerificationError
from provena.core.keys import AgentKey
from provena.core.state import ProjectState


def test_full_flow_replays_identically(lab):
    tech = lab.join("contributor", kind="instrument")
    plan = lab.put_plan(lab.owner)
    raw = lab.put_entity(tech, b"OD600\n0.41\n")
    result = lab.put_entity(lab.owner, b"Kd=7nM\n", name="fit.json", refs=[raw])
    lab.add(builders.activity(lab.state, lab.owner, used=[raw], generated=[result],
                              plan_ref=plan, details={"command": "python fit.py"}))
    s = lab.secrets[plan]
    lab.add(builders.reveal(lab.state, lab.owner, plan, salt=s.salt, plain_sha256=s.plain_sha256))
    reviewer = lab.join("reviewer")
    lab.add(builders.attest(lab.state, reviewer, result, type="review", verdict="pass",
                            note="looks right"))

    replayed = ProjectState.replay(lab.log)
    assert replayed.order == lab.state.order
    assert plan in replayed.reveals
    assert replayed.attestations[result]
    assert builders.open_entry_fields(replayed, lab.owner, lab.log[0]) == {"name": "assay-42"}
    detail = builders.open_entry_fields(replayed, reviewer, lab.log[5])
    assert {k: v for k, v in detail.items() if k != "details_salt"} == {"command": "python fit.py"}


def test_non_member_cannot_write(lab):
    stranger = AgentKey.generate()
    e = entries.build(stranger, "plan", project=lab.state.project, body={"commitment": "00" * 32})
    with pytest.raises(VerificationError, match="not an active member"):
        lab.state.apply(e)


@pytest.mark.parametrize("role", ["reviewer", "viewer"])
def test_read_roles_cannot_register_data(lab, role):
    agent = lab.join(role)
    with pytest.raises(VerificationError):
        lab.put_entity(agent)


def test_viewer_cannot_attest(lab):
    viewer = lab.join("viewer")
    target = lab.put_entity(lab.owner)
    with pytest.raises(VerificationError):
        lab.add(builders.attest(lab.state, viewer, target, type="review"))


def test_chain_gap_detected(lab):
    """A hub that drops an author's entry is caught by the author's next entry."""
    lab.put_entity(lab.owner)
    body, secrets, size = lab.content(lab.owner, b"second")
    dropped = builders.entity(lab.state, lab.owner, body, secrets, name="a", plain_size=size)
    fork_state = ProjectState.replay(lab.log)
    fork_state.apply(dropped)
    body, secrets, size = lab.content(lab.owner, b"third")
    after = builders.entity(fork_state, lab.owner, body, secrets, name="b", plain_size=size)
    with pytest.raises(VerificationError, match="chain gap"):
        lab.state.apply(after)


def test_ref_must_exist(lab):
    with pytest.raises(VerificationError, match="not in this project"):
        lab.put_entity(lab.owner, refs=["ab" * 32])


def test_plan_must_precede_activity(lab):
    """Preregistration order: an activity can only cite a plan already in the log."""
    raw = lab.put_entity(lab.owner)
    with pytest.raises(VerificationError):
        lab.add(builders.activity(lab.state, lab.owner, used=[raw], plan_ref="cd" * 32))


def test_activity_rules(lab):
    raw = lab.put_entity(lab.owner)
    with pytest.raises(VerificationError, match="both used and generated"):
        lab.add(builders.activity(lab.state, lab.owner, used=[raw], generated=[raw]))
    with pytest.raises(VerificationError, match="use or generate"):
        lab.add(builders.activity(lab.state, lab.owner))


def test_reveal_requires_correct_opening_and_only_once(lab):
    plan = lab.put_plan(lab.owner)
    s = lab.secrets[plan]
    with pytest.raises(VerificationError):
        lab.add(builders.reveal(lab.state, lab.owner, plan, salt=bytes(32),
                                plain_sha256=s.plain_sha256))
    lab.add(builders.reveal(lab.state, lab.owner, plan, salt=s.salt,
                            plain_sha256=s.plain_sha256))
    with pytest.raises(VerificationError, match="already revealed"):
        lab.add(builders.reveal(lab.state, lab.owner, plan, salt=s.salt,
                                plain_sha256=s.plain_sha256))


def test_only_author_or_admin_reveals_and_redacts(lab):
    a, b = lab.join("contributor"), lab.join("contributor")
    h = lab.put_entity(a)
    s = lab.secrets[h]
    with pytest.raises(VerificationError):
        lab.add(builders.reveal(lab.state, b, h, salt=s.salt, plain_sha256=s.plain_sha256))
    with pytest.raises(VerificationError):
        lab.add(builders.redact(lab.state, b, h, reason="gdpr"))
    lab.add(builders.redact(lab.state, a, h, reason="gdpr"))
    assert h in lab.state.redacted and h in lab.state.entries  # existence survives redaction
    with pytest.raises(VerificationError, match="redacted"):
        lab.add(builders.reveal(lab.state, a, h, salt=s.salt, plain_sha256=s.plain_sha256))


def test_remove_member_rotates_and_locks_out(lab):
    tech = lab.join("contributor")
    entry, new_pek = builders.member_remove(lab.state, lab.owner, tech.id)
    lab.add(entry)
    assert lab.state.epoch == 1 and tech.id not in lab.state.wraps[1]
    assert builders.epoch_key(lab.state, lab.owner) == new_pek
    late = entries.build(tech, "plan", project=lab.state.project, prev=lab.state.heads.get(tech.id),
                         body={"commitment": "00" * 32})
    with pytest.raises(VerificationError, match="not an active member"):
        lab.add(late)


def test_content_must_use_current_epoch(lab):
    stale_body, secrets, size = lab.content(lab.owner, b"x")
    entry, _ = builders.rotate(lab.state, lab.owner)
    lab.add(entry)
    with pytest.raises(VerificationError, match="current epoch"):
        lab.add(builders.entity(lab.state, lab.owner, stale_body, secrets, name="x",
                                plain_size=size))


def test_cannot_lose_last_owner(lab):
    with pytest.raises(VerificationError, match="at least one owner"):
        lab.add(builders.member_role(lab.state, lab.owner, lab.owner.id, "viewer"))
    assert lab.state.role_of(lab.owner.id) == "owner"  # rejected entries are rolled back


def test_maintainer_cannot_create_owner(lab):
    m = lab.join("maintainer")
    with pytest.raises(VerificationError, match="only owners"):
        lab.add(builders.member_add(lab.state, m, AgentKey.generate().make_card("person"),
                                    "owner"))


def test_wraps_must_cover_exactly_active_members(lab):
    lab.join("contributor")
    entry, _ = builders.rotate(lab.state, lab.owner)
    entry["body"]["wraps"].popitem()
    with pytest.raises(VerificationError):  # signature breaks first; rebuild properly below
        lab.add(entry)
    state = lab.state
    wraps, _ = builders._fresh_wraps(state, state.epoch + 1, set())
    wraps.popitem()
    bad = entries.build(lab.owner, "key", project=state.project, prev=state.heads[lab.owner.id],
                        body={"action": "rotate", "epoch": state.epoch + 1, "wraps": wraps})
    with pytest.raises(VerificationError, match="exactly the active members"):
        lab.add(bad)


def test_key_succession(lab):
    lab.put_entity(lab.owner)
    entry, _ = builders.rotate(lab.state, lab.owner)
    lab.add(entry)
    new_key = AgentKey.generate()
    h = lab.add(builders.succeed(lab.state, lab.owner, new_key.make_card("person")))
    assert lab.state.role_of(new_key.id) == "owner"
    assert lab.state.role_of(lab.owner.id) is None
    assert lab.state.heads[new_key.id] == h
    # successor can read every epoch and keeps writing on the same chain
    assert builders.epoch_key(lab.state, new_key, 0)
    lab.put_entity(new_key)
    with pytest.raises(VerificationError):
        lab.put_entity(lab.owner)


def test_cross_project_entry_rejected(lab):
    from tests.conftest import Lab

    other = Lab()
    h = other.put_entity(other.owner)
    with pytest.raises(VerificationError):
        lab.state.apply(other.state.entries[h])


def test_tampered_log_fails_replay(lab):
    lab.put_entity(lab.owner)
    lab.log[1]["body"]["size"] += 1
    with pytest.raises(VerificationError):
        ProjectState.replay(lab.log)


def test_grant_rules(lab):
    a, b = lab.join("contributor"), lab.join("contributor")
    h = lab.put_entity(a)
    s = lab.secrets[h]
    reviewer = AgentKey.generate()
    card = reviewer.make_card("person", "reviewer")

    def grant(author):
        return builders.grant(lab.state, author, h, card, dek=s.dek, salt=s.salt,
                              plain_sha256=s.plain_sha256, name="x.csv")

    with pytest.raises(VerificationError, match="author or an admin"):
        lab.add(grant(b))
    g = lab.add(grant(a))
    assert reviewer.id in lab.state.grants[h]
    opened = builders.open_grant(lab.state.entries[g], reviewer)
    assert opened["dek"] == s.dek and opened["name"] == "x.csv"
    lab.add(builders.redact(lab.state, a, h, reason="withdrawn"))
    with pytest.raises(VerificationError, match="redacted"):
        lab.add(grant(a))


def test_succession_card_without_id_rejected_cleanly(lab):
    """Regression (security review #4): a card lacking `id` used to crash _record outside
    the rollback, leaving a half-applied succession."""
    new_key = AgentKey.generate()
    card = new_key.make_card("person")
    entry = builders.succeed(lab.state, lab.owner, card)
    body_card = {k: v for k, v in entry["body"]["card"].items() if k != "id"}
    bad = entries.build(lab.owner, "key", project=lab.state.project,
                        prev=lab.state.heads[lab.owner.id],
                        body={**entry["body"], "card": body_card})
    with pytest.raises(VerificationError):
        lab.add(bad)
    assert lab.state.role_of(lab.owner.id) == "owner"
    assert new_key.id not in lab.state.members
    ProjectState.replay(lab.log)


def test_cid_cannot_be_registered_twice(lab):
    """Regression (security review #3): a contributor aliasing an owner's ciphertext."""
    c = lab.join("contributor")
    h = lab.put_entity(lab.owner)
    body = lab.state.entries[h]["body"]
    s = lab.secrets[h]
    with pytest.raises(VerificationError, match="already registered"):
        lab.add(builders.entity(lab.state, c, dict(body), s, name="alias", plain_size=1))


def test_outputs_must_follow_their_plan(lab):
    """Regression (security review #2): result registered before the plan, then an activity
    claiming to have generated it under that plan."""
    result = lab.put_entity(lab.owner, b"Kd=7nM\n", name="result.csv")
    plan = lab.put_plan(lab.owner)
    with pytest.raises(VerificationError, match="registered after the plan"):
        lab.add(builders.activity(lab.state, lab.owner, generated=[result], plan_ref=plan))
    raw = lab.put_entity(lab.owner)  # inputs from before the plan are fine
    out = lab.put_entity(lab.owner, b"out", name="out.csv")
    lab.add(builders.activity(lab.state, lab.owner, used=[result, raw], generated=[out],
                              plan_ref=plan))
    with pytest.raises(VerificationError, match="already generated"):
        lab.add(builders.activity(lab.state, lab.owner, used=[raw], generated=[out]))


def test_facility_capture_attestation(lab):
    facility = lab.join("reviewer", kind="org")
    run = lab.put_entity(lab.owner, b"LC-MS run 17\n", name="run17.raw")
    lab.add(builders.attest(lab.state, facility, run, type="capture", verdict="pass",
                            note="operated by core facility, instrument QE-02"))
    assert lab.state.attestations[run]


def test_cannot_claim_someone_elses_entity_as_output(lab):
    """Regression (re-review #1): a contributor squatting the provenance of another's data."""
    mallory, alice = lab.join("contributor"), lab.join("contributor")
    plan = lab.put_plan(mallory)
    data = lab.put_entity(alice, b"alice's data\n")
    with pytest.raises(VerificationError, match="entity's author or an admin"):
        lab.add(builders.activity(lab.state, mallory, generated=[data], plan_ref=plan))
    lab.add(builders.activity(lab.state, alice, generated=[data], plan_ref=plan))


def test_trailing_newline_hex_rejected(lab):
    e = entries.build(lab.owner, "plan", project=lab.state.project,
                      prev=lab.state.heads[lab.owner.id], body={"commitment": "00" * 32})
    e["refs"] = ["ab" * 32 + "\n"]
    with pytest.raises(VerificationError):
        entries.check_shape(e)


def test_malformed_grant_body_is_a_verification_error(lab):
    h = lab.put_entity(lab.owner)
    bad = entries.build(lab.owner, "grant", project=lab.state.project,
                        prev=lab.state.heads[lab.owner.id], refs=[h],
                        body={"target": h, "to": "not-a-card", "wrap": "x"})
    with pytest.raises(VerificationError, match="malformed grant"):
        lab.add(bad)


def test_late_joiner_can_succeed_their_key(lab):
    """Found by the randomised parity test: a member who joined after epoch 0 never held the
    epoch-0 key, so requiring a re-wrap of every epoch made their succession impossible."""
    e, _ = builders.rotate(lab.state, lab.owner)
    lab.add(e)
    late = lab.join("contributor")              # joins at epoch 1
    new = AgentKey.generate()
    lab.add(builders.succeed(lab.state, late, new.make_card("person")))
    assert lab.state.role_of(new.id) == "contributor"
    assert set(lab.state.wraps[1]) >= {new.id} and new.id not in lab.state.wraps[0]
    lab.put_entity(new)
