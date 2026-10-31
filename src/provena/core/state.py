"""Ledger state machine (ARCHITECTURE.md §6.3).

The current membership, roles, key epochs, reveals and redactions of a project are *derived* by
replaying its entries from genesis. Hub and clients run this same code, so authorization decisions
are reproducible by anyone holding the log.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field

from provena.core import commitment, entries
from provena.core.canonical import canonicalize
from provena.core.errors import VerificationError
from provena.core.hashing import sha256
from provena.core.keys import AgentPublic, verify_card

ROLES = ("owner", "maintainer", "contributor", "reviewer", "viewer")
WRITERS = {"owner", "maintainer", "contributor"}
ADMINS = {"owner", "maintainer"}
# capture: a facility vouches it performed the measurement; operator: who ran the instrument
ATTEST_TYPES = ("review", "replicate", "calibration", "endorse", "dispute", "capture",
                "operator")
VERDICTS = ("pass", "fail", "inconclusive", None)
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")  # \Z: "$" would accept a trailing newline


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)  # JSON true is not a number


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise VerificationError(msg)


def _hex64(value, what: str) -> str:
    _need(isinstance(value, str) and bool(_HEX64.match(value)), f"{what} must be hex sha256")
    return value


META_LIMITS = {"title": 200, "description": 4000, "license": 64}
# Exactly the body fields each kind may carry: no kind smuggles arbitrary data.
BODY_FIELDS = {
    "genesis": {"policy", "members", "epoch", "wraps", "meta"},
    "entity": {"commitment", "cid", "size", "epoch", "dek", "capture"},
    "plan": {"commitment", "cid", "size", "epoch", "dek"},
    "activity": {"used", "generated", "plan", "epoch", "external"},
    "reveal": {"target", "salt", "plain_sha256", "dek", "name"},
    "attest": {"target", "type", "verdict", "epoch"},
    "redact": {"target", "reason"},
    "grant": {"target", "to", "wrap"},
    "meta": {"title", "description", "license", "tags"},
    "member": {"action", "card", "role", "wraps", "agent", "epoch"},
    "key": {"action", "epoch", "wraps", "card", "epoch_wraps"},
}


# ADR 0009: rules 2 only add fields (and actions); rules 1 stay frozen.
RULES_VERSIONS = (1, 2)
BODY_FIELDS_V2 = {**BODY_FIELDS,
                  "activity": BODY_FIELDS["activity"] | {"status", "commitment"},
                  "reveal": BODY_FIELDS["reveal"] | {"details"},
                  "member": BODY_FIELDS["member"] | {"epoch_wraps"}}
STEP_STATUS = ("ok", "failed")
SNAPSHOT_VERSION = 1


def status_matches(status, details: dict) -> bool:
    """A revealed step must not contradict its public status: exit code 0 is `ok`, anything
    else `failed` (details without an integer exit code do not decide)."""
    code = details.get("exit_code")
    if not _is_int(code):
        return True
    return status == ("ok" if code == 0 else "failed")


def _check_body_fields(entry: dict, rules: int = 1) -> None:
    allowed = (BODY_FIELDS if rules == 1 else BODY_FIELDS_V2)[entry["kind"]]
    extra = set(entry["body"]) - allowed
    _need(not extra, f"{entry['kind']} body has unknown fields {sorted(extra)}")


def _check_capture(capture) -> None:
    _need(isinstance(capture, dict) and set(capture) <= {"by", "file_mtime", "observed"},
          "capture must be {by, file_mtime, observed}")
    _need(isinstance(capture.get("by", ""), str), "capture.by must be a string")
    for k in ("file_mtime", "observed"):
        _need(k not in capture or (_is_int(capture[k]) and capture[k] >= 0),
              f"capture.{k} must be a non-negative integer")


def _check_meta(meta) -> dict:
    """Public, self-described project card. Plain strings only, bounded sizes."""
    _need(isinstance(meta, dict), "meta must be an object")
    _need(set(meta) <= {*META_LIMITS, "tags"}, "meta: unknown field")
    for k, limit in META_LIMITS.items():
        if k in meta:
            _need(isinstance(meta[k], str) and len(meta[k]) <= limit, f"meta.{k} invalid")
    tags = meta.get("tags", [])
    _need(isinstance(tags, list) and len(tags) <= 20 and all(
        isinstance(t, str) and 0 < len(t) <= 40 for t in tags), "meta.tags invalid")
    return dict(meta)


@dataclass
class Member:
    pub: AgentPublic
    role: str
    card: dict
    active: bool = True


@dataclass
class ProjectState:
    project: str
    policy: dict
    members: dict[str, Member] = field(default_factory=dict)
    epoch: int = 0
    wraps: dict[int, dict[str, str]] = field(default_factory=dict)
    entries: dict[str, dict] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    heads: dict[str, str] = field(default_factory=dict)
    reveals: dict[str, dict] = field(default_factory=dict)
    redacted: set[str] = field(default_factory=set)
    attestations: dict[str, list[str]] = field(default_factory=dict)
    grants: dict[str, dict[str, AgentPublic]] = field(default_factory=dict)
    cids: dict[str, str] = field(default_factory=dict)  # ciphertext id -> owning entry
    meta: dict = field(default_factory=dict)  # public project card: title, license, tags…
    position: dict[str, int] = field(default_factory=dict)  # entry hash -> log index
    generated_by: dict[str, str] = field(default_factory=dict)  # entity -> activity

    @property
    def rules(self) -> int:
        return self.policy.get("rules", 1)

    # -- construction -----------------------------------------------------------------------

    @classmethod
    def from_genesis(cls, genesis: dict) -> ProjectState:
        entries.check_shape(genesis)
        _need(genesis["kind"] == "genesis", "first entry must be genesis")
        _need(genesis["prev"] is None and not genesis["refs"], "genesis has no prev/refs")
        body = genesis["body"]
        policy = body.get("policy")
        _need(isinstance(policy, dict) and set(policy) <= {"visibility", "witnesses", "rules"}
              and policy.get("visibility") in ("private", "public"),
              "genesis: policy.visibility must be private|public")
        _need(_is_int(policy.get("witnesses", 0)), "genesis: policy.witnesses int")
        _need(policy.get("rules", 1) in RULES_VERSIONS and _is_int(policy.get("rules", 1)),
              f"genesis: unknown ledger rules {policy.get('rules')!r} (this verifier knows "
              f"{RULES_VERSIONS})")
        _check_body_fields(genesis, policy.get("rules", 1))
        state = cls(project=entries.entry_hash(genesis), policy=policy)
        for m in body.get("members", []):
            state._add_member(m.get("card"), m.get("role"))
        author = state.members.get(genesis["author"])
        _need(author is not None and author.role == "owner", "genesis author must be an owner")
        if "meta" in body:
            state.meta = _check_meta(body["meta"])
        entries.verify_signature(genesis, author.pub)
        state._set_wraps(0, body.get("wraps"))
        state._record(genesis)
        return state

    @classmethod
    def replay(cls, log: list[dict]) -> ProjectState:
        _need(bool(log), "empty log")
        state = cls.from_genesis(log[0])
        for e in log[1:]:
            state.apply(e)
        return state

    # -- snapshots: a cache of a replay, never evidence ----------------------------------------

    def snapshot(self) -> dict:
        """Everything a replay derived, as JSON. `resume` rebuilds the state from it and the
        same log prefix without re-checking that prefix; the holder of the snapshot vouches that
        the prefix is the one it replayed (the hub: its own database; a checkout: its own file).
        Verifiers never use snapshots."""
        return copy.deepcopy({
            "v": SNAPSHOT_VERSION, "project": self.project, "policy": self.policy,
            "order": list(self.order),
            "members": [{"card": m.card, "role": m.role, "active": m.active}
                        for m in self.members.values()],
            "epoch": self.epoch, "wraps": {str(k): v for k, v in self.wraps.items()},
            "heads": self.heads, "reveals": self.reveals, "redacted": sorted(self.redacted),
            "attestations": self.attestations,
            "grants": {k: {a: p.to_dict() for a, p in v.items()} for k, v in self.grants.items()},
            "cids": self.cids, "meta": self.meta, "generated_by": self.generated_by,
        })

    @classmethod
    def resume(cls, snap: dict, log: list[dict], hashes: list[str] | None = None
               ) -> ProjectState:
        """The state after *log*, from a snapshot of a prefix of it: the prefix is taken as
        replayed, the rest is applied with every check. *hashes* (the log's entry hashes, when
        the caller stores them) must match the snapshot's order; without them the caller has
        made sure the prefix is byte-identical to what was replayed."""
        _need(snap.get("v") == SNAPSHOT_VERSION, "unknown snapshot version")
        snap = copy.deepcopy(snap)  # the state owns what it is built from
        order = snap["order"]
        _need(len(order) <= len(log), "snapshot is ahead of the log")
        if hashes is not None:
            _need(list(hashes[:len(order)]) == order, "snapshot does not match the log")
        state = cls(project=snap["project"], policy=snap["policy"], epoch=snap["epoch"],
                    heads=snap["heads"], reveals=snap["reveals"], redacted=set(snap["redacted"]),
                    attestations=snap["attestations"], cids=snap["cids"], meta=snap["meta"],
                    generated_by=snap["generated_by"])
        for m in snap["members"]:
            pub = AgentPublic.from_dict(m["card"])
            state.members[pub.id] = Member(pub=pub, role=m["role"], card=m["card"],
                                           active=m["active"])
        state.wraps = {int(k): v for k, v in snap["wraps"].items()}
        state.grants = {k: {a: AgentPublic.from_dict(p) for a, p in v.items()}
                        for k, v in snap["grants"].items()}
        for i, h in enumerate(order):
            state.entries[h], state.position[h] = log[i], i
        state.order = list(order)
        for e in log[len(order):]:
            state.apply(e)
        return state

    # -- queries ----------------------------------------------------------------------------

    def role_of(self, agent_id: str) -> str | None:
        m = self.members.get(agent_id)
        return m.role if m and m.active else None

    def active_ids(self) -> set[str]:
        return {i for i, m in self.members.items() if m.active}

    def public_key(self, agent_id: str) -> AgentPublic:
        return self.members[agent_id].pub

    def can_read(self, agent_id: str) -> bool:
        return self.policy["visibility"] == "public" or self.role_of(agent_id) is not None

    # -- application ------------------------------------------------------------------------

    def apply(self, entry: dict) -> str:
        """Validate *entry* against the current state and apply it. Returns its hash."""
        entries.check_shape(entry)
        h = entries.entry_hash(entry)
        _need(h not in self.entries, "duplicate entry")
        _need(entry["project"] == self.project, "entry belongs to another project")
        _need(entry["kind"] != "genesis", "second genesis")
        _check_body_fields(entry, self.rules)
        author = entry["author"]
        role = self.role_of(author)
        _need(role is not None, f"author {author} is not an active member")
        entries.verify_signature(entry, self.members[author].pub, shape_checked=True)
        _need(entry["prev"] == self.heads.get(author),
              "prev does not match the author's previous entry (chain gap or fork)")
        for r in entry["refs"]:
            _need(r in self.entries, f"ref {r[:12]} is not in this project")
        if entry["sealed"] is not None:
            _need(self._epoch_field(entry["body"]) is not None, "sealed entries must name epoch")
        # Only membership and keys can be mutated before a rule fails; reveals, attestations,
        # redactions and grants are written as the last step of their rule, after every check.
        mutable = ("members", "epoch", "wraps")
        snapshot = copy.deepcopy({k: getattr(self, k) for k in mutable})
        try:
            successor = getattr(self, f"_apply_{entry['kind']}")(entry, role)
        except BaseException as exc:
            for k, v in snapshot.items():  # a rejected entry leaves no trace
                setattr(self, k, v)
            if isinstance(exc, (KeyError, TypeError, AttributeError, ValueError, IndexError)):
                raise VerificationError(f"malformed {entry['kind']} body: {exc!r}") from exc
            raise
        self._record(entry, h, successor)
        return h

    def _record(self, entry: dict, h: str | None = None, successor: str | None = None) -> None:
        """Cannot fail: every value it needs was validated before."""
        h = h or entries.entry_hash(entry)
        self.entries[h] = entry
        self.position[h] = len(self.order)
        self.order.append(h)
        self.heads[entry["author"]] = h
        if successor:
            self.heads[successor] = h  # a key successor continues the author's chain
        if entry["kind"] in ("entity", "plan") and entry["body"].get("cid"):
            self.cids[entry["body"]["cid"]] = h
        if entry["kind"] == "activity":
            for g in entry["body"].get("generated", []):
                self.generated_by[g] = h

    # -- per-kind rules ---------------------------------------------------------------------

    def _apply_entity(self, entry: dict, role: str) -> None:
        _need(role in WRITERS, f"role {role} cannot register data")
        if "capture" in entry["body"]:
            _check_capture(entry["body"]["capture"])
        self._check_content_body(entry["body"], require_blob=True)

    def _apply_plan(self, entry: dict, role: str) -> None:
        _need(role in WRITERS, f"role {role} cannot register plans")
        self._check_content_body(entry["body"], require_blob=False)

    def _apply_activity(self, entry: dict, role: str) -> None:
        _need(role in WRITERS, f"role {role} cannot record activities")
        body = entry["body"]
        for key, kinds in (("used", ("entity",)), ("generated", ("entity",))):
            items = body.get(key, [])
            _need(isinstance(items, list), f"activity.{key} must be a list")
            for h in items:
                self._target(h, kinds, f"activity.{key}")
                _need(h in entry["refs"], f"activity.{key} targets must be listed in refs")
        _need(bool(body.get("generated")) or bool(body.get("used"))
              or bool(body.get("external")), "activity must use or generate something")
        for g in body.get("generated", []):
            _need(g not in self.generated_by, "entity was already generated by another activity")
            # Claiming someone else's data as your output would also squat its provenance.
            _need(role in ADMINS or self.entries[g]["author"] == entry["author"],
                  "only the entity's author or an admin can record what generated it")
        if body.get("plan") is not None:
            self._target(body["plan"], ("plan",), "activity.plan")
            _need(body["plan"] in entry["refs"], "activity.plan must be listed in refs")
            # Outputs registered before the plan cannot have been produced under it (HARKing).
            plan_at = self.position[body["plan"]]
            _need(all(self.position[g] > plan_at for g in body.get("generated", [])),
                  "generated entities must be registered after the plan they claim to follow")
        external = body.get("external", [])
        _need(isinstance(external, list) and len(external) <= 100 and all(
            isinstance(x, dict) and set(x) == {"project", "entry"}
            and _HEX64.match(str(x["project"])) and _HEX64.match(str(x["entry"]))
            and x["project"] != self.project for x in external),
            "activity.external must list {project, entry} of other projects")
        overlap = set(body.get("used", [])) & set(body.get("generated", []))
        _need(not overlap, "an entity cannot be both used and generated by one activity")
        if self.rules >= 2:  # a provable step: public status, committed details
            _need(body.get("status") in STEP_STATUS, f"activity.status must be {STEP_STATUS}")
            _hex64(body.get("commitment"), "activity.commitment")

    def _apply_reveal(self, entry: dict, role: str) -> None:
        body = entry["body"]
        kinds = ("entity", "plan", "activity") if self.rules >= 2 else ("entity", "plan")
        target = self._target(body.get("target"), kinds, "reveal.target")
        _need(role in ADMINS or target["author"] == entry["author"],
              "only the author or an admin can reveal")
        earlier = self.reveals.get(body["target"])
        if earlier is not None:
            # rules 2: once more, to publish the content key of a file revealed without it
            _need(self.rules >= 2 and target["kind"] != "activity" and not earlier.get("dek")
                  and body.get("dek") and body.get("salt") == earlier.get("salt")
                  and body.get("plain_sha256") == earlier.get("plain_sha256"),
                  "already revealed")
        if target["kind"] == "activity":
            _need("commitment" in target["body"], "this activity has no commitment to open")
            _need(not body.get("dek"), "an activity has no content key")
            if "details" in body:
                _need(isinstance(body["details"], dict), "reveal.details must be an object")
                _need(sha256(canonicalize(body["details"])).hex() == body.get("plain_sha256"),
                      "reveal.details do not match the opened commitment")
                _need(status_matches(target["body"].get("status"), body["details"]),
                      "the step's public status contradicts its revealed exit code")
        else:
            _need("details" not in body, "only an activity reveal carries details")
        _need(body["target"] not in self.redacted, "cannot reveal redacted content")
        _need(body["target"] in entry["refs"], "reveal.target must be listed in refs")
        name = body.get("name", "x")
        _need(isinstance(name, str) and 0 < len(name) <= 255, "reveal.name must be a short string")
        commitment.verify_opening(bytes.fromhex(target["body"]["commitment"]),
                                  bytes.fromhex(_hex64(body.get("salt"), "reveal.salt")),
                                  bytes.fromhex(_hex64(body.get("plain_sha256"), "reveal.plain")))
        self.reveals[body["target"]] = {**(earlier or {}), **body}

    def _apply_attest(self, entry: dict, role: str) -> None:
        _need(role != "viewer", "viewers cannot attest")
        body = entry["body"]
        self._target(body.get("target"), entries.KINDS, "attest.target")
        _need(body["target"] in entry["refs"], "attest.target must be listed in refs")
        _need(body.get("type") in ATTEST_TYPES, f"attest.type must be one of {ATTEST_TYPES}")
        _need(body.get("verdict") in VERDICTS, "attest.verdict invalid")
        self.attestations.setdefault(body["target"], []).append(entries.entry_hash(entry))

    def _apply_redact(self, entry: dict, role: str) -> None:
        body = entry["body"]
        target = self._target(body.get("target"), ("entity", "plan"), "redact.target")
        _need(role in ADMINS or target["author"] == entry["author"],
              "only the author or an admin can redact")
        _need(body["target"] in entry["refs"], "redact.target must be listed in refs")
        _need(isinstance(body.get("reason"), str) and body["reason"], "redact.reason required")
        self.redacted.add(body["target"])

    def _apply_grant(self, entry: dict, role: str) -> None:
        body = entry["body"]
        target = self._target(body.get("target"), ("entity", "plan"), "grant.target")
        _need(role in ADMINS or target["author"] == entry["author"],
              "only the author or an admin can share content")
        _need(body["target"] in entry["refs"], "grant.target must be listed in refs")
        _need(body["target"] not in self.redacted, "cannot share redacted content")
        _need(isinstance(body.get("wrap"), str), "grant.wrap required")
        grantee = verify_card(body.get("to"))
        self.grants.setdefault(body["target"], {})[grantee.id] = grantee

    def _apply_meta(self, entry: dict, role: str) -> None:
        _need(role in ADMINS, "only owners/maintainers edit the project card")
        self.meta = _check_meta(entry["body"])

    def _apply_member(self, entry: dict, role: str) -> None:
        _need(role in ADMINS, "only owners/maintainers manage members")
        body, action = entry["body"], entry["body"].get("action")
        if action == "add":
            new_role = body.get("role")
            _need(role == "owner" or new_role != "owner", "only owners can add owners")
            pub = self._add_member(body.get("card"), new_role)
            wraps = body.get("wraps")
            _need(isinstance(wraps, dict) and set(wraps) == {pub.id},
                  "member.add must wrap the current epoch key for the new member only")
            self.wraps[self.epoch][pub.id] = wraps[pub.id]
        elif action == "remove":
            target = self._member(body.get("agent"))
            _need(role == "owner" or target.role != "owner", "only owners can remove owners")
            target.active = False
            self._require_owner_left()
            self._rotate(body.get("epoch"), body.get("wraps"))
        elif action == "role":
            target = self._member(body.get("agent"))
            new_role = body.get("role")
            _need(new_role in ROLES, "unknown role")
            _need(role == "owner" or "owner" not in (target.role, new_role),
                  "only owners can grant or change owner")
            target.role = new_role
            self._require_owner_left()
        elif action == "rewrap" and self.rules >= 2:
            # earlier epochs' keys for a member who joined later (history, recovery)
            target = self._member(body.get("agent"))
            _need(target.active, "rewrap is for an active member")
            wraps = body.get("epoch_wraps")
            readable = {str(e) for e, w in self.wraps.items() if entry["author"] in w}
            _need(isinstance(wraps, dict) and wraps and set(wraps) <= readable,
                  "member.rewrap may only share epoch keys its author can read")
            for epoch, sealed in wraps.items():
                _need(isinstance(sealed, str), "member.rewrap wraps must be sealed keys")
                _need(target.pub.id not in self.wraps[int(epoch)],
                      f"member already holds the key of epoch {epoch}")
                self.wraps[int(epoch)][target.pub.id] = sealed
        else:
            raise VerificationError(f"unknown member action {action!r}")

    def _apply_key(self, entry: dict, role: str) -> str | None:
        body, action = entry["body"], entry["body"].get("action")
        if action == "rotate":
            _need(role in ADMINS, "only owners/maintainers rotate project keys")
            self._rotate(body.get("epoch"), body.get("wraps"))
            return None
        elif action == "succeed":
            old = self.members[entry["author"]]
            new = self._add_member(body.get("card"), old.role)
            old.active = False
            wraps = body.get("epoch_wraps")
            readable = {str(e) for e, w in self.wraps.items() if entry["author"] in w}
            _need(isinstance(wraps, dict) and set(wraps) == readable,
                  "key.succeed must re-wrap exactly the epoch keys the old key could read")
            for epoch, sealed in wraps.items():
                self.wraps[int(epoch)][new.id] = sealed
            return new.id
        else:
            raise VerificationError(f"unknown key action {action!r}")

    # -- helpers ----------------------------------------------------------------------------

    def _add_member(self, card, role) -> AgentPublic:
        _need(isinstance(card, dict), "member card required")
        _need(role in ROLES, f"unknown role {role!r}")
        pub = verify_card(card)
        _need(pub.id not in self.members, f"agent {pub.id} was already a member")
        self.members[pub.id] = Member(pub=pub, role=role, card=card)
        return pub

    def _member(self, agent_id) -> Member:
        m = self.members.get(agent_id)
        _need(m is not None and m.active, f"{agent_id} is not an active member")
        return m

    def _require_owner_left(self) -> None:
        _need(any(m.active and m.role == "owner" for m in self.members.values()),
              "a project must keep at least one owner")

    def _set_wraps(self, epoch: int, wraps) -> None:
        _need(isinstance(wraps, dict) and all(isinstance(v, str) for v in wraps.values()),
              "wraps must map agent id -> sealed key")
        _need(set(wraps) == self.active_ids(),
              "epoch key must be wrapped for exactly the active members")
        self.wraps[epoch] = dict(wraps)

    def _rotate(self, epoch, wraps) -> None:
        _need(_is_int(epoch) and epoch == self.epoch + 1, "key epochs must increase by one")
        self._set_wraps(epoch, wraps)
        self.epoch = epoch

    def _epoch_field(self, body: dict) -> int | None:
        epoch = body.get("epoch")
        if epoch is None:
            return None
        _need(_is_int(epoch) and epoch in self.wraps, "unknown epoch")
        return epoch

    def _check_content_body(self, body: dict, *, require_blob: bool) -> None:
        _hex64(body.get("commitment"), "commitment")
        has_blob = body.get("cid") is not None
        _need(has_blob or not require_blob, "entity requires a cid")
        if has_blob:
            _hex64(body["cid"], "cid")
            # One owner per ciphertext: otherwise a contributor could alias someone else's
            # blob and then publish, share or shred it through their own entry.
            _need(body["cid"] not in self.cids, "cid is already registered in this project")
            _need(_is_int(body.get("size")) and body["size"] >= 0, "size must be int")
            _need(isinstance(body.get("dek"), str), "dek wrap required with a blob")
            _need(_is_int(body.get("epoch")) and body["epoch"] == self.epoch,
                  "new content must use the current epoch")

    def _target(self, h, kinds, what: str) -> dict:
        _hex64(h, what)
        target = self.entries.get(h)
        _need(target is not None, f"{what} {h[:12]} not found in project")
        _need(target["kind"] in kinds, f"{what} must be one of {kinds}")
        return target
