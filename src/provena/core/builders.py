"""Pure constructors for well-formed entries (client side; no I/O).

Each builder reads what it needs from the current ProjectState (project id, the author's chain
head, member keys, epoch) so that callers cannot get prev/epoch/wraps wrong by hand.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import BinaryIO

from provena.core import aead, commitment, entries
from provena.core.canonical import canonicalize
from provena.core.encoding import b64u, unb64u
from provena.core.errors import ProvenaError
from provena.core.hashing import sha256
from provena.core.keys import AgentKey
from provena.core.seal import open_sealed, seal_to, unwrap, wrap
from provena.core.state import ProjectState


def _epoch_info(epoch: int) -> bytes:
    return f"epoch-{epoch}".encode()


def _aad(project: str | None) -> bytes:
    return b"provena/sealed/" + (project or "genesis").encode()


def seal_fields(pek: bytes, project: str | None, obj: dict) -> str:
    return b64u(wrap(pek, canonicalize(obj), _aad(project)))


def open_fields(pek: bytes, project: str | None, sealed: str) -> dict:
    return json.loads(unwrap(pek, unb64u(sealed), _aad(project)))


def wrap_epoch_key(pek: bytes, epoch: int, kem_pub: bytes) -> str:
    return b64u(seal_to(kem_pub, pek, _epoch_info(epoch)))


def epoch_key(state: ProjectState, agent: AgentKey, epoch: int | None = None) -> bytes:
    epoch = state.epoch if epoch is None else epoch
    wrapped = state.wraps.get(epoch, {}).get(agent.id)
    if wrapped is None:  # removed, or added after this epoch
        raise ProvenaError(f"agent {agent.id} holds no project key for epoch {epoch} "
                         "(not an active member then)")
    return open_sealed(agent.kem_private, unb64u(wrapped), _epoch_info(epoch))


def open_entry_fields(state: ProjectState, agent: AgentKey, entry: dict) -> dict | None:
    if entry["sealed"] is None:
        return None
    project = None if entry["kind"] == "genesis" else state.project
    pek = epoch_key(state, agent, entry["body"].get("epoch", 0))
    return open_fields(pek, project, entry["sealed"])


def _entry(state: ProjectState, author: AgentKey, kind: str, *, refs=(), body=None,
           sealed=None, ts=None) -> dict:
    return entries.build(author, kind, project=state.project, prev=state.heads.get(author.id),
                         refs=list(dict.fromkeys(refs)), body=body or {}, sealed=sealed, ts=ts)


# -- project lifecycle ---------------------------------------------------------------------------

RULES = 2  # ADR 0009: new projects get the newest ledger rules


def new_project(owner: AgentKey, owner_card: dict, *, visibility: str = "private",
                witnesses: int = 0, name: str = "", ts: int | None = None,
                rules: int = RULES) -> tuple[dict, bytes]:
    pek = aead.new_key()
    policy = {"visibility": visibility, "witnesses": witnesses}
    if rules != 1:  # rules 1 genesis entries carry no version, as before ADR 0009
        policy["rules"] = rules
    body = {
        "policy": policy,
        "members": [{"card": owner_card, "role": "owner"}],
        "epoch": 0,
        "wraps": {owner.id: wrap_epoch_key(pek, 0, owner.public.kem_pub)},
    }
    sealed = seal_fields(pek, None, {"name": name}) if name else None
    return entries.build(owner, "genesis", project=None, body=body, sealed=sealed, ts=ts), pek


# -- content -------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ContentSecrets:
    """Client-only material for one piece of content. Never sent to the hub."""
    salt: bytes
    plain_sha256: bytes
    dek: bytes


def encrypt_content(pek: bytes, epoch: int, src: BinaryIO, dst: BinaryIO
                    ) -> tuple[dict, ContentSecrets, int]:
    """Encrypt src into dst; return (public body, secrets, plaintext size)."""
    dek = aead.new_key()
    info = aead.encrypt_stream(dek, src, dst)
    salt = commitment.new_salt()
    c = commitment.commit(salt, info.plain_sha256)
    body = {"commitment": c.hex(), "cid": info.cipher_sha256.hex(), "size": info.cipher_size,
            "epoch": epoch, "dek": b64u(wrap(pek, dek, c))}
    return body, ContentSecrets(salt, info.plain_sha256, dek), info.plain_size


def content_dek(pek: bytes, body: dict) -> bytes:
    return unwrap(pek, unb64u(body["dek"]), bytes.fromhex(body["commitment"]))


def entity(state: ProjectState, author: AgentKey, body: dict, secrets: ContentSecrets, *,
           name: str, plain_size: int, media_type: str | None = None, refs=(), ts=None) -> dict:
    pek = epoch_key(state, author)
    private = {"name": name, "plain_size": plain_size, "salt": secrets.salt.hex(),
               "plain_sha256": secrets.plain_sha256.hex()}
    if media_type:
        private["media_type"] = media_type
    return _entry(state, author, "entity", refs=refs, body=body,
                  sealed=seal_fields(pek, state.project, private), ts=ts)


def plan(state: ProjectState, author: AgentKey, body: dict, secrets: ContentSecrets, *,
         title: str, refs=(), ts=None) -> dict:
    pek = epoch_key(state, author)
    private = {"title": title, "salt": secrets.salt.hex(),
               "plain_sha256": secrets.plain_sha256.hex()}
    body = {**body, "epoch": state.epoch}
    return _entry(state, author, "plan", refs=refs, body=body,
                  sealed=seal_fields(pek, state.project, private), ts=ts)


def activity(state: ProjectState, author: AgentKey, *, used=(), generated=(), plan_ref=None,
             details: dict | None = None, external=(), ts=None) -> dict:
    """*external*: (project, entry) pairs of inputs that live in other projects; prove them by
    attaching those projects' bundles (make_bundle(..., external=[…]))."""
    body = {"used": list(used), "generated": list(generated), "plan": plan_ref,
            "epoch": state.epoch}
    if external:
        body["external"] = [{"project": p, "entry": e} for p, e in external]
    refs = [*used, *generated, *([plan_ref] if plan_ref else [])]
    if state.rules >= 2:
        # a provable step: public status, salted commitment to the sealed details, so they
        # can be opened later (`reveal`) and checked by anyone
        details = dict(details or {})
        salt = commitment.new_salt()
        body["status"] = "failed" if details.get("exit_code") not in (None, 0) else "ok"
        body["commitment"] = commitment.commit(salt, sha256(canonicalize(details))).hex()
        sealed = seal_fields(epoch_key(state, author), state.project,
                             {**details, DETAILS_SALT: salt.hex()})
        return _entry(state, author, "activity", refs=refs, body=body, sealed=sealed, ts=ts)
    sealed = seal_fields(epoch_key(state, author), state.project, details) if details else None
    if sealed is None:
        body.pop("epoch")
    return _entry(state, author, "activity", refs=refs, body=body, sealed=sealed, ts=ts)


DETAILS_SALT = "details_salt"  # sealed beside an activity's details (rules 2)


def opened_details(private: dict) -> tuple[bytes, dict]:
    """(salt, details) of a rules-2 activity from its sealed fields."""
    details = {k: v for k, v in private.items() if k != DETAILS_SALT}
    return bytes.fromhex(private[DETAILS_SALT]), details


def reveal_activity(state: ProjectState, author: AgentKey, target: str, private: dict, *,
                    publish_details: bool = True, ts=None) -> dict:
    """Open a step's committed details (rules 2); with *publish_details* they become public."""
    salt, details = opened_details(private)
    body = {"target": target, "salt": salt.hex(),
            "plain_sha256": sha256(canonicalize(details)).hex(), "dek": None}
    if publish_details:
        body["details"] = details
    return _entry(state, author, "reveal", refs=[target], body=body, ts=ts)


def member_rewrap(state: ProjectState, author: AgentKey, agent_id: str, *, ts=None) -> dict:
    """Give an active member the keys of every earlier epoch the author can read and they
    cannot (rules 2): history for someone added after a rotation, or a recovery key."""
    member = state.members[agent_id]
    epochs = {str(e): wrap_epoch_key(epoch_key(state, author, e), e, member.pub.kem_pub)
              for e, wraps in state.wraps.items() if author.id in wraps and agent_id not in wraps}
    if not epochs:
        raise ProvenaError("that member already holds every epoch key you can read")
    body = {"action": "rewrap", "agent": agent_id, "epoch_wraps": epochs}
    return _entry(state, author, "member", body=body, ts=ts)


def reveal(state: ProjectState, author: AgentKey, target: str, *, salt: bytes,
           plain_sha256: bytes, dek: bytes | None = None, name: str | None = None,
           ts=None) -> dict:
    """*name* publishes the file name too (it is otherwise sealed)."""
    body = {"target": target, "salt": salt.hex(), "plain_sha256": plain_sha256.hex(),
            "dek": b64u(dek) if dek else None}
    if name:
        body["name"] = name
    return _entry(state, author, "reveal", refs=[target], body=body, ts=ts)


def attest(state: ProjectState, author: AgentKey, target: str, *, type: str,
           verdict: str | None = None, note: str | None = None, ts=None) -> dict:
    body = {"target": target, "type": type, "verdict": verdict}
    sealed = None
    if note:
        body["epoch"] = state.epoch
        sealed = seal_fields(epoch_key(state, author), state.project, {"note": note})
    return _entry(state, author, "attest", refs=[target], body=body, sealed=sealed, ts=ts)


def redact(state: ProjectState, author: AgentKey, target: str, *, reason: str, ts=None) -> dict:
    return _entry(state, author, "redact", refs=[target],
                  body={"target": target, "reason": reason}, ts=ts)


def _grant_info(target: str) -> bytes:
    return b"grant/" + target.encode()


def grant(state: ProjectState, author: AgentKey, target: str, card: dict, *, dek: bytes,
          salt: bytes, plain_sha256: bytes, name: str, ts=None) -> dict:
    """Share one piece of content with a non-member: its DEK and commitment opening are
    sealed to the grantee's KEM key, and the grant itself is on the ledger (an access log)."""
    secret = {"dek": b64u(dek), "salt": salt.hex(), "plain_sha256": plain_sha256.hex(),
              "name": name}
    wrap = b64u(seal_to(bytes.fromhex(card["kem"]), canonicalize(secret), _grant_info(target)))
    return _entry(state, author, "grant", refs=[target],
                  body={"target": target, "to": card, "wrap": wrap}, ts=ts)


def open_grant(entry: dict, agent: AgentKey) -> dict:
    target = entry["body"]["target"]
    secret = json.loads(open_sealed(agent.kem_private, unb64u(entry["body"]["wrap"]),
                                    _grant_info(target)))
    secret["dek"] = unb64u(secret["dek"])
    return secret


def meta(state: ProjectState, author: AgentKey, *, ts=None, **fields) -> dict:
    """Replace the public project card (title, description, license, tags). Public!"""
    card = {k: v for k, v in {**state.meta, **fields}.items() if v is not None}
    return _entry(state, author, "meta", body=card, ts=ts)


# -- membership and keys -------------------------------------------------------------------------

def member_add(state: ProjectState, author: AgentKey, card: dict, role: str, *, ts=None) -> dict:
    pek = epoch_key(state, author)
    body = {"action": "add", "card": card, "role": role,
            "wraps": {card["id"]: wrap_epoch_key(pek, state.epoch, bytes.fromhex(card["kem"]))}}
    return _entry(state, author, "member", body=body, ts=ts)


def _fresh_wraps(state: ProjectState, epoch: int, exclude: set[str]) -> tuple[dict, bytes]:
    pek = os.urandom(32)
    wraps = {i: wrap_epoch_key(pek, epoch, state.members[i].pub.kem_pub)
             for i in state.active_ids() - exclude}
    return wraps, pek


def member_remove(state: ProjectState, author: AgentKey, agent_id: str, *, ts=None
                  ) -> tuple[dict, bytes]:
    epoch = state.epoch + 1
    wraps, pek = _fresh_wraps(state, epoch, {agent_id})
    body = {"action": "remove", "agent": agent_id, "epoch": epoch, "wraps": wraps}
    return _entry(state, author, "member", body=body, ts=ts), pek


def member_role(state: ProjectState, author: AgentKey, agent_id: str, role: str, *, ts=None
                ) -> dict:
    return _entry(state, author, "member", body={"action": "role", "agent": agent_id,
                                                 "role": role}, ts=ts)


def rotate(state: ProjectState, author: AgentKey, *, ts=None) -> tuple[dict, bytes]:
    epoch = state.epoch + 1
    wraps, pek = _fresh_wraps(state, epoch, set())
    body = {"action": "rotate", "epoch": epoch, "wraps": wraps}
    return _entry(state, author, "key", body=body, ts=ts), pek


def succeed(state: ProjectState, old: AgentKey, new_card: dict, *, ts=None) -> dict:
    new_kem = bytes.fromhex(new_card["kem"])
    epoch_wraps = {str(e): wrap_epoch_key(epoch_key(state, old, e), e, new_kem)
                   for e, wraps in state.wraps.items() if old.id in wraps}
    body = {"action": "succeed", "card": new_card, "epoch_wraps": epoch_wraps}
    return _entry(state, old, "key", body=body, ts=ts)
