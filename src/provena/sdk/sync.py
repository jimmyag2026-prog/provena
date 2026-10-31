"""Synchronising a local repository with a hub: pull, push, clone.

The hub is the sequencer, so after a sync the local log is the hub's order followed by any local
entries not yet accepted. Every receipt and tree head is verified against the pinned hub key, and
each new head must be consistent with the last one seen (a forked or rewritten hub log fails).
"""

from __future__ import annotations

import functools
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from provena.client.hub import HubClient, HubError
from provena.core import entries, merkle, rotation
from provena.core.errors import ProvenaError, VerificationError
from provena.core.keys import AgentKey, AgentPublic, verify_card
from provena.core.receipts import verify_set
from provena.core.state import ProjectState
from provena.core.treehead import verify_head
from provena.store.repo import Repo


@dataclass
class SyncResult:
    pulled: int = 0
    pushed: int = 0
    blobs_up: int = 0
    blobs_down: int = 0
    head: dict = field(default_factory=dict)
    stranded: int = 0  # own pending entries set aside (they depended on unconfirmed entries)
    blobs_missing: int = 0  # readable ciphertext the hub could not serve (yet)
    conflicts: int = 0  # paths with two concurrent versions (ours + a teammate's), unresolved
    rotated: str = ""  # the hub handed its log key over to this one (ADR 0010) and we followed


def _locked(fn):
    """Sync reads the local log, talks to the hub and rewrites the log: one writer at a time
    (a concurrent `provena add` waits instead of being overwritten)."""
    @functools.wraps(fn)
    def wrapper(repo: Repo, *args, **kwargs):
        with repo.writing():
            return fn(repo, *args, **kwargs)
    return wrapper


class SyncIntegrityError(VerificationError):
    """The hub contradicts what we hold: a changed log key, a rolled-back or forked log.
    Nothing was written; do not push until it is explained (exit 6)."""

    def __init__(self, message: str, error: str = "E_FORK"):
        super().__init__(message)
        self.error = error


class SyncIncomplete(ProvenaError):
    """Sync stopped with work left (entries set aside, files not uploaded) (exit 5)."""

    def __init__(self, message: str, error: str = "E_INCOMPLETE"):
        super().__init__(message)
        self.error = error


def make_client(url: str, agent: AgentKey | None) -> HubClient:
    """Factory indirection so tests can swap in an in-process transport."""
    return HubClient(url, agent=agent)


@_locked
def pin_hub(repo: Repo, url: str, client: HubClient) -> dict:
    info = client.info()
    card = info["card"]
    verify_card(card)
    pinned = repo.config.get("hub_card")
    if pinned and pinned["id"] != card["id"] and not follow_rotation(repo, info):
        raise VerificationError(f"hub key changed: pinned {pinned['id']}, got {card['id']}")
    repo.set_config(hub=url, hub_card=card)
    return card


def follow_rotation(repo: Repo, info: dict) -> str:
    """If the pinned hub handed its log key over to the key it now serves (ADR 0010: a statement
    signed by both keys, oldest first), re-pin to the new key and return its id; else "".
    Heads and receipts signed by earlier keys stay checkable with the cards kept here."""
    pinned, live = repo.config.get("hub_card"), info["card"]
    if not pinned or pinned["id"] == live["id"]:
        return ""
    try:
        path = rotation.chain(info.get("rotations") or [], pinned["id"], live["id"])
    except VerificationError:
        return ""
    if not path or path[-1]["new"] != live:
        return ""
    past = repo.config.get("hub_past_cards", []) + [s["old"] for s in path]
    repo.set_config(hub_card=live, hub_past_cards=past, hub_rotations=info["rotations"])
    return live["id"]


def _adopt_rotations(info: dict) -> dict:
    """Config for a checkout that first meets a hub which has rotated (clone, rehome): the
    earlier cards of the chain ending at the key it serves, to check old heads and receipts.
    First use is trust on first use either way; the chain must still verify."""
    rotations = info.get("rotations") or []
    if not rotations:
        return {}
    rotation.successors(rotations)
    first = rotations[0]["old"]["id"]
    path = rotation.chain(rotations, first, info["card"]["id"])
    if not path or path[-1]["new"] != info["card"]:
        raise VerificationError("hub's key hand-overs do not end at the key it serves")
    return {"hub_past_cards": [st["old"] for st in path], "hub_rotations": rotations}


def _check_pin(repo: Repo, client: HubClient) -> str:
    """Before reading or writing: the hub must still sign with the key we pinned, or with a
    successor that key handed over to. Returns the new key id when we followed a rotation."""
    info = client.info()
    pinned, live = (repo.config.get("hub_card") or {}).get("id"), info["card"]["id"]
    if not pinned or live == pinned:
        return ""
    followed = follow_rotation(repo, info)
    if not followed:
        raise SyncIntegrityError(error="E_HUB_KEY", message=
            f"the hub at {repo.config.get('hub')} now signs with log key {live}, but this "
            f"project pinned {pinned} and the hub shows no hand-over signed by it; nothing "
            f"was pushed or pulled. It may be a different or reset hub: investigate first")
    return followed


def _hub_pub(repo: Repo) -> AgentPublic:
    return verify_card(repo.config["hub_card"])


def hub_cards(repo: Repo) -> dict[str, dict]:
    """Every log key this project's hub has signed with: the current one and its predecessors."""
    cards = {c["id"]: c for c in repo.config.get("hub_past_cards", [])}
    if repo.config.get("hub_card"):
        cards[repo.config["hub_card"]["id"]] = repo.config["hub_card"]
    return cards


def _card_for(repo: Repo, signer: str) -> dict:
    card = hub_cards(repo).get(signer)
    if card is None:
        raise VerificationError(f"head signed by {signer}, which is not this project's hub")
    return card


def _check_receipt(receipt: dict, pub: AgentPublic, pid: str, index: int, entry: dict) -> None:
    """A receipt must be signed by the pinned hub and name this entry, position and project."""
    verify_set(receipt, pub)
    if (receipt["entry_hash"] != entries.entry_hash(entry) or receipt["index"] != index
            or receipt["project"] != pid):
        raise VerificationError("receipt does not match entry, position or project")


def _save_receipt(repo: Repo, receipt: dict) -> None:
    with open(repo.dir / "receipts.jsonl", "a") as f:
        f.write(json.dumps(receipt) + "\n")


def _check_head(repo: Repo, client: HubClient, head: dict | None = None) -> dict:
    pid, pub = repo.state.project, _hub_pub(repo)
    head = client.sth(pid) if head is None else head
    verify_head(head, pub)
    synced = repo.config.get("synced", 0)
    if head["size"] < synced:
        raise SyncIntegrityError(_rollback(repo, head["size"], synced), "E_ROLLBACK")
    if head["size"] != synced:  # a teammate pushed between our steps: nothing is wrong
        raise SyncIncomplete(f"the hub moved on while syncing (head {head['size']}, ours "
                             f"{synced}): another member pushed meanwhile — run it again",
                             "E_CONFLICT")
    local_root = merkle.root(repo.leaves()[:synced]).hex()
    if head["root"] != local_root:
        raise VerificationError("hub head root does not match our copy of the log")
    known = hub_cards(repo)
    previous = [h["head"] for h in repo.heads() if h["head"]["signer"] in known]
    if previous:
        prev = max(previous, key=lambda h: h["size"])
        if prev["size"] > head["size"]:
            raise SyncIntegrityError(_rollback(repo, head["size"], prev["size"]), "E_ROLLBACK")
        if prev["size"] < head["size"]:
            proof = [bytes.fromhex(p) for p in client.consistency(pid, prev["size"],
                                                                  head["size"])]
            merkle.verify_consistency(prev["size"], head["size"], bytes.fromhex(prev["root"]),
                                      bytes.fromhex(head["root"]), proof)
    if not previous or max(h["size"] for h in previous) < head["size"]:
        repo.add_head(head, repo.config["hub_card"])
    _refresh_evidence(repo, client, head)
    return head


def _rollback(repo: Repo, now: int, had: int) -> str:
    return (f"the hub at {repo.config.get('hub')} rolled back: it now holds {now} entries of "
            f"this project, but signed receipts for {had}. Nothing was changed locally; the "
            f"operator restored an old backup or lost data. Keep this checkout (it holds the "
            f"signed entries) and ask the operator; `provena mirror` checks a second hub")


def _refresh_evidence(repo: Repo, client: HubClient, head: dict) -> None:
    """Fetch witness cosignatures for *head* and anchor records for the project."""
    pid = head["project"]
    cosigs = repo.read_extra("cosigs.json", {})
    def checked(heads: list[dict]) -> None:  # cosignatures from before a rotation name theirs
        for h in heads:
            verify_head(h, verify_card(_card_for(repo, h["signer"])))

    current = client.cosignatures(pid, head["size"])
    if current:
        checked([c["head"] for c in current if "head" in c])
        cosigs[str(head["size"])] = {"head": head, "cosignatures": current}
    latest = client.latest_cosignatures(pid)
    if latest["head"] and latest["head"]["size"] <= head["size"]:
        checked([latest["head"]] + [c["head"] for c in latest["cosignatures"] if "head" in c])
        cosigs[str(latest["head"]["size"])] = latest
    repo.write_extra("cosigs.json", cosigs)
    # an anchor covers the head as signed then: pair it with the key that signed it
    repo.write_extra("anchors.json", [{**r, "log_card": _card_for(repo, r["head"]["signer"])}
                                      for r in client.anchors(pid)])


@_locked
def pull(repo: Repo, client: HubClient, *, blobs: bool = True,
         agent: AgentKey | None = None) -> SyncResult:
    result = SyncResult()
    result.rotated = _check_pin(repo, client) if repo.config.get("hub_card") else ""
    pid, pub = repo.state.project, _hub_pub(repo)
    synced = repo.config.get("synced", 0)
    # head first, entries up to it: a teammate pushing meanwhile cannot make the two disagree
    head = client.sth(pid)
    if head["size"] < synced:
        verify_head(head, pub)
        raise SyncIntegrityError(_rollback(repo, head["size"], synced), "E_ROLLBACK")
    if synced:  # the hub's log must still begin with the entries we hold receipts for
        verify_head(head, pub)
        ours = merkle.root(repo.leaves()[:synced])
        proof = [] if head["size"] == synced else [
            bytes.fromhex(x) for x in client.consistency(pid, synced, head["size"])]
        try:
            if head["size"] == synced:
                if bytes.fromhex(head["root"]) != ours:
                    raise VerificationError("root differs")
            else:
                merkle.verify_consistency(synced, head["size"], ours,
                                          bytes.fromhex(head["root"]), proof)
        except VerificationError:
            raise SyncIntegrityError(
                f"the hub at {repo.config.get('hub')} no longer holds the {synced} entries we "
                f"have its receipts for at the start of its log: it was rolled back and then "
                f"written to, or it forked. Nothing was changed locally; keep this checkout "
                f"and tell the operator", "E_ROLLBACK") from None
    remote = client.entries(pid, start=synced)[: max(0, head["size"] - synced)]
    for i, item in enumerate(remote):
        if item["index"] != synced + i:
            raise VerificationError("hub returned a gap in the log")
        # receipts from before a key rotation are signed by the key of their day
        signer = (item["receipt"] or {}).get("signer", "")
        _check_receipt(item["receipt"], pub if signer == pub.id else
                       verify_card(_card_for(repo, signer)), pid, synced + i, item["entry"])
    new = [item["entry"] for item in remote]
    local = repo.log()
    seen = {entries.entry_hash(e) for e in new}
    # entries read from a mirror are not ours to keep: the primary either confirms them (they
    # arrive in `new`) or they are dropped — never left pending, never pushed
    from_mirror = set(repo.config.get("mirror_pending", []))
    pending = [e for e in local[synced:] if entries.entry_hash(e) not in seen | from_mirror]
    kept, stranded = _replayable(local[:synced] + new, pending)
    for item in remote:  # receipts first: a crash after `synced` moves must not lose them
        _save_receipt(repo, item["receipt"])
    if stranded:
        with open(repo.dir / "stranded.jsonl", "a") as f:
            f.writelines(json.dumps(e) + "\n" for e in stranded)
        # their files are no longer on the ledger: `status` shows them again and
        # `provena stranded redo` records them anew
        gone = {entries.entry_hash(e) for e in stranded}
        tracked = repo.tracked
        repo.write_extra("tracked.json", {k: v for k, v in tracked.items()
                                          if v["entry"] not in gone})
    repo.replace_log(local[:synced] + new + kept)
    repo.set_config(synced=synced + len(new), mirror_pending=[])
    result.pulled, result.stranded = len(new), len(stranded)
    if agent is not None and new and kept:
        result.conflicts = _record_conflicts(repo, agent, new, kept)
    result.head = _check_head(repo, client, head) if repo.config["synced"] else {}
    if blobs:
        # every readable entry still missing its ciphertext, not just this pull's new ones:
        # a push or mirror (which pull without blobs) may have advanced `synced` earlier
        result.blobs_down, result.blobs_missing = _download_blobs(repo, client, repo.log(),
                                                                  agent, required=[])
    return result


def _record_conflicts(repo: Repo, agent: AgentKey, new: list[dict], kept: list[dict]) -> int:
    """Two versions of one path recorded concurrently: ours (not yet pushed) and a teammate's
    (just pulled). Both stay on the ledger; `status` shows the conflict until
    `provena resolve PATH --keep HASH` picks the version this checkout tracks."""
    from provena.core import builders

    state = repo.state

    def name(e: dict) -> str | None:
        if e["kind"] not in ("entity", "plan"):
            return None
        try:
            return (builders.open_entry_fields(state, agent, e) or {}).get("name")
        except Exception:  # noqa: BLE001 — an epoch this key cannot read
            return None

    mine = {name(e): entries.entry_hash(e) for e in kept if e["author"] == agent.id}
    found = list(repo.config.get("conflicts", []))
    for e in new:
        n = name(e)
        if n and n in mine and e["author"] != agent.id:
            item = {"path": n, "mine": mine[n], "theirs": entries.entry_hash(e),
                    "author": e["author"]}
            if item not in found:
                found.append(item)
    repo.set_config(conflicts=found)
    return len(found)


def _replayable(base: list[dict], pending: list[dict]) -> tuple[list[dict], list[dict]]:
    """Own pending entries that still apply on top of *base*; the rest (e.g. built on a
    mirror entry the primary never confirmed) are set aside instead of wedging every sync."""
    state = ProjectState.replay(base)
    kept, stranded = [], []
    for e in pending:
        try:
            state.apply(e)
            kept.append(e)
        except ProvenaError:
            stranded.append(e)
    return kept, stranded


@_locked
def pull_mirror(repo: Repo, url: str, client: HubClient, *,
                agent: AgentKey | None = None, trusted_logs: set[str] = frozenset()
                ) -> SyncResult:
    """Read new entries from a mirror while the primary hub is unreachable.

    The mirror's log key is pinned like the primary's (first use pins it). Its head must be
    signed by that key, and the Merkle root over our synced prefix plus the mirror's entries
    must equal the mirror's head root — the mirror can only extend the history we hold. The
    entries are kept *after* our synced prefix without moving it: the next pull from the primary
    brings the same entries with the primary's own receipts (and would expose any mismatch)."""
    url = _norm_url(url)
    card = client.info()["card"]
    pub = verify_card(card)
    if card["id"] == (repo.config.get("hub_card") or {}).get("id"):
        raise VerificationError("that is this project's primary hub: use `provena pull`")
    mirrors = {_norm_url(u): v for u, v in repo.config.get("mirrors", {}).items()}
    if url in mirrors and mirrors[url]["card"]["id"] != card["id"]:
        raise VerificationError("mirror's log key changed since it was first used")
    if url not in mirrors and card["id"] not in trusted_logs:
        # no trust on first use here: the mirror's entries are taken on its key alone
        raise VerificationError(f"mirror {url} (log key {card['id']}) is not pinned: run "
                                "`provena mirror --check URL` while the primary is up, or "
                                f"`provena trust add log {card['id']}` after checking the key")
    pid, synced = repo.state.project, repo.config.get("synced", 0)
    head = client.sth(pid)
    verify_head(head, pub)
    earlier = (mirrors.get(url) or {}).get("head")
    if earlier and earlier["size"] <= head["size"] and earlier["size"] > 0:
        try:
            proof = [bytes.fromhex(x)
                     for x in client.consistency(pid, earlier["size"], head["size"])]
            merkle.verify_consistency(earlier["size"], head["size"], bytes.fromhex(earlier["root"]),
                                      bytes.fromhex(head["root"]), proof)
        except (VerificationError, HubError) as exc:
            raise VerificationError("the mirror's head contradicts the head it showed before "
                                    "(kept in your config as evidence)") from exc
    elif earlier and earlier["size"] > head["size"]:
        raise VerificationError("the mirror's log shrank since it was last read")
    local = repo.log()
    if head["size"] < synced:
        raise VerificationError(f"mirror holds {head['size']} entries, fewer than the "
                                f"{synced} already synced: nothing to read")
    remote = client.entries(pid, start=synced)[: head["size"] - synced]
    for i, item in enumerate(remote):
        if item["index"] != synced + i:
            raise VerificationError("mirror returned a gap in the log")
        _check_receipt(item["receipt"], pub, pid, synced + i, item["entry"])
    new = [item["entry"] for item in remote]
    leaves = repo.leaves()[:synced] + [entries.entry_leaf(e) for e in new]
    if len(leaves) != head["size"] or merkle.root(leaves).hex() != head["root"]:
        raise VerificationError("mirror's entries do not extend our log to its signed head")
    seen = {entries.entry_hash(e) for e in new}
    pending = [e for e in local[synced:] if entries.entry_hash(e) not in seen]
    mirrors[url] = {**mirrors.get(url, {}), "card": card, "head": head}
    already = set(repo.config.get("mirror_pending", []))
    # mark them provisional *before* they enter the log: a crash in between must never leave
    # mirror entries looking like the user's own (which push would relay)
    repo.set_config(mirrors=mirrors,
                    mirror_pending=sorted(already | {entries.entry_hash(e) for e in new}))
    repo.replace_log(local[:synced] + new + pending)
    result = SyncResult()
    result.pulled = len(new)
    # any readable entry still missing ciphertext; failures are not fatal (log already updated)
    result.blobs_down, result.blobs_missing = _download_blobs(repo, client, repo.log(), agent,
                                                              required=[])
    result.head = head
    return result


def _download_blobs(repo: Repo, client: HubClient, new: list[dict],
                    agent: AgentKey | None, required: list[dict] | None = None) -> int:
    """Fetch missing ciphertext for *new*. Failures for entries not in *required* (older ones,
    e.g. never uploaded by their author) are skipped rather than failing the pull."""
    must = {entries.entry_hash(e) for e in (new if required is None else required)}
    missing = 0
    state, n = repo.state, 0
    readable = agent is not None and state.role_of(agent.id) is not None
    for e in new:
        h = entries.entry_hash(e)
        cid = e["body"].get("cid") if e["kind"] in ("entity", "plan") else None
        if not cid or repo.has_blob(cid) or h in state.redacted:
            continue
        public = state.policy["visibility"] == "public" or (
            state.reveals.get(h) or {}).get("dek")
        if not (readable or public):
            continue
        try:
            client.download_blob(state.project, cid, repo.blob_path(cid),
                                 max_size=e["body"]["size"])
        except HubError:
            if h in must:
                raise
            missing += 1
            continue
        n += 1
    return n, missing


@_locked
def push(repo: Repo, client: HubClient, *, agent: AgentKey | None = None) -> SyncResult:
    pid = repo.state.project
    if repo.config.get("primary"):
        raise SyncIncomplete(error="E_READONLY", message=
            f"this checkout was cloned from a mirror; writes go to the project's primary hub "
            f"{repo.config['primary']['url']}: run `provena remote --rehome` once it is up")
    rotated = _check_pin(repo, client)
    # cleared only when every entry and file is on the hub: a push cut short (killed,
    # throttled, network) is reported by `status` / `doctor` instead of looking complete
    repo.set_config(push_incomplete=True)
    if client.project(pid) is None:
        genesis = repo.log()[0]
        res = client.create_project(genesis)
        _check_receipt(res["receipt"], _hub_pub(repo), pid, 0, genesis)
        _save_receipt(repo, res["receipt"])
        repo.set_config(synced=1)
    result = pull(repo, client, blobs=False, agent=agent)
    result.rotated = result.rotated or rotated
    synced = repo.config["synced"]
    from_mirror = set(repo.config.get("mirror_pending", []))
    pending = [e for e in repo.log()[synced:] if entries.entry_hash(e) not in from_mirror]
    pub = _hub_pub(repo)
    for e in pending:
        res = client.submit(pid, e)
        r = res["receipt"]
        if r.get("index") != synced and r.get("entry_hash") == entries.entry_hash(e):
            verify_set(r, pub)  # accepted, but behind a teammate's concurrent push
            raise SyncIncomplete("another member pushed at the same moment; the hub took this "
                                 "entry at a later position — run `provena push` again",
                                 "E_CONFLICT")
        _check_receipt(r, pub, pid, synced, e)
        _save_receipt(repo, res["receipt"])
        synced += 1
        repo.set_config(synced=synced)
    result.pushed = len(pending)
    state = repo.state
    local = []
    for h in state.order:
        e = state.entries[h]
        cid = e["body"].get("cid") if e["kind"] in ("entity", "plan") else None
        if cid and h not in state.redacted and repo.has_blob(cid):
            local.append(cid)
    local = list(dict.fromkeys(local))  # the same content may back several entries
    missing = client.missing_blobs(pid, local) if local else set()
    for cid in local:
        if cid in missing:
            client.put_blob(pid, cid, repo.blob_path(cid))
            result.blobs_up += 1
    result.head = _check_head(repo, client)
    left = client.missing_blobs(pid, local) if local else set()
    if left:
        raise SyncIncomplete(f"{len(left)} files are still not on the hub after uploading; "
                             f"run `provena push` again")
    repo.set_config(push_incomplete=False)
    return result


def _norm_url(url: str) -> str:
    """One spelling per hub for key pinning: lower-case scheme and host, no default port,
    no trailing slash."""
    from urllib.parse import urlsplit, urlunsplit

    u = urlsplit(url.strip())
    host = (u.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    try:
        port = u.port
    except ValueError as exc:
        raise VerificationError(f"not a valid hub URL: {url}") from exc
    if port and not ((u.scheme == "https" and port == 443) or (u.scheme == "http" and port == 80)):
        host = f"{host}:{port}"
    return urlunsplit((u.scheme.lower(), host, u.path.rstrip("/"), "", ""))


@_locked
def mirror(repo: Repo, url: str, client: HubClient, *, primary: HubClient | None = None,
           check_only: bool = False) -> dict:
    """Replicate the hub-sequenced prefix of the log, and its ciphertext, to a second hub.

    Entries are author-signed, so any hub can sequence them; the same entries in the same order
    give the same Merkle root, so the mirror's head must equal our copy of the log at its size.
    Any difference is evidence that one of the two hubs forked. Anyone can clone from the mirror
    if the primary is down. *check_only* compares without writing. With *primary*, the log is
    first brought up to date from it, so redactions made from other checkouts are known (their
    ciphertext is never re-published) and an honest mirror ahead of a stale checkout is not
    mistaken for a fork."""
    if repo.config.get("primary"):
        raise SyncIncomplete(error="E_READONLY", message=
                             "this checkout was cloned from a mirror; mirror from a checkout "
                             "of the primary hub (`provena remote --rehome` first)")
    if primary is not None:
        pull(repo, primary, blobs=False)
    url = _norm_url(url)
    card = client.info()["card"]
    pub = verify_card(card)
    primary = repo.config.get("hub_card") or {}
    if card["id"] == primary.get("id"):
        raise VerificationError("that is this project's primary hub")
    mirrors = {_norm_url(u): v for u, v in repo.config.get("mirrors", {}).items()}
    if url in mirrors and mirrors[url]["card"]["id"] != card["id"]:
        raise VerificationError("mirror's log key changed since it was first used")
    pid, log, synced = repo.state.project, repo.log(), repo.config.get("synced", 0)
    if not synced:
        raise VerificationError("push to the primary hub first: only sequenced entries mirror")
    leaves = repo.leaves()

    def same(head: dict) -> None:
        verify_head(head, pub)
        if head["size"] > synced:
            raise VerificationError(f"mirror holds {head['size']} entries, more than the "
                                    f"primary's {synced}: the logs diverged")
        if head["root"] != merkle.root(leaves[:head["size"]]).hex():
            raise VerificationError(f"mirror head at size {head['size']} differs from our log: "
                                    "one of the hubs forked")

    info = client.project(pid)
    start = 0
    if info is not None and info.get("head"):
        same(info["head"])
        start = info["head"]["size"]
    if check_only:
        mirrors[url] = {"card": card, "size": start, "head": (info or {}).get("head")}
        repo.set_config(mirrors=mirrors)
        return {"size": start, "behind": synced - start, "card": card}
    for i in range(start, synced):
        e = log[i]
        res = client.create_project(e) if i == 0 else client.submit(pid, e)
        _check_receipt(res["receipt"], pub, pid, i, e)
    state, uploaded = repo.state, 0
    for h in state.order[:synced]:
        e = state.entries[h]
        cid = e["body"].get("cid") if e["kind"] in ("entity", "plan") else None
        if cid and h not in state.redacted and repo.has_blob(cid) \
                and not client.has_blob(pid, cid):
            client.put_blob(pid, cid, repo.blob_path(cid))
            uploaded += 1
    head = client.sth(pid)
    same(head)
    if head["size"] != synced:
        raise VerificationError("mirror did not sequence every entry")
    mirrors[url] = {"card": card, "size": synced, "head": head}  # signed: fork evidence
    repo.set_config(mirrors=mirrors)
    # so that a checkout cloned from the mirror writes to the primary, not to the mirror
    try:
        client.set_primary(pid, repo.config["hub"], repo.config["hub_card"],
                           repo.config.get("hub_rotations"))
    except HubError as exc:
        if exc.status not in (404, 405):
            raise  # an older mirror hub cannot record it: clones from it are not read-only
    return {"size": synced, "pushed": synced - start, "blobs_up": uploaded, "card": card}


@_locked
def rehome(repo: Repo, client: HubClient) -> dict:
    """A checkout cloned from a mirror moves to the project's primary hub (its key is the one
    the mirror recorded); the mirror becomes a read-only fallback."""
    primary = repo.config["primary"]
    info = client.info()
    card = info["card"]
    verify_card(card)
    try:
        handed = card["id"] != primary["card"]["id"] and rotation.chain(
            info.get("rotations") or [], primary["card"]["id"], card["id"])
    except VerificationError:
        handed = None
    if card["id"] != primary["card"]["id"] and not handed:
        raise SyncIntegrityError(f"{primary['url']} signs with {card['id']}, not with the "
                                 f"primary key {primary['card']['id']} the mirror recorded")
    upstream = (client.project(repo.state.project) or {}).get("primary")
    if upstream and upstream["card"]["id"] != card["id"]:
        raise SyncIntegrityError(f"{primary['url']} is itself a mirror (of {upstream['url']}); "
                                 f"writing there would fork the project")
    mirrors = dict(repo.config.get("mirrors", {}))
    mirrors[_norm_url(repo.config["hub"])] = {"card": repo.config["hub_card"],
                                              "size": repo.config.get("synced", 0), "head": None}
    repo.set_config(hub=primary["url"], hub_card=card, synced=0, primary=None, mirrors=mirrors,
                    **_adopt_rotations(info))
    pull(repo, client)  # the same entries: the primary's receipts replace the mirror's
    return card


def clone(url: str, pid: str, dest: Path, agent_name: str, agent: AgentKey,
          client: HubClient) -> tuple[Repo, SyncResult]:
    if not re.fullmatch(r"[0-9a-f]{64}", pid):
        raise VerificationError(f"{pid!r}: clone takes the full 64-hex project id (the "
                                f"`project` printed by init, in config.json or a .pvb)")
    info = client.info()
    card = info["card"]
    verify_card(card)
    adopted = _adopt_rotations(info)
    remote = client.entries(pid, start=0)
    if not remote or entries.entry_hash(remote[0]["entry"]) != pid:
        raise VerificationError("hub did not return this project's genesis")
    info = client.project(pid) or {}
    dest.mkdir(parents=True, exist_ok=True)
    repo = Repo.init(dest, agent_name, remote[0]["entry"])
    primary = info.get("primary")
    repo.set_config(hub=url, hub_card=card, synced=0, **adopted,
                    primary=primary if primary and primary["card"]["id"] != card["id"] else None)
    return repo, pull(repo, client, agent=agent)


def bundle_evidence(repo: Repo, head: dict) -> dict:
    """Witness cosignatures and anchors the repo holds that can be attached to a bundle on
    *head*: anything on a hub head no larger than it (make_bundle adds consistency proofs)."""
    card = repo.config.get("hub_card")
    credentials = repo.read_extra("credentials.json", [])
    if not card:
        return {"cosignatures": [], "anchors": [], "credentials": credentials}
    items = []
    for record in repo.read_extra("cosigs.json", {}).values():
        if record["head"]["size"] <= head["size"]:
            for c in record["cosignatures"]:  # a cosignature from before a key rotation
                cosigned = c.get("head") or record["head"]  # names the head it signed
                items.append({**c, "head": cosigned,
                              "log_card": hub_cards(repo).get(cosigned["signer"], card)})
    return {"cosignatures": items, "anchors": repo.read_extra("anchors.json", []),
            "credentials": credentials, "receipts": _receipts(repo),
            "log_rotations": repo.config.get("hub_rotations", [])}


def _receipts(repo: Repo) -> dict[str, dict]:
    path = repo.dir / "receipts.jsonl"
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            out[r["entry_hash"]] = r
    return out
