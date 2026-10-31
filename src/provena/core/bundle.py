"""Proof bundles (`.pvb`): portable, offline-verifiable evidence about ledger entries.

Two modes:
  selective  only the target entries, their lineage, and the entries that introduced each
             author's key, each with an RFC 9162 inclusion proof against one signed tree head.
             Reveals as little of the project as possible.
  full       every entry up to the head; the verifier replays the whole state machine, so
             authorization (membership at the time, revocations) is proven too.
"""

from __future__ import annotations

from provena.core import entries, merkle
from provena.core.encoding import b64u

FORMAT = "provena-bundle/1"


def _key_intros(log: list[dict]) -> dict[str, int]:
    """agent id -> index of the entry that introduced its card."""
    intros: dict[str, int] = {}
    for i, e in enumerate(log):
        body = e["body"]
        if e["kind"] == "genesis":
            for m in body["members"]:
                intros.setdefault(m["card"]["id"], i)
        elif e["kind"] == "member" and body.get("action") == "add":
            intros.setdefault(body["card"]["id"], i)
        elif e["kind"] == "key" and body.get("action") == "succeed":
            intros.setdefault(body["card"]["id"], i)
    return intros


def lineage_closure(log: list[dict], targets: list[str],
                    hashes: list[str] | None = None) -> set[str]:
    """Everything a target depends on: its references and, for data, the activity that
    generated it (activities point at their outputs, so that edge must be walked backwards),
    recursively."""
    hashes = hashes or [entries.entry_hash(e) for e in log]
    by_hash = dict(zip(hashes, log, strict=True))
    generated_by = {g: h for h, e in by_hash.items() if e["kind"] == "activity"
                    for g in e["body"].get("generated", [])}
    seen, stack = set(), list(targets)
    explicit = set(targets)
    while stack:
        h = stack.pop()
        if h in seen:
            continue
        seen.add(h)
        e = by_hash[h]
        if e["kind"] == "activity" and h not in explicit:
            # reached as "how was this made": its inputs and plan, not its other outputs
            # (those are siblings the prover did not ask to disclose)
            body = e["body"]
            stack.extend([*body.get("used", []), *([body["plan"]] if body.get("plan") else [])])
        else:
            stack.extend(e["refs"])
        if h in generated_by:
            stack.append(generated_by[h])
    return seen


def make_bundle(log: list[dict], head: dict, head_signer_card: dict, targets: list[str], *,
                mode: str = "selective", lineage: bool = True,
                openings: dict[str, dict] | None = None,
                contents: dict[str, bytes] | None = None,
                cosignatures: list[dict] | None = None,
                anchors: list[dict] | None = None,
                credentials: list[dict] | None = None,
                log_rotations: list[dict] | None = None,
                receipts: dict[str, dict] | None = None,
                external: list[dict] | None = None) -> dict:
    """Build a bundle proving *targets* against *head* (which must cover them).

    openings maps entry hash -> {"salt": hex, "plain_sha256": hex}; contents optionally embeds
    plaintext for opened entries so a reader can check the actual bytes.
    """
    log = log[: head["size"]]
    if not log:
        raise ValueError("empty log")
    hashes = [entries.entry_hash(e) for e in log]
    index = {h: i for i, h in enumerate(hashes)}
    tree = merkle.MerkleLog(merkle.leaf_hash(bytes.fromhex(h)) for h in hashes)  # one, cached
    missing = [t for t in targets if t not in index]
    if missing:
        raise ValueError(f"targets not covered by the tree head: {missing}")
    if mode == "full":
        items = [{"index": i, "entry": e} for i, e in enumerate(log)]
    elif mode == "selective":
        wanted = lineage_closure(log, targets, hashes) if lineage else set(targets)
        wanted.add(hashes[0])
        intros = _key_intros(log)
        # attestations about any wanted entry travel with it
        for i, e in enumerate(log):
            if e["kind"] in ("attest", "reveal", "redact", "grant") \
                    and e["body"]["target"] in wanted:
                wanted.add(hashes[i])
        for h in list(wanted):
            wanted.add(hashes[intros[log[index[h]]["author"]]])
        items = [{"index": index[h], "entry": log[index[h]],
                  "proof": [p.hex() for p in tree.inclusion_proof(index[h])]}
                 for h in sorted(wanted, key=index.__getitem__)]
    else:
        raise ValueError(f"unknown mode {mode!r}")
    for it in items:  # signed per-entry sequencing receipts (SET) from the head's log, if held
        r = (receipts or {}).get(hashes[it["index"]])
        if r and r.get("signer") == head["signer"] and r.get("index") == it["index"]:
            it["receipt"] = r
    opened = {}
    for h, o in (openings or {}).items():
        opened[h] = {"salt": o["salt"], "plain_sha256": o["plain_sha256"]}
        if contents and h in contents:
            opened[h]["content"] = b64u(contents[h])
    bundle = {
        "format": FORMAT,
        "mode": mode,
        "project": hashes[0],
        "head": head,
        "head_signer": head_signer_card,
        "targets": list(targets),
        "entries": items,
        "openings": opened,
        "cosignatures": _cosig_items(tree, head, head_signer_card, cosignatures or []),
        "anchors": _anchor_items(tree, head, anchors or []),
        # only credentials about authors in this bundle: others would leak who is in the project
        "credentials": [c for c in credentials or []
                        if isinstance(c, dict) and c.get("credential", {}).get("subject")
                        in {it["entry"]["author"] for it in items}],
        "external": list(external or []),  # bundles of other projects cited by activities
    }
    if log_rotations:  # the hub's log key hand-overs (ADR 0010); absent when it never rotated
        bundle["log_rotations"] = list(log_rotations)
    return bundle


def _consistency_to(tree: merkle.MerkleLog, older: dict, head: dict) -> list[str] | None:
    """Hex consistency proof from *older* to *head*, or None if older is not a prefix."""
    if older["project"] != head["project"] or not 0 < older["size"] <= head["size"]:
        return None
    if tree.root(older["size"]).hex() != older["root"]:
        return None
    if older["size"] == head["size"]:
        return []
    return [p.hex() for p in tree.consistency_proof(older["size"], head["size"])]


def _cosig_items(tree: merkle.MerkleLog, head: dict, head_card: dict,
                 records: list[dict]) -> list:
    """Cosignature items: {cosig, card, head, log_card, consistency}. A record without "head"
    is a cosignature on the bundle head itself."""
    items = []
    for r in records:
        cosigned = r.get("head", head)
        proof = _consistency_to(tree, cosigned, head)
        if proof is not None:
            items.append({"cosig": r["cosig"], "card": r["card"], "head": cosigned,
                          "log_card": r.get("log_card", head_card), "consistency": proof})
    return items


def _anchor_items(tree: merkle.MerkleLog, head: dict, records: list[dict]) -> list[dict]:
    """Attach, to each anchor record of this log, a consistency proof to the bundle head."""
    items = []
    for r in records:
        proof = _consistency_to(tree, r["head"], head)
        if proof is not None:
            items.append({**r, "consistency": proof})
    return items
