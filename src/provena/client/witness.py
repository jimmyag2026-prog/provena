"""A witness: cosigns hub tree heads after checking they extend what it saw before.

One witness may watch the same project on several hubs (a primary and its mirrors, see
`provena mirror`): it remembers every root it has seen per size, across hubs, so two hubs that
disagree at a size, or a hub that does not extend another's history, are refused as a fork."""

from __future__ import annotations

import json
import time
from pathlib import Path

from provena.client.hub import HubClient
from provena.core import merkle, rotation
from provena.core.errors import VerificationError
from provena.core.keys import AgentKey, verify_card
from provena.core.witness import check_extension, cosign

MAX_ROOTS = 1000  # remembered (size, root) pairs per project; the largest are kept


class Witness:
    def __init__(self, key: AgentKey, card: dict, state_path: Path):
        self.key, self.card, self.state_path = key, card, state_path
        self._clients: dict[str, HubClient] = {}  # hubs seen this run, to fetch proofs from

    def _load(self) -> dict:
        return json.loads(self.state_path.read_text()) if self.state_path.exists() else {}

    def _save(self, state: dict) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2))
        tmp.replace(self.state_path)

    def observe(self, client: HubClient, project: str) -> dict:
        """One round: fetch the latest head, verify it extends the last one seen, cosign it,
        hand the cosignature to the hub, and remember the head."""
        info = client.info()
        log = verify_card(info["card"])
        state = self._load()
        self._clients[client.url] = client
        if project in state.get("forks", {}):
            raise VerificationError(f"a fork of project {project[:12]} was seen earlier "
                                    f"({state['forks'][project]['why']}); refusing to cosign")
        pinned = state.setdefault("logs", {}).get(client.url)
        handed = None
        if pinned and pinned != log.id:  # only a hand-over signed by the pinned key (ADR 0010)
            handed = rotation.chain(info.get("rotations") or [], pinned, log.id)
            if not handed:
                raise VerificationError(f"hub at {client.url} changed its log key "
                                        f"({pinned} -> {log.id}) without a hand-over signed "
                                        "by the old key; refusing to cosign")
        # every earlier key of this hub, kept so each project's append-only check carries
        # across the hand-over, not only the first project seen after it
        past = state.setdefault("past_logs", {}).setdefault(client.url, [])
        for st in handed or ():
            if st["old"]["id"] not in past:
                past.append(st["old"]["id"])
        state["logs"][client.url] = log.id
        head = client.sth(project)
        if head["project"] != project:
            raise VerificationError("hub returned a head for another project")
        key = f"{log.id}/{project}"
        previous = state.get(key)
        if previous is None:
            previous = next((state[f"{old}/{project}"] for old in reversed(past)
                             if f"{old}/{project}" in state), None)
        proof = []
        if previous and previous["size"] < head["size"]:
            proof = [bytes.fromhex(p) for p in client.consistency(project, previous["size"],
                                                                  head["size"])]
        check_extension(previous, head, log, proof, frozenset(past))
        try:
            self._check_across_hubs(state, client, project, head, previous)
        except VerificationError as exc:  # keep the evidence; stop cosigning this project
            state.setdefault("forks", {})[project] = {"why": str(exc), "head": head,
                                                      "url": client.url}
            self._save(state)
            raise
        c = cosign(self.key, head, int(time.time() * 1000))
        client.add_cosignature(project, head["size"], c, self.card)
        state[key] = head
        self._save(state)
        return c

    def _check_across_hubs(self, state: dict, client: HubClient, project: str, head: dict,
                           previous: dict | None) -> None:
        """Every head of the project, from any hub, must lie on one history: equal roots at
        equal sizes, and consistency proofs to the nearest smaller and larger roots seen (each
        proof fetched from the hub that signed the larger head). A disagreement names both
        hubs: the witness cannot tell which one is honest, only that they are not."""
        roots = state.setdefault("roots", {}).setdefault(project, {})
        for n, v in list(roots.items()):  # state files from before hubs were remembered
            if isinstance(v, str):
                roots[n] = {"root": v, "url": None}
        size = head["size"]

        def fork(other: dict, why: str) -> VerificationError:
            return VerificationError(f"fork of project {project[:12]}: {client.url} at size "
                                     f"{size} and {other['url'] or 'an earlier hub'} {why}; "
                                     "refusing to cosign")

        seen = roots.get(str(size))
        if seen and seen["root"] != head["root"]:
            raise fork(seen, "disagree on the root")
        smaller = [int(n) for n in roots if int(n) < size]
        if smaller and not (previous and previous["size"] == max(smaller)):
            m = max(smaller)
            proof = [bytes.fromhex(x) for x in client.consistency(project, m, size)]
            try:
                merkle.verify_consistency(m, size, bytes.fromhex(roots[str(m)]["root"]),
                                          bytes.fromhex(head["root"]), proof)
            except VerificationError as exc:
                raise fork(roots[str(m)], f"at size {m} are not one history") from exc
        larger = [int(n) for n in roots if int(n) > size]
        if larger:
            big = roots[str(min(larger))]
            source = self._clients.get(big["url"]) or (
                HubClient(big["url"]) if big["url"] else None)
            if source is None:
                raise fork(big, "cannot be compared (unknown hub)")
            proof = [bytes.fromhex(x) for x in source.consistency(project, size, min(larger))]
            try:
                merkle.verify_consistency(size, min(larger), bytes.fromhex(head["root"]),
                                          bytes.fromhex(big["root"]), proof)
            except VerificationError as exc:
                raise fork(big, f"at size {min(larger)} are not one history") from exc
        roots[str(size)] = {"root": head["root"], "url": client.url}
        for n in sorted(roots, key=int)[:-MAX_ROOTS]:  # drop the smallest: larger ones still
            del roots[n]                                # anchor every later comparison
