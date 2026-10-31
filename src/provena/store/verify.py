"""Verification of a local repository against its own log and blob store."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from provena.core import aead, builders, commitment
from provena.core.errors import ProvenaError
from provena.core.keys import AgentKey
from provena.core.state import ProjectState
from provena.store.repo import Repo


@dataclass
class Report:
    entries: int = 0
    blobs_checked: int = 0
    contents_checked: int = 0
    missing_blobs: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


class _HashSink:
    def __init__(self):
        self.h = hashlib.sha256()

    def write(self, b: bytes) -> int:
        self.h.update(b)
        return len(b)


def verify_repo(repo: Repo, agent: AgentKey | None = None) -> Report:
    """Replay the log, check every blob against its cid and, given a member key, every
    decrypted plaintext against its sealed hash and commitment."""
    report = Report()
    try:
        state = ProjectState.replay(repo.log())
    except ProvenaError as exc:
        report.problems.append(f"log replay failed: {exc}")
        return report
    report.entries = len(state.order)
    for h in state.order:
        entry = state.entries[h]
        cid = entry["body"].get("cid") if entry["kind"] in ("entity", "plan") else None
        if not cid or h in state.redacted:
            continue
        if not repo.has_blob(cid):
            report.missing_blobs.append(h)
            continue
        data = repo.blob_path(cid).read_bytes()
        report.blobs_checked += 1
        if hashlib.sha256(data).hexdigest() != cid:
            report.problems.append(f"{h[:12]}: blob does not match cid")
            continue
        if agent is None or state.role_of(agent.id) is None:
            continue
        try:
            private = builders.open_entry_fields(state, agent, entry)
            dek = repo.blob_dek(agent, h)
            sink = _HashSink()
            with open(repo.blob_path(cid), "rb") as src:
                aead.decrypt_stream(dek, src, sink)
            plain = sink.h.digest()
            if plain.hex() != private["plain_sha256"]:
                raise ProvenaError("plaintext hash differs from sealed record")
            commitment.verify_opening(bytes.fromhex(entry["body"]["commitment"]),
                                      bytes.fromhex(private["salt"]), plain)
            report.contents_checked += 1
        except ProvenaError as exc:
            report.problems.append(f"{h[:12]}: {exc}")
    return report
