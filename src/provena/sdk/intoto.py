"""Export a recorded step as an in-toto Statement in a DSSE envelope (ADR 0011: interop).

Supply-chain tools (Sigstore, SLSA verifiers, `in-toto` libraries) read DSSE envelopes; the
statement names the step's outputs by sha256 and points back at the ledger, where the full
proof lives. Exporting discloses the output names and content hashes: it is a publication.
"""

from __future__ import annotations

import base64
import json

from provena.core import builders
from provena.core.keys import AgentKey, AgentPublic, verify_dsse

STATEMENT = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_RUN = "https://github.com/jimmyag2026-prog/provena/blob/main/docs/spec/predicate-run-v1.md"


def run_statement(project, activity: str) -> dict:
    """in-toto Statement for *activity* (a `provena.sdk.Project`'s step)."""
    repo, agent = project.repo, project.agent
    state = repo.state
    e = state.entries[activity]
    if e["kind"] != "activity":
        raise ValueError(f"{activity[:12]} is a {e['kind']}, not a step")
    if e["author"] != agent.id:
        # the envelope is signed by the step's author (predicate spec); others prove it instead
        raise ValueError(f"step {activity[:12]} was recorded by {e['author']}: only its author "
                         f"exports it as a signed statement (`provena prove` works for anyone)")

    def digest(h: str) -> dict:
        try:
            private = builders.open_entry_fields(state, agent, state.entries[h]) or {}
        except Exception as exc:  # noqa: BLE001 — sealed for an epoch this key cannot read
            raise ValueError(f"cannot read {h[:12]} with this key: {exc}") from None
        return {"name": private.get("name") or h, "digest": {"sha256": private["plain_sha256"]},
                "annotations": {"provena_entry": h}}

    body = e["body"]
    reveal = state.reveals.get(activity) or {}
    head = repo.heads()[-1]["head"] if repo.heads() else None
    return {
        "_type": STATEMENT,
        "subject": [digest(g) for g in body.get("generated", [])],
        "predicateType": PREDICATE_RUN,
        "predicate": {
            "ledger": {"project": state.project, "entry": activity,
                       "index": state.position[activity], "rules": state.rules,
                       "head": head},
            "author": e["author"], "status": body.get("status"),
            "plan": body.get("plan"),
            "used": [digest(u) for u in body.get("used", [])],
            "external": body.get("external", []),
            # details only once they are public on the ledger (`provena reveal <step>`)
            "details": reveal.get("details"),
        },
    }


def envelope(agent: AgentKey, statement: dict) -> dict:
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    return {"payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": agent.id,
                            "sig": base64.b64encode(agent.sign_dsse(PAYLOAD_TYPE,
                                                                    payload)).decode()}]}


def open_envelope(env: dict, pub: AgentPublic) -> dict:
    """Check the envelope signature by *pub* and return the statement."""
    payload = base64.b64decode(env["payload"])
    sigs = [s for s in env.get("signatures", []) if s.get("keyid") == pub.id]
    if not sigs:
        raise ValueError(f"no signature by {pub.id}")
    verify_dsse(pub, env["payloadType"], payload, base64.b64decode(sigs[0]["sig"]))
    return json.loads(payload)
