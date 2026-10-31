"""Export a ledger as W3C PROV-JSON (ADR 0003).

Public structure (entities, activities, agents and their relations) is always exported. Names,
commands and times come from sealed fields and appear only when the caller passes them in
*private* (i.e. a member decrypted them and chose to include them).
"""

from __future__ import annotations

from datetime import UTC, datetime

from provena.core.state import ProjectState

NS = {"pv": "https://provena.dev/ns#", "pve": "urn:provena:entry:",
      "pva": "urn:provena:agent:", "xsd": "http://www.w3.org/2001/XMLSchema#"}


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def to_prov(state: ProjectState, private: dict[str, dict] | None = None) -> dict:
    private = private or {}
    doc: dict = {"prefix": dict(NS), "entity": {}, "activity": {}, "agent": {},
                 "wasGeneratedBy": {}, "used": {}, "wasAssociatedWith": {},
                 "wasAttributedTo": {}}
    for agent_id, member in state.members.items():
        doc["agent"][f"pva:{agent_id}"] = {
            "prov:type": f"pv:{member.card['kind']}", "pv:role": member.role,
            **({"prov:label": member.card["name"]} if member.card.get("name") else {})}
    n = 0

    def rel(kind: str, value: dict) -> None:
        nonlocal n
        n += 1
        doc[kind][f"_:r{n}"] = value

    for h in state.order:
        e = state.entries[h]
        ident, body, extra = f"pve:{h}", e["body"], private.get(h) or {}
        if e["kind"] in ("entity", "plan"):
            doc["entity"][ident] = {
                "prov:type": "prov:Plan" if e["kind"] == "plan" else "pv:Data",
                "pv:commitment": body["commitment"],
                **({"pv:cid": body["cid"]} if body.get("cid") else {}),
                **({"prov:label": extra.get("name") or extra.get("title")}
                   if extra.get("name") or extra.get("title") else {}),
                "pv:revealed": h in state.reveals, "pv:redacted": h in state.redacted}
            rel("wasAttributedTo", {"prov:entity": ident, "prov:agent": f"pva:{e['author']}"})
        elif e["kind"] == "activity":
            act = {"prov:type": "pv:Activity"}
            if "started" in extra:
                act["prov:startTime"] = _iso(extra["started"])
                act["prov:endTime"] = _iso(extra["ended"])
            if "command" in extra:
                act["pv:command"] = " ".join(extra["command"])
                act["pv:exitCode"] = extra.get("exit_code")
            doc["activity"][ident] = act
            assoc = {"prov:activity": ident, "prov:agent": f"pva:{e['author']}"}
            if body.get("plan"):
                assoc["prov:plan"] = f"pve:{body['plan']}"
            rel("wasAssociatedWith", assoc)
            for u in body.get("used", []):
                rel("used", {"prov:activity": ident, "prov:entity": f"pve:{u}"})
            for g in body.get("generated", []):
                rel("wasGeneratedBy", {"prov:entity": f"pve:{g}", "prov:activity": ident})
    return {k: v for k, v in doc.items() if v}
