"""Export a project as an RO-Crate 1.1 package with a Provena proof bundle inside.

The crate holds the decrypted files (or only their metadata), schema.org descriptions of each
file, step (CreateAction) and agent, and `provena-proof.pvb` proving every exported file against
the ledger: a reader can check each file with `provena verify provena-proof.pvb --content`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from provena.sdk.project import Project
from provena.store.content import decrypt_verified
from provena.store.paths import UnsafePath, safe_relpath

CONTEXT = "https://w3id.org/ro/crate/1.1/context"
AGENT_TYPES = {"person": "Person", "org": "Organization", "instrument": "IndividualProduct",
               "software": "SoftwareApplication", "hub": "SoftwareApplication"}


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


RESERVED_NAMES = {"ro-crate-metadata.json", "provena-proof.pvb"}


def export_rocrate(project: Project, dest: Path, *, include_content: bool = True,
                   include_private: bool = False) -> dict:
    """*include_private* adds recorded commands and step times to the crate's actions; file
    names and contents are exported either way (that is what a crate is for)."""
    state, repo = project.repo.state, project.repo
    dest.mkdir(parents=True, exist_ok=True)
    meta = state.meta
    graph: list[dict] = [{"@id": "ro-crate-metadata.json", "@type": "CreativeWork",
                          "conformsTo": {"@id": "https://w3id.org/ro/crate/1.1"},
                          "about": {"@id": "./"}}]
    files, file_ids, actions = [], {}, []
    latest: dict[str, str] = {}
    for h in state.order:
        e = state.entries[h]
        if e["kind"] == "entity" and h not in state.redacted:
            name = project.details(h)["name"]
            latest[name] = h  # later registrations of a path supersede earlier ones
    for name, h in sorted(latest.items()):
        safe_relpath(name)  # crate ids and file paths come from the ledger: refuse unsafe ones
        if name.casefold() in RESERVED_NAMES:
            raise UnsafePath(f"entity name {name!r} collides with a crate file")
        private = project.details(h)
        body = state.entries[h]["body"]
        node = {"@id": name, "@type": "File", "name": Path(name).name,
                "contentSize": str(private["plain_size"]), "sha256": private["plain_sha256"],
                "identifier": f"urn:provena:entry:{h}",
                "author": {"@id": f"#{state.entries[h]['author']}"}}
        if private.get("media_type"):
            node["encodingFormat"] = private["media_type"]
        if include_content and repo.has_blob(body["cid"]):
            decrypt_verified(repo.blob_path(body["cid"]), repo.blob_dek(project.agent, h),
                             dest / safe_relpath(name), private["salt"],
                             private["plain_sha256"], body["commitment"])
        files.append(node)
        file_ids[h] = name
    for h in state.order:
        e = state.entries[h]
        if e["kind"] != "activity":
            continue
        private = project.details(h) or {}
        body = e["body"]
        name = " ".join(private.get("command", [])) if include_private else ""
        action = {"@id": f"#{h}", "@type": "CreateAction",
                  "name": name or f"activity {h[:12]}",
                  "identifier": f"urn:provena:entry:{h}", "agent": {"@id": f"#{e['author']}"},
                  "object": [{"@id": file_ids[u]} for u in body.get("used", []) if u in file_ids],
                  "result": [{"@id": file_ids[g]} for g in body.get("generated", [])
                             if g in file_ids]}
        if include_private and "started" in private:
            action["startTime"], action["endTime"] = (_iso(private["started"]),
                                                      _iso(private["ended"]))
        if private.get("exit_code") not in (None, 0):
            action["actionStatus"] = "http://schema.org/FailedActionStatus"
        actions.append(action)
    agents = [{"@id": f"#{agent_id}", "@type": AGENT_TYPES.get(m.card["kind"], "Thing"),
               "name": m.card.get("name") or agent_id, "identifier": agent_id}
              for agent_id, m in state.members.items()]
    root = {"@id": "./", "@type": "Dataset",
            "name": meta.get("title") or f"Provena project {state.project[:12]}",
            "identifier": f"urn:provena:project:{state.project}",
            "datePublished": _iso(state.entries[state.order[-1]]["ts"]),
            "hasPart": [{"@id": f["@id"]} for f in files] + [{"@id": "provena-proof.pvb"}],
            "mentions": [{"@id": a["@id"]} for a in actions]}
    if meta.get("description"):
        root["description"] = meta["description"]
    if meta.get("license"):
        root["license"] = meta["license"]
    if meta.get("tags"):
        root["keywords"] = meta["tags"]
    proof = {"@id": "provena-proof.pvb", "@type": "File", "name": "Provena proof bundle",
             "encodingFormat": "application/json",
             "description": "Verify with: provena verify provena-proof.pvb "
                            "--content <entry>=<file>"}
    graph += [root, *files, *actions, *agents, proof]
    crate = {"@context": CONTEXT, "@graph": graph}
    (dest / "ro-crate-metadata.json").write_text(json.dumps(crate, indent=2, ensure_ascii=False))
    if file_ids:
        project.prove(list(file_ids), dest / "provena-proof.pvb", open=list(file_ids))
    return crate
