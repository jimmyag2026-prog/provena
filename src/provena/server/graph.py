"""Server-side SVG of a project's provenance DAG (public projects only).

Layered layout: each node's column is its longest-path depth from a source; rows follow log
order. Plain SVG with theme-aware classes, no client-side code.
"""

from __future__ import annotations

import re
from html import escape

from provena.core.state import ProjectState

COL_W, ROW_H, NODE_W, NODE_H, PAD = 180, 46, 150, 30, 16
MAX_NODES = 200
KIND_CLASS = {"entity": "g-entity", "plan": "g-plan", "activity": "g-activity",
              "external": "g-external"}
HEX64 = re.compile(r"[0-9a-f]{64}")


def lineage_svg(state: ProjectState, labels: dict[str, str] | None = None, *,
                link_external: bool = True) -> str | None:
    """*labels* (entry hash -> text) lets a local, decrypting caller show names; the public
    hub never passes it. Inputs from other projects (`activity.external`) are drawn as their
    own nodes, linked to that entry's hub page when *link_external*."""
    nodes = [h for h in state.order if state.entries[h]["kind"] in KIND_CLASS][-MAX_NODES:]
    if not nodes:
        return None
    present = set(nodes)
    edges: list[tuple[str, str]] = []
    external: dict[str, tuple[str, str]] = {}  # node id -> (project, entry)
    for h in list(nodes):
        e = state.entries[h]
        if e["kind"] != "activity":
            continue
        body = e["body"]
        sources = list(body.get("used", [])) + ([body["plan"]] if body.get("plan") else [])
        edges += [(s, h) for s in sources if s in present]
        for x in body.get("external", []):
            if not (HEX64.fullmatch(x["project"]) and HEX64.fullmatch(x["entry"])):
                continue
            node = f"ext:{x['project']}:{x['entry']}"
            if node not in external and len(nodes) < MAX_NODES + 50:
                external[node] = (x["project"], x["entry"])
                nodes.insert(0, node)
            if node in external:
                edges.append((node, h))
        edges += [(h, g) for g in body.get("generated", []) if g in present]
    edges = list(dict.fromkeys(edges))  # repeated citations draw one edge
    # Longest-path layering by relaxation. Log order is not topological here: outputs are
    # registered before the activity that claims them. The graph is a DAG (the state machine
    # only lets an activity reference earlier entries, and each entity has one generator).
    depth = {h: 0 for h in nodes}
    for _ in range(len(nodes)):
        changed = False
        for a, b in edges:
            if depth[b] < depth[a] + 1:
                depth[b], changed = depth[a] + 1, True
        if not changed:
            break
    rows: dict[int, int] = {}
    pos = {}
    for h in nodes:
        col = depth[h]
        pos[h] = (PAD + col * COL_W, PAD + rows.get(col, 0) * ROW_H)
        rows[col] = rows.get(col, 0) + 1
    width = PAD * 2 + (max(depth.values()) * COL_W) + NODE_W
    height = PAD * 2 + max(rows.values()) * ROW_H
    parts = [f'<svg class="lineage" viewBox="0 0 {width} {height}" width="{width}" '
             f'height="{height}" role="img" aria-label="Provenance graph">']
    for a, b in edges:
        (x1, y1), (x2, y2) = pos[a], pos[b]
        sx, sy, tx, ty = x1 + NODE_W, y1 + NODE_H / 2, x2, y2 + NODE_H / 2
        mid = (sx + tx) / 2
        parts.append(f'<path class="g-edge" d="M{sx},{sy} C{mid},{sy} {mid},{ty} {tx},{ty}"/>')
    for h in nodes:
        x, y = pos[h]
        if h in external:
            project, entry = external[h]
            box = (f'<g class="g-external"><title>entry {entry} of project {project}</title>'
                   f'<rect x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" rx="6"/>'
                   f'<text x="{x + NODE_W / 2}" y="{y + NODE_H / 2 + 4}">↗ {project[:6]}:'
                   f'{entry[:8]}</text></g>')
            parts.append(f'<a href="/p/{project}/e/{entry}">{box}</a>' if link_external
                         else box)
            continue
        kind = state.entries[h]["kind"]
        marks = ("✓ " if h in state.reveals else "") + ("✗ " if h in state.redacted else "")
        text = (labels or {}).get(h) or f"{kind} {h[:8]}"
        label = marks + (text if len(text) <= 22 else text[:21] + "…")
        parts.append(
            f'<g class="{KIND_CLASS[kind]}"><title>{escape(kind)} {h}</title>'
            f'<rect x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" rx="'
            f'{NODE_H // 2 if kind == "activity" else 6}"/>'
            f'<text x="{x + NODE_W / 2}" y="{y + NODE_H / 2 + 4}">{escape(label)}</text></g>')
    parts.append("</svg>")
    return "".join(parts)
