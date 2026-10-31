"""`provena ui`: a local, read-only browser view of a repository.

Runs on 127.0.0.1 only, decrypts with the key already unlocked in this process, and never sends
keys or plaintext anywhere. A random token (in the printed URL, then a cookie) and a strict Host
check keep other local web pages and DNS-rebinding sites out.
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from html import escape
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from provena import __version__
from provena.core import aead, builders
from provena.core.keys import AgentKey
from provena.server.graph import lineage_svg
from provena.server.web import CSP, STATIC
from provena.store.repo import Repo
from provena.store.verify import verify_repo

TEXT_PREVIEW = 64 * 1024


def _when(ms) -> str:
    try:
        return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError, TypeError):
        return "(invalid time)"


def _content_disposition(name: str) -> str:
    """RFC 6266/5987: an ASCII fallback with nothing that can break the header, plus the real
    (UTF-8, percent-encoded) name."""
    fallback = "".join(c for c in name if 0x20 <= ord(c) < 0x7F and c not in '"\\;') or "download"
    return f'attachment; filename="{fallback}"; filename*=UTF-8\'\'{quote(name, safe="")}'


def create_ui(repo: Repo, agent: AgentKey, port: int, token: str | None = None, *,
              allow_test_host: bool = False) -> FastAPI:
    token = token or secrets.token_urlsafe(24)
    app = FastAPI(title="Provena (local)", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.token = token
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"} | (
        {"testserver"} if allow_test_host else set())
    cookie = f"provena_ui_{port}"  # cookies are not port-scoped: one name per UI instance
    css = (STATIC / "style.css").read_text()

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host") not in allowed_hosts:
            return Response("bad host", status_code=421)
        from_url = request.query_params.get("t")
        given = from_url or request.cookies.get(cookie)
        if not secrets.compare_digest(given or "", token):
            return Response("missing or wrong token: open the URL printed by `provena ui`",
                            status_code=401)
        if from_url:  # move the token into a cookie and out of the address bar / history
            response = RedirectResponse(request.url.path, status_code=303)
        else:
            response = await call_next(request)
        response.set_cookie(cookie, token, httponly=True, samesite="strict")
        response.headers["Content-Security-Policy"] = CSP.replace("script-src 'self'",
                                                                  "script-src 'none'")
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def private(h: str) -> dict:
        try:
            return builders.open_entry_fields(repo.state, agent, repo.state.entries[h]) or {}
        except Exception:
            return {"_sealed": True}

    def label(h: str) -> str:
        e, p = repo.state.entries[h], private(h)
        if e["kind"] == "activity":
            if not p.get("command"):
                return "activity"
            # `provena run` records a shell command and its cwd; SDK/Jupyter steps a description
            return ("$ " if "cwd" in p else "") + " ".join(p["command"])
        return p.get("name") or p.get("title") or ""

    def page(title: str, body: str) -> HTMLResponse:
        meta = repo.state.meta
        name = escape(meta.get("title") or private(repo.state.order[0]).get("name")
                      or repo.state.project[:12])
        return HTMLResponse(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)}</title>
<style>{css}</style></head><body><main>
<header class="top"><a class="brand" href="/">{name}</a>
<span class="muted mono">local · read-only · {escape(agent.id)} · v{__version__}</span></header>
{body}</main></body></html>""")

    def entry_link(h: str) -> str:
        return f"<a class='mono' href='/e/{h}'>{h[:12]}</a>"

    @app.get("/", response_class=HTMLResponse)
    def home():
        st = repo.state
        rows = []
        for i, h in enumerate(st.order):
            e = st.entries[h]
            flags = " ".join(f"<span class='pill'>{f}</span>" for f, on in (
                ("revealed", h in st.reveals), ("redacted", h in st.redacted),
                (f"{len(st.attestations.get(h, []))} attest", st.attestations.get(h))) if on)
            rows.append(f"<tr><td>{i}</td><td>{entry_link(h)}</td><td>{escape(e['kind'])}</td>"
                        f"<td>{escape(label(h))}</td><td class='mono'>{escape(e['author'][:14])}"
                        f"</td><td>{_when(e['ts'])}</td><td>{flags}</td></tr>")
        hub = repo.config.get("hub")
        heads = [x["head"] for x in repo.heads()]
        latest = max(heads, key=lambda x: x["size"]) if heads else None
        members = "".join(
            f"<tr><td class='mono'>{escape(i)}</td><td>{escape(m.card.get('name') or '')}</td>"
            f"<td>{escape(m.card['kind'])}</td><td>{escape(m.role)}</td>"
            f"<td>{'active' if m.active else 'removed'}</td></tr>"
            for i, m in st.members.items())
        svg = lineage_svg(st, {h: label(h).removeprefix("$ ") for h in st.order
                               if st.entries[h]["kind"] in ("entity", "plan", "activity")},
                          link_external=False)  # other projects live on a hub, not here
        body = f"""
<h1>{escape(st.meta.get('title') or 'Project ledger')}</h1>
<div class="card"><dl class="kv">
<dt>Project</dt><dd class="mono">{st.project}</dd>
<dt>Entries</dt><dd>{len(st.order)} · key epoch {st.epoch}</dd>
<dt>Hub</dt><dd>{escape(hub or 'none (local only)')} · synced {repo.config.get('synced', 0)}</dd>
<dt>Latest head</dt><dd>{f"size {latest['size']} signed by {escape(latest['signer'][:16])}… at "
                         f"{_when(latest['time'])}" if latest else 'no checkpoint yet'}</dd>
</dl></div>
<p><a href="/verify">Verify this repository now</a></p>
{f"<h2>Provenance</h2><div class='card graph-wrap'>{svg}</div>" if svg else ""}
<h2>Ledger</h2><div class="table-wrap"><table><tr><th>#</th><th>Entry</th><th>Kind</th>
<th>Name / command</th><th>Author</th><th>Client time</th><th></th></tr>{''.join(rows)}
</table></div>
<h2>Members</h2><div class="table-wrap"><table><tr><th>Agent</th><th>Name</th><th>Kind</th>
<th>Role</th><th>Status</th></tr>{members}</table></div>"""
        return page("Provena", body)

    @app.get("/e/{h}", response_class=HTMLResponse)
    def entry(h: str):
        st = repo.state
        if h not in st.entries:
            raise HTTPException(404, "no such entry")
        e = st.entries[h]
        p = private(h)
        refs = " ".join(entry_link(r) for r in e["refs"]) or "—"
        att = " ".join(entry_link(a) for a in st.attestations.get(h, [])) or "—"
        content = ""
        cid = e["body"].get("cid") if e["kind"] in ("entity", "plan") else None
        if cid and repo.has_blob(cid) and h not in st.redacted:
            content = f"<p><a href='/raw/{h}'>Download decrypted content</a></p>"
            if p.get("plain_size", TEXT_PREVIEW + 1) <= TEXT_PREVIEW:
                data = _plaintext(h)
                try:
                    content += f"<pre class='card code'>{escape(data.decode())}</pre>"
                except UnicodeDecodeError:
                    content += "<p class='muted'>(binary content)</p>"
        status = ", ".join(f for f, on in (("revealed", h in st.reveals),
                                           ("redacted", h in st.redacted)) if on) or "sealed"
        public_json = escape(json.dumps(e["body"], indent=2))
        sealed_json = escape(json.dumps(p, indent=2, ensure_ascii=False))
        body = f"""
<h1>{escape(e['kind'])} <span class="mono">{h[:16]}</span></h1>
<div class="card"><dl class="kv">
<dt>Position</dt><dd>#{st.order.index(h)}</dd>
<dt>Author</dt><dd class="mono">{escape(e['author'])}</dd>
<dt>Client time</dt><dd>{_when(e['ts'])}</dd>
<dt>References</dt><dd>{refs}</dd>
<dt>Attestations</dt><dd>{att}</dd>
<dt>Status</dt><dd>{status}</dd>
</dl></div>
<h2>Public body</h2><pre class="card code">{public_json}</pre>
<h2>Sealed fields (decrypted locally)</h2><pre class="card code">{sealed_json}</pre>
{content}"""
        return page(f"{h[:12]} · Provena", body)

    def _plaintext(h: str) -> bytes:
        cid = repo.state.entries[h]["body"]["cid"]
        return aead.decrypt_bytes(repo.blob_dek(agent, h), repo.blob_path(cid).read_bytes())

    @app.get("/raw/{h}")
    def raw(h: str):
        st = repo.state
        e = st.entries.get(h)
        if not e or e["kind"] not in ("entity", "plan") or h in st.redacted:
            raise HTTPException(404, "no content")
        name = (private(h).get("name") or h[:12]).split("/")[-1]
        return Response(_plaintext(h), media_type="application/octet-stream",
                        headers={"Content-Disposition": _content_disposition(name)})

    @app.get("/verify", response_class=HTMLResponse)
    def verify():
        report = verify_repo(repo, agent)
        items = "".join(f"<li class='err'>{escape(x)}</li>" for x in report.problems)
        body = f"""<h1>Repository verification</h1>
<div class="card result {'ok' if report.ok else 'bad'}"><div class="verdict">
{'OK' if report.ok else 'FAILED'}</div><ul>
<li class='fact'>{report.entries} entries replayed (signatures, chains, permissions)</li>
<li class='fact'>{report.blobs_checked} ciphertexts match their cid</li>
<li class='fact'>{report.contents_checked} plaintexts match their commitments</li>
{f"<li class='note'>{len(report.missing_blobs)} ciphertexts not stored locally</li>"
 if report.missing_blobs else ""}{items}</ul></div><p><a href="/">Back</a></p>"""
        return page("Verify · Provena", body)

    return app
