"""Provena Hub HTTP API v1 (ARCHITECTURE.md §6.2).

No `from __future__ import annotations` here: FastAPI must see real annotation objects, or a
`Depends(...)` on a closure silently degrades to an optional query parameter (an auth bypass).
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from provena import __version__
from provena.core.errors import ProvenaError, VerificationError
from provena.core.keys import AgentKey, verify_card
from provena.core.receipts import verify_request
from provena.core.state import ProjectState
from provena.server import web
from provena.server.hub import Conflict, Forbidden, Hub, NotFound, Unavailable
from provena.server.limits import Limits, TokenBuckets, client_key
from provena.server.storage import Storage

MAX_ENTRY_BYTES = 1 << 20
MAX_BLOB_BYTES = 1 << 30
ANCHOR_MIN_INTERVAL = 30.0
MAX_BLOB_QUERY = 1000   # cids per POST /blobs/missing
MAX_CONCURRENT_UPLOADS = 16
PAGE_SIZE = 1000


def load_or_create_hub_key(data_dir: Path, passphrase: str, name: str = "provena-hub"
                           ) -> tuple[AgentKey, dict]:
    key_path, card_path = data_dir / "hub.key.json", data_dir / "hub.card.json"
    data_dir.mkdir(parents=True, exist_ok=True)
    _finish_rotation(data_dir)
    if not key_path.exists() and hub_rotations(data_dir):
        raise VerificationError(f"{key_path} is missing but this hub has rotated its key: "
                                "restore the key file (a new key would look like a takeover)")
    if key_path.exists():
        return (AgentKey.load_encrypted(json.loads(key_path.read_text()), passphrase),
                json.loads(card_path.read_text()))
    key = AgentKey.generate()
    card = key.make_card("hub", name)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(key.export_encrypted(passphrase), f)
    card_path.write_text(json.dumps(card, indent=2))
    return key, card


def hub_rotations(data_dir: Path) -> list[dict]:
    path = data_dir / "hub.rotations.json"
    return json.loads(path.read_text()) if path.exists() else []


def rotate_hub_key(data_dir: Path, passphrase: str, name: str | None = None) -> dict:
    """Hand the hub's log key over to a new one (ADR 0010); the hub must be stopped. Returns
    the signed rotation statement. The old key file is kept as hub.key.retired-<id>.json: shred
    it once clients and witnesses have followed."""
    from provena.core import rotation

    old_key, old_card = load_or_create_hub_key(data_dir, passphrase)
    new_key = AgentKey.generate()
    new_card = new_key.make_card("hub", old_card.get("name", "") if name is None else name)
    stmt = rotation.make(old_key, old_card, new_key, new_card, int(time.time() * 1000))
    rotations = hub_rotations(data_dir) + [stmt]
    rotation.successors(rotations)  # the chain must stay linear
    # crash-safe order: (1) the new key, (2) the statement — the commit point — then (3) the
    # swap, which _finish_rotation completes on the next start if it was cut short
    _write_durably(data_dir / "hub.key.next.json",
                   json.dumps(new_key.export_encrypted(passphrase)), 0o600)
    _write_durably(data_dir / "hub.rotations.json", json.dumps(rotations, indent=2))
    _finish_rotation(data_dir)
    return stmt


def _write_durably(path: Path, text: str, mode: int = 0o644) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _finish_rotation(data_dir: Path) -> None:
    """Complete a rotation cut short after its statement was written; drop one cut short
    before (no client ever saw that key)."""
    nxt = data_dir / "hub.key.next.json"
    if not nxt.exists():
        return
    rotations = hub_rotations(data_dir)
    new_id = json.loads(nxt.read_text())["id"]
    if not rotations or rotations[-1]["new"]["id"] != new_id:
        nxt.unlink()
        return
    key_path = data_dir / "hub.key.json"
    old_id = rotations[-1]["old"]["id"]
    if key_path.exists() and json.loads(key_path.read_text())["id"] == old_id:
        key_path.replace(data_dir / f"hub.key.retired-{old_id}.json")
    nxt.replace(key_path)
    _write_durably(data_dir / "hub.card.json", json.dumps(rotations[-1]["new"], indent=2))


def create_app(data_dir: Path, key: AgentKey, card: dict, *, anchor_provider=None,
               anchor_interval: float = 0, limits: Limits | None = None,
               trust_forwarded_for: bool = False, blob_store=None,
               database: str | None = None, reanchor_days: float | None = None,
               creators_file: Path | None = None,
               projects_per_creator: int | None = None, base_path: str = "",
               policy_file: Path | None = None) -> FastAPI:
    """Build the hub app. anchor_interval > 0 runs anchoring in the background every N s."""
    hub = Hub(Storage(data_dir, blob_store, database), key, card, anchor_provider)
    hub.creators_file, hub.projects_per_creator = creators_file, projects_per_creator
    if policy_file is not None:  # orgs and quotas (ADR 0012); replaces --creators
        from provena.server.policy import Policy

        hub.policy = Policy(policy_file)
    hub.base_path = "/" + base_path.strip("/") if base_path.strip("/") else ""  # e.g. /provena
    hub.reshred()  # finish any redaction whose storage delete failed earlier
    rotations = hub_rotations(data_dir)
    if rotations and rotations[-1]["new"]["id"] != card["id"]:
        raise VerificationError("hub.rotations.json does not end at this hub's key")
    hub.resign_heads()  # a no-op unless the key was rotated since the last start
    if reanchor_days:
        hub.reanchor_after_ms = int(reanchor_days * 86_400_000)

    # anchoring health for monitoring: an idle hub has nothing new to anchor, so the age of the
    # last anchor alone raises false alarms — attempts and failures tell them apart
    anchor_stats = {"attempts": 0, "failures": 0, "last_attempt": 0.0, "last_ok": 0.0}

    def anchor_once():
        anchor_stats["attempts"] += 1
        anchor_stats["last_attempt"] = time.time()
        try:
            result = hub.run_anchor()
        except Exception:
            anchor_stats["failures"] += 1
            raise
        anchor_stats["last_ok"] = time.time()
        return result

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        task = None
        if anchor_interval > 0:
            async def loop():
                while True:
                    await asyncio.sleep(anchor_interval)
                    try:
                        await asyncio.to_thread(anchor_once)
                    except Exception as exc:  # keep serving; anchoring retries next tick
                        logging.getLogger("provena.hub").warning("anchoring failed: %s", exc)
            task = asyncio.create_task(loop())
        yield
        if task:
            task.cancel()

    app = FastAPI(title="Provena Hub", version=__version__, lifespan=lifespan)
    app.state.hub = hub
    last_anchor_request = [float("-inf")]  # monotonic() starts near 0 on a fresh boot
    upload_slots = asyncio.Semaphore(MAX_CONCURRENT_UPLOADS)
    limits = limits or Limits()
    write_buckets = TokenBuckets(limits.writes_per_minute / 60, limits.burst)
    project_buckets = TokenBuckets(limits.projects_per_hour / 3600, limits.project_burst)

    def _client(request: Request) -> str:
        if trust_forwarded_for and request.headers.get("x-forwarded-for"):
            # The rightmost entry was added by our own proxy; anything left of it is whatever
            # the client chose to send.
            return client_key(request.headers["x-forwarded-for"].split(",")[-1].strip())
        return client_key(request.client.host) if request.client else "unknown"

    @app.middleware("http")
    async def _limit_writes(request: Request, call_next):
        if request.method in ("POST", "PUT"):
            who = _client(request)
            creating = request.url.path == "/v1/projects"
            bucket = project_buckets if creating else write_buckets
            if not bucket.take(who):
                return JSONResponse({"error": "rate limit exceeded; retry later"},
                                    status_code=429, headers={"Retry-After": "10"})
            if creating and hub.project_count() >= limits.max_projects:
                return JSONResponse({"error": "this hub accepts no new projects"},
                                    status_code=503)
        return await call_next(request)

    @app.exception_handler(ProvenaError)
    async def _errors(_request: Request, exc: ProvenaError):
        status = (404 if isinstance(exc, NotFound) else 409 if isinstance(exc, Conflict)
                  else 403 if isinstance(exc, Forbidden)
                  else 503 if isinstance(exc, Unavailable) else 422)
        return JSONResponse({"error": str(exc)}, status_code=status)

    async def warm(pid: str) -> None:
        """Load a project off the event loop: a cold replay of a large log must not stall
        every other request (async routes then find it cached)."""
        await asyncio.to_thread(hub._entry, pid)

    async def reader(request: Request, pid: str) -> str | None:
        """Allow public projects; for private ones require a signed request from a member."""
        await warm(pid)
        if hub.visibility(pid) == "public":
            return None
        return await _authenticated_member(request, pid)

    async def _authenticated_member(request: Request, pid: str, extra=None) -> str:
        """Require a signed request from a member, or from one of *extra* (id -> public key)."""
        agent = request.headers.get("X-Provena-Agent")
        if not agent:
            raise HTTPException(401, "signed request required for a private project")
        state = hub._state(pid)
        if state.role_of(agent) is not None:
            pub = state.public_key(agent)
        elif extra and agent in extra:
            pub = extra[agent]
        else:
            raise HTTPException(403, "not a member of this project")
        try:
            # the client signed the path it sent; a proxy that strips --base-path removed it
            verify_request(pub, request.method, hub.base_path + request.url.path,
                           request.url.query, await request.body(),
                           int(request.headers.get("X-Provena-Time", "0")),
                           request.headers.get("X-Provena-Signature", ""),
                           int(time.time() * 1000))
        except (VerificationError, ValueError) as exc:
            raise HTTPException(401, f"bad request signature: {exc}") from exc
        return agent

    async def _json(request: Request) -> dict:
        raw = await request.body()
        if len(raw) > MAX_ENTRY_BYTES:
            raise HTTPException(413, "entry too large")
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise HTTPException(400, "invalid JSON") from exc

    @app.get("/healthz")
    def healthz():
        """Liveness + readiness for load balancers: the database answers and no project is
        quarantined silently (quarantined ones are listed, not fatal)."""
        hub.storage.catalog_count()  # the database answers
        return {"ok": True, "projects": hub.project_count(), "quarantined": len(hub.broken)}

    @app.get("/metrics")
    def metrics():
        anchors = hub.storage.anchors()
        last_anchor = anchors[-1][0]["time"] if anchors else 0
        lines = [
            "# TYPE provena_projects gauge", f"provena_projects {hub.project_count()}",
            "# TYPE provena_projects_quarantined gauge",
            f"provena_projects_quarantined {len(hub.broken)}",
            "# TYPE provena_entries gauge",
            f"provena_entries {hub.storage.entries_count()}",
            "# TYPE provena_upload_slots_free gauge",
            f"provena_upload_slots_free {upload_slots._value}",
            "# TYPE provena_anchors gauge", f"provena_anchors {len(anchors)}",
            "# TYPE provena_last_anchor_seconds gauge",
            f"provena_last_anchor_seconds {last_anchor / 1000:.3f}",
            "# TYPE provena_anchor_attempts_total counter",
            f"provena_anchor_attempts_total {anchor_stats['attempts']}",
            "# TYPE provena_anchor_failures_total counter",
            f"provena_anchor_failures_total {anchor_stats['failures']}",
            "# TYPE provena_last_anchor_attempt_seconds gauge",
            f"provena_last_anchor_attempt_seconds {anchor_stats['last_attempt']:.3f}",
            "# TYPE provena_last_anchor_success_seconds gauge",
            f"provena_last_anchor_success_seconds {anchor_stats['last_ok']:.3f}",
            "# TYPE provena_anchor_independent gauge",  # 1 = RFC 3161 TSA, 0 = self-anchoring
            f"provena_anchor_independent {int(hub.anchor_provider.name != 'self')}",
        ]
        return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    @app.get("/v1/orgs/{org}/usage")
    def org_usage(org: str, request: Request):
        """An org's projects and stored bytes against its limits, for the holder of one of its
        API keys (`Authorization: Bearer KEY`)."""
        auth = request.headers.get("authorization", "")
        if hub.policy is None or not auth.startswith("Bearer ") or \
                hub.policy.org_for_key(auth.removeprefix("Bearer ").strip()) != org:
            raise HTTPException(401, "a valid API key of this org is required")
        projects = hub.storage.org_projects(org)
        limits = hub.policy.limits(org) or {}
        return {"org": org, "projects": projects, "bytes": hub.storage.org_bytes(org),
                "limits": {k: limits.get(k) for k in ("max_projects", "max_bytes")}}

    @app.get("/v1/hub")
    def hub_info():
        return {"card": card, "version": __version__, "projects": hub.project_count(),
                "rotations": rotations}

    @app.post("/v1/projects", status_code=201)
    async def create_project(request: Request):
        body = await _json(request)
        requester = None
        if hub.policy is not None:  # who asks decides whose quota pays (ADR 0012)
            try:
                genesis = ProjectState.from_genesis(body["entry"])
            except (ProvenaError, KeyError, TypeError, ValueError) as exc:
                raise HTTPException(400, f"invalid genesis: {exc}") from exc
            requester = request.headers.get("X-Provena-Agent")
            if not requester or genesis.role_of(requester) is None:
                raise HTTPException(401, "this hub needs project creation signed by a member")
            try:
                verify_request(genesis.public_key(requester), request.method,
                               hub.base_path + request.url.path, request.url.query,
                               await request.body(),
                               int(request.headers.get("X-Provena-Time", "0")),
                               request.headers.get("X-Provena-Signature", ""),
                               int(time.time() * 1000))
            except (VerificationError, ValueError) as exc:
                raise HTTPException(401, f"bad request signature: {exc}") from exc
        return await asyncio.to_thread(hub.create_project, body["entry"], requester)

    @app.get("/v1/projects/{pid}")
    def project_info(pid: str):
        public = hub.visibility(pid) == "public"
        return {"project": pid, "visibility": hub.visibility(pid), "size": hub.size(pid),
                "head": hub.storage.head(pid),
                "meta": hub._state(pid).meta if public else None,
                "primary": hub.storage.primary(pid)}

    @app.post("/v1/projects/{pid}/primary")
    async def set_primary(pid: str, request: Request):
        """On a mirror: which hub is the project's primary, so a checkout cloned from here
        writes there instead of forking the project. Set once, by a member."""
        await warm(pid)
        who = await _authenticated_member(request, pid)
        if hub._state(pid).members[who].role not in ("owner", "maintainer"):
            raise HTTPException(403, "only owners and maintainers record the primary hub")
        body = await _json(request)
        card, url = body.get("card"), body.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise HTTPException(400, "url must be an http(s) URL")
        try:
            verify_card(card)
        except Exception as exc:
            raise HTTPException(400, f"invalid hub card: {exc}") from exc
        if card["id"] == hub.card["id"]:
            raise HTTPException(400, "this hub is not a mirror of itself")
        current = hub.storage.primary(pid)
        if current and current["card"]["id"] != card["id"]:
            from provena.core import rotation

            try:  # the primary rotated its log key: follow a hand-over signed by both keys
                followed = rotation.chain(body.get("rotations") or [], current["card"]["id"],
                                          card["id"])
            except (ProvenaError, KeyError, TypeError, ValueError):
                followed = None
            if not followed:
                raise HTTPException(409, "a different primary hub is already recorded")
        hub.storage.set_primary(pid, url, card)
        return {"primary": hub.storage.primary(pid)}

    @app.post("/v1/projects/{pid}/entries", status_code=201)
    async def submit(pid: str, request: Request):
        body = await _json(request)
        return await asyncio.to_thread(hub.submit, pid, body["entry"])

    @app.get("/v1/projects/{pid}/entries")
    async def list_entries(pid: str, start: int = 0, limit: int = PAGE_SIZE,
                           _agent: Annotated[str | None, Depends(reader)] = None):
        size = hub.size(pid)
        end = min(size, start + max(1, min(limit, PAGE_SIZE)))
        return {"entries": hub.storage.entries(pid, max(0, start), end), "size": size}

    @app.get("/v1/projects/{pid}/sth")
    def sth(pid: str, size: int | None = None):
        head = hub.storage.head(pid, size) if hub.size(pid) else None
        if head is None:
            raise HTTPException(404, "no tree head for that size")
        return head

    @app.get("/v1/projects/{pid}/checkpoint")
    def checkpoint(pid: str):
        """The latest tree head as a C2SP checkpoint (signed note), for log witnesses."""
        from provena.core import checkpoint as cp

        head = hub.storage.head(pid) if hub.size(pid) else None
        if head is None:
            raise HTTPException(404, "no tree head yet")
        return Response(cp.sign(key, pid, head), media_type="text/plain; charset=utf-8")

    @app.get("/v1/hub/vkey")
    def hub_vkey(project: str):
        """The verifier key a witness configures for one project's checkpoints."""
        from provena.core import checkpoint as cp

        return Response(cp.vkey(cp.origin(key.id, project), key.public.sign_pub) + "\n",
                        media_type="text/plain")

    @app.get("/v1/projects/{pid}/proofs/inclusion")
    def inclusion(pid: str, index: int, size: int):
        return {"index": index, "size": size, "proof": hub.inclusion(pid, index, size)}

    @app.get("/v1/projects/{pid}/proofs/consistency")
    def consistency(pid: str, first: int, second: int):
        return {"first": first, "second": second,
                "proof": hub.consistency(pid, first, second)}

    @app.post("/v1/projects/{pid}/cosignatures", status_code=201)
    async def add_cosignature(pid: str, request: Request):
        body = await _json(request)
        await warm(pid)
        hub.add_cosignature(pid, int(body["size"]), body["cosig"], body["card"])
        return {"ok": True}

    @app.get("/v1/projects/{pid}/cosignatures/latest")
    def latest_cosignatures(pid: str):
        size = hub.storage.latest_cosigned_size(pid)
        if size is None:
            return {"head": None, "cosignatures": []}
        return {"head": hub.storage.head(pid, size),
                "cosignatures": hub.cosignatures(pid, size)}

    @app.get("/v1/projects/{pid}/cosignatures")
    def cosignatures(pid: str, size: int):
        return {"size": size, "cosignatures": hub.cosignatures(pid, size)}

    @app.get("/v1/projects/{pid}/anchors")
    def project_anchors(pid: str):
        hub.visibility(pid)  # 404 for unknown projects
        return {"anchors": hub.anchors_for(pid)}

    @app.post("/v1/anchors/run")
    def run_anchor():
        now = time.monotonic()
        if now - last_anchor_request[0] < ANCHOR_MIN_INTERVAL:
            raise HTTPException(429, "anchoring was requested too recently")
        last_anchor_request[0] = now
        anchor = anchor_once()
        return {"anchored": anchor is not None, "anchor": anchor}

    @app.put("/v1/projects/{pid}/blobs/{cid}")
    async def put_blob(pid: str, cid: str, request: Request):
        await warm(pid)
        expected = hub.expect_blob(pid, cid)
        if expected is None:
            return Response(status_code=200)  # already stored; do not read the body
        if expected > MAX_BLOB_BYTES:
            raise HTTPException(413, "blob too large")
        if upload_slots.locked():
            raise HTTPException(503, "too many uploads in progress; retry later")
        async with upload_slots:
            tmp = hub.storage.upload_path(pid, cid)
            h, written = hashlib.sha256(), 0
            try:
                with open(tmp, "wb") as f:
                    async for chunk in request.stream():
                        written += len(chunk)
                        if written > expected:  # never spool more than the ledger allows
                            raise HTTPException(413, "blob is larger than the size on the ledger")
                        h.update(chunk)
                        f.write(chunk)
                created = await asyncio.to_thread(hub.commit_upload, pid, cid, tmp, written,
                                                  h.hexdigest())
            finally:
                tmp.unlink(missing_ok=True)  # every exit path, client disconnects included
        return Response(status_code=201 if created else 200)

    @app.head("/v1/projects/{pid}/blobs/{cid}")
    async def head_blob(pid: str, cid: str, request: Request):
        await warm(pid)
        # same authorization as GET: on a private project, existence of a cid is not public
        if hub.visibility(pid) != "public" and not hub.is_public_blob(pid, cid):
            await _authenticated_member(request, pid, hub.blob_grantees(pid, cid))
        return Response(status_code=200 if hub.blob_owner(pid, cid) else 404)

    @app.post("/v1/projects/{pid}/blobs/missing")
    async def missing_blobs(pid: str, request: Request):
        """Which of these cids the hub does not store (one request instead of a HEAD per
        blob when pushing). Members only on private projects, like the ledger itself."""
        await warm(pid)
        if hub.visibility(pid) != "public":
            await _authenticated_member(request, pid)
        cids = (await _json(request)).get("cids")
        if (not isinstance(cids, list) or len(cids) > MAX_BLOB_QUERY
                or not all(isinstance(c, str) for c in cids)):
            raise HTTPException(400, f"cids must be a list of at most {MAX_BLOB_QUERY} strings")
        return {"missing": await asyncio.to_thread(
            lambda: [c for c in cids if not hub.blob_owner(pid, c)])}

    @app.get("/v1/projects/{pid}/blobs/{cid}")
    async def get_blob(pid: str, cid: str, request: Request):
        await warm(pid)
        if not hub.blob_owner(pid, cid):
            raise HTTPException(404, "no such blob")
        if hub.visibility(pid) != "public" and not hub.is_public_blob(pid, cid):
            await _authenticated_member(request, pid, hub.blob_grantees(pid, cid))
        return hub.storage.blobs.response(pid, cid)

    web.install(app, hub)
    return app
