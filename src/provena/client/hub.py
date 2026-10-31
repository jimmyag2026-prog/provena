"""HTTP client for a Provena Hub. Signs requests with the agent key when one is given."""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

from provena.core.errors import ProvenaError, VerificationError
from provena.core.keys import AgentKey
from provena.core.receipts import sign_request


class HubError(ProvenaError):
    def __init__(self, status: int, message: str, retry_after: str | None = None):
        super().__init__(f"hub returned {status}: {message}")
        self.status = status
        try:
            self.retry_after = float(retry_after) if retry_after else None
        except ValueError:
            self.retry_after = None


class HubClient:
    def __init__(self, url: str, *, agent: AgentKey | None = None,
                 http: httpx.Client | None = None):
        self.url = url.rstrip("/")
        self.agent = agent
        if http is None:
            import httpx  # optional dependency ([client]): verifying needs no network stack

            http = httpx.Client(base_url=self.url, timeout=120)
        self.http = http

    retry_wait = float(os.environ.get("PROVENA_RETRY_WAIT", 120))  # seconds of 429 backoff

    def _send(self, method: str, path: str, *, params=None, json=None, content=None,
              ok=(200, 201), sign: bool = True, stream: bool = False) -> httpx.Response:
        """One request; a 429 is retried after the hub's Retry-After (bounded in total by
        `retry_wait`), so a long push resumes by itself instead of stopping half way.
        *content* may be a callable returning a fresh body for each attempt."""
        waited = 0.0
        while True:
            try:
                return self._send_once(method, path, params=params, json=json,
                                       content=content() if callable(content) else content,
                                       ok=ok, sign=sign, stream=stream)
            except HubError as exc:
                # only throttling the hub asks us to wait out (rate limits send Retry-After)
                if exc.status != 429 or exc.retry_after is None:
                    raise
                delay = min(max(exc.retry_after, 0.1), 30.0)
                if waited + delay > self.retry_wait:
                    raise
                time.sleep(delay)
                waited += delay

    def _send_once(self, method: str, path: str, *, params=None, json=None, content=None,
                   ok=(200, 201), sign: bool = True, stream: bool = False) -> httpx.Response:
        request = self.http.build_request(method, path, params=params, json=json,
                                          content=content)
        if self.agent is not None and sign:
            request.headers.update(sign_request(
                self.agent, method, request.url.path, request.url.query.decode()
                if isinstance(request.url.query, bytes) else request.url.query,
                request.content, int(time.time() * 1000)))
        response = self.http.send(request, stream=stream)
        if response.status_code not in ok:
            response.read()
            try:
                message = response.json().get("error") or response.json().get("detail")
            except ValueError:
                message = response.text
            raise HubError(response.status_code, str(message),
                           retry_after=response.headers.get("Retry-After"))
        return response

    def info(self) -> dict:
        return self._send("GET", "/v1/hub").json()

    def project(self, pid: str) -> dict | None:
        try:
            return self._send("GET", f"/v1/projects/{pid}").json()
        except HubError as exc:
            if exc.status == 404:
                return None
            raise

    def set_primary(self, pid: str, url: str, card: dict, rotations: list | None = None
                    ) -> dict:
        return self._send("POST", f"/v1/projects/{pid}/primary",
                          json={"url": url, "card": card, "rotations": rotations or []}).json()

    def create_project(self, genesis: dict) -> dict:
        return self._send("POST", "/v1/projects", json={"entry": genesis}).json()

    def submit(self, pid: str, entry: dict) -> dict:
        return self._send("POST", f"/v1/projects/{pid}/entries", json={"entry": entry}).json()

    def entries(self, pid: str, start: int = 0) -> list[dict]:
        """All entries from *start*, following the hub's pagination."""
        out: list[dict] = []
        while True:
            page = self._send("GET", f"/v1/projects/{pid}/entries",
                              params={"start": start + len(out)}).json()
            out.extend(page["entries"])
            if not page["entries"] or start + len(out) >= page["size"]:
                return out

    def sth(self, pid: str, size: int | None = None) -> dict:
        params = {"size": size} if size is not None else None
        return self._send("GET", f"/v1/projects/{pid}/sth", params=params).json()

    def consistency(self, pid: str, first: int, second: int) -> list[str]:
        return self._send("GET", f"/v1/projects/{pid}/proofs/consistency",
                          params={"first": first, "second": second}).json()["proof"]

    def inclusion(self, pid: str, index: int, size: int) -> list[str]:
        return self._send("GET", f"/v1/projects/{pid}/proofs/inclusion",
                          params={"index": index, "size": size}).json()["proof"]

    def has_blob(self, pid: str, cid: str) -> bool:
        return self._send("HEAD", f"/v1/projects/{pid}/blobs/{cid}",
                          ok=(200, 404)).status_code == 200

    def missing_blobs(self, pid: str, cids: list[str]) -> set[str]:
        """The subset of *cids* the hub does not store, in batches of 1000."""
        missing: set[str] = set()
        for i in range(0, len(cids), 1000):
            missing.update(self._send("POST", f"/v1/projects/{pid}/blobs/missing",
                                      json={"cids": cids[i:i + 1000]}).json()["missing"])
        return missing

    def put_blob(self, pid: str, cid: str, data: bytes | Path) -> None:
        """Upload ciphertext. A Path is streamed from disk. Uploads are not signed: the hub
        accepts only bytes that hash to a cid the ledger already references (ADR 0005)."""
        if isinstance(data, Path):
            def chunks(path=data):
                with open(path, "rb") as f:
                    yield from iter(lambda: f.read(1 << 20), b"")
            content = chunks  # a fresh stream for every attempt
        else:
            content = data
        self._send("PUT", f"/v1/projects/{pid}/blobs/{cid}", content=content, sign=False)

    def get_blob(self, pid: str, cid: str) -> bytes:
        return self._send("GET", f"/v1/projects/{pid}/blobs/{cid}").content

    def download_blob(self, pid: str, cid: str, dest: Path, max_size: int | None = None) -> None:
        """Stream ciphertext to *dest*; it appears only if it hashes to *cid*. *max_size* (the
        size recorded on the ledger) bounds what a misbehaving hub can make us write."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dest.parent, suffix=".part")
        h, n = hashlib.sha256(), 0
        try:
            with os.fdopen(fd, "wb") as f:
                response = self._send("GET", f"/v1/projects/{pid}/blobs/{cid}", stream=True)
                try:
                    for chunk in response.iter_bytes(1 << 20):
                        n += len(chunk)
                        if max_size is not None and n > max_size:
                            raise VerificationError("hub sent more bytes than the ledger records")
                        h.update(chunk)
                        f.write(chunk)
                finally:
                    response.close()
            if h.hexdigest() != cid:
                raise VerificationError("downloaded blob does not hash to its cid")
            os.replace(tmp, dest)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def add_cosignature(self, pid: str, size: int, cosig: dict, card: dict) -> None:
        self._send("POST", f"/v1/projects/{pid}/cosignatures",
                   json={"size": size, "cosig": cosig, "card": card})

    def cosignatures(self, pid: str, size: int) -> list[dict]:
        return self._send("GET", f"/v1/projects/{pid}/cosignatures",
                          params={"size": size}).json()["cosignatures"]

    def latest_cosignatures(self, pid: str) -> dict:
        return self._send("GET", f"/v1/projects/{pid}/cosignatures/latest").json()

    def anchors(self, pid: str) -> list[dict]:
        return self._send("GET", f"/v1/projects/{pid}/anchors").json()["anchors"]

    def run_anchor(self) -> dict:
        return self._send("POST", "/v1/anchors/run").json()
