"""Hub ledger service: sequencing, receipts, tree heads, blob policy (transport-agnostic)."""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import OrderedDict

from provena.core import anchor as anchoring
from provena.core import entries, merkle, rfc3161
from provena.core.encoding import b64u, unb64u
from provena.core.errors import ProvenaError, VerificationError
from provena.core.keys import AgentKey, verify_card
from provena.core.receipts import make_set
from provena.core.state import ProjectState
from provena.core.treehead import make_head
from provena.core.witness import verify_cosig
from provena.server.storage import Storage


class NotFound(ProvenaError):
    pass


class Conflict(ProvenaError):
    pass


class Unavailable(ProvenaError):
    pass


class Forbidden(ProvenaError):
    pass


class SelfAnchorProvider:
    """Development provider: the hub timestamps the root itself (no independent trust)."""

    name = "self"

    def __init__(self, key: AgentKey):
        self.key = key

    def stamp(self, digest: bytes) -> dict:
        return anchoring.self_stamp(self.key, digest, int(time.time() * 1000))


class RFC3161AnchorProvider:
    """Anchors to an RFC 3161 Time-Stamp Authority. *post* sends a DER request and returns the
    DER response (injectable for tests); by default it POSTs to *url* over HTTPS."""

    name = "rfc3161"

    def __init__(self, url: str, post=None):
        self.url = url
        self._post = post or self._http_post

    def _http_post(self, request: bytes) -> bytes:
        import httpx

        r = httpx.post(self.url, content=request, timeout=60,
                       headers={"Content-Type": "application/timestamp-query"})
        r.raise_for_status()
        return r.content

    def stamp(self, digest: bytes) -> dict:
        nonce = int.from_bytes(os.urandom(8), "big")
        token = rfc3161.token_from_response(self._post(rfc3161.make_request(digest, nonce)))
        rfc3161.inspect_token(token, digest)  # never store a receipt we could not verify
        return {"token": b64u(token), "tsa": self.url}


COLD_LOAD_WAIT = 30.0  # seconds a request waits for a cold-load slot before a 503
SNAPSHOT_EVERY = 500  # entries between stored replay snapshots of a project


class Hub:
    """Sequencer and policy for many independent project logs.

    Project state is loaded on first use and kept in an LRU cache (`cache_size` projects);
    listings come from the storage catalog, so start-up does not replay every log. Cache misses
    load under the same lock as writes, so a reload can never race a write.
    """

    def __init__(self, storage: Storage, key: AgentKey, card: dict, anchor_provider=None,
                 cache_size: int = 2000, cold_loads: int = 4):
        self.storage, self.key, self.card = storage, key, card
        self.anchor_provider = anchor_provider or SelfAnchorProvider(key)
        self.reanchor_after_ms: int | None = None
        self._anchor_lock = threading.Lock()
        self._lock = threading.RLock()
        self._cache: OrderedDict[str, tuple[ProjectState, merkle.MerkleLog]] = OrderedDict()
        self.cache_size = cache_size
        self.broken: dict[str, str] = {}
        self._loading: dict[str, threading.Lock] = {}  # single-flight cold loads
        # at most this many replays of evicted projects at once: a flood of reads for cold
        # projects gets 503s instead of tying up every worker thread
        self._cold_slots = threading.BoundedSemaphore(cold_loads)
        self._anchor_cache: dict[str, list[dict]] = {}
        self._snapshot_sizes: dict[str, int] = {}  # project -> size of its stored snapshot
        self._anchor_cache_size = -1
        # project creation policy (writes need no account, so keys are free to make): an
        # allowlist file of agent ids, re-read on every creation, and a per-creator cap
        self.creators_file = None
        self.projects_per_creator: int | None = None
        self.policy = None  # provena.server.policy.Policy, when the hub runs with --policy
        self._catalog_missing_projects()

    def cosignatures(self, project: str, size: int) -> list[dict]:
        """Cosignatures at *size*; one made before a key rotation carries the head it signed
        (the hub re-signed that size since, see resign_heads)."""
        from provena.core.witness import head_id

        out = self.storage.cosignatures(project, size)
        current = self.storage.head(project, size)
        if current is None or all(c["cosig"]["head"] == head_id(current) for c in out):
            return out
        retired = {head_id(h): h for h in self.storage.retired_heads(project, size)}
        return [c if c["cosig"]["head"] == head_id(current) or c["cosig"]["head"] not in retired
                else {**c, "head": retired[c["cosig"]["head"]]} for c in out]

    def resign_heads(self) -> int:
        """After a log key rotation (ADR 0010): sign each project's latest head with the current
        key, so clients that followed the rotation can check it. Older heads stay as signed."""
        resigned = 0
        with self._lock:
            for project in self.storage.projects():
                head = self.storage.head(project)
                if head is None or head["signer"] == self.key.id:
                    continue
                log = merkle.MerkleLog([entries.entry_leaf(e)
                                        for e in self.storage.load_log(project)])
                fresh = make_head(self.key, project, log)
                if (fresh["size"], fresh["root"]) != (head["size"], head["root"]):
                    raise VerificationError(f"stored log of {project} does not match its head")
                self.storage.replace_head(project, head, fresh)
                resigned += 1
        return resigned

    def _catalog_missing_projects(self) -> None:
        """One-time migration for logs stored before the catalog existed."""
        known = {row["project"] for row in self.storage.catalog()}
        for project in self.storage.projects():
            if project in known:
                continue
            try:
                state = self._load(project)[0]
            except Exception:
                continue  # recorded in self.broken by _load
            created = self.storage.entry_by_hash(project, project)["integrated_time"]
            self.storage.catalog_upsert(project, state.policy["visibility"], state.meta, created)

    def _load(self, project: str) -> tuple[ProjectState, merkle.MerkleLog]:
        """Read and replay a log; the caller may or may not hold the hub lock. A copy that is
        already cached wins: it may have been loaded, and written to, meanwhile. A snapshot that
        a write overtook (loaded, written, evicted while we replayed) is replayed again under the
        lock instead of being inserted stale."""
        log, state, leaves = self._replay(project)
        with self._lock:
            if project not in self._cache:
                head = self.storage.head(project)
                if head and head["size"] != len(log):
                    log, state, leaves = self._replay(project)
                self._remember(project, state, merkle.MerkleLog(leaves))
            self._cache.move_to_end(project)
            return self._cache[project]

    def _replay(self, project: str) -> tuple[list[dict], ProjectState, list[bytes]]:
        """Load a project's state: from its snapshot plus the entries after it when there is
        one, else by a full replay. Every stored entry is still hashed: the hashes must match
        the stored ones and the signed head, so damaged rows are quarantined as before (the
        snapshot only skips re-checking signatures and rules of entries already sequenced)."""
        try:
            log, stored = self.storage.load_log_with_hashes(project)
            snap = self.storage.snapshot(project)
            head = self.storage.head(project)
        except Exception as exc:  # storage trouble is transient: no quarantine
            raise Unavailable(f"could not read project log: {exc}") from exc
        covered = 0
        try:
            hashes = [entries.entry_hash(e) for e in log]
            leaves = [merkle.leaf_hash(bytes.fromhex(h)) for h in hashes]
            if hashes != stored:
                raise VerificationError("stored entries do not match their recorded hashes")
            if head and head["size"] == len(log) and \
                    merkle.MerkleLog(leaves).root().hex() != head["root"]:
                raise VerificationError("stored entries do not match the signed tree head")
            state = None
            if snap is not None:
                try:
                    state = ProjectState.resume(snap, log, hashes)
                    covered = len(snap["order"])
                except Exception as exc:  # a stale or damaged cache: replay instead, and say so
                    logging.getLogger("provena.hub").warning(
                        "project %s: snapshot not used (%s); replaying the log", project, exc)
            state = state or ProjectState.replay(log)
        except Exception as exc:  # isolate: one bad log must not take down the hub
            logging.getLogger("provena.hub").error("project %s failed replay: %s", project, exc)
            self.broken[project] = str(exc)
            raise Unavailable(f"project log failed verification on load: {exc}") from exc
        self._snapshot_sizes[project] = covered  # 0 after a refused snapshot: replace it soon
        self._maybe_snapshot(project, state)
        return log, state, leaves

    def _maybe_snapshot(self, project: str, state: ProjectState) -> None:
        """Every SNAPSHOT_EVERY entries, or every tenth of the log for big ones: a snapshot
        costs O(size) to write, so the total stays O(n log n) instead of O(n²)."""
        n = len(state.order)
        if n - self._snapshot_sizes.get(project, 0) < max(SNAPSHOT_EVERY, n // 10):
            return
        try:
            self.storage.put_snapshot(project, state.snapshot())
            self._snapshot_sizes[project] = len(state.order)
        except Exception as exc:  # only a cache: the next cold load replays more
            logging.getLogger("provena.hub").warning(
                "project %s: could not store snapshot: %s", project, exc)

    def _remember(self, project: str, state: ProjectState, log: merkle.MerkleLog) -> None:
        """Insert as most recently used; evict the least recently used beyond the limit."""
        self._cache[project] = (state, log)
        self._cache.move_to_end(project)
        while len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)

    def _entry(self, project: str) -> tuple[ProjectState, merkle.MerkleLog]:
        if project in self.broken:
            raise Unavailable(f"project log failed verification on load: {self.broken[project]}")
        inline = self._lock._is_owned()  # a writer holding the hub lock loads in place
        with self._lock:
            if project in self._cache:
                self._cache.move_to_end(project)
                return self._cache[project]
            if not self.storage.catalog_has(project):
                raise NotFound("unknown project")
            if inline:
                return self._load(project)
            gate = self._loading.setdefault(project, threading.Lock())
        # Cold load: replay outside the hub lock (a large log must not stall every other
        # project), one loader per project; the others wait for it and then hit the cache.
        with gate:
            try:
                with self._lock:
                    if project in self._cache:
                        self._cache.move_to_end(project)
                        return self._cache[project]
                if not self._cold_slots.acquire(timeout=COLD_LOAD_WAIT):
                    raise Unavailable("hub busy loading projects; retry shortly")
                try:
                    return self._load(project)
                finally:
                    self._cold_slots.release()
            finally:
                with self._lock:
                    if self._loading.get(project) is gate:
                        del self._loading[project]

    def _state(self, project: str) -> ProjectState:
        return self._entry(project)[0]

    def project_count(self) -> int:
        return self.storage.catalog_count()

    # -- writes ------------------------------------------------------------------------------

    def create_project(self, genesis: dict, requester: str | None = None) -> dict:
        """*requester*: the agent that signed the request (checked by the caller). Under a
        policy it must belong to the account the project is charged to, so nobody can put a
        project (a mirror, say) on another org's quota."""
        with self._lock:
            state = ProjectState.from_genesis(genesis)
            if self.storage.catalog_has(state.project) or state.project in self.broken:
                raise Conflict("project already exists")
            creator = genesis["author"]
            account = self._admit_creator(creator)
            if self.policy is not None:
                charged = self.policy.account(requester) if requester else None
                if charged is None or charged[0] != account:
                    raise Forbidden(f"projects of {account} are created on this hub only by "
                                    f"its own agents (signed requests)")
            self._remember(state.project, state, merkle.MerkleLog())
            try:
                return self._sequence(state.project, genesis, catalog=(state, None),
                                      creator=creator, account=account)
            except BaseException:
                self._cache.pop(state.project, None)  # nothing was persisted: forget it
                raise

    def _admit_creator(self, creator: str) -> str | None:
        """Who is accountable for a new project (its org, or `agent:<id>`), under the policy
        file (ADR 0012); without one, the older --creators / --projects-per-creator rules."""
        if self.policy is not None:
            account = self.policy.account(creator)
            if account is None:
                raise Forbidden(f"this hub only accepts projects from agents its operator has "
                                f"admitted; ask them to add agent {creator} to an org")
            name, limits = account
            if limits["max_projects"] is not None and \
                    len(self.storage.org_projects(name)) >= limits["max_projects"]:
                raise Forbidden(f"{name} has reached this hub's limit of "
                                f"{limits['max_projects']} projects")
            return name
        if self.creators_file is not None:
            try:
                lines = self.creators_file.read_text().splitlines()
            except OSError as exc:  # fail closed: a missing allowlist admits nobody
                logging.getLogger("provena.hub").error("creators file unreadable: %s", exc)
                lines = []
            allowed = {line.split("#")[0].strip() for line in lines} - {""}
            if creator not in allowed:
                raise Forbidden(f"this hub only accepts projects from registered creators; "
                                f"ask the operator to add agent {creator}")
        if (self.projects_per_creator is not None
                and self.storage.creator_count(creator) >= self.projects_per_creator):
            raise Forbidden(f"agent {creator} has reached this hub's limit of "
                            f"{self.projects_per_creator} projects")
        return None

    def submit(self, project: str, entry: dict) -> dict:
        self._entry(project)  # warm the cache before taking the lock (cold loads run outside it)
        with self._lock:
            state = self._state(project)
            h = entries.entry_hash(entry) if isinstance(entry, dict) else None
            if h and h in state.entries:
                raise Conflict("entry already in log")
            state.apply(entry)
            shred = None
            if entry["kind"] == "redact":
                shred = state.entries[entry["body"]["target"]]["body"].get("cid")
            try:
                result = self._sequence(project, entry,
                                        catalog=(state, 0) if entry["kind"] == "meta" else None,
                                        shred=shred)
            except BaseException:
                self._cache.pop(project, None)  # memory must never run ahead of storage
                try:
                    self._load(project)
                except Unavailable:
                    pass  # quarantined by _load
                raise
            self._maybe_snapshot(project, state)  # after the entry is stored, never before
        if shred:
            self._shred(project, shred)  # storage I/O outside the lock
        return result

    def _sequence(self, project: str, entry: dict, *, catalog=None, shred=None,
                  creator: str | None = None, account: str | None = None) -> dict:
        """Append and sign. *catalog* = (state, created or None for now) and *shred* (a cid to
        delete) are recorded in the same transaction as the entry: a crash or database error
        can never leave a committed project out of the catalog, or a committed redaction
        without its pending deletion."""
        now = int(time.time() * 1000)
        log = self._cache[project][1]
        h = entries.entry_hash(entry)
        index = log.append(entries.entry_leaf(entry))
        receipt = make_set(self.key, project, index, h, now)
        head = make_head(self.key, project, log, now)
        extra = []
        if catalog is not None:
            state, created = catalog
            extra.append(self.storage.catalog_stmt(project, state.policy["visibility"],
                                                   state.meta, now if created is None else created))
        if shred:
            extra.append(self.storage.pending_shred_stmt(project, shred))
        if creator:
            extra.append(self.storage.creator_stmt(project, creator))
        if account:
            extra.append(self.storage.project_org_stmt(project, account))
        self.storage.append(project, index, h, entry, now, receipt, head, extra=tuple(extra))
        return {"index": index, "entry_hash": h, "receipt": receipt, "head": head}

    def _shred(self, project: str, cid: str) -> bool:
        """Delete redacted ciphertext and its plaintext cache. The pending row was committed
        with the redaction; it is cleared only on success, so a failure or a crash is retried
        at the next start. Redacted blobs are never served meanwhile (blob_owner)."""
        try:
            self.storage.delete_published(project, cid)  # verified-plaintext cache, if any
            if self.storage.has_blob(project, cid):
                self.storage.delete_blob(project, cid)
            self.storage.uncount_blob(project, cid)  # idempotent: retries never double-free
            self.storage.done_shred(project, cid)
            return True
        except Exception as exc:
            logging.getLogger("provena.hub").error("could not delete redacted blob %s/%s: %s",
                                                   project, cid, exc)
            return False

    def reshred(self) -> None:
        """Retry deletions that failed earlier (or were cut short by a crash)."""
        for project, cid in self.storage.pending_shreds():
            self._shred(project, cid)

    def expect_blob(self, project: str, cid: str) -> int | None:
        """Validate an upload before reading it. Returns the ciphertext size the ledger
        records, or None if the blob is already stored."""
        state = self._state(project)
        owner = state.cids.get(cid)
        if owner is None:
            raise NotFound("cid is not referenced by any entry of this project")
        if owner in state.redacted:
            raise VerificationError("content was redacted")
        if self.storage.has_blob(project, cid):
            return None
        size = state.entries[owner]["body"]["size"]
        self._check_quota(project, size)
        return size

    def _check_quota(self, project: str, size: int) -> None:
        """Storage quota of the project's org (ADR 0012). Concurrent uploads may overshoot it
        by the uploads in flight; projects created before the policy are not counted."""
        account = self.storage.project_org(project) if self.policy is not None else None
        if account is None:
            return
        limits = self.policy.limits(account)
        if limits is None:  # the operator removed the org (or the file is broken): no new data
            raise Forbidden(f"{account} is no longer admitted on this hub: no new uploads")
        if limits["max_bytes"] is not None and \
                self.storage.org_bytes(account) + size > limits["max_bytes"]:
            raise Forbidden(f"{account} would exceed this hub's storage quota of "
                            f"{limits['max_bytes']} bytes")

    def commit_upload(self, project: str, cid: str, tmp, size: int, sha256_hex: str) -> bool:
        """Publish a spooled upload. Validated under the sequencing lock, published outside it
        (an S3 upload can take minutes), then re-checked: a redaction sequenced meanwhile wins
        and the object is deleted again."""
        with self._lock:
            expected = self.expect_blob(project, cid)
            if expected is None:
                return False
            if size != expected:
                raise VerificationError("blob size differs from the size on the ledger")
            if sha256_hex != cid:
                raise VerificationError("blob does not hash to its cid")
        self.storage.publish_blob(project, cid, tmp)
        self.storage.count_blob(project, cid, size)  # before the redaction check: a shred
        with self._lock:                             # that raced the upload removes it again
            owner = self._state(project).cids.get(cid)
            redacted = owner in self._state(project).redacted
        if redacted and owner is not None:
            self.storage.add_pending_shred(project, cid)
            self._shred(project, cid)
            raise VerificationError("content was redacted")
        return True

    def put_blob(self, project: str, cid: str, chunks) -> bool:
        """Stream *chunks* (an iterable of bytes) to storage, checking size and hash on the
        way; nothing becomes visible unless both match the ledger."""
        expected = self.expect_blob(project, cid)
        if expected is None:
            return False
        self.storage.write_blob(project, cid, chunks, expected)
        self.storage.count_blob(project, cid, expected)
        return True

    # -- witnesses and anchors ---------------------------------------------------------------

    def add_cosignature(self, project: str, size: int, cosig: dict, card: dict) -> None:
        head = self.storage.head(project, size)
        if head is None:
            raise NotFound("no tree head of that size")
        verify_cosig(cosig, head, verify_card(card))
        self.storage.add_cosignature(project, size, cosig, card)

    def run_anchor(self) -> dict | None:
        """Anchor the latest head of every project. An unchanged root is re-stamped only after
        `reanchor_after_ms` (ADR 0008: long-lived records keep collecting fresh time-stamps
        from current TSAs/algorithms). The external stamp runs outside the sequencing lock."""
        with self._anchor_lock:
            with self._lock:
                heads = [h for row in self.storage.catalog()
                         if (h := self.storage.head(row["project"])) is not None]
            if not heads:
                return None
            root, ordered = anchoring.root_of_roots(heads)
            previous = self.storage.anchors()
            now = int(time.time() * 1000)
            if previous and previous[-1][0]["digest"] == root.hex():
                age = now - previous[-1][0]["time"]
                if self.reanchor_after_ms is None or age < self.reanchor_after_ms:
                    return None
            receipt = self.anchor_provider.stamp(root)
            anchor = {"v": 1, "provider": self.anchor_provider.name, "digest": root.hex(),
                      "size": len(ordered), "time": int(time.time() * 1000), "receipt": receipt}
            self.storage.add_anchor(anchor, ordered)
            return anchor

    def tsa_fingerprints(self, recent: int = 20) -> list[str]:
        """Certificate fingerprints of the TSAs this hub's recent anchors were stamped by."""
        fps = set()
        for anchor, _heads in self.storage.anchors()[-recent:]:
            if anchor["provider"] == "rfc3161":
                root = bytes.fromhex(anchor["digest"])
                token = unb64u(anchor["receipt"]["token"])
                fps.add(rfc3161.inspect_token(token, root).tsa_fingerprint)
        return sorted(fps)

    def anchors_for(self, project: str) -> list[dict]:
        """Anchor records covering *project*, computed once per anchoring round."""
        anchors = self.storage.anchors()
        if self._anchor_cache_size != len(anchors):
            self._anchor_cache, self._anchor_cache_size = {}, len(anchors)
        if project not in self._anchor_cache:
            self._anchor_cache[project] = self._compute_anchors_for(project, anchors)
        return self._anchor_cache[project]

    def _compute_anchors_for(self, project: str, anchors) -> list[dict]:
        records = []
        for anchor, heads in anchors:
            leaves = [anchoring.anchor_leaf(h) for h in heads]
            for i, h in enumerate(heads):
                if h["project"] == project:
                    records.append({"anchor": anchor, "head": h, "index": i,
                                    "proof": [p.hex() for p in merkle.inclusion_proof(leaves, i)]})
        return records

    # -- reads -------------------------------------------------------------------------------

    def visibility(self, project: str) -> str:
        return self._state(project).policy["visibility"]

    def blob_owner(self, project: str, cid: str) -> str | None:
        """The entry owning *cid* in *project*, if its ciphertext is stored here and it was not
        redacted (a failed storage delete must never make redacted content readable)."""
        state = self._state(project)
        owner = state.cids.get(cid)
        if owner is None or owner in state.redacted or not self.storage.has_blob(project, cid):
            return None
        return owner

    def is_public_blob(self, project: str, cid: str) -> bool:
        owner = self._state(project).cids.get(cid)
        reveal = self._state(project).reveals.get(owner) if owner else None
        return bool(reveal and reveal.get("dek"))

    def blob_grantees(self, project: str, cid: str) -> dict:
        owner = self._state(project).cids.get(cid)
        return self._state(project).grants.get(owner, {}) if owner else {}

    def size(self, project: str) -> int:
        return len(self._entry(project)[1])

    def inclusion(self, project: str, index: int, size: int) -> list[str]:
        log = self._entry(project)[1]
        if not 0 <= index < size <= len(log):
            raise NotFound("index/size out of range")
        return [p.hex() for p in log.inclusion_proof(index, size)]

    def consistency(self, project: str, first: int, second: int) -> list[str]:
        log = self._entry(project)[1]
        if not 0 < first <= second <= len(log):
            raise NotFound("sizes out of range")
        return [p.hex() for p in log.consistency_proof(first, second)]
