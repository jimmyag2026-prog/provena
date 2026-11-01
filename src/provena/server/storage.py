"""Hub persistence: SQLite or PostgreSQL for log metadata, a BlobStore (filesystem or S3) for
ciphertext."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from pathlib import Path

from provena.server.blobstore import BlobStore, FsBlobStore


class BlobRejected(ValueError):
    pass


_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")  # \Z: "$" would accept a trailing newline

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    project TEXT NOT NULL,
    idx BIGINT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    entry TEXT NOT NULL,
    integrated_time BIGINT NOT NULL,
    receipt TEXT NOT NULL,
    PRIMARY KEY (project, idx)
);
CREATE TABLE IF NOT EXISTS cosignatures (
    project TEXT NOT NULL,
    size BIGINT NOT NULL,
    witness TEXT NOT NULL,
    cosig TEXT NOT NULL,
    card TEXT NOT NULL,
    PRIMARY KEY (project, size, witness)
);
CREATE TABLE IF NOT EXISTS anchors (
    id {serial},
    anchor TEXT NOT NULL,
    heads TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS catalog (
    project TEXT PRIMARY KEY,
    visibility TEXT NOT NULL,
    meta TEXT NOT NULL,
    created BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_shreds (
    project TEXT NOT NULL,
    cid TEXT NOT NULL,
    PRIMARY KEY (project, cid)
);
CREATE TABLE IF NOT EXISTS heads (
    project TEXT NOT NULL,
    size BIGINT NOT NULL,
    head TEXT NOT NULL,
    PRIMARY KEY (project, size)
);
CREATE TABLE IF NOT EXISTS creators (
    project TEXT PRIMARY KEY,
    creator TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS creators_by_creator ON creators (creator);
CREATE TABLE IF NOT EXISTS retired_heads (
    project TEXT NOT NULL,
    size BIGINT NOT NULL,
    head TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
    project TEXT PRIMARY KEY,
    size BIGINT NOT NULL,
    state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS primaries (
    project TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    card TEXT NOT NULL
);
"""


class _Sql:
    """The one place that differs between SQLite and PostgreSQL: connection, placeholder,
    serial column and transactions. Every query below is written once, in portable SQL."""

    def __init__(self, dsn_or_path):
        self.lock = threading.Lock()
        if isinstance(dsn_or_path, str) and dsn_or_path.startswith("postgres"):
            import psycopg  # optional dependency: pip install "provena-ledger[postgres]"

            try:
                self.conn = psycopg.connect(dsn_or_path, autocommit=True)
            except Exception as exc:  # driver messages can quote DSN fragments (passwords)
                kind = type(exc).__name__
                raise RuntimeError("could not connect to the PostgreSQL database in "
                                   "PROVENA_HUB_DATABASE_URL (details withheld: the DSN may "
                                   f"contain a password; error type {kind})") from None
            self.mark, self.kind = "%s", "postgres"
            with self.conn.transaction():
                for stmt in SCHEMA.format(serial="BIGSERIAL PRIMARY KEY").split(";"):
                    if stmt.strip():
                        self.conn.execute(stmt)
        else:
            self.conn = sqlite3.connect(dsn_or_path, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=FULL")  # sequenced entries survive a crash
            self.mark, self.kind = "?", "sqlite"
            self.conn.executescript(SCHEMA.format(serial="INTEGER PRIMARY KEY AUTOINCREMENT"))

    def rows(self, sql: str, params=()) -> list[tuple]:
        with self.lock:
            return list(self.conn.execute(sql.replace("?", self.mark), params).fetchall())

    def migrate(self, statements: list[str], version: int) -> None:
        """One schema step and its version bump, all or nothing (SQLite's Python driver does
        not open a transaction before DDL on its own, so it is opened explicitly)."""
        bump = ("INSERT INTO meta VALUES ('schema_version', ?) ON CONFLICT (key) "
                "DO UPDATE SET value = excluded.value")
        with self.lock:
            if self.kind == "postgres":
                with self.conn.transaction():
                    for sql in statements:
                        self.conn.execute(sql)
                    self.conn.execute(bump.replace("?", self.mark), (str(version),))
                return
            level, self.conn.isolation_level = self.conn.isolation_level, None
            try:
                self.conn.execute("BEGIN")
                try:
                    for sql in statements:
                        self.conn.execute(sql)
                    self.conn.execute(bump, (str(version),))
                    self.conn.execute("COMMIT")
                except BaseException:
                    self.conn.execute("ROLLBACK")
                    raise
            finally:
                self.conn.isolation_level = level

    def write(self, *statements: tuple[str, tuple]) -> None:
        """Run statements atomically."""
        with self.lock:
            if self.kind == "postgres":
                with self.conn.transaction():
                    for sql, params in statements:
                        self.conn.execute(sql.replace("?", self.mark), params)
            else:
                with self.conn:
                    for sql, params in statements:
                        self.conn.execute(sql, params)


# Schema changes after the base schema (version 1), applied in order at start, each in one
# transaction with its version bump. Never edit a released step: add the next one.
SCHEMA_VERSION = 2
MIGRATIONS: dict[int, list[str]] = {
    2: [  # hub orgs and quotas (ADR 0012)
        "CREATE TABLE IF NOT EXISTS project_orgs (project TEXT PRIMARY KEY, org TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS project_orgs_by_org ON project_orgs (org)",
        "CREATE TABLE IF NOT EXISTS blob_usage (project TEXT NOT NULL, cid TEXT NOT NULL, "
        "bytes BIGINT NOT NULL, PRIMARY KEY (project, cid))",
    ],
}


class SchemaTooNew(RuntimeError):
    pass


class Storage:
    def __init__(self, data_dir: Path, blobs: BlobStore | None = None,
                 database: str | None = None):
        """*database*: a `postgresql://…` DSN, or None for `<data_dir>/hub.sqlite3`."""
        self.data_dir = data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        self.blobs = blobs or FsBlobStore(data_dir / "blobs")
        self.sweep_partials()
        self._sql = _Sql(database or str(data_dir / "hub.sqlite3"))
        self._migrate()

    def schema_version(self) -> int:
        rows = self._sql.rows("SELECT value FROM meta WHERE key = 'schema_version'")
        return int(rows[0][0]) if rows else 1

    def _migrate(self) -> None:
        current = self.schema_version()
        if current > SCHEMA_VERSION:
            raise SchemaTooNew(f"this hub's database has schema version {current}, newer than "
                               f"this Provena ({SCHEMA_VERSION}): upgrade Provena, never "
                               "downgrade a hub")
        for v in range(current + 1, SCHEMA_VERSION + 1):
            self._sql.migrate(MIGRATIONS[v], v)

    # -- orgs and usage (ADR 0012) ------------------------------------------------------------

    @staticmethod
    def project_org_stmt(project: str, org: str) -> tuple:
        return ("INSERT INTO project_orgs VALUES (?, ?)", (project, org))

    def project_org(self, project: str) -> str | None:
        rows = self._sql.rows("SELECT org FROM project_orgs WHERE project = ?", (project,))
        return rows[0][0] if rows else None

    def org_projects(self, org: str) -> list[str]:
        return [r[0] for r in self._sql.rows(
            "SELECT project FROM project_orgs WHERE org = ? ORDER BY project", (org,))]

    def org_bytes(self, org: str) -> int:
        return int(self._sql.rows("SELECT COALESCE(SUM(u.bytes), 0) FROM blob_usage u "
                                  "JOIN project_orgs o ON u.project = o.project WHERE o.org = ?",
                                  (org,))[0][0])

    def count_blob(self, project: str, cid: str, size: int) -> None:
        """One row per stored ciphertext: repeated or concurrent uploads count it once."""
        self._sql.write(("INSERT INTO blob_usage VALUES (?, ?, ?) ON CONFLICT (project, cid) "
                         "DO NOTHING", (project, cid, size)))

    def uncount_blob(self, project: str, cid: str) -> None:
        self._sql.write(("DELETE FROM blob_usage WHERE project = ? AND cid = ?", (project, cid)))

    def usage_bytes(self, project: str) -> int:
        return int(self._sql.rows("SELECT COALESCE(SUM(bytes), 0) FROM blob_usage WHERE "
                                  "project = ?", (project,))[0][0])

    # -- catalog: what listings need without loading project state ----------------------------

    @staticmethod
    def catalog_stmt(project: str, visibility: str, meta: dict, created: int) -> tuple:
        """Statement for `append(extra=…)`: catalog rows commit with the entry that changes them."""
        return ("INSERT INTO catalog VALUES (?, ?, ?, ?) ON CONFLICT (project) DO UPDATE SET "
                "visibility = excluded.visibility, meta = excluded.meta",
                (project, visibility, json.dumps(meta), created))

    def catalog_upsert(self, project: str, visibility: str, meta: dict, created: int) -> None:
        self._sql.write(self.catalog_stmt(project, visibility, meta, created))

    def catalog(self) -> list[dict]:
        rows = self._sql.rows("SELECT project, visibility, meta FROM catalog ORDER BY created")
        return [{"project": p, "visibility": v, "meta": json.loads(m)} for p, v, m in rows]

    def catalog_has(self, project: str) -> bool:
        return bool(self._sql.rows("SELECT 1 FROM catalog WHERE project = ?", (project,)))

    def catalog_count(self) -> int:
        return self._sql.rows("SELECT COUNT(*) FROM catalog")[0][0]

    @staticmethod
    def creator_stmt(project: str, creator: str) -> tuple:
        """Who created a project (genesis author), committed with the genesis entry."""
        return ("INSERT INTO creators VALUES (?, ?)", (project, creator))

    def creator_count(self, creator: str) -> int:
        """Projects created by *creator* (hubs older than this table count from zero)."""
        return self._sql.rows("SELECT COUNT(*) FROM creators WHERE creator = ?", (creator,))[0][0]

    def primary(self, project: str) -> dict | None:
        """For a mirrored project: the hub that sequences it (set once by a member)."""
        rows = self._sql.rows("SELECT url, card FROM primaries WHERE project = ?", (project,))
        return {"url": rows[0][0], "card": json.loads(rows[0][1])} if rows else None

    def set_primary(self, project: str, url: str, card: dict) -> None:
        # the key never changes once recorded (the endpoint checks); its URL may move
        self._sql.write(("INSERT INTO primaries VALUES (?, ?, ?) ON CONFLICT (project) "
                         "DO UPDATE SET url = excluded.url", (project, url, json.dumps(card))))

    def entries_count(self) -> int:
        return self._sql.rows("SELECT COUNT(*) FROM entries")[0][0]

    # -- deletions to retry (a redaction whose storage delete failed) ------------------------

    @staticmethod
    def pending_shred_stmt(project: str, cid: str) -> tuple:
        return ("INSERT INTO pending_shreds VALUES (?, ?) ON CONFLICT DO NOTHING", (project, cid))

    def add_pending_shred(self, project: str, cid: str) -> None:
        self._sql.write(self.pending_shred_stmt(project, cid))

    def pending_shreds(self) -> list[tuple[str, str]]:
        return [tuple(r) for r in self._sql.rows("SELECT project, cid FROM pending_shreds")]

    def done_shred(self, project: str, cid: str) -> None:
        self._sql.write(("DELETE FROM pending_shreds WHERE project = ? AND cid = ?",
                         (project, cid)))

    def projects(self) -> list[str]:
        rows = self._sql.rows("SELECT project FROM entries WHERE idx = 0 "
                              "ORDER BY integrated_time, project")
        return [r[0] for r in rows]

    def load_log(self, project: str) -> list[dict]:
        rows = self._sql.rows("SELECT entry FROM entries WHERE project = ? ORDER BY idx",
                              (project,))
        return [json.loads(r[0]) for r in rows]

    def load_log_with_hashes(self, project: str) -> tuple[list[dict], list[str]]:
        rows = self._sql.rows("SELECT entry, hash FROM entries WHERE project = ? ORDER BY idx",
                              (project,))
        return [json.loads(r[0]) for r in rows], [r[1] for r in rows]

    def snapshot(self, project: str) -> dict | None:
        rows = self._sql.rows("SELECT state FROM snapshots WHERE project = ?", (project,))
        return json.loads(rows[0][0]) if rows else None

    def put_snapshot(self, project: str, snap: dict) -> None:
        self._sql.write(("INSERT INTO snapshots VALUES (?, ?, ?) ON CONFLICT (project) DO UPDATE "
                         "SET size = excluded.size, state = excluded.state",
                         (project, len(snap["order"]), json.dumps(snap))))

    def entries(self, project: str, start: int, end: int) -> list[dict]:
        rows = self._sql.rows(
            "SELECT idx, entry, integrated_time, receipt FROM entries WHERE project = ? "
            "AND idx >= ? AND idx < ? ORDER BY idx", (project, start, end))
        return [{"index": i, "entry": json.loads(e), "integrated_time": t,
                 "receipt": json.loads(r)} for i, e, t, r in rows]

    def sequenced_times(self, project: str) -> dict[str, int]:
        """entry hash -> when this hub sequenced it (the time in its receipt)."""
        rows = self._sql.rows("SELECT hash, integrated_time FROM entries WHERE project = ?",
                              (project,))
        return {h: t for h, t in rows}

    def entry_by_hash(self, project: str, entry_hash: str) -> dict | None:
        rows = self._sql.rows("SELECT idx, integrated_time FROM entries WHERE project = ? AND "
                              "hash = ?", (project, entry_hash))
        return {"index": rows[0][0], "integrated_time": rows[0][1]} if rows else None

    def append(self, project: str, index: int, entry_hash: str, entry: dict, at_ms: int,
               receipt: dict, head: dict, extra: tuple = ()) -> None:
        """*extra*: statements that must commit with this entry (catalog, pending shreds)."""
        self._sql.write(
            ("INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?)",
             (project, index, entry_hash, json.dumps(entry), at_ms, json.dumps(receipt))),
            ("INSERT INTO heads VALUES (?, ?, ?)", (project, head["size"], json.dumps(head))),
            *extra)

    def replace_head(self, project: str, old: dict, head: dict) -> None:
        """Re-signed head at an existing size (same root), after a log key rotation. The old
        head is kept: witness cosignatures on it stay checkable."""
        self._sql.write(("INSERT INTO retired_heads VALUES (?, ?, ?)",
                         (project, old["size"], json.dumps(old))),
                        ("UPDATE heads SET head = ? WHERE project = ? AND size = ?",
                         (json.dumps(head), project, head["size"])))

    def retired_heads(self, project: str, size: int) -> list[dict]:
        rows = self._sql.rows("SELECT head FROM retired_heads WHERE project = ? AND size = ?",
                              (project, size))
        return [json.loads(r[0]) for r in rows]

    def head(self, project: str, size: int | None = None) -> dict | None:
        if size is None:
            rows = self._sql.rows("SELECT head FROM heads WHERE project = ? ORDER BY size DESC "
                                  "LIMIT 1", (project,))
        else:
            rows = self._sql.rows("SELECT head FROM heads WHERE project = ? AND size = ?",
                                  (project, size))
        return json.loads(rows[0][0]) if rows else None

    # -- witnesses and anchors ---------------------------------------------------------------

    def add_cosignature(self, project: str, size: int, cosig: dict, card: dict) -> None:
        self._sql.write((
            "INSERT INTO cosignatures VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (project, size, witness) DO UPDATE SET cosig = excluded.cosig, "
            "card = excluded.card",
            (project, size, cosig["witness"], json.dumps(cosig), json.dumps(card))))

    def cosignatures(self, project: str, size: int) -> list[dict]:
        rows = self._sql.rows("SELECT cosig, card FROM cosignatures WHERE project = ? AND "
                              "size = ?", (project, size))
        return [{"cosig": json.loads(c), "card": json.loads(k)} for c, k in rows]

    def latest_cosigned_size(self, project: str) -> int | None:
        return self._sql.rows("SELECT MAX(size) FROM cosignatures WHERE project = ?",
                              (project,))[0][0]

    def add_anchor(self, anchor: dict, heads: list[dict]) -> None:
        self._sql.write(("INSERT INTO anchors (anchor, heads) VALUES (?, ?)",
                         (json.dumps(anchor), json.dumps(heads))))

    def anchors(self) -> list[tuple[dict, list[dict]]]:
        rows = self._sql.rows("SELECT anchor, heads FROM anchors ORDER BY id")
        return [(json.loads(a), json.loads(h)) for a, h in rows]

    # -- blobs (delegated to a BlobStore) ---------------------------------------------------

    def has_blob(self, project: str, cid: str) -> bool:
        return self.blobs.exists(project, cid)

    def upload_path(self, project: str, cid: str) -> Path:
        return self.blobs.new_upload(project, cid)

    def publish_blob(self, project: str, cid: str, tmp: Path) -> None:
        self.blobs.publish(project, cid, tmp)

    def published_path(self, project: str, cid: str) -> Path:
        """Cache of verified plaintext for content published with its key."""
        if not (_HEX64.match(project) and _HEX64.match(cid)):
            raise ValueError("project and cid must be hex sha256")
        return self.data_dir / "published" / project / cid[:2] / cid

    def blobs_open(self, project: str, cid: str):
        return self.blobs.open(project, cid)

    def trim_published(self, max_bytes: int) -> None:
        """Keep the plaintext cache under *max_bytes*, evicting the least recently used files
        (it is a cache: evicted files are decrypted and verified again on demand)."""
        files = []
        for f in (self.data_dir / "published").glob("*/*/*"):
            try:
                if not f.name.endswith(".part"):
                    files.append((f.stat(), f))
            except FileNotFoundError:  # removed concurrently (shred, another trim)
                continue
        total = sum(st.st_size for st, _ in files)
        for st, f in sorted(files, key=lambda x: x[0].st_atime):
            if total <= max_bytes:
                break
            f.unlink(missing_ok=True)
            total -= st.st_size

    def delete_published(self, project: str, cid: str) -> None:
        self.published_path(project, cid).unlink(missing_ok=True)

    def delete_blob(self, project: str, cid: str) -> None:
        self.blobs.delete(project, cid)

    def sweep_partials(self) -> int:
        """Remove upload and plaintext-cache leftovers from a crash or kill (never published)."""
        legacy = [*self.data_dir.glob("*.upload"), *self.data_dir.glob("published/*/*/*.part")]
        for leftover in legacy:
            leftover.unlink(missing_ok=True)
        return len(legacy) + self.blobs.sweep()

    def write_blob(self, project: str, cid: str, chunks, expected_size: int) -> None:
        """Spool a stream, then publish it only if it has exactly *expected_size* bytes
        hashing to *cid*."""
        tmp = self.blobs.new_upload(project, cid)
        h, n = hashlib.sha256(), 0
        try:
            with open(tmp, "wb") as f:
                for chunk in chunks:
                    n += len(chunk)
                    if n > expected_size:
                        raise BlobRejected("blob is larger than the size on the ledger")
                    h.update(chunk)
                    f.write(chunk)
            if n != expected_size:
                raise BlobRejected("blob size differs from the size on the ledger")
            if h.hexdigest() != cid:
                raise BlobRejected("blob does not hash to its cid")
            self.blobs.publish(project, cid, tmp)
        finally:
            tmp.unlink(missing_ok=True)
