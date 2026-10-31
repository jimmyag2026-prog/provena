"""Local Provena repository: the `.provena/` directory inside a project working tree.

    .provena/
      config.json      project id, agent name, optional hub url
      log.jsonl        one entry per line, in ledger order
      tracked.json     working-tree path -> {entry, sha256} of the latest registration
      blobs/ab/<cid>   ciphertext, content-addressed by sha256(ciphertext)
      heads.jsonl      signed tree heads seen for this log (self checkpoints and hub STHs)
      cosigs.json      witness cosignatures per hub head size
      anchors.json     anchor records covering this project (with the hub card)
      lock             held (flock) by the one process writing at a time

No plaintext secrets are stored here: salts, plaintext hashes and DEKs live inside the sealed
fields of entries, readable only with a project epoch key.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: no advisory locks here (single writer assumed)
    fcntl = None

from provena.core import builders, entries
from provena.core.errors import ProvenaError, VerificationError
from provena.core.hashing import sha256
from provena.core.keys import AgentKey
from provena.core.state import ProjectState
from provena.store.paths import UnsafePath, safe_relpath

DIRNAME = ".provena"


class RepoError(ProvenaError):
    pass


class RefNotFound(RepoError):
    """A reference that names no entry (exit 2, E_NOT_FOUND)."""


class RepoCorrupt(RepoError):
    """A local file under .provena/ is damaged or does not replay (exit 6, E_CORRUPT)."""


LOCK_WAIT = 300.0  # seconds to wait for another writer (a push can upload large blobs)
SNAPSHOT_EVERY = 200  # entries between replay snapshots (.provena/state.snapshot.json)


def _snapshot_key() -> bytes | None:
    """This user's key for checkout snapshots (created on first use), or None."""
    from provena.store.home import home_dir

    path = home_dir() / "snapshot.key"
    try:
        return bytes.fromhex(path.read_text().strip())
    except (OSError, ValueError):
        pass
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(os.urandom(32).hex())
    except FileExistsError:  # another process created it meanwhile
        pass
    except OSError:
        return None
    try:
        return bytes.fromhex(path.read_text().strip())
    except (OSError, ValueError):
        return None


def _snapshot_mac(key: bytes, n: int, digest: str, text: str) -> str:
    return hmac.new(key, f"{n}\n{digest}\n{text}".encode(), hashlib.sha256).hexdigest()


class Repo:
    def __init__(self, root: Path):
        self.root = root
        self.dir = root / DIRNAME
        self._state: ProjectState | None = None
        self._loaded_size = -1             # log.jsonl size the cached state was replayed from
        self._mutex = threading.RLock()    # threads sharing this Repo
        self._depth = 0
        self._lock_file = None
        self._reloaded = False             # another writer appended since state was cached

    # -- writers: one at a time, always on the latest log ---------------------------------

    @contextlib.contextmanager
    def writing(self):
        """Hold the project's write lock (re-entrant). On entry the cached state is reloaded
        if another process or Repo object appended meanwhile, so entries built inside the
        block chain onto the real last entry; build *and* append inside one block."""
        with self._mutex:
            if self._depth == 0:
                self._acquire()
                self._reloaded = False
            self._depth += 1
            try:
                if self._depth == 1:
                    self._refresh()
                yield self
            finally:
                self._depth -= 1
                if self._depth == 0:
                    self._release()

    def _acquire(self) -> None:
        if fcntl is None:
            return
        f = open(self.dir / "lock", "a+")
        deadline = time.monotonic() + LOCK_WAIT
        while True:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    f.close()
                    raise RepoError(f"another Provena process has been writing to this project "
                                    f"for over {LOCK_WAIT:g}s ({self.dir / 'lock'}); retry "
                                    f"when it finishes") from None
                time.sleep(0.02)
        self._lock_file = f

    def _release(self) -> None:
        if self._lock_file is not None:
            fcntl.flock(self._lock_file, fcntl.LOCK_UN)
            self._lock_file.close()
            self._lock_file = None

    def _refresh(self) -> None:
        try:
            size = (self.dir / "log.jsonl").stat().st_size
        except FileNotFoundError:
            return
        if self._state is not None and size != self._loaded_size:
            self._state = None  # replayed from disk on next use
            self._reloaded = True

    # -- lifecycle --------------------------------------------------------------------------

    @classmethod
    def init(cls, root: Path, agent_name: str, genesis: dict) -> Repo:
        repo = cls(root)
        if repo.dir.exists():
            raise RepoError(f"{repo.dir} already exists")
        (repo.dir / "blobs").mkdir(parents=True)
        state = ProjectState.from_genesis(genesis)
        repo._write_json("config.json", {"project": state.project, "agent": agent_name,
                                         "hub": None})
        repo._write_json("tracked.json", {})
        (repo.dir / "log.jsonl").write_text(json.dumps(genesis) + "\n")
        repo._state = state
        return repo

    @classmethod
    def find(cls, start: Path | None = None) -> Repo:
        here = (start or Path.cwd()).resolve()
        for d in (here, *here.parents):
            if (d / DIRNAME / "config.json").exists():
                return cls(d)
        raise RepoError("not inside a Provena repository (run `provena init`)")

    # -- config / small json files ----------------------------------------------------------

    def _read_json(self, name: str):
        path = self.dir / name
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise RepoCorrupt(f"{path} is damaged (not valid JSON: {exc}); restore it from a "
                              f"backup or clone the project again from its hub") from None

    def _write_json(self, name: str, value) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=f".{name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(value, indent=2, sort_keys=True))
            os.replace(tmp, self.dir / name)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    @property
    def config(self) -> dict:
        return self._read_json("config.json")

    def set_config(self, **updates) -> None:
        with self.writing():
            self._write_json("config.json", {**self.config, **updates})

    @property
    def tracked(self) -> dict[str, dict]:
        return self._read_json("tracked.json")

    def track(self, path: str, entry_hash: str, plain_sha256: bytes) -> None:
        record = {"entry": entry_hash, "sha256": plain_sha256.hex()}
        with self.writing():
            self._write_json("tracked.json", {**self.tracked, path: record})

    # -- log ---------------------------------------------------------------------------------

    def log(self) -> list[dict]:
        return self._parse_log((self.dir / "log.jsonl").read_bytes())

    def _parse_log(self, raw: bytes) -> list[dict]:
        path, out = self.dir / "log.jsonl", []
        for n, line in enumerate(raw.decode().split("\n"), 1):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                raise RepoCorrupt(f"{path} line {n} is damaged (not valid JSON); restore "
                                  f"the file, or clone the project again from its hub "
                                  f"(entries you never pushed are only here)") from None
        return out

    def _load_state(self, raw: bytes) -> ProjectState:
        """Replay log.jsonl, resuming from the snapshot of a byte-identical prefix of it when
        there is one. The snapshot carries an HMAC under a key in the user's Provena home, so a
        file written into a shared or synced checkout by someone else is ignored (`verify` and
        `doctor` always replay in full)."""
        log = self._parse_log(raw)
        snap_path = self.dir / "state.snapshot.json"
        key = _snapshot_key()
        state, covered = None, 0
        try:
            snap = json.loads(snap_path.read_text())
            n, text = snap["log_bytes"], snap["state"]
            if key and hmac.compare_digest(snap["mac"], _snapshot_mac(key, n, snap["log_sha256"],
                                                                      text)) \
                    and len(raw) >= n and sha256(raw[:n]).hex() == snap["log_sha256"]:
                inner = json.loads(text)
                state = ProjectState.resume(inner, log)
                covered = len(inner["order"])
        except Exception:  # missing, stale, foreign or damaged: it is only a cache
            state = None
        if state is None:
            state = ProjectState.replay(log)
        if key and len(state.order) - covered >= SNAPSHOT_EVERY:
            try:
                text, digest = json.dumps(state.snapshot()), sha256(raw).hex()
                fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".snapshot.", suffix=".tmp")
                with os.fdopen(fd, "w") as f:
                    json.dump({"log_bytes": len(raw), "log_sha256": digest, "state": text,
                               "mac": _snapshot_mac(key, len(raw), digest, text)}, f)
                os.replace(tmp, snap_path)
            except OSError:
                pass  # a read-only checkout replays in full next time
        return state

    @property
    def state(self) -> ProjectState:
        if self._state is None:
            path = self.dir / "log.jsonl"
            raw = path.read_bytes()
            size = len(raw)
            try:
                self._state = self._load_state(raw)
            except VerificationError as exc:
                raise RepoCorrupt(f"the local ledger {path} does not verify ({exc}): it was "
                                  f"changed outside Provena. `provena verify` shows where; "
                                  f"a clone from the hub restores pushed entries") from None
            self._loaded_size = size if path.stat().st_size == size else -1
        return self._state

    def append(self, entry: dict) -> str:
        """Append one entry. Build it inside `with repo.writing():` when other processes
        may write too: an entry built on a state that another writer has since extended is
        refused here (never written), instead of forking the author's chain."""
        with self.writing():
            try:
                h = self.state.apply(entry)  # validates before anything touches disk
            except VerificationError as exc:
                if self._reloaded:  # built on a state another writer had already extended
                    raise RepoError("another process wrote to this project while this entry "
                                    "was being prepared; nothing was written, run it again"
                                    ) from exc
                raise
            with open(self.dir / "log.jsonl", "a") as f:
                f.write(json.dumps(entry) + "\n")
            self._loaded_size = (self.dir / "log.jsonl").stat().st_size
        return h

    def replace_log(self, log: list[dict]) -> None:
        with self.writing():
            state = ProjectState.replay(log)
            fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".log.jsonl.", suffix=".tmp")
            with os.fdopen(fd, "w") as f:
                f.write("".join(json.dumps(e) + "\n" for e in log))
            os.replace(tmp, self.dir / "log.jsonl")
            (self.dir / "state.snapshot.json").unlink(missing_ok=True)  # of the old log
            self._state = state
            self._loaded_size = (self.dir / "log.jsonl").stat().st_size

    MIN_PREFIX = 6

    def resolve(self, ref: str) -> str:
        """Entry hash from a full hash, a unique hex prefix (≥ 6), `#N` (log position), a
        tracked path, or a path on the ledger (names are sealed: needs `self.reader`)."""
        order = self.state.order
        if ref.startswith("#") and ref[1:].isdigit():
            n = int(ref[1:])
            if n >= len(order):
                raise RefNotFound(f"{ref}: the log has {len(order)} entries (#0…#{len(order) - 1})")
            return order[n]
        hexish = set(ref) <= set("0123456789abcdef")
        if not hexish:
            rel = self.relpath(ref)
            tracked = self.tracked
            if rel in tracked:
                return tracked[rel]["entry"]
            found = self._by_ledger_name(rel)
            if found:
                return found
            raise RefNotFound(f"{ref!r} is not on the ledger"
                            + ("" if self.reader else " (or its name is sealed: unlock a key)")
                            + "; record it with `provena add` first")
        if len(ref) < self.MIN_PREFIX:
            raise RepoError(f"{ref!r}: give at least {self.MIN_PREFIX} hex characters of the hash, "
                            f"or #N for a log position")
        matches = [h for h in order if h.startswith(ref)]
        if not matches:
            raise RefNotFound(f"no entry hash starts with {ref!r}")
        if len(matches) > 1:
            raise RepoError(f"{ref!r} matches {len(matches)} entries: "
                            + ", ".join(f"{h[:12]} (#{order.index(h)})" for h in matches[:5]))
        return matches[0]

    reader = None  # an AgentKey that may open sealed names (set when a key is unlocked)

    def _by_ledger_name(self, rel: str) -> str | None:
        """The latest data or plan entry whose sealed name is *rel* (a clone that has not
        checked the file out, a plan registered by someone else)."""
        if self.reader is None:
            return None
        found = None
        for h in self.state.order:
            e = self.state.entries[h]
            if e["kind"] not in ("entity", "plan") or h in self.state.redacted:
                continue
            try:
                private = builders.open_entry_fields(self.state, self.reader, e) or {}
            except Exception:  # noqa: BLE001 — an epoch this key cannot read
                continue
            if rel in (private.get("name"), private.get("title")):
                found = h
        return found

    def relpath(self, path: str | Path) -> str:
        p = Path(path).resolve()
        try:
            return p.relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return Path(path).as_posix()

    def checked_relpath(self, path: str | Path) -> str:
        """The ledger name for a file to record: inside the project, not Provena's own state,
        a regular file (a symlink keeps its own name). Paths outside would be written to the
        append-only ledger for good and break every collaborator's checkout."""
        given = Path(path)
        rel = None
        for p, root in ((Path(os.path.abspath(given)), Path(os.path.abspath(self.root))),
                        (given.resolve(), self.root.resolve())):
            try:
                rel = p.relative_to(root)
                break
            except ValueError:
                continue
        if rel is None or not rel.parts:
            raise RepoError(f"{path} is outside the project ({self.root}); copy or move it "
                            f"into the project first")
        try:  # exactly the names every collaborator's checkout will accept
            safe_relpath(rel.as_posix())
        except UnsafePath:
            raise RepoError(f"{path}: this name cannot be recorded (Provena or git metadata, "
                            f"or characters other systems refuse: ':', '\\', control "
                            f"characters, device names)") from None
        if given.is_symlink() and not given.resolve().is_relative_to(self.root.resolve()):
            raise RepoError(f"{path} links to {given.resolve()}, outside the project; copy the "
                            f"file in if you mean to record it")
        if given.is_dir():
            raise RepoError(f"{path} is a directory; name the files in it")
        if not given.is_file():
            raise RepoError(f"{path}: no such file")
        return rel.as_posix()

    def read_extra(self, name: str, default):
        path = self.dir / name
        return json.loads(path.read_text()) if path.exists() else default

    def write_extra(self, name: str, value) -> None:
        self._write_json(name, value)

    # -- tree heads ------------------------------------------------------------------------

    def add_head(self, head: dict, signer_card: dict) -> None:
        with open(self.dir / "heads.jsonl", "a") as f:
            f.write(json.dumps({"head": head, "signer_card": signer_card}) + "\n")

    def heads(self) -> list[dict]:
        path = self.dir / "heads.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def leaves(self) -> list[bytes]:
        return [entries.entry_leaf(self.state.entries[h]) for h in self.state.order]

    # -- blobs -------------------------------------------------------------------------------

    def blob_path(self, cid: str) -> Path:
        return self.dir / "blobs" / cid[:2] / cid

    def has_blob(self, cid: str) -> bool:
        return self.blob_path(cid).exists()

    def encrypt_file(self, agent: AgentKey, path: Path):
        """Encrypt *path* into the blob store. Returns (body, secrets, plain_size)."""
        state = self.state
        pek = builders.epoch_key(state, agent)
        fd, tmp = tempfile.mkstemp(dir=self.dir / "blobs")
        try:
            with open(path, "rb") as src, os.fdopen(fd, "wb") as dst:
                body, secrets, size = builders.encrypt_content(pek, state.epoch, src, dst)
            dest = self.blob_path(body["cid"])
            dest.parent.mkdir(exist_ok=True)
            os.replace(tmp, dest)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return body, secrets, size

    def put_blob(self, cid: str, data: bytes) -> None:
        if sha256(data).hex() != cid:
            raise RepoError("blob content does not match its cid")
        dest = self.blob_path(cid)
        dest.parent.mkdir(exist_ok=True)
        dest.write_bytes(data)

    def blob_dek(self, agent: AgentKey, entry_hash: str) -> bytes:
        entry = self.state.entries[entry_hash]
        pek = builders.epoch_key(self.state, agent, entry["body"]["epoch"])
        return builders.content_dek(pek, entry["body"])

    def entry(self, entry_hash: str) -> dict:
        return self.state.entries[entry_hash]

    def entry_index(self, entry_hash: str) -> int:
        return self.state.order.index(entry_hash)

    @staticmethod
    def hash_of(entry: dict) -> str:
        return entries.entry_hash(entry)
