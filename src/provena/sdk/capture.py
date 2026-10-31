"""Capture daemon (Phase 3, level C1): register instrument output as soon as it is stable.

Run on the instrument PC with an `instrument` agent key. A file is registered once its size and
mtime have been unchanged for one polling interval (instruments write incrementally). A file that
changes later is registered again as a new version that references the previous one, so an
overwrite is visible on the ledger instead of silent. State lives in `.provena/capture.json`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from provena.sdk.project import Project


@dataclass
class CaptureResult:
    registered: list[tuple[str, str]] = field(default_factory=list)  # (path, entry hash)
    pending: list[str] = field(default_factory=list)


class Capture:
    def __init__(self, project: Project, watch: Path, *, pattern: str = "*"):
        self.project, self.watch, self.pattern = project, watch.resolve(), pattern
        self.repo = project.repo
        self._seen: dict[str, tuple[int, int]] = {}  # path -> (size, mtime_ns) last poll

    def _state(self) -> dict:
        return self.repo.read_extra("capture.json", {})

    def poll(self) -> CaptureResult:
        """One scan. Files must look identical on two consecutive polls to be registered."""
        result, state = CaptureResult(), self._state()
        for path in sorted(self.watch.rglob(self.pattern)):
            if not path.is_file() or self.repo.dir in path.parents:
                continue
            rel = self.repo.relpath(path)
            st = path.stat()
            sig = (st.st_size, st.st_mtime_ns)
            done = state.get(rel)
            if done and (done["size"], done["mtime_ns"]) == sig:
                continue
            if self._seen.get(rel) != sig:  # still being written, or first sighting
                self._seen[rel] = sig
                result.pending.append(rel)
                continue
            capture = {"by": self.project.agent.id, "file_mtime": st.st_mtime_ns // 1_000_000,
                       "observed": int(time.time() * 1000)}
            h = self.project.add(path, refs=[done["entry"]] if done else (), capture=capture)
            state[rel] = {"entry": h, "size": sig[0], "mtime_ns": sig[1]}
            self.repo.write_extra("capture.json", state)  # persist per file: restart-safe
            result.registered.append((rel, h))
        return result

    def run(self, interval: float = 2.0, *, push_every: int = 0, stop=lambda: False) -> None:
        polls = 0
        while not stop():
            res = self.poll()
            for rel, h in res.registered:
                print(f"captured {rel} -> {h[:12]}", flush=True)
            polls += 1
            if push_every and res.registered and polls % push_every == 0:
                try:
                    self.project.push()
                except Exception as exc:  # offline: entries stay queued locally
                    print(f"push failed, will retry: {exc}", flush=True)
            time.sleep(interval)
