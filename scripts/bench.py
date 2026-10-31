"""Micro-benchmarks for the numbers quoted in docs/devlog/benchmarks.md.

    uv run python scripts/bench.py [--entries 10000]
"""

import argparse
import os
import platform
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from provena.core import aead, builders, entries, merkle  # noqa: E402
from provena.core.bundle import make_bundle  # noqa: E402
from provena.core.keys import AgentKey  # noqa: E402
from provena.core.state import ProjectState  # noqa: E402
from provena.core.treehead import make_head  # noqa: E402
from provena.core.verify import verify_bundle  # noqa: E402


def timed(label, fn, unit=None, count=None):
    t = time.perf_counter()
    out = fn()
    dt = time.perf_counter() - t
    rate = f"  ({count / dt:,.0f} {unit}/s)" if count else ""
    print(f"{label:<48} {dt * 1000:>9.1f} ms{rate}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--entries", type=int, default=10_000)
    n = ap.parse_args().entries
    print(f"python {platform.python_version()} · {platform.machine()} · {n:,} entries\n")

    data = os.urandom(64 << 20)
    key = aead.new_key()
    ct = timed("encrypt 64 MiB (AES-256-GCM STREAM)", lambda: aead.encrypt_bytes(key, data),
               "MiB", 64)
    timed("decrypt 64 MiB", lambda: aead.decrypt_bytes(key, ct), "MiB", 64)

    owner = AgentKey.generate()
    genesis, pek = builders.new_project(owner, owner.make_card("person"))
    state = ProjectState.from_genesis(genesis)
    log = [genesis]
    secrets = builders.ContentSecrets(b"\1" * 32, b"\2" * 32, b"\3" * 32)

    def build():
        for i in range(n - 1):
            e = builders.plan(state, owner, {"commitment": f"{i:064x}"}, secrets, title="x")
            state.apply(e)
            log.append(e)

    timed(f"build + sign + apply {n - 1:,} entries", build, "entries", n - 1)
    timed(f"replay {n:,} entries (verify every signature)",
          lambda: ProjectState.replay(log), "entries", n)
    import json

    snap = json.dumps(ProjectState.replay(log[:-10]).snapshot())
    timed(f"resume {n:,} entries from a snapshot (+10 checked)",
          lambda: ProjectState.resume(json.loads(snap), log), "entries", n)
    leaves = [entries.entry_leaf(e) for e in log]
    mlog = merkle.MerkleLog()

    def append_with_roots():
        for leaf in leaves:
            mlog.append(leaf)
            mlog.root()

    timed(f"Merkle append + new root, {n:,} times", append_with_roots, "appends", n)
    timed("1,000 inclusion proofs", lambda: [mlog.inclusion_proof(i * (n // 1000))
                                            for i in range(1000)], "proofs", 1000)
    head = make_head(owner, state.project, mlog)
    target = entries.entry_hash(log[n // 2])
    sel = timed("make selective bundle (1 target)",
                lambda: make_bundle(log, head, owner.make_card("person"), [target]))
    timed("verify selective bundle", lambda: verify_bundle(sel))
    full = timed("make full bundle", lambda: make_bundle(log, head, owner.make_card("person"),
                                                         [target], mode="full"))
    report = timed("verify full bundle (replay + root)", lambda: verify_bundle(full))
    assert report.ok, report.errors
    print(f"\nselective bundle {len(str(sel)) / 1024:,.1f} KiB · full bundle "
          f"{len(str(full)) / 1024 / 1024:,.1f} MiB")


if __name__ == "__main__":
    main()
