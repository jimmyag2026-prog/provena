# Benchmarks

Reproduce: `uv run python scripts/bench.py [--entries N]` · 2026-10-31 · Apple Silicon laptop,
single process, no hub/network involved.

```
python 3.12.12 · arm64 · 10,000 entries

encrypt 64 MiB (AES-256-GCM STREAM)                   67.1 ms  (953 MiB/s)
decrypt 64 MiB                                        84.5 ms  (757 MiB/s)
build + sign + apply 9,999 entries                  2481.5 ms  (4,029 entries/s)
replay 10,000 entries (verify every signature)      1371.5 ms  (7,291 entries/s)
resume 10,000 entries from a snapshot (+10 checked)    3.7 ms  (2026-10-31, state snapshots)
Merkle append + new root, 10,000 times                45.1 ms  (221,924 appends/s)
1,000 inclusion proofs                                 7.7 ms  (129,924 proofs/s)
make selective bundle (1 target)                     210.8 ms
verify selective bundle                                1.1 ms
make full bundle                                     206.1 ms
verify full bundle (replay + root)                  1567.1 ms

selective bundle 4.7 KiB · full bundle 7.7 MiB
```

## Reading the numbers

- **Encryption is not the bottleneck**: ~1 GiB/s per core; a 64 MiB instrument file costs ~60 ms.
- **Ledger writes** are bound by Ed25519 signing plus canonical JSON (~4k entries/s per writer);
  a lab writes far fewer.
- **Replay** (every signature and rule, from genesis) runs at ~7k entries/s, so a 10k-entry
  project loads in ~1.4 s on hub start and on `clone`.
- **Merkle** append with a fresh root and inclusion proofs are effectively free (cached perfect
  subtrees, `MerkleLog`).
- **Selective bundles** are ~5 KiB and verify in ~1 ms regardless of project size. **Full
  bundles** grow with the log (~0.8 KiB per entry) and verify at replay speed: use them when
  authorization at signing time matters.

History: building a selective bundle took 813 ms and full verification 3.0 s before the bundle
builder reused one cached tree and the verifier stopped replaying twice (2026-10-31).

## Hub at scale (2026-10-31)

One process, SQLite, filesystem blobs, 2,000 public projects × 20 entries:

| | |
|---|---|
| sequencing 40,000 entries (sign + apply + persist + new head each) | 21.9 s (~1,800 entries/s) |
| cold start: replay and re-verify every signature | 7.2 s (~5,500 entries/s) |
| resident memory of the loaded hub | ~100 MB (~2.5 KB per entry) |
| SQLite size | 88 MB (~2.2 KB per entry incl. receipts and heads) |

Extrapolated: ~1 M entries ≈ 3 min start, ~2.5 GB RAM. The current design keeps every project's
state in memory, which is fine for a lab or institute hub. Plan for larger hubs, in order:
1. ~~**Lazy project loading**~~ — done 2026-10-31: cold start 7.2 s → 0.1 s at this size; state
   loads on first access into an LRU; listings read a catalog table.
2. **Verified snapshots**: persist a state snapshot at a signed tree head; on start, replay only
   entries after it (signatures were verified on ingest; the snapshot is bound to the head root).
3. **Horizontal split**: projects are independent logs, so hubs shard by project id behind one
   front door; the root-of-roots anchor spans shards.
