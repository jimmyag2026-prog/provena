"""RFC 9162 (Certificate Transparency v2) Merkle tree hashing and proofs.

Implemented directly rather than imported: this is the root of trust and must stay small enough to
audit in one sitting. Inputs to the proof builders are *leaf hashes*, not raw leaves.
"""

from __future__ import annotations

from collections.abc import Sequence

from provena.core.errors import VerificationError
from provena.core.hashing import sha256

EMPTY_ROOT = sha256(b"")


def leaf_hash(data: bytes) -> bytes:
    return sha256(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


class MerkleLog:
    """Append-only leaf list with cached perfect subtrees.

    Every subtree [start, start + 2^j) with start aligned to 2^j is immutable once complete, so
    its hash is computed once. Roots and proofs for any tree size then cost O(log^2 n) hashes
    instead of O(n).
    """

    def __init__(self, leaves: Sequence[bytes] = ()):
        self.leaves: list[bytes] = list(leaves)
        self._cache: dict[tuple[int, int], bytes] = {}

    def __len__(self) -> int:
        return len(self.leaves)

    def append(self, leaf: bytes) -> int:
        self.leaves.append(leaf)
        return len(self.leaves) - 1

    def _range(self, start: int, end: int) -> bytes:
        n = end - start
        if n == 1:
            return self.leaves[start]
        perfect = n & (n - 1) == 0
        if perfect and (start, n) in self._cache:
            return self._cache[(start, n)]
        k = _split(n)
        h = node_hash(self._range(start, start + k), self._range(start + k, end))
        if perfect:
            self._cache[(start, n)] = h
        return h

    def root(self, size: int | None = None) -> bytes:
        size = len(self.leaves) if size is None else size
        return EMPTY_ROOT if size == 0 else self._range(0, size)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        size = len(self.leaves) if size is None else size
        if not 0 <= index < size <= len(self.leaves):
            raise ValueError("index out of range")
        return self._path(index, 0, size)

    def _path(self, m: int, start: int, end: int) -> list[bytes]:
        n = end - start
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return self._path(m, start, start + k) + [self._range(start + k, end)]
        return self._path(m - k, start + k, end) + [self._range(start, start + k)]

    def consistency_proof(self, first: int, second: int | None = None) -> list[bytes]:
        second = len(self.leaves) if second is None else second
        if not 0 < first <= second <= len(self.leaves):
            raise ValueError("first must be in 1..size")
        return self._subproof(first, 0, second, True)

    def _subproof(self, m: int, start: int, end: int, complete: bool) -> list[bytes]:
        n = end - start
        if m == n:
            return [] if complete else [self._range(start, end)]
        k = _split(n)
        if m <= k:
            return self._subproof(m, start, start + k, complete) + [self._range(start + k, end)]
        return self._subproof(m - k, start + k, end, False) + [self._range(start, start + k)]


def root(leaves: Sequence[bytes]) -> bytes:
    return MerkleLog(leaves).root()


def inclusion_proof(leaves: Sequence[bytes], index: int) -> list[bytes]:
    return MerkleLog(leaves).inclusion_proof(index)


def consistency_proof(leaves: Sequence[bytes], first: int) -> list[bytes]:
    return MerkleLog(leaves).consistency_proof(first)


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes],
                     expected_root: bytes) -> None:
    """RFC 9162 §2.1.3.2. Raises VerificationError on any mismatch."""
    if not 0 <= index < size:
        raise VerificationError("inclusion: index out of range")
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            raise VerificationError("inclusion: proof too long")
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0 or r != expected_root:
        raise VerificationError("inclusion: root mismatch")


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes,
                       proof: Sequence[bytes]) -> None:
    """RFC 9162 §2.1.4.2. Raises VerificationError on any mismatch."""
    if not 0 < first <= second:
        raise VerificationError("consistency: invalid sizes")
    if first == second:
        if proof or first_root != second_root:
            raise VerificationError("consistency: equal sizes must have equal roots, empty proof")
        return
    path = list(proof)
    if first & (first - 1) == 0:  # exact power of two
        path.insert(0, first_root)
    if not path:
        raise VerificationError("consistency: empty proof")
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            raise VerificationError("consistency: proof too long")
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    if sn != 0 or fr != first_root or sr != second_root:
        raise VerificationError("consistency: root mismatch")
