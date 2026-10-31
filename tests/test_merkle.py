import pytest

from provena.core import merkle
from provena.core.errors import VerificationError

# Leaves and roots from the Certificate Transparency reference test suite (RFC 6962 hashing).
CT_LEAVES = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43",
             b"\x50\x51\x52\x53\x54\x55\x56\x57",
             b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"]
CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def _leaves(n):
    return [merkle.leaf_hash(i.to_bytes(4, "big")) for i in range(n)]


def test_ct_reference_roots():
    hashes = [merkle.leaf_hash(x) for x in CT_LEAVES]
    for size, expected in enumerate(CT_ROOTS, start=1):
        assert merkle.root(hashes[:size]).hex() == expected


def test_empty_root():
    assert merkle.root([]).hex() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


@pytest.mark.parametrize("n", range(1, 34))
def test_inclusion_all(n):
    leaves = _leaves(n)
    r = merkle.root(leaves)
    for i in range(n):
        merkle.verify_inclusion(leaves[i], i, n, merkle.inclusion_proof(leaves, i), r)


@pytest.mark.parametrize("n", range(1, 34))
def test_consistency_all(n):
    leaves = _leaves(n)
    for m in range(1, n + 1):
        merkle.verify_consistency(m, n, merkle.root(leaves[:m]), merkle.root(leaves),
                                  merkle.consistency_proof(leaves, m))


def test_inclusion_rejects_tampering():
    leaves = _leaves(11)
    r, proof = merkle.root(leaves), merkle.inclusion_proof(leaves, 5)
    with pytest.raises(VerificationError):
        merkle.verify_inclusion(leaves[6], 5, 11, proof, r)
    with pytest.raises(VerificationError):
        merkle.verify_inclusion(leaves[5], 4, 11, proof, r)
    with pytest.raises(VerificationError):  # (size itself is authenticated by the signed tree head)
        merkle.verify_inclusion(leaves[5], 5, 17, proof, r)
    with pytest.raises(VerificationError):
        merkle.verify_inclusion(leaves[5], 5, 11, proof[:-1], r)
    with pytest.raises(VerificationError):
        merkle.verify_inclusion(leaves[5], 5, 11, proof + [r], r)


def test_consistency_rejects_rewritten_history():
    leaves = _leaves(13)
    forked = list(leaves)
    forked[2] = merkle.leaf_hash(b"rewritten")
    proof = merkle.consistency_proof(forked, 7)
    with pytest.raises(VerificationError):
        merkle.verify_consistency(7, 13, merkle.root(leaves[:7]), merkle.root(forked), proof)
    with pytest.raises(VerificationError):
        merkle.verify_consistency(8, 13, merkle.root(leaves[:8]), merkle.root(leaves), [])


def test_incremental_log_matches_fresh_trees():
    log = merkle.MerkleLog()
    leaves = _leaves(70)
    for i, leaf in enumerate(leaves):
        log.append(leaf)
        assert log.root() == merkle.MerkleLog(leaves[: i + 1]).root()
    for size in (1, 17, 64, 70):
        assert log.root(size) == merkle.root(leaves[:size])
        for idx in (0, size // 2, size - 1):
            merkle.verify_inclusion(leaves[idx], idx, size, log.inclusion_proof(idx, size),
                                    log.root(size))
        for first in (1, size // 3 or 1, size):
            merkle.verify_consistency(first, size, log.root(first), log.root(size),
                                      log.consistency_proof(first, size))
