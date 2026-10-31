"""Python and the browser verifier must produce byte-identical canonical JSON (RFC 8785
subset) for any value Provena signs; any divergence would split signatures across verifiers."""

import json
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from provena.core.canonical import canonicalize
from provena.core.errors import CanonicalizationError
from provena.core.hashing import sha256

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

ALPHABET = ["a", "Z", "0", " ", "\"", "\\", "/", "\n", "\t", "\x00", "\x1f", "\x7f", "é", "€",
            " ", " ", "﻿", "דּ", "\U0001f600", "\U00010000", "中", "ß"]


def _string(rng):
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 8)))


def _value(rng, depth=0):
    kinds = ["str", "int", "bool", "null"] + (["list", "obj"] if depth < 4 else [])
    kind = rng.choice(kinds)
    if kind == "str":
        return _string(rng)
    if kind == "int":
        return rng.choice([0, -1, 1, 2**53 - 1, -(2**53 - 1), rng.randint(-10**12, 10**12)])
    if kind == "bool":
        return rng.random() < 0.5
    if kind == "null":
        return None
    if kind == "list":
        return [_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {_string(rng): _value(rng, depth + 1) for _ in range(rng.randint(0, 5))}


def test_python_and_js_canonical_bytes_agree(tmp_path):
    rng = random.Random(20261031)
    values = [_value(rng) for _ in range(400)]
    path = tmp_path / "values.json"
    path.write_text(json.dumps(values, ensure_ascii=True))  # transport-safe; same values
    proc = subprocess.run(["node", str(ROOT / "tests" / "js" / "canon.mjs"), str(path)],
                          capture_output=True, text=True, check=True)
    js = json.loads(proc.stdout)
    for value, j in zip(values, js, strict=True):
        py = canonicalize(value)
        assert j["canonical"].encode() == py, value
        assert j["hash"] == sha256(py).hex()


def test_lone_surrogates_rejected_by_both(tmp_path):
    bad = ["\ud800", "a\udc00b", {"\udbff": 1}, ["ok", "\ud83d"]]
    for value in bad:
        with pytest.raises(CanonicalizationError):
            canonicalize(value)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad, ensure_ascii=True))  # \uXXXX escapes survive transport
    proc = subprocess.run(["node", str(ROOT / "tests" / "js" / "canon.mjs"), str(path)],
                          capture_output=True, text=True, check=True)
    assert all("error" in r for r in json.loads(proc.stdout))
    assert canonicalize("\U0001f600")  # a proper pair is fine
