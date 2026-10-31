"""ADR 0009: both verifiers use exactly the rule tables in docs/spec/rules.json."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from provena.core import state

ROOT = Path(__file__).resolve().parents[1]
SPEC = json.loads((ROOT / "docs" / "spec" / "rules.json").read_text())
SPEC.pop("$comment")


def _norm(t: dict) -> dict:
    out = {}
    for k, v in t.items():
        if isinstance(v, dict):
            out[k] = {kk: sorted(vv) if isinstance(vv, list | set | frozenset) else vv
                      for kk, vv in v.items()}
        else:
            out[k] = list(v)
    return out


def test_python_tables_match_the_spec():
    py = {"ROLES": state.ROLES, "ATTEST_TYPES": state.ATTEST_TYPES,
          "META_LIMITS": state.META_LIMITS, "BODY_FIELDS": state.BODY_FIELDS,
          "BODY_FIELDS_V2": state.BODY_FIELDS_V2, "RULES_VERSIONS": state.RULES_VERSIONS,
          "STEP_STATUS": state.STEP_STATUS}
    assert _norm(py) == _norm(SPEC)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_browser_tables_match_the_spec():
    code = ("import('" + (ROOT / "src/provena/server/static/verifier.js").as_uri() +
            "').then(m => console.log(JSON.stringify(m.RULES_TABLES)))")
    out = subprocess.run(["node", "--input-type=module", "-e", code], capture_output=True,
                         text=True, check=True).stdout
    assert _norm(json.loads(out)) == _norm(SPEC)
