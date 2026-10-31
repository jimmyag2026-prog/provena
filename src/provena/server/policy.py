"""Hub creation policy: orgs, their agents, quotas and API keys (ADR 0012).

Writes stay self-authenticated by agent keys (ADR 0005); the policy only decides who may create
projects on this hub and how much they may store. The file is re-read when it changes, and a
file that does not parse admits nobody (fail closed), like `--creators`.

    {"orgs": {"lab-a": {"agents": ["pv1a…"], "max_projects": 50,
                        "max_bytes": 10737418240, "api_keys": ["sha256:<hex>"]}},
     "default": {"max_projects": 3, "max_bytes": 1073741824}}

`default` (optional) applies to agents in no org, each agent counted on its own; without it only
org agents may create projects. API keys are stored as SHA-256 hashes (`provena hub api-key`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from pathlib import Path

LIMIT_KEYS = ("max_projects", "max_bytes")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")


class PolicyError(ValueError):
    pass


def _limits(d: dict, where: str) -> dict:
    out = {}
    for k in LIMIT_KEYS:
        v = d.get(k)
        if v is not None and (type(v) is not int or v < 0):
            raise PolicyError(f"{where}.{k} must be a non-negative integer or absent")
        out[k] = v
    return out


def parse(data: dict) -> dict:
    if not isinstance(data, dict) or set(data) - {"orgs", "default"}:
        raise PolicyError("policy: only `orgs` and `default` are allowed")
    orgs, owner = {}, {}
    for name, org in (data.get("orgs") or {}).items():
        if not NAME_RE.fullmatch(name) or not isinstance(org, dict) \
                or set(org) - {"agents", "api_keys", *LIMIT_KEYS}:
            raise PolicyError(f"policy: bad org {name!r}")
        agents = org.get("agents", [])
        keys = org.get("api_keys", [])
        if not all(isinstance(a, str) and a.startswith("pv1") for a in agents) or not all(
                isinstance(k, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", k) for k in keys):
            raise PolicyError(f"policy: org {name}: agents are pv1… ids, api_keys sha256:<hex>")
        for a in agents:
            if a in owner:
                raise PolicyError(f"policy: agent {a} is in orgs {owner[a]} and {name}")
            owner[a] = name
        orgs[name] = {**_limits(org, name), "agents": set(agents),
                      "api_keys": [k.removeprefix("sha256:") for k in keys]}
    default = data.get("default")
    if default is not None and (not isinstance(default, dict) or set(default) - set(LIMIT_KEYS)):
        raise PolicyError("policy: default takes only max_projects and max_bytes")
    return {"orgs": orgs, "owner": owner,
            "default": None if default is None else _limits(default, "default")}


def hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


class Policy:
    def __init__(self, path: Path):
        self.path, self._stamp, self._data = path, None, parse({})

    def _current(self) -> dict:
        try:
            stat = self.path.stat()
            stamp = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino, stat.st_size)
            if stamp != self._stamp:
                self._data, self._stamp = parse(json.loads(self.path.read_text())), stamp
        except (OSError, ValueError) as exc:  # fail closed: nobody may create projects
            logging.getLogger("provena.hub").error("policy file %s unusable: %s", self.path, exc)
            self._data, self._stamp = parse({}), None
        return self._data

    def account(self, agent: str) -> tuple[str, dict] | None:
        """(accounting name, limits) for a creator: its org, or `agent:<id>` under the default;
        None if this agent may not create projects here."""
        data = self._current()
        org = data["owner"].get(agent)
        if org is not None:
            return org, data["orgs"][org]
        if data["default"] is None:
            return None
        return f"agent:{agent}", data["default"]

    def limits(self, account: str) -> dict | None:
        data = self._current()
        if account.startswith("agent:"):
            return data["default"]
        return data["orgs"].get(account)

    def org_for_key(self, api_key: str) -> str | None:
        digest = hash_key(api_key)
        for name, org in self._current()["orgs"].items():
            if any(hmac.compare_digest(digest, k) for k in org["api_keys"]):
                return name
        return None
