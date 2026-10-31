"""Per-user state: agent keyfiles and cards under $PROVENA_HOME (default ~/.provena)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from provena.core.errors import ProvenaError
from provena.core.keys import AgentKey


def home_dir() -> Path:
    return Path(os.environ.get("PROVENA_HOME", Path.home() / ".provena"))


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


class Home:
    def __init__(self, path: Path | None = None):
        self.path = path or home_dir()

    def _key_path(self, name: str) -> Path:
        return self.path / "agents" / f"{_agent_file(name)}.key.json"

    def card_path(self, name: str) -> Path:
        return self.path / "agents" / f"{_agent_file(name)}.card.json"

    def has_agent(self, name: str) -> bool:
        return self._key_path(name).exists()

    def create_agent(self, name: str, passphrase: str, kind: str, display: str = "",
                     scrypt_n: int = 2**15) -> AgentKey:
        if self.has_agent(name):
            raise FileExistsError(f"agent {name!r} already exists")
        agent = AgentKey.generate()
        keyfile = agent.export_encrypted(passphrase, n=scrypt_n)
        _write_private(self._key_path(name), json.dumps(keyfile, indent=2))
        self.card_path(name).write_text(json.dumps(agent.make_card(kind, display), indent=2))
        return agent

    def load_agent(self, name: str, passphrase: str) -> AgentKey:
        return AgentKey.load_encrypted(json.loads(self._key_path(name).read_text()), passphrase)

    def card(self, name: str) -> dict:
        return json.loads(self.card_path(name).read_text())

    # -- trust store: whose time statements this user accepts ---------------------------------

    TRUST_KINDS = ("logs", "witnesses", "tsas", "orgs")

    def _trust_file(self) -> dict:
        path = self.path / "trust.json"
        return json.loads(path.read_text()) if path.exists() else {}

    def explicit_trust(self) -> dict[str, set[str]]:
        """What this user added (`provena trust add`)."""
        data = self._trust_file()
        return {k: set(data.get(k, [])) for k in self.TRUST_KINDS}

    def uses_default_trust(self) -> bool:
        return self._trust_file().get("defaults", True) and \
            os.environ.get("PROVENA_NO_DEFAULT_TRUST") != "1"

    def trust(self) -> dict[str, set[str]]:
        """Explicit trust plus the built-in defaults (unless switched off): the verifier still
        decides (ADR 0007) — the defaults are listed by `provena trust list` and named in
        verification output when they made the difference."""
        trust = self.explicit_trust()
        if self.uses_default_trust():
            dropped = set(self._trust_file().get("dropped_defaults", []))
            for kind, ids in default_trust().items():
                trust[kind] |= set(ids) - dropped
        return trust

    def set_trust(self, kind: str, value: str, present: bool = True) -> None:
        if kind not in self.TRUST_KINDS:
            raise ValueError(f"trust kind must be one of {self.TRUST_KINDS}")
        trust = self.explicit_trust()
        value = value.lower() if kind == "tsas" else value
        (trust[kind].add if present else trust[kind].discard)(value)
        dropped = set(self._trust_file().get("dropped_defaults", []))
        if value in default_trust().get(kind, {}):  # a built-in id: remember the choice
            (dropped.discard if present else dropped.add)(value)
        self._write_trust(trust, self._trust_file().get("defaults", True), dropped)

    def set_default_trust(self, on: bool) -> None:
        self._write_trust(self.explicit_trust(), on,
                          set(self._trust_file().get("dropped_defaults", [])))

    def _write_trust(self, trust: dict[str, set[str]], defaults: bool,
                     dropped: set[str]) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        (self.path / "trust.json").write_text(json.dumps(
            {**{k: sorted(v) for k, v in trust.items()}, "defaults": defaults,
             "dropped_defaults": sorted(dropped)}, indent=2))


def _agent_file(name: str) -> str:
    """Agent names become file names: no separators, no leading dot (`../x` wrote outside).
    Anything else stays valid, so keys created under earlier rules still load."""
    if (not name or name.startswith(".") or any(c in name for c in "/\\\0")
            or not name.isprintable()):
        raise ProvenaError(f"invalid agent name {name!r}: no '/', '\\', leading '.' or "
                           f"control characters")
    return name


def default_trust() -> dict[str, dict[str, str]]:
    """Built-in trusted ids shipped with this release: kind -> {id: label}."""
    path = Path(__file__).resolve().parents[1] / "trust_defaults.json"
    data = json.loads(path.read_text()) if path.exists() else {}
    return {k: v for k, v in data.items() if not k.startswith("$")}
