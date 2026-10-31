"""Passphrases without a terminal (agents, CI, services) and with one (people).

Order: a file named by ``<ENV>_FILE`` (per agent: ``<ENV>_FILE_<NAME>``), then ``<ENV>``, then
an interactive prompt when stdin is a terminal. Without any of them the caller gets
`SecretUnavailable`, never a prompt that blocks or crashes on a closed stdin.
"""

from __future__ import annotations

import getpass
import os
import re
import stat
import sys
from pathlib import Path

from provena.core.errors import ProvenaError


class SecretUnavailable(ProvenaError):
    pass


def _env_suffix(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", name).upper()


def read_secret(prompt: str, *, env: str, name: str | None = None,
                confirm: bool = False, service: bool = False) -> str:
    """*service*: a server's secret (Docker/Kubernetes mount them 0444, owned by root), so the
    file may be readable by others and surrounding whitespace is stripped."""
    files = ([f"{env}_FILE_{_env_suffix(name)}"] if name else []) + [f"{env}_FILE"]
    for var in files:
        if os.environ.get(var):
            path = Path(os.environ[var])
            try:
                mode = path.stat().st_mode
                text = path.read_text()
            except OSError as exc:
                raise SecretUnavailable(f"{var}: cannot read {path} ({exc.strerror})") from None
            if not service and os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise SecretUnavailable(f"{var}: {path} is readable by other users; "
                                        f"run `chmod 600 {path}`")
            return text.strip() if service else text.rstrip("\r\n")
    if os.environ.get(env) is not None:
        return os.environ[env]
    if not sys.stdin.isatty():
        raise SecretUnavailable(
            f"no passphrase and no terminal to ask for one: set {files[-1]} to a file "
            f"(mode 600) holding it, or {env}")
    first = getpass.getpass(f"{prompt}: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != first:
        raise SecretUnavailable("passphrases do not match")
    return first
