"""Shared CLI helpers: errors, key loading, formatting, file registration."""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from pathlib import Path

from provena.core import builders
from provena.core.errors import DecryptionError, ProvenaError, VerificationError
from provena.core.keys import AgentKey
from provena.core.treehead import make_head
from provena.store.content import decrypt_verified
from provena.store.home import Home
from provena.store.paths import UnsafePath, safe_relpath
from provena.store.repo import Repo
from provena.store.secrets import SecretUnavailable, read_secret

# exit codes (docs/spec/cli-contract-v1.md); `run`/`rerun` pass the program's own code through
EXIT_VERIFY, EXIT_USAGE, EXIT_NETWORK, EXIT_AUTH, EXIT_STATE, EXIT_INTEGRITY, EXIT_CHALLENGE = \
    1, 2, 3, 4, 5, 6, 7


# contract error code -> exit code (docs/spec/cli-contract-v1.md §2)
ERROR_EXITS = {"E_CONFLICT": 5, "E_INCOMPLETE": 5, "E_STRANDED": 5, "E_READONLY": 5,
               "E_TOO_EARLY": 5, "E_FORBIDDEN": 4, "E_NO_PASSPHRASE": 4, "E_PASSPHRASE": 4,
               "E_CORRUPT": 6, "E_HUB_KEY": 6, "E_ROLLBACK": 6, "E_FORK": 6, "E_LATE": 7,
               "E_VOID": 7, "E_OMITTED": 7, "E_VERIFY": 1, "E_UNTRUSTED": 1}


class CliError(Exception):
    """*code* is the exit code (default: from *error*, else 2), *error* the contract's error
    code, *hint* the next command to try."""

    def __init__(self, message: str, code: int | None = None, error: str | None = None,
                 hint: str | None = None):
        super().__init__(message)
        self.code = code if code is not None else ERROR_EXITS.get(error, EXIT_USAGE)
        self.error, self.hint = error, hint

def _passphrase(confirm: bool = False, name: str | None = None) -> str:
    try:
        return read_secret("Provena key passphrase", env="PROVENA_PASSPHRASE", name=name,
                           confirm=confirm)
    except SecretUnavailable as exc:
        raise CliError(str(exc), EXIT_AUTH, "E_NO_PASSPHRASE") from None

def _agent_name(args, repo: Repo | None = None) -> str:
    if args.agent:
        return args.agent
    if repo is not None:
        return repo.config["agent"]
    return "default"

def _load_agent(args, repo: Repo | None = None) -> AgentKey:
    home, name = Home(), _agent_name(args, repo)
    if not home.has_agent(name):
        raise CliError(f"no agent named {name!r}; run `provena keygen --name {name}`")
    try:
        agent = home.load_agent(name, _passphrase(name=name))
    except DecryptionError as exc:
        raise CliError(f"cannot unlock agent {name!r}: {exc}", EXIT_AUTH) from None
    if repo is not None:
        repo.reader = agent  # paths on the ledger resolve with this key
    return agent

def _short(h: str | None, n: int = 12) -> str:
    return (h or "-")[:n]

def _when(ms: int) -> str:
    try:
        return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%SZ")
    except (OverflowError, OSError, ValueError):  # client timestamps are self-reported
        return f"(invalid time {ms})"

def _file_sha256(path: Path) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()

def _register_file(repo: Repo, agent: AgentKey, path: Path, *, media_type=None, kind="entity",
                   title=None) -> str:
    from provena.sdk import Project

    project = Project(repo, agent, repo.config["agent"])
    # the CLI commands decide about retries themselves (`add`/`plan` skip unchanged files;
    # a step's outputs are always its own entries)
    if kind == "plan":
        return project.plan(path, title=title, force=True)
    return project.add(path, media_type=media_type, force=True)

def _summary(repo: Repo, agent: AgentKey | None, entry: dict) -> str:
    body = entry["body"]
    if entry["kind"] in ("reveal", "attest", "redact"):
        extra = body.get("type") or body.get("reason") or ""
        return f"-> {_short(body['target'])} {extra}".rstrip()
    if entry["kind"] == "member":
        who = body.get("agent") or body.get("card", {}).get("id")
        return f"{body['action']} {_short(who, 16)} {body.get('role') or ''}".rstrip()
    if entry["kind"] == "key":
        return body["action"] + (f" epoch={body['epoch']}" if "epoch" in body else "")
    if agent is None or entry["sealed"] is None:
        return ""
    try:
        private = builders.open_entry_fields(repo.state, agent, entry) or {}
    except (ProvenaError, KeyError):
        return "(sealed)"
    if entry["kind"] == "activity":
        cmd = " ".join(private.get("command", []))
        return f"$ {cmd} (exit {private.get('exit_code')})"
    return private.get("name") or private.get("title") or ""

def _safe_relpath(name: str) -> Path:
    try:
        return safe_relpath(name)
    except UnsafePath as exc:
        raise CliError(str(exc)) from exc

def _decrypt_to(cipher_path: Path, dek: bytes, dest: Path, salt_hex: str, plain_hex: str,
                commitment_hex: str) -> int:
    try:
        return decrypt_verified(cipher_path, dek, dest, salt_hex, plain_hex, commitment_hex)
    except DecryptionError:
        raise  # damaged ciphertext: the caller decides (checkout drops the local copy)
    except VerificationError as exc:  # decrypted, but not what the ledger committed to
        raise CliError(str(exc), error="E_CORRUPT") from exc

def _best_head(repo: Repo, agent: AgentKey, needed: int, agent_name: str) -> dict:
    usable = [h for h in repo.heads() if needed <= h["head"]["size"] <= len(repo.state.order)]
    if usable:
        return max(usable, key=lambda h: (h["signer_card"]["kind"] == "hub", h["head"]["size"]))
    head = make_head(agent, repo.state.project, repo.leaves())
    chosen = {"head": head, "signer_card": Home().card(agent_name)}
    repo.add_head(head, chosen["signer_card"])
    return chosen

def _evidence(repo: Repo, head: dict) -> dict:
    from provena.sdk.sync import bundle_evidence

    return bundle_evidence(repo, head)

def _hub_client(repo: Repo, agent: AgentKey):
    from provena.sdk import sync

    url = repo.config.get("hub")
    if not url:
        raise CliError("no hub configured; run `provena remote <url>`")
    return sync, sync.make_client(url, agent)

def _bibtex_safe(text: str) -> str:
    """Ledger text must not inject into the citer's LaTeX: drop braces, backslashes, control
    characters and escape the remaining specials."""
    text = "".join(ch for ch in text if ch.isprintable() and ch not in "{}\\")
    for ch in "#$%&_^~":
        text = text.replace(ch, "\\" + ch)
    return text

def _outputs(paths: list[str], root: Path | None = None) -> list[Path]:
    """Files named or inside named directories. With *root*, a file (or symlink) resolving
    outside it, or into its `.provena`, is refused: it would be encrypted into the ledger."""
    files = []
    for p in map(Path, paths):
        files.extend(sorted(f for f in p.rglob("*") if f.is_file()) if p.is_dir() else [p])
    if root is not None:
        root = root.resolve()
        for f in files:
            real = f.resolve()
            if f.exists() and (not real.is_relative_to(root)
                               or real.is_relative_to(root / ".provena")):
                raise CliError(f"{f} resolves to {real}, outside this repository; refusing to "
                               "record it")
    return files


def _openable(repo: Repo, h: str, *, steps: bool = True) -> None:
    """Data and plans carry a salted commitment; so do steps under ledger rules 2."""
    entry = repo.entry(h)
    kind = entry["kind"]
    if kind == "activity" and steps and "commitment" in entry["body"]:
        return
    if kind not in ("entity", "plan"):
        raise CliError(f"{h[:12]} is a {kind} entry: only data files and plans"
                       + (" (and steps, with `provena reveal`)" if kind == "activity" else "")
                       + " have a commitment to open" + (
                           "; this step was recorded under ledger rules 1, without one"
                           if kind == "activity" else ""))


def _challenge_guard(repo: Repo, target: str, force: bool) -> None:
    """In a project that runs a challenge, anything disclosed before the deadline other than
    the protocol, targets and scorer voids it (a copy of the truth could be in it)."""
    info = repo.read_extra("challenge.json", None)
    if not info or force or time.time() * 1000 > info["deadline"]:
        return
    if target in {info["protocol"], info["targets"], info["score"]}:
        return
    raise CliError(f"this project runs the challenge '{info.get('title', '')}' until "
                   f"{_when(info['deadline'])}: disclosing {target[:12]} now would void it",
                   error="E_CONFIRM", hint="wait until after the deadline (`provena challenge "
                   "close`), publish it from another project, or add --force to void it")
