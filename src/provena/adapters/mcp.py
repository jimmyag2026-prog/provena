"""`provena mcp`: a Model Context Protocol server (stdio, JSON-RPC 2.0) for one project.

The server is the project's writer for the agent: it unlocks the agent key once at start (from
a passphrase file or the environment, never from the conversation) and every write goes through
the repository lock, so the CLI can still be used beside it. The key never enters the model's
context: tools take paths, entry references and plain values, and return complete hashes.

Implemented by hand (newline-delimited JSON-RPC over stdin/stdout) so the core keeps one
dependency; it follows the MCP specification's initialize / tools/list / tools/call flow.
"""

from __future__ import annotations

import json
import sys
import time
import traceback
from pathlib import Path

from provena import __version__
from provena.core.errors import ProvenaError
from provena.sdk import verify as sdk_verify
from provena.sdk.project import Project
from provena.store.home import Home
from provena.store.repo import Repo
from provena.store.secrets import read_secret

PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")

INSTRUCTIONS = (
    "Provena keeps a signed, encrypted, append-only ledger of this research project. Record "
    "every step you take with record_step (also failed ones and steps without files: a model "
    "call, a search). Preregister protocols with preregister BEFORE the results exist. Data "
    "files: add_file. To show someone a result, prove it and give them the .pvb; verify checks "
    "one. Entries are named by full hash, a unique prefix of 6+ hex characters, #N or path. "
    "The ledger cannot be edited: what you record stays (that is the point).")


def _schema(props: dict, required=()) -> dict:
    return {"type": "object", "properties": props, "required": list(required),
            "additionalProperties": False}


_STR = {"type": "string"}
_STRS = {"type": "array", "items": {"type": "string"}}

TOOLS = {
    "status": ("Project id, entries, what is not pushed or not finished.", _schema({})),
    "add_file": ("Record a data file of the project (encrypted, committed). Re-adding unchanged "
                 "content is a no-op.", _schema({"path": _STR, "media_type": _STR}, ["path"])),
    "preregister": ("Commit to a protocol/plan file now; its content stays sealed until revealed. "
                    "Do this before producing results that should follow it.",
                    _schema({"path": _STR, "title": _STR}, ["path"])),
    "record_step": ("Record one step that happened: a tool call, a model call, a script run. "
                    "Works without files. args/result/error/transcript are sealed; status "
                    "(ok/failed) is public.",
                    _schema({"tool": {"type": "string", "description": "what ran, e.g. "
                                      "'web_search' or 'python fit.py'"},
                             "args": {"type": "object"}, "result": {},
                             "error": _STR, "exit_code": {"type": "integer"},
                             "model": {"type": "string", "description": "provider/model-id "
                                       "if a model produced it"},
                             "used": {**_STRS, "description": "inputs: entry refs or recorded "
                                      "paths"},
                             "outputs": {**_STRS, "description": "files this step wrote "
                                         "(recorded now)"},
                             "plan": _STR, "transcript": _STR}, ["tool"])),
    "reveal": ("Make a committed entry public: a data file or plan (with its content key when "
               "with_key), or a step's details.",
               _schema({"ref": _STR, "with_key": {"type": "boolean"}}, ["ref"])),
    "log": ("The ledger's entries (newest last).", _schema({"limit": {"type": "integer"}})),
    "prove": ("Write a proof bundle (.pvb) for entries; open=refs whose commitments to open.",
              _schema({"refs": _STRS, "output": _STR, "open": _STRS,
                       "full": {"type": "boolean"}}, ["refs", "output"])),
    "verify": ("Verify a proof bundle file; returns validity, trust level, per-entry facts and "
               "whether preregistration holds.",
               _schema({"bundle": _STR, "require": {"type": "string", "enum": [
                   "unverified", "self-sequenced", "log-sequenced", "witnessed",
                   "anchored"]}}, ["bundle"])),
    "push": ("Send local entries and files to the project's hub.", _schema({})),
    "pull": ("Fetch teammates' entries from the hub.", _schema({})),
}


class Server:
    def __init__(self, project: Project):
        self.project = project

    # -- tools ------------------------------------------------------------------------------

    def _entry(self, h: str) -> dict:
        repo = self.project.repo
        e = repo.entry(h)
        names = {v["entry"]: k for k, v in repo.tracked.items()}
        return {"hash": h, "index": repo.entry_index(h), "kind": e["kind"],
                "path": names.get(h), "status": e["body"].get("status")}

    def _path(self, path: str) -> Path:
        p = Path(path)
        return p if p.is_absolute() else self.project.repo.root / p

    def _bundle_path(self, path: str, *, write: bool) -> Path:
        """Bundles the model names stay inside the project: a prompt-injected agent must not
        read or overwrite anything else (~/.provena/trust.json, ~/.ssh/…)."""
        root = self.project.repo.root.resolve()
        p = self._path(path).resolve()
        if not p.is_relative_to(root) or p.relative_to(root).parts[:1] == (".provena",):
            raise ToolError("E_INPUT", f"{path}: bundles are read and written inside the "
                            f"project only", "use a path like out/result.pvb")
        if write and p.suffix != ".pvb":
            raise ToolError("E_INPUT", f"{path}: a bundle file name ends in .pvb")
        if write and p.exists() and p.suffix == ".pvb" and not _is_bundle(p):
            raise ToolError("E_INPUT", f"{path} exists and is not a proof bundle")
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def call(self, name: str, a: dict) -> dict:
        proj, repo = self.project, self.project.repo
        if name == "status":
            synced = repo.config.get("synced", 0)
            return {"project": proj.id, "entries": len(repo.state.order), "hub":
                    repo.config.get("hub"), "unpushed": len(repo.state.order) - synced
                    if repo.config.get("hub") else None,
                    "push_incomplete": bool(repo.config.get("push_incomplete")),
                    "rules": repo.state.rules}
        if name == "add_file":
            path = self._path(a["path"])
            rel = repo.checked_relpath(path)
            rec = repo.tracked.get(rel)
            if rec and rec["entry"] in repo.state.entries and \
                    repo.entry(rec["entry"])["author"] == proj.agent.id and \
                    _sha(path) == rec["sha256"]:
                return {**self._entry(rec["entry"]), "unchanged": True}
            return {**self._entry(proj.add(path, media_type=a.get("media_type"))),
                    "unchanged": False}
        if name == "preregister":
            return self._entry(proj.plan(self._path(a["path"]), title=a.get("title")))
        if name == "record_step":
            r = proj.record(a["tool"], a.get("args"), a.get("result"),
                            used=[str(self._path(u)) if (self.project.repo.root / u).exists()
                                  else u for u in a.get("used", [])],
                            outputs=[self._path(o) for o in a.get("outputs", [])],
                            error=a.get("error"), exit_code=a.get("exit_code"),
                            model=a.get("model"), trace=a.get("transcript"),
                            plan=a.get("plan"))
            return {"activity": self._entry(r["activity"]), "status": r["status"],
                    "outputs": [self._entry(h) for h in r["outputs"]],
                    "trace": self._entry(r["trace"])}
        if name == "reveal":
            h = proj.resolve(a["ref"])
            step = repo.entry(h)["kind"] == "activity"
            if h in repo.state.reveals and (step or not (
                    a.get("with_key") and not repo.state.reveals[h].get("dek"))):
                return {"target": self._entry(h), "unchanged": True}
            if repo.entry(h)["kind"] == "activity":
                from provena.core import builders

                private = builders.open_entry_fields(repo.state, proj.agent, repo.entry(h))
                with repo.writing():
                    r = repo.append(builders.reveal_activity(repo.state, proj.agent, h,
                                                             private))
                return {"reveal": self._entry(r), "target": self._entry(h),
                        "details": repo.state.reveals[h].get("details")}
            r = proj.reveal(h, with_key=bool(a.get("with_key")), with_name=True)
            return {"reveal": self._entry(r), "target": self._entry(h)}
        if name == "log":
            order = repo.state.order[-int(a.get("limit") or 50):]
            return {"entries": [self._entry(h) for h in order]}
        if name == "prove":
            out = self._bundle_path(a["output"], write=True)
            for ref in a.get("open", []):
                if repo.entry(proj.resolve(ref))["kind"] == "activity":
                    raise ToolError("E_INPUT", f"{ref} is a step: open it on the ledger with "
                                    f"the reveal tool, then prove it")
            bundle = proj.prove(a["refs"], out, full=bool(a.get("full")),
                                open=a.get("open", []))
            return {"bundle": str(out), "targets": bundle["targets"],
                    "head": bundle["head"], "mode": bundle["mode"]}
        if name == "verify":
            v = sdk_verify(self._bundle_path(a["bundle"], write=False), require=a.get("require"))
            return {k: v[k] for k in ("valid", "accepted", "trust", "require", "entries",
                                      "preregistration", "evidence", "errors", "notes")}
        if name == "push":
            r = proj.push()
            return {"pushed": r.pushed, "blobs_up": r.blobs_up, "head": r.head}
        if name == "pull":
            r = proj.pull()
            return {"pulled": r.pulled, "blobs_down": r.blobs_down, "head": r.head}
        raise KeyError(name)

    # -- JSON-RPC ---------------------------------------------------------------------------

    def handle(self, msg: dict) -> dict | None:
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:  # a notification (initialized, cancelled …): no reply
            return None
        try:
            if method == "initialize":
                asked = (msg.get("params") or {}).get("protocolVersion")
                return _ok(mid, {"protocolVersion": asked if asked in PROTOCOLS else
                                 PROTOCOLS[0],
                                 "capabilities": {"tools": {"listChanged": False}},
                                 "serverInfo": {"name": "provena", "version": __version__},
                                 "instructions": INSTRUCTIONS})
            if method == "ping":
                return _ok(mid, {})
            if method == "tools/list":
                return _ok(mid, {"tools": [{"name": n, "description": d, "inputSchema": s}
                                           for n, (d, s) in TOOLS.items()]})
            if method == "tools/call":
                params = msg.get("params") or {}
                name, args = params.get("name"), params.get("arguments") or {}
                if name not in TOOLS:
                    return _err(mid, -32602, f"unknown tool {name!r}")
                return _ok(mid, self._tool(name, args))
            return _err(mid, -32601, f"method not found: {method}")
        except Exception as exc:  # noqa: BLE001 — a protocol error must not kill the server
            return _err(mid, -32603, f"{type(exc).__name__}: {exc}")

    def _tool(self, name: str, args: dict) -> dict:
        try:
            _check_args(TOOLS[name][1], args)
            result = self.call(name, args)
            return {"content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
                    "structuredContent": result, "isError": False}
        except (ProvenaError, OSError, KeyError, TypeError, ValueError) as exc:
            # a tool error the model can read and act on (MCP: isError, not a protocol error),
            # with the CLI contract's codes (docs/spec/cli-contract-v1.md)
            code, hint = _error_code(exc)
            error = {"code": code, "message": str(exc), "hint": hint,
                     "error": type(exc).__name__}
            return {"content": [{"type": "text", "text": json.dumps(error)}],
                    "structuredContent": error, "isError": True}


class ToolError(ProvenaError):
    def __init__(self, code: str, message: str, hint: str | None = None):
        super().__init__(message)
        self.error, self.hint = code, hint


_TYPES = {"string": str, "integer": int, "boolean": bool, "object": dict, "array": list}


def _check_args(schema: dict, args) -> None:
    """The declared input schema, enforced: unknown or mistyped arguments are errors, so a
    misspelled `outputs` cannot quietly leave a file out of the record."""
    if not isinstance(args, dict):
        raise ToolError("E_USAGE", "arguments must be an object")
    props = schema.get("properties", {})
    unknown = sorted(set(args) - set(props))
    if unknown:
        raise ToolError("E_USAGE", f"unknown argument(s) {unknown}; accepted: {sorted(props)}")
    missing = [k for k in schema.get("required", []) if k not in args]
    if missing:
        raise ToolError("E_USAGE", f"missing argument(s) {missing}")
    for k, v in args.items():
        want = props[k].get("type")
        typ = _TYPES.get(want)
        if typ and (not isinstance(v, typ) or (typ is int and isinstance(v, bool))):
            raise ToolError("E_USAGE", f"{k} must be {want}")
        if want == "array" and props[k].get("items", {}).get("type") == "string" and \
                not all(isinstance(x, str) for x in v):
            raise ToolError("E_USAGE", f"{k} must be a list of strings (entry hashes or paths)")
        if "enum" in props[k] and v not in props[k]["enum"]:
            raise ToolError("E_USAGE", f"{k} must be one of {props[k]['enum']}")


def _error_code(exc: Exception) -> tuple[str, str | None]:
    from provena.sdk.sync import SyncIncomplete, SyncIntegrityError
    from provena.store.repo import RefNotFound, RepoCorrupt

    if isinstance(exc, ToolError):
        return exc.error, exc.hint
    if isinstance(exc, SyncIntegrityError | SyncIncomplete):
        return exc.error, None
    if isinstance(exc, RefNotFound | FileNotFoundError):
        return "E_NOT_FOUND", "the log tool lists entries; paths are relative to the project"
    if isinstance(exc, RepoCorrupt):
        return "E_CORRUPT", None
    from provena.client.hub import HubError

    if isinstance(exc, HubError):
        return {401: "E_FORBIDDEN", 403: "E_FORBIDDEN", 409: "E_CONFLICT"}.get(
            exc.status, "E_HUB"), None
    return "E_INPUT", None


def _is_bundle(path: Path) -> bool:
    try:
        return json.loads(path.read_text()).get("format", "").startswith("provena-bundle/")
    except (OSError, ValueError, AttributeError):
        return False


def _ok(mid, result) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _sha(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def open_project(path: str | Path, agent: str | None = None,
                 passphrase_file: str | None = None) -> Project:
    repo = Repo.find(Path(path))
    name = agent or repo.config["agent"]
    if passphrase_file:  # same rules as PROVENA_PASSPHRASE_FILE (mode 600)
        import os

        os.environ["PROVENA_PASSPHRASE_FILE"] = passphrase_file
    secret = read_secret("Provena key passphrase", env="PROVENA_PASSPHRASE", name=name)
    return Project(repo, Home().load_agent(name, secret), name)


def serve(project: Project, stdin=None, stdout=None) -> None:
    """Read JSON-RPC messages, one per line, until stdin closes."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    server = Server(project)
    for line in stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            reply = _err(None, -32700, "parse error")
        else:
            reply = server.handle(msg) if isinstance(msg, dict) else _err(None, -32600,
                                                                           "invalid request")
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()


def main(project_dir: str, agent: str | None = None, passphrase_file: str | None = None) -> int:
    try:
        project = open_project(project_dir, agent, passphrase_file)
    except Exception as exc:  # noqa: BLE001 — reported to the MCP host's log (stderr)
        print(f"provena mcp: cannot open {project_dir}: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 4
    print(f"provena mcp: project {project.id} as {project.agent.id} (started "
          f"{time.strftime('%H:%M:%S')})", file=sys.stderr, flush=True)
    serve(project)
    return 0
