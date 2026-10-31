from __future__ import annotations

import hashlib
import json
import os
import platform
import time
import traceback
from contextlib import contextmanager
from pathlib import Path

from provena import __version__
from provena.core import builders, prov
from provena.core.bundle import make_bundle
from provena.core.errors import ProvenaError
from provena.core.keys import AgentKey
from provena.core.treehead import make_head
from provena.sdk import sync
from provena.store.home import Home
from provena.store.repo import Repo


def init(path: str | Path, *, name: str | None = None, agent: str = "default",
         passphrase: str | None = None, kind: str = "software", public: bool = False,
         hub: str | None = None) -> Project:
    """A new project in *path* (and the agent key, if it does not exist yet): everything an
    integration needs without the CLI. The passphrase comes from *passphrase* or the usual
    PROVENA_PASSPHRASE_FILE / PROVENA_PASSPHRASE."""
    from provena.store.secrets import read_secret

    home = Home()
    secret = passphrase if passphrase is not None else read_secret(
        "Provena key passphrase", env="PROVENA_PASSPHRASE", name=agent)
    key = home.load_agent(agent, secret) if home.has_agent(agent) else \
        home.create_agent(agent, secret, kind, agent, scrypt_n=int(
            os.environ.get("PROVENA_SCRYPT_N", 2**15)))
    root = Path(path)
    root.mkdir(parents=True, exist_ok=True)
    genesis, _ = builders.new_project(key, home.card(agent), name=name or root.name,
                                      visibility="public" if public else "private")
    project = Project(Repo.init(root.resolve(), agent, genesis), key, agent)
    if hub:
        card = sync.pin_hub(project.repo, hub, sync.make_client(hub, None))
        home.set_trust("logs", card["id"])
    return project


def open(path: str | Path = ".", *, agent: str | None = None,  # noqa: A001 (module API)
         passphrase: str | None = None) -> Project:
    """Open the repository containing *path* with the named agent key."""
    repo = Repo.find(Path(path))
    name = agent or repo.config["agent"]
    if passphrase is None:
        from provena.store.secrets import read_secret

        passphrase = read_secret("Provena key passphrase", env="PROVENA_PASSPHRASE", name=name)
    secret = passphrase
    return Project(repo, Home().load_agent(name, secret), name)


class Run:
    """Collects the outputs of one activity; see Project.run."""

    def __init__(self, project: Project):
        self.project = project
        self.outputs: list[str] = []
        self.traces: list[str] = []
        self.activity: str | None = None

    def output(self, path: str | Path, *, media_type: str | None = None) -> str:
        # always a new entry: this step produced it, even if the bytes match an earlier file
        h = self.project.add(path, media_type=media_type, force=True)
        self.outputs.append(h)
        return h

    def trace(self, content: str | bytes, *, name: str | None = None) -> str:
        """Record an AI agent's transcript (prompts, tool calls, outputs) as an encrypted output
        of this step. It stays sealed like any entity; reveal it to let others audit the run."""
        data = content.encode() if isinstance(content, str) else content
        folder = self.project.repo.root / "traces"
        folder.mkdir(exist_ok=True)
        path = folder / (name or f"trace-{int(time.time() * 1000)}.jsonl")
        path.write_bytes(data)
        h = self.output(path, media_type="application/x-provena-trace")
        self.traces.append(h)
        return h


class Project:
    def __init__(self, repo: Repo, agent: AgentKey, agent_name: str):
        self.repo, self.agent, self.agent_name = repo, agent, agent_name
        repo.reader = agent

    @property
    def id(self) -> str:
        return self.repo.state.project

    def resolve(self, ref: str) -> str:
        return self.repo.resolve(ref)

    # -- writing ---------------------------------------------------------------------------

    def _register(self, path: Path, kind: str, *, media_type=None, title=None, refs=(),
                  capture: dict | None = None) -> str:
        repo = self.repo
        repo.checked_relpath(path)  # before any work
        with repo.writing():  # other processes may write to this project too
            state = repo.state
            body, secrets, size = repo.encrypt_file(self.agent, path)
            if capture is not None:
                body["capture"] = capture  # public, instrument-clock metadata (self-reported)
            rel = repo.checked_relpath(path)
            if kind == "plan":
                entry = builders.plan(state, self.agent, body, secrets, title=title or rel,
                                      refs=refs)
            else:
                entry = builders.entity(state, self.agent, body, secrets, name=rel,
                                        plain_size=size, media_type=media_type, refs=refs)
            h = repo.append(entry)
            repo.track(rel, h, secrets.plain_sha256)
        return h

    def path(self, path: str | Path) -> Path:
        """A relative path is taken from the working directory if it exists there, else from
        the project root (agents often run outside the project directory)."""
        p = Path(path)
        return p if p.is_absolute() or p.exists() else self.repo.root / p

    def _same(self, path: Path, kind: str) -> str | None:
        """The entry this agent already recorded for *path* with this exact content."""
        rec = self.repo.tracked.get(self.repo.checked_relpath(path))
        e = self.repo.state.entries.get(rec["entry"]) if rec else None
        if e and e["kind"] == kind and e["author"] == self.agent.id:
            import hashlib

            h = hashlib.sha256(path.read_bytes()).hexdigest()
            if h == rec["sha256"]:
                return rec["entry"]
        return None

    def add(self, path: str | Path, *, media_type: str | None = None, refs=(),
            capture: dict | None = None, force: bool = False) -> str:
        """Encrypt, commit to and register a data file. Returns its entry hash; a file this
        agent already recorded with the same content returns that entry (retries are safe;
        *force* records it again).

        *refs* links earlier entries (e.g. the previous version of this file); *capture* is
        public capture metadata written by `provena capture` (see docs/design/attested-capture.md).
        """
        path = self.path(path)
        if not (force or refs or capture) and (same := self._same(path, "entity")):
            return same
        return self._register(path, "entity", media_type=media_type,
                              refs=[self._ref(r) for r in refs], capture=capture)

    def plan(self, path: str | Path, *, title: str | None = None, force: bool = False) -> str:
        """Preregister a protocol/analysis plan (content stays sealed until revealed); the
        same content preregistered again returns the earlier entry."""
        path = self.path(path)
        if not force and (same := self._same(path, "plan")):
            return same
        return self._register(path, "plan", title=title)

    def plan_text(self, text: str, name: str, *, title: str | None = None) -> str:
        """Preregister a plan given as text (written to plans/<name> in the project)."""
        target = self.repo.root / "plans" / name
        target.parent.mkdir(exist_ok=True)
        target.write_text(text)
        return self.plan(target, title=title or name)

    def _ref(self, ref: str) -> str:
        return ref if ref in self.repo.state.entries else self.repo.resolve(str(ref))

    @contextmanager
    def run(self, description: str, *, plan: str | None = None, used=(),
            params: dict | None = None, model: str | None = None,
            harness: str | Path | None = None, external=()):
        """Record a process step. Outputs registered via run.output() become `generated`;
        the activity is appended on exit, including when the block raises.

        For AI agents: *model* names the model (provider/model-id or a weights hash) and
        *harness* is the agent program, whose sha256 is recorded; run.trace() keeps the
        transcript. All of it is sealed with the project key."""
        used_refs = [self._ref(u) for u in used]
        plan_ref = self._ref(plan) if plan else None
        params = _storable(params or {}, "params")  # fails before the tool runs, not after
        run = Run(self)
        started = int(time.time() * 1000)
        error = None
        try:
            yield run
        except BaseException as exc:
            error = exc
            raise
        finally:
            try:
                self._record_run(run, description, used_refs, plan_ref, params, model, harness,
                                 external, started, error)
            except Exception as exc:
                if error is None:
                    raise
                # never replace the tool's own exception with a recording failure
                error.add_note(f"provena: this step could not be recorded: {exc}")

    def _record_run(self, run, description, used_refs, plan_ref, params, model, harness,
                    external, started, error) -> None:
        details = {
            "command": [description], "exit_code": 0 if error is None else 1,
            "started": started, "ended": int(time.time() * 1000),
            "params": params,
            "env": {"python": platform.python_version(), "platform": platform.platform(),
                    "provena": __version__, "agent": self.agent_name},
        }
        if model is not None:
            details["model"] = model
        if harness is not None:
            details["harness_sha256"] = hashlib.sha256(Path(harness).read_bytes()).hexdigest()
        if run.traces:
            details["traces"] = run.traces
        if error is not None:
            details["error"] = "".join(
                traceback.format_exception_only(type(error), error)).strip()
        if not (used_refs or run.outputs or external):
            # a step without files (a model call, a search) is recorded through a sealed
            # summary of the call, so it still appears on the ledger
            run.trace(json.dumps({"description": description, "params": params,
                                  "model": model, "error": details.get("error")},
                                 sort_keys=True), name=f"step-{started}-{os.getpid()}.json")
            details["traces"] = run.traces
        with self.repo.writing():
            run.activity = self.repo.append(builders.activity(
                self.repo.state, self.agent, used=used_refs, generated=run.outputs,
                plan_ref=plan_ref, details=details, external=external))

    def record(self, tool: str, args: dict | None = None, result=None, *, used=(),
               outputs=(), error: str | None = None, exit_code: int | None = None,
               model: str | None = None, trace: str | bytes | None = None,
               plan: str | None = None, started: int | None = None,
               ended: int | None = None) -> dict:
        """Record one tool call or step that already happened (an AI agent's model call, a web
        search, a script): one call, one activity, even without files.

        *args* are normalized like run(params=); *result* and *error* are sealed in a trace
        entity together with *trace* (the transcript), never in the public body. *used* are
        entries or recorded paths, *outputs* files to register as this step's outputs.
        Returns {"activity", "outputs", "trace", "status"} with complete hashes."""
        params = _storable(args or {}, "args")
        used_refs = [self._ref(u) for u in used]
        plan_ref = self._ref(plan) if plan else None
        now = int(time.time() * 1000)
        code = exit_code if exit_code is not None else (1 if error else 0)
        run = Run(self)
        for path in outputs:
            run.output(self.path(path))
        sealed = {"tool": tool, "args": params, "result": _storable(result, "result"),
                  "error": error}
        if trace is not None:
            sealed["transcript"] = trace.decode() if isinstance(trace, bytes) else trace
        run.trace(json.dumps(sealed, sort_keys=True), name=f"call-{now}-{os.getpid()}-"
                  f"{len(self.repo.state.order)}.json")
        details = {"command": [tool], "exit_code": code, "params": params,
                   "started": started or now, "ended": ended or now, "traces": run.traces,
                   "env": {"provena": __version__, "agent": self.agent_name}}
        if model is not None:
            details["model"] = model
        if error is not None:
            details["error"] = error
        with self.repo.writing():
            run.activity = self.repo.append(builders.activity(
                self.repo.state, self.agent, used=used_refs, generated=run.outputs,
                plan_ref=plan_ref, details=details))
        return {"activity": run.activity, "outputs": run.outputs[:-1] if run.traces else
                run.outputs, "trace": run.traces[-1],
                "status": self.repo.entry(run.activity)["body"].get("status")}

    def attest(self, target: str, *, type: str, verdict: str | None = None,  # noqa: A002
               note: str | None = None) -> str:
        with self.repo.writing():
            return self.repo.append(builders.attest(self.repo.state, self.agent, self._ref(target),
                                                    type=type, verdict=verdict, note=note))

    def reveal(self, target: str, *, with_key: bool = False, with_name: bool = False) -> str:
        h = self._ref(target)
        private = builders.open_entry_fields(self.repo.state, self.agent, self.repo.entry(h))
        dek = self.repo.blob_dek(self.agent, h) if with_key else None
        name = (private.get("name") or private.get("title")) if with_name else None
        with self.repo.writing():
            return self.repo.append(builders.reveal(
                self.repo.state, self.agent, h, salt=bytes.fromhex(private["salt"]),
                plain_sha256=bytes.fromhex(private["plain_sha256"]), dek=dek, name=name))

    def share(self, target: str, card: dict) -> str:
        """Grant one non-member (their agent card) access to one entry's content."""
        h = self._ref(target)
        private = builders.open_entry_fields(self.repo.state, self.agent, self.repo.entry(h))
        with self.repo.writing():
            return self.repo.append(builders.grant(
                self.repo.state, self.agent, h, card, dek=self.repo.blob_dek(self.agent, h),
                salt=bytes.fromhex(private["salt"]),
                plain_sha256=bytes.fromhex(private["plain_sha256"]),
                name=private.get("name") or private.get("title") or h[:12]))

    # -- reading and proving -----------------------------------------------------------------

    def read(self, target: str) -> bytes:
        from provena.core import aead

        h = self._ref(target)
        cid = self.repo.entry(h)["body"]["cid"]
        return aead.decrypt_bytes(self.repo.blob_dek(self.agent, h),
                                  self.repo.blob_path(cid).read_bytes())

    def details(self, target: str) -> dict | None:
        h = self._ref(target)
        return builders.open_entry_fields(self.repo.state, self.agent, self.repo.entry(h))

    def log(self) -> list[dict]:
        state = self.repo.state
        out = []
        for i, h in enumerate(state.order):
            e = state.entries[h]
            try:
                private = builders.open_entry_fields(state, self.agent, e)
            except Exception:  # sealed under an epoch this agent cannot read
                private = None
            out.append({"index": i, "hash": h, "kind": e["kind"], "author": e["author"],
                        "ts": e["ts"], "private": private})
        return out

    def prove(self, targets, out: str | Path | None = None, *, full: bool = False,
              open=(), external=()) -> dict:  # noqa: A002  (mirrors the CLI's --open)
        """*external*: bundles (dicts) of other projects proving entries your activities cite."""
        targets = [self._ref(t) for t in targets]
        needed = max(self.repo.entry_index(t) for t in targets) + 1
        heads = [h for h in self.repo.heads() if needed <= h["head"]["size"]
                 <= len(self.repo.state.order)]
        if heads:
            chosen = max(heads, key=lambda h: (h["signer_card"]["kind"] == "hub",
                                               h["head"]["size"]))
        else:
            chosen = {"head": make_head(self.agent, self.id, self.repo.leaves()),
                      "signer_card": Home().card(self.agent_name)}
            self.repo.add_head(chosen["head"], chosen["signer_card"])
        openings = {}
        for ref in open:
            if self.repo.entry(self._ref(ref))["kind"] == "activity":
                raise ProvenaError(f"{ref} is a step: open it on the ledger with "
                                   f"Project.reveal(), then prove it")
            private = self.details(ref)
            openings[self._ref(ref)] = {"salt": private["salt"],
                                        "plain_sha256": private["plain_sha256"]}
        bundle = make_bundle(self.repo.log(), chosen["head"], chosen["signer_card"], targets,
                             mode="full" if full else "selective", openings=openings,
                             external=list(external),
                             **sync.bundle_evidence(self.repo, chosen["head"]))
        if out is not None:
            Path(out).write_text(json.dumps(bundle, indent=1))
        return bundle

    def export_prov(self, *, include_private: bool = False) -> dict:
        private = {}
        if include_private:
            private = {row["hash"]: row["private"] for row in self.log() if row["private"]}
        return prov.to_prov(self.repo.state, private)

    # -- hub ---------------------------------------------------------------------------------

    def _client(self):
        url = self.repo.config.get("hub")
        if not url:
            raise ValueError("no hub configured (provena remote <url>)")
        return sync.make_client(url, self.agent)  # the one factory (tests swap the transport)

    def push(self, client=None):
        """Push; raises sync.SyncIncomplete (E_STRANDED) when own entries were set aside."""
        return _complete(sync.push(self.repo, client or self._client(), agent=self.agent))

    def pull(self, client=None):
        return _complete(sync.pull(self.repo, client or self._client(), agent=self.agent))


def _complete(result):
    if result.stranded:
        raise sync.SyncIncomplete(
            f"{result.stranded} of your entries no longer apply on the hub's log and were set "
            f"aside (stranded.jsonl); `provena stranded redo` records their files again",
            "E_STRANDED")
    return result


def _storable(value, where: str):
    """Signed entries carry no floats (canonical JSON, ADR 0002): floats become their exact
    decimal text, paths and tuples their plain forms; anything else is refused up front."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value if -(2**53) < value < 2**53 else str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError(f"{where}: keys must be strings, got {k!r}")
            out[k] = _storable(v, f"{where}.{k}")
        return out
    if isinstance(value, list | tuple):
        return [_storable(v, f"{where}[{i}]") for i, v in enumerate(value)]
    raise TypeError(f"{where}: cannot record a {type(value).__name__}; pass str/int/float/"
                    f"bool/None, lists or dicts of them")
