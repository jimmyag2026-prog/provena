"""Commands that write or read the local ledger."""

from __future__ import annotations

import json
import os
import platform
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from provena import __version__
from provena.cli import output, sandbox
from provena.cli.common import (
    EXIT_STATE,
    CliError,
    _agent_name,
    _challenge_guard,
    _decrypt_to,
    _file_sha256,
    _hub_client,
    _load_agent,
    _openable,
    _outputs,
    _passphrase,
    _register_file,
    _safe_relpath,
    _short,
    _summary,
    _when,
)
from provena.core import aead, builders
from provena.core.errors import DecryptionError, ProvenaError
from provena.core.keys import verify_card
from provena.store.home import Home, home_dir
from provena.store.repo import Repo


def cmd_keygen(args):
    home, name = Home(), args.name or _agent_name(args)
    n = int(os.environ.get("PROVENA_SCRYPT_N", 2**15))
    agent = home.create_agent(name, _passphrase(confirm=True, name=name), args.kind,
                              args.display, scrypt_n=n)
    print(f"created agent {name}: {agent.id}")
    print(f"card: {home.card_path(name)}")
    output.data(agent={"name": name, "id": agent.id, "kind": args.kind},
                card_path=str(home.card_path(name)))

def cmd_card(args):
    name = _agent_name(args)
    if not Home().has_agent(name):
        raise CliError(f"no agent named {name!r}", error="E_NOT_FOUND",
                       hint=f"provena --agent {name} keygen")
    card = Home().card(name)
    print(json.dumps(card, indent=2))
    output.data(card=card)

def cmd_init(args):
    root = Path(args.path).resolve()
    name = _agent_name(args)
    agent = _load_agent(args)
    genesis, _ = builders.new_project(agent, Home().card(name),
                                      visibility="public" if args.public else "private",
                                      witnesses=args.witnesses, name=args.name or root.name)
    repo = Repo.init(root, name, genesis)
    print(f"initialized project {repo.config['project']} in {repo.dir}")
    output.data(project=repo.config["project"], path=str(root), agent=name,
                agent_id=agent.id, visibility="public" if args.public else "private")

def cmd_add(args):
    repo = Repo.find()
    names = [repo.checked_relpath(p) for p in args.files]  # all checked before any is added
    agent = _load_agent(args, repo)
    recorded = []
    for p, name in zip(args.files, names, strict=True):
        h, unchanged = (None, False) if args.force else _unchanged(repo, name, Path(p),
                                                                    agent.id)
        if not unchanged:
            h = _register_file(repo, agent, Path(p), media_type=args.media_type)
        print(f"entity {_short(h)}  {name}" + ("  (unchanged, already recorded)" if unchanged
                                              else ""), flush=True)  # a killed batch shows
        recorded.append({**output.entry_ref(repo, h, name), "unchanged": unchanged})
        output.item(recorded[-1])
    output.data(entries=recorded)


def _unchanged(repo: Repo, name: str, path: Path, author: str) -> tuple[str | None, bool]:
    """Retries are safe: a file this agent already recorded with this content is not
    recorded again (someone else's entry is not yours: that goes through the usual rules)."""
    rec = repo.tracked.get(name)
    e = repo.state.entries.get(rec["entry"]) if rec else None
    if e and e["author"] == author and _file_sha256(path).hex() == rec["sha256"]:
        return rec["entry"], True
    return None, False

def cmd_plan(args):
    repo = Repo.find()
    repo.checked_relpath(args.file)
    agent = _load_agent(args, repo)
    name = repo.checked_relpath(args.file)
    h, unchanged = (None, False) if args.force else _unchanged(repo, name, Path(args.file),
                                                                agent.id)
    if unchanged and repo.entry(h)["kind"] != "plan":
        h, unchanged = None, False
    if not unchanged:
        h = _register_file(repo, agent, Path(args.file), kind="plan", title=args.title)
    print(f"plan {_short(h)}  {name} " + ("(unchanged, already preregistered)" if unchanged
                                         else "(committed; content stays sealed)"))
    output.data(entry={**output.entry_ref(repo, h, name), "unchanged": unchanged})

def cmd_run(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    if not args.command:
        raise CliError("usage: provena run [options] -- <command> ...")
    external = []
    for spec in args.external:
        pid, _, entry_ref = spec.partition(":")
        if not (len(pid) == 64 and len(entry_ref) == 64):
            raise CliError("--external takes PROJECT:ENTRY (full hashes)")
        external.append((pid, entry_ref))
    used = []
    inputs = [*args.used, *([] if args.no_auto_inputs else _code_args(repo, args.command))]
    for ref in inputs:
        path = Path(ref)
        if not path.exists():  # an entry reference rather than a file
            used.append(repo.resolve(ref))
            continue
        for f in _outputs([ref], repo.root):  # a directory stands for the files in it
            h = _current_entry(repo, agent, f)
            if h not in used:
                used.append(h)
    plan_ref = repo.resolve(args.plan) if args.plan else None
    before = {f: _file_sha256(f) for f in _outputs(args.out, repo.root) if f.exists()}
    # a step with no declared inputs may still produce nothing we can see: keep its output as
    # a sealed transcript, so every executed command is on the ledger (failures included)
    # (only when nothing at all is declared: a step with --out keeps its terminal)
    transcript = None if used or external or args.out else repo.root / "transcripts" / \
        f"run-{int(time.time() * 1000)}.log"
    started = int(time.time() * 1000)
    proc = _execute(args.command, transcript)
    ended = int(time.time() * 1000)
    generated = []
    named = {Path(p).resolve() for p in args.out if not Path(p).is_dir()}
    for f in _outputs(args.out, repo.root):
        # a directory's unchanged files are not this step's outputs; files named one by one are
        if not f.exists() or (f in before and _file_sha256(f) == before[f]
                              and f.resolve() not in named):
            continue
        generated.append(_register_file(repo, agent, f))
    if transcript is not None:
        if generated:
            transcript.unlink(missing_ok=True)
        else:
            generated.append(_register_file(repo, agent, transcript))
    elif not (used or external or generated):
        # --out was declared but nothing appeared there: record that the command ran
        note = repo.root / "transcripts" / f"run-{started}.log"
        note.parent.mkdir(exist_ok=True)
        note.write_text(json.dumps({"command": args.command, "exit_code": proc.returncode,
                                    "outputs": "none appeared in " + ", ".join(args.out)}))
        generated.append(_register_file(repo, agent, note))
    details = {"command": args.command, "exit_code": proc.returncode, "started": started,
               "ended": ended, "cwd": repo.relpath(Path.cwd()),
               "env": {"python": platform.python_version(), "platform": platform.platform(),
                       "provena": __version__}}
    with repo.writing():
        h = repo.append(builders.activity(repo.state, agent, used=used, generated=generated,
                                          plan_ref=plan_ref, details=details, external=external))
    print(f"activity {_short(h)}  exit={proc.returncode}  used={len(used)} "
          f"generated={len(generated)}", file=sys.stderr if output.json_mode() else sys.stdout)
    names = {v["entry"]: k for k, v in repo.tracked.items()}
    output.data(activity=output.entry_ref(repo, h), exit_code=proc.returncode,
                status=repo.entry(h)["body"].get("status"),
                used=[output.entry_ref(repo, u, names.get(u)) for u in used],
                generated=[output.entry_ref(repo, g, names.get(g)) for g in generated],
                transcript=repo.relpath(transcript) if transcript and transcript.exists()
                else None)
    missing_out = [o for o in args.out if not Path(o).exists()]
    if missing_out:
        output.warn("W_NO_OUTPUT", f"declared outputs that never appeared: {missing_out}")
    if proc.returncode != 0:
        print("note: the failed run is recorded too — the ledger keeps negative results.")
        output.error("E_PROGRAM", f"the program exited {proc.returncode} (the step is "
                     f"recorded as failed)")
    return proc.returncode

def _execute(command: list[str], transcript: Path | None) -> subprocess.CompletedProcess:
    """Run *command*; with a *transcript*, its stdout and stderr are also copied there."""
    if transcript is None:  # with --json, stdout carries only the envelope (contract §1)
        return subprocess.run(command, stdout=2 if output.json_mode() else None)
    import threading

    transcript.parent.mkdir(exist_ok=True)
    with open(transcript, "wb") as log:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lock = threading.Lock()

        def pump(src, dst):
            for chunk in iter(lambda: src.read1(65536), b""):
                with lock:
                    log.write(chunk)
                if dst is not None:
                    if output.json_mode() and dst is not sys.stderr.buffer:
                        dst = sys.stderr.buffer
                    try:
                        dst.write(chunk)
                        dst.flush()
                    except (BrokenPipeError, ValueError):  # our reader went away: keep
                        dst = None                          # draining, or the child blocks

        threads = [threading.Thread(target=pump, args=(proc.stdout, sys.stdout.buffer)),
                   threading.Thread(target=pump, args=(proc.stderr, sys.stderr.buffer))]
        for t in threads:
            t.start()
        code = proc.wait()
        for t in threads:
            t.join()
    return subprocess.CompletedProcess(command, code)


def _current_entry(repo: Repo, agent, path: Path) -> str:
    """The entry for *path* as it is now: the tracked one if unchanged, else a new version."""
    rec = repo.tracked.get(repo.relpath(path))
    if rec and _file_sha256(path).hex() == rec["sha256"]:
        return rec["entry"]
    return _register_file(repo, agent, path)


def _code_args(repo: Repo, command: list[str]) -> list[str]:
    """Files inside the repository named on the command line (e.g. `python fit.py`): recorded
    as inputs so the step can be re-run from the ledger alone."""
    found = []
    for arg in command[1:]:
        path = Path(arg)
        try:
            if path.is_file() and path.resolve().is_relative_to(repo.root.resolve()) \
                    and not path.resolve().is_relative_to(repo.dir.resolve()):
                found.append(arg)
        except (OSError, ValueError):
            continue
    return found


def cmd_rerun(args):
    """Re-execute a recorded `provena run` step in a fresh workspace built from the decrypted
    inputs, and compare every output with the plaintext hash on the ledger."""
    repo = Repo.find()
    agent = _load_agent(args, repo)
    state = repo.state
    act = repo.resolve(args.ref)
    entry = state.entries[act]
    if entry["kind"] != "activity":
        raise CliError("rerun needs an activity entry")
    details = builders.open_entry_fields(state, agent, entry) or {}
    if "cwd" not in details or not details.get("command"):
        raise CliError("this activity was not recorded by `provena run`; nothing to re-execute")
    command, body = details["command"], entry["body"]
    if not (isinstance(command, list) and command
            and all(isinstance(a, str) and a.isprintable() for a in command)):
        raise CliError("recorded command contains control characters; refusing to display or run")
    author = state.members.get(entry["author"])
    who = f"{author.card.get('name') or '(no name)'} [{entry['author']}]" if author else \
        entry["author"]
    print(f"recorded command, written by {who}:\n  {shlex.join(command)}")
    inputs = [builders.open_entry_fields(state, agent, state.entries[u])["name"]
              for u in body.get("used", [])]
    if inputs:
        print("inputs restored into the workspace (they may be code that runs):")
        for name in inputs:
            print(f"  {_safe_relpath(name)}")
    if not args.yes:
        print("re-run executes this command on your machine; pass --yes to proceed")
        return 2
    work = Path(args.workdir or tempfile.mkdtemp(prefix="provena-rerun-")).resolve()
    for u in body.get("used", []):
        private = builders.open_entry_fields(state, agent, state.entries[u])
        _decrypt_to(repo.blob_path(state.entries[u]["body"]["cid"]), repo.blob_dek(agent, u),
                    work / _safe_relpath(private["name"]), private["salt"],
                    private["plain_sha256"], state.entries[u]["body"]["commitment"])
    cwd = work if details["cwd"] in (".", "") else work / _safe_relpath(details["cwd"])
    cwd.mkdir(parents=True, exist_ok=True)
    for g in body.get("generated", []):  # output folders existed when the step first ran
        name = builders.open_entry_fields(state, agent, state.entries[g])["name"]
        (work / _safe_relpath(name)).parent.mkdir(parents=True, exist_ok=True)
    # The child must not inherit our key passphrase or other Provena settings.
    env = {k: v for k, v in os.environ.items() if not k.startswith("PROVENA_")}
    if args.sandbox == "off":
        code = subprocess.run(command, cwd=cwd, timeout=args.timeout, env=env).returncode
    else:  # no network, no keys, no home directory or repository, writes only to the workspace
        code = sandbox.run_untrusted(command, work=work, cwd=cwd, env=env, check=False,
                                     timeout=args.timeout, mode=args.sandbox,
                                     deny_read=[home_dir(), repo.dir, repo.root])
    rows, ok = [], code == details.get("exit_code")
    for g in body.get("generated", []):
        private = builders.open_entry_fields(state, agent, state.entries[g])
        path = work / _safe_relpath(private["name"])
        if not path.exists():
            rows.append(("missing", private["name"]))
            ok = False
        elif _file_sha256(path).hex() == private["plain_sha256"]:
            rows.append(("match", private["name"]))
        else:
            rows.append(("DIFFERS", private["name"]))
            ok = False
    print(f"exit code {code} (recorded {details.get('exit_code')})")
    for status, name in rows:
        print(f"  {status:<8} {name}")
    verdict = "pass" if ok else "fail"
    print(f"replication {verdict.upper()} · workspace {work}")
    if args.attest:
        note = "; ".join(f"{n}: {st}" for st, n in rows) + f"; exit {code}"
        with repo.writing():
            h = repo.append(builders.attest(repo.state, agent, act, type="replicate",
                                            verdict=verdict, note=f"provena rerun: {note}"))
        print(f"recorded replicate attestation {_short(h)}")
    return 0 if ok else 1

def cmd_log(args):
    repo = Repo.find()
    agent = None if args.no_decrypt else _load_agent(args, repo)
    state = repo.state
    if args.json:
        print(json.dumps([state.entries[h] for h in state.order], indent=2))
        return
    for i, h in enumerate(state.order):
        e = state.entries[h]
        flags = ("R" if h in state.reveals else " ") + ("X" if h in state.redacted else " ")
        print(f"{i:>4} {_short(h)} {flags} {e['kind']:<8} {_short(e['author'], 16)} "
              f"{_when(e['ts'])}  {_summary(repo, agent, e)}")
    if output.json_mode():
        names = {v["entry"]: k for k, v in repo.tracked.items()}
        if agent is not None:  # entries of other members carry their (sealed) names too
            for h in state.order:
                if h not in names and state.entries[h]["kind"] in ("entity", "plan"):
                    try:
                        private = builders.open_entry_fields(state, agent, state.entries[h])
                        names[h] = (private or {}).get("name") or (private or {}).get("title")
                    except Exception:  # noqa: BLE001 — an epoch this key cannot read
                        pass
        output.data(project=state.project, entries=[
            {"hash": h, "index": i, "kind": state.entries[h]["kind"],
             "author": state.entries[h]["author"], "ts": state.entries[h]["ts"],
             "path": names.get(h), "revealed": h in state.reveals,
             "redacted": h in state.redacted, "synced": i < repo.config.get("synced", 0),
             "body": state.entries[h]["body"]} for i, h in enumerate(state.order)])

def cmd_show(args):
    repo = Repo.find()
    h = repo.resolve(args.ref)
    entry = repo.entry(h)
    out = {"hash": h, "index": repo.entry_index(h), "entry": entry}
    if not args.no_decrypt:
        agent = _load_agent(args, repo)
        out["sealed_fields"] = builders.open_entry_fields(repo.state, agent, entry)
    out["reveal"] = repo.state.reveals.get(h)
    out["attestations"] = repo.state.attestations.get(h, [])
    out["redacted"] = h in repo.state.redacted
    print(json.dumps(out, indent=2))
    output.data(**out)

def cmd_cat(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    h = repo.resolve(args.ref)
    cid = repo.entry(h)["body"].get("cid")
    if not cid or not repo.has_blob(cid):
        raise CliError("no local content for this entry")
    dek = repo.blob_dek(agent, h)
    with open(repo.blob_path(cid), "rb") as src:
        if args.output:
            with open(args.output, "wb") as dst:
                aead.decrypt_stream(dek, src, dst)
        else:
            aead.decrypt_stream(dek, src, sys.stdout.buffer)

def cmd_status(args):
    repo = Repo.find()
    changes = []
    for rel, rec in sorted(repo.tracked.items()):
        path = repo.root / rel
        if not path.exists():
            print(f"  deleted   {rel}")
            changes.append({"path": rel, "state": "deleted", "entry": rec["entry"]})
        elif _file_sha256(path).hex() != rec["sha256"]:
            print(f"  modified  {rel}  (registered {_short(rec['entry'])})")
            changes.append({"path": rel, "state": "modified", "entry": rec["entry"]})
    changed = len(changes)
    output.data(changes=changes)
    print("clean" if not changed else f"{changed} tracked file(s) differ from the ledger")
    synced = repo.config.get("synced", 0)
    mirrored = len(repo.config.get("mirror_pending", []))
    output.data(project=repo.state.project, agent=repo.config["agent"], changed=changed,
                hub=repo.config.get("hub"), entries=len(repo.state.order), synced=synced,
                unpushed=len(repo.state.order) - synced - mirrored if repo.config.get("hub")
                else None, provisional=mirrored,
                push_incomplete=bool(repo.config.get("push_incomplete")),
                stranded=len(_stranded(repo)),
                read_only_mirror_clone=bool(repo.config.get("primary")))
    if repo.config.get("hub"):
        mirrored = len(repo.config.get("mirror_pending", []))
        pending = len(repo.state.order) - repo.config.get("synced", 0) - mirrored
        print(f"hub {repo.config['hub']}: " + (f"{pending} entr{'y' if pending == 1 else 'ies'} "
                                                 "not pushed yet" if pending else "in sync"))
        if mirrored:
            print(f"{mirrored} entr{'y' if mirrored == 1 else 'ies'} read from a mirror, "
                  "provisional until `provena pull` from the hub confirms them")
        if repo.config.get("push_incomplete"):
            print("the last push did not finish (interrupted, throttled or offline): some "
                  "entries or files may not be on the hub — run `provena push`")
        if repo.config.get("primary"):
            print(f"cloned from a mirror: read-only until `provena remote --rehome` "
                  f"(primary {repo.config['primary']['url']})")
    else:
        print("no hub configured: the ledger is local only (`provena remote <url>`)")
    conflicts = repo.config.get("conflicts", [])
    for c in conflicts:
        print(f"  CONFLICT  {c['path']}  yours {c['mine'][:12]} / theirs {c['theirs'][:12]}  "
              f"(`provena resolve {c['path']} --keep <hash>`)")
    output.data(conflicts=conflicts)
    stranded = _stranded(repo)
    if stranded:
        print(f"{len(stranded)} entr{'y' if len(stranded) == 1 else 'ies'} set aside by a sync "
              f"(not on the ledger): `provena stranded list` / `provena stranded redo`")


def _stranded(repo: Repo) -> list[dict]:
    path = repo.dir / "stranded.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def cmd_stranded(args):
    """Entries a pull set aside because they no longer applied on the hub's log. Data files
    and plans can be recorded again (re-encrypted under the current project key)."""
    repo = Repo.find()
    items = _stranded(repo)
    if not items:
        print("nothing set aside")
        return 0
    agent = _load_agent(args, repo)
    rows, privates = [], []
    for e in items:
        try:
            private = builders.open_entry_fields(repo.state, agent, e) or {}
        except Exception:  # noqa: BLE001 — sealed for an epoch we cannot read
            private = {}
        rows.append((e, private.get("name") or private.get("title")))
        privates.append(private)
    if args.action == "list":
        output.data(stranded=[{"hash": Repo.hash_of(e), "kind": e["kind"], "path": name,
                               "redoable": e["kind"] in ("entity", "plan") and bool(name)}
                              for e, name in rows])
        for e, name in rows:
            print(f"{Repo.hash_of(e)[:12]}  {e['kind']:<9} {name or '(sealed)'}")
        return 0
    mapping = []
    left, redone = [], 0
    for (e, name), private in zip(rows, privates, strict=True):
        path = repo.root / name if name else None
        if e["kind"] in ("entity", "plan") and path is not None and path.is_file():
            if _file_sha256(path).hex() != private.get("plain_sha256"):
                output.warn("W_CHANGED", f"{name} changed since it was set aside; recording "
                            f"its current content")
            h = _register_file(repo, agent, path, kind=e["kind"],
                               title=private.get("title") if e["kind"] == "plan" else None,
                               media_type=e["body"].get("media_type"))
            print(f"{e['kind']} {_short(h)}  {name} (recorded again)")
            mapping.append({"old": Repo.hash_of(e), "new": h, "path": name})
            redone += 1
        else:
            left.append(e)
            print(f"cannot redo {Repo.hash_of(e)[:12]} ({e['kind']}"
                  f"{', ' + name + ' is gone' if name and e['kind'] in ('entity', 'plan') else ''}"
                  f"): record it again by hand")
    done = repo.dir / "stranded.done.jsonl"
    with open(done, "a") as f:
        f.writelines(json.dumps(e) + "\n" for e, _ in rows if e not in left)
    (repo.dir / "stranded.jsonl").write_text("".join(json.dumps(e) + "\n" for e in left))
    print(f"{redone} recorded again; `provena push` to send them")
    output.data(redone=mapping, left=[{"hash": Repo.hash_of(e), "kind": e["kind"]}
                                      for e in left])
    if left:
        output.error("E_STRANDED", f"{len(left)} entries need to be recorded by hand")
    return EXIT_STATE if left else 0

def cmd_lineage(args):
    """Print the provenance tree of an entry: generating activity, its inputs and plan, and
    recursively their origins."""
    repo = Repo.find()
    agent = None if args.no_decrypt else _load_agent(args, repo)
    state = repo.state
    generated_by = {g: h for h in state.order if state.entries[h]["kind"] == "activity"
                    for g in state.entries[h]["body"].get("generated", [])}

    def label(h: str) -> str:
        e = state.entries[h]
        extra = _summary(repo, agent, e)
        marks = "".join(f" [{m}]" for m, on in (("revealed", h in state.reveals),
                                                 ("redacted", h in state.redacted)) if on)
        n = len(state.attestations.get(h, []))
        if n:
            marks += f" [{n} attestation(s)]"
        return f"{e['kind']} {_short(h)} #{state.order.index(h)} {extra}".rstrip() + marks

    def walk(h: str, prefix: str, seen: set[str]) -> None:
        act = generated_by.get(h)
        if act is None or act in seen:
            return
        seen.add(act)
        body = state.entries[act]["body"]
        print(f"{prefix}└─ generated by {label(act)}")
        inputs = ([("under", body["plan"])] if body.get("plan") else []) + [
            ("used", u) for u in body.get("used", [])]
        for i, (rel, src) in enumerate(inputs):
            last = i == len(inputs) - 1
            print(f"{prefix}   {'└' if last else '├'}─ {rel} {label(src)}")
            walk(src, prefix + ("      " if last else "   │  "), seen)

    target = repo.resolve(args.ref)
    print(label(target))
    walk(target, "", set())

def cmd_meta(args):
    repo = Repo.find()
    fields = {"title": args.title, "description": args.description, "license": args.license}
    if args.tag:
        fields["tags"] = args.tag
    if any(v is not None for v in fields.values()):
        agent = _load_agent(args, repo)
        with repo.writing():
            repo.append(builders.meta(repo.state, agent, **fields))
        print("project card updated (visible to the hub; public for public projects)")
    print(json.dumps(repo.state.meta, indent=2, ensure_ascii=False))

def _member_id(state, ref: str) -> str:
    """A full agent id, or a unique prefix of a member's id (as `provena log` shows them)."""
    if ref in state.members:
        return ref
    matches = [i for i in state.members if i.startswith(ref)]
    if len(matches) != 1:
        raise CliError(f"{ref!r} matches {len(matches)} members; see `provena member list`")
    return matches[0]


def cmd_member(args):
    repo = Repo.find()
    if args.action == "list":
        output.data(members=[{"id": i, "role": m.role, "active": m.active,
                              "name": m.card.get("name"), "kind": m.card.get("kind")}
                             for i, m in repo.state.members.items()])
        for i, m in repo.state.members.items():
            print(f"{i}  {m.role:<11} {'active' if m.active else 'removed':<8} "
                  f"{m.card.get('name') or ''}")
        return 0
    if not args.target:
        raise CliError(f"member {args.action} needs a card file (add) or an agent id")
    agent = _load_agent(args, repo)
    if args.action == "add":
        card = json.loads(Path(args.target).read_text())
        verify_card(card)
        with repo.writing():
            h = repo.append(builders.member_add(repo.state, agent, card, args.role))
            if args.history:
                h = _share_history(repo, agent, card["id"]) or h
    elif args.action == "history":  # someone added earlier, without --history
        with repo.writing():
            h = _share_history(repo, agent, _member_id(repo.state, args.target))
        if h is None:
            raise CliError("that member already holds every epoch key you can read",
                           EXIT_STATE, "E_CONFLICT")
    elif args.action == "rm":
        with repo.writing():
            entry, _ = builders.member_remove(repo.state, agent,
                                              _member_id(repo.state, args.target))
            h = repo.append(entry)
    else:
        with repo.writing():
            h = repo.append(builders.member_role(repo.state, agent,
                                                 _member_id(repo.state, args.target), args.role))
    print(f"member {args.action} {_short(h)}")
    output.data(entry=output.entry_ref(repo, h), action=args.action)
    _push_if_remote(repo, agent)


def _share_history(repo: Repo, agent, member_id: str) -> str | None:
    """Rules 2: re-share earlier epoch keys with *member_id* (None if nothing to share)."""
    if repo.state.rules < 2:
        raise CliError("this project uses ledger rules 1, which cannot share history keys "
                       "with a member added later (a project created now gets rules 2)")
    try:
        return repo.append(builders.member_rewrap(repo.state, agent, member_id))
    except ProvenaError:
        return None


def _push_if_remote(repo: Repo, agent) -> None:
    """Ledger changes others act on (membership, reveals, redactions) go to the hub at once,
    as `share` does; without a hub they stay local until `provena push`."""
    if repo.config.get("hub"):
        from provena.sdk import sync

        try:
            sync.push(repo, sync.make_client(repo.config["hub"], agent), agent=agent)
            print("pushed to the hub")
            output.data(pushed=True)
        except Exception as exc:  # the change is recorded locally either way
            output.data(pushed=False)
            output.warn("W_NOT_PUSHED", f"saved locally but not pushed ({exc}); run "
                        f"`provena push` when the hub is reachable")

def cmd_resolve(args):
    """Pick which of two concurrent versions of a path this checkout tracks (and checks out).
    Both stay on the ledger; nothing is written to it."""
    repo = Repo.find()
    conflicts = repo.config.get("conflicts", [])
    rel = repo.relpath(args.path)
    item = next((c for c in conflicts if c["path"] == rel), None)
    if item is None:
        raise CliError(f"no conflict recorded for {rel}", error="E_NOT_FOUND")
    keep = repo.resolve(args.keep)
    if keep not in (item["mine"], item["theirs"]):
        raise CliError(f"--keep must be one of {item['mine'][:12]} (yours) or "
                       f"{item['theirs'][:12]} (theirs)")
    agent = _load_agent(args, repo)
    entry = repo.entry(keep)
    private = builders.open_entry_fields(repo.state, agent, entry)
    dest = repo.root / _safe_relpath(rel)
    rec = repo.tracked.get(rel)
    if dest.exists() and not args.force and (rec is None or
                                             _file_sha256(dest).hex() != rec["sha256"]):
        raise CliError(f"{rel} has local changes that are not on the ledger; record them "
                       f"(`provena add {rel}`) or pass --force to overwrite", error="E_CONFLICT")
    cid = entry["body"]["cid"]
    if not repo.has_blob(cid) and repo.config.get("hub"):  # the teammate's file, from the hub
        _, client = _hub_client(repo, agent)
        client.download_blob(repo.state.project, cid, repo.blob_path(cid),
                             max_size=entry["body"]["size"])
    if not repo.has_blob(cid):
        raise CliError(f"no local ciphertext for {keep[:12]}", error="E_INCOMPLETE",
                       hint="provena pull")
    with repo.writing():  # tracked.json and config.json: one writer at a time
        _decrypt_to(repo.blob_path(cid), repo.blob_dek(agent, keep), dest, private["salt"],
                    private["plain_sha256"], entry["body"]["commitment"])
        repo.track(rel, keep, bytes.fromhex(private["plain_sha256"]))
        repo.set_config(conflicts=[c for c in repo.config.get("conflicts", []) if c != item])
    print(f"{rel} now tracks {keep[:12]} ({'yours' if keep == item['mine'] else 'theirs'}); "
          f"the other version stays on the ledger")
    output.data(path=rel, kept=keep, other=item["theirs"] if keep == item["mine"]
                else item["mine"])
    return 0


def cmd_config(args):
    """`config agent NAME`: which local key this checkout signs with (e.g. after recovery)."""
    repo = Repo.find()
    if args.value is not None:
        if not Home().has_agent(args.value):
            raise CliError(f"no local agent {args.value!r} (`provena --agent {args.value} "
                           f"keygen`)")
        card = Home().card(args.value)
        member = repo.state.members.get(card["id"])
        if member is None or not member.active:
            output.warn("W_NOT_MEMBER", f"{args.value} ({card['id']}) is not an active member "
                        f"of this project yet")
        repo.set_config(agent=args.value)
    print(f"agent: {repo.config['agent']}")
    output.data(agent=repo.config["agent"])


def cmd_rotate(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    with repo.writing():
        entry, _ = builders.rotate(repo.state, agent)
        repo.append(entry)
    print(f"rotated to epoch {repo.state.epoch}")
    output.data(epoch=repo.state.epoch, entry=output.entry_ref(repo, repo.state.order[-1]))
    _push_if_remote(repo, agent)

def cmd_succeed(args):
    """Hand this agent's role and every epoch key it can read to a successor key: a local
    agent name (the project then signs as it) or a card file of someone else's new key."""
    repo = Repo.find()
    agent = _load_agent(args, repo)
    home, local = Home(), None
    if home.has_agent(args.successor):
        local, card = args.successor, home.card(args.successor)
    elif Path(args.successor).is_file():
        card = json.loads(Path(args.successor).read_text())
    else:
        raise CliError(f"{args.successor!r} is neither a local agent nor a card file; "
                       f"create it with `provena --agent NAME keygen`")
    verify_card(card)
    if card["id"] == agent.id:
        raise CliError("the successor must be a different key")
    with repo.writing():
        h = repo.append(builders.succeed(repo.state, agent, card))
    if local and repo.config["agent"] == _agent_name(args, repo):
        repo.set_config(agent=local)
    output.data(entry=output.entry_ref(repo, h), old=agent.id, new=card["id"],
                signing_agent=repo.config["agent"])
    print(f"key {_short(agent.id)} -> {_short(card['id'])} ({_short(h)}); the old key is "
          "now inactive in this project" + (f"; this project now signs as {local!r}"
                                             if local else ""))
    _push_if_remote(repo, agent)


def cmd_reveal(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    h = repo.resolve(args.ref)
    _openable(repo, h)
    _challenge_guard(repo, h, getattr(args, "force", False))
    if repo.entry(h)["kind"] == "activity":
        return _reveal_step(repo, agent, h)
    done = repo.state.reveals.get(h)
    if done is not None and args.with_key and not done.get("dek") and repo.state.rules >= 2:
        done = None  # rules 2: reveal once more, now with the content key
    if done is not None:
        if args.with_key and not done.get("dek"):
            raise CliError(f"{h[:12]} is already revealed without its content key, and this "
                           f"project's ledger rules 1 cannot add it later", error="E_CONFLICT")
        print(f"{h[:12]} is already revealed" + (" with its content key" if done.get("dek")
                                                 else ""))
        output.data(target=output.entry_ref(repo, h), unchanged=True,
                    content_key=bool(done.get("dek")))
        return 0
    private = builders.open_entry_fields(repo.state, agent, repo.entry(h))
    dek = repo.blob_dek(agent, h) if args.with_key else None
    name = (private.get("name") or private.get("title")) if args.with_name else None
    with repo.writing():
        r = repo.append(builders.reveal(repo.state, agent, h, salt=bytes.fromhex(private["salt"]),
                                        plain_sha256=bytes.fromhex(private["plain_sha256"]),
                                        dek=dek, name=name))
    print(f"reveal {_short(r)} -> {_short(h)}" + (" (content key published)" if dek else ""))
    output.data(reveal=output.entry_ref(repo, r), target=output.entry_ref(repo, h),
                unchanged=False, content_key=dek is not None)
    _push_if_remote(repo, agent)

def _reveal_step(repo: Repo, agent, h: str) -> int:
    """Rules 2: publish a step's committed details (command, exit code, model, params…)."""
    if h in repo.state.reveals:
        print(f"step {h[:12]} is already opened")
        output.data(target=output.entry_ref(repo, h), unchanged=True,
                    details=repo.state.reveals[h].get("details"))
        return 0
    private = builders.open_entry_fields(repo.state, agent, repo.entry(h))
    with repo.writing():
        r = repo.append(builders.reveal_activity(repo.state, agent, h, private))
    details = repo.state.reveals[h].get("details")
    print(f"reveal {_short(r)} -> step {_short(h)}: details are public now "
          f"(exit code {details.get('exit_code')})")
    output.data(reveal=output.entry_ref(repo, r), target=output.entry_ref(repo, h),
                unchanged=False, details=details)
    _push_if_remote(repo, agent)
    return 0


def cmd_attest(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    with repo.writing():
        h = repo.append(builders.attest(repo.state, agent, repo.resolve(args.ref), type=args.type,
                                        verdict=args.verdict, note=args.note))
    print(f"attest {_short(h)}")
    output.data(attestation=output.entry_ref(repo, h))

def cmd_redact(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    target = repo.resolve(args.ref)
    with repo.writing():
        h = repo.append(builders.redact(repo.state, agent, target, reason=args.reason))
    cid = repo.entry(target)["body"].get("cid")
    if cid and repo.has_blob(cid):
        repo.blob_path(cid).unlink()
    print(f"redact {_short(h)} -> {_short(target)} (local ciphertext deleted)")
    output.data(redaction=output.entry_ref(repo, h), target=output.entry_ref(repo, target))
    _push_if_remote(repo, agent)
    if not repo.config.get("hub"):
        print("no hub configured: the hub copy is deleted when you `provena push`")
    name = (builders.open_entry_fields(repo.state, agent, repo.entry(target)) or {}).get("name")
    if name and (repo.root / _safe_relpath(name)).exists():
        print(f"note: your working copy {name} is untouched; delete it yourself if required")

def cmd_checkout(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    state = repo.state
    targets = [repo.resolve(r) for r in args.refs] if args.refs else [
        h for h in state.order if state.entries[h]["kind"] == "entity"]
    latest: dict[str, str] = {}
    for h in targets:
        if h in state.redacted:
            continue
        name = builders.open_entry_fields(state, agent, state.entries[h]).get("name")
        if name:
            latest[name] = h  # later registrations of the same path win
    done: list[dict] = []
    for name, h in latest.items():
        entry = state.entries[h]
        private = builders.open_entry_fields(state, agent, entry)
        dest = repo.root / _safe_relpath(name)
        if dest.exists() and not args.force:
            if _file_sha256(dest).hex() == private["plain_sha256"]:
                repo.track(repo.relpath(dest), h, bytes.fromhex(private["plain_sha256"]))
                done.append({"path": name, "hash": h, "status": "same"})
                continue
            print(f"  skip      {name} (exists and differs; --force to overwrite)")
            done.append({"path": name, "hash": h, "status": "differs"})
            continue
        cid = entry["body"]["cid"]
        if not repo.has_blob(cid):
            print(f"  missing   {name} (no local ciphertext; run `provena pull`)")
            done.append({"path": name, "hash": h, "status": "missing"})
            continue
        try:
            _decrypt_to(repo.blob_path(cid), repo.blob_dek(agent, h), dest, private["salt"],
                        private["plain_sha256"], entry["body"]["commitment"])
        except DecryptionError:
            # damaged local ciphertext: drop it, so the next pull fetches a good copy
            repo.blob_path(cid).unlink(missing_ok=True)
            raise CliError(f"the local ciphertext of {name} was damaged and has been removed",
                           error="E_CORRUPT", hint="provena pull; then provena checkout") \
                from None
        repo.track(repo.relpath(dest), h, bytes.fromhex(private["plain_sha256"]))
        print(f"  checkout  {name}")
        done.append({"path": name, "hash": h, "status": "written"})
    output.data(files=done)
    left = [d for d in done if d["status"] in ("missing", "differs")]
    if left:
        output.error("E_INCOMPLETE", f"{len(left)} files not checked out (missing ciphertext "
                     f"or a different local copy)", "provena pull; or --force")
        return EXIT_STATE

def cmd_capture(args):
    from provena.sdk import Project
    from provena.sdk.capture import Capture

    repo = Repo.find()
    agent = _load_agent(args, repo)
    project = Project(repo, agent, _agent_name(args, repo))
    capture = Capture(project, Path(args.dir), pattern=args.pattern)
    if args.once:  # two polls one interval apart: register whatever is stable now
        capture.poll()
        time.sleep(args.interval)
        for rel, h in capture.poll().registered:
            print(f"captured {rel} -> {h[:12]}")
        return 0
    print(f"capturing {args.dir} as {agent.id} every {args.interval}s (Ctrl-C to stop)")
    try:
        capture.run(args.interval, push_every=args.push_every)
    except KeyboardInterrupt:
        return 0

def cmd_ui(args):
    import secrets as _secrets

    import uvicorn

    from provena.cli.ui import create_ui

    repo = Repo.find()
    agent = _load_agent(args, repo)
    token = _secrets.token_urlsafe(24)
    app = create_ui(repo, agent, args.port, token)
    print(f"Provena local UI (read-only): http://127.0.0.1:{args.port}/?t={token}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
