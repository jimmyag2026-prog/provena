"""Proofs, verification, trust, identity, sharing and publishing."""

from __future__ import annotations

import io
import json
import re
import sys
import time
from pathlib import Path

from provena.cli import output
from provena.cli.common import (
    CliError,
    _agent_name,
    _best_head,
    _bibtex_safe,
    _challenge_guard,
    _decrypt_to,
    _evidence,
    _file_sha256,
    _hub_client,
    _load_agent,
    _openable,
    _passphrase,
    _register_file,
    _safe_relpath,
    _short,
    _when,
)
from provena.cli.ledger import cmd_reveal
from provena.core import aead, builders
from provena.core.bundle import make_bundle
from provena.core.errors import ProvenaError
from provena.core.keys import verify_card
from provena.core.treehead import make_head
from provena.core.verify import LEVELS, load_bundle, verify_bundle
from provena.sdk.verifying import entry_facts as _entry_facts
from provena.sdk.verifying import evidence_facts as _evidence_facts
from provena.store.home import Home
from provena.store.repo import Repo, RepoError
from provena.store.verify import verify_repo


def _parse_deadline(text: str) -> int:
    from datetime import datetime as _dt

    try:
        value = _dt.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CliError(f"--before needs an ISO 8601 time, e.g. 2026-11-01T00:00Z ({exc})") from exc
    if value.tzinfo is None:
        raise CliError("--before needs an explicit time zone (Z or +08:00)")
    return int(value.timestamp() * 1000)


def cmd_verify(args):
    if args.bundle:
        return _verify_bundle_file(args)
    if args.json:
        raise CliError("--json needs a bundle file")
    repo = Repo.find()
    agent = None if args.no_decrypt else _load_agent(args, repo)
    report = verify_repo(repo, agent)
    output.data(format="provena-verify-local/1", ok=report.ok, entries=report.entries,
                blobs_checked=report.blobs_checked, contents_checked=report.contents_checked,
                missing_blobs=sorted(report.missing_blobs), problems=list(report.problems))
    if report.missing_blobs:
        output.warn("W_MISSING_BLOBS", f"{len(report.missing_blobs)} files have no local "
                    f"ciphertext and were not checked (`provena pull`)")
    if not report.ok:
        output.error("E_VERIFY", "; ".join(report.problems[:3]) or "the ledger does not verify")
    print(f"entries: {report.entries}  blobs: {report.blobs_checked}  "
          f"contents: {report.contents_checked}  missing blobs: {len(report.missing_blobs)}")
    for p in report.problems:
        print(f"  FAIL {p}")
    print("OK" if report.ok else "FAILED")
    return 0 if report.ok else 1

def _default_only(store: dict) -> dict:
    """Trusted ids that come only from the built-in defaults."""
    explicit = Home().explicit_trust()
    return {k: v - explicit.get(k, set()) for k, v in store.items()}


def _verify_bundle_file(args):
    lines: list[str] = []
    result = _check_bundle_file(args, lines.append)
    output.data(verify={**result, "accepted": result["exit"] == 0})
    if result["exit"]:
        output.error("E_REQUIRE" if result.get("valid") else "E_VERIFY",
                     "; ".join(result.get("errors") or []) or "requirements not met")
    if args.json:  # `accepted`: valid *and* every --require / --before check passed
        print(json.dumps({**result, "accepted": result["exit"] == 0}, indent=1,
                         sort_keys=True))
    else:
        print("\n".join(lines))
    if args.badge:
        Path(args.badge).write_text(_badge(result))
    return result["exit"]


BADGE_COLORS = {"anchored": "#2e7d32", "witnessed": "#388e3c", "log-sequenced": "#689f38",
                "self-sequenced": "#f9a825", "unverified": "#9e9e9e"}


def _badge(result: dict) -> str:
    """A shields-style SVG: what an outsider's verifier concluded, nothing more."""
    label = "provena"
    value = (result.get("trust") or "unverified") if result.get("valid") else "invalid"
    color = BADGE_COLORS.get(value, "#c62828")
    lw, vw = 7 * len(label) + 10, 7 * len(value) + 10
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + vw}" height="20" '
            f'role="img" aria-label="{label}: {value}"><title>{label}: {value}</title>'
            f'<rect width="{lw}" height="20" fill="#555"/>'
            f'<rect x="{lw}" width="{vw}" height="20" fill="{color}"/>'
            f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="5" y="14">{label}</text><text x="{lw + 5}" y="14">{value}</text></g>'
            f'</svg>\n')


def _check_bundle_file(args, say) -> dict:
    """Verify a bundle file; *say* gets the human-readable lines. Returns the machine-readable
    verdict (`provena verify --json`, format provena-verify/1) including the exit code."""
    result: dict = {"format": "provena-verify/1", "valid": False, "trust": None, "facts": [],
                    "notes": [], "errors": [], "targets": [], "time_bounds": {}, "checks": {}}
    try:
        bundle = load_bundle(Path(args.bundle).read_text())
    except (ProvenaError, ValueError) as exc:  # unreadable or float-carrying bundle: invalid
        result["errors"].append(f"{type(exc).__name__}: {exc}")
        say(f"  ✗ {type(exc).__name__}: {exc}\nINVALID")
        return {**result, "exit": 1}
    contents = {}
    for spec in args.content:
        ref, _, path = spec.partition("=")
        contents[ref] = Path(path).read_bytes()
    if contents:  # REF may be a hash prefix, or a tracked path when run inside the repo
        hashes = [Repo.hash_of(it["entry"]) for it in bundle["entries"]]
        resolved = {}
        for ref, data in contents.items():
            matches = [h for h in hashes if h.startswith(ref)]
            if len(matches) != 1:
                try:
                    matches = [Repo.find().resolve(ref)]
                except (RepoError, ProvenaError) as exc:
                    raise CliError(f"--content {ref!r} matches no entry in the bundle") from exc
            resolved[matches[0]] = data
        contents = resolved
        opened = set(bundle.get("openings", {})) | {
            it["entry"]["body"]["target"] for it in bundle["entries"]
            if it["entry"]["kind"] == "reveal"}
        unopened = [h for h in contents if h not in opened]
        if unopened:  # a usage error, not a failed verification
            raise CliError(f"--content names {unopened[0][:12]}, which this bundle does not "
                           f"open, so a file cannot be checked against it",
                           error="E_INPUT", hint="prove it with --open, or reveal it")
        result["checks"]["content"] = {h: None for h in contents}
    store = Home().trust()
    report = verify_bundle(bundle, trusted_logs=store["logs"] | set(args.trust_log),
                           trusted_witnesses=store["witnesses"] | set(args.trust_witness),
                           trusted_tsas=store["tsas"] | set(args.trust_tsa),
                           trusted_orgs=store["orgs"] | set(args.trust_org),
                           external_contents=contents)
    if "content" in result["checks"]:
        result["checks"]["content"] = {h: report.ok for h in result["checks"]["content"]}
    result.update(valid=report.ok, trust=report.trust if report.ok else None,
                  project=report.project, mode=report.mode, facts=report.facts,
                  notes=report.notes, errors=report.errors, targets=report.targets,
                  time_bounds=report.time_bounds,
                  head={"size": report.head_size, "time": report.head_time,
                        "signer": report.head_signer},
                  preregistration=report.preregistration,
                  entries=_entry_facts(bundle, report),
                  evidence=_evidence_facts(bundle, report))
    defaults = _default_only(store)
    if report.ok and report.head_signer in defaults.get("logs", set()) and \
            report.head_signer not in set(args.trust_log):
        report.notes.append(f"log {report.head_signer} is trusted by a built-in default "
                            f"(`provena trust defaults` lists them; `off` to rely only on yours)")
    for fact in report.facts:
        say(f"  ✓ {fact}")
    for note in report.notes:
        say(f"  ! {note}")
    for err in report.errors:
        say(f"  ✗ {err}")
    say(f"VALID ({report.trust})" if report.ok else "INVALID")
    if not report.ok:
        return {**result, "exit": 1}
    code = 0
    if args.require:
        ok = LEVELS.index(report.trust) >= LEVELS.index(args.require)
        result["checks"]["require"] = {"level": args.require, "ok": ok,
                                       "reached": report.trust if report.ok else None}
        if not ok:
            say(f"trust level {report.trust} is below the required {args.require}")
            return {**result, "exit": 1}
    if args.before:
        deadline = _parse_deadline(args.before)
        check = result["checks"]["before"] = {"time": deadline, "ok": False, "late": []}
        if not bundle["targets"]:
            say("bundle has no targets: nothing is proven before the deadline")
            return {**result, "exit": 1}
        stray = sorted(set(contents) - set(bundle["targets"]))
        if stray:
            say("--content names entries that are not targets of this bundle, so the "
                f"deadline does not cover them: {', '.join(h[:12] for h in stray)}")
            return {**result, "exit": 1}
        late = [t for t in bundle["targets"]
                if report.time_bounds.get(t, deadline + 1) > deadline]
        for t in bundle["targets"]:
            bound = report.time_bounds.get(t)
            status = ("no trusted time evidence" if bound is None else
                      f"existed no later than {_when(bound)}")
            say(f"  {'✓' if t not in late else '✗'} {t[:12]} before {args.before}: {status}")
        check.update(ok=not late, late=late)
        code = 1 if late else 0
    return {**result, "exit": code}

def cmd_doctor(args):
    """Check the setup end to end and say what to do about anything missing."""
    from provena.sdk import sync

    results: list[tuple[str, bool, str, bool]] = []

    def check(name: str, ok: bool, fix: str = "", info: str = "", optional: bool = False
              ) -> bool:
        """*fix* is shown only when the check fails, *info* only when it passes; optional
        checks (witnesses, anchors) are reported but do not make doctor fail."""
        results.append((name, ok, info if ok else fix, optional))
        return ok

    home = Home()
    name = _agent_name(args)
    try:
        repo = Repo.find()
        name = _agent_name(args, repo)
    except RepoError:
        repo = None
    if args.verifier or (repo is None and not home.has_agent(name)):
        # someone who was only handed a .pvb: no key, no repository needed
        trust = home.trust()
        explicit = home.explicit_trust()
        check("verifier mode", True, info="no key or repository needed to verify bundles")
        check("trusted logs", bool(trust["logs"]),
              "`provena trust add log <hub log key>` (checked out of band)",
              info=f"{len(trust['logs'])} ({len(trust['logs'] - explicit['logs'])} built-in)")
        check("trusted TSAs", bool(trust["tsas"]), "`provena trust add tsa <fingerprint>` "
              "to reach `anchored`", info=str(len(trust["tsas"])), optional=True)
        check("trusted witnesses", bool(trust["witnesses"]), "`provena trust add witness <id>` "
              "to reach `witnessed`", optional=True)
        check("built-in trust", home.uses_default_trust(), "off (`provena trust defaults on`)",
              info="on (`provena trust defaults` lists it)", optional=True)
        return _doctor_report(results)
    agent = None
    if check("agent key exists", home.has_agent(name), f"run `provena keygen --name {name}`"):
        try:
            agent = home.load_agent(name, _passphrase())
            check("agent key unlocks", True, info=agent.id)
        except ProvenaError as exc:
            check("agent key unlocks", False, str(exc))
    if repo is None:
        check("inside a repository", False, "run `provena init` or `provena clone`")
    else:
        report = verify_repo(repo, agent)
        check("ledger replays and verifies", report.ok, "; ".join(report.problems[:3]))
        check("all ciphertext stored locally", not report.missing_blobs,
              f"{len(report.missing_blobs)} missing: run `provena pull`")
        if agent:
            role = repo.state.role_of(agent.id)
            check("you are an active member", role is not None, "ask an owner to add you",
                  info=f"role {role}")
        hub = repo.config.get("hub")
        if check("hub configured", bool(hub), "`provena remote <url>`", optional=True) and hub:
            pinned = (repo.config.get("hub_card") or {}).get("id")
            synced = repo.config.get("synced", 0)
            try:
                client = sync.make_client(hub, None)
                info = client.info()
                live = info["card"]["id"]
                from provena.core import rotation

                try:
                    handed = live != pinned and rotation.chain(info.get("rotations") or [],
                                                               pinned, live)
                except ProvenaError:
                    handed = None
                check("hub reachable, log key matches pin", live == pinned or bool(handed),
                      "hub key CHANGED with no hand-over signed by the pinned key: do not "
                      "push; investigate", info=live if live == pinned else
                      f"{live} (rotated from {pinned}, signed hand-over: the next pull follows)")
                size = (client.project(repo.state.project) or {}).get("size", 0)
                check("hub still holds every entry we synced", size >= synced,
                      f"the hub has {size} entries, we hold receipts for {synced}: it rolled "
                      f"back (old backup or data loss); keep this checkout, tell the operator",
                      info=f"{size} on the hub")
            except Exception as exc:  # network errors are reported, not raised
                check("hub reachable, log key matches pin", False, str(exc))
            check("hub log key is trusted", pinned in home.trust()["logs"],
                  f"`provena trust add log {pinned}`")
            mirrored = len(repo.config.get("mirror_pending", []))
            pending = len(repo.state.order) - repo.config.get("synced", 0) - mirrored
            check("everything pushed", pending == 0, f"{pending} entries pending: `provena push`")
            check("last push finished", not repo.config.get("push_incomplete"),
                  "it was cut short; files may be missing on the hub: `provena push`")
            stranded = repo.dir / "stranded.jsonl"
            n = len(stranded.read_text().splitlines()) if stranded.exists() else 0
            check("no entries set aside by a sync", n == 0,
                  f"{n} entries were not pushed: `provena stranded list` / `redo`")
            check("no provisional mirror entries", not mirrored,
                  f"{mirrored} entries read from a mirror await the primary: `provena pull`",
                  optional=True)
            witnessed = any(r["cosignatures"] for r in repo.read_extra("cosigs.json", {}).values())
            check("witness cosignatures present", witnessed,
                  "ask an independent witness to run `provena witness`", optional=True)
            independent = [a for a in repo.read_extra("anchors.json", [])
                           if (a.get("anchor") or {}).get("provider") not in (None, "self")]
            check("independent anchors present (RFC 3161)", bool(independent),
                  "the hub self-anchors: run it with --tsa; then `provena pull`", optional=True)
    return _doctor_report(results)


def _doctor_report(results) -> int:
    width = max(len(n) for n, *_ in results)
    for n, ok, detail, optional in results:
        mark = "✓" if ok else ("·" if optional else "✗")
        print(f"  {mark} {n:<{width}}  {('optional: ' if optional and not ok else '') + detail}")
    failed = [n for n, ok, _, optional in results if not ok and not optional]
    output.data(checks=[{"name": n, "ok": ok, "detail": detail, "optional": optional}
                        for n, ok, detail, optional in results], failed=failed)
    if failed:
        output.error("E_INCOMPLETE", f"{len(failed)} check(s) need attention: {failed}",
                     results[[n for n, *_ in results].index(failed[0])][2] or None)
    print("all good" if not failed else f"{len(failed)} item(s) need attention")
    return 0 if not failed else 1

def cmd_checkpoint(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    head = make_head(agent, repo.state.project, repo.leaves())
    repo.add_head(head, Home().card(_agent_name(args, repo)))
    print(f"checkpoint size={head['size']} root={head['root'][:16]}… (self-signed)")

def cmd_prove(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    targets = [repo.resolve(r) for r in args.refs]
    pending = (len(repo.state.order) - repo.config.get("synced", 0)
               - len(repo.config.get("mirror_pending", [])))
    if set(repo.config.get("mirror_pending", [])) & set(targets):
        print("note: some targets were read from a mirror and are not yet confirmed by the "
              "primary hub; `provena pull` from it before proving them", file=sys.stderr)
    if repo.config.get("hub") and pending:
        print(f"note: {pending} entries are not pushed yet; this bundle is at most "
              "self-sequenced — `provena push` first for hub timing", file=sys.stderr)
    chosen = _best_head(repo, agent, max(repo.entry_index(t) for t in targets) + 1,
                        _agent_name(args, repo))
    openings, contents = {}, {}
    for ref in args.open:
        h = repo.resolve(ref)
        _openable(repo, h, steps=False)  # a step is opened on the ledger: `provena reveal`
        private = builders.open_entry_fields(repo.state, agent, repo.entry(h))
        openings[h] = {"salt": private["salt"], "plain_sha256": private["plain_sha256"]}
        if args.embed:
            cid = repo.entry(h)["body"].get("cid")
            buf = io.BytesIO()
            with open(repo.blob_path(cid), "rb") as src:
                aead.decrypt_stream(repo.blob_dek(agent, h), src, buf)
            contents[h] = buf.getvalue()
    bundle = make_bundle(repo.log(), chosen["head"], chosen["signer_card"], targets,
                         mode="full" if args.full else "selective",
                         lineage=not args.no_lineage, openings=openings, contents=contents,
                         external=[json.loads(Path(f).read_text()) for f in args.external],
                         **_evidence(repo, chosen["head"]))
    Path(args.output).write_text(json.dumps(bundle, indent=1))
    output.data(bundle=str(Path(args.output).resolve()), targets=targets,
                entry_count=len(bundle["entries"]), head=chosen["head"],
                mode="full" if args.full else "selective", opened=list(openings))
    print(f"wrote {args.output}: {len(bundle['entries'])} entries, head size "
          f"{chosen['head']['size']} signed by {chosen['head']['signer'][:16]}")

def cmd_cite(args):
    """A citation for an entry: stable hub URL, entry hash, log position and the hub head that
    covers it, so readers can check existence and time and ask for a proof bundle."""
    repo = Repo.find()
    h = repo.resolve(args.ref)
    index = repo.entry_index(h)
    pid, hub_url = repo.state.project, repo.config.get("hub")
    hub_card = repo.config.get("hub_card") or {}
    from provena.sdk import sync

    known = sync.hub_cards(repo)
    heads = [x["head"] for x in repo.heads() if x["head"]["signer"] in known
             and x["head"]["size"] > index]
    head = min(heads, key=lambda x: x["size"]) if heads else None
    anchors = [a for a in repo.read_extra("anchors.json", []) if a["head"]["size"] > index]
    record = {
        "project": pid, "entry": h, "index": index, "kind": repo.entry(h)["kind"],
        "url": f"{hub_url.rstrip('/')}/p/{pid}/e/{h}" if hub_url else None,
        "log": hub_card.get("id"),
        "head": {"size": head["size"], "root": head["root"], "time": head["time"]}
        if head else None,
        "anchored": min(a["anchor"]["time"] for a in anchors) if anchors else None,
    }
    if record["head"] is None:
        print("note: not yet sequenced by a hub; run `provena push` for a citable record",
              file=sys.stderr)
    if args.format == "json":
        print(json.dumps(record, indent=2))
    elif args.format == "bibtex":
        year = _when(head["time"])[:4] if head else ""
        title = _bibtex_safe(repo.state.meta.get("title") or "")
        print(f"@misc{{provena:{h[:12]},\n  title = {{"
              + (f"{title}: " if title else "") + f"Provena ledger entry {h[:12]}}},\n"
              f"  howpublished = {{\\url{{{record['url'] or 'urn:provena:entry:' + h}}}}},\n"
              f"  note = {{project {pid}, entry {h}, log position {index}"
              + (f", log head {head['size']}:{head['root']}" if head else "") + "}},\n"
              f"  year = {{{year}}}\n}}")
    else:
        line = f"Provena ledger entry {h} (project {pid}, position #{index}"
        if head:
            line += f", sequenced by {record['log']} no later than {_when(head['time'])}"
        if record["anchored"]:
            line += f", anchored {_when(record['anchored'])}"
        print(line + ")." + (f" {record['url']}" if record["url"] else ""))

def cmd_export(args):
    from provena.sdk import Project

    repo = Repo.find()
    agent = _load_agent(args, repo)
    project = Project(repo, agent, _agent_name(args, repo))
    if args.format == "intoto":
        from provena.sdk import intoto

        if not (args.step and args.output):
            raise CliError("export intoto needs --step REF and -o FILE")
        h = repo.resolve(args.step)
        env = intoto.envelope(agent, intoto.run_statement(project, h))
        Path(args.output).write_text(json.dumps(env, indent=1))
        print(f"wrote in-toto statement for step {h[:12]} (DSSE, signed by {agent.id}) to "
              f"{args.output}; it discloses the step's output names and hashes")
        output.data(step=h, envelope=str(Path(args.output).resolve()), keyid=agent.id)
        return 0
    if args.format == "rocrate":
        from provena.sdk.rocrate import export_rocrate

        if not args.output:
            raise CliError("export rocrate needs -o DIR")
        crate = export_rocrate(project, Path(args.output),
                               include_content=not args.metadata_only,
                               include_private=args.include_private)
        print(f"wrote RO-Crate with {len(crate['@graph'])} nodes to {args.output} "
              "(includes provena-proof.pvb)")
        if not args.metadata_only:
            print("note: the crate holds DECRYPTED copies of the files; share it only with "
                  "people who may read them (--metadata-only leaves them out)")
        return
    doc = project.export_prov(include_private=args.include_private)
    text = json.dumps(doc, indent=2)
    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote PROV-JSON to {args.output}")
    else:
        print(text)

def cmd_identity(args):
    from provena.core import identity

    if args.action == "issue":
        org_name = _agent_name(args)
        org_card = Home().card(org_name)
        if org_card["kind"] != "org":
            raise CliError(f"agent {org_name!r} is not an org agent (`keygen --kind org`)")
        subject = json.loads(Path(args.target).read_text())
        verify_card(subject)
        claims = {k: v for k, v in (("name", args.name), ("affiliation", args.affiliation),
                                    ("orcid", args.orcid), ("role", args.role)) if v}
        now = int(time.time() * 1000)
        cred = identity.issue(_load_agent(args), subject["id"], claims, issued=now,
                              expires=now + int(args.days * 86_400_000))
        out = {"credential": cred, "issuer_card": org_card}
        Path(args.output).write_text(json.dumps(out, indent=2, ensure_ascii=False))
        print(f"issued credential for {subject['id']} -> {args.output}")
    else:  # attach: keep it in the repo so `prove` ships it for that author
        repo = Repo.find()
        item = json.loads(Path(args.target).read_text())
        identity.verify(item["credential"], item["issuer_card"],
                        at_ms=int(time.time() * 1000))  # refuses expired credentials
        creds = [c for c in repo.read_extra("credentials.json", [])
                 if c["credential"]["sig"] != item["credential"]["sig"]]
        repo.write_extra("credentials.json", [*creds, item])
        print(f"attached credential for {item['credential']['subject']} "
              f"from org {item['credential']['issuer']}")

def cmd_trust(args):
    from provena.store.home import default_trust

    home = Home()
    if args.action == "defaults":
        if args.kind in ("on", "off"):
            home.set_default_trust(args.kind == "on")
        on = home.uses_default_trust()
        builtin = default_trust()
        print(f"built-in trust is {'ON' if on else 'OFF'}:")
        for kind, ids in builtin.items():
            for i, label in ids.items():
                print(f"  {kind[:-1]:<8} {i}  {label}")
        output.data(defaults=on, builtin=builtin)
        return 0
    kind = {"log": "logs", "witness": "witnesses", "tsa": "tsas",
            "org": "orgs"}.get(args.kind or "", "")
    if args.from_url:
        if args.action != "add" or kind != "logs" or args.value:
            raise CliError("usage: provena trust add log --from-url URL [--yes]")
        from provena.sdk import sync

        live = sync.make_client(args.from_url, None).info()["card"]["id"]
        output.data(log_key=live, url=args.from_url, added=args.yes)
        if not args.yes:
            # trusting what a server says about itself is circular: compare out of band
            print(f"{args.from_url} signs with log key {live}\ncompare it with the key the "
                  f"operator published, then: provena trust add log {live}  (or --yes)")
            return 0
        args.value = live
    if args.action in ("add", "remove"):
        if not (kind and args.value):
            raise CliError("usage: provena trust add|remove log|witness|tsa|org VALUE")
        value = args.value.strip().lower() if kind == "tsas" else args.value.strip()
        if args.action == "add" and kind == "tsas" and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise CliError("a TSA is trusted by its certificate's full SHA-256 fingerprint "
                           "(64 hex characters, as `provena verify` prints it)")
        if args.action == "add" and kind != "tsas" and not re.fullmatch(r"pv1a[a-z2-7]{32}",
                                                                        value):
            raise CliError("expected a full agent id (pv1a… , 36 characters)")
        if args.action == "remove" and value != args.value:
            home.set_trust(kind, args.value, present=False)  # also an oddly stored spelling
        home.set_trust(kind, value, present=args.action == "add")
        print(f"{'trusted' if args.action == 'add' else 'no longer trusted'}: {args.kind} "
              f"{value}")
        output.data(trust={k: sorted(v) for k, v in home.trust().items()})
        return 0
    explicit = home.explicit_trust()
    output.data(trust={k: sorted(v) for k, v in home.trust().items()},
                explicit={k: sorted(v) for k, v in explicit.items()},
                defaults=home.uses_default_trust())
    for k, values in home.trust().items():
        print(f"{k}:")
        for v in sorted(values):
            print(f"  {v}" + ("" if v in explicit[k] else "  (built-in default)"))

def cmd_share(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    target = repo.resolve(args.ref)
    _challenge_guard(repo, target, getattr(args, "force", False))
    card = json.loads(Path(args.to).read_text())
    verify_card(card)
    private = builders.open_entry_fields(repo.state, agent, repo.entry(target))
    name = private.get("name") or private.get("title") or target[:12]
    with repo.writing():
        g = repo.append(builders.grant(repo.state, agent, target, card,
                                       dek=repo.blob_dek(agent, target),
                                       salt=bytes.fromhex(private["salt"]),
                                       plain_sha256=bytes.fromhex(private["plain_sha256"]),
                                       name=name))
    if repo.config.get("hub"):
        sync, client = _hub_client(repo, agent)
        sync.push(repo, client, agent=agent)
    chosen = _best_head(repo, agent, repo.entry_index(g) + 1, _agent_name(args, repo))
    bundle = make_bundle(repo.log(), chosen["head"], chosen["signer_card"], [target, g],
                         **_evidence(repo, chosen["head"]))
    out = args.output or f"{target[:12]}.share.pvb"
    Path(out).write_text(json.dumps(bundle, indent=1))
    output.data(grant=output.entry_ref(repo, g), target=output.entry_ref(repo, target),
                to=card["id"], bundle=str(Path(out).resolve()))
    print(f"granted {_short(target)} to {card['id']} (ledger entry {_short(g)}); "
          f"send them {out}")

def _open_destination(out_dir: Path, name: str, *, force: bool) -> Path:
    """Where a file named by a bundle's author may be written: inside *out_dir*, no hidden
    components (dotfiles, .github/…), never over an existing file unless --force."""
    rel = _safe_relpath(name)
    if any(part.startswith(".") for part in rel.parts):
        raise CliError(f"refusing hidden path from bundle: {name!r}")
    dest = out_dir / rel
    if not dest.resolve().is_relative_to(out_dir):  # e.g. a symlinked directory inside out_dir
        raise CliError(f"refusing path that leaves the output directory: {name!r}")
    if dest.exists() and not force:
        raise CliError(f"{dest} exists; pass --force to overwrite")
    return dest


def cmd_open(args):
    from provena.core.encoding import unb64u
    from provena.sdk import sync

    bundle = load_bundle(Path(args.bundle).read_text())
    report = verify_bundle(bundle)
    if not report.ok:
        raise CliError("bundle does not verify: " + "; ".join(report.errors))
    if args.agent and not Home().has_agent(args.agent):
        raise CliError(f"no agent named {args.agent!r} here", error="E_NOT_FOUND",
                       hint="provena keygen --name NAME, or the --agent the bundle was shared to")
    agent = _load_agent(args) if Home().has_agent(_agent_name(args)) else None
    proven = {Repo.hash_of(it["entry"]): it["entry"] for it in bundle["entries"]}
    targets = set(bundle["targets"])
    jobs = []  # (target hash, dek, salt, plain, name)
    for e in proven.values():
        body = e["body"]
        if body.get("target") not in targets:
            continue  # open only what the bundle is about, never incidental lineage entries
        if e["kind"] == "grant" and agent is not None and body["to"]["id"] == agent.id:
            secret = builders.open_grant(e, agent)
            jobs.append((body["target"], secret["dek"], secret["salt"], secret["plain_sha256"],
                         secret["name"]))
        elif e["kind"] == "reveal" and body.get("dek"):
            jobs.append((body["target"], unb64u(body["dek"]), body["salt"],
                         body["plain_sha256"], body.get("name") or body["target"][:12]))
    if not jobs:
        raise CliError("this bundle grants you nothing to open")
    client = sync.make_client(args.hub, agent) if args.hub else None
    out_dir = Path(args.output).resolve()
    opened = []
    for target, dek, salt, plain, name in jobs:
        body = proven[target]["body"]
        existing = out_dir / _safe_relpath(name)
        if existing.is_file() and not args.force and _file_sha256(existing).hex() == plain:
            print(f"{existing} is already this content")
            opened.append({"target": target, "path": str(existing), "unchanged": True})
            continue
        dest = _open_destination(out_dir, name, force=args.force)
        if args.blob:
            cipher_path = Path(args.blob)
            if _file_sha256(cipher_path).hex() != body["cid"]:
                raise CliError("ciphertext does not match its cid")
        elif client:
            cipher_path = dest.with_name(dest.name + ".provena-cipher")
            client.download_blob(bundle["project"], body["cid"], cipher_path,
                                 max_size=body["size"])  # cid- and size-checked
        else:
            raise CliError("pass --hub URL (or --blob FILE) to fetch the ciphertext")
        try:
            size = _decrypt_to(cipher_path, dek, dest, salt, plain, body["commitment"])
        finally:
            if not args.blob:
                cipher_path.unlink(missing_ok=True)
        print(f"opened {_short(target)} -> {dest} ({size} bytes, matches commitment)")
        opened.append({"target": target, "path": str(dest), "bytes": size, "unchanged": False})
    output.data(opened=opened)

SEAL_FORMAT = "provena-seal/1"


def cmd_seal(args):
    """Commit to a whole data package now, to publish it later: every file is recorded
    (encrypted, committed), and a manifest of their hashes is preregistered as one plan. A
    proof of the manifest then shows the package existed no later than its anchor time."""
    repo = Repo.find()
    root = Path(args.dir)
    if not root.is_dir():
        raise CliError(f"{args.dir} is not a directory")
    reveal_after = _parse_deadline(args.reveal_after)
    files = sorted(p for p in root.rglob("*") if p.is_file()
                   and not any(part.startswith(".") for part in p.relative_to(root).parts))
    if not files:
        raise CliError(f"{args.dir} holds no files to seal")
    names = [repo.checked_relpath(f) for f in files]  # all checked before any is recorded
    agent = _load_agent(args, repo)
    rows = []
    for f, name in zip(files, names, strict=True):
        rec = repo.tracked.get(name)
        same = rec and rec["entry"] in repo.state.entries and \
            _file_sha256(f).hex() == rec["sha256"]
        h = rec["entry"] if same else _register_file(repo, agent, f)
        rows.append({"path": name, "entry": h, "sha256": _file_sha256(f).hex()})
    manifest = Path(f"{root.resolve()}.seal.json")
    manifest.write_text(json.dumps({"format": SEAL_FORMAT, "dir": repo.relpath(root),
                                    "reveal_after_ms": reveal_after, "files": rows},
                                   indent=1, sort_keys=True))
    plan = _register_file(repo, agent, manifest, kind="plan",
                          title=f"seal {repo.relpath(root)} (reveal after {_when(reveal_after)})")
    print(f"sealed {len(rows)} files of {args.dir} under manifest {plan[:12]} "
          f"({repo.relpath(manifest)}); reveal after {_when(reveal_after)}")
    output.data(manifest=output.entry_ref(repo, plan, repo.relpath(manifest)), files=rows,
                reveal_after_ms=reveal_after)
    if repo.config.get("hub"):
        sync, client = _hub_client(repo, agent)
        sync.push(repo, client, agent=agent)
        output.data(pushed=True)
    else:
        output.warn("W_LOCAL_ONLY", "no hub: the seal's time rests on your own clock until you "
                    "push to a hub (receipts) with anchoring")
    return 0


def cmd_unseal(args):
    """After the date: publish the manifest and every sealed file (content keys included)."""
    repo = Repo.find()
    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("format") != SEAL_FORMAT:
        raise CliError(f"{args.manifest} is not a Provena seal manifest")
    now = int(time.time() * 1000)
    if now < manifest["reveal_after_ms"] and not args.force:
        output.data(reveal_after_ms=manifest["reveal_after_ms"], now_ms=now)
        raise CliError(f"sealed until {_when(manifest['reveal_after_ms'])}", error="E_TOO_EARLY",
                       hint="wait, or --force to publish early (the ledger shows when)")
    agent = _load_agent(args, repo)
    plan = repo.resolve(repo.relpath(manifest_path))
    targets = [plan, *[row["entry"] for row in manifest["files"]]]
    published = []
    for h in targets:
        done = repo.state.reveals.get(h)
        if done and done.get("dek"):
            continue
        private = builders.open_entry_fields(repo.state, agent, repo.entry(h))
        with repo.writing():
            repo.append(builders.reveal(repo.state, agent, h, salt=bytes.fromhex(private["salt"]),
                                        plain_sha256=bytes.fromhex(private["plain_sha256"]),
                                        dek=repo.blob_dek(agent, h),
                                        name=private.get("name") or private.get("title")))
        published.append(h)
    print(f"unsealed {len(published)} entries (manifest {plan[:12]} and its files are public)")
    output.data(manifest=plan, published=published, early=now < manifest["reveal_after_ms"])
    if repo.config.get("hub"):
        sync, client = _hub_client(repo, agent)
        sync.push(repo, client, agent=agent)
    return 0


def cmd_publish(args):
    args.with_key = True
    args.with_name = not args.keep_name_sealed
    cmd_reveal(args)
    repo = Repo.find()
    if repo.config.get("hub"):
        agent = _load_agent(args, repo)
        sync, client = _hub_client(repo, agent)
        sync.push(repo, client, agent=agent)
        print("published: content is now downloadable and verifiable by anyone via the hub")
    else:
        output.warn("W_LOCAL_ONLY", "no hub configured: the content key is published in your "
                    "local ledger only; `provena remote URL` and `provena push` to publish it")
