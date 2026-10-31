"""Offline verifier for proof bundles. Depends on provena.core only (ARCHITECTURE.md §5.4).

The verifier never trusts the bundle's own claims: it recomputes every hash, signature and proof
and reports *facts* it established, plus the trust level of the time statement.

Validity and trust are separate. A bundle is valid when every signature and proof checks out.
Its trust level depends only on keys the *verifier* chose to trust (logs, witnesses, TSA
certificates) — never on anything the bundle says about itself. Evidence signed by keys outside
those sets is reported as a note, not as a fact.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from provena.core import commitment, entries, identity, merkle, rotation
from provena.core.anchor import verify_anchor_record
from provena.core.bundle import FORMAT, _key_intros
from provena.core.canonical import canonicalize
from provena.core.encoding import unb64u
from provena.core.errors import CanonicalizationError, VerificationError
from provena.core.hashing import sha256
from provena.core.keys import AgentPublic, verify_card
from provena.core.receipts import verify_set
from provena.core.state import ProjectState, status_matches
from provena.core.treehead import verify_head
from provena.core.witness import verify_cosig

_HEX = re.compile(r"[0-9a-f]{64}")
TRUST_UNVERIFIED = "unverified"  # head signer is neither trusted nor a project member
TRUST_SELF = "self-sequenced"   # signed by a project member: time is the author's own claim
TRUST_LOG = "log-sequenced"     # signed by an independent log (hub)
TRUST_WITNESSED = "witnessed"   # plus cosignatures from independent witnesses
TRUST_ANCHORED = "anchored"     # plus an external timestamp over the log head
MAX_EXTERNAL = 20  # attached bundles of other projects (one level deep)
CLOCK_SKEW_MS = 300_000  # tolerated hub-vs-TSA clock difference
LEVELS = (TRUST_UNVERIFIED, TRUST_SELF, TRUST_LOG, TRUST_WITNESSED, TRUST_ANCHORED)


@dataclass
class BundleReport:
    ok: bool = False
    project: str = ""
    mode: str = ""
    head_size: int = 0
    head_time: int = 0
    head_signer: str = ""
    trust: str = ""
    facts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    verified_entries: dict[str, int] = field(default_factory=dict)
    targets: list[str] = field(default_factory=list)
    # target hash -> earliest *trusted* "existed no later than" time (ms): trusted head, signed
    # receipt from a trusted log, or anchor by a trusted TSA. Absent = no trusted time evidence.
    time_bounds: dict[str, int] = field(default_factory=dict)
    # entry hash -> sequencing time from a signed receipt of a *trusted* log, for every entry
    # that carries one (not only targets). Trusting the log makes this the entry's time in both
    # directions: it did not exist in the log before, and existed no later than, this moment.
    sequenced: dict[str, int] = field(default_factory=dict)
    # one record per activity that cites a plan in this bundle: {plan, activity, holds,
    # ordered (positions from a trusted log), reason (when not holds)}
    preregistration: list[dict] = field(default_factory=list)

    def bound(self, target: str, ms: int) -> None:
        self.time_bounds[target] = min(ms, self.time_bounds.get(target, ms))


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise VerificationError(msg)


def load_bundle(text: str) -> dict:
    """Parse a bundle file. Floats are rejected anywhere (signed structures never contain them,
    and the browser verifier scans the raw text the same way); a UTF-8 BOM is ignored."""
    def no_float(token: str):
        raise CanonicalizationError(f"floats are not allowed in bundles ({token})")
    return json.loads(text.removeprefix("\ufeff"), parse_float=no_float,
                      parse_constant=no_float)


def verify_bundle(bundle: dict, *, trusted_logs: set[str] | None = None, _depth: int = 0,
                  trusted_witnesses: set[str] | None = None,
                  trusted_tsas: set[str] | None = None,
                  trusted_orgs: set[str] | None = None,
                  external_contents: dict[str, bytes] | None = None) -> BundleReport:
    """Verify *bundle*. trusted_* are agent ids (logs, witnesses) and TSA certificate SHA-256
    fingerprints; without them the result can be valid but at most `self-sequenced`."""
    report = BundleReport()
    trust = {"logs": set(trusted_logs or ()), "witnesses": set(trusted_witnesses or ()),
             "tsas": {t.lower() for t in trusted_tsas or ()}, "orgs": set(trusted_orgs or ())}
    try:
        _follow_rotations(bundle, report, trust)
        _verify(bundle, report, trust, external_contents or {})
        _witness_and_anchor_facts(bundle, report, trust)
        _credential_facts(bundle, report, trust)
        _external_facts(bundle, report, trust, _depth)
        report.ok = True
    except Exception as exc:  # fail closed on anything malformed
        report.errors.append(f"{type(exc).__name__}: {exc}")
    return report


def _follow_rotations(bundle, report, trust) -> None:
    """A trusted log key that handed over to a new key (ADR 0010) vouches for its successor."""
    statements = bundle.get("log_rotations")
    statements = [] if statements is None else statements  # absent or null; `{}` is malformed
    _need(isinstance(statements, list), "log_rotations must be a list")
    for new, root in sorted(rotation.extend_trust(trust["logs"], statements).items()):
        trust["logs"].add(new)
        report.notes.append(f"log key {new} is trusted as the successor of {root} "
                            "(hand-over signed by both keys)")


def _verify(bundle, report, trust, external_contents) -> None:
    _need(bundle.get("format") == FORMAT, "unknown bundle format")
    report.project, report.mode = bundle["project"], bundle["mode"]
    report.targets = list(bundle["targets"])
    head = bundle["head"]
    signer = verify_card(bundle["head_signer"])
    verify_head(head, signer)
    _need(head["project"] == bundle["project"], "head is for another project")
    report.head_size, report.head_time, report.head_signer = head["size"], head["time"], signer.id

    items = sorted(bundle["entries"], key=lambda it: it["index"])
    _need(bool(items) and items[0]["index"] == 0, "bundle must include the genesis entry")
    genesis = items[0]["entry"]
    _need(entries.entry_hash(genesis) == bundle["project"], "genesis does not match project id")

    if bundle["mode"] == "full":
        indexed, state = _verify_full(items, head)
        member_ids = set(state.members)
    else:
        indexed = _verify_selective(items, head)
        member_ids = set(_key_intros([it["entry"] for it in items]))
    report.verified_entries = {h: i for h, (i, _) in indexed.items()}
    if signer.id in trust["logs"]:
        report.trust = TRUST_LOG
    elif signer.id in member_ids:
        report.trust = TRUST_SELF
    else:
        report.trust = TRUST_UNVERIFIED
    when = _iso(head["time"])
    report.facts.append(f"log head: {head['size']} entries, root {head['root'][:16]}…, signed "
                        f"by {signer.id} with time {when}")
    if bundle["mode"] == "selective":
        report.notes.append("selective bundle: membership/revocation at signing time is not "
                            "proven (use a full bundle for that)")
    if report.trust == TRUST_SELF:
        report.notes.append("the head is signed by a project member: its time is the author's "
                            "own claim, not independent evidence")
    elif report.trust == TRUST_UNVERIFIED:
        report.notes.append(f"the head signer {signer.id} is not a log you trust: order and "
                            f"times are its unverified claim (trust it with --trust-log)")

    for t in bundle["targets"]:
        _need(t in indexed, f"target {t[:12]} not proven by this bundle")
        i, e = indexed[t]
        if report.trust == TRUST_LOG:
            report.bound(t, head["time"])
            report.facts.append(f"entry {t[:12]} ({e['kind']}) by {e['author']} is #{i} in "
                                f"project {bundle['project'][:12]}, existing no later than "
                                f"{when} (per trusted log)")
        else:
            report.facts.append(f"entry {t[:12]} ({e['kind']}) signed by {e['author']} belongs "
                                f"to project {bundle['project'][:12]}")
    if report.trust != TRUST_LOG:
        report.notes.append("log positions and order (#n, plan-before-result) are asserted by "
                            "an untrusted head signer and are reported as notes")
    _receipt_facts(bundle, items, indexed, signer, report)
    _lineage_facts(indexed, report, ordered=report.trust == TRUST_LOG)
    _opening_facts(bundle, indexed, report, external_contents)


def _verify_full(items, head) -> tuple[dict[str, tuple[int, dict]], ProjectState]:
    _need([it["index"] for it in items] == list(range(head["size"])),
          "full bundle must contain every entry up to the head")
    log = [it["entry"] for it in items]
    state = ProjectState.replay(log)  # proves authorization, chains and per-kind rules
    leaves = [entries.entry_leaf(e) for e in log]
    _need(merkle.root(leaves).hex() == head["root"], "entries do not hash to the head root")
    return {h: (i, state.entries[h]) for i, h in enumerate(state.order)}, state


def _verify_selective(items, head) -> dict[str, tuple[int, dict]]:
    root = bytes.fromhex(head["root"])
    indexed: dict[str, tuple[int, dict]] = {}
    for it in items:
        e = it["entry"]
        entries.check_shape(e)
        merkle.verify_inclusion(entries.entry_leaf(e), it["index"], head["size"],
                                [bytes.fromhex(p) for p in it["proof"]], root)
        indexed[entries.entry_hash(e)] = (it["index"], e)
    # Author keys come only from proven key-introducing entries that precede their use.
    keys: dict[str, tuple[int, AgentPublic]] = {}
    for _, (i, e) in sorted(indexed.items(), key=lambda kv: kv[1][0]):
        for agent_id in _key_intros([e]):
            keys.setdefault(agent_id, (i, verify_card(_find_card(e, agent_id))))
    project = items[0]["entry"]
    for h, (i, e) in indexed.items():
        _need(e is project or e["project"] == entries.entry_hash(project),
              f"entry {h[:12]} belongs to another project")
        _need(e["author"] in keys, f"no proven key for author {e['author']}")
        intro_index, pub = keys[e["author"]]
        _need(intro_index <= i, f"author key of {h[:12]} introduced after the entry")
        entries.verify_signature(e, pub)
        if e["prev"] in indexed:  # an author's chain can only point backwards in the log
            _need(indexed[e["prev"]][0] < i, f"entry {h[:12]} precedes its own prev entry")
    return indexed


def _find_card(entry: dict, agent_id: str) -> dict:
    body = entry["body"]
    if entry["kind"] == "genesis":
        return next(m["card"] for m in body["members"] if m["card"]["id"] == agent_id)
    return body["card"]


def _receipt_facts(bundle, items, indexed, signer, report) -> None:
    """Signed entry timestamps (SET) give each entry its own sequencing time, tighter than
    "no later than the head". Only meaningful from a trusted log; always checked."""
    head = bundle["head"]
    for it in items:
        if "receipt" not in it:
            continue
        r = it["receipt"]
        _need(isinstance(r, dict), "receipt must be an object")
        verify_set(r, signer)  # must be signed by the head's own log
        h = entries.entry_hash(it["entry"])
        _need(r["project"] == bundle["project"] and r["index"] == it["index"]
              and r["entry_hash"] == h, "receipt does not match its entry")
        _need(r["integrated_time"] <= head["time"], "receipt is dated after the head")
        if report.trust == TRUST_LOG:
            report.sequenced[h] = r["integrated_time"]
        if h in bundle["targets"] and report.trust == TRUST_LOG:
            report.bound(h, r["integrated_time"])
        if h in bundle["targets"]:
            what = (f"entry {h[:12]} was sequenced at {_iso(r['integrated_time'])} "
                    f"(signed receipt)")
            (report.facts if report.trust == TRUST_LOG else report.notes).append(
                what if report.trust == TRUST_LOG else f"{what} — signer not trusted")


def _lineage_facts(indexed, report, *, ordered: bool) -> None:
    """*ordered*: positions come from a trusted log, so order-based statements are facts."""
    order_fact = report.facts.append if ordered else report.notes.append
    for h, (i, e) in sorted(indexed.items(), key=lambda kv: kv[1][0]):
        body = e["body"]
        if e["kind"] == "activity":
            used = [u[:12] for u in body.get("used", []) if u in indexed]
            gen = [g[:12] for g in body.get("generated", []) if g in indexed]
            status = f" [{body['status']}]" if body.get("status") else ""
            report.facts.append(f"activity {h[:12]} (#{i}){status} used {used or '[]'} and "
                                f"generated {gen or '[]'}")
            plan = body.get("plan")
            if plan in indexed:
                p_i = indexed[plan][0]
                _need(p_i < i, "plan must precede the activity citing it")
                outputs = [indexed[g][0] for g in body.get("generated", []) if g in indexed]
                holds = len(outputs) == len(body.get("generated", [])) and all(
                    o > p_i for o in outputs)
                missing = len(body.get("generated", [])) - len(outputs)
                report.preregistration.append({
                    "plan": plan, "activity": h, "holds": holds, "ordered": ordered,
                    # proven: the order comes from a trusted log, not the bundle's author
                    "proven": holds and ordered,
                    # target: about what was asked to be proven (not an upstream step reached
                    # through lineage, whose other outputs the prover chose not to disclose)
                    "target": h in report.targets or any(
                        g in report.targets for g in body.get("generated", [])),
                    "reason": ("order-unproven" if not ordered else None) if holds
                    else "outputs-not-in-bundle" if missing else "output-before-plan"})
                if holds:
                    order_fact(
                        f"plan {plan[:12]} (#{p_i}) was registered before activity {h[:12]} "
                        f"(#{i}) and before all of its outputs: preregistration holds")
                else:
                    why = (f"{missing} of its outputs are not in this bundle (prove them too, "
                           "or use a full bundle)" if missing else
                           "an output was registered before the plan")
                    report.notes.append(
                        f"activity {h[:12]} cites plan {plan[:12]}, but {why}: "
                        "preregistration NOT shown")
        elif e["kind"] == "attest" and body["target"] in indexed:
            verdict = f", verdict {body['verdict']}" if body.get("verdict") else ""
            report.facts.append(f"{body['type']} attestation by {e['author']} on "
                                f"{body['target'][:12]}{verdict}")
        elif e["kind"] == "grant" and body["target"] in indexed:
            report.facts.append(f"access to {body['target'][:12]} was granted by {e['author']} "
                                f"to {body['to']['id']} (#{i})")
        elif e["kind"] == "redact" and body["target"] in indexed:
            report.facts.append(f"entry {body['target'][:12]} was redacted ({body['reason']}); "
                                f"its existence remains provable")


def _opening_facts(bundle, indexed, report, external_contents) -> None:
    openings = dict(bundle.get("openings", {}))
    for _i, e in indexed.values():  # on-ledger reveals are openings too
        if e["kind"] == "reveal" and e["body"]["target"] in indexed:
            openings.setdefault(e["body"]["target"], e["body"])
    for h, o in openings.items():
        _need(h in indexed, f"opening for unproven entry {h[:12]}")
        target = indexed[h][1]
        plain = bytes.fromhex(o["plain_sha256"])
        commitment.verify_opening(bytes.fromhex(target["body"]["commitment"]),
                                  bytes.fromhex(o["salt"]), plain)
        # embedded plaintext and a file the verifier supplies are each checked: one must
        # never stand in for the other
        checks = [(label, content) for label, content in (
            ("embedded content", unb64u(o["content"]) if o.get("content") else None),
            ("supplied content", external_contents.get(h))) if content is not None]
        for label, content in checks:
            _need(hashlib.sha256(content).digest() == plain,
                  f"{label} for {h[:12]} does not match its commitment")
            report.facts.append(f"{label} of {h[:12]} ({len(content)} bytes) matches its "
                                f"commitment")
        if "details" in o:  # selective bundles do not replay the state machine
            _need(target["kind"] == "activity" and isinstance(o["details"], dict)
                  and sha256(canonicalize(o["details"])).hex() == o["plain_sha256"],
                  f"opened details of {h[:12]} do not match its commitment")
            _need(status_matches(target["body"].get("status"), o["details"]),
                  f"step {h[:12]}: public status contradicts its revealed exit code")
        if target["kind"] == "activity" and isinstance(o.get("details"), dict):
            d = o["details"]
            command = json.dumps(d.get("command"), separators=(",", ":"))
            code = "?" if d.get("exit_code") is None else d["exit_code"]
            report.facts.append(f"step {h[:12]} ({target['body'].get('status')}) opened: exit "
                                f"code {code}, command {command}"
                                + (f", model {d['model']}" if d.get("model") else ""))
        elif not checks:
            report.facts.append(f"commitment of {h[:12]} opens to plaintext sha256 "
                                f"{o['plain_sha256'][:16]}…")
    unopened = sorted(set(external_contents) - set(openings))
    _need(not unopened, f"content supplied for {', '.join(h[:12] for h in unopened)}, which "
          f"this bundle does not open: it cannot be checked (prove with --open)")


def _linked_head(item: dict, bundle: dict) -> tuple[dict, str]:
    """Verify an older (or equal) head carried by an evidence item and its link to the bundle
    head: signed by its log, same project, consistent with the bundle head. Returns
    (head, log id); whether that log is trusted is the caller's decision."""
    head, older = bundle["head"], item["head"]
    log = verify_card(item["log_card"])
    _need(log.id == older["signer"], "evidence: log card does not match its head")
    verify_head(older, log)
    _need(older["project"] == bundle["project"], "evidence is for another project")
    _need(0 < older["size"] <= head["size"], "evidence head is newer than the bundle head")
    _need(older["time"] <= head["time"], "evidence head is dated after the bundle head")
    if older["size"] == head["size"]:
        _need(older["root"] == head["root"], "evidence head forks from the bundle head")
    else:
        merkle.verify_consistency(older["size"], head["size"], bytes.fromhex(older["root"]),
                                  bytes.fromhex(head["root"]),
                                  [bytes.fromhex(p) for p in item["consistency"]])
    return older, log.id


def _witness_and_anchor_facts(bundle, report, trust) -> None:
    """Cosignatures and anchors are always checked cryptographically; they raise the trust
    level only when signed by trusted keys over a trusted log and cover every target."""
    targets = {t: report.verified_entries[t] for t in bundle["targets"]}
    based_on_log = report.trust in (TRUST_LOG, TRUST_WITNESSED)

    sizes: dict[str, int] = {}  # trusted witness -> largest head it cosigned
    for item in bundle.get("cosignatures", []):
        cosigned, log_id = _linked_head(item, bundle)
        pub = verify_card(item["card"])
        verify_cosig(item["cosig"], cosigned, pub)
        what = (f"log head of size {cosigned['size']} cosigned by witness {pub.id} at "
                f"{_iso(item['cosig']['time'])}")
        if log_id in trust["logs"] and pub.id in trust["witnesses"]:
            sizes[pub.id] = max(sizes.get(pub.id, 0), cosigned["size"])
            report.facts.append(what)
        else:
            report.notes.append(f"{what} — not counted: witness or log not in your trusted set")
    # the project's own policy may ask for more than one independent witness
    genesis = next(it["entry"] for it in bundle["entries"] if it["index"] == 0)
    count = genesis["body"]["policy"].get("witnesses", 0)
    _need(isinstance(count, int) and not isinstance(count, bool), "genesis: witnesses")
    required = max(1, count)
    covering = sum(1 for n in sizes.values() if all(i < n for i in targets.values()))
    if based_on_log and targets and covering >= required:
        report.trust = TRUST_WITNESSED
    elif based_on_log and targets and covering:
        report.notes.append(f"the project's policy asks for {required} witnesses; {covering} "
                            "trusted witness(es) cover the targets: not witnessed")

    for item in bundle.get("anchors", []):
        anchored, log_id = _linked_head(item, bundle)
        provider, at, issuer, fingerprint = verify_anchor_record(
            item, anchored, log=verify_card(item["log_card"]))
        _need(at >= anchored["time"] - CLOCK_SKEW_MS,
              "anchor time precedes the head it anchors (inconsistent evidence)")
        covered = [t for t, i in targets.items() if i < anchored["size"]]
        trusted = log_id in trust["logs"] and (provider == "self" or fingerprint in trust["tsas"])
        for t in covered:
            claim = (f"entry {t[:12]} existed no later than {_iso(at)} "
                     f"(anchored via {provider}: {issuer})")
            if trusted:
                report.bound(t, at)
                report.facts.append(claim)
            else:
                report.notes.append(f"{claim} — not counted: "
                                    + ("TSA certificate not trusted (--trust-tsa "
                                       f"{fingerprint})" if provider != "self"
                                       else "log not trusted"))
        if provider == "self":
            report.notes.append("a `self` anchor is signed by the hub itself and adds no "
                                "independent time evidence")
        elif trusted and covered and len(covered) == len(targets) and \
                report.trust in (TRUST_LOG, TRUST_WITNESSED):
            report.trust = TRUST_ANCHORED


def _credential_facts(bundle, report, trust) -> None:
    """Who holds the authors' keys, per organisations the verifier trusts. A credential is
    checked at the head's time, so it is a fact only when that time comes from a trusted log
    (otherwise a backdated head could revive an expired credential). A credential that does
    not check out is reported, never fatal; credentials for non-authors are ignored."""
    authors = {it["entry"]["author"] for it in bundle["entries"]}
    time_trusted = report.trust in (TRUST_LOG, TRUST_WITNESSED, TRUST_ANCHORED)
    for item in bundle.get("credentials", []):
        cred = item.get("credential") if isinstance(item, dict) else None
        if not isinstance(cred, dict) or not isinstance(cred.get("subject"), str) \
                or cred["subject"] not in authors:
            continue  # credentials are unsigned bundle content: anything malformed is skipped
        try:
            issuer = identity.verify(cred, item["issuer_card"], at_ms=bundle["head"]["time"])
        except Exception as exc:  # never let a relayed credential invalidate the bundle
            report.notes.append(f"credential for {cred.get('subject')} not accepted: {exc}")
            continue
        claims = ", ".join(f"{k}: {v}" for k, v in sorted(cred["claims"].items()))
        what = f"author {cred['subject']} is {claims} per org {issuer.id}"
        if issuer.id not in trust["orgs"]:
            report.notes.append(f"{what} — not counted: org not in your trusted set")
        elif not time_trusted:
            report.notes.append(f"{what} — not counted: the head time it was checked at is "
                                "not from a trusted log")
        else:
            report.facts.append(what)


def _external_facts(bundle, report, trust, depth) -> None:
    """Inputs from other projects: each attached bundle is verified on its own, with the same
    trust sets, and must prove the cited entry. One level only (no bundles inside bundles)."""
    attached = bundle.get("external", [])
    _need(depth == 0 or not attached, "external bundles may not nest")
    _need(len(attached) <= MAX_EXTERNAL, "too many external bundles")
    reports = []
    for sub in attached:
        r = verify_bundle(sub, trusted_logs=trust["logs"], trusted_witnesses=trust["witnesses"],
                          trusted_tsas=trust["tsas"], trusted_orgs=trust["orgs"], _depth=1)
        _need(r.ok, f"external bundle for project {str(sub.get('project'))[:12]} is invalid: "
                    + "; ".join(r.errors))
        reports.append(r)
    for it in bundle["entries"]:
        e = it["entry"]
        h = entries.entry_hash(e)
        if e["kind"] != "activity" or h not in report.verified_entries:
            continue
        external = e["body"].get("external", [])
        _need(isinstance(external, list) and len(external) <= 100 and all(
            isinstance(x, dict) and set(x) == {"project", "entry"}
            and _HEX.fullmatch(str(x["project"])) and _HEX.fullmatch(str(x["entry"]))
            for x in external), "activity.external is malformed")
        for x in external:
            # the cited entry must be a *target* of the attached bundle: the trust level of a
            # bundle describes its targets, not every lineage entry it happens to carry
            proof = next((r for r in reports if r.project == x["project"]
                          and x["entry"] in r.verified_entries
                          and x["entry"] in r.targets), None)
            if proof is None:
                report.notes.append(f"activity {h[:12]} cites {x['entry'][:12]} in project "
                                    f"{x['project'][:12]}, but no attached bundle proves it")
                continue
            what = (f"activity {h[:12]} used entry {x['entry'][:12]} of project "
                    f"{x['project'][:12]} (that project's evidence: {proof.trust})")
            (report.facts if proof.trust in (TRUST_LOG, TRUST_WITNESSED, TRUST_ANCHORED)
             else report.notes).append(what)
