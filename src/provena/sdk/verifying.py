"""Verify a proof bundle from a program: the same verdict as `provena verify --json`."""

from __future__ import annotations

from pathlib import Path

from provena.core.verify import LEVELS, TRUST_LOG, load_bundle, verify_bundle
from provena.store.home import Home
from provena.store.repo import Repo

FORMAT = "provena-verify/1"


def verify(bundle: dict | str | Path, *, require: str | None = None,
           trusted_logs=(), trusted_witnesses=(), trusted_tsas=(), trusted_orgs=(),
           contents: dict[str, bytes] | None = None, use_home_trust: bool = True) -> dict:
    """Verify *bundle* (a dict, JSON text or a .pvb path) against the trust store of
    $PROVENA_HOME (unless *use_home_trust* is False) plus the given ids. Returns the
    provena-verify/1 verdict: valid, accepted, trust, entries[], preregistration[],
    evidence, facts, notes, errors."""
    if isinstance(bundle, Path) or (isinstance(bundle, str) and not bundle.lstrip()
                                    .startswith("{")):
        bundle = Path(bundle).read_text()
    if isinstance(bundle, str):
        bundle = load_bundle(bundle)
    store = Home().trust() if use_home_trust else {k: set() for k in Home.TRUST_KINDS}
    report = verify_bundle(bundle, trusted_logs=store["logs"] | set(trusted_logs),
                           trusted_witnesses=store["witnesses"] | set(trusted_witnesses),
                           trusted_tsas=store["tsas"] | set(trusted_tsas),
                           trusted_orgs=store["orgs"] | set(trusted_orgs),
                           external_contents=contents or {})
    reached = report.trust if report.ok else None
    accepted = report.ok and (require is None or (
        reached is not None and LEVELS.index(reached) >= LEVELS.index(require)))
    return {"format": FORMAT, "valid": report.ok, "accepted": accepted, "trust": reached,
            "require": {"level": require, "reached": reached, "ok": accepted}
            if require else None,
            "project": report.project, "mode": report.mode, "targets": report.targets,
            "head": {"size": report.head_size, "time": report.head_time,
                     "signer": report.head_signer},
            "entries": entry_facts(bundle, report) if report.ok else [],
            "preregistration": report.preregistration,
            "evidence": evidence_facts(bundle, report) if report.ok else {},
            "time_bounds": report.time_bounds, "facts": report.facts, "notes": report.notes,
            "errors": report.errors}


def entry_facts(bundle: dict, report) -> list[dict]:
    """Per proven entry, what a program needs without parsing `facts`."""
    by_hash = {Repo.hash_of(it["entry"]): it["entry"] for it in bundle.get("entries", [])}
    revealed = {e["body"]["target"] for e in by_hash.values() if e["kind"] == "reveal"}
    opened = set(bundle.get("openings", {})) | revealed
    rows = []
    for h, i in sorted(report.verified_entries.items(), key=lambda kv: kv[1]):
        e = by_hash.get(h, {})
        rows.append({"hash": h, "index": i, "kind": e.get("kind"), "author": e.get("author"),
                     "target": h in report.targets, "sequenced": report.sequenced.get(h),
                     "time_bound": report.time_bounds.get(h), "opened": h in opened})
    return rows


def evidence_facts(bundle: dict, report) -> dict:
    anchors = [{"provider": (a.get("anchor") or {}).get("provider"),
                "tsa": ((a.get("anchor") or {}).get("receipt") or {}).get("tsa")}
               for a in bundle.get("anchors", [])]
    return {"head_signer": report.head_signer, "log_trusted": report.trust in (
        TRUST_LOG, "witnessed", "anchored"),
            # witnesses whose cosignatures the bundle carries (trusted or not: see `trust`)
            "witnesses": sorted({(item.get("card") or {}).get("id")
                                 for item in bundle.get("cosignatures", [])} - {None}),
            "anchors": anchors}
