"""The hub's own check of a published leaderboard, with the rules `challenge audit` applies
(provena.core.challenge) over the logs and receipt times this hub holds.

It is a second opinion, not proof: a reader who does not trust this hub runs
`provena challenge audit` on the bundles. Scores stay the evaluator's claim either way.
"""

from __future__ import annotations

import hashlib
from contextlib import closing

from provena.core import aead
from provena.core import challenge as rules
from provena.core.encoding import unb64u
from provena.core.errors import ProvenaError

MAX_ROWS = 100       # rows checked per leaderboard (bounded work per page view)
MAX_PLAIN = 1 << 20  # protocol size read for its terms


def published_plain(hub, pid: str, state, h: str, limit: int = MAX_PLAIN) -> bytes | None:
    """The content of entry *h* if it was published with its key and matches the ledger."""
    rv = state.reveals.get(h)
    body = state.entries[h]["body"] if h in state.entries else {}
    if (not rv or not rv.get("dek") or h in state.redacted or not body.get("cid")
            or body.get("size", 0) > limit + 4096 or not hub.blob_owner(pid, body["cid"])):
        return None
    try:
        with closing(hub.storage.blobs_open(pid, body["cid"])) as src:
            plain = aead.decrypt_bytes(unb64u(rv["dek"]), src.read())
    except (ProvenaError, ValueError, OSError):
        return None
    return plain if hashlib.sha256(plain).hexdigest() == rv["plain_sha256"] else None


def _log_until(hub, project: str, cutoff: int) -> tuple[list[dict], dict[str, int]]:
    """The project's log as sequenced up to *cutoff* (ms), with this hub's receipt times: the
    check judges what existed when the board was scored, so later entries cannot change it."""
    state = hub._state(project)
    times = hub.storage.sequenced_times(project)
    return [state.entries[h] for h in state.order if times.get(h, cutoff + 1) <= cutoff], times


_CACHE: dict[tuple, dict] = {}  # (scoring step, board digest) -> result; logs before the cutoff
_CACHE_MAX = 256                # never change, so a result never goes stale


def check(hub, activity: dict, rows: list[dict], cutoff: int) -> dict:
    """The hub's verdict on a leaderboard produced by the scoring step *activity*, sequenced at
    *cutoff*: {"verdict": "ok" | "ok-open" | "partial" | "fail" | "unchecked", "why",
    "protocol", "org", "rows": {index: (ok | None, why)}, "absent": [...]}. Only "ok" means
    every row was re-derived here and no registered on-time submission is missing."""
    key = (hashlib.sha256(repr((sorted(activity.items()), rows, cutoff)).encode()).hexdigest(),)
    if key in _CACHE:
        return _CACHE[key]
    out = _check(hub, activity, rows, cutoff)
    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.pop(next(iter(_CACHE)))
    _CACHE[key] = out
    return out


def _check(hub, activity: dict, rows: list[dict], cutoff: int) -> dict:
    out = {"verdict": "unchecked", "why": "", "protocol": None, "org": None, "rows": {},
           "absent": []}
    if len(rows) > MAX_ROWS:
        out["why"] = f"the board has {len(rows)} rows; this hub checks boards of up to {MAX_ROWS}"
        return out
    cited = {(x["project"], x["entry"]) for x in activity["body"].get("external", [])}
    protocol = org = terms = None
    for project, entry in sorted(cited):
        try:
            state = hub._state(project)
        except Exception:  # noqa: BLE001 — not on this hub
            continue
        if state.entries.get(entry, {}).get("kind") != "plan":
            continue
        plain = published_plain(hub, project, state, entry)
        if plain is None or rules.MARK.encode() not in plain:
            continue
        if protocol is not None:
            out["why"] = "the scoring step cites more than one challenge protocol"
            return out
        try:
            terms = rules.parse_terms(plain.decode())
        except (rules.ChallengeError, UnicodeDecodeError) as exc:
            out["why"] = f"protocol {entry[:12]}: {exc}"
            return out
        protocol, org = entry, project
    if protocol is None:
        out["why"] = "no published challenge protocol among the cited entries on this hub"
        return out
    out["protocol"], out["org"] = protocol, org
    deadline, evaluator, bad, unchecked = terms["deadline-ms"], activity["author"], 0, 0
    if len(terms["teams"]) > MAX_ROWS:
        out["why"] = f"{len(terms['teams'])} registered teams; this hub checks up to {MAX_ROWS}"
        out["verdict"] = "unchecked"
        return out
    try:
        org_log, org_times = _log_until(hub, org, cutoff)
        for name, h in (("protocol", protocol), ("truth commitment", terms["truth"])):
            if org_times.get(h, deadline + 1) > deadline:
                raise rules.ChallengeError(f"the {name} was not sequenced before the deadline",
                                           "E_VOID")
        plans, members = rules.organizer_log(org_log, org_times, protocol, terms)
        projects = [r["project"] for r in rows]
        if len(set(projects)) != len(projects) or len({r["team"] for r in rows}) != len(rows):
            raise rules.ChallengeError("the board lists a team or project more than once")
        expected = {(org, protocol), (org, terms["truth"]), (org, terms["scorer"])}
        expected |= {(r["project"], r.get("predictions")) for r in rows}
        if cited != expected:
            raise rules.ChallengeError("the scoring step does not cite exactly the protocol, "
                                       "truth, scorer and the scored submissions")
    except (rules.ChallengeError, TypeError) as exc:
        out.update(verdict="fail", why=str(exc))
        return out
    for i, r in enumerate(rows):
        try:
            log, times = _log_until(hub, r["project"], cutoff)
        except Exception:  # noqa: BLE001
            out["rows"][i] = (None, "project not on this hub")
            unchecked += 1
            continue
        try:
            team, pred, grant = rules.submission(r["project"], log, None, org, protocol,
                                                 evaluator, plans)
            rules.eligible(team, r["project"], terms, evaluator, members)
            on_time = rules.on_time(times, pred, grant, deadline)
            if (team, pred, on_time) != (r["team"], r.get("predictions"), r["on_time"]):
                raise rules.ChallengeError("row differs from the team's log "
                                           f"(on time: {'yes' if on_time else 'no'})")
            out["rows"][i] = (True, "")
        except rules.ChallengeError as exc:
            out["rows"][i] = (False, str(exc))
            bad += 1
    on_board = set(projects)
    for spec in terms["teams"]:
        agent, _, project = spec.partition(":")
        if project in on_board:
            continue
        try:
            log, times = _log_until(hub, project, cutoff)
            team, pred, grant = rules.submission(project, log, None, org, protocol, evaluator,
                                                 plans)
            if team == agent and rules.on_time(times, pred, grant, deadline):
                bad += 1
                out["absent"].append(f"{spec} (submitted on time, not on the board)")
                continue
        except Exception:  # noqa: BLE001 — no valid submission here: absent, not omitted
            pass
        out["absent"].append(spec)
    out["verdict"] = ("fail" if bad else "partial" if unchecked
                      else "ok" if terms["teams"] else "ok-open")
    if unchecked:
        out["why"] = f"{unchecked} row(s) are projects this hub does not hold"
    return out
