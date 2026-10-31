"""Challenge rules (docs/design/challenge-mode.md), as pure functions over ledger data.

Callers bring the data: the CLI from proof bundles (times from trusted receipts in a verify
report), the hub from its own logs and receipts. Nothing here reads files or the network, so
the evaluator, a third-party auditor and the hub's challenge page apply the same rules.
"""

from __future__ import annotations

import re
from datetime import datetime

from provena.core import entries
from provena.core.errors import ProvenaError

MARK = "<!-- provena-challenge"
TERMS_RE = re.compile(re.escape(MARK) + r"\n(.*?)\n-->", re.S)
TERM_KEYS = ("truth", "targets", "scorer", "scorer-sha256", "deadline", "deadline-ms", "teams")
BOARD_KEYS = ("team", "project", "predictions", "on_time")


class ChallengeError(ProvenaError):
    """A challenge rule is broken. *error* is the CLI contract code (E_VOID, E_LATE, …) or None
    for invalid input; *hint* the next thing to try."""

    def __init__(self, message: str, error: str | None = None, hint: str | None = None):
        super().__init__(message)
        self.error, self.hint = error, hint


def parse_time(text: str) -> int:
    """ISO 8601 with an explicit zone -> ms since the epoch."""
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ChallengeError(f"need an ISO 8601 time, e.g. 2026-11-01T00:00Z ({exc})") from exc
    if value.tzinfo is None:
        raise ChallengeError("need an explicit time zone (Z or +08:00)")
    return int(value.timestamp() * 1000)


def terms_block(truth: str, targets: str, scorer: str, score_sha: str, deadline: str,
                deadline_ms: int, teams: list[str]) -> str:
    return (f"\n{MARK}\n"
            f"truth: {truth}\ntargets: {targets}\nscorer: {scorer}\n"
            f"scorer-sha256: {score_sha}\ndeadline: {deadline}\ndeadline-ms: {deadline_ms}\n"
            f"teams: {','.join(teams)}\n-->\n")


def parse_team(spec: str) -> str:
    """A registered team is an agent *and* the one project it submits from: registering only
    agents would let a team submit from several projects and forward its best (review 7)."""
    agent, sep, project = spec.partition(":")
    if not sep or not agent.startswith("pv1") or not re.fullmatch(r"[0-9a-f]{64}", project):
        raise ChallengeError(f"--team takes AGENT_ID:PROJECT_ID, not {spec!r}")
    return spec


def parse_terms(text: str) -> dict:
    """Exactly one terms block, every key once, and a deadline whose machine and human forms
    agree: what the evaluator enforces is what readers of the protocol see."""
    blocks = TERMS_RE.findall(text)
    if len(blocks) != 1 or text.count(MARK) != 1:
        raise ChallengeError("protocol must contain exactly one provena-challenge terms block")
    terms: dict = {}
    for line in blocks[0].splitlines():
        key, sep, value = line.partition(": ")
        if not sep or key not in TERM_KEYS or key in terms:
            raise ChallengeError(f"protocol terms: unexpected or repeated line {line!r}")
        terms[key] = value
    if set(terms) != set(TERM_KEYS):
        raise ChallengeError(f"protocol terms lack {sorted(set(TERM_KEYS) - set(terms))}")
    if not re.fullmatch(r"[0-9]{1,15}", terms["deadline-ms"]):
        raise ChallengeError("protocol terms: deadline-ms must be plain digits")
    terms["deadline-ms"] = int(terms["deadline-ms"])
    if parse_time(terms["deadline"]) != terms["deadline-ms"]:
        raise ChallengeError("protocol terms: deadline and deadline-ms disagree")
    terms["teams"] = [parse_team(t) for t in terms["teams"].split(",") if t]
    return terms


def on_time(sequenced: dict[str, int], pred: str, grant: str, deadline: int) -> bool:
    """On time / late only from *trusted hub receipts* of the predictions and the grant: a
    head-time bound alone would let anyone who re-bundles the team's project (with a later head
    and the receipts stripped) make an on-time submission look late."""
    times = [sequenced.get(h) for h in (pred, grant)]
    if None in times:
        raise ChallengeError(f"submission {pred[:12]}: no trusted hub receipts for the "
                             "predictions and grant, so its timing is unprovable (ask the team "
                             "for its bundle)")
    return max(times) <= deadline


def organizer_log(log: list[dict], sequenced: dict[str, int], protocol: str,
                  terms: dict) -> tuple[set, set]:
    """Checks on the organizer's full log; returns (its plan hashes, every agent that was ever a
    member and so could read the truth before its reveal). Up to the deadline the log may
    disclose only the public terms (protocol, targets, scorer); every other reveal or grant must
    be sequenced by a trusted log after it — a copy of the truth under another entry, or even a
    key-less opening (salt + content hash) of a small label file, would leak it. A submission
    citing any *other* plan of the organizer exposes terms handed out selectively."""
    hashes = [entries.entry_hash(e) for e in log]
    if protocol not in hashes:
        raise ChallengeError("the organizer's log does not contain the protocol")
    public = {protocol, terms["targets"], terms["scorer"]}
    for h, e in zip(hashes, log, strict=True):
        if e["kind"] not in ("reveal", "grant"):
            continue
        if e["kind"] == "reveal" and e["body"]["target"] in public:
            continue
        at = sequenced.get(h)
        if at is None or at <= terms["deadline-ms"]:
            what = "the truth" if e["body"]["target"] == terms["truth"] else "content"
            when = "without trusted time" if at is None else "before the deadline"
            raise ChallengeError(f"{what} was disclosed by entry {h[:12]} {when}: challenge "
                                 "void", "E_VOID")
    plans = {h for h, e in zip(hashes, log, strict=True) if e["kind"] == "plan"}
    members = {m["card"]["id"] for m in log[0]["body"]["members"]}
    members |= {e["body"]["card"]["id"] for e in log
                if e["kind"] in ("member", "key") and "card" in e["body"]}
    return plans, members


def submission(project: str, log: list[dict], targets: set[str] | None, org: str,
               protocol: str, evaluator_id: str, org_plans: set[str]) -> tuple[str, str, str]:
    """(team agent id, predictions entry, grant entry) derived from the team's full log — never
    from hints. Exactly one activity may cite this challenge's protocol, generating exactly one
    entity, and exactly one grant of it to this evaluator may exist. *targets*: what the bundle
    proves (None when the log itself is the source, as on the hub)."""
    hashes = [entries.entry_hash(e) for e in log]
    other = {x["entry"] for e in log if e["kind"] == "activity"
             for x in e["body"].get("external", [])
             if x["project"] == org and x["entry"] in org_plans - {protocol}}
    if other:
        raise ChallengeError(f"project {project[:12]} cites another plan of the organizer "
                             f"({sorted(other)[0][:12]}): the organizer handed out different "
                             "terms")
    cites = [(h, e) for h, e in zip(hashes, log, strict=True) if e["kind"] == "activity"
             and {"project": org, "entry": protocol} in e["body"].get("external", [])]
    if len(cites) != 1 or len(cites[0][1]["body"].get("generated", [])) != 1:
        raise ChallengeError(f"project {project[:12]} must contain exactly one submission")
    _, activity = cites[0]
    pred = activity["body"]["generated"][0]
    grants = [h for h, e in zip(hashes, log, strict=True) if e["kind"] == "grant"
              and e["body"]["to"]["id"] == evaluator_id]
    if len(grants) != 1 or log[hashes.index(grants[0])]["body"]["target"] != pred:
        raise ChallengeError(f"project {project[:12]} must grant exactly its one submission "
                             "to the evaluator")
    if targets is not None and not {pred, grants[0]} <= targets:
        raise ChallengeError(f"bundle for {project[:12]} must target the submission and grant")
    return activity["author"], pred, grants[0]


def eligible(team: str, project: str, terms: dict, evaluator_id: str,
             org_members: set[str]) -> None:
    """Who may be on the board at all."""
    if team == evaluator_id:
        raise ChallengeError("the evaluator cannot compete in its own challenge")
    if team in org_members:
        raise ChallengeError(f"{team} is a member of the organizer's project (could read the "
                             "truth)")
    if terms["teams"] and f"{team}:{project}" not in terms["teams"]:
        raise ChallengeError(f"{team} with project {project[:12]} is not a registered team")
