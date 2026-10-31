"""`provena challenge`: preregistered, blinded challenges (experimental).

Wraps the flow of docs/design/challenge-mode.md and examples/challenge_demo.sh with the design's
recommended defaults (predictions go to the evaluator only; the evaluator is a separate agent).
All guarantees come from the ordinary ledger, bundles and verifier: the `challenge` / `submission`
fields added to bundles are unsigned hints, always re-checked against proven entries.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from provena.cli import output, sandbox
from provena.cli.common import EXIT_CHALLENGE, CliError, _agent_name, _load_agent, _when
from provena.core import builders, merkle
from provena.core import challenge as rules
from provena.core.challenge import BOARD_KEYS, MARK, ChallengeError
from provena.core.encoding import unb64u
from provena.core.verify import MAX_EXTERNAL, load_bundle, verify_bundle
from provena.sdk import Project, sync
from provena.store.content import decrypt_verified
from provena.store.home import Home, home_dir
from provena.store.repo import Repo


def _project(args) -> Project:
    repo = Repo.find()
    return Project(repo, _load_agent(args, repo), _agent_name(args, repo))


def _deadline_ms(text: str) -> int:
    from provena.cli.proofs import _parse_deadline

    return _parse_deadline(text)


def _push(proj: Project) -> None:
    if proj.repo.config.get("hub"):
        proj.push()


def _verify(path: Path, label: str):
    bundle = load_bundle(path.read_text())
    report = verify_bundle(bundle, **_trust_kwargs())
    if not report.ok:
        raise CliError(f"{label} does not verify: " + "; ".join(report.errors))
    return bundle, report


def _open_target(bundle: dict, target: str, dest: Path, hub_url: str, agent, *,
                 published: bool = False) -> Path:
    """Decrypt one target of *bundle* that is published with its key or (unless *published*)
    granted to us. Challenge terms, inputs, scorer and truth must be *published*: everyone,
    not only the evaluator, can then read and audit them."""
    for it in bundle["entries"]:
        e, body = it["entry"], it["entry"]["body"]
        if body.get("target") != target:
            continue
        if e["kind"] == "reveal" and body.get("dek"):
            dek, salt, plain = unb64u(body["dek"]), body["salt"], body["plain_sha256"]
        elif e["kind"] == "grant" and not published and agent and body["to"]["id"] == agent.id:
            secret = builders.open_grant(e, agent)
            dek, salt, plain = secret["dek"], secret["salt"], secret["plain_sha256"]
        else:
            continue
        content = next(x["entry"]["body"] for x in bundle["entries"]
                       if Repo.hash_of(x["entry"]) == target)
        cipher = dest.with_name(dest.name + ".provena-cipher")
        dest.parent.mkdir(parents=True, exist_ok=True)
        sync.make_client(hub_url, agent).download_blob(bundle["project"], content["cid"], cipher,
                                                       max_size=content["size"])
        try:
            decrypt_verified(cipher, dek, dest, salt, plain, content["commitment"])
        finally:
            cipher.unlink(missing_ok=True)
        return dest
    raise CliError(f"bundle does not publish{'' if published else ' or grant you'} entry "
                   f"{target[:12]}")


# -- the protocol is the signed authority -------------------------------------------------------
# Everything a verifier relies on (which entry is the truth, the inputs, the scorer, the deadline,
# who may submit) is written into the preregistered protocol, which is published with its key.
# The `challenge` hint in bundles only says which entry the protocol is.

_terms_block, _team, _terms = rules.terms_block, rules.parse_team, rules.parse_terms


def _protocol_terms(bundle: dict, report, hub_url: str, agent, work: Path) -> tuple[str, dict]:
    """The protocol entry named by the hint must be a proven target with published content."""
    protocol = (bundle.get("challenge") or {}).get("protocol")
    if protocol not in report.targets:
        raise CliError("challenge bundle does not prove its protocol entry")
    path = _open_target(bundle, protocol, work / "protocol.md", hub_url, agent, published=True)
    terms = _terms(path.read_text())
    if not {terms["truth"], terms["targets"], terms["scorer"]} <= set(report.targets):
        raise CliError("challenge bundle does not prove the truth, targets and scorer named by "
                       "the protocol")
    if len({protocol, terms["truth"], terms["targets"], terms["scorer"]}) != 4:
        # the truth must never be one of the items published before the deadline
        raise CliError("protocol, truth, targets and scorer must be four different entries")
    return protocol, terms


def _on_time(report, pred: str, grant: str, deadline: int) -> bool:
    return rules.on_time(report.sequenced, pred, grant, deadline)


# -- organizer ----------------------------------------------------------------------------------

def _prior_disclosures(proj: Project) -> list[str]:
    return [h for h, e in proj.repo.state.entries.items() if e["kind"] in ("reveal", "grant")]


def cmd_init(args):
    proj = _project(args)
    if proj.repo.state.policy["visibility"] != "public":
        raise CliError("run challenges from a public project (`provena init --public`)")
    if not proj.repo.config.get("hub"):  # without hub receipts nothing is provably on time
        raise CliError("configure the hub first (`provena remote URL`): the protocol and the "
                       "truth commitment need hub receipts dated before the deadline")
    deadline = _deadline_ms(args.deadline)
    if deadline <= time.time() * 1000:
        raise CliError(f"the deadline {_when(deadline)} is not in the future: teams could "
                       f"never submit on time")
    if proj.repo.read_extra("challenge.json", None):
        raise CliError("this project already runs a challenge: use a new public project "
                       "for each challenge (its log must contain only this one)")
    disclosed = _prior_disclosures(proj)
    if disclosed:  # the evaluator would void the challenge: refuse now, not at the deadline
        raise CliError(f"this project already disclosed content ({len(disclosed)} reveal/grant "
                       f"entries, e.g. {disclosed[0][:12]}); before the deadline a challenge "
                       f"project may disclose only its protocol, targets and scorer",
                       error="E_VOID", hint="use a new public project; put public inputs such "
                       "as training data into the --targets file")
    teams = [_team(t) for t in args.team]
    head = Path(args.protocol).read_text() if args.protocol else (
        f"# {args.title}\n\nSubmission deadline: {args.deadline}\n"
        f"Scoring program: {Path(args.score).name}\n"
        "Ground truth is committed now and revealed after the deadline.\n")
    if MARK in head:
        raise CliError("--protocol text must not contain its own provena-challenge block")
    score_sha = hashlib.sha256(Path(args.score).read_bytes()).hexdigest()
    truth = proj.plan(args.truth, title="ground truth")          # commitment only
    targets = proj.add(args.targets)
    score = proj.add(args.score)
    protocol = Path("challenge-protocol.md")
    protocol.write_text(head + _terms_block(truth, targets, score, score_sha, args.deadline,
                                            deadline, teams))
    p = proj.plan(protocol, title="protocol")
    with proj.repo.writing():
        proj.repo.append(builders.meta(proj.repo.state, proj.agent, title=args.title,
                                       description=f"Challenge. Deadline {args.deadline}.",
                                       tags=["challenge"]))
    _push(proj)
    for h in (p, targets, score):                                 # protocol, inputs, scorer public
        proj.reveal(h, with_key=True, with_name=True)
    _push(proj)
    info = {"protocol": p, "truth": truth, "targets": targets, "score": score,
            "deadline": deadline, "title": args.title}
    proj.repo.write_extra("challenge.json", info)
    bundle = proj.prove([p, truth, targets, score])
    Path(args.output).write_text(json.dumps({**bundle, "challenge": {"protocol": p}}, indent=1))
    output.data(organizer_project=proj.id, protocol=p, truth=truth, targets=targets,
                scorer=score, deadline_ms=deadline, teams=teams,
                bundle=str(Path(args.output).resolve()))
    print(f"challenge {args.title!r}: truth committed ({truth[:12]}), protocol {p[:12]}, "
          f"deadline {_when(deadline)}; give teams {args.output}")


def cmd_close(args):
    proj = _project(args)
    info = proj.repo.read_extra("challenge.json", None)
    if not info:
        raise CliError("no challenge here (run `provena challenge init` first)")
    if time.time() * 1000 <= info["deadline"]:
        # a truth revealed early lets anyone submit it "on time"; evaluators reject it anyway
        output.data(deadline_ms=info["deadline"])
        raise CliError(f"the deadline ({_when(info['deadline'])}) has not passed",
                       error="E_TOO_EARLY", hint="wait until the deadline, then close")
    if not proj.repo.config.get("hub"):
        raise CliError("the reveal needs a hub receipt dated after the deadline (`provena "
                       "remote`)")
    done = proj.repo.state.reveals.get(info["truth"])
    if done and done.get("dek"):  # closed before: write the truth bundle again (idempotent)
        reveal = next(h for h in reversed(proj.repo.state.order)
                      if proj.repo.entry(h)["kind"] == "reveal"
                      and proj.repo.entry(h)["body"]["target"] == info["truth"])
        output.data(unchanged=True)
    else:
        reveal = proj.reveal(info["truth"], with_key=True, with_name=True)
    _push(proj)
    # full: the evaluator checks every disclosure of the truth in the organizer's log
    bundle = proj.prove([info["truth"], reveal], full=True)
    Path(args.output).write_text(json.dumps(bundle, indent=1))
    output.data(truth=info["truth"], reveal=reveal, bundle=str(Path(args.output).resolve()))
    print(f"ground truth revealed; give the evaluator {args.output}")


# -- team ----------------------------------------------------------------------------------------

def cmd_submit(args):
    challenge, report = _verify(Path(args.challenge), "challenge bundle")
    proj = _project(args)
    hub = args.hub or proj.repo.config.get("hub")
    if not hub:
        raise CliError("configure a hub (`provena remote`) or pass --hub")
    work = Path(tempfile.mkdtemp(prefix="provena-submit-"))
    protocol, terms = _protocol_terms(challenge, report, hub, proj.agent, work)
    print(f"protocol {protocol[:12]}: deadline {_when(terms['deadline-ms'])}, scorer sha256 "
          f"{terms['scorer-sha256'][:16]}…, teams: "
          f"{', '.join(terms['teams']) or 'open registration'}")
    mine = f"{proj.agent.id}:{proj.id}"
    if terms["teams"] and mine not in terms["teams"]:
        raise CliError(f"this agent and project ({mine}) are not a registered team",
                       error="E_FORBIDDEN", hint="ask the organizer to register AGENT:PROJECT")
    card = json.loads(Path(args.evaluator).read_text())
    cited = [h for h, e in proj.repo.state.entries.items() if e["kind"] == "activity"
             and {"project": challenge["project"], "entry": protocol}
             in e["body"].get("external", [])]
    if cited:
        # a submit cut short (e.g. the hub was down) resumes with the same predictions; any
        # other second submission is refused: it would void this team's entry
        pred = proj.repo.state.entries[cited[0]]["body"]["generated"][0]
        private = builders.open_entry_fields(proj.repo.state, proj.agent, proj.repo.entry(pred))
        same = hashlib.sha256(Path(args.predictions).read_bytes()).hexdigest() == \
            private["plain_sha256"]
        if len(cited) > 1 or not same:
            output.data(existing_submission=pred, activity=cited[0])
            raise CliError(f"this project already submitted ({cited[0][:12]}): a challenge "
                           f"takes exactly one submission per team, and a second one voids "
                           f"yours", error="E_CONFLICT")
        print(f"resuming the submission {pred[:12]} recorded earlier")
    else:
        with proj.run("challenge submission",
                      external=[(challenge["project"], protocol),
                                (challenge["project"], terms["targets"])]) as run:
            run.output(args.predictions)
        pred = run.outputs[0]
    _push(proj)
    granted = [h for h, e in proj.repo.state.entries.items() if e["kind"] == "grant"
               and e["body"]["target"] == pred and e["body"]["to"]["id"] == card["id"]]
    grant = granted[0] if granted else proj.share(pred, card)
    _push(proj)
    # full bundle: the evaluator must see the team's whole log to count submissions and grants.
    # It is attached to the public leaderboard, so the log's *structure* (kinds, authors, times,
    # recipients) becomes public: submit from a project dedicated to this challenge.
    bundle = proj.prove([pred, grant], full=True)
    out = Path(args.output)
    out.write_text(json.dumps(bundle, indent=1))
    sub = verify_bundle(load_bundle(json.dumps(bundle)), **_trust_kwargs())
    try:
        on_time = _on_time(sub, pred, grant, terms["deadline-ms"])
        status = "ON TIME" if on_time else "LATE"
    except (CliError, ChallengeError):
        on_time, status = None, "not yet provable (push to a trusted hub)"
    output.data(project=proj.id, team=proj.agent.id, protocol=protocol,
                predictions=pred, grant=grant, deadline_ms=terms["deadline-ms"],
                on_time=on_time, bundle=str(out.resolve()))
    if on_time is False:
        output.error("E_LATE", "the submission was sequenced after the deadline")
    print(f"submitted {pred[:12]}; {status}; send {out} to the evaluator (keep a "
          f"copy: `challenge audit --submission` checks the leaderboard against it). Do not "
          f"write to this project again before the deadline")
    return 0 if on_time else EXIT_CHALLENGE


# -- evaluator ----------------------------------------------------------------------------------

def _organizer_log(truth_bundle: dict, report, protocol: str, terms: dict) -> tuple[set, set]:
    if truth_bundle.get("mode") != "full":
        raise CliError("truth bundle must be a full bundle of the organizer's project")
    return rules.organizer_log([it["entry"] for it in truth_bundle["entries"]],
                               report.sequenced, protocol, terms)


def _submission(sub: dict, report, org: str, protocol: str, evaluator_id: str,
                org_plans: set[str]) -> tuple:
    if sub.get("mode") != "full":
        raise CliError(f"submission from {sub.get('project', '?')[:12]} must be a full bundle")
    return rules.submission(sub["project"], [it["entry"] for it in sub["entries"]],
                            set(report.targets), org, protocol, evaluator_id, org_plans)


def _check_inputs(challenge: dict, ch_report, truth_bundle: dict, tr_report,
                  subs: list[tuple[dict, object]], evaluator_id: str, hub: str, agent,
                  work: Path) -> tuple[str, dict, list[dict]]:
    """Every rule the evaluator applies before scoring, and any third party re-applies to a
    published leaderboard (`challenge audit`). Returns (protocol, terms, rows); each row's
    team, project, predictions entry and on_time are derived from proofs, never hints."""
    org = challenge["project"]
    protocol, terms = _protocol_terms(challenge, ch_report, hub, agent, work)
    deadline = terms["deadline-ms"]
    if len(subs) + 2 > MAX_EXTERNAL:
        raise CliError(f"at most {MAX_EXTERNAL - 2} submissions fit in one leaderboard bundle")
    for name, h in (("protocol", protocol), ("truth commitment", terms["truth"])):
        bound = ch_report.time_bounds.get(h)
        if bound is None or bound > deadline:
            untrusted = ch_report.trust in ("unverified", "self-sequenced")
            raise CliError(f"the {name} is not provably fixed before the deadline"
                           + (f": its time comes from log key {ch_report.head_signer}, which "
                              f"you do not trust" if untrusted else ""),
                           error="E_UNTRUSTED" if untrusted else "E_VOID",
                           hint=f"provena trust add log {ch_report.head_signer} (after checking "
                           f"it against the key the organizer published)" if untrusted
                           else None)
    if truth_bundle["project"] != org or terms["truth"] not in tr_report.targets:
        raise CliError("truth bundle does not prove the truth entry named by the protocol")
    org_plans, org_members = _organizer_log(truth_bundle, tr_report, protocol, terms)
    rows, seen = [], set()
    for sub, report in subs:
        team, pred, grant = _submission(sub, report, org, protocol, evaluator_id, org_plans)
        rules.eligible(team, sub["project"], terms, evaluator_id, org_members)
        if team in seen:
            raise CliError(f"more than one submission from {team}")
        seen.add(team)
        _complete_before_deadline(sub, deadline, hub, agent)
        on_time = _on_time(report, pred, grant, deadline)
        rows.append({"team": team, "project": sub["project"], "predictions": pred,
                     "on_time": on_time, "bundle": sub})
    return protocol, terms, rows


def _complete_before_deadline(sub: dict, deadline: int, hub: str, agent) -> None:
    """A team's bundle must hold everything its log sequenced before the deadline, or an
    early snapshot could hide a second submission. Tree heads are public: the hub's head one
    entry past the bundle is dated when that entry was sequenced."""
    from provena.client.hub import HubError
    from provena.core.keys import verify_card
    from provena.core.treehead import verify_head

    head = sub["head"]
    client = sync.make_client(hub, agent)
    try:
        nxt = client.sth(sub["project"], head["size"] + 1)
    except HubError as exc:
        if exc.status == 404:
            return  # nothing after the bundle
        raise
    pub = verify_card(sub["head_signer"])
    verify_head(nxt, pub)
    if nxt["signer"] != head["signer"] or nxt["project"] != sub["project"]:
        raise CliError("the hub answered with a head of another log")
    proof = [bytes.fromhex(p) for p in client.consistency(sub["project"], head["size"],
                                                          nxt["size"])]
    merkle.verify_consistency(head["size"], nxt["size"], bytes.fromhex(head["root"]),
                              bytes.fromhex(nxt["root"]), proof)
    if nxt["time"] <= deadline:
        raise CliError(f"the bundle of project {sub['project'][:12]} stops at entry "
                       f"{head['size'] - 1}, but its log has entries sequenced before the "
                       f"deadline after that: the team must send a bundle made after the "
                       f"deadline (`provena prove --full` on its submission and grant)")


def cmd_score(args):
    proj = _project(args)
    if not proj.repo.config.get("hub"):
        raise CliError("configure the hub first (`provena remote URL`): the leaderboard is "
                       "published there for `challenge audit`")
    work = Path(args.workdir or tempfile.mkdtemp(prefix="provena-challenge-")).resolve()
    challenge, ch_report = _verify(Path(args.challenge), "challenge bundle")
    truth_bundle, tr_report = _verify(Path(args.truth), "truth bundle")
    subs = [_verify(Path(path), f"submission {path}") for path in args.submission]
    protocol, terms, rows = _check_inputs(challenge, ch_report, truth_bundle, tr_report, subs,
                                          proj.agent.id, args.hub, proj.agent, work)
    org = challenge["project"]
    truth = _open_target(truth_bundle, terms["truth"], work / "truth.csv", args.hub, proj.agent,
                         published=True)
    score_entry = terms["scorer"]
    score = _open_target(challenge, score_entry, work / "score.py", args.hub, proj.agent,
                         published=True)
    score_sha = hashlib.sha256(score.read_bytes()).hexdigest()
    if score_sha != terms["scorer-sha256"]:
        raise CliError("scoring program does not match the hash in the preregistered protocol")
    if not args.yes:  # the scorer is the organizer's code: run it only on explicit consent
        how = sandbox.available() if args.sandbox != "off" else None
        how = f"sandboxed with {how}" if how else "NOT sandboxed"
        print(f"the scoring program from project {org[:12]} is in {score}; read it, then "
              f"re-run with --yes to execute it ({how})")
        output.data(scorer=str(score), scorer_sha256=score_sha, sandbox=how)
        output.error("E_CONFIRM", "the organizer's scoring program runs only with --yes",
                     f"read {score}, then add --yes")
        return 2
    external = [(org, protocol), (org, terms["truth"]), (org, score_entry)]
    for r in rows:
        r["path"] = str(Path("submissions") / r["project"][:16] / "predictions.csv")
        _open_target(r["bundle"], r["predictions"], work / r["path"], args.hub, proj.agent)
        external.append((r["project"], r["predictions"]))
    if not terms["teams"]:
        output.warn("W_OPEN_REGISTRATION", "open registration — one entrant can still submit "
                    "from several keys; register AGENT:PROJECT teams to prevent best-of-N")
    eligible = [r for r in rows if r["on_time"] or args.include_late]
    env = {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8", "HOME": str(work),
           "PYTHONDONTWRITEBYTECODE": "1"}
    with proj.run("challenge scoring", external=external,
                  params={"scorer_sha256": score_sha}) as run:
        sandbox.run_untrusted([sys.executable, "score.py", *[r["path"] for r in eligible]],
                              work=work, env=env, timeout=args.timeout, mode=args.sandbox,
                              deny_read=[home_dir(), proj.repo.dir, proj.repo.root])
        raw = _scores(work / "scores.json", [r["path"] for r in eligible])
        board = [{**{k: r[k] for k in BOARD_KEYS}, "score": raw.get(r["path"]),
                  "protocol": protocol} for r in rows]  # which challenge this row belongs to
        local = proj.repo.root / "leaderboard.json"
        local.write_text(json.dumps(board, indent=2))
        run.output(local)
    board_entry = run.outputs[0]
    _push(proj)
    published = proj.reveal(board_entry, with_key=True, with_name=True)   # anyone can audit
    _push(proj)
    bundle = proj.prove([board_entry, published],
                        external=[challenge, truth_bundle, *(r["bundle"] for r in rows)])
    Path(args.output).write_text(json.dumps(bundle, indent=1))
    output.data(protocol=protocol, leaderboard=board_entry, rows=board,
                bundle=str(Path(args.output).resolve()))
    print(f"{'team (agent)':<38} {'on time':<8} score")
    for r in board:
        print(f"{r['team']:<38} {'yes' if r['on_time'] else 'NO':<8} {r['score']}")
    print(f"leaderboard proof: {args.output}; inputs in {work} ({truth.name}, score.py, "
          "submissions/)")




def _scores(path: Path, paths: list[str]) -> dict:
    """The scorer's output, which gets published: only finite numbers for the given prediction
    files. Anything else (text, nested data) could carry whatever the organizer's code read."""
    def no_constant(token):
        raise CliError(f"scores.json: {token} is not a score")
    try:
        raw = json.loads(path.read_text(), parse_constant=no_constant)
    except (OSError, ValueError) as exc:
        raise CliError(f"the scoring program did not write a valid scores.json ({exc})") from exc
    if not isinstance(raw, dict) or set(raw) - set(paths):
        raise CliError("scores.json must map the given prediction files to numbers, nothing else")
    for value in raw.values():
        if value is not None and (isinstance(value, bool) or not isinstance(value, int | float)
                                  or not abs(value) < 1e300):
            raise CliError(f"scores.json: {value!r} is not a finite number")
    return raw


def cmd_audit(args):
    """Re-check a published leaderboard without trusting the evaluator for anything but the
    scores themselves: the inputs, the rules and each row's on-time status are re-derived."""
    work = Path(tempfile.mkdtemp(prefix="provena-audit-"))
    lb, lb_report = _verify(Path(args.leaderboard), "leaderboard bundle")
    challenge, ch_report = _verify(Path(args.challenge), "challenge bundle")
    org = challenge["project"]
    log = {Repo.hash_of(it["entry"]): it["entry"] for it in lb["entries"]}
    runs = [e for h, e in log.items() if e["kind"] == "activity" and h in lb_report.verified_entries
            and set(e["body"].get("generated", [])) & set(lb_report.targets)]
    if len(runs) != 1 or len(runs[0]["body"]["generated"]) != 1:
        raise CliError("leaderboard bundle must prove one scoring step and its one output")
    scoring, board_entry = runs[0], runs[0]["body"]["generated"][0]
    evaluator = scoring["author"]
    attached = lb.get("external", [])
    truths = [b for b in attached if b["project"] == org and b.get("mode") == "full"]
    if len(truths) != 1:
        raise CliError("leaderboard must attach exactly one full bundle of the organizer")
    tr_report = verify_bundle(truths[0], **_trust_kwargs())
    subs = [(b, verify_bundle(b, **_trust_kwargs())) for b in attached if b["project"] != org]
    protocol, terms, rows = _check_inputs(challenge, ch_report, truths[0], tr_report, subs,
                                          evaluator, args.hub, None, work)
    cited = {(x["project"], x["entry"]) for x in scoring["body"].get("external", [])}
    expected = {(org, protocol), (org, terms["truth"]), (org, terms["scorer"])}
    expected |= {(r["project"], r["predictions"]) for r in rows}
    if cited != expected:
        # citing the scorer entry binds its content, whose hash the protocol fixes
        raise CliError("the scoring step does not cite exactly the protocol, truth, scorer and "
                       "the attached submissions")
    path = _open_target(lb, board_entry, work / "leaderboard.json", args.hub, None,
                        published=True)
    board = json.loads(path.read_text())
    derived = sorted((r["team"], r["project"], r["predictions"], r["on_time"]) for r in rows)
    claimed = sorted(tuple(row[k] for k in BOARD_KEYS) for row in board)
    if derived != claimed:
        raise CliError("leaderboard rows differ from what the attached proofs show")
    on_board = {r["project"] for r in rows}
    for path in args.submission:  # a team's own bundle: its on-time entry must be on the board
        sub, report = _verify(Path(path), f"submission {path}")
        if sub["project"] in on_board:
            _, pred, _ = _submission(sub, report, org, protocol, evaluator, {protocol})
            scored = next(r["predictions"] for r in rows if r["project"] == sub["project"])
            if pred != scored:
                raise CliError(f"the leaderboard scored entry {scored[:12]} of project "
                               f"{sub['project'][:12]}, but this submission is {pred[:12]}")
            continue
        try:
            team, pred, grant = _submission(sub, report, org, protocol, evaluator,
                                            {protocol})
            on_time = _on_time(report, pred, grant, terms["deadline-ms"])
        except (CliError, ChallengeError):
            continue
        if on_time and (not terms["teams"] or f"{team}:{sub['project']}" in terms["teams"]):
            raise CliError(f"the leaderboard omits an on-time submission: team {team}, "
                           f"project {sub['project'][:12]}", EXIT_CHALLENGE, "E_OMITTED")
    missing = [t for t in terms["teams"]
               if t not in {f"{r['team']}:{r['project']}" for r in rows}]
    print(f"leaderboard {board_entry[:12]} by evaluator {evaluator}: protocol {protocol[:12]}, "
          f"deadline {_when(terms['deadline-ms'])}")
    print(f"{'team (agent)':<38} {'on time':<8} score (evaluator's claim)")
    for row in board:
        print(f"{row['team']:<38} {'yes' if row['on_time'] else 'NO':<8} {row['score']}")
    if missing:
        print(f"registered but absent: {', '.join(missing)}")
    if not terms["teams"]:
        print("open registration: one entrant may have used several keys")
    output.data(verdict="ok", protocol=protocol, leaderboard=board_entry, evaluator=evaluator,
                rows=board, registered_absent=missing, open_registration=not terms["teams"])
    print("AUDIT OK: inputs, rules and on-time status re-derived; scores are the evaluator's "
          "claim (predictions are shared with the evaluator only)")


# -- anyone: where a challenge stands; teams: join ------------------------------------------

def cmd_status(args):
    """From public data only (the protocol, the organizer's public log, tree heads): the
    deadline, whether the truth was revealed (and when), and whether it leaked early."""
    from provena.core.receipts import verify_set

    challenge, report = _verify(Path(args.challenge), "challenge bundle")
    work = Path(tempfile.mkdtemp(prefix="provena-status-"))
    protocol, terms = _protocol_terms(challenge, report, args.hub, None, work)
    org, deadline = challenge["project"], terms["deadline-ms"]
    from provena.core import entries as core_entries
    from provena.core.keys import verify_card
    from provena.core.state import ProjectState

    client = sync.make_client(args.hub, None)
    log = client.entries(org)
    # times count only from the log the challenge bundle names (what teams verified), never
    # from whatever key the hub reports about itself
    hub_key = challenge["head_signer"]
    pub = verify_card(hub_key)
    ProjectState.replay([item["entry"] for item in log])  # signatures and rules, all of it
    public = {protocol, terms["targets"], terms["scorer"]}
    reveal_at, early = None, []
    for i, item in enumerate(log):
        e, r = item["entry"], item["receipt"]
        verify_set(r, pub)
        if r["entry_hash"] != core_entries.entry_hash(e) or r["index"] != i:
            raise CliError("the hub's receipts do not match its entries", error="E_FORK")
        if e["kind"] not in ("reveal", "grant"):
            continue
        target = e["body"].get("target")
        if e["kind"] == "reveal" and target == terms["truth"] and e["body"].get("dek"):
            at = r["integrated_time"]
            reveal_at = at if reveal_at is None else min(reveal_at, at)
        if r["integrated_time"] <= deadline and target not in public:
            early.append(r["entry_hash"])  # as the evaluator judges: anything else is a leak
    now = int(time.time() * 1000)
    teams = []
    for spec in terms["teams"]:
        agent, _, project = spec.partition(":")
        try:
            head = client.sth(project)
            teams.append({"team": agent, "project": project, "entries": head["size"],
                          "last_write_ms": head["time"]})
        except Exception:  # noqa: BLE001 — not on this hub (yet)
            teams.append({"team": agent, "project": project, "entries": 0,
                          "last_write_ms": None})
    state = ("void" if early else "closed" if reveal_at is not None
             else "open" if now <= deadline else "awaiting close")
    output.data(protocol=protocol, organizer_project=org, deadline_ms=deadline, now_ms=now,
                state=state, truth_revealed_ms=reveal_at, early_disclosures=early,
                hub_log_key=hub_key["id"], teams=teams, open_registration=not terms["teams"])
    print(f"protocol {protocol[:12]} · deadline {_when(deadline)} · {state.upper()}"
          + (f" (truth revealed {_when(reveal_at)})" if reveal_at else ""))
    if early:
        print(f"  content other than the protocol, targets and scorer was disclosed before "
              f"the deadline by {len(early)} entr{'y' if len(early) == 1 else 'ies'} "
              f"({', '.join(h[:12] for h in early[:3])}): the challenge is void (a copy of "
              f"the truth could be in any of it)")
    for t in teams:
        print(f"  team {t['team'][:16]}… project {t['project'][:12]}: {t['entries']} entries")
    if state == "void":
        output.error("E_VOID", "content other than the protocol, targets and scorer was "
                     "disclosed before the deadline")
        return EXIT_CHALLENGE
    return 0


def cmd_join(args):
    """Team: a project dedicated to this challenge, on the challenge's hub, and the
    AGENT:PROJECT line to send the organizer for registration."""
    from provena.core import builders as b
    from provena.store.home import Home as _Home

    challenge, report = _verify(Path(args.challenge), "challenge bundle")
    work = Path(tempfile.mkdtemp(prefix="provena-join-"))
    protocol, terms = _protocol_terms(challenge, report, args.hub, None, work)
    name = _agent_name(args)
    if not _Home().has_agent(name):
        raise CliError(f"no agent {name!r} yet", error="E_NOT_FOUND",
                       hint=f"provena --agent {name} keygen --kind software")
    agent = _load_agent(args)
    dest = Path(args.dir or f"challenge-{protocol[:8]}").resolve()
    if (dest / ".provena").exists():
        repo = Repo(dest)
    else:
        dest.mkdir(parents=True, exist_ok=True)
        genesis, _ = b.new_project(agent, _Home().card(name), name=f"entry-{protocol[:8]}")
        repo = Repo.init(dest, name, genesis)
    if not repo.config.get("hub"):
        card = sync.pin_hub(repo, args.hub, sync.make_client(args.hub, None))
        _Home().set_trust("logs", card["id"])
    line = f"{agent.id}:{repo.state.project}"
    registered = line in terms["teams"]
    output.data(registration=line, project=repo.state.project, path=str(dest),
                registered=registered, deadline_ms=terms["deadline-ms"], protocol=protocol,
                hub=args.hub)
    print(f"entry project {repo.state.project[:12]} in {dest}")
    print(f"send this line to the organizer to register: {line}" if not registered else
          "already registered with this challenge")
    return 0


def _trust_kwargs() -> dict:
    trust = Home().trust()
    return {"trusted_logs": trust["logs"], "trusted_tsas": trust["tsas"],
            "trusted_witnesses": trust["witnesses"], "trusted_orgs": trust["orgs"]}


def add_parser(sub) -> None:
    s = sub.add_parser("challenge", help="preregistered blinded challenges (experimental)")
    c = s.add_subparsers(dest="challenge_cmd", required=True)
    p = c.add_parser("init", help="organizer: commit truth, publish targets + scorer")
    p.add_argument("--title", required=True)
    p.add_argument("--truth", required=True)
    p.add_argument("--targets", required=True)
    p.add_argument("--score", required=True, help="scoring program: score.py PRED_FILE...")
    p.add_argument("--deadline", required=True, help="ISO time with zone")
    p.add_argument("--protocol", help="your own protocol text (terms are appended)")
    p.add_argument("--team", action="append", default=[], metavar="AGENT_ID:PROJECT_ID",
                   help="registered team and the one project it submits from (repeatable; "
                        "default: open registration)")
    p.add_argument("-o", "--output", default="challenge.pvb")
    p.set_defaults(fn=cmd_init)
    p = c.add_parser("submit", help="team: register predictions, share with the evaluator")
    p.add_argument("challenge", help="challenge.pvb from the organizer")
    p.add_argument("--predictions", required=True)
    p.add_argument("--evaluator", required=True, help="evaluator's agent card")
    p.add_argument("--hub", help="hub to read the published protocol from (default: remote)")
    p.add_argument("-o", "--output", default="submission.pvb")
    p.set_defaults(fn=cmd_submit)
    p = c.add_parser("close", help="organizer: reveal the truth after the deadline")
    p.add_argument("-o", "--output", default="truth.pvb")
    p.set_defaults(fn=cmd_close)
    p = c.add_parser("score", help="evaluator: score on-time submissions reproducibly")
    p.add_argument("challenge", help="challenge.pvb (the bundle teams received)")
    p.add_argument("--truth", required=True, help="truth.pvb from the organizer")
    p.add_argument("--submission", action="append", default=[], required=True)
    p.add_argument("--hub", required=True)
    p.add_argument("--include-late", action="store_true")
    p.add_argument("--yes", action="store_true", help="execute the organizer's scoring program")
    p.add_argument("--workdir")
    p.add_argument("--timeout", type=float, default=600)
    p.add_argument("--sandbox", choices=["auto", "require", "off"], default="auto",
                   help="run the scorer without network, writes outside its work directory or "
                        "access to your Provena keys (bwrap / sandbox-exec; default: if available)")
    p.add_argument("-o", "--output", default="leaderboard.pvb")
    p.set_defaults(fn=cmd_score)
    p = c.add_parser("status", help="anyone: deadline, closed or void, team activity")
    p.add_argument("challenge", help="challenge.pvb")
    p.add_argument("--hub", required=True)
    p.set_defaults(fn=cmd_status)
    p = c.add_parser("join", help="team: a dedicated entry project and the line to register")
    p.add_argument("challenge", help="challenge.pvb")
    p.add_argument("--hub", required=True)
    p.add_argument("--dir", help="where to create the entry project (default: challenge-<id>)")
    p.set_defaults(fn=cmd_join)
    p = c.add_parser("audit", help="anyone: re-check a published leaderboard")
    p.add_argument("leaderboard", help="leaderboard.pvb from the evaluator")
    p.add_argument("--challenge", required=True, help="challenge.pvb (the bundle teams received)")
    p.add_argument("--hub", required=True, help="hub serving the published protocol and board")
    p.add_argument("--submission", action="append", default=[],
                   help="a team's own submission bundle: fail if the board omits it")
    p.set_defaults(fn=cmd_audit)
