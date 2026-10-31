"""`provena challenge` end to end against an in-process hub (experimental commands)."""

import json
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from provena.cli import sandbox
from provena.cli.main import main
from provena.client.hub import HubClient
from provena.sdk import sync
from provena.server.app import create_app, load_or_create_hub_key
from provena.server.limits import Limits

URL = "http://testserver"
SCORE = """import csv, json, sys
truth = {r["seq"]: r["label"] for r in csv.DictReader(open("truth.csv"))}
out = {}
for p in sys.argv[1:]:
    rows = list(csv.DictReader(open(p)))
    out[p] = sum(r["label"] == truth[r["seq"]] for r in rows) / len(truth)
json.dump(out, open("scores.json", "w"))
"""


@pytest.fixture
def clock(monkeypatch):
    """time.time() everywhere (clients, hub, receipts) plus a settable offset in seconds."""
    real, offset = time.time, [0.0]
    monkeypatch.setattr(time, "time", lambda: real() + offset[0])
    return offset


def _soon(seconds=60) -> str:
    return datetime.fromtimestamp(time.time() + seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


_HTTP: list = []  # the in-process hub of the current `world`


@pytest.fixture
def world(tmp_path, monkeypatch, clock):
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PROVENA_PASSPHRASE", "pw")
    monkeypatch.setenv("PROVENA_SCRYPT_N", "1024")
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    http = TestClient(create_app(tmp_path / "hub", key, card,
                                 limits=Limits(project_burst=100, burst=1000)))
    monkeypatch.setattr(sync, "make_client",
                        lambda url, agent: HubClient(url, agent=agent, http=http))
    _HTTP[:] = [http]
    for a in ("organizer", "team1", "team2", "evaluator"):
        assert main(["--agent", a, "keygen", "--display", a]) == 0
    return tmp_path


def _in(path, monkeypatch):
    path.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(path)


def test_challenge_end_to_end(world, monkeypatch, capsys):
    t = world
    _in(t / "org", monkeypatch)
    (t / "org" / "targets.csv").write_text("seq\nAUGC\nGGCA\nUUAG\n")
    (t / "org" / "truth.csv").write_text("seq,label\nAUGC,1\nGGCA,0\nUUAG,1\n")
    (t / "org" / "score.py").write_text(SCORE)
    assert main(["--agent", "organizer", "init", "--public", "--name", "rna"]) == 0
    assert main(["--agent", "organizer", "remote", URL]) == 0
    assert main(["--agent", "organizer", "challenge", "init", "--title", "RNA binders",
                 "--truth", "truth.csv", "--targets", "targets.csv", "--score", "score.py",
                 "--deadline", _soon(), "-o", str(t / "challenge.pvb")]) == 0

    evaluator_card = str(t / "home" / "agents" / "evaluator.card.json")
    for team, labels in (("team1", "1 0 1"), ("team2", "1 1 1")):
        _in(t / team, monkeypatch)
        seqs = ("AUGC", "GGCA", "UUAG")
        rows = "".join(f"{s},{v}\n" for s, v in zip(seqs, labels.split(), strict=True))
        (t / team / "predictions.csv").write_text("seq,label\n" + rows)
        assert main(["--agent", team, "init", "--name", team]) == 0
        assert main(["--agent", team, "remote", URL]) == 0
        capsys.readouterr()
        assert main(["--agent", team, "challenge", "submit", str(t / "challenge.pvb"),
                     "--predictions", "predictions.csv", "--evaluator", evaluator_card,
                     "-o", str(t / f"{team}.pvb")]) == 0
        assert "ON TIME" in capsys.readouterr().out

    _in(t / "org", monkeypatch)
    assert main(["--agent", "organizer", "challenge", "close"]) == 5      # E_TOO_EARLY
    _past_deadline(t)

    _in(t / "eval", monkeypatch)
    assert main(["--agent", "evaluator", "init", "--name", "evaluation", "--public"]) == 0
    assert main(["--agent", "evaluator", "remote", URL]) == 0
    capsys.readouterr()
    score_args = ["--agent", "evaluator", "challenge", "score", str(t / "challenge.pvb"),
                  "--truth", str(t / "truth.pvb"),
                  "--submission", str(t / "team1.pvb"), "--submission", str(t / "team2.pvb"),
                  "--hub", URL, "--workdir", str(t / "work"), "-o", str(t / "leaderboard.pvb")]
    assert main(score_args) == 2                       # never runs organizer code unasked
    assert "--yes" in capsys.readouterr().out
    assert main([*score_args, "--yes"]) == 0
    out = capsys.readouterr().out
    assert "1.0" in out and "0.666" in out
    capsys.readouterr()
    assert main(["verify", str(t / "leaderboard.pvb"), "--require", "log-sequenced"]) == 0
    verdict = capsys.readouterr().out
    assert verdict.count("used entry") == 5   # protocol, truth, scorer, two submissions
    board = json.loads((t / "eval" / "leaderboard.json").read_text())
    agents = {json.loads((t / "home" / "agents" / f"{n}.card.json").read_text())["id"]: n
              for n in ("team1", "team2")}
    assert {agents[r["team"]]: r["score"] for r in board} == {"team1": 1.0,
                                                             "team2": pytest.approx(2 / 3)}
    assert all(r["on_time"] for r in board)
    assert "/" not in json.dumps([r["team"] for r in board])   # no local paths published
    assert os.path.exists(t / "work" / "truth.csv")

    # anyone, with no key of their own, re-derives everything but the scores
    monkeypatch.delenv("PROVENA_PASSPHRASE")
    _in(t / "public", monkeypatch)
    capsys.readouterr()
    assert main(["challenge", "audit", str(t / "leaderboard.pvb"), "--challenge",
                 str(t / "challenge.pvb"), "--hub", URL]) == 0
    out = capsys.readouterr().out
    assert "AUDIT OK" in out and "open registration" in out

    # the hub's page re-applies the same rules to its own logs once the board is published
    monkeypatch.setenv("PROVENA_PASSPHRASE", "pw")
    _in(t / "eval", monkeypatch)
    assert main(["--agent", "evaluator", "publish", "leaderboard.json"]) == 0
    assert main(["--agent", "evaluator", "push"]) == 0
    from provena.store.repo import Repo

    page = _HTTP[0].get(f"/classic/p/{Repo.find().state.project}").text
    assert "every row matches" in page and page.count("<td>✓</td>") == 2
    view = _HTTP[0].get(f"/v1/projects/{Repo.find().state.project}/overview").json()
    assert view["leaderboard"]["check"]["verdict"] == "ok-open"
    assert [r["ok"] for r in view["leaderboard"]["check"]["rows"]] == [True, True]
    # a falsified row (late made on time, or another prediction entry) is caught by the hub
    from provena.server import challenge_check

    hub = _HTTP[0].app.state.hub
    pid = Repo.find().state.project
    state = hub._state(pid)
    h, step = next((h, e) for h, e in state.entries.items() if e["kind"] == "activity"
                   and e["body"].get("external"))
    at = hub.storage.entry_by_hash(pid, h)["integrated_time"]

    def check(rows, activity=step):
        return challenge_check._check(hub, activity, rows, at)   # uncached

    assert check(board)["verdict"] == "ok-open"                  # open registration
    result = check([{**board[0], "on_time": False}, board[1]])
    assert result["verdict"] == "fail"
    assert result["rows"][0][0] is False and result["rows"][1] == (True, "")
    # review: rows the hub cannot see, duplicates and oversized boards are never "ok"
    ghost = {"team": "pv1aghost", "project": "aa" * 32, "predictions": "bb" * 32,
             "on_time": True, "score": 1.0}
    cites = [*step["body"]["external"], {"project": "aa" * 32, "entry": "bb" * 32}]
    with_ghost = {**step, "body": {**step["body"], "external": cites}}
    assert check([*board, ghost], with_ghost)["verdict"] == "partial"
    assert check([*board, {**board[1], "score": 99}])["verdict"] == "fail"
    assert check(board * 51)["verdict"] == "unchecked"
    assert check([{**board[0], "predictions": [1]}, board[1]])["verdict"] == "fail"


def _past_deadline(t, clock_offset=None):
    clock = clock_offset if clock_offset is not None else _CLOCK[0]
    clock[0] += 120
    assert main(["--agent", "organizer", "challenge", "close", "-o", str(t / "truth.pvb")]) == 0


_CLOCK: list = []


@pytest.fixture(autouse=True)
def _remember_clock(clock):
    _CLOCK[:] = [clock]


def _setup_challenge(t, monkeypatch, deadline=None, teams=(), score=SCORE):
    deadline = deadline or _soon()
    _in(t / "org", monkeypatch)
    (t / "org" / "targets.csv").write_text("seq\nAUGC\nGGCA\nUUAG\n")
    (t / "org" / "truth.csv").write_text("seq,label\nAUGC,1\nGGCA,0\nUUAG,1\n")
    (t / "org" / "score.py").write_text(score)
    main(["--agent", "organizer", "init", "--public", "--name", "rna"])
    main(["--agent", "organizer", "remote", URL])
    assert main(["--agent", "organizer", "challenge", "init", "--title", "RNA",
                 "--truth", "truth.csv", "--targets", "targets.csv", "--score", "score.py",
                 "--deadline", deadline, "-o", str(t / "challenge.pvb"),
                 *[a for team in teams for a in ("--team", team)]]) == 0


def _new_project(t, monkeypatch, team, where):
    _in(where, monkeypatch)
    main(["--agent", team, "init", "--name", team])
    main(["--agent", team, "remote", URL])
    from provena.store.repo import Repo

    return Repo.find(where).state.project


def _submit(t, monkeypatch, team, labels, out, where=None):
    _in(where or t / team, monkeypatch)
    rows = "".join(f"{s},{v}\n" for s, v in zip(("AUGC", "GGCA", "UUAG"), labels, strict=True))
    (Path.cwd() / "predictions.csv").write_text("seq,label\n" + rows)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not (Path.cwd() / ".provena").exists():
        main(["--agent", team, "init", "--name", team])
        main(["--agent", team, "remote", URL])
    return main(["--agent", team, "challenge", "submit", str(t / "challenge.pvb"),
                 "--predictions", "predictions.csv", "--evaluator",
                 str(t / "home" / "agents" / "evaluator.card.json"), "-o", str(out)])


def _score(t, monkeypatch, subs):
    _in(t / "eval", monkeypatch)
    if not (t / "eval" / ".provena").exists():
        main(["--agent", "evaluator", "init", "--name", "ev", "--public"])
        main(["--agent", "evaluator", "remote", URL])
    args = ["--agent", "evaluator", "challenge", "score", str(t / "challenge.pvb"), "--truth",
            str(t / "truth.pvb"), "--hub", URL, "--yes", "-o", str(t / "lb.pvb")]
    for s in subs:
        args += ["--submission", str(s)]
    return main(args)


def test_organizer_cannot_swap_truth_or_deadline(world, monkeypatch, capsys):
    """Review 6 #1: the evaluator takes the truth entry and deadline only from the
    preregistered, published protocol named in the bundle the teams received."""
    t = world
    _setup_challenge(t, monkeypatch)
    assert _submit(t, monkeypatch, "team1", "101", t / "a" / "submission.pvb") == 0
    _CLOCK[0][0] += 120
    _in(t / "org", monkeypatch)
    (t / "org" / "truth2.csv").write_text("seq,label\nAUGC,1\nGGCA,1\nUUAG,1\n")
    main(["--agent", "organizer", "plan", "truth2.csv"])
    info = json.loads((t / "org" / ".provena" / "challenge.json").read_text())
    from provena.store.repo import Repo

    truth2 = Repo.find(t / "org").tracked["truth2.csv"]["entry"]
    info.update(truth=truth2)
    (t / "org" / ".provena" / "challenge.json").write_text(json.dumps(info))
    assert main(["--agent", "organizer", "challenge", "close", "-o", str(t / "truth.pvb")]) == 0
    capsys.readouterr()
    assert _score(t, monkeypatch, [t / "a" / "submission.pvb"]) == 2
    err = capsys.readouterr().err
    assert "not provably fixed before the deadline" in err or "truth entry named" in err


def test_one_submission_per_team_and_no_name_collisions(world, monkeypatch, capsys):
    """Review 6 #2 and #3."""
    t = world
    _setup_challenge(t, monkeypatch)
    assert _submit(t, monkeypatch, "team1", "100", t / "a" / "submission.pvb") == 0
    capsys.readouterr()
    assert _submit(t, monkeypatch, "team1", "101", t / "b" / "submission.pvb") == 5  # 2nd try
    assert "already submitted" in capsys.readouterr().err
    # bypassing the CLI: a second submission written directly, before the deadline
    from provena import sdk

    ch = json.loads((t / "challenge.pvb").read_text())
    proj = sdk.open(t / "team1", agent="team1", passphrase="pw")
    (t / "team1" / "p2.csv").write_text("seq,label\nAUGC,1\nGGCA,1\nUUAG,1\n")
    with proj.run("challenge submission",
                  external=[(ch["project"], ch["challenge"]["protocol"])]) as run:
        run.output(t / "team1" / "p2.csv")
    proj.share(run.outputs[0], json.loads((t / "home" / "agents" / "evaluator.card.json")
                                          .read_text()))
    proj.push()
    (t / "b").mkdir(exist_ok=True)
    (t / "b" / "submission.pvb").write_text(json.dumps(proj.prove(
        [run.outputs[0]], full=True)))
    assert _submit(t, monkeypatch, "team2", "111", t / "c" / "submission.pvb") == 0
    _in(t / "org", monkeypatch)
    _past_deadline(t)
    capsys.readouterr()
    assert _score(t, monkeypatch, [t / "b" / "submission.pvb"]) == 2      # best-of-N refused
    assert "exactly one submission" in capsys.readouterr().err
    assert _score(t, monkeypatch, [t / "a" / "submission.pvb"]) == 2      # the early snapshot
    assert "sequenced before the deadline" in capsys.readouterr().err
    assert _score(t, monkeypatch, [t / "c" / "submission.pvb"]) == 0     # same file names fine


def test_truth_disclosed_before_deadline_voids_challenge(world, monkeypatch, capsys):
    """Review 7 H1: an early reveal or grant of the truth (here: quietly granted to team2) lets
    a team submit it "on time"; the evaluator checks every disclosure in the organizer's log."""
    t = world
    _setup_challenge(t, monkeypatch)
    _in(t / "org", monkeypatch)
    assert main(["--agent", "organizer", "share", "truth.csv", "--to",
                 str(t / "home" / "agents" / "team2.card.json"), "--force"]) == 0
    main(["--agent", "organizer", "push"])
    assert _submit(t, monkeypatch, "team2", "101", t / "c" / "submission.pvb") == 0
    _in(t / "org", monkeypatch)
    assert main(["--agent", "organizer", "challenge", "close"]) == 5     # no early close at all
    _past_deadline(t)
    capsys.readouterr()
    assert _score(t, monkeypatch, [t / "c" / "submission.pvb"]) == 7      # E_VOID
    assert "before the deadline: challenge void" in capsys.readouterr().err


def test_organizer_member_cannot_compete(world, monkeypatch, capsys):
    t = world
    _setup_challenge(t, monkeypatch)
    _in(t / "org", monkeypatch)
    assert main(["--agent", "organizer", "member", "add",
                 str(t / "home" / "agents" / "team2.card.json"), "--role", "viewer"]) == 0
    main(["--agent", "organizer", "push"])
    assert _submit(t, monkeypatch, "team2", "101", t / "c" / "submission.pvb") == 0
    _in(t / "org", monkeypatch)
    _past_deadline(t)
    capsys.readouterr()
    assert _score(t, monkeypatch, [t / "c" / "submission.pvb"]) == 2
    assert "member of the organizer's project" in capsys.readouterr().err


def test_registered_team_submits_from_its_one_project(world, monkeypatch, capsys):
    """Review 7 H2: registering agents alone allowed best-of-N across projects."""
    t = world
    team1 = json.loads((t / "home" / "agents" / "team1.card.json").read_text())["id"]
    a = _new_project(t, monkeypatch, "team1", t / "team1a")
    _new_project(t, monkeypatch, "team1", t / "team1b")
    _in(t / "org", monkeypatch)
    assert main(["--agent", "organizer", "init", "--public", "--name", "rna"]) == 0
    assert main(["--agent", "organizer", "challenge", "init", "--title", "RNA", "--truth", "x",
                 "--targets", "x", "--score", "x", "--deadline", _soon(),
                 "--team", team1]) == 2                               # project required
    _setup_challenge(t, monkeypatch, teams=[f"{team1}:{a}"])
    assert _submit(t, monkeypatch, "team1", "000", t / "b.pvb", where=t / "team1b") == 4
    assert "not a registered team" in capsys.readouterr().err
    assert _submit(t, monkeypatch, "team1", "101", t / "a.pvb", where=t / "team1a") == 0
    _in(t / "org", monkeypatch)
    _past_deadline(t)
    assert _score(t, monkeypatch, [t / "a.pvb"]) == 0
    # the hub's check: registered team on the board → ok; left off while on time → fail
    from provena.server import challenge_check
    from provena.store.repo import Repo

    hub = _HTTP[0].app.state.hub
    pid = Repo.find().state.project
    h, step = next((h, e) for h, e in hub._state(pid).entries.items()
                   if e["kind"] == "activity" and e["body"].get("external"))
    at = hub.storage.entry_by_hash(pid, h)["integrated_time"]
    board = json.loads((t / "eval" / "leaderboard.json").read_text())
    assert challenge_check._check(hub, step, board, at)["verdict"] == "ok"
    kept = [x for x in step["body"]["external"] if x["project"] != a]
    omitted = challenge_check._check(hub, {**step, "body": {**step["body"], "external": kept}},
                                     [], at)
    assert omitted["verdict"] == "fail" and "on time" in omitted["absent"][0]


def test_terms_block_is_unambiguous():
    """Review 7 M3: one block, unique keys, machine and human deadlines agree."""
    from provena.core.challenge import ChallengeError as CliError
    from provena.core.challenge import parse_terms as _terms
    from provena.core.challenge import terms_block as _terms_block

    h = "ab" * 32
    good = _terms_block(h, h, h, h, "2026-11-01T00:00Z", 1793491200000, [])
    assert _terms(good)["deadline-ms"] == 1793491200000
    bad = [
        good.replace("1793491200000", "99999999999999") + good,             # two blocks
        _terms_block(h, h, h, h, "2026-11-01T00:00Z", 99999999999999, []),   # disagree
        good.replace("1793491200000", "1_793_491_200_000"),
        good.replace("teams: ", "truth: " + h + "\nteams: "),               # repeated key
        good.replace(f"scorer: {h}\n", ""),                                 # missing key
    ]
    for text in bad:
        with pytest.raises(CliError):
            _terms(text)


def test_leaderboard_limit_fails_fast(world, monkeypatch, capsys):
    """Review 7 M1: more submissions than one bundle can attach is refused up front."""
    t = world
    _setup_challenge(t, monkeypatch)
    assert _submit(t, monkeypatch, "team1", "101", t / "a.pvb") == 0
    _in(t / "org", monkeypatch)
    _past_deadline(t)
    capsys.readouterr()
    assert _score(t, monkeypatch, [t / "a.pvb"] * 19) == 2
    assert "at most 18 submissions" in capsys.readouterr().err


def test_selectively_handed_terms_are_exposed(world, monkeypatch, capsys):
    """Review 7 L3: an organizer giving one team different terms is caught, and blamed, when
    that team's submission cites a different plan of the organizer's project."""
    t = world
    _setup_challenge(t, monkeypatch)
    _in(t / "org", monkeypatch)
    for name in ("truth.csv", "targets.csv", "score.py"):
        (t / "org" / f"b-{name}").write_text((t / "org" / name).read_text() + "\n")
    (t / "org" / ".provena" / "challenge.json").unlink()   # a dishonest organizer's bypass
    from provena.cli import challenge as challenge_cli  # (it runs its own code)

    monkeypatch.setattr(challenge_cli, "_prior_disclosures", lambda proj: [])
    assert main(["--agent", "organizer", "challenge", "init", "--title", "RNA", "--truth",
                 "b-truth.csv", "--targets", "b-targets.csv", "--score", "b-score.py",
                 "--deadline", _soon(), "-o", str(t / "other.pvb")]) == 0
    (t / "challenge.pvb").rename(t / "real.pvb")
    (t / "other.pvb").rename(t / "challenge.pvb")
    assert _submit(t, monkeypatch, "team2", "101", t / "c.pvb") == 0
    (t / "real.pvb").rename(t / "challenge.pvb")
    _in(t / "org", monkeypatch)
    json_path = t / "org" / ".provena" / "challenge.json"
    info = json.loads(json_path.read_text())
    from provena.store.repo import Repo

    info["truth"] = Repo.find(t / "org").tracked["truth.csv"]["entry"]
    json_path.write_text(json.dumps(info))
    _past_deadline(t)
    capsys.readouterr()
    assert _score(t, monkeypatch, [t / "c.pvb"]) in (2, 7)
    err = capsys.readouterr().err   # the other terms' publication is itself a disclosure
    assert "different terms" in err or "content was disclosed" in err


def test_audit_catches_a_dishonest_evaluator(world, monkeypatch, capsys):
    """A late submission marked on time by a modified evaluator is caught by `audit`."""
    from provena.cli import challenge as ch

    t = world
    _setup_challenge(t, monkeypatch)
    assert _submit(t, monkeypatch, "team1", "101", t / "a.pvb") == 0
    _in(t / "org", monkeypatch)
    _past_deadline(t)
    assert _submit(t, monkeypatch, "team2", "101", t / "late.pvb") == 7    # LATE
    honest = ch._check_inputs

    def lying(*a, **kw):
        protocol, terms, rows = honest(*a, **kw)
        return protocol, terms, [{**r, "on_time": True} for r in rows]

    monkeypatch.setattr(ch, "_check_inputs", lying)
    assert _score(t, monkeypatch, [t / "a.pvb", t / "late.pvb"]) == 0
    monkeypatch.setattr(ch, "_check_inputs", honest)
    capsys.readouterr()
    assert main(["challenge", "audit", str(t / "lb.pvb"), "--challenge", str(t / "challenge.pvb"),
                 "--hub", URL]) == 2
    assert "rows differ" in capsys.readouterr().err


def test_truth_copy_disclosed_early_voids_challenge(world, monkeypatch, capsys):
    """An identical copy of the truth under another entry, published before the deadline."""
    t = world
    _setup_challenge(t, monkeypatch)
    _in(t / "org", monkeypatch)
    (t / "org" / "notes.csv").write_text((t / "org" / "truth.csv").read_text())
    assert main(["--agent", "organizer", "add", "notes.csv"]) == 0
    assert main(["--agent", "organizer", "publish", "notes.csv", "--force"]) == 0
    main(["--agent", "organizer", "push"])
    assert _submit(t, monkeypatch, "team1", "101", t / "a.pvb") == 0
    _in(t / "org", monkeypatch)
    _past_deadline(t)
    capsys.readouterr()
    assert _score(t, monkeypatch, [t / "a.pvb"]) == 7      # E_VOID
    assert "content was disclosed" in capsys.readouterr().err


def _strip_receipts(src: Path, dst: Path):
    b = json.loads(src.read_text())
    for it in b["entries"]:
        it.pop("receipt", None)
    dst.write_text(json.dumps(b))


def test_stripped_receipts_make_timing_unprovable_not_late(world, monkeypatch, capsys):
    """Review 9: dropping a team's receipts used to make an on-time submission "late"."""
    t = world
    _setup_challenge(t, monkeypatch)
    assert _submit(t, monkeypatch, "team1", "101", t / "team1" / "a.pvb") == 0   # ON TIME
    assert _submit(t, monkeypatch, "team2", "111", t / "team2" / "b.pvb") == 0   # ON TIME
    sub = json.loads((t / "team1" / "a.pvb").read_text())
    pred, grant = sub["targets"]
    _in(t / "org", monkeypatch)
    _past_deadline(t)
    # after the deadline team1 keeps using its project (here: publishes its predictions)
    _in(t / "team1", monkeypatch)
    assert main(["--agent", "team1", "publish", "predictions.csv"]) == 0
    # a later full bundle of the same project: head is now after the deadline; receipts
    # (unsigned bundle items) are optional, so the evaluator drops them
    assert main(["--agent", "team1", "prove", pred, grant, "--full", "-o",
                 str(t / "later.pvb")]) == 0
    _strip_receipts(t / "later.pvb", t / "stripped.pvb")
    from provena.cli.challenge import _trust_kwargs
    from provena.core.verify import load_bundle, verify_bundle
    dl = json.loads((t / "org" / ".provena" / "challenge.json").read_text())["deadline"]
    full = verify_bundle(load_bundle((t / "later.pvb").read_text()), **_trust_kwargs())
    bare = verify_bundle(load_bundle((t / "stripped.pvb").read_text()), **_trust_kwargs())
    assert full.ok and bare.ok and full.head_time > dl
    assert all(full.time_bounds[h] <= dl for h in (pred, grant))      # honest: on time
    assert all(bare.time_bounds[h] > dl for h in (pred, grant))       # stripped: "late"
    capsys.readouterr()
    assert _score(t, monkeypatch, [t / "stripped.pvb", t / "team2" / "b.pvb"]) == 2
    assert "timing is unprovable" in capsys.readouterr().err


def test_audit_detects_an_omitted_team_from_its_own_bundle(world, monkeypatch, capsys):
    """Review 9: a registered on-time team left off the board."""
    t = world
    ids = {n: json.loads((t / "home" / "agents" / f"{n}.card.json").read_text())["id"]
           for n in ("team1", "team2")}
    p1 = _new_project(t, monkeypatch, "team1", t / "team1")
    p2 = _new_project(t, monkeypatch, "team2", t / "team2")
    _setup_challenge(t, monkeypatch, teams=[f"{ids['team1']}:{p1}", f"{ids['team2']}:{p2}"])
    assert _submit(t, monkeypatch, "team1", "101", t / "a.pvb") == 0
    assert _submit(t, monkeypatch, "team2", "101", t / "b.pvb") == 0
    _in(t / "org", monkeypatch)
    _past_deadline(t)
    assert _score(t, monkeypatch, [t / "a.pvb"]) == 0          # team2 silently dropped
    monkeypatch.delenv("PROVENA_PASSPHRASE")
    _in(t / "public", monkeypatch)
    capsys.readouterr()
    assert main(["challenge", "audit", str(t / "lb.pvb"), "--challenge",
                 str(t / "challenge.pvb"), "--hub", URL]) == 0
    assert "registered but absent" in capsys.readouterr().out
    assert main(["challenge", "audit", str(t / "lb.pvb"), "--challenge",
                 str(t / "challenge.pvb"), "--hub", URL, "--submission", str(t / "b.pvb")]) == 7
    assert "omits an on-time submission" in capsys.readouterr().err


HOSTILE = SCORE.replace("out = {}", '''out = {}
import os, socket
# hidden = denied (sandbox-exec) or absent / an empty mount over it (bwrap)
try:
    open(os.environ["PROBE"], "rb").read()
    raise SystemExit("read the evaluator's key file")
except (PermissionError, FileNotFoundError):
    pass
try:
    socket.create_connection(("1.1.1.1", 80), timeout=3)
    raise SystemExit("reached the network")
except OSError:
    pass
try:
    open(os.path.expanduser("~/../escape.txt"), "w")
    raise SystemExit("wrote outside the work directory")
except OSError:
    pass
import subprocess
for cmd in (["/usr/bin/open", "-g", "/System/Applications/Calculator.app"],
            ["/usr/bin/defaults", "write", "provena.review", "x", "1"]):
    if os.path.exists(cmd[0]) and subprocess.run(cmd, capture_output=True).returncode == 0:
        raise SystemExit("escaped through " + cmd[0])
for probe in (os.environ["REAL_HOME"], os.environ["REPO_FILE"], os.environ["OTHER_RUN"]):
    try:
        seen = os.listdir(probe) if os.path.isdir(probe) else open(probe).read()
    except (PermissionError, FileNotFoundError):
        continue
    stubs = set(os.environ["STUBS"].split(","))   # mount points bwrap creates for the runtime
    if seen and not (isinstance(seen, list) and set(seen) <= stubs):
        raise SystemExit("read " + probe)''')


@pytest.mark.skipif(sandbox.available() is None, reason="no sandbox tool on this platform")
def test_scorer_runs_sandboxed(world, monkeypatch, capsys):
    """The organizer's scorer can neither read Provena keys nor reach the network nor write
    outside its work directory."""
    t = world
    _setup_challenge(t, monkeypatch, score=HOSTILE)
    assert _submit(t, monkeypatch, "team1", "101", t / "a.pvb") == 0
    _in(t / "org", monkeypatch)
    _past_deadline(t)
    key_file = sorted((t / "home" / "agents").glob("evaluator*"))[0]
    monkeypatch.setattr(sandbox, "_wrap", _probe_wrap(sandbox._wrap, key_file))
    capsys.readouterr()
    assert _score(t, monkeypatch, [t / "a.pvb"]) == 0, capsys.readouterr().err


def _probe_wrap(real, key_file):
    """Tell the hostile scorer where a key file is (its environment is otherwise scrubbed)."""
    def wrap(tool, argv, work, deny):
        repo_file = deny[-1] / "notes.txt"            # the evaluator's working tree
        repo_file.write_text("private notes")
        other = Path(tempfile.mkdtemp(prefix="provena-challenge-")) / "truth.csv"
        other.write_text("an earlier run's decrypted truth")   # another run's work folder
        home = Path.home().resolve()
        stubs = {r.relative_to(home).parts[0] for r in sandbox._runtime()
                 if r.is_relative_to(home) and r != home}
        return ["env", f"PROBE={key_file.resolve()}", f"REAL_HOME={Path.home()}",
                f"STUBS={','.join(sorted(stubs))}",
                f"REPO_FILE={repo_file}", f"OTHER_RUN={other}", *real(tool, argv, work, deny)]
    return wrap


def test_scores_must_be_numbers(world, monkeypatch, capsys):
    """Review 11: the published leaderboard carried any JSON the scorer wrote."""
    t = world
    leaky = SCORE.replace('json.dump(out, open("scores.json", "w"))',
                          'json.dump({p: "secret" for p in out}, open("scores.json", "w"))')
    _setup_challenge(t, monkeypatch, score=leaky)
    assert _submit(t, monkeypatch, "team1", "101", t / "a.pvb") == 0
    _in(t / "org", monkeypatch)
    _past_deadline(t)
    capsys.readouterr()
    assert _score(t, monkeypatch, [t / "a.pvb"]) == 2
    assert "not a finite number" in capsys.readouterr().err


@pytest.mark.skipif(sandbox.available() is None, reason="no sandbox tool on this platform")
def test_sandbox_allows_a_runtime_inside_the_denied_repository(tmp_path, monkeypatch):
    """Review 12: with the venv inside the evaluator's repository, the final deny blocked the
    interpreter itself, so every real scoring run failed."""
    import sys

    monkeypatch.delenv("PROVENA_PASSPHRASE", raising=False)
    runtime_parent = next(p for p in sandbox._runtime() if p != Path("/")).parent
    work = tmp_path / "work"
    work.mkdir()
    (work / "s.py").write_text("import json, csv; open('ok', 'w').write('1')\n")
    sandbox.run_untrusted([sys.executable, "s.py"], work=work, env={"PATH": "/usr/bin"},
                          timeout=30, deny_read=[runtime_parent], mode="require")
    assert (work / "ok").read_text() == "1"


def test_a_submission_cut_short_resumes(world, monkeypatch, capsys):
    """Review of Phase 0: a failed push left the activity local and no grant; retrying was
    refused as a second submission."""
    import httpx

    from provena.sdk.project import Project

    t = world
    _setup_challenge(t, monkeypatch)
    real = Project.push

    def down(self, client=None):
        raise httpx.ConnectError("hub down")

    monkeypatch.setattr(Project, "push", down)
    assert _submit(t, monkeypatch, "team1", "101", t / "a.pvb") == 3
    monkeypatch.setattr(Project, "push", real)
    capsys.readouterr()
    assert _submit(t, monkeypatch, "team1", "101", t / "a.pvb") == 0      # same predictions
    assert "resuming" in capsys.readouterr().out
    assert _submit(t, monkeypatch, "team1", "111", t / "b.pvb") == 5      # different: refused
    _in(t / "org", monkeypatch)
    _past_deadline(t)
    assert _score(t, monkeypatch, [t / "a.pvb"]) == 0


def test_status_and_join(world, monkeypatch, capsys):
    t = world
    _setup_challenge(t, monkeypatch)
    _in(t / "outsider", monkeypatch)
    capsys.readouterr()
    assert main(["--json", "challenge", "status", str(t / "challenge.pvb"), "--hub", URL]) == 0
    st = json.loads(capsys.readouterr().out)["data"]
    assert st["state"] == "open" and st["early_disclosures"] == []
    _in(t / "joiner", monkeypatch)
    assert main(["--json", "--agent", "team1", "challenge", "join", str(t / "challenge.pvb"),
                 "--hub", URL, "--dir", str(t / "joiner" / "entry")]) == 0
    j = json.loads(capsys.readouterr().out)["data"]
    agent_id, _, project = j["registration"].partition(":")
    assert len(project) == 64 and (t / "joiner" / "entry" / ".provena").exists()
    assert not j["registered"]                                    # open registration here
    assert _submit(t, monkeypatch, "team1", "101", t / "a.pvb", where=t / "joiner" / "entry") == 0
    _in(t / "outsider", monkeypatch)
    _CLOCK[0][0] += 120
    capsys.readouterr()
    assert main(["--json", "challenge", "status", str(t / "challenge.pvb"), "--hub", URL]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["state"] == "awaiting close"
    _in(t / "org", monkeypatch)
    assert main(["--agent", "organizer", "challenge", "close", "-o", str(t / "truth.pvb")]) == 0
    _in(t / "outsider", monkeypatch)
    capsys.readouterr()
    assert main(["--json", "challenge", "status", str(t / "challenge.pvb"), "--hub", URL]) == 0
    st = json.loads(capsys.readouterr().out)["data"]
    assert st["state"] == "closed" and st["truth_revealed_ms"] > st["deadline_ms"]


def test_status_reports_an_early_disclosure_as_void(world, monkeypatch, capsys):
    t = world
    _setup_challenge(t, monkeypatch)
    _in(t / "org", monkeypatch)
    assert main(["--agent", "organizer", "share", "truth.csv", "--to",
                 str(t / "home" / "agents" / "team2.card.json"), "--force"]) == 0
    _in(t / "outsider", monkeypatch)
    capsys.readouterr()
    assert main(["--json", "challenge", "status", str(t / "challenge.pvb"), "--hub", URL]) == 7
    out = json.loads(capsys.readouterr().out)
    assert out["data"]["state"] == "void" and out["error"]["code"] == "E_VOID"


def test_a_challenge_project_cannot_void_itself_by_accident(world, monkeypatch, capsys):
    """Internal race (2026-10-31): the organizer published a training file before `challenge
    init`; the challenge was void at the deadline. Now init refuses, and so does a disclosure
    while the challenge is open (unless --force)."""
    t = world
    _in(t / "pre", monkeypatch)
    (t / "pre" / "train.csv").write_text("x,y\n1,2\n")
    (t / "pre" / "targets.csv").write_text("seq\nA\n")
    (t / "pre" / "truth.csv").write_text("seq,label\nA,1\n")
    (t / "pre" / "score.py").write_text(SCORE)
    assert main(["--agent", "organizer", "init", "--public", "--name", "pre"]) == 0
    assert main(["--agent", "organizer", "remote", URL]) == 0
    assert main(["--agent", "organizer", "add", "train.csv"]) == 0
    assert main(["--agent", "organizer", "publish", "train.csv"]) == 0
    capsys.readouterr()
    assert main(["--json", "--agent", "organizer", "challenge", "init", "--title", "X",
                 "--truth", "truth.csv", "--targets", "targets.csv", "--score", "score.py",
                 "--deadline", _soon(), "-o", str(t / "x.pvb")]) == 7
    err = json.loads(capsys.readouterr().out)["error"]
    assert err["code"] == "E_VOID" and "--targets" in err["hint"]

    _setup_challenge(t, monkeypatch)                     # a clean project: fine
    (t / "org" / "notes.csv").write_text("n\n1\n")
    assert main(["--agent", "organizer", "add", "notes.csv"]) == 0
    capsys.readouterr()
    assert main(["--json", "--agent", "organizer", "publish", "notes.csv"]) == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "E_CONFIRM"
    assert main(["--agent", "organizer", "publish", "targets.csv"]) == 0   # a public term
    assert main(["--agent", "organizer", "publish", "notes.csv", "--force"]) == 0
    capsys.readouterr()
    assert main(["challenge", "status", str(t / "challenge.pvb"), "--hub", URL]) == 7
    assert "other than the protocol, targets and scorer" in capsys.readouterr().out
