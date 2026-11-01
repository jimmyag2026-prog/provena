import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from provena.client.hub import HubClient
from provena.core import builders
from provena.core.keys import AgentKey
from provena.sdk import sync
from provena.server.app import create_app, load_or_create_hub_key
from provena.store.repo import Repo


def _hub_with(tmp_path, visibility):
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    http = TestClient(create_app(tmp_path / "hub", key, card))
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"), visibility=visibility,
                                      name="secret-name")
    repo = Repo.init(tmp_path / "a", "alice", genesis)
    client = HubClient("http://testserver", agent=alice, http=http)
    sync.pin_hub(repo, "http://testserver", client)
    sync.push(repo, client, agent=alice)
    return http, repo, alice


def test_index_and_public_project(tmp_path):
    http, repo, _ = _hub_with(tmp_path, "public")
    pid = repo.state.project
    page = http.get("/classic").text
    assert "Verify a proof bundle" in page and pid[:16] in page
    project = http.get(f"/classic/p/{pid}").text
    assert "genesis" in project and "secret-name" not in project  # sealed fields stay sealed
    assert http.get("/static/verifier.js").status_code == 200


def test_private_project_page_hides_entries(tmp_path):
    http, repo, _ = _hub_with(tmp_path, "private")
    pid = repo.state.project
    assert pid[:16] not in http.get("/classic").text
    page = http.get(f"/classic/p/{pid}").text
    assert "private" in page and "genesis" not in page
    assert http.get(f"/classic/p/{'ab' * 32}").status_code == 404


def test_absurd_client_timestamp_does_not_break_page(tmp_path):
    """Regression (review, low): a public entry with ts near 2^53 made /p/{pid} return 500."""
    http, repo, alice = _hub_with(tmp_path, "public")
    secrets = builders.ContentSecrets(b"\0" * 32, b"\0" * 32, b"\0" * 32)
    repo.append(builders.plan(repo.state, alice, {"commitment": "ab" * 32}, secrets,
                              title="x", ts=2**53 - 1))
    sync.push(repo, HubClient("http://testserver", agent=alice, http=http), agent=alice)
    page = http.get(f"/classic/p/{repo.state.project}")
    assert page.status_code == 200 and "invalid time" in page.text


def test_witness_refuses_changed_log_key(tmp_path):
    import pytest

    from provena.client.witness import Witness
    from provena.core.errors import VerificationError

    http, repo, _ = _hub_with(tmp_path, "public")
    w = AgentKey.generate()
    witness = Witness(w, w.make_card("org"), tmp_path / "w.json")
    client = HubClient("http://testserver", http=http)
    witness.observe(client, repo.state.project)
    key, card = load_or_create_hub_key(tmp_path / "other-hub", "pw")
    other = HubClient("http://testserver", http=TestClient(create_app(tmp_path / "other-hub",
                                                                      key, card)))
    with pytest.raises(VerificationError, match="changed its log key"):
        witness.observe(other, repo.state.project)


def test_lineage_graph_on_public_project(tmp_path):
    http, repo, alice = _hub_with(tmp_path, "public")
    secrets = builders.ContentSecrets(b"\0" * 32, b"\0" * 32, b"\0" * 32)
    plan = repo.append(builders.plan(repo.state, alice, {"commitment": "ab" * 32}, secrets,
                                     title="p"))
    (tmp_path / "a" / "r.csv").write_text("1\n")
    body, sec, size = repo.encrypt_file(alice, tmp_path / "a" / "r.csv")
    raw = repo.append(builders.entity(repo.state, alice, body, sec, name="r", plain_size=size))
    (tmp_path / "a" / "o.csv").write_text("2\n")
    body, sec, size = repo.encrypt_file(alice, tmp_path / "a" / "o.csv")
    out = repo.append(builders.entity(repo.state, alice, body, sec, name="o", plain_size=size))
    repo.append(builders.activity(repo.state, alice, used=[raw], generated=[out],
                                  plan_ref=plan))
    sync.push(repo, HubClient("http://testserver", agent=alice, http=http), agent=alice)
    page = http.get(f"/classic/p/{repo.state.project}").text
    assert "<svg class=\"lineage\"" in page and page.count("g-edge") == 3


def test_project_card_and_search(tmp_path):
    http, repo, alice = _hub_with(tmp_path, "public")
    repo.append(builders.meta(repo.state, alice, title="Kinase binder screen",
                              description="Round 1 of the X:Y binder campaign",
                              license="CC-BY-4.0", tags=["binders", "spr"]))
    sync.push(repo, HubClient("http://testserver", agent=alice, http=http), agent=alice)
    assert "Kinase binder screen" in http.get("/classic?q=binder").text
    assert "Kinase binder screen" not in http.get("/classic?q=rna").text
    page = http.get(f"/classic/p/{repo.state.project}").text
    assert "CC-BY-4.0" in page and "Round 1" in page
    assert http.get(f"/v1/projects/{repo.state.project}").json()["meta"]["tags"] == [
        "binders", "spr"]


def test_meta_rules():
    import pytest

    from provena.core.errors import VerificationError
    from tests.conftest import Lab

    lab = Lab()
    c = lab.join("contributor")
    with pytest.raises(VerificationError, match="owners/maintainers"):
        lab.add(builders.meta(lab.state, c, title="x"))
    with pytest.raises(VerificationError):
        lab.add(builders.meta(lab.state, lab.owner, title="x" * 201))
    lab.add(builders.meta(lab.state, lab.owner, title="ok", tags=["a"]))
    assert lab.state.meta == {"title": "ok", "tags": ["a"]}


def test_entry_page_does_not_render_untrusted_fields_and_sets_csp(tmp_path):
    """Regression (review 3 #1): an attest body's extra `commitment` field was rendered raw.
    Extra body fields are now rejected outright; pages also carry a strict CSP."""
    import pytest

    from provena.core import entries as entries_mod
    from provena.core.errors import VerificationError

    http, repo, alice = _hub_with(tmp_path, "public")
    target = repo.state.order[0]
    evil = entries_mod.build(alice, "attest", project=repo.state.project,
                             prev=repo.state.heads[alice.id], refs=[target],
                             body={"target": target, "type": "endorse", "verdict": None,
                                   "commitment": "<script>alert(1)</script>"})
    with pytest.raises(VerificationError, match="unknown fields"):
        repo.append(evil)
    page = http.get(f"/classic/p/{repo.state.project}/e/{target}")
    assert page.status_code == 200
    assert "script-src 'self'" in page.headers["content-security-policy"]


def test_pages_in_chinese(tmp_path):
    http, repo, _ = _hub_with(tmp_path, "public")
    zh = http.get("/classic", headers={"accept-language": "zh-CN,zh;q=0.9"}).text
    assert "可验证的科学" in zh and 'lang="zh-CN"' in zh
    assert 'lang="zh-CN"' in http.get("/", headers={"accept-language": "zh-CN"}).text  # SPA
    assert "Verifiable science" in http.get("/classic?lang=en",
                                            headers={"accept-language": "zh-CN"}).text
    project = http.get(f"/classic/p/{repo.state.project}?lang=zh").text
    assert "账本" in project and "可见性" in project


def test_published_files_download_verified_plaintext(tmp_path):
    http, repo, alice = _hub_with(tmp_path, "public")
    (tmp_path / "a" / "数据.csv").write_text("x,y\n1,2\n")
    body, sec, size = repo.encrypt_file(alice, tmp_path / "a" / "数据.csv")
    h = repo.append(builders.entity(repo.state, alice, body, sec, name="数据.csv",
                                    plain_size=size))
    (tmp_path / "a" / "private.csv").write_text("secret")
    body2, sec2, size2 = repo.encrypt_file(alice, tmp_path / "a" / "private.csv")
    h2 = repo.append(builders.entity(repo.state, alice, body2, sec2, name="private.csv",
                                     plain_size=size2))
    repo.append(builders.reveal(repo.state, alice, h, salt=sec.salt,
                                plain_sha256=sec.plain_sha256, dek=sec.dek, name="数据.csv"))
    repo.append(builders.reveal(repo.state, alice, h2, salt=sec2.salt,
                                plain_sha256=sec2.plain_sha256))      # opened, key kept
    sync.push(repo, HubClient("http://testserver", agent=alice, http=http), agent=alice)
    page = http.get(f"/classic/p/{repo.state.project}?lang=en").text
    assert "Published files" in page and "数据.csv" in page and "private.csv" not in page
    r = http.get(f"/p/{repo.state.project}/files/{h}")
    assert r.status_code == 200 and r.content == b"x,y\n1,2\n"
    assert "filename*=UTF-8''" in r.headers["content-disposition"]
    assert http.get(f"/p/{repo.state.project}/files/{h2}").status_code == 404
    assert not list((tmp_path / "hub").rglob("*.part"))   # scratch file removed after sending


def test_published_readme_is_the_project_card(tmp_path):
    from provena.server.web import render_markdown

    assert render_markdown("# T\n<script>x</script>\n- a `b`\n") == (
        "<h2>T</h2>\n<p>&lt;script&gt;x&lt;/script&gt;</p>\n<ul><li>a <code>b</code></li></ul>")
    http, repo, alice = _hub_with(tmp_path, "public")
    (tmp_path / "a" / "README.md").write_text("# Kinase screen\nRound 1 data.\n")
    body, sec, size = repo.encrypt_file(alice, tmp_path / "a" / "README.md")
    h = repo.append(builders.entity(repo.state, alice, body, sec, name="README.md",
                                    plain_size=size))
    repo.append(builders.reveal(repo.state, alice, h, salt=sec.salt,
                                plain_sha256=sec.plain_sha256, dek=sec.dek, name="README.md"))
    sync.push(repo, HubClient("http://testserver", agent=alice, http=http), agent=alice)
    page = http.get(f"/classic/p/{repo.state.project}").text
    assert "<h2>Kinase screen</h2>" in page and "<p>Round 1 data.</p>" in page


def test_published_download_is_cached_and_redaction_clears_it(tmp_path):
    http, repo, alice = _hub_with(tmp_path, "public")
    (tmp_path / "a" / "d.csv").write_text("1,2\n")
    body, sec, size = repo.encrypt_file(alice, tmp_path / "a" / "d.csv")
    h = repo.append(builders.entity(repo.state, alice, body, sec, name="d.csv", plain_size=size))
    repo.append(builders.reveal(repo.state, alice, h, salt=sec.salt,
                                plain_sha256=sec.plain_sha256, dek=sec.dek, name="d.csv"))
    client = HubClient("http://testserver", agent=alice, http=http)
    sync.push(repo, client, agent=alice)
    url = f"/p/{repo.state.project}/files/{h}"
    assert http.get(url).content == b"1,2\n" and http.get(url).content == b"1,2\n"
    cache = list((tmp_path / "hub" / "published").rglob(body["cid"]))
    assert len(cache) == 1
    repo.append(builders.redact(repo.state, alice, h, reason="withdrawn"))
    sync.push(repo, client, agent=alice)
    assert http.get(url).status_code == 404 and not cache[0].exists()


def _publish_board(tmp_path, board_text, *, scored=True):
    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    http = TestClient(create_app(tmp_path / "hub", key, card))
    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"), visibility="public")
    repo = Repo.init(tmp_path / "a", "alice", genesis)
    client = HubClient("http://testserver", agent=alice, http=http)
    sync.pin_hub(repo, "http://testserver", client)
    (tmp_path / "a" / "leaderboard.json").write_text(board_text)
    body, sec, size = repo.encrypt_file(alice, tmp_path / "a" / "leaderboard.json")
    h = repo.append(builders.entity(repo.state, alice, body, sec, name="leaderboard.json",
                                    plain_size=size))
    if scored:  # the scoring step that cites submissions in other projects
        repo.append(builders.activity(repo.state, alice, generated=[h],
                                      details={"command": ["score"]},
                                      external=[("ab" * 32, "cd" * 32)]))
    repo.append(builders.reveal(repo.state, alice, h, salt=sec.salt,
                                plain_sha256=sec.plain_sha256, dek=sec.dek,
                                name="leaderboard.json"))
    sync.push(repo, client, agent=alice)
    return http.get(f"/classic/p/{repo.state.project}")


def test_published_leaderboard_renders_ranked(tmp_path):
    board = [{"team": "pv1aaa<script>", "project": "ab" * 32, "predictions": "cd" * 32,
              "on_time": True, "score": 0.5},
             {"team": "pv1bbb", "project": "ef" * 32, "predictions": "01" * 32,
              "on_time": False, "score": 0.9}]
    page = _publish_board(tmp_path, json.dumps(board)).text
    assert "Leaderboard" in page and "challenge audit" in page
    assert "could not check this leaderboard" in page      # no challenge protocol behind it
    assert page.index("pv1aaa") < page.index("pv1bbb")          # on time first, then score
    assert "<script>" not in page.split("Leaderboard", 1)[1]


@pytest.mark.parametrize("text,scored", [
    ('[{"team": "x", "project": "' + "ab" * 32 + '", "on_time": true, "score": 1}]', False),
    ('[{"team": "x", "project": "' + "ab" * 32 + '", "on_time": true, "score": Infinity}]', True),
    ('[{"team": "x", "project": "' + "ab" * 32 + '", "on_time": true, "score": NaN}]', True),
    ('[{"team": "x", "project": "' + "ab" * 32 + '", "on_time": true, "score": 1' + "0" * 400
     + '}]', True),
])
def test_leaderboard_card_needs_a_scoring_step_and_finite_scores(tmp_path, text, scored):
    """Review 10: any project could show an authoritative-looking board; Infinity ranked first;
    a huge integer score made the project page fail."""
    r = _publish_board(tmp_path, text, scored=scored)
    assert r.status_code == 200 and "Leaderboard" not in r.text


def test_lineage_graph_draws_inputs_from_other_projects():
    from provena.core.state import ProjectState
    from provena.server.graph import lineage_svg

    alice = AgentKey.generate()
    genesis, _ = builders.new_project(alice, alice.make_card("person"), visibility="public")
    state = ProjectState.from_genesis(genesis)
    other, entry = "ab" * 32, "cd" * 32
    state.apply(builders.activity(state, alice, used=[], generated=[], plan_ref=None,
                                  details={"command": ["score"]},
                                  external=[(other, entry)]))
    svg = lineage_svg(state)
    assert f'href="/p/{other}/e/{entry}"' in svg and "g-external" in svg
    assert "href" not in lineage_svg(state, link_external=False)


def test_pages_behind_a_path_prefix(tmp_path):
    """DO trial hub: Caddy strips /provena; links on the pages must carry it again."""
    from fastapi.testclient import TestClient

    from provena.server.app import create_app, load_or_create_hub_key

    key, card = load_or_create_hub_key(tmp_path / "hub", "pw")
    http = TestClient(create_app(tmp_path / "hub", key, card, base_path="provena/"))
    html = http.get("/classic").text
    assert 'href="/provena/static/style.css"' in html and 'href="/static/' not in html
    plain = TestClient(create_app(tmp_path / "hub2", *load_or_create_hub_key(tmp_path / "hub2",
                                                                             "pw")))
    assert 'href="/static/style.css"' in plain.get("/").text


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("lang,word", [("en", "Preregistration"), ("zh-CN", "预注册")])
def test_reader_explains_the_verdict(tmp_path, lang, word):
    """Proof Reader: a dropped bundle gets a plain-language meaning and the preregistration
    table (runs static/app.js under node with a stub DOM)."""
    import subprocess

    from provena.core.bundle import make_bundle
    from tests.conftest import Lab
    from tests.test_bundle import HUB_CARD, _head

    lab = Lab()
    plan = lab.put_plan(lab.owner)
    raw = lab.put_entity(lab.owner, b"x\n")
    out = lab.put_entity(lab.owner, b"y\n")
    act = lab.add(builders.activity(lab.state, lab.owner, used=[raw], generated=[out],
                                    plan_ref=plan))
    bundle = make_bundle(lab.log, _head(lab), HUB_CARD, [act])
    f = tmp_path / "b.pvb"
    f.write_text(json.dumps(bundle))
    root = Path(__file__).resolve().parents[1]
    res = json.loads(subprocess.run(["node", str(root / "tests" / "js" / "reader.mjs"), str(f),
                                     lang], capture_output=True, text=True, check=True).stdout)
    assert not res["hidden"] and "ok" in res["cls"]
    assert word in res["text"] and "VALID" in res["text"]


def test_pages_have_json_twins(tmp_path):
    """What the pages show is also served as JSON (for agents, and a future SPA)."""
    http, repo, _ = _hub_with(tmp_path, "public")
    pid = repo.state.project
    listing = http.get("/v1/catalog").json()
    assert [p["project"] for p in listing["projects"]] == [pid] and listing["private"] == 0
    assert http.get("/v1/catalog", params={"q": "no-such-thing"}).json()["projects"] == []
    view = http.get(f"/v1/projects/{pid}/overview").json()
    assert view["visibility"] == "public" and view["head"]["size"] == 1
    assert [e["kind"] for e in view["entries"]] == ["genesis"] and view["entries_total"] == 1
    assert view["files"] == [] and view["lineage"] == [] and view["leaderboard"] is None
    assert http.get(f"/v1/projects/{'0' * 64}/overview").status_code == 404

    http2, repo2, _ = _hub_with(tmp_path / "priv", "private")
    assert http2.get("/v1/catalog").json() == {"projects": [], "private": 1, "unlisted": 0}
    private = http2.get(f"/v1/projects/{repo2.state.project}/overview").json()
    assert "entries" not in private and private["meta"] == {}


def test_the_browser_reader_checks_a_hub_log_itself(tmp_path):
    """/app (beta) checks a project's log in the browser: verifyPublicLog under node, on what
    the hub serves, and on the same log with one entry altered."""
    from tests.test_js_verifier import ROOT, _run_node

    http, repo, alice = _hub_with(tmp_path, "public")
    (tmp_path / "a" / "x.csv").write_text("x\n")
    body, sec, size = repo.encrypt_file(alice, tmp_path / "a" / "x.csv")
    repo.append(builders.entity(repo.state, alice, body, sec, name="x.csv", plain_size=size))
    client = HubClient("http://testserver", agent=alice, http=http)
    sync.push(repo, client, agent=alice)
    pid = repo.state.project
    page = http.get("/app")
    assert page.status_code == 200 and "spa.js" in page.text
    assert http.get("/static/spa.js").status_code == 200
    card = http.get("/v1/hub").json()["card"]
    head = http.get(f"/v1/projects/{pid}/sth").json()
    log = [it["entry"] for it in http.get(f"/v1/projects/{pid}/entries").json()["entries"]]
    altered = [log[0], {**log[1], "ts": log[1]["ts"] + 1}]
    out = _run_node(tmp_path, {"vectors": json.loads((ROOT / "tests" / "vectors" / "core.json")
                                                     .read_text()), "bundles": {},
                               "logs": {
        "served": {"pid": pid, "card": card, "head": head, "log": log},
        "altered": {"pid": pid, "card": card, "head": head, "log": altered},
        "short": {"pid": pid, "card": card, "head": head, "log": log[:1]},
        # review: another project's genuine head and log shown under this project's id
        "other": {"pid": "ab" * 32, "card": card, "head": head, "log": log}}})
    assert out["logs"]["served"]["ok"] and out["logs"]["served"]["size"] == 2
    assert not out["logs"]["altered"]["ok"] and not out["logs"]["short"]["ok"]
    assert "another project" in out["logs"]["other"]["error"]


def test_the_spa_is_the_front_end_and_classic_pages_stay(tmp_path):
    """The canonical page URLs (cited in bundles) serve the SPA shell; /classic serves the same
    content without JavaScript, and its links stay classic (except file downloads)."""
    from tests.test_js_verifier import ROOT, _run_node

    http, repo, alice = _hub_with(tmp_path, "public")
    pid = repo.state.project
    h = repo.state.order[0]
    for path in ("/", f"/p/{pid}", f"/p/{pid}/e/{h}"):
        page = http.get(path)
        assert page.status_code == 200 and "spa.js" in page.text and "/classic" in page.text
    from provena.server.web import BUILD

    assert f"/static/{BUILD}/spa.js" in http.get("/").text      # cache-busting build path
    assert http.get(f"/static/{BUILD}/verifier.js").status_code == 200
    assert http.get(f"/p/{'ab' * 32}").status_code == 404
    assert http.get(f"/p/{pid}/e/not-a-hash").status_code == 404
    assert http.get("/app?lang=zh", follow_redirects=False).headers["location"] == "/?lang=zh"
    assert http.get("/app", follow_redirects=False).headers["location"] == "/"
    classic = http.get(f"/classic/p/{pid}").text
    assert f'href="/classic/p/{pid}/e/' in classic or f"href='/classic/p/{pid}/e/" in classic
    assert f"href='/p/{pid}/e/" not in classic and f'href="/p/{pid}/e/' not in classic
    view = http.get(f"/v1/projects/{pid}/entries/{h}").json()
    assert view["index"] == 0 and view["entry"]["kind"] == "genesis"
    assert http.get(f"/v1/projects/{pid}/entries/{'ab' * 32}").status_code == 404
    head = http.get(f"/v1/projects/{pid}/sth").json()
    proof = http.get(f"/v1/projects/{pid}/proofs/inclusion",
                     params={"index": 0, "size": head["size"]}).json()["proof"]
    card = http.get("/v1/hub").json()["card"]
    out = _run_node(tmp_path, {"vectors": json.loads((ROOT / "tests" / "vectors" / "core.json")
                                                     .read_text()), "bundles": {},
                               "entries": {
        "ok": [pid, h, card, head, view["entry"], 0, proof],
        "wrong_project": ["ab" * 32, h, card, head, view["entry"], 0, proof],
        "altered": [pid, h, card, head, {**view["entry"], "ts": 1}, 0, proof],
        "wrong_index": [pid, h, card, head, view["entry"], 1, proof]}})
    assert out["entries"]["ok"]["ok"]
    assert not out["entries"]["wrong_project"]["ok"] and not out["entries"]["altered"]["ok"]
    assert not out["entries"]["wrong_index"]["ok"]

    http2, repo2, _ = _hub_with(tmp_path / "priv", "private")
    private = http2.get(f"/v1/projects/{repo2.state.project}/entries/"
                        f"{repo2.state.order[0]}").json()
    assert "entry" not in private and private["kind"] == "genesis"


def test_unlisted_project_leaves_catalog_but_stays_reachable(tmp_path, monkeypatch):
    """Operator-side unlisting (0.2.1): out of the listing and its search, still served by id
    with proofs — the ledger is append-only, so nothing is deleted."""
    from provena.server.hub import parse_project_ids

    http, repo, alice = _hub_with(tmp_path, "public")
    pid = repo.state.project
    secrets = builders.ContentSecrets(b"\0" * 32, b"\0" * 32, b"\0" * 32)
    repo.append(builders.plan(repo.state, alice, {"commitment": "ab" * 32}, secrets, title="x"))
    sync.push(repo, HubClient("http://testserver", agent=alice, http=http), agent=alice)
    hub = http.app.state.hub
    assert [p["project"] for p in http.get("/v1/catalog").json()["projects"]] == [pid]

    # the file form (re-read on every listing) and the env/static form both apply
    unlisted = tmp_path / "unlisted.txt"
    unlisted.write_text(f"# rehearsal projects\n{pid}   # pilot\n")
    hub.unlisted_file = unlisted
    assert hub.unlisted_projects() == {pid}
    assert parse_project_ids("a, b\nc # d") == {"a", "b", "c"}

    listing = http.get("/v1/catalog").json()
    assert listing == {"projects": [], "private": 0, "unlisted": 1}
    assert http.get("/v1/catalog", params={"q": "x"}).json()["projects"] == []
    page = http.get("/classic").text
    assert pid[:16] not in page and "0 private and 1 unlisted project(s)" in page
    # a witness enumerating the hub still sees it (public), flagged
    full = http.get("/v1/catalog", params={"include": "unlisted"}).json()["projects"]
    assert [p["project"] for p in full] == [pid] and full[0]["unlisted"] is True
    # everything addressed by id is untouched
    assert http.get(f"/v1/projects/{pid}").json()["visibility"] == "public"
    assert http.get(f"/v1/projects/{pid}/overview").json()["head"]["size"] == 2
    assert http.get(f"/classic/p/{pid}").status_code == 200
    assert http.get(f"/p/{pid}").status_code == 200
    consistency = http.get(f"/v1/projects/{pid}/proofs/consistency",
                           params={"first": 1, "second": 2}).json()
    assert consistency["proof"]
    assert http.get(f"/v1/projects/{pid}/proofs/inclusion",
                    params={"index": 0, "size": 2}).json()["proof"]

    unlisted.unlink()  # a lost file lists everything again, with a log line, not a 500
    assert http.get("/v1/catalog").json()["unlisted"] == 0


def test_hub_serve_reads_unlisted_setting(tmp_path, monkeypatch):
    """`--unlisted FILE` and PROVENA_HUB_UNLISTED_PROJECTS reach the hub from `hub serve`."""
    import uvicorn

    from provena.cli.main import main

    captured = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.setdefault("app", app))
    monkeypatch.setenv("PROVENA_HUB_PASSPHRASE", "pw")
    monkeypatch.setenv("PROVENA_HUB_UNLISTED_PROJECTS", "aa" * 32 + ", " + "bb" * 32)
    f = tmp_path / "unlisted.txt"
    f.write_text("cc" * 32 + "\n")
    assert main(["hub", "serve", "--data", str(tmp_path / "hub"), "--unlisted", str(f),
                 "--anchor-interval", "0"]) == 0
    hub = captured["app"].state.hub
    assert hub.unlisted_projects() == {"aa" * 32, "bb" * 32, "cc" * 32}
    assert main(["hub", "serve", "--data", str(tmp_path / "hub2"),
                 "--unlisted", str(tmp_path / "missing.txt")]) != 0
