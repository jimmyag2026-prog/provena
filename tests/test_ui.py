from fastapi.testclient import TestClient

from provena.cli.ui import create_ui
from provena.core import builders
from provena.store.repo import Repo


def _ui(lab, tmp_path):
    repo = Repo.init(tmp_path / "r", "owner", lab.log[0])
    for e in lab.log[1:]:
        repo.append(e)
    return repo, TestClient(create_ui(repo, lab.owner, 8741, token="tok", allow_test_host=True))


def test_ui_requires_token_and_shows_decrypted_names(lab, tmp_path):
    (tmp_path / "x.csv").write_text("a,b\n")
    repo, http = _ui(lab, tmp_path)
    body, secrets, size = repo.encrypt_file(lab.owner, tmp_path / "x.csv")
    h = repo.append(builders.entity(repo.state, lab.owner, body, secrets, name="x.csv",
                                    plain_size=size))
    assert http.get("/").status_code == 401
    assert http.get("/?t=wrong").status_code == 401
    home = http.get("/?t=tok")
    assert home.status_code == 200 and "x.csv" in home.text
    assert "script-src 'none'" in home.headers["content-security-policy"]
    page = http.get(f"/e/{h}")                      # cookie set by the first request
    assert "a,b" in page.text and "Sealed fields" in page.text
    assert http.get(f"/raw/{h}").content == b"a,b\n"
    assert "OK" in http.get("/verify").text


def test_ui_rejects_foreign_host(lab, tmp_path):
    _, http = _ui(lab, tmp_path)
    r = http.get("/?t=tok", headers={"host": "evil.example:8741"})
    assert r.status_code == 421


def test_ui_token_moves_to_cookie_and_unicode_download(lab, tmp_path):
    """Regression (review 4 #5, #6)."""
    (tmp_path / "数据.csv").write_text("x")
    repo, http = _ui(lab, tmp_path)
    body, secrets, size = repo.encrypt_file(lab.owner, tmp_path / "数据.csv")
    h = repo.append(builders.entity(repo.state, lab.owner, body, secrets, name='a"\\数据.csv',
                                    plain_size=size))
    r = http.get("/?t=tok", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert "provena_ui_8741" in r.headers["set-cookie"]
    raw = http.get(f"/raw/{h}")
    assert raw.status_code == 200 and raw.content == b"x"
    cd = raw.headers["content-disposition"]
    assert "filename*=UTF-8''" in cd and '\\' not in cd.split(";")[1]
    assert raw.headers["referrer-policy"] == "no-referrer"


def test_ui_rejects_testserver_host_by_default(lab, tmp_path):
    repo = Repo.init(tmp_path / "r2", "owner", lab.log[0])
    http = TestClient(create_ui(repo, lab.owner, 8741, token="tok"))
    assert http.get("/?t=tok").status_code == 421
