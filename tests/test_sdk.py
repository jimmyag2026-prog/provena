import json

import pytest

from provena import sdk
from provena.cli.main import main
from provena.core.verify import verify_bundle


@pytest.fixture
def proj(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PROVENA_PASSPHRASE", "pw")
    monkeypatch.setenv("PROVENA_SCRYPT_N", "1024")
    work = tmp_path / "exp"
    work.mkdir()
    monkeypatch.chdir(work)
    main(["keygen", "--kind", "software", "--display", "analysis-agent"])
    main(["init", "--name", "sdk-demo"])
    return sdk.open(work)


def test_notebook_style_workflow(proj, tmp_path):
    (tmp_path / "exp" / "protocol.md").write_text("fit a Hill curve; report Kd\n")
    (tmp_path / "exp" / "raw.csv").write_text("c,s\n1,0.1\n")
    plan = proj.plan("protocol.md")
    raw = proj.add("raw.csv")
    with proj.run("fit binding curve", plan=plan, used=[raw], params={"model": "hill"}) as run:
        (tmp_path / "exp" / "kd.json").write_text('{"kd_nM": 7}')
        run.output("kd.json", media_type="application/json")
    assert run.activity
    details = proj.details(run.activity)
    assert details["command"] == ["fit binding curve"] and details["params"] == {"model": "hill"}
    assert proj.read(run.outputs[0]) == b'{"kd_nM": 7}'

    bundle = proj.prove([run.activity], tmp_path / "kd.pvb", open=[run.outputs[0]])
    report = verify_bundle(bundle)
    assert report.ok and report.trust == "self-sequenced"
    # without a trusted log, order-based claims are notes, not facts
    assert any("preregistration holds" in n for n in report.notes)
    assert not any("preregistration holds" in f for f in report.facts)


def test_failed_run_is_still_recorded(proj, tmp_path):
    (tmp_path / "exp" / "in.csv").write_text("x\n")
    raw = proj.add("in.csv")
    with pytest.raises(ZeroDivisionError):
        with proj.run("divide", used=[raw]):
            raise ZeroDivisionError("division by zero")
    last = proj.log()[-1]
    assert last["kind"] == "activity"
    assert last["private"]["exit_code"] == 1 and "ZeroDivisionError" in last["private"]["error"]


def test_prov_export(proj, tmp_path, capsys):
    (tmp_path / "exp" / "a.csv").write_text("a\n")
    a = proj.add("a.csv")
    with proj.run("transform", used=[a]) as run:
        (tmp_path / "exp" / "b.csv").write_text("b\n")
        run.output("b.csv")
    doc = proj.export_prov()
    assert f"pve:{a}" in doc["entity"] and f"pve:{run.activity}" in doc["activity"]
    assert any(r["prov:entity"] == f"pve:{a}" for r in doc["used"].values())
    assert "prov:label" not in doc["entity"][f"pve:{a}"]  # names stay private by default
    full = proj.export_prov(include_private=True)
    assert full["entity"][f"pve:{a}"]["prov:label"] == "a.csv"
    assert "prov:startTime" in full["activity"][f"pve:{run.activity}"]

    capsys.readouterr()
    assert main(["export", "prov"]) == 0
    assert "wasGeneratedBy" in json.loads(capsys.readouterr().out)


def test_open_requires_passphrase(proj, monkeypatch, tmp_path):
    from provena.store.secrets import SecretUnavailable

    monkeypatch.delenv("PROVENA_PASSPHRASE")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    with pytest.raises(SecretUnavailable):
        sdk.open(tmp_path / "exp")


def test_ai_agent_provenance(proj, tmp_path):
    (tmp_path / "exp" / "papers.csv").write_text("doi\n10.1/x\n")
    harness = tmp_path / "exp" / "agent.py"
    harness.write_text("print('agent')\n")
    papers = proj.add("papers.csv")
    with proj.run("summarise literature", used=[papers], model="anthropic/claude-opus-5-5",
                  harness=harness) as run:
        run.trace('{"role": "user", "content": "summarise"}\n{"role": "assistant"}\n')
        (tmp_path / "exp" / "summary.md").write_text("# Summary\n")
        run.output("summary.md")
    details = proj.details(run.activity)
    assert details["model"] == "anthropic/claude-opus-5-5"
    assert len(details["harness_sha256"]) == 64
    assert details["traces"] == run.traces and run.traces[0] in run.outputs
    assert proj.read(run.traces[0]).startswith(b'{"role": "user"')
    # traces are sealed until revealed; revealing with key makes them auditable by anyone
    reveal = proj.reveal(run.traces[0], with_key=True)
    assert proj.repo.state.reveals[run.traces[0]]["dek"] and reveal


def test_jupyter_cell_recording(proj, tmp_path):
    from provena.sdk.ipython import record_cell

    (tmp_path / "exp" / "raw.csv").write_text("1\n2\n")
    proj.add("raw.csv")
    ns = {}

    def execute(src):
        exec(src, ns)

    src = "total = sum(int(x) for x in open('raw.csv'))\nopen('total.txt','w').write(str(total))\n"
    run = record_cell(proj, '"sum the plate" --used raw.csv --out total.txt', src, execute)
    assert ns["total"] == 3
    details = proj.details(run.activity)
    assert details["command"] == ["sum the plate"]
    assert proj.read(run.outputs[0]).decode() == src          # exact cell code is on record
    assert proj.read(run.outputs[1]) == b"3"

    with pytest.raises(ValueError):
        record_cell(proj, '"bad cell" --used raw.csv', "raise ValueError('boom')", execute)
    assert proj.log()[-1]["private"]["exit_code"] == 1        # failed cells are recorded too


def test_rocrate_export_is_verifiable(proj, tmp_path):
    import json as _json

    from provena.sdk.rocrate import export_rocrate

    exp = tmp_path / "exp"
    (exp / "data").mkdir()
    (exp / "data" / "raw.csv").write_text("1,2\n")
    raw = proj.add("data/raw.csv", media_type="text/csv")
    with proj.run("compute", used=[raw]) as run:
        (exp / "out.txt").write_text("3\n")
        run.output("out.txt")
    crate_dir = tmp_path / "crate"
    crate = export_rocrate(proj, crate_dir)
    graph = {n["@id"]: n for n in crate["@graph"]}
    assert graph["./"]["@type"] == "Dataset"
    assert graph["data/raw.csv"]["encodingFormat"] == "text/csv"
    action = next(n for n in crate["@graph"] if n["@type"] == "CreateAction")
    assert action["object"] == [{"@id": "data/raw.csv"}]
    assert action["result"] == [{"@id": "out.txt"}]
    assert (crate_dir / "data" / "raw.csv").read_text() == "1,2\n"
    bundle = _json.loads((crate_dir / "provena-proof.pvb").read_text())
    report = verify_bundle(bundle, external_contents={
        raw: (crate_dir / "data" / "raw.csv").read_bytes()})
    assert report.ok and any("matches its commitment" in f for f in report.facts)


def test_rocrate_refuses_ledger_path_traversal(proj, tmp_path):
    from provena.core import builders
    from provena.sdk.rocrate import export_rocrate
    from provena.store.paths import UnsafePath

    (tmp_path / "exp" / "x.csv").write_text("x")
    repo = proj.repo
    body, secrets, size = repo.encrypt_file(proj.agent, tmp_path / "exp" / "x.csv")
    repo.append(builders.entity(repo.state, proj.agent, body, secrets,
                                name="../../escaped.txt", plain_size=size))
    with pytest.raises(UnsafePath):
        export_rocrate(proj, tmp_path / "crate")
    assert not (tmp_path / "escaped.txt").exists()


def test_rocrate_reserved_names_and_private_gate(proj, tmp_path):
    from provena.sdk.rocrate import export_rocrate
    from provena.store.paths import UnsafePath

    exp = tmp_path / "exp"
    (exp / "a.csv").write_text("a")
    a = proj.add("a.csv")
    with proj.run("secret command line", used=[a]) as run:
        (exp / "b.csv").write_text("b")
        run.output("b.csv")
    crate = export_rocrate(proj, tmp_path / "c1")
    assert "secret command line" not in json.dumps(crate)
    crate = export_rocrate(proj, tmp_path / "c2", include_private=True)
    assert "secret command line" in json.dumps(crate)
    (exp / "ro-crate-metadata.json").write_text("{}")
    proj.add("ro-crate-metadata.json")
    with pytest.raises(UnsafePath):
        export_rocrate(proj, tmp_path / "c3")


def test_an_integration_without_the_cli(tmp_path, monkeypatch):
    """Integrator acceptance: init, plan from text, one line per tool call, prove, verify."""
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PROVENA_SCRYPT_N", "1024")
    monkeypatch.chdir(tmp_path)                                  # not the project directory
    proj = sdk.init(tmp_path / "study", agent="bot", passphrase="pw")
    plan = proj.plan_text("Predict X; success if AUC > 0.8", "protocol.md")
    assert proj.plan_text("Predict X; success if AUC > 0.8", "protocol.md") == plan  # retry
    proj.record("web_search", {"q": "x", "k": 0.5}, {"hits": 3})
    (tmp_path / "study" / "results").mkdir()
    (tmp_path / "study" / "results" / "fit.json").write_text("{}")
    r = proj.record("python fit.py", outputs=["results/fit.json"], plan="plans/protocol.md")
    failed = proj.record("fetch", {"url": "u"}, error="HTTP 500")
    assert failed["status"] == "failed" and r["status"] == "ok"
    proj.prove(["results/fit.json"], tmp_path / "out.pvb")       # the output alone: its
    v = sdk.verify(tmp_path / "out.pvb")                         # sibling (the trace) stays
    assert v["valid"] and not v["preregistration"][0]["holds"]   # undisclosed (review 5 F7)
    proj.prove([r["activity"]], tmp_path / "step.pvb")           # the step: all its outputs
    v = sdk.verify(tmp_path / "step.pvb")
    rows = [x for x in v["preregistration"] if x["target"]]
    assert v["valid"] and rows and rows[0]["holds"] and rows[0]["reason"] == "order-unproven"
