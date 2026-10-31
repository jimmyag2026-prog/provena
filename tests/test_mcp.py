"""`provena mcp`, driven over stdio exactly as an MCP host (Claude Code, Spark Research) does."""

import json
import os
import subprocess
import sys

import pytest

from provena.cli.main import main


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVENA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PROVENA_SCRYPT_N", "1024")
    secret = tmp_path / "pass"
    secret.write_text("pw\n")
    secret.chmod(0o600)
    monkeypatch.setenv("PROVENA_PASSPHRASE_FILE", str(secret))
    monkeypatch.delenv("PROVENA_PASSPHRASE", raising=False)
    work = tmp_path / "proj"
    work.mkdir()
    monkeypatch.chdir(work)
    assert main(["keygen", "--kind", "software"]) == 0 and main(["init", "--name", "x"]) == 0
    return work


class Host:
    def __init__(self, work):
        self.proc = subprocess.Popen([sys.executable, "-m", "provena.cli.main", "mcp",
                                      "--project", str(work)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env=dict(os.environ))
        self.n = 0

    def rpc(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notify:
            self.n += 1
            msg["id"] = self.n
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        return None if notify else json.loads(self.proc.stdout.readline())

    def tool(self, name, **args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})["result"]
        return r["isError"], r["structuredContent"]

    def close(self):
        self.proc.stdin.close()
        assert self.proc.wait(timeout=20) == 0


def test_an_agent_records_proves_and_verifies_through_mcp(project):
    host = Host(project)
    init = host.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                   "clientInfo": {"name": "test", "version": "0"}})
    assert init["result"]["protocolVersion"] == "2025-06-18"
    assert "record_step" in init["result"]["instructions"]
    host.rpc("notifications/initialized", notify=True)
    tools = {t["name"] for t in host.rpc("tools/list")["result"]["tools"]}
    assert {"record_step", "preregister", "prove", "verify"} <= tools

    (project / "protocol.md").write_text("predict binding; success if AUC > 0.8")
    err, plan = host.tool("preregister", path="protocol.md", title="prereg")
    assert not err and plan["kind"] == "plan" and len(plan["hash"]) == 64
    err, search = host.tool("record_step", tool="web_search", args={"q": "RNA binders"},
                            result={"hits": 3}, model="provider/model-x")
    assert not err and search["status"] == "ok"
    (project / "pred.csv").write_text("seq,score\nAUGC,0.9\n")
    err, fit = host.tool("record_step", tool="python fit.py", plan="protocol.md",
                         outputs=["pred.csv"], args={"lr": 0.05})
    assert not err and fit["outputs"][0]["path"] == "pred.csv"
    err, failed = host.tool("record_step", tool="python eval.py", error="CUDA OOM",
                            exit_code=1)
    assert not err and failed["status"] == "failed"
    err, rev = host.tool("reveal", ref=failed["activity"]["hash"])
    assert not err and rev["details"]["error"] == "CUDA OOM"
    err, again = host.tool("add_file", path="pred.csv")
    assert not err and again["unchanged"]

    err, p = host.tool("prove", refs=[fit["activity"]["hash"]], output="fit.pvb",
                       open=["pred.csv"])
    assert not err and (project / "fit.pvb").exists()
    err, v = host.tool("verify", bundle="fit.pvb")
    assert not err and v["valid"] and v["preregistration"][0]["holds"]
    err, v = host.tool("verify", bundle="fit.pvb", require="log-sequenced")
    assert not err and not v["accepted"]                   # no hub: only self-sequenced

    err, bad = host.tool("add_file", path="/etc/hosts")
    assert err and "outside the project" in bad["message"]   # a tool error, not a crash
    assert host.rpc("nope")["error"]["code"] == -32601
    host.close()
    assert main(["verify"]) == 0                            # the CLI agrees, ledger intact


def test_the_key_never_comes_from_the_conversation(project, monkeypatch):
    monkeypatch.delenv("PROVENA_PASSPHRASE_FILE")
    proc = subprocess.run([sys.executable, "-m", "provena.cli.main", "mcp", "--project",
                           str(project)], input="", capture_output=True, text=True,
                          env=dict(os.environ))
    assert proc.returncode == 4 and "PROVENA_PASSPHRASE_FILE" in proc.stderr


def test_mcp_refuses_bad_arguments_and_paths_outside_the_project(project, tmp_path):
    host = Host(project)
    host.rpc("initialize", {"protocolVersion": "2025-06-18"})
    err, e = host.tool("record_step", tool="x", outputz=["typo.csv"])
    assert err and e["code"] == "E_USAGE" and "outputz" in e["message"]
    err, e = host.tool("log", limit="3")
    assert err and e["code"] == "E_USAGE"
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    (project / "p.md").write_text("plan")
    err, plan = host.tool("preregister", path="p.md")
    err, e = host.tool("prove", refs=[plan["hash"]], output=str(victim))
    assert err and victim.read_text() == "keep me"
    err, e = host.tool("prove", refs=[plan["hash"]], output="../escape.pvb")
    assert err and not (tmp_path / "escape.pvb").exists()
    err, ok = host.tool("prove", refs=[plan["hash"]], output="out/p.pvb")
    assert not err and (project / "out" / "p.pvb").exists()
    err, e = host.tool("verify", bundle=str(victim))
    assert err and e["code"] == "E_INPUT"
    err, again = host.tool("preregister", path="p.md")            # a retry: no new entry
    assert not err and again["hash"] == plan["hash"]
    host.close()
