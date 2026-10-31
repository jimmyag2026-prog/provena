"""Sandbox command construction (the Linux path cannot run on every test host)."""

import tempfile
from pathlib import Path

from provena.cli import sandbox


def test_bwrap_hides_home_and_temp_then_mounts_runtime_and_work(monkeypatch, tmp_path):
    home = Path("/nonexistent/ada")                # not inside the temp dir, as on real hosts
    venv = home / "repo" / ".venv"
    work = Path(tempfile.gettempdir()).resolve() / "provena-challenge-x"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(sandbox, "_runtime", lambda: [venv])
    keys = Path("/srv/keys")                       # a denied path outside the home directory
    argv = sandbox._wrap("bwrap", ["python", "score.py"], work,
                         [keys, home / "repo", work.parent / "eval" / ".provena"])
    assert str(work.parent / "eval" / ".provena") not in argv   # nested in the hidden temp dir
    joined = " ".join(argv)
    order = [argv.index(str(home)), argv.index(str(venv)), argv.index(str(work))]
    assert order == sorted(order)                  # later mounts cover earlier ones
    assert f"--tmpfs {Path(tempfile.gettempdir()).resolve()}" in joined
    assert f"--ro-bind {venv} {venv}" in joined and f"--bind {work} {work}" in joined
    work_at = argv.index("--bind")                 # only the work directory is writable
    for hidden in (home, Path(tempfile.gettempdir()).resolve()):
        i = argv.index(str(hidden), work_at)
        assert argv[i - 1] == "--remount-ro"
    for flag in ("--unshare-all", "--new-session", "--die-with-parent"):
        assert flag in argv
    assert argv[-3:] == ["--", "python", "score.py"]


def test_macos_profile_denies_services_and_rereads_runtime_last(monkeypatch, tmp_path):
    home = tmp_path / "home"
    venv = home / "repo" / ".venv"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(sandbox, "_runtime", lambda: [venv])
    keys = home / ".provena"
    profile = sandbox._wrap("sandbox-exec", ["python"], tmp_path / "w", [keys, home / "repo"])[2]
    for rule in ("(deny network*)", "(deny mach-lookup)", "(deny lsopen)", "(deny signal)"):
        assert rule in profile
    final = profile.rsplit("(deny file-read*", 1)[1]
    assert str(keys) in final and f'"{home / "repo"}"' not in final   # venv stays readable


def test_detached_descendants_are_killed(tmp_path):
    """macOS: a child that calls setsid left the process group and outlived the run."""
    import os
    import sys
    import time

    pidfile = tmp_path / "child.pid"
    script = ("import os, sys, time\n"
              "if os.fork() == 0:\n"
              "    os.setsid()\n"
              f"    open({str(pidfile)!r}, 'w').write(str(os.getpid()))\n"
              "    time.sleep(60)\n"
              "    sys.exit()\n"
              "time.sleep(0.5)\n")
    sandbox.run_untrusted([sys.executable, "-c", script], work=tmp_path, env=dict(os.environ),
                          timeout=30, deny_read=[], mode="off")
    pid = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    os.kill(pid, 9)
    raise AssertionError("the detached child survived the run")
