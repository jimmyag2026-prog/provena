"""Run an untrusted program (a challenge's scoring program) with the least access the platform
offers: no network, writes only to its work directory, Provena keys and repo state unreadable,
and resource limits. Linux uses bubblewrap (`bwrap`), macOS `sandbox-exec`; without either the
program runs with resource limits only, and `--sandbox require` refuses instead."""

from __future__ import annotations

import functools
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from provena.cli import output
from provena.cli.common import CliError

FILE_LIMIT = 1 << 30  # bytes any one file the program writes may reach
MEMORY_LIMIT = 8 << 30  # address space (Linux; macOS ignores RLIMIT_AS)


BWRAP_CORE = ["--unshare-all", "--new-session", "--die-with-parent", "--dev", "/dev",
              "--proc", "/proc"]


@functools.cache
def available() -> str | None:
    if sys.platform.startswith("linux") and shutil.which("bwrap"):
        # installed is not enough: unprivileged user namespaces may be disabled (e.g. by
        # AppArmor on recent Ubuntu), so probe once with the options a real run uses
        probe = subprocess.run(["bwrap", "--ro-bind", "/", "/", *BWRAP_CORE, "true"],
                               capture_output=True, timeout=10)
        return "bwrap" if probe.returncode == 0 else None
    if sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").exists():
        return "sandbox-exec"
    return None


def _sb_string(path: Path) -> str:
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _runtime() -> list[Path]:
    """What the interpreter itself must read (it may live under $HOME, e.g. a venv)."""
    return sorted({Path(p).resolve() for p in (sys.prefix, sys.base_prefix, sys.exec_prefix)})


def _wrap(tool: str, argv: list[str], work: Path, deny_read: list[Path]) -> list[str]:
    """Hidden: the whole home directory and *deny_read* (keys, the evaluator's repository);
    visible again: the work directory and the Python runtime. No network, no IPC."""
    home = Path.home().resolve()
    # temp directories hold other runs' work folders (decrypted truths, predictions)
    temps = sorted({Path(tempfile.gettempdir()).resolve(), Path("/tmp").resolve()})
    if tool == "bwrap":
        empty = [home, *[t for t in temps if t != Path("/")],
                 *[d for d in deny_read if d.exists()]]
        # a path inside another hidden one is already hidden (and a later mount over its
        # parent would bury it, so it could not be remounted read-only)
        empty = sorted({d for d in empty if not any(d != e and d.is_relative_to(e)
                                                     for e in empty)})
        mounts = ["--ro-bind", "/", "/", *[a for d in empty for a in ("--tmpfs", str(d))]]
        mounts += [a for r in _runtime() if r.is_relative_to(home)
                   for a in ("--ro-bind", str(r), str(r))]
        # the empty mounts become read-only once the work directory is mounted inside them
        # (non-recursive, so work stays writable): otherwise a program writes beside its work
        # directory into memory-backed tmpfs
        sealed = [a for d in empty for a in ("--remount-ro", str(d))]
        return ["bwrap", *mounts, "--bind", str(work), str(work), *sealed, *BWRAP_CORE,
                "--chdir", str(work), "--", *argv]
    hidden = " ".join(f"(subpath {_sb_string(d)})" for d in [home, *temps, *deny_read])
    visible = " ".join(f"(subpath {_sb_string(d)})" for d in [work, *_runtime()])
    # Denied again last (keys nested in an allowed path) — but never a directory that holds
    # the work folder or the interpreter (e.g. a venv inside the repository): those stay
    # hidden by the first deny except for exactly the allowed subtrees.
    keep = [work, *_runtime()]
    keys = " ".join(f"(subpath {_sb_string(d)})" for d in deny_read
                    if not any(k.is_relative_to(d) for k in keep))
    profile = ("(version 1)(allow default)"
               "(deny network*)(deny mach-lookup)(deny lsopen)"   # no services, no `open`
               "(deny process-info*)(allow process-info* (target self))"  # no parent's env
               "(deny signal)(allow signal (target self))"   # cannot stop or kill your processes
               "(deny file-write*)"
               f"(allow file-write* (subpath {_sb_string(work)}) (literal \"/dev/null\"))"
               f"(deny file-read* {hidden})(allow file-read* {visible})"
               "(allow file-read-metadata)"  # stat() for path traversal; not contents/listings
               + (f"(deny file-read* {keys})" if keys else ""))
    return ["/usr/bin/sandbox-exec", "-p", profile, *argv]


def _limits(cpu_seconds: float):
    def apply() -> None:
        import resource

        if cpu_seconds is not None:
            cpu = int(cpu_seconds) + 5
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if sys.platform.startswith("linux"):
            resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))
    return apply


def run_untrusted(argv: list[str], *, work: Path, env: dict, timeout: float | None,
                  deny_read: list[Path], mode: str = "auto", cwd: Path | None = None,
                  check: bool = True) -> int:
    """Run *argv* in *work* (or *cwd* inside it); returns its exit code (with *check*, a
    non-zero exit is an error). The program gets no terminal (stdin closed, its own session:
    it cannot inject keystrokes into the user's shell), and its whole process group is killed
    when it ends or times out."""
    tool = None if mode == "off" else available()
    if "PROVENA_PASSPHRASE" in os.environ and tool != "bwrap":
        # on macOS (and without a PID namespace) any same-user program can read other
        # processes' environments, the user's shell included: no sandbox-exec rule stops it
        message = ("PROVENA_PASSPHRASE is set: a program you run can read it from your "
                   "processes' environment. Unset it and enter the passphrase when asked")
        if mode == "require":
            raise CliError(message)
        output.warn("W_ENV_PASSPHRASE", message)
    if mode == "require" and tool is None:
        raise CliError("no sandbox available (bwrap on Linux, sandbox-exec on macOS); pass "
                       "--sandbox off to run the program with resource limits only")
    if tool is None and mode == "auto":
        output.warn("W_NO_SANDBOX", "no sandbox available; the program runs with resource "
                    "limits only")
    work = work.resolve()
    deny = [d.resolve() for d in deny_read]
    command = _wrap(tool, argv, work, deny) if tool else argv
    tag = secrets.token_hex(16)  # inherited by every descendant, found again by _sweep
    proc = subprocess.Popen(command, cwd=cwd or work,
                            env={**env, "TMPDIR": str(work), RUN_TAG: tag},
                            stdin=subprocess.DEVNULL, start_new_session=True,
                            preexec_fn=_limits(timeout) if os.name == "posix" else None)
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise CliError(f"the program ran longer than {timeout:g}s and was stopped") from exc
    finally:
        _kill_group(proc)
        if tool != "bwrap":  # bwrap: its PID namespace dies with the program
            _sweep(tag)
    if check and code != 0:
        raise CliError(f"the program failed (exit {code}"
                       f"{', inside ' + tool if tool else ''}); nothing was recorded as output")
    return code


def _kill_group(proc: subprocess.Popen) -> None:
    """Children the program left behind (its session's process group) do not outlive it."""
    if os.name != "posix":
        proc.kill()
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    proc.wait()


RUN_TAG = "PROVENA_SANDBOX_RUN"


def _tagged(tag: str) -> list[int]:
    """Live processes of this user whose environment carries *tag*."""
    needle = f"{RUN_TAG}={tag}"
    if sys.platform.startswith("linux"):
        found = []
        for d in Path("/proc").iterdir():
            try:
                if d.name.isdigit() and needle.encode() in \
                        (d / "environ").read_bytes().split(b"\0"):
                    found.append(int(d.name))
            except OSError:
                continue
        return found
    try:  # macOS: `ps -E` appends each process's environment to its command
        out = subprocess.run(["ps", "-E", "-ww", "-o", "pid=,command=", "-U", str(os.getuid())],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return [int(line.split(None, 1)[0]) for line in out.splitlines()
            if f" {needle}" in line and line.strip()]


def _sweep(tag: str) -> None:
    """Kill descendants that left the process group (`setsid`). Best effort: a program that
    removes the variable from its environment before detaching is not found."""
    for _ in range(5):  # a survivor may fork while we kill
        pids = [p for p in _tagged(tag) if p != os.getpid()]
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
