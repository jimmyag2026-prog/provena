"""Jupyter / IPython integration.

    %load_ext provena.sdk.ipython
    %%provena "fit binding curve" --used raw/plate1.csv --out results/kd.json --plan protocol.md
    ...cell code...

The cell runs normally; afterwards its outputs are registered, the cell source is stored as an
encrypted output (so the exact code is part of the record), and an activity links everything.
A cell that raises is still recorded. The passphrase comes from $PROVENA_PASSPHRASE.
"""

from __future__ import annotations

import argparse
import shlex
from collections.abc import Callable
from pathlib import Path

from provena.sdk.project import Project
from provena.sdk.project import open as open_project

_project: Project | None = None


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="%%provena", add_help=False)
    p.add_argument("description")
    p.add_argument("--used", action="append", default=[])
    p.add_argument("--out", action="append", default=[])
    p.add_argument("--plan")
    p.add_argument("--model")
    return p


def record_cell(project: Project, line: str, source: str, execute: Callable[[str], object]):
    """Run *source* through *execute* inside a provenance run. Returns the Run."""
    args = _parser().parse_args(shlex.split(line))
    with project.run(args.description, plan=args.plan, used=args.used,
                     model=args.model, params={"source": "jupyter-cell"}) as run:
        try:
            execute(source)
        finally:
            folder = project.repo.root / "cells"
            folder.mkdir(exist_ok=True)
            cell = folder / f"cell-{len(list(folder.glob('cell-*.py'))) + 1:04d}.py"
            cell.write_text(source)
            run.output(cell, media_type="text/x-python")
            for out in args.out:
                if Path(out).exists():
                    run.output(out)
    return run


def load_ipython_extension(ipython) -> None:  # pragma: no cover - needs a live IPython
    from IPython.core.magic import register_cell_magic

    @register_cell_magic("provena")
    def provena_magic(line, cell):
        global _project
        if _project is None:
            _project = open_project(".")

        def execute(source: str):
            result = ipython.run_cell(source)
            if result.error_in_exec is not None:
                raise result.error_in_exec
            if result.error_before_exec is not None:
                raise result.error_before_exec

        run = record_cell(_project, line, cell, execute)
        print(f"provena: recorded activity {run.activity[:12]} "
              f"({len(run.outputs)} output(s) incl. cell source)")
