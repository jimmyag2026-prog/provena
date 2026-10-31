"""High-level Python API for instruments, notebooks and AI agents.

    from provena import sdk

    proj = sdk.open("experiments/assay-42")            # agent key from $PROVENA_HOME
    plan = proj.plan("protocol.md")
    raw = proj.add("raw/plate1.csv")
    with proj.run("fit binding curve", plan=plan, used=[raw]) as run:
        fit_and_save("results/kd.json")
        run.output("results/kd.json")
    proj.prove([run.activity], "kd.pvb", open=[run.outputs[0]])

Every call signs and appends to the local ledger immediately; `push()` sends it to the hub.
A run that raises is still recorded (with the exception type) before the error propagates.
"""

from provena.sdk.project import Project, Run, init, open
from provena.sdk.verifying import verify

__all__ = ["Project", "Run", "init", "open", "verify"]
