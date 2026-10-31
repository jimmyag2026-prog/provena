# Provena for AI agents: the MCP server

`provena mcp --project DIR` serves one project to an AI agent over MCP (stdio). The agent records
its steps, preregisters protocols, proves results and verifies other people's proofs; the
agent key is unlocked once by the server from a passphrase file and never enters the model's
context.

## Setup (once)

```bash
provena --agent lab-agent keygen --kind software --display "lab agent"
printf '%s\n' 'a long passphrase' > ~/.provena/lab-agent.pass && chmod 600 ~/.provena/lab-agent.pass
cd my-study && PROVENA_PASSPHRASE_FILE=~/.provena/lab-agent.pass provena --agent lab-agent init --name my-study
provena remote https://hub.example.org          # optional: receipts, sharing, mirrors
```

## Tools

| Tool | Use it to |
|---|---|
| `status` | see the project id, entries, what is not pushed |
| `preregister` | commit to a protocol **before** results exist (content stays sealed) |
| `add_file` | record a data file (re-adding unchanged content is a no-op) |
| `record_step` | record one step that happened — a model call, a search, a script — with `args`, `result`, `error`/`exit_code`, `model`, `used`, `outputs`, `plan`, `transcript`. Works without files; failed steps too. |
| `reveal` | publish a file, a plan, or a step's details |
| `prove` / `verify` | write a `.pvb` for entries / check one (validity, trust level, preregistration) |
| `push` / `pull`, `log` | sync with the hub; list entries |

Results are JSON (`structuredContent`) with complete entry hashes; a failed tool call returns
`isError: true` with a message the model can act on.

## Claude Code

```json
{ "mcpServers": { "provena": {
    "command": "provena",
    "args": ["--agent", "lab-agent", "mcp", "--project", "/path/to/my-study",
             "--passphrase-file", "/Users/me/.provena/lab-agent.pass"] } } }
```

Paths in tool arguments are relative to the project; `prove`/`verify` read and write `.pvb` files
inside the project only. Arguments are checked against each tool's schema (an unknown or mistyped
argument is an error, not silently ignored), and tool errors carry the CLI contract's codes
(`E_USAGE`, `E_NOT_FOUND`, `E_INPUT`, …) with a `hint`.

## Python, without the CLI

```python
from provena import sdk
proj = sdk.init("my-study", agent="lab-agent", hub="https://jimmyresearch.com/provena")
plan = proj.plan_text("Predict X; success if AUC > 0.8", "protocol.md")
proj.record("web_search", {"q": "…"}, {"hits": 3})          # one line per tool call
proj.record("python fit.py", outputs=["results/fit.json"], plan="plans/protocol.md")
proj.push(); step = proj.record(...)["activity"]
proj.prove([step], "fit.pvb")         # prove the *step* to show it followed its plan
verdict = sdk.verify("fit.pvb")       # rows with "target": true; "proven" needs a trusted hub
```

To show that a step followed its preregistered plan, prove the step (its activity entry): the
bundle then holds all of its outputs. Proving one output alone keeps the step's other outputs
undisclosed, so its preregistration row reads `outputs-not-in-bundle`; rows for upstream steps
reached through lineage are marked `"target": false`.

## Spark Research

Spark Research loads external MCP servers as `mcp_client` extensions, and records every call
of them in its own execution records. Register Provena once (the passphrase variable is passed
by name through Spark's env allowlist; its value never enters Spark's config):

```bash
spark-research ext add-mcp provena \
  --cmd "provena --agent lab-agent mcp --project /path/to/my-study" --trust
# then allow the variable through: add "PROVENA_PASSPHRASE_FILE" to "env" in
# ~/.spark-research/extensions/provena/mcp.json, and `spark-research ext verify provena`
```

Spark's agents then see the tools as `mcp:provena:record_step`, `mcp:provena:preregister`, …;
`docs/integrations/spark-research.md` describes the research flow that uses them.
