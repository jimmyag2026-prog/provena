# Spark Research × Provena

Spark Research (the research agent platform) keeps its own evidence graph of a project; Provena
adds what that graph cannot give an outsider: entries signed by the agent's key, committed before
the results exist, ordered by a hub's receipts, and checkable by anyone from a `.pvb` file without
trusting Spark, the agent or the lab.

## How they connect

Spark loads Provena as an external MCP server (`mcp_client` extension). Every call goes through
Spark's ToolBus — authorized, budgeted, and recorded in Spark's own execution records — and lands
on the Provena ledger as a signed entry:

```
Spark agent ──(mcp:provena:preregister / record_step / prove / verify)──▶ provena mcp
     │                                                                     │
     └── Spark evidence graph: external_tool_call observation             └── signed ledger entry
```

## Setup (once)

```bash
# an identity for the Spark agent, and its ledger
provena --agent spark-research keygen --kind software --display "Spark Research agent"
#   passphrase in a file only you can read, e.g. ~/.provena/spark-research.pass (chmod 600)
mkdir -p ~/ledgers/my-study && cd ~/ledgers/my-study && provena --agent spark-research init --name my-study
provena remote https://hub.example.org            # optional: hub receipts → log-sequenced proofs

# register with Spark (TOFU: re-run `ext load … --trust` whenever mcp.json changes)
spark-research ext add-mcp provena --trust --cmd \
  "provena --agent spark-research mcp --project $HOME/ledgers/my-study --passphrase-file $HOME/.provena/spark-research.pass"
spark-research ext verify ~/.spark-research/extensions/provena   # 4 checks, incl. a real round trip
```

`--passphrase-file` keeps the passphrase out of Spark's configuration and environment: the
command line carries only the file's path.

## Use

Ask Spark for a study in the usual way and say that it keeps a Provena ledger; the planner now
sees the `mcp:provena:*` tools. A typical order: `preregister` the protocol first, run the work,
`record_step` each step (searches, model calls, scripts — failures too), then `prove` the result and
hand the `.pvb` to whoever must check it (`provena verify`, or drag it onto any hub page).

## Field run (2026-10-31)

The first real run (Spark main + PR #130, DeepSeek) did call
`mcp:provena:preregister` and the plan landed on the ledger as entry #1 with a real hash. The run
also showed three gaps on the Spark side, all fixed in spark-research PR #130:

1. the research-loop path never told sub-agents' models the external tools exist;
2. the chat planner's inventory did not list connected external tools, so it ruled them out;
3. `mcp:<ext>:<tool>` names are rejected by OpenAI-compatible providers (HTTP 400): they are now
   encoded on the wire only.

In that run the planner did not go on to `record_step` the literature search and said so
honestly; whether a step got recorded was still the agent's choice.

## Automatic recording (spark-research #131)

Spark no longer leaves it to the model. While the `provena` extension is connected, Spark's
`ProvenaMirror` records, without the model asking:

- every task the orchestrator executes, as one step whose tool is `spark:<kind>:<skill|tool>`,
  with `status` ok/failed and the output (truncated to 4000 characters) sealed in the step details;
- every audited tool call of a sub-agent, failures included (calls refused by policy are not steps,
  and calls to `mcp:provena:*` itself are skipped so a record is never recorded twice);
- one `push` at the end of each round, so the hub's receipts give the steps a trusted time.

A failed `record_step` never fails the research: it is counted and reported at the end of the
round. Verified live on 2026-10-31: a literature search became activity #3 with its trace entry,
and the pushed ledger verified `anchored` on the trial hub.
