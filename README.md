# Provena

> GitHub for code. Hugging Face for models. **Provena for verifiable science.**
>
> A ledger of experimental data and process, kept encrypted and backed by proof.

**The evidence layer for AI-driven research.** Challenges, autonomous research agents and data
publishers attach to each result evidence that anyone can check in a browser, without trusting
whoever issued it. Agents are first-class users: an MCP server (`provena mcp`), a machine
contract for the CLI (`provena --json …`, [`docs/spec/cli-contract-v1.md`](docs/spec/cli-contract-v1.md))
and a Python SDK.

Provena is part of [Spark Science](https://sparkscience.xyz/provena/), an AI-for-science community
of researchers and developers. A public trial hub runs at
[jimmyresearch.com/provena](https://jimmyresearch.com/provena/)
([details](docs/integrations/trial-hub.md)).

Provena records every dataset, protocol and processing step of an experiment as a signed entry
in an append-only Merkle log. Content is encrypted on your machine; the hub only ever sees
ciphertext, hashes and signatures. Anyone holding a *proof bundle* (`.pvb`) can check — offline,
in a terminal or by dropping it on any hub's front page — who recorded which unaltered data, in
what order, no later than when, and how a result was produced.

**What it proves:** integrity, authorship (people, instruments, AI agents), time bounds (trusted
hub, independent witnesses, RFC 3161 time-stamps), order (a preregistered plan precedes every
result it governs), lineage, and completeness (failed runs and withdrawn data stay visible).
**What it does not prove:** that a measurement reflects reality — see
[`docs/design/attested-capture.md`](docs/design/attested-capture.md) for how instrument keys and
facility co-signatures raise that bar.

## Install

```bash
pip install "provena[client]"               # CLI + SDK
pip install "provena[client,server]"        # + run a hub (add s3 / postgres extras as needed)
```

## Quickstart

```bash
provena keygen --display "Ada Lovelace"
provena init --name binding-assay
provena plan protocol.md                          # preregister: only a commitment is public
provena add raw/plate1.csv                        # encrypt, commit, sign
provena run --plan protocol.md --used raw/plate1.csv --out results/ -- python fit.py
provena log && provena lineage results/kd.json    # the ledger and how a result was made
provena ui                                        # browse it locally in your browser
provena remote https://hub.example.org && provena push
provena prove results/kd.json -o kd.pvb           # proof bundle
provena verify kd.pvb --require log-sequenced     # facts + trust level
provena doctor                                    # is everything set up and backed by evidence?
```

Failed runs are recorded too; `provena rerun <step> --yes --attest` re-executes a recorded step
and records whether it replicates.

### From Python, notebooks, instruments and AI agents

```python
from provena import sdk

proj = sdk.open("experiments/assay-42")          # passphrase from $PROVENA_PASSPHRASE_FILE
raw = proj.add("raw/plate1.csv")
with proj.run("fit binding curve", plan="protocol.md", used=[raw],
              model="anthropic/claude-opus-5-5", harness="agent.py") as run:
    run.trace(transcript)                         # sealed, revealable later
    run.output("results/kd.json")
proj.prove([run.activity], "kd.pvb", open=run.outputs)
```

- One call per tool call, files optional: `proj.record("web_search", {"q": q}, result,
  model="provider/model")`; `sdk.verify("kd.pvb")` returns the structured verdict
- **MCP** (Claude Code, Spark Research, any MCP host): `provena mcp --project DIR
  --passphrase-file F` — `record_step`, `preregister`, `prove`, `verify`, … The key stays in the
  server. Setup: [`docs/integrations/mcp.md`](docs/integrations/mcp.md),
  [Spark Research](docs/integrations/spark-research.md)
- Jupyter: `%load_ext provena.sdk.ipython`, then `%%provena "step" --used … --out …`
- Instruments: `provena capture out/ --push-every 10` signs files with the instrument's own key
  as soon as they are complete

### Sharing, publishing, citing

| Goal | Command |
|---|---|
| one reviewer reads one file | `provena share F --to reviewer.card.json` → they run `provena open x.pvb --hub URL` |
| prove a protocol came first | `provena reveal protocol.md` |
| publish data | `provena publish F` |
| withdraw consent | `provena redact F --reason consent-withdrawn` (the record that it existed stays) |
| cite a result | `provena cite F --format bibtex` |
| hand over a package | `provena export rocrate -o crate/` (RO-Crate + proof bundle) |
| commit to a dataset now, publish later | `provena seal data/ --reveal-after 2027-01-01T00:00Z` → `provena unseal data.seal.json` |
| a step for supply-chain tools | `provena export intoto --step REF -o step.dsse.json` (in-toto + DSSE) |
| a badge for a README / board | `provena verify kd.pvb --badge provena.svg` |
| run a blind challenge | `provena challenge init / join / submit / status / close / score / audit` |
| use another lab's data | `provena run --external PROJECT:ENTRY …`, then `prove --external their.pvb` |
| say who holds a key | an institution's `org` agent: `provena identity issue …` |

### Trust is your decision

`VALID` means every signature and proof checks out. The trust level — `unverified`,
`self-sequenced`, `log-sequenced`, `witnessed`, `anchored` — depends only on the logs,
witnesses, TSA certificates and organisations *you* trust (`provena trust list`), never on what
a bundle says about itself (ADR 0007). This release ships one built-in default — the public
[trial hub](docs/integrations/trial-hub.md) `https://jimmyresearch.com/provena` and its TSA —
listed by `provena trust defaults` and switched off with `provena trust defaults off`.

## Run a hub

```bash
provena hub serve --data /var/lib/provena --tsa https://freetsa.org/tsr
```

SQLite or PostgreSQL (`PROVENA_HUB_DATABASE_URL`), filesystem or S3-compatible blob storage
(`--s3-bucket`), RFC 3161 anchoring, witness cosignatures, rate limits, a public explorer with a
drag-and-drop verifier, and citation pages. See [`docs/DEPLOY.md`](docs/DEPLOY.md).

## Documentation

- [User guide](docs/GUIDE.md) · [中文指南](docs/GUIDE.zh.md) · [Pilot runbook (zh)](docs/PILOT.md) · demos: `examples/demo.sh`, `examples/challenge_demo.sh` (primitives), `examples/challenge_cli_demo.sh` (challenge commands)
- [Architecture](docs/ARCHITECTURE.md) · [threat model](docs/THREAT_MODEL.md) ·
  [decisions](docs/adr/) · [hub API](docs/API.md) · [bundle format](docs/spec/bundle-v1.md)
- Designs: [attested capture](docs/design/attested-capture.md) ·
  [challenge mode](docs/design/challenge-mode.md) · [benchmarks](docs/devlog/benchmarks.md)
- [Changelog](CHANGELOG.md)

## Development

```bash
uv sync
uv run pytest -q          # includes Python/JS verifier parity tests (needs Node ≥ 22)
uv run ruff check .
```

Status: v0.2.0 (2026-10-31). Ledger rules 2 for new projects ([ADR 0009](docs/adr/0009-ledger-rules-version.md)).
Independent security reviews and agent-driven field tests ([findings](docs/design/agent-ux-review.md),
[plan](docs/design/next-dev-plan.md)); every confirmed finding is fixed and has a regression test
(see the changelog).

## License

[Provena License](LICENSE), modelled on the Kimi K3 license: free to use, modify and redistribute
under MIT-style terms, with two conditions for large commercial use — running a hub as a service
for third parties with more than USD 1M revenue over 12 months needs a separate agreement, and
products above 1M monthly users or USD 1M monthly revenue must credit Provena. Research and
teaching institutions, internal use, and the client, SDK, MCP server and verifiers are exempt;
the verifiers can always be run and redistributed to check proofs. This is a source-available
license, not an OSI-approved open-source license.
