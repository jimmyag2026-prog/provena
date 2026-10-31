# ADR 0011: Interoperate through existing envelopes

**Status:** accepted · 2026-10-31

## Context

Evidence that only Provena can read stays inside Provena. Supply-chain tooling (in-toto, SLSA,
Sigstore) already verifies DSSE envelopes; research agents already speak MCP.

## Decision

- The internal entry format and proof bundles do not change.
- Outward, a recorded step is exported as an **in-toto Statement v1** in a **DSSE** envelope
  signed with the author's Ed25519 key (standard PAE signing; `keyid` = agent id), predicate
  `docs/spec/predicate-run-v1.md`. The statement points back to the ledger entry; the bundle is
  the full proof.
- Agents reach Provena through an **MCP server** (`provena mcp`), implemented without extra
  dependencies; tools mirror the CLI contract (`docs/spec/cli-contract-v1.md`).
- Tree heads are also served as **C2SP checkpoints** (`GET /v1/projects/{pid}/checkpoint`, verifier key at `/v1/hub/vkey`), so existing transparency-log witnesses can cosign them; the note signature is Ed25519 over the note text, which starts with a printable origin and cannot equal a ledger message. Later, as needed: SCITT receipts.

## Consequences

The ledger key also produces DSSE signatures; the two message formats cannot collide (ledger
messages start with a length byte and a `provena/…` tag, PAE with `DSSEv1 `), and the key exposes
only "sign a PAE", not "sign these bytes".
