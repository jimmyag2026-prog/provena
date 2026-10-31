# ADR 0012: Hub orgs, quotas and API keys

**Status:** accepted · 2026-10-31 · extends PR #3 (`--creators`, `--projects-per-creator`)

## Context

A hosted hub (the trial zone, later a paid one) must decide who may create projects and how
much they may store. Writes are self-authenticated by agent keys (ADR 0005) and keys cost
nothing to make, so per-agent limits alone are weak and accounts would duplicate identity.

## Decision

1. **A policy file** (`hub serve --policy FILE`, JSON, re-read when it changes) lists **orgs**:
   the agent ids that belong to them, `max_projects`, `max_bytes`, and API keys stored only as
   SHA-256 hashes. An optional `default` gives limits to agents in no org (each counted on its
   own as `agent:<id>`); without it only org agents create projects. A file that does not parse
   admits nobody (fail closed), as `--creators` does. `--policy` and `--creators` are exclusive.
2. **Accounting** is fixed at creation: the project is charged to its creator's org, recorded
   in the same transaction as the genesis entry. The creation request must be **signed by a
   genesis member who belongs to that same account**, so nobody (a mirror pushed by an
   outsider, say) can put a project on another org's quota. Moving an agent between orgs later
   does not move its projects. Stored ciphertext is counted as one row per stored file (so
   retried or concurrent uploads count once, and a shred — even one racing an upload or
   retried — frees it exactly once); projects created before the policy are not charged.
3. **Enforcement** happens where the hub already validates: project creation (`max_projects`)
   and upload (`max_bytes`, HTTP 403 → `E_FORBIDDEN`). Concurrent uploads may overshoot a quota
   by the uploads in flight. Members' entries to existing projects are never blocked by quotas;
   new uploads of an account the policy no longer covers (org removed, or a broken file) are.
4. **API keys** are for org admins, not for writes: `GET /v1/orgs/{org}/usage` with
   `Authorization: Bearer KEY` returns the org's projects, bytes and limits.
   `provena hub api-key ORG` prints a new key once and the hash line for the policy.
5. **Schema versions**: the hub database records `schema_version` in a `meta` table; numbered
   migrations run at start, each in one explicit transaction with its version bump (SQLite
   included); a database newer
   than the code refuses to start (never downgrade a hub).

## Consequences

- No accounts, no passwords on the hub: the operator edits one file; agents keep their keys.
- Quotas are an operator's tool, not a security boundary between orgs: every project's
  integrity guarantees are unchanged.
