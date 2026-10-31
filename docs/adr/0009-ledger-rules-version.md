# ADR 0009: Ledger rules are versioned per project

**Status:** accepted · 2026-10-31

## Context

The state machine (`core/state.py`, mirrored in `server/static/verifier.js`) is the definition of a
valid ledger. Every rule change so far was a silent protocol upgrade: tightening a rule makes old
logs fail to replay; loosening one makes old verifiers reject new entries. The next changes —
re-sharing history keys with a member, provable step status, publishing a content key after a
reveal — all need new entry shapes.

## Decision

1. The genesis policy carries `rules: 1 | 2`; absent means 1. A project's rules never change after
   genesis. New projects are created with the newest rules; existing projects keep theirs.
2. Both verifiers dispatch on the project's rules. **Rules 1 are frozen**: every log and bundle that
   verified before keeps verifying, with the same facts.
3. The tables both verifiers share (roles, attestation types, verdicts, body fields per kind and
   rules version, metadata limits) live in `docs/spec/rules.json`; a test fails if either verifier
   differs from it.
4. Rules 2 add, and only add:
   - **`member.rewrap`** `{action, agent, epoch_wraps}` by an owner/maintainer: hands an active
     member the keys of earlier epochs the author can read and the member cannot. `member add
     --history` and the recovery flow use it, so a member added after a rotation can read history.
   - **Provable steps**: an activity carries a public `status` (`ok` | `failed`) and a salted
     `commitment` to its sealed details (command, exit code, model, harness, params, …).
     A `reveal` of an activity opens that commitment and may publish the `details` themselves;
     verifiers check `sha256(canonical(details))` against the opened commitment.
   - **Publishing a key later**: a data file or plan revealed without its content key may be
     revealed once more, with the same opening, to add the key.
5. A verifier that meets an unknown rules version refuses the bundle; it never guesses.

## Consequences

- One more field in genesis; old genesis entries are untouched (absent = 1).
- Rule growth is now additive and testable: randomized histories run under both versions in both
  verifiers.
- A project that wants rules 2 features must be created anew (or, later, migrate through an explicit
  entry — not part of this ADR).
