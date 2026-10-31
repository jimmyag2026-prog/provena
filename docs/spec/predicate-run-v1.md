# in-toto predicate: a recorded research step (v1)

`predicateType`: `https://github.com/jimmyag2026-prog/provena/blob/main/docs/spec/predicate-run-v1.md`
(provisional URI until the project has its own domain). Produced by
`provena export intoto --step REF -o step.dsse.json`, wrapped in a DSSE envelope
(`payloadType: application/vnd.in-toto+json`) signed with the step author's Ed25519 key
(`keyid` = the Provena agent id; the public key is in the agent's card).

- `subject`: the step's outputs — `name` (the recorded path), `digest.sha256` (plaintext hash,
  the same value the ledger commits to), `annotations.provena_entry` (entry hash).
- `predicate.ledger`: `project`, `entry` (the activity hash), `index`, `rules`, and the latest
  tree head the exporter holds. The authoritative proof is a Provena bundle of that entry:
  `provena prove <entry> --open <outputs>`.
- `predicate.author`, `status` (`ok`|`failed`, rules 2), `plan` (preregistered plan entry or
  null), `used` (inputs as name/digest/entry), `external` (inputs in other projects).
- `predicate.details`: the step's command, exit code, model, parameters — **only** when they are
  already public on the ledger (`provena reveal <step>`), otherwise null.

Exporting discloses output names and content hashes; do it when you publish the step.
