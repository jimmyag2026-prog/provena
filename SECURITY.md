# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | yes |
| < 0.2 | no (0.1.0 was never tagged) |

## Reporting a vulnerability

Email **jimmyag2026@gmail.com** with a description, the affected version (`provena --version`)
and, if you have one, a minimal reproduction (a bundle, a ledger directory or a request
sequence). Do not open a public issue for anything that could let someone forge, backdate or
hide a record before a fix ships.

We ask for a **90-day coordinated disclosure window** from the first report. You will get an
acknowledgement within a few days, a fix or a mitigation plan as soon as we have one, and credit
in the changelog unless you prefer otherwise. Confirmed findings are fixed with a regression test
and listed under *Security* in `CHANGELOG.md`, as the earlier review rounds were.

## Scope

- The ledger format and its rules (`docs/spec/`, `docs/adr/`): anything that lets an entry be
  altered, reordered, backdated, removed or attributed to the wrong key without detection.
- The verifiers, Python (`provena verify`, `provena.core`) and JavaScript
  (`src/provena/server/static/verifier.js`, the hub's in-browser check), including any case where
  the two disagree.
- The hub API and pages (`src/provena/server/`): authentication of writes, receipts and tree
  heads, access to private ciphertext, rate limits, the catalog and proof endpoints.
- Client-side encryption and key handling (`provena.core.aead`, sealing, key files, passphrase
  handling, the MCP server's key custody).

Out of scope: what `docs/THREAT_MODEL.md` lists as accepted limits of v0.x (for example, that a
measurement reflects reality, or an honest-but-compromised author's own machine), and
denial-of-service against a hub beyond its documented limits.
