# ADR 0010: A hub's log key can be handed over

**Status:** accepted · 2026-10-31 · supersedes the DEPLOY.md rule "one log key per hub, forever"

## Context

Clients, witnesses and verifiers pin a hub by its log key. Until now a changed key looked exactly
like a hostile takeover, so a key could never be retired — not for hygiene, not for a new
algorithm (ADR 0008), not after decades of archiving. A key change must stay distinguishable
from a takeover.

## Decision

1. **Hand-over statement** `{v: 1, old: <old hub card>, new: <new hub card>, time, sig_old,
   sig_new}`: both keys sign `JCS({v, old, new, time})` under the tag `provena/log-rotation/v1`.
   The old key authorizes the hand-over; the new key proves it is held. A key handed to two
   successors is a fork and is refused.
2. **The hub** (`provena hub rotate-key --data DIR --yes`, hub stopped) appends the statement to
   `hub.rotations.json`, serves the chain (oldest first) in `GET /v1/hub` as `rotations`, and on
   start re-signs each project's latest head with the new key. Older heads, receipts and anchors
   stay as signed; re-signed heads are kept so witness cosignatures on them stay checkable (each
   such cosignature is served with the head it signed).
3. **Clients and witnesses** that pinned a key follow a chain from it to the key the hub now
   serves, keep the earlier cards to check old heads, and report `W_HUB_KEY_ROTATED`. A key change
   without such a chain is still `E_HUB_KEY` (exit 6), and a witness still refuses to cosign.
   The append-only check carries across the hand-over.
4. **Trust moves forward only.** A bundle may carry `log_rotations`; both verifiers treat the
   successor of a trusted log key as trusted (and say so in a note), never the predecessor of
   one. A client that follows a hand-over from a key the user trusts adds the successor to the
   user's trusted logs. ADR 0007 is unchanged: trust still starts from the verifier's own set.

## Consequences

- Planned rotation is routine. The old key file is kept as `hub.key.retired-<id>.json` until
  clients and witnesses have synced, then shredded.
- **A leaked key is not a rotation.** Whoever holds the old key can sign a hand-over to a key of
  their own; forward trust would follow it. After a compromise the operator announces it out of
  band and verifiers drop the old key (`provena trust remove log ID`): with the old key untrusted,
  nothing it signs — heads or hand-overs — carries trust.
- A rotation cut short is finished (statement written) or dropped (not yet written) on the next
  start; a hub whose key file is missing after a rotation refuses to mint a new one.
- Known limit: a bundle on a head signed by the new key carries only receipts signed by that key,
  so pre-rotation entries are timed by the head (or by anchors on older heads), not by their own
  receipts. Carrying receipts across keys needs a verifier change and is left for later.
- Bundles from hubs that never rotated are byte-for-byte unchanged (`log_rotations` is absent);
  older verifiers ignore the field and simply do not extend trust.
