# Proof bundle format `provena-bundle/1`

**Status: implemented (M5, extended M8/M13)** · code: `src/provena/core/bundle.py`; verifiers `src/provena/core/verify.py` (reference) and `src/provena/server/static/verifier.js` (browser; same rules, including the full-mode state replay)

A bundle is a single JSON document (extension `.pvb`). It carries everything needed to check a
set of claims offline; the verifier recomputes every hash, signature and proof and trusts nothing
the bundle says about itself. JSON floats (and `NaN` / `Infinity`) anywhere in the file make it
invalid (signed structures never contain them; both verifiers scan the raw text); a UTF-8 BOM is
ignored. Extra top-level fields such as `challenge` or `submission` (written by
`provena challenge`) are unsigned hints that verifiers ignore and tools re-derive from proven
entries.

```jsonc
{
  "format": "provena-bundle/1",
  "mode": "selective" | "full",
  "project": "<hex entry hash of genesis>",
  "head": { "v":1, "project", "size", "root", "time", "signer", "sig" },   // signed tree head
  "head_signer": { agent card of the head signer },
  "targets": ["<entry hash>", ...],                 // what the bundle is about
  "entries": [ { "index": 3, "entry": {…}, "proof": ["<hex>", …],      // proof omitted in full mode
                 "receipt"?: { SET signed by the head's log: v, project, index, entry_hash,
                               integrated_time, signer, sig } }, … ],
  "openings": { "<entry hash>": { "salt", "plain_sha256", "content"?: "<b64url plaintext>" } },
  "cosignatures": [ { "cosig": {v, head: head_id, witness, time, sig}, "card": witness card,
                      "head": the cosigned head (≤ bundle head), "log_card": its log's card,
                      "consistency": [hex] from that head to the bundle head } ],
  "log_rotations"?: [ { v, old: hub card, new: hub card, time, sig_old, sig_new }, … ],
                    // the hub's log key hand-overs, oldest first (ADR 0010); absent if none
  "external": [ <provena-bundle/1 of another project>, … ],   // proves activity.external inputs
  "credentials": [ { "credential": {v, issuer, subject, claims, issued, expires, sig},
                     "issuer_card": org agent card } ],     // who holds an author key, per an org
  "anchors": [ {
      "anchor": { "v":1, "provider": "self"|"rfc3161", "digest": root-of-roots, "size", "time",
                  "receipt": {self: {digest,time,signer,sig}} | {rfc3161: {token: b64url DER, tsa}} },
      "head": <the project head that was anchored (may be older than "head")>,
      "index", "proof": inclusion of that head in the root of roots,
      "consistency": [hex] from the anchored head to the bundle head,
      "log_card": card of the log that signed the anchored head } ]
}
```

## Verification algorithm

1. `format` must match; `head_signer` card self-signature valid; `head` signature valid; head is for `project`.
2. Optional trust policy: head signer ∈ `--trust-log` set.
3. Genesis (index 0) present and `entry_hash(genesis) == project`.
4. **full**: entries are exactly indices `0..size-1`; replay through `ProjectState` (proves membership, roles, author chains, per-kind rules at the time of each entry); Merkle root of leaves == `head.root`.
   **selective**: each entry passes shape check and RFC 9162 inclusion proof against `head.root`; each author's key comes from a proven key-introducing entry (genesis / member add / key succeed) at an index ≤ the entry's index; signatures verify; a `prev` must point to an earlier entry. Bundles built by `provena prove` also include attest / reveal / redact / grant entries on the wanted entries and the activity that generated each target.
   **receipts** (any mode): each SET must be signed by the head's log and name this entry's project, index and hash, with `integrated_time ≤ head.time`; it becomes a fact (and a trusted time bound) only when that log is trusted.
5. Targets must be among proven entries.
6. Facts: activity lineage among proven entries; "preregistration holds" only if the plan precedes the activity and *every* generated output is proven and registered after the plan (otherwise a note says which condition failed); order-based statements are facts only under a trusted log, notes otherwise; attestations and redactions on proven entries.
   **external**: at most 20 attached bundles (`MAX_EXTERNAL`), never nested; each is verified with the same trust sets and an invalid one invalidates the whole bundle; each `activity.external` citation (≤ 100 `{project, entry}` hex pairs) must be a target of an attached bundle for that project, and is stated as a fact only if that bundle reaches at least `log-sequenced`.
7. Openings (bundle-supplied or on-ledger `reveal` entries): salted commitment opens; supplied plaintext (embedded or external file) hashes to `plain_sha256`. Under ledger rules 2 (`policy.rules`, ADR 0009, table in `docs/spec/rules.json`) an activity carries `status` (`ok`|`failed`) and a `commitment` to its sealed details; a reveal of it may carry `details`, which must satisfy `sha256(JCS(details)) = plain_sha256` (checked in selective bundles too). A verifier refuses a rules version it does not know.
8. Cosignatures: the cosigned head is signed by `log_card` and consistent with the bundle head; witness card valid; cosignature is over `head_id(cosigned head)`; optional `--trust-witness` set must be hit. `witnessed` requires cosigned heads covering every target from at least `max(1, policy.witnesses)` distinct trusted witnesses (the genesis policy).
9. Anchors: anchored head signed by `log_card` (and trusted, if `--trust-log`); anchored head included in the anchored root of roots; stamp valid for that root (`self`: hub signature; `rfc3161`: CMS signature, messageDigest, imprint, EKU timeStamping, validity at genTime); anchored head consistent with the bundle head. Every target with index < anchored size gets "existed no later than <stamp time>".

10. Credentials: issuer card is an `org` agent; signature (`provena/credential/v1`) over the credential; claims well-formed; valid at the bundle head's time. Reported as facts only for issuers in the verifier's trusted orgs *and* when that head time is trusted (log-sequenced or better); otherwise, or if a credential fails, a note; never affect the trust level.

## Trust levels reported (ADR 0007)

Validity (`VALID`) means every signature and proof checks out. The trust level depends only on
the verifier's own trust sets — log ids, witness ids, TSA certificate SHA-256 fingerprints —
never on the bundle. Evidence from untrusted signers is verified and then reported as a note.
The one way a bundle widens trust is `log_rotations` (ADR 0010): a log key that a trusted key
handed over to (both keys signed the statement) is trusted too — forward only, never back.

| level | requires | time statement means |
|---|---|---|
| `unverified` | head signer neither trusted nor a project member | a claim by an unknown key |
| `self-sequenced` | head signed by a project member | the author's own claim |
| `log-sequenced` | head signer ∈ trusted logs | the trusted log's claim |
| `witnessed` | + a trusted witness cosigned a trusted-log head covering every target | the log could not fork without the witness noticing |
| `anchored` | + an RFC 3161 token from a trusted TSA over a trusted-log head covering every target | bounded by the TSA's time (`self` anchors never count) |

An anchor whose time precedes the anchored head's time (beyond 5 min skew) makes the bundle invalid.

## Known limits of selective mode

Selective bundles do not prove that an author was still a member (not removed, key not
succeeded) when an entry was written — that needs the whole log. The verifier prints this caveat;
use `--full` when authorization matters.
