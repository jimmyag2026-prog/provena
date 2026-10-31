# Phase 3 design: attested capture (instruments and AI agents)

**Status: draft for decision** · 2026-10-31 · P3-1 (capture daemon) and a first cut of P3-4 (agent model/harness/trace in `run()`) implemented; P3-2, P3-3 not started

## 1. The gap this closes

Provena v0.x proves that a *record* is intact, authored, ordered and dated. It does not prove
the record came from a real measurement: between the detector and the first signature there is
a **capture gap** where a person or script can substitute data. Phase 3 narrows that gap in
steps; none closes it completely (you cannot attest that the right sample went into the
instrument), and the verifier must say exactly which step was reached.

## 2. Capture assurance ladder

| Level | What signs first | What the verifier can state | Cost to adopt |
|---|---|---|---|
| C0 *operator* (today) | the researcher's key, whenever they run `provena add` | "registered by A at ≤ T" | none |
| C1 *capture daemon* | an `instrument` agent key on the instrument PC, seconds after the file appears | "registered by instrument I within Δ of file creation (instrument clock)" | install `provena-capture`, one key per instrument |
| C2 *hardware-held key* | the same, but the key lives in a TPM 2.0 / secure element and cannot be exported | "signed by a non-exportable key certified by vendor root R" | TPM-equipped PC or USB HSM per instrument |
| C3 *measured capture* | C2 + a TPM quote binding the key to the hash of the capture software and OS | "signed by capture software S (sha256) on a measured-boot host" | TPM + measured boot; vendor root trust |
| C4 *facility co-signature* | C1–C3 + a core facility's `org` agent attests each run it operated | "facility F attests it performed this run" | an independent facility in the loop |

C4 is orthogonal to C1–C3 and the cheapest *independent* signal; recommended first pilot is
**C1 + C4** (no special hardware, an independent party).

## 3. Model changes (additive, `v` stays 1)

- **Agent card** gains optional `attestation`:
  `{"type": "none" | "tpm2" | "yubihsm" | "sev-snp", "evidence": b64url, "measured": {"capture_sha256": hex}}`.
  The card signature already covers it; verification of `evidence` is pluggable like anchors.
- **Entity body** gains optional public `capture`: `{"by": <instrument agent id>, "file_mtime": ms, "observed": ms}`
  (instrument-clock, self-reported; bounded above by the hub's integrated time).
- **Attest types** gain `capture` (facility operated this run) and `operator` (named person ran it).
- **AI agents** (`software` cards): `activity.sealed` carries `model` (provider + model id, or weights sha256),
  `trace_commitment` (salted commitment to the full prompt/tool transcript), `harness_sha256`.
  The key lives in the *harness*, never in model context — a model can request a signature, it
  cannot exfiltrate the key. Trace reveal works like plan reveal.

## 4. Verifier semantics (follows ADR 0007)

- Capture claims are facts only when the instrument card's attestation verifies against a
  **root the verifier trusts** (`provena trust add tpm-root <fp>`); otherwise notes.
- New report field `capture` per target: `C0…C4` reached, with the reason the next level was not.
- `Δ = observed − file_mtime` and `integrated_time − observed` are reported, never interpreted.

## 5. Milestones

| # | Deliverable | Acceptance |
|---|---|---|
| P3-1 | `provena-capture` daemon: watch folder → `add` with instrument key, offline queue, `capture` body | 1,000 files/h; restart-safe; never re-registers a file |
| P3-2 | Facility attestation flow (`attest --type capture`), facility dashboard on the hub | a facility can co-sign runs from a queue in < 3 clicks |
| P3-3 | TPM 2.0 key + `tpm2` attestation verifier (EK cert chain → AK → key) | verifies against Infineon/STM/Nuvoton roots; fails closed |
| P3-4 | AI-agent provenance: SDK `run()` records model + trace commitment; reveal of traces | an agent's analysis is reproducible from revealed trace + inputs |

## 6. Decisions needed

1. Pilot target: one instrument class + one facility (suggest plate reader or LC-MS in a core facility).
2. Whether C2/C3 hardware is in scope for v1, or C1 + C4 only.
3. Whether AI-agent traces default to sealed (recommended) or public.
