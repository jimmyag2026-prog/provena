# The Provena trial hub

`https://jimmyresearch.com/provena` — a public trial zone (since 2026-10-31) on a small shared
server; no guarantee of uptime or retention while it is a trial. Deployment: `deploy/do/`.

| What | Value |
|---|---|
| Log key (`provena trust add log …`) | `pv1au5paant4hgacofid4mzitstnqlsh7bv2` |
| Anchoring | RFC 3161 via freetsa.org, hourly; TSA certificate SHA-256 `32e841a95cc1164101ffde41298ef2fc75c1c4372ef095e88a6bbd47dfb191fc` |
| Who may create projects | agent ids on the operator's list (ask to be added); members of existing projects write freely |
| External witness | `pv1a3ejpunb26rszlgvdmhj62eusvbb2fe6c` (card: `deploy/witness/trial-witness.card.json`): `.github/workflows/trial-witness.yml` runs hourly on GitHub's machines (live since 2026-10-31), checks that every public project's log only grows, and cosigns its head |

Both values ship as **built-in trust** with this release, so `provena verify` reaches
`log-sequenced` / `anchored` for bundles from this hub without setup. They are listed by
`provena trust defaults` (and marked in `provena trust list`); `provena trust defaults off`, or
`PROVENA_NO_DEFAULT_TRUST=1`, makes the verifier rely only on what you added yourself. Check the
log key independently before relying on it: `curl -s https://jimmyresearch.com/provena/v1/hub`.

## The trial witness

A witness keeps the hub honest about history: it remembers the last head it saw of each project
and cosigns a new head only if a consistency proof shows the log grew append-only (a fork or a
rollback makes the run fail and stops it cosigning that project). The trial witness runs on
GitHub Actions with its own key, which exists only in the repository's secrets, and keeps its
state on the `witness-state` branch — not on the hub it watches. It is a separate machine and
key, but the same operator: count it as `witnessed` only if that is enough for you
(`provena trust add witness pv1a3ejpunb26rszlgvdmhj62eusvbb2fe6c`). A witness run by someone
else is stronger; `provena witness URL PROJECT…` on any machine is all it takes.
