# Pilot report: internal race on the trial hub (2026-10-31)

PILOT.md §7.1, option "先办一场内部赛" (chosen by the user). `examples/pilot_internal.sh`, run
against `https://jimmyresearch.com/provena`, agents only (`--json` envelopes and exit codes).

## Setup

- **Data**: Fisher's iris table, seaborn-data copy, SHA-256 `9cc1c345…8e355` (pinned in the run).
  Every 5th flower's species (30) is the sealed truth; the other 120 rows, labelled, are part of
  the published targets file together with the 30 unlabelled rows.
- **Roles**: organizer, evaluator, three registered teams (`AGENT:PROJECT`), an outside auditor
  with no key of anyone involved. Deadline 5 minutes after `challenge init`.
- **Teams**: team1 nearest centroid on the four measurements; team2 a petal-length rule; team3
  registered and never submitted.

## Result (second run)

| | |
|---|---|
| Submissions | team1 and team2 `ON TIME` (trusted hub receipts) |
| Board | team2 1.0, team1 0.9667 (accuracy on the 30 held-out flowers) |
| Outside audit | `AUDIT OK` with each team's own bundle (`--submission`); "registered but absent: team3" |
| Hub page | `/p/17b23d4e…` — the hub's own check: **ok**, team3 listed as absent |

The four claims of PILOT.md §1 held: the truth was fixed before the deadline and revealed after
it; on-time status came only from hub receipts; the board was re-derived by an outsider; an
absent registered team is visible.

## What broke (and was fixed)

The **first run was void**. The organizer had published its training file before
`challenge init`; under the challenge rules anything disclosed before the deadline other than the
protocol, targets and scorer voids the challenge (a copy of the truth could be in it), and
`challenge status` said so at the deadline — correctly, but too late and with a misleading
message ("the truth was disclosed"). Fixed in the same PR:

- `challenge init` refuses a project that already disclosed content (`E_VOID`, hint: use a new
  project, put public inputs such as training data into `--targets`);
- `reveal` / `publish` / `share` of anything else while the project's challenge is open need
  `--force` (`E_CONFIRM`);
- `challenge status` names what was disclosed early.

## Still open

- A pilot with an **external** organizer (RNA structure challenge or Poreva Open) when the user
  picks one: `docs/pilots/organizer-kit.md`.
- The trial witness runs once its repository secrets are set (`docs/integrations/trial-hub.md`).
