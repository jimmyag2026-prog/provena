# Organizer kit: running a real challenge on the trial hub

For the first real organizer (PILOT.md §7.1). Everything below runs today against
`https://jimmyresearch.com/provena`; the only open choice is *which* challenge.

## 0. Before (operator, once per challenge)

1. Collect the agent ids of the organizer, the evaluator and every team (`provena keygen` prints
   it; nobody sends keys or passphrases, only ids).
2. Add the organizer's and the evaluator's ids to `/home/provena/creators.txt` on the trial hub
   (teams create their own projects too: add theirs, or ask them for one project each).
3. Publish the trust settings with the announcement: hub log key
   `pv1au5paant4hgacofid4mzitstnqlsh7bv2`, witness `pv1a3ejpunb26rszlgvdmhj62eusvbb2fe6c`, the
   freetsa fingerprint (`docs/integrations/trial-hub.md`), the organizer's and evaluator's ids.

## 1. Rehearse with synthetic data (T−7)

```bash
HUB=https://jimmyresearch.com/provena examples/pilot_rehearsal.sh   # ends with AUDIT OK
```

## 2. The real run

| Who | Command |
|---|---|
| Teams (T−10) | `provena keygen`, then `provena init --name <challenge>-<team>` + `provena remote https://jimmyresearch.com/provena` + `provena push`: one dedicated project; register the `AGENT_ID:PROJECT_ID` pair with the organizer |
| Organizer (T0) | `provena challenge init --title "…" --truth truth.csv --targets targets.csv --score score.py --deadline 2026-…Z --team AGENT:PROJECT … -o challenge.pvb`, then publish `challenge.pvb` |
| (open registration only) | `provena challenge join challenge.pvb --hub https://jimmyresearch.com/provena` creates the dedicated project after the challenge is published; with a registration list (the default here) teams create it before T0 as above |
| Teams (T0…T1) | `provena challenge submit challenge.pvb --predictions predictions.csv --evaluator evaluator.card.json -o team.pvb` until it prints `ON TIME`; send `team.pvb` to the evaluator |
| Anyone | `provena challenge status challenge.pvb --hub https://jimmyresearch.com/provena` |
| Organizer (after T1) | `provena challenge close` |
| Evaluator | `provena challenge score challenge.pvb --truth truth.pvb --submission … --hub … --yes -o leaderboard.pvb`, then `provena publish leaderboard.json && provena push` — the hub's project page shows the board with its own row-by-row check |
| Anyone (T1+3) | `provena challenge audit leaderboard.pvb --challenge challenge.pvb --hub …`; each team adds `--submission team.pvb` |

## 3. What to report after the pilot (PILOT.md §6)

The four claims of PILOT.md §1, each with the command output that shows it, the hub page of the
leaderboard (its "Hub check" verdict), and every place an agent or person had to read prose
instead of JSON — that list feeds the next round of the CLI contract.
