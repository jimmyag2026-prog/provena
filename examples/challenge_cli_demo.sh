#!/usr/bin/env bash
# `provena challenge` commands end to end against a real hub with a real clock:
# registered teams -> init (truth committed, terms published) -> submit -> deadline passes ->
# close -> score -> anyone audits the published leaderboard.
# Usage: examples/challenge_cli_demo.sh [workdir]   (throwaway PROVENA_HOME; no real keys touched)
set -euo pipefail
WORK="${1:-$(mktemp -d)}"
mkdir -p "$WORK"
export PROVENA_HOME="$WORK/home" PROVENA_PASSPHRASE=demo PROVENA_HUB_PASSPHRASE=demo-hub
export PROVENA_SCRYPT_N=1024
PORT="${PORT:-18796}"; HUB="http://127.0.0.1:$PORT"
DEADLINE_IN="${DEADLINE_IN:-20}"   # seconds from now
P="provena"
pid() { python3 -c "import json;print(json.load(open('.provena/config.json'))['project'])"; }
aid() { python3 -c "import json;print(json.load(open('$PROVENA_HOME/agents/$1.card.json'))['id'])"; }
card() { echo "$PROVENA_HOME/agents/$1.card.json"; }

$P hub serve --data "$WORK/hub" --port "$PORT" --anchor-interval 0 > "$WORK/hub.log" 2>&1 &
HUB_PID=$!; trap 'kill $HUB_PID 2>/dev/null' EXIT
for _ in $(seq 100); do curl -sf --noproxy "*" "$HUB/healthz" >/dev/null && break; sleep 0.2; done   # wait for the hub
for a in organizer team1 team2 evaluator; do $P --agent "$a" keygen --display "$a" >/dev/null; done

echo "== 1. teams create the one project each will submit from"
TEAMS=()
for t in team1 team2; do
  mkdir -p "$WORK/$t" && cd "$WORK/$t"
  $P --agent "$t" init --name "$t-rna" >/dev/null && $P --agent "$t" remote "$HUB" >/dev/null
  TEAMS+=(--team "$(aid "$t"):$(pid)")
done

echo "== 2. organizer: truth committed; protocol (with registered teams), targets, scorer public"
mkdir -p "$WORK/org" && cd "$WORK/org"
$P --agent organizer init --name rna-challenge --public >/dev/null
$P --agent organizer remote "$HUB" >/dev/null
printf 'seq\nAUGC\nGGCA\nUUAG\n' > targets.csv
printf 'seq,label\nAUGC,1\nGGCA,0\nUUAG,1\n' > truth.csv
cat > score.py <<'PY'
import csv, json, sys
truth = {r["seq"]: r["label"] for r in csv.DictReader(open("truth.csv"))}
json.dump({p: sum(r["label"] == truth[r["seq"]] for r in csv.DictReader(open(p))) / len(truth)
           for p in sys.argv[1:]}, open("scores.json", "w"))
PY
DEADLINE="$(python3 -c "import datetime as d;print((d.datetime.now(d.timezone.utc)+d.timedelta(seconds=$DEADLINE_IN)).strftime('%Y-%m-%dT%H:%M:%SZ'))")"
$P --agent organizer challenge init --title "RNA binders" --truth truth.csv --targets targets.csv \
  --score score.py --deadline "$DEADLINE" "${TEAMS[@]}" -o "$WORK/challenge.pvb"

echo "== 3. teams submit before the deadline (predictions go to the evaluator only)"
cd "$WORK/team1"; printf 'seq,label\nAUGC,1\nGGCA,0\nUUAG,1\n' > pred.csv
$P --agent team1 challenge submit "$WORK/challenge.pvb" --predictions pred.csv \
  --evaluator "$(card evaluator)" -o "$WORK/team1.pvb"
cd "$WORK/team2"; printf 'seq,label\nAUGC,1\nGGCA,1\nUUAG,1\n' > pred.csv
$P --agent team2 challenge submit "$WORK/challenge.pvb" --predictions pred.csv \
  --evaluator "$(card evaluator)" -o "$WORK/team2.pvb"

echo "== 4. organizer closes after the deadline ($DEADLINE)"
cd "$WORK/org"
until $P --agent organizer challenge close -o "$WORK/truth.pvb" 2>/dev/null; do sleep 2; done

echo "== 5. evaluator scores (runs the preregistered scorer only with --yes)"
mkdir -p "$WORK/eval" && cd "$WORK/eval"
$P --agent evaluator init --name rna-evaluation --public >/dev/null
$P --agent evaluator remote "$HUB" >/dev/null
$P --agent evaluator challenge score "$WORK/challenge.pvb" --truth "$WORK/truth.pvb" \
  --submission "$WORK/team1.pvb" --submission "$WORK/team2.pvb" --hub "$HUB" --yes \
  --workdir "$WORK/eval-work" -o "$WORK/leaderboard.pvb"

echo "== 6. anyone audits the published leaderboard (no key needed)"
mkdir -p "$WORK/public" && cd "$WORK/public"
env -u PROVENA_PASSPHRASE $P challenge audit "$WORK/leaderboard.pvb" \
  --challenge "$WORK/challenge.pvb" --hub "$HUB"
