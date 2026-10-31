#!/usr/bin/env bash
# Challenge mode with today's primitives (see docs/design/challenge-mode.md):
# preregistered truth -> blinded team submissions -> deadline -> reveal -> grants to the
# evaluator -> reproducible scoring citing every input across projects -> one verifiable bundle.
# Usage: examples/challenge_demo.sh [workdir]   (throwaway PROVENA_HOME; no real keys touched)
set -euo pipefail
WORK="${1:-$(mktemp -d)}"
mkdir -p "$WORK"
export PROVENA_HOME="$WORK/home" PROVENA_PASSPHRASE=demo PROVENA_HUB_PASSPHRASE=demo-hub
export PROVENA_SCRYPT_N=1024
PORT="${PORT:-18795}"; HUB="http://127.0.0.1:$PORT"
P="provena"
pid() { python3 -c "import json;print(json.load(open('.provena/config.json'))['project'])"; }
tracked() { python3 -c "import json;print(json.load(open('.provena/tracked.json'))['$1']['entry'])"; }
card() { echo "$PROVENA_HOME/agents/$1.card.json"; }

$P hub serve --data "$WORK/hub" --port "$PORT" --anchor-interval 0 > "$WORK/hub.log" 2>&1 &
HUB_PID=$!; trap 'kill $HUB_PID 2>/dev/null' EXIT
for _ in $(seq 100); do curl -sf --noproxy "*" "$HUB/healthz" >/dev/null && break; sleep 0.2; done   # wait for the hub
for a in organizer team1 team2 evaluator; do $P --agent "$a" keygen --display "$a" >/dev/null; done

echo "== 1. organizer preregisters protocol + sealed truth, publishes targets"
mkdir -p "$WORK/org" && cd "$WORK/org"
$P --agent organizer init --name challenge --public >/dev/null
printf 'seq\nAUGC\nGGCA\nUUAG\n' > targets.csv
printf 'seq,label\nAUGC,1\nGGCA,0\nUUAG,1\n' > truth.csv
cat > score.py <<'PY'
import csv, json, sys
truth = {r["seq"]: r["label"] for r in csv.DictReader(open("truth.csv"))}
scores = {}
for path in sys.argv[1:]:
    rows = list(csv.DictReader(open(path)))
    scores[path] = sum(r["label"] == truth[r["seq"]] for r in rows) / len(truth)
json.dump(scores, open("scores.json", "w"), indent=1)
PY
printf 'Metric: accuracy vs truth.csv. Scoring code sha256: %s\n' \
  "$(shasum -a 256 score.py | cut -d' ' -f1)" > protocol.md
$P --agent organizer plan protocol.md >/dev/null
$P --agent organizer plan truth.csv >/dev/null           # commitment only: truth stays sealed
$P --agent organizer add targets.csv score.py >/dev/null
$P --agent organizer remote "$HUB" >/dev/null && $P --agent organizer push >/dev/null
$P --agent organizer publish targets.csv >/dev/null
$P --agent organizer publish score.py >/dev/null
$P hub anchor "$HUB" >/dev/null || true
ORG=$(pid); TARGETS=$(tracked targets.csv); TRUTH=$(tracked truth.csv)
$P --agent organizer prove targets.csv -o "$WORK/targets.pvb" >/dev/null

for team in team1 team2; do
  echo "== 2. $team predicts in its own private project, citing the published targets"
  mkdir -p "$WORK/$team" && cd "$WORK/$team"
  $P --agent "$team" init --name "$team" >/dev/null
  $P --agent "$team" open "$WORK/targets.pvb" --hub "$HUB" -o . >/dev/null
  if [ "$team" = team1 ]; then labels="1 0 1"; else labels="1 1 1"; fi
  python3 - "$labels" <<'PY'
import csv, sys
labels = sys.argv[1].split()
rows = [r["seq"] for r in csv.DictReader(open("targets.csv"))]
with open("predictions.csv", "w") as f:
    f.write("seq,label\n" + "".join(f"{s},{l}\n" for s, l in zip(rows, labels)))
PY
  $P --agent "$team" run --external "$ORG:$TARGETS" --out predictions.csv -- true >/dev/null
  $P --agent "$team" remote "$HUB" >/dev/null && $P --agent "$team" push >/dev/null
done

echo "== 3. deadline: the hub anchors; then the truth is revealed"
$P hub anchor "$HUB" >/dev/null 2>&1 || true
cd "$WORK/org" && $P --agent organizer publish truth.csv >/dev/null
$P --agent organizer prove truth.csv score.py -o "$WORK/truth.pvb" >/dev/null

echo "== 4. teams share predictions with the evaluator only"
for team in team1 team2; do
  cd "$WORK/$team"
  $P --agent "$team" share predictions.csv --to "$(card evaluator)" -o "$WORK/$team.share.pvb" >/dev/null
done

echo "== 5. evaluator scores, citing truth, scoring code and both submissions"
mkdir -p "$WORK/eval" && cd "$WORK/eval"
$P --agent evaluator init --name evaluation --public >/dev/null
$P --agent evaluator open "$WORK/truth.pvb" --hub "$HUB" -o . >/dev/null
for team in team1 team2; do
  $P --agent evaluator open "$WORK/$team.share.pvb" --hub "$HUB" -o "$team" >/dev/null
done
cp "$WORK/org/score.py" .             # also published; the protocol pins its sha256
EXT=(--external "$ORG:$TRUTH")
for team in team1 team2; do
  cd "$WORK/$team"; TP=$(pid); PRED=$(tracked predictions.csv)
  $P --agent "$team" prove predictions.csv -o "$WORK/$team.proof.pvb" >/dev/null
  cd "$WORK/eval"; EXT+=(--external "$TP:$PRED")
done
$P --agent evaluator run "${EXT[@]}" --out scores.json -- \
  python3 score.py team1/predictions.csv team2/predictions.csv >/dev/null
$P --agent evaluator remote "$HUB" >/dev/null && $P --agent evaluator push >/dev/null
cat scores.json
$P --agent evaluator prove scores.json --open scores.json --embed \
  --external "$WORK/truth.pvb" --external "$WORK/team1.proof.pvb" \
  --external "$WORK/team2.proof.pvb" -o "$WORK/leaderboard.pvb" >/dev/null

echo "== 6. anyone verifies the leaderboard"
$P verify "$WORK/leaderboard.pvb"
