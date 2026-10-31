#!/usr/bin/env bash
# PILOT.md §7.1 "internal race": a real (small) challenge on a running hub with real public data,
# driven by agents through --json envelopes and exit codes only.
#   HUB=https://jimmyresearch.com/provena ADMIT='ssh root@host "cat >> /home/provena/creators.txt"' \
#     examples/pilot_internal.sh [workdir]
# Data: Fisher's iris measurements (seaborn-data copy, pinned by SHA-256). The organizer holds back
# every 5th flower's species as the truth; teams train on the other 120 and predict the 30. The
# training rows are part of the targets file: before the deadline a challenge project may disclose
# only its protocol, targets and scorer (anything else voids it; `challenge init` refuses).
# Three registered teams: two submit (a nearest-centroid model and a petal-length rule), one
# registers and never submits. The evaluator publishes the board; an outsider audits it.
set -euo pipefail
: "${HUB:?set HUB to the hub URL}"
WORK="${1:-$(mktemp -d)}"; mkdir -p "$WORK"
export PROVENA_HOME="$WORK/home" PROVENA_SCRYPT_N=1024
( umask 077; head -c 24 /dev/urandom | base64 > "$WORK/pass" )
export PROVENA_PASSPHRASE_FILE="$WORK/pass"; unset PROVENA_PASSPHRASE || true
exec </dev/null
DEADLINE_IN="${DEADLINE_IN:-300}"
IRIS_URL="https://raw.githubusercontent.com/mwaskom/seaborn-data/master/iris.csv"
IRIS_SHA256="${IRIS_SHA256:-}"
P() { provena --json "$@"; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]))" "$1"; }
step() { printf '\n== %s\n' "$*" >&2; }
aid() { python3 -c "import json;print(json.load(open('$PROVENA_HOME/agents/$1.card.json'))['id'])"; }

step "data: the public iris table"
curl -sfL "$IRIS_URL" -o "$WORK/iris.csv"
got=$(python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$WORK/iris.csv")
[[ -z $IRIS_SHA256 || $got == "$IRIS_SHA256" ]] || { echo "iris.csv changed: $got" >&2; exit 1; }
echo "iris.csv sha256 $got" >&2

for a in organizer evaluator team1 team2 team3 auditor; do P --agent "$a" keygen --kind software >/dev/null; done
if [[ -n ${ADMIT:-} ]]; then
  for a in organizer evaluator team1 team2 team3; do printf '%s  # internal race\n' "$(aid $a)"; done | sh -c "$ADMIT"
fi

step "organizer: split the table; targets = training rows (labelled) + test rows; commit the truth"
mkdir -p "$WORK/org" && cd "$WORK/org"
python3 - "$WORK/iris.csv" <<'PY'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1])))
feats = ["sepal_length", "sepal_width", "petal_length", "petal_width"]
test = [(f"f{i:03d}", r) for i, r in enumerate(rows) if i % 5 == 0]
train = [r for i, r in enumerate(rows) if i % 5]
with open("targets.csv", "w", newline="") as f:  # species blank = predict it
    w = csv.writer(f); w.writerow(["id"] + feats + ["species"])
    for j, r in enumerate(train): w.writerow([f"t{j:03d}"] + [r[k] for k in feats] + [r["species"]])
    for i, r in test: w.writerow([i] + [r[k] for k in feats] + [""])
with open("truth.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["id", "species"])
    for i, r in test: w.writerow([i, r["species"]])
PY
cat > score.py <<'PY'
import csv, json, sys
truth = {r["id"]: r["species"] for r in csv.DictReader(open("truth.csv"))}
json.dump({p: round(sum(r["species"] == truth.get(r["id"]) for r in csv.DictReader(open(p)))
                    / len(truth), 4) for p in sys.argv[1:]}, open("scores.json", "w"))
PY
P --agent organizer init --name iris-internal-race --public >/dev/null
P --agent organizer remote "$HUB" >/dev/null

step "teams: one entry project each; AGENT:PROJECT lines for the registration list"
TEAMS=()
for t in team1 team2 team3; do
  mkdir -p "$WORK/$t" && cd "$WORK/$t"
  pid=$(P --agent "$t" init --name "iris-$t" | field '["data"]["project"]')
  P --agent "$t" remote "$HUB" >/dev/null
  TEAMS+=(--team "$(aid $t):$pid")
done
cd "$WORK/org"
DEADLINE="$(python3 -c "import datetime as d;print((d.datetime.now(d.timezone.utc)+d.timedelta(seconds=$DEADLINE_IN)).strftime('%Y-%m-%dT%H:%M:%SZ'))")"
P --agent organizer challenge init --title "Iris internal race" --truth truth.csv --targets targets.csv \
  --score score.py --deadline "$DEADLINE" "${TEAMS[@]}" -o "$WORK/challenge.pvb" >/dev/null
echo "deadline $DEADLINE" >&2

predict() {  # $1 team dir, $2 model: centroid | petal
  python3 - "$WORK/org/targets.csv" "$2" > "$1/pred.csv" <<'PY'
import csv, sys
feats = ["sepal_length", "sepal_width", "petal_length", "petal_width"]
rows = list(csv.DictReader(open(sys.argv[1])))
train = [r for r in rows if r["species"]]; targets = [r for r in rows if not r["species"]]
def centroid(r):
    best = None
    for sp in sorted({t["species"] for t in train}):
        pts = [t for t in train if t["species"] == sp]
        c = [sum(float(p[k]) for p in pts) / len(pts) for k in feats]
        d = sum((float(r[k]) - c[j]) ** 2 for j, k in enumerate(feats))
        best = min(best or (d, sp), (d, sp))
    return best[1]
def petal(r):
    pl = float(r["petal_length"])
    return "setosa" if pl < 2.5 else "versicolor" if pl < 4.9 else "virginica"
model = centroid if sys.argv[2] == "centroid" else petal
print("id,species")
for r in targets: print(f'{r["id"]},{model(r)}')
PY
}

step "team1 (nearest centroid) and team2 (petal-length rule) submit before the deadline"
for spec in team1:centroid team2:petal; do
  t=${spec%%:*}; cd "$WORK/$t"; predict "$WORK/$t" "${spec##*:}"
  P --agent "$t" challenge submit "$WORK/challenge.pvb" --predictions pred.csv \
    --evaluator "$PROVENA_HOME/agents/evaluator.card.json" -o "$WORK/$t.pvb" | field '["data"]["on_time"]' >&2
done

step "waiting for the deadline ($DEADLINE); team3 never submits"
until python3 -c "import datetime as d,sys;sys.exit(d.datetime.now(d.timezone.utc)<=d.datetime.fromisoformat('$DEADLINE'.replace('Z','+00:00')))"; do sleep 10; done
state=$(P challenge status "$WORK/challenge.pvb" --hub "$HUB" | field '["data"]["state"]')
[[ $state == "awaiting close" ]] || { echo "challenge state after the deadline: $state" >&2; exit 1; }
sleep 5  # the next tree head after the deadline dates every bundle's completeness

step "organizer closes; evaluator scores and publishes the board"
cd "$WORK/org"; P --agent organizer challenge close -o "$WORK/truth.pvb" >/dev/null
mkdir -p "$WORK/eval" && cd "$WORK/eval"
P --agent evaluator init --name iris-evaluation --public >/dev/null
P --agent evaluator remote "$HUB" >/dev/null
P --agent evaluator challenge score "$WORK/challenge.pvb" --truth "$WORK/truth.pvb" \
  --submission "$WORK/team1.pvb" --submission "$WORK/team2.pvb" --hub "$HUB" --yes \
  -o "$WORK/leaderboard.pvb" | field '["data"]["rows"]' >&2
P --agent evaluator publish leaderboard.json >/dev/null
P --agent evaluator push >/dev/null
EVAL_PID=$(P --agent evaluator status | field '["data"]["project"]')

step "an outsider audits with no key of anyone involved; each team checks its own entry"
mkdir -p "$WORK/outside" && cd "$WORK/outside"
key=$(P challenge status "$WORK/challenge.pvb" --hub "$HUB" | field '["data"]["hub_log_key"]')
P --agent auditor trust add log "$key" >/dev/null
for t in team1 team2; do
  P --agent auditor challenge audit "$WORK/leaderboard.pvb" --challenge "$WORK/challenge.pvb" \
    --hub "$HUB" --submission "$WORK/$t.pvb" | field '["data"]["verdict"]' >&2
done
echo "board: $HUB/p/$EVAL_PID" >&2
curl -sf "$HUB/v1/projects/$EVAL_PID/overview" | python3 -c "
import json, sys
b = json.load(sys.stdin)['leaderboard']
print('hub check:', b['check']['verdict'], '| absent:', b['check']['absent'])" >&2
echo "internal race OK: $WORK" >&2
