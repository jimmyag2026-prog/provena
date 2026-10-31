#!/usr/bin/env bash
# PILOT.md rehearsal against a *running* hub with synthetic data, driven the way agents drive it:
# --json envelopes and exit codes only, passphrase files, no terminal.
#   HUB=https://jimmyresearch.com/provena ADMIT='ssh root@host "cat >> /home/provena/creators.txt"' \
#     examples/pilot_rehearsal.sh [workdir]
# ADMIT receives the new agent ids (one per line) on stdin, for a hub that restricts creators.
set -euo pipefail
: "${HUB:?set HUB to the hub URL}"
WORK="${1:-$(mktemp -d)}"; mkdir -p "$WORK"
export PROVENA_HOME="$WORK/home" PROVENA_SCRYPT_N=1024
( umask 077; head -c 24 /dev/urandom | base64 > "$WORK/pass" )
export PROVENA_PASSPHRASE_FILE="$WORK/pass"; unset PROVENA_PASSPHRASE || true
exec </dev/null
DEADLINE_IN="${DEADLINE_IN:-120}"
P() { provena --json "$@"; }                                   # one envelope on stdout
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]))" "$1"; }
step() { printf '\n== %s\n' "$*" >&2; }

for a in organizer evaluator team1 team2 auditor; do P --agent "$a" keygen --kind software >/dev/null; done
ids=$(for a in organizer evaluator team1 team2; do
  python3 -c "import json;print(json.load(open('$PROVENA_HOME/agents/$a.card.json'))['id'])"; done)
if [[ -n ${ADMIT:-} ]]; then printf '%s  # pilot rehearsal\n' $ids | sh -c "$ADMIT"; fi

step "organizer: a public project; truth committed, terms published"
mkdir -p "$WORK/org" && cd "$WORK/org"
P --agent organizer init --name pilot-rehearsal --public >/dev/null
P --agent organizer remote "$HUB" >/dev/null
printf 'seq\nAUGC\nGGCA\nUUAG\nCCGU\n' > targets.csv
printf 'seq,label\nAUGC,1\nGGCA,0\nUUAG,1\nCCGU,0\n' > truth.csv
cat > score.py <<'PY'
import csv, json, sys
truth = {r["seq"]: r["label"] for r in csv.DictReader(open("truth.csv"))}
json.dump({p: sum(r["label"] == truth[r["seq"]] for r in csv.DictReader(open(p))) / len(truth)
           for p in sys.argv[1:]}, open("scores.json", "w"))
PY

step "teams: one entry project each on the hub; AGENT:PROJECT lines for the organizer"
TEAMS=()
for t in team1 team2; do
  mkdir -p "$WORK/$t" && cd "$WORK/$t"
  pid=$(P --agent "$t" init --name "$t-entry" | field '["data"]["project"]')
  P --agent "$t" remote "$HUB" >/dev/null
  aid=$(python3 -c "import json;print(json.load(open('$PROVENA_HOME/agents/$t.card.json'))['id'])")
  TEAMS+=(--team "$aid:$pid")
done
cd "$WORK/org"
DEADLINE="$(python3 -c "import datetime as d;print((d.datetime.now(d.timezone.utc)+d.timedelta(seconds=$DEADLINE_IN)).strftime('%Y-%m-%dT%H:%M:%SZ'))")"
P --agent organizer challenge init --title "Pilot rehearsal" --truth truth.csv --targets targets.csv \
  --score score.py --deadline "$DEADLINE" "${TEAMS[@]}" -o "$WORK/challenge.pvb" >/dev/null
P challenge status "$WORK/challenge.pvb" --hub "$HUB" | field '["data"]["state"]' >&2

step "team1 submits on time"
cd "$WORK/team1"; printf 'seq,label\nAUGC,1\nGGCA,0\nUUAG,1\nCCGU,1\n' > pred.csv
P --agent team1 challenge submit "$WORK/challenge.pvb" --predictions pred.csv \
  --evaluator "$PROVENA_HOME/agents/evaluator.card.json" -o "$WORK/team1.pvb" | field '["data"]["on_time"]' >&2

step "waiting for the deadline ($DEADLINE); team2 is late"
until [[ $(P challenge status "$WORK/challenge.pvb" --hub "$HUB" | field '["data"]["state"]') != open ]]; do sleep 5; done
cd "$WORK/team2"; printf 'seq,label\nAUGC,1\nGGCA,1\nUUAG,1\nCCGU,0\n' > pred.csv
set +e; P --agent team2 challenge submit "$WORK/challenge.pvb" --predictions pred.csv \
  --evaluator "$PROVENA_HOME/agents/evaluator.card.json" -o "$WORK/team2.pvb" >/dev/null; late=$?; set -e
[[ $late == 7 ]] || { echo "team2 should be LATE (exit 7), got $late" >&2; exit 1; }

step "organizer closes; evaluator scores in the sandbox; the board is public"
cd "$WORK/org"; P --agent organizer challenge close -o "$WORK/truth.pvb" >/dev/null
mkdir -p "$WORK/eval" && cd "$WORK/eval"
P --agent evaluator init --name pilot-evaluation --public >/dev/null
P --agent evaluator remote "$HUB" >/dev/null
P --agent evaluator challenge score "$WORK/challenge.pvb" --truth "$WORK/truth.pvb" \
  --submission "$WORK/team1.pvb" --submission "$WORK/team2.pvb" --hub "$HUB" --yes \
  -o "$WORK/leaderboard.pvb" | field '["data"]["rows"]' >&2

step "an outsider audits with no key of anyone involved; team1 checks its own entry"
mkdir -p "$WORK/outside" && cd "$WORK/outside"
key=$(P challenge status "$WORK/challenge.pvb" --hub "$HUB" | field '["data"]["hub_log_key"]')
P --agent auditor trust add log "$key" >/dev/null   # the published log key (compare out of band)
P --agent auditor challenge audit "$WORK/leaderboard.pvb" --challenge "$WORK/challenge.pvb" \
  --hub "$HUB" --submission "$WORK/team1.pvb" | field '["data"]["verdict"]' >&2
P challenge status "$WORK/challenge.pvb" --hub "$HUB" | field '["data"]["state"]' >&2
echo "rehearsal OK: $WORK" >&2
