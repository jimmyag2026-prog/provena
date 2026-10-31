#!/usr/bin/env bash
# End-to-end Provena demo: hub + researcher + reviewer + witness + anchoring + verification.
# Usage: examples/demo.sh [workdir]   (uses a throwaway PROVENA_HOME; no real keys touched)
set -euo pipefail
WORK="${1:-$(mktemp -d)}"
mkdir -p "$WORK/lab"
export PROVENA_HOME="$WORK/home" PROVENA_PASSPHRASE=demo PROVENA_HUB_PASSPHRASE=demo-hub
export PROVENA_SCRYPT_N=1024   # fast keys for the demo only
PORT="${PORT:-18790}" HUB="http://127.0.0.1:${PORT:-18790}"

provena hub serve --data "$WORK/hub" --port "$PORT" --anchor-interval 0 > "$WORK/hub.log" 2>&1 &
HUB_PID=$!
trap 'kill $HUB_PID 2>/dev/null' EXIT
for _ in $(seq 100); do curl -sf --noproxy "*" "$HUB/healthz" >/dev/null && break; sleep 0.2; done   # wait for the hub

cd "$WORK/lab"
provena keygen --display "Ada (PI)" >/dev/null
provena --agent reviewer keygen --display "Reviewer 2" >/dev/null
provena --agent witness keygen --kind org --display "Independent witness" >/dev/null
provena init --name binding-assay >/dev/null

echo "Hypothesis: compound X binds target Y with Kd < 10 nM" > protocol.md
printf 'conc_nM,signal\n1,0.08\n10,0.51\n100,0.93\n' > plate1.csv
cat > fit.py <<'PY'
import csv, json
rows = list(csv.DictReader(open("plate1.csv")))
kd = next(float(r["conc_nM"]) for r in rows if float(r["signal"]) >= 0.5)
json.dump({"kd_nM": kd}, open("kd.json", "w"))
PY

provena plan protocol.md
provena add plate1.csv
provena run --plan protocol.md --used plate1.csv --used fit.py --out kd.json -- python3 fit.py
provena remote "$HUB"
provena push
PROJECT=$(python3 -c "import json;print(json.load(open('.provena/config.json'))['project'])")

provena --agent witness witness "$HUB" "$PROJECT"
# trust is your decision: the hub was trusted by `remote`; also trust this witness
provena trust add witness "$(python3 -c "import json;print(json.load(open('$PROVENA_HOME/agents/witness.card.json'))['id'])")" >/dev/null
provena hub anchor "$HUB"
provena pull
provena reveal protocol.md
provena push

provena share kd.json --to "$PROVENA_HOME/agents/reviewer.card.json" -o "$WORK/kd.share.pvb"
provena --agent reviewer open "$WORK/kd.share.pvb" --hub "$HUB" -o "$WORK/reviewer-inbox"
echo "--- reviewer received: $(cat "$WORK/reviewer-inbox/kd.json")"

provena --agent witness witness "$HUB" "$PROJECT"   # cosign the latest head too
provena pull
provena prove kd.json --open kd.json -o "$WORK/kd.pvb"
provena verify "$WORK/kd.pvb" --content kd.json=kd.json
echo "--- open $HUB in a browser and drop $WORK/kd.pvb onto the page (Ctrl-C to stop)"
