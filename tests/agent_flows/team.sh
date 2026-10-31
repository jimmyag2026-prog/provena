#!/usr/bin/env bash
# Lanes B/E/F: agents through a hub — concurrent writers, a rotation that strands an entry,
# a reset hub, a mirror clone.
source "$(dirname "$0")/common.sh"
start_hub hub 18911; HUB=$HUB_URL
start_hub mirror 18912; MIRROR=$HUB_URL
export PROVENA_HOME=$W/home
expect 0 $P keygen; expect 0 $P --agent bench keygen
mkdir "$W/pi" && cd "$W/pi"
expect 0 $P init --name team
expect 0 $P remote "$HUB"
for i in $(seq 8); do echo "a$i" > "a$i.txt"; echo "b$i" > "b$i.txt"; done
$P add a*.txt > /dev/null & A=$!; $P add b*.txt > /dev/null & B=$!   # two writers at once
wait $A; wait $B
expect 0 $P verify
expect 0 $P push
expect 0 $P member add "$W/home/agents/bench.card.json" --role contributor
PID=$(python3 -c "import json; print(json.load(open('.provena/config.json'))['project'])")
cd "$W" && expect 0 $P --agent bench clone "$HUB" "$PID" bench && cd "$W/bench"
echo r > r.txt && expect 0 $P --agent bench add r.txt               # on the old project key
cd "$W/pi" && expect 0 $P rotate && expect 0 $P push                # meanwhile: a rotation
cd "$W/bench"
expect 5 $P --agent bench push                                      # set aside, not "pushed 0"
expect 1 $P --agent bench doctor
expect 0 $P --agent bench stranded redo
expect 0 $P --agent bench push
cd "$W/pi" && expect 0 $P pull && expect 0 $P mirror "$MIRROR"
cd "$W" && expect 0 $P clone "$MIRROR" "$PID" fromMirror && cd fromMirror
echo n > n.txt && expect 0 $P add n.txt
expect 5 $P push                                                    # a mirror clone is read-only
expect 0 $P remote --rehome
expect 0 $P push
echo "team flow OK"
