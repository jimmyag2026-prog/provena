# Shared setup for agent-flow scripts: an agent drives `provena` with no terminal.
# Usage: source common.sh; each script checks exit codes, never prose.
set -euo pipefail
P=${PROVENA:-provena}
W=$(mktemp -d "${TMPDIR:-/tmp}/provena-flow.XXXXXX")
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
export PROVENA_SCRYPT_N=1024
printf 'flow-test-passphrase\n' > "$W/pass"; chmod 600 "$W/pass"
export PROVENA_PASSPHRASE_FILE="$W/pass"
unset PROVENA_PASSPHRASE || true
exec </dev/null                      # agents have no terminal

expect() {  # expect CODE cmd... : the command must exit with CODE
  local want=$1; shift
  set +e; "$@"; local got=$?; set -e
  if [ "$got" != "$want" ]; then echo "FAIL: '$*' exited $got, expected $want" >&2; exit 1; fi
}

start_hub() {  # start_hub NAME PORT [args...] -> URL in $HUB_URL
  local name=$1 port=$2; shift 2
  PROVENA_HUB_PASSPHRASE_FILE="$W/pass" $P hub serve --data "$W/$name" --port "$port" \
    --anchor-interval 0 "$@" > "$W/$name.log" 2>&1 &
  HUB_URL="http://127.0.0.1:$port"
  for _ in $(seq 50); do curl -sf "$HUB_URL/healthz" >/dev/null && return; sleep 0.2; done
  cat "$W/$name.log" >&2; exit 1
}
