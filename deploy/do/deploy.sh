#!/usr/bin/env bash
# The only deploy path for the Provena trial hub. Run as root on the server:
#   deploy.sh --expect <sha> [--actor <name>] [--note <text>]
# Fast-forwards /home/provena/provena to the pushed main (must equal --expect), installs it into
# /home/provena/venv, restarts the hub and appends one line to /var/log/provena/deploys.log.
set -euo pipefail
REPO=/home/provena/provena BARE=/home/provena/provena.git VENV=/home/provena/venv
LOG=/var/log/provena/deploys.log
EXPECT="" ACTOR=unknown NOTE=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --expect) EXPECT=$2; shift 2 ;;
    --actor) ACTOR=$2; shift 2 ;;
    --note) NOTE=$2; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
[[ -n $EXPECT ]] || { echo "--expect <sha> is required" >&2; exit 2; }
exec 9>/run/provena-deploy.lock
flock -n 9 || { echo "another deploy is running" >&2; exit 2; }
mkdir -p "$(dirname "$LOG")" && touch "$LOG" && { chattr +a "$LOG" 2>/dev/null || true; }
g() { git -c safe.directory="$REPO" -c safe.directory="$BARE" -C "$REPO" "$@"; }
prev=$(g rev-parse HEAD)
g fetch -q "$BARE" main
new=$(g rev-parse FETCH_HEAD)
[[ $new == "$EXPECT" ]] || { echo "ABORT: server main=$new, expected $EXPECT (push to 'do' first)" >&2; exit 4; }
[[ -z $(g status --porcelain) ]] || { echo "ABORT: $REPO has local changes" >&2; exit 3; }
g merge -q --ff-only FETCH_HEAD || { echo "ABORT: not a fast-forward" >&2; exit 5; }
chown -R root:root "$REPO" "$BARE" && chmod -R go-w "$REPO" "$BARE" && chmod -R o+rX "$REPO"
"$VENV/bin/pip" install -q --upgrade "$REPO[server,client]"
cmp -s "$REPO/deploy/do/provena-hub.service" /etc/systemd/system/provena-hub.service || {
  install -m 644 "$REPO/deploy/do/provena-hub.service" /etc/systemd/system/provena-hub.service
  systemctl daemon-reload; }
systemctl enable -q provena-hub && systemctl restart provena-hub
ok=0
for _ in $(seq 1 20); do
  curl -sf http://127.0.0.1:8803/healthz >/dev/null && { ok=1; break; }; sleep 1
done
client=${SSH_CLIENT:-local}; client=${client%% *}
printf '%s sha=%s prev=%s healthy=%s actor=%s ssh_client=%s note="%s"\n' "$(date -u +%FT%TZ)" \
  "$new" "$prev" "$ok" "$ACTOR" "$client" "${NOTE//\"/\'}" >> "$LOG"
(( ok )) || { echo "deployed $new but /healthz did not answer: journalctl -u provena-hub" >&2; exit 6; }
echo "deployed $new (was $prev); healthy"
