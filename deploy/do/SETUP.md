# Provena trial hub on the DO droplet

`https://jimmyresearch.com/provena` → Caddy (`uri strip_prefix /provena`) → `127.0.0.1:8803`,
user `provena`, data in `/home/provena/hub-data`, RFC 3161 anchoring via freetsa.org (trial).
Same deploy discipline as safe-tx-guard: a bare repo on the server, `git push do main`, then
`deploy.sh --expect <sha>`; every deploy is one append-only line in `/var/log/provena/deploys.log`.

## One-time (as root)

```bash
useradd --system --create-home --shell /usr/sbin/nologin provena
git init --bare /home/provena/provena.git
git clone /home/provena/provena.git /home/provena/provena      # after the first push
python3 -m venv /home/provena/venv
install -d -o provena -g provena -m 700 /home/provena/hub-data
# hub key passphrase: generated here, never leaves the server
( umask 077; openssl rand -base64 32 > /home/provena/hub.pass ); chown provena:provena /home/provena/hub.pass
# who may create projects: agent ids, one per line
install -o provena -g provena -m 644 /dev/null /home/provena/creators.txt
python3 /home/provena/provena/deploy/do/caddy-provena.py && caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy
```

## Each deploy (from a checkout of main)

```bash
git push do main
ssh root@<hub-server> /home/provena/provena/deploy/do/deploy.sh --expect "$(git rev-parse main)" --actor <you> --note "<why>"
```

## Admit a creator

Append the agent id (`provena card | jq -r .id`) to `/home/provena/creators.txt` (re-read on every
creation, no restart). Publish the hub's log key (`curl -s https://jimmyresearch.com/provena/v1/hub`)
so readers can `provena trust add log <id>` after checking it.
