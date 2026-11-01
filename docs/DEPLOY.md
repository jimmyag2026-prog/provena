# Deploying a Provena Hub

**Status: draft** · applies to v0.x

## What the hub holds

| Path under `--data` | Content | Back up? |
|---|---|---|
| `hub.key.json` | log signing key, scrypt-encrypted | **yes, offline** — losing it ends the log's identity (clients pin it) |
| `hub.card.json` | public card of the log key | yes |
| `hub.sqlite3` (+ `-wal`) | entries, receipts, tree heads, cosignatures, anchors | yes (`sqlite3 hub.sqlite3 ".backup b.sqlite3"`) |
| `blobs/` | ciphertext only | yes (content-addressed; rsync-safe) |
| `published/` | verified plaintext of content *published with its key* (public anyway), cached for downloads; LRU, 5 GiB | no (rebuilt on demand) |
| `spool/` | upload staging (S3 deployments) | no |

The hub never holds project keys, and plaintext only of content its authors published with the
key (which anyone can decrypt anyway). Losing `blobs/` loses availability, not
integrity: authors still hold their ciphertext locally and can `push` again.

## PostgreSQL (optional)

```bash
pip install "provena-ledger[server,client,postgres]"
export PROVENA_HUB_DATABASE_URL=postgresql://provena@db.internal/provena   # password via ~/.pgpass
provena hub serve --data /var/lib/provena
```

Entries, receipts, tree heads, cosignatures and anchors then live in PostgreSQL (back it up like
any database; never restore an older snapshot over a newer one, see below). `--data` still holds
the log key and, unless S3 is configured, the ciphertext.

## Object storage (optional)

```bash
pip install "provena-ledger[server,client,s3]"
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…   # or an instance role / ~/.aws config
provena hub serve --data /var/lib/provena --s3-bucket lab-hub \
    --s3-endpoint https://sgp1.digitaloceanspaces.com
```

The hub needs `s3:ListBucket` (S3 answers 403 instead of 404 without it) plus `s3:GetObject`, `s3:PutObject` and `s3:DeleteObject`. **Turn bucket versioning off** (or add a lifecycle rule that expires noncurrent versions quickly): with versioning, a redaction only adds a delete marker and earlier versions survive. The bucket holds only ciphertext under `provena/<project>/<cid>`; uploads are size- and
hash-checked on the hub before an object is written. SQLite metadata and the log key stay in
`--data`. Keep the bucket private: the hub enforces read permissions.

## Run

```bash
pip install "provena-ledger[server,client]"     # or: docker build -t provena-hub .
export PROVENA_HUB_PASSPHRASE_FILE=/etc/provena/hub_pass   # 0600; never on the command line
provena hub serve --data /var/lib/provena --host 127.0.0.1 --port 8740 \
    --tsa https://freetsa.org/tsr --anchor-interval 600
```

The PyPI package named plain `provena` is an unrelated project; install `provena-ledger` (the command and the import stay `provena`).

Writes are rate-limited per client address (`--writes-per-minute`; project creation 20/hour, burst 10); `--max-projects` caps the hub's total number of projects. Keys cost nothing to make, so a hub reachable from the internet should also restrict who may create projects: `--creators FILE` (agent ids, one per line, `#` comments; re-read on every creation, a missing file admits nobody) and `--projects-per-creator N`. For a shared hub use `--policy FILE` instead (ADR 0012): orgs with their agent ids, `max_projects`, `max_bytes` and API keys (stored as hashes; `provena hub api-key ORG` makes one), plus an optional `default` for agents in no org:

```json
{"orgs": {"lab-a": {"agents": ["pv1a…"], "max_projects": 50, "max_bytes": 10737418240,
                    "api_keys": ["sha256:…"]}},
 "default": {"max_projects": 3, "max_bytes": 1073741824}}
```

The file is re-read when it changes; one that does not parse admits nobody and accepts no new uploads. On a policy hub a project is created only by a signed request from an agent of the org it is charged to (mirror a project there from a checkout of that org). Org admins read their usage with `GET /v1/orgs/ORG/usage` and `Authorization: Bearer KEY`. The hub database carries a schema version and migrates forward at start; it refuses to run against a database written by a newer Provena. Existing projects keep accepting their members' writes either way. For a mirror, list the project owners' ids (the genesis author), not the member who runs `provena mirror`; behind a reverse proxy add `--behind-proxy` so limits apply to the real client (only if the proxy overwrites `X-Forwarded-For`).

Heads are re-anchored every `--reanchor-days` (default 30) so old anchors survive a weakened hash or TSA (ADR 0008).

Put TLS in front (Caddy: `hub.example.org { reverse_proxy 127.0.0.1:8740 }`). The API is
stateless apart from SQLite; run a single process per data directory (sequencing takes an
in-process lock).

## Mirrors and witnesses (availability, fork detection)

A second hub run by another party can hold the same projects. Project owners (or anyone holding a
clone) replicate with `provena mirror https://mirror.example.org`, e.g. from a nightly job; the
mirror sequences the same author-signed entries, so its heads have the same roots at the same
sizes, and anyone can `provena clone` from it while the primary is down. `provena mirror` records the primary on the mirror, so such a clone is read-only until `provena remote --rehome` moves it to the primary (writing to a mirror would fork the project). One `hub serve` process per data directory (a second one refuses to start).

Existing transparency-log witnesses can watch a project too: each tree head is served as a C2SP checkpoint (`/v1/projects/<pid>/checkpoint`, verifier key from `/v1/hub/vkey?project=<pid>`).

Run at least one independent witness against both hubs with one state file:

```bash
provena --agent witness witness https://hub.example.org <project> --state w.json
provena --agent witness witness https://mirror.example.org <project> --state w.json
```

It cosigns each hub's heads only if they extend what it saw before *and* agree with the other
hub's roots at the same size (consistency-checked across hubs); a disagreement is a fork and is
refused. Readers who trust the witness then reach `witnessed` only on fork-free heads.

## Monitoring

Point the load balancer at `GET /healthz`. Scrape `GET /metrics` (Prometheus) and alert on:

- `provena_projects_quarantined > 0` — a log failed to replay: investigate before anything else;
- `provena_anchor_failures_total` increasing, or `time() - provena_last_anchor_attempt_seconds`
  above a few anchoring intervals — anchoring is failing or stopped. (`provena_last_anchor_seconds`
  alone is not an alarm: an idle hub has no new root to anchor.)
- `provena_anchor_independent == 0` in production — the hub self-anchors.

Forks and rollbacks are detected outside the hub, by whoever holds signed heads: witnesses refuse
to cosign, clients exit 6 (`E_ROLLBACK` / `E_FORK`). Alert on your witness cron's exit code.

## Backup and restore

- Back up `hub.sqlite3` with `sqlite3 hub.sqlite3 ".backup b.sqlite3"` (or your PostgreSQL
  backups), plus `hub.key.json`, `hub.card.json` and the blob store, **at least as often as you can
  afford to lose writes** — entries sequenced after the backup exist only in clients and mirrors.
- Restore: stop the hub, put the backup in place, start it, check `/healthz`; then
  `provena mirror --check <mirror>` and `provena pull` from a checkout that pushed recently.
- **If the restored copy is older than what clients hold**, every client that synced later gets
  `E_ROLLBACK` (exit 6) and keeps its data: the signed receipts prove the rollback happened, and
  there is no in-place repair. Choose openly: restore a newer backup (or rebuild from a mirror that
  is ahead: it holds the same author-signed entries), or announce the incident and move projects
  to a new log. Never try to make the rollback look like it did not happen.
- A witness that saw a fork refuses that project until its operator has investigated; after a
  documented resolution, remove the project from the witness state file to resume cosigning.

## Operational guarantees to keep

- **Change the log key only by hand-over** (ADR 0010): stop the hub, `provena hub rotate-key
  --data DIR --yes`, start it. Clients and witnesses follow the hand-over (signed by both keys)
  on their next sync; a key that changes without one still looks like a takeover and is refused.
  Shred `hub.key.retired-<id>.json` once they have synced. **After a leak, do not rotate and
  move on:** announce it out of band so verifiers drop the old key (`provena trust remove log
  ID`) — whoever holds it can sign hand-overs too.
- **Never restore an older database over a newer one.** Witnesses and clients hold later heads
  and will (correctly) report the hub as forked.
- **Run at least one independent witness** (`provena witness <hub> <project>...` on a cron, on
  a machine and key the hub operator does not control).
- **Anchoring**: use an RFC 3161 TSA in production. `self` anchoring is for development and the
  verifier says so.
- Deploy from git and record what runs (SHA, version, operator) in an append-only deploy log,
  following the repository's existing deployment conventions.
