# Hub HTTP API v1

All bodies are JSON unless noted. Errors from the ledger and the write throttle are
`{"error": "..."}`: 403 (project creation not allowed for this agent), 404 (unknown), 409 (duplicate), 422 (rejected by verification/state machine),
429 (throttled), 503 (project quarantined, hub not accepting new projects). Request-level errors
use FastAPI's `{"detail": "..."}`: 400 (invalid JSON), 401/403 (private read), 404 (no tree head
of that size, no blob), 413 (too large), 429 (anchor run too soon), 503 (upload slots busy).
Writes need no session auth (ADR 0005). Private reads need headers `X-Provena-Agent`,
`X-Provena-Time` (unix ms, ±5 min) and `X-Provena-Signature` = Ed25519 over
`tag("provena/request/v1") ‖ JCS({method, path, query, body: sha256 hex, agent, time})`.

| Method & path | Body / params | Returns |
|---|---|---|
| `GET /v1/orgs/{org}/usage` | `Authorization: Bearer <org API key>` | `{org, projects, bytes, limits}` (ADR 0012; 401 without a key of that org) |
| `GET /v1/projects/{pid}/entries/{hash}` | | one entry as the citation page shows it: `{project, hash, index, size, kind, sequenced, visibility, anchored?}`, plus `entry`, `revealed`, `redacted` for public projects; 404 if unknown |
| `GET /v1/catalog?q=` | | `{projects: [{project, meta, size, time}], private}`: public projects (what the home page lists) |
| `GET /v1/projects/{pid}/overview` | | what the project page shows: `{project, visibility, head, cosignatures, anchors, meta}`, and for public projects the newest 1000 `entries` (+ `entries_total`; page the rest through `/entries`), `files`, `lineage`, `leaderboard` (rows + the hub's check) |
| `GET /v1/hub` | | `{card, version, projects, rotations}`: `rotations` = the log key hand-overs, oldest first (ADR 0010) |
| `POST /v1/projects` | `{entry: genesis}` | `{index, entry_hash, receipt, head}` |
| `GET /v1/projects/{pid}` | | `{project, visibility, size, head, meta}` (`meta` only for public projects) |
| `POST /v1/projects/{pid}/entries` | `{entry}` | `{index, entry_hash, receipt (SET), head (STH)}` |
| `GET /v1/projects/{pid}/entries` 🔒 | `start`, `limit` (≤1000) | `{entries: [{index, entry, integrated_time, receipt}], size}` |
| `GET /v1/projects/{pid}/sth` | `size?` | signed tree head |
| `GET /v1/projects/{pid}/proofs/inclusion` | `index`, `size` | `{index, size, proof: [hex]}` |
| `GET /v1/projects/{pid}/proofs/consistency` | `first`, `second` | `{first, second, proof: [hex]}` |
| `PUT /v1/projects/{pid}/blobs/{cid}` | raw ciphertext | 201 created / 200 existed |
| `HEAD/GET /v1/projects/{pid}/blobs/{cid}` 🔒* | | ciphertext |
| `GET /v1/projects/{pid}/checkpoint` | | the latest tree head as a C2SP checkpoint (signed note, origin `provena/<hub id>/<pid>`) for transparency-log witnesses |
| `GET /v1/hub/vkey?project=PID` | | the C2SP verifier key for that origin |
| `POST /v1/projects/{pid}/primary` 🔒 | `{"url", "card"}` | on a mirror: the project's primary hub (set once; `GET /v1/projects/{pid}` returns it as `primary`) |
| `POST /v1/projects/{pid}/blobs/missing` 🔒 | `{"cids": [...]}` (≤1000) | `{"missing": [...]}`: referenced cids the hub does not store |
| `POST /v1/projects/{pid}/cosignatures` | `{size, cosig, card}` | `{ok}` |
| `GET /v1/projects/{pid}/cosignatures` | `size` | `{size, cosignatures: [{cosig, card}]}` |
| `GET /v1/projects/{pid}/cosignatures/latest` | | `{head \| null, cosignatures}`: the largest cosigned head (for bundles on later heads); a cosignature made before a key rotation carries the `head` it signed |
| `GET /v1/projects/{pid}/anchors` | | `{anchors: [{anchor, head, index, proof}]}` |
| `POST /v1/anchors/run` | | `{anchored, anchor}` (30 s throttle) |
| `GET /healthz` | | `{ok, projects, quarantined}` for load balancers |
| `GET /metrics` | | Prometheus text: projects, quarantined, entries, upload slots, anchors, last anchor time |
| `GET /`, `GET /p/{pid}`, `GET /p/{pid}/e/{entry}` | | the single-page front end (landing + bundle verifier, project explorer, citation page), which checks logs and entries in the browser; agents use the JSON above |
| `GET /classic`, `/classic/p/{pid}`, `/classic/p/{pid}/e/{entry}` | | the same pages server-rendered, for clients without JavaScript |
| `GET /p/{pid}/files/{entry}` | | plaintext of content published with its key, verified against the commitment before serving |
| `GET /static/*` | | the browser verifier and page assets |

🔒 private projects only; public projects are open. *Blobs are also served to grantees of that
entity (signed request) and to everyone once revealed with its key.
