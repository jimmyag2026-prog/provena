# CLI contract v1 (`provena-cli/1`)

**Status: normative for 0.2** · What an agent (or any program) may rely on when it drives the
`provena` command line. Human-readable text is not part of the contract and may change.

## 1. Output

- `--json` is a global flag (`provena --json <command> …`). With it, **stdout carries exactly one
  JSON object** (one line), and every human-oriented line goes to stderr.
- `provena run` / `rerun` keep the program's own stdout/stderr; with `--json` the envelope is
  written to stdout **after** the program has exited, and the program's stdout goes to stderr.
- Without `--json`, output is for people.

Envelope:

```json
{"schema": "provena-cli/1", "command": "add", "ok": true, "exit": 0,
 "data": {...}, "warnings": [{"code": "...", "message": "..."}], "error": null}
```

On failure `ok` is false, `data` may be partial, and
`error = {"code": "E_…", "message": "…", "hint": "…"}`.

**Identifiers in `data` are always complete** (64-hex entry hashes and project ids, full agent ids).
Entries are described as `{"hash", "index", "kind", "path"?}`; `index` is the log position.

## 2. Exit codes

| Code | Meaning | Error codes |
|---|---|---|
| 0 | success, including an idempotent no-op ("already recorded") | — |
| 1 | verification failed or a `--require` level was not reached | `E_VERIFY`, `E_REQUIRE` |
| 2 | usage or invalid input | `E_USAGE`, `E_INPUT`, `E_NOT_FOUND`, `E_AMBIGUOUS` |
| 3 | network: hub unreachable, rate-limit retries exhausted | `E_NETWORK` |
| 4 | authentication or permission | `E_NO_PASSPHRASE`, `E_PASSPHRASE`, `E_FORBIDDEN` |
| 5 | state needs action: work left or a conflict | `E_INCOMPLETE`, `E_STRANDED`, `E_CONFLICT`, `E_READONLY` |
| 6 | integrity alarm: the hub or local files contradict signed records | `E_HUB_KEY`, `E_ROLLBACK`, `E_FORK`, `E_CORRUPT` |
| 7 | challenge verdict | `E_LATE`, `E_VOID`, `E_OMITTED` |
| — | also used: `E_PROGRAM` (`run`: the program failed; exit = its code), `E_CONFIRM` (a step that needs `--yes`; exit 2), `E_TOO_EARLY` (exit 5), `E_UNTRUSTED` (the evidence comes from a log you do not trust; exit 1, `hint` names the key) | |
| 130 | interrupted (Ctrl-C) | `E_INTERRUPTED` |
| other | `run` / `rerun`: the program's own exit code (also in `data.exit_code`) | — |

## 3. Secrets

The passphrase of agent `NAME` is read from, in order: the file named by
`PROVENA_PASSPHRASE_FILE_<NAME>` (upper-cased, non-alphanumerics → `_`), the file named by
`PROVENA_PASSPHRASE_FILE`, `PROVENA_PASSPHRASE`, a terminal prompt. Files must not be readable by
group or others. With none of them and no terminal: exit 4, `E_NO_PASSPHRASE`. The hub key uses the
same rules with `PROVENA_HUB_PASSPHRASE`, except that its file may be readable by others (container
secrets are mounted 0444). Servers (`hub serve`, `ui`, `capture`) are not commands with a result:
they print their start line to stderr and run until stopped.

## 4. Idempotency

Retrying a command after a timeout or a kill must be safe:

| Command | Repeat with the same input |
|---|---|
| `add`, `plan` | unchanged content recorded by the same agent → no new entry, exit 0, `unchanged: true` on that entry (`data.entries[i]`, `data.entry`); `--force` records again |
| `reveal`, `publish` | already done → exit 0, `data.unchanged: true` |
| `challenge submit` | the same predictions → resumes the earlier submission (same grant), exit 0 |
| `checkout`, `open` | identical file present → exit 0 |
| `challenge close` | already closed → re-writes the truth bundle, exit 0 |
| `push`, `pull` | always safe; resume where they stopped |

With `--json-lines`, batch commands (`add a b c`) print one JSON line per completed item as it is
recorded, then the envelope.

## 5. References

An entry may be named by its full hash, a unique hex prefix of at least 6 characters, `#N` (log
position), or a path. Paths resolve from the ledger as well as the local `tracked.json`
(a clone that has not checked a file out can still name it).

## 6. Stability

Fields are only added within `provena-cli/1`; a removal or a change of meaning bumps the schema.
`verify --json` keeps its own schema identifier (`provena-verify/1`) inside `data`.
