# Provena user guide

**Status: draft** · v0.x · the commands below are exercised by `examples/demo.sh`,
`examples/challenge_cli_demo.sh` and the test suite; kept in sync with [`GUIDE.zh.md`](GUIDE.zh.md)

Provena keeps a signed, append-only ledger of your experiment: every dataset, every protocol,
every processing step. Content is encrypted on your machine; anyone you choose can later verify
— offline, without trusting Provena — what existed, who produced it, in what order and no later
than when.

## 1. Concepts in one table

| Concept | What it is | Git / HF analogue |
|---|---|---|
| **agent** | your identity: an Ed25519 signing key + X25519 encryption key. Also instruments and AI agents. | SSH key |
| **project** | one append-only ledger (Merkle log), identified by the hash of its genesis entry | repository |
| **entity** | a registered data file: encrypted blob + salted commitment | committed file |
| **plan** | a preregistered protocol/hypothesis: commitment now, content revealed later | — |
| **activity** | a process step: which entities it used, which it generated, under which plan | commit message, but structured |
| **hub** | sequences entries, issues signed receipts and tree heads, stores ciphertext | GitHub / HF Hub |
| **proof bundle** (`.pvb`) | a self-contained file proving specific claims about entries | — |

## 2. Set up

```bash
pip install "provena[client]"       # add [server] to run a hub
provena keygen --display "Ada Lovelace"
```

The key lives in `~/.provena/agents/` (or `$PROVENA_HOME/agents/`) encrypted with your
passphrase. Without a terminal (agents, CI, services) put it in a file readable only by you and
set `PROVENA_PASSPHRASE_FILE` (or `PROVENA_PASSPHRASE_FILE_<AGENT>` per key); `PROVENA_PASSPHRASE`
also works but is visible to your other processes. Never pass it as an argument. A key created
while one of them is set gets that passphrase. `provena card > ada.card.json` writes the public card you
give to collaborators. Several identities on one machine: `provena --agent NAME …` (or
`keygen --name NAME`).

Programs and AI agents: put `--json` first (`provena --json add data.csv`). stdout then carries
exactly one JSON object with complete entry hashes and the exit code; all text goes to stderr.
The fields and exit codes are specified in `docs/spec/cli-contract-v1.md`. Re-running a command
after a timeout is safe: unchanged files are not recorded twice.

## 3. Record an experiment

```bash
mkdir binding-assay && cd binding-assay          # with protocol.md, raw/*.csv, fit.py in it
provena init --name binding-assay                # prints the project id
provena plan protocol.md                         # preregistration: only a commitment is public
provena add raw/plate1.csv raw/plate2.csv
provena run --plan protocol.md --used raw/ --out results/ -- python fit.py
provena log
```

`run` executes the command and records an activity whether it succeeds or fails — negative
results stay on the ledger. In projects created since ledger rules 2, every step shows publicly
whether it succeeded (`ok` / `failed`) and commits to its sealed details (command, exit code,
model, parameters); `provena reveal <step>` publishes those details and anyone can check them
against the commitment. `--used` takes files, directories or entries; repository files named
on the command line (`fit.py`) are recorded as inputs too, so the step can be re-run from the
ledger alone (`--no-auto-inputs` turns this off, e.g. for a config file you do not want in the
ledger). `--out results/` records the files the command created or changed there. A step that
declares no input and produces no output (a model call, a web search) is still recorded: its
stdout/stderr become a sealed transcript under `transcripts/`. `add` and `plan` take regular
files inside the project only (a symlink keeps its own name). Instruments and analysis code can do the same from Python:

```python
from provena import sdk
proj = sdk.open(".")
with proj.run("fit binding curve", plan="protocol.md", used=["raw/plate1.csv"]) as run:
    ...
    run.output("results/kd.json")
```

### Replicate a step

```bash
provena rerun <activity> --yes --attest      # rebuild inputs, re-execute, compare outputs
```

`rerun` prints the recorded command and its author before doing anything, and only executes with
`--yes`: the command comes from the ledger, so treat it like code from that collaborator.
Non-deterministic steps (random seeds, timestamps, GPU nondeterminism) show up as `DIFFERS`.
Add `--sandbox require` to run it without network or access to your keys, home directory or
repository (bubblewrap on Linux, `sandbox-exec` on macOS; unset `PROVENA_PASSPHRASE` first).

### In Jupyter

```python
%load_ext provena.sdk.ipython
```
```python
%%provena "fit binding curve" --used raw/plate1.csv --out results/kd.json --plan protocol.md
kd = fit(load("raw/plate1.csv")); save(kd, "results/kd.json")
```

The cell runs normally; its exact source is stored (encrypted) as an output of the step, so the
record shows which code produced the result. Cells that raise are recorded too.

### Browse it

```bash
provena ui        # prints http://127.0.0.1:8741/?t=<token>; read-only, decrypts locally
```

## 4. Collaborate through a hub

```bash
provena remote https://hub.example.org     # pins the hub's log key (trust on first use)
provena push                               # entries + ciphertext; every receipt verified
provena member add bob.card.json --role contributor    # Bob's `provena card` output
provena member list
# Bob (project id: printed by `provena init`, or ask Ada):
provena clone https://hub.example.org <project-id> && cd <dir> && provena checkout
```

Roles: `owner` > `maintainer` > `contributor` (writes data) > `reviewer` (attests) > `viewer`.
Removing a member rotates the project key; they keep what they could already read, nothing
new.

### A second hub (mirror)

```bash
provena mirror https://mirror.example.org          # entries + ciphertext sequenced so far
provena mirror --check https://mirror.example.org  # fork check: same root at its size?
```

Entries are signed by their authors, so any hub can hold the same log; the same entries in the same order give the same Merkle root. If the main hub is down, anyone can `provena clone` from the mirror (such a checkout is read-only: it knows the primary from the mirror and writes there after `provena remote --rehome`), and an existing checkout can
catch up with `provena pull --from https://mirror.example.org` (pin the mirror first with
`provena mirror --check` while the main hub is up). Entries read this way stay provisional: the
next `pull` from the main hub keeps only what it confirms, and you never push them. A mirror whose head differs from your log at the same size is evidence that one of the hubs forked. A witness pointed at both hubs (same state file) checks this continuously and refuses to cosign either side of a fork. Re-run `provena mirror` after a redaction: the mirror deletes the ciphertext when the redaction reaches it.

### When a sync cannot finish

`push` and `pull` never report success with work left. Exit codes: 3 the hub is unreachable (a
rate limit is waited out by itself); 5 something is left to do — the last push was cut short
(`status` says so; push again), or some of your unpushed entries no longer apply on top of the
hub's log, e.g. after a teammate rotated the project key (they are set aside, their files show as
untracked; `provena stranded list`, then `provena stranded redo` records them again); 6 the hub
contradicts what you hold — its log key changed (nothing is written) or it rolled back to fewer
entries than you have receipts for (keep your checkout; tell the operator). Two members recording the same path at the same time is a conflict (exit 5): both
versions stay on the ledger; `provena resolve PATH --keep HASH` picks the one your checkout uses.

### Key recovery

Your agent key is the only way to decrypt project data you can read. Set up recovery once:

```bash
provena --agent recovery keygen --display "Ada (recovery)"   # long passphrase (unset
                                                              # PROVENA_PASSPHRASE); keep the
                                                              # keyfile offline (USB / paper)
provena member add ~/.provena/agents/recovery.card.json --role owner --history
```

`--history` also hands the recovery key every earlier epoch key you hold, so it reads data
recorded before it was added (ledger rules 2; `provena member history <id>` does it later for
someone added without it). If a device is lost: create a new key on the new device, then with the
recovery key add it — with its history — and remove the lost one (removal rotates the project key,
so the lost key reads nothing new):

```bash
provena --agent laptop2 keygen --display "Ada (laptop 2)"
provena --agent recovery member add ~/.provena/agents/laptop2.card.json --role owner --history
provena member list                                  # ids; a unique prefix is enough below
provena --agent recovery member rm <lost-agent-id>
provena config agent laptop2                         # this checkout now signs with the new key
```

**Several devices.** One key per device, each a member (with `--history`), all bound to you by an
organization credential if you have one (`provena identity`). Keys are never copied between
machines: a key used on two machines at once forks its own chain of entries.

For a planned key change (old key still available) use key succession, once per project; the
successor keeps the role and every epoch key, and the old key becomes inactive:

```bash
provena --agent laptop2 keygen --display "Ada (laptop 2)"
provena succeed laptop2          # or a card file of a key created elsewhere
```

## 5. Prove things

```bash
provena prove results/kd.json --open results/kd.json -o kd.pvb     # selective (minimal disclosure)
provena prove results/kd.json --full -o kd-full.pvb               # whole log: proves authorization too
provena verify kd.pvb --trust-log <hub-log-id> --content <entry>=results/kd.json
```

The verifier prints only facts it re-derived itself, then a **trust level**. `VALID` means the
cryptography checks out; the level depends only on what *you* trust (`provena trust list`):

| Level | Meaning |
|---|---|
| `unverified` | valid, but signed by a log you don't trust: order and times are claims |
| `self-sequenced` | signed by a project member; times are the author's claim |
| `log-sequenced` | ordered and timed by a hub you trust (`provena remote` trusts the hub you pin) |
| `witnessed` | a witness you trust confirmed that hub did not fork |
| `anchored` | a time-stamp authority you trust dated the log head |

```bash
provena trust add witness pv1a...                 # an independent witness's full id
provena trust add tsa <64-hex fingerprint>        # TSA cert fingerprint, shown in verify notes
provena verify kd.pvb --json             # machine-readable verdict (same exit codes)
provena verify kd.pvb --require anchored          # non-zero exit below that level (for CI)
provena verify kd.pvb --before 2026-11-01T00:00Z  # every target provably existed before then
```

`--before` counts only *trusted* time evidence: the head of a log you trust, the signed receipt
the hub issued when it sequenced the entry, or a time-stamp from a TSA you trust. With `--json`,
`accepted` is true only if the bundle is valid *and* every `--require` / `--before` check passed.

A witness is anyone independent who creates a key once (`provena --agent witness keygen`) and
then runs, e.g. from cron, `provena --agent witness witness https://hub.example.org <project-id>`;
it cosigns heads only if they extend what it saw before. Cosignatures live on the hub: run
`provena pull` (or `push`) before `prove` so your bundle carries them and verifies `witnessed`.

Reviewers without Provena installed can drop the `.pvb` onto any hub's front page; it is
verified in the browser.

### Who is behind a key

Keys are pseudonymous. An institution can vouch for its people with an `org` agent:

```bash
provena --agent uni keygen --kind org --display "Example University"      # the institution
provena --agent uni identity issue ada.card.json --name "Ada Lovelace" \
    --affiliation "Dept. of Chemistry" --orcid 0000-0002-1825-0097 -o ada.cred.json
provena identity attach ada.cred.json        # in the project: bundles now carry it
provena trust add org <university agent id>  # readers decide whose word counts
```

A credential covers entries signed while it was valid (from its issue time): entries recorded
before it was issued are reported with "not valid at the time in question".

## 6. Share, publish, withdraw

| Goal | Command | What becomes public |
|---|---|---|
| one reviewer reads one file | `provena share F --to rev.card.json` | a `grant` entry (who got access to what) |
| prove the protocol came first | `provena reveal protocol.md` | the commitment opening (salt + hash) |
| publish data | `provena publish F` | the content key and the file name: anyone can fetch and decrypt |
| withdraw consent | `provena redact F --reason consent-withdrawn` | that it was redacted; ciphertext deleted locally and (pushed at once) on the hub; delete your working copy yourself |
| cite a result | `provena cite F --format bibtex` | — |
| hand over a package | `provena export rocrate -o crate/` | RO-Crate + proof bundle (holds decrypted files; `--metadata-only` leaves them out) |

`reveal`, `redact`, `share` and membership changes are pushed immediately when a hub is
configured.

### Use another lab's data

```bash
provena open their-dataset.pvb --hub https://hub.example.org   # verify, decrypt what it shares
provena run --external <their-project>:<their-entry> --out results/ -- python analyze.py
provena push                                                    # hub timing for the new step
provena prove results/x.csv --external their-dataset.pvb -o x.pvb
```

`--external` takes the full 64-character project id and entry hash (`provena show` prints them).

The verifier checks their bundle with the same trust settings and reports "used entry … of
project … (that project's evidence: log-sequenced)". A full preregistered, blinded challenge
built this way is in `examples/challenge_demo.sh`.

### Run a challenge (experimental)

Every party first runs `provena init` (the organizer: `init --public`) and `provena remote URL`
in its own project; the commands below refuse to run without a hub, because on-time status comes
only from hub receipts. `examples/challenge_cli_demo.sh` runs the whole flow.

```bash
# organizer: truth committed, protocol + targets + scorer public
provena challenge init --title "RNA binders" --truth truth.csv --targets targets.csv \
    --score score.py --deadline 2026-12-01T00:00Z --team <agent-id>:<project-id> -o challenge.pvb
# each team, from its registered project
provena challenge submit challenge.pvb --predictions pred.csv --evaluator eval.card.json -o team1.pvb
#   exit 0 = ON TIME, 7 = LATE; a second submit is refused. Do not write to this project again
#   before the deadline (a bundle must cover everything sequenced before it)
# organizer, after the deadline
provena challenge close -o truth.pvb
# evaluator
provena challenge score challenge.pvb --truth truth.pvb --submission team1.pvb \
    --submission team2.pvb --hub URL --yes -o leaderboard.pvb
# anyone (no key needed); a team can add --submission its-own.pvb to check it was not left out
provena challenge audit leaderboard.pvb --challenge challenge.pvb --hub URL
```

The scoring program is run as `python score.py PRED_FILE...` in a work directory holding
`truth.csv`, and must write `scores.json` mapping each prediction path to a number. It runs
sandboxed where bubblewrap (Linux) or `sandbox-exec` (macOS) exist: no network, no access to
your Provena keys, your home directory or your repository, writes only to its work directory (`--sandbox require|off`). Unset `PROVENA_PASSPHRASE` and type the passphrase when scoring: on macOS any program you run can read other processes' environments.

Register teams as `--team AGENT_ID:PROJECT_ID` (each team's one submission project); without a list anyone may enter, and one person can enter with several keys. Submit from a project used only for this challenge: the leaderboard attaches each team's full bundle, whose contents stay encrypted but whose log structure becomes public. `close` works only after the deadline; a truth disclosed earlier voids the challenge. The evaluator publishes the leaderboard; `audit` needs no key and re-derives the inputs, the rules and every row's on-time status from the attached proofs — only the scores themselves remain the evaluator's claim.

## 7. What Provena does not prove

That the data reflects reality. It proves integrity, authorship, order and time of
*records*. Signing at the instrument (an `instrument` agent key on the device) moves the
signature closer to the measurement; it does not make a dishonest lab honest.
