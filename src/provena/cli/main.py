"""`provena` command line interface."""

from __future__ import annotations

import argparse
import json
import sys

from provena import __version__
from provena.cli.common import (  # noqa: F401 (CliError etc. are API used by tests)
    ERROR_EXITS,
    EXIT_AUTH,
    EXIT_INTEGRITY,
    EXIT_NETWORK,
    EXIT_STATE,
    EXIT_USAGE,
    CliError,
    _bibtex_safe,
    _safe_relpath,
)
from provena.cli.hubcmds import (
    cmd_clone,
    cmd_hub_anchor,
    cmd_hub_api_key,
    cmd_hub_rotate_key,
    cmd_hub_serve,
    cmd_mirror,
    cmd_pull,
    cmd_push,
    cmd_remote,
    cmd_witness,
)
from provena.cli.ledger import (
    cmd_add,
    cmd_attest,
    cmd_capture,
    cmd_card,
    cmd_cat,
    cmd_checkout,
    cmd_config,
    cmd_init,
    cmd_keygen,
    cmd_lineage,
    cmd_log,
    cmd_member,
    cmd_meta,
    cmd_plan,
    cmd_redact,
    cmd_rerun,
    cmd_resolve,
    cmd_reveal,
    cmd_rotate,
    cmd_run,
    cmd_show,
    cmd_status,
    cmd_stranded,
    cmd_succeed,
    cmd_ui,
)
from provena.cli.proofs import (
    cmd_checkpoint,
    cmd_cite,
    cmd_doctor,
    cmd_export,
    cmd_identity,
    cmd_open,
    cmd_prove,
    cmd_publish,
    cmd_seal,
    cmd_share,
    cmd_trust,
    cmd_unseal,
    cmd_verify,
)
from provena.core.challenge import ChallengeError
from provena.core.errors import DecryptionError, ProvenaError
from provena.core.verify import LEVELS
from provena.sdk.sync import SyncIncomplete, SyncIntegrityError
from provena.store.repo import RefNotFound, RepoCorrupt, RepoError
from provena.store.secrets import SecretUnavailable


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="provena", description="Verifiable ledger of experiments.")
    p.add_argument("--version", action="version", version=f"provena {__version__}")
    p.add_argument("--agent", help="agent name under $PROVENA_HOME (default: repo's agent)")
    p.add_argument("--json", action="store_true", dest="envelope",
                   help="machine output: one JSON envelope on stdout, all text on stderr "
                   "(docs/spec/cli-contract-v1.md)")
    p.add_argument("--json-lines", action="store_true", dest="json_lines",
                   help="like --json, plus one JSON line per item as batch commands record it")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="create an agent identity")
    s.add_argument("--name", help="agent name (default: --agent or 'default')")
    s.add_argument("--kind", default="person",
                   choices=["person", "instrument", "software", "org"])
    s.add_argument("--display", default="", help="display name on the agent card")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("card", help="print your agent card (share it to be added to projects)")
    s.set_defaults(fn=cmd_card)

    s = sub.add_parser("init", help="create a project ledger in a directory")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--name")
    s.add_argument("--public", action="store_true")
    s.add_argument("--witnesses", type=int, default=0)
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("add", help="register data files (encrypted + committed)")
    s.add_argument("files", nargs="+")
    s.add_argument("--media-type")
    s.add_argument("--force", action="store_true",
                   help="record again even if the content is unchanged")
    s.set_defaults(fn=cmd_add)

    s = sub.add_parser("plan", help="preregister a plan/protocol (commitment only)")
    s.add_argument("file")
    s.add_argument("--title")
    s.add_argument("--force", action="store_true",
                   help="preregister again even if the content is unchanged")
    s.set_defaults(fn=cmd_plan)

    s = sub.add_parser("run", help="run a command and record it as an activity")
    s.add_argument("--plan")
    s.add_argument("--used", action="append", default=[])
    s.add_argument("--out", action="append", default=[])
    s.add_argument("--no-auto-inputs", action="store_true",
                   help="do not record repository files named on the command line as inputs")
    s.add_argument("--external", action="append", default=[],
                   help="PROJECT:ENTRY of an input that lives in another project")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("rerun", help="re-execute a recorded run and compare outputs")
    s.add_argument("ref", help="activity entry")
    s.add_argument("--yes", action="store_true", help="really execute the recorded command")
    s.add_argument("--attest", action="store_true", help="record a replicate attestation")
    s.add_argument("--workdir", help="workspace directory (default: a new temp dir)")
    s.add_argument("--timeout", type=float, default=None)
    s.add_argument("--sandbox", choices=["off", "auto", "require"], default="off",
                   help="run the command without network or access to your keys, home "
                        "directory or repository (bwrap / sandbox-exec); off by default "
                        "because real analyses often need tools under your home directory")
    s.set_defaults(fn=cmd_rerun)

    s = sub.add_parser("log", help="list ledger entries")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-decrypt", action="store_true")
    s.set_defaults(fn=cmd_log)

    s = sub.add_parser("show", help="show one entry")
    s.add_argument("ref")
    s.add_argument("--no-decrypt", action="store_true")
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("cat", help="decrypt content of an entry")
    s.add_argument("ref")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_cat)

    s = sub.add_parser("status", help="compare tracked files to the ledger")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("doctor", help="check keys, ledger, hub, trust and evidence")
    s.add_argument("--verifier", action="store_true",
                   help="check only what verifying bundles needs (no key, no repository)")
    s.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("verify", help="verify the local ledger, or a .pvb proof bundle")
    s.add_argument("bundle", nargs="?", help="proof bundle file (omit to verify the repo)")
    s.add_argument("--badge", metavar="SVG", help="also write a status badge (trust level "
                   "reached, or invalid) for a README or a leaderboard")
    s.add_argument("--no-decrypt", action="store_true")
    s.add_argument("--trust-log", action="append", default=[],
                   help="also trust log ID for this run (see `provena trust`)")
    s.add_argument("--trust-witness", action="append", default=[],
                   help="also trust witness ID for this run")
    s.add_argument("--trust-org", action="append", default=[],
                   help="also trust identity credentials issued by this org agent")
    s.add_argument("--trust-tsa", action="append", default=[],
                   help="also trust the TSA certificate with this SHA-256 fingerprint")
    s.add_argument("--require", choices=list(LEVELS),
                   help="exit non-zero unless the bundle reaches this trust level")
    s.add_argument("--before", help="exit non-zero unless every target has trusted evidence "
                                    "of existing before this ISO time (e.g. 2026-11-01T00:00Z)")
    s.add_argument("--json", action="store_true",
                   help="print the verdict as JSON (format provena-verify/1); same exit codes")
    s.add_argument("--content", action="append", default=[],
                   help="REF=PATH: check a file against the commitment of entry REF")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("checkpoint", help="sign the current local log head (self-sequenced)")
    s.set_defaults(fn=cmd_checkpoint)

    s = sub.add_parser("prove", help="export a proof bundle for entries")
    s.add_argument("refs", nargs="+")
    s.add_argument("-o", "--output", required=True)
    s.add_argument("--full", action="store_true", help="include the whole log (proves authz)")
    s.add_argument("--no-lineage", action="store_true")
    s.add_argument("--open", action="append", default=[], help="disclose commitment of REF")
    s.add_argument("--embed", action="store_true", help="embed plaintext of opened entries")
    s.add_argument("--external", action="append", default=[],
                   help="bundle (.pvb) of another project proving an input you cited")
    s.set_defaults(fn=cmd_prove)

    s = sub.add_parser("remote", help="set and pin the project's hub")
    s.add_argument("url", nargs="?")
    s.add_argument("--rehome", action="store_true",
                   help="a checkout cloned from a mirror: switch to the project's primary hub")
    s.set_defaults(fn=cmd_remote)

    s = sub.add_parser("stranded", help="entries a sync set aside (they no longer applied)")
    s.add_argument("action", choices=["list", "redo"])
    s.set_defaults(fn=cmd_stranded)

    s = sub.add_parser("trust", help="manage the logs, witnesses and TSAs you trust")
    s.add_argument("action", choices=["list", "add", "remove", "defaults"])
    s.add_argument("kind", nargs="?", choices=["log", "witness", "tsa", "org", "on", "off"],
                   help="for `defaults`: on|off (built-in trust shipped with this release)")
    s.add_argument("value", nargs="?", help="agent id, or TSA certificate SHA-256 fingerprint")
    s.add_argument("--from-url", metavar="URL",
                   help="log: print the key a hub signs with (add it with --yes)")
    s.add_argument("--yes", action="store_true")
    s.set_defaults(fn=cmd_trust)

    s = sub.add_parser("mcp", help="run an MCP server (stdio) for an AI agent: it records, "
                       "proves and verifies in this project")
    s.add_argument("--project", default=".", help="the project directory (default: here)")
    s.add_argument("--passphrase-file", help="file (mode 600) holding the agent key's "
                   "passphrase, for hosts that do not pass environment variables")
    s.set_defaults(fn=lambda a: __import__("provena.adapters.mcp", fromlist=["main"]).main(
        a.project, a.agent, a.passphrase_file))

    s = sub.add_parser("resolve", help="pick which of two concurrent versions of a path "
                       "this checkout tracks")
    s.add_argument("path")
    s.add_argument("--keep", required=True, help="the entry hash (or prefix) to keep")
    s.add_argument("--force", action="store_true",
                   help="overwrite local changes to the file that are not on the ledger")
    s.set_defaults(fn=cmd_resolve)

    s = sub.add_parser("config", help="this checkout's settings")
    s.add_argument("key", choices=["agent"])
    s.add_argument("value", nargs="?", help="set it (omit to print)")
    s.set_defaults(fn=cmd_config)

    s = sub.add_parser("push", help="send local entries and blobs to the hub")
    s.set_defaults(fn=cmd_push)

    s = sub.add_parser("pull", help="fetch new entries and blobs from the hub")
    s.add_argument("--from", dest="source", metavar="MIRROR_URL",
                   help="read from a mirror while the primary hub is unreachable")
    s.set_defaults(fn=cmd_pull)

    s = sub.add_parser("clone", help="clone a project from a hub")
    s.add_argument("url")
    s.add_argument("project")
    s.add_argument("dir", nargs="?")
    s.set_defaults(fn=cmd_clone)

    s = sub.add_parser("mirror", help="replicate this project's sequenced log to a second hub")
    s.add_argument("url")
    s.add_argument("--check", action="store_true",
                   help="only compare the mirror's head with our log (fork check)")
    s.set_defaults(fn=cmd_mirror)

    s = sub.add_parser("hub", help="run a Provena Hub")
    hub_sub = s.add_subparsers(dest="hub_cmd", required=True)
    h = hub_sub.add_parser("serve")
    h.add_argument("--data", default="./hub-data")
    h.add_argument("--host", default="127.0.0.1")
    h.add_argument("--port", type=int, default=8740)
    h.add_argument("--name", default="provena-hub")
    h.add_argument("--anchor-interval", type=float, default=600.0,
                   help="seconds between anchoring rounds (0 disables)")
    h.add_argument("--tsa", help="RFC 3161 TSA URL for anchoring (default: self-anchor)")
    h.add_argument("--reanchor-days", type=float, default=30.0,
                   help="re-stamp an unchanged root after this many days (0 disables)")
    h.add_argument("--writes-per-minute", type=float, default=120.0,
                   help="per-client write rate limit")
    h.add_argument("--max-projects", type=int, default=100_000)
    h.add_argument("--base-path", default="", metavar="/PREFIX",
                   help="served under a path prefix by a reverse proxy that strips it "
                   "(e.g. /provena): page links carry it")
    h.add_argument("--creators", metavar="FILE",
                   help="only these agent ids (one per line, # comments) may create projects; "
                   "re-read on every creation, so edit it without restarting")
    h.add_argument("--projects-per-creator", type=int,
                   help="cap on projects created by one agent id")
    h.add_argument("--policy", metavar="FILE",
                   help="orgs, their agents, project and storage quotas and API keys (JSON, "
                   "re-read when it changes; see docs/DEPLOY.md)")
    h.add_argument("--s3-bucket", help="store ciphertext in this S3-compatible bucket "
                   "(credentials from the standard AWS environment/config)")
    h.add_argument("--s3-prefix", default="provena/")
    h.add_argument("--s3-endpoint", help="e.g. https://sgp1.digitaloceanspaces.com")
    h.add_argument("--behind-proxy", action="store_true",
                   help="take the client address from X-Forwarded-For (only behind your proxy)")
    h.set_defaults(fn=cmd_hub_serve)
    h = hub_sub.add_parser("rotate-key", help="hand the hub's log key over to a new key "
                           "(hub stopped; clients and witnesses follow the signed hand-over)")
    h.add_argument("--data", default="./hub-data")
    h.add_argument("--yes", action="store_true")
    h.set_defaults(fn=cmd_hub_rotate_key)
    h = hub_sub.add_parser("api-key", help="make an API key for an org (prints the key once "
                           "and the hash for the policy file)")
    h.add_argument("org")
    h.set_defaults(fn=cmd_hub_api_key)
    h = hub_sub.add_parser("anchor", help="ask a hub to anchor now")
    h.add_argument("url")
    h.set_defaults(fn=cmd_hub_anchor)

    s = sub.add_parser("witness", help="cosign a hub's heads after checking consistency")
    s.add_argument("url")
    s.add_argument("projects", nargs="+")
    s.add_argument("--state", help="witness state file (default under $PROVENA_HOME)")
    s.set_defaults(fn=cmd_witness)

    s = sub.add_parser("capture", help="watch an instrument folder and register stable files")
    s.add_argument("dir")
    s.add_argument("--pattern", default="*")
    s.add_argument("--interval", type=float, default=2.0)
    s.add_argument("--push-every", type=int, default=0, help="push every N polls (0: never)")
    s.add_argument("--once", action="store_true", help="one stable scan, then exit")
    s.set_defaults(fn=cmd_capture)

    s = sub.add_parser("meta", help="show or edit the project card (title, license, tags)")
    s.add_argument("--title")
    s.add_argument("--description")
    s.add_argument("--license", help="e.g. CC-BY-4.0")
    s.add_argument("--tag", action="append", help="repeatable; replaces the tag list")
    s.set_defaults(fn=cmd_meta)

    s = sub.add_parser("cite", help="citation for an entry (text, bibtex or json)")
    s.add_argument("ref")
    s.add_argument("--format", choices=["text", "bibtex", "json"], default="text")
    s.set_defaults(fn=cmd_cite)

    from provena.cli import challenge

    challenge.add_parser(sub)

    s = sub.add_parser("lineage", help="show how an entry was produced")
    s.add_argument("ref")
    s.add_argument("--no-decrypt", action="store_true")
    s.set_defaults(fn=cmd_lineage)

    s = sub.add_parser("ui", help="browse this repository in your browser (local, read-only)")
    s.add_argument("--port", type=int, default=8741)
    s.set_defaults(fn=cmd_ui)

    s = sub.add_parser("identity", help="issue or attach org-signed identity credentials")
    s.add_argument("action", choices=["issue", "attach"])
    s.add_argument("target", help="issue: subject's agent card file; attach: credential file")
    s.add_argument("--name")
    s.add_argument("--affiliation")
    s.add_argument("--orcid")
    s.add_argument("--role")
    s.add_argument("--days", type=float, default=365)
    s.add_argument("-o", "--output", default="credential.json")
    s.set_defaults(fn=cmd_identity)

    s = sub.add_parser("export", help="export the ledger as W3C PROV-JSON or an RO-Crate, "
                       "or a step as an in-toto statement (DSSE)")
    s.add_argument("format", choices=["prov", "rocrate", "intoto"])
    s.add_argument("--step", help="intoto: the step (activity) to export")
    s.add_argument("-o", "--output")
    s.add_argument("--include-private", action="store_true",
                   help="include decrypted names/commands (you are publishing them)")
    s.add_argument("--metadata-only", action="store_true",
                   help="rocrate: describe files without writing their decrypted content")
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("member", help="manage project members")
    s.add_argument("action", choices=["list", "add", "rm", "role", "history"])
    s.add_argument("target", nargs="?",
                   help="card file (add) or agent id or unique prefix (rm/role/history)")
    s.add_argument("--role", default="contributor")
    s.add_argument("--history", action="store_true",
                   help="add: also share every earlier epoch key you can read (rules 2), so "
                   "the new member reads data recorded before they joined")
    s.set_defaults(fn=cmd_member)

    s = sub.add_parser("rotate", help="rotate the project key")
    s.set_defaults(fn=cmd_rotate)

    s = sub.add_parser("succeed", help="replace your key in this project with a new one "
                       "(planned key change; the old key must still be available)")
    s.add_argument("successor", help="local agent name (from `provena --agent NAME keygen`) "
                   "or the new key's card file")
    s.set_defaults(fn=cmd_succeed)

    s = sub.add_parser("reveal", help="open a commitment publicly")
    s.add_argument("ref")
    s.add_argument("--with-key", action="store_true", help="also publish the content key")
    s.add_argument("--with-name", action="store_true", help="also publish the file name")
    s.add_argument("--force", action="store_true",
                   help="disclose even though this project's challenge is still open (voids it)")
    s.set_defaults(fn=cmd_reveal)

    s = sub.add_parser("attest", help="review/replicate/endorse an entry")
    s.add_argument("ref")
    s.add_argument("--type", required=True,
                   choices=["review", "replicate", "calibration", "endorse", "dispute",
                            "capture", "operator"])
    s.add_argument("--verdict", choices=["pass", "fail", "inconclusive"])
    s.add_argument("--note")
    s.set_defaults(fn=cmd_attest)

    s = sub.add_parser("share", help="grant a non-member access to one entry (on the ledger)")
    s.add_argument("ref")
    s.add_argument("--to", required=True, help="recipient's agent card file")
    s.add_argument("-o", "--output")
    s.add_argument("--force", action="store_true",
                   help="disclose even though this project's challenge is still open (voids it)")
    s.set_defaults(fn=cmd_share)

    s = sub.add_parser("open", help="verify a bundle and decrypt what it grants or publishes")
    s.add_argument("bundle")
    s.add_argument("--hub", help="hub URL to fetch ciphertext from")
    s.add_argument("--blob", help="local ciphertext file instead of the hub")
    s.add_argument("-o", "--output", default=".")
    s.add_argument("--force", action="store_true", help="overwrite existing files")
    s.set_defaults(fn=cmd_open)

    s = sub.add_parser("seal", help="commit to a data package now, publish it after a date "
                       "(fresh datasets, priority dates)")
    s.add_argument("dir")
    s.add_argument("--reveal-after", required=True, help="ISO time with zone")
    s.set_defaults(fn=cmd_seal)
    s = sub.add_parser("unseal", help="publish a sealed package once its date has passed")
    s.add_argument("manifest", help="the DIR.seal.json written by `provena seal`")
    s.add_argument("--force", action="store_true", help="publish before the date")
    s.set_defaults(fn=cmd_unseal)

    s = sub.add_parser("publish", help="reveal with key + push: anyone can read and verify")
    s.add_argument("ref")
    s.add_argument("--keep-name-sealed", action="store_true",
                   help="publish content but not the file name")
    s.add_argument("--force", action="store_true",
                   help="disclose even though this project's challenge is still open (voids it)")
    s.set_defaults(fn=cmd_publish)

    s = sub.add_parser("checkout", help="decrypt registered files into the working tree")
    s.add_argument("refs", nargs="*")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_checkout)

    s = sub.add_parser("redact", help="crypto-shred content; its existence stays on the ledger")
    s.add_argument("ref")
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_redact)
    return p

def _network_errors() -> tuple:
    try:
        import httpx
    except ImportError:  # installed without [client]: no network commands work anyway
        return ()
    return (httpx.HTTPError,)


def _global_options(raw: list[str]) -> list[str]:
    """The options before the subcommand (`provena --agent x --json add …`)."""
    out, skip = [], False
    for tok in raw:
        if skip:
            skip = False
            continue
        if not tok.startswith("-"):
            break
        out.append(tok)
        skip = tok == "--agent"
    return out


def main(argv: list[str] | None = None) -> int:
    from provena.cli import output

    raw = sys.argv[1:] if argv is None else argv
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        if exc.code and {"--json", "--json-lines"} & set(_global_options(raw)):
            output.start(True)
            output.emit(next((a for a in raw if not a.startswith("-")), ""), 2,
                        {"code": "E_USAGE", "message": "invalid arguments (see stderr)",
                         "hint": "provena <command> --help"}, sys.stdout)
            return 2
        raise
    if getattr(args, "command", None) and args.command[:1] == ["--"]:
        args.command = args.command[1:]
    real_stdout = sys.stdout
    args.envelope = args.envelope or args.json_lines
    output.start(args.envelope, args.json_lines, real_stdout)
    if args.envelope:  # every human line to stderr; stdout carries the envelope only
        sys.stdout = sys.stderr
    try:
        code, error = _dispatch(args)
    finally:
        sys.stdout = real_stdout
    if args.envelope:
        sub = getattr(args, "challenge_cmd", None) or getattr(args, "hub_cmd", None) or \
            (args.action if args.cmd in ("member", "trust", "stranded") else None)
        output.emit(f"{args.cmd} {sub}" if sub else args.cmd or "", code, error, real_stdout)
    return code


def _fail(code: int, message: str, prefix: str = "error", err: str | None = None,
          hint: str | None = None) -> tuple[int, dict]:
    from provena.cli.output import DEFAULT_ERRORS

    print(f"provena: {prefix}: {message}", file=sys.stderr)
    return code, {"code": err or DEFAULT_ERRORS.get(code, "E_ERROR"), "message": message,
                  "hint": hint}


def _dispatch(args) -> tuple[int, dict | None]:
    from provena.cli import output
    from provena.client.hub import HubError

    try:
        code = args.fn(args) or 0
        return code, (output.pending_error() if code else None)
    except CliError as exc:
        return _fail(exc.code, str(exc), err=exc.error, hint=exc.hint)
    except ChallengeError as exc:  # a broken challenge rule: E_VOID, E_LATE, … or bad input
        return _fail(ERROR_EXITS.get(exc.error, EXIT_USAGE), str(exc), err=exc.error,
                     hint=exc.hint)
    except RepoCorrupt as exc:
        return _fail(EXIT_INTEGRITY, str(exc), err="E_CORRUPT",
                     hint="provena verify; or clone again from the hub")
    except RefNotFound as exc:
        return _fail(EXIT_USAGE, str(exc), err="E_NOT_FOUND", hint="provena --json log")
    except DecryptionError as exc:  # a key was unlocked: damaged ciphertext, not a passphrase
        return _fail(EXIT_INTEGRITY, f"stored ciphertext is damaged: {exc}", err="E_CORRUPT",
                     hint="provena pull (fetches a good copy from the hub)")
    except SyncIntegrityError as exc:
        return _fail(EXIT_INTEGRITY, str(exc), "INTEGRITY", err=exc.error)
    except SyncIncomplete as exc:
        return _fail(EXIT_STATE, str(exc), "incomplete", err=exc.error)
    except SecretUnavailable as exc:
        return _fail(EXIT_AUTH, str(exc), err="E_NO_PASSPHRASE")
    except HubError as exc:
        code, err = {401: (EXIT_AUTH, "E_FORBIDDEN"), 403: (EXIT_AUTH, "E_FORBIDDEN"),
                     404: (EXIT_USAGE, "E_NOT_FOUND"), 409: (EXIT_STATE, "E_CONFLICT"),
                     429: (EXIT_NETWORK, "E_NETWORK")}.get(exc.status, (EXIT_USAGE, "E_HUB"))
        return _fail(code, str(exc), err=err)
    except (RepoError, ProvenaError, FileExistsError, FileNotFoundError) as exc:
        return _fail(EXIT_USAGE, str(exc), err="E_INPUT")
    except _network_errors() as exc:
        try:
            where = exc.request.url
        except (AttributeError, RuntimeError):  # httpx raises when no request is attached
            where = None
        return _fail(EXIT_NETWORK, f"{exc}" + (f" ({where})" if where else ""),
                     "network error")
    except json.JSONDecodeError as exc:
        return _fail(EXIT_INTEGRITY, f"a file is not valid JSON (corrupted or not a Provena "
                     f"file): {exc}", err="E_CORRUPT")
    except IsADirectoryError as exc:
        return _fail(EXIT_USAGE, f"{exc.filename} is a directory", err="E_INPUT")
    except PermissionError as exc:
        return _fail(EXIT_USAGE, f"permission denied: {exc.filename}", err="E_INPUT")
    except KeyboardInterrupt:
        return _fail(130, "interrupted (anything already recorded stays recorded; check "
                     "`provena status`)", "interrupted")

if __name__ == "__main__":
    sys.exit(main())
