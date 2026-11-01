"""Commands that talk to a hub, and running one."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from provena.cli import output
from provena.cli.common import EXIT_STATE, CliError, _agent_name, _hub_client, _load_agent
from provena.store.home import Home
from provena.store.repo import Repo
from provena.store.secrets import read_secret


def cmd_remote(args):
    from provena.sdk import sync

    repo = Repo.find()
    if args.rehome:
        primary = repo.config.get("primary")
        if not primary:
            raise CliError("--rehome is for checkouts cloned from a mirror")
        card = sync.rehome(repo, sync.make_client(primary["url"], _load_agent(args, repo)))
        print(f"now using the primary hub {primary['url']} (log key {card['id']}); the "
              f"mirror stays a read-only fallback")
        return
    if not args.url:
        raise CliError("usage: provena remote URL  (or --rehome)")
    card = sync.pin_hub(repo, args.url, sync.make_client(args.url, None))
    Home().set_trust("logs", card["id"])
    print(f"hub {args.url} pinned to log key {card['id']} (added to your trusted logs)")
    output.data(hub=args.url, log_key=card["id"])

def _warn_sync(repo, r) -> None:
    if r.blobs_missing:
        print(f"note: {r.blobs_missing} files are not on the hub yet (their author may still "
              "be uploading); `provena pull` again later", file=sys.stderr)


def cmd_push(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    sync, client = _hub_client(repo, agent)
    r = sync.push(repo, client, agent=agent)
    _warn_sync(repo, r)
    output.data(pushed=r.pushed, blobs_up=r.blobs_up, pulled=r.pulled, head=r.head,
                stranded=r.stranded)
    print(f"pushed {r.pushed} entries, {r.blobs_up} blobs (pulled {r.pulled}); hub head "
          f"size={r.head['size']} root={r.head['root'][:16]}… verified")
    return _stranded_exit(repo, r)


def _stranded_exit(repo, r) -> int:
    """Entries that no longer apply on the hub's log were not pushed: say so, exit 5. Paths
    with two concurrent versions need a choice: also exit 5."""
    if r.rotated:
        output.data(log_key=r.rotated)
        home = Home()
        # trust moves forward with the hand-over (ADR 0010), as it does in the verifiers
        followed = any(c["id"] in home.trust()["logs"]
                       for c in repo.config.get("hub_past_cards", []))
        if followed:
            home.set_trust("logs", r.rotated)
        output.warn("W_HUB_KEY_ROTATED", f"the hub handed its log key over to {r.rotated} "
                    "(signed by the key you pinned); this checkout now pins the new key"
                    + (", trusted as the successor of a key you trust" if followed else ""))
    conflicts = repo.config.get("conflicts", [])
    if not r.stranded and conflicts:
        output.data(conflicts=conflicts)
        for c in conflicts:
            print(f"provena: CONFLICT {c['path']}: yours {c['mine'][:12]}, theirs "
                  f"{c['theirs'][:12]} (by {c['author'][:16]}…); both are on the ledger — "
                  f"`provena resolve {c['path']} --keep <hash>`", file=sys.stderr)
        output.error("E_CONFLICT", f"{len(conflicts)} path(s) have two concurrent versions",
                     "provena resolve PATH --keep HASH")
        return EXIT_STATE
    if not r.stranded:
        return 0
    output.error("E_STRANDED", f"{r.stranded} entries were set aside and not pushed",
                 "provena stranded list; provena stranded redo")
    print(f"provena: {r.stranded} of your unpushed entries no longer apply on top of the "
          f"hub's log (e.g. a teammate rotated the project key or changed your role meanwhile) "
          f"and were NOT pushed; their files show as untracked in `provena status`. "
          f"`provena stranded list` shows them; `provena stranded redo` records their files "
          f"again", file=sys.stderr)
    return EXIT_STATE

def cmd_pull(args):
    repo = Repo.find()
    agent = _load_agent(args, repo)
    if args.source:
        from provena.sdk import sync

        r = sync.pull_mirror(repo, args.source, sync.make_client(args.source, agent),
                             agent=agent, trusted_logs=Home().trust()["logs"])
        print(f"read {r.pulled} entries, {r.blobs_down} blobs from mirror {args.source} "
              f"(head size {r.head['size']}, signed by its pinned key and consistent with your "
              "log); they stay provisional until `provena pull` from the primary confirms "
              "them, and are never pushed by you")
        return
    sync, client = _hub_client(repo, agent)
    r = sync.pull(repo, client, agent=agent)
    _warn_sync(repo, r)
    size = r.head.get("size", 0)
    print(f"pulled {r.pulled} entries, {r.blobs_down} blobs; hub head size={size} verified")
    output.data(pulled=r.pulled, blobs_down=r.blobs_down, blobs_missing=r.blobs_missing,
                head=r.head, stranded=r.stranded)
    return _stranded_exit(repo, r)

def cmd_mirror(args):
    from provena.sdk import sync

    repo = Repo.find()
    agent = _load_agent(args, repo)
    if not repo.config.get("hub"):
        raise CliError("set the project's primary hub first (`provena remote`)")
    r = sync.mirror(repo, args.url, sync.make_client(args.url, agent),
                    primary=sync.make_client(repo.config["hub"], agent), check_only=args.check)
    output.data(mirror=args.url, log_key=r["card"]["id"], size=r["size"],
                behind=r.get("behind"), pushed=r.get("pushed"), blobs_up=r.get("blobs_up"),
                consistent=True)
    if args.check:
        print(f"mirror {args.url} (log key {r['card']['id']}): {r['size']} entries, identical "
              f"to ours; {r['behind']} behind")
    else:
        print(f"mirrored {r['pushed']} entries, {r['blobs_up']} blobs to {args.url}; its head "
              f"(size {r['size']}) has the same root as ours")

def cmd_clone(args):
    from provena.sdk import sync

    agent = _load_agent(args)
    dest = Path(args.dir or args.project[:12]).resolve()
    repo, r = sync.clone(args.url, args.project, dest, _agent_name(args), agent,
                         sync.make_client(args.url, agent))
    print(f"cloned {r.pulled} entries, {r.blobs_down} blobs into {repo.root}")
    output.data(project=repo.state.project, path=str(repo.root), pulled=r.pulled,
                blobs_down=r.blobs_down, read_only=bool(repo.config.get("primary")))

def cmd_hub_serve(args):
    import uvicorn

    from provena.server.app import create_app, load_or_create_hub_key

    data = Path(args.data).resolve()
    data.mkdir(parents=True, exist_ok=True)
    lock = _lock_data_dir(data)  # noqa: F841 (held for the life of the process)
    # PROVENA_HUB_PASSPHRASE_FILE (e.g. a Docker secret), PROVENA_HUB_PASSPHRASE, or a prompt
    passphrase = read_secret("Hub key passphrase", env="PROVENA_HUB_PASSPHRASE", service=True)
    key, card = load_or_create_hub_key(data, passphrase, args.name)
    print(f"Provena Hub log key {card['id']} serving {data} on {args.host}:{args.port}",
          flush=True)  # an ops agent tailing the log needs the key at start, not at exit
    provider = None
    if args.tsa:
        from provena.server.hub import RFC3161AnchorProvider

        provider = RFC3161AnchorProvider(args.tsa)
    from provena.server.limits import Limits

    blob_store = None
    if args.s3_bucket:
        from provena.server.blobstore import S3BlobStore

        blob_store = S3BlobStore(args.s3_bucket, prefix=args.s3_prefix,
                                 endpoint_url=args.s3_endpoint, spool_dir=data / "spool")
    database = os.environ.get("PROVENA_HUB_DATABASE_URL")  # DSNs carry passwords: env only
    creators = Path(args.creators).resolve() if args.creators else None
    if creators is not None and not creators.is_file():
        raise CliError(f"creators file {creators} does not exist")
    policy = Path(args.policy).resolve() if args.policy else None
    if policy is not None:
        from provena.server.policy import PolicyError, parse

        if creators is not None:
            raise CliError("use --policy or --creators, not both (the policy lists org agents)")
        try:
            parse(json.loads(policy.read_text()))
        except (OSError, ValueError, PolicyError) as exc:
            raise CliError(f"policy file {policy}: {exc}") from None
    unlisted_file = Path(args.unlisted).resolve() if args.unlisted else None
    if unlisted_file is not None and not unlisted_file.is_file():
        raise CliError(f"unlisted file {unlisted_file} does not exist")
    from provena.server.hub import parse_project_ids

    unlisted = parse_project_ids(os.environ.get("PROVENA_HUB_UNLISTED_PROJECTS", ""))
    if creators is None and policy is None and args.host not in ("127.0.0.1", "localhost", "::1"):
        print("note: anyone who can reach this hub can create projects; restrict it with "
              "--policy FILE (orgs and quotas) or --creators FILE", file=sys.stderr)
    app = create_app(data, key, card, anchor_provider=provider, blob_store=blob_store,
                     database=database, reanchor_days=args.reanchor_days,
                     anchor_interval=args.anchor_interval,
                     limits=Limits(writes_per_minute=args.writes_per_minute,
                                   max_projects=args.max_projects),
                     trust_forwarded_for=args.behind_proxy, creators_file=creators,
                     projects_per_creator=args.projects_per_creator, base_path=args.base_path,
                     policy_file=policy, unlisted=unlisted, unlisted_file=unlisted_file)
    uvicorn.run(app, host=args.host, port=args.port)

def _lock_data_dir(data: Path):
    """One hub process per data directory: two would sequence the same logs concurrently."""
    try:
        import fcntl
    except ImportError:
        return None
    f = open(data / "hub.lock", "a+")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        f.close()
        raise CliError(f"another hub is already serving {data}") from None
    return f


def cmd_hub_rotate_key(args):
    """Hand the hub's log key over to a fresh one (ADR 0010). The hub must be stopped."""
    from provena.server.app import rotate_hub_key

    data = Path(args.data).resolve()
    if not (data / "hub.key.json").exists():
        raise CliError(f"no hub key in {data}", error="E_NOT_FOUND")
    lock = _lock_data_dir(data)  # noqa: F841 (refuses while a hub serves this directory)
    if not args.yes:
        print("this replaces the hub's log key: the old key signs a hand-over to a new one; "
              "clients and witnesses that pinned the old key follow it on their next sync. "
              "Re-run with --yes")
        raise CliError("rotating the hub log key needs --yes", error="E_CONFIRM",
                       hint="provena hub rotate-key --data DIR --yes")
    passphrase = read_secret("Hub key passphrase", env="PROVENA_HUB_PASSPHRASE", service=True)
    stmt = rotate_hub_key(data, passphrase)
    old, new = stmt["old"]["id"], stmt["new"]["id"]
    retired = data / f"hub.key.retired-{old}.json"
    output.data(old=old, new=new, time=stmt["time"], retired_key=str(retired))
    print(f"log key {old} handed over to {new}. Start the hub again; once clients and "
          f"witnesses have synced, shred {retired}")


def cmd_hub_api_key(args):
    """A new API key for an org: the key is shown once; the hub's policy keeps only its hash."""
    import secrets

    from provena.server.policy import NAME_RE, hash_key

    if not NAME_RE.fullmatch(args.org):
        raise CliError(f"org names are lowercase letters, digits, . _ - (not {args.org!r})")
    key = f"pvk_{args.org}_{secrets.token_urlsafe(32)}"
    output.data(org=args.org, api_key=key, policy_entry=f"sha256:{hash_key(key)}")
    print(f"API key for org {args.org} (shown once; give it to the org, keep no copy):\n  {key}\n"
          f'add to orgs.{args.org}.api_keys in the policy file:\n  "sha256:{hash_key(key)}"')


def cmd_hub_anchor(args):
    from provena.sdk import sync

    result = sync.make_client(args.url, None).run_anchor()
    anchor = result.get("anchor")
    output.data(anchor=anchor)
    print(f"anchored root {anchor['digest'][:16]}… via {anchor['provider']}"
          if anchor else "nothing new to anchor")

def cmd_witness(args):
    from provena.client.witness import Witness
    from provena.sdk import sync

    name = _agent_name(args)
    agent = _load_agent(args)
    state = Path(args.state or Home().path / "witness" / f"{name}.json")
    state.parent.mkdir(parents=True, exist_ok=True)
    witness = Witness(agent, Home().card(name), state)
    client = sync.make_client(args.url, None)
    cosigned = []
    for pid in args.projects:
        c = witness.observe(client, pid)
        print(f"cosigned {pid[:12]} head {c['head'][:16]}…")
        cosigned.append({"project": pid, "head": c["head"], "size": c.get("size")})
    output.data(hub=args.url, witness=agent.id, cosigned=cosigned)
