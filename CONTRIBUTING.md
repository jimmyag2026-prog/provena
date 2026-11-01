# Contributing

## Dev setup

```bash
uv sync                    # Python 3.11+; Node >= 22 for the JS verifier parity tests
uv run ruff check .
uv run pytest -q
```

The import package is `provena`; the PyPI distribution is `provena-ledger`.

## Pull requests

- Work on a branch, open a PR, squash-merge; `main` takes no direct pushes.
- **Protocol changes need an ADR first** (`docs/adr/`): anything that alters what a verifier
  accepts, the bundle format, the ledger rules or the hub API.
- **Both verifiers change together**: a rule implemented in Python (`provena.core`) is
  implemented in the JavaScript verifier (`src/provena/server/static/verifier.js`) in the same
  PR, with a parity test (`tests/test_js_verifier.py`, `tests/test_rules_single_source.py`,
  `tests/test_state_fuzz.py`; the shared rule tables are `docs/spec/rules.json`).
- **Every bug fix ships with a regression test that fails on the old code.**
- Keep `CHANGELOG.md` current (Keep a Changelog format, SemVer).
- Never commit credentials, server addresses or personal data; CI and the hub read secrets from
  files and the environment only.

## Where things live

| What | Where |
|---|---|
| User guide (en / zh) | `docs/GUIDE.md`, `docs/GUIDE.zh.md` |
| Architecture, threat model, hub API, deployment | `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/API.md`, `docs/DEPLOY.md` |
| Specs (bundle, rules, CLI contract, predicates) | `docs/spec/` |
| Decisions | `docs/adr/` |
| Design drafts and reviews | `docs/design/` |
| Release notes | `docs/release/` |
| Integrations (MCP, Spark Research, the trial hub) | `docs/integrations/` |

## Licence

Contributions are accepted under the [Provena License](LICENSE); by opening a PR you agree that
your contribution is licensed under it.
