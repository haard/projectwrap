# AGENTS.md

## Project

**pwrap** (package: `projectwrap`) — a CLI tool that wraps project shell
environments in [bubblewrap](https://github.com/containers/bubblewrap)
sandboxes. It limits the blast radius of supply chain attacks by isolating
each project's filesystem, environment, and optionally encrypting secrets
at rest with [gocryptfs](https://nuetzlich.net/gocryptfs/).

- **Language:** Python 3.11+ (standard library only — zero pip dependencies)
- **Package manager:** Poetry (dev dependencies only)
- **Entry point:** `pwrap` → `project_wrap.cli:main`
- **License:** MIT

## Design Principles

These are load-bearing. Every change should respect them:

1. **Reviewable** — small codebase, no pip dependencies, no magic.
2. **Fail fast** — invalid config is an error, not a warning.
3. **Explicit over convenient** — no implicit defaults that hide security decisions.
4. **Init scripts as the extension point** — venv, aliases, setup go in init scripts, not in pwrap.

## Repository Layout

```
src/project_wrap/
├── __init__.py       # version
├── cli.py            # argparse entry point, dispatches to core/scaffold/guide/deps
├── core.py           # config loading, bwrap arg building, project execution
├── validate.py       # config schema validation, path/name/shell checks
├── scaffold.py       # --new project creation, template management
├── guide.py          # --guide interactive wizard: auto-detect + Q&A → config
├── deps.py           # optional dependency checking (bwrap, gocryptfs)
├── vault.py          # gocryptfs encrypted volume lifecycle (single + shared)
└── templates/        # default project.toml, init.fish, init.sh
tests/
├── conftest.py       # autouse fixtures: stub bwrap probe, isolate docker sockets
├── test_cli.py
├── test_core.py
├── test_deps.py
├── test_guide.py     # guided mode: detection, config gen, wizard flow
├── test_scaffold.py
├── test_vault.py
└── test_vault_integration.py  # opt-in, execs real bwrap/gocryptfs/unshare
completions/          # fish, bash, zsh shell completions
```

## Development Setup

```bash
poetry install              # install with dev dependencies
poetry run pytest           # run tests
poetry run ruff check .     # lint
poetry run mypy src/project_wrap tests   # type check
```

## Code Style

- **`from __future__ import annotations`** at the top of every module.
- **Type hints everywhere** — mypy runs in `strict = true` mode on `src/`.
  Tests are relaxed (`disallow_untyped_defs = false` etc.).
- **Line length:** 100 characters (ruff config).
- **Ruff rules:** `E, F, I, N, W, UP` (pyupgrade — use modern syntax).
- **Docstrings:** module-level docstring on every file. Public functions get
  docstrings. Use Google-style or plain prose — match the surrounding file.
- **Error handling:** raise `SystemExit` with a user-facing message for
  config/validation errors. Let unexpected exceptions propagate.
- **No third-party imports** in `src/project_wrap/` — stdlib only.
- **Dataclasses** for structured config objects (e.g. `VaultConfig`, `ProjectExec`,
  `Dependency`).
- **Path handling:** always use `pathlib.Path`, never `os.path`. Expand `~`
  and env vars via `core.expand_path()`.

## Testing

```bash
poetry run pytest                          # unit tests (default)
poetry run pytest -m "not integration"     # explicitly exclude integration
poetry run pytest -m integration           # integration tests (opt-in, needs bwrap/gocryptfs)
poetry run pytest tests/test_core.py -v    # single file
poetry run pytest -k "test_name"           # single test
```

- **Unit tests** must not depend on host state. The `conftest.py` autouse
  fixtures stub the bwrap feature probe and isolate docker socket candidates.
- **Integration tests** are marked `@pytest.mark.integration` and exec real
  `bwrap`/`gocryptfs`/`unshare`. They are excluded from CI.
- **Real probe tests** are marked `@pytest.mark.real_probe` to opt out of the
  bwrap probe stub.
- Use `monkeypatch` for environment/dependency stubbing. Use `tmp_path` for
  filesystem isolation.
- Tests use `pytest.raises(SystemExit)` for validation error paths.

## Security Considerations

This is a **security tool**. Changes to sandboxing logic require extra care:

- **Docker socket masking** (`_DOCKER_SOCKET_CANDIDATES` in `core.py`): a
  reachable docker socket is a full root escape. Never remove or weaken this.
- **Config directory blacklist**: `~/.config/pwrap` is always tmpfs'd inside
  the sandbox. Code inside the sandbox must not read other project configs.
- **Whitelist is read-only**: whitelisted paths use `--ro-bind`, not `--bind`.
  Use `writable` for rw exceptions.
- **Path validation**: `validate_project_name()` prevents path traversal.
  `check_config_permissions()` refuses world/group-writable configs.
- **Vault passwords**: never appear on the command line, in the environment,
  or on disk. The shared-vault primary keeps only a per-session scrypt
  verifier in memory.
- **TIOCSTI**: auto-enabled on kernels < 6.2 via `--new-session`.
- **Missing paths**: blacklist/writable paths that don't exist on the host
  abort with an aggregated error listing every missing path.

When modifying `build_bwrap_args()` or anything in `vault.py`, re-read the
security defaults section in `README.md` and the relevant tests.

## Architecture Notes

- **`core.py`** builds the bwrap argument list (`build_bwrap_args`) and
  constructs the shell argv (`build_shell_argv`). The project dir is always
  writable; home is bound read-only.
- **`vault.py`** has two modes: `shared=False` (single terminal, unshare +
  gocryptfs + bwrap exec chain) and `shared=True` (primary terminal mounts
  and serves; additional terminals attach via unix socket with password
  re-entry). The primary uses a PTY proxy so the shell gets a controlling
  terminal.
- **`scaffold.py`** manages user-editable templates in `~/.config/pwrap/`.
  On first run, package templates are copied with `.tpl.` infixed names.
- **`guide.py`** implements `pwrap --guide <dir>` — an interactive wizard
  that auto-detects project features (venv, Docker, `.env` files, language)
  and asks targeted questions to generate a customized config. Uses an
  injectable `Prompter` protocol (`ConsolePrompter` for real use,
  `ScriptedPrompter` for tests).
- **`deps.py`** probes optional dependencies. The bwrap probe checks for
  `--unshare-user` and `--uid` flags (required by the vault uid-mapping chain).

## Commit Conventions

- Keep commits focused. The git log shows a mix of feature commits and
  dependabot merges.
- Update `CHANGELOG.md` for user-facing changes (version-prefixed sections).
- The version in `pyproject.toml` uses a date-based scheme: `YYYYMM.N.P`.
