# Changelog

## 202610.1.0

- Known limitation: `pwrap unpack` extraction filter does not resolve hardlink
  targets through symlinks. A malicious archive containing a symlink member
  followed by a hardlink member whose linkname is relative but resolves
  through that symlink (e.g. `link -> /tmp` then hardlink `a -> link/file`)
  could create a hardlink inside the extraction directory that shares an inode
  with a file outside it. Impact is limited to linking to existing files (no
  new files created outside the dest), and the threat model is archives from
  trusted `pwrap pack` runs. Fix planned — `pack.py:_make_extract_filter`

- Add `pwrap pack <project> [-o FILE]` and `pwrap unpack <file> <path> [--force]`
  for moving a project between workstations. `pack` writes a `.pwrap.tar.gz`
  containing the project folder, the config (`project.toml` + init scripts),
  and the gocryptfs cipherdir if `[encrypted]` is configured (ciphertext only —
  the vault password is never stored). A currently mounted vault mountpoint is
  excluded from the project files so decrypted plaintext never lands in the
  archive. `unpack` installs the config into `~/.config/pwrap/<name>/`, unpacks
  the project into the given path, extracts the vault, and rewrites every
  config path that pointed inside the old project directory (`dir`,
  blacklist/whitelist/writable entries, `[encrypted]` paths, `[env]` values)
  to the new location. The rewritten config is validated before anything is
  installed: schema errors abort, and blacklist/writable entries that don't
  exist on the new host are commented out (same as `pwrap --new`). Extraction
  is hardened against path traversal and symlink escapes. Note: `pack` and
  `unpack` are now reserved words — a project literally named `pack` or
  `unpack` can no longer be launched positionally — `pack.py`, `cli.py`,
  `scaffold.py`, `README.md`
- Fix single-mode vault leak: the gocryptfs daemon outlived the session,
  keeping its mount namespace alive and holding the project flock — stale
  daemons caused false "another session is active" prompts and blocked
  shared-mode attach. A watcher subshell now unmounts and reaps the daemon
  when the session exits, including when the main process is killed by a
  signal, and the sandbox no longer inherits the project lock fd (bwrap
  does not close inherited fds) — `vault.py`
- Add `pwrap --guide <dir>` — guided setup wizard that interactively converts
  an existing folder into a pwrap config. Auto-detects project features
  (venv, Docker, `.env` files, git, language) and asks targeted questions:
  sandbox on/off, Docker access (auto-detects the socket), network isolation,
  clean environment, encrypted vault for secrets (`.env` files, shell history,
  Claude state), home paths to whitelist, and venv activation. Generates a
  customized `project.toml` and init script, and optionally initializes a
  gocryptfs encrypted volume — `guide.py`, `cli.py`, `README.md`
- Guided mode enhancements:
  - **WSL detection** (`is_wsl()`): probes for WSL2 via `/proc/sys/kernel/osrelease`
    and `/mnt/wsl`. On WSL, asks about Windows drive access (`/mnt`) and
    auto-whitelists `/mnt/wsl/resolv.conf` for DNS when network is not isolated
    and `/mnt` stays blacklisted
  - **Docker on WSL**: the Docker question is always asked on WSL, even when
    the Docker Desktop socket is not currently visible (Docker Desktop may not
    be running). Prints the expected socket path
    (`/mnt/wsl/docker-desktop-bind-mounts/<distro>/docker.sock`) for manual
    addition to `writable`
  - **HOME inside vault**: option to set `HOME` to `vault/.home` so all
    shell/tool state is encrypted at rest. Init script includes `mkdir -p`
    for first-launch setup. When `clean_env` is off, checks for host XDG
    vars (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`,
    `XDG_STATE_HOME`) that would override HOME-relative defaults and
    offers to enable `clean_env` to strip them
  - **Configurable blacklist**: `blacklist_mnt` parameter controls whether
    `/mnt` is included in the default blacklist
  - Docker question text now warns: "exposes docker socket = root on host"

## 202610.0.0

- **Breaking:** shared vault sessions (`shared = true`) no longer use a vault
  token. The primary no longer prints a token and no longer injects
  `$PWRAP_VAULT_TOKEN` into the sandbox; additional terminals must re-enter
  the gocryptfs password to attach. The password is read by the primary
  itself, piped to gocryptfs over stdin, and then replaced in memory by a
  per-session scrypt verifier (salt + digest, constant-time compare) — so
  the secret never reaches the terminal scrollback or the sandbox
  environment, and a dump of the primary yields only a salted hash. A
  failed attach is rate-limited as before (1s delay before the error) —
  `vault.py`, `README.md`

## 202604.6.0

- Add `devices = true` sandbox option to enable host device passthrough (FIDO2/YubiKey,
  USB, etc.). Uses `--dev-bind /dev /dev` instead of minimal devtmpfs. Dangerous devices
  are auto-masked: `/dev/input/*` (keylogging), `/dev/sd*`/`/dev/nvme*` (raw disk),
  `/dev/kvm`, `/dev/mem`, `/dev/kmem`. Additional devices can be masked via `blacklist`.
  — `core.py`, `validate.py`
- **Breaking:** `whitelist` entries are now bound read-only (`--ro-bind`)
  instead of read-write (`--bind`). This reduces blast radius of whitelisting
  broad trees (e.g. `/mnt/wsl` for WSL DNS) where the bound path contains
  writable sockets or files the sandboxee shouldn't be able to mutate. Use
  `writable` for rw exceptions — `core.py`
- Docker socket mask deduplicates candidates by canonical path, so
  `/var/run/docker.sock` (symlink to `/run/docker.sock` on modern Linux) no
  longer produces a duplicate `--ro-bind` that bwrap refuses with "Can't
  create file at /var/run/docker.sock: No such file or directory" —
  `core.py`
- Docker socket mask now covers WSL Docker Desktop paths
  (`/mnt/wsl/docker-desktop-bind-mounts/*/docker.sock` and
  `/mnt/wsl/docker-desktop/shared-sockets/*.sock`). Previously, a project
  whitelisting `/mnt/wsl` (e.g. to get resolv.conf) had a clean path to the
  host Docker engine — reachable via `curl --unix-socket …` — which is a
  full root escape. Candidate list now accepts glob patterns — `core.py`
- Docker socket mask skips candidates whose path is already under a
  blacklisted directory. Fixes a regression where projects with `/mnt` in
  their blacklist failed to launch with `bwrap: Can't bind mount
  /oldroot/dev/null on /newroot/mnt/wsl/.../docker.sock: No such file or
  directory` — WSL's dynamic submounts under `/mnt/wsl/docker-desktop-*`
  don't propagate through `--ro-bind / /`, so the mask's destination
  didn't exist when bwrap processed it. Skipping is safe: a blacklisted
  parent already hides the socket — `core.py`
- Default `pwrap --new` template now uses deny-by-default home
  (`blacklist = ["~", "/mnt"]`) with a narrow `whitelist` for shell config
  and `~/.gitconfig`. Previously the template enumerated credential dirs
  (`.ssh`, `.aws`, `.gnupg`, ...) which rotted as new tools added new
  credential files (`.claude.json`, `.boto`, `.config/op`,
  `.config/pypoetry`, `.config/uv` were all readable on a vanilla install).
  Template-only; existing configs unaffected — `templates/project.toml`
- Default template now sets `clean_env = true`. Without it, host env leaks
  into the sandbox (a probe caught `ANTHROPIC_API_KEY` and `CODESTRAL_API_KEY`
  passing through). Template-only — `templates/project.toml`
- README gains a "WSL users" subsection in Security Defaults explaining that
  `/etc/resolv.conf` symlinks into `/mnt/wsl` and recommending a narrow
  `whitelist = ["/mnt/wsl/resolv.conf"]` instead of the whole tree (which
  contains the Docker Desktop engine socket)

## 202604.4

- Docker socket mask now covers `/var/run/docker.sock`,
  `~/.docker/desktop/docker-cli.sock`, and `~/.docker/run/docker.sock` in
  addition to `/run/docker.sock`. Previously only `/run/docker.sock` was
  masked, leaving Docker Desktop installs reachable from inside the sandbox
  (full escape to root via `connect()`) — `core.py`
- **Breaking:** `writable` paths that don't exist on the host now abort instead
  of being silently `mkdir`'d on the host. Missing paths in `blacklist` and
  `writable` are aggregated into a single error listing every missing entry
  (was: one-at-a-time on `blacklist`, silent auto-create on `writable`).
  `whitelist` unchanged — still skips missing entries by design — `core.py`
- `pwrap --new` now creates `~/.config/pwrap/<name>/` with mode 0700 and its
  files with mode 0600, so a process umask of 002 no longer produces a config
  that `pwrap <name>` immediately refuses to load (#1). The config-perm
  refusal error also states the required mode and a `chmod` hint —
  `scaffold.py`, `validate.py`
- `pwrap --new` comments out `blacklist`/`whitelist`/`writable` template
  entries whose paths don't exist on the host, eliminating the fail/edit/rerun
  loop on fresh systems — `scaffold.py`
- Default template includes a commented guide for enabling docker inside the
  sandbox (uncomment the matching socket in `writable`)
- Extracted `scaffold.py` from `core.py` (template management, project
  creation) so security-adjacent argv construction in `core.py` is easier to
  review
- GitHub Actions CI (ruff + pytest on Python 3.11) runs on push/PR;
  mypy/matrix/integration tests tracked in #7/#8/#9
- README updated for new docker-mask paths and writable-must-exist semantics

## 202604.3

- Blacklist file entries now bind `/dev/null` instead of overlaying a tmpfs (fixes blacklisting
  individual files vs directories) — `core.py`
- Writable paths that already exist are bound as-is instead of unconditionally calling `mkdir` —
  file entries in `writable` now work correctly
- Encrypted vaults inject `--unshare-user --uid --gid` into the bwrap command so processes inside
  the sandbox see the real uid instead of root — `vault.py:_inject_uid`
- Shared-mode vault (`serve()`) passes real uid/gid through `--real-uid`/`--real-gid` CLI args and
  applies the nested user-ns mapping for primary and attached sessions
- Dependency checker gains a `feature_probe` hook and an `UNSUPPORTED` status; bwrap probe verifies
  `--unshare-user` / `--uid` support at startup (`deps.py:_probe_bwrap`)
- `UnsupportedDependencyError` raised when a binary is present but fails its feature probe
- `--check-deps` verbose output now shows the probe failure reason for unsupported dependencies
- Shared test fixture (`conftest.py`) stubs the bwrap feature probe for unit tests; opt out with
  `@pytest.mark.real_probe`
- Integration tests (`test_vault_integration.py`) exercise the full unshare → gocryptfs → bwrap
  uid-drop chain end-to-end
- README: documented bubblewrap >= 0.4 requirement, added "encrypted vault, minimal sandbox"
  example, updated uid-reporting note, clarified writable path semantics, trimmed default blacklist
  display
- Template (`project.toml`): removed stale root/uid warning comment, added WSL DNS whitelist hint,
  clarified `/mnt` blacklist comment
- Pytest markers added: `integration`, `real_probe`
- Added CHANGELOG.md
