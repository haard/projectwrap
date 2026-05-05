# Changelog

## 202604.4.1a0

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
