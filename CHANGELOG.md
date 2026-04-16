# Changelog

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
