# pwrap

pwrap wraps project shell environments in bubblewrap sandboxes, and aims to
_limit the blast radius_ of e.g. supply chain attacks and protect your production
infrastructure from your sloppy side project.

**Does:**
- Launches sandboxed shells with per-project filesystem isolation
- Hides sensitive paths (credentials, configs, SSH keys) via tmpfs overlays
- Exposes only what each project needs (whitelisting)
- Mounts gocryptfs encrypted volumes inside isolated namespaces
- Runs init scripts for env vars, venv activation, aliases

**Doesn't do:**
- Network filtering (it's all-or-nothing via `unshare_net`)
- Container-level isolation (no cgroups, no seccomp, no resource limits)
- Do package management or dependency resolution
- Protect you from your own misconfiguration

**Dependencies:** Python 3.11+ (stdlib only, no pip dependencies),
[bubblewrap](https://github.com/containers/bubblewrap) for sandboxing,
[gocryptfs](https://nuetzlich.net/gocryptfs/) for encrypted volumes.

**Design principles:**
- **Reviewable** — small codebase, no pip dependencies, no magic
- **Fail fast** — invalid config is an error, not a warning
- **Explicit over convenient** — no implicit defaults that hide security decisions
- **Init scripts as the extension point** — env vars, venv, aliases all go there,
  not in config schema

## Installation

pwrap has no pip dependencies — only the standard library. For a security tool,
installing from source lets you audit what you're running:

```bash
git clone https://github.com/haard/projectwrap
cd projectwrap
pip install --no-deps .
```

Or from PyPI if you prefer convenience: `pipx install projectwrap`

Check optional dependencies with `pwrap --check-deps`.

## Quick Start

```bash
pwrap --new ~/projects/myproject    # creates config + init script
# edit ~/.config/pwrap/myproject/project.toml and init script
pwrap myproject                     # launch sandboxed shell
```

On first run, `--new` creates editable templates in `~/.config/pwrap/`. Edit them
to set your defaults, then run `--new` again.

## Examples

### Basic sandboxed project

`~/.config/pwrap/myproject/project.toml`:
```toml
[project]
name = "myproject"
dir = "~/projects/myproject"
shell = "/usr/bin/fish"

[sandbox]
enabled = true
blacklist = [
    "~/.kube",
    "~/.aws",
    "~/.ssh",
]
whitelist = [
    "~/.kube/myproject",
    "~/.ssh/myproject_ed25519",
    "~/.ssh/known_hosts",
]
```

`~/.config/pwrap/myproject/init.fish`:
```fish
source .venv/bin/activate.fish
set -gx KUBECONFIG ~/.kube/myproject/config
set -gx GIT_SSH_COMMAND "ssh -i ~/.ssh/myproject_ed25519 -o IdentitiesOnly=yes"
```

The config directory (`~/.config/pwrap`) is always blacklisted automatically — code
inside the sandbox cannot read other project configs.

### Encrypted AI chat history

Keep aichat/Claude chat history encrypted at rest, decrypted only inside the sandbox.
Uses gocryptfs mounted in an isolated namespace (invisible on host).

**Setup:**
```bash
# Initialize encrypted directory (once, prompts for password)
mkdir -p ~/.config/pwrap/myproject/encrypted
gocryptfs -init ~/.config/pwrap/myproject/encrypted
```

**Config** (`project.toml`):
```toml
[project]
name = "myproject"
dir = "~/projects/myproject"
shell = "/usr/bin/fish"

[sandbox]
enabled = true

[encrypted]
cipherdir = "encrypted"
mountpoint = "~/.local/share/aichat"
```

**Init script** (`init.fish`):
```fish
set -gx AICHAT_CONFIG_DIR ~/.local/share/aichat
# For Claude Code:
# set -gx CLAUDE_CONFIG_DIR ~/.local/share/claude
```

On `pwrap myproject`, gocryptfs prompts for the password, mounts the decrypted
volume inside an isolated mount namespace, and launches the sandboxed shell.
The decrypted files are invisible to host processes and disappear when the shell
exits.

If you enter the wrong password, gocryptfs re-prompts up to its own retry limit
and then exits non-zero. pwrap aborts on that failure without launching the
sandbox — no shell starts, no partial mount is left behind. Re-run `pwrap
myproject` to try again.

**`PWRAP_VAULT_DIR`**: inside any sandbox with an `[encrypted]` section, pwrap
exports `PWRAP_VAULT_DIR` pointing at the mountpoint. Use it from init scripts
or app configs to redirect history/state into the vault without hardcoding the
path per project (e.g. `set savehist-file (expand-file-name "history" "$PWRAP_VAULT_DIR/emacs")`).

**You will appear as root inside encrypted projects.** Mounting gocryptfs
unprivileged requires `unshare --user --map-root-user`, so inside the sandbox
`whoami` reports `root` and `id -u` reports `0`. This is a user-namespace
remapping only — you have no real privileges on the host, cannot read
root-owned files outside the namespace, and cannot escalate. Your real files
(project dir, home bind-mounts, the vault mountpoint itself) remain owned by
your real uid. Scripts that gate on `[ "$UID" = 0 ]` will misbehave; prefer
`[ "$USER" = root ]` checks or, better, check the presence of
`$PROJECT_WRAP` / `$PWRAP_VAULT_DIR`.

**Multiple terminals** (`shared = false`, default): each terminal gets an
independent gocryptfs mount. Writes to different files merge on next session;
writes to the same file from two sessions may lose the first session's changes.
pwrap warns and prompts for confirmation when a concurrent session is detected.

**Shared mode** (`shared = true`): the first terminal becomes the **primary**
session. It mounts gocryptfs, prints a vault token, and stays in the
foreground of the terminal that launched it (no background daemon — the
serve process is a normal child of your shell). Additional terminals running
`pwrap myproject` prompt for the token and attach as children of the primary.
Inside the sandbox, `echo $PWRAP_VAULT_TOKEN` retrieves the token. When the
primary exits (shell exit, Ctrl-C, or closing its terminal), all attached
terminals are terminated and the mount is released — keep the primary
terminal open for the duration of the session.

### GUI apps in sandbox (WSL2)

To run emacs or other GUI apps inside the sandbox on WSL2:

```toml
[sandbox]
writable = [
    "/tmp/.X11-unix",           # X11 display socket
    "/mnt/wslg/runtime-dir",   # Wayland + PulseAudio
]
```

## Configuration

`pwrap --new` generates a `project.toml` template with all options documented.
The three config sections:

| Section | Purpose |
|---|---|
| `[project]` | name, dir, shell |
| `[sandbox]` | blacklist, whitelist, writable, namespace options |
| `[encrypted]` | gocryptfs cipherdir, mountpoint, shared mode |

Init scripts (`init.fish` or `init.sh`) run inside the sandbox for env vars,
venv activation, aliases, and tool version switching.

## Usage

```bash
pwrap                                      # list projects
pwrap myproject                            # launch project
pwrap -v myproject                         # verbose output
pwrap --new ~/projects/myproject           # create config (name from dir)
pwrap --new ~/projects/myproject custom    # create with explicit name
pwrap --new --shell /bin/bash ~/projects/x # specify shell
pwrap --check-deps                         # check optional dependencies
pwrap --version                            # show version
```

## Security Defaults

When sandboxing is enabled:

- Home is **read-only**; only the project directory is writable
- Config directory (`~/.config/pwrap`) is always blacklisted
- PID and IPC namespaces are isolated
- TIOCSTI injection blocked automatically on kernels < 6.2
- XDG runtime directory isolated
- Sandbox dies with parent process
- Encrypted volumes mount in isolated namespace (invisible on host)
- All paths in shell commands are quoted to prevent injection

## Shell Completions

```bash
# Fish
cp completions/project.fish ~/.config/fish/completions/pwrap.fish
# Bash
cp completions/project.bash /etc/bash_completion.d/pwrap
# Zsh
cp completions/_project ~/.local/share/zsh/site-functions/_pwrap
```

## Development

```bash
poetry install              # install with dev dependencies
poetry run pytest           # run tests
poetry run ruff check src/  # lint
poetry run mypy src/        # type check
```

## License

MIT
