# pwrap

pwrap wraps project shell environments in bubblewrap sandboxes, and aims to
_limit the blast radius_ of e.g. supply chain attacks and protect your production
infrastructure from your sloppy side project.



### Why ###

I got tired of my ad-hoc fish bwrap scripts, I'm increasingly worried about supply chain attacks, 
and Claude Code "auto mode" is just not made to run without isolation.

If every side project feels like a potential vector — one [npm|pip|cargo] install away from pwned AWS credentials,
and custom-wrapping with bwrap and some vault product feels too fragile or too much work, pwrap might help.

### Status ###

pwrap _works_ but has not been tested by anyone but me, and has not been
reviewed/audited by anyone except Opus 4.6 and codestral. pwrap comes with
_absolutely no warranty_.


**Does:**
- Launches sandboxed shells with per-project filesystem isolation
- Hides sensitive paths (credentials, configs, SSH keys) via tmpfs overlays
- Exposes only what each project needs (whitelisting)
- Mounts gocryptfs encrypted volumes inside isolated namespaces
- Runs init scripts for venv activation, aliases, setup

**Doesn't do:**
- Network filtering (it's all-or-nothing via `unshare_net`)
- Container-level isolation (no cgroups, no seccomp, no resource limits)
- Package management or dependency resolution
- Protect you from your own misconfiguration
- Protect you from `root`

**Dependencies:** Python 3.11+ (stdlib only, no pip dependencies),
[bubblewrap](https://github.com/containers/bubblewrap) ≥ 0.4 for sandboxing
(encrypted volumes need `--unshare-user` / `--uid` support to drop back to
the real uid inside the sandbox),
[gocryptfs](https://nuetzlich.net/gocryptfs/) for encrypted volumes.

**Design principles:**
- **Reviewable** — small codebase, no pip dependencies, no magic
- **Fail fast** — invalid config is an error, not a warning
- **Explicit over convenient** — no implicit defaults that hide security decisions
- **Init scripts as the extension point** — venv, aliases, setup

#### Installation ####

pwrap has no pip dependencies — only the standard library. 
Installing from source lets you see what you are running and is preferred:

```bash
git clone https://github.com/haard/projectwrap
cd projectwrap
# this is where you can still safely review the code before running
pip install --no-deps .
```

Or from PyPI if you prefer convenience: `pipx install projectwrap`

Check optional dependencies with `pwrap --check-deps`.

#### Quick Start ####

```bash
pwrap --new ~/projects/myproject    # creates config + init script
# edit ~/.config/pwrap/myproject/project.toml and init script
pwrap myproject                     # launch sandboxed shell
```

On first run, `--new` creates editable templates in `~/.config/pwrap/`. Edit them
to set your defaults, then run `--new` again.

#### Examples ####

##### Basic sandboxed project #####

`~/.config/pwrap/myproject/project.toml`:
```toml
[project]
name = "myproject"
dir = "~/projects/myproject"
shell = "/usr/bin/fish"

[sandbox]
enabled = true
blacklist = [  # can't be accessed at all from the sandbox
    "~/.kube",
    "~/.aws",
    "~/.ssh",
    "~/projects/",  # hide all other projects
    # trimmed for brevity — see the generated template (`pwrap --new`) for
    # the full default blacklist (GCP, Azure, GPG, docker, npm, PyPI, /mnt).
]
whitelist = [  # exceptions to the blacklist
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
inside the sandbox cannot read own or other project configs. The project directory
is always whitelisted and writable, even if a parent is blacklisted.

##### Encrypted AI chat history #####

Keep aichat/Claude chat history encrypted at rest, decrypted only inside the
sandbox.

**Setup:**
```bash
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
mountpoint = "~/projects/myproject/vault"

# Big Hammer approach to move history files, nvm envs etc:
# Note: XDG_DATA_HOME can only affect the shell itself if set here
# not in init script
[env]
XDG_DATA_HOME = "vault/.config"
```

**Init script** (`init.fish`):
```fish
set -gx AICHAT_CONFIG_DIR vault/aichat

```

##### Claude Code in sandbox #####

Claude Code writes state to several paths under `~/` (`~/.claude`,
`~/.claude.json.lock`, `~/.local/state/claude`, `~/.cache/claude-cli-nodejs`,
`~/.npm`). Rather than making each of these writable, redirect all of Claude's
state into the project directory:

```toml
[env]
CLAUDE_CONFIG_DIR = "vault/claude"   # or any writable path inside the sandbox
```

This gives each project its own Claude state (settings, history, MCP logs) —
no leakage between sandboxed projects. With an `[encrypted]` volume, Claude's
state is encrypted at rest.

##### Encrypted vault, minimal sandbox rules #####

Minimal sandbox configuration — no custom blacklists or whitelists, no
`clean_env`. The goal is to keep secrets (kubeconfig, shell history, LLM
chat logs) encrypted at rest and isolated per project, without locking down
the rest of the environment.

```toml
[project]
name = "myproject"
dir = "~/projects/myproject"
shell = "/usr/bin/fish"

[sandbox]
enabled = true

[encrypted]
cipherdir = "encrypted"
mountpoint = "~/projects/myproject/vault"

[env]
KUBECONFIG = "vault/kubeconfig"
CLAUDE_CONFIG_DIR = "vault/claude"
XDG_DATA_HOME = "vault/.config"   # fish history, tool state
```

`init.fish`:
```fish
source .venv/bin/activate.fish
```

`[sandbox] enabled = true` still applies the security defaults below: home
is bound read-only, the config dir is blacklisted, the docker socket is
masked, `/tmp` is a tmpfs, and PID/IPC namespaces are isolated. With no
custom blacklist/whitelist/writable entries, the only writable paths are
the project directory and the vault mountpoint — reads from anywhere else
under home still work, but writes outside those two paths fail. Add entries
to `writable` to poke rw holes in the read-only home if you need them. The
encrypted vault holds project-specific secrets and history that disappear
when the shell exits; `vault/` lives inside the project directory so it's
writable by default.

##### Maximum isolation #####

Default-deny for both filesystem and environment. Nothing is visible or set
unless explicitly allowed.

```toml
[project]
name = "myproject"
dir = "~/projects/myproject"
shell = "/usr/bin/fish"

[sandbox]
enabled = true
clean_env = true                  # only PATH/HOME/USER/SHELL/TERM/LANG
blacklist = [
    "~",                          # hide all dotfiles and home contents
    "/mnt",                       # WSL: hide Windows drives
]
whitelist = [
    "~/.config/fish",             # shell config (read-only)
    "~/.pyenv",                   # python versions (read-only)
]

[env]
XDG_DATA_HOME = ".config"        # fish history, tool state → project dir
```

The project directory is always writable regardless of blacklist. With
`XDG_DATA_HOME` pointing inside it, fish history and XDG-aware tools write
their state there instead of the (hidden) home directory.

##### GUI apps in sandbox #####

To run emacs or other GUI apps inside the sandbox on WSL2:

```toml
[sandbox]
writable = [
    "/tmp/.X11-unix",           # X11 display socket
    "/mnt/wslg/runtime-dir",   # Wayland + PulseAudio
]
```

#### Configuration ####

`pwrap --new` generates a `project.toml` template with all options documented.
The config sections:

| Section | Purpose |
|---|---|
| `[project]` | name, dir, shell |
| `[sandbox]` | blacklist, whitelist, writable, namespace options |
| `[env]` | environment variables, set before the shell starts |
| `[encrypted]` | gocryptfs cipherdir, mountpoint, shared mode |

`[env]` values are injected via bwrap `--setenv` (sandboxed) or `os.environ`
(non-sandboxed), so the shell sees them from the start — unlike init scripts
which run after the shell is already up. Values starting with `~/` are
expanded. Use `[env]` for variables that tools read at startup (e.g.
`XDG_DATA_HOME`), and init scripts for everything else.

Init scripts (`init.fish` or `init.sh`) run inside the sandbox for venv
activation, aliases, and tool version switching.

##### Encrypted volumes #####

On launch, gocryptfs prompts for the password, mounts the decrypted volume
inside an isolated mount namespace, and launches the sandboxed shell. The
decrypted files are invisible to host processes and disappear when the shell
exits. If you enter the wrong password, gocryptfs exits immediately (no
retry) and pwrap aborts without launching the sandbox. Re-run to try again.

**Environment variables**: `PWRAP_VAULT_DIR` is exported inside any sandbox
with an `[encrypted]` section, pointing at the mountpoint. Use it from init
scripts or app configs to redirect history/state into the vault without
hardcoding paths per project.

**If `id -u` reports 0 inside the sandbox**, your bubblewrap is too old —
run `pwrap --check-deps`. Encrypted vaults need `--unshare-user` / `--uid`
support (bubblewrap ≥ 0.4) to drop back to your real uid.

**Multiple terminals** (`shared = false`, default): each terminal gets an
independent gocryptfs mount. Writes to different files merge on next
session; writes to the same file from two sessions may lose one session's
changes. pwrap warns and prompts for confirmation when a concurrent session
is detected.

**Shared mode** (`shared = true`): the first terminal becomes the
**primary** session. It mounts gocryptfs, prints a vault token, and stays
in the foreground (no background daemon). Additional terminals prompt for
the token and attach as children. `$PWRAP_VAULT_TOKEN` is available inside
the sandbox. When the primary exits, all attached terminals are terminated
and the mount is released.

#### Usage ####

```bash
pwrap                                      # list projects
pwrap myproject                            # launch project
pwrap -v myproject                         # verbose output
pwrap --new ~/projects/myproject           # create config (name = dir basename)
pwrap --new --shell /bin/bash ~/projects/x # specify shell
pwrap --check-deps                         # check optional dependencies
pwrap --version                            # show version
```

#### Security Defaults ####

When sandboxing is enabled:

- Home is **read-only**; only the project directory is writable
- Config directory (`~/.config/pwrap`) is always blacklisted
- Docker socket (`/run/docker.sock`) masked — `connect()` works on
  ro-bound sockets, so an exposed docker socket is a full escape to root
- Default template blacklists credential dirs (SSH, GPG, AWS, GCP, Azure,
  Docker, npm, PyPI) and `/mnt` (WSL Windows drives)
- PID and IPC namespaces are isolated
- TIOCSTI injection blocked automatically on kernels < 6.2
- XDG runtime directory isolated (D-Bus, Wayland, keyring sockets)
- Sandbox dies with parent process
- Encrypted volumes mount in isolated namespace (invisible on host)
- Writable paths are auto-created (as directories) if they don't exist;
  paths that already exist are bound as-is, so a file entry binds that file

Run your editor from inside the sandbox if it has any capacity to run
linters, hooks, or anything else from the project environment. A
super-protected terminal does nothing if a malicious `.pth` can escape
via your linter.

#### Shell Completions ####

```bash
# Fish
cp completions/project.fish ~/.config/fish/completions/pwrap.fish
# Bash
cp completions/project.bash /etc/bash_completion.d/pwrap
# Zsh
cp completions/_project ~/.local/share/zsh/site-functions/_pwrap
```

#### Development ####

```bash
poetry install              # install with dev dependencies
poetry run pytest           # run tests
poetry run ruff check src/  # lint
poetry run mypy src/        # type check
```

#### License ####

MIT
