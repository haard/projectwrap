# project-wrap

Isolated project environments with bubblewrap sandboxing.

A CLI tool that launches shell environments for your projects with:
- **Filesystem isolation** via [bubblewrap](https://github.com/containers/bubblewrap) — hide sensitive configs from project shells
- **Encrypted secrets** via [age](https://age-encryption.org/) — decrypt archives into sandbox tmpfs (RAM-only, auto-cleanup)
- **Shell-agnostic** — works with fish, bash, zsh
- **TOML configuration** — declarative, easy to version control

## Installation

```bash
# From PyPI
pipx install projectwrap

# From source
git clone https://github.com/haard/projectwrap
cd projectwrap
pip install -e .
```

The command is called `pwrap`.

### Dependencies

Required:
- Python 3.11+

Optional (checked at runtime):
- `bubblewrap` — for sandbox isolation (`sudo apt install bubblewrap`)
- `age` — for decrypting secrets (`sudo apt install age`)

Check dependency status:
```bash
pwrap --check-deps
```

## Quick Start

1. Create a project config (generates `project.toml`, `init.fish`, `init.sh`):
```bash
pwrap --new ~/projects/myproject
```

2. Edit `~/.config/project/myproject/project.toml` to configure sandboxing, and
   `init.fish`/`init.sh` for environment setup.

3. Launch the project:
```bash
pwrap myproject
```

## Configuration Reference

### Directory Structure

```
~/.config/project/
├── myproject/
│   ├── project.toml      # Required: project configuration
│   ├── init.fish         # Optional: runs inside sandbox (fish)
│   ├── init.bash         # Optional: runs inside sandbox (bash)
│   └── init.sh           # Optional: fallback init script
└── another-project/
    └── project.toml
```

### project.toml

```toml
[project]
name = "Display Name"           # Optional, defaults to directory name
dir = "~/projects/myproject"    # Required: project working directory
shell = "/usr/bin/fish"         # Optional, defaults to $SHELL

[sandbox]
enabled = true                  # Enable bubblewrap isolation
blacklist = [                   # Paths to hide (overlaid with tmpfs)
    "~/.config/project",
    "~/.kube",
    "~/.aws",
    "~/.ssh",
]
whitelist = [                   # Exceptions to blacklist (bound back)
    "~/.kube/myproject",
    "~/.ssh/myproject_ed25519",    # This project's SSH key only
    "~/.ssh/known_hosts",
]
writable = [                    # Extra writable paths (home is read-only)
    "~/.pyenv/shims",
    "~/.keychain",
    # "~/.claude",               # For running Claude Code inside sandbox
]
unshare_net = false             # Isolate network namespace
unshare_pid = true              # Isolate PID namespace (default: true)

[secrets]                        # age-encrypted archive (sandbox only)
archive = "secrets.tar.age"     # Relative to config dir, or absolute
identity = "~/.age/key.txt"     # age identity file
dest = "/tmp/secrets"           # Decrypted into sandbox tmpfs (default: /tmp/pwrap-secrets)

```

### Init Scripts

Init scripts run **inside** the sandbox after environment setup. Use them for:
- Environment variables (`set -gx`, `export`)
- Virtual environment activation (`source .venv/bin/activate.fish`)
- Tool version switching (pyenv, nvm, etc.)
- Project-specific aliases

The tool looks for (in order):
1. `init.{shell}` — e.g., `init.fish` for fish shell
2. `init.sh` — fallback for any shell

Example `init.fish`:
```fish
# Extra setup that runs inside the sandbox
set -gx DJANGO_SETTINGS_MODULE myproject.settings.local
alias dj "python manage.py"
```

### Secrets

The `[secrets]` section decrypts an age-encrypted tar archive into the sandbox's `/tmp`
(tmpfs). Secrets live only in RAM, are visible only inside the sandbox, and are
automatically cleaned up when the shell exits. Requires `sandbox.enabled = true`.

Create an encrypted archive:
```bash
# Generate an age key (once)
age-keygen -o ~/.age/key.txt

# Create and encrypt a secrets archive
tar cf - kubeconfig.yaml .env | age -e -R ~/.age/key.txt.pub > secrets.tar.age

# Place it in your project config dir
mv secrets.tar.age ~/.config/project/myproject/
```

Configure in `project.toml`:
```toml
[secrets]
archive = "secrets.tar.age"      # Relative to config dir
identity = "~/.age/key.txt"
dest = "/tmp/secrets"            # Optional, default: /tmp/pwrap-secrets
```

## Usage

```bash
# List all projects
pwrap

# Load a project (sandboxed if configured)
pwrap myproject

# Load with verbose output
pwrap -v myproject

# Create a new project config (name defaults to directory basename)
pwrap --new ~/projects/myproject

# Create with explicit name
pwrap --new ~/projects/myproject my-custom-name

# Create without sandbox
pwrap --new ~/projects/myproject --no-sandbox

# Check optional dependencies
pwrap --check-deps

# Show version
pwrap --version
```

## How It Works

1. **Config loading**: Reads `project.toml` from outside any sandbox
2. **tmux rename**: Renames current tmux window to project name
3. **Sandbox setup**: Builds bubblewrap arguments from config
4. **Shell launch**: Execs into sandboxed shell with init script
5. **Secrets decryption**: If configured, decrypts age archive into `/tmp` (sandbox tmpfs)

The key security property: **the config directory itself is blacklisted**, so code running inside the sandbox cannot read other project configs or modify its own sandboxing rules.

## Security Defaults

When sandboxing is enabled, project-wrap applies these hardening measures automatically:

- Home directory is mounted **read-only**; only the project directory is writable
- PID namespace is isolated by default (`unshare_pid = true`)
- IPC namespace is isolated (`--unshare-ipc`)
- TIOCSTI input injection is blocked automatically on vulnerable kernels (< 6.2) via
  `--new-session`. Can be forced on/off with `new_session = true/false` in config.
  Note: `--new-session` breaks fish shell TTY on some setups
- Sandbox dies with parent process (`--die-with-parent`)
- XDG runtime directory (`/run/user/$UID`) is isolated
- Blacklisted paths must exist (config error otherwise)
- Whitelist paths must be children of a blacklisted path (config error otherwise)
- All paths in shell commands are quoted to prevent injection

## Shell Completions

### Fish
```bash
cp completions/project.fish ~/.config/fish/completions/pwrap.fish
```

### Bash
```bash
cp completions/project.bash /etc/bash_completion.d/pwrap
# or source in .bashrc
```

### Zsh
```bash
cp completions/_project ~/.local/share/zsh/site-functions/_pwrap
```

## Development

```bash
# Install with dev dependencies
poetry install

# Run tests
poetry run pytest

# Type checking
poetry run mypy src/

# Linting
poetry run ruff check src/
```

## License

MIT
