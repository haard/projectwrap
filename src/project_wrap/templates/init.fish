# init.fish — runs inside the sandbox after project loads
# Customize for your project, or delete if not needed.

# Virtual environment activation
# source .venv/bin/activate.fish

# Environment variables
# set -gx KUBECONFIG ~/.kube/myproject/config
# set -gx DATABASE_URL postgres://localhost/myproject

# Claude Code / AI tools (with [encrypted] volume)
# set -gx CLAUDE_CONFIG_DIR ~/.local/share/claude
# set -gx AICHAT_CONFIG_DIR ~/.local/share/aichat
# Inside an [encrypted] project, $PWRAP_VAULT_DIR points at the mountpoint,
# e.g. set -gx FOO_HISTORY $PWRAP_VAULT_DIR/foo-history

# Project-specific aliases
# alias run "python manage.py runserver"

# Tool version switching
# pyenv local 3.12.0
