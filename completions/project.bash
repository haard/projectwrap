# Bash completions for project-wrap
# Install: cp completions/project.bash /etc/bash_completion.d/pwrap
#      or: source completions/project.bash in your .bashrc

_pwrap_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/pwrap"

    # Options
    if [[ ${cur} == -* ]]; then
        COMPREPLY=($(compgen -W "-l --list -v --verbose --check-deps --new --no-sandbox --version -h --help" -- "${cur}"))
        return 0
    fi

    # Project names
    if [[ -d "${config_dir}" ]]; then
        local projects=$(ls -1 "${config_dir}" 2>/dev/null | grep -v '^\.')
        COMPREPLY=($(compgen -W "${projects}" -- "${cur}"))
    fi
}

complete -F _pwrap_completions pwrap
