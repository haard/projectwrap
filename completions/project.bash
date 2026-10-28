# Bash completions for project-wrap
# Install: cp completions/project.bash /etc/bash_completion.d/pwrap
#      or: source completions/project.bash in your .bashrc

_pwrap_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/pwrap"
    local -a projects=()

    if [[ -d "${config_dir}" ]]; then
        projects=($(ls -1 "${config_dir}" 2>/dev/null | grep -v '^\.'))
    fi

    # First word: subcommand or project name
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=($(compgen -W "pack unpack ${projects[*]}" -- "${cur}"))
        return 0
    fi

    case "${COMP_WORDS[1]}" in
        pack)
            if [[ ${cur} == -* ]]; then
                COMPREPLY=($(compgen -W "-o --output -h --help" -- "${cur}"))
            else
                COMPREPLY=($(compgen -W "${projects[*]}" -- "${cur}"))
            fi
            return 0
            ;;
        unpack)
            if [[ ${cur} == -* ]]; then
                COMPREPLY=($(compgen -W "--force -h --help" -- "${cur}"))
            else
                COMPREPLY=($(compgen -f -- "${cur}"))
            fi
            return 0
            ;;
    esac

    # Options
    if [[ ${cur} == -* ]]; then
        COMPREPLY=($(compgen -W "-l --list -v --verbose --check-deps --new --no-sandbox --version -h --help" -- "${cur}"))
        return 0
    fi

    # Project names
    COMPREPLY=($(compgen -W "${projects[*]}" -- "${cur}"))
}

complete -F _pwrap_completions pwrap
