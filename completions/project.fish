# Fish completions for project-wrap
# Install: cp completions/project.fish ~/.config/fish/completions/pwrap.fish

function __pwrap_list
    set -l config_dir ~/.config/project
    if test -d $config_dir
        for item in $config_dir/*
            if test -d $item; or test -f $item
                basename $item
            end
        end
    end
end

# Disable file completions
complete -c pwrap -f

# Project names (first positional argument)
complete -c pwrap -n "not __fish_seen_argument -s l -l list --check-deps" \
    -a "(__pwrap_list)" \
    -d "Project"

# Options
complete -c pwrap -s l -l list -d "List available projects"
complete -c pwrap -s v -l verbose -d "Verbose output"
complete -c pwrap -l check-deps -d "Check optional dependencies"
complete -c pwrap -l new -d "Create new project config" -rF
complete -c pwrap -l no-sandbox -d "Disable sandbox in generated config"
complete -c pwrap -l version -d "Show version"
complete -c pwrap -s h -l help -d "Show help"
