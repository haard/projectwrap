# Fish completions for project-wrap
# Install: cp completions/project.fish ~/.config/fish/completions/pwrap.fish

function __pwrap_list
    set -l config_dir ~/.config/pwrap
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

# Subcommands (first argument)
complete -c pwrap -n "not __fish_seen_subcommand_from pack unpack" \
    -a "pack unpack" -d "Subcommand"

# Project names (first positional argument)
complete -c pwrap -n "not __fish_seen_subcommand_from pack unpack; and not __fish_seen_argument -s l -l list --check-deps" \
    -a "(__pwrap_list)" \
    -d "Project"

# pwrap pack <project> [-o FILE]
complete -c pwrap -n "__fish_seen_subcommand_from pack" \
    -a "(__pwrap_list)" -d "Project to pack"
complete -c pwrap -n "__fish_seen_subcommand_from pack" \
    -s o -l output -d "Output archive" -rF

# pwrap unpack <file> <path> [--force]
complete -c pwrap -n "__fish_seen_subcommand_from unpack" \
    -l force -d "Replace existing config / unpack over non-empty dirs"
complete -c pwrap -n "__fish_seen_subcommand_from unpack" \
    -a "*.pwrap.tar.gz" -d "Archive" -rF
complete -c pwrap -n "__fish_seen_subcommand_from unpack" \
    -d "New project directory" -rF

# Options
complete -c pwrap -s l -l list -d "List available projects"
complete -c pwrap -s v -l verbose -d "Verbose output"
complete -c pwrap -l check-deps -d "Check optional dependencies"
complete -c pwrap -l new -d "Create new project config" -rF
complete -c pwrap -l no-sandbox -d "Disable sandbox in generated config"
complete -c pwrap -l version -d "Show version"
complete -c pwrap -s h -l help -d "Show help"
