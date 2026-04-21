_elev() {
    local cur prev words cword
    if type -t _get_comp_words_by_ref >/dev/null; then
        _get_comp_words_by_ref -n : cur prev words cword
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

    case "$prev" in
        -u)
            COMPREPLY=( $(compgen -u -- "$cur") )
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "-u -v -h -k --version --help --reset-timestamp" -- "$cur") )
        return 0
    fi

    local i cmd_idx
    for (( i=1; i < cword; i++ )); do
        if [[ ${words[i]} != -* ]]; then
            cmd_idx=$i
            break
        fi
        if [[ ${words[i]} == -u ]]; then
            ((i++))
        fi
    done

    if [[ -n $cmd_idx ]]; then
        if type -t _command_offset >/dev/null; then
            _command_offset $cmd_idx
        else
            COMPREPLY=( $(compgen -c -- "$cur") )
        fi
        return
    fi

    COMPREPLY=( $(compgen -c -- "$cur") )
}
complete -F _elev elev
