#compdef elev

_elev() {
    _arguments -S \
        '(-u)-u[user]:user:_users' \
        '(-e --edit-config)'{-e,--edit-config}'[edit config]' \
        '(-v --version)'{-v,--version}'[show version]' \
        '(-h --help)'{-h,--help}'[show help]' \
        '*::arguments: _normal'
}

_elev "$@"
