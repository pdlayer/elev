#compdef elev

_elev() {
    _arguments -S \
        '(-u)-u[user]:user:_users' \
        '(-v --version)'{-v,--version}'[show version]' \
        '(-h --help)'{-h,--help}'[show help]' \
        '(-k --reset-timestamp)'{-k,--reset-timestamp}'[invalidate cached authentication]' \
        '*::arguments: _normal'
}

_elev "$@"
