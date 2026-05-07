project(
  'elev',
  'c',
  version : '1.0.0',
  meson_version : '>=1.3.0',
  default_options : [
    'buildtype=release',
    'c_std=c11',
    'warning_level=3',
  ],
)

cc = meson.get_compiler('c')
system = host_machine.system()

c_args = [
  '-D_POSIX_C_SOURCE=200809L',
  '-DELEV_RUN="@0@"'.format(get_option('runtime_dir')),
]
link_args = []
use_pie = false

if system == 'linux'
  c_args += [
    '-D_GNU_SOURCE',
    '-fstack-protector-strong',
    '-D_FORTIFY_SOURCE=3',
  ]
  use_pie = true
  link_args += [
    '-Wl,-z,relro,-z,now',
    '-Wl,-z,noexecstack',
  ]
elif ['freebsd', 'netbsd', 'openbsd'].contains(system)
  c_args += [
    '-fstack-protector-strong',
  ]
  use_pie = true
elif system == 'darwin'
  c_args += ['-fstack-protector-strong']
endif

pam_dep = cc.find_library('pam', required : system != 'darwin')
deps = []
if pam_dep.found()
  deps += pam_dep
endif

elev_bin = executable(
  'elev',
  [
    'elev.c',
    'config.c',
    'pam.c',
    'util.c',
  ],
  dependencies : deps,
  c_args : c_args,
  link_args : link_args,
  pie : use_pie,
  install : true,
  install_dir : get_option('bindir'),
  install_mode : 'rwsr-xr-x',
)

install_data(
  'elev.1',
  install_dir : join_paths(get_option('mandir'), 'man1'),
  follow_symlinks : true,
)

install_data(
  'elev.5',
  install_dir : join_paths(get_option('mandir'), 'man5'),
  follow_symlinks : true,
)

install_data(
  'elev.7',
  install_dir : join_paths(get_option('mandir'), 'man7'),
  follow_symlinks : true,
)

install_data(
  'elev.bash',
  install_dir : join_paths(get_option('datadir'), 'bash-completion', 'completions'),
  rename : 'elev',
  follow_symlinks : true,
)

install_data(
  'elev.zsh',
  install_dir : join_paths(get_option('datadir'), 'zsh', 'site-functions'),
  rename : '_elev',
  follow_symlinks : true,
)

install_data(
  'elev.pam',
  install_dir : get_option('pamdir'),
  rename : 'elev',
  follow_symlinks : true,
)
