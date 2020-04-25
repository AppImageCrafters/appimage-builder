#  Copyright  2020 Alexis Lopez Zubieta
#
#  Permission is hereby granted, free of charge, to any person obtaining a
#  copy of this software and associated documentation files (the "Software"),
#  to deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.

apt_core_packages = [
    'util-linux',
    'coreutils',
    'adduser',
    'avahi-daemon',
    'base-files',
    'bind9-host',
    'consolekit',
    'dbus',
    'debconf',
    'dpkg',
    'lsb-base',
    'libcap2-bin',
    'libinput-bin',
    'multiarch-support',
    'passwd',
    'systemd',
    'systemd-sysv',
    'ucf',
    'iso-codes',
    'shared-mime-info',
    'mount',
    'xdg-user-dirs',
    'sysvinit-utils',
    'debianutils',
    'init-system-helpers',
    'libpam-runtime',
    'libpam-modules-bin',

]

apt_font_config_packages = [
    'libfontconfig*',
    'fontconfig',
    'fontconfig-config',
    'libfreetype*',
]

apt_xclient_packages = [
    'x11-common',
    'libx11-*',
    'libxcb1',
    'libxcb-shape0',
    'libxcb-shm0',
    'libxcb-glx0',
    'libxcb-xfixes0',
    'libxcb-present0',
    'libxcb-render0',
    'libxcb-dri2-0',
    'libxcb-dri3-0',
]

apt_graphics_stack_packages = [
    'libglvnd*',
    'libglx*',
    'libgl1*',
    'libdrm*',
    'libegl1*',
    'libegl1-*',
    'libglapi*',
    'libgles2*',
    'libgbm*',
    'mesa-*',
]

apt_glibc_packages = ['libc6', 'zlib1g', 'libstdc++6']

#   packages required by the runtime generators
apt_proot_apprun_packages = ['proot', 'coreutils']
apt_classic_apprun_packages = ['coreutils']
apt_wrapper_apprun_packages = []
