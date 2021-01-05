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


"""
 Manually crafted lists of packages used to determine what should be excluded by default or deployed in
 a different partition.
"""

# libc, libstdc++ its close dependencies, those packages will be deployed to AppDir/opt/libc
glibc = ["libc6", "zlib1g", "libstdc++6"]

# packages that apt and dpkg assume as installed
apt_core = ["dpkg", "debconf", "dpkg", "apt"]

# system service packages are usually safe to exclude
system_services = [
    "util-linux",
    "coreutils",
    "adduser",
    "avahi-daemon",
    "base-files",
    "bind9-host",
    "consolekit",
    "dbus",
    "debconf",
    "dpkg",
    "lsb-base",
    "libcap2-bin",
    "libinput-bin",
    "multiarch-support",
    "passwd",
    "systemd",
    "systemd-sysv",
    "ucf",
    "iso-codes",
    "shared-mime-info",
    "mount",
    "xdg-user-dirs",
    "sysvinit-utils",
    "debianutils",
    "init-system-helpers",
    "libpam-runtime",
    "libpam-modules-bin",
    # fontconfig can be excluded most of the time
    "libfontconfig*",
    "fontconfig",
    "fontconfig-config",
    "libfreetype*",
]

# because of issues with the nvidia driver and to achieve better performance the graphics
# stack packages are also excluded by default
graphics = [
    "libglvnd*",
    "libglx*",
    "libgl1*",
    "libdrm*",
    "libegl1*",
    "libegl1-*",
    "libglapi*",
    "libgles2*",
    "libgbm*",
    "mesa-*",
    # the following X11 libraries are tightly related to the packages above
    "x11-common",
    "libx11-*",
    "libxcb1",
    "libxcb-shape0",
    "libxcb-shm0",
    "libxcb-glx0",
    "libxcb-xfixes0",
    "libxcb-present0",
    "libxcb-render0",
    "libxcb-dri2-0",
    "libxcb-dri3-0",
]
