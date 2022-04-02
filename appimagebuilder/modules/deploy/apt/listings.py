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

# libc, libstdc++ its close dependencies, those packages will be deployed to AppDir/runtime/compat
glibc = ["libc6", "zlib1g", "libstdc++6"]

# packages that apt and dpkg assume as installed
apt_core = ["dpkg", "debconf", "apt"]

# system service packages are usually safe to exclude
system_services = [
    "adduser",
    "avahi-daemon",
    "base-files",
    "bind9-host",
    "consolekit",
    "coreutils",
    "dbus",
    "debconf",
    "debianutils",
    "dpkg",
    "fdisk",
    "init-system-helpers",
    "iso-codes",
    "libcap2-bin",
    "libinput-bin",
    "libpam-modules-bin",
    "libpam-runtime",
    "lsb-base",
    "mount",
    "multiarch-support",
    "passwd",
    "shared-mime-info",
    "systemd",
    "systemd-sysv",
    "sysvinit-utils",
    "ucf",
    "util-linux",
    "xdg-user-dirs",
    # fontconfig can be excluded most of the time
    "fontconfig",
    "fontconfig-config",
]

# because of issues with the nvidia driver and to achieve better performance the graphics
# stack packages are also excluded by default
graphics = [
    "libdrm*",
    "libegl-*",
    "libegl1*",
    "libegl1-*",
    "libgbm*",
    "libgl1*",
    "libglapi*",
    "libgles*",
    "libglvnd*",
    "libglx*",
    "mesa-*",
    # the following X11 libraries are tightly related to the packages above
    "libx11-*",
    "libxcb-dri2-0",
    "libxcb-dri3-0",
    "libxcb-glx0",
    "libxcb-present0",
    "libxcb-render0",
    "libxcb-shape0",
    "libxcb-shm0",
    "libxcb-xfixes0",
    "libxcb1",
    "x11-common",
]

default_exclude_list = []
default_exclude_list.extend(apt_core)
default_exclude_list.extend(system_services)
default_exclude_list.extend(graphics)
