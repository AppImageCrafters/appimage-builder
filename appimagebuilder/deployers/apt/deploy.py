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
import logging
import os
from pathlib import Path

from .venv import Venv


class Deploy:
    """Deploy deb packages into an AppDir using apt-get to resolve the packages and their dependencies"""

    # manually crafted lists of packages used to determine what should be excluded by default or deployed in
    # a different partition
    listings = {
        "glibc": ["libc6", "zlib1g", "libstdc++6"],
        # system service packages are usually safe to exclude
        "system_services": [
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
        ],
        # because of issues with the nvidia driver and to achieve better performance the graphics
        # stack packages are also excluded by default
        "graphics": [
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
        ],
    }

    def __init__(self, apt_venv: Venv):
        self.apt_venv = apt_venv
        self.logger = logging.getLogger("AptPackageDeploy")

    def deploy(self, packages: [str], target: str, exclude: [str] = []):
        """Deploy the packages and their dependencies to target.

        Packages listed in exclude will not be deployed nor their dependencies.
        Packages from the system services and graphics listings will be added by default to the exclude list.
        Packages from the glibc listing will be deployed using <target>/opt/libc as prefix
        """
        if not os.getenv("ABUILDER_APT_SKIP_UPDATE", False):
            self.apt_venv.update()
        else:
            self.logger.warning(
                "Skipping`apt update` execution. Newly added sources will not be available!"
            )

        # resolve package names patterns
        packages = self.apt_venv.search_names(packages)
        exclude = self.apt_venv.search_names(exclude)

        # extend exclude list with default values keeping the packages that were required explicitly
        exclude = self._refine_exclude(exclude, packages)

        # set the excluded packages as installed to avoid their retrieval
        self.apt_venv.set_installed_packages(exclude)

        # use apt-get install --download-only to ensure that all the dependencies are resolved and downloaded
        self.apt_venv.install_download_only(packages)

        # manually extract downloaded packages to be able to create the opt/libc partition
        # where the glibc library and other related packages will be placed
        self._extract(packages, target)

    def _refine_exclude(self, exclude, packages):
        # avoid duplicates
        exclude = set(exclude)
        # don't bundle graphic stack packages
        exclude = exclude.union(self.listings["graphics"])
        # don't bundle system services
        exclude = exclude.union(self.listings["system_services"])
        # don't exclude explicitly required packges
        exclude.difference_update(packages)
        return exclude

    def _extract(self, packages, target: str):
        target = Path(target).absolute()
        # ensure target directories exists
        libc_target = target / "opt" / "libc"
        target.mkdir(exist_ok=True, parents=True)
        libc_target.mkdir(exist_ok=True, parents=True)

        # make sure that all glibc related package will be properly identified
        libc_packages = self.apt_venv.install_simulate(self.listings["glibc"])
        libc_packages_paths = self.apt_venv.resolve_archive_paths(libc_packages)

        # make sure that only the required packages and their dependencies are bundled (not the whole apt cache)
        packages = self.apt_venv.install_simulate(packages)
        packages_paths = self.apt_venv.resolve_archive_paths(packages)

        for path in packages_paths:
            final_target = target
            if path in libc_packages_paths:
                final_target = libc_target

            self.logger.info(
                "Deploying %s to %s" % (os.path.basename(path), final_target)
            )
            self.apt_venv.extract_archive(path, final_target)
