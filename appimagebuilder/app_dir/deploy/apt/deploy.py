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
import fnmatch
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
        # packages that apt and dpkg assume as installed
        "apt_core": ["dpkg", "debconf", "dpkg", "apt"],
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

    def deploy(
        self, package_names: [str], appdir_root: str, exclude_patterns=None
    ) -> [str]:
        """Deploy the packages and their dependencies to appdir_root.

        Packages listed in exclude will not be deployed nor their dependencies.
        Packages from the system services and graphics listings will be added by default to the exclude list.
        Packages from the glibc listing will be deployed using <target>/opt/libc as prefix
        """
        if exclude_patterns is None:
            exclude_patterns = []

        if not os.getenv("ABUILDER_APT_SKIP_UPDATE", False):
            self.apt_venv.update()
        else:
            self.logger.warning(
                "Skipping`apt update` execution. Newly added sources will not be available!"
            )

        # set apt core packages as installed, required for it to properly resolve dependencies
        apt_core_packages = self.apt_venv.search_packages(self.listings["apt_core"])
        self.apt_venv.set_installed_packages(apt_core_packages)

        # resolve patterns in package listings
        packages = self.apt_venv.search_packages(package_names)

        # set the excluded packages as installed to avoid their retrieval
        excluded_packages = self._resolve_excluded_packages(exclude_patterns)
        excluded_packages = [pkg for pkg in excluded_packages if pkg not in packages]

        self.apt_venv.set_installed_packages(excluded_packages)

        # use apt-get install --download-only to ensure that all the dependencies are resolved and downloaded
        self.apt_venv.install_download_only(packages)

        extracted_packages = self._extract_packages(appdir_root, packages)
        return [str(package) for package in extracted_packages]

    def _extract_packages(self, appdir_root, packages):
        # manually extract downloaded packages to be able to create the opt/libc partition
        # where the glibc library and other related packages will be placed
        appdir_root = Path(appdir_root).absolute()
        # ensure target directories exists
        libc_root = appdir_root / "opt" / "libc"
        appdir_root.mkdir(exist_ok=True, parents=True)
        libc_root.mkdir(exist_ok=True, parents=True)
        # list libc related packages
        libc_packages = self.apt_venv.install_simulate(self.listings["glibc"])
        # make sure that only the required packages and their dependencies are bundled
        packages = self.apt_venv.install_simulate(packages)
        for package in packages:
            final_target = appdir_root
            if package in libc_packages:
                final_target = libc_root

            self.logger.info(
                "Deploying %s to %s" % (package.get_expected_file_name(), final_target)
            )
            self.apt_venv.extract_package(package, final_target)

        return packages

    def _resolve_excluded_packages(self, patterns):
        # remove duplicated
        patterns = set(patterns)
        # don't bundle graphic stack packages
        patterns = patterns.union(self.listings["graphics"])
        # don't bundle system services
        patterns = patterns.union(self.listings["system_services"])

        # resolve packages
        packages = self.apt_venv.search_packages(patterns)
        return packages
