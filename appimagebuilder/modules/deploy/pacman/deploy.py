#   Copyright  2020 Alexis Lopez Zubieta
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#   sell copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
import logging
import os
from pathlib import Path

from .venv import Venv


class Deploy:
    listings = {
        "glibc": ["glibc", "gcc-libs", "zstd"],
        "pacman_core": ["pacman"],
        "system": [
            "tzdata",
            "filesystem",
            "linux-api-headers",
            "systemd",
            "dbus",
            "util-linux",
            "coreutils",
            "avahi",
            "polkit",
            "thin-provisioning-tools",
            "upower",
            "dmraid",
            "iso-codes",
        ],
        "graphics": [
            "libx11",
            "libxcb",
            "libdrm",
            "libxfixes",
            "libxxf86vm",
            "mesa",
            "wayland",
            "libglvnd",
        ],
    }

    def __init__(self, venv: Venv):
        self.pacman_venv = venv
        self.logger = logging.getLogger("PacmanPackageDeploy")

    def deploy(self, packages: [str], appdir_root: str, exclude: [str] = None):
        self.pacman_venv.update()

        appdir_root = Path(appdir_root)
        if not exclude:
            exclude = []

        exclude.extend(self.listings["pacman_core"])
        exclude.extend(self.listings["system"])
        exclude.extend(self.listings["graphics"])

        # don't exclude explicitly required packages
        exclude = [pkg for pkg in exclude if pkg not in packages]

        self.logger.debug("Excluded packages: %s" % " ".join(exclude))

        package_files = self.pacman_venv.retrieve(packages, exclude)
        self.logger.debug("Candidate packages: %s" % " ".join(package_files))

        deployed_packages = []
        for file in package_files:
            name, version = self.pacman_venv.read_package_data(file)
            target = (
                appdir_root / "runtime" / "compat"
                if name in self.listings["glibc"]
                else appdir_root
            )

            self.logger.info("Deploying %s=%s to %s" % (name, version, target))
            self.pacman_venv.extract(file, target)
            deployed_packages.append("%s=%s" % (name, version))

        # create symlinks existent in a regular archlinux system
        os.symlink("usr/bin", appdir_root / "bin")
        os.symlink("usr/bin", appdir_root / "sbin")
        os.symlink("usr/lib", appdir_root / "lib")
        os.symlink("usr/lib", appdir_root / "lib64")
        os.symlink("lib", appdir_root / "usr" / "lib64")
        os.symlink("bin", appdir_root / "usr" / "sbin")

        os.symlink("usr/bin", appdir_root / "runtime" / "compat" / "bin")
        os.symlink("usr/bin", appdir_root / "runtime" / "compat" / "sbin")
        os.symlink("usr/lib", appdir_root / "runtime" / "compat" / "lib")
        os.symlink("usr/lib", appdir_root / "runtime" / "compat" / "lib64")
        os.symlink("lib", appdir_root / "runtime" / "compat" / "usr" / "lib64")
        os.symlink("bin", appdir_root / "runtime" / "compat" / "usr" / "sbin")
        return deployed_packages
