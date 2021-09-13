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
                appdir_root / "opt" / "libc"
                if name in self.listings["glibc"]
                else appdir_root
            )

            self.logger.info("Deploying %s=%s to %s" % (name, version, target))
            self.pacman_venv.extract(file, target)
            deployed_packages.append("%s=%s" % (name, version))

        # create symlinks existent in a regular archlinux system
        self._recreate_archlinux_fs_structure(appdir_root)
        return deployed_packages

    def _recreate_archlinux_fs_structure(self, appdir_root):
        links = {
            "bin": "usr/bin",
            "sbin": "usr/bin",
            "lib": "usr/lib",
            "lib64": "usr/lib",
            "usr/lib64": "lib",
            "usr/sbin": "bin",
        }

        for prefix in [appdir_root, appdir_root / "opt" / "lib"]:
            for dst, src in links.items():
                dst = prefix / dst
                if not dst.exists() and (prefix / src).exists():
                    os.symlink(src, dst)
