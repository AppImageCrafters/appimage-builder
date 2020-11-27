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
from pathlib import Path

from .venv import Venv


class Deploy:
    listings = {
        "glibc": ["glibc", "gcc-libs", "zstd"],
        "pacman_core": ["pacman"],
        "system": [
            "tzdata",
            "filesystem",
            "linux-api-headers"
        ]
    }

    def __init__(self, venv: Venv):
        self.pacman_venv = venv
        self.logger = logging.getLogger("PacmanPackageDeploy")

    def deploy(self, packages: [str], appdir_root: str, exclude: [str] = None):
        appdir_root = Path(appdir_root)

        if not exclude:
            exclude = []

        exclude.extend(self.listings["pacman_core"])
        exclude.extend(self.listings["system"])

        self.logger.debug("Excluded packages: ", exclude)

        package_files = self.pacman_venv.retrieve(packages, exclude)
        self.logger.debug("Candidate packages: ", package_files)

        deployed_packages = []
        for file in package_files:
            name, version = self.pacman_venv.read_package_data(file)
            target = appdir_root / "opt" / "libc" if name in self.listings["glibc"] else appdir_root

            self.logger.info("Deploying %s=%s to %s" % (name, version, target))
            self.pacman_venv.extract(file, target)
            deployed_packages.append("%s=%s" % (name, version))

        return deployed_packages
