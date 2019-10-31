#  Copyright  2019 Alexis Lopez Zubieta
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

import os
import shutil
import tempfile
import subprocess
import logging


class PkgTool:
    def __init__(self):
        self.logger = logging.getLogger("PkgTool")

    def find_pkgs_of(self, files):
        pkgs = []

        result = subprocess.run(["dpkg-query", "-S", *files], stdout=subprocess.PIPE)
        output = result.stdout.decode('utf-8')

        for line in output.splitlines():
            pkg_name, file_path = line.split(" ")
            pkgs.append(pkg_name.rstrip(":"))

        return set(pkgs)

    def deploy_pkgs(self, pkgs, appdir):
        temp_dir = tempfile.mkdtemp()

        for pkg in pkgs:
            self.logger.info("Downloading: %s" % pkg)
            self._download_pkg(pkg, temp_dir)

        self._extract_pkgs_to(temp_dir, appdir)

        shutil.rmtree(temp_dir)

    def _download_pkg(self, pkg, target_dir):
        result = subprocess.run(["apt-get", "download", pkg], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=target_dir)

        if result.returncode != 0:
            self.logger.error("Packages download failed. Error: " + result.stderr.decode('utf-8'))

    def _extract_pkg_to(self, pkg_file, target_dir):
        result = subprocess.run(["dpkg-deb", "-x", pkg_file, target_dir], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                cwd=target_dir)

        if result.returncode != 0:
            self.logger.error("Package extraction failed. Error: " + result.stderr.decode('utf-8'))

    def _extract_pkgs_to(self, temp_dir, appdir):
        for root, dirs, files in os.walk(temp_dir):
            for filename in files:
                if (filename.endswith(".deb")):
                    self.logger.info("Extracting: %s" % filename)
                    self._extract_pkg_to(os.path.join(root, filename), appdir)
