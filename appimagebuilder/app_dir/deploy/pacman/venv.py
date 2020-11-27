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
import re
import subprocess
from pathlib import Path


class PacmanVenvError(RuntimeError):
    pass


class Venv:
    def __init__(
            self,
            root,
            sources: [str],
            keys: [str],
            architectures: [],
            user_options: {} = None,
    ):
        self._root = Path(root)
        self._dbpath = self._root / "db"
        self._cachedir = self._root / "pkg"
        self._gpgdir = self._root / "gnupg"
        self._sources = sources
        self._keys = keys
        self._architectures = architectures
        self._user_options = user_options

        self._dbpath.mkdir(parents=True, exist_ok=True)
        self._cachedir.mkdir(parents=True, exist_ok=True)
        self._gpgdir.mkdir(parents=True, exist_ok=True)

        self._logger = logging.getLogger("pacman")

    def update(self):
        command = "pacman -Sy --quiet --dbpath %s" % (self._dbpath)
        self._logger.debug(command)

        output = subprocess.run(command, shell=True)
        self._assert_successful_output(output)
        return output

    def retrieve(self, packages: [str], excluded_packages: [str] = None):
        initial_install_list = self._run_pacman_list_packages_and_versions(" ".join(packages))

        exclude_str = ""
        packages_str = ""
        for package in initial_install_list:
            pkg_name, pkg_version = package.split("=", 1)
            if pkg_name in excluded_packages:
                exclude_str = exclude_str + "--assume-installed %s " % package

            if pkg_name in packages:
                packages_str = packages_str + "%s " % package

        self._run_pacman_download_packages(packages_str, exclude_str)
        files = self._run_pacman_list_package_files(exclude_str, packages_str)

        return files

    def extract(self, file, target):
        os.makedirs(target, exist_ok=True)
        command = "bsdtar " \
                  "--exclude .BUILDINFO " \
                  "--exclude .MTREE " \
                  "--exclude .PKGINFO " \
                  "--exclude .INSTALL " \
                  "-xf %s -C %s " % (file, target)
        self._logger.debug(command)
        output = subprocess.run(command, shell=True)
        self._assert_successful_output(output)
        return output

    def _run_pacman_download_packages(self, packages_str, exclude_str):
        command = "pacman -Sy --downloadonly --noconfirm --dbpath %s --cachedir %s %s %s" % (
            self._dbpath,
            self._cachedir,
            exclude_str,
            packages_str,
        )
        self._logger.debug(command)
        output = subprocess.run(command, shell=True)
        self._assert_successful_output(output)
        return output

    def _run_pacman_list_packages_and_versions(self, packages_str):
        command = "pacman -S --print-format '%%n=%%v' --noconfirm --dbpath %s --cachedir %s %s" % (
            self._dbpath,
            self._cachedir,
            packages_str,
        )
        self._logger.debug(command)
        output = subprocess.run(command, stdout=subprocess.PIPE, shell=True)
        self._assert_successful_output(output)

        return output.stdout.decode("utf-8").splitlines()

    def _run_pacman_list_package_files(self, exclude_str, packages_str):
        command = "pacman -S --print-format '%%l' --noconfirm --dbpath %s --cachedir %s %s %s" % (
            self._dbpath,
            self._cachedir,
            exclude_str,
            packages_str,
        )
        self._logger.debug(command)
        output = subprocess.run(command, stdout=subprocess.PIPE, shell=True)
        self._assert_successful_output(output)

        files = re.findall("file://(/.*)", output.stdout.decode("utf-8"))
        return files

    @staticmethod
    def _assert_successful_output(output):
        if output.returncode:
            raise PacmanVenvError(
                '"%s" execution failed with code %s' % (output.args, output.returncode)
            )

    def read_package_data(self, file):
        command = "pacman -Qp %s" % file
        self._logger.debug(command)
        output = subprocess.run(command, stdout=subprocess.PIPE, shell=True)
        self._assert_successful_output(output)

        lines = output.stdout.decode("utf-8").splitlines()
        if lines:
            first_line = lines[0]
            line_parts = first_line.split(" ")

            # name, version
            return line_parts[0], line_parts[1]

        raise PacmanVenvError("Unable to read package info from: '%s'" % file)
