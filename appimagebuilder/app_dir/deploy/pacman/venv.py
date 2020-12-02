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
    default_options = []

    def __init__(
        self,
        root,
        repositories: {str: [str]} = None,
        architecture: str = "auto",
        user_options: {} = None,
    ):
        self._root = Path(root)
        self._config_path = self._root / "pacman.conf"
        self._db_path = self._root / "db"
        self._cache_dir = self._root / "pkg"
        self._gpg_dir = self._root / "gnupg"
        self._repositories = repositories
        self._architecture = architecture
        self._options = user_options

        self._db_path.mkdir(parents=True, exist_ok=True)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._gpg_dir.mkdir(parents=True, exist_ok=True)

        self._logger = logging.getLogger("pacman")
        self._generate_config()
        self._configure_keyring()

    def update(self):
        command = "pacman --config %s -Sy --quiet" % (self._config_path)
        self._logger.debug(command)

        output = subprocess.run(command, shell=True)
        self._assert_successful_output(output)
        return output

    def retrieve(self, packages: [str], excluded_packages: [str] = None):
        initial_install_list = self._run_pacman_list_packages_and_versions(
            " ".join(packages)
        )

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
        command = (
            "bsdtar "
            "--exclude .BUILDINFO "
            "--exclude .MTREE "
            "--exclude .PKGINFO "
            "--exclude .INSTALL "
            "-xf %s -C %s " % (file, target)
        )
        self._logger.debug(command)
        output = subprocess.run(command, shell=True)
        self._assert_successful_output(output)
        return output

    def _run_pacman_download_packages(self, packages_str, exclude_str):
        command = "pacman --config %s -Sy --downloadonly --noconfirm %s %s" % (
            self._config_path,
            exclude_str,
            packages_str,
        )
        self._logger.debug(command)
        output = subprocess.run(command, shell=True)
        self._assert_successful_output(output)
        return output

    def _run_pacman_list_packages_and_versions(self, packages_str):
        command = "pacman --config %s -S --print-format '%%n=%%v' --noconfirm %s" % (
            self._config_path,
            packages_str,
        )
        self._logger.debug(command)
        output = subprocess.run(command, stdout=subprocess.PIPE, shell=True)
        self._assert_successful_output(output)

        return output.stdout.decode("utf-8").splitlines()

    def _run_pacman_list_package_files(self, exclude_str, packages_str):
        command = "pacman --config %s -S --print-format '%%l' --noconfirm %s %s" % (
            self._config_path,
            exclude_str,
            packages_str,
        )
        self._logger.debug(command)
        output = subprocess.run(command, stdout=subprocess.PIPE, shell=True)
        self._assert_successful_output(output)

        files = re.findall("file://(.*)", output.stdout.decode("utf-8"))
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

    def _generate_config(self):
        with open(self._config_path, "w") as f:
            f.write(
                "# Generated by appimage-builder, modifications will be overridden on next execution\n"
            )
            f.write("[options]\n")
            if self._architecture:
                f.write("Architecture = %s\n" % self._architecture)

            f.write("DBPath = %s\n" % self._db_path)
            f.write("CacheDir = %s\n" % self._cache_dir)
            f.write("GPGDir = %s\n" % self._gpg_dir)
            if not self._repositories:
                f.write("Include = /etc/pacman.conf\n")

            if self._repositories:
                for repository in self._repositories:
                    f.write("[%s]\n" % repository)
                    for server in self._repositories[repository]:
                        f.write("Server = %s\n" % server)

    def _configure_keyring(self):
        command = "pacman-key --config %s --init" % self._config_path
        self._logger.debug(command)
        self._assert_successful_output(subprocess.run(command, shell=True))

        command = "pacman-key --config %s --populate archlinux" % self._config_path
        self._logger.debug(command)
        self._assert_successful_output(subprocess.run(command, shell=True))
