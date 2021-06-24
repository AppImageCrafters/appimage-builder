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
import glob
import logging
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from appimagebuilder.utils import shell

DEPENDS_ON = ["bsdtar", "pacman", "pacman-key", "fakeroot", "gpg-agent"]


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
        self._keyrings = []
        self._architecture = architecture
        self._options = user_options if user_options else {}
        self._deps = dict()

        self._db_path.mkdir(parents=True, exist_ok=True)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._gpg_dir.mkdir(parents=True, exist_ok=True)

        self._logger = logging.getLogger("pacman")
        self._deps = shell.resolve_commands_paths(DEPENDS_ON)
        self._generate_config()
        self._start_gpg_agent()
        self._configure_keyring()

    def __del__(self):
        # cleanup
        if hasattr(self, "_gpg_agent_proc") and self._gpg_agent_proc:
            self._gpg_agent_proc.terminate()

    def update(self):
        self._run_command("{fakeroot} {pacman} --config {config} -Sy --quiet")

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
            "{bsdtar} "
            "--exclude .BUILDINFO "
            "--exclude .MTREE "
            "--exclude .PKGINFO "
            "--exclude .INSTALL "
            "-xf {file} -C {target} "
        )
        self._run_command(command, file=file, target=target)

    def _run_pacman_download_packages(self, packages_str, exclude_str):
        self._run_command(
            "{fakeroot} {pacman} --config {config} -Sy --downloadonly "
            "--noconfirm {exclude} {packages}",
            exclude=exclude_str,
            packages=packages_str,
        )

    def _run_pacman_list_packages_and_versions(self, packages_str):
        command = (
            "{pacman} --config {config} -S "
            "--print-format '%n=%v' "
            "--noconfirm {packages}"
        )
        output = self._run_command(
            command, packages=packages_str, stdout=subprocess.PIPE
        )  # noqa:

        return output.stdout.read().decode("utf-8").splitlines()  # noqa:

    def _run_pacman_list_package_files(self, exclude_str, packages_str):
        command = (
            "{pacman} --config {config} -S "
            "--print-format '%%l' "
            "--noconfirm {exclude} {packages}"
        )
        self._logger.debug(command)
        output = self._run_command(
            command, packages=packages_str, exclude=exclude_str, stdout=subprocess.PIPE
        )  # noqa:
        files = re.findall("file://(.*)", output.stdout.read().decode("utf-8"))
        return files

    def read_package_data(self, file):
        output = self._run_command(
            "{pacman} -Qp {file}", file=file, stdout=subprocess.PIPE  # noqa:
        )

        lines = output.stdout.read().decode("utf-8").splitlines()  # noqa:
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

            for k, v in self._options.items():
                self._logger.warning("Setting option: %s = %s" % (k, v))
                f.write("%s = %s\n" % (k, v))

            if self._repositories:
                for repository in self._repositories:
                    f.write("[%s]\n" % repository)
                    for server in self._repositories[repository]:
                        f.write("Server = %s\n" % server)

    def _configure_keyring(self):
        if not self._keyrings:
            self._logger.info("Using system keyrings")
            default_keyrigns_path = Path("/usr/share/pacman/keyrings/")
            for x in default_keyrigns_path.glob("*.gpg"):
                self._keyrings.append(x.stem)

        # Ensure the keyring is properly initialized
        self._run_command("{fakeroot} {pacman-key} --config {config} --init")

        self._run_command(
            "{fakeroot} {pacman-key} --config {config} --populate {keyrings}",
            keyrings=" ".join(self._keyrings),
        )

    def _start_gpg_agent(self):
        # start gpg-agent if not running
        #   (pkill -0 doesn't kill the process just checks if it's running)
        if subprocess.call(["pkill", "-0", "gpg-agent"]) != 0:
            self._gpg_agent_proc = self._run_command(
                "{gpg-agent} --homedir" f" {self._gpg_dir}" " --server",
                assert_success=False,
                wait_for_completion=False,
            )
        else:
            self._gpg_agent_proc = None

    def _run_command(
        self,
        command,
        stdout=sys.stdout,
        assert_success=True,
        wait_for_completion=True,
        wait_for_completion_timeout=None,
        **kwargs,
    ):
        """
        Runs a command as a subprocess
        :param command: command to execute, does not need to be formatted
        :param stdout: where to pipe the standard output
        :param assert_success: should we check if the process succeeded?
        :param wait_for_completion: should we wait for completion?
        :param wait_for_completion_timeout: if yes, how much?
        :param kwargs: additional params which should be passed to format
        :return:
        """
        command = command.format(config=self._config_path, **self._deps, **kwargs)
        # log it
        self._logger.debug(command)

        # need to split the command into args
        _proc = subprocess.Popen(
            shlex.split(command), stdout=stdout, stdin=sys.stdin, stderr=sys.stderr
        )

        if wait_for_completion:
            _proc.wait(wait_for_completion_timeout)

        if assert_success:
            shell.assert_successful_result(_proc)

        # return the process instance for future use
        # if necessary
        return _proc
