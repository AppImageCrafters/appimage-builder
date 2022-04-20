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


import fnmatch
import hashlib
import logging
import os
import pathlib
import subprocess
from pathlib import Path
from urllib import request

from appimagebuilder.utils import shell
from .package import Package

DEPENDS_ON = ["dpkg-deb", "apt-get", "apt-key", "fakeroot", "apt-cache"]


class Venv:
    def __init__(
        self,
        base_path: str,
        sources: [str],
        keys: [str],
        architectures: [],
        user_options: {} = None,
    ):
        self.logger = logging.getLogger("apt")
        self._deps = shell.resolve_commands_paths(DEPENDS_ON)

        self.sources = sources
        self.keys = keys
        self.architectures = architectures
        self.user_options = user_options

        self._generate_paths(base_path)
        self._write_apt_conf(user_options, architectures)
        self._write_sources_list(sources)
        self._write_keys(keys)
        self._write_dpkg_arch(architectures)

    def _generate_paths(self, base_path):
        self._base_path = Path(base_path).absolute()
        self._apt_conf_path = self._base_path / "apt.conf"
        self._apt_conf_parts_path = self._base_path / "apt.conf.d"
        self._apt_sources_list_path = self._base_path / "sources.list"
        self._apt_sources_list_parts_path = self._base_path / "sources.list.d"
        self._apt_preferences_parts_path = self._base_path / "preferences.d"
        self._apt_key_parts_path = self._base_path / "keys"
        self._dpkg_path = self._base_path / "dpkg"
        self._dpkg_status_path = self._dpkg_path / "status"
        self._apt_archives_path = self._base_path / "archives"

        self._base_path.mkdir(parents=True, exist_ok=True)
        self._apt_conf_parts_path.mkdir(parents=True, exist_ok=True)
        self._apt_preferences_parts_path.mkdir(parents=True, exist_ok=True)
        self._apt_key_parts_path.mkdir(parents=True, exist_ok=True)
        self._dpkg_path.mkdir(parents=True, exist_ok=True)
        self._dpkg_status_path.touch(exist_ok=True)

    def _write_apt_conf(self, user_options, architectures: [str]):
        options = {
            "Dir": self._base_path,
            "Dir::State": self._base_path,
            "Dir::Cache": self._base_path,
            "Dir::Etc::Main": self._apt_conf_path,
            "Dir::Etc::Parts": self._apt_conf_parts_path,
            "Dir::Etc::SourceList": self._apt_sources_list_path,
            "Dir::Etc::SourceListParts": self._apt_sources_list_parts_path,
            "Dir::Etc::PreferencesParts": self._apt_preferences_parts_path,
            "Dir::Etc::TrustedParts": self._apt_key_parts_path,
            "Dir::State::status": self._dpkg_status_path,
            "Dir::Ignore-Files-Silently": False,
            "APT::Install-Recommends": False,
            "APT::Install-Suggests": False,
            "APT::Immediate-Configure": False,
            "APT::Architecture": architectures[0],
            "APT::Architectures": architectures,
            "Acquire::Languages": "none",
        }

        if user_options:
            options.update(user_options)

        # write apt.conf
        with open(self._apt_conf_path, "w") as f:
            for k, v in options.items():
                if isinstance(v, str) or isinstance(v, pathlib.Path):
                    f.write('%s "%s";\n' % (k, v))
                    continue

                if isinstance(v, list):
                    f.write("%s {" % k)
                    for sv in v:
                        f.write('"%s"; ' % sv)
                    f.write("}\n")
                    continue

                f.write("%s %s;\n" % (k, v))

    def _write_sources_list(self, sources):
        with open(self._apt_sources_list_path, "w") as f:
            for line in sources:
                f.write("%s\n" % line)

    def _write_keys(self, keys: [str]):
        for key_url in keys:
            key_url_hash = hashlib.md5(key_url.encode()).hexdigest()
            key_path = os.path.join(self._apt_key_parts_path, "%s.asc" % key_url_hash)
            if not os.path.exists(key_path):
                self.logger.info("Download key file: %s" % key_url)
                request.urlretrieve(key_url, key_path)

    def _get_environment(self):
        env = os.environ.copy()
        env["APT_CONFIG"] = self._apt_conf_path
        env["DEBIAN_FRONTEND"] = "noninteractive"

        return env

    def set_installed_packages(self, packages):
        with open(self._dpkg_status_path, "w") as f:
            for package in packages:
                f.write(
                    "Package: %s\n"
                    "Status: install ok installed\n"
                    "Version: %s\n"
                    "Architecture: %s\n"
                    "\n" % (package.name, package.version, package.arch)
                )

    def _run_apt_cache_show(self, package_names: [str]):
        if not package_names:
            return None

        command = "{apt-cache} show %s" % " ".join(package_names)
        command = command.format(**self._deps)
        self.logger.debug(command)

        _proc = subprocess.run(
            command, stdout=subprocess.PIPE, shell=True, env=self._get_environment()
        )
        shell.assert_successful_result(_proc)
        return _proc

    def update(self) -> None:
        command = "apt-get update"
        self.logger.info(command)

        _proc = subprocess.run(command, shell=True, env=self._get_environment())
        shell.assert_successful_result(_proc)

    def search_names(self, patterns: [str]):
        output = self._run_apt_cache_pkgnames()
        packages = output.stdout.decode("utf-8").splitlines()

        filtered_packages = []
        for pattern in patterns:
            filtered_packages.extend(fnmatch.filter(packages, pattern))

        return filtered_packages

    def _run_apt_cache_pkgnames(self):
        command = "{apt-cache} pkgnames".format(**self._deps)
        self.logger.debug(command)
        proc = subprocess.run(
            command, stdout=subprocess.PIPE, shell=True, env=self._get_environment()
        )
        shell.assert_successful_result(proc)
        return proc

    def resolve_packages(self, packages: [Package]) -> [Package]:
        packages_str = [str(package) for package in packages]
        output = self._run_apt_get_install_download_only(packages_str)

        stdout_str = output.stderr.decode("utf-8")
        installed_packages = []
        for line in stdout_str.splitlines():
            if line.startswith("Dequeuing") and line.endswith(".deb"):
                file_path = Path(line.split(" ")[1])
                installed_packages.append(Package.from_file_path(file_path))

        return installed_packages

    def _run_apt_get_install_download_only(self, packages: [str]):
        command = (
            "{apt-get} install -y --no-install-recommends --download-only -o Debug::pkgAcquire=1 "
            "{packages}".format(**self._deps, packages=" ".join(packages))
        )
        self.logger.debug(command)
        command = subprocess.run(
            command,
            stderr=subprocess.PIPE,
            shell=True,
            env=self._get_environment(),
        )

        shell.assert_successful_result(command)
        return command

    def resolve_archive_paths(self, packages: [Package]):
        paths = [
            self._apt_archives_path / pkg.get_expected_file_name() for pkg in packages
        ]
        return paths

    def extract_package(self, package, target):
        path = self._apt_archives_path / package.get_expected_file_name()

        command = "{dpkg-deb} -x {archive} {directory}".format(
            **self._deps, archive=path, directory=target
        )
        self.logger.debug(command)
        output = subprocess.run(command, shell=True, env=self._get_environment())
        shell.assert_successful_result(output)

    def _write_dpkg_arch(self, architectures: [str]):
        with open(self._dpkg_path / "arch", "w") as f:
            for arch in architectures:
                f.write("%s\n" % arch)

    def search_packages(self, names):
        packages = []

        pkg_name = None
        pkg_version = None
        pkg_arch = None

        output = self._run_apt_cache_show(names)
        for line in output.stdout.decode("utf-8").splitlines():
            if line.startswith("Package:"):
                pkg_name = line.split(" ", maxsplit=2)[1]

            if line.startswith("Architecture"):
                pkg_arch = line.split(" ", maxsplit=2)[1]

            if line.startswith("Version:"):
                pkg_version = line.split(" ", maxsplit=2)[1]

            # empty lines indicate the end of a package description block
            if not line and pkg_name:
                packages.append(Package(pkg_name, pkg_version, pkg_arch))
                pkg_name = None
                pkg_arch = None
                pkg_version = None

        # empty lines indicate the end of a package description block
        if pkg_name:
            packages.append(Package(pkg_name, pkg_version, pkg_arch))

        return packages
