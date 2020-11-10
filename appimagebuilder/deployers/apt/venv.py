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
import re
import subprocess
import urllib
from pathlib import Path
from urllib import request

from .errors import AptVenvError


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

        self._generate_paths(base_path)
        self._write_apt_conf(user_options, architectures)
        self._write_sources_list(sources)
        self._write_keys(keys)

    def _generate_paths(self, base_path):
        self._base_path = Path(base_path).absolute()
        self._apt_conf_path = self._base_path / "apt.conf"
        self._apt_sources_list_path = self._base_path / "sources.list"
        self._apt_key_parts_path = self._base_path / "keys"
        self._dpkg_path = self._base_path / "dpkg"
        self._dpkg_status_path = self._dpkg_path / "status"
        self._apt_archives_path = self._base_path / "archives"

        self._base_path.mkdir(parents=True, exist_ok=True)
        self._apt_key_parts_path.mkdir(parents=True, exist_ok=True)
        self._dpkg_path.mkdir(parents=True, exist_ok=True)
        self._dpkg_status_path.touch(exist_ok=True)

    def _write_apt_conf(self, user_options, architectures: [str]):
        options = {
            "Dir": self._base_path,
            "Dir::State": self._base_path,
            "Dir::Cache": self._base_path,
            "Dir::Etc::Main": self._apt_conf_path,
            "Dir::Etc::Parts": self._base_path,
            "Dir::Etc::sourcelist": self._apt_sources_list_path,
            "Dir::Etc::PreferencesParts": self._base_path,
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
                if isinstance(v, str):
                    f.write("%s \"%s\";\n" % (k, v))
                    continue

                if isinstance(v, list):
                    f.write("%s {" % k)
                    for sv in v:
                        f.write("\"%s\"; " % sv)
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

    def set_installed_packages(self, packages: [str]):
        with open(self._dpkg_status_path, "w") as f:
            for package in packages:
                try:
                    # read package info
                    output = self._run_apt_cache_show(package)

                    # write package info setting the status to installed
                    for line in output.stdout.decode("utf-8").splitlines():
                        if line.startswith("Package:"):
                            f.write("%s\n" % line)
                            f.write("Status: install ok installed\n")

                        if line.startswith("Architecture:") or line.startswith(
                                "Version"
                        ):
                            f.write("%s\n" % line)
                        if not line:
                            f.write("%s\n" % line)
                            break
                except AptVenvError:
                    # errors here safe to be ignored as some packages from the exclusion list may not be present
                    # in the sources listings
                    pass

    def _run_apt_cache_show(self, package):
        output = subprocess.run(
            "apt-cache show %s" % package,
            stdout=subprocess.PIPE,
            shell=True,
            env=self._get_environment(),
        )
        self._assert_successful_output(output)
        return output

    def update(self) -> None:
        output = subprocess.run(
            "apt-get update", shell=True, env=self._get_environment()
        )
        self._assert_successful_output(output)

    def search_names(self, patterns: [str]):
        output = self._run_apt_cache_pkgnames()
        packages = output.stdout.decode("utf-8").splitlines()

        filtered_packages = []
        for pattern in patterns:
            filtered_packages.extend(fnmatch.filter(packages, pattern))

        return filtered_packages

    def _run_apt_cache_pkgnames(self):
        output = subprocess.run(
            "apt-cache pkgnames",
            stdout=subprocess.PIPE,
            shell=True,
            env=self._get_environment(),
        )
        self._assert_successful_output(output)
        return output

    def install_download_only(self, packages: [str]):
        packages_str = " ".join(packages)
        output = subprocess.run(
            "apt-get install -y --download-only %s" % packages_str,
            shell=True,
            env=self._get_environment(),
        )
        self._assert_successful_output(output)

    def install_simulate(self, packages) -> (str, str, str):
        output = self._run_apt_get_simulate_install(packages)

        # find installed packages name, version and arch
        results = re.findall(
            "Inst\s+(?P<pkg_name>[\w|\d|\-|\.]+)\s+\((?P<pkg_version>\S+)\s.*\[(?P<pkg_arch>.*)\]\)",
            output.stdout.decode("utf-8"),
        )

        return results

    def _run_apt_get_simulate_install(self, packages):
        output = subprocess.run(
            "apt-get install -y --simulate %s" % (" ".join(packages)),
            stdout=subprocess.PIPE,
            shell=True,
            env=self._get_environment(),
        )

        self._assert_successful_output(output)
        return output

    def resolve_archive_paths(self, packages: [(str, str, str)]):
        paths = []
        for pkg_tuple in packages:
            file_name = "%s_%s_%s.deb" % pkg_tuple

            # apt encodes invalid chars to comply the deb file naming convention
            file_name = urllib.parse.quote(file_name, safe="+*").lower()

            # allows using '*' in file name parts
            path = next(self._apt_archives_path.glob(file_name))

            if not path.exists():
                raise AptVenvError(
                    "Unable to find archive path for %s %s %s. "
                    "This is provably an appimage-builder issue, please report it."
                    % pkg_tuple
                )

            paths.append(path)

        return paths

    def extract_archive(self, path, target):
        output = subprocess.run(
            "dpkg-deb -x %s %s" % (path, target),
            shell=True,
            env=self._get_environment(),
        )
        self._assert_successful_output(output)

    @staticmethod
    def _assert_successful_output(output):
        if output.returncode:
            raise AptVenvError(
                '"%s" execution failed with code %s' % (output.args, output.returncode)
            )
