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
import glob
import logging
import os
import re
import subprocess
from pathlib import Path


class AptPackageDeployError(Exception):
    pass


class AptPackageDeploy:
    """Deploy deb packages into an AppDir using apt-get to resolve the packages and their dependencies"""

    # manually crafted lists of packages used to determine what should be excluded by default or deployed in
    # a different partition
    listings = {
        "glibc": ["libc6", "zlib1g", "libstdc++6"],
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

    def __init__(self, cache_dir, sources: [str], keys: [str], options: {}):
        self.cache_dir = os.path.abspath(cache_dir)
        self.apt_conf_path = os.path.join(self.cache_dir, "apt.conf")

        self.dpkg_dir_path = os.path.join(self.cache_dir, "dpkg")
        self.dpkg_status_path = os.path.join(self.dpkg_dir_path, "status")

        self.sources = sources
        self.apt_sources_path = os.path.join(self.cache_dir, "sources.list")

        self.keys = keys
        self.options = {
            "Dir": self.cache_dir,
            "Dir::State": self.cache_dir,
            "Dir::Cache": self.cache_dir,
            "Dir::Etc::Main": self.apt_conf_path,
            "Dir::Etc::Parts": self.cache_dir,
            "Dir::Etc::sourcelist": self.apt_sources_path,
            "Dir::Etc::PreferencesParts": self.cache_dir,
            "Dir::State::status": self.dpkg_status_path,
            "Dir::Ignore-Files-Silently": False,
            "APT::Install-Recommends": False,
            "APT::Install-Suggests": False,
            "APT::Immediate-Configure": False,
            "Acquire::Languages": "none",
        }
        self.options.update(options)

        self.logger = logging.getLogger("AptPackageDeploy")

    def deploy(self, packages: [str], target: str, exclude: [str]):
        """Deploy the packages and their dependencies to appdir. The packages listed in exclude will not be
        deployed nor their dependencies.

        Packages from the system services and graphics listings will be added by default to the exclude list.

        Packages from the glibc listing will be deployed using <target>/opt/libc as prefix
        """

        self._configure()

        # avoid packages from previous builds mix with the current build
        self._clean()

        self._update()

        # resolve package names patterns
        packages = self._extend_package_names_patterns(packages)
        exclude = self._extend_package_names_patterns(exclude)

        # extend exclude list with default values keeping the packages that were required explicitly
        exclude = self._refine_exclude(exclude, packages)

        # set the excluded packages as installed to avoid their retrieval
        self._set_installed_packages(exclude)

        # use apt-get install --download-only to ensure that all the dependencies are resolved and downloaded
        self._download(packages)

        # manually extract downloaded packages to be able to create the opt/libc partition
        # where the glibc library and other related packages will be placed
        self._extract(target)

    def _refine_exclude(self, exclude, packages):
        # avoid duplicates
        exclude = set(exclude)
        # don't bundle graphic stack packages
        exclude = exclude.union(self.listings['graphics'])
        # don't bundle system services
        exclude = exclude.union(self.listings['system_services'])
        # don't exclude explicitly required packges
        exclude.difference_update(packages)
        return exclude

    def _configure(self):
        os.makedirs(self.cache_dir, exist_ok=True)
        os.makedirs(self.dpkg_dir_path, exist_ok=True)
        os.makedirs(os.path.join(self.dpkg_dir_path, "updates"), exist_ok=True)
        os.makedirs(os.path.join(self.dpkg_dir_path, "info"), exist_ok=True)

        os.putenv("DEBIAN_FRONTEND", "noninteractive")
        os.putenv("APT_CONFIG", self.apt_conf_path)

        # write apt.conf
        with open(self.apt_conf_path, "w") as f:
            for k, v in self.options.items():
                f.write("%s %s;\n" % (k, v))

        # write sources.list
        with open(self.apt_sources_path, "w") as f:
            for line in self.sources:
                f.write("%s\n" % line)

        Path(self.dpkg_status_path).touch(exist_ok=True)

    def _update(self):
        if os.getenv("ABUILDER_APT_SKIP_UPDATE", False):
            self.logger.warning("`apt-get update` skip, newly added repositories will not be reachable!")
            return

        output = subprocess.run("apt-get update", shell=True)
        if output.returncode:
            raise AptPackageDeployError('"%s" execution failed with code %s' % (output.args, output.returncode))

    @staticmethod
    def _download(packages):
        output = subprocess.run(
            "apt-get install -y --download-only %s" % (" ".join(packages)),
            shell=True,
        )
        if output.returncode:
            raise AptPackageDeployError(
                '"%s" execution failed with code %s' % (output.args, output.returncode)
            )

    def _extract(self, target: str):
        for package_path in glob.glob(self.cache_dir + "/archives/*.deb"):
            self.logger.info("Deploying %s" % os.path.basename(package_path))
            self._extract_deb(package_path, target)

    def _resolve_package_file_path(self, package):
        pattern = self.cache_dir + "/archives/%s_*_%s.deb"
        paths = glob.glob(pattern % (package["name"], package["architecture"]))
        if paths:
            return paths[0]

        raise AptPackageDeployError(
            "Unable to determine file path for %s" % package["name"]
        )

    @staticmethod
    def _extract_deb(package_path, target):
        output = subprocess.run(
            "dpkg-deb -x %s %s" % (package_path, target), shell=True
        )
        if output.returncode:
            raise AptPackageDeployError(
                '"%s" execution failed with code %s' % (output.args, output.returncode)
            )

    @staticmethod
    def _parse_deb_info(stdout):
        """Read the first package information from the dpkg-deb --info output"""
        package = {}

        # read package name
        search = re.match("Package: (.+)\n", stdout)
        package["name"] = search.group(1)

        search = re.search("Architecture: (.*)", stdout, flags=re.MULTILINE)
        package["architecture"] = search.group(1)

        search = re.search("Version: (.*)", stdout, flags=re.MULTILINE)
        package["version"] = search.group(1)

        search = re.search("Pre-Depends: (.*)", stdout, flags=re.MULTILINE)
        if search:
            pkg_list = search.group(1).split(",")
            pkg_list = [pkg.strip() for pkg in pkg_list]
            pkg_list = [pkg.split(" ")[0] for pkg in pkg_list]
            package["pre-depends"] = pkg_list
        else:
            package["pre-depends"] = []

        search = re.search("Depends: (.*)", stdout, flags=re.MULTILINE)
        if search:
            pkg_list = search.group(1).split(",")
            pkg_list = [pkg.strip() for pkg in pkg_list]
            pkg_list = [pkg.split(" ")[0] for pkg in pkg_list]
            package["depends"] = pkg_list
        else:
            package["depends"] = []

        return package

    def _clean(self):
        if os.getenv("ABUILDER_APT_SKIP_CLEAN", False):
            self.logger.warning("`apt-get clean` skip, excluded package may still be deployed if they are in cache!")
            return

        output = subprocess.run("apt-get clean", shell=True)
        if output.returncode:
            raise AptPackageDeployError(
                '"%s" execution failed with code %s' % (output.args, output.returncode)
            )

    def _set_installed_packages(self, exclude):
        with open(self.dpkg_dir_path + "/status", "w") as f:
            for package in exclude:
                # read package info
                output = subprocess.run(
                    "apt-cache show %s" % package,
                    stdout=subprocess.PIPE,
                    shell=True,
                )

                # write package info setting the status to installed
                for line in output.stdout.decode("utf-8").splitlines():
                    if line.startswith("Package:"):
                        f.write("%s\n" % line)
                        f.write("Status: install ok installed\n")

                    if line.startswith("Architecture:") or line.startswith("Version"):
                        f.write("%s\n" % line)
                    if not line:
                        f.write("%s\n" % line)
                        break

    @staticmethod
    def _extend_package_names_patterns(patterns):
        output = subprocess.run(
            "apt-cache pkgnames", stdout=subprocess.PIPE, shell=True
        )
        if output.returncode:
            raise AptPackageDeployError(
                '"%s" execution failed with code %s' % (output.args, output.returncode)
            )
        packages = output.stdout.decode("utf-8").splitlines()

        filtered_packages = []
        for pattern in patterns:
            filtered_packages.extend(fnmatch.filter(packages, pattern))

        return filtered_packages


if __name__ == "__main__":
    # execute only if run as the entry point into the program
    pkgDeploy = AptPackageDeploy(
        "/tmp/apt-deploy-cache",
        ["deb [arch=amd64] http://deb.debian.org/debian/ bullseye main"],
        keys=[],
        options={
            "APT::Get::AllowUnauthenticated": True,
            "Acquire::AllowInsecureRepositories": True,
        },
    )

    pkgDeploy.deploy(["perl"], "/tmp/AppDir", [])
