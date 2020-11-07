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
import glob
import hashlib
import logging
import os
import subprocess

from pathlib import Path
from urllib import request

from .errors import PackageDeployError
from .utils import filter_packages_cache, resolve_packages_from_simulated_install, \
    package_tuples_to_file_names, run_apt_get_update, run_dpkg_deb_extract, run_apt_get_install_download_only


class PackageDeploy:
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
        self.apt_keys_path = os.path.join(self.cache_dir, "keys")

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
            "Dir::Etc::TrustedParts": self.apt_keys_path,
            "Dir::State::status": self.dpkg_status_path,
            "Dir::Ignore-Files-Silently": False,
            "APT::Install-Recommends": False,
            "APT::Install-Suggests": False,
            "APT::Immediate-Configure": False,
            "Acquire::Languages": "none",
        }
        self.options.update(options)

        self.logger = logging.getLogger("AptPackageDeploy")

    def deploy(self, packages: [str], target: str, exclude: [str] = []):
        """Deploy the packages and their dependencies to target.

        Packages listed in exclude will not be deployed nor their dependencies.
        Packages from the system services and graphics listings will be added by default to the exclude list.
        Packages from the glibc listing will be deployed using <target>/opt/libc as prefix
        """

        self._configure()

        self._update()

        # resolve package names patterns
        packages = filter_packages_cache(packages)
        exclude = filter_packages_cache(exclude)

        # extend exclude list with default values keeping the packages that were required explicitly
        exclude = self._refine_exclude(exclude, packages)

        # set the excluded packages as installed to avoid their retrieval
        self._set_installed_packages(exclude)

        # use apt-get install --download-only to ensure that all the dependencies are resolved and downloaded
        run_apt_get_install_download_only(packages)

        # manually extract downloaded packages to be able to create the opt/libc partition
        # where the glibc library and other related packages will be placed
        self._extract(packages, target)

    def _refine_exclude(self, exclude, packages):
        # avoid duplicates
        exclude = set(exclude)
        # don't bundle graphic stack packages
        exclude = exclude.union(self.listings["graphics"])
        # don't bundle system services
        exclude = exclude.union(self.listings["system_services"])
        # don't exclude explicitly required packges
        exclude.difference_update(packages)
        return exclude

    def _configure(self):
        os.makedirs(self.cache_dir, exist_ok=True)
        os.makedirs(self.apt_keys_path, exist_ok=True)
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

        self._retrieve_keys()

    def _retrieve_keys(self):
        for key_url in self.keys:
            key_url_hash = hashlib.md5(key_url.encode()).hexdigest()
            key_path = os.path.join(self.apt_keys_path, "%s.asc" % key_url_hash)
            if not os.path.exists(key_path):
                self.logger.info("Download key file: %s" % key_url)
                request.urlretrieve(key_url, key_path)

    def _update(self):
        if os.getenv("ABUILDER_APT_SKIP_UPDATE", False):
            self.logger.warning(
                "`apt-get update` skip, newly added repositories will not be reachable!"
            )
            return

        run_apt_get_update()

    def _extract(self, packages, target: str):
        # ensure target directories exists
        libc_target = os.path.join(target, "opt/libc")
        os.makedirs(libc_target, exist_ok=True)
        os.makedirs(target, exist_ok=True)

        # make sure that all glibc related package will be properly identified
        libc_packages = resolve_packages_from_simulated_install(
            self.listings["glibc"]
        )
        libc_package_files = package_tuples_to_file_names(libc_packages)

        # make sure that only the required packages and their dependencies are bundled (not the whole apt cache)
        packages = resolve_packages_from_simulated_install(packages)
        package_files = package_tuples_to_file_names(packages)

        for file in package_files:
            package_path = os.path.join(self.cache_dir, "archives", file)
            if os.path.basename(package_path) in libc_package_files:
                self.logger.info(
                    "Deploying %s to %s" % (os.path.basename(package_path), libc_target)
                )
                run_dpkg_deb_extract(package_path, libc_target)
            else:
                self.logger.info(
                    "Deploying %s to %s" % (os.path.basename(package_path), target)
                )
                run_dpkg_deb_extract(package_path, target)

    def _resolve_package_file_path(self, package):
        pattern = self.cache_dir + "/archives/%s_*_%s.deb"
        paths = glob.glob(pattern % (package["name"], package["architecture"]))
        if paths:
            return paths[0]

        raise PackageDeployError(
            "Unable to determine file path for %s" % package["name"]
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
