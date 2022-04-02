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
import logging
import os
import pathlib

from . import listings
from .venv import Venv


class Deploy:
    """Deploy deb packages into an AppDir using apt-get to resolve the packages and their dependencies"""

    def __init__(self, apt_venv: Venv):
        self.apt_venv = apt_venv
        self.logger = logging.getLogger("AptPackageDeploy")

    def deploy(
        self, include_patterns: [str], appdir_root: pathlib.Path, exclude_patterns=None
    ) -> [str]:
        """Deploy the packages and their dependencies to appdir_root.

        Packages listed in exclude will not be deployed nor their dependencies.
        Packages from the system services and graphics listings will be added by default to the exclude list.
        Packages from the glibc listing will be deployed using <target>/runtime/compat as prefix
        """
        if not include_patterns:
            # quick return if there is no packages to be deployed
            return

        self._prepare_apt_venv()
        deploy_list = self._resolve_packages_to_deploy(
            include_patterns, exclude_patterns
        )
        extracted_packages = self._extract_packages(appdir_root, deploy_list)
        return [str(package) for package in extracted_packages]

    def _prepare_apt_venv(self):
        if not os.getenv("ABUILDER_APT_SKIP_UPDATE", False):
            self.apt_venv.update()
        else:
            self.logger.warning(
                "Skipping`apt update` execution. Newly added sources will not be available!"
            )
        # set apt core packages as installed, required for it to properly resolve dependencies
        apt_core_packages = self.apt_venv.search_packages(listings.apt_core)
        apt_core_packages = self._remove_old_packages(apt_core_packages)
        self.apt_venv.set_installed_packages(apt_core_packages)

    def _resolve_packages_to_deploy(self, include_patterns, exclude_patterns):
        if exclude_patterns is None:
            exclude_patterns = []

        # extend user defined exclude listing with the default exclude listing
        exclude_patterns.extend(listings.default_exclude_list)
        excluded_packages = set(self.apt_venv.search_packages(exclude_patterns))
        # don't exclude explicitly required packages
        required_packages = set(self.apt_venv.search_packages(include_patterns))
        excluded_packages = excluded_packages.difference(required_packages)
        self.apt_venv.set_installed_packages(excluded_packages)
        # lists packages to be installed including dependencies
        deploy_list = set(self.apt_venv.resolve_packages(include_patterns))

        return deploy_list

    def _extract_packages(self, appdir_root, packages):
        # manually extract downloaded packages to be able to create the runtime/compat partition
        # where the glibc library and other related packages will be placed

        # ensure target directories exists
        libc_root = appdir_root / "runtime" / "compat"
        appdir_root.mkdir(exist_ok=True, parents=True)
        libc_root.mkdir(exist_ok=True, parents=True)
        libc_packages = self.list_glibc_related_packages()

        for package in packages:
            final_target = appdir_root
            if package in libc_packages:
                final_target = libc_root

            self.logger.info(
                "Deploying %s to %s" % (package.get_expected_file_name(), final_target)
            )
            self.apt_venv.extract_package(package, final_target)

        return packages

    def list_glibc_related_packages(self):
        initial_libc_packages = []
        for pkg_name in listings.glibc:
            for arch in self.apt_venv.architectures:
                initial_libc_packages.append("%s:%s" % (pkg_name, arch))
        libc_packages = self.apt_venv.resolve_packages(initial_libc_packages)
        return libc_packages

    def _remove_old_packages(self, apt_core_packages):
        latest_packages = {}
        for package in apt_core_packages:
            pkg_tuple = (package.name, package.arch)
            if pkg_tuple not in latest_packages:
                latest_packages[pkg_tuple] = package
            else:
                if package > latest_packages[pkg_tuple]:
                    latest_packages[pkg_tuple] = package

        return latest_packages.values()
