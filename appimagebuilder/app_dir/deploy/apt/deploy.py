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
from pathlib import Path

from . import listings
from .venv import Venv


class Deploy:
    """Deploy deb packages into an AppDir using apt-get to resolve the packages and their dependencies"""

    def __init__(self, apt_venv: Venv):
        self.apt_venv = apt_venv
        self.logger = logging.getLogger("AptPackageDeploy")

    def deploy(
        self, package_names: [str], appdir_root: str, exclude_patterns=None
    ) -> [str]:
        """Deploy the packages and their dependencies to appdir_root.

        Packages listed in exclude will not be deployed nor their dependencies.
        Packages from the system services and graphics listings will be added by default to the exclude list.
        Packages from the glibc listing will be deployed using <target>/opt/libc as prefix
        """
        if exclude_patterns is None:
            exclude_patterns = []

        self._prepare_apt_venv()

        deploy_list = self._resolve_packages_to_deploy(exclude_patterns, package_names)

        # use apt-get install --download-only to avoid packages being configured by apt-get
        self.apt_venv.install_download_only(deploy_list)

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
        self.apt_venv.set_installed_packages(apt_core_packages)

    def _resolve_packages_to_deploy(self, exclude_patterns, package_names):
        # extend user defined exclude listing with the default exclude listing
        exclude_patterns.extend(listings.default_exclude_list)
        excluded_packages = set(self.apt_venv.search_packages(exclude_patterns))
        # don't exclude explicitly required packages
        required_packages = set(self.apt_venv.search_packages(package_names))
        excluded_packages = excluded_packages.difference(required_packages)
        # lists packages to be installed including dependencies
        full_install_list = set(self.apt_venv.install_simulate(package_names))
        refined_exclude_list = excluded_packages.intersection(full_install_list)
        refined_install_list = full_install_list.difference(refined_exclude_list)
        # set the exclude packages as installed to avoid their retrieval by the "apt-get install" method
        self.apt_venv.set_installed_packages(refined_exclude_list)
        return refined_install_list

    def _extract_packages(self, appdir_root, packages):
        # manually extract downloaded packages to be able to create the opt/libc partition
        # where the glibc library and other related packages will be placed
        appdir_root = Path(appdir_root).absolute()
        # ensure target directories exists
        libc_root = appdir_root / "opt" / "libc"
        appdir_root.mkdir(exist_ok=True, parents=True)
        libc_root.mkdir(exist_ok=True, parents=True)
        # list libc related packages
        libc_packages = self.apt_venv.install_simulate(listings.glibc)

        for package in packages:
            final_target = appdir_root
            if package in libc_packages:
                final_target = libc_root

            self.logger.info(
                "Deploying %s to %s" % (package.get_expected_file_name(), final_target)
            )
            self.apt_venv.extract_package(package, final_target)

        return packages
