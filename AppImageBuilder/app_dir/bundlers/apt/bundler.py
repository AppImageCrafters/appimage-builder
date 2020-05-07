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
import logging
import os

from AppImageBuilder.commands.apt_get import AptGet
from AppImageBuilder.commands.dpkg_deb import DpkgDeb, DpkgDebError
from .settings_validator import AptSettingsValidator
from .util import is_deb_file
from ..bundler import Bundler
from .config import Config
from .package_lists import *


class AptBundler(Bundler):
    def __init__(self, settings):
        super().__init__(settings)

        self.core_packages = apt_core_packages
        self.font_config_packages = apt_font_config_packages
        self.xclient_packages = apt_xclient_packages
        self.graphics_stack_packages = apt_graphics_stack_packages
        self.glibc_packages = apt_glibc_packages

        #   packages required by the runtime generators
        self.proot_apprun_packages = apt_proot_apprun_packages
        self.classic_apprun_packages = apt_classic_apprun_packages
        self.wrapper_apprun_packages = apt_wrapper_apprun_packages

        self.config = None
        self.apt_get = None

        self.deployed_packages = []

    def validate_configuration(self):
        validator = AptSettingsValidator(self.settings)
        validator.validate()

    def get_run_report(self):
        return {
            'apt': {
                'sources': sorted(self.config.apt_source_lines),
                'packages': sorted(self.deployed_packages)
            }
        }

    def run(self):
        self.config = Config(self.cache_dir)
        self.config.load(self.settings)
        self.config.generate()

        self.apt_get = AptGet(self.config.apt_prefix, self.config.get_apt_conf_path())

        if not os.getenv('AB_APT_NO_UPDATE', False):
            self.apt_get.update()

        self.config.clear_installed_packages()

        self._extend_partitions()
        exclusion_list = self._generate_exclusion_list()

        self.config.set_installed_packages(exclusion_list)

        self.apt_get.install(self.config.apt_include)

        self._extract_packages_into_app_dir(self.app_dir, exclusion_list)

    def _extract_packages_into_app_dir(self, app_dir_path, exclusion_list):
        archives_path = self.config.get_apt_archives_path()

        for file_name in os.listdir(archives_path):
            if is_deb_file(file_name):
                package_name, package_version, package_arch = self._extract_package_info(file_name)

                if not self._is_excluded(package_name):
                    file_path = os.path.join(archives_path, file_name)
                    partition_path = self._resolve_partition_path(package_name, app_dir_path)
                    logging.info("Deploying: %s %s %s => %s" %
                                 (package_name, package_version, package_arch,
                                  partition_path.replace(app_dir_path, 'AppDir'))
                                 )

                    self.deployed_packages.append("%s %s %s" % (package_name, package_version, package_arch))

                    package_files = self._extract_deb(file_path, partition_path)
                    self._make_symlinks_relative(package_files, partition_path)

    def _extract_deb(self, file_path, root):
        try:
            os.makedirs(root, exist_ok=True)
            dpkg_deb = DpkgDeb()
            dpkg_deb.log_command = False
            dpkg_deb.extract(file_path, root)

            return dpkg_deb.extracted_files
        except DpkgDebError as er:
            logging.error(er)

    def _generate_exclusion_list(self):
        complete_install_list = self.apt_get.generate_install_list(self.config.apt_include)

        exclusion_list = []
        for package in complete_install_list:
            if self._is_excluded(package[0]):
                exclusion_list.append(package)

        return exclusion_list

    def _is_excluded(self, package_name):
        for package_exp in self.config.apt_include:
            if package_exp and fnmatch.fnmatch(package_name, package_exp):
                return False

        for package_exp in self.excluded_packages:
            if package_exp and fnmatch.fnmatch(package_name, package_exp):
                return True

        for package_exp in self.config.apt_exclude:
            if package_exp and fnmatch.fnmatch(package_name, package_exp):
                return True

        return False

    def _extend_partitions(self):
        for name, packages in self.partitions.items():
            raw_package_list = self.apt_get.generate_install_list(packages)
            package_names = [pkg[0] for pkg in raw_package_list]
            self.partitions[name].extend(package_names)

    @staticmethod
    def _extract_package_info(file_name):
        file_name, file_extension = os.path.splitext(file_name)

        reversed_file_name = file_name[::-1]
        arch, version, name = reversed_file_name.split('_', 2)

        return name[::-1], version[::-1], arch[::-1]
