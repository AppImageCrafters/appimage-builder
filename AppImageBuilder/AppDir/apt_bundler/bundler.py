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

from AppImageBuilder.commands.apt_get import AptGet
from AppImageBuilder.commands.dpkg_deb import DpkgDeb, DpkgDebError


class AptBundler:
    def __init__(self, config):
        self.config = config

        self.apt_get = AptGet(self.config.apt_prefix, self.config.get_apt_conf_path())
        self.dpkg_deb = DpkgDeb()
        self.default_exclude_list = [
            'adduser',
            'avahi-daemon',
            'base-files',
            'bind9-host',
            'consolekit',
            'dbus',
            'debconf',
            'dpkg',
            'lsb-base',
            'multiarch-support',
            'passwd',
            'systemd',
        ]

    def deploy_packages(self, app_dir_path):
        self.apt_get.update()

        exclusion_list = self._generate_exclusion_list()
        self.config.set_installed_packages(exclusion_list)

        self.apt_get.install(self.config.apt_include)

        self._extract_packages_into_app_dir(app_dir_path)

    def _extract_packages_into_app_dir(self, app_dir_path):
        archives_path = self.config.get_apt_archives_path()

        for file_name in os.listdir(archives_path):
            if self._is_deb_file(file_name):
                file_path = os.path.join(archives_path, file_name)
                self._extract_deb(file_path, app_dir_path)

    def _is_deb_file(self, file_name):
        return file_name.endswith('.deb')

    def _extract_deb(self, file_path, app_dir_path):
        try:
            self.dpkg_deb.extract(file_path, app_dir_path)
        except DpkgDebError as er:
            logging.error(er)

    def _generate_exclusion_list(self):
        exclusion_list = self.default_exclude_list
        exclusion_list.extend(self.config.apt_exclude)

        for pkg in self.config.apt_include:
            if pkg in exclusion_list:
                exclusion_list.remove(pkg)

        return exclusion_list
