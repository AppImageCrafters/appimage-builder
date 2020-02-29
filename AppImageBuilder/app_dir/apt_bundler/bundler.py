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
from .util import is_deb_file


class AptBundler:
    def __init__(self, config):
        self.config = config

        self.apt_get = AptGet(self.config.apt_prefix, self.config.get_apt_conf_path())
        self.dpkg_deb = DpkgDeb()
        self.dpkg_deb.log_command = False

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
            'libcap2-bin',
            'libinput-bin',
            'multiarch-support',
            'passwd',
            'systemd',
            'ucf',
            'iso-codes',
            'shared-mime-info',
            'mount',
            'xdg-user-dirs',
            'sysvinit-utils',
            'debianutils',
            'init-system-helpers',

            # fontconfig (is evil don't bundle it)
            'libfontconfig*',
            'fontconfig',
            'fontconfig-config',
            'libfreetype*',

            # X11
            'libx11-*',
            'libx11-xcb1*',
            'libxcb*',
            'libxcb-*',
            'libxfixes*',
            'libxrender*',
            'libxcomposite*',
            'libxdamage*',
            'libxcursor*',
            'libxdmcp6',

            # wayland
            'libwayland-server*',
            'libwayland-cursor*',
            'libwayland-client*',
            'libwayland-egl1*',

            # graphics stack
            'libgl1*',
            'libdrm*',
            'libegl1*',
            'libglapi*',
        ]
        self.partitions = {
            'opt/libc': [
                'libc6',
                'zlib1g',
                'libbsd0',
                'libglib2.0-0',
                'libstdc++6',
            ],
        }

    def deploy_packages(self, app_dir_path):
        if not os.getenv('APPIMAGE_BUILDER_DISABLE_APT_UPDATE', False):
            self.apt_get.update()

        self.config.clear_installed_packages()

        self._extend_partitions()
        exclusion_list = self._generate_exclusion_list()

        self.config.set_installed_packages2(exclusion_list)

        install_list = self.config.apt_include

        # required by AppRun
        install_list.append('grep')
        install_list.append('util-linux')
        install_list.append('coreutils')

        self.apt_get.install(self.config.apt_include)

        self._extract_packages_into_app_dir(app_dir_path)

    def _extract_packages_into_app_dir(self, app_dir_path):
        archives_path = self.config.get_apt_archives_path()

        for file_name in os.listdir(archives_path):
            if is_deb_file(file_name):
                file_path = os.path.join(archives_path, file_name)

                package_name = self._get_package_name(file_name)
                partition_path = self._resolve_partition_path(package_name, app_dir_path)
                logging.info("Deploying: %s to %s" % (file_name, partition_path.replace(app_dir_path, 'AppDir')))

                self._extract_deb(file_path, partition_path)

    def _extract_deb(self, file_path, root):
        try:
            os.makedirs(root, exist_ok=True)
            self.dpkg_deb.extract(file_path, root)
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

        for package_exp in self.default_exclude_list:
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
    def _get_package_name(file_name):
        reversed_file_name = file_name[::-1]
        extension, version, name = reversed_file_name.split('_', 2)
        return name[::-1]

    def _resolve_partition_path(self, package_name, app_dir_path):
        for name, packages in self.partitions.items():
            if package_name in packages:
                return os.path.join(app_dir_path, name)

        return app_dir_path
