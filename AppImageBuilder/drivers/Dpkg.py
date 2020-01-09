#  Copyright  2019 Alexis Lopez Zubieta
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
import os
import tempfile
import hashlib

from AppImageBuilder import drivers
from AppImageBuilder import tools


class DpkgDependency(drivers.Dependency):
    package_name = None

    def __init__(self, driver=None, source=None, target=None, package_name=None):
        super().__init__(driver, source, target)
        self.package_name = package_name

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, DpkgDependency):
            # don't attempt to compare against unrelated types
            return False

        return super().__eq__(o) and self.package_name == o.package_name

    def __str__(self):
        return super().__str__()

    def deploy(self, app_dir):
        pass


class Dpkg(drivers.Driver):
    id = 'dpkg'
    dpkg = None
    cache = {}

    # Base packages are will be excluded from the deploy list
    base_packages = {
        'minimal': [
            'ucf',  # Update Configuration File
            'coreutils',  # basic file, shell and text manipulation utilities of the GNU operating system.
            'dpkg',  # Debian package management system
            'debconf',  # Debian configuration management system
            'cdebconf',  # Debian configuration management system
            'sensible-utils',  # Utilities for sensible alternative selection
            'qtchooser',  # Wrapper to select between Qt development binary versions
            'systemd', # system and service manager
            'passwd', # change user password
            'procps', # Command line and full screen utilities for browsing procfs
            'util-linux', # miscellaneous system utilities
        ],
    }

    default_base_packages = 'minimal'

    def __init__(self):
        self.dpkg = tools.Dpkg()
        self.apt = tools.Apt()

    def list_base_dependencies(self, app_dir):
        dependencies = []
        if 'base' in self.config:
            self.default_base_packages = self.config['base']

        exclude_list = set()
        if self.default_base_packages in self.base_packages.keys():
            exclude_list.update(self.base_packages[self.default_base_packages])
        else:
            self.logger().error('Unknown dpkg base: %s' % self.default_base_packages)

        deploy_list = set()
        if 'include' in self.config:
            to_include = self.config['include']
            for package in to_include:
                if package in exclude_list:
                    self.logger().info('Forcing deployment of base package: %s' % package)
                    exclude_list.remove(package)

            self.logger().info('Listing dependencies of: %s' % ','.join(to_include))
            deploy_list.update(self.apt.dependencies(to_include))

        if 'exclude' in self.config:
            exclude_list.update(self.config['exclude'])

        for package in exclude_list:
            if package in deploy_list:
                deploy_list.remove(package)

        self.apt.download(deploy_list)

        self.dpkg.unpack_packages(os.path.join(self.apt.root, 'var', 'cache', 'apt', 'archives'), app_dir.path)

        return []

    def load_config(self, config):
        super().load_config(config)

        self.create_chroot()

    def create_chroot(self):
        self.logger().info("Updating apt cache")
        self.arch = self.config['arch'] if 'arch' in self.config else self.dpkg.get_deb_host_arch()
        self.sources = self.config['sources'] if 'sources' in self.config else self.apt.get_host_sources()
        self.apt_cache_dir = self.make_temp_dir_path()
        self.logger().info("Building base system at: %s" % self.apt_cache_dir)
        self.apt.configure(root=self.apt_cache_dir, arch=self.arch, sources=self.sources)
        self.apt.update()

    def make_temp_dir_path(self):
        name = hashlib.md5(os.getcwd().encode('utf-8')).hexdigest()
        path = "/tmp/appimage-builder-%s" % name
        os.makedirs(path, exist_ok=True)
        return path
