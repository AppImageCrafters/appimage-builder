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
import os

from .bundler import Bundler
from .apt.bundler import AptBundler
from .yum.bundler import YumBundler


class BundlerFactoryError(RuntimeError):
    pass


class BundlerFactory:
    def __init__(self, app_dir, cache_dir):
        self.bundlers = {
            'apt': AptBundler
        }
        self.app_dir = app_dir
        self.cache_dir = cache_dir

        self.glibc_partition = 'opt/libc'
        self.runtime = None

    def list_bundlers(self):
        return self.bundlers.keys()

    def create(self, name, settings):
        self._validate_bundler_name(name)
        bundler_class = self.bundlers[name]
        bundler = bundler_class(settings)

        self._configure_bundler(bundler)
        bundler.validate_configuration()

        return bundler

    def _configure_bundler(self, bundler: Bundler):
        bundler.app_dir = self.app_dir
        bundler.cache_dir = self.cache_dir
        self._configure_packages(bundler)
        self._configure_partitions(bundler)

    def _validate_bundler_name(self, name):
        if name not in self.bundlers:
            raise BundlerFactoryError("Unknown bundler: %s. Allowed values are %s"
                                      % (name, ', '.join(self.bundlers.keys())))

    def _configure_packages(self, bundler):
        if self.runtime == 'wrapper':
            bundler.included_packages = bundler.wrapper_apprun_packages

            bundler.excluded_packages = [
                *bundler.core_packages,
                *bundler.font_config_packages,
                *bundler.graphics_stack_packages,
                *bundler.xclient_packages,
            ]

        if self.runtime == 'proot':
            bundler.included_packages = bundler.proot_apprun_packages
            bundler.excluded_packages = bundler.core_packages

        if self.runtime == 'classic':
            bundler.included_packages = bundler.classic_apprun_packages
            bundler.excluded_packages = bundler.core_packages

    def _configure_partitions(self, bundler):
        if self.runtime == 'wrapper':
            bundler.partitions[self.glibc_partition] = bundler.glibc_packages
