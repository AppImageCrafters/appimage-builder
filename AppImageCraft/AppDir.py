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
import logging

from AppImageCraft.AppRunBuilder import AppRunBuilder
from AppImageCraft.LinkerTool import LinkerTool
from AppImageCraft.PkgTool import PkgTool
from AppImageCraft.AppDirIsolator import AppDirIsolator
from AppImageCraft.Hook.Qt5Hook import Qt5Hook


class AppDir:
    path = ""

    app_id = ""
    app_name = ""
    app_summary = ""
    app_description = ""
    app_categories = []
    app_runnable = ""

    bundle_include = set()
    bundle_exclude = set()
    bundle_packages = set()

    deploy_registry = {}
    libs_registry = {}

    bundle_ldd_dependencies = set()

    def __init__(self, path=None, app_runnable=None):
        self.path = path
        self.app_runnable = app_runnable
        self.logger = logging.getLogger("AppDir")

    def install(self, additional_pkgs=None, excluded_pkgs=None):
        if excluded_pkgs is None:
            excluded_pkgs = set()

        if additional_pkgs is None:
            additional_pkgs = set()

        early_deployed_files = self._deploy_packages(additional_pkgs, excluded_pkgs)

        app_dir_isolator = AppDirIsolator(self.path)
        app_dir_isolator.isolate()

        self.deploy_registry = {**early_deployed_files, **app_dir_isolator.deploy_map}
        self.libs_registry = app_dir_isolator.libs_map

        hooks = [Qt5Hook(self)]
        for hook in hooks:
            if hook.active():
                hook.after_install()


    def _deploy_packages(self, additional_pkgs, excluded_pkgs):
        self.logger.debug("Deploying packages to: %s" % self.path)
        absolute_app_dir_path = os.path.abspath(self.path)

        pkg_tool = PkgTool()
        self.bundle_packages = set(additional_pkgs)

        if self.bundle_ldd_dependencies:
            self.bundle_packages = self.bundle_packages.union(
                pkg_tool.find_owner_packages(self.bundle_ldd_dependencies))

        self.bundle_packages = self.bundle_packages.difference(excluded_pkgs)
        return pkg_tool.deploy_pkgs(self.bundle_packages, absolute_app_dir_path)

    def _generate_ld_path(self, elf_files):
        ld_paths = set()
        for file in elf_files:
            dir_name = os.path.dirname(file)
            relative_path = os.path.relpath(dir_name, self.path)
            ld_paths.add(relative_path)

        return list(ld_paths)

    def generate_app_run(self):
        if not self.app_runnable:
            raise RuntimeError("Missing runnable")

        linker = LinkerTool()

        app_run_generator = AppRunBuilder(self.path, self.app_runnable, linker.binary_path)

        elf_files = linker.list_libraries_files(self.path)
        app_run_generator.library_paths = self._generate_ld_path(elf_files)

        app_run_generator.build()
