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
import argparse
import logging

from AppImageCraft.AppRunBuilder import AppRunBuilder
from AppImageCraft.LinkerTool import LinkerTool
from AppImageCraft.PkgTool import PkgTool
from AppImageCraft.AppDirIsolator import AppDirIsolator
import json


class AppDir:
    appdir_path = ""

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

    def __init__(self, app_dir=None, app_runnable=None):
        self.appdir_path = app_dir
        self.app_runnable = app_runnable
        self.logger = logging.getLogger("AppDir")

    def install(self, additional_pkgs=None, excluded_pkgs=None):
        if excluded_pkgs is None:
            excluded_pkgs = set()

        if additional_pkgs is None:
            additional_pkgs = set()

        early_deployed_files = self._deploy_packages(additional_pkgs, excluded_pkgs)

        app_dir_isolator = AppDirIsolator(self.appdir_path)
        app_dir_isolator.isolate()

        self.deploy_registry = {**early_deployed_files, **app_dir_isolator.deploy_map}
        self.libs_registry = app_dir_isolator.libs_map

    def _deploy_packages(self, additional_pkgs, excluded_pkgs):
        self.logger.debug("Deploying packages to: %s" % self.appdir_path)
        absolute_app_dir_path = os.path.abspath(self.appdir_path)

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
            relative_path = os.path.relpath(dir_name, self.appdir_path)
            ld_paths.add(relative_path)

        return list(ld_paths)

    def generate_app_run(self):
        if not self.app_runnable:
            raise RuntimeError("Missing runnable")

        linker = LinkerTool()

        app_run_generator = AppRunBuilder(self.appdir_path, self.app_runnable, linker.binary_path)

        elf_files = linker.list_libraries_files(self.appdir_path)
        app_run_generator.library_paths = self._generate_ld_path(elf_files)

        app_run_generator.build()


def main():
    parser = argparse.ArgumentParser(description='AppDir crafting tool')
    parser.add_argument('--appdir', dest='appdir', default=os.getcwd(), help='target AppDir (default: $PWD)')
    parser.add_argument('--app', dest='app', help='target Application path relative to the AppDir')
    parser.add_argument('--install-deps', dest='do_install_deps', action='store_true',
                        help='install dependencies of the App into the AppDir')

    parser.add_argument('--update-run-paths', dest='do_run_paths_update', action='store_true',
                        help='Update the run paths of the installed binaries')

    parser.add_argument('--generate-apprun', dest='do_generate_apprun', action='store_true',
                        help='Generate the AppRun file required to properly start the App')

    args = parser.parse_args()

    if args.do_install_deps:
        print("Installing application dependencies")
        appDir = AppDir()
        appDir.load()
        appDir.install()

    if args.do_generate_apprun:
        print("Generating the AppRun file")
        appDir = AppDir()
        appDir.load()
        appDir.generate_app_run()


if __name__ == '__main__':
    main()
