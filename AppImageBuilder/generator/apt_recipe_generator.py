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
import os

from AppImageBuilder.commands.dpkg_architecture import DpkgArchitecture
from AppImageBuilder.commands.dpkg_query import DpkgQuery
from AppImageBuilder.app_dir.bundlers.apt.package_lists import *


class AptRecipeGenerator:
    @staticmethod
    def get_arch():
        dpkg_architecture = DpkgArchitecture()
        return dpkg_architecture.get_deb_host_arch()

    @staticmethod
    def get_sources():
        sources = []
        for root, dir, files in os.walk('/etc/apt/'):
            for file_name in files:
                if file_name.endswith('list'):
                    new_sources = AptRecipeGenerator._read_sources_list_file(os.path.join(root, file_name))
                    sources.extend(new_sources)

        return sources

    @staticmethod
    def resolve_includes(runtime_libs):
        packages = AptRecipeGenerator._map_files_to_packages(runtime_libs)
        packages = AptRecipeGenerator._remove_excluded_packages(packages)
        packages = AptRecipeGenerator._remove_nested_dependencies(packages)

        return list(sorted(packages))

    @staticmethod
    def _map_files_to_packages(runtime_libs):
        dpkg_query = DpkgQuery()
        packages = dpkg_query.search(runtime_libs)
        return packages

    @staticmethod
    def _remove_nested_dependencies(packages):
        dpkg_query = DpkgQuery()
        dependencies = dpkg_query.depends(packages)
        for pkd_name, pkg_depends in dependencies.items():
            for dependency in pkg_depends:
                if dependency in packages:
                    packages.remove(dependency)

        return packages

    @staticmethod
    def _remove_excluded_packages(packages):
        exclusion_list = []
        exclusion_list.extend(apt_core_packages)
        exclusion_list.extend(apt_xclient_packages)
        exclusion_list.extend(apt_graphics_stack_packages)
        exclusion_list.extend(apt_font_config_packages)
        filtered_packages = set()
        for package in packages:
            excluded = False
            for exclusion_rule in exclusion_list:
                if fnmatch.fnmatch(package, exclusion_rule):
                    excluded = True

            if not excluded:
                filtered_packages.add(package)
        return filtered_packages

    @staticmethod
    def _read_sources_list_file(path):
        sources = []
        with open(path, 'r') as f:
            for line in f.readlines():
                if line.startswith('deb '):
                    sources.append({'sourceline': line.strip(), 'key_url': ''})

        return sources

    @staticmethod
    def resolve_excludes():
        return []
