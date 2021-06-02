#  Copyright  2021 Alexis Lopez Zubieta
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

from appimagebuilder.context import BundleInfo
from appimagebuilder.modules.generate.package_managers.apt.package_filter import (
    PackageFilter,
)
from appimagebuilder.modules.generate.recipe_sections.package_manager_recipe_section_generator import (
    PackageManagerSectionGenerator,
)
from appimagebuilder.modules.generate.package_managers import apt


class AptSectionGenerator(PackageManagerSectionGenerator):
    _file_package_resolver: apt.FilePackageResolver
    _package_repository_resolver: apt.PackageRepositoryResolver

    def __init__(
        self,
        file_package_resolver: apt.FilePackageResolver,
        package_repository_resolver: apt.PackageRepositoryResolver,
    ):
        self._file_package_resolver = file_package_resolver
        self._package_repository_resolver = package_repository_resolver
        self.logger = logging.getLogger(str(self.__class__))

    def id(self) -> str:
        return "apt"

    def generate(self, dependencies: [str], bundle_info: BundleInfo) -> ({}, [str]):
        # map files to packages to create the include list
        dependency_map = self._file_package_resolver.resolve(dependencies)
        unresolved_dependencies = set(dependencies).difference(dependency_map.keys())

        package_filter = PackageFilter()
        include_list = package_filter.filter(dependency_map.values())

        # map packages to repositories to create the sources lists
        source_lines = self._package_repository_resolver.resolve_source_lines(
            include_list
        )

        architectures = self._extract_architecture_from_package_names(include_list)

        result = {
            "arch": architectures,
            "allow_unauthenticated": True,
            "sources": [{"sourceline": sourceline} for sourceline in source_lines],
            "include": sorted(include_list),
        }

        return result, list(unresolved_dependencies)

    @staticmethod
    def _extract_architecture_from_package_names(pkg_names):
        architectures = set()
        for pkg_name in pkg_names:
            parts = pkg_name.split(sep=":", maxsplit=1)
            if len(parts) > 1:
                architectures.add(parts[1])

        return list(architectures)
