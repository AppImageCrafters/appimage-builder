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
from appimagebuilder.context import BundleInfo
from appimagebuilder.modules.generate.package_managers.pacman.file_package_resolver import (
    FilePackageResolver,
)
from appimagebuilder.modules.generate.recipe_sections.package_manager_recipe_section_generator import (
    PackageManagerSectionGenerator,
)


class PacmanSectionGenerator(PackageManagerSectionGenerator):
    def __init__(self, file_package_resolver: FilePackageResolver):
        self._file_package_resolver = file_package_resolver

    def id(self) -> str:
        return "pacman"

    def generate(self, dependencies: [str], bundle_info: BundleInfo) -> ({}, [str]):
        file_package_map = self._file_package_resolver.resolve(dependencies)

        include_list = set(file_package_map.values())

        missing_files = self._find_missing_files(dependencies, file_package_map)

        section = {
            # "Architecture": "",
            # "repositories": {},
            "include": sorted(include_list),
            "exclude": [],
            # "options": {"SigLevel": "Optional TrustAll"},
        }

        return section, missing_files

    def _find_missing_files(self, dependencies, file_package_map):
        missing_files = set(dependencies)
        for k in file_package_map.keys():
            if k in missing_files:
                missing_files.remove(k)
        return missing_files
