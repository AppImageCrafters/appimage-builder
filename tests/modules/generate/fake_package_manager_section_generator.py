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
from appimagebuilder.modules.generate.recipe_sections.package_manager_recipe_section_generator import (
    PackageManagerSectionGenerator,
)


class FakePackageManagerSectionGenerator(PackageManagerSectionGenerator):
    def __init__(self, id, preset_section, missing):
        self.preset_section = preset_section
        self.missing = missing
        self._id = id

    def id(self) -> str:
        return self._id

    def generate(self, dependencies: [str], bundle_info: BundleInfo) -> ({}, [str]):
        return self.preset_section, self.missing
