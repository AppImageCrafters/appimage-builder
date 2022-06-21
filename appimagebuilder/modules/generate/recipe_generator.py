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
import pathlib

from appimagebuilder.modules.analisys.app_runtime_analyser import AppRuntimeAnalyser
from appimagebuilder.context import BundleInfo
from appimagebuilder.modules.generate.bundle_info_gatherer import BundleInfoGatherer
from appimagebuilder.modules.generate.recipe_sections.package_manager_recipe_section_generator import (
    PackageManagerSectionGenerator,
)
from appimagebuilder.modules.generate.recipe_sections.test_section_generator import (
    TestSectionGenerator,
)


class RecipeGenerator:
    """
    Generates a recipe from an staged install
    https://www.gnu.org/software/automake/manual/html_node/Staged-Installs.html
    https://www.gnu.org/prep/standards/html_node/DESTDIR.html
    https://appimage-builder.readthedocs.io/en/latest/reference/version_1.html
    """

    app_dir: pathlib.Path
    _package_manager_sections_generators: [PackageManagerSectionGenerator]
    _bundle_info_gatherer: BundleInfoGatherer
    _runtime_analyser: AppRuntimeAnalyser

    def __init__(
        self,
        package_managers: [PackageManagerSectionGenerator],
        bundle_info_gatherer: BundleInfoGatherer,
        runtime_analyser: AppRuntimeAnalyser,
    ):
        self._package_manager_sections_generators = package_managers
        self._bundle_info_gatherer = bundle_info_gatherer
        self._runtime_analyser = runtime_analyser
        self.bundle_info = BundleInfo()

    def generate(self, app_dir):
        bundle_info = self._bundle_info_gatherer.gather_info(app_dir)
        runtime_dependencies = self._gather_runtime_dependencies(bundle_info)

        sections = self._generate_package_manager_sections(
            bundle_info, runtime_dependencies
        )

        return self._generate_v1_recipe(bundle_info, sections)

    def _generate_package_manager_sections(self, bundle_info, runtime_dependencies):
        """Resolve dependencies using the available package manager section generators"""

        results = {}
        for section_generator in self._package_manager_sections_generators:
            recipe_section, unresolved_files = section_generator.generate(
                runtime_dependencies, bundle_info
            )

            results[section_generator.id()] = recipe_section

            runtime_dependencies = unresolved_files

        return results

    def _gather_runtime_dependencies(self, bundle_info: BundleInfo):
        """launch application and inspect runtime dependencies"""

        runtime_dependencies = self._runtime_analyser.run_app_analysis(
            bundle_info.app_dir,
            bundle_info.app_info.exec,
            bundle_info.app_info.exec_args,
        )

        return runtime_dependencies

    def _generate_v1_recipe(self, bundle_info, sections):
        """generate recipe using the application information and the package manager sections"""

        recipe = {
            "version": 1,
            "AppDir": {
                "path": str(bundle_info.app_dir),
                "app_info": {
                    "id": bundle_info.app_info.id,
                    "name": bundle_info.app_info.name,
                    "icon": bundle_info.app_info.icon,
                    "version": str(bundle_info.app_info.version),
                    "exec": bundle_info.app_info.exec,
                    "exec_args": bundle_info.app_info.exec_args,
                },
            },
            "AppImage": {
                "arch": bundle_info.runtime_arch,
                "update-information": bundle_info.update_string,
            },
        }

        for id, section in sections.items():
            recipe["AppDir"][id] = section

        test_section_generator = TestSectionGenerator()
        recipe["AppDir"]["test"] = test_section_generator.generate()

        return recipe
