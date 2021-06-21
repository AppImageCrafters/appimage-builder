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
from unittest import TestCase

from appimagebuilder.context import AppInfo, BundleInfo
from appimagebuilder.modules.generate.recipe_generator import RecipeGenerator
from appimagebuilder.recipe.schema import RecipeSchema
from tests.modules.generate.fake_path import FakePath
from tests.modules.generate.fake_runtime_analyser import FakeAppRuntimeAnalyser
from tests.modules.generate.fake_bundle_info_gatherer import FakeBundleInfoGatherer
from tests.modules.generate.fake_package_manager_section_generator import (
    FakePackageManagerSectionGenerator,
)


class TestRecipeGenerator(TestCase):
    def setUp(self) -> None:
        self.generator = RecipeGenerator(
            package_managers=[
                FakePackageManagerSectionGenerator(
                    "apt",
                    {
                        "arch": "amd64",
                        "sources": [],
                        "include": ["libc6"],
                    },
                    ["/missing/file"],
                ),
                FakePackageManagerSectionGenerator(
                    "files",
                    {
                        "include": ["/missing/file"],
                    },
                    [],
                ),
            ],
            bundle_info_gatherer=FakeBundleInfoGatherer(
                BundleInfo(
                    app_dir=pathlib.Path("AppDir"),
                    app_info=AppInfo(
                        id="fooview",
                        name="Foo View",
                        icon="fooview",
                        exec="usr/bin/fooview",
                        exec_args="$@",
                    ),
                    update_string="update_string",
                    runtime_arch="amd64",
                )
            ),
            runtime_analyser=FakeAppRuntimeAnalyser(
                ["/lib64/ld-linux-x86-64.so.2", "/missing/file"]
            ),
        )

    def test_generate(self):
        recipe = self.generator.generate(FakePath("/tmp/AppDir"))
        schema = RecipeSchema()
        self.assertTrue(schema.v1.validate(recipe))
        self.assertIn("apt", recipe["AppDir"])
        self.assertIn("files", recipe["AppDir"])
