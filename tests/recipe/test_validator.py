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

#   Copyright  2020 Alexis Lopez Zubieta
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#   sell copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
import os
from pathlib import Path
from unittest import TestCase

import yaml

from appimagebuilder import recipe
from appimagebuilder.recipe.schema import RecipeSchema


class TestRecipeSchema(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = RecipeSchema()

    def test_validate_version(self):
        recipe = 1
        self.schema.version.validate(recipe)

    def test_validate_script(self):
        recipe = "ls /home"
        self.schema.script.validate(recipe)

        recipe = ["ls /home"]
        self.schema.script.validate(recipe)

    def test_validate_appdir(self):
        recipe = {
            "path": "/tmp/AppDir",
            "before_bundle": ["ls"],
            "after_bundle": ["ls"],
            "before_runtime": "ls",
            "after_runtime": "ls",
            "app_info": {
                "id": "appid",
                "name": "kcalc",
                "icon": "icon",
                "version": "version",
                "exec": "bin/bash",
                "exec_args": "$@",
            },
            "runtime": {
                "path_mappings": ["/one:more", "/two:more"],
                "env": {
                    "PATH": "${APPDIR}/usr/bin:${PATH}",
                },
                "arch": ["i386", "x86_64", "aarch64", "gnueabihf"],
                "preserve": ["usr/bin/example"],
                "debug": False,
            },
            "files": {"include": ["/one", "/two"], "exclude": ["three", "four"]},
            "test": {
                "debian": {
                    "image": "ubuntu",
                    "command": "./AppDir",
                    "use_host_x": False,
                    "env": {"PATH": "/bin"},
                },
                "ubuntu": {
                    "image": "ubuntu",
                    "command": "./AppDir",
                },
            },
        }
        self.schema.v1_appdir.validate(recipe)

    def test_validate_apt(self):
        recipe = {
            "arch": "i386",
            "sources": [
                {
                    "sourceline": "deb [arch=i386] http://mx.archive.ubuntu.com/ubuntu/ bionic main",
                    "key_url": "http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x3b4fe6acc0b21f32",
                }
            ],
            "include": ["qmlscene"],
            "exclude": ["dpkg"],
        }
        self.schema.v1_apt.validate(recipe)

    def test_validate_examples(self):
        os.environ["APP_VERSION"] = "latest"
        os.environ["TARGET_ARCH"] = "auto"

        files = Path(__file__).parent.glob("../../recipes/*/*.yml")
        schema = RecipeSchema()
        for file in files:
            recipe_loader = recipe.Loader()
            raw_recipe_data = recipe_loader.load(file)
            recipe_roamer = recipe.Roamer(raw_recipe_data)
            schema.validate(recipe_roamer)
