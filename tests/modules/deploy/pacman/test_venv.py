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

import shutil
from pathlib import Path
from unittest import TestCase, skipIf

from appimagebuilder.modules.deploy.pacman.venv import Venv


@skipIf(not shutil.which("pacman"), reason="requires pacman")
class TestVenv(TestCase):
    venv_path = None
    appdir_path = None

    @classmethod
    def setUpClass(cls):
        cls.appdir_path = Path("/tmp/AppDir")
        cls.venv_path = Path("/tmp/pacman-venv")
        cls.pacman_venv = Venv(
            cls.venv_path,
            repositories={
                "core": ["https://mirror.rackspace.com/archlinux/$repo/os/$arch"]
            },
            architecture="auto",
        )
        cls.pacman_venv.update()
        cls.appdir_path.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        pass
        # shutil.rmtree(cls.venv_path)
        # shutil.rmtree(cls.appdir_path)

    def test_retrieve(self):
        self.pacman_venv.retrieve(
            ["bash"], ["tzdata", "filesystem", "linux-api-headers"]
        )

    def test_extract(self):
        files = self.pacman_venv.retrieve(
            ["bash"], ["tzdata", "filesystem", "linux-api-headers"]
        )
        self.pacman_venv.extract(files[0], self.appdir_path)

    def test_read_package_data(self):
        files = self.pacman_venv.retrieve(
            ["bash"], ["tzdata", "filesystem", "linux-api-headers"]
        )
        self.assertTrue(self.pacman_venv.read_package_data(files[0]))
