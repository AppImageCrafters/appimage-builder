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
from appimagebuilder.modules.deploy.pacman.deploy import Deploy


@skipIf(not shutil.which("pacman"), reason="requires pacman")
class TestDeploy(TestCase):
    venv_path = None
    appdir_path = None

    @classmethod
    def setUpClass(cls):
        cls.appdir_path = Path("/tmp/AppDir")
        cls.venv_path = Path("/tmp/pacman-venv")
        cls.pacman_venv = Venv(cls.venv_path)
        cls.pacman_venv.update()
        cls.appdir_path.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.venv_path)
        shutil.rmtree(cls.appdir_path)

    def test_deploy(self):
        deploy = Deploy(self.pacman_venv)
        deployed_packages = deploy.deploy(["bash"], self.appdir_path)
        print("Deployed packages:")
        for package in deployed_packages:
            print(package)

        self.assertTrue(next(self.appdir_path.glob("usr")))
        self.assertTrue(next(self.appdir_path.glob("runtime/compat/usr")))
