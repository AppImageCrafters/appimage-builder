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
import shutil
from pathlib import Path
from unittest import TestCase, skipIf
from appimagebuilder.modules.deploy.apt import Deploy
from appimagebuilder.modules.deploy.apt.venv import Venv


@skipIf(not shutil.which("apt-get"), reason="requires apt-get")
class TestDeploy(TestCase):
    venv_path = None
    appdir_path = None

    @classmethod
    def setUpClass(cls):
        cls.venv_path = "/tmp/apt-venv"
        cls.appdir_path = Path("/tmp/AppDir")
        cls.apt_venv = Venv(
            cls.venv_path,
            ["deb [arch=amd64] http://deb.debian.org/debian/ bullseye main"],
            ["https://ftp-master.debian.org/keys/archive-key-10.asc"],
            ["amd64"],
        )

    @classmethod
    def tearDownClass(cls):
        pass
        # shutil.rmtree(cls.venv_path)
        # shutil.rmtree(cls.appdir_path)

    def test_deploy(self):
        logging.basicConfig(level=0)

        apt_deploy = Deploy(self.apt_venv)
        apt_deploy.deploy(["perl", "util-linux"], self.appdir_path)
        self.assertTrue(next(self.appdir_path.glob("usr")))
        self.assertTrue(next(self.appdir_path.glob("runtime/compat/lib")))
