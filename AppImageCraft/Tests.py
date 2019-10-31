#  Copyright  2019 Alexis Lopez Zubieta
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

import unittest
import tempfile
import shutil
import os

from PkgTool import PkgTool
from LinkerTool import LinkerTool
from AppDir import AppDir


class PkgToolTestCase(unittest.TestCase):

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.pkg_tool = PkgTool()

    def test_find_pkgs_of(self):
        pkgs = self.pkg_tool.find_pkgs_of(["/bin/echo", "/bin/less"])
        self.assertEqual(pkgs, {"coreutils", "less"})

    def test_deploy_pkgs(self):
        temp_dir = tempfile.mkdtemp()

        self.pkg_tool.deploy_pkgs(['less'], temp_dir)

        deployed_files = []
        for root, dirs, files in os.walk(temp_dir):
            for filename in files:
                deployed_files.append(os.path.join(root, filename))

        print(deployed_files)
        shutil.rmtree(temp_dir)

        assert deployed_files


class LddToolTestCase(unittest.TestCase):

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.ldd_tool = LinkerTool()

    def test_list_dependencies(self):
        (dependencies, missing) = self.ldd_tool.list_link_dependencies("/bin/echo")

        assert dependencies
        assert not missing


class AppDirTestCase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.temp_dir, "usr", "bin"))
        self.runnable_path = os.path.join(self.temp_dir, "usr", "bin", "echo")
        shutil.copy("/bin/echo", self.runnable_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_load(self):
        self.app_dir = AppDir()

        self.app_dir.load()
        assert self.app_dir.bundle_ldd_dependencies

    def test_deploy(self):
        self.app_dir = AppDir(self.temp_dir, self.runnable_path)

        self.app_dir.load()
        self.app_dir.install()

        assert self.app_dir.bundle_ldd_dependencies
        assert self.app_dir.bundle_packages
        deployed_files = []
        for root, dirs, files in os.walk(self.temp_dir):
            for filename in files:
                deployed_files.append(os.path.join(root, filename))

        print(deployed_files)
        assert deployed_files


if __name__ == '__main__':
    unittest.main()
