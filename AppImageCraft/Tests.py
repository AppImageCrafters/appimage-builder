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

from AppImageCraft.tools.PkgTool import PkgTool
from AppImageCraft.tools.LinkerTool import LinkerTool
from AppImageCraft.AppDir import AppDir
from AppImageCraft.AppDirIsolator import AppDirIsolator


class PkgToolTestCase(unittest.TestCase):

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.pkg_tool = PkgTool()

    def test_find_pkgs_of(self):
        pkgs = self.pkg_tool.find_owner_packages("/bin/echo")
        self.assertEqual(pkgs, {"coreutils"})

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


class LinkerToolTestCase(unittest.TestCase):

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.ldd_tool = LinkerTool()

    def test_list_dependencies(self):
        dependencies_map = self.ldd_tool.list_link_dependencies("/bin/echo")
        assert dependencies_map

    def test_parse_output_regular(self):
        output = self.ldd_tool._parse(
            "        linux-vdso.so.1 (0x00007f4fc901c000)\n"
            "        libc.so.6 => /AppDir/lib/x86_64-linux-gnu/libc.so.6 (0x00007f4fc8803000)\n"
            "        /AppDir/lib/x86_64-linux-gnu/ld-2.27.so (0x00007f4fc8df7000)\n")

        expected = {
            "linux-vdso.so.1": None,
            "libc.so.6": "/AppDir/lib/x86_64-linux-gnu/libc.so.6",
            "/AppDir/lib/x86_64-linux-gnu/ld-2.27.so": None
        }

        assert output == expected

    def test_parse_output_static(self):
        output = self.ldd_tool._parse("        statically linked\n")
        expected = {}
        assert output == expected


class AppDirIsolatorTestCase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.temp_dir, "usr", "bin"))

        shutil.copy("/bin/echo", os.path.join(self.temp_dir, "usr/bin"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_deploy_linker(self):
        isolator = AppDirIsolator(self.temp_dir)
        isolator.deploy_linker()

        deployed_linker_path = LinkerTool.find_binary_path(self.temp_dir)
        assert deployed_linker_path.startswith(self.temp_dir)

    def test_list_files_with_external_dependencies(self):
        isolator = AppDirIsolator(self.temp_dir)

        files = isolator.list_files_with_external_dependencies()
        assert os.path.join(self.temp_dir, "usr", "bin", "echo") in files

    def test_isolate(self):
        isolator = AppDirIsolator(self.temp_dir)
        isolator.isolate()

        files = isolator.list_files_with_external_dependencies()
        assert not files


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
        self.app_dir = AppDir(self.temp_dir)

        self.app_dir.install(additional_pkgs=["coreutils"])

        deployed_files = []
        for root, dirs, files in os.walk(self.temp_dir):
            for filename in files:
                deployed_files.append(os.path.join(root, filename))

        print(deployed_files)
        assert deployed_files


if __name__ == '__main__':
    unittest.main()
