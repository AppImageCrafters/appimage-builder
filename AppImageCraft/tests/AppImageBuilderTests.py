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

import os
import shutil
import unittest
import tempfile
import subprocess

from AppImageCraft.tests import tests_common
from AppImageCraft import AppImageBuilder
from AppImageCraft import AppDir2
from AppImageCraft import drivers


class AppImageBuilderTestCase(unittest.TestCase):
    def setUp(self):
        self.app_dir_path, self.runnable_path = tests_common.create_echo_app_dir()
        self.app_dir = AppDir2(self.app_dir_path)

    def tearDown(self):
        shutil.rmtree(self.app_dir_path)

    def test_bundle_dependencies(self):
        builder = AppImageBuilder()
        builder.app_dir = self.app_dir
        builder.drivers = {
            drivers.Source.id: drivers.Source(),
            drivers.Linker.id: drivers.Linker(),
            drivers.Dpkg.id: drivers.Dpkg()
        }

        builder.bundle_dependencies()

        linker_path = self.app_dir_path + '/lib/x86_64-linux-gnu/ld-2.27.so'
        libc_path = self.app_dir_path + '/lib/x86_64-linux-gnu/libc.so.6'
        self.assertTrue(os.path.exists(linker_path))
        self.assertTrue(os.path.exists(libc_path))

        libraries_path = self.app_dir_path + '/lib/x86_64-linux-gnu'
        command = [linker_path, '--inhibit-cache', '--library-path', libraries_path, self.runnable_path, 'hello']

        result = subprocess.run(command, stdout=subprocess.PIPE)
        self.assertEqual(0, result.returncode)

        output = result.stdout.decode('utf-8').strip()
        self.assertEqual('hello', output)

    def test_linker_driver_lockup_dependencies(self):
        linker = drivers.Linker()
        dependencies = linker.lockup_file_dependencies(self.runnable_path, self.app_dir)

        expected = [drivers.LinkerDependency(linker, '/lib/x86_64-linux-gnu/libc.so.6', None, 'libc6.so.6'),
                    drivers.LinkerDependency(linker, '/lib/x86_64-linux-gnu/ld-2.27.so', None,
                                             '/lib/x86_64-linux-gnu/ld-2.27.so')]

        self.assertEqual(dependencies, expected)

    def test_linker_driver_deploy(self):
        linker = drivers.Linker()
        dependency = drivers.LinkerDependency(linker, '/lib/x86_64-linux-gnu/libc.so.6', None, 'libc6.so.6')
        dependency.deploy(self.app_dir)
        self.assertTrue(os.path.exists(self.app_dir_path + '/lib/x86_64-linux-gnu/libc.so.6'))


if __name__ == '__main__':
    unittest.main()
